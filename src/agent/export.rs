use std::fs::OpenOptions;
use std::io::{Cursor, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::Serialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::ZipWriter;
use zip::write::SimpleFileOptions;

use super::state::{DbError, DbHandle, ReferenceBody};
use crate::agent::models::{FieldEntry, ItemResponse};

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExportJobError {
    pub code: String,
    pub message: String,
}

impl ExportJobError {
    fn not_found(message: impl Into<String>) -> Self {
        Self {
            code: "not_found".to_owned(),
            message: message.into(),
        }
    }

    fn bad_reference(message: impl Into<String>) -> Self {
        Self {
            code: "bad_reference".to_owned(),
            message: message.into(),
        }
    }

    fn encrypt_failed() -> Self {
        Self {
            code: "encrypt_failed".to_owned(),
            message: "failed to encrypt export".to_owned(),
        }
    }

    fn io_failed(message: impl Into<String>) -> Self {
        Self {
            code: "io_failed".to_owned(),
            message: message.into(),
        }
    }

    fn internal() -> Self {
        Self {
            code: "internal_error".to_owned(),
            message: "internal error".to_owned(),
        }
    }

    fn from_db(error: DbError) -> Self {
        match error {
            DbError::NotFound => Self::not_found("not found"),
            DbError::NotFoundMessage(message) => Self::not_found(message),
            DbError::AccessDenied => Self {
                code: "access_denied".to_owned(),
                message: "access denied".to_owned(),
            },
            DbError::BadRequest(message) => Self {
                code: "bad_request".to_owned(),
                message,
            },
            DbError::Conflict(message) => Self {
                code: "conflict".to_owned(),
                message,
            },
            DbError::Internal => Self::internal(),
        }
    }
}

pub async fn run_export_job(
    database: DbHandle,
    job_store_path: PathBuf,
    job_id: String,
    dir_name: String,
    item_name: String,
    contact_name: String,
) -> Result<PathBuf, ExportJobError> {
    let public_key = database
        .contact_public_key(contact_name.clone())
        .await
        .map_err(ExportJobError::from_db)?;
    let recipient = age::x25519::Recipient::from_str(&public_key)
        .map_err(|_| ExportJobError::bad_reference("contact has an invalid age public key"))?;
    let item = database
        .get_item(dir_name.clone(), item_name.clone(), None, true, true, true)
        .await
        .map_err(ExportJobError::from_db)?;
    let zip = build_zip(database, &dir_name, &item_name, item).await?;
    let encrypted = encrypt_zip(zip, recipient)?;
    write_job_output(
        &job_store_path,
        &job_id,
        &contact_name,
        &item_name,
        &encrypted,
    )
}

async fn build_zip(
    database: DbHandle,
    dir_name: &str,
    item_name: &str,
    item: ItemResponse,
) -> Result<Zeroizing<Vec<u8>>, ExportJobError> {
    let mut output = Zeroizing::new(Vec::new());
    let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
    let ItemResponse {
        name,
        fields,
        files,
        ..
    } = item;
    let mut export_files = Vec::new();

    {
        let mut cursor = Cursor::new(&mut *output);
        let mut zip = ZipWriter::new(&mut cursor);

        for file in &files {
            let response = database
                .get_reference(
                    dir_name.to_owned(),
                    item_name.to_owned(),
                    file.name.clone(),
                    None,
                    true,
                    true,
                )
                .await
                .map_err(ExportJobError::from_db)?;
            let etag = response
                .etag
                .ok_or_else(|| ExportJobError::bad_reference("file response missing checksum"))?;
            let bytes = reference_body_bytes(response.body).await?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != etag {
                return Err(ExportJobError::bad_reference("file checksum mismatch"));
            }
            zip.start_file(format!("files/{etag}"), options)
                .map_err(|_| ExportJobError::internal())?;
            zip.write_all(&bytes)
                .map_err(|_| ExportJobError::internal())?;
            export_files.push(ExportFile {
                name: file.name.clone(),
                sha256: etag,
            });
        }

        zip.start_file("fields.json", options)
            .map_err(|_| ExportJobError::internal())?;
        let export = ExportItem {
            name,
            fields,
            files: export_files,
        };
        let fields_bytes = Zeroizing::new(
            serde_json::to_vec_pretty(&export).map_err(|_| ExportJobError::internal())?,
        );
        zip.write_all(&fields_bytes)
            .map_err(|_| ExportJobError::internal())?;
        zip.finish().map_err(|_| ExportJobError::internal())?;
    }

    Ok(output)
}

async fn reference_body_bytes(body: ReferenceBody) -> Result<Zeroizing<Vec<u8>>, ExportJobError> {
    match body {
        ReferenceBody::Bytes(bytes) => Ok(bytes),
        ReferenceBody::Stream(mut receiver) => {
            let mut bytes = Zeroizing::new(Vec::new());
            while let Some(chunk) = receiver.recv().await {
                let chunk = chunk.map_err(ExportJobError::from_db)?;
                bytes.extend_from_slice(&chunk);
            }
            Ok(bytes)
        }
    }
}

fn encrypt_zip(
    zip: Zeroizing<Vec<u8>>,
    recipient: age::x25519::Recipient,
) -> Result<Zeroizing<Vec<u8>>, ExportJobError> {
    let recipients: [&dyn age::Recipient; 1] = [&recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|_| ExportJobError::encrypt_failed())?;
    let mut encrypted = Zeroizing::new(Vec::new());
    {
        let mut writer = encryptor
            .wrap_output(&mut *encrypted)
            .map_err(|_| ExportJobError::encrypt_failed())?;
        writer
            .write_all(&zip)
            .map_err(|_| ExportJobError::encrypt_failed())?;
        writer
            .finish()
            .map_err(|_| ExportJobError::encrypt_failed())?;
    }
    Ok(encrypted)
}

fn write_job_output(
    job_store_path: &Path,
    job_id: &str,
    contact_name: &str,
    item_name: &str,
    encrypted: &[u8],
) -> Result<PathBuf, ExportJobError> {
    std::fs::create_dir_all(job_store_path)
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    std::fs::set_permissions(
        job_store_path,
        std::fs::Permissions::from_mode(PRIVATE_DIR_MODE),
    )
    .map_err(|error| ExportJobError::io_failed(error.to_string()))?;

    let job_dir = job_store_path.join(job_id);
    std::fs::create_dir(&job_dir).map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    std::fs::set_permissions(&job_dir, std::fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;

    let file_name = format!("{contact_name}_{item_name}.export");
    let final_path = job_dir.join(file_name);
    let temp_path = job_dir.join("output.tmp");
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&temp_path)
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    file.write_all(encrypted)
        .and_then(|()| file.flush())
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    drop(file);
    std::fs::rename(&temp_path, &final_path).map_err(|error| {
        let _ = std::fs::remove_file(&temp_path);
        ExportJobError::io_failed(error.to_string())
    })?;
    Ok(final_path)
}

#[derive(Serialize)]
struct ExportItem {
    name: String,
    fields: Vec<FieldEntry>,
    files: Vec<ExportFile>,
}

#[derive(Serialize)]
struct ExportFile {
    name: String,
    sha256: String,
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};
    use std::os::unix::fs::PermissionsExt;

    use age::Decryptor;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use zip::ZipArchive;

    use super::run_export_job;
    use crate::agent::models::{CreateContactRequest, CreateItemRequest};
    use crate::agent::state::DbHandle;

    #[tokio::test]
    async fn export_job_writes_decryptable_archive_with_fields_and_files() {
        let database = DbHandle::test();
        database.create_dir("Personal".to_owned()).await.unwrap();
        let identity = age::x25519::Identity::generate();
        database
            .create_contact(
                "alice".to_owned(),
                CreateContactRequest {
                    name: None,
                    age_public_key: identity.to_public().to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        let file_id = database
            .create_file(b"shared notes".to_vec())
            .await
            .unwrap();
        database
            .create_item(
                "Personal".to_owned(),
                "Github".to_owned(),
                serde_json::from_value::<CreateItemRequest>(json!({
                    "fields": [
                        {"name": "username", "type": "string", "data": "alice"},
                        {"name": "password", "type": "string", "concealed": true, "data": "secret"}
                    ],
                    "files": [
                        {"name": "notes.txt", "id": file_id}
                    ]
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let jobs = tempfile::tempdir().unwrap();

        let output_path = run_export_job(
            database,
            jobs.path().to_owned(),
            "00112233445566778899aabbccddeeff".to_owned(),
            "Personal".to_owned(),
            "Github".to_owned(),
            "alice".to_owned(),
        )
        .await
        .unwrap();

        assert_eq!(
            0o600,
            output_path.metadata().unwrap().permissions().mode() & 0o777
        );
        let encrypted = std::fs::File::open(&output_path).unwrap();
        let decryptor = Decryptor::new(encrypted).unwrap();
        let mut reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut zip_bytes = Vec::new();
        reader.read_to_end(&mut zip_bytes).unwrap();
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();

        let fields = read_zip_entry(&mut archive, "fields.json");
        let fields: serde_json::Value = serde_json::from_slice(&fields).unwrap();
        assert_eq!("Github", fields["name"]);
        assert_eq!("alice", entry_named(&fields["fields"], "username")["data"]);
        assert_eq!("secret", entry_named(&fields["fields"], "password")["data"]);
        let sha256 = entry_named(&fields["files"], "notes.txt")["sha256"]
            .as_str()
            .unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(b"shared notes")), sha256);
        assert_eq!(
            b"shared notes",
            read_zip_entry(&mut archive, &format!("files/{sha256}")).as_slice()
        );
    }

    fn read_zip_entry(archive: &mut ZipArchive<Cursor<Vec<u8>>>, name: &str) -> Vec<u8> {
        let mut file = archive.by_name(name).unwrap();
        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes).unwrap();
        bytes
    }

    fn entry_named<'a>(entries: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        entries
            .as_array()
            .unwrap()
            .iter()
            .find(|entry| entry["name"] == name)
            .expect("entry exists")
    }
}
