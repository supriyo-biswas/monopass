use std::fs;
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use flate2::{Compression, GzBuilder};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tar::{Builder, EntryType, Header, HeaderMode};
use tempfile::NamedTempFile;
use zeroize::Zeroizing;

use super::state::{
    DbError, DbHandle, ExportSnapshot, ExportSnapshotFile, FILE_RECORD_PLAINTEXT_BYTES,
};
use crate::agent::models::{FieldEntry, FieldType};
use crate::secret::SecretString;

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const EXPORT_FORMAT: &str = "monopass-export";
const EXPORT_VERSION: u64 = 1;
const MANIFEST_PATH: &str = "manifest.json";
const MAX_MANIFEST_BYTES: usize = 16 * 1024 * 1024;

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
    let snapshot = database
        .export_snapshot(dir_name, item_name.clone())
        .await
        .map_err(ExportJobError::from_db)?;

    tokio::task::spawn_blocking(move || {
        write_export(
            &job_store_path,
            &job_id,
            &contact_name,
            &item_name,
            recipient,
            snapshot,
        )
    })
    .await
    .map_err(|_| ExportJobError::internal())?
}

fn write_export(
    job_store_path: &Path,
    job_id: &str,
    contact_name: &str,
    item_name: &str,
    recipient: age::x25519::Recipient,
    snapshot: ExportSnapshot,
) -> Result<PathBuf, ExportJobError> {
    create_private_dir_all(job_store_path)?;
    let job_dir = job_store_path.join(job_id);
    fs::create_dir(&job_dir).map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    fs::set_permissions(&job_dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;

    let file_name = format!(
        "{}_{}.export",
        safe_output_component(contact_name),
        safe_output_component(item_name)
    );
    let final_path = job_dir.join(file_name);
    let mut temporary = NamedTempFile::new_in(&job_dir)
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))
        .map_err(|error| ExportJobError::io_failed(error.to_string()))?;

    stream_export(temporary.as_file_mut(), recipient, snapshot)?;

    persist_export(temporary, &final_path)?;
    Ok(final_path)
}

fn safe_output_component(value: &str) -> String {
    value
        .chars()
        .map(|character| match character {
            '/' | '\0' => '_',
            character => character,
        })
        .collect()
}

fn persist_export(temporary: NamedTempFile, final_path: &Path) -> Result<(), ExportJobError> {
    temporary
        .persist_noclobber(final_path)
        .map(|_| ())
        .map_err(|error| ExportJobError::io_failed(error.error.to_string()))
}

fn stream_export(
    output: &mut fs::File,
    recipient: age::x25519::Recipient,
    snapshot: ExportSnapshot,
) -> Result<(), ExportJobError> {
    let ExportSnapshot {
        name,
        fields,
        files,
    } = snapshot;
    let manifest = ExportManifest {
        format: EXPORT_FORMAT,
        version: EXPORT_VERSION,
        name,
        fields: fields.into_iter().map(ExportField::from).collect(),
        files: files
            .iter()
            .map(|file| ExportFile {
                name: file.name.clone(),
                sha256: file.sha256.clone(),
                size: file.size,
            })
            .collect(),
    };
    let manifest_bytes =
        Zeroizing::new(serde_json::to_vec(&manifest).map_err(|_| ExportJobError::internal())?);
    if manifest_bytes.len() > MAX_MANIFEST_BYTES {
        return Err(ExportJobError::bad_reference(
            "export manifest exceeds 16 MiB",
        ));
    }

    let recipients: [&dyn age::Recipient; 1] = [&recipient];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|_| ExportJobError::encrypt_failed())?;
    let age_writer = encryptor
        .wrap_output(output)
        .map_err(|_| ExportJobError::encrypt_failed())?;
    let gzip = GzBuilder::new()
        .mtime(0)
        .write(age_writer, Compression::default());
    let mut tar = Builder::new(gzip);
    tar.mode(HeaderMode::Deterministic);

    append_bytes(&mut tar, MANIFEST_PATH, &manifest_bytes)
        .map_err(|_| ExportJobError::internal())?;
    for file in files {
        append_snapshot_file(&mut tar, file)?;
    }

    tar.finish().map_err(|_| ExportJobError::internal())?;
    let gzip = tar.into_inner().map_err(|_| ExportJobError::internal())?;
    let age_writer = gzip.finish().map_err(|_| ExportJobError::internal())?;
    let output = age_writer
        .finish()
        .map_err(|_| ExportJobError::encrypt_failed())?;
    output
        .flush()
        .map_err(|error| ExportJobError::io_failed(error.to_string()))
}

fn append_snapshot_file(
    tar: &mut Builder<flate2::write::GzEncoder<age::stream::StreamWriter<&mut fs::File>>>,
    file: ExportSnapshotFile,
) -> Result<(), ExportJobError> {
    let ExportSnapshotFile {
        name: _,
        size,
        sha256,
        chunks,
    } = file;
    let path = format!("files/{sha256}");
    let mut header = regular_header(size)?;
    let mut reader = SnapshotFileReader::new(chunks);
    tar.append_data(&mut header, path, &mut reader)
        .map_err(|_| ExportJobError::bad_reference("failed to stream file"))?;
    reader.finish()?;
    if reader.size != size || reader.sha256() != sha256 {
        return Err(ExportJobError::bad_reference(
            "file size or checksum changed during export",
        ));
    }
    Ok(())
}

fn append_bytes<W: Write>(tar: &mut Builder<W>, path: &str, bytes: &[u8]) -> io::Result<()> {
    let size = u64::try_from(bytes.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "entry too large"))?;
    let mut header = regular_header_io(size)?;
    tar.append_data(&mut header, path, bytes)
}

fn regular_header(size: u64) -> Result<Header, ExportJobError> {
    regular_header_io(size).map_err(|_| ExportJobError::internal())
}

fn regular_header_io(size: u64) -> io::Result<Header> {
    let mut header = Header::new_gnu();
    header.set_entry_type(EntryType::Regular);
    header.set_mode(PRIVATE_FILE_MODE);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header.set_cksum();
    Ok(header)
}

fn create_private_dir_all(path: &Path) -> Result<(), ExportJobError> {
    fs::create_dir_all(path).map_err(|error| ExportJobError::io_failed(error.to_string()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|error| ExportJobError::io_failed(error.to_string()))
}

struct SnapshotFileReader {
    chunks: tokio::sync::mpsc::Receiver<Result<Zeroizing<Vec<u8>>, DbError>>,
    current: Option<Zeroizing<Vec<u8>>>,
    offset: usize,
    size: u64,
    digest: Sha256,
}

impl SnapshotFileReader {
    fn new(chunks: tokio::sync::mpsc::Receiver<Result<Zeroizing<Vec<u8>>, DbError>>) -> Self {
        Self {
            chunks,
            current: None,
            offset: 0,
            size: 0,
            digest: Sha256::new(),
        }
    }

    fn finish(&mut self) -> Result<(), ExportJobError> {
        let mut buffer = Zeroizing::new(vec![0; FILE_RECORD_PLAINTEXT_BYTES]);
        while self
            .read(&mut buffer)
            .map_err(|_| ExportJobError::bad_reference("failed to stream file"))?
            != 0
        {}
        Ok(())
    }

    fn sha256(&self) -> String {
        format!("{:x}", self.digest.clone().finalize())
    }
}

impl Read for SnapshotFileReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if let Some(current) = self.current.as_ref()
                && self.offset < current.len()
            {
                let count = output.len().min(current.len() - self.offset);
                let bytes = &current[self.offset..self.offset + count];
                output[..count].copy_from_slice(bytes);
                self.offset += count;
                self.size = self
                    .size
                    .checked_add(u64::try_from(count).map_err(io::Error::other)?)
                    .ok_or_else(|| io::Error::other("file size overflow"))?;
                self.digest.update(bytes);
                return Ok(count);
            }

            self.current = None;
            self.offset = 0;
            match self.chunks.blocking_recv() {
                Some(Ok(chunk)) => self.current = Some(chunk),
                Some(Err(_)) => return Err(io::Error::other("database file stream failed")),
                None => return Ok(0),
            }
        }
    }
}

#[derive(Serialize)]
struct ExportManifest {
    format: &'static str,
    version: u64,
    name: String,
    fields: Vec<ExportField>,
    files: Vec<ExportFile>,
}

#[derive(Serialize)]
struct ExportField {
    name: String,
    #[serde(rename = "type")]
    field_type: FieldType,
    concealed: bool,
    data: SecretString,
}

impl From<FieldEntry> for ExportField {
    fn from(field: FieldEntry) -> Self {
        Self {
            name: field.name,
            field_type: field.field_type,
            concealed: field.concealed,
            data: field.data,
        }
    }
}

#[derive(Serialize)]
struct ExportFile {
    name: String,
    sha256: String,
    size: u64,
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{BufReader, Read, Write};
    use std::os::unix::fs::PermissionsExt;

    use age::Decryptor;
    use flate2::bufread::MultiGzDecoder;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tar::Archive;
    use zeroize::Zeroizing;

    use super::{persist_export, run_export_job, write_export};
    use crate::agent::models::{CreateContactRequest, CreateItemRequest};
    use crate::agent::state::{DbHandle, ExportSnapshot, ExportSnapshotFile};

    #[tokio::test]
    async fn export_job_writes_decryptable_archive_with_manifest_first_and_streamed_file() {
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
        let file_bytes = vec![0xa5; crate::agent::state::FILE_RECORD_PLAINTEXT_BYTES * 3 + 7];
        let file_id = database.create_file(file_bytes.clone()).await.unwrap();
        let alpha_bytes = b"alpha file".to_vec();
        let alpha_id = database.create_file(alpha_bytes.clone()).await.unwrap();
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
                        {"name": "notes.bin", "id": file_id},
                        {"name": "alpha.bin", "id": alpha_id}
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
        let encrypted = fs::File::open(&output_path).unwrap();
        let decryptor = Decryptor::new(encrypted).unwrap();
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let gzip = MultiGzDecoder::new(BufReader::new(reader));
        assert_eq!(Some(0), gzip.header().map(|header| header.mtime()));
        let mut archive = Archive::new(gzip);
        let mut entries = archive.entries().unwrap();

        let mut manifest_entry = entries.next().unwrap().unwrap();
        assert_eq!(
            "manifest.json",
            manifest_entry.path().unwrap().to_str().unwrap()
        );
        assert!(manifest_entry.header().entry_type().is_file());
        assert_eq!(0, manifest_entry.header().mtime().unwrap());
        assert_eq!(0, manifest_entry.header().uid().unwrap());
        assert_eq!(0, manifest_entry.header().gid().unwrap());
        assert_eq!(0o600, manifest_entry.header().mode().unwrap());
        let mut manifest = Vec::new();
        manifest_entry.read_to_end(&mut manifest).unwrap();
        drop(manifest_entry);
        let manifest: serde_json::Value = serde_json::from_slice(&manifest).unwrap();
        assert_eq!("monopass-export", manifest["format"]);
        assert_eq!(1, manifest["version"]);
        assert_eq!("Github", manifest["name"]);
        assert_eq!(
            "alice",
            entry_named(&manifest["fields"], "username")["data"]
        );
        assert_eq!(
            "secret",
            entry_named(&manifest["fields"], "password")["data"]
        );
        assert_eq!("alpha.bin", manifest["files"][0]["name"]);
        assert_eq!("notes.bin", manifest["files"][1]["name"]);
        let alpha = entry_named(&manifest["files"], "alpha.bin");
        let alpha_sha256 = alpha["sha256"].as_str().unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&alpha_bytes)), alpha_sha256);
        let file = entry_named(&manifest["files"], "notes.bin");
        let sha256 = file["sha256"].as_str().unwrap();
        assert_eq!(format!("{:x}", Sha256::digest(&file_bytes)), sha256);
        assert_eq!(file_bytes.len() as u64, file["size"].as_u64().unwrap());

        let mut alpha_entry = entries.next().unwrap().unwrap();
        assert_eq!(
            format!("files/{alpha_sha256}"),
            alpha_entry.path().unwrap().to_str().unwrap()
        );
        let mut actual_alpha = Vec::new();
        alpha_entry.read_to_end(&mut actual_alpha).unwrap();
        assert_eq!(alpha_bytes, actual_alpha);
        drop(alpha_entry);

        let mut file_entry = entries.next().unwrap().unwrap();
        assert_eq!(
            format!("files/{sha256}"),
            file_entry.path().unwrap().to_str().unwrap()
        );
        let mut actual = Vec::new();
        file_entry.read_to_end(&mut actual).unwrap();
        assert_eq!(file_bytes, actual);
        drop(file_entry);
        assert!(entries.next().is_none());

        let names = fs::read_dir(output_path.parent().unwrap())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(vec![output_path.file_name().unwrap()], names);
    }

    #[test]
    fn no_clobber_publication_preserves_existing_output_and_removes_temporary_file() {
        let directory = tempfile::tempdir().unwrap();
        let final_path = directory.path().join("final.export");
        fs::write(&final_path, b"existing").unwrap();
        let mut temporary = tempfile::NamedTempFile::new_in(directory.path()).unwrap();
        temporary.write_all(b"replacement").unwrap();
        let temporary_path = temporary.path().to_owned();
        assert_ne!(
            Some(std::ffi::OsStr::new("output.tmp")),
            temporary_path.file_name()
        );

        let error = persist_export(temporary, &final_path).unwrap_err();

        assert_eq!("io_failed", error.code);
        assert_eq!(b"existing", fs::read(final_path).unwrap().as_slice());
        assert!(!temporary_path.exists());
    }

    #[test]
    fn failed_stream_removes_random_temporary_job_file() {
        let jobs = tempfile::tempdir().unwrap();
        let identity = age::x25519::Identity::generate();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .try_send(Ok(Zeroizing::new(b"wrong".to_vec())))
            .unwrap();
        drop(sender);
        let snapshot = ExportSnapshot {
            name: "source".to_owned(),
            fields: Vec::new(),
            files: vec![ExportSnapshotFile {
                name: "notes".to_owned(),
                size: 5,
                sha256: format!("{:x}", Sha256::digest(b"right")),
                chunks: receiver,
            }],
        };

        let error = write_export(
            jobs.path(),
            "00112233445566778899aabbccddeeff",
            "alice",
            "source",
            identity.to_public(),
            snapshot,
        )
        .unwrap_err();

        assert_eq!("bad_reference", error.code);
        let job_dir = jobs.path().join("00112233445566778899aabbccddeeff");
        assert_eq!(0, fs::read_dir(job_dir).unwrap().count());
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
