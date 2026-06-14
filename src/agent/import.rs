use std::collections::HashSet;
use std::fs::File;
use std::io::{Cursor, Read};
use std::path::Path;
use std::str::FromStr;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;
use zip::ZipArchive;

use super::models::{CreateField, CreateItemRequest, FieldEntry, FileInput};
use super::state::{DbError, DbHandle};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportJobError {
    pub code: String,
    pub message: String,
}

impl ImportJobError {
    fn bad_archive(message: impl Into<String>) -> Self {
        Self {
            code: "bad_archive".to_owned(),
            message: message.into(),
        }
    }

    fn decrypt_failed() -> Self {
        Self {
            code: "decrypt_failed".to_owned(),
            message: "failed to decrypt export".to_owned(),
        }
    }

    fn from_db(error: DbError) -> Self {
        match error {
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
            DbError::Internal => Self {
                code: "internal_error".to_owned(),
                message: "internal error".to_owned(),
            },
            DbError::NotFound => Self {
                code: "not_found".to_owned(),
                message: "not found".to_owned(),
            },
            DbError::NotFoundMessage(message) => Self {
                code: "not_found".to_owned(),
                message,
            },
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportItem {
    name: String,
    #[serde(default)]
    fields: Vec<FieldEntry>,
    #[serde(default)]
    files: Vec<ExportFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFile {
    name: String,
    sha256: String,
}

pub async fn run_import_job(
    database: DbHandle,
    dir_name: String,
    item_name: String,
    encrypted_path: impl AsRef<Path>,
) -> Result<(), ImportJobError> {
    let private_key = database
        .age_private_identity()
        .await
        .map_err(ImportJobError::from_db)?;
    let zip_bytes = decrypt_export(encrypted_path.as_ref(), &private_key)?;
    let mut archive = ZipArchive::new(Cursor::new(zip_bytes.as_slice()))
        .map_err(|_| ImportJobError::bad_archive("export is not a valid zip archive"))?;
    let entry_names = archive_entry_names(&mut archive)?;
    validate_file_entry_names(&entry_names)?;
    let export = read_fields(&mut archive)?;
    let _ = export.name;

    let mut request = CreateItemRequest {
        fields: export
            .fields
            .into_iter()
            .map(|field| CreateField {
                name: field.name,
                field_type: field.field_type,
                concealed: Some(field.concealed),
                data: field.data,
            })
            .collect(),
        files: Vec::new(),
    };

    for file in export.files {
        validate_sha256_hex(&file.sha256)?;
        let entry_name = format!("files/{}", file.sha256);
        if !entry_names.contains(&entry_name) {
            return Err(ImportJobError::bad_archive(format!(
                "missing file entry {entry_name}"
            )));
        }
        let bytes = read_zip_entry(&mut archive, &entry_name)?;
        let actual = format!("{:x}", Sha256::digest(bytes.as_slice()));
        if actual != file.sha256 {
            return Err(ImportJobError::bad_archive(format!(
                "checksum mismatch for {entry_name}"
            )));
        }
        let id = database
            .create_file_from_bytes(bytes)
            .await
            .map_err(ImportJobError::from_db)?;
        request.files.push(FileInput {
            name: file.name,
            id,
        });
    }

    database
        .create_item(dir_name, item_name, request, None)
        .await
        .map_err(ImportJobError::from_db)
}

fn decrypt_export(path: &Path, private_key: &str) -> Result<Zeroizing<Vec<u8>>, ImportJobError> {
    let identity = age::x25519::Identity::from_str(private_key)
        .map_err(|_| ImportJobError::decrypt_failed())?;
    let input = File::open(path).map_err(|_| ImportJobError::decrypt_failed())?;
    let decryptor = age::Decryptor::new(input).map_err(|_| ImportJobError::decrypt_failed())?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| ImportJobError::decrypt_failed())?;
    let mut output = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut output)
        .map_err(|_| ImportJobError::decrypt_failed())?;
    Ok(output)
}

fn archive_entry_names(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
) -> Result<HashSet<String>, ImportJobError> {
    let mut names = HashSet::new();
    for index in 0..archive.len() {
        let entry = archive
            .by_index(index)
            .map_err(|_| ImportJobError::bad_archive("failed to read zip entry"))?;
        names.insert(entry.name().to_owned());
    }
    Ok(names)
}

fn validate_file_entry_names(names: &HashSet<String>) -> Result<(), ImportJobError> {
    for name in names {
        if let Some(sha256) = name.strip_prefix("files/") {
            validate_sha256_hex(sha256)?;
        }
    }
    Ok(())
}

fn read_fields(archive: &mut ZipArchive<Cursor<&[u8]>>) -> Result<ExportItem, ImportJobError> {
    let bytes = read_zip_entry(archive, "fields.json")?;
    serde_json::from_slice(bytes.as_slice())
        .map_err(|_| ImportJobError::bad_archive("fields.json is malformed"))
}

fn read_zip_entry(
    archive: &mut ZipArchive<Cursor<&[u8]>>,
    name: &str,
) -> Result<Zeroizing<Vec<u8>>, ImportJobError> {
    let mut entry = archive
        .by_name(name)
        .map_err(|_| ImportJobError::bad_archive(format!("missing zip entry {name}")))?;
    let mut bytes = Zeroizing::new(Vec::new());
    entry
        .read_to_end(&mut bytes)
        .map_err(|_| ImportJobError::bad_archive(format!("failed to read zip entry {name}")))?;
    Ok(bytes)
}

fn validate_sha256_hex(value: &str) -> Result<(), ImportJobError> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(ImportJobError::bad_archive(
            "sha256 must be 64 lowercase hex characters",
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use super::*;

    #[test]
    fn missing_fields_json_is_rejected() {
        let zip = zip_with_entries([(
            "files/2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
            b"hello".as_slice(),
        )]);
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();

        let error = read_fields(&mut archive).unwrap_err();

        assert_eq!("bad_archive", error.code);
    }

    #[test]
    fn malformed_fields_json_is_rejected() {
        let zip = zip_with_entries([("fields.json", b"not json".as_slice())]);
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();

        let error = read_fields(&mut archive).unwrap_err();

        assert_eq!("fields.json is malformed", error.message);
    }

    #[test]
    fn invalid_file_sha_name_is_rejected() {
        let zip = zip_with_entries([("files/not-sha", b"hello".as_slice())]);
        let mut archive = ZipArchive::new(Cursor::new(zip.as_slice())).unwrap();
        let names = archive_entry_names(&mut archive).unwrap();

        let error = validate_file_entry_names(&names).unwrap_err();

        assert_eq!("bad_archive", error.code);
    }

    #[test]
    fn invalid_age_payload_is_rejected() {
        let path = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(path.path(), b"not age").unwrap();

        let error = decrypt_export(path.path(), "AGE-SECRET-KEY-invalid").unwrap_err();

        assert_eq!("decrypt_failed", error.code);
    }

    fn zip_with_entries<const N: usize>(entries: [(&str, &[u8]); N]) -> Zeroizing<Vec<u8>> {
        let mut output = Cursor::new(Vec::new());
        let mut zip = ZipWriter::new(&mut output);
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        for (name, bytes) in entries {
            zip.start_file(name, options).unwrap();
            zip.write_all(bytes).unwrap();
        }
        zip.finish().unwrap();
        Zeroizing::new(output.into_inner())
    }
}
