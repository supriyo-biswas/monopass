use std::collections::HashSet;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use flate2::bufread::MultiGzDecoder;
use serde::Deserialize;
use tar::{Archive, EntryType};
use tokio::runtime::Handle;
use zeroize::Zeroizing;

use super::models::{CreateField, CreateItemRequest, FieldType, FileInput};
use super::state::{
    CreatedFile, DbError, DbHandle, FILE_RECORD_PLAINTEXT_BYTES, MAX_FILE_UPLOAD_BYTES,
};
use crate::secret::SecretString;

const EXPORT_FORMAT: &str = "monopass-export";
const EXPORT_VERSION: u64 = 1;
const MANIFEST_PATH: &[u8] = b"manifest.json";
const MAX_MANIFEST_BYTES: u64 = 16 * 1024 * 1024;
const TAR_BLOCK_BYTES: usize = 512;

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

    fn internal() -> Self {
        Self {
            code: "internal_error".to_owned(),
            message: "internal error".to_owned(),
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
            DbError::Internal => Self::internal(),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportManifest {
    format: String,
    version: u64,
    name: String,
    fields: Vec<ExportField>,
    files: Vec<ExportFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportField {
    name: String,
    #[serde(rename = "type")]
    field_type: FieldType,
    concealed: bool,
    data: SecretString,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExportFile {
    name: String,
    sha256: String,
    size: u64,
}

struct ParsedImport {
    request: CreateItemRequest,
    newly_created_ids: Vec<String>,
}

struct ParseFailure {
    error: ImportJobError,
    newly_created_ids: Vec<String>,
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
    let encrypted_path = encrypted_path.as_ref().to_owned();
    let parser_database = database.clone();
    let runtime = Handle::current();
    let parsed = tokio::task::spawn_blocking(move || {
        parse_export(
            &parser_database,
            &runtime,
            &encrypted_path,
            private_key.as_str(),
        )
    })
    .await
    .map_err(|_| ImportJobError::internal())?;

    let parsed = match parsed {
        Ok(parsed) => parsed,
        Err(failure) => {
            cleanup_new_files(&database, &failure.newly_created_ids).await;
            return Err(failure.error);
        }
    };

    let result = database
        .create_item(dir_name, item_name, parsed.request, None)
        .await
        .map_err(ImportJobError::from_db);
    if result.is_err() {
        cleanup_new_files(&database, &parsed.newly_created_ids).await;
    }
    result
}

async fn cleanup_new_files(database: &DbHandle, ids: &[String]) {
    for id in ids {
        let _ = database.delete_unattached_file(id.clone()).await;
    }
}

fn parse_export(
    database: &DbHandle,
    runtime: &Handle,
    encrypted_path: &Path,
    private_key: &str,
) -> Result<ParsedImport, ParseFailure> {
    let mut newly_created_ids = Vec::new();
    let result = (|| -> Result<CreateItemRequest, ImportJobError> {
        let identity = age::x25519::Identity::from_str(private_key)
            .map_err(|_| ImportJobError::decrypt_failed())?;
        let input = File::open(encrypted_path).map_err(|_| ImportJobError::decrypt_failed())?;
        let decryptor = age::Decryptor::new(input).map_err(|_| ImportJobError::decrypt_failed())?;
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .map_err(|_| ImportJobError::decrypt_failed())?;
        let age_failed = Arc::new(AtomicBool::new(false));
        let tracked = TrackingReader::new(reader, age_failed.clone());
        let gzip = MultiGzDecoder::new(BufReader::new(tracked));
        let mut archive = Archive::new(gzip);

        let mut request = {
            let mut entries = archive
                .entries()
                .map_err(|_| archive_read_error(&age_failed, "invalid tar archive"))?
                .raw(true);
            let mut manifest_entry = entries
                .next()
                .ok_or_else(|| ImportJobError::bad_archive("manifest.json must be first"))?
                .map_err(|_| archive_read_error(&age_failed, "failed to read manifest entry"))?;
            validate_regular_entry(
                &manifest_entry,
                MANIFEST_PATH,
                None,
                "manifest.json must be the first regular entry",
            )?;
            if manifest_entry.size() > MAX_MANIFEST_BYTES {
                return Err(ImportJobError::bad_archive("manifest.json exceeds 16 MiB"));
            }
            let manifest_capacity = usize::try_from(manifest_entry.size())
                .map_err(|_| ImportJobError::bad_archive("manifest.json is too large"))?;
            let mut manifest_bytes = Zeroizing::new(Vec::with_capacity(manifest_capacity));
            manifest_entry
                .read_to_end(&mut manifest_bytes)
                .map_err(|_| archive_read_error(&age_failed, "failed to read manifest.json"))?;
            if manifest_bytes.len() != manifest_capacity {
                return Err(ImportJobError::bad_archive(
                    "manifest.json ended before its declared size",
                ));
            }
            drop(manifest_entry);

            let manifest: ExportManifest = serde_json::from_slice(&manifest_bytes)
                .map_err(|_| ImportJobError::bad_archive("manifest.json is malformed"))?;
            validate_manifest(&manifest)?;
            let ExportManifest {
                format: _,
                version: _,
                name,
                fields,
                files,
            } = manifest;
            let _ = name;
            let mut request = CreateItemRequest {
                fields: fields
                    .into_iter()
                    .map(|field| CreateField {
                        name: field.name,
                        field_type: field.field_type,
                        concealed: Some(field.concealed),
                        data: field.data,
                    })
                    .collect(),
                files: Vec::with_capacity(files.len()),
            };

            for file in files {
                let expected_path = format!("files/{}", file.sha256);
                let mut entry = entries
                    .next()
                    .ok_or_else(|| {
                        ImportJobError::bad_archive(format!("missing file entry {expected_path}"))
                    })?
                    .map_err(|_| {
                        archive_read_error(
                            &age_failed,
                            format!("failed to read file entry {expected_path}"),
                        )
                    })?;
                validate_regular_entry(
                    &entry,
                    expected_path.as_bytes(),
                    Some(file.size),
                    "file entry has an invalid path, type, or size",
                )?;
                let created = stream_file_to_database(
                    database,
                    runtime,
                    &mut entry,
                    file.size,
                    file.sha256.clone(),
                )
                .map_err(|error| match error {
                    StreamFileError::Archive => {
                        archive_read_error(&age_failed, "failed to read file entry")
                    }
                    StreamFileError::Database(DbError::BadRequest(message)) => {
                        ImportJobError::bad_archive(message)
                    }
                    StreamFileError::Database(error) => ImportJobError::from_db(error),
                })?;
                drop(entry);
                if created.newly_created {
                    newly_created_ids.push(created.id.clone());
                }
                request.files.push(FileInput {
                    name: file.name,
                    id: created.id,
                });
            }

            match entries.next() {
                Some(Ok(_)) => {
                    return Err(ImportJobError::bad_archive(
                        "archive contains unexpected extra entries",
                    ));
                }
                Some(Err(_)) => {
                    return Err(archive_read_error(
                        &age_failed,
                        "failed to read archive terminator",
                    ));
                }
                None => {}
            }
            request
        };

        let mut gzip = archive.into_inner();
        validate_tar_terminator_and_finish(&mut gzip, &age_failed)?;
        Ok(std::mem::take(&mut request))
    })();

    match result {
        Ok(request) => Ok(ParsedImport {
            request,
            newly_created_ids,
        }),
        Err(error) => Err(ParseFailure {
            error,
            newly_created_ids,
        }),
    }
}

fn validate_manifest(manifest: &ExportManifest) -> Result<(), ImportJobError> {
    if manifest.format != EXPORT_FORMAT {
        return Err(ImportJobError::bad_archive("unsupported export format"));
    }
    if manifest.version != EXPORT_VERSION {
        return Err(ImportJobError::bad_archive("unsupported export version"));
    }

    let mut names = HashSet::new();
    for field in &manifest.fields {
        if !names.insert(field.name.as_str()) {
            return Err(ImportJobError::bad_archive(format!(
                "duplicate manifest entry name `{}`",
                field.name
            )));
        }
    }
    let mut hashes = HashSet::new();
    for file in &manifest.files {
        if !names.insert(file.name.as_str()) {
            return Err(ImportJobError::bad_archive(format!(
                "duplicate manifest entry name `{}`",
                file.name
            )));
        }
        if !hashes.insert(file.sha256.as_str()) {
            return Err(ImportJobError::bad_archive(format!(
                "duplicate file checksum `{}`",
                file.sha256
            )));
        }
        validate_sha256_hex(&file.sha256)?;
        if file.size > MAX_FILE_UPLOAD_BYTES {
            return Err(ImportJobError::bad_archive("file is too large"));
        }
    }
    Ok(())
}

fn validate_regular_entry<R: Read>(
    entry: &tar::Entry<'_, R>,
    expected_path: &[u8],
    expected_size: Option<u64>,
    message: &str,
) -> Result<(), ImportJobError> {
    let entry_type = entry.header().entry_type();
    let is_regular = entry_type == EntryType::Regular || entry_type == EntryType::new(b'\0');
    if !is_regular
        || entry.path_bytes().as_ref() != expected_path
        || expected_size.is_some_and(|size| entry.size() != size)
    {
        return Err(ImportJobError::bad_archive(message));
    }
    Ok(())
}

enum StreamFileError {
    Archive,
    Database(DbError),
}

fn stream_file_to_database<R: Read>(
    database: &DbHandle,
    runtime: &Handle,
    entry: &mut R,
    expected_size: u64,
    expected_sha256: String,
) -> Result<CreatedFile, StreamFileError> {
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let database = database.clone();
    let task = runtime.spawn(async move {
        database
            .create_file_from_chunks_validated(receiver, expected_size, Some(expected_sha256))
            .await
    });
    let mut buffer = Zeroizing::new(vec![0; FILE_RECORD_PLAINTEXT_BYTES]);
    let mut size = 0_u64;
    let read_result = (|| -> io::Result<()> {
        loop {
            let count = entry.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(count).map_err(io::Error::other)?)
                .ok_or_else(|| io::Error::other("file size overflow"))?;
            sender
                .blocking_send(Zeroizing::new(buffer[..count].to_vec()))
                .map_err(|_| io::Error::other("database file receiver closed"))?;
        }
        Ok(())
    })();
    drop(sender);
    let database_result = runtime
        .block_on(task)
        .map_err(|_| StreamFileError::Database(DbError::Internal))?;
    if read_result.is_err() || size != expected_size {
        return Err(StreamFileError::Archive);
    }
    database_result.map_err(StreamFileError::Database)
}

fn validate_tar_terminator_and_finish<R: std::io::BufRead>(
    gzip: &mut MultiGzDecoder<R>,
    age_failed: &AtomicBool,
) -> Result<(), ImportJobError> {
    let mut buffer = Zeroizing::new(vec![0; FILE_RECORD_PLAINTEXT_BYTES]);
    let mut count = 0_usize;
    let mut exact_zero_terminator = true;
    loop {
        let read = gzip
            .read(&mut buffer)
            .map_err(|_| archive_read_error(age_failed, "invalid gzip payload"))?;
        if read == 0 {
            break;
        }
        if count >= TAR_BLOCK_BYTES
            || read > TAR_BLOCK_BYTES.saturating_sub(count)
            || buffer[..read].iter().any(|byte| *byte != 0)
        {
            exact_zero_terminator = false;
        }
        count = count.saturating_add(read);
    }
    if !exact_zero_terminator || count != TAR_BLOCK_BYTES {
        return Err(ImportJobError::bad_archive(
            "archive has an invalid tar terminator or trailing data",
        ));
    }
    Ok(())
}

fn archive_read_error(age_failed: &AtomicBool, message: impl Into<String>) -> ImportJobError {
    if age_failed.load(Ordering::Relaxed) {
        ImportJobError::decrypt_failed()
    } else {
        ImportJobError::bad_archive(message)
    }
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

struct TrackingReader<R> {
    inner: R,
    failed: Arc<AtomicBool>,
}

impl<R> TrackingReader<R> {
    fn new(inner: R, failed: Arc<AtomicBool>) -> Self {
        Self { inner, failed }
    }
}

impl<R: Read> Read for TrackingReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buffer).inspect_err(|_| {
            self.failed.store(true, Ordering::Relaxed);
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Seek, Write};

    use flate2::Compression;
    use flate2::write::GzEncoder;
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use tar::{Builder, EntryType, Header};

    use super::*;

    #[test]
    fn malformed_and_unknown_manifests_are_rejected() {
        let unknown_version: ExportManifest = serde_json::from_value(json!({
            "format": "monopass-export",
            "version": 2,
            "name": "source",
            "fields": [],
            "files": []
        }))
        .unwrap();
        assert_eq!(
            "bad_archive",
            validate_manifest(&unknown_version).unwrap_err().code
        );

        let duplicate: ExportManifest = serde_json::from_value(json!({
            "format": "monopass-export",
            "version": 1,
            "name": "source",
            "fields": [
                {"name": "same", "type": "string", "concealed": false, "data": "x"}
            ],
            "files": [
                {"name": "same", "sha256": "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824", "size": 5}
            ]
        }))
        .unwrap();
        assert_eq!(
            "bad_archive",
            validate_manifest(&duplicate).unwrap_err().code
        );

        for (sha256, size) in [
            ("ABC".to_owned(), 1),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
                MAX_FILE_UPLOAD_BYTES + 1,
            ),
        ] {
            let invalid: ExportManifest = serde_json::from_value(json!({
                "format": "monopass-export",
                "version": 1,
                "name": "source",
                "fields": [],
                "files": [
                    {"name": "file", "sha256": sha256, "size": size}
                ]
            }))
            .unwrap();
            assert_eq!("bad_archive", validate_manifest(&invalid).unwrap_err().code);
        }
    }

    #[tokio::test]
    async fn import_round_trip_streams_large_incompressible_file() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let mut bytes = vec![0_u8; 2 * 1024 * 1024 + 19];
        getrandom::fill(&mut bytes).unwrap();
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let manifest = serde_json::to_vec(&json!({
            "format": "monopass-export",
            "version": 1,
            "name": "source-name",
            "fields": [
                {"name": "password", "type": "string", "concealed": true, "data": "secret"}
            ],
            "files": [
                {"name": "random.bin", "sha256": sha256, "size": bytes.len()}
            ]
        }))
        .unwrap();
        let export = encrypted_export(
            &database,
            vec![
                ("manifest.json".to_owned(), manifest, EntryType::Regular),
                (format!("files/{sha256}"), bytes.clone(), EntryType::Regular),
            ],
        )
        .await;

        run_import_job(
            database.clone(),
            "Imported".to_owned(),
            "target-name".to_owned(),
            export.path(),
        )
        .await
        .unwrap();

        let item = database
            .get_item(
                "Imported".to_owned(),
                "target-name".to_owned(),
                None,
                true,
                true,
                true,
            )
            .await
            .unwrap();
        assert_eq!("target-name", item.name);
        assert_eq!("secret", item.fields[0].data.as_str());
        assert_eq!(bytes.len() as u64, item.files[0].size);
        let response = database
            .get_reference(
                "Imported".to_owned(),
                "target-name".to_owned(),
                "random.bin".to_owned(),
                None,
                true,
                true,
            )
            .await
            .unwrap();
        let mut actual = Vec::new();
        match response.body {
            super::super::state::ReferenceBody::Stream(mut chunks) => {
                while let Some(chunk) = chunks.recv().await {
                    actual.extend_from_slice(&chunk.unwrap());
                }
            }
            super::super::state::ReferenceBody::Bytes(bytes) => actual.extend_from_slice(&bytes),
        }
        assert_eq!(bytes, actual);
    }

    #[tokio::test]
    async fn age_encrypted_legacy_zip_signature_fails_as_bad_archive() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let export = encrypt_plaintext(&database, b"PK\x03\x04legacy zip bytes").await;

        let error = run_import_job(
            database,
            "Imported".to_owned(),
            "legacy".to_owned(),
            export.path(),
        )
        .await
        .unwrap_err();

        assert_eq!("bad_archive", error.code);
    }

    #[tokio::test]
    async fn failed_import_deletes_only_newly_created_blobs() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let deduplicated = b"already stored".to_vec();
        let deduplicated_id = database.create_file(deduplicated.clone()).await.unwrap();
        let new_bytes = b"new import bytes".to_vec();
        let new_sha256 = format!("{:x}", Sha256::digest(&new_bytes));
        let deduplicated_sha256 = format!("{:x}", Sha256::digest(&deduplicated));
        let manifest = serde_json::to_vec(&json!({
            "format": "monopass-export",
            "version": 1,
            "name": "source",
            "fields": [],
            "files": [
                {"name": "new.bin", "sha256": new_sha256, "size": new_bytes.len()},
                {"name": "existing.bin", "sha256": deduplicated_sha256, "size": deduplicated.len()}
            ]
        }))
        .unwrap();
        let export = encrypted_export(
            &database,
            vec![
                ("manifest.json".to_owned(), manifest, EntryType::Regular),
                (format!("files/{new_sha256}"), new_bytes, EntryType::Regular),
                (
                    format!("files/{deduplicated_sha256}"),
                    deduplicated,
                    EntryType::Regular,
                ),
                (
                    "unexpected".to_owned(),
                    b"extra".to_vec(),
                    EntryType::Regular,
                ),
            ],
        )
        .await;

        let error = run_import_job(
            database.clone(),
            "Imported".to_owned(),
            "failed".to_owned(),
            export.path(),
        )
        .await
        .unwrap_err();

        assert_eq!("bad_archive", error.code);
        assert!(database.lookup_file_by_sha256(new_sha256).await.is_err());
        assert_eq!(
            deduplicated_id,
            database
                .lookup_file_by_sha256(deduplicated_sha256)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn item_create_failure_removes_new_import_blobs() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        database
            .create_item(
                "Imported".to_owned(),
                "existing".to_owned(),
                CreateItemRequest::default(),
                None,
            )
            .await
            .unwrap();
        let bytes = b"new attachment".to_vec();
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let export = encrypted_export(
            &database,
            vec![
                (
                    "manifest.json".to_owned(),
                    serde_json::to_vec(&json!({
                        "format": "monopass-export",
                        "version": 1,
                        "name": "source",
                        "fields": [],
                        "files": [
                            {"name": "attachment", "sha256": sha256, "size": bytes.len()}
                        ]
                    }))
                    .unwrap(),
                    EntryType::Regular,
                ),
                (format!("files/{sha256}"), bytes, EntryType::Regular),
            ],
        )
        .await;

        let error = run_import_job(
            database.clone(),
            "Imported".to_owned(),
            "existing".to_owned(),
            export.path(),
        )
        .await
        .unwrap_err();

        assert_eq!("conflict", error.code);
        assert!(database.lookup_file_by_sha256(sha256).await.is_err());
    }

    #[tokio::test]
    async fn corrupted_age_authentication_fails_closed() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let mut export = encrypted_export(
            &database,
            vec![(
                "manifest.json".to_owned(),
                serde_json::to_vec(&json!({
                    "format": "monopass-export",
                    "version": 1,
                    "name": "source",
                    "fields": [],
                    "files": []
                }))
                .unwrap(),
                EntryType::Regular,
            )],
        )
        .await;
        let file = export.as_file_mut();
        let length = file.metadata().unwrap().len();
        file.seek(std::io::SeekFrom::Start(length - 1)).unwrap();
        let mut last = [0_u8; 1];
        file.read_exact(&mut last).unwrap();
        last[0] ^= 0x80;
        file.seek(std::io::SeekFrom::Start(length - 1)).unwrap();
        file.write_all(&last).unwrap();
        file.flush().unwrap();

        let error = run_import_job(
            database,
            "Imported".to_owned(),
            "corrupt".to_owned(),
            export.path(),
        )
        .await
        .unwrap_err();

        assert_eq!("decrypt_failed", error.code);
    }

    #[tokio::test]
    async fn malformed_tar_manifest_and_file_entries_fail_closed() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let bytes = b"hello".to_vec();
        let sha256 = format!("{:x}", Sha256::digest(&bytes));
        let manifest = serde_json::to_vec(&json!({
            "format": "monopass-export",
            "version": 1,
            "name": "source",
            "fields": [],
            "files": [
                {"name": "notes", "sha256": sha256, "size": bytes.len()}
            ]
        }))
        .unwrap();
        let other_sha256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let cases = vec![
            (
                "manifest-order",
                vec![
                    (format!("files/{sha256}"), bytes.clone(), EntryType::Regular),
                    (
                        "manifest.json".to_owned(),
                        manifest.clone(),
                        EntryType::Regular,
                    ),
                ],
            ),
            (
                "manifest-type",
                vec![(
                    "manifest.json".to_owned(),
                    manifest.clone(),
                    EntryType::Directory,
                )],
            ),
            (
                "file-path",
                vec![
                    (
                        "manifest.json".to_owned(),
                        manifest.clone(),
                        EntryType::Regular,
                    ),
                    (
                        format!("files/{other_sha256}"),
                        bytes.clone(),
                        EntryType::Regular,
                    ),
                ],
            ),
            (
                "file-size",
                vec![
                    (
                        "manifest.json".to_owned(),
                        serde_json::to_vec(&json!({
                            "format": "monopass-export",
                            "version": 1,
                            "name": "source",
                            "fields": [],
                            "files": [
                                {"name": "notes", "sha256": sha256, "size": bytes.len() + 1}
                            ]
                        }))
                        .unwrap(),
                        EntryType::Regular,
                    ),
                    (format!("files/{sha256}"), bytes.clone(), EntryType::Regular),
                ],
            ),
            (
                "file-checksum",
                vec![
                    (
                        "manifest.json".to_owned(),
                        manifest.clone(),
                        EntryType::Regular,
                    ),
                    (
                        format!("files/{sha256}"),
                        b"jello".to_vec(),
                        EntryType::Regular,
                    ),
                ],
            ),
            (
                "missing-file",
                vec![("manifest.json".to_owned(), manifest, EntryType::Regular)],
            ),
        ];

        for (target, entries) in cases {
            let export = encrypted_export(&database, entries).await;
            let error = run_import_job(
                database.clone(),
                "Imported".to_owned(),
                target.to_owned(),
                export.path(),
            )
            .await
            .unwrap_err();
            assert_eq!("bad_archive", error.code, "{target}: {}", error.message);
        }
    }

    #[tokio::test]
    async fn unknown_manifest_fields_and_bad_gzip_checksum_are_rejected() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let unknown = encrypted_export(
            &database,
            vec![(
                "manifest.json".to_owned(),
                serde_json::to_vec(&json!({
                    "format": "monopass-export",
                    "version": 1,
                    "name": "source",
                    "fields": [],
                    "files": [],
                    "unknown": true
                }))
                .unwrap(),
                EntryType::Regular,
            )],
        )
        .await;
        assert_eq!(
            "bad_archive",
            run_import_job(
                database.clone(),
                "Imported".to_owned(),
                "unknown".to_owned(),
                unknown.path(),
            )
            .await
            .unwrap_err()
            .code
        );

        let mut gzip = gzip_entries(vec![(
            "manifest.json".to_owned(),
            serde_json::to_vec(&json!({
                "format": "monopass-export",
                "version": 1,
                "name": "source",
                "fields": [],
                "files": []
            }))
            .unwrap(),
            EntryType::Regular,
        )]);
        let last = gzip.last_mut().unwrap();
        *last ^= 0x80;
        let corrupted_gzip = encrypt_plaintext(&database, &gzip).await;
        assert_eq!(
            "bad_archive",
            run_import_job(
                database,
                "Imported".to_owned(),
                "gzip".to_owned(),
                corrupted_gzip.path(),
            )
            .await
            .unwrap_err()
            .code
        );
    }

    #[tokio::test]
    async fn manifest_over_16_mib_is_rejected_before_deserialization() {
        let database = DbHandle::test();
        database.create_dir("Imported".to_owned()).await.unwrap();
        let export = encrypted_export(
            &database,
            vec![(
                "manifest.json".to_owned(),
                vec![b' '; MAX_MANIFEST_BYTES as usize + 1],
                EntryType::Regular,
            )],
        )
        .await;

        let error = run_import_job(
            database,
            "Imported".to_owned(),
            "oversized".to_owned(),
            export.path(),
        )
        .await
        .unwrap_err();

        assert_eq!("bad_archive", error.code);
        assert!(error.message.contains("16 MiB"));
    }

    async fn encrypted_export(
        database: &DbHandle,
        entries: Vec<(String, Vec<u8>, EntryType)>,
    ) -> tempfile::NamedTempFile {
        let gzip = gzip_entries(entries);
        encrypt_plaintext(database, &gzip).await
    }

    fn gzip_entries(entries: Vec<(String, Vec<u8>, EntryType)>) -> Vec<u8> {
        let mut tar = Builder::new(Vec::new());
        for (path, bytes, entry_type) in entries {
            let mut header = Header::new_gnu();
            header.set_entry_type(entry_type);
            header.set_mode(0o600);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            tar.append_data(&mut header, path, bytes.as_slice())
                .unwrap();
        }
        tar.finish().unwrap();
        let tar = tar.into_inner().unwrap();
        let mut gzip = GzEncoder::new(Vec::new(), Compression::default());
        gzip.write_all(&tar).unwrap();
        gzip.finish().unwrap()
    }

    async fn encrypt_plaintext(database: &DbHandle, plaintext: &[u8]) -> tempfile::NamedTempFile {
        let identity_text = database.age_private_identity().await.unwrap();
        let identity = age::x25519::Identity::from_str(identity_text.as_str()).unwrap();
        let recipient = identity.to_public();
        let recipients: [&dyn age::Recipient; 1] = [&recipient];
        let encryptor = age::Encryptor::with_recipients(recipients.into_iter()).unwrap();
        let mut output = tempfile::NamedTempFile::new().unwrap();
        {
            let mut writer = encryptor.wrap_output(&mut output).unwrap();
            writer.write_all(plaintext).unwrap();
            writer.finish().unwrap();
        }
        output.flush().unwrap();
        output
    }
}
