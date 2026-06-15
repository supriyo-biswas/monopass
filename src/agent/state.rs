use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use base64::engine::general_purpose;
use chrono::{DateTime, SecondsFormat, Utc};
use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rusqlite::{Connection, OptionalExtension};
use sha1::Sha1;
use sha2::Digest;
use sha2::{Sha256, Sha512};
use tokio::sync::{Mutex, mpsc, oneshot};
use url::Url;
use zeroize::{Zeroize, Zeroizing};

use super::models::{
    ContactResponse, CreateContactRequest, CreateField, CreateItemRequest, DirResponse, Field,
    FieldEntry, FieldType, FileInput, FileMetadata, FileMetadataEntry, ItemResponse,
    ItemSummaryResponse, ItemVersionSummaryResponse, JobErrorResponse, JobResponse, JobStatus,
    JobTarget, JobType, PaginatedResponse, UpdateContactRequest, UpdateDirRequest,
    UpdateFieldEntry, UpdateFileEntry, UpdateItemRequest,
};
use super::process::ProcessChainHash;
use crate::conceal::inferred_concealed;
use crate::config::Config;
use crate::db;
use crate::settings::{AUTH_TTL_SETTING, GC_SECONDS_SETTING, SettingsError, user_setting};

const AUTH_CACHE_CAPACITY: usize = 32;
const AUTH_EXPIRY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);
pub(crate) const DATABASE_READER_WORKERS: usize = 8;
const ITEM_VERSION_RETENTION: Duration = Duration::from_secs(90 * 24 * 60 * 60);
const FILE_ORPHAN_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);
const FILE_ID_BYTES: usize = 16;
const FILE_KEY_BYTES: usize = 32;
const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;
const AES_GCM_NONCE_BYTES: usize = 12;
const FILE_NONCE_PREFIX_BYTES: usize = 8;
const AES_GCM_TAG_BYTES: usize = 16;
pub(crate) const FILE_RECORD_PLAINTEXT_BYTES: usize = 8 * 1024;
pub(crate) const MAX_FILE_RECORDS: u64 = u32::MAX as u64;
pub(crate) const MAX_FILE_UPLOAD_BYTES: u64 = MAX_FILE_RECORDS * FILE_RECORD_PLAINTEXT_BYTES as u64;
const PAGE_MARKER_VERSION: u8 = 1;
const PASSWORD_ITERATIONS: u32 = 5_000;
const INTERNAL_DIR_NAME: &str = "_Internal";
const FILE_ENCRYPTION_KEY_ITEM_NAME: &str = "FileEncryptionKey";
#[cfg(test)]
const AGE_PUBLIC_KEY_ITEM_NAME: &str = "AgePublicKey";
const AGE_PRIVATE_KEY_ITEM_NAME: &str = "AgePrivateKey";
const DIR_HIDDEN: i64 = 1 << 0;
const DIR_SYSTEM: i64 = 1 << 1;
const ITEM_HIDDEN: i64 = 1 << 0;
pub(crate) const ITEM_READ_MUSTAUTH: i64 = 1 << 1;

#[derive(Debug, Clone)]
pub struct AgentState {
    database_path: PathBuf,
    file_store_path: PathBuf,
    job_store_path: PathBuf,
    inner: Arc<Mutex<InnerState>>,
    active_database_requests: Arc<AtomicUsize>,
}

impl AgentState {
    pub fn new(config: &Config) -> Self {
        Self::from_paths(
            config.database_path(),
            config.file_store_path(),
            config.job_store_path(),
        )
    }

    #[cfg(test)]
    pub fn from_database_path(database_path: impl AsRef<Path>) -> Self {
        let database_path = database_path.as_ref();
        Self::from_paths(
            database_path,
            database_path.with_extension("files"),
            database_path.with_extension("jobs"),
        )
    }

    pub fn from_paths(
        database_path: impl AsRef<Path>,
        file_store_path: impl AsRef<Path>,
        job_store_path: impl AsRef<Path>,
    ) -> Self {
        Self {
            database_path: database_path.as_ref().to_owned(),
            file_store_path: file_store_path.as_ref().to_owned(),
            job_store_path: job_store_path.as_ref().to_owned(),
            inner: Arc::new(Mutex::new(InnerState::default())),
            active_database_requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn job_store_path(&self) -> &Path {
        &self.job_store_path
    }

    pub fn spawn_auth_expiry_lock_task(&self) {
        let state = self.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(AUTH_EXPIRY_SWEEP_INTERVAL);
            loop {
                interval.tick().await;
                state.unload_if_authorization_expired(Instant::now()).await;
            }
        });
    }

    pub async fn unlock(
        &self,
        password: Zeroizing<String>,
        process_hash: ProcessChainHash,
    ) -> Result<(), UnlockError> {
        let mut inner = self.inner.lock().await;

        if let Some(verifier) = &inner.password_verifier {
            if !verifier.verify(&password) {
                return Err(UnlockError::AccessDenied);
            }
            let database = inner.database.clone().ok_or(UnlockError::AccessDenied)?;
            let auth_epoch = inner.auth_epoch;
            drop(inner);
            let auth_ttl = database
                .user_setting_duration(AUTH_TTL_SETTING)
                .await
                .map_err(|_| UnlockError::AccessDenied)?;
            let mut inner = self.inner.lock().await;
            let database_is_current = inner
                .database
                .as_ref()
                .is_some_and(|current| current.ptr_eq(&database));
            if inner.auth_epoch != auth_epoch || !database_is_current {
                return Err(UnlockError::AccessDenied);
            }
            let now = Instant::now();
            inner.authorized_processes.insert(process_hash, now);
            inner.record_authorization_expiry(now + auth_ttl);
            return Ok(());
        }

        let database_path = self.database_path.clone();
        let file_store_path = self.file_store_path.clone();
        let database_password = password.clone();
        let handle = tokio::task::spawn_blocking(move || {
            DbHandle::open_pool(
                database_path,
                file_store_path,
                &database_password,
                DATABASE_READER_WORKERS,
            )
        })
        .await
        .map_err(|_| UnlockError::UnlockFailed)?
        .map_err(|_| UnlockError::UnlockFailed)?;
        let auth_ttl = handle
            .user_setting_duration(AUTH_TTL_SETTING)
            .await
            .map_err(|_| UnlockError::AccessDenied)?;

        inner.invalidate_auth_epoch();
        inner.database = Some(handle);
        inner.password_verifier = Some(PasswordVerifier::new(&password)?);
        let now = Instant::now();
        inner.last_authorized_database_access = Some(now);
        inner.authorized_processes.insert(process_hash, now);
        inner.record_authorization_expiry(now + auth_ttl);
        Ok(())
    }

    pub async fn lock(&self, now: Instant) {
        let mut inner = self.inner.lock().await;
        inner.invalidate_auth_epoch();
        inner.authorized_processes.clear();
        inner.max_authorization_expires_at = Some(now);
    }

    #[cfg(test)]
    pub async fn is_unlocked(&self) -> bool {
        self.inner.lock().await.database.is_some()
    }

    #[cfg(test)]
    pub async fn is_authorized(&self, process_hash: &ProcessChainHash) -> bool {
        self.authorization_expires_at(process_hash).await.is_some()
    }

    pub async fn authorization_expires_at(
        &self,
        process_hash: &ProcessChainHash,
    ) -> Option<Instant> {
        let database = self.inner.lock().await.database.clone()?;
        let auth_ttl = database
            .user_setting_duration(AUTH_TTL_SETTING)
            .await
            .ok()?;

        self.inner.lock().await.authorized_processes.expires_at(
            process_hash,
            Instant::now(),
            auth_ttl,
        )
    }

    pub async fn verify_settings_password(&self, password: &str) -> bool {
        let inner = self.inner.lock().await;
        inner.database.is_some()
            && inner
                .password_verifier
                .as_ref()
                .is_some_and(|verifier| verifier.verify(password))
    }

    pub async fn authorize_database_access(
        &self,
        process_hash: &ProcessChainHash,
    ) -> Option<DbHandle> {
        let database = self.inner.lock().await.database.clone()?;
        let auth_ttl = database
            .user_setting_duration(AUTH_TTL_SETTING)
            .await
            .ok()?;

        let mut inner = self.inner.lock().await;
        let now = Instant::now();
        let database = inner.database.clone();
        let authorized = database.is_some()
            && inner
                .authorized_processes
                .contains(process_hash, now, auth_ttl);

        if authorized {
            inner.last_authorized_database_access = Some(now);
            database
        } else {
            None
        }
    }

    pub async fn unload_if_authorization_expired(&self, now: Instant) -> bool {
        let database = self.inner.lock().await.database.clone();
        let Some(database) = database else {
            return false;
        };
        let auth_ttl = database
            .user_setting_duration(AUTH_TTL_SETTING)
            .await
            .unwrap_or(Duration::ZERO);
        let gc_interval = database
            .user_setting_duration(GC_SECONDS_SETTING)
            .await
            .ok();

        let cleanup_due = {
            let mut inner = self.inner.lock().await;
            if self.has_active_database_work_locked(&inner) {
                return false;
            }
            inner.authorized_processes.retain_unexpired(now, auth_ttl);
            inner.max_authorization_expires_at =
                inner.authorized_processes.max_expires_at(auth_ttl);
            let should_unload =
                inner.database.is_some() && inner.max_authorization_expires_at.is_none();

            if should_unload {
                gc_interval.is_some_and(|gc_interval| {
                    inner
                        .last_cleanup_at
                        .is_none_or(|last_cleanup| now.duration_since(last_cleanup) >= gc_interval)
                })
            } else {
                false
            }
        };

        if cleanup_due {
            let version_cutoff = now.checked_sub(ITEM_VERSION_RETENTION).unwrap_or(now);
            let file_cutoff = now.checked_sub(FILE_ORPHAN_RETENTION).unwrap_or(now);
            let _ = database
                .cleanup_before_unload(version_cutoff, file_cutoff)
                .await;
        }

        let mut inner = self.inner.lock().await;
        let should_unload = inner.database.as_ref().is_some_and(|current| {
            current.ptr_eq(&database)
                && inner.max_authorization_expires_at.is_none()
                && !self.has_active_database_work_locked(&inner)
        });

        if cleanup_due {
            inner.last_cleanup_at = Some(now);
        }

        if should_unload {
            Self::unload_locked(&mut inner);
        }

        should_unload
    }

    fn unload_locked(inner: &mut InnerState) {
        inner.invalidate_auth_epoch();
        inner.database = None;
        inner.password_verifier = None;
        inner.authorized_processes.clear();
        inner.last_authorized_database_access = None;
        inner.max_authorization_expires_at = None;
    }

    #[cfg(test)]
    pub async fn database_handle(&self) -> Option<DbHandle> {
        self.inner.lock().await.database.clone()
    }

    #[cfg(test)]
    pub async fn store_database_handle(&self, handle: DbHandle) {
        let mut inner = self.inner.lock().await;
        inner.invalidate_auth_epoch();
        inner.database = Some(handle);
        inner.last_authorized_database_access = Some(Instant::now());
    }

    #[cfg(test)]
    pub async fn store_password_verifier(&self, password: &str) {
        self.inner.lock().await.password_verifier = Some(PasswordVerifier::new(password).unwrap());
    }

    #[cfg(test)]
    pub async fn authorize_process_hash(&self, process_hash: ProcessChainHash) {
        self.inner
            .lock()
            .await
            .authorized_processes
            .insert(process_hash, Instant::now());
    }

    #[cfg(test)]
    pub async fn authorize_process_hash_at(&self, process_hash: ProcessChainHash, now: Instant) {
        self.inner
            .lock()
            .await
            .authorized_processes
            .insert(process_hash, now);
    }

    #[cfg(test)]
    pub async fn has_password_verifier(&self) -> bool {
        self.inner.lock().await.password_verifier.is_some()
    }

    #[cfg(test)]
    pub async fn last_authorized_database_access(&self) -> Option<Instant> {
        self.inner.lock().await.last_authorized_database_access
    }

    #[cfg(test)]
    pub async fn set_last_authorized_database_access(
        &self,
        last_authorized_database_access: Option<Instant>,
    ) {
        self.inner.lock().await.last_authorized_database_access = last_authorized_database_access;
    }

    #[cfg(test)]
    pub async fn max_authorization_expires_at(&self) -> Option<Instant> {
        self.inner.lock().await.max_authorization_expires_at
    }

    #[cfg(test)]
    pub async fn set_max_authorization_expires_at(&self, expires_at: Option<Instant>) {
        self.inner.lock().await.max_authorization_expires_at = expires_at;
    }

    #[cfg(test)]
    pub async fn set_last_cleanup_at(&self, last_cleanup_at: Option<Instant>) {
        self.inner.lock().await.last_cleanup_at = last_cleanup_at;
    }

    pub async fn register_active_job(&self, job_id: String) {
        self.inner.lock().await.active_jobs.insert(job_id);
    }

    pub async fn unregister_active_job(&self, job_id: &str) {
        self.inner.lock().await.active_jobs.remove(job_id);
    }

    pub fn begin_active_database_request(&self) -> ActiveDatabaseRequest {
        self.active_database_requests
            .fetch_add(1, Ordering::Relaxed);
        ActiveDatabaseRequest {
            active_database_requests: self.active_database_requests.clone(),
        }
    }

    fn has_active_database_work_locked(&self, inner: &InnerState) -> bool {
        !inner.active_jobs.is_empty() || self.active_database_requests.load(Ordering::Relaxed) > 0
    }

    #[cfg(test)]
    pub async fn active_job_count(&self) -> usize {
        self.inner.lock().await.active_jobs.len()
    }

    #[cfg(test)]
    pub fn active_database_request_count(&self) -> usize {
        self.active_database_requests.load(Ordering::Relaxed)
    }
}

#[derive(Debug)]
pub struct ActiveDatabaseRequest {
    active_database_requests: Arc<AtomicUsize>,
}

impl Drop for ActiveDatabaseRequest {
    fn drop(&mut self) {
        self.active_database_requests
            .fetch_sub(1, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnlockError {
    AccessDenied,
    UnlockFailed,
}

#[derive(Debug, Default)]
struct InnerState {
    database: Option<DbHandle>,
    password_verifier: Option<PasswordVerifier>,
    authorized_processes: AuthCache,
    last_authorized_database_access: Option<Instant>,
    max_authorization_expires_at: Option<Instant>,
    last_cleanup_at: Option<Instant>,
    active_jobs: HashSet<String>,
    auth_epoch: u64,
}

impl InnerState {
    fn invalidate_auth_epoch(&mut self) {
        self.auth_epoch = self.auth_epoch.wrapping_add(1);
    }

    fn record_authorization_expiry(&mut self, expires_at: Instant) {
        self.max_authorization_expires_at = Some(
            self.max_authorization_expires_at
                .map_or(expires_at, |current| current.max(expires_at)),
        );
    }
}

#[derive(Debug)]
struct PasswordVerifier {
    salt: [u8; 16],
    hash: [u8; 32],
}

impl PasswordVerifier {
    fn new(password: &str) -> Result<Self, UnlockError> {
        let mut salt = [0u8; 16];
        getrandom::fill(&mut salt).map_err(|_| UnlockError::UnlockFailed)?;

        let mut hash = [0u8; 32];
        pbkdf2_hmac::<Sha256>(password.as_bytes(), &salt, PASSWORD_ITERATIONS, &mut hash);

        Ok(Self { salt, hash })
    }

    fn verify(&self, password: &str) -> bool {
        let mut hash = Zeroizing::new([0u8; 32]);
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            &self.salt,
            PASSWORD_ITERATIONS,
            &mut *hash,
        );
        *hash == self.hash
    }
}

impl Drop for PasswordVerifier {
    fn drop(&mut self) {
        self.salt.zeroize();
        self.hash.zeroize();
    }
}

#[derive(Debug, Default)]
struct AuthCache {
    entries: Vec<AuthCacheEntry>,
}

impl AuthCache {
    fn insert(&mut self, process_hash: ProcessChainHash, now: Instant) {
        self.entries
            .retain(|entry| entry.process_hash != process_hash);
        self.entries.push(AuthCacheEntry {
            process_hash,
            inserted_at: now,
        });

        if self.entries.len() > AUTH_CACHE_CAPACITY {
            self.entries.remove(0);
        }
    }

    fn contains(&mut self, process_hash: &ProcessChainHash, now: Instant, ttl: Duration) -> bool {
        self.retain_unexpired(now, ttl);

        let Some(index) = self
            .entries
            .iter()
            .position(|entry| &entry.process_hash == process_hash)
        else {
            return false;
        };

        let entry = self.entries.remove(index);
        self.entries.push(entry);
        true
    }

    fn expires_at(
        &self,
        process_hash: &ProcessChainHash,
        now: Instant,
        ttl: Duration,
    ) -> Option<Instant> {
        let entry = self
            .entries
            .iter()
            .find(|entry| &entry.process_hash == process_hash)?;
        let expires_at = entry.inserted_at + ttl;

        (expires_at > now).then_some(expires_at)
    }

    fn retain_unexpired(&mut self, now: Instant, ttl: Duration) {
        self.entries
            .retain(|entry| now.duration_since(entry.inserted_at) < ttl);
    }

    fn max_expires_at(&self, ttl: Duration) -> Option<Instant> {
        self.entries
            .iter()
            .map(|entry| entry.inserted_at + ttl)
            .max()
    }

    fn clear(&mut self) {
        self.entries.clear();
    }
}

#[derive(Debug)]
struct AuthCacheEntry {
    process_hash: ProcessChainHash,
    inserted_at: Instant,
}

#[derive(Debug, Clone)]
pub struct DbHandle {
    pool: Arc<DbPool>,
}

impl DbHandle {
    fn open_pool(
        database_path: impl AsRef<Path>,
        file_store_path: impl AsRef<Path>,
        password: &str,
        reader_workers: usize,
    ) -> rusqlite::Result<Self> {
        let database_path = database_path.as_ref();
        let writer = db::open_encrypted_database_with_password(database_path, password)?;
        let mut readers = Vec::with_capacity(reader_workers);
        for _ in 0..reader_workers {
            readers.push(db::open_encrypted_database_reader_with_password(
                database_path,
                password,
            )?);
        }

        Ok(Self::new(
            writer,
            readers,
            file_store_path.as_ref().to_owned(),
        ))
    }

    fn new(writer: Connection, readers: Vec<Connection>, file_store_path: PathBuf) -> Self {
        let writer = Self::spawn_worker(writer, file_store_path.clone());
        let readers = readers
            .into_iter()
            .map(|connection| Self::spawn_worker(connection, file_store_path.clone()))
            .collect();

        Self {
            pool: Arc::new(DbPool {
                writer,
                readers,
                #[cfg(test)]
                file_store_path,
                next_reader: AtomicUsize::new(0),
                #[cfg(test)]
                dispatch_counts: DispatchCounts::default(),
                #[cfg(test)]
                fail_next_cleanup_before_unload: std::sync::atomic::AtomicBool::new(false),
            }),
        }
    }

    fn spawn_worker(connection: Connection, file_store_path: PathBuf) -> DbWorker {
        let (sender, mut receiver) = mpsc::channel::<DbCommand>(32);

        tokio::task::spawn_blocking(move || {
            let mut worker = DatabaseWorker::new(connection, file_store_path);
            while let Some(command) = receiver.blocking_recv() {
                worker.handle(command);
            }
        });

        DbWorker { sender }
    }

    pub async fn create_dir(&self, name: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::CreateDir { name, reply })
            .await
    }

    pub async fn get_dir(&self, name: String) -> Result<DirResponse, DbError> {
        self.request_reader(|reply| DbCommand::GetDir { name, reply })
            .await
    }

    pub async fn list_dirs(
        &self,
        page: PageRequest,
    ) -> Result<PaginatedResponse<DirResponse>, DbError> {
        self.request_reader(|reply| DbCommand::ListDirs { page, reply })
            .await
    }

    pub async fn create_contact(
        &self,
        email: String,
        request: CreateContactRequest,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::CreateContact {
            email,
            request,
            reply,
        })
        .await
    }

    pub async fn list_contacts(
        &self,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ContactResponse>, DbError> {
        self.request_reader(|reply| DbCommand::ListContacts { page, reply })
            .await
    }

    pub async fn delete_contact(&self, email: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::DeleteContact { email, reply })
            .await
    }

    pub async fn update_contact(
        &self,
        email: String,
        request: UpdateContactRequest,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::UpdateContact {
            email,
            request,
            reply,
        })
        .await
    }

    pub async fn update_dir(&self, name: String, request: UpdateDirRequest) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::UpdateDir {
            name,
            new_name: request.name,
            reply,
        })
        .await
    }

    pub async fn delete_dir(&self, name: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::DeleteDir { name, reply })
            .await
    }

    #[cfg(test)]
    pub async fn create_file(&self, body: Vec<u8>) -> Result<String, DbError> {
        self.create_file_from_bytes(Zeroizing::new(body)).await
    }

    pub async fn create_file_from_bytes(
        &self,
        body: Zeroizing<Vec<u8>>,
    ) -> Result<String, DbError> {
        let expected_size = u64::try_from(body.len()).map_err(|_| DbError::Internal)?;
        validate_file_upload_size(expected_size)?;
        let (sender, receiver) = mpsc::channel(8);
        let send_task = tokio::spawn(async move {
            for chunk in body.chunks(FILE_RECORD_PLAINTEXT_BYTES) {
                if sender.send(Zeroizing::new(chunk.to_vec())).await.is_err() {
                    return;
                }
            }
        });
        let result = self.create_file_from_chunks(receiver, expected_size).await;
        send_task.await.map_err(|_| DbError::Internal)?;
        result
    }

    pub async fn create_file_from_chunks(
        &self,
        chunks: mpsc::Receiver<Zeroizing<Vec<u8>>>,
        expected_size: u64,
    ) -> Result<String, DbError> {
        validate_file_upload_size(expected_size)?;
        self.request_writer(|reply| DbCommand::CreateFile {
            chunks,
            expected_size,
            reply,
        })
        .await
    }

    pub async fn lookup_file_by_sha256(&self, sha256: String) -> Result<String, DbError> {
        self.request_reader(|reply| DbCommand::LookupFileBySha256 { sha256, reply })
            .await
    }

    pub async fn create_item(
        &self,
        dir_name: String,
        item_name: String,
        request: CreateItemRequest,
        source: Option<ItemSource>,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::CreateItem {
            dir_name,
            item_name,
            request,
            source,
            reply,
        })
        .await
    }

    pub async fn get_item(
        &self,
        dir_name: String,
        item_name: String,
        version: Option<i64>,
        reveal: bool,
        raw: bool,
        mustauth_satisfied: bool,
    ) -> Result<ItemResponse, DbError> {
        self.request_reader(|reply| DbCommand::GetItem {
            dir_name,
            item_name,
            version,
            reveal,
            raw,
            mustauth_satisfied,
            reply,
        })
        .await
    }

    pub async fn update_item(
        &self,
        dir_name: String,
        item_name: String,
        request: UpdateItemRequest,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::UpdateItem {
            dir_name,
            item_name,
            request,
            reply,
        })
        .await
    }

    pub async fn list_items(
        &self,
        dir_name: String,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ItemSummaryResponse>, DbError> {
        self.request_reader(|reply| DbCommand::ListItems {
            dir_name,
            page,
            reply,
        })
        .await
    }

    pub async fn list_item_versions(
        &self,
        dir_name: String,
        item_name: String,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ItemVersionSummaryResponse>, DbError> {
        self.request_reader(|reply| DbCommand::ListItemVersions {
            dir_name,
            item_name,
            page,
            reply,
        })
        .await
    }

    pub async fn delete_item(&self, dir_name: String, item_name: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::DeleteItem {
            dir_name,
            item_name,
            reply,
        })
        .await
    }

    pub async fn restore_item_version(
        &self,
        dir_name: String,
        item_name: String,
        version: i64,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::RestoreItemVersion {
            dir_name,
            item_name,
            version,
            reply,
        })
        .await
    }

    pub async fn get_reference(
        &self,
        dir_name: String,
        item_name: String,
        field_name: String,
        version: Option<i64>,
        raw: bool,
        mustauth_satisfied: bool,
    ) -> Result<ReferenceResponse, DbError> {
        self.request_reader(|reply| DbCommand::GetReference {
            dir_name,
            item_name,
            field_name,
            version,
            raw,
            mustauth_satisfied,
            reply,
        })
        .await
    }

    pub async fn list_settings(&self) -> Result<HashMap<String, String>, DbError> {
        self.request_reader(|reply| DbCommand::ListSettings { reply })
            .await
    }

    pub async fn upsert_setting(&self, name: String, value: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::UpsertSetting { name, value, reply })
            .await
    }

    pub async fn create_import_job(
        &self,
        job_id: String,
        dir_name: String,
        item_name: String,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::CreateImportJob {
            job_id,
            dir_name,
            item_name,
            reply,
        })
        .await
    }

    pub async fn create_export_job(
        &self,
        job_id: String,
        dir_name: String,
        item_name: String,
        contact_name: String,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::CreateExportJob {
            job_id,
            dir_name,
            item_name,
            contact_name,
            reply,
        })
        .await
    }

    pub async fn mark_job_running(&self, job_id: String) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::MarkJobRunning { job_id, reply })
            .await
    }

    pub async fn mark_job_succeeded(
        &self,
        job_id: String,
        output_path: Option<PathBuf>,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::MarkJobSucceeded {
            job_id,
            output_path,
            reply,
        })
        .await
    }

    pub async fn mark_job_failed(
        &self,
        job_id: String,
        code: String,
        message: String,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::MarkJobFailed {
            job_id,
            code,
            message,
            reply,
        })
        .await
    }

    pub async fn get_job(&self, job_id: String) -> Result<JobResponse, DbError> {
        self.request_reader(|reply| DbCommand::GetJob { job_id, reply })
            .await
    }

    pub async fn age_private_identity(&self) -> Result<Zeroizing<String>, DbError> {
        self.request_reader(|reply| DbCommand::AgePrivateIdentity { reply })
            .await
    }

    pub async fn contact_public_key(&self, email: String) -> Result<String, DbError> {
        self.request_reader(|reply| DbCommand::ContactPublicKey { email, reply })
            .await
    }

    async fn user_setting_duration(&self, name: &str) -> Result<Duration, DbError> {
        let name = name.to_owned();
        self.request_reader(|reply| DbCommand::GetUserSettingDuration { name, reply })
            .await
    }

    async fn cleanup_before_unload(
        &self,
        version_cutoff: Instant,
        file_cutoff: Instant,
    ) -> Result<(), DbError> {
        #[cfg(test)]
        if self
            .pool
            .fail_next_cleanup_before_unload
            .swap(false, Ordering::Relaxed)
        {
            return Err(DbError::Internal);
        }

        self.request_writer(|reply| DbCommand::CleanupBeforeUnload {
            version_cutoff,
            file_cutoff,
            reply,
        })
        .await
    }

    async fn request_writer<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, DbError>>) -> DbCommand,
    ) -> Result<T, DbError> {
        #[cfg(test)]
        self.pool
            .dispatch_counts
            .writer
            .fetch_add(1, Ordering::Relaxed);
        self.request(&self.pool.writer, build).await
    }

    async fn request_reader<T>(
        &self,
        build: impl FnOnce(oneshot::Sender<Result<T, DbError>>) -> DbCommand,
    ) -> Result<T, DbError> {
        let reader = self.next_reader().ok_or(DbError::Internal)?;
        #[cfg(test)]
        self.pool
            .dispatch_counts
            .reader
            .fetch_add(1, Ordering::Relaxed);
        self.request(reader, build).await
    }

    fn next_reader(&self) -> Option<&DbWorker> {
        let reader_count = self.pool.readers.len();
        if reader_count == 0 {
            return None;
        }

        let index = self.pool.next_reader.fetch_add(1, Ordering::Relaxed) % reader_count;
        self.pool.readers.get(index)
    }

    async fn request<T>(
        &self,
        worker: &DbWorker,
        build: impl FnOnce(oneshot::Sender<Result<T, DbError>>) -> DbCommand,
    ) -> Result<T, DbError> {
        let (reply, receiver) = oneshot::channel();
        worker
            .sender
            .send(build(reply))
            .await
            .map_err(|_| DbError::Internal)?;
        receiver.await.map_err(|_| DbError::Internal)?
    }

    #[cfg(test)]
    pub fn test() -> Self {
        static NEXT_TEST_DATABASE: AtomicUsize = AtomicUsize::new(0);

        let database_name = format!(
            "file:pass_rs_test_{}?mode=memory&cache=shared",
            NEXT_TEST_DATABASE.fetch_add(1, Ordering::Relaxed)
        );
        let connection = Connection::open_with_flags(
            &database_name,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                | rusqlite::OpenFlags::SQLITE_OPEN_CREATE
                | rusqlite::OpenFlags::SQLITE_OPEN_URI,
        )
        .unwrap();
        connection
            .pragma_update(None, "foreign_keys", "ON")
            .unwrap();
        connection
            .execute_batch(
                r#"
                CREATE TABLE system_settings (
                    name TEXT PRIMARY KEY,
                    value TEXT
                ) WITHOUT ROWID;
                CREATE TABLE dirs (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    bitmask INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE contacts (
                    email TEXT PRIMARY KEY,
                    name TEXT,
                    age_public_key TEXT NOT NULL,
                    description TEXT,
                    created_at INTEGER NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE items (
                    id INTEGER PRIMARY KEY,
                    dir_id INTEGER NOT NULL REFERENCES dirs (id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    bitmask INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    oldest_version_id INTEGER,
                    latest_version_id INTEGER,
                    UNIQUE (dir_id, name),
                    FOREIGN KEY (id, oldest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED,
                    FOREIGN KEY (id, latest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED
                );
                CREATE TABLE item_versions (
                    version_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL REFERENCES items (id) ON DELETE CASCADE,
                    fields TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (item_id, version_id)
                ) WITHOUT ROWID;
                CREATE TABLE files (
                    id BLOB PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE (sha256)
                ) WITHOUT ROWID;
                CREATE TABLE item_version_file_mapping (
                    item_id INTEGER NOT NULL,
                    version_id INTEGER NOT NULL,
                    file_id BLOB NOT NULL REFERENCES files (id) ON DELETE CASCADE,
                    file_name TEXT NOT NULL,
                    PRIMARY KEY (item_id, version_id, file_id),
                    UNIQUE (item_id, version_id, file_name),
                    FOREIGN KEY (item_id, version_id) REFERENCES item_versions (item_id, version_id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                CREATE TABLE jobs (
                    job_id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    status TEXT NOT NULL,
                    target_dir TEXT NOT NULL,
                    target_item TEXT NOT NULL,
                    target_contact TEXT,
                    output_path TEXT,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    started_at INTEGER,
                    finished_at INTEGER,
                    error_code TEXT,
                    error_message TEXT
                ) WITHOUT ROWID;
                "#,
            )
            .unwrap();
        let readers = (0..DATABASE_READER_WORKERS)
            .map(|_| {
                let reader = Connection::open_with_flags(
                    &database_name,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
                        | rusqlite::OpenFlags::SQLITE_OPEN_URI,
                )
                .unwrap();
                reader.pragma_update(None, "foreign_keys", "ON").unwrap();
                reader
            })
            .collect();
        let file_store_path = std::env::temp_dir().join(format!(
            "pass_rs_test_files_{}",
            NEXT_TEST_DATABASE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&file_store_path);
        std::fs::create_dir_all(&file_store_path).unwrap();
        insert_test_file_key(&connection);
        insert_test_user_settings(&connection);
        Self::new(connection, readers, file_store_path)
    }

    pub fn ptr_eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.pool, &other.pool)
    }

    #[cfg(test)]
    pub(crate) fn dispatch_counts(&self) -> (usize, usize) {
        (
            self.pool.dispatch_counts.writer.load(Ordering::Relaxed),
            self.pool.dispatch_counts.reader.load(Ordering::Relaxed),
        )
    }

    #[cfg(test)]
    async fn test_slow_read(&self, duration: Duration) -> Result<(), DbError> {
        self.request_reader(|reply| DbCommand::TestSleep { duration, reply })
            .await
    }

    #[cfg(test)]
    pub(crate) async fn test_slow_write(&self, duration: Duration) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::TestSleep { duration, reply })
            .await
    }

    #[cfg(test)]
    fn test_file_path(&self, id: &str) -> PathBuf {
        file_path(&self.pool.file_store_path, id)
    }

    #[cfg(test)]
    fn test_file_store_entries(&self) -> Vec<PathBuf> {
        fn collect_files(path: &Path, entries: &mut Vec<PathBuf>) {
            for entry in std::fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    collect_files(&path, entries);
                } else if path.is_file() {
                    entries.push(path);
                }
            }
        }

        let mut entries = Vec::new();
        collect_files(&self.pool.file_store_path, &mut entries);
        entries
    }

    #[cfg(test)]
    async fn test_set_file_created_at(&self, id: &str, created_at: i64) -> Result<(), DbError> {
        let id = hex_decode_exact(id, FILE_ID_BYTES).ok_or(DbError::Internal)?;
        self.request_writer(|reply| DbCommand::TestSetFileCreatedAt {
            id,
            created_at,
            reply,
        })
        .await
    }

    #[cfg(test)]
    async fn test_file_nonce_len(&self, id: &str) -> Result<usize, DbError> {
        let id = hex_decode_exact(id, FILE_ID_BYTES).ok_or(DbError::Internal)?;
        self.request_reader(|reply| DbCommand::TestFileNonceLen { id, reply })
            .await
    }

    #[cfg(test)]
    async fn test_set_dir_bitmask(&self, name: &str, bitmask: i64) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::TestSetDirBitmask {
            name: name.to_owned(),
            bitmask,
            reply,
        })
        .await
    }

    #[cfg(test)]
    pub(crate) async fn test_set_item_bitmask(
        &self,
        dir_name: &str,
        item_name: &str,
        bitmask: i64,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::TestSetItemBitmask {
            dir_name: dir_name.to_owned(),
            item_name: item_name.to_owned(),
            bitmask,
            reply,
        })
        .await
    }

    #[cfg(test)]
    async fn test_item_version_count(
        &self,
        dir_name: &str,
        item_name: &str,
    ) -> Result<i64, DbError> {
        self.request_reader(|reply| DbCommand::TestItemVersionCount {
            dir_name: dir_name.to_owned(),
            item_name: item_name.to_owned(),
            reply,
        })
        .await
    }

    #[cfg(test)]
    async fn test_item_versions(
        &self,
        dir_name: &str,
        item_name: &str,
    ) -> Result<Vec<i64>, DbError> {
        self.request_reader(|reply| DbCommand::TestItemVersions {
            dir_name: dir_name.to_owned(),
            item_name: item_name.to_owned(),
            reply,
        })
        .await
    }

    #[cfg(test)]
    async fn test_set_item_versions_created_at(
        &self,
        dir_name: &str,
        item_name: &str,
        include_latest: bool,
        created_at: i64,
    ) -> Result<(), DbError> {
        self.request_writer(|reply| DbCommand::TestSetItemVersionsCreatedAt {
            dir_name: dir_name.to_owned(),
            item_name: item_name.to_owned(),
            include_latest,
            created_at,
            reply,
        })
        .await
    }

    #[cfg(test)]
    async fn test_oldest_version_is_earliest(
        &self,
        dir_name: &str,
        item_name: &str,
    ) -> Result<bool, DbError> {
        self.request_reader(|reply| DbCommand::TestOldestVersionIsEarliest {
            dir_name: dir_name.to_owned(),
            item_name: item_name.to_owned(),
            reply,
        })
        .await
    }

    #[cfg(test)]
    fn test_fail_next_cleanup_before_unload(&self) {
        self.pool
            .fail_next_cleanup_before_unload
            .store(true, Ordering::Relaxed);
    }
}

#[derive(Debug)]
struct DbPool {
    writer: DbWorker,
    readers: Vec<DbWorker>,
    #[cfg(test)]
    file_store_path: PathBuf,
    next_reader: AtomicUsize,
    #[cfg(test)]
    dispatch_counts: DispatchCounts,
    #[cfg(test)]
    fail_next_cleanup_before_unload: std::sync::atomic::AtomicBool,
}

#[cfg(test)]
#[derive(Debug, Default)]
struct DispatchCounts {
    writer: AtomicUsize,
    reader: AtomicUsize,
}

#[derive(Debug)]
struct DbWorker {
    sender: mpsc::Sender<DbCommand>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CopySource {
    pub dir_name: String,
    pub item_name: String,
}

pub enum ItemSource {
    Copy(CopySource),
    Move(CopySource),
}

pub struct ReferenceResponse {
    pub body: ReferenceBody,
    pub etag: Option<String>,
}

pub enum ReferenceBody {
    Bytes(Zeroizing<Vec<u8>>),
    Stream(mpsc::Receiver<Result<Zeroizing<Vec<u8>>, DbError>>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbError {
    AccessDenied,
    BadRequest(String),
    Conflict(String),
    Internal,
    NotFound,
    NotFoundMessage(String),
}

impl DbError {
    fn not_found(message: impl Into<String>) -> Self {
        Self::NotFoundMessage(message.into())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    pub count: u64,
    pub marker: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PageMarkerScope {
    Dirs,
    Contacts,
    Items { dir_id: i64 },
    ItemVersions { item_id: i64 },
}

impl PageMarkerScope {
    fn associated_data(self) -> Vec<u8> {
        match self {
            Self::Dirs => b"monopass:dirs".to_vec(),
            Self::Contacts => b"monopass:contacts".to_vec(),
            Self::Items { dir_id } => {
                let mut data = b"monopass:items:".to_vec();
                data.extend_from_slice(&dir_id.to_be_bytes());
                data
            }
            Self::ItemVersions { item_id } => {
                let mut data = b"monopass:item-versions:".to_vec();
                data.extend_from_slice(&item_id.to_be_bytes());
                data
            }
        }
    }
}

enum DbCommand {
    CreateDir {
        name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    GetDir {
        name: String,
        reply: oneshot::Sender<Result<DirResponse, DbError>>,
    },
    ListDirs {
        page: PageRequest,
        reply: oneshot::Sender<Result<PaginatedResponse<DirResponse>, DbError>>,
    },
    CreateContact {
        email: String,
        request: CreateContactRequest,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    ListContacts {
        page: PageRequest,
        reply: oneshot::Sender<Result<PaginatedResponse<ContactResponse>, DbError>>,
    },
    DeleteContact {
        email: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    UpdateContact {
        email: String,
        request: UpdateContactRequest,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    UpdateDir {
        name: String,
        new_name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    DeleteDir {
        name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    CreateFile {
        chunks: mpsc::Receiver<Zeroizing<Vec<u8>>>,
        expected_size: u64,
        reply: oneshot::Sender<Result<String, DbError>>,
    },
    LookupFileBySha256 {
        sha256: String,
        reply: oneshot::Sender<Result<String, DbError>>,
    },
    CreateItem {
        dir_name: String,
        item_name: String,
        request: CreateItemRequest,
        source: Option<ItemSource>,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    GetItem {
        dir_name: String,
        item_name: String,
        version: Option<i64>,
        reveal: bool,
        raw: bool,
        mustauth_satisfied: bool,
        reply: oneshot::Sender<Result<ItemResponse, DbError>>,
    },
    UpdateItem {
        dir_name: String,
        item_name: String,
        request: UpdateItemRequest,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    ListItems {
        dir_name: String,
        page: PageRequest,
        reply: oneshot::Sender<Result<PaginatedResponse<ItemSummaryResponse>, DbError>>,
    },
    ListItemVersions {
        dir_name: String,
        item_name: String,
        page: PageRequest,
        reply: oneshot::Sender<Result<PaginatedResponse<ItemVersionSummaryResponse>, DbError>>,
    },
    DeleteItem {
        dir_name: String,
        item_name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    RestoreItemVersion {
        dir_name: String,
        item_name: String,
        version: i64,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    GetReference {
        dir_name: String,
        item_name: String,
        field_name: String,
        version: Option<i64>,
        raw: bool,
        mustauth_satisfied: bool,
        reply: oneshot::Sender<Result<ReferenceResponse, DbError>>,
    },
    ListSettings {
        reply: oneshot::Sender<Result<HashMap<String, String>, DbError>>,
    },
    UpsertSetting {
        name: String,
        value: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    CreateImportJob {
        job_id: String,
        dir_name: String,
        item_name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    CreateExportJob {
        job_id: String,
        dir_name: String,
        item_name: String,
        contact_name: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    MarkJobRunning {
        job_id: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    MarkJobSucceeded {
        job_id: String,
        output_path: Option<PathBuf>,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    MarkJobFailed {
        job_id: String,
        code: String,
        message: String,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    GetJob {
        job_id: String,
        reply: oneshot::Sender<Result<JobResponse, DbError>>,
    },
    AgePrivateIdentity {
        reply: oneshot::Sender<Result<Zeroizing<String>, DbError>>,
    },
    ContactPublicKey {
        email: String,
        reply: oneshot::Sender<Result<String, DbError>>,
    },
    GetUserSettingDuration {
        name: String,
        reply: oneshot::Sender<Result<Duration, DbError>>,
    },
    CleanupBeforeUnload {
        version_cutoff: Instant,
        file_cutoff: Instant,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestSleep {
        duration: Duration,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestSetFileCreatedAt {
        id: Vec<u8>,
        created_at: i64,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestFileNonceLen {
        id: Vec<u8>,
        reply: oneshot::Sender<Result<usize, DbError>>,
    },
    #[cfg(test)]
    TestSetDirBitmask {
        name: String,
        bitmask: i64,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestSetItemBitmask {
        dir_name: String,
        item_name: String,
        bitmask: i64,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestItemVersionCount {
        dir_name: String,
        item_name: String,
        reply: oneshot::Sender<Result<i64, DbError>>,
    },
    #[cfg(test)]
    TestItemVersions {
        dir_name: String,
        item_name: String,
        reply: oneshot::Sender<Result<Vec<i64>, DbError>>,
    },
    #[cfg(test)]
    TestSetItemVersionsCreatedAt {
        dir_name: String,
        item_name: String,
        include_latest: bool,
        created_at: i64,
        reply: oneshot::Sender<Result<(), DbError>>,
    },
    #[cfg(test)]
    TestOldestVersionIsEarliest {
        dir_name: String,
        item_name: String,
        reply: oneshot::Sender<Result<bool, DbError>>,
    },
}

struct DatabaseWorker {
    connection: Connection,
    file_store_path: PathBuf,
}

impl DatabaseWorker {
    fn new(connection: Connection, file_store_path: PathBuf) -> Self {
        Self {
            connection,
            file_store_path,
        }
    }

    fn handle(&mut self, command: DbCommand) {
        match command {
            DbCommand::CreateDir { name, reply } => {
                let _ = reply.send(self.create_dir(&name));
            }
            DbCommand::GetDir { name, reply } => {
                let _ = reply.send(self.get_dir(&name));
            }
            DbCommand::ListDirs { page, reply } => {
                let _ = reply.send(self.list_dirs(page));
            }
            DbCommand::CreateContact {
                email,
                request,
                reply,
            } => {
                let _ = reply.send(self.create_contact(&email, request));
            }
            DbCommand::ListContacts { page, reply } => {
                let _ = reply.send(self.list_contacts(page));
            }
            DbCommand::DeleteContact { email, reply } => {
                let _ = reply.send(self.delete_contact(&email));
            }
            DbCommand::UpdateContact {
                email,
                request,
                reply,
            } => {
                let _ = reply.send(self.update_contact(&email, request));
            }
            DbCommand::UpdateDir {
                name,
                new_name,
                reply,
            } => {
                let _ = reply.send(self.update_dir(&name, &new_name));
            }
            DbCommand::DeleteDir { name, reply } => {
                let _ = reply.send(self.delete_dir(&name));
            }
            DbCommand::CreateFile {
                chunks,
                expected_size,
                reply,
            } => {
                let _ = reply.send(self.create_file(chunks, expected_size));
            }
            DbCommand::LookupFileBySha256 { sha256, reply } => {
                let _ = reply.send(self.lookup_file_by_sha256(&sha256));
            }
            DbCommand::CreateItem {
                dir_name,
                item_name,
                request,
                source,
                reply,
            } => {
                let _ = reply.send(self.create_item(&dir_name, &item_name, request, source));
            }
            DbCommand::GetItem {
                dir_name,
                item_name,
                version,
                reveal,
                raw,
                mustauth_satisfied,
                reply,
            } => {
                let _ = reply.send(self.get_item(
                    &dir_name,
                    &item_name,
                    version,
                    reveal,
                    raw,
                    mustauth_satisfied,
                ));
            }
            DbCommand::UpdateItem {
                dir_name,
                item_name,
                request,
                reply,
            } => {
                let _ = reply.send(self.update_item(&dir_name, &item_name, request));
            }
            DbCommand::ListItems {
                dir_name,
                page,
                reply,
            } => {
                let _ = reply.send(self.list_items(&dir_name, page));
            }
            DbCommand::ListItemVersions {
                dir_name,
                item_name,
                page,
                reply,
            } => {
                let _ = reply.send(self.list_item_versions(&dir_name, &item_name, page));
            }
            DbCommand::DeleteItem {
                dir_name,
                item_name,
                reply,
            } => {
                let _ = reply.send(self.delete_item(&dir_name, &item_name));
            }
            DbCommand::RestoreItemVersion {
                dir_name,
                item_name,
                version,
                reply,
            } => {
                let _ = reply.send(self.restore_item_version(&dir_name, &item_name, version));
            }
            DbCommand::GetReference {
                dir_name,
                item_name,
                field_name,
                version,
                raw,
                mustauth_satisfied,
                reply,
            } => {
                let _ = reply.send(self.get_reference(
                    &dir_name,
                    &item_name,
                    &field_name,
                    version,
                    raw,
                    mustauth_satisfied,
                ));
            }
            DbCommand::ListSettings { reply } => {
                let _ = reply.send(self.list_settings());
            }
            DbCommand::UpsertSetting { name, value, reply } => {
                let _ = reply.send(self.upsert_setting(&name, &value));
            }
            DbCommand::CreateImportJob {
                job_id,
                dir_name,
                item_name,
                reply,
            } => {
                let _ = reply.send(self.create_import_job(&job_id, &dir_name, &item_name));
            }
            DbCommand::CreateExportJob {
                job_id,
                dir_name,
                item_name,
                contact_name,
                reply,
            } => {
                let _ = reply.send(self.create_export_job(
                    &job_id,
                    &dir_name,
                    &item_name,
                    &contact_name,
                ));
            }
            DbCommand::MarkJobRunning { job_id, reply } => {
                let _ = reply.send(self.mark_job_running(&job_id));
            }
            DbCommand::MarkJobSucceeded {
                job_id,
                output_path,
                reply,
            } => {
                let _ = reply.send(self.mark_job_succeeded(&job_id, output_path.as_deref()));
            }
            DbCommand::MarkJobFailed {
                job_id,
                code,
                message,
                reply,
            } => {
                let _ = reply.send(self.mark_job_failed(&job_id, &code, &message));
            }
            DbCommand::GetJob { job_id, reply } => {
                let _ = reply.send(self.get_job(&job_id));
            }
            DbCommand::AgePrivateIdentity { reply } => {
                let _ = reply.send(self.age_private_identity());
            }
            DbCommand::ContactPublicKey { email, reply } => {
                let _ = reply.send(self.contact_public_key(&email));
            }
            DbCommand::GetUserSettingDuration { name, reply } => {
                let _ = reply.send(self.user_setting_duration(&name));
            }
            DbCommand::CleanupBeforeUnload {
                version_cutoff,
                file_cutoff,
                reply,
            } => {
                let _ = reply.send(self.cleanup_before_unload(version_cutoff, file_cutoff));
            }
            #[cfg(test)]
            DbCommand::TestSleep { duration, reply } => {
                std::thread::sleep(duration);
                let _ = reply.send(Ok(()));
            }
            #[cfg(test)]
            DbCommand::TestSetFileCreatedAt {
                id,
                created_at,
                reply,
            } => {
                let result = self
                    .connection
                    .execute(
                        "UPDATE files SET created_at = ?1 WHERE id = ?2",
                        (created_at, id),
                    )
                    .map(|_| ())
                    .map_err(|_| DbError::Internal);
                let _ = reply.send(result);
            }
            #[cfg(test)]
            DbCommand::TestFileNonceLen { id, reply } => {
                let result = self
                    .connection
                    .query_row(
                        "SELECT length(nonce) FROM files WHERE id = ?1",
                        [id],
                        |row| row.get::<_, i64>(0),
                    )
                    .optional()
                    .map_err(|_| DbError::Internal)
                    .and_then(|value| {
                        value
                            .ok_or(DbError::NotFound)
                            .and_then(|len| usize::try_from(len).map_err(|_| DbError::Internal))
                    });
                let _ = reply.send(result);
            }
            #[cfg(test)]
            DbCommand::TestSetDirBitmask {
                name,
                bitmask,
                reply,
            } => {
                let result = self
                    .connection
                    .execute(
                        "UPDATE dirs SET bitmask = ?1 WHERE name = ?2",
                        (bitmask, name),
                    )
                    .map_err(|_| DbError::Internal)
                    .and_then(|changed| {
                        if changed == 0 {
                            Err(DbError::NotFound)
                        } else {
                            Ok(())
                        }
                    });
                let _ = reply.send(result);
            }
            #[cfg(test)]
            DbCommand::TestSetItemBitmask {
                dir_name,
                item_name,
                bitmask,
                reply,
            } => {
                let result = dir_id_in(&self.connection, &dir_name)
                    .and_then(|dir_id| dir_id.ok_or(DbError::NotFound))
                    .and_then(|dir_id| {
                        self.connection
                            .execute(
                                "UPDATE items SET bitmask = ?1 WHERE dir_id = ?2 AND name = ?3",
                                (bitmask, dir_id, item_name),
                            )
                            .map_err(|_| DbError::Internal)
                    })
                    .and_then(|changed| {
                        if changed == 0 {
                            Err(DbError::NotFound)
                        } else {
                            Ok(())
                        }
                    });
                let _ = reply.send(result);
            }
            #[cfg(test)]
            DbCommand::TestItemVersionCount {
                dir_name,
                item_name,
                reply,
            } => {
                let _ = reply.send(self.test_item_version_count(&dir_name, &item_name));
            }
            #[cfg(test)]
            DbCommand::TestItemVersions {
                dir_name,
                item_name,
                reply,
            } => {
                let _ = reply.send(self.test_item_versions(&dir_name, &item_name));
            }
            #[cfg(test)]
            DbCommand::TestSetItemVersionsCreatedAt {
                dir_name,
                item_name,
                include_latest,
                created_at,
                reply,
            } => {
                let _ = reply.send(self.test_set_item_versions_created_at(
                    &dir_name,
                    &item_name,
                    include_latest,
                    created_at,
                ));
            }
            #[cfg(test)]
            DbCommand::TestOldestVersionIsEarliest {
                dir_name,
                item_name,
                reply,
            } => {
                let _ = reply.send(self.test_oldest_version_is_earliest(&dir_name, &item_name));
            }
        }
    }

    fn create_dir(&self, name: &str) -> Result<(), DbError> {
        validate_name(name)?;
        let now = now_timestamp();
        self.connection
            .execute(
                "INSERT INTO dirs (name, created_at, updated_at) VALUES (?1, ?2, ?2)",
                (name, now),
            )
            .map(|_| ())
            .map_err(map_insert_error)
    }

    fn get_dir(&self, name: &str) -> Result<DirResponse, DbError> {
        self.connection
            .query_row(
                r#"
                SELECT v.name, v.created_at, v.updated_at, count(i.id)
                FROM dirs v
                LEFT JOIN items i ON i.dir_id = v.id AND (i.bitmask & ?2) = 0
                WHERE v.name = ?1 AND (v.bitmask & ?2) = 0
                GROUP BY v.id
                "#,
                (name, ITEM_HIDDEN),
                |row| {
                    Ok(DirResponse {
                        name: row.get(0)?,
                        created_at: format_timestamp(row.get(1)?),
                        updated_at: format_timestamp(row.get(2)?),
                        items: row.get::<_, i64>(3)? as u64,
                    })
                },
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| dir_not_found(name))
    }

    fn list_dirs(&self, page: PageRequest) -> Result<PaginatedResponse<DirResponse>, DbError> {
        let limit = page_limit(page.count)?;
        let marker_name = match page.marker {
            Some(marker) => {
                let id = self.decrypt_page_marker(&marker, PageMarkerScope::Dirs)?;
                Some(
                    self.connection
                        .query_row(
                            "SELECT name FROM dirs WHERE id = ?1 AND (bitmask & ?2) = 0",
                            (id, DIR_HIDDEN),
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(|_| DbError::Internal)?
                        .ok_or_else(invalid_page_marker)?,
                )
            }
            None => None,
        };

        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT v.id, v.name, v.created_at, v.updated_at, count(i.id)
                FROM dirs v
                LEFT JOIN items i ON i.dir_id = v.id AND (i.bitmask & ?3) = 0
                WHERE (?1 IS NULL OR v.name >= ?1)
                  AND (v.bitmask & ?3) = 0
                GROUP BY v.id
                ORDER BY v.name
                LIMIT ?2
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let sql_limit = i64::try_from(limit + 1).map_err(|_| DbError::Internal)?;
        let rows = statement
            .query_map((marker_name.as_deref(), sql_limit, DIR_HIDDEN), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    DirResponse {
                        name: row.get(1)?,
                        created_at: format_timestamp(row.get(2)?),
                        updated_at: format_timestamp(row.get(3)?),
                        items: row.get::<_, i64>(4)? as u64,
                    },
                ))
            })
            .map_err(|_| DbError::Internal)?;

        let mut rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)?;
        let next_marker = if rows.len() > limit {
            let (id, _) = rows.pop().ok_or(DbError::Internal)?;
            Some(self.encrypt_page_marker(id, PageMarkerScope::Dirs)?)
        } else {
            None
        };
        let entries = rows
            .into_iter()
            .map(|(_, response)| response)
            .collect::<Vec<_>>();
        Ok(PaginatedResponse {
            count: entries.len() as u64,
            entries,
            next_marker,
        })
    }

    fn create_contact(&self, email: &str, request: CreateContactRequest) -> Result<(), DbError> {
        validate_name(email)?;
        validate_age_public_key(&request.age_public_key)?;
        let now = now_timestamp();
        self.connection
            .execute(
                r#"
                INSERT INTO contacts (email, name, age_public_key, description, created_at)
                VALUES (?1, ?2, ?3, ?4, ?5)
                "#,
                (
                    email,
                    request.name,
                    request.age_public_key,
                    request.description,
                    now,
                ),
            )
            .map(|_| ())
            .map_err(map_insert_error)
    }

    fn update_contact(&self, email: &str, request: UpdateContactRequest) -> Result<(), DbError> {
        validate_name(email)?;
        validate_name(&request.email)?;
        if let Some(age_public_key) = request.age_public_key.as_deref() {
            validate_age_public_key(age_public_key)?;
        }

        let update_name = request.name.is_some();
        let name = request.name.flatten();
        let changed = self
            .connection
            .execute(
                r#"
                UPDATE contacts
                SET email = ?2,
                    name = CASE WHEN ?3 THEN ?4 ELSE name END,
                    age_public_key = COALESCE(?5, age_public_key)
                WHERE email = ?1
                "#,
                (
                    email,
                    request.email,
                    update_name,
                    name,
                    request.age_public_key,
                ),
            )
            .map_err(map_update_error)?;
        if changed == 0 {
            Err(contact_not_found(email))
        } else {
            Ok(())
        }
    }

    fn list_contacts(
        &self,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ContactResponse>, DbError> {
        let limit = page_limit(page.count)?;
        let marker_email = match page.marker {
            Some(marker) => {
                let email = self.decrypt_text_page_marker(&marker, PageMarkerScope::Contacts)?;
                self.connection
                    .query_row("SELECT 1 FROM contacts WHERE email = ?1", [&email], |_| {
                        Ok(())
                    })
                    .optional()
                    .map_err(|_| DbError::Internal)?
                    .ok_or_else(invalid_page_marker)?;
                Some(email)
            }
            None => None,
        };

        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT email, name, age_public_key, description, created_at
                FROM contacts
                WHERE (?1 IS NULL OR email >= ?1)
                ORDER BY email
                LIMIT ?2
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let sql_limit = i64::try_from(limit + 1).map_err(|_| DbError::Internal)?;
        let rows = statement
            .query_map((marker_email.as_deref(), sql_limit), |row| {
                Ok(ContactResponse {
                    email: row.get(0)?,
                    name: row.get(1)?,
                    age_public_key: row.get(2)?,
                    description: row.get(3)?,
                    created_at: format_timestamp(row.get(4)?),
                })
            })
            .map_err(|_| DbError::Internal)?;

        let mut rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)?;
        let next_marker = if rows.len() > limit {
            let contact = rows.pop().ok_or(DbError::Internal)?;
            Some(self.encrypt_text_page_marker(&contact.email, PageMarkerScope::Contacts)?)
        } else {
            None
        };
        Ok(PaginatedResponse {
            count: rows.len() as u64,
            entries: rows,
            next_marker,
        })
    }

    fn delete_contact(&self, email: &str) -> Result<(), DbError> {
        let changed = self
            .connection
            .execute("DELETE FROM contacts WHERE email = ?1", [email])
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(contact_not_found(email))
        } else {
            Ok(())
        }
    }

    fn list_settings(&self) -> Result<HashMap<String, String>, DbError> {
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT name, value
                FROM system_settings
                WHERE name LIKE 'user.%'
                ORDER BY name
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let rows = statement
            .query_map([], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })
            .map_err(|_| DbError::Internal)?;
        rows.collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(|_| DbError::Internal)
    }

    fn upsert_setting(&self, name: &str, value: &str) -> Result<(), DbError> {
        let setting = user_setting(name).map_err(|error| map_named_settings_error(error, name))?;
        setting.validate(value).map_err(map_settings_error)?;
        self.connection
            .execute(
                r#"
                INSERT INTO system_settings (name, value)
                VALUES (?1, ?2)
                ON CONFLICT(name) DO UPDATE SET value = excluded.value
                "#,
                (name, value),
            )
            .map(|_| ())
            .map_err(|_| DbError::Internal)
    }

    fn create_import_job(
        &self,
        job_id: &str,
        dir_name: &str,
        item_name: &str,
    ) -> Result<(), DbError> {
        validate_job_id(job_id)?;
        validate_name(dir_name)?;
        validate_item_name(item_name)?;
        public_dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        let now = now_timestamp();
        self.connection
            .execute(
                r#"
                INSERT INTO jobs (
                    job_id, type, status, target_dir, target_item,
                    created_at, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?6)
                "#,
                (
                    job_id,
                    JobType::Import.as_str(),
                    JobStatus::Queued.as_str(),
                    dir_name,
                    item_name,
                    now,
                ),
            )
            .map(|_| ())
            .map_err(map_insert_error)
    }

    fn create_export_job(
        &self,
        job_id: &str,
        dir_name: &str,
        item_name: &str,
        contact_name: &str,
    ) -> Result<(), DbError> {
        validate_job_id(job_id)?;
        validate_name(dir_name)?;
        validate_item_name(item_name)?;
        validate_name(contact_name)?;
        let dir_id =
            public_dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        public_item_id_in(&self.connection, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        contact_exists_in(&self.connection, contact_name)?
            .ok_or_else(|| contact_not_found(contact_name))?;
        let now = now_timestamp();
        self.connection
            .execute(
                r#"
                INSERT INTO jobs (
                    job_id, type, status, target_dir, target_item, target_contact,
                    created_at, updated_at
                )
                VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                "#,
                (
                    job_id,
                    JobType::Export.as_str(),
                    JobStatus::Queued.as_str(),
                    dir_name,
                    item_name,
                    contact_name,
                    now,
                ),
            )
            .map(|_| ())
            .map_err(map_insert_error)
    }

    fn mark_job_running(&self, job_id: &str) -> Result<(), DbError> {
        validate_job_id(job_id)?;
        let now = now_timestamp();
        let changed = self
            .connection
            .execute(
                r#"
                UPDATE jobs
                SET status = ?1, started_at = COALESCE(started_at, ?2), updated_at = ?2
                WHERE job_id = ?3
                "#,
                (JobStatus::Running.as_str(), now, job_id),
            )
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(job_not_found(job_id))
        } else {
            Ok(())
        }
    }

    fn mark_job_succeeded(&self, job_id: &str, output_path: Option<&Path>) -> Result<(), DbError> {
        validate_job_id(job_id)?;
        let now = now_timestamp();
        let output_path = output_path.map(|path| path.to_string_lossy().into_owned());
        let changed = self
            .connection
            .execute(
                r#"
                UPDATE jobs
                SET status = ?1, updated_at = ?2, finished_at = ?2,
                    output_path = ?3, error_code = NULL, error_message = NULL
                WHERE job_id = ?4
                "#,
                (JobStatus::Succeeded.as_str(), now, output_path, job_id),
            )
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(job_not_found(job_id))
        } else {
            Ok(())
        }
    }

    fn mark_job_failed(&self, job_id: &str, code: &str, message: &str) -> Result<(), DbError> {
        validate_job_id(job_id)?;
        let now = now_timestamp();
        let changed = self
            .connection
            .execute(
                r#"
                UPDATE jobs
                SET status = ?1, updated_at = ?2, finished_at = ?2,
                    error_code = ?3, error_message = ?4
                WHERE job_id = ?5
                "#,
                (JobStatus::Failed.as_str(), now, code, message, job_id),
            )
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(job_not_found(job_id))
        } else {
            Ok(())
        }
    }

    fn get_job(&self, job_id: &str) -> Result<JobResponse, DbError> {
        validate_job_id(job_id)?;
        self.connection
            .query_row(
                r#"
                SELECT job_id, type, status, target_dir, target_item,
                       created_at, updated_at, started_at, finished_at,
                       error_code, error_message, target_contact, output_path
                FROM jobs
                WHERE job_id = ?1
                "#,
                [job_id],
                |row| {
                    let job_type: String = row.get(1)?;
                    let status: String = row.get(2)?;
                    let error_code: Option<String> = row.get(9)?;
                    let error_message: Option<String> = row.get(10)?;
                    Ok(JobResponse {
                        job_id: row.get(0)?,
                        job_type: match job_type.as_str() {
                            "import" => JobType::Import,
                            "export" => JobType::Export,
                            _ => JobType::Import,
                        },
                        status: JobStatus::from_str(&status).unwrap_or(JobStatus::Failed),
                        target: JobTarget {
                            dir: row.get(3)?,
                            item: row.get(4)?,
                            contact: row.get(11)?,
                        },
                        created_at: format_timestamp(row.get(5)?),
                        updated_at: format_timestamp(row.get(6)?),
                        started_at: row.get::<_, Option<i64>>(7)?.map(format_timestamp),
                        finished_at: row.get::<_, Option<i64>>(8)?.map(format_timestamp),
                        output_path: row.get(12)?,
                        error: error_code
                            .zip(error_message)
                            .map(|(code, message)| JobErrorResponse { code, message }),
                    })
                },
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| job_not_found(job_id))
    }

    fn contact_public_key(&self, email: &str) -> Result<String, DbError> {
        validate_name(email)?;
        self.connection
            .query_row(
                "SELECT age_public_key FROM contacts WHERE email = ?1",
                [email],
                |row| row.get(0),
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| contact_not_found(email))
    }

    fn age_private_identity(&self) -> Result<Zeroizing<String>, DbError> {
        let dir_id = dir_id_in(&self.connection, INTERNAL_DIR_NAME)?.ok_or(DbError::Internal)?;
        let item_id = item_id_in(&self.connection, dir_id, AGE_PRIVATE_KEY_ITEM_NAME)?
            .ok_or(DbError::Internal)?;
        let fields = source_fields(&self.connection, item_id)?;
        let key = fields
            .get("key")
            .filter(|field| matches!(field.field_type, FieldType::String))
            .map(|field| field.data.as_str())
            .ok_or(DbError::Internal)?;
        Ok(Zeroizing::new(key.to_owned()))
    }

    fn user_setting_duration(&self, name: &str) -> Result<Duration, DbError> {
        let setting = user_setting(name).map_err(|error| map_named_settings_error(error, name))?;
        let value: String = self
            .connection
            .query_row(
                "SELECT value FROM system_settings WHERE name = ?1",
                [name],
                |row| row.get(0),
            )
            .map_err(|_| DbError::Internal)?;
        setting.parse_duration(&value).map_err(map_settings_error)
    }

    fn update_dir(&self, name: &str, new_name: &str) -> Result<(), DbError> {
        validate_name(new_name)?;
        let Some((_, bitmask)) = dir_row_in(&self.connection, name)? else {
            return Err(dir_not_found(name));
        };
        if bitmask_has(bitmask, DIR_HIDDEN) {
            return Err(dir_not_found(name));
        }
        let changed = self
            .connection
            .execute(
                "UPDATE dirs SET name = ?1, updated_at = ?2 WHERE name = ?3 AND (bitmask & ?4) = 0",
                (new_name, now_timestamp(), name, DIR_HIDDEN),
            )
            .map_err(map_update_error)?;
        if changed == 0 {
            Err(dir_not_found(name))
        } else {
            Ok(())
        }
    }

    fn delete_dir(&self, name: &str) -> Result<(), DbError> {
        let (id, bitmask, item_count) = self
            .connection
            .query_row(
                r#"
                SELECT v.id, v.bitmask, count(i.id)
                FROM dirs v
                LEFT JOIN items i ON i.dir_id = v.id
                WHERE v.name = ?1
                GROUP BY v.id
                "#,
                [name],
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, i64>(2)?,
                    ))
                },
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| dir_not_found(name))?;
        if bitmask_has(bitmask, DIR_HIDDEN) {
            return Err(dir_not_found(name));
        }
        if item_count > 0 {
            return Err(DbError::Conflict("directory is not empty".to_owned()));
        }

        let changed = self
            .connection
            .execute("DELETE FROM dirs WHERE id = ?1", [id])
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(dir_not_found(name))
        } else {
            Ok(())
        }
    }

    fn create_file(
        &mut self,
        mut chunks: mpsc::Receiver<Zeroizing<Vec<u8>>>,
        expected_size: u64,
    ) -> Result<String, DbError> {
        validate_file_upload_size(expected_size)?;
        let key = self.file_encryption_key()?;
        let mut id = [0u8; FILE_ID_BYTES];
        getrandom::fill(&mut id).map_err(|_| DbError::Internal)?;
        let id_hex = hex_encode(&id);
        let mut nonce_prefix = [0u8; FILE_NONCE_PREFIX_BYTES];
        getrandom::fill(&mut nonce_prefix).map_err(|_| DbError::Internal)?;
        let now = now_timestamp();

        let temp_path = write_temp_path(&self.file_store_path, &id_hex)?;
        let final_path = file_path(&self.file_store_path, &id_hex);
        if let Some(parent) = final_path.parent() {
            create_private_dir_all(parent)?;
        }
        let mut temp_file = create_private_blob_file(&temp_path)?;
        let mut sha256 = Sha256::new();
        let mut size = 0_u64;
        let mut counter = 0_u64;
        let mut last_tag = [0u8; AES_GCM_TAG_BYTES];
        let mut wrote_record = false;

        while let Some(chunk) = chunks.blocking_recv() {
            if chunk.len() > FILE_RECORD_PLAINTEXT_BYTES {
                let _ = std::fs::remove_file(&temp_path);
                return Err(DbError::BadRequest("file chunk too large".to_owned()));
            }
            size = size
                .checked_add(u64::try_from(chunk.len()).map_err(|_| DbError::Internal)?)
                .ok_or(DbError::Internal)?;
            if size > expected_size {
                let _ = std::fs::remove_file(&temp_path);
                return Err(DbError::BadRequest(
                    "request body exceeds content-length".to_owned(),
                ));
            }
            sha256.update(&chunk);
            last_tag = encrypt_chunk_record(&mut temp_file, &key, &nonce_prefix, counter, &chunk)?;
            counter = counter.checked_add(1).ok_or(DbError::Internal)?;
            wrote_record = true;
        }
        if size != expected_size {
            let _ = std::fs::remove_file(&temp_path);
            return Err(DbError::BadRequest(
                "request body ended before content-length".to_owned(),
            ));
        }
        if !wrote_record {
            last_tag = encrypt_chunk_record(&mut temp_file, &key, &nonce_prefix, counter, &[])?;
        }
        temp_file.flush().map_err(|_| DbError::Internal)?;
        drop(temp_file);
        let sha256 = hex_encode(&sha256.finalize());

        if let Some(existing_id) = self.file_id_by_sha256(&sha256)? {
            let _ = std::fs::remove_file(&temp_path);
            return Ok(hex_encode(&existing_id));
        }

        let transaction = self
            .connection
            .transaction()
            .map_err(|_| DbError::Internal)?;
        let insert_result = transaction.execute(
            r#"
            INSERT INTO files (id, sha256, size, nonce, tag, created_at)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            (
                id.as_slice(),
                sha256,
                i64::try_from(size)
                    .map_err(|_| DbError::BadRequest("file too large".to_owned()))?,
                nonce_prefix.as_slice(),
                last_tag.as_slice(),
                now,
            ),
        );
        if insert_result.is_err() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(DbError::Internal);
        }
        if std::fs::rename(&temp_path, &final_path).is_err() {
            let _ = std::fs::remove_file(&temp_path);
            return Err(DbError::Internal);
        }
        if transaction.commit().is_err() {
            let _ = std::fs::remove_file(final_path);
            return Err(DbError::Internal);
        }

        Ok(id_hex)
    }

    fn lookup_file_by_sha256(&self, sha256: &str) -> Result<String, DbError> {
        validate_sha256_hex(sha256)?;
        self.file_id_by_sha256(sha256)?
            .map(|id| hex_encode(&id))
            .ok_or_else(|| DbError::not_found(format!("file with sha256 `{sha256}` not found")))
    }

    fn file_id_by_sha256(&self, sha256: &str) -> Result<Option<Vec<u8>>, DbError> {
        self.connection
            .query_row("SELECT id FROM files WHERE sha256 = ?1", [sha256], |row| {
                row.get(0)
            })
            .optional()
            .map_err(|_| DbError::Internal)
    }

    fn create_item(
        &mut self,
        dir_name: &str,
        item_name: &str,
        request: CreateItemRequest,
        source: Option<ItemSource>,
    ) -> Result<(), DbError> {
        validate_item_name(item_name)?;
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| DbError::Internal)?;
        let dir_id = writable_dir_id_in(&transaction, dir_name)?;

        match source {
            Some(ItemSource::Move(source)) => {
                move_item_in(&transaction, dir_id, item_name, request, source)?;
            }
            source => {
                create_item_in(&transaction, dir_id, item_name, request, source)?;
            }
        }

        if transaction.commit().is_err() {
            return Err(DbError::Internal);
        }
        Ok(())
    }

    fn get_item(
        &self,
        dir_name: &str,
        item_name: &str,
        version: Option<i64>,
        reveal: bool,
        raw: bool,
        mustauth_satisfied: bool,
    ) -> Result<ItemResponse, DbError> {
        let dir_id =
            dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        let (_, item_bitmask) = public_item_row_in(&self.connection, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        if (reveal || raw) && bitmask_has(item_bitmask, ITEM_READ_MUSTAUTH) && !mustauth_satisfied {
            return Err(DbError::AccessDenied);
        }
        let row = item_version_row(&self.connection, dir_id, item_name, version)?;

        let mut fields: std::collections::HashMap<String, Field> =
            serde_json::from_str(row.fields_json.as_str()).map_err(|_| DbError::Internal)?;
        if raw {
            // Raw mode intentionally leaves stored field data unchanged.
        } else if reveal {
            resolve_totp_fields(&mut fields)?;
        } else {
            mask_concealed_fields(&mut fields);
        }
        let files = file_metadata(&self.connection, row.item_id, row.version_id)?;
        let total_versions = item_total_versions(&self.connection, row.item_id)?;
        Ok(ItemResponse {
            name: row.item_name,
            fields: field_entries(fields),
            files: file_metadata_entries(files),
            created_at: format_timestamp(row.item_created_at),
            updated_at: format_timestamp(row.item_updated_at),
            total_versions,
        })
    }

    fn list_items(
        &self,
        dir_name: &str,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ItemSummaryResponse>, DbError> {
        let dir_id =
            dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        let limit = page_limit(page.count)?;
        let marker_name = match page.marker {
            Some(marker) => {
                let id = self.decrypt_page_marker(&marker, PageMarkerScope::Items { dir_id })?;
                Some(
                    self.connection
                        .query_row(
                            "SELECT name FROM items WHERE dir_id = ?1 AND id = ?2 AND (bitmask & ?3) = 0",
                            (dir_id, id, ITEM_HIDDEN),
                            |row| row.get::<_, String>(0),
                        )
                        .optional()
                        .map_err(|_| DbError::Internal)?
                        .ok_or_else(invalid_page_marker)?,
                )
            }
            None => None,
        };
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT id, name, created_at, updated_at
                FROM items
                WHERE dir_id = ?1
                  AND (?2 IS NULL OR name >= ?2)
                  AND (bitmask & ?4) = 0
                ORDER BY name
                LIMIT ?3
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let sql_limit = i64::try_from(limit + 1).map_err(|_| DbError::Internal)?;
        let rows = statement
            .query_map(
                (dir_id, marker_name.as_deref(), sql_limit, ITEM_HIDDEN),
                |row| {
                    Ok((
                        row.get::<_, i64>(0)?,
                        ItemSummaryResponse {
                            name: row.get(1)?,
                            created_at: format_timestamp(row.get(2)?),
                            updated_at: format_timestamp(row.get(3)?),
                        },
                    ))
                },
            )
            .map_err(|_| DbError::Internal)?;
        let mut rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)?;
        let next_marker = if rows.len() > limit {
            let (id, _) = rows.pop().ok_or(DbError::Internal)?;
            Some(self.encrypt_page_marker(id, PageMarkerScope::Items { dir_id })?)
        } else {
            None
        };
        let entries = rows
            .into_iter()
            .map(|(_, response)| response)
            .collect::<Vec<_>>();
        Ok(PaginatedResponse {
            count: entries.len() as u64,
            entries,
            next_marker,
        })
    }

    fn list_item_versions(
        &self,
        dir_name: &str,
        item_name: &str,
        page: PageRequest,
    ) -> Result<PaginatedResponse<ItemVersionSummaryResponse>, DbError> {
        let dir_id =
            dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        let item_id = public_item_id_in(&self.connection, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        let limit = page_limit(page.count)?;
        let marker_version = match page.marker {
            Some(marker) => {
                let version_id =
                    self.decrypt_page_marker(&marker, PageMarkerScope::ItemVersions { item_id })?;
                let exists = self
                    .connection
                    .query_row(
                        "SELECT 1 FROM item_versions WHERE item_id = ?1 AND version_id = ?2",
                        (item_id, version_id),
                        |_| Ok(()),
                    )
                    .optional()
                    .map_err(|_| DbError::Internal)?
                    .is_some();
                if !exists {
                    return Err(invalid_page_marker());
                }
                Some(version_id)
            }
            None => None,
        };
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT version_id, created_at
                FROM item_versions
                WHERE item_id = ?1 AND (?2 IS NULL OR version_id <= ?2)
                ORDER BY version_id DESC
                LIMIT ?3
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let sql_limit = i64::try_from(limit + 1).map_err(|_| DbError::Internal)?;
        let rows = statement
            .query_map((item_id, marker_version, sql_limit), |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    ItemVersionSummaryResponse {
                        version: row.get(0)?,
                        created_at: format_timestamp(row.get(1)?),
                    },
                ))
            })
            .map_err(|_| DbError::Internal)?;
        let mut rows = rows
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)?;
        let next_marker = if rows.len() > limit {
            let (version_id, _) = rows.pop().ok_or(DbError::Internal)?;
            Some(self.encrypt_page_marker(version_id, PageMarkerScope::ItemVersions { item_id })?)
        } else {
            None
        };
        let entries = rows
            .into_iter()
            .map(|(_, response)| response)
            .collect::<Vec<_>>();
        Ok(PaginatedResponse {
            count: entries.len() as u64,
            entries,
            next_marker,
        })
    }

    fn update_item(
        &mut self,
        dir_name: &str,
        item_name: &str,
        request: UpdateItemRequest,
    ) -> Result<(), DbError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| DbError::Internal)?;
        let dir_id = writable_dir_id_in(&transaction, dir_name)?;
        let item_id = public_item_id_in(&transaction, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;

        update_item_in(&transaction, item_id, dir_id, item_name, request)?;

        if transaction.commit().is_err() {
            return Err(DbError::Internal);
        }
        Ok(())
    }

    fn delete_item(&self, dir_name: &str, item_name: &str) -> Result<(), DbError> {
        let dir_id = match dir_row_in(&self.connection, dir_name)? {
            Some((_, bitmask)) if bitmask_has(bitmask, DIR_SYSTEM) => {
                return Err(DbError::AccessDenied);
            }
            Some((id, _)) => id,
            None => return Err(dir_not_found(dir_name)),
        };
        public_item_id_in(&self.connection, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        let changed = self
            .connection
            .execute(
                "DELETE FROM items WHERE dir_id = ?1 AND name = ?2 AND (bitmask & ?3) = 0",
                (dir_id, item_name, ITEM_HIDDEN),
            )
            .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            Err(item_not_found(dir_name, item_name))
        } else {
            Ok(())
        }
    }

    fn restore_item_version(
        &mut self,
        dir_name: &str,
        item_name: &str,
        version: i64,
    ) -> Result<(), DbError> {
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| DbError::Internal)?;
        let dir_id = writable_dir_id_in(&transaction, dir_name)?;
        let item = transaction
            .query_row(
                r#"
                SELECT id, latest_version_id
                FROM items
                WHERE dir_id = ?1 AND name = ?2 AND (bitmask & ?3) = 0
                "#,
                (dir_id, item_name, ITEM_HIDDEN),
                |row| Ok((row.get::<_, i64>(0)?, row.get::<_, i64>(1)?)),
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        let (item_id, latest_version_id) = item;
        if version == latest_version_id {
            return Err(DbError::BadRequest(
                "cannot restore latest version".to_owned(),
            ));
        }

        let source_fields = item_fields_for_version(&transaction, item_id, version)?;
        let source_files = source_files_for_version(&transaction, item_id, version)?;
        let now = now_timestamp();
        let restored_version_id = create_item_version(&transaction, item_id, &source_fields, now)?;

        for (name, source_file) in source_files {
            attach_existing_file(
                &transaction,
                item_id,
                restored_version_id,
                &name,
                &source_file.id,
            )?;
        }

        transaction
            .execute(
                r#"
                UPDATE items
                SET latest_version_id = ?1, updated_at = ?2
                WHERE id = ?3
                "#,
                (restored_version_id, now, item_id),
            )
            .map_err(map_update_error)?;

        transaction.commit().map_err(|_| DbError::Internal)
    }

    fn get_reference(
        &self,
        dir_name: &str,
        item_name: &str,
        field_name: &str,
        version: Option<i64>,
        raw: bool,
        mustauth_satisfied: bool,
    ) -> Result<ReferenceResponse, DbError> {
        let dir_id =
            dir_id_in(&self.connection, dir_name)?.ok_or_else(|| dir_not_found(dir_name))?;
        let (_, item_bitmask) = public_item_row_in(&self.connection, dir_id, item_name)?
            .ok_or_else(|| item_not_found(dir_name, item_name))?;
        if bitmask_has(item_bitmask, ITEM_READ_MUSTAUTH) && !mustauth_satisfied {
            return Err(DbError::AccessDenied);
        }
        let row = item_version_row(&self.connection, dir_id, item_name, version)?;

        let fields: std::collections::HashMap<String, Field> =
            serde_json::from_str(row.fields_json.as_str()).map_err(|_| DbError::Internal)?;
        if let Some(field) = fields.get(field_name) {
            if matches!(field.field_type, FieldType::Totp) {
                let bytes = if raw {
                    Zeroizing::new(field.data.as_bytes().to_vec())
                } else {
                    Zeroizing::new(current_totp(&field.data)?.into_bytes())
                };
                return Ok(ReferenceResponse {
                    body: ReferenceBody::Bytes(bytes),
                    etag: None,
                });
            }

            return Ok(ReferenceResponse {
                body: ReferenceBody::Bytes(Zeroizing::new(field.data.as_bytes().to_vec())),
                etag: None,
            });
        }

        let file = self
            .connection
            .query_row(
                r#"
                SELECT f.id, f.sha256, f.nonce
                FROM item_version_file_mapping m
                JOIN files f ON f.id = m.file_id
                WHERE m.item_id = ?1 AND m.version_id = ?2 AND m.file_name = ?3
                "#,
                (row.item_id, row.version_id, field_name),
                |row| {
                    Ok(StoredFile {
                        id: row.get(0)?,
                        sha256: row.get(1)?,
                        nonce: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or_else(|| reference_not_found(dir_name, item_name, field_name))?;
        let key = self.file_encryption_key()?;
        let mut key_bytes = [0u8; FILE_KEY_BYTES];
        key_bytes.copy_from_slice(&*key);
        let file_store_path = self.file_store_path.clone();
        let etag = file.sha256.clone();
        let (sender, receiver) = mpsc::channel(8);
        std::thread::spawn(move || {
            let key = Zeroizing::new(key_bytes);
            stream_decrypt_stored_file(&file_store_path, &key, &file, sender);
        });
        Ok(ReferenceResponse {
            body: ReferenceBody::Stream(receiver),
            etag: Some(etag),
        })
    }

    fn cleanup_before_unload(
        &mut self,
        version_cutoff: Instant,
        file_cutoff: Instant,
    ) -> Result<(), DbError> {
        self.cleanup_old_item_versions(version_cutoff)?;
        self.cleanup_orphan_files(file_cutoff)
    }

    fn cleanup_old_item_versions(&mut self, cutoff: Instant) -> Result<(), DbError> {
        let cutoff_timestamp = instant_to_timestamp(cutoff);
        let transaction = self
            .connection
            .transaction()
            .map_err(|_| DbError::Internal)?;
        let affected_item_ids = {
            let mut statement = transaction
                .prepare(
                    r#"
                    SELECT DISTINCT item_id
                    FROM item_versions v
                    JOIN items i ON i.id = v.item_id
                    WHERE v.created_at <= ?1
                      AND v.version_id <> i.latest_version_id
                    "#,
                )
                .map_err(|_| DbError::Internal)?;
            statement
                .query_map([cutoff_timestamp], |row| row.get::<_, i64>(0))
                .map_err(|_| DbError::Internal)?
                .collect::<rusqlite::Result<Vec<_>>>()
                .map_err(|_| DbError::Internal)?
        };

        transaction
            .execute(
                r#"
                DELETE FROM item_versions
                WHERE created_at <= ?1
                  AND NOT EXISTS (
                    SELECT 1
                    FROM items i
                    WHERE i.id = item_versions.item_id
                      AND i.latest_version_id = item_versions.version_id
                  )
                "#,
                [cutoff_timestamp],
            )
            .map_err(|_| DbError::Internal)?;

        for item_id in affected_item_ids {
            transaction
                .execute(
                    r#"
                    UPDATE items
                    SET oldest_version_id = (
                        SELECT version_id
                        FROM item_versions
                        WHERE item_id = ?1
                        ORDER BY created_at, version_id
                        LIMIT 1
                    )
                    WHERE id = ?1
                    "#,
                    [item_id],
                )
                .map_err(|_| DbError::Internal)?;
        }

        transaction.commit().map_err(|_| DbError::Internal)
    }

    fn cleanup_orphan_files(&mut self, cutoff: Instant) -> Result<(), DbError> {
        let cutoff_timestamp = instant_to_timestamp(cutoff);
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT id
                FROM files
                WHERE created_at <= ?1
                  AND NOT EXISTS (
                    SELECT 1 FROM item_version_file_mapping WHERE file_id = files.id
                  )
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        let ids = statement
            .query_map([cutoff_timestamp], |row| row.get::<_, Vec<u8>>(0))
            .map_err(|_| DbError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)?;
        drop(statement);

        for id in ids {
            let id_hex = hex_encode(&id);
            let path = file_path(&self.file_store_path, &id_hex);
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(_) => continue,
            }
            self.connection
                .execute(
                    r#"
                    DELETE FROM files
                    WHERE id = ?1
                      AND NOT EXISTS (
                        SELECT 1 FROM item_version_file_mapping WHERE file_id = ?1
                      )
                    "#,
                    [id],
                )
                .map_err(|_| DbError::Internal)?;
        }

        Ok(())
    }

    fn encrypt_page_marker(&self, row_id: i64, scope: PageMarkerScope) -> Result<String, DbError> {
        let key = self.file_encryption_key()?;
        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| DbError::Internal)?;
        let mut tag = [0u8; AES_GCM_TAG_BYTES];
        let ciphertext = aes_256_gcm_encrypt_with_aad(
            &key,
            &nonce,
            &row_id.to_be_bytes(),
            scope.associated_data().as_slice(),
            &mut tag,
        )?;

        let mut token = Vec::with_capacity(1 + AES_GCM_NONCE_BYTES + ciphertext.len() + tag.len());
        token.push(PAGE_MARKER_VERSION);
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&ciphertext);
        token.extend_from_slice(&tag);
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(token))
    }

    fn decrypt_page_marker(&self, marker: &str, scope: PageMarkerScope) -> Result<i64, DbError> {
        let token = general_purpose::URL_SAFE_NO_PAD
            .decode(marker)
            .map_err(|_| invalid_page_marker())?;
        if token.len() != 1 + AES_GCM_NONCE_BYTES + 8 + AES_GCM_TAG_BYTES
            || token[0] != PAGE_MARKER_VERSION
        {
            return Err(invalid_page_marker());
        }

        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        nonce.copy_from_slice(&token[1..1 + AES_GCM_NONCE_BYTES]);
        let ciphertext_start = 1 + AES_GCM_NONCE_BYTES;
        let tag_start = token.len() - AES_GCM_TAG_BYTES;
        let mut tag = [0u8; AES_GCM_TAG_BYTES];
        tag.copy_from_slice(&token[tag_start..]);
        let key = self.file_encryption_key()?;
        let plaintext = aes_256_gcm_decrypt_with_aad(
            &key,
            &nonce,
            &token[ciphertext_start..tag_start],
            scope.associated_data().as_slice(),
            &tag,
        )
        .map_err(|_| invalid_page_marker())?;
        let id = plaintext
            .as_slice()
            .try_into()
            .map(i64::from_be_bytes)
            .map_err(|_| invalid_page_marker())?;
        Ok(id)
    }

    fn encrypt_text_page_marker(
        &self,
        value: &str,
        scope: PageMarkerScope,
    ) -> Result<String, DbError> {
        let key = self.file_encryption_key()?;
        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        getrandom::fill(&mut nonce).map_err(|_| DbError::Internal)?;
        let mut tag = [0u8; AES_GCM_TAG_BYTES];
        let ciphertext = aes_256_gcm_encrypt_with_aad(
            &key,
            &nonce,
            value.as_bytes(),
            scope.associated_data().as_slice(),
            &mut tag,
        )?;

        let mut token = Vec::with_capacity(1 + AES_GCM_NONCE_BYTES + ciphertext.len() + tag.len());
        token.push(PAGE_MARKER_VERSION);
        token.extend_from_slice(&nonce);
        token.extend_from_slice(&ciphertext);
        token.extend_from_slice(&tag);
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(token))
    }

    fn decrypt_text_page_marker(
        &self,
        marker: &str,
        scope: PageMarkerScope,
    ) -> Result<String, DbError> {
        let token = general_purpose::URL_SAFE_NO_PAD
            .decode(marker)
            .map_err(|_| invalid_page_marker())?;
        if token.len() <= 1 + AES_GCM_NONCE_BYTES + AES_GCM_TAG_BYTES
            || token[0] != PAGE_MARKER_VERSION
        {
            return Err(invalid_page_marker());
        }

        let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
        nonce.copy_from_slice(&token[1..1 + AES_GCM_NONCE_BYTES]);
        let ciphertext_start = 1 + AES_GCM_NONCE_BYTES;
        let tag_start = token.len() - AES_GCM_TAG_BYTES;
        let mut tag = [0u8; AES_GCM_TAG_BYTES];
        tag.copy_from_slice(&token[tag_start..]);
        let key = self.file_encryption_key()?;
        let mut plaintext = aes_256_gcm_decrypt_with_aad(
            &key,
            &nonce,
            &token[ciphertext_start..tag_start],
            scope.associated_data().as_slice(),
            &tag,
        )
        .map_err(|_| invalid_page_marker())?;
        String::from_utf8(std::mem::take(&mut *plaintext)).map_err(|_| invalid_page_marker())
    }

    fn file_encryption_key(&self) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, DbError> {
        let dir_id = dir_id_in(&self.connection, INTERNAL_DIR_NAME)?.ok_or(DbError::Internal)?;
        let item_id = item_id_in(&self.connection, dir_id, FILE_ENCRYPTION_KEY_ITEM_NAME)?
            .ok_or(DbError::Internal)?;
        let fields = source_fields(&self.connection, item_id)?;
        let key_hex = fields
            .get("key")
            .filter(|field| matches!(field.field_type, FieldType::String))
            .map(|field| Zeroizing::new(field.data.as_str().to_owned()))
            .ok_or(DbError::Internal)?;
        decode_file_key(key_hex.as_str())
    }

    #[cfg(test)]
    fn test_item_version_count(&self, dir_name: &str, item_name: &str) -> Result<i64, DbError> {
        self.connection
            .query_row(
                r#"
                SELECT count(v.version_id)
                FROM items i
                JOIN dirs d ON d.id = i.dir_id
                JOIN item_versions v ON v.item_id = i.id
                WHERE d.name = ?1 AND i.name = ?2
                "#,
                (dir_name, item_name),
                |row| row.get(0),
            )
            .map_err(|_| DbError::Internal)
    }

    #[cfg(test)]
    fn test_item_versions(&self, dir_name: &str, item_name: &str) -> Result<Vec<i64>, DbError> {
        let mut statement = self
            .connection
            .prepare(
                r#"
                SELECT v.version_id
                FROM items i
                JOIN dirs d ON d.id = i.dir_id
                JOIN item_versions v ON v.item_id = i.id
                WHERE d.name = ?1 AND i.name = ?2
                ORDER BY v.version_id
                "#,
            )
            .map_err(|_| DbError::Internal)?;
        statement
            .query_map((dir_name, item_name), |row| row.get::<_, i64>(0))
            .map_err(|_| DbError::Internal)?
            .collect::<rusqlite::Result<Vec<_>>>()
            .map_err(|_| DbError::Internal)
    }

    #[cfg(test)]
    fn test_set_item_versions_created_at(
        &self,
        dir_name: &str,
        item_name: &str,
        include_latest: bool,
        created_at: i64,
    ) -> Result<(), DbError> {
        let dir_id = public_dir_id_in(&self.connection, dir_name)?.ok_or(DbError::NotFound)?;
        let item_id = item_id_in(&self.connection, dir_id, item_name)?.ok_or(DbError::NotFound)?;
        let latest_version_id: i64 = self
            .connection
            .query_row(
                "SELECT latest_version_id FROM items WHERE id = ?1",
                [item_id],
                |row| row.get(0),
            )
            .map_err(|_| DbError::Internal)?;
        let changed = if include_latest {
            self.connection.execute(
                "UPDATE item_versions SET created_at = ?1 WHERE item_id = ?2",
                (created_at, item_id),
            )
        } else {
            self.connection.execute(
                "UPDATE item_versions SET created_at = ?1 WHERE item_id = ?2 AND version_id <> ?3",
                (created_at, item_id, latest_version_id),
            )
        }
        .map_err(|_| DbError::Internal)?;
        if changed == 0 {
            return Err(DbError::NotFound);
        }
        Ok(())
    }

    #[cfg(test)]
    fn test_oldest_version_is_earliest(
        &self,
        dir_name: &str,
        item_name: &str,
    ) -> Result<bool, DbError> {
        let value: i64 = self
            .connection
            .query_row(
                r#"
                SELECT i.oldest_version_id = (
                    SELECT v.version_id
                    FROM item_versions v
                    WHERE v.item_id = i.id
                    ORDER BY v.created_at, v.version_id
                    LIMIT 1
                )
                FROM items i
                JOIN dirs d ON d.id = i.dir_id
                WHERE d.name = ?1 AND i.name = ?2
                "#,
                (dir_name, item_name),
                |row| row.get(0),
            )
            .map_err(|_| DbError::Internal)?;
        Ok(value != 0)
    }
}

fn bitmask_has(bitmask: i64, flag: i64) -> bool {
    bitmask & flag == flag
}

fn dir_not_found(name: &str) -> DbError {
    DbError::not_found(format!("dir `{name}` not found"))
}

fn item_not_found(dir_name: &str, item_name: &str) -> DbError {
    DbError::not_found(format!("item `{dir_name}/{item_name}` not found"))
}

fn contact_not_found(email: &str) -> DbError {
    DbError::not_found(format!("contact `{email}` not found"))
}

fn job_not_found(job_id: &str) -> DbError {
    DbError::not_found(format!("job `{job_id}` not found"))
}

fn reference_not_found(dir_name: &str, item_name: &str, field_name: &str) -> DbError {
    DbError::not_found(format!(
        "reference `{dir_name}/{item_name}/{field_name}` not found"
    ))
}

fn contact_exists_in(connection: &Connection, email: &str) -> Result<Option<()>, DbError> {
    connection
        .query_row("SELECT 1 FROM contacts WHERE email = ?1", [email], |_| {
            Ok(())
        })
        .optional()
        .map_err(|_| DbError::Internal)
}

fn dir_row_in(connection: &Connection, name: &str) -> Result<Option<(i64, i64)>, DbError> {
    connection
        .query_row(
            "SELECT id, bitmask FROM dirs WHERE name = ?1",
            [name],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| DbError::Internal)
}

fn dir_id_in(connection: &Connection, name: &str) -> Result<Option<i64>, DbError> {
    Ok(dir_row_in(connection, name)?.map(|(id, _)| id))
}

fn public_dir_id_in(connection: &Connection, name: &str) -> Result<Option<i64>, DbError> {
    Ok(dir_row_in(connection, name)?
        .filter(|(_, bitmask)| !bitmask_has(*bitmask, DIR_HIDDEN))
        .map(|(id, _)| id))
}

fn writable_dir_id_in(connection: &Connection, name: &str) -> Result<i64, DbError> {
    let Some((id, bitmask)) = dir_row_in(connection, name)? else {
        return Err(dir_not_found(name));
    };
    if bitmask_has(bitmask, DIR_SYSTEM) {
        return Err(DbError::AccessDenied);
    }
    Ok(id)
}

fn item_row_in(
    connection: &Connection,
    dir_id: i64,
    name: &str,
) -> Result<Option<(i64, i64)>, DbError> {
    connection
        .query_row(
            "SELECT id, bitmask FROM items WHERE dir_id = ?1 AND name = ?2",
            (dir_id, name),
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|_| DbError::Internal)
}

fn item_id_in(connection: &Connection, dir_id: i64, name: &str) -> Result<Option<i64>, DbError> {
    Ok(item_row_in(connection, dir_id, name)?.map(|(id, _)| id))
}

fn public_item_id_in(
    connection: &Connection,
    dir_id: i64,
    name: &str,
) -> Result<Option<i64>, DbError> {
    Ok(public_item_row_in(connection, dir_id, name)?.map(|(id, _)| id))
}

fn public_item_row_in(
    connection: &Connection,
    dir_id: i64,
    name: &str,
) -> Result<Option<(i64, i64)>, DbError> {
    Ok(item_row_in(connection, dir_id, name)?
        .filter(|(_, bitmask)| !bitmask_has(*bitmask, ITEM_HIDDEN)))
}

fn create_item_in(
    transaction: &rusqlite::Transaction<'_>,
    dir_id: i64,
    item_name: &str,
    request: CreateItemRequest,
    source: Option<ItemSource>,
) -> Result<(), DbError> {
    if item_id_in(transaction, dir_id, item_name)?.is_some() {
        return Err(DbError::Conflict("item already exists".to_owned()));
    }

    let mut fields = Default::default();
    let mut source_file_map = std::collections::HashMap::new();
    if let Some(ItemSource::Copy(source)) = source {
        let source_dir_id = public_dir_id_in(transaction, &source.dir_name)?
            .ok_or_else(|| dir_not_found(&source.dir_name))?;
        let source_item_id = public_item_id_in(transaction, source_dir_id, &source.item_name)?
            .ok_or_else(|| item_not_found(&source.dir_name, &source.item_name))?;
        fields = source_fields(transaction, source_item_id)?;
        source_file_map = source_files(transaction, source_item_id)?;
    }

    let request_files = merge_request_fields_and_files(&mut fields, request)?;
    let request_file_names = request_files
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let mut final_file_names = request_file_names.clone();
    final_file_names.extend(source_file_map.keys().cloned());
    validate_field_and_file_name_uniqueness(&fields, &final_file_names)?;

    let now = now_timestamp();
    transaction
        .execute(
            r#"
            INSERT INTO items (dir_id, name, created_at, updated_at)
            VALUES (?1, ?2, ?3, ?3)
            "#,
            (dir_id, item_name, now),
        )
        .map_err(map_insert_error)?;
    let item_id = transaction.last_insert_rowid();
    let version_id = create_item_version(transaction, item_id, &fields, now)?;

    for (name, id) in request_files {
        claim_pending_file(transaction, item_id, version_id, &name, &id)?;
    }

    for (name, source_file) in source_file_map {
        if request_file_names.contains(&name) {
            continue;
        }
        attach_existing_file(transaction, item_id, version_id, &name, &source_file.id)?;
    }

    update_item_version_pointers(transaction, item_id, version_id, version_id)?;

    Ok(())
}

fn move_item_in(
    transaction: &rusqlite::Transaction<'_>,
    destination_dir_id: i64,
    destination_item_name: &str,
    request: CreateItemRequest,
    source: CopySource,
) -> Result<(), DbError> {
    let Some((source_dir_id, source_dir_bitmask)) = dir_row_in(transaction, &source.dir_name)?
    else {
        return Err(dir_not_found(&source.dir_name));
    };
    if bitmask_has(source_dir_bitmask, DIR_SYSTEM) {
        return Err(DbError::AccessDenied);
    }
    let source_item_id = public_item_id_in(transaction, source_dir_id, &source.item_name)?
        .ok_or_else(|| item_not_found(&source.dir_name, &source.item_name))?;

    if !request.fields.is_empty() || !request.files.is_empty() {
        return Err(DbError::BadRequest(
            "move_from request body must be empty".to_owned(),
        ));
    }

    if let Some(destination_item_id) =
        item_id_in(transaction, destination_dir_id, destination_item_name)?
    {
        let _ = destination_item_id;
        return Err(DbError::Conflict("item already exists".to_owned()));
    }

    transaction
        .execute(
            r#"
            UPDATE items
            SET dir_id = ?1, name = ?2, updated_at = ?3
            WHERE id = ?4
            "#,
            (
                destination_dir_id,
                destination_item_name,
                now_timestamp(),
                source_item_id,
            ),
        )
        .map_err(map_update_error)?;

    Ok(())
}

fn update_item_in(
    transaction: &rusqlite::Transaction<'_>,
    item_id: i64,
    destination_dir_id: i64,
    destination_item_name: &str,
    request: UpdateItemRequest,
) -> Result<(), DbError> {
    let mut fields = source_fields(transaction, item_id)?;
    let (request_files, removed_file_names) = merge_update_fields_and_files(&mut fields, request)?;
    let request_file_names = request_files
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    let source_file_map = source_files(transaction, item_id)?;
    let mut final_file_names = source_file_map
        .keys()
        .cloned()
        .collect::<std::collections::HashSet<_>>();
    for name in &removed_file_names {
        final_file_names.remove(name);
    }
    final_file_names.extend(request_file_names.iter().cloned());
    validate_field_and_file_name_uniqueness(&fields, &final_file_names)?;
    let now = now_timestamp();
    let version_id = create_item_version(transaction, item_id, &fields, now)?;

    for (name, source_file) in source_file_map {
        if request_file_names.contains(&name) || removed_file_names.contains(&name) {
            continue;
        }
        attach_existing_file(transaction, item_id, version_id, &name, &source_file.id)?;
    }

    for (name, id) in request_files {
        claim_pending_file(transaction, item_id, version_id, &name, &id)?;
    }

    transaction
        .execute(
            r#"
            UPDATE items
            SET dir_id = ?1, name = ?2, latest_version_id = ?3, updated_at = ?4
            WHERE id = ?5
            "#,
            (
                destination_dir_id,
                destination_item_name,
                version_id,
                now,
                item_id,
            ),
        )
        .map_err(map_update_error)?;

    Ok(())
}

fn merge_request_fields_and_files(
    fields: &mut std::collections::HashMap<String, Field>,
    request: CreateItemRequest,
) -> Result<std::collections::HashMap<String, Vec<u8>>, DbError> {
    let mut names = std::collections::HashSet::new();
    for field in request.fields {
        let name = field.name.clone();
        validate_unique_name(&mut names, "field", &name)?;
        fields.insert(name.clone(), normalize_field(&name, field)?);
    }
    validate_file_inputs(request.files)
}

fn merge_update_fields_and_files(
    fields: &mut std::collections::HashMap<String, Field>,
    request: UpdateItemRequest,
) -> Result<
    (
        std::collections::HashMap<String, Vec<u8>>,
        std::collections::HashSet<String>,
    ),
    DbError,
> {
    let mut field_names = std::collections::HashSet::new();
    for entry in request.fields {
        let name = update_field_name(&entry);
        validate_unique_name(&mut field_names, "field", name)?;
        match entry {
            UpdateFieldEntry::Set(field) => {
                let name = field.name.clone();
                fields.insert(name.clone(), normalize_field(&name, field.into())?);
            }
            UpdateFieldEntry::Remove(_) => {
                fields.remove(name);
            }
        }
    }

    let mut set_files = Vec::new();
    let mut removed_file_names = std::collections::HashSet::new();
    let mut file_names = std::collections::HashSet::new();
    for entry in request.files {
        let name = update_file_name(&entry);
        validate_unique_name(&mut file_names, "file", name)?;
        match entry {
            UpdateFileEntry::Set(file) => {
                set_files.push(file.into());
            }
            UpdateFileEntry::Remove(_) => {
                removed_file_names.insert(name.to_owned());
            }
        }
    }

    validate_file_inputs(set_files).map(|files| (files, removed_file_names))
}

struct ItemVersionRow {
    item_id: i64,
    item_name: String,
    version_id: i64,
    fields_json: Zeroizing<String>,
    item_created_at: i64,
    item_updated_at: i64,
}

fn item_version_row(
    connection: &Connection,
    dir_id: i64,
    item_name: &str,
    version: Option<i64>,
) -> Result<ItemVersionRow, DbError> {
    connection
        .query_row(
            r#"
            SELECT i.id, i.name, v.version_id, v.fields, i.created_at, i.updated_at
            FROM items i
            JOIN item_versions v
              ON v.item_id = i.id
             AND v.version_id = COALESCE(?3, i.latest_version_id)
            WHERE i.dir_id = ?1 AND i.name = ?2
            "#,
            (dir_id, item_name, version),
            |row| {
                Ok(ItemVersionRow {
                    item_id: row.get(0)?,
                    item_name: row.get(1)?,
                    version_id: row.get(2)?,
                    fields_json: Zeroizing::new(row.get(3)?),
                    item_created_at: row.get(4)?,
                    item_updated_at: row.get(5)?,
                })
            },
        )
        .optional()
        .map_err(|_| DbError::Internal)?
        .ok_or(DbError::NotFound)
}

fn source_fields(
    connection: &Connection,
    item_id: i64,
) -> Result<std::collections::HashMap<String, Field>, DbError> {
    let fields_json: Zeroizing<String> = Zeroizing::new(
        connection
            .query_row(
                r#"
            SELECT v.fields
            FROM items i
            JOIN item_versions v ON v.item_id = i.id AND v.version_id = i.latest_version_id
            WHERE i.id = ?1
            "#,
                [item_id],
                |row| row.get::<_, String>(0),
            )
            .map_err(|_| DbError::Internal)?,
    );
    serde_json::from_str(fields_json.as_str()).map_err(|_| DbError::Internal)
}

fn item_fields_for_version(
    connection: &Connection,
    item_id: i64,
    version_id: i64,
) -> Result<std::collections::HashMap<String, Field>, DbError> {
    let fields_json: Zeroizing<String> = Zeroizing::new(
        connection
            .query_row(
                "SELECT fields FROM item_versions WHERE item_id = ?1 AND version_id = ?2",
                (item_id, version_id),
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(|_| DbError::Internal)?
            .ok_or(DbError::NotFound)?,
    );
    serde_json::from_str(fields_json.as_str()).map_err(|_| DbError::Internal)
}

fn item_total_versions(connection: &Connection, item_id: i64) -> Result<u64, DbError> {
    let count = connection
        .query_row(
            "SELECT count(*) FROM item_versions WHERE item_id = ?1",
            [item_id],
            |row| row.get::<_, i64>(0),
        )
        .map_err(|_| DbError::Internal)?;
    u64::try_from(count).map_err(|_| DbError::Internal)
}

fn source_files(
    connection: &Connection,
    item_id: i64,
) -> Result<std::collections::HashMap<String, StoredFile>, DbError> {
    let latest_version_id = connection
        .query_row(
            "SELECT latest_version_id FROM items WHERE id = ?1",
            [item_id],
            |row| row.get(0),
        )
        .map_err(|_| DbError::Internal)?;
    source_files_for_version(connection, item_id, latest_version_id)
}

fn source_files_for_version(
    connection: &Connection,
    item_id: i64,
    version_id: i64,
) -> Result<std::collections::HashMap<String, StoredFile>, DbError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT f.id, m.file_name, f.sha256, f.nonce
            FROM item_version_file_mapping m
            JOIN files f ON f.id = m.file_id
            WHERE m.item_id = ?1 AND m.version_id = ?2
            "#,
        )
        .map_err(|_| DbError::Internal)?;
    let rows = statement
        .query_map((item_id, version_id), |row| {
            let name = row.get::<_, String>(1)?;
            Ok((
                name.clone(),
                StoredFile {
                    id: row.get(0)?,
                    sha256: row.get(2)?,
                    nonce: row.get(3)?,
                },
            ))
        })
        .map_err(|_| DbError::Internal)?;
    rows.collect::<rusqlite::Result<_>>()
        .map_err(|_| DbError::Internal)
}

fn file_metadata(
    connection: &Connection,
    item_id: i64,
    version_id: i64,
) -> Result<std::collections::HashMap<String, FileMetadata>, DbError> {
    let mut statement = connection
        .prepare(
            r#"
            SELECT m.file_name, f.size
            FROM item_version_file_mapping m
            JOIN files f ON f.id = m.file_id
            WHERE m.item_id = ?1 AND m.version_id = ?2
            ORDER BY m.file_name
            "#,
        )
        .map_err(|_| DbError::Internal)?;
    let rows = statement
        .query_map((item_id, version_id), |row| {
            Ok((
                row.get::<_, String>(0)?,
                FileMetadata {
                    size: row.get::<_, i64>(1)? as u64,
                },
            ))
        })
        .map_err(|_| DbError::Internal)?;
    rows.collect::<rusqlite::Result<_>>()
        .map_err(|_| DbError::Internal)
}

fn field_entries(fields: std::collections::HashMap<String, Field>) -> Vec<FieldEntry> {
    let mut entries: Vec<_> = fields
        .into_iter()
        .map(|(name, field)| FieldEntry::from_named(name, field))
        .collect();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

fn file_metadata_entries(
    files: std::collections::HashMap<String, FileMetadata>,
) -> Vec<FileMetadataEntry> {
    let mut entries: Vec<_> = files
        .into_iter()
        .map(|(name, file)| FileMetadataEntry {
            name,
            size: file.size,
        })
        .collect();
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    entries
}

#[derive(Debug, Clone)]
struct StoredFile {
    id: Vec<u8>,
    sha256: String,
    nonce: Vec<u8>,
}

fn validate_file_inputs(
    files: Vec<FileInput>,
) -> Result<std::collections::HashMap<String, Vec<u8>>, DbError> {
    let mut names = std::collections::HashSet::new();
    let mut seen = std::collections::HashSet::new();
    let mut validated = std::collections::HashMap::new();
    for input in files {
        let name = input.name;
        validate_name(&name)?;
        if !names.insert(name.clone()) {
            return Err(DbError::BadRequest(format!("duplicate file name `{name}`")));
        }
        let id = hex_decode_exact(&input.id, FILE_ID_BYTES).ok_or_else(|| {
            DbError::BadRequest("file id must be 32 lowercase hex characters".to_owned())
        })?;
        if !seen.insert(id.clone()) {
            return Err(DbError::BadRequest(
                "file id must not be used more than once".to_owned(),
            ));
        }
        validated.insert(name, id);
    }
    Ok(validated)
}

fn validate_sha256_hex(value: &str) -> Result<(), DbError> {
    if hex_decode_exact(value, 32).is_some() {
        Ok(())
    } else {
        Err(DbError::BadRequest(
            "sha256 must be 64 lowercase hex characters".to_owned(),
        ))
    }
}

fn validate_job_id(value: &str) -> Result<(), DbError> {
    if hex_decode_exact(value, 16).is_some() {
        Ok(())
    } else {
        Err(DbError::BadRequest(
            "job id must be 32 lowercase hex characters".to_owned(),
        ))
    }
}

pub(crate) fn validate_file_upload_size(size: u64) -> Result<(), DbError> {
    if size > MAX_FILE_UPLOAD_BYTES {
        Err(DbError::BadRequest("file too large".to_owned()))
    } else {
        Ok(())
    }
}

fn map_settings_error(error: SettingsError) -> DbError {
    match error {
        SettingsError::InvalidValue => DbError::BadRequest("invalid setting value".to_owned()),
        SettingsError::UnknownSetting => DbError::NotFound,
    }
}

fn map_named_settings_error(error: SettingsError, name: &str) -> DbError {
    match error {
        SettingsError::InvalidValue => DbError::BadRequest("invalid setting value".to_owned()),
        SettingsError::UnknownSetting => DbError::not_found(format!("setting `{name}` not found")),
    }
}

fn page_limit(count: u64) -> Result<usize, DbError> {
    if !(1..=200).contains(&count) {
        return Err(DbError::BadRequest(
            "count must be between 1 and 200".to_owned(),
        ));
    }
    usize::try_from(count).map_err(|_| DbError::Internal)
}

fn invalid_page_marker() -> DbError {
    DbError::BadRequest("invalid marker".to_owned())
}

fn claim_pending_file(
    transaction: &rusqlite::Transaction<'_>,
    item_id: i64,
    version_id: i64,
    name: &str,
    id: &[u8],
) -> Result<(), DbError> {
    attach_existing_file(transaction, item_id, version_id, name, id)
}

fn attach_existing_file(
    transaction: &rusqlite::Transaction<'_>,
    item_id: i64,
    version_id: i64,
    name: &str,
    id: &[u8],
) -> Result<(), DbError> {
    let exists = transaction
        .query_row("SELECT 1 FROM files WHERE id = ?1", [id], |_| Ok(()))
        .optional()
        .map_err(|_| DbError::Internal)?
        .is_some();
    if !exists {
        return Err(DbError::BadRequest("file not found".to_owned()));
    }

    transaction
        .execute(
            r#"
            INSERT INTO item_version_file_mapping (item_id, version_id, file_id, file_name)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            (item_id, version_id, id, name),
        )
        .map(|_| ())
        .map_err(map_insert_error)
}

fn create_item_version(
    transaction: &rusqlite::Transaction<'_>,
    item_id: i64,
    fields: &std::collections::HashMap<String, Field>,
    created_at: i64,
) -> Result<i64, DbError> {
    let version_id: i64 = transaction
        .query_row(
            "SELECT COALESCE(latest_version_id, 0) + 1 FROM items WHERE id = ?1",
            [item_id],
            |row| row.get(0),
        )
        .map_err(|_| DbError::Internal)?;
    let fields_json = Zeroizing::new(serde_json::to_string(fields).map_err(|_| DbError::Internal)?);
    transaction
        .execute(
            r#"
            INSERT INTO item_versions (version_id, item_id, fields, created_at)
            VALUES (?1, ?2, ?3, ?4)
            "#,
            (version_id, item_id, fields_json.as_str(), created_at),
        )
        .map_err(map_insert_error)?;
    Ok(version_id)
}

fn update_item_version_pointers(
    transaction: &rusqlite::Transaction<'_>,
    item_id: i64,
    oldest_version_id: i64,
    latest_version_id: i64,
) -> Result<(), DbError> {
    transaction
        .execute(
            r#"
            UPDATE items
            SET oldest_version_id = ?1, latest_version_id = ?2
            WHERE id = ?3
            "#,
            (oldest_version_id, latest_version_id, item_id),
        )
        .map(|_| ())
        .map_err(|_| DbError::Internal)
}

fn stream_decrypt_stored_file(
    file_store_path: &Path,
    key: &[u8; FILE_KEY_BYTES],
    file: &StoredFile,
    sender: mpsc::Sender<Result<Zeroizing<Vec<u8>>, DbError>>,
) {
    let id_hex = hex_encode(&file.id);
    let result = stream_decrypt_records(
        file_path(file_store_path, &id_hex),
        key,
        &file.nonce,
        &sender,
    );
    if let Err(error) = result {
        let _ = sender.blocking_send(Err(error));
    }
}

fn write_temp_path(file_store_path: &Path, id_hex: &str) -> Result<PathBuf, DbError> {
    let temp_dir = file_store_path.join("tmp");
    create_private_dir_all(&temp_dir)?;
    Ok(temp_dir.join(format!("{id_hex}.tmp")))
}

fn create_private_dir_all(path: &Path) -> Result<(), DbError> {
    fs::create_dir_all(path).map_err(|_| DbError::Internal)?;
    fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))
        .map_err(|_| DbError::Internal)
}

fn create_private_blob_file(path: &Path) -> Result<fs::File, DbError> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(PRIVATE_FILE_MODE)
        .open(path)
        .map_err(|_| DbError::Internal)
}

fn decode_file_key(key_hex: &str) -> Result<Zeroizing<[u8; FILE_KEY_BYTES]>, DbError> {
    let key = Zeroizing::new(hex_decode_exact(key_hex, FILE_KEY_BYTES).ok_or(DbError::Internal)?);
    let mut bytes = [0u8; FILE_KEY_BYTES];
    bytes.copy_from_slice(&key);
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
fn insert_test_file_key(connection: &Connection) {
    connection
        .execute(
            r#"
            INSERT INTO dirs (name, bitmask, created_at, updated_at)
            VALUES (?1, ?2, 1, 1)
            "#,
            (INTERNAL_DIR_NAME, DIR_HIDDEN | DIR_SYSTEM),
        )
        .unwrap();
    insert_test_internal_key_item(
        connection,
        FILE_ENCRYPTION_KEY_ITEM_NAME,
        ITEM_HIDDEN | ITEM_READ_MUSTAUTH,
        r#"{"key":{"type":"string","concealed":true,"data":"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"}}"#,
    );
    insert_test_internal_key_item(
        connection,
        AGE_PUBLIC_KEY_ITEM_NAME,
        0,
        r#"{"key":{"type":"string","concealed":false,"data":"age1unused"}}"#,
    );
    insert_test_internal_key_item(
        connection,
        AGE_PRIVATE_KEY_ITEM_NAME,
        ITEM_HIDDEN | ITEM_READ_MUSTAUTH,
        r#"{"key":{"type":"string","concealed":true,"data":"AGE-SECRET-KEY-unused"}}"#,
    );
}

#[cfg(test)]
fn insert_test_internal_key_item(
    connection: &Connection,
    item_name: &str,
    bitmask: i64,
    fields: &str,
) {
    connection
        .execute(
            r#"
            INSERT INTO items (dir_id, name, bitmask, created_at, updated_at)
            VALUES (
                (SELECT id FROM dirs WHERE name = ?1),
                ?2,
                ?3,
                1,
                1
            )
            "#,
            (INTERNAL_DIR_NAME, item_name, bitmask),
        )
        .unwrap();
    let item_id = connection.last_insert_rowid();
    connection
        .execute(
            r#"
            INSERT INTO item_versions (item_id, version_id, fields, created_at)
            VALUES (?1, 1, ?2, 1)
            "#,
            (item_id, fields),
        )
        .unwrap();
    connection
        .execute(
            "UPDATE items SET oldest_version_id = 1, latest_version_id = 1 WHERE id = ?1",
            [item_id],
        )
        .unwrap();
}

#[cfg(test)]
fn insert_test_user_settings(connection: &Connection) {
    connection
        .execute(
            "INSERT INTO system_settings (name, value) VALUES (?1, ?2), (?3, ?4)",
            (
                AUTH_TTL_SETTING,
                crate::settings::auth_ttl_setting().default,
                GC_SECONDS_SETTING,
                crate::settings::gc_seconds_setting().default,
            ),
        )
        .unwrap();
}

fn encrypt_chunk_record(
    writer: &mut impl Write,
    key: &[u8; FILE_KEY_BYTES],
    nonce_prefix: &[u8; FILE_NONCE_PREFIX_BYTES],
    counter: u64,
    plaintext: &[u8],
) -> Result<[u8; AES_GCM_TAG_BYTES], DbError> {
    if plaintext.len() > FILE_RECORD_PLAINTEXT_BYTES {
        return Err(DbError::BadRequest("file chunk too large".to_owned()));
    }
    let length = u32::try_from(plaintext.len()).map_err(|_| DbError::Internal)?;
    let nonce = record_nonce(nonce_prefix, counter)?;
    let mut tag = [0u8; AES_GCM_TAG_BYTES];
    let ciphertext = aes_256_gcm_encrypt(key, &nonce, plaintext, &mut tag)?;
    writer
        .write_all(&length.to_be_bytes())
        .and_then(|()| writer.write_all(&tag))
        .and_then(|()| writer.write_all(&ciphertext))
        .map_err(|_| DbError::Internal)?;
    Ok(tag)
}

fn decrypt_chunk_record(
    reader: &mut impl Read,
    key: &[u8; FILE_KEY_BYTES],
    nonce_prefix: &[u8],
    counter: u64,
) -> Result<Option<Zeroizing<Vec<u8>>>, DbError> {
    if nonce_prefix.len() != FILE_NONCE_PREFIX_BYTES {
        return Err(DbError::Internal);
    }
    let mut length_bytes = [0u8; 4];
    if !read_record_prefix(reader, &mut length_bytes)? {
        return Ok(None);
    }
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length > FILE_RECORD_PLAINTEXT_BYTES {
        return Err(DbError::Internal);
    }
    let mut tag = [0u8; AES_GCM_TAG_BYTES];
    reader.read_exact(&mut tag).map_err(|_| DbError::Internal)?;
    let mut ciphertext = vec![0u8; length];
    reader
        .read_exact(&mut ciphertext)
        .map_err(|_| DbError::Internal)?;
    let mut prefix = [0u8; FILE_NONCE_PREFIX_BYTES];
    prefix.copy_from_slice(nonce_prefix);
    let nonce = record_nonce(&prefix, counter)?;
    decrypt_file(key, &nonce, &tag, &ciphertext).map(Some)
}

fn read_record_prefix(reader: &mut impl Read, buffer: &mut [u8; 4]) -> Result<bool, DbError> {
    match reader.read_exact(buffer) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(_) => Err(DbError::Internal),
    }
}

fn record_nonce(
    nonce_prefix: &[u8; FILE_NONCE_PREFIX_BYTES],
    counter: u64,
) -> Result<[u8; AES_GCM_NONCE_BYTES], DbError> {
    if counter >= MAX_FILE_RECORDS {
        return Err(DbError::BadRequest("file too large".to_owned()));
    }
    let counter = u32::try_from(counter).map_err(|_| DbError::Internal)?;
    let mut nonce = [0u8; AES_GCM_NONCE_BYTES];
    nonce[..FILE_NONCE_PREFIX_BYTES].copy_from_slice(nonce_prefix);
    nonce[FILE_NONCE_PREFIX_BYTES..].copy_from_slice(&counter.to_be_bytes());
    Ok(nonce)
}

fn stream_decrypt_records(
    path: PathBuf,
    key: &[u8; FILE_KEY_BYTES],
    base_nonce: &[u8],
    sender: &mpsc::Sender<Result<Zeroizing<Vec<u8>>, DbError>>,
) -> Result<(), DbError> {
    let mut file = std::fs::File::open(path).map_err(|_| DbError::Internal)?;
    let mut counter = 0_u64;
    loop {
        match decrypt_chunk_record(&mut file, key, base_nonce, counter) {
            Ok(Some(chunk)) => {
                if !chunk.is_empty() && sender.blocking_send(Ok(chunk)).is_err() {
                    return Ok(());
                }
            }
            Ok(None) => return Ok(()),
            Err(error) => return Err(error),
        }
        counter = counter.checked_add(1).ok_or(DbError::Internal)?;
    }
}

fn decrypt_file(
    key: &[u8; FILE_KEY_BYTES],
    nonce: &[u8],
    tag: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>, DbError> {
    if nonce.len() != AES_GCM_NONCE_BYTES || tag.len() != AES_GCM_TAG_BYTES {
        return Err(DbError::Internal);
    }
    let mut tag_bytes = [0u8; AES_GCM_TAG_BYTES];
    tag_bytes.copy_from_slice(tag);
    aes_256_gcm_decrypt(key, nonce, ciphertext, &tag_bytes)
}

fn file_path(root: &Path, id_hex: &str) -> PathBuf {
    root.join(&id_hex[..2]).join(id_hex)
}

#[cfg(test)]
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    hex_encode(&Sha256::digest(bytes))
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn hex_decode_exact(value: &str, bytes: usize) -> Option<Vec<u8>> {
    if value.len() != bytes * 2 {
        return None;
    }
    let mut decoded = Vec::with_capacity(bytes);
    for pair in value.as_bytes().chunks_exact(2) {
        decoded.push((hex_value(pair[0])? << 4) | hex_value(pair[1])?);
    }
    Some(decoded)
}

fn hex_value(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn instant_to_timestamp(instant: Instant) -> i64 {
    let now = Instant::now();
    if let Some(age) = now.checked_duration_since(instant) {
        now_timestamp() - age.as_secs() as i64
    } else {
        now_timestamp()
    }
}

fn aes_256_gcm_encrypt(
    key: &[u8; FILE_KEY_BYTES],
    nonce: &[u8; AES_GCM_NONCE_BYTES],
    plaintext: &[u8],
    tag: &mut [u8; AES_GCM_TAG_BYTES],
) -> Result<Vec<u8>, DbError> {
    aes_256_gcm_encrypt_with_aad(key, nonce, plaintext, &[], tag)
}

fn aes_256_gcm_encrypt_with_aad(
    key: &[u8; FILE_KEY_BYTES],
    nonce: &[u8; AES_GCM_NONCE_BYTES],
    plaintext: &[u8],
    associated_data: &[u8],
    tag: &mut [u8; AES_GCM_TAG_BYTES],
) -> Result<Vec<u8>, DbError> {
    let input_len = i32::try_from(plaintext.len())
        .map_err(|_| DbError::BadRequest("file too large".to_owned()))?;
    let associated_data_len =
        i32::try_from(associated_data.len()).map_err(|_| DbError::Internal)?;
    unsafe {
        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(DbError::Internal);
        }
        let _guard = CipherContext(ctx);
        if openssl_sys::EVP_EncryptInit_ex(
            ctx,
            openssl_sys::EVP_aes_256_gcm(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        if openssl_sys::EVP_CIPHER_CTX_ctrl(
            ctx,
            openssl_sys::EVP_CTRL_GCM_SET_IVLEN,
            AES_GCM_NONCE_BYTES as i32,
            std::ptr::null_mut(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        if openssl_sys::EVP_EncryptInit_ex(
            ctx,
            std::ptr::null(),
            std::ptr::null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) != 1
        {
            return Err(DbError::Internal);
        }

        if !associated_data.is_empty() {
            let mut aad_written = 0;
            if openssl_sys::EVP_EncryptUpdate(
                ctx,
                std::ptr::null_mut(),
                &mut aad_written,
                associated_data.as_ptr(),
                associated_data_len,
            ) != 1
            {
                return Err(DbError::Internal);
            }
        }

        let mut ciphertext = vec![0u8; plaintext.len() + AES_GCM_TAG_BYTES];
        let mut written = 0;
        if openssl_sys::EVP_EncryptUpdate(
            ctx,
            ciphertext.as_mut_ptr(),
            &mut written,
            plaintext.as_ptr(),
            input_len,
        ) != 1
        {
            return Err(DbError::Internal);
        }
        let mut total = written as usize;
        let mut final_written = 0;
        if openssl_sys::EVP_EncryptFinal_ex(
            ctx,
            ciphertext.as_mut_ptr().add(total),
            &mut final_written,
        ) != 1
        {
            return Err(DbError::Internal);
        }
        total += final_written as usize;
        ciphertext.truncate(total);
        if openssl_sys::EVP_CIPHER_CTX_ctrl(
            ctx,
            openssl_sys::EVP_CTRL_GCM_GET_TAG,
            AES_GCM_TAG_BYTES as i32,
            tag.as_mut_ptr().cast(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        Ok(ciphertext)
    }
}

fn aes_256_gcm_decrypt(
    key: &[u8; FILE_KEY_BYTES],
    nonce: &[u8],
    ciphertext: &[u8],
    tag: &[u8; AES_GCM_TAG_BYTES],
) -> Result<Zeroizing<Vec<u8>>, DbError> {
    aes_256_gcm_decrypt_with_aad(key, nonce, ciphertext, &[], tag)
}

fn aes_256_gcm_decrypt_with_aad(
    key: &[u8; FILE_KEY_BYTES],
    nonce: &[u8],
    ciphertext: &[u8],
    associated_data: &[u8],
    tag: &[u8; AES_GCM_TAG_BYTES],
) -> Result<Zeroizing<Vec<u8>>, DbError> {
    let input_len = i32::try_from(ciphertext.len()).map_err(|_| DbError::Internal)?;
    let associated_data_len =
        i32::try_from(associated_data.len()).map_err(|_| DbError::Internal)?;
    unsafe {
        let ctx = openssl_sys::EVP_CIPHER_CTX_new();
        if ctx.is_null() {
            return Err(DbError::Internal);
        }
        let _guard = CipherContext(ctx);
        if openssl_sys::EVP_DecryptInit_ex(
            ctx,
            openssl_sys::EVP_aes_256_gcm(),
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        if openssl_sys::EVP_CIPHER_CTX_ctrl(
            ctx,
            openssl_sys::EVP_CTRL_GCM_SET_IVLEN,
            AES_GCM_NONCE_BYTES as i32,
            std::ptr::null_mut(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        if openssl_sys::EVP_DecryptInit_ex(
            ctx,
            std::ptr::null(),
            std::ptr::null_mut(),
            key.as_ptr(),
            nonce.as_ptr(),
        ) != 1
        {
            return Err(DbError::Internal);
        }

        if !associated_data.is_empty() {
            let mut aad_written = 0;
            if openssl_sys::EVP_DecryptUpdate(
                ctx,
                std::ptr::null_mut(),
                &mut aad_written,
                associated_data.as_ptr(),
                associated_data_len,
            ) != 1
            {
                return Err(DbError::Internal);
            }
        }

        let mut plaintext = Zeroizing::new(vec![0u8; ciphertext.len()]);
        let mut written = 0;
        if openssl_sys::EVP_DecryptUpdate(
            ctx,
            plaintext.as_mut_ptr(),
            &mut written,
            ciphertext.as_ptr(),
            input_len,
        ) != 1
        {
            return Err(DbError::Internal);
        }
        if openssl_sys::EVP_CIPHER_CTX_ctrl(
            ctx,
            openssl_sys::EVP_CTRL_GCM_SET_TAG,
            AES_GCM_TAG_BYTES as i32,
            tag.as_ptr().cast_mut().cast(),
        ) != 1
        {
            return Err(DbError::Internal);
        }
        let mut final_written = 0;
        if openssl_sys::EVP_DecryptFinal_ex(
            ctx,
            plaintext.as_mut_ptr().add(written as usize),
            &mut final_written,
        ) != 1
        {
            return Err(DbError::Internal);
        }
        plaintext.truncate(written as usize + final_written as usize);
        Ok(plaintext)
    }
}

struct CipherContext(*mut openssl_sys::EVP_CIPHER_CTX);

impl Drop for CipherContext {
    fn drop(&mut self) {
        unsafe {
            openssl_sys::EVP_CIPHER_CTX_free(self.0);
        }
    }
}

fn normalize_field(name: &str, field: CreateField) -> Result<Field, DbError> {
    if matches!(field.field_type, FieldType::Totp) {
        validate_totp_url(&field.data)?;
    }

    let concealed = matches!(field.field_type, FieldType::Totp)
        || field.concealed.unwrap_or_else(|| inferred_concealed(name));
    Ok(Field {
        field_type: field.field_type,
        concealed,
        data: field.data,
    })
}

fn mask_concealed_fields(fields: &mut std::collections::HashMap<String, Field>) {
    for field in fields.values_mut() {
        if field.concealed {
            field.data = "******".into();
        }
    }
}

fn resolve_totp_fields(
    fields: &mut std::collections::HashMap<String, Field>,
) -> Result<(), DbError> {
    for field in fields.values_mut() {
        if matches!(field.field_type, FieldType::Totp) {
            field.data = current_totp(&field.data)?.into();
        }
    }

    Ok(())
}

fn validate_totp_url(data: &str) -> Result<(), DbError> {
    parse_totp_url(data).map(|_| ())
}

fn current_totp(data: &str) -> Result<String, DbError> {
    generate_totp_at(data, now_timestamp() as u64)
}

fn generate_totp_at(data: &str, unix_time: u64) -> Result<String, DbError> {
    let params = parse_totp_url(data)?;
    let counter = unix_time / params.period;
    let counter_bytes = counter.to_be_bytes();
    let code = match params.algorithm {
        TotpAlgorithm::Sha1 => {
            let mut mac =
                Hmac::<Sha1>::new_from_slice(&params.secret).map_err(|_| invalid_totp_field())?;
            mac.update(&counter_bytes);
            truncate_hmac(mac.finalize().into_bytes().as_slice(), params.digits)
        }
        TotpAlgorithm::Sha256 => {
            let mut mac =
                Hmac::<Sha256>::new_from_slice(&params.secret).map_err(|_| invalid_totp_field())?;
            mac.update(&counter_bytes);
            truncate_hmac(mac.finalize().into_bytes().as_slice(), params.digits)
        }
        TotpAlgorithm::Sha512 => {
            let mut mac =
                Hmac::<Sha512>::new_from_slice(&params.secret).map_err(|_| invalid_totp_field())?;
            mac.update(&counter_bytes);
            truncate_hmac(mac.finalize().into_bytes().as_slice(), params.digits)
        }
    };

    Ok(format!("{code:0width$}", width = params.digits as usize))
}

fn truncate_hmac(result: &[u8], digits: u32) -> u64 {
    let offset = (result[result.len() - 1] & 0x0f) as usize;
    let binary = ((u32::from(result[offset]) & 0x7f) << 24)
        | (u32::from(result[offset + 1]) << 16)
        | (u32::from(result[offset + 2]) << 8)
        | u32::from(result[offset + 3]);

    u64::from(binary) % 10_u64.pow(digits)
}

struct TotpParams {
    secret: Zeroizing<Vec<u8>>,
    digits: u32,
    period: u64,
    algorithm: TotpAlgorithm,
}

enum TotpAlgorithm {
    Sha1,
    Sha256,
    Sha512,
}

fn parse_totp_url(data: &str) -> Result<TotpParams, DbError> {
    let url = Url::parse(data).map_err(|_| invalid_totp_field())?;
    if url.scheme() != "otpauth" || url.host_str() != Some("totp") {
        return Err(invalid_totp_field());
    }

    let mut secret = None;
    let mut digits = 6;
    let mut period = 30;
    let mut algorithm = TotpAlgorithm::Sha1;

    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "secret" => secret = Some(decode_base32_secret(&value)?),
            "digits" => digits = parse_totp_digits(&value)?,
            "period" => period = parse_totp_period(&value)?,
            "algorithm" => algorithm = parse_totp_algorithm(&value)?,
            _ => {}
        }
    }

    Ok(TotpParams {
        secret: secret.ok_or_else(invalid_totp_field)?,
        digits,
        period,
        algorithm,
    })
}

fn decode_base32_secret(secret: &str) -> Result<Zeroizing<Vec<u8>>, DbError> {
    if secret.is_empty()
        || secret.contains('=')
        || secret
            .chars()
            .any(|character| character.is_ascii_whitespace())
    {
        return Err(invalid_totp_field());
    }

    match secret.len() % 8 {
        0 | 2 | 4 | 5 | 7 => {}
        _ => return Err(invalid_totp_field()),
    }

    let normalized = Zeroizing::new(secret.to_ascii_uppercase());
    let decoded = BASE32_NOPAD
        .decode(normalized.as_bytes())
        .map_err(|_| invalid_totp_field())?;
    Ok(Zeroizing::new(decoded))
}

fn parse_totp_digits(digits: &str) -> Result<u32, DbError> {
    let digits = digits.parse().map_err(|_| invalid_totp_field())?;
    if (1..=10).contains(&digits) {
        Ok(digits)
    } else {
        Err(invalid_totp_field())
    }
}

fn parse_totp_period(period: &str) -> Result<u64, DbError> {
    let period = period.parse().map_err(|_| invalid_totp_field())?;
    if period > 0 {
        Ok(period)
    } else {
        Err(invalid_totp_field())
    }
}

fn parse_totp_algorithm(algorithm: &str) -> Result<TotpAlgorithm, DbError> {
    match algorithm.to_ascii_uppercase().as_str() {
        "SHA1" => Ok(TotpAlgorithm::Sha1),
        "SHA256" => Ok(TotpAlgorithm::Sha256),
        "SHA512" => Ok(TotpAlgorithm::Sha512),
        _ => Err(invalid_totp_field()),
    }
}

fn invalid_totp_field() -> DbError {
    DbError::BadRequest(
        "totp field data must be an otpauth://totp URL with an unpadded Base32 secret and valid parameters".to_owned(),
    )
}

fn validate_name(name: &str) -> Result<(), DbError> {
    if name.is_empty() {
        Err(DbError::BadRequest("name must not be empty".to_owned()))
    } else {
        Ok(())
    }
}

fn validate_unique_name(
    names: &mut std::collections::HashSet<String>,
    kind: &str,
    name: &str,
) -> Result<(), DbError> {
    validate_name(name)?;
    if names.insert(name.to_owned()) {
        Ok(())
    } else {
        Err(DbError::BadRequest(format!(
            "duplicate {kind} name `{name}`"
        )))
    }
}

fn validate_field_and_file_name_uniqueness(
    fields: &std::collections::HashMap<String, Field>,
    file_names: &std::collections::HashSet<String>,
) -> Result<(), DbError> {
    if let Some(name) = fields.keys().find(|name| file_names.contains(*name)) {
        return Err(DbError::BadRequest(format!(
            "field and file names must be unique: `{name}`"
        )));
    }
    Ok(())
}

fn update_field_name(entry: &UpdateFieldEntry) -> &str {
    match entry {
        UpdateFieldEntry::Set(field) => &field.name,
        UpdateFieldEntry::Remove(remove) => &remove.name,
    }
}

fn update_file_name(entry: &UpdateFileEntry) -> &str {
    match entry {
        UpdateFileEntry::Set(file) => &file.name,
        UpdateFileEntry::Remove(remove) => &remove.name,
    }
}

fn validate_age_public_key(age_public_key: &str) -> Result<(), DbError> {
    if age_public_key.is_empty() {
        return Err(DbError::BadRequest(
            "age public key must not be empty".to_owned(),
        ));
    }
    age::x25519::Recipient::from_str(age_public_key)
        .map(|_| ())
        .map_err(|_| DbError::BadRequest("age public key is invalid".to_owned()))
}

fn validate_item_name(name: &str) -> Result<(), DbError> {
    validate_name(name)?;
    if name.chars().count() > 255 {
        Err(DbError::BadRequest(
            "item name must be 255 characters or shorter".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn now_timestamp() -> i64 {
    Utc::now().timestamp()
}

fn format_timestamp(timestamp: i64) -> String {
    DateTime::from_timestamp(timestamp, 0)
        .unwrap_or(DateTime::<Utc>::UNIX_EPOCH)
        .to_rfc3339_opts(SecondsFormat::Secs, true)
}

fn map_insert_error(error: rusqlite::Error) -> DbError {
    match sqlite_error_code(&error) {
        Some(rusqlite::ErrorCode::ConstraintViolation) => {
            DbError::Conflict("resource already exists".to_owned())
        }
        _ => DbError::Internal,
    }
}

fn map_update_error(error: rusqlite::Error) -> DbError {
    match sqlite_error_code(&error) {
        Some(rusqlite::ErrorCode::ConstraintViolation) => {
            DbError::Conflict("resource already exists".to_owned())
        }
        _ => DbError::Internal,
    }
}

fn sqlite_error_code(error: &rusqlite::Error) -> Option<rusqlite::ErrorCode> {
    match error {
        rusqlite::Error::SqliteFailure(error, _) => Some(error.code),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::time::{Duration, Instant};

    use data_encoding::BASE32_NOPAD;
    use rusqlite::Connection;
    use tempfile::{NamedTempFile, TempDir};
    use zeroize::Zeroizing;

    use super::{
        AgentState, AuthCache, CreateContactRequest, CreateItemRequest, DATABASE_READER_WORKERS,
        DbError, DbHandle, FILE_RECORD_PLAINTEXT_BYTES, MAX_FILE_RECORDS, MAX_FILE_UPLOAD_BYTES,
        PRIVATE_DIR_MODE, PRIVATE_FILE_MODE, PageRequest, UnlockError, UpdateContactRequest,
    };
    use crate::agent::process::ProcessChainHash;

    const AUTH_TTL: Duration = Duration::from_secs(900);
    const CLEANUP_INTERVAL: Duration = Duration::from_secs(3600);

    fn field<'a>(item: &'a super::ItemResponse, name: &str) -> &'a super::FieldEntry {
        item.fields
            .iter()
            .find(|field| field.name == name)
            .expect("field exists")
    }

    fn file<'a>(item: &'a super::ItemResponse, name: &str) -> &'a super::FileMetadataEntry {
        item.files
            .iter()
            .find(|file| file.name == name)
            .expect("file exists")
    }

    fn has_field(item: &super::ItemResponse, name: &str) -> bool {
        item.fields.iter().any(|field| field.name == name)
    }

    fn has_file(item: &super::ItemResponse, name: &str) -> bool {
        item.files.iter().any(|file| file.name == name)
    }

    fn item_request<T>(mut value: serde_json::Value) -> serde_json::Result<T>
    where
        T: serde::de::DeserializeOwned,
    {
        map_named_entries(&mut value, "fields");
        map_named_entries(&mut value, "files");
        serde_json::from_value(value)
    }

    fn map_named_entries(value: &mut serde_json::Value, key: &str) {
        let Some(entries) = value.get_mut(key) else {
            return;
        };
        let Some(map) = entries.as_object_mut() else {
            return;
        };
        let named = std::mem::take(map)
            .into_iter()
            .map(|(name, mut entry)| {
                if let Some(entry) = entry.as_object_mut() {
                    entry.insert("name".to_owned(), serde_json::Value::String(name));
                }
                entry
            })
            .collect();
        *entries = serde_json::Value::Array(named);
    }

    fn legacy_overlap_database() -> (TempDir, DbHandle) {
        let tempdir = tempfile::tempdir().unwrap();
        let database_path = tempdir.path().join("legacy-overlap.db");
        let mut writer = Connection::open(&database_path).unwrap();
        writer.pragma_update(None, "foreign_keys", "ON").unwrap();
        writer
            .execute_batch(
                r#"
                CREATE TABLE dirs (
                    id INTEGER PRIMARY KEY,
                    name TEXT UNIQUE NOT NULL,
                    bitmask INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );
                CREATE TABLE items (
                    id INTEGER PRIMARY KEY,
                    dir_id INTEGER NOT NULL REFERENCES dirs (id) ON DELETE CASCADE,
                    name TEXT NOT NULL,
                    bitmask INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL,
                    oldest_version_id INTEGER,
                    latest_version_id INTEGER,
                    UNIQUE (dir_id, name),
                    FOREIGN KEY (id, oldest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED,
                    FOREIGN KEY (id, latest_version_id) REFERENCES item_versions (item_id, version_id) DEFERRABLE INITIALLY DEFERRED
                );
                CREATE TABLE item_versions (
                    version_id INTEGER NOT NULL,
                    item_id INTEGER NOT NULL REFERENCES items (id) ON DELETE CASCADE,
                    fields TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY (item_id, version_id)
                ) WITHOUT ROWID;
                CREATE TABLE files (
                    id BLOB PRIMARY KEY,
                    sha256 TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    nonce BLOB NOT NULL,
                    tag BLOB NOT NULL,
                    created_at INTEGER NOT NULL,
                    UNIQUE (sha256)
                ) WITHOUT ROWID;
                CREATE TABLE item_version_file_mapping (
                    item_id INTEGER NOT NULL,
                    version_id INTEGER NOT NULL,
                    file_id BLOB NOT NULL REFERENCES files (id) ON DELETE CASCADE,
                    file_name TEXT NOT NULL,
                    PRIMARY KEY (item_id, version_id, file_id),
                    UNIQUE (item_id, version_id, file_name),
                    FOREIGN KEY (item_id, version_id) REFERENCES item_versions (item_id, version_id) ON DELETE CASCADE
                ) WITHOUT ROWID;
                "#,
            )
            .unwrap();
        let reader = Connection::open(&database_path).unwrap();
        reader.pragma_update(None, "foreign_keys", "ON").unwrap();

        let file_id = vec![1u8; 32];
        let fields = serde_json::json!({
            "password": {
                "name": "password",
                "type": "string",
                "concealed": true,
                "data": "field-bytes"
            }
        });
        let transaction = writer.transaction().unwrap();
        transaction
            .execute(
                "INSERT INTO dirs (id, name, bitmask, created_at, updated_at) VALUES (1, 'dir', 0, 1, 1)",
                [],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO items (id, dir_id, name, bitmask, created_at, updated_at, oldest_version_id, latest_version_id) VALUES (1, 1, 'item', 0, 1, 1, 1, 1)",
                [],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO item_versions (version_id, item_id, fields, created_at) VALUES (1, 1, ?1, 1)",
                [fields.to_string()],
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO files (id, sha256, size, nonce, tag, created_at) VALUES (?1, ?2, 4, ?3, ?4, 1)",
                (
                    &file_id,
                    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    vec![2u8; 8],
                    vec![3u8; 16],
                ),
            )
            .unwrap();
        transaction
            .execute(
                "INSERT INTO item_version_file_mapping (item_id, version_id, file_id, file_name) VALUES (1, 1, ?1, 'password')",
                [&file_id],
            )
            .unwrap();
        transaction.commit().unwrap();

        (tempdir, DbHandle::new(writer, vec![reader], PathBuf::new()))
    }

    async fn block_reader_workers(
        database: &DbHandle,
    ) -> Vec<tokio::task::JoinHandle<Result<(), DbError>>> {
        let before = database.dispatch_counts().1;
        let mut tasks = Vec::with_capacity(DATABASE_READER_WORKERS);
        for _ in 0..DATABASE_READER_WORKERS {
            let database = database.clone();
            tasks.push(tokio::spawn(async move {
                database.test_slow_read(Duration::from_secs(3)).await
            }));
        }
        wait_for_reader_dispatches(database, before + DATABASE_READER_WORKERS).await;
        tasks
    }

    async fn wait_for_reader_dispatches(database: &DbHandle, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if database.dispatch_counts().1 >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for reader dispatches"
            );
            tokio::task::yield_now().await;
        }
    }

    #[tokio::test]
    async fn failed_sqlcipher_unlock_returns_error() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());

        assert!(
            state
                .unlock(password("wrong"), ProcessChainHash::test(1))
                .await
                .is_err()
        );
        assert!(!state.is_unlocked().await);
    }

    #[tokio::test]
    async fn successful_unlock_stores_database_handle() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());

        assert!(
            state
                .unlock(password("correct"), ProcessChainHash::test(1))
                .await
                .is_ok()
        );
        assert!(state.database_handle().await.is_some());
        assert!(state.has_password_verifier().await);
        assert!(state.last_authorized_database_access().await.is_some());
        assert!(state.max_authorization_expires_at().await.is_some());
        assert!(state.is_authorized(&ProcessChainHash::test(1)).await);
    }

    #[tokio::test]
    async fn settings_password_verifier_accepts_only_correct_password() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;

        assert!(state.verify_settings_password("correct").await);
        assert!(!state.verify_settings_password("wrong").await);
    }

    #[tokio::test]
    async fn settings_password_verifier_fails_closed_without_verifier() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;

        assert!(!state.verify_settings_password("correct").await);
    }

    #[tokio::test]
    async fn settings_password_verifier_fails_closed_when_locked() {
        let state = AgentState::from_database_path("missing.db");
        state.store_password_verifier("correct").await;

        assert!(!state.verify_settings_password("correct").await);
    }

    #[tokio::test]
    async fn settings_password_verification_does_not_authorize_or_extend_expiry() {
        let state = AgentState::from_database_path("missing.db");
        let original_expiry = Instant::now() + Duration::from_secs(1);
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .set_max_authorization_expires_at(Some(original_expiry))
            .await;

        assert!(state.verify_settings_password("correct").await);

        assert!(!state.is_authorized(&ProcessChainHash::test(1)).await);
        assert_eq!(
            Some(original_expiry),
            state.max_authorization_expires_at().await
        );
    }

    #[tokio::test]
    async fn first_unlock_sets_max_authorization_expiry() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let before = Instant::now();

        state
            .unlock(password("correct"), ProcessChainHash::test(1))
            .await
            .unwrap();

        let expires_at = state.max_authorization_expires_at().await.unwrap();
        assert!(expires_at >= before + AUTH_TTL);
        assert!(expires_at <= Instant::now() + AUTH_TTL);
    }

    #[tokio::test]
    async fn repeated_unlock_after_success_verifies_password_and_does_not_replace_handle() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());

        state
            .unlock(password("correct"), ProcessChainHash::test(1))
            .await
            .unwrap();
        let first_handle = state.database_handle().await.unwrap();

        assert!(
            state
                .unlock(password("wrong"), ProcessChainHash::test(2))
                .await
                .is_err()
        );
        state
            .unlock(password("correct"), ProcessChainHash::test(2))
            .await
            .unwrap();
        let second_handle = state.database_handle().await.unwrap();

        assert!(first_handle.ptr_eq(&second_handle));
        assert!(state.is_authorized(&ProcessChainHash::test(2)).await);
    }

    #[tokio::test]
    async fn later_successful_unlock_extends_max_authorization_expiry() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());

        state
            .unlock(password("correct"), ProcessChainHash::test(1))
            .await
            .unwrap();
        let original_expiry = Instant::now() + Duration::from_secs(1);
        state
            .set_max_authorization_expires_at(Some(original_expiry))
            .await;

        state
            .unlock(password("correct"), ProcessChainHash::test(2))
            .await
            .unwrap();

        assert!(state.max_authorization_expires_at().await.unwrap() > original_expiry);
    }

    #[tokio::test]
    async fn failed_unlock_does_not_update_max_authorization_expiry() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        state
            .unlock(password("correct"), ProcessChainHash::test(1))
            .await
            .unwrap();
        let original_expiry = state.max_authorization_expires_at().await;

        assert!(
            state
                .unlock(password("wrong"), ProcessChainHash::test(1))
                .await
                .is_err()
        );

        assert_eq!(original_expiry, state.max_authorization_expires_at().await);
    }

    #[tokio::test]
    async fn lock_clears_authorizations_and_marks_expiry_due_without_unloading() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        let database = DbHandle::test();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;

        state.lock(now).await;

        assert!(!state.is_authorized(&ProcessChainHash::test(1)).await);
        assert_eq!(Some(now), state.max_authorization_expires_at().await);
        assert!(
            state
                .database_handle()
                .await
                .is_some_and(|handle| handle.ptr_eq(&database))
        );
        assert!(state.has_password_verifier().await);
    }

    #[tokio::test]
    async fn authorization_expiry_unload_after_lock_clears_unlocked_state() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state.lock(now).await;

        assert!(state.unload_if_authorization_expired(now).await);

        assert!(state.database_handle().await.is_none());
        assert!(!state.has_password_verifier().await);
        assert_eq!(None, state.max_authorization_expires_at().await);
    }

    #[tokio::test]
    async fn concurrent_lock_makes_in_flight_repeated_unlock_fail_closed() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let now = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;
        let blockers = block_reader_workers(&database).await;
        let before_unlock_read = database.dispatch_counts().1;
        let unlock_state = state.clone();
        let unlock_task = tokio::spawn(async move {
            unlock_state
                .unlock(password("correct"), ProcessChainHash::test(2))
                .await
        });
        wait_for_reader_dispatches(&database, before_unlock_read + 1).await;
        let lock_time = Instant::now();

        state.lock(lock_time).await;

        assert_eq!(Err(UnlockError::AccessDenied), unlock_task.await.unwrap());
        for blocker in blockers {
            assert!(blocker.await.unwrap().is_ok());
        }
        assert!(!state.is_authorized(&ProcessChainHash::test(2)).await);
        assert_eq!(Some(lock_time), state.max_authorization_expires_at().await);
    }

    #[tokio::test]
    async fn concurrent_lock_and_unload_keep_in_flight_repeated_unlock_closed() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let now = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;
        let blockers = block_reader_workers(&database).await;
        let before_unlock_read = database.dispatch_counts().1;
        let unlock_state = state.clone();
        let unlock_task = tokio::spawn(async move {
            unlock_state
                .unlock(password("correct"), ProcessChainHash::test(2))
                .await
        });
        wait_for_reader_dispatches(&database, before_unlock_read + 1).await;

        state.lock(now).await;
        assert!(state.unload_if_authorization_expired(now).await);

        assert_eq!(Err(UnlockError::AccessDenied), unlock_task.await.unwrap());
        for blocker in blockers {
            assert!(blocker.await.unwrap().is_ok());
        }
        assert!(state.database_handle().await.is_none());
        assert!(!state.has_password_verifier().await);
        assert!(!state.is_authorized(&ProcessChainHash::test(2)).await);
    }

    #[tokio::test]
    async fn concurrent_unlock_attempts_store_one_handle() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let mut tasks = Vec::new();

        for _ in 0..8 {
            let state = state.clone();
            tasks.push(tokio::spawn(async move {
                state
                    .unlock(password("correct"), ProcessChainHash::test(1))
                    .await
            }));
        }

        for task in tasks {
            assert!(task.await.unwrap().is_ok());
        }

        assert!(state.database_handle().await.is_some());
    }

    #[tokio::test]
    async fn database_access_records_authorized_database_access() {
        let state = AgentState::from_database_path("missing.db");
        let old_access = Instant::now() - Duration::from_secs(60);
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        state
            .set_last_authorized_database_access(Some(old_access))
            .await;

        assert!(
            state
                .authorize_database_access(&ProcessChainHash::test(1))
                .await
                .is_some()
        );

        assert!(state.last_authorized_database_access().await.unwrap() > old_access);
    }

    #[tokio::test]
    async fn authorization_check_does_not_record_authorized_database_access() {
        let state = AgentState::from_database_path("missing.db");
        let old_access = Instant::now() - Duration::from_secs(60);
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        state
            .set_last_authorized_database_access(Some(old_access))
            .await;

        assert!(state.is_authorized(&ProcessChainHash::test(1)).await);

        assert_eq!(
            Some(old_access),
            state.last_authorized_database_access().await
        );
    }

    #[tokio::test]
    async fn authorization_expiry_requires_unlocked_cached_hash() {
        let state = AgentState::from_database_path("missing.db");
        let inserted_at = Instant::now();
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), inserted_at)
            .await;

        assert_eq!(
            None,
            state
                .authorization_expires_at(&ProcessChainHash::test(1))
                .await
        );

        state.store_database_handle(DbHandle::test()).await;

        assert_eq!(
            Some(inserted_at + AUTH_TTL),
            state
                .authorization_expires_at(&ProcessChainHash::test(1))
                .await
        );
        assert_eq!(
            None,
            state
                .authorization_expires_at(&ProcessChainHash::test(2))
                .await
        );
    }

    #[tokio::test]
    async fn lowered_auth_ttl_expires_existing_cached_authorization() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database
            .upsert_setting("user.authTtlSeconds".to_owned(), "1".to_owned())
            .await
            .unwrap();
        state.store_database_handle(database).await;
        state
            .authorize_process_hash_at(
                ProcessChainHash::test(1),
                Instant::now() - Duration::from_secs(2),
            )
            .await;

        assert_eq!(
            None,
            state
                .authorization_expires_at(&ProcessChainHash::test(1))
                .await
        );
    }

    #[tokio::test]
    async fn authorization_expiry_unload_before_max_expiry_does_nothing() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state.set_last_authorized_database_access(Some(now)).await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;

        assert!(
            !state
                .unload_if_authorization_expired(now + AUTH_TTL - Duration::from_secs(1))
                .await
        );

        assert!(state.database_handle().await.is_some());
        assert!(state.has_password_verifier().await);
        assert!(state.is_authorized(&ProcessChainHash::test(1)).await);
        assert_eq!(
            Some(now + AUTH_TTL),
            state.max_authorization_expires_at().await
        );
    }

    #[tokio::test]
    async fn authorization_expiry_unload_clears_unlocked_state() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state.set_last_authorized_database_access(Some(now)).await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;

        assert!(state.unload_if_authorization_expired(now + AUTH_TTL).await);

        assert!(state.database_handle().await.is_none());
        assert!(!state.has_password_verifier().await);
        assert_eq!(None, state.last_authorized_database_access().await);
        assert_eq!(None, state.max_authorization_expires_at().await);
        assert!(!state.is_authorized(&ProcessChainHash::test(1)).await);
    }

    #[tokio::test]
    async fn authorization_expiry_unload_waits_for_active_jobs() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state.set_last_authorized_database_access(Some(now)).await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;
        state
            .register_active_job("00112233445566778899aabbccddeeff".to_owned())
            .await;

        assert_eq!(1, state.active_job_count().await);
        assert!(!state.unload_if_authorization_expired(now + AUTH_TTL).await);
        assert!(state.database_handle().await.is_some());

        state
            .unregister_active_job("00112233445566778899aabbccddeeff")
            .await;

        assert_eq!(0, state.active_job_count().await);
        assert!(state.unload_if_authorization_expired(now + AUTH_TTL).await);
        assert!(state.database_handle().await.is_none());
    }

    #[tokio::test]
    async fn authorization_expiry_unload_waits_for_active_database_requests() {
        let state = AgentState::from_database_path("missing.db");
        let now = Instant::now();
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now)
            .await;
        state.set_last_authorized_database_access(Some(now)).await;
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;
        let active_request = state.begin_active_database_request();

        assert_eq!(1, state.active_database_request_count());
        assert!(!state.unload_if_authorization_expired(now + AUTH_TTL).await);
        assert!(state.database_handle().await.is_some());

        drop(active_request);

        assert_eq!(0, state.active_database_request_count());
        assert!(state.unload_if_authorization_expired(now + AUTH_TTL).await);
        assert!(state.database_handle().await.is_none());
    }

    #[tokio::test]
    async fn unlock_after_authorization_expiry_unload_reopens_database() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let now = Instant::now();
        state
            .unlock(password("correct"), ProcessChainHash::test(1))
            .await
            .unwrap();
        let first_handle = state.database_handle().await.unwrap();
        state
            .set_max_authorization_expires_at(Some(now + AUTH_TTL))
            .await;
        state
            .unload_if_authorization_expired(Instant::now() + AUTH_TTL)
            .await;

        state
            .unlock(password("correct"), ProcessChainHash::test(2))
            .await
            .unwrap();
        let second_handle = state.database_handle().await.unwrap();

        assert!(!first_handle.ptr_eq(&second_handle));
        assert!(state.is_authorized(&ProcessChainHash::test(2)).await);
    }

    #[tokio::test]
    async fn authorization_expiry_unload_skips_cleanup_when_not_due() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let now = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state.set_last_authorized_database_access(Some(now)).await;
        state.set_max_authorization_expires_at(Some(now)).await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now - AUTH_TTL)
            .await;
        state.set_last_cleanup_at(Some(now)).await;
        let before = database.dispatch_counts();

        assert!(state.unload_if_authorization_expired(now).await);

        let after = database.dispatch_counts();
        assert_eq!(before.0, after.0);
        assert!(state.database_handle().await.is_none());
    }

    #[tokio::test]
    async fn authorization_expiry_unload_uses_configured_cleanup_interval() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database
            .upsert_setting("user.gcSeconds".to_owned(), "120".to_owned())
            .await
            .unwrap();
        let now = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state.set_last_authorized_database_access(Some(now)).await;
        state.set_max_authorization_expires_at(Some(now)).await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now - AUTH_TTL)
            .await;
        state
            .set_last_cleanup_at(Some(now - Duration::from_secs(119)))
            .await;
        let before = database.dispatch_counts();

        assert!(state.unload_if_authorization_expired(now).await);

        let after = database.dispatch_counts();
        assert_eq!(before.0, after.0);
    }

    #[tokio::test]
    async fn authorization_expiry_unload_runs_cleanup_when_due() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let now = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state.set_last_authorized_database_access(Some(now)).await;
        state.set_max_authorization_expires_at(Some(now)).await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), now - AUTH_TTL)
            .await;
        state
            .set_last_cleanup_at(Some(now - CLEANUP_INTERVAL))
            .await;
        let before = database.dispatch_counts();

        assert!(state.unload_if_authorization_expired(now).await);

        let after = database.dispatch_counts();
        assert_eq!(before.0 + 1, after.0);
        assert!(state.database_handle().await.is_none());
    }

    #[tokio::test]
    async fn cleanup_error_does_not_block_authorization_expiry_unload() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let now = Instant::now();
        database.test_fail_next_cleanup_before_unload();
        state.store_database_handle(database).await;
        state.store_password_verifier("correct").await;
        state.set_last_authorized_database_access(Some(now)).await;
        state.set_max_authorization_expires_at(Some(now)).await;
        state
            .set_last_cleanup_at(Some(now - CLEANUP_INTERVAL))
            .await;

        assert!(state.unload_if_authorization_expired(now).await);

        assert!(state.database_handle().await.is_none());
        assert!(!state.has_password_verifier().await);
    }

    #[tokio::test]
    async fn database_worker_copy_item_merges_with_request_overrides() {
        let database = DbHandle::test();
        database.create_dir("source".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        let old_notes_id = database.create_file(b"old notes".to_vec()).await.unwrap();
        let new_notes_id = database.create_file(b"new notes".to_vec()).await.unwrap();
        database
            .create_item(
                "source".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    },
                    "files": {
                        "notes": {"id": old_notes_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .create_item(
                "dest".to_owned(),
                "copy".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "new"}
                    },
                    "files": {
                        "notes": {"id": new_notes_id}
                    }
                }))
                .unwrap(),
                Some(super::ItemSource::Copy(super::CopySource {
                    dir_name: "source".to_owned(),
                    item_name: "item".to_owned(),
                })),
            )
            .await
            .unwrap();

        let item = database
            .get_item(
                "dest".to_owned(),
                "copy".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();

        assert_eq!(
            1,
            database
                .test_item_version_count("dest", "copy")
                .await
                .unwrap()
        );
        assert_eq!("alice", field(&item, "username").data);
        assert_eq!("new", field(&item, "password").data);
        assert_eq!(9, file(&item, "notes").size);
        assert_eq!(
            b"new".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dest".to_owned(),
                        "copy".to_owned(),
                        "password".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            b"old".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "source".to_owned(),
                        "item".to_owned(),
                        "password".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            b"new notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dest".to_owned(),
                        "copy".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body
            )
            .await
            .as_slice()
        );
    }

    #[tokio::test]
    async fn settings_registry_validates_defaults_and_limits() {
        assert!(
            crate::settings::auth_ttl_setting()
                .validate(crate::settings::auth_ttl_setting().default)
                .is_ok()
        );
        assert!(
            crate::settings::gc_seconds_setting()
                .validate(crate::settings::gc_seconds_setting().default)
                .is_ok()
        );
        assert!(crate::settings::auth_ttl_setting().validate("0").is_err());
        assert!(
            crate::settings::auth_ttl_setting()
                .validate("604801")
                .is_err()
        );
        assert!(crate::settings::auth_ttl_setting().validate("abc").is_err());
    }

    #[tokio::test]
    async fn database_worker_lists_and_updates_user_settings_only() {
        let database = DbHandle::test();

        database
            .upsert_setting("user.authTtlSeconds".to_owned(), "1200".to_owned())
            .await
            .unwrap();
        let settings = database.list_settings().await.unwrap();

        assert_eq!(
            Some(&"1200".to_owned()),
            settings.get("user.authTtlSeconds")
        );
        assert_eq!(Some(&"3600".to_owned()), settings.get("user.gcSeconds"));
        assert!(!settings.contains_key("sys.fileEncryptionKey"));
    }

    #[tokio::test]
    async fn database_worker_updates_contact_email_name_and_public_key() {
        let database = DbHandle::test();
        let original_key = age::x25519::Identity::generate().to_public().to_string();
        let updated_key = age::x25519::Identity::generate().to_public().to_string();

        database
            .create_contact(
                "alice@example.com".to_owned(),
                CreateContactRequest {
                    name: Some("Alice".to_owned()),
                    age_public_key: original_key,
                    description: None,
                },
            )
            .await
            .unwrap();

        database
            .update_contact(
                "alice@example.com".to_owned(),
                UpdateContactRequest {
                    email: "alice.renamed@example.com".to_owned(),
                    name: Some(Some("Alice Renamed".to_owned())),
                    age_public_key: Some(updated_key.clone()),
                },
            )
            .await
            .unwrap();

        assert!(matches!(
            database
                .contact_public_key("alice@example.com".to_owned())
                .await,
            Err(DbError::NotFoundMessage(message)) if message == "contact `alice@example.com` not found"
        ));
        assert_eq!(
            updated_key,
            database
                .contact_public_key("alice.renamed@example.com".to_owned())
                .await
                .unwrap()
        );
        let contacts = database.list_contacts(default_page()).await.unwrap();
        assert_eq!("alice.renamed@example.com", contacts.entries[0].email);
        assert_eq!(Some("Alice Renamed".to_owned()), contacts.entries[0].name);
    }

    #[tokio::test]
    async fn database_worker_persists_import_job_status() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let job_id = "00112233445566778899aabbccddeeff".to_owned();

        database
            .create_import_job(job_id.clone(), "dir".to_owned(), "item".to_owned())
            .await
            .unwrap();
        let queued = database.get_job(job_id.clone()).await.unwrap();
        assert_eq!(super::JobStatus::Queued, queued.status);
        assert_eq!("dir", queued.target.dir);
        assert_eq!("item", queued.target.item);
        assert_eq!(None, queued.target.contact);
        assert_eq!(None, queued.output_path);

        database.mark_job_running(job_id.clone()).await.unwrap();
        let running = database.get_job(job_id.clone()).await.unwrap();
        assert_eq!(super::JobStatus::Running, running.status);
        assert!(running.started_at.is_some());

        database
            .mark_job_failed(
                job_id.clone(),
                "bad_archive".to_owned(),
                "fields.json is malformed".to_owned(),
            )
            .await
            .unwrap();
        let failed = database.get_job(job_id).await.unwrap();
        assert_eq!(super::JobStatus::Failed, failed.status);
        assert!(failed.finished_at.is_some());
        assert_eq!("bad_archive", failed.error.unwrap().code);
    }

    #[tokio::test]
    async fn database_worker_persists_export_job_target_and_output_path() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_contact(
                "alice".to_owned(),
                CreateContactRequest {
                    name: None,
                    age_public_key: age::x25519::Identity::generate().to_public().to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                CreateItemRequest::default(),
                None,
            )
            .await
            .unwrap();
        let job_id = "00112233445566778899aabbccddeeff".to_owned();
        let output_path = PathBuf::from("/tmp/monopass-export-job/output.export");

        database
            .create_export_job(
                job_id.clone(),
                "dir".to_owned(),
                "item".to_owned(),
                "alice".to_owned(),
            )
            .await
            .unwrap();
        let queued = database.get_job(job_id.clone()).await.unwrap();
        assert_eq!(super::JobType::Export, queued.job_type);
        assert_eq!(super::JobStatus::Queued, queued.status);
        assert_eq!("dir", queued.target.dir);
        assert_eq!("item", queued.target.item);
        assert_eq!(Some("alice".to_owned()), queued.target.contact);
        assert_eq!(None, queued.output_path);

        database
            .mark_job_succeeded(job_id.clone(), Some(output_path.clone()))
            .await
            .unwrap();
        let succeeded = database.get_job(job_id).await.unwrap();
        assert_eq!(super::JobStatus::Succeeded, succeeded.status);
        assert_eq!(
            Some(output_path.to_string_lossy().into_owned()),
            succeeded.output_path
        );
    }

    #[tokio::test]
    async fn database_worker_rejects_invalid_or_unknown_settings() {
        let database = DbHandle::test();

        assert_eq!(
            Err(DbError::BadRequest("invalid setting value".to_owned())),
            database
                .upsert_setting("user.authTtlSeconds".to_owned(), "abc".to_owned())
                .await
        );
        assert_eq!(
            Err(DbError::BadRequest("invalid setting value".to_owned())),
            database
                .upsert_setting("user.authTtlSeconds".to_owned(), "604801".to_owned())
                .await
        );
        assert_eq!(
            Err(DbError::NotFoundMessage(
                "setting `sys.fileEncryptionKey` not found".to_owned()
            )),
            database
                .upsert_setting("sys.fileEncryptionKey".to_owned(), "900".to_owned())
                .await
        );
    }

    #[tokio::test]
    async fn database_worker_rejects_invalid_totp_copy_overrides() {
        let database = DbHandle::test();
        database.create_dir("source".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        database
            .create_item(
                "source".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        let error = database
            .create_item(
                "dest".to_owned(),
                "copy".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "totp": {"type": "totp", "data": "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP&period=0"}
                    }
                }))
                .unwrap(),
                Some(super::ItemSource::Copy(super::CopySource {
                    dir_name: "source".to_owned(),
                    item_name: "item".to_owned(),
                })),
            )
            .await
            .unwrap_err();

        assert!(matches!(error, super::DbError::BadRequest(_)));
    }

    #[tokio::test]
    async fn database_worker_move_item_renames_without_new_version() {
        let database = DbHandle::test();
        database.create_dir("source".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        database
            .create_item(
                "source".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        database
            .create_item(
                "dest".to_owned(),
                "renamed".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "source".to_owned(),
                    item_name: "item".to_owned(),
                })),
            )
            .await
            .unwrap();

        assert_eq!(
            1,
            database
                .test_item_version_count("dest", "renamed")
                .await
                .unwrap()
        );
        assert!(matches!(
            database
                .get_item(
                    "source".to_owned(),
                    "item".to_owned(),
                    None,
                    true,
                    false,
                    false
                )
                .await,
            Err(super::DbError::NotFoundMessage(message)) if message == "item `source/item` not found"
        ));

        let item = database
            .get_item(
                "dest".to_owned(),
                "renamed".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("alice", field(&item, "username").data);
        assert_eq!("old", field(&item, "password").data);
    }

    #[tokio::test]
    async fn database_worker_move_item_rejects_body_and_existing_destination() {
        let database = DbHandle::test();
        database.create_dir("source".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        for (dir, item) in [("source", "item"), ("dest", "existing")] {
            database
                .create_item(
                    dir.to_owned(),
                    item.to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }

        let error = database
            .create_item(
                "dest".to_owned(),
                "moved".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "new"}
                    }
                }))
                .unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "source".to_owned(),
                    item_name: "item".to_owned(),
                })),
            )
            .await
            .unwrap_err();
        assert!(matches!(error, super::DbError::BadRequest(_)));

        let error = database
            .create_item(
                "dest".to_owned(),
                "existing".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "source".to_owned(),
                    item_name: "item".to_owned(),
                })),
            )
            .await
            .unwrap_err();
        assert_eq!(
            super::DbError::Conflict("item already exists".to_owned()),
            error
        );
    }

    #[tokio::test]
    async fn read_methods_dispatch_to_reader_workers() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let before = database.dispatch_counts();

        database.get_dir("dir".to_owned()).await.unwrap();
        database.list_dirs(default_page()).await.unwrap();
        database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                false,
                false,
                false,
            )
            .await
            .unwrap();
        database
            .list_items("dir".to_owned(), default_page())
            .await
            .unwrap();

        let after = database.dispatch_counts();
        assert_eq!(before.0, after.0);
        assert_eq!(before.1 + 4, after.1);
    }

    #[tokio::test]
    async fn list_dirs_paginates_by_name_and_marker_includes_next_entry() {
        let database = DbHandle::test();
        for name in ["beta", "alpha", "charlie"] {
            database.create_dir(name.to_owned()).await.unwrap();
        }

        let first = database
            .list_dirs(PageRequest {
                count: 1,
                marker: None,
            })
            .await
            .unwrap();
        assert_eq!(1, first.count);
        assert_eq!(vec!["alpha"], names(&first.entries));
        let marker = first.next_marker.unwrap();

        let second = database
            .list_dirs(PageRequest {
                count: 2,
                marker: Some(marker),
            })
            .await
            .unwrap();
        assert_eq!(2, second.count);
        assert_eq!(vec!["beta", "charlie"], names(&second.entries));
        assert_eq!(None, second.next_marker);
    }

    #[tokio::test]
    async fn list_items_paginates_by_name_and_rejects_cross_scope_markers() {
        let database = DbHandle::test();
        database.create_dir("work".to_owned()).await.unwrap();
        database.create_dir("home".to_owned()).await.unwrap();
        for name in ["zulu", "alpha", "bravo"] {
            database
                .create_item(
                    "work".to_owned(),
                    name.to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }

        let first = database
            .list_items(
                "work".to_owned(),
                PageRequest {
                    count: 1,
                    marker: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(vec!["alpha"], item_names(&first.entries));
        let marker = first.next_marker.unwrap();

        let second = database
            .list_items(
                "work".to_owned(),
                PageRequest {
                    count: 2,
                    marker: Some(marker.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(vec!["bravo", "zulu"], item_names(&second.entries));
        assert_eq!(None, second.next_marker);

        let error = database
            .list_items(
                "home".to_owned(),
                PageRequest {
                    count: 1,
                    marker: Some(marker),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(DbError::BadRequest("invalid marker".to_owned()), error);
    }

    #[tokio::test]
    async fn hidden_items_are_not_publicly_visible_or_mutable() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "secret".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "totp": {"type": "totp", "data": "otpauth://totp/test?secret=JBSWY3DPEHPK3PXP"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "dir".to_owned(),
                "secret".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database
            .test_set_item_bitmask("dir", "secret", super::ITEM_HIDDEN)
            .await
            .unwrap();

        assert_eq!(0, database.get_dir("dir".to_owned()).await.unwrap().items);
        assert_eq!(
            Vec::<&str>::new(),
            item_names(
                &database
                    .list_items("dir".to_owned(), default_page())
                    .await
                    .unwrap()
                    .entries
            )
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .get_item(
                    "dir".to_owned(),
                    "secret".to_owned(),
                    None,
                    true,
                    false,
                    false
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .list_item_versions("dir".to_owned(), "secret".to_owned(), default_page())
                .await
                .unwrap_err()
        );
        assert!(matches!(
            database
                .get_reference(
                    "dir".to_owned(),
                    "secret".to_owned(),
                    "totp".to_owned(),
                    None,
                    false,
                    false,
                )
                .await
                .map(|_| ()),
            Err(DbError::NotFoundMessage(message)) if message == "item `dir/secret` not found"
        ));
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .update_item(
                    "dir".to_owned(),
                    "secret".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .restore_item_version("dir".to_owned(), "secret".to_owned(), 1)
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .create_item(
                    "dest".to_owned(),
                    "copy".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    Some(super::ItemSource::Copy(super::CopySource {
                        dir_name: "dir".to_owned(),
                        item_name: "secret".to_owned(),
                    })),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .create_item(
                    "dest".to_owned(),
                    "moved".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    Some(super::ItemSource::Move(super::CopySource {
                        dir_name: "dir".to_owned(),
                        item_name: "secret".to_owned(),
                    })),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .delete_item("dir".to_owned(), "secret".to_owned())
                .await
                .unwrap_err()
        );
    }

    #[tokio::test]
    async fn read_mustauth_items_gate_secret_bearing_reads() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let normal_file_id = database
            .create_file(b"normal notes".to_vec())
            .await
            .unwrap();
        let guarded_file_id = database
            .create_file(b"guarded notes".to_vec())
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "normal".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "normal-secret"}
                    },
                    "files": {
                        "notes": {"id": normal_file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "guarded".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "guarded-secret"}
                    },
                    "files": {
                        "notes": {"id": guarded_file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .test_set_item_bitmask("dir", "guarded", super::ITEM_READ_MUSTAUTH)
            .await
            .unwrap();

        let normal = database
            .get_item(
                "dir".to_owned(),
                "normal".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("normal-secret", field(&normal, "password").data);
        assert_eq!(
            b"normal notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "normal".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            b"normal-secret".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "normal".to_owned(),
                        "password".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );

        let masked = database
            .get_item(
                "dir".to_owned(),
                "guarded".to_owned(),
                None,
                false,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("******", field(&masked, "password").data);

        assert_eq!(
            DbError::AccessDenied,
            database
                .get_item(
                    "dir".to_owned(),
                    "guarded".to_owned(),
                    None,
                    true,
                    false,
                    false,
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .get_item(
                    "dir".to_owned(),
                    "guarded".to_owned(),
                    None,
                    false,
                    true,
                    false,
                )
                .await
                .unwrap_err()
        );
        assert!(matches!(
            database
                .get_reference(
                    "dir".to_owned(),
                    "guarded".to_owned(),
                    "notes".to_owned(),
                    None,
                    false,
                    false,
                )
                .await
                .map(|_| ()),
            Err(DbError::AccessDenied)
        ));

        let revealed = database
            .get_item(
                "dir".to_owned(),
                "guarded".to_owned(),
                None,
                true,
                false,
                true,
            )
            .await
            .unwrap();
        assert_eq!("guarded-secret", field(&revealed, "password").data);
        let raw = database
            .get_item(
                "dir".to_owned(),
                "guarded".to_owned(),
                None,
                false,
                true,
                true,
            )
            .await
            .unwrap();
        assert_eq!("guarded-secret", field(&raw, "password").data);
        assert_eq!(
            b"guarded notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "guarded".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        true,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            b"guarded-secret".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "guarded".to_owned(),
                        "password".to_owned(),
                        None,
                        false,
                        true,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
    }

    #[tokio::test]
    async fn hidden_read_mustauth_items_return_not_found() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "secret".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "secret"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .test_set_item_bitmask(
                "dir",
                "secret",
                super::ITEM_HIDDEN | super::ITEM_READ_MUSTAUTH,
            )
            .await
            .unwrap();

        assert_eq!(
            DbError::NotFoundMessage("item `dir/secret` not found".to_owned()),
            database
                .get_item(
                    "dir".to_owned(),
                    "secret".to_owned(),
                    None,
                    true,
                    false,
                    false,
                )
                .await
                .unwrap_err()
        );
        assert!(matches!(
            database
                .get_reference(
                    "dir".to_owned(),
                    "secret".to_owned(),
                    "notes".to_owned(),
                    None,
                    false,
                    false,
                )
                .await
                .map(|_| ()),
            Err(DbError::NotFoundMessage(message)) if message == "item `dir/secret` not found"
        ));
    }

    #[tokio::test]
    async fn list_dirs_rejects_invalid_and_stale_markers() {
        let database = DbHandle::test();
        database.create_dir("alpha".to_owned()).await.unwrap();
        database.create_dir("bravo".to_owned()).await.unwrap();

        let marker = database
            .list_dirs(PageRequest {
                count: 1,
                marker: None,
            })
            .await
            .unwrap()
            .next_marker
            .unwrap();
        let mut tampered_marker = marker.clone();
        let replacement = if marker.starts_with('A') { "B" } else { "A" };
        tampered_marker.replace_range(0..1, replacement);
        let tampered = database
            .list_dirs(PageRequest {
                count: 1,
                marker: Some(tampered_marker),
            })
            .await
            .unwrap_err();
        assert_eq!(DbError::BadRequest("invalid marker".to_owned()), tampered);

        database.delete_dir("bravo".to_owned()).await.unwrap();

        let stale = database
            .list_dirs(PageRequest {
                count: 1,
                marker: Some(marker),
            })
            .await
            .unwrap_err();
        assert_eq!(DbError::BadRequest("invalid marker".to_owned()), stale);

        let invalid = database
            .list_dirs(PageRequest {
                count: 1,
                marker: Some("not-valid-base64".to_owned()),
            })
            .await
            .unwrap_err();
        assert_eq!(DbError::BadRequest("invalid marker".to_owned()), invalid);
    }

    #[tokio::test]
    async fn hidden_dirs_are_not_publicly_visible_but_accept_item_writes() {
        let database = DbHandle::test();
        database.create_dir("hidden".to_owned()).await.unwrap();
        database
            .test_set_dir_bitmask("hidden", super::DIR_HIDDEN)
            .await
            .unwrap();

        assert_eq!(
            DbError::NotFoundMessage("dir `hidden` not found".to_owned()),
            database.get_dir("hidden".to_owned()).await.unwrap_err()
        );
        assert_eq!(
            Vec::<&str>::new(),
            names(&database.list_dirs(default_page()).await.unwrap().entries)
        );
        assert_eq!(
            DbError::NotFoundMessage("dir `hidden` not found".to_owned()),
            database
                .update_dir(
                    "hidden".to_owned(),
                    crate::agent::models::UpdateDirRequest {
                        name: "renamed".to_owned(),
                    },
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::NotFoundMessage("dir `hidden` not found".to_owned()),
            database.delete_dir("hidden".to_owned()).await.unwrap_err()
        );
        database
            .create_item(
                "hidden".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "secret"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "hidden".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database.create_dir("visible".to_owned()).await.unwrap();
        database
            .create_item(
                "hidden".to_owned(),
                "moved".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "visible".to_owned(),
                    item_name: "missing".to_owned(),
                })),
            )
            .await
            .unwrap_err();
        database
            .create_item(
                "visible".to_owned(),
                "source".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .create_item(
                "hidden".to_owned(),
                "moved".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "visible".to_owned(),
                    item_name: "source".to_owned(),
                })),
            )
            .await
            .unwrap();
        assert_eq!(
            vec!["item", "moved"],
            item_names(
                &database
                    .list_items("hidden".to_owned(), default_page())
                    .await
                    .unwrap()
                    .entries
            )
        );
        database
            .create_item(
                "visible".to_owned(),
                "restored".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Move(super::CopySource {
                    dir_name: "hidden".to_owned(),
                    item_name: "moved".to_owned(),
                })),
            )
            .await
            .unwrap();
        database
            .delete_item("hidden".to_owned(), "item".to_owned())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn internal_public_age_key_is_readable_but_private_key_is_hidden() {
        let database = DbHandle::test();

        assert!(
            !names(&database.list_dirs(default_page()).await.unwrap().entries)
                .contains(&"_Internal")
        );
        assert_eq!(
            vec!["AgePublicKey"],
            item_names(
                &database
                    .list_items("_Internal".to_owned(), default_page())
                    .await
                    .unwrap()
                    .entries
            )
        );
        let public_key = database
            .get_item(
                "_Internal".to_owned(),
                "AgePublicKey".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("age1unused", field(&public_key, "key").data);
        assert_eq!(
            DbError::NotFoundMessage("item `_Internal/AgePrivateKey` not found".to_owned()),
            database
                .get_item(
                    "_Internal".to_owned(),
                    "AgePrivateKey".to_owned(),
                    None,
                    true,
                    false,
                    true,
                )
                .await
                .unwrap_err()
        );
    }

    #[tokio::test]
    async fn database_worker_patch_creates_new_version_and_keeps_latest_state() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let old_notes_id = database.create_file(b"old notes".to_vec()).await.unwrap();
        let new_notes_id = database.create_file(b"new notes".to_vec()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    },
                    "files": {
                        "notes": {"id": old_notes_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "new"}
                    },
                    "files": {
                        "notes": {"id": new_notes_id}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            2,
            database
                .test_item_version_count("dir", "item")
                .await
                .unwrap()
        );
        let item = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("alice", field(&item, "username").data);
        assert_eq!("new", field(&item, "password").data);
        assert_eq!(9, file(&item, "notes").size);
        assert_eq!(
            b"new notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "item".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
    }

    #[tokio::test]
    async fn database_worker_patch_removes_fields_and_files_in_new_versions() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let notes_id = database.create_file(b"old notes".to_vec()).await.unwrap();
        let attachment_id = database.create_file(b"attachment".to_vec()).await.unwrap();
        let notes_path = database.test_file_path(&notes_id);
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    },
                    "files": {
                        "notes": {"id": notes_id},
                        "attachment": {"id": attachment_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"remove": true},
                        "missing": {"remove": true}
                    },
                    "files": {
                        "notes": {"remove": true},
                        "missing": {"remove": true}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            2,
            database
                .test_item_version_count("dir", "item")
                .await
                .unwrap()
        );
        let latest = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert!(!has_field(&latest, "username"));
        assert_eq!("old", field(&latest, "password").data);
        assert!(!has_file(&latest, "notes"));
        assert_eq!(10, file(&latest, "attachment").size);
        assert!(matches!(
            database
                .get_reference(
                    "dir".to_owned(),
                    "item".to_owned(),
                    "notes".to_owned(),
                    None,
                    false,
                    false,
                )
                .await,
            Err(DbError::NotFoundMessage(message)) if message == "reference `dir/item/notes` not found"
        ));
        assert!(notes_path.exists());

        let original = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                Some(1),
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("alice", field(&original, "username").data);
        assert_eq!(9, file(&original, "notes").size);

        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"remove": true}
                    },
                    "files": {
                        "attachment": {"remove": true}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let empty_latest = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert!(empty_latest.fields.is_empty());
        assert!(empty_latest.files.is_empty());
    }

    #[tokio::test]
    async fn list_item_versions_paginates_newest_first_and_scopes_markers() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        for item in ["first", "second"] {
            database
                .create_item(
                    "dir".to_owned(),
                    item.to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }
        for value in ["two", "three"] {
            database
                .update_item(
                    "dir".to_owned(),
                    "first".to_owned(),
                    item_request(serde_json::json!({
                        "fields": {
                            "value": {"type": "string", "data": value}
                        }
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }

        let first_page = database
            .list_item_versions(
                "dir".to_owned(),
                "first".to_owned(),
                PageRequest {
                    count: 1,
                    marker: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(vec![3], version_numbers(&first_page.entries));
        assert!(first_page.entries[0].created_at.ends_with('Z'));
        let marker = first_page.next_marker.unwrap();

        let second_page = database
            .list_item_versions(
                "dir".to_owned(),
                "first".to_owned(),
                PageRequest {
                    count: 2,
                    marker: Some(marker.clone()),
                },
            )
            .await
            .unwrap();
        assert_eq!(vec![2, 1], version_numbers(&second_page.entries));
        assert_eq!(None, second_page.next_marker);

        let error = database
            .list_item_versions(
                "dir".to_owned(),
                "second".to_owned(),
                PageRequest {
                    count: 1,
                    marker: Some(marker),
                },
            )
            .await
            .unwrap_err();
        assert_eq!(DbError::BadRequest("invalid marker".to_owned()), error);
    }

    #[tokio::test]
    async fn historical_item_reads_and_restore_use_requested_retained_version() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let old_notes_id = database.create_file(b"old notes".to_vec()).await.unwrap();
        let new_notes_id = database.create_file(b"new notes".to_vec()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "old"}
                    },
                    "files": {
                        "notes": {"id": old_notes_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "new"}
                    },
                    "files": {
                        "notes": {"id": new_notes_id}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();

        let latest = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("new", field(&latest, "password").data);
        assert_eq!(9, file(&latest, "notes").size);

        let masked_old = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                Some(1),
                false,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("******", field(&masked_old, "password").data);
        assert_eq!(9, file(&masked_old, "notes").size);

        let revealed_old = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                Some(1),
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("old", field(&revealed_old, "password").data);
        assert_eq!(
            b"old notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "item".to_owned(),
                        "notes".to_owned(),
                        Some(1),
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            DbError::NotFound,
            database
                .get_item(
                    "dir".to_owned(),
                    "item".to_owned(),
                    Some(99),
                    true,
                    false,
                    false
                )
                .await
                .unwrap_err()
        );

        let before = database.dispatch_counts();
        database
            .restore_item_version("dir".to_owned(), "item".to_owned(), 1)
            .await
            .unwrap();
        let after = database.dispatch_counts();
        assert_eq!(before.0 + 1, after.0);
        assert_eq!(before.1, after.1);

        assert_eq!(
            vec![1, 2, 3],
            database.test_item_versions("dir", "item").await.unwrap()
        );
        assert_eq!(2, database.test_file_store_entries().len());
        let restored = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("old", field(&restored, "password").data);
        assert_eq!(
            b"old notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "item".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert!(matches!(
            database
                .restore_item_version("dir".to_owned(), "item".to_owned(), 3)
                .await
                .unwrap_err(),
            DbError::BadRequest(_)
        ));
        assert_eq!(
            DbError::NotFound,
            database
                .restore_item_version("dir".to_owned(), "item".to_owned(), 99)
                .await
                .unwrap_err()
        );
    }

    #[tokio::test]
    async fn database_worker_first_item_version_is_one() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            vec![1],
            database.test_item_versions("dir", "item").await.unwrap()
        );
    }

    #[tokio::test]
    async fn database_worker_item_versions_increment_per_item() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();
        for value in ["one", "two"] {
            database
                .update_item(
                    "dir".to_owned(),
                    "item".to_owned(),
                    item_request(serde_json::json!({
                        "fields": {
                            "password": {"type": "string", "data": value}
                        }
                    }))
                    .unwrap(),
                )
                .await
                .unwrap();
        }

        assert_eq!(
            vec![1, 2, 3],
            database.test_item_versions("dir", "item").await.unwrap()
        );
    }

    #[tokio::test]
    async fn database_worker_separate_items_each_start_at_version_one() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        for item_name in ["first", "second"] {
            database
                .create_item(
                    "dir".to_owned(),
                    item_name.to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    None,
                )
                .await
                .unwrap();
        }

        assert_eq!(
            vec![1],
            database.test_item_versions("dir", "first").await.unwrap()
        );
        assert_eq!(
            vec![1],
            database.test_item_versions("dir", "second").await.unwrap()
        );
    }

    #[tokio::test]
    async fn database_worker_file_mappings_are_scoped_by_item_and_version() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let first_id = database.create_file(b"first notes".to_vec()).await.unwrap();
        let second_id = database
            .create_file(b"second notes".to_vec())
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "first".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": first_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "second".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": second_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        assert_eq!(
            vec![1],
            database.test_item_versions("dir", "first").await.unwrap()
        );
        assert_eq!(
            vec![1],
            database.test_item_versions("dir", "second").await.unwrap()
        );
        assert_eq!(
            b"first notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "first".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
        assert_eq!(
            b"second notes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "second".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
    }

    #[tokio::test]
    async fn write_methods_dispatch_to_writer_worker() {
        let database = DbHandle::test();
        let before = database.dispatch_counts();

        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .update_dir(
                "dir".to_owned(),
                crate::agent::models::UpdateDirRequest {
                    name: "renamed".to_owned(),
                },
            )
            .await
            .unwrap();
        database
            .create_item(
                "renamed".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "renamed".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database
            .delete_item("renamed".to_owned(), "item".to_owned())
            .await
            .unwrap();
        database.delete_dir("renamed".to_owned()).await.unwrap();

        let after = database.dispatch_counts();
        assert_eq!(before.0 + 6, after.0);
        assert_eq!(before.1, after.1);
    }

    #[tokio::test]
    async fn delete_dir_requires_empty_dir() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();

        let error = database.delete_dir("dir".to_owned()).await.unwrap_err();
        assert_eq!(
            DbError::Conflict("directory is not empty".to_owned()),
            error
        );
        assert!(
            database
                .get_item(
                    "dir".to_owned(),
                    "item".to_owned(),
                    None,
                    false,
                    false,
                    false
                )
                .await
                .is_ok()
        );

        database
            .delete_item("dir".to_owned(), "item".to_owned())
            .await
            .unwrap();
        database.delete_dir("dir".to_owned()).await.unwrap();
    }

    #[tokio::test]
    async fn system_dirs_reject_item_mutations() {
        let database = DbHandle::test();
        database.create_dir("frozen".to_owned()).await.unwrap();
        database.create_dir("dest".to_owned()).await.unwrap();
        database
            .create_item(
                "frozen".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "frozen".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "old"}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database
            .test_set_dir_bitmask("frozen", super::DIR_SYSTEM)
            .await
            .unwrap();

        assert_eq!(
            DbError::AccessDenied,
            database
                .create_item(
                    "frozen".to_owned(),
                    "new".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    None,
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .create_item(
                    "frozen".to_owned(),
                    "copy".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    Some(super::ItemSource::Copy(super::CopySource {
                        dir_name: "dest".to_owned(),
                        item_name: "missing".to_owned(),
                    })),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .create_item(
                    "frozen".to_owned(),
                    "moved".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    Some(super::ItemSource::Move(super::CopySource {
                        dir_name: "dest".to_owned(),
                        item_name: "missing".to_owned(),
                    })),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .create_item(
                    "dest".to_owned(),
                    "moved".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                    Some(super::ItemSource::Move(super::CopySource {
                        dir_name: "frozen".to_owned(),
                        item_name: "item".to_owned(),
                    })),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .update_item(
                    "frozen".to_owned(),
                    "item".to_owned(),
                    item_request(serde_json::json!({})).unwrap(),
                )
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .restore_item_version("frozen".to_owned(), "item".to_owned(), 1)
                .await
                .unwrap_err()
        );
        assert_eq!(
            DbError::AccessDenied,
            database
                .delete_item("frozen".to_owned(), "item".to_owned())
                .await
                .unwrap_err()
        );
    }

    #[tokio::test]
    async fn get_reference_dispatches_to_reader_worker() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let notes_id = database.create_file(b"hello".to_vec()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": notes_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let before = database.dispatch_counts();

        assert_eq!(
            b"hello".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "item".to_owned(),
                        "notes".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body
            )
            .await
            .as_slice()
        );

        let after = database.dispatch_counts();
        assert_eq!(before.0, after.0);
        assert_eq!(before.1 + 1, after.1);
    }

    #[tokio::test]
    async fn create_file_writes_ciphertext_and_reference_decrypts_plaintext() {
        let database = DbHandle::test();
        let (sender, receiver) = tokio::sync::mpsc::channel(2);
        sender
            .send(Zeroizing::new(b"secret ".to_vec()))
            .await
            .unwrap();
        sender
            .send(Zeroizing::new(b"notes".to_vec()))
            .await
            .unwrap();
        drop(sender);
        let file_id = database
            .create_file_from_chunks(receiver, 12)
            .await
            .unwrap();
        let encrypted_path = database.test_file_path(&file_id);
        let encrypted = std::fs::read(&encrypted_path).unwrap();

        assert_ne!(b"secret notes".as_slice(), encrypted.as_slice());
        assert_eq!(
            PRIVATE_FILE_MODE,
            std::fs::metadata(&encrypted_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );
        assert_eq!(
            PRIVATE_DIR_MODE,
            std::fs::metadata(encrypted_path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );
        assert_eq!(
            PRIVATE_DIR_MODE,
            std::fs::metadata(database.pool.file_store_path.join("tmp"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777
        );

        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        let reference = database
            .get_reference(
                "dir".to_owned(),
                "item".to_owned(),
                "notes".to_owned(),
                None,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            b"secret notes".as_slice(),
            reference_body(reference.body).await.as_slice()
        );
        assert_eq!(Some(super::sha256_hex(b"secret notes")), reference.etag);
    }

    #[tokio::test]
    async fn uploaded_file_stores_fixed_records_and_round_trips() {
        let database = DbHandle::test();
        let body = vec![7; FILE_RECORD_PLAINTEXT_BYTES + 3];

        let file_id = database.create_file(body.clone()).await.unwrap();
        assert_eq!(
            super::FILE_NONCE_PREFIX_BYTES,
            database.test_file_nonce_len(&file_id).await.unwrap()
        );
        let encrypted = std::fs::read(database.test_file_path(&file_id)).unwrap();

        let first_len = u32::from_be_bytes(encrypted[..4].try_into().unwrap()) as usize;
        let second_offset = 4 + super::AES_GCM_TAG_BYTES + first_len;
        let second_len = u32::from_be_bytes(
            encrypted[second_offset..second_offset + 4]
                .try_into()
                .unwrap(),
        ) as usize;
        assert_eq!(FILE_RECORD_PLAINTEXT_BYTES, first_len);
        assert_eq!(3, second_len);

        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let reference = database
            .get_reference(
                "dir".to_owned(),
                "item".to_owned(),
                "notes".to_owned(),
                None,
                false,
                false,
            )
            .await
            .unwrap();

        assert_eq!(body, reference_body(reference.body).await);
    }

    #[tokio::test]
    async fn create_file_rejects_uploads_larger_than_nonce_counter_space() {
        let database = DbHandle::test();
        let (_sender, receiver) = tokio::sync::mpsc::channel(1);
        let before = database.dispatch_counts();

        let error = database
            .create_file_from_chunks(receiver, MAX_FILE_UPLOAD_BYTES + 1)
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest("file too large".to_owned()),
            error
        );
        assert_eq!(before, database.dispatch_counts());
        assert!(super::validate_file_upload_size(MAX_FILE_UPLOAD_BYTES).is_ok());
    }

    #[tokio::test]
    async fn create_file_rejects_oversized_internal_chunks() {
        let database = DbHandle::test();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Zeroizing::new(vec![0; FILE_RECORD_PLAINTEXT_BYTES + 1]))
            .await
            .unwrap();
        drop(sender);

        let error = database
            .create_file_from_chunks(receiver, (FILE_RECORD_PLAINTEXT_BYTES + 1) as u64)
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest("file chunk too large".to_owned()),
            error
        );
        assert!(database.test_file_store_entries().is_empty());
    }

    #[test]
    fn file_record_nonce_uses_prefix_and_big_endian_counter() {
        let prefix = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

        let zero = super::record_nonce(&prefix, 0).unwrap();
        assert_eq!(&prefix, &zero[..8]);
        assert_eq!([0, 0, 0, 0], zero[8..]);

        let nonzero = super::record_nonce(&prefix, 0x0102_0304).unwrap();
        assert_eq!([1, 2, 3, 4], nonzero[8..]);
        assert_eq!(
            super::DbError::BadRequest("file too large".to_owned()),
            super::record_nonce(&prefix, MAX_FILE_RECORDS).unwrap_err()
        );
    }

    #[test]
    fn decrypt_chunk_record_rejects_invalid_stored_nonce_length() {
        let key = [0u8; super::FILE_KEY_BYTES];
        let mut input = &b""[..];

        assert_eq!(
            super::DbError::Internal,
            super::decrypt_chunk_record(&mut input, &key, &[0; 12], 0).unwrap_err()
        );
    }

    #[tokio::test]
    async fn uploaded_file_can_be_attached_to_multiple_items() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let file_id = database
            .create_file(b"shared notes".to_vec())
            .await
            .unwrap();

        for item in ["first", "second"] {
            database
                .create_item(
                    "dir".to_owned(),
                    item.to_owned(),
                    item_request(serde_json::json!({
                        "files": {
                            "notes": {"id": file_id}
                        }
                    }))
                    .unwrap(),
                    None,
                )
                .await
                .unwrap();
        }

        for item in ["first", "second"] {
            let response = database
                .get_reference(
                    "dir".to_owned(),
                    item.to_owned(),
                    "notes".to_owned(),
                    None,
                    false,
                    false,
                )
                .await
                .unwrap();
            assert_eq!(
                b"shared notes".as_slice(),
                reference_body(response.body).await.as_slice()
            );
        }
        assert_eq!(1, database.test_file_store_entries().len());
    }

    #[tokio::test]
    async fn same_file_id_cannot_be_attached_twice_to_one_item() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let file_id = database.create_file(b"notes".to_vec()).await.unwrap();

        let error = database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "first": {"id": file_id},
                        "second": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest("file id must not be used more than once".to_owned()),
            error
        );
    }

    #[tokio::test]
    async fn duplicate_field_and_file_names_are_rejected() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let file_id = database.create_file(b"notes".to_vec()).await.unwrap();

        let field_error = database
            .create_item(
                "dir".to_owned(),
                "duplicate-fields".to_owned(),
                item_request(serde_json::json!({
                    "fields": [
                        {"name": "password", "type": "string", "data": "one"},
                        {"name": "password", "type": "string", "data": "two"}
                    ]
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            super::DbError::BadRequest("duplicate field name `password`".to_owned()),
            field_error
        );

        let file_error = database
            .create_item(
                "dir".to_owned(),
                "duplicate-files".to_owned(),
                item_request(serde_json::json!({
                    "files": [
                        {"name": "notes", "id": file_id},
                        {"name": "notes", "id": file_id}
                    ]
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            super::DbError::BadRequest("duplicate file name `notes`".to_owned()),
            file_error
        );

        let overlap_error = database
            .create_item(
                "dir".to_owned(),
                "overlap".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "one"}
                    },
                    "files": {
                        "password": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(
            super::DbError::BadRequest(
                "field and file names must be unique: `password`".to_owned()
            ),
            overlap_error
        );
    }

    #[tokio::test]
    async fn reference_reads_prefer_matching_fields_over_files() {
        let (_tempdir, database) = legacy_overlap_database();

        assert_eq!(
            b"field-bytes".as_slice(),
            reference_body(
                database
                    .get_reference(
                        "dir".to_owned(),
                        "item".to_owned(),
                        "password".to_owned(),
                        None,
                        false,
                        false,
                    )
                    .await
                    .unwrap()
                    .body,
            )
            .await
            .as_slice()
        );
    }

    #[tokio::test]
    async fn update_rejects_field_and_file_name_overlap_in_final_item() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let file_id = database.create_file(b"file-bytes".to_vec()).await.unwrap();
        let new_file_id = database.create_file(b"new-file".to_vec()).await.unwrap();

        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "field-bytes"}
                    },
                    "files": {
                        "notes": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        let error = database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "password": {"id": new_file_id}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest(
                "field and file names must be unique: `password`".to_owned()
            ),
            error
        );
    }

    #[tokio::test]
    async fn copy_item_shares_file_mapping_without_copying_blob() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let file_id = database.create_file(b"copy me".to_vec()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "source".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": file_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();

        database
            .create_item(
                "dir".to_owned(),
                "copy".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Copy(super::CopySource {
                    dir_name: "dir".to_owned(),
                    item_name: "source".to_owned(),
                })),
            )
            .await
            .unwrap();

        assert_eq!(1, database.test_file_store_entries().len());
        let response = database
            .get_reference(
                "dir".to_owned(),
                "copy".to_owned(),
                "notes".to_owned(),
                None,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            b"copy me".as_slice(),
            reference_body(response.body).await.as_slice()
        );
    }

    #[tokio::test]
    async fn duplicate_upload_returns_existing_id_and_removes_temp_blob() {
        let database = DbHandle::test();

        let first_id = database.create_file(b"duplicate".to_vec()).await.unwrap();
        let second_id = database.create_file(b"duplicate".to_vec()).await.unwrap();

        assert_eq!(first_id, second_id);
        assert_eq!(1, database.test_file_store_entries().len());
    }

    #[tokio::test]
    async fn lookup_file_by_sha256_returns_existing_file_id() {
        let database = DbHandle::test();
        let file_id = database.create_file(b"lookup".to_vec()).await.unwrap();

        assert_eq!(
            file_id,
            database
                .lookup_file_by_sha256(super::sha256_hex(b"lookup"))
                .await
                .unwrap()
        );
        assert_eq!(
            super::DbError::NotFoundMessage(format!(
                "file with sha256 `{}` not found",
                super::sha256_hex(b"missing")
            )),
            database
                .lookup_file_by_sha256(super::sha256_hex(b"missing"))
                .await
                .unwrap_err()
        );
        assert!(matches!(
            database
                .lookup_file_by_sha256("ABC".to_owned())
                .await
                .unwrap_err(),
            super::DbError::BadRequest(_)
        ));
    }

    #[tokio::test]
    async fn create_file_removes_temp_file_when_stream_ends_before_content_length() {
        let database = DbHandle::test();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Zeroizing::new(b"partial".to_vec()))
            .await
            .unwrap();
        drop(sender);

        let error = database
            .create_file_from_chunks(receiver, 10)
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest("request body ended before content-length".to_owned()),
            error
        );
        assert!(database.test_file_store_entries().is_empty());
    }

    #[tokio::test]
    async fn create_file_removes_temp_file_when_stream_exceeds_content_length() {
        let database = DbHandle::test();
        let (sender, receiver) = tokio::sync::mpsc::channel(1);
        sender
            .send(Zeroizing::new(b"too long".to_vec()))
            .await
            .unwrap();
        drop(sender);

        let error = database
            .create_file_from_chunks(receiver, 3)
            .await
            .unwrap_err();

        assert_eq!(
            super::DbError::BadRequest("request body exceeds content-length".to_owned()),
            error
        );
        assert!(database.test_file_store_entries().is_empty());
    }

    #[tokio::test]
    async fn authorization_expiry_unload_removes_old_orphan_files_when_cleanup_due() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let file_id = database.create_file(b"orphan".to_vec()).await.unwrap();
        let file_path = database.test_file_path(&file_id);
        database
            .test_set_file_created_at(&file_id, super::now_timestamp() - 8 * 24 * 60 * 60)
            .await
            .unwrap();
        let last_access = Instant::now();
        state.store_database_handle(database).await;
        state.store_password_verifier("correct").await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        state
            .set_max_authorization_expires_at(Some(last_access + AUTH_TTL))
            .await;
        state
            .set_last_cleanup_at(Some(last_access - CLEANUP_INTERVAL))
            .await;

        assert!(
            state
                .unload_if_authorization_expired(last_access + AUTH_TTL)
                .await
        );

        assert!(!file_path.exists());
    }

    #[tokio::test]
    async fn authorization_expiry_unload_retains_recent_or_attached_files_when_cleanup_due() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let recent_id = database.create_file(b"recent".to_vec()).await.unwrap();
        let attached_id = database.create_file(b"attached".to_vec()).await.unwrap();
        let recent_path = database.test_file_path(&recent_id);
        let attached_path = database.test_file_path(&attached_id);
        database
            .test_set_file_created_at(&attached_id, super::now_timestamp() - 8 * 24 * 60 * 60)
            .await
            .unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "attached": {"id": attached_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let last_access = Instant::now();
        state.store_database_handle(database).await;
        state.store_password_verifier("correct").await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        state
            .set_max_authorization_expires_at(Some(last_access + AUTH_TTL))
            .await;
        state
            .set_last_cleanup_at(Some(last_access - CLEANUP_INTERVAL))
            .await;

        assert!(
            state
                .unload_if_authorization_expired(last_access + AUTH_TTL)
                .await
        );

        assert!(recent_path.exists());
        assert!(attached_path.exists());
    }

    #[tokio::test]
    async fn authorization_expiry_unload_removes_old_non_latest_versions_and_repairs_oldest_pointer_when_cleanup_due()
     {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "old"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "password": {"type": "string", "data": "new"}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database
            .test_set_item_versions_created_at(
                "dir",
                "item",
                false,
                super::now_timestamp() - 91 * 24 * 60 * 60,
            )
            .await
            .unwrap();
        let last_access = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        state
            .set_max_authorization_expires_at(Some(last_access + AUTH_TTL))
            .await;
        state
            .set_last_cleanup_at(Some(last_access - CLEANUP_INTERVAL))
            .await;

        assert!(
            state
                .unload_if_authorization_expired(last_access + AUTH_TTL)
                .await
        );

        assert_eq!(
            1,
            database
                .test_item_version_count("dir", "item")
                .await
                .unwrap()
        );
        assert!(
            database
                .test_oldest_version_is_earliest("dir", "item")
                .await
                .unwrap()
        );
        let item = database
            .get_item(
                "dir".to_owned(),
                "item".to_owned(),
                None,
                true,
                false,
                false,
            )
            .await
            .unwrap();
        assert_eq!("new", field(&item, "password").data);
    }

    #[tokio::test]
    async fn authorization_expiry_unload_keeps_latest_version_even_when_cleanup_due() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .test_set_item_versions_created_at(
                "dir",
                "item",
                true,
                super::now_timestamp() - 91 * 24 * 60 * 60,
            )
            .await
            .unwrap();
        let last_access = Instant::now();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        state
            .set_max_authorization_expires_at(Some(last_access + AUTH_TTL))
            .await;
        state
            .set_last_cleanup_at(Some(last_access - CLEANUP_INTERVAL))
            .await;

        assert!(
            state
                .unload_if_authorization_expired(last_access + AUTH_TTL)
                .await
        );

        assert_eq!(
            1,
            database
                .test_item_version_count("dir", "item")
                .await
                .unwrap()
        );
        assert!(
            database
                .get_item(
                    "dir".to_owned(),
                    "item".to_owned(),
                    None,
                    false,
                    false,
                    false
                )
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn authorization_expiry_unload_orphans_files_after_old_version_cleanup_when_cleanup_due()
    {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        let old_id = database.create_file(b"old notes".to_vec()).await.unwrap();
        let new_id = database.create_file(b"new notes".to_vec()).await.unwrap();
        let old_path = database.test_file_path(&old_id);
        let new_path = database.test_file_path(&new_id);
        database
            .create_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": old_id}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        database
            .update_item(
                "dir".to_owned(),
                "item".to_owned(),
                item_request(serde_json::json!({
                    "files": {
                        "notes": {"id": new_id}
                    }
                }))
                .unwrap(),
            )
            .await
            .unwrap();
        database
            .test_set_file_created_at(&old_id, super::now_timestamp() - 8 * 24 * 60 * 60)
            .await
            .unwrap();
        database
            .test_set_item_versions_created_at(
                "dir",
                "item",
                false,
                super::now_timestamp() - 91 * 24 * 60 * 60,
            )
            .await
            .unwrap();
        let last_access = Instant::now();
        state.store_database_handle(database).await;
        state.store_password_verifier("correct").await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        state
            .set_max_authorization_expires_at(Some(last_access + AUTH_TTL))
            .await;
        state
            .set_last_cleanup_at(Some(last_access - CLEANUP_INTERVAL))
            .await;

        assert!(
            state
                .unload_if_authorization_expired(last_access + AUTH_TTL)
                .await
        );

        assert!(!old_path.exists());
        assert!(new_path.exists());
    }

    #[tokio::test]
    async fn copy_item_dispatches_to_writer_worker() {
        let database = DbHandle::test();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_item(
                "dir".to_owned(),
                "source".to_owned(),
                item_request(serde_json::json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"}
                    }
                }))
                .unwrap(),
                None,
            )
            .await
            .unwrap();
        let before = database.dispatch_counts();

        database
            .create_item(
                "dir".to_owned(),
                "copy".to_owned(),
                item_request(serde_json::json!({})).unwrap(),
                Some(super::ItemSource::Copy(super::CopySource {
                    dir_name: "dir".to_owned(),
                    item_name: "source".to_owned(),
                })),
            )
            .await
            .unwrap();

        let after = database.dispatch_counts();
        assert_eq!(before.0 + 1, after.0);
        assert_eq!(before.1, after.1);
    }

    #[tokio::test]
    async fn simultaneous_reads_complete_through_multiple_reader_workers() {
        let database = DbHandle::test();
        let started = Instant::now();
        let tasks = (0..super::DATABASE_READER_WORKERS)
            .map(|_| {
                let database = database.clone();
                tokio::spawn(async move {
                    database
                        .test_slow_read(Duration::from_millis(150))
                        .await
                        .unwrap();
                })
            })
            .collect::<Vec<_>>();

        for task in tasks {
            task.await.unwrap();
        }

        assert!(started.elapsed() < Duration::from_millis(700));
    }

    #[tokio::test]
    async fn blocked_reader_does_not_prevent_writer_from_completing() {
        let database = DbHandle::test();
        let slow_read = {
            let database = database.clone();
            tokio::spawn(async move {
                database
                    .test_slow_read(Duration::from_millis(300))
                    .await
                    .unwrap();
            })
        };
        tokio::time::sleep(Duration::from_millis(50)).await;

        let started = Instant::now();
        database.create_dir("dir".to_owned()).await.unwrap();

        assert!(started.elapsed() < Duration::from_millis(250));
        slow_read.await.unwrap();
    }

    #[tokio::test]
    async fn queued_writes_preserve_single_writer_order() {
        let database = DbHandle::test();
        let slow_write = {
            let database = database.clone();
            tokio::spawn(async move {
                database
                    .test_slow_write(Duration::from_millis(200))
                    .await
                    .unwrap();
            })
        };
        tokio::time::sleep(Duration::from_millis(25)).await;

        let started = Instant::now();
        database.create_dir("dir".to_owned()).await.unwrap();

        assert!(started.elapsed() >= Duration::from_millis(120));
        assert!(database.get_dir("dir".to_owned()).await.is_ok());
        slow_write.await.unwrap();
    }

    #[test]
    fn totp_generation_matches_rfc_6238_vectors() {
        let sha1_secret = BASE32_NOPAD.encode(b"12345678901234567890");
        let sha256_secret = BASE32_NOPAD.encode(b"12345678901234567890123456789012");
        let sha512_secret = BASE32_NOPAD
            .encode(b"1234567890123456789012345678901234567890123456789012345678901234");

        for (time, sha1, sha256, sha512) in [
            (59, "94287082", "46119246", "90693936"),
            (1_111_111_109, "07081804", "68084774", "25091201"),
            (1_111_111_111, "14050471", "67062674", "99943326"),
            (1_234_567_890, "89005924", "91819424", "93441116"),
            (2_000_000_000, "69279037", "90698825", "38618901"),
            (20_000_000_000, "65353130", "77737706", "47863826"),
        ] {
            assert_eq!(
                sha1,
                super::generate_totp_at(
                    &format!("otpauth://totp/test?secret={sha1_secret}&digits=8&period=30"),
                    time,
                )
                .unwrap()
            );
            assert_eq!(
                sha256,
                super::generate_totp_at(
                    &format!(
                        "otpauth://totp/test?secret={sha256_secret}&digits=8&period=30&algorithm=SHA256"
                    ),
                    time,
                )
                .unwrap()
            );
            assert_eq!(
                sha512,
                super::generate_totp_at(
                    &format!(
                        "otpauth://totp/test?secret={sha512_secret}&digits=8&period=30&algorithm=SHA512"
                    ),
                    time,
                )
                .unwrap()
            );
        }
    }

    #[test]
    fn auth_cache_evicts_least_recently_used_entry_after_32_entries() {
        let mut cache = AuthCache::default();
        let now = Instant::now();

        for value in 0..32 {
            cache.insert(ProcessChainHash::test(value), now);
        }
        assert!(cache.contains(&ProcessChainHash::test(0), now, AUTH_TTL));

        cache.insert(ProcessChainHash::test(32), now);

        assert!(cache.contains(&ProcessChainHash::test(0), now, AUTH_TTL));
        assert!(!cache.contains(&ProcessChainHash::test(1), now, AUTH_TTL));
    }

    #[test]
    fn auth_cache_expires_after_fixed_ttl() {
        let mut cache = AuthCache::default();
        let now = Instant::now();
        cache.insert(ProcessChainHash::test(1), now);

        assert!(!cache.contains(&ProcessChainHash::test(1), now + AUTH_TTL, AUTH_TTL));
    }

    #[test]
    fn auth_cache_expires_at_returns_insertion_plus_ttl() {
        let mut cache = AuthCache::default();
        let now = Instant::now();
        cache.insert(ProcessChainHash::test(1), now);

        assert_eq!(
            Some(now + AUTH_TTL),
            cache.expires_at(&ProcessChainHash::test(1), now, AUTH_TTL)
        );
    }

    #[test]
    fn auth_cache_expires_at_returns_none_at_or_after_expiry() {
        let mut cache = AuthCache::default();
        let now = Instant::now();
        cache.insert(ProcessChainHash::test(1), now);

        assert_eq!(
            None,
            cache.expires_at(&ProcessChainHash::test(1), now + AUTH_TTL, AUTH_TTL)
        );
        assert_eq!(
            None,
            cache.expires_at(
                &ProcessChainHash::test(1),
                now + AUTH_TTL + Duration::from_secs(1),
                AUTH_TTL
            )
        );
    }

    #[test]
    fn auth_cache_expires_at_does_not_change_lru_ordering() {
        let mut cache = AuthCache::default();
        let now = Instant::now();

        for value in 0..32 {
            cache.insert(ProcessChainHash::test(value), now);
        }

        assert_eq!(
            Some(now + AUTH_TTL),
            cache.expires_at(&ProcessChainHash::test(0), now, AUTH_TTL)
        );
        cache.insert(ProcessChainHash::test(32), now);

        assert!(!cache.contains(&ProcessChainHash::test(0), now, AUTH_TTL));
        assert!(cache.contains(&ProcessChainHash::test(1), now, AUTH_TTL));
    }

    #[test]
    fn auth_cache_lookup_does_not_extend_expiration() {
        let mut cache = AuthCache::default();
        let now = Instant::now();
        cache.insert(ProcessChainHash::test(1), now);

        assert!(cache.contains(
            &ProcessChainHash::test(1),
            now + AUTH_TTL - Duration::from_secs(1),
            AUTH_TTL
        ));
        assert!(!cache.contains(&ProcessChainHash::test(1), now + AUTH_TTL, AUTH_TTL));
    }

    #[test]
    fn auth_cache_reinsert_refreshes_insertion_time() {
        let mut cache = AuthCache::default();
        let now = Instant::now();
        cache.insert(ProcessChainHash::test(1), now);
        cache.insert(
            ProcessChainHash::test(1),
            now + AUTH_TTL - Duration::from_secs(1),
        );

        assert!(cache.contains(&ProcessChainHash::test(1), now + AUTH_TTL, AUTH_TTL));
    }

    fn create_encrypted_database(path: &std::path::Path, password: &str) {
        crate::db::create_encrypted_database_with_password(path, password).unwrap();
    }

    fn password(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    fn default_page() -> PageRequest {
        PageRequest {
            count: 50,
            marker: None,
        }
    }

    fn names(entries: &[crate::agent::models::DirResponse]) -> Vec<&str> {
        entries.iter().map(|entry| entry.name.as_str()).collect()
    }

    fn item_names(entries: &[crate::agent::models::ItemSummaryResponse]) -> Vec<&str> {
        entries.iter().map(|entry| entry.name.as_str()).collect()
    }

    fn version_numbers(entries: &[crate::agent::models::ItemVersionSummaryResponse]) -> Vec<i64> {
        entries.iter().map(|entry| entry.version).collect()
    }

    async fn reference_body(body: super::ReferenceBody) -> Vec<u8> {
        match body {
            super::ReferenceBody::Bytes(mut bytes) => std::mem::take(&mut *bytes),
            super::ReferenceBody::Stream(mut receiver) => {
                let mut bytes = Vec::new();
                while let Some(chunk) = receiver.recv().await {
                    let mut chunk = chunk.unwrap();
                    bytes.extend(std::mem::take(&mut *chunk));
                }
                bytes
            }
        }
    }
}
