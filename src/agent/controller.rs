use axum::Extension;
use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::rejection::JsonRejection;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose;
use chrono::{Duration as ChronoDuration, SecondsFormat, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;
use std::time::Instant;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use zeroize::Zeroizing;

use super::error::ApiError;
use super::models::{
    AuthStatusResponse, ContactResponse, CreateContactRequest, CreateFileResponse,
    CreateItemRequest, JobAcceptedResponse, JobResponse, JobStatus, ListPageQuery,
    PaginatedResponse, UpdateContactRequest, UpdateDirRequest, UpdateItemRequest,
    UpdateSettingRequest,
};
use super::process::ProcessChainHash;
use super::state::{
    AgentState, CopySource, DbError, DbHandle, FILE_RECORD_PLAINTEXT_BYTES, ItemSource,
    PageRequest, ReferenceBody, UnlockError, validate_file_upload_size,
};

const DEFAULT_PAGE_COUNT: u64 = 50;
const MAX_PAGE_COUNT: u64 = 200;
const PRIVATE_FILE_MODE: u32 = 0o600;

pub async fn unlock(
    State(state): State<AgentState>,
    process_hash: Option<Extension<ProcessChainHash>>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiError> {
    let Extension(process_hash) = process_hash.ok_or_else(ApiError::access_denied)?;
    let password = bearer_password(&headers)?;

    state
        .unlock(password, process_hash)
        .await
        .map(|()| StatusCode::OK)
        .map_err(|error| match error {
            UnlockError::AccessDenied => ApiError::access_denied(),
            UnlockError::UnlockFailed => ApiError::unlock_failed(),
        })
}

pub async fn lock(
    State(state): State<AgentState>,
    process_hash: Option<Extension<ProcessChainHash>>,
) -> Result<StatusCode, ApiError> {
    let Extension(_) = process_hash.ok_or_else(ApiError::access_denied)?;
    state.lock(Instant::now()).await;
    Ok(StatusCode::OK)
}

pub async fn status(
    State(state): State<AgentState>,
    process_hash: Option<Extension<ProcessChainHash>>,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let Extension(process_hash) = process_hash.ok_or_else(ApiError::access_denied)?;
    let expires_at = state
        .authorization_expires_at(&process_hash)
        .await
        .ok_or_else(ApiError::access_denied)?;
    let reauth_timestamp = reauth_timestamp(expires_at).ok_or_else(ApiError::access_denied)?;

    Ok(Json(AuthStatusResponse { reauth_timestamp }))
}

fn reauth_timestamp(expires_at: Instant) -> Option<String> {
    let remaining = expires_at.checked_duration_since(Instant::now())?;
    if remaining.is_zero() {
        return None;
    }

    let timestamp = Utc::now() + ChronoDuration::from_std(remaining).ok()?;
    Some(timestamp.to_rfc3339_opts(SecondsFormat::Secs, true))
}

fn bearer_password(headers: &HeaderMap) -> Result<Zeroizing<String>, ApiError> {
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .ok_or_else(ApiError::access_denied)?
        .to_str()
        .map_err(|_| ApiError::access_denied())?;

    let token = authorization
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or_else(ApiError::access_denied)?;

    let password_bytes = Zeroizing::new(
        general_purpose::STANDARD
            .decode(token)
            .map_err(|_| ApiError::access_denied())?,
    );

    let password = std::str::from_utf8(&password_bytes).map_err(|_| ApiError::access_denied())?;

    Ok(Zeroizing::new(password.to_owned()))
}

async fn optional_bearer_password_is_valid(state: &AgentState, headers: &HeaderMap) -> bool {
    match bearer_password(headers) {
        Ok(password) => state.verify_settings_password(&password).await,
        Err(_) => false,
    }
}

pub async fn create_dir(
    Extension(database): Extension<DbHandle>,
    Path(dir_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    database
        .create_dir(dir_name)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn get_dir(
    Extension(database): Extension<DbHandle>,
    Path(dir_name): Path<String>,
) -> Result<Json<super::models::DirResponse>, ApiError> {
    database
        .get_dir(dir_name)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn list_dirs(
    Extension(database): Extension<DbHandle>,
    query: Result<Query<ListPageQuery>, QueryRejection>,
) -> Result<Json<PaginatedResponse<super::models::DirResponse>>, ApiError> {
    let page = page_request(query)?;
    database
        .list_dirs(page)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn create_contact(
    Extension(database): Extension<DbHandle>,
    Path(email): Path<String>,
    request: Result<Json<CreateContactRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    database
        .create_contact(email, request)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn update_contact(
    Extension(database): Extension<DbHandle>,
    Path(email): Path<String>,
    request: Result<Json<UpdateContactRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    database
        .update_contact(email, request)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn list_contacts(
    Extension(database): Extension<DbHandle>,
    query: Result<Query<ListPageQuery>, QueryRejection>,
) -> Result<Json<PaginatedResponse<ContactResponse>>, ApiError> {
    let page = page_request(query)?;
    database
        .list_contacts(page)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn delete_contact(
    Extension(database): Extension<DbHandle>,
    Path(email): Path<String>,
) -> Result<Json<Value>, ApiError> {
    database
        .delete_contact(email)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn list_settings(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    headers: HeaderMap,
) -> Result<Json<std::collections::HashMap<String, String>>, ApiError> {
    let password = bearer_password(&headers)?;
    if !state.verify_settings_password(&password).await {
        return Err(ApiError::access_denied());
    }

    database
        .list_settings()
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn update_setting(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    Path(name): Path<String>,
    headers: HeaderMap,
    request: Result<Json<UpdateSettingRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let password = bearer_password(&headers)?;
    if !state.verify_settings_password(&password).await {
        return Err(ApiError::access_denied());
    }

    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    database
        .upsert_setting(name, request.value)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn update_dir(
    Extension(database): Extension<DbHandle>,
    Path(dir_name): Path<String>,
    request: Result<Json<UpdateDirRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    database
        .update_dir(dir_name, request)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn delete_dir(
    Extension(database): Extension<DbHandle>,
    Path(dir_name): Path<String>,
) -> Result<Json<Value>, ApiError> {
    database
        .delete_dir(dir_name)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn create_file(
    Extension(database): Extension<DbHandle>,
    headers: HeaderMap,
    mut body: Body,
) -> Result<Json<CreateFileResponse>, ApiError> {
    let expected_size = content_length(&headers)?;
    validate_file_upload_size(expected_size).map_err(ApiError::from)?;
    let (sender, receiver) = tokio::sync::mpsc::channel(8);
    let task = tokio::spawn(async move {
        database
            .create_file_from_chunks(receiver, expected_size)
            .await
    });
    let mut received_size = 0_u64;
    let mut buffer = Zeroizing::new(Vec::with_capacity(FILE_RECORD_PLAINTEXT_BYTES));

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(error) => {
                drop(sender);
                let _ = task.await;
                return Err(ApiError::bad_request(error.to_string()));
            }
        };
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        received_size = received_size
            .checked_add(u64::try_from(chunk.len()).map_err(|_| ApiError::internal_error())?)
            .ok_or_else(ApiError::internal_error)?;
        if received_size > expected_size {
            drop(sender);
            let _ = task.await;
            return Err(ApiError::bad_request("request body exceeds content-length"));
        }
        send_upload_body_bytes(&sender, &mut buffer, chunk).await?;
    }
    if !buffer.is_empty() {
        sender
            .send(std::mem::take(&mut buffer))
            .await
            .map_err(|_| ApiError::internal_error())?;
    }
    drop(sender);

    task.await
        .map_err(|_| ApiError::internal_error())?
        .map(|id| Json(CreateFileResponse { id }))
        .map_err(ApiError::from)
}

async fn send_upload_body_bytes(
    sender: &tokio::sync::mpsc::Sender<Zeroizing<Vec<u8>>>,
    buffer: &mut Zeroizing<Vec<u8>>,
    mut chunk: &[u8],
) -> Result<(), ApiError> {
    while !chunk.is_empty() {
        let remaining = FILE_RECORD_PLAINTEXT_BYTES - buffer.len();
        let take = remaining.min(chunk.len());
        buffer.extend_from_slice(&chunk[..take]);
        chunk = &chunk[take..];

        if buffer.len() == FILE_RECORD_PLAINTEXT_BYTES {
            sender
                .send(std::mem::take(buffer))
                .await
                .map_err(|_| ApiError::internal_error())?;
        }
    }
    Ok(())
}

pub async fn lookup_file_by_sha256(
    Extension(database): Extension<DbHandle>,
    Path(sha256): Path<String>,
) -> Result<Json<CreateFileResponse>, ApiError> {
    database
        .lookup_file_by_sha256(sha256)
        .await
        .map(|id| Json(CreateFileResponse { id }))
        .map_err(ApiError::from)
}

pub async fn import_item(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    mut body: Body,
) -> Result<(StatusCode, Json<JobAcceptedResponse>), ApiError> {
    let encrypted_path = spool_import_body(&mut body).await?;
    let job_id = random_job_id().map_err(|_| ApiError::internal_error())?;
    database
        .create_import_job(job_id.clone(), dir_name.clone(), item_name.clone())
        .await
        .map_err(ApiError::from)?;
    state.register_active_job(job_id.clone()).await;
    spawn_import_task(
        state,
        database,
        job_id.clone(),
        dir_name,
        item_name,
        encrypted_path,
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(JobAcceptedResponse {
            job_id,
            status: JobStatus::Queued,
        }),
    ))
}

pub async fn export_item(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name, contact_name)): Path<(String, String, String)>,
) -> Result<(StatusCode, Json<JobAcceptedResponse>), ApiError> {
    let job_id = random_job_id().map_err(|_| ApiError::internal_error())?;
    database
        .create_export_job(
            job_id.clone(),
            dir_name.clone(),
            item_name.clone(),
            contact_name.clone(),
        )
        .await
        .map_err(ApiError::from)?;
    state.register_active_job(job_id.clone()).await;
    spawn_export_task(
        state,
        database,
        job_id.clone(),
        dir_name,
        item_name,
        contact_name,
    );

    Ok((
        StatusCode::ACCEPTED,
        Json(JobAcceptedResponse {
            job_id,
            status: JobStatus::Queued,
        }),
    ))
}

pub async fn get_job(
    Extension(database): Extension<DbHandle>,
    Path(job_id): Path<String>,
) -> Result<Json<JobResponse>, ApiError> {
    database
        .get_job(job_id)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

fn spawn_import_task(
    state: AgentState,
    database: DbHandle,
    job_id: String,
    dir_name: String,
    item_name: String,
    encrypted_path: PathBuf,
) {
    tokio::spawn(async move {
        let result = async {
            database.mark_job_running(job_id.clone()).await?;
            match super::import::run_import_job(
                database.clone(),
                dir_name,
                item_name,
                encrypted_path.clone(),
            )
            .await
            {
                Ok(()) => database.mark_job_succeeded(job_id.clone(), None).await,
                Err(error) => {
                    database
                        .mark_job_failed(job_id.clone(), error.code, error.message)
                        .await
                }
            }
        }
        .await;
        if let Err(error) = result {
            let _ = database
                .mark_job_failed(
                    job_id.clone(),
                    "internal_error".to_owned(),
                    match error {
                        DbError::BadRequest(message)
                        | DbError::Conflict(message)
                        | DbError::NotFoundMessage(message) => message,
                        DbError::AccessDenied => "access denied".to_owned(),
                        DbError::Internal => "internal error".to_owned(),
                        DbError::NotFound => "not found".to_owned(),
                    },
                )
                .await;
        }
        let _ = std::fs::remove_file(&encrypted_path);
        state.unregister_active_job(&job_id).await;
    });
}

fn spawn_export_task(
    state: AgentState,
    database: DbHandle,
    job_id: String,
    dir_name: String,
    item_name: String,
    contact_name: String,
) {
    tokio::spawn(async move {
        let result = async {
            database.mark_job_running(job_id.clone()).await?;
            match super::export::run_export_job(
                database.clone(),
                state.job_store_path().to_owned(),
                job_id.clone(),
                dir_name,
                item_name,
                contact_name,
            )
            .await
            {
                Ok(output_path) => {
                    database
                        .mark_job_succeeded(job_id.clone(), Some(output_path))
                        .await
                }
                Err(error) => {
                    database
                        .mark_job_failed(job_id.clone(), error.code, error.message)
                        .await
                }
            }
        }
        .await;
        if let Err(error) = result {
            let _ = database
                .mark_job_failed(
                    job_id.clone(),
                    "internal_error".to_owned(),
                    match error {
                        DbError::BadRequest(message)
                        | DbError::Conflict(message)
                        | DbError::NotFoundMessage(message) => message,
                        DbError::AccessDenied => "access denied".to_owned(),
                        DbError::Internal => "internal error".to_owned(),
                        DbError::NotFound => "not found".to_owned(),
                    },
                )
                .await;
        }
        state.unregister_active_job(&job_id).await;
    });
}

async fn spool_import_body(body: &mut Body) -> Result<PathBuf, ApiError> {
    let dir = std::env::temp_dir().join("monopass-import");
    std::fs::create_dir_all(&dir).map_err(|_| ApiError::internal_error())?;
    let mut path = dir.join(random_job_id().map_err(|_| ApiError::internal_error())?);
    path.set_extension("export");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(PRIVATE_FILE_MODE)
        .open(&path)
        .map_err(|_| ApiError::internal_error())?;
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|error| {
            let _ = std::fs::remove_file(&path);
            ApiError::bad_request(error.to_string())
        })?;
        let Some(chunk) = frame.data_ref() else {
            continue;
        };
        if let Err(error) = file.write_all(chunk) {
            let _ = std::fs::remove_file(&path);
            return Err(ApiError::bad_request(error.to_string()));
        }
    }
    file.flush().map_err(|_| ApiError::internal_error())?;
    Ok(path)
}

fn random_job_id() -> io::Result<String> {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).map_err(|error| io::Error::other(error.to_string()))?;
    Ok(hex_encode(&bytes))
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

fn content_length(headers: &HeaderMap) -> Result<u64, ApiError> {
    headers
        .get(header::CONTENT_LENGTH)
        .ok_or_else(|| ApiError::bad_request("content-length is required"))?
        .to_str()
        .map_err(|_| ApiError::bad_request("content-length must be a valid integer"))?
        .parse::<u64>()
        .map_err(|_| ApiError::bad_request("content-length must be a valid integer"))
}

pub async fn create_item(
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    request: Result<Json<CreateItemRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let source = item_source(&query)?;
    let request = match request {
        Ok(Json(request)) => request,
        Err(JsonRejection::MissingJsonContentType(_))
            if matches!(source.as_ref(), Some(ItemSource::Move(_))) =>
        {
            CreateItemRequest::default()
        }
        Err(error) => return Err(ApiError::bad_request(error.to_string())),
    };
    database
        .create_item(dir_name, item_name, request, source)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn get_item(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Json<super::models::ItemResponse>, ApiError> {
    let reveal = query.get("reveal").is_some_and(|value| value == "true");
    let raw = query.get("raw").is_some_and(|value| value == "true");
    let version = optional_positive_version(&query)?;
    let mustauth_satisfied =
        (reveal || raw) && optional_bearer_password_is_valid(&state, &headers).await;
    database
        .get_item(
            dir_name,
            item_name,
            version,
            reveal,
            raw,
            mustauth_satisfied,
        )
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn update_item(
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    request: Result<Json<UpdateItemRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    database
        .update_item(dir_name, item_name, request)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn list_items(
    Extension(database): Extension<DbHandle>,
    Path(dir_name): Path<String>,
    query: Result<Query<ListPageQuery>, QueryRejection>,
) -> Result<Json<PaginatedResponse<super::models::ItemSummaryResponse>>, ApiError> {
    let page = page_request(query)?;
    database
        .list_items(dir_name, page)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

pub async fn list_item_versions(
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    query: Result<Query<ListPageQuery>, QueryRejection>,
) -> Result<Json<PaginatedResponse<super::models::ItemVersionSummaryResponse>>, ApiError> {
    let page = page_request(query)?;
    database
        .list_item_versions(dir_name, item_name, page)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

fn page_request(
    query: Result<Query<ListPageQuery>, QueryRejection>,
) -> Result<PageRequest, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.to_string()))?;
    let count = query.count.unwrap_or(DEFAULT_PAGE_COUNT);
    if !(1..=MAX_PAGE_COUNT).contains(&count) {
        return Err(ApiError::bad_request("count must be between 1 and 200"));
    }
    Ok(PageRequest {
        count,
        marker: query.marker,
    })
}

pub async fn delete_item(
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
) -> Result<Json<Value>, ApiError> {
    database
        .delete_item(dir_name, item_name)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn restore_item_version(
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name)): Path<(String, String)>,
    Query(query): Query<HashMap<String, String>>,
) -> Result<Json<Value>, ApiError> {
    let version = required_positive_version(&query)?;
    database
        .restore_item_version(dir_name, item_name, version)
        .await
        .map(|()| empty_json())
        .map_err(ApiError::from)
}

pub async fn get_reference(
    State(state): State<AgentState>,
    Extension(database): Extension<DbHandle>,
    Path((dir_name, item_name, field_name)): Path<(String, String, String)>,
    Query(query): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Result<Response, ApiError> {
    let raw = query.get("raw").is_some_and(|value| value == "true");
    let version = optional_positive_version(&query)?;
    let mustauth_satisfied = optional_bearer_password_is_valid(&state, &headers).await;
    let reference = database
        .get_reference(
            dir_name,
            item_name,
            field_name,
            version,
            raw,
            mustauth_satisfied,
        )
        .await
        .map_err(ApiError::from)?;

    let body = match reference.body {
        ReferenceBody::Bytes(mut bytes) => Body::from(std::mem::take(&mut *bytes)),
        ReferenceBody::Stream(receiver) => {
            let stream = ReceiverStream::new(receiver).map(|result| {
                result
                    .map(|mut bytes| Bytes::from(std::mem::take(&mut *bytes)))
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "file decrypt failed"))
            });
            Body::from_stream(stream)
        }
    };
    let mut response = ([(header::CONTENT_TYPE, "application/octet-stream")], body).into_response();
    if let Some(etag) = reference.etag {
        let value =
            axum::http::HeaderValue::from_str(&etag).map_err(|_| ApiError::internal_error())?;
        response.headers_mut().insert(header::ETAG, value);
    }
    Ok(response)
}

fn optional_positive_version(query: &HashMap<String, String>) -> Result<Option<i64>, ApiError> {
    query
        .get("version")
        .map(|value| parse_positive_version(value))
        .transpose()
}

fn required_positive_version(query: &HashMap<String, String>) -> Result<i64, ApiError> {
    query
        .get("version")
        .ok_or_else(|| ApiError::bad_request("version is required"))
        .and_then(|value| parse_positive_version(value))
}

fn parse_positive_version(value: &str) -> Result<i64, ApiError> {
    let version = value
        .parse::<i64>()
        .map_err(|_| ApiError::bad_request("version must be a positive integer"))?;
    if version <= 0 {
        return Err(ApiError::bad_request("version must be a positive integer"));
    }
    Ok(version)
}

fn item_source(query: &HashMap<String, String>) -> Result<Option<ItemSource>, ApiError> {
    match (query.get("copy_from"), query.get("move_from")) {
        (Some(_), Some(_)) => Err(ApiError::bad_request(
            "copy_from and move_from are mutually exclusive",
        )),
        (Some(value), None) => parse_item_source(value, "copy_from")
            .map(ItemSource::Copy)
            .map(Some),
        (None, Some(value)) => parse_item_source(value, "move_from")
            .map(ItemSource::Move)
            .map(Some),
        (None, None) => Ok(None),
    }
}

fn parse_item_source(value: &str, name: &str) -> Result<CopySource, ApiError> {
    let (dir_name, item_name) = value
        .split_once('/')
        .ok_or_else(|| ApiError::bad_request(format!("invalid {name}")))?;
    if dir_name.is_empty() || item_name.is_empty() || item_name.contains('/') {
        return Err(ApiError::bad_request(format!("invalid {name}")));
    }

    Ok(CopySource {
        dir_name: dir_name.to_owned(),
        item_name: item_name.to_owned(),
    })
}

fn empty_json() -> Json<Value> {
    Json(json!({}))
}

impl From<DbError> for ApiError {
    fn from(error: DbError) -> Self {
        match error {
            DbError::AccessDenied => Self::access_denied(),
            DbError::BadRequest(message) => Self::bad_request(message),
            DbError::Conflict(message) => Self::conflict(message),
            DbError::Internal => Self::internal_error(),
            DbError::NotFound => Self::not_found("not found"),
            DbError::NotFoundMessage(message) => Self::not_found(message),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};
    use tempfile::NamedTempFile;
    use zeroize::Zeroizing;

    use super::{bearer_password, lock, send_upload_body_bytes, status, unlock};
    use crate::agent::process::ProcessChainHash;
    use crate::agent::state::{AgentState, DbHandle, FILE_RECORD_PLAINTEXT_BYTES};

    #[tokio::test]
    async fn unlock_missing_bearer_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = unlock(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(1))),
            HeaderMap::new(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_malformed_bearer_returns_access_denied() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, HeaderValue::from_static("Basic abc"));

        let state = AgentState::from_database_path("missing.db");
        let error = unlock(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(1))),
            headers,
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_missing_process_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = unlock(
            axum::extract::State(state),
            None,
            authorization_headers("correct"),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_failed_sqlcipher_unlock_returns_unlock_failed() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let error = unlock(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(1))),
            authorization_headers("wrong"),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_success_returns_ok_and_stores_handle() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let status = unlock(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(1))),
            authorization_headers("correct"),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, status);
        assert!(state.database_handle().await.is_some());
    }

    #[tokio::test]
    async fn lock_missing_process_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = lock(axum::extract::State(state), None).await.unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn lock_success_returns_ok_and_clears_authorization() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;

        let response = lock(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, response);
        assert!(!state.is_authorized(&ProcessChainHash::test(1)).await);
    }

    #[tokio::test]
    async fn upload_body_bytes_are_normalized_to_file_records() {
        let (sender, mut receiver) = tokio::sync::mpsc::channel(8);
        let mut buffer = Zeroizing::new(Vec::new());

        send_upload_body_bytes(&sender, &mut buffer, &[1; 3])
            .await
            .unwrap();
        send_upload_body_bytes(&sender, &mut buffer, &[2; FILE_RECORD_PLAINTEXT_BYTES + 5])
            .await
            .unwrap();
        assert_eq!(
            FILE_RECORD_PLAINTEXT_BYTES,
            receiver.recv().await.unwrap().len()
        );
        assert_eq!(8, buffer.len());

        if !buffer.is_empty() {
            sender.send(std::mem::take(&mut buffer)).await.unwrap();
        }
        drop(sender);

        assert_eq!(8, receiver.recv().await.unwrap().len());
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn invalid_base64_returns_access_denied() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer !!!"),
        );

        let error = bearer_password(&headers).unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[test]
    fn non_utf8_password_returns_access_denied() {
        let token = general_purpose::STANDARD.encode([0xff, 0xfe]);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );

        let error = bearer_password(&headers).unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn already_unlocked_wrong_password_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;

        let error = unlock(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(2))),
            authorization_headers("wrong"),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn already_unlocked_correct_password_caches_new_hash() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;

        let response = unlock(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(2))),
            authorization_headers("correct"),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, response);
        assert!(state.is_authorized(&ProcessChainHash::test(2)).await);
    }

    #[tokio::test]
    async fn status_returns_ok_only_for_unlocked_authorized_hash() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;

        let response = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap();
        assert!(
            DateTime::parse_from_rfc3339(&response.reauth_timestamp)
                .unwrap()
                .with_timezone(&Utc)
                > Utc::now()
        );

        assert_eq!(
            StatusCode::FORBIDDEN,
            status(
                axum::extract::State(state),
                Some(axum::Extension(ProcessChainHash::test(2))),
            )
            .await
            .unwrap_err()
            .status
        );
    }

    #[tokio::test]
    async fn status_returns_reauth_timestamp_about_fifteen_minutes_after_authorization() {
        let state = AgentState::from_database_path("missing.db");
        let authorized_at = Instant::now();
        let before = Utc::now();
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), authorized_at)
            .await;

        let response = status(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap();

        let timestamp = DateTime::parse_from_rfc3339(&response.reauth_timestamp)
            .unwrap()
            .with_timezone(&Utc);
        assert!(timestamp >= before + ChronoDuration::seconds(899));
        assert!(timestamp <= Utc::now() + ChronoDuration::seconds(900));
    }

    #[tokio::test]
    async fn status_does_not_refresh_last_authorized_database_access() {
        let state = AgentState::from_database_path("missing.db");
        let last_access = Instant::now() - Duration::from_secs(60);
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;

        let _ = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap();

        assert_eq!(
            Some(last_access),
            state.last_authorized_database_access().await
        );
    }

    #[tokio::test]
    async fn status_does_not_extend_auth_expiration() {
        let state = AgentState::from_database_path("missing.db");
        let authorized_at = Instant::now() - Duration::from_secs(899);
        let max_expires_at = authorized_at + Duration::from_secs(1);
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash_at(ProcessChainHash::test(1), authorized_at)
            .await;
        state
            .set_max_authorization_expires_at(Some(max_expires_at))
            .await;
        let expires_at_before = state
            .authorization_expires_at(&ProcessChainHash::test(1))
            .await
            .unwrap();

        let _ = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap();

        assert_eq!(
            Some(expires_at_before),
            state
                .authorization_expires_at(&ProcessChainHash::test(1))
                .await
        );
        assert_eq!(
            Some(max_expires_at),
            state.max_authorization_expires_at().await
        );
    }

    #[tokio::test]
    async fn status_with_expired_auth_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash_at(
                ProcessChainHash::test(1),
                Instant::now() - Duration::from_secs(900),
            )
            .await;

        let error = status(
            axum::extract::State(state),
            Some(axum::Extension(ProcessChainHash::test(1))),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn status_missing_process_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = status(axum::extract::State(state), None).await.unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    fn authorization_headers(password: &str) -> HeaderMap {
        let token = general_purpose::STANDARD.encode(password);
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
        );
        headers
    }

    fn create_encrypted_database(path: &std::path::Path, password: &str) {
        crate::db::create_encrypted_database_with_password(path, password).unwrap();
    }
}
