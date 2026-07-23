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
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
use super::gui_auth::PromptOutcome;
use super::models::{
    AccessScope, AuthScopeQuery, AuthStatusResponse, AuthUnlockMethod, AuthUnlockMethodsResponse,
    ContactResponse, CreateContactRequest, CreateFileResponse, CreateItemRequest,
    JobAcceptedResponse, JobResponse, JobStatus, ListItemsQuery, ListPageQuery, PaginatedResponse,
    ShellCompletionKind, ShellCompletionsQuery, ShellCompletionsResponse, UpdateContactRequest,
    UpdateDirRequest, UpdateItemRequest, UpdateSettingRequest,
};
#[cfg(any(not(target_os = "macos"), test))]
use super::process::DirectUnlockCaller;
#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
use super::process::ProcessDisplay;
use super::process::ScopeHash;
use super::state::{
    AgentState, CopySource, DbError, DbHandle, FILE_RECORD_PLAINTEXT_BYTES, ItemListRequest,
    ItemSource, PageRequest, ReferenceBody, validate_file_upload_size,
};

const DEFAULT_PAGE_COUNT: u64 = 50;
const MAX_PAGE_COUNT: u64 = 200;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
const CLIENT_CAPABILITIES_HEADER: &str = "x-client-capabilities";

pub async fn shell_completions(
    Extension(database): Extension<DbHandle>,
    query: Result<Query<ShellCompletionsQuery>, QueryRejection>,
) -> Result<Json<ShellCompletionsResponse>, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.to_string()))?;
    let kinds = parse_completion_kinds(&query.kinds)?;
    validate_completion_prefix(&query.prefix, &kinds)?;
    database
        .shell_completions(query.prefix, kinds)
        .await
        .map(Json)
        .map_err(ApiError::from)
}

fn parse_completion_kinds(
    value: &str,
) -> Result<std::collections::HashSet<ShellCompletionKind>, ApiError> {
    let mut kinds = std::collections::HashSet::new();
    if value.is_empty() {
        return Err(ApiError::bad_request("kinds must not be empty"));
    }
    for value in value.split(',') {
        let kind = match value {
            "dir" => ShellCompletionKind::Dir,
            "item" => ShellCompletionKind::Item,
            "field" => ShellCompletionKind::Field,
            "file" => ShellCompletionKind::File,
            "contact" => ShellCompletionKind::Contact,
            _ => return Err(ApiError::bad_request("unsupported completion kind")),
        };
        if !kinds.insert(kind) {
            return Err(ApiError::bad_request(
                "completion kinds must not contain duplicates",
            ));
        }
    }
    Ok(kinds)
}

fn validate_completion_prefix(
    prefix: &str,
    kinds: &std::collections::HashSet<ShellCompletionKind>,
) -> Result<(), ApiError> {
    if kinds.len() == 1 && kinds.contains(&ShellCompletionKind::Contact) {
        return Ok(());
    }
    let parts = prefix.split('/').collect::<Vec<_>>();
    if parts.len() > 3
        || parts
            .iter()
            .take(parts.len().saturating_sub(1))
            .any(|part| part.is_empty())
    {
        return Err(ApiError::bad_request("invalid completion path prefix"));
    }
    Ok(())
}

pub async fn unlock_methods(
    headers: HeaderMap,
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
) -> Result<Json<AuthUnlockMethodsResponse>, ApiError> {
    let query = auth_scope_query(query)?;
    Ok(Json(AuthUnlockMethodsResponse {
        methods: unlock_methods_for_headers(&headers, query.scope),
    }))
}

fn unlock_methods_for_headers(
    headers: &HeaderMap,
    explicit_scope: Option<AccessScope>,
) -> Vec<AuthUnlockMethod> {
    let scope_query = explicit_scope
        .map(|scope| format!("?scope={}", scope.as_str()))
        .unwrap_or_default();
    if should_advertise_gui_unlock(headers) {
        return vec![AuthUnlockMethod {
            url: format!("/api/v1/auth/unlock/gui{scope_query}"),
            accepts_master_password: false,
        }];
    }

    vec![AuthUnlockMethod {
        url: format!("/api/v1/auth/unlock/direct{scope_query}"),
        accepts_master_password: true,
    }]
}

fn auth_scope_query(
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
) -> Result<AuthScopeQuery, ApiError> {
    query
        .map(|Query(query)| query)
        .map_err(|error| ApiError::bad_request(error.to_string()))
}

#[cfg(target_os = "macos")]
fn should_advertise_gui_unlock(_headers: &HeaderMap) -> bool {
    true
}

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
fn should_advertise_gui_unlock(headers: &HeaderMap) -> bool {
    headers
        .get(CLIENT_CAPABILITIES_HEADER)
        .and_then(|value| value.to_str().ok())
        .is_some_and(client_capabilities_include_gui_session)
}

#[cfg(all(target_os = "linux", not(any(feature = "gtk", feature = "qt"))))]
fn should_advertise_gui_unlock(_headers: &HeaderMap) -> bool {
    false
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn should_advertise_gui_unlock(_headers: &HeaderMap) -> bool {
    false
}

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
fn client_capabilities_include_gui_session(value: &str) -> bool {
    value.split(',').any(|capability| {
        let capability = capability.trim();
        ["x-session=", "wayland-session="].iter().any(|prefix| {
            capability
                .strip_prefix(prefix)
                .is_some_and(|session| !session.trim().is_empty())
        })
    })
}

#[cfg(any(not(target_os = "macos"), test))]
pub async fn unlock_direct(
    State(state): State<AgentState>,
    scope_hash: Option<Extension<ScopeHash>>,
    caller: Option<Extension<DirectUnlockCaller>>,
    headers: HeaderMap,
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
) -> Result<StatusCode, ApiError> {
    let access_scope = auth_scope_query(query)?.access_scope();
    let Extension(scope_hash) = scope_hash.ok_or_else(ApiError::access_denied)?;
    let Extension(caller) = caller.ok_or_else(ApiError::access_denied)?;
    let password = bearer_password(&headers)?;

    state
        .unlock_direct_for_scope(password, scope_hash, access_scope, caller)
        .await
        .map(|()| StatusCode::OK)
        .map_err(|error| match error {
            super::state::UnlockError::AccessDenied => ApiError::access_denied(),
            super::state::UnlockError::MigrationNeeded => ApiError::migration_needed(),
            super::state::UnlockError::UnlockFailed => ApiError::unlock_failed(),
        })
}

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
pub async fn unlock_gui(
    State(state): State<AgentState>,
    scope_hash: Option<Extension<ScopeHash>>,
    display: Option<Extension<ProcessDisplay>>,
    headers: HeaderMap,
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
) -> Result<StatusCode, ApiError> {
    unlock_gui_with_prompt(
        State(state),
        scope_hash,
        display,
        headers,
        query,
        super::gui_auth::prompt_password,
    )
    .await
}

#[cfg(any(
    target_os = "macos",
    all(target_os = "linux", any(feature = "gtk", feature = "qt"))
))]
async fn unlock_gui_with_prompt<F, Fut>(
    State(state): State<AgentState>,
    scope_hash: Option<Extension<ScopeHash>>,
    display: Option<Extension<ProcessDisplay>>,
    headers: HeaderMap,
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
    prompt: F,
) -> Result<StatusCode, ApiError>
where
    F: Fn(Option<ProcessDisplay>, AccessScope) -> Fut,
    Fut: std::future::Future<Output = PromptOutcome>,
{
    let Extension(scope_hash) = scope_hash.ok_or_else(ApiError::access_denied)?;
    let access_scope = auth_scope_query(query)?.access_scope();
    if !gui_unlock_request_allowed(&headers) {
        return Err(ApiError::access_denied());
    }
    if state
        .is_scope_denied_for_scope(&scope_hash, access_scope)
        .await
    {
        return Err(ApiError::temporary_lockout());
    }
    let display = display.map(|Extension(display)| display);

    let password = match prompt(display, access_scope).await {
        PromptOutcome::Allowed(password) => password,
        PromptOutcome::Denied => {
            state
                .deny_scope_hash_for_scope(scope_hash, access_scope)
                .await;
            return Err(ApiError::temporary_lockout());
        }
        PromptOutcome::Dismissed => return Err(ApiError::access_denied()),
    };

    state
        .unlock_for_scope(password, scope_hash, access_scope)
        .await
        .map(|()| StatusCode::OK)
        .map_err(|error| match error {
            super::state::UnlockError::MigrationNeeded => ApiError::migration_needed(),
            super::state::UnlockError::AccessDenied | super::state::UnlockError::UnlockFailed => {
                ApiError::access_denied()
            }
        })
}

#[cfg(target_os = "macos")]
fn gui_unlock_request_allowed(_headers: &HeaderMap) -> bool {
    true
}

#[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
fn gui_unlock_request_allowed(headers: &HeaderMap) -> bool {
    should_advertise_gui_unlock(headers)
}
pub async fn lock(
    State(state): State<AgentState>,
    scope_hash: Option<Extension<ScopeHash>>,
) -> Result<StatusCode, ApiError> {
    let Extension(_) = scope_hash.ok_or_else(ApiError::access_denied)?;
    state.lock(Instant::now()).await;
    Ok(StatusCode::OK)
}

pub async fn status(
    State(state): State<AgentState>,
    scope_hash: Option<Extension<ScopeHash>>,
    query: Result<Query<AuthScopeQuery>, QueryRejection>,
) -> Result<Json<AuthStatusResponse>, ApiError> {
    let Extension(scope_hash) = scope_hash.ok_or_else(ApiError::access_denied)?;
    let access_scope = auth_scope_query(query)?.access_scope();
    let expires_at = state
        .authorization_expires_at_for_scope(&scope_hash, access_scope)
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
        Ok(password) => state.verify_master_password(&password).await,
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
    Extension(database): Extension<DbHandle>,
) -> Result<Json<std::collections::HashMap<String, String>>, ApiError> {
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
    request: Result<Json<UpdateSettingRequest>, JsonRejection>,
) -> Result<Json<Value>, ApiError> {
    let Json(request) = request.map_err(|error| ApiError::bad_request(error.to_string()))?;
    state
        .upsert_user_setting(&database, name, request.value)
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
    state.register_active_job(job_id.clone()).await;
    if let Err(error) = database
        .create_import_job(job_id.clone(), dir_name.clone(), item_name.clone())
        .await
    {
        state.unregister_active_job(&job_id).await;
        let _ = std::fs::remove_file(&encrypted_path);
        return Err(ApiError::from(error));
    }
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
    state.register_active_job(job_id.clone()).await;
    if let Err(error) = database
        .create_export_job(
            job_id.clone(),
            dir_name.clone(),
            item_name.clone(),
            contact_name.clone(),
        )
        .await
    {
        state.unregister_active_job(&job_id).await;
        return Err(ApiError::from(error));
    }
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
    query: Result<Query<ListItemsQuery>, QueryRejection>,
) -> Result<Json<PaginatedResponse<super::models::ItemSummaryResponse>>, ApiError> {
    let Query(query) = query.map_err(|error| ApiError::bad_request(error.to_string()))?;
    let count = validated_page_count(query.count)?;
    database
        .list_items(
            dir_name,
            ItemListRequest {
                page: PageRequest {
                    count,
                    marker: query.marker,
                },
                glob: query.glob,
                direction: query.dir.unwrap_or_default(),
            },
        )
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
    let count = validated_page_count(query.count)?;
    Ok(PageRequest {
        count,
        marker: query.marker,
    })
}

fn validated_page_count(count: Option<u64>) -> Result<u64, ApiError> {
    let count = count.unwrap_or(DEFAULT_PAGE_COUNT);
    if !(1..=MAX_PAGE_COUNT).contains(&count) {
        return Err(ApiError::bad_request("count must be between 1 and 200"));
    }
    Ok(count)
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
                    .map_err(|_| io::Error::other("file decrypt failed"))
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
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::extract::rejection::QueryRejection;
    use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose;
    use chrono::{DateTime, Duration as ChronoDuration, Utc};
    use tempfile::NamedTempFile;
    use zeroize::Zeroizing;

    use super::{
        bearer_password, export_item, import_item, lock, parse_completion_kinds,
        send_upload_body_bytes, status, unlock_methods, validate_completion_prefix,
    };
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    use crate::agent::gui_auth::PromptOutcome;
    use crate::agent::models::{
        AccessScope, AuthScopeQuery, CreateContactRequest, CreateItemRequest, ShellCompletionKind,
    };
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    use crate::agent::process::ProcessDisplay;
    use crate::agent::process::{DirectUnlockCaller, ScopeHash};
    use crate::agent::state::{AgentState, DbHandle, FILE_RECORD_PLAINTEXT_BYTES};

    fn default_scope_query() -> Result<axum::extract::Query<AuthScopeQuery>, QueryRejection> {
        Ok(axum::extract::Query(AuthScopeQuery::default()))
    }

    fn scope_query(
        scope: AccessScope,
    ) -> Result<axum::extract::Query<AuthScopeQuery>, QueryRejection> {
        Ok(axum::extract::Query(AuthScopeQuery { scope: Some(scope) }))
    }

    #[test]
    fn shell_completion_query_validation_is_strict_and_contact_prefixes_are_opaque() {
        let kinds = parse_completion_kinds("dir,item,field,file,contact").unwrap();
        assert_eq!(5, kinds.len());
        assert!(parse_completion_kinds("").is_err());
        assert!(parse_completion_kinds("dir,dir").is_err());
        assert!(parse_completion_kinds("dir,unknown").is_err());

        assert!(validate_completion_prefix("", &kinds).is_ok());
        assert!(validate_completion_prefix("Personal/", &kinds).is_ok());
        assert!(validate_completion_prefix("Personal/GitHub/", &kinds).is_ok());
        assert!(validate_completion_prefix("/Personal", &kinds).is_err());
        assert!(validate_completion_prefix("Personal//pass", &kinds).is_err());
        assert!(validate_completion_prefix("Personal/GitHub/pass/more", &kinds).is_err());

        let contact = std::collections::HashSet::from([ShellCompletionKind::Contact]);
        assert!(validate_completion_prefix("opaque//contact/value", &contact).is_ok());
    }

    #[tokio::test]
    async fn unlock_methods_propagates_explicit_settings_scope() {
        let response = unlock_methods(HeaderMap::new(), scope_query(AccessScope::Settings))
            .await
            .unwrap();
        let method = response.methods.first().unwrap();
        assert!(method.url.ends_with("?scope=settings"));
    }

    #[tokio::test]
    #[cfg(not(target_os = "macos"))]
    async fn unlock_methods_returns_direct_method() {
        let response = unlock_methods(HeaderMap::new(), default_scope_query())
            .await
            .unwrap();

        assert_eq!(
            serde_json::json!({
                "methods": [
                    {
                        "url": "/api/v1/auth/unlock/direct",
                        "accepts_master_password": true
                    }
                ]
            }),
            serde_json::to_value(response.0).unwrap()
        );
    }

    #[tokio::test]
    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    async fn unlock_methods_returns_gui_method_for_x_session_capability() {
        let response = unlock_methods(x_session_headers(), default_scope_query())
            .await
            .unwrap();

        assert_eq!(
            serde_json::json!({
                "methods": [
                    {
                        "url": "/api/v1/auth/unlock/gui",
                        "accepts_master_password": false
                    }
                ]
            }),
            serde_json::to_value(response.0).unwrap()
        );
    }

    #[tokio::test]
    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    async fn unlock_methods_returns_gui_method_for_wayland_session_capability() {
        let response = unlock_methods(wayland_session_headers(), default_scope_query())
            .await
            .unwrap();

        assert_eq!(
            serde_json::json!({
                "methods": [
                    {
                        "url": "/api/v1/auth/unlock/gui",
                        "accepts_master_password": false
                    }
                ]
            }),
            serde_json::to_value(response.0).unwrap()
        );
    }

    #[test]
    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    fn linux_gui_capabilities_accept_x_and_wayland_sessions() {
        assert!(super::client_capabilities_include_gui_session(
            "x-session=:1"
        ));
        assert!(super::client_capabilities_include_gui_session(
            "wayland-session=wayland-0"
        ));
        assert!(super::client_capabilities_include_gui_session(
            "unknown=value, wayland-session=wayland-0"
        ));
        assert!(!super::client_capabilities_include_gui_session(
            "wayland-session="
        ));
        assert!(!super::client_capabilities_include_gui_session(
            "unknown=value"
        ));
    }

    #[tokio::test]
    #[cfg(target_os = "macos")]
    async fn unlock_methods_returns_gui_method() {
        let response = unlock_methods(HeaderMap::new(), default_scope_query())
            .await
            .unwrap();

        assert_eq!(
            serde_json::json!({
                "methods": [
                    {
                        "url": "/api/v1/auth/unlock/gui",
                        "accepts_master_password": false
                    }
                ]
            }),
            serde_json::to_value(response.0).unwrap()
        );
    }

    #[tokio::test]
    async fn unlock_missing_bearer_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            HeaderMap::new(),
            default_scope_query(),
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
        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            headers,
            default_scope_query(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_missing_scope_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = super::unlock_direct(
            axum::extract::State(state),
            None,
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("correct"),
            default_scope_query(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_missing_direct_caller_policy_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            None,
            authorization_headers("correct"),
            default_scope_query(),
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
        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("wrong"),
            default_scope_query(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn unlock_schema_two_database_returns_migration_needed() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");
        let conn = rusqlite::Connection::open(file.path()).unwrap();
        conn.pragma_update(None, "key", "correct").unwrap();
        crate::db::downgrade_to_schema_two(&conn);
        drop(conn);

        let state = AgentState::from_database_path(file.path());
        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("correct"),
            default_scope_query(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::BAD_GATEWAY, error.status);
    }

    #[tokio::test]
    async fn unlock_success_returns_ok_and_stores_handle() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let status = super::unlock_direct(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("correct"),
            default_scope_query(),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, status);
        assert!(state.database_handle().await.is_some());
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_submits_prompt_password_once() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Allowed(Zeroizing::new("correct".to_owned()))
                }
            }
        };

        let response = super::unlock_gui_with_prompt(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            None,
            gui_unlock_headers(),
            default_scope_query(),
            prompt,
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, response);
        assert!(state.is_authorized(&ScopeHash::test(1)).await);
        assert_eq!(1, *prompts.lock().unwrap());
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_settings_scope_authorizes_settings_only() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");
        let state = AgentState::from_database_path(file.path());

        super::unlock_gui_with_prompt(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            None,
            gui_unlock_headers(),
            scope_query(AccessScope::Settings),
            |_display, access_scope| async move {
                assert_eq!(AccessScope::Settings, access_scope);
                PromptOutcome::Allowed(Zeroizing::new("correct".to_owned()))
            },
        )
        .await
        .unwrap();

        assert!(
            state
                .is_authorized_for_scope(&ScopeHash::test(1), AccessScope::Settings)
                .await
        );
        assert!(!state.is_authorized(&ScopeHash::test(1)).await);
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_wrong_password_returns_access_denied_without_retry() {
        let file = NamedTempFile::new().unwrap();
        create_encrypted_database(file.path(), "correct");

        let state = AgentState::from_database_path(file.path());
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Allowed(Zeroizing::new("wrong".to_owned()))
                }
            }
        };

        for _ in 0..2 {
            let error = super::unlock_gui_with_prompt(
                axum::extract::State(state.clone()),
                Some(axum::Extension(ScopeHash::test(1))),
                None,
                gui_unlock_headers(),
                default_scope_query(),
                &prompt,
            )
            .await
            .unwrap_err();

            assert_eq!(StatusCode::FORBIDDEN, error.status);
        }
        assert_eq!(2, *prompts.lock().unwrap());
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_cancel_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = super::unlock_gui_with_prompt(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            None,
            gui_unlock_headers(),
            default_scope_query(),
            |_display, _access_scope| async { PromptOutcome::Dismissed },
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_remembers_explicit_denial_for_same_scope_only() {
        let state = AgentState::from_database_path("missing.db");
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Denied
                }
            }
        };

        for scope_hash in [ScopeHash::test(1), ScopeHash::test(1), ScopeHash::test(2)] {
            let error = super::unlock_gui_with_prompt(
                axum::extract::State(state.clone()),
                Some(axum::Extension(scope_hash)),
                None,
                gui_unlock_headers(),
                default_scope_query(),
                &prompt,
            )
            .await
            .unwrap_err();
            assert_eq!(StatusCode::FORBIDDEN, error.status);
        }

        assert_eq!(2, *prompts.lock().unwrap());
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_denials_are_separate_for_items_and_settings() {
        let state = AgentState::from_database_path("missing.db");
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Denied
                }
            }
        };

        for access_scope in [
            AccessScope::Items,
            AccessScope::Settings,
            AccessScope::Items,
        ] {
            let error = super::unlock_gui_with_prompt(
                axum::extract::State(state.clone()),
                Some(axum::Extension(ScopeHash::test(1))),
                None,
                gui_unlock_headers(),
                scope_query(access_scope),
                &prompt,
            )
            .await
            .unwrap_err();
            assert_eq!(StatusCode::FORBIDDEN, error.status);
        }

        assert_eq!(2, *prompts.lock().unwrap());
    }

    #[tokio::test]
    #[cfg(any(
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    async fn unlock_gui_does_not_remember_dismissal() {
        let state = AgentState::from_database_path("missing.db");
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Dismissed
                }
            }
        };

        for _ in 0..2 {
            let error = super::unlock_gui_with_prompt(
                axum::extract::State(state.clone()),
                Some(axum::Extension(ScopeHash::test(1))),
                None,
                gui_unlock_headers(),
                default_scope_query(),
                &prompt,
            )
            .await
            .unwrap_err();
            assert_eq!(StatusCode::FORBIDDEN, error.status);
        }

        assert_eq!(2, *prompts.lock().unwrap());
    }

    #[tokio::test]
    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    async fn unlock_gui_without_x_session_capability_returns_access_denied_without_prompting() {
        let state = AgentState::from_database_path("missing.db");
        let prompts = Arc::new(Mutex::new(0usize));
        let prompt = {
            let prompts = Arc::clone(&prompts);
            move |_display: Option<ProcessDisplay>, _access_scope| {
                let prompts = Arc::clone(&prompts);
                async move {
                    *prompts.lock().unwrap() += 1;
                    PromptOutcome::Allowed(Zeroizing::new("correct".to_owned()))
                }
            }
        };

        let error = super::unlock_gui_with_prompt(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            None,
            HeaderMap::new(),
            default_scope_query(),
            prompt,
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
        assert_eq!(0, *prompts.lock().unwrap());
    }

    #[tokio::test]
    async fn lock_missing_scope_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = lock(axum::extract::State(state), None).await.unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn lock_success_returns_ok_and_clears_authorization() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.authorize_scope_hash(ScopeHash::test(1)).await;
        state
            .authorize_scope_hash_for_scope(ScopeHash::test(1), AccessScope::Settings)
            .await;

        let response = lock(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, response);
        assert!(!state.is_authorized(&ScopeHash::test(1)).await);
        assert!(
            !state
                .is_authorized_for_scope(&ScopeHash::test(1), AccessScope::Settings)
                .await
        );
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

        let error = super::unlock_direct(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(2))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("wrong"),
            default_scope_query(),
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

        let response = super::unlock_direct(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(2))),
            Some(axum::Extension(DirectUnlockCaller::Agent)),
            authorization_headers("correct"),
            default_scope_query(),
        )
        .await
        .unwrap();

        assert_eq!(StatusCode::OK, response);
        assert!(state.is_authorized(&ScopeHash::test(2)).await);
    }

    #[tokio::test]
    async fn status_returns_ok_only_for_unlocked_authorized_hash() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.authorize_scope_hash(ScopeHash::test(1)).await;

        let response = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            default_scope_query(),
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
                Some(axum::Extension(ScopeHash::test(2))),
                default_scope_query(),
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
            .authorize_scope_hash_at(ScopeHash::test(1), authorized_at)
            .await;

        let response = status(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            default_scope_query(),
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
    async fn settings_status_uses_settings_authorization_ttl() {
        let state = AgentState::from_database_path("missing.db");
        let authorized_at = Instant::now();
        let before = Utc::now();
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_scope_hash_at_for_scope(
                ScopeHash::test(1),
                AccessScope::Settings,
                authorized_at,
            )
            .await;

        let response = status(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            scope_query(AccessScope::Settings),
        )
        .await
        .unwrap();

        let timestamp = DateTime::parse_from_rfc3339(&response.reauth_timestamp)
            .unwrap()
            .with_timezone(&Utc);
        assert!(timestamp >= before + ChronoDuration::seconds(299));
        assert!(timestamp <= Utc::now() + ChronoDuration::seconds(300));
    }

    #[tokio::test]
    async fn status_does_not_refresh_last_authorized_database_access() {
        let state = AgentState::from_database_path("missing.db");
        let last_access = Instant::now() - Duration::from_secs(60);
        state.store_database_handle(DbHandle::test()).await;
        state.authorize_scope_hash(ScopeHash::test(1)).await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;

        let _ = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            default_scope_query(),
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
            .authorize_scope_hash_at(ScopeHash::test(1), authorized_at)
            .await;
        state
            .set_max_authorization_expires_at(Some(max_expires_at))
            .await;
        let expires_at_before = state
            .authorization_expires_at(&ScopeHash::test(1))
            .await
            .unwrap();

        let _ = status(
            axum::extract::State(state.clone()),
            Some(axum::Extension(ScopeHash::test(1))),
            default_scope_query(),
        )
        .await
        .unwrap();

        assert_eq!(
            Some(expires_at_before),
            state.authorization_expires_at(&ScopeHash::test(1)).await
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
            .authorize_scope_hash_at(
                ScopeHash::test(1),
                Instant::now() - Duration::from_secs(900),
            )
            .await;

        let error = status(
            axum::extract::State(state),
            Some(axum::Extension(ScopeHash::test(1))),
            default_scope_query(),
        )
        .await
        .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[tokio::test]
    async fn import_job_is_active_before_job_record_write_completes() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("Personal".to_owned()).await.unwrap();
        let blocker = block_writer(&database).await;
        let import_state = state.clone();
        let import_database = database.clone();
        let import_task = tokio::spawn(async move {
            import_item(
                axum::extract::State(import_state),
                axum::Extension(import_database),
                axum::extract::Path(("Personal".to_owned(), "github".to_owned())),
                Body::from("not an age export"),
            )
            .await
        });

        wait_for_active_jobs(&state, 1).await;
        let now = Instant::now();
        state.lock(now).await;

        assert!(!state.unload_if_authorization_expired(now).await);
        assert_eq!(1, state.active_job_count().await);
        assert_eq!(StatusCode::ACCEPTED, import_task.await.unwrap().unwrap().0);
        assert!(blocker.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn export_job_is_active_before_job_record_write_completes() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        database.create_dir("Personal".to_owned()).await.unwrap();
        database
            .create_item(
                "Personal".to_owned(),
                "github".to_owned(),
                CreateItemRequest::default(),
                None,
            )
            .await
            .unwrap();
        database
            .create_contact(
                "alice@example.com".to_owned(),
                CreateContactRequest {
                    name: Some("alice".to_owned()),
                    age_public_key: age::x25519::Identity::generate().to_public().to_string(),
                    description: None,
                },
            )
            .await
            .unwrap();
        let blocker = block_writer(&database).await;
        let export_state = state.clone();
        let export_database = database.clone();
        let export_task = tokio::spawn(async move {
            export_item(
                axum::extract::State(export_state),
                axum::Extension(export_database),
                axum::extract::Path((
                    "Personal".to_owned(),
                    "github".to_owned(),
                    "alice@example.com".to_owned(),
                )),
            )
            .await
        });

        wait_for_active_jobs(&state, 1).await;
        let now = Instant::now();
        state.lock(now).await;

        assert!(!state.unload_if_authorization_expired(now).await);
        assert_eq!(1, state.active_job_count().await);
        assert_eq!(StatusCode::ACCEPTED, export_task.await.unwrap().unwrap().0);
        assert!(blocker.await.unwrap().is_ok());
    }

    #[tokio::test]
    async fn status_missing_scope_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let error = status(axum::extract::State(state), None, default_scope_query())
            .await
            .unwrap_err();

        assert_eq!(StatusCode::FORBIDDEN, error.status);
    }

    #[cfg(target_os = "macos")]
    fn gui_unlock_headers() -> HeaderMap {
        HeaderMap::new()
    }

    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    fn gui_unlock_headers() -> HeaderMap {
        x_session_headers()
    }

    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    fn x_session_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            super::CLIENT_CAPABILITIES_HEADER,
            HeaderValue::from_static("x-session=:1"),
        );
        headers
    }

    #[cfg(all(target_os = "linux", any(feature = "gtk", feature = "qt")))]
    fn wayland_session_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            super::CLIENT_CAPABILITIES_HEADER,
            HeaderValue::from_static("wayland-session=wayland-0"),
        );
        headers
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

    async fn block_writer(
        database: &DbHandle,
    ) -> tokio::task::JoinHandle<Result<(), super::DbError>> {
        let before = database.dispatch_counts().0;
        let worker_database = database.clone();
        let task = tokio::spawn(async move {
            worker_database
                .test_slow_write(Duration::from_secs(3))
                .await
        });
        wait_for_writer_dispatches(database, before + 1).await;
        task
    }

    async fn wait_for_writer_dispatches(database: &DbHandle, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if database.dispatch_counts().0 >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for writer dispatches"
            );
            tokio::task::yield_now().await;
        }
    }

    async fn wait_for_active_jobs(state: &AgentState, expected: usize) {
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if state.active_job_count().await >= expected {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for active jobs"
            );
            tokio::task::yield_now().await;
        }
    }

    fn create_encrypted_database(path: &std::path::Path, password: &str) {
        crate::db::create_encrypted_database_with_password(path, password).unwrap();
    }
}
