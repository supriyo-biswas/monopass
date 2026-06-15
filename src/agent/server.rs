use axum::Router;
use axum::middleware;
use axum::routing::{get, post, put};

use super::auth;
use super::controller;
use super::state::AgentState;
use crate::config::Config;

pub struct Server {
    state: AgentState,
}

impl Server {
    pub fn new(config: &Config) -> Self {
        let state = AgentState::new(config);
        state.spawn_auth_expiry_lock_task();

        Self { state }
    }

    pub fn router(self) -> Router {
        Self::router_with_state(self.state)
    }

    fn router_with_state(state: AgentState) -> Router {
        auth_routes()
            .merge(database_routes(state.clone()))
            .route_layer(middleware::from_fn(auth::require_same_uid_and_gid))
            .with_state(state)
    }
}

fn auth_routes() -> Router<AgentState> {
    Router::new()
        .route("/api/v1/auth/unlock", post(controller::unlock))
        .route("/api/v1/auth/lock", post(controller::lock))
        .route("/api/v1/auth/status", get(controller::status))
}

fn database_routes(state: AgentState) -> Router<AgentState> {
    Router::new()
        .route("/api/v1/dirs", get(controller::list_dirs))
        .route("/api/v1/contacts", get(controller::list_contacts))
        .route(
            "/api/v1/contact/{contact_email}",
            put(controller::create_contact)
                .patch(controller::update_contact)
                .delete(controller::delete_contact),
        )
        .route("/api/v1/settings", get(controller::list_settings))
        .route("/api/v1/settings/{name}", put(controller::update_setting))
        .route("/api/v1/jobs/status/{job_id}", get(controller::get_job))
        .route(
            "/api/v1/jobs/import/{dir_name}/{item_name}",
            put(controller::import_item),
        )
        .route(
            "/api/v1/jobs/export/{dir_name}/{item_name}/{contact_name}",
            put(controller::export_item),
        )
        .route("/api/v1/file/upload", put(controller::create_file))
        .route(
            "/api/v1/file/lookup/sha256/{sha256}",
            get(controller::lookup_file_by_sha256),
        )
        .route(
            "/api/v1/dir/{dir_name}",
            put(controller::create_dir)
                .get(controller::get_dir)
                .patch(controller::update_dir)
                .delete(controller::delete_dir),
        )
        .route("/api/v1/dir/{dir_name}/items", get(controller::list_items))
        .route(
            "/api/v1/dir/{dir_name}/item/{item_name}/versions",
            get(controller::list_item_versions),
        )
        .route(
            "/api/v1/dir/{dir_name}/item/{item_name}/restore",
            put(controller::restore_item_version),
        )
        .route(
            "/api/v1/dir/{dir_name}/item/{item_name}",
            put(controller::create_item)
                .get(controller::get_item)
                .patch(controller::update_item)
                .delete(controller::delete_item),
        )
        .route(
            "/api/v1/ref/{dir_name}/{item_name}/{field_name}",
            get(controller::get_reference),
        )
        .route_layer(middleware::from_fn_with_state(
            state,
            auth::require_unlocked_database,
        ))
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};
    use base64::Engine;
    use base64::engine::general_purpose;
    use http_body_util::BodyExt;
    use serde_json::json;
    use tempfile::NamedTempFile;
    use tower::ServiceExt;

    use crate::agent::process::ProcessChainHash;
    use crate::agent::state::{AgentState, DbHandle, ITEM_READ_MUSTAUTH, MAX_FILE_UPLOAD_BYTES};

    #[tokio::test]
    async fn locked_database_route_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    #[tokio::test]
    async fn unlocked_database_route_with_missing_hash_returns_access_denied() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    #[tokio::test]
    async fn unlocked_database_route_with_cached_hash_reaches_handler() {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn unlock_authorizes_hash_for_subsequent_database_route() {
        let file = NamedTempFile::new().unwrap();
        crate::db::create_encrypted_database_with_password(file.path(), "correct").unwrap();

        let state = AgentState::from_database_path(file.path());
        let router = super::auth_routes()
            .merge(super::database_routes(state.clone()))
            .with_state(state);

        let response = router
            .clone()
            .oneshot(post_request_with_hash_and_password(
                "/api/v1/auth/unlock",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn lock_clears_hash_for_subsequent_database_route() {
        let file = NamedTempFile::new().unwrap();
        crate::db::create_encrypted_database_with_password(file.path(), "correct").unwrap();

        let state = AgentState::from_database_path(file.path());
        let router = super::auth_routes()
            .merge(super::database_routes(state.clone()))
            .with_state(state);

        let response = router
            .clone()
            .oneshot(post_request_with_hash_and_password(
                "/api/v1/auth/unlock",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(post_request_with_hash(
                "/api/v1/auth/lock",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();
        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    #[tokio::test]
    async fn unlocked_database_route_refreshes_last_authorized_database_access() {
        let state = AgentState::from_database_path("missing.db");
        let last_access = Instant::now() - Duration::from_secs(60);
        state.store_database_handle(DbHandle::test()).await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        state
            .set_last_authorized_database_access(Some(last_access))
            .await;
        let router = super::database_routes(state.clone()).with_state(state.clone());

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
        assert!(state.last_authorized_database_access().await.unwrap() > last_access);
    }

    #[tokio::test]
    async fn database_route_response_body_delays_unload_until_dropped() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state.clone());

        let response = router
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(1, state.active_database_request_count());
        let now = Instant::now();

        state.lock(now).await;

        assert!(!state.unload_if_authorization_expired(now).await);
        drop(response);
        assert_eq!(0, state.active_database_request_count());
        assert!(state.unload_if_authorization_expired(now).await);
    }

    #[tokio::test]
    async fn streaming_reference_response_body_delays_unload_until_dropped() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state.clone());
        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let response = router
            .clone()
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/file/upload",
                b"stream me",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let file_id = json_body(response).await["id"].as_str().unwrap().to_owned();
        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({"files": {"notes": {"id": file_id}}}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        drop(response);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/notes",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(1, state.active_database_request_count());
        let now = Instant::now();

        state.lock(now).await;

        assert!(!state.unload_if_authorization_expired(now).await);
        drop(response);
        assert_eq!(0, state.active_database_request_count());
        assert!(state.unload_if_authorization_expired(now).await);
    }

    #[tokio::test]
    async fn dir_api_creates_gets_lists_updates_and_deletes() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(json!({}), json_body(response).await);

        let response = router
            .clone()
            .oneshot(request_with_hash("/api/v1/dirs", ProcessChainHash::test(1)))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!(1, body["count"]);
        assert_eq!(serde_json::Value::Null, body["next_marker"]);
        assert_eq!("personal", body["entries"][0]["name"]);
        assert_eq!(0, body["entries"][0]["items"]);
        assert!(
            body["entries"][0]["created_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/dir/personal",
                json!({"name":"renamed"}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/renamed",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!("renamed", json_body(response).await["name"]);

        let response = router
            .oneshot(delete_request_with_hash(
                "/api/v1/dir/renamed",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn dir_list_api_paginates_and_rejects_invalid_query() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        for name in ["beta", "alpha"] {
            router
                .clone()
                .oneshot(put_request_with_hash(
                    &format!("/api/v1/dir/{name}"),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
        }

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dirs?count=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!(1, body["count"]);
        assert_eq!("alpha", body["entries"][0]["name"]);
        let marker = body["next_marker"].as_str().unwrap();

        let response = router
            .clone()
            .oneshot(request_with_hash(
                &format!("/api/v1/dirs?count=1&marker={marker}"),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("beta", body["entries"][0]["name"]);
        assert_eq!(serde_json::Value::Null, body["next_marker"]);

        for path in [
            "/api/v1/dirs?count=0",
            "/api/v1/dirs?count=201",
            "/api/v1/dirs?count=abc",
            "/api/v1/dirs?marker=invalid",
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash(path, ProcessChainHash::test(1)))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{path}");
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn contact_api_creates_lists_and_deletes() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        let public_key = age::x25519::Identity::generate().to_public().to_string();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/contact/alice@example.com",
                json!({
                    "name": "Alice",
                    "age_public_key": public_key,
                    "description": "Personal laptop",
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(json!({}), json_body(response).await);

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/contact/alice@example.com",
                json!({
                    "name": "Alice",
                    "age_public_key": public_key,
                    "description": "Personal laptop",
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::CONFLICT, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/contacts",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!(1, body["count"]);
        assert_eq!("alice@example.com", body["entries"][0]["email"]);
        assert_eq!("Alice", body["entries"][0]["name"]);
        assert_eq!(public_key, body["entries"][0]["age_public_key"]);
        assert_eq!("Personal laptop", body["entries"][0]["description"]);
        assert!(
            body["entries"][0]["created_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        assert_eq!(serde_json::Value::Null, body["next_marker"]);

        let response = router
            .clone()
            .oneshot(delete_request_with_hash(
                "/api/v1/contact/alice@example.com",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .oneshot(delete_request_with_hash(
                "/api/v1/contact/alice@example.com",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());
    }

    #[tokio::test]
    async fn contact_api_updates_email_name_and_public_key() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        let original_key = age::x25519::Identity::generate().to_public().to_string();
        let updated_key = age::x25519::Identity::generate().to_public().to_string();

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/contact/alice@example.com",
                json!({
                    "name": "Alice",
                    "age_public_key": original_key,
                    "description": null,
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/contact/alice@example.com",
                json!({
                    "email": "alice.renamed@example.com",
                    "name": "Alice Renamed",
                    "age_public_key": updated_key,
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/contacts",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("alice.renamed@example.com", body["entries"][0]["email"]);
        assert_eq!("Alice Renamed", body["entries"][0]["name"]);
        assert_eq!(updated_key, body["entries"][0]["age_public_key"]);

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/contact/bob@example.com",
                json!({
                    "age_public_key": age::x25519::Identity::generate().to_public().to_string(),
                    "description": null,
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/contact/alice.renamed@example.com",
                json!({
                    "email": "bob@example.com",
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::CONFLICT, response.status());

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/contact/missing@example.com",
                json!({
                    "email": "missing-renamed@example.com",
                    "name": null,
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = router
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/contact/alice.renamed@example.com",
                json!({
                    "email": "alice.renamed@example.com",
                    "age_public_key": "not-an-age-key",
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
    }

    #[tokio::test]
    async fn contact_list_api_paginates_and_rejects_invalid_query() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        for email in ["beta@example.com", "alpha@example.com"] {
            let public_key = age::x25519::Identity::generate().to_public().to_string();
            router
                .clone()
                .oneshot(json_request_with_hash(
                    "PUT",
                    &format!("/api/v1/contact/{email}"),
                    json!({
                        "age_public_key": public_key,
                        "description": null,
                    }),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
        }

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/contacts?count=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!(1, body["count"]);
        assert_eq!("alpha@example.com", body["entries"][0]["email"]);
        assert_eq!(serde_json::Value::Null, body["entries"][0]["description"]);
        let marker = body["next_marker"].as_str().unwrap();

        let response = router
            .clone()
            .oneshot(request_with_hash(
                &format!("/api/v1/contacts?count=1&marker={marker}"),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("beta@example.com", body["entries"][0]["email"]);
        assert_eq!(serde_json::Value::Null, body["next_marker"]);

        for path in [
            "/api/v1/contacts?count=0",
            "/api/v1/contacts?count=201",
            "/api/v1/contacts?count=abc",
            "/api/v1/contacts?marker=invalid",
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash(path, ProcessChainHash::test(1)))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{path}");
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn contact_api_rejects_invalid_create_requests() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        for (path, body) in [
            (
                "/api/v1/contact/alice",
                json!({"age_public_key": "", "description": null}),
            ),
            (
                "/api/v1/contact/alice",
                json!({"age_public_key": "not-an-age-key", "description": null}),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(json_request_with_hash(
                    "PUT",
                    path,
                    body,
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{path}");
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn item_api_handles_metadata_fields_and_file_bytes() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/file/upload",
                b"hello",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let file_id = json_body(response).await["id"].as_str().unwrap().to_owned();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "data": "secret"},
                        "otp_code": {"type": "totp", "concealed": false, "data": "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"},
                        "public_key": {"type": "string", "data": "public"}
                    },
                    "files": {
                        "notes": {"id": file_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/items",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("github", body["entries"][0]["name"]);
        assert!(body["entries"][0].get("fields").is_none());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert!(body["created_at"].as_str().unwrap().ends_with('Z'));
        assert!(body["updated_at"].as_str().unwrap().ends_with('Z'));
        assert_eq!(1, body["total_versions"]);
        assert_eq!(true, json_field(&body, "password")["concealed"]);
        assert_eq!(true, json_field(&body, "otp_code")["concealed"]);
        assert_eq!(false, json_field(&body, "public_key")["concealed"]);
        assert_eq!("******", json_field(&body, "password")["data"]);
        assert_eq!("******", json_field(&body, "otp_code")["data"]);
        assert_eq!("public", json_field(&body, "public_key")["data"]);
        assert_eq!(5, json_file(&body, "notes")["size"]);

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?reveal=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("secret", json_field(&body, "password")["data"]);
        let otp = json_field(&body, "otp_code")["data"].as_str().unwrap();
        assert_eq!(6, otp.len());
        assert!(otp.chars().all(|character| character.is_ascii_digit()));

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("secret", json_field(&body, "password")["data"]);
        assert_eq!(
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub",
            json_field(&body, "otp_code")["data"]
        );

        for path in [
            "/api/v1/dir/personal/item/github?reveal",
            "/api/v1/dir/personal/item/github?reveal=false",
            "/api/v1/dir/personal/item/github?reveal=yes",
            "/api/v1/dir/personal/item/github?raw",
            "/api/v1/dir/personal/item/github?raw=false",
            "/api/v1/dir/personal/item/github?raw=yes",
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash(path, ProcessChainHash::test(1)))
                .await
                .unwrap();
            let body = json_body(response).await;
            assert_eq!("******", json_field(&body, "password")["data"]);
            assert_eq!("******", json_field(&body, "otp_code")["data"]);
        }

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/otp_code",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "application/octet-stream",
            response.headers()[header::CONTENT_TYPE]
        );
        let otp = body_bytes(response).await;
        assert_eq!(6, otp.len());
        assert!(otp.iter().all(u8::is_ascii_digit));

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/otp_code?raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            b"otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&issuer=GitHub".as_slice(),
            body_bytes(response).await.as_ref()
        );

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/password",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "application/octet-stream",
            response.headers()[header::CONTENT_TYPE]
        );
        assert!(response.headers().get(header::ETAG).is_none());
        assert_eq!(b"secret".as_slice(), body_bytes(response).await.as_ref());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/notes",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "application/octet-stream",
            response.headers()[header::CONTENT_TYPE]
        );
        assert!(response.headers().get(header::ETAG).is_some());
        assert_eq!(b"hello".as_slice(), body_bytes(response).await.as_ref());

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github/file/notes",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());
    }

    #[tokio::test]
    async fn item_api_rejects_field_and_file_name_collisions() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let file_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let second_file_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"new notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/conflict",
                json!({
                    "fields": {
                        "password": {"type": "string", "data": "secret"}
                    },
                    "files": {
                        "password": {"id": file_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let body = json_body(response).await;
        assert_eq!("bad_request", body["error"]["code"]);
        assert_eq!(
            "field and file names must be unique: `password`",
            body["error"]["message"]
        );

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "data": "secret"}
                    },
                    "files": {
                        "notes": {"id": file_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/dir/personal/item/github",
                json!({
                    "files": {
                        "password": {"id": second_file_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        let body = json_body(response).await;
        assert_eq!("bad_request", body["error"]["code"]);
        assert_eq!(
            "field and file names must be unique: `password`",
            body["error"]["message"]
        );
    }

    #[tokio::test]
    async fn item_create_api_names_missing_dir() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/Me/item/foo",
                json!({"fields": {}, "files": {}}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        let body = json_body(response).await;
        assert_eq!("not_found", body["error"]["code"]);
        assert_eq!("dir `Me` not found", body["error"]["message"]);
    }

    #[tokio::test]
    async fn item_api_patch_merges_fields_and_replaces_files() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let old_notes_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"old notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let new_notes_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"new notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    },
                    "files": {
                        "notes": {"id": old_notes_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "data": "new"}
                    },
                    "files": {
                        "notes": {"id": new_notes_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("alice", json_field(&body, "username")["data"]);
        assert_eq!("new", json_field(&body, "password")["data"]);
        assert_eq!(9, json_file(&body, "notes")["size"]);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/notes",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(b"new notes".as_slice(), body_bytes(response).await.as_ref());
    }

    #[tokio::test]
    async fn item_api_patch_removes_fields_and_files() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let notes_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"old notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let attachment_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"attachment",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    },
                    "files": {
                        "notes": {"id": notes_id},
                        "attachment": {"id": attachment_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "username": {"remove": true}
                    },
                    "files": {
                        "notes": {"remove": true}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert!(!has_json_field(&body, "username"));
        assert_eq!("old", json_field(&body, "password")["data"]);
        assert!(!has_json_file(&body, "notes"));
        assert_eq!(10, json_file(&body, "attachment")["size"]);

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/notes",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?version=1&raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("alice", json_field(&body, "username")["data"]);
        assert_eq!(9, json_file(&body, "notes")["size"]);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/ref/personal/github/attachment",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(
            b"attachment".as_slice(),
            body_bytes(response).await.as_ref()
        );
    }

    #[tokio::test]
    async fn item_api_rejects_ambiguous_patch_remove_entries() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        for body in [
            json!({"fields": {"password": {"remove": true, "type": "string", "data": "new"}}}),
            json!({"files": {"notes": {"remove": true, "id": "00112233445566778899aabbccddeeff"}}}),
            json!({"fields": {"password": {"remove": false}}}),
            json!({"files": {"notes": {"id": "bad"}}}),
        ] {
            let response = router
                .clone()
                .oneshot(json_request_with_hash(
                    "PATCH",
                    "/api/v1/dir/personal/item/github",
                    body,
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status());
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn read_mustauth_item_api_requires_correct_bearer_for_secret_reads() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state.clone());

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let file_id = json_body(
            router
                .clone()
                .oneshot(bytes_request_with_hash(
                    "PUT",
                    "/api/v1/file/upload",
                    b"guarded notes",
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap(),
        )
        .await["id"]
            .as_str()
            .unwrap()
            .to_owned();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/guarded",
                json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "secret"}
                    },
                    "files": {
                        "notes": {"id": file_id}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        state
            .database_handle()
            .await
            .unwrap()
            .test_set_item_bitmask("personal", "guarded", ITEM_READ_MUSTAUTH)
            .await
            .unwrap();

        for path in [
            "/api/v1/dir/personal/item/guarded?reveal=true",
            "/api/v1/dir/personal/item/guarded?raw=true",
            "/api/v1/ref/personal/guarded/notes",
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash(path, ProcessChainHash::test(1)))
                .await
                .unwrap();
            assert_eq!(StatusCode::FORBIDDEN, response.status());
            assert_eq!("access_denied", json_body(response).await["error"]["code"]);

            for authorization in [
                "Basic abc".to_owned(),
                "Bearer !!!".to_owned(),
                bearer("wrong"),
            ] {
                let response = router
                    .clone()
                    .oneshot(request_with_hash_and_authorization(
                        path,
                        ProcessChainHash::test(1),
                        &authorization,
                    ))
                    .await
                    .unwrap();
                assert_eq!(StatusCode::FORBIDDEN, response.status());
                assert_eq!("access_denied", json_body(response).await["error"]["code"]);
            }
        }

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/guarded",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "******",
            json_field(&json_body(response).await, "password")["data"]
        );

        let response = router
            .clone()
            .oneshot(request_with_hash_and_password(
                "/api/v1/dir/personal/item/guarded?reveal=true",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "secret",
            json_field(&json_body(response).await, "password")["data"]
        );

        let response = router
            .clone()
            .oneshot(request_with_hash_and_password(
                "/api/v1/dir/personal/item/guarded?raw=true",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "secret",
            json_field(&json_body(response).await, "password")["data"]
        );

        let response = router
            .clone()
            .oneshot(request_with_hash_and_password(
                "/api/v1/ref/personal/guarded/notes",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            b"guarded notes".as_slice(),
            body_bytes(response).await.as_ref()
        );

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/_Internal/item/AgePublicKey?raw=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            "age1unused",
            json_field(&json_body(response).await, "key")["data"]
        );
        assert!(!state.is_authorized(&ProcessChainHash::test(2)).await);
    }

    #[tokio::test]
    async fn delete_dir_with_items_returns_conflict() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(delete_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::CONFLICT, response.status());
        let body = json_body(response).await;
        assert_eq!("conflict", body["error"]["code"]);
        assert_eq!("directory is not empty", body["error"]["message"]);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn item_list_api_paginates() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        for name in ["zulu", "alpha"] {
            router
                .clone()
                .oneshot(json_request_with_hash(
                    "PUT",
                    &format!("/api/v1/dir/personal/item/{name}"),
                    json!({}),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
        }

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/items?count=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("alpha", body["entries"][0]["name"]);
        let marker = body["next_marker"].as_str().unwrap();

        let response = router
            .oneshot(request_with_hash(
                &format!("/api/v1/dir/personal/items?count=1&marker={marker}"),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("zulu", body["entries"][0]["name"]);
        assert_eq!(serde_json::Value::Null, body["next_marker"]);
    }

    #[tokio::test]
    async fn item_version_api_lists_reads_and_restores_versions() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "old"}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PATCH",
                "/api/v1/dir/personal/item/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "concealed": true, "data": "new"}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github/versions?count=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!(1, body["count"]);
        assert_eq!(2, body["entries"][0]["version"]);
        assert!(
            body["entries"][0]["created_at"]
                .as_str()
                .unwrap()
                .ends_with('Z')
        );
        let marker = body["next_marker"].as_str().unwrap();

        let response = router
            .clone()
            .oneshot(request_with_hash(
                &format!("/api/v1/dir/personal/item/github/versions?count=1&marker={marker}"),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!(1, body["entries"][0]["version"]);
        assert_eq!(serde_json::Value::Null, body["next_marker"]);

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?version=1&reveal=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        let body = json_body(response).await;
        assert_eq!("old", json_field(&body, "password")["data"]);
        assert_eq!(2, body["total_versions"]);

        let response = router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal/item/github/restore?version=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(json!({}), json_body(response).await);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?reveal=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(
            "old",
            json_field(&json_body(response).await, "password")["data"]
        );
    }

    #[tokio::test]
    async fn item_version_api_rejects_invalid_versions_and_missing_restore_version() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        for path in [
            "/api/v1/dir/personal/item/github?version=",
            "/api/v1/dir/personal/item/github?version=abc",
            "/api/v1/dir/personal/item/github?version=0",
            "/api/v1/dir/personal/item/github?version=-1",
            "/api/v1/ref/personal/github/missing?version=0",
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash(path, ProcessChainHash::test(1)))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{path}");
        }

        let response = router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal/item/github/restore",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/personal/item/github?version=99",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = router
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal/item/github/restore?version=1",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
    }

    #[tokio::test]
    async fn item_api_supports_copy_from_and_move_from_query_params() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        for dir in ["source", "dest"] {
            router
                .clone()
                .oneshot(put_request_with_hash(
                    &format!("/api/v1/dir/{dir}"),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
        }

        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/source/item/github",
                json!({
                    "fields": {
                        "username": {"type": "string", "data": "alice"},
                        "password": {"type": "string", "data": "old"}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/dest/item/copy?copy_from=source/github",
                json!({
                    "fields": {
                        "password": {"type": "string", "data": "copied"}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/dest/item/moved?move_from=source/github",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/source/item/github",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/dir/dest/item/moved?reveal=true",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let body = json_body(response).await;
        assert_eq!("alice", json_field(&body, "username")["data"]);
        assert_eq!("old", json_field(&body, "password")["data"]);

        let response = router
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/dest/item/bad?copy_from=dest/copy&move_from=dest/moved",
                json!({}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());
    }

    #[tokio::test]
    async fn item_api_rejects_remove_entries_in_create_and_copy_requests() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        for dir in ["source", "dest"] {
            router
                .clone()
                .oneshot(put_request_with_hash(
                    &format!("/api/v1/dir/{dir}"),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
        }
        router
            .clone()
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/source/item/github",
                json!({}),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        for (path, body) in [
            (
                "/api/v1/dir/dest/item/create-field",
                json!({"fields": {"password": {"remove": true}}}),
            ),
            (
                "/api/v1/dir/dest/item/create-file",
                json!({"files": {"notes": {"remove": true, "id": "00112233445566778899aabbccddeeff"}}}),
            ),
            (
                "/api/v1/dir/dest/item/copy?copy_from=source/github",
                json!({"fields": {"password": {"remove": true}}}),
            ),
        ] {
            let response = router
                .clone()
                .oneshot(json_request_with_hash(
                    "PUT",
                    path,
                    body,
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{path}");
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn file_lookup_api_returns_existing_file_id() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);
        let response = router
            .clone()
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/file/upload",
                b"hello",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let file_id = json_body(response).await["id"].as_str().unwrap().to_owned();

        let response = router
            .oneshot(request_with_hash(
                &format!(
                    "/api/v1/file/lookup/sha256/{}",
                    crate::agent::state::sha256_hex(b"hello")
                ),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(file_id, json_body(response).await["id"]);
    }

    #[tokio::test]
    async fn file_lookup_api_rejects_malformed_and_missing_hashes() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/file/lookup/sha256/ABC",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::BAD_REQUEST, response.status());

        let response = router
            .oneshot(request_with_hash(
                &format!(
                    "/api/v1/file/lookup/sha256/{}",
                    crate::agent::state::sha256_hex(b"missing")
                ),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::NOT_FOUND, response.status());
    }

    #[tokio::test]
    async fn duplicate_file_upload_returns_existing_file_id() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let first = router
            .clone()
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/file/upload",
                b"hello",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let first_id = json_body(first).await["id"].as_str().unwrap().to_owned();

        let second = router
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/file/upload",
                b"hello",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, second.status());
        assert_eq!(first_id, json_body(second).await["id"]);
    }

    #[tokio::test]
    async fn file_api_rejects_missing_content_length() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let mut request = Request::builder()
            .method("PUT")
            .uri("/api/v1/file/upload")
            .body(Body::from(b"hello".to_vec()))
            .unwrap();
        request.extensions_mut().insert(ProcessChainHash::test(1));

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert_eq!(
            "content-length is required",
            json_body(response).await["error"]["message"]
        );
    }

    #[tokio::test]
    async fn file_api_rejects_too_large_content_length_before_database_work() {
        let state = AgentState::from_database_path("missing.db");
        let database = DbHandle::test();
        let before = database.dispatch_counts();
        state.store_database_handle(database.clone()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        let router = super::database_routes(state.clone()).with_state(state);

        let mut request = Request::builder()
            .method("PUT")
            .uri("/api/v1/file/upload")
            .header(
                header::CONTENT_LENGTH,
                (MAX_FILE_UPLOAD_BYTES + 1).to_string(),
            )
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(ProcessChainHash::test(1));

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert_eq!(
            "file too large",
            json_body(response).await["error"]["message"]
        );
        let after = database.dispatch_counts();
        assert_eq!(before.0, after.0);
    }

    #[tokio::test]
    async fn file_api_rejects_body_shorter_than_content_length() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let mut request = Request::builder()
            .method("PUT")
            .uri("/api/v1/file/upload")
            .header(header::CONTENT_LENGTH, "10")
            .body(Body::from(b"hello".to_vec()))
            .unwrap();
        request.extensions_mut().insert(ProcessChainHash::test(1));

        let response = router.oneshot(request).await.unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
        assert_eq!(
            "request body ended before content-length",
            json_body(response).await["error"]["message"]
        );
    }

    #[tokio::test]
    async fn item_api_rejects_invalid_totp_urls() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        for (index, data) in [
            "seed",
            "https://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP",
            "otpauth://hotp/GitHub:alice?secret=JBSWY3DPEHPK3PXP",
            "otpauth://totp/GitHub:alice",
            "otpauth://totp/GitHub:alice?secret=",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP=",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PX0",
            "otpauth://totp/GitHub:alice?secret=A",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=0",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=11",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&digits=abc",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&period=0",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&period=abc",
            "otpauth://totp/GitHub:alice?secret=JBSWY3DPEHPK3PXP&algorithm=MD5",
        ]
        .into_iter()
        .enumerate()
        {
            let response = router
                .clone()
                .oneshot(json_request_with_hash(
                    "PUT",
                    &format!("/api/v1/dir/personal/item/bad{index}"),
                    json!({
                        "fields": {
                            "totp": {"type": "totp", "data": data}
                        }
                    }),
                    ProcessChainHash::test(1),
                ))
                .await
                .unwrap();

            assert_eq!(StatusCode::BAD_REQUEST, response.status(), "{data}");
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn item_api_rejects_inline_file_payloads() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        let response = router
            .oneshot(json_request_with_hash(
                "PUT",
                "/api/v1/dir/personal/item/github",
                json!({
                    "files": {
                        "notes": {"content": "hello"}
                    }
                }),
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::BAD_REQUEST, response.status());
    }

    #[tokio::test]
    async fn duplicate_create_returns_conflict() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        router
            .clone()
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        let response = router
            .oneshot(put_request_with_hash(
                "/api/v1/dir/personal",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::CONFLICT, response.status());
        assert_eq!("conflict", json_body(response).await["error"]["code"]);
    }

    #[tokio::test]
    async fn settings_api_lists_and_updates_user_settings() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .clone()
            .oneshot(request_with_hash_and_password(
                "/api/v1/settings",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(
            json!({"user.authTtlSeconds":"900","user.gcSeconds":"3600"}),
            json_body(response).await
        );

        let response = router
            .clone()
            .oneshot(json_request_with_hash_and_password(
                "PUT",
                "/api/v1/settings/user.authTtlSeconds",
                json!({"value":"1200"}),
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::OK, response.status());
        assert_eq!(json!({}), json_body(response).await);

        let response = router
            .oneshot(request_with_hash_and_password(
                "/api/v1/settings",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!("1200", json_body(response).await["user.authTtlSeconds"]);
    }

    #[tokio::test]
    async fn settings_api_requires_valid_bearer_password() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .clone()
            .oneshot(request_with_hash(
                "/api/v1/settings",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        assert_eq!("access_denied", json_body(response).await["error"]["code"]);

        for authorization in [
            "Basic abc".to_owned(),
            "Bearer !!!".to_owned(),
            format!("Bearer {}", general_purpose::STANDARD.encode([0xff, 0xfe])),
            format!("Bearer {}", general_purpose::STANDARD.encode("wrong")),
            "Bearer ".to_owned(),
        ] {
            let response = router
                .clone()
                .oneshot(request_with_hash_and_authorization(
                    "/api/v1/settings",
                    ProcessChainHash::test(1),
                    &authorization,
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::FORBIDDEN, response.status());
            assert_eq!("access_denied", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn settings_api_rejects_invalid_unknown_and_internal_settings() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        for body in [json!({}), json!({"value":"abc"}), json!({"value":"0"})] {
            let response = router
                .clone()
                .oneshot(json_request_with_hash_and_password(
                    "PUT",
                    "/api/v1/settings/user.authTtlSeconds",
                    body,
                    ProcessChainHash::test(1),
                    "correct",
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::BAD_REQUEST, response.status());
            assert_eq!("bad_request", json_body(response).await["error"]["code"]);
        }

        for path in [
            "/api/v1/settings/user.missing",
            "/api/v1/settings/sys.fileEncryptionKey",
        ] {
            let response = router
                .clone()
                .oneshot(json_request_with_hash_and_password(
                    "PUT",
                    path,
                    json!({"value":"900"}),
                    ProcessChainHash::test(1),
                    "correct",
                ))
                .await
                .unwrap();
            assert_eq!(StatusCode::NOT_FOUND, response.status());
            assert_eq!("not_found", json_body(response).await["error"]["code"]);
        }
    }

    #[tokio::test]
    async fn settings_api_denies_locked_or_unauthorized_callers_before_password_handling() {
        let state = AgentState::from_database_path("missing.db");
        let router = super::database_routes(state.clone()).with_state(state);
        let response = router
            .oneshot(request_with_hash_and_password(
                "/api/v1/settings",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        assert_eq!("access_denied", json_body(response).await["error"]["code"]);

        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        let router = super::database_routes(state.clone()).with_state(state);
        let response = router
            .oneshot(request_with_hash_and_password(
                "/api/v1/settings",
                ProcessChainHash::test(1),
                "correct",
            ))
            .await
            .unwrap();
        assert_eq!(StatusCode::FORBIDDEN, response.status());
        assert_eq!("access_denied", json_body(response).await["error"]["code"]);
    }

    #[tokio::test]
    async fn job_api_returns_not_found_for_missing_job() {
        let state = authorized_state().await;
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(request_with_hash(
                "/api/v1/jobs/status/00112233445566778899aabbccddeeff",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::NOT_FOUND, response.status());
        assert_eq!("not_found", json_body(response).await["error"]["code"]);
    }

    #[tokio::test]
    async fn import_api_accepts_job_and_persists_failure_status() {
        let state = authorized_state().await;
        let database = state.database_handle().await.unwrap();
        database.create_dir("dir".to_owned()).await.unwrap();
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(bytes_request_with_hash(
                "PUT",
                "/api/v1/jobs/import/dir/imported",
                b"not an age export",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::ACCEPTED, response.status());
        let accepted = json_body(response).await;
        assert_eq!("queued", accepted["status"]);
        let job_id = accepted["job_id"].as_str().unwrap();

        let mut job = database.get_job(job_id.to_owned()).await.unwrap();
        for _ in 0..20 {
            if job.status == crate::agent::models::JobStatus::Failed {
                break;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
            job = database.get_job(job_id.to_owned()).await.unwrap();
        }

        assert_eq!(crate::agent::models::JobStatus::Failed, job.status);
        assert!(job.error.is_some());
    }

    #[tokio::test]
    async fn export_api_accepts_job_and_records_target() {
        let state = authorized_state().await;
        let database = state.database_handle().await.unwrap();
        database.create_dir("dir".to_owned()).await.unwrap();
        database
            .create_contact(
                "alice".to_owned(),
                crate::agent::models::CreateContactRequest {
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
                crate::agent::models::CreateItemRequest::default(),
                None,
            )
            .await
            .unwrap();
        let router = super::database_routes(state.clone()).with_state(state);

        let response = router
            .oneshot(put_request_with_hash(
                "/api/v1/jobs/export/dir/item/alice",
                ProcessChainHash::test(1),
            ))
            .await
            .unwrap();

        assert_eq!(StatusCode::ACCEPTED, response.status());
        let accepted = json_body(response).await;
        assert_eq!("queued", accepted["status"]);
        let job = database
            .get_job(accepted["job_id"].as_str().unwrap().to_owned())
            .await
            .unwrap();
        assert_eq!(crate::agent::models::JobType::Export, job.job_type);
        assert_eq!("dir", job.target.dir);
        assert_eq!("item", job.target.item);
        assert_eq!(Some("alice".to_owned()), job.target.contact);
    }

    fn request_with_hash(path: &str, process_hash: ProcessChainHash) -> Request<Body> {
        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn request_with_hash_and_password(
        path: &str,
        process_hash: ProcessChainHash,
        password: &str,
    ) -> Request<Body> {
        request_with_hash_and_authorization(path, process_hash, &bearer(password))
    }

    fn request_with_hash_and_authorization(
        path: &str,
        process_hash: ProcessChainHash,
        authorization: &str,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("GET")
            .uri(path)
            .header(header::AUTHORIZATION, authorization)
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn put_request_with_hash(path: &str, process_hash: ProcessChainHash) -> Request<Body> {
        let mut request = Request::put(path).body(Body::empty()).unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn post_request_with_hash_and_password(
        path: &str,
        process_hash: ProcessChainHash,
        password: &str,
    ) -> Request<Body> {
        let mut request = Request::post(path)
            .header(header::AUTHORIZATION, bearer(password))
            .body(Body::empty())
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn post_request_with_hash(path: &str, process_hash: ProcessChainHash) -> Request<Body> {
        let mut request = Request::post(path).body(Body::empty()).unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn delete_request_with_hash(path: &str, process_hash: ProcessChainHash) -> Request<Body> {
        let mut request = Request::delete(path).body(Body::empty()).unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn json_request_with_hash(
        method: &str,
        path: &str,
        body: serde_json::Value,
        process_hash: ProcessChainHash,
    ) -> Request<Body> {
        let body = item_json(body);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn json_request_with_hash_and_password(
        method: &str,
        path: &str,
        body: serde_json::Value,
        process_hash: ProcessChainHash,
        password: &str,
    ) -> Request<Body> {
        let body = item_json(body);
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::AUTHORIZATION, bearer(password))
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    fn item_json(mut value: serde_json::Value) -> serde_json::Value {
        map_named_entries(&mut value, "fields");
        map_named_entries(&mut value, "files");
        value
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

    fn bytes_request_with_hash(
        method: &str,
        path: &str,
        body: &[u8],
        process_hash: ProcessChainHash,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header(header::CONTENT_LENGTH, body.len().to_string())
            .body(Body::from(body.to_vec()))
            .unwrap();
        request.extensions_mut().insert(process_hash);
        request
    }

    async fn authorized_state() -> AgentState {
        let state = AgentState::from_database_path("missing.db");
        state.store_database_handle(DbHandle::test()).await;
        state.store_password_verifier("correct").await;
        state
            .authorize_process_hash(ProcessChainHash::test(1))
            .await;
        state
    }

    fn bearer(password: &str) -> String {
        format!("Bearer {}", general_purpose::STANDARD.encode(password))
    }

    async fn json_body(response: axum::response::Response) -> serde_json::Value {
        serde_json::from_slice(&body_bytes(response).await).unwrap()
    }

    fn json_field<'a>(body: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        body["fields"]
            .as_array()
            .unwrap()
            .iter()
            .find(|field| field["name"] == name)
            .expect("field exists")
    }

    fn json_file<'a>(body: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
        body["files"]
            .as_array()
            .unwrap()
            .iter()
            .find(|file| file["name"] == name)
            .expect("file exists")
    }

    fn has_json_field(body: &serde_json::Value, name: &str) -> bool {
        body["fields"]
            .as_array()
            .unwrap()
            .iter()
            .any(|field| field["name"] == name)
    }

    fn has_json_file(body: &serde_json::Value, name: &str) -> bool {
        body["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|file| file["name"] == name)
    }

    async fn body_bytes(response: axum::response::Response) -> axum::body::Bytes {
        response.into_body().collect().await.unwrap().to_bytes()
    }
}
