use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Path;
use axum::extract::Request;
use axum::extract::State;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use http_body::{Frame, SizeHint};
use tokio::net::UnixListener;

use super::error::ApiError;
use super::models::AccessScope;
use super::process::{ProcessDisplay, ResolvedAuthorizationScope, ScopeHash, UltimateProcess};
use super::state::{ActiveDatabaseRequest, AgentState};
use crate::settings::ProcessIdentificationType;

#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    authorization: Option<PeerAuthorization>,
}

#[derive(Debug, Clone)]
pub(crate) struct PeerAuthorization {
    uid: u32,
    scope: Option<ResolvedAuthorizationScope>,
    originating_process_hash: Option<ScopeHash>,
    ultimate: Option<UltimateProcess>,
}

impl PeerAuthorization {
    pub(crate) fn scope_hash(
        &self,
        identification_type: ProcessIdentificationType,
    ) -> Option<ScopeHash> {
        match identification_type {
            ProcessIdentificationType::InsecureAll => Some(ScopeHash::insecure_all(self.uid)),
            ProcessIdentificationType::ProcessChain => {
                self.scope.as_ref().map(|scope| scope.hash.clone())
            }
            ProcessIdentificationType::OriginatingProcess => self.originating_process_hash.clone(),
        }
    }

    #[cfg(test)]
    pub(crate) fn test(uid: u32, process_chain: ScopeHash, originating_process: ScopeHash) -> Self {
        Self {
            uid,
            scope: Some(ResolvedAuthorizationScope {
                hash: process_chain,
                originating_process_hash: originating_process.clone(),
                display: None,
                ultimate: UltimateProcess::test("test-client"),
            }),
            originating_process_hash: Some(originating_process),
            ultimate: Some(UltimateProcess::test("test-client")),
        }
    }
}

impl Connected<IncomingStream<'_, UnixListener>> for PeerConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self::from_peer_credentials(stream.io().peer_cred().ok().map(PeerCredentials::from))
    }
}

impl PeerConnectInfo {
    fn from_peer_credentials(credentials: Option<PeerCredentials>) -> Self {
        Self {
            authorization: authorized_peer_authorization(credentials.as_ref()),
        }
    }

    fn authorization(&self) -> Option<&PeerAuthorization> {
        self.authorization.as_ref()
    }

    #[cfg(test)]
    fn scope_hash(&self) -> Option<ScopeHash> {
        self.authorization()?
            .scope_hash(ProcessIdentificationType::ProcessChain)
    }

    fn display(&self) -> Option<&ProcessDisplay> {
        self.authorization
            .as_ref()
            .and_then(|authorization| authorization.scope.as_ref())
            .and_then(|scope| scope.display.as_ref())
    }

    fn ultimate(&self) -> Option<&UltimateProcess> {
        self.authorization
            .as_ref()
            .and_then(|authorization| authorization.ultimate.as_ref())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PeerCredentials {
    pid: Option<i32>,
    uid: u32,
    gid: u32,
}

impl From<tokio::net::unix::UCred> for PeerCredentials {
    fn from(credentials: tokio::net::unix::UCred) -> Self {
        Self {
            pid: credentials.pid(),
            uid: credentials.uid(),
            gid: credentials.gid(),
        }
    }
}

pub async fn require_same_uid_and_gid(
    State(state): State<AgentState>,
    ConnectInfo(connect_info): ConnectInfo<PeerConnectInfo>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(authorization) = connect_info.authorization() {
        let identification_type = state.process_identification_type().await;
        let scope_hash = authorization
            .scope_hash(identification_type)
            .ok_or_else(ApiError::access_denied)?;
        request.extensions_mut().insert(scope_hash);
        request.extensions_mut().insert(authorization.clone());
        if let Some(display) = connect_info.display() {
            request.extensions_mut().insert(display.clone());
        }
        if let Some(ultimate) = connect_info.ultimate() {
            request.extensions_mut().insert(ultimate.clone());
        }
        Ok(next.run(request).await)
    } else {
        Err(ApiError::access_denied())
    }
}

#[cfg(any(not(target_os = "macos"), test))]
pub async fn require_direct_unlock_caller(
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let caller = request
        .extensions()
        .get::<UltimateProcess>()
        .and_then(super::process::direct_unlock_caller)
        .ok_or_else(ApiError::access_denied)?;
    request.extensions_mut().insert(caller);
    Ok(next.run(request).await)
}

pub async fn require_unlocked_database(
    State(state): State<AgentState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    require_authorized_database(state, request, next, AccessScope::Items).await
}

pub async fn require_settings_authorization(
    State(state): State<AgentState>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    require_authorized_database(state, request, next, AccessScope::Settings).await
}

pub async fn require_setting_member_authorization(
    State(state): State<AgentState>,
    Path(name): Path<String>,
    request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if request.method() == Method::GET && name.starts_with("cli.") {
        require_authorized_database_for_scopes(
            state,
            request,
            next,
            &[AccessScope::Items, AccessScope::Settings],
        )
        .await
    } else {
        require_authorized_database(state, request, next, AccessScope::Settings).await
    }
}

async fn require_authorized_database(
    state: AgentState,
    request: Request,
    next: Next,
    access_scope: AccessScope,
) -> Result<Response, ApiError> {
    require_authorized_database_for_scopes(state, request, next, &[access_scope]).await
}

async fn require_authorized_database_for_scopes(
    state: AgentState,
    mut request: Request,
    next: Next,
    access_scopes: &[AccessScope],
) -> Result<Response, ApiError> {
    let Some(scope_hash) = request.extensions().get::<ScopeHash>() else {
        return Err(ApiError::access_denied());
    };

    if state.is_migration_needed().await {
        return Err(ApiError::migration_needed());
    }

    let mut database = None;
    for access_scope in access_scopes {
        database = state
            .authorize_database_access_for_scope(scope_hash, *access_scope)
            .await;
        if database.is_some() {
            break;
        }
    }

    if let Some(database) = database {
        let active_request = state.begin_active_database_request();
        request.extensions_mut().insert(database);
        let response = next.run(request).await;
        Ok(response.map(|body| {
            Body::new(GuardedBody {
                body,
                _active_request: active_request,
            })
        }))
    } else {
        Err(ApiError::access_denied())
    }
}

struct GuardedBody {
    body: Body,
    _active_request: ActiveDatabaseRequest,
}

impl HttpBody for GuardedBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.body).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.body.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.body.size_hint()
    }
}

fn authorized_peer_authorization(
    credentials: Option<&PeerCredentials>,
) -> Option<PeerAuthorization> {
    let credentials = credentials?;
    if !peer_credentials_are_authorized(Some(credentials)) {
        return None;
    }

    let scope = credentials
        .pid
        .and_then(|pid| super::process::resolve_authorization_scope(pid, credentials.uid));
    let originating_process_hash = scope
        .as_ref()
        .map(|scope| scope.originating_process_hash.clone())
        .or_else(|| {
            credentials.pid.and_then(|pid| {
                super::process::resolve_originating_process_scope_hash(pid, credentials.uid)
            })
        });
    let ultimate = scope
        .as_ref()
        .map(|scope| scope.ultimate.clone())
        .or_else(|| {
            credentials
                .pid
                .and_then(|pid| super::process::resolve_direct_process(pid, credentials.uid))
        });
    Some(PeerAuthorization {
        uid: credentials.uid,
        scope,
        originating_process_hash,
        ultimate,
    })
}

fn peer_credentials_are_authorized(credentials: Option<&PeerCredentials>) -> bool {
    matches!(
        credentials,
        Some(credentials)
            if credentials.uid == current_process_uid()
                && credentials.gid == current_process_gid()
    )
}

fn current_process_uid() -> u32 {
    unsafe { libc::geteuid() }
}

fn current_process_gid() -> u32 {
    unsafe { libc::getegid() }
}

#[cfg(test)]
mod tests {
    use axum::Router;
    use axum::body::Body;
    use axum::extract::connect_info::ConnectInfo;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use tower::ServiceExt;

    use crate::agent::process::{
        DirectUnlockCaller, ProcessDisplay, ResolvedAuthorizationScope, ScopeHash, UltimateProcess,
    };
    use crate::settings::ProcessIdentificationType;

    use super::{
        PeerAuthorization, PeerConnectInfo, PeerCredentials, current_process_gid,
        current_process_uid,
    };

    #[test]
    fn matching_uid_and_gid_are_authorized() {
        assert!(super::peer_credentials_are_authorized(Some(
            &PeerCredentials {
                pid: Some(123),
                uid: current_process_uid(),
                gid: current_process_gid(),
            },
        )));
    }

    #[test]
    fn mismatched_uid_is_rejected() {
        assert!(!super::peer_credentials_are_authorized(Some(
            &PeerCredentials {
                pid: Some(123),
                uid: current_process_uid().wrapping_add(1),
                gid: current_process_gid(),
            },
        )));
    }

    #[test]
    fn mismatched_gid_is_rejected() {
        assert!(!super::peer_credentials_are_authorized(Some(
            &PeerCredentials {
                pid: Some(123),
                uid: current_process_uid(),
                gid: current_process_gid().wrapping_add(1),
            },
        )));
    }

    #[test]
    fn missing_credentials_are_rejected() {
        assert!(!super::peer_credentials_are_authorized(None));
    }

    #[test]
    fn missing_peer_pid_still_allows_same_user_insecure_mode() {
        assert!(super::peer_credentials_are_authorized(Some(
            &PeerCredentials {
                pid: None,
                uid: current_process_uid(),
                gid: current_process_gid(),
            },
        )));
    }

    #[test]
    fn missing_credentials_produce_no_scope_hash() {
        let connect_info = PeerConnectInfo::from_peer_credentials(None);

        assert_eq!(None, connect_info.scope_hash());
    }

    #[test]
    fn mismatched_uid_produces_no_scope_hash() {
        let connect_info = PeerConnectInfo::from_peer_credentials(Some(PeerCredentials {
            pid: Some(std::process::id() as i32),
            uid: current_process_uid().wrapping_add(1),
            gid: current_process_gid(),
        }));

        assert_eq!(None, connect_info.scope_hash());
    }

    #[test]
    fn mismatched_gid_produces_no_scope_hash() {
        let connect_info = PeerConnectInfo::from_peer_credentials(Some(PeerCredentials {
            pid: Some(std::process::id() as i32),
            uid: current_process_uid(),
            gid: current_process_gid().wrapping_add(1),
        }));

        assert_eq!(None, connect_info.scope_hash());
    }

    #[test]
    fn missing_pid_produces_no_scope_hash() {
        let connect_info = PeerConnectInfo::from_peer_credentials(Some(PeerCredentials {
            pid: None,
            uid: current_process_uid(),
            gid: current_process_gid(),
        }));

        assert_eq!(None, connect_info.scope_hash());
    }

    #[test]
    fn matching_credentials_precompute_scope_hash() {
        let connect_info = PeerConnectInfo::from_peer_credentials(Some(PeerCredentials {
            pid: Some(std::process::id() as i32),
            uid: current_process_uid(),
            gid: current_process_gid(),
        }));

        assert!(connect_info.scope_hash().is_some());
    }

    #[tokio::test]
    async fn middleware_with_no_precomputed_hash_returns_access_denied() {
        let response = router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                authorization: None,
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    #[tokio::test]
    async fn insecure_all_accepts_same_user_without_process_lineage() {
        let state = crate::agent::state::AgentState::from_database_path("missing.db");
        state
            .set_process_identification_type_for_test(ProcessIdentificationType::InsecureAll)
            .await;
        let response = Router::new()
            .route("/", get(any_hash_handler))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                super::require_same_uid_and_gid,
            ))
            .with_state(state)
            .oneshot(request_with_connect_info(PeerConnectInfo {
                authorization: Some(PeerAuthorization {
                    uid: current_process_uid(),
                    scope: None,
                    originating_process_hash: None,
                    ultimate: None,
                }),
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn middleware_inserts_precomputed_hash_into_request_extensions() {
        let response = router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                authorization: Some(PeerAuthorization {
                    uid: current_process_uid(),
                    originating_process_hash: Some(ScopeHash::test(2)),
                    ultimate: Some(UltimateProcess::test("example")),
                    scope: Some(ResolvedAuthorizationScope {
                        hash: ScopeHash::test(1),
                        originating_process_hash: ScopeHash::test(2),
                        display: None,
                        ultimate: UltimateProcess::test("example"),
                    }),
                }),
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn middleware_inserts_precomputed_display_into_request_extensions() {
        let display = ProcessDisplay {
            name: "Example".to_owned(),
            path: "example".into(),
            icon: None,
            gui_application: None,
        };
        let response = display_router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                authorization: Some(PeerAuthorization {
                    uid: current_process_uid(),
                    originating_process_hash: Some(ScopeHash::test(2)),
                    ultimate: Some(UltimateProcess::test("example")),
                    scope: Some(ResolvedAuthorizationScope {
                        hash: ScopeHash::test(1),
                        originating_process_hash: ScopeHash::test(2),
                        display: Some(display),
                        ultimate: UltimateProcess::test("example"),
                    }),
                }),
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn direct_unlock_middleware_derives_agent_policy_from_verified_ultimate_process() {
        let response = direct_router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                authorization: Some(PeerAuthorization {
                    uid: current_process_uid(),
                    originating_process_hash: Some(ScopeHash::test(2)),
                    ultimate: Some(UltimateProcess::test_agent()),
                    scope: Some(ResolvedAuthorizationScope {
                        hash: ScopeHash::test(1),
                        originating_process_hash: ScopeHash::test(2),
                        display: None,
                        ultimate: UltimateProcess::test_agent(),
                    }),
                }),
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    #[tokio::test]
    async fn direct_unlock_middleware_rejects_missing_ultimate_process() {
        let request = Request::get("/").body(Body::empty()).unwrap();
        let response = Router::new()
            .route("/", get(direct_caller_required_handler))
            .route_layer(middleware::from_fn(super::require_direct_unlock_caller))
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    fn router() -> Router {
        let state = crate::agent::state::AgentState::from_database_path("missing.db");
        Router::new()
            .route("/", get(hash_required_handler))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                super::require_same_uid_and_gid,
            ))
            .with_state(state)
    }

    fn display_router() -> Router {
        let state = crate::agent::state::AgentState::from_database_path("missing.db");
        Router::new()
            .route("/", get(display_required_handler))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                super::require_same_uid_and_gid,
            ))
            .with_state(state)
    }

    fn direct_router() -> Router {
        let state = crate::agent::state::AgentState::from_database_path("missing.db");
        Router::new()
            .route("/", get(direct_caller_required_handler))
            .route_layer(middleware::from_fn(super::require_direct_unlock_caller))
            .route_layer(middleware::from_fn_with_state(
                state.clone(),
                super::require_same_uid_and_gid,
            ))
            .with_state(state)
    }

    async fn hash_required_handler(scope_hash: Option<axum::Extension<ScopeHash>>) -> StatusCode {
        match scope_hash {
            Some(axum::Extension(scope_hash)) if scope_hash == ScopeHash::test(1) => StatusCode::OK,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    async fn any_hash_handler(scope_hash: Option<axum::Extension<ScopeHash>>) -> StatusCode {
        if scope_hash.is_some() {
            StatusCode::OK
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        }
    }

    async fn display_required_handler(
        display: Option<axum::Extension<ProcessDisplay>>,
    ) -> StatusCode {
        match display {
            Some(axum::Extension(display)) if display.name == "Example" => StatusCode::OK,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    async fn direct_caller_required_handler(
        caller: Option<axum::Extension<DirectUnlockCaller>>,
    ) -> StatusCode {
        match caller {
            Some(axum::Extension(DirectUnlockCaller::Agent)) => StatusCode::OK,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn request_with_connect_info(connect_info: PeerConnectInfo) -> Request<Body> {
        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(connect_info));
        request
    }
}
