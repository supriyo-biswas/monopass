use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, Bytes, HttpBody};
use axum::extract::Request;
use axum::extract::State;
use axum::extract::connect_info::{ConnectInfo, Connected};
use axum::middleware::Next;
use axum::response::Response;
use axum::serve::IncomingStream;
use http_body::{Frame, SizeHint};
use tokio::net::UnixListener;

use super::error::ApiError;
use super::process::{ProcessDisplay, ResolvedAuthorizationScope, ScopeHash};
use super::state::{ActiveDatabaseRequest, AgentState};

#[derive(Debug, Clone)]
pub struct PeerConnectInfo {
    scope: Option<ResolvedAuthorizationScope>,
}

impl Connected<IncomingStream<'_, UnixListener>> for PeerConnectInfo {
    fn connect_info(stream: IncomingStream<'_, UnixListener>) -> Self {
        Self::from_peer_credentials(stream.io().peer_cred().ok().map(PeerCredentials::from))
    }
}

impl PeerConnectInfo {
    fn from_peer_credentials(credentials: Option<PeerCredentials>) -> Self {
        Self {
            scope: authorized_peer_scope(credentials.as_ref()),
        }
    }

    fn scope_hash(&self) -> Option<&ScopeHash> {
        self.scope.as_ref().map(|scope| &scope.hash)
    }

    fn display(&self) -> Option<&ProcessDisplay> {
        self.scope.as_ref().and_then(|scope| scope.display.as_ref())
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
    ConnectInfo(connect_info): ConnectInfo<PeerConnectInfo>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    if let Some(scope_hash) = connect_info.scope_hash() {
        request.extensions_mut().insert(scope_hash.clone());
        if let Some(display) = connect_info.display() {
            request.extensions_mut().insert(display.clone());
        }
        Ok(next.run(request).await)
    } else {
        Err(ApiError::access_denied())
    }
}

pub async fn require_unlocked_database(
    State(state): State<AgentState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let Some(scope_hash) = request.extensions().get::<ScopeHash>() else {
        return Err(ApiError::access_denied());
    };

    if let Some(database) = state.authorize_database_access(scope_hash).await {
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

fn authorized_peer_scope(
    credentials: Option<&PeerCredentials>,
) -> Option<ResolvedAuthorizationScope> {
    let credentials = credentials?;
    if !peer_credentials_are_authorized(Some(credentials)) {
        return None;
    }

    super::process::resolve_authorization_scope(credentials.pid?, credentials.uid)
}

fn peer_credentials_are_authorized(credentials: Option<&PeerCredentials>) -> bool {
    matches!(
        credentials,
        Some(credentials)
            if credentials.uid == current_process_uid()
                && credentials.gid == current_process_gid()
                && credentials.pid.is_some()
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

    use crate::agent::process::{ProcessDisplay, ResolvedAuthorizationScope, ScopeHash};

    use super::{PeerConnectInfo, PeerCredentials, current_process_gid, current_process_uid};

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
    fn missing_peer_pid_is_rejected() {
        assert!(!super::peer_credentials_are_authorized(Some(
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
            .oneshot(request_with_connect_info(PeerConnectInfo { scope: None }))
            .await
            .unwrap();

        assert_eq!(StatusCode::FORBIDDEN, response.status());
    }

    #[tokio::test]
    async fn middleware_inserts_precomputed_hash_into_request_extensions() {
        let response = router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                scope: Some(ResolvedAuthorizationScope {
                    hash: ScopeHash::test(1),
                    display: None,
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
            icon_path: None,
            modified: None,
        };
        let response = display_router()
            .oneshot(request_with_connect_info(PeerConnectInfo {
                scope: Some(ResolvedAuthorizationScope {
                    hash: ScopeHash::test(1),
                    display: Some(display),
                }),
            }))
            .await
            .unwrap();

        assert_eq!(StatusCode::OK, response.status());
    }

    fn router() -> Router {
        Router::new()
            .route("/", get(hash_required_handler))
            .route_layer(middleware::from_fn(super::require_same_uid_and_gid))
    }

    fn display_router() -> Router {
        Router::new()
            .route("/", get(display_required_handler))
            .route_layer(middleware::from_fn(super::require_same_uid_and_gid))
    }

    async fn hash_required_handler(scope_hash: Option<axum::Extension<ScopeHash>>) -> StatusCode {
        match scope_hash {
            Some(axum::Extension(scope_hash)) if scope_hash == ScopeHash::test(1) => StatusCode::OK,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
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

    fn request_with_connect_info(connect_info: PeerConnectInfo) -> Request<Body> {
        let mut request = Request::get("/").body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(connect_info));
        request
    }
}
