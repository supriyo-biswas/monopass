use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ErrorBody {
    pub code: ApiErrorCode,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiErrorCode {
    AccessDenied,
    BadRequest,
    Conflict,
    InternalError,
    NotFound,
    // Keep this condition in sync with the GUI unlock route.
    #[cfg(any(
        test,
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    TemporaryLockout,
    #[cfg_attr(target_os = "macos", allow(dead_code))]
    UnlockFailed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    pub(crate) status: StatusCode,
    body: ErrorResponse,
}

impl ApiError {
    pub fn access_denied() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: ErrorResponse {
                error: ErrorBody {
                    code: ApiErrorCode::AccessDenied,
                    message: "access denied".to_owned(),
                },
            },
        }
    }

    // Keep this condition in sync with the GUI unlock route.
    #[cfg(any(
        test,
        target_os = "macos",
        all(target_os = "linux", any(feature = "gtk", feature = "qt"))
    ))]
    pub fn temporary_lockout() -> Self {
        Self::new(
            StatusCode::FORBIDDEN,
            ApiErrorCode::TemporaryLockout,
            "temporarily locked out after denial",
        )
    }

    #[cfg_attr(target_os = "macos", allow(dead_code))]
    pub fn unlock_failed() -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            body: ErrorResponse {
                error: ErrorBody {
                    code: ApiErrorCode::UnlockFailed,
                    message: "failed to unlock database".to_owned(),
                },
            },
        }
    }

    pub fn bad_request(message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, ApiErrorCode::BadRequest, message)
    }

    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, ApiErrorCode::NotFound, message)
    }

    pub fn conflict(message: impl Into<String>) -> Self {
        Self::new(StatusCode::CONFLICT, ApiErrorCode::Conflict, message)
    }

    pub fn internal_error() -> Self {
        Self::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            ApiErrorCode::InternalError,
            "internal error",
        )
    }

    fn new(status: StatusCode, code: ApiErrorCode, message: impl Into<String>) -> Self {
        Self {
            status,
            body: ErrorResponse {
                error: ErrorBody {
                    code,
                    message: message.into(),
                },
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(self.body)).into_response()
    }
}

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    use http_body_util::BodyExt;
    use serde_json::json;

    use super::ApiError;

    #[tokio::test]
    async fn serializes_access_denied() {
        assert_error_response(
            ApiError::access_denied(),
            StatusCode::FORBIDDEN,
            json!({"error":{"code":"access_denied","message":"access denied"}}),
        )
        .await;
    }

    #[tokio::test]
    async fn serializes_temporary_lockout() {
        assert_error_response(
            ApiError::temporary_lockout(),
            StatusCode::FORBIDDEN,
            json!({
                "error": {
                    "code": "temporary_lockout",
                    "message": "temporarily locked out after denial"
                }
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn serializes_unlock_failed() {
        assert_error_response(
            ApiError::unlock_failed(),
            StatusCode::FORBIDDEN,
            json!({"error":{"code":"unlock_failed","message":"failed to unlock database"}}),
        )
        .await;
    }

    #[tokio::test]
    async fn serializes_not_found() {
        assert_error_response(
            ApiError::not_found("not found"),
            StatusCode::NOT_FOUND,
            json!({"error":{"code":"not_found","message":"not found"}}),
        )
        .await;
    }

    async fn assert_error_response(
        error: ApiError,
        expected_status: StatusCode,
        expected_body: serde_json::Value,
    ) {
        let response = error.into_response();
        assert_eq!(expected_status, response.status());

        let body = response.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(expected_body, body);
    }
}
