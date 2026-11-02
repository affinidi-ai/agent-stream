use axum::Json;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use serde::Serialize;

/// Health check response
#[derive(Debug, Serialize)]
pub struct HealthCheckResponse {
    status: String,
}

#[derive(Debug, Serialize)]
pub struct AliveCheckResponse {
    status: String,
}

/// Health check endpoint
///
/// GET /api/v1/health
///
/// Response:
/// ```json
/// {
///   "status": "OK"
/// }
/// ```
pub async fn health_check() -> impl IntoResponse {
    let status = if crate::server::mode::is_ready_to_serve() {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    if status == StatusCode::OK {
        (StatusCode::OK, Json(HealthCheckResponse { status: "OK".to_string() })).into_response()
    } else {
        StatusCode::SERVICE_UNAVAILABLE.into_response()
    }
}

pub async fn alive_check() -> Json<AliveCheckResponse> {
    Json(AliveCheckResponse { status: "OK".to_string() })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::server::mode::{self, ServerMode};

    fn health_status() -> StatusCode {
        tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap()
            .block_on(health_check())
            .into_response()
            .status()
    }

    #[test]
    fn health_reports_readiness_from_the_server_mode() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        mode::set_server_mode(ServerMode::Standby);
        assert_eq!(health_status(), StatusCode::SERVICE_UNAVAILABLE, "standby");

        mode::set_server_mode(ServerMode::Active);
        assert_eq!(health_status(), StatusCode::SERVICE_UNAVAILABLE, "activating");

        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
        assert_eq!(health_status(), StatusCode::OK, "active and ready");

        mode::set_server_mode(ServerMode::Standby);
        assert_eq!(health_status(), StatusCode::SERVICE_UNAVAILABLE, "demoted");

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn alive_response_is_ok() {
        let body = AliveCheckResponse { status: "OK".to_string() };
        assert_eq!(body.status, "OK");
    }
}
