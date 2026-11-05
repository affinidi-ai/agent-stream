//! Logout at the provider reaching the dashboard: OpenID Connect Back-Channel
//! Logout 1.0. The provider posts a signed logout token server to server, and
//! the sessions it names end at once.

use std::sync::Arc;

use axum::{
    Form, Json,
    extract::State,
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{info, warn};

use super::handlers::OidcState;
use super::tokens::verify_logout_token;

/// The largest back-channel logout request accepted.
pub const MAX_BACKCHANNEL_LOGOUT_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
pub struct BackchannelLogoutForm {
    logout_token: Option<String>,
}

fn no_store(
    status: StatusCode,
    body: serde_json::Value,
) -> Response {
    let mut response = (status, Json(body)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// End the sessions a logout token from the provider names. Answers `200`
/// whether or not any matched, since a logout is idempotent and the provider
/// may retry, and `400` for a token that does not verify.
/// POST /oidc/backchannel-logout
pub async fn oidc_backchannel_logout(
    State(oidc): State<Arc<OidcState>>,
    Form(form): Form<BackchannelLogoutForm>,
) -> Response {
    let invalid = |detail: &str| {
        warn!(%detail, "OIDC back-channel logout refused");
        no_store(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid_request" }))
    };
    let Some(token) = form
        .logout_token
        .filter(|token| !token.is_empty())
    else {
        return invalid("the request has no logout_token");
    };
    let metadata = match oidc
        .discovery
        .metadata(&oidc.config)
        .await
    {
        Ok(metadata) => metadata,
        Err(detail) => {
            warn!(%detail, "OIDC back-channel logout could not be checked: the provider is unavailable");
            return no_store(
                StatusCode::SERVICE_UNAVAILABLE,
                serde_json::json!({ "error": "temporarily_unavailable" }),
            );
        }
    };
    let target =
        match verify_logout_token(&token, &oidc.config, &oidc.jwks, &metadata.jwks_uri, &oidc.seen_logout_tokens).await
        {
            Ok(target) => target,
            Err(detail) => return invalid(&detail),
        };

    let issuer = &oidc.config.issuer;
    let ended = oidc
        .session_manager
        .remove_sessions_where(|session| {
            session
                .oidc
                .as_ref()
                .is_some_and(|binding| target.matches(issuer, binding))
        })
        .await;
    let user_ids: std::collections::BTreeSet<&str> = ended
        .iter()
        .map(|session| session.user_id.as_str())
        .collect();
    info!(ended = ended.len(), user_ids = ?user_ids, by_sid = target.sid.is_some(), "OIDC back-channel logout");
    no_store(StatusCode::OK, serde_json::json!({}))
}
