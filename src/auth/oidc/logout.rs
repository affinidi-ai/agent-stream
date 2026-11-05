//! Logout at the provider reaching the dashboard: OpenID Connect Back-Channel
//! Logout 1.0. The provider posts a signed logout token server to server, and
//! the sessions it names end at once.

use std::sync::Arc;

use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{HeaderValue, StatusCode, header::CACHE_CONTROL},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{info, warn};

use super::handlers::OidcState;
use super::tokens::{TokenFailure, verify_logout_token};
use crate::auth::storage::OidcIdentity;

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

fn unavailable() -> Response {
    no_store(StatusCode::SERVICE_UNAVAILABLE, serde_json::json!({ "error": "temporarily_unavailable" }))
}

/// The user whose sessions without a provider binding a logout for `subject`
/// also ends: sessions created by OIDC sign-in before sessions recorded it.
async fn unbound_session_owner(
    oidc: &OidcState,
    subject: Option<&str>,
) -> anyhow::Result<Option<String>> {
    let Some(subject) = subject else {
        return Ok(None);
    };
    let identity = OidcIdentity {
        issuer: oidc.config.issuer.clone(),
        subject: subject.to_string(),
    };
    Ok(oidc
        .storage
        .load_user_by_oidc_identity(&identity)
        .await?
        .map(|user| user.user_id))
}

/// End the sessions a logout token from the provider names. Answers `200`
/// whether or not any matched, since a logout is idempotent and the provider
/// may retry, `400` for a request that does not verify or a logout that could
/// not end every session it names, and `503` when the provider's keys cannot
/// be reached.
/// POST /oidc/backchannel-logout
pub async fn oidc_backchannel_logout(
    State(oidc): State<Arc<OidcState>>,
    form: Result<Form<BackchannelLogoutForm>, FormRejection>,
) -> Response {
    // `detail` can echo the unsigned token header, so it is logged escaped.
    let invalid = |detail: &str| {
        warn!(?detail, "OIDC back-channel logout refused");
        no_store(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "invalid_request" }))
    };
    let Ok(Form(form)) = form else {
        return invalid("the request is not a form");
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
            return unavailable();
        }
    };
    let verified =
        match verify_logout_token(&token, &oidc.config, &oidc.jwks, &metadata.jwks_uri, &oidc.seen_logout_tokens).await
        {
            Ok(verified) => verified,
            Err(TokenFailure::KeysUnavailable(detail)) => {
                warn!(?detail, "OIDC back-channel logout could not be checked: the provider's keys are unavailable");
                return unavailable();
            }
            Err(TokenFailure::Invalid(detail)) => return invalid(&detail),
        };
    let target = verified.target;

    let issuer = &oidc.config.issuer;
    let (unbound_owner, lookup_failed) = match unbound_session_owner(&oidc, target.subject.as_deref()).await {
        Ok(owner) => (owner, false),
        Err(detail) => {
            warn!(%detail, "OIDC back-channel logout could not look up the account's sessions without a binding");
            (None, true)
        }
    };
    let removed = oidc
        .session_manager
        .remove_sessions_where(|session| match &session.oidc {
            Some(binding) => target.matches(issuer, binding),
            None => unbound_owner
                .as_deref()
                .is_some_and(|user_id| user_id == session.user_id),
        })
        .await;
    let user_ids: std::collections::BTreeSet<&str> = removed
        .ended
        .iter()
        .map(|session| session.user_id.as_str())
        .collect();
    info!(ended = removed.ended.len(), failed = removed.failed, user_ids = ?user_ids, by_sid = target.sid.is_some(), "OIDC back-channel logout");
    if removed.failed > 0 || lookup_failed {
        // The provider may send the token again, and that retry must not be
        // refused as a replay.
        oidc.seen_logout_tokens
            .forget(&verified.jti);
        return no_store(StatusCode::BAD_REQUEST, serde_json::json!({ "error": "logout_failed" }));
    }
    no_store(StatusCode::OK, serde_json::json!({}))
}
