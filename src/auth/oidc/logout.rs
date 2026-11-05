//! Sign-out across the dashboard and the provider. OpenID Connect
//! Back-Channel Logout 1.0: the provider posts a signed logout token server to
//! server, and the sessions it names end at once. RP-Initiated Logout 1.0:
//! signing out of the dashboard gives the browser the provider's sign-out
//! address, so the person is signed out there too.

use std::sync::Arc;

use axum::{
    Form, Json,
    extract::{State, rejection::FormRejection},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{CACHE_CONTROL, SET_COOKIE},
    },
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use url::Url;

use super::handlers::OidcState;
use super::tokens::{TokenFailure, verify_logout_token};
use crate::auth::session::OidcSessionBinding;
use crate::auth::storage::OidcIdentity;
use crate::delegation_vault::oauth::random_url_token;

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
/// not end every session it names, and `503` when the provider or its keys
/// cannot be reached or this instance is not the ready Active one, whose
/// sessions are the live ones.
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
    if !crate::server::mode::is_ready_to_serve() {
        warn!("OIDC back-channel logout refused: this instance is not the ready Active instance");
        return unavailable();
    }
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

/// What a dashboard sign-out answers: the provider's sign-out address, when
/// the browser should go there next.
#[derive(Debug, Serialize)]
pub struct SignOutAnswer {
    #[serde(skip_serializing_if = "Option::is_none")]
    end_session_url: Option<String>,
}

/// End this browser's dashboard session and clear its cookie. When the session
/// came from an OIDC sign-in, `logout.rp_initiated` is on and the provider
/// publishes an `end_session_endpoint`, the answer carries the provider's
/// sign-out address for the dashboard to open. A session that is already gone
/// gets the same answer without it.
/// POST /oidc/logout, and POST /auth/logout in OIDC mode
pub async fn oidc_logout(
    State(oidc): State<Arc<OidcState>>,
    headers: HeaderMap,
) -> Response {
    let session = match crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        Some(token) => {
            let session = oidc
                .session_manager
                .validate_session_record(&token)
                .await;
            oidc.session_manager
                .remove_session(&token)
                .await;
            session
        }
        None => None,
    };
    let binding = session
        .as_ref()
        .and_then(|session| session.oidc.as_ref());
    let end_session_url = match binding {
        Some(binding)
            if oidc
                .config
                .logout
                .rp_initiated =>
        {
            end_session_url(&oidc, binding).await
        }
        _ => None,
    };
    if let Some(session) = &session {
        info!(user_id = %session.user_id, to_provider = end_session_url.is_some(), "OIDC sign-out");
    }

    let mut response = Json(SignOutAnswer { end_session_url }).into_response();
    let headers = response.headers_mut();
    if let Ok(clear) = HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
        headers.insert(SET_COOKIE, clear);
    }
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The provider's `end_session_endpoint` with `id_token_hint` (the session's
/// ID token, which a provider accepts even once expired), `client_id`,
/// `post_logout_redirect_uri` when configured, and a fresh `state`. `None`
/// when the provider has no such endpoint or cannot be reached.
async fn end_session_url(
    oidc: &OidcState,
    binding: &OidcSessionBinding,
) -> Option<String> {
    let metadata = oidc
        .discovery
        .metadata(&oidc.config)
        .await
        .inspect_err(|detail| warn!(%detail, "OIDC sign-out stays local: the provider is unavailable"))
        .ok()?;
    let mut url = Url::parse(
        metadata
            .end_session_endpoint
            .as_deref()?,
    )
    .ok()?;
    {
        let mut query = url.query_pairs_mut();
        if let Some(id_token) = &binding.id_token {
            query.append_pair("id_token_hint", id_token);
        }
        query.append_pair("client_id", &oidc.config.client_id);
        if let Some(post_logout) = &oidc
            .config
            .logout
            .post_logout_redirect_uri
        {
            query.append_pair("post_logout_redirect_uri", post_logout);
        }
        query.append_pair("state", &random_url_token());
    }
    Some(url.into())
}
