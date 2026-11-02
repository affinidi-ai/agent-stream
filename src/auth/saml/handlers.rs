use axum::{
    Form, Json,
    extract::State,
    http::{HeaderMap, StatusCode, header::SET_COOKIE},
    response::{Html, IntoResponse, Redirect, Response},
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info};

use super::service::SamlService;
use super::user_provisioning::provision_user_from_saml;
use crate::auth::session::SessionManager;
use crate::auth::session_cookie::{
    SAML_CORRELATION_COOKIE_NAME, build_saml_correlation_cookie, clear_saml_correlation_cookie,
};
use crate::auth::session_finalizer::{
    AuthenticatedPrincipal, SessionFinalizationError, SessionFinalizer, SessionManagerFinalizer,
};
use crate::auth::storage::PasskeyStorage;

/// Lifetime of the SAML correlation cookie, matching the AuthnRequest TTL.
const SAML_CORRELATION_TTL_SECS: u64 = 5 * 60;

/// Encode a string as a JavaScript string literal safe to embed inside an
/// inline `<script>` element: serde_json covers the JS string context
/// (quotes/escapes `"` and `\`), and escaping `<`, `>`, `&` to `\uXXXX` stops a
/// value containing `</script>` from closing the element (HTML-context XSS).
fn js_string_literal(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// Extract the SAML correlation-cookie value (the outstanding AuthnRequest id)
/// from the request's `Cookie` header, if present. The value is read verbatim;
/// this is sound because the request id is `_<uuid-v4>` (URL-safe, so cookie
/// percent-encoding is a no-op) and is compared against the same raw id echoed
/// back in `Response@InResponseTo`.
fn extract_saml_correlation(headers: &HeaderMap) -> Option<String> {
    let cookie_header = headers
        .get(axum::http::header::COOKIE)?
        .to_str()
        .ok()?;
    cookie_header
        .split(';')
        .find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            if name.trim() == SAML_CORRELATION_COOKIE_NAME {
                Some(value.trim().to_string())
            } else {
                None
            }
        })
}

/// SAML state for authentication
#[derive(Clone)]
pub struct SamlState {
    /// SAML service instance
    pub saml_service: Arc<SamlService>,

    /// Storage for user data
    pub storage: Arc<PasskeyStorage>,

    /// Session manager
    pub session_manager: Arc<SessionManager>,

    /// Path to avatars storage
    pub avatars_storage_path: String,

    /// Optional notification store for sending notifications
    pub notification_store: Arc<tokio::sync::RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,

    /// Terms enforcement for human authentication.
    pub terms_manager: Arc<crate::terms::TermsManager>,
}

/// SAML login request (POST form from Azure AD)
#[derive(Debug, Deserialize)]
pub struct SamlLoginForm {
    #[serde(rename = "SAMLResponse")]
    pub saml_response: String,

    #[serde(rename = "RelayState")]
    #[allow(dead_code)]
    pub relay_state: Option<String>,
}

/// Response for successful SAML login
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SamlLoginResponse {
    pub session_token: String,
    pub user: SamlUserInfo,
}

/// User information from SAML
#[derive(Debug, Serialize)]
#[allow(dead_code)]
pub struct SamlUserInfo {
    pub user_id: String,
    pub username: String,
    pub role: String,
}

/// Initiate SAML login (SP-initiated flow)
/// GET /saml/login
pub async fn saml_login(State(saml_state): State<Arc<SamlState>>) -> Result<Response, StatusCode> {
    info!("Initiating SAML login");

    // Create authentication request
    let (redirect_url, request_id) = saml_state
        .saml_service
        .create_authn_request()
        .map_err(|e| {
            error!("Failed to create SAML authn request: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Bind this browser to the request via a correlation cookie, verified at
    // the ACS, so the response cannot be completed in a different browser.
    let cookie = build_saml_correlation_cookie(&request_id, SAML_CORRELATION_TTL_SECS);
    let mut headers = HeaderMap::new();
    headers.insert(
        SET_COOKIE,
        cookie.parse().map_err(|e| {
            error!("Failed to build SAML correlation cookie: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?,
    );

    // Redirect to IdP, carrying the correlation cookie.
    Ok((headers, Redirect::to(&redirect_url)).into_response())
}

/// Assertion Consumer Service - receives SAML response from Azure AD
/// POST /saml/acs
pub async fn saml_acs(
    State(saml_state): State<Arc<SamlState>>,
    headers: HeaderMap,
    Form(form): Form<SamlLoginForm>,
) -> Result<Response, SessionFinalizationError> {
    info!("Processing SAML response at ACS endpoint");

    // The AuthnRequest id this browser started with (correlation cookie).
    let expected_request_id = extract_saml_correlation(&headers);

    // Validate SAML response and extract assertion
    let assertion = saml_state
        .saml_service
        .validate_response(&form.saml_response, expected_request_id.as_deref())
        .map_err(|e| {
            error!("SAML response validation failed: {}", e);
            StatusCode::UNAUTHORIZED
        })?;

    // Extract user attributes
    let attributes = saml_state
        .saml_service
        .extract_attributes(&assertion)
        .map_err(|e| {
            error!("Failed to extract SAML attributes: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Provision or update user
    let user = match provision_user_from_saml(
        &saml_state.storage,
        &attributes,
        saml_state
            .saml_service
            .config(),
        &saml_state.avatars_storage_path,
    )
    .await
    {
        Ok(user) => user,
        Err(e) => {
            error!("Failed to provision user from SAML: {}", e);
            // Surface an appliance user-limit breach as a readable page (403) rather
            // than a blank 500, since the browser lands here straight from the IdP.
            if let Some(limit) = e.downcast_ref::<crate::config::LimitExceeded>() {
                return Ok(
                    (StatusCode::FORBIDDEN, Html(saml_provisioning_error_page(&limit.message()))).into_response()
                );
            }
            return Err(StatusCode::INTERNAL_SERVER_ERROR.into());
        }
    };

    let finalized_session = SessionManagerFinalizer::new(
        saml_state
            .session_manager
            .clone(),
        saml_state
            .terms_manager
            .clone(),
    )
    .finalize_session(AuthenticatedPrincipal::new(user.username.clone(), user.user_id.clone()))
    .await?;

    // Trigger user.login integration (async, non-blocking)
    let notif_store_guard = saml_state
        .notification_store
        .read()
        .await;
    if let Some(notif_store) = notif_store_guard.as_ref() {
        let notif = notif_store.clone();
        let user_clone = user.clone();
        crate::observability::spawn_traced_task("integration.user_login", async move {
            crate::integrations::trigger_user_login(notif.as_ref(), &user_clone).await;
        });
    }
    drop(notif_store_guard);

    info!("SAML login successful for user: {} (role: {:?})", user.username, user.role);

    tracing::info!("Setting SAML session cookie");

    let (csp, html) = login_success_page(&finalized_session.session_token);

    // Clear the single-use correlation cookie now that login has completed.
    let mut headers = finalized_session.headers;
    if let Ok(clear) = clear_saml_correlation_cookie().parse() {
        headers.append(SET_COOKIE, clear);
    }
    headers.insert(axum::http::header::CONTENT_SECURITY_POLICY, csp);

    Ok((headers, Html(html)).into_response())
}

/// The page that hands a new SAML session to the dashboard and redirects to
/// it, with the policy that lets only its own script run. The token is emitted
/// as a JS string literal safe for an inline `<script>` (see
/// [`js_string_literal`]).
fn login_success_page(session_token: &str) -> (axum::http::HeaderValue, String) {
    let nonce = crate::proxy::security_headers::script_nonce();
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0;url=/">
    <script nonce="{}">
        sessionStorage.setItem('session_token', {});
        window.location.href = '/';
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
</body>
</html>"#,
        nonce,
        js_string_literal(session_token)
    );
    (crate::proxy::security_headers::inline_script_page_csp(&nonce), html)
}

/// Render a minimal, self-contained HTML page shown when SSO provisioning is refused
/// (e.g. the appliance user limit is reached). The message is HTML-escaped.
fn saml_provisioning_error_page(message: &str) -> String {
    let escaped = message
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;");
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Sign-in unavailable</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; color: #1f2937;">
    <h1 style="font-size: 1.25rem;">Sign-in unavailable</h1>
    <p>{escaped}</p>
    <p style="color: #6b7280;">Please contact your administrator, then <a href="/">try again</a>.</p>
</body>
</html>"#
    )
}

/// Serve SAML metadata
/// GET /saml/metadata
pub async fn saml_metadata(State(saml_state): State<Arc<SamlState>>) -> Result<Response, StatusCode> {
    info!("Serving SAML metadata");

    let metadata = saml_state
        .saml_service
        .generate_metadata()
        .map_err(|e| {
            error!("Failed to generate SAML metadata: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    Ok(([(axum::http::header::CONTENT_TYPE, "application/xml")], metadata).into_response())
}

/// SAML logout endpoint
/// POST /saml/logout
pub async fn saml_logout(
    State(saml_state): State<Arc<SamlState>>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    info!("Processing SAML logout");

    if let Some(token) = crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        saml_state
            .session_manager
            .remove_session(&token)
            .await;
        info!("Session deleted");
    }

    let session_cookie =
        match axum::http::header::HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
            Ok(value) => value,
            Err(err) => {
                error!("Failed to serialize session cookie header: {}", err);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let mut response_headers = axum::http::header::HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, session_cookie);

    (response_headers, StatusCode::OK).into_response()
}

/// Check SAML authentication status
/// GET /auth/check
pub async fn saml_check_auth(
    headers: axum::http::HeaderMap,
    axum::Extension(session_manager): axum::Extension<Arc<SessionManager>>,
    axum::Extension(terms_manager): axum::Extension<Arc<crate::terms::TermsManager>>,
) -> Result<Json<serde_json::Value>, Response> {
    let session_token =
        crate::auth_manager::middleware::extract_session_token_from_headers(&headers).ok_or_else(|| {
            tracing::debug!("Auth check: No session token found in Authorization header or cookie");
            StatusCode::UNAUTHORIZED.into_response()
        })?;

    tracing::debug!(
        "Auth check: Validating session token {}...",
        session_token
            .chars()
            .take(8)
            .collect::<String>()
    );

    // Validate session
    match session_manager
        .validate_session_record(&session_token)
        .await
    {
        Some(session) => {
            let consent_required = if session.terms_gate == crate::auth::session::TermsSessionGate::ConsentPending {
                terms_manager
                    .status(&session.user_id, crate::terms::AcceptanceContext::Login)
                    .await
                    .map_err(IntoResponse::into_response)?
                    .consent_required
            } else {
                false
            };
            tracing::info!("Auth check: Session valid for user {} ({})", session.username, session.user_id);
            Ok(Json(serde_json::json!({
                "authenticated": true,
                "username": session.username,
                "user_id": session.user_id,
                "consent_required": consent_required,
                "terms_enabled": terms_manager.is_enabled()
            })))
        }
        None => {
            tracing::warn!(
                "Auth check: Session validation failed for token {}...",
                session_token
                    .chars()
                    .take(8)
                    .collect::<String>()
            );
            Err(StatusCode::UNAUTHORIZED.into_response())
        }
    }
}

/// Generic logout endpoint for SAML (compatible with frontend)
/// POST /auth/logout
pub async fn saml_logout_generic(
    headers: axum::http::HeaderMap,
    axum::Extension(session_manager): axum::Extension<Arc<SessionManager>>,
) -> impl IntoResponse {
    info!("Processing generic SAML logout");

    if let Some(token) = crate::auth_manager::middleware::extract_session_token_from_headers(&headers) {
        session_manager
            .remove_session(&token)
            .await;
        info!("Session removed");
    }

    let session_cookie =
        match axum::http::header::HeaderValue::from_str(&crate::auth::session_cookie::clear_session_cookie()) {
            Ok(value) => value,
            Err(err) => {
                error!("Failed to serialize session cookie header: {}", err);
                return StatusCode::INTERNAL_SERVER_ERROR.into_response();
            }
        };

    let mut response_headers = axum::http::header::HeaderMap::new();
    response_headers.insert(axum::http::header::SET_COOKIE, session_cookie);

    (response_headers, StatusCode::OK).into_response()
}

#[cfg(test)]
mod tests {
    use super::{js_string_literal, login_success_page};

    #[test]
    fn the_login_page_script_carries_the_nonce_its_policy_allows() {
        let (csp, html) = login_success_page("tok\"</script><script>alert(1)</script>");
        let csp = csp.to_str().unwrap();
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap();

        assert!(html.contains(&format!("<script nonce=\"{nonce}\">")), "{html}");
        assert_eq!(
            html.matches("<script")
                .count(),
            1,
            "only the page's own script: {html}"
        );
        assert!(csp.contains(&format!("script-src 'nonce-{nonce}';")), "only the nonce may run script: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert_ne!(login_success_page("tok").0, login_success_page("tok").0, "a fresh nonce per page");
    }

    #[test]
    fn js_string_literal_escapes_script_close_and_quotes() {
        // A benign id round-trips as a quoted literal.
        assert_eq!(js_string_literal("abc-123"), "\"abc-123\"");
        // A value trying to break out of the <script> element is neutralised:
        // no literal "</script>" and no unescaped quote survive.
        let out = js_string_literal("a\"</script><script>alert(1)</script>");
        assert!(!out.contains("</script>"), "must not contain a literal </script>: {out}");
        assert!(!out.contains('<'), "all < escaped: {out}");
        assert!(out.contains("\\u003c"));
        assert!(out.contains("\\\""), "inner quote escaped: {out}");
    }
}
