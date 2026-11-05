use std::sync::Arc;

use axum::{
    extract::{Query, State},
    http::{
        HeaderMap, HeaderValue, StatusCode,
        header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, REFERRER_POLICY, SET_COOKIE},
    },
    response::{Html, IntoResponse, Redirect, Response},
};
use base64::Engine;
use serde::Deserialize;
use subtle::ConstantTimeEq;
use tracing::{info, warn};
use url::Url;

use super::config::{OidcConfig, TokenEndpointAuthMethod};
use super::discovery::{Discovery, ProviderMetadata};
use super::pending::{PENDING_SIGN_IN_TTL, PendingSignIns};
use super::roles::{mapped_role, unmet_required_claim};
use super::tokens::verify_id_token;
use super::user_provisioning::{ProvisionRefusal, provision_user_from_oidc};
use crate::auth::session::SessionManager;
use crate::auth::session_cookie::{
    OIDC_STATE_COOKIE_NAME, build_oidc_state_cookie, clear_oidc_state_cookie, request_cookie,
};
use crate::auth::session_finalizer::{AuthenticatedPrincipal, SessionFinalizer, SessionManagerFinalizer};
use crate::auth::sign_in_pages::{login_success_page, sign_in_error_page};
use crate::auth::storage::{OidcIdentity, PasskeyStorage, UserData};
use crate::delegation_vault::oauth::{generate_pkce_challenge, generate_pkce_verifier, random_url_token};
use crate::jwt_bearer::JwksClient;

/// The largest token endpoint response accepted.
const MAX_TOKEN_RESPONSE_BYTES: usize = 256 * 1024;

/// Everything OIDC sign-in needs.
pub struct OidcState {
    pub config: Arc<OidcConfig>,
    discovery: Discovery,
    jwks: JwksClient,
    token_client: reqwest::Client,
    pending: PendingSignIns,
    pub storage: Arc<PasskeyStorage>,
    pub session_manager: Arc<SessionManager>,
    pub notification_store: Arc<tokio::sync::RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,
    terms_manager: Arc<crate::terms::TermsManager>,
}

impl OidcState {
    pub fn new(
        config: OidcConfig,
        storage: Arc<PasskeyStorage>,
        session_manager: Arc<SessionManager>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> anyhow::Result<Self> {
        let short = std::time::Duration::from_secs(crate::http_client::SHORT_TIMEOUT_SECS);
        Ok(Self {
            config: Arc::new(config),
            discovery: Discovery::new(crate::http_client::with_service_endpoint_resolver(short)?),
            jwks: JwksClient::new(crate::http_client::with_service_endpoint_resolver(short)?),
            token_client: crate::http_client::with_service_endpoint_resolver(std::time::Duration::from_secs(
                crate::http_client::EXTERNAL_TIMEOUT_SECS,
            ))?,
            pending: PendingSignIns::default(),
            storage,
            session_manager,
            notification_store: Arc::new(tokio::sync::RwLock::new(None)),
            terms_manager,
        })
    }

    /// Fetch the provider's discovery document once at startup, so a problem
    /// with it is in the log before anyone tries to sign in. Sign-in fetches it
    /// again if this attempt fails.
    pub async fn check_provider(&self) {
        match self
            .discovery
            .metadata(&self.config)
            .await
        {
            Ok(_) => info!(issuer = %self.config.issuer, "OIDC sign-in is ready"),
            Err(detail) => warn!(
                issuer = %self.config.issuer,
                %detail,
                "The OpenID provider cannot be used yet; dashboard sign-in will retry it"
            ),
        }
    }
}

/// Why a sign-in was refused. The reason code goes to the log; the browser
/// gets a generic page.
#[derive(Debug)]
enum Refusal {
    StateUnknown,
    BindingMismatch,
    AccessDenied,
    ExchangeFailed,
    IdTokenInvalid,
    ClaimNotAllowed,
    RoleUnmapped,
    UserDisabled,
    UserLimit(crate::config::LimitExceeded),
    OpUnavailable,
    ServerError,
}

impl Refusal {
    fn code(&self) -> &'static str {
        match self {
            Self::StateUnknown => "state_unknown",
            Self::BindingMismatch => "binding_mismatch",
            Self::AccessDenied => "access_denied",
            Self::ExchangeFailed => "exchange_failed",
            Self::IdTokenInvalid => "id_token_invalid",
            Self::ClaimNotAllowed => "claim_not_allowed",
            Self::RoleUnmapped => "role_unmapped",
            Self::UserDisabled => "user_disabled",
            Self::UserLimit(_) => "user_limit",
            Self::OpUnavailable => "op_unavailable",
            Self::ServerError => "server_error",
        }
    }

    /// `401` for a code or ID token that did not verify, so the sign-in
    /// throttle counts it; `400` for an unknown or unbound `state`, which
    /// cannot be guessed and comes from stale or parallel sign-ins; `403` for
    /// an account the policy refuses.
    fn status(&self) -> StatusCode {
        match self {
            Self::StateUnknown | Self::BindingMismatch => StatusCode::BAD_REQUEST,
            Self::ExchangeFailed | Self::IdTokenInvalid => StatusCode::UNAUTHORIZED,
            Self::AccessDenied
            | Self::ClaimNotAllowed
            | Self::RoleUnmapped
            | Self::UserDisabled
            | Self::UserLimit(_) => StatusCode::FORBIDDEN,
            Self::OpUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::ServerError => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    fn message(&self) -> String {
        match self {
            Self::StateUnknown | Self::BindingMismatch => {
                "This sign-in has expired or was started in another browser. Start again from the sign-in page."
                    .to_string()
            }
            Self::AccessDenied => "The identity provider did not complete the sign-in.".to_string(),
            Self::ClaimNotAllowed | Self::RoleUnmapped | Self::UserDisabled => {
                "Your account is not allowed to use this dashboard.".to_string()
            }
            Self::UserLimit(limit) => limit.message(),
            Self::OpUnavailable => "Sign-in is unavailable: the identity provider could not be reached.".to_string(),
            Self::ExchangeFailed | Self::IdTokenInvalid | Self::ServerError => {
                "The sign-in could not be completed.".to_string()
            }
        }
    }
}

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        let mut response = (self.status(), Html(sign_in_error_page(&self.message()))).into_response();
        let headers = response.headers_mut();
        // On a mismatch the cookie belongs to a newer sign-in in this browser,
        // which must still be able to finish.
        if !matches!(self, Self::BindingMismatch)
            && let Ok(clear) = HeaderValue::from_str(&clear_oidc_state_cookie())
        {
            headers.append(SET_COOKIE, clear);
        }
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// Log a refusal with its reason code and what caused it, and return it.
fn refused(
    refusal: Refusal,
    user_id: Option<&str>,
    detail: impl std::fmt::Display,
) -> Refusal {
    warn!(reason = refusal.code(), user_id = user_id.unwrap_or("-"), %detail, "OIDC sign-in refused");
    refusal
}

/// Start an OIDC sign-in: send the browser to the provider with PKCE, a
/// `state` and a `nonce`, bound to this browser by a cookie.
/// GET /oidc/login
pub async fn oidc_login(State(oidc): State<Arc<OidcState>>) -> Response {
    let metadata = match oidc
        .discovery
        .metadata(&oidc.config)
        .await
    {
        Ok(metadata) => metadata,
        Err(detail) => return refused(Refusal::OpUnavailable, None, detail).into_response(),
    };
    let Ok(mut authorization) = Url::parse(&metadata.authorization_endpoint) else {
        return refused(Refusal::OpUnavailable, None, "authorization_endpoint is not a URL").into_response();
    };

    let state = random_url_token();
    let nonce = random_url_token();
    let code_verifier = generate_pkce_verifier();
    authorization
        .query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("client_id", &oidc.config.client_id)
        .append_pair(
            "redirect_uri",
            oidc.config
                .redirect_uri
                .as_str(),
        )
        .append_pair("scope", &oidc.config.scopes.join(" "))
        .append_pair("state", &state)
        .append_pair("nonce", &nonce)
        .append_pair("code_challenge", &generate_pkce_challenge(&code_verifier))
        .append_pair("code_challenge_method", "S256");

    let Ok(cookie) = HeaderValue::from_str(&build_oidc_state_cookie(&state, PENDING_SIGN_IN_TTL.as_secs())) else {
        return refused(Refusal::ServerError, None, "the state cookie could not be built").into_response();
    };
    oidc.pending
        .insert(state, nonce, code_verifier);

    let mut headers = HeaderMap::new();
    headers.insert(SET_COOKIE, cookie);
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    (headers, Redirect::to(authorization.as_str())).into_response()
}

/// What the provider sends the browser back with.
#[derive(Debug, Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
}

/// Finish an OIDC sign-in: check the browser binding, exchange the code,
/// verify the ID token, apply `required_claims` and `role_mapping`, and hand
/// the new session to the dashboard.
/// GET /oidc/callback
pub async fn oidc_callback(
    State(oidc): State<Arc<OidcState>>,
    headers: HeaderMap,
    Query(params): Query<CallbackParams>,
) -> Response {
    match complete_sign_in(&oidc, &headers, params).await {
        Ok(response) => response,
        Err(refusal) => refusal.into_response(),
    }
}

async fn complete_sign_in(
    oidc: &OidcState,
    headers: &HeaderMap,
    params: CallbackParams,
) -> Result<Response, Refusal> {
    let state = params
        .state
        .ok_or_else(|| refused(Refusal::StateUnknown, None, "the callback has no state"))?;
    let bound = request_cookie(headers, OIDC_STATE_COOKIE_NAME).is_some_and(|cookie| {
        cookie
            .as_bytes()
            .ct_eq(state.as_bytes())
            .into()
    });
    if !bound {
        return Err(refused(Refusal::BindingMismatch, None, "the state cookie is missing or names another sign-in"));
    }
    let pending = oidc
        .pending
        .take(&state)
        .ok_or_else(|| refused(Refusal::StateUnknown, None, "no sign-in is waiting for this state"))?;
    if let Some(error) = params.error {
        return Err(refused(Refusal::AccessDenied, None, format!("the provider answered {}", loggable_code(&error))));
    }
    let code = params
        .code
        .ok_or_else(|| refused(Refusal::ExchangeFailed, None, "the callback has no code"))?;

    let metadata = oidc
        .discovery
        .metadata(&oidc.config)
        .await
        .map_err(|detail| refused(Refusal::OpUnavailable, None, detail))?;
    let id_token = match exchange_code(oidc, &metadata, &code, &pending.code_verifier).await {
        Ok(id_token) => id_token,
        Err(failure) => {
            if failure.endpoint_may_have_moved {
                oidc.discovery
                    .mark_stale()
                    .await;
            }
            return Err(refused(Refusal::ExchangeFailed, None, failure.detail));
        }
    };
    let verified = verify_id_token(&id_token, &oidc.config, &oidc.jwks, &metadata.jwks_uri, &pending.nonce)
        .await
        .map_err(|detail| refused(Refusal::IdTokenInvalid, None, detail))?;

    let identity = OidcIdentity {
        issuer: oidc.config.issuer.clone(),
        subject: verified.subject,
    };
    let existing = oidc
        .storage
        .load_user_by_oidc_identity(&identity)
        .await
        .map_err(|e| refused(Refusal::ServerError, None, e))?;
    let existing_id = existing
        .as_ref()
        .map(|user| user.user_id.as_str());

    if let Some(claim) = unmet_required_claim(&verified.claims, &oidc.config.required_claims) {
        end_sessions(oidc, existing.as_ref()).await;
        return Err(refused(Refusal::ClaimNotAllowed, existing_id, format!("required claim {claim} is not met")));
    }
    let Some(role) = mapped_role(&verified.claims, &oidc.config.role_mapping) else {
        end_sessions(oidc, existing.as_ref()).await;
        return Err(refused(Refusal::RoleUnmapped, existing_id, "no value of the role claim is mapped"));
    };

    let provisioned =
        match provision_user_from_oidc(&oidc.storage, identity, &verified.claims, &oidc.config.claims, role.clone())
            .await
        {
            Ok(provisioned) => provisioned,
            Err(ProvisionRefusal::NotApproved) => {
                end_sessions(oidc, existing.as_ref()).await;
                return Err(refused(Refusal::UserDisabled, existing_id, "the user is not approved"));
            }
            Err(ProvisionRefusal::UserLimit(limit)) => {
                return Err(refused(Refusal::UserLimit(limit), None, "the appliance user limit is reached"));
            }
            Err(ProvisionRefusal::UsernameTaken) => {
                return Err(refused(
                    Refusal::ServerError,
                    None,
                    "every username for this account belongs to another user",
                ));
            }
            Err(ProvisionRefusal::Storage(e)) => return Err(refused(Refusal::ServerError, existing_id, e)),
        };
    let user = provisioned.user;
    if provisioned.role_changed {
        end_sessions(oidc, Some(&user)).await;
    }

    let finalized = SessionManagerFinalizer::new(oidc.session_manager.clone(), oidc.terms_manager.clone())
        .finalize_session(AuthenticatedPrincipal::new(user.username.clone(), user.user_id.clone()))
        .await
        .map_err(|e| refused(Refusal::ServerError, Some(&user.user_id), format!("{e:?}")))?;

    if let Some(store) = oidc
        .notification_store
        .read()
        .await
        .clone()
    {
        let user = user.clone();
        crate::observability::spawn_traced_task("integration.user_login", async move {
            crate::integrations::trigger_user_login(store.as_ref(), &user).await;
        });
    }
    info!(user_id = %user.user_id, role = %role, "OIDC sign-in succeeded");

    let (csp, html) = login_success_page(&finalized.session_token);
    let mut response_headers = finalized.headers;
    if let Ok(clear) = HeaderValue::from_str(&clear_oidc_state_cookie()) {
        response_headers.append(SET_COOKIE, clear);
    }
    response_headers.insert(CONTENT_SECURITY_POLICY, csp);
    response_headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response_headers.insert(REFERRER_POLICY, HeaderValue::from_static("no-referrer"));
    Ok((response_headers, Html(html)).into_response())
}

/// End every session of a user whose access a sign-in withdrew or changed, so
/// their other tabs and devices sign in again under the new decision.
async fn end_sessions(
    oidc: &OidcState,
    user: Option<&UserData>,
) {
    if let Some(user) = user {
        let ended = oidc
            .session_manager
            .remove_sessions_for_user(&user.user_id)
            .await;
        if ended > 0 {
            info!(user_id = %user.user_id, ended, "Ended the user's other sessions after an OIDC sign-in");
        }
    }
}

/// An OAuth error code from the provider, reduced to the characters such codes
/// use, so a hostile value cannot forge log lines.
fn loggable_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

#[derive(Debug, Default, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    error: Option<String>,
}

/// Why a code exchange failed. `detail` is for the log and never holds the
/// code, the secret or a token.
struct ExchangeFailure {
    detail: String,
    /// The token endpoint could not be reached, answered `404`, or failed
    /// with a `5xx`: a moved endpoint could explain it, so the discovery
    /// document is fetched again. An OAuth error such as `invalid_grant` is
    /// the caller's fault and leaves the document alone.
    endpoint_may_have_moved: bool,
}

impl ExchangeFailure {
    fn endpoint(detail: String) -> Self {
        Self {
            detail,
            endpoint_may_have_moved: true,
        }
    }

    fn response(detail: String) -> Self {
        Self {
            detail,
            endpoint_may_have_moved: false,
        }
    }
}

/// Whether a token endpoint answer suggests the endpoint itself is wrong
/// rather than the request.
fn endpoint_may_have_moved(status: reqwest::StatusCode) -> bool {
    status == reqwest::StatusCode::NOT_FOUND || status.is_server_error()
}

/// Exchange the authorization code at the token endpoint and return the ID
/// token.
async fn exchange_code(
    oidc: &OidcState,
    metadata: &ProviderMetadata,
    code: &str,
    code_verifier: &str,
) -> Result<String, ExchangeFailure> {
    crate::url_validation::validate_service_endpoint_url(&metadata.token_endpoint)
        .await
        .map_err(|e| ExchangeFailure::endpoint(format!("token endpoint refused: {e}")))?;
    let config = &oidc.config;
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", config.redirect_uri.as_str()),
        ("code_verifier", code_verifier),
    ];
    let mut request = oidc
        .token_client
        .post(&metadata.token_endpoint)
        .header(reqwest::header::ACCEPT, "application/json");
    match config.token_endpoint_auth_method {
        TokenEndpointAuthMethod::ClientSecretBasic => {
            request =
                request.header(AUTHORIZATION, basic_credentials(&config.client_id, config.client_secret.expose()));
        }
        TokenEndpointAuthMethod::ClientSecretPost => {
            form.push(("client_id", &config.client_id));
            form.push(("client_secret", config.client_secret.expose()));
        }
    }
    let response = request
        .form(&form)
        .send()
        .await
        .map_err(|e| ExchangeFailure::endpoint(format!("token request failed: {}", e.without_url())))?;
    let status = response.status();
    let body = crate::http_client::read_capped(response, MAX_TOKEN_RESPONSE_BYTES)
        .await
        .map_err(ExchangeFailure::response)?;
    let parsed: TokenResponse = serde_json::from_slice(&body).unwrap_or_default();
    if !status.is_success() {
        let error = parsed
            .error
            .as_deref()
            .map(loggable_code)
            .unwrap_or_else(|| "no error code".to_string());
        let detail = format!("token endpoint answered HTTP {status} ({error})");
        return Err(if endpoint_may_have_moved(status) {
            ExchangeFailure::endpoint(detail)
        } else {
            ExchangeFailure::response(detail)
        });
    }
    parsed
        .id_token
        .ok_or_else(|| ExchangeFailure::response("the token response has no id_token".to_string()))
}

/// `client_secret_basic` credentials: each part form-encoded, then joined and
/// base64-encoded (RFC 6749 section 2.3.1).
fn basic_credentials(
    client_id: &str,
    client_secret: &str,
) -> String {
    let encode = |value: &str| url::form_urlencoded::byte_serialize(value.as_bytes()).collect::<String>();
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", encode(client_id), encode(client_secret)))
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_form_encode_each_part_first() {
        assert_eq!(basic_credentials("agent-stream", "s3cret"), "Basic YWdlbnQtc3RyZWFtOnMzY3JldA==");
        let encoded = basic_credentials("a:b", "p@ss word");
        let decoded = String::from_utf8(
            base64::engine::general_purpose::STANDARD
                .decode(
                    encoded
                        .strip_prefix("Basic ")
                        .unwrap(),
                )
                .unwrap(),
        )
        .unwrap();
        assert_eq!(decoded, "a%3Ab:p%40ss+word");
    }

    #[test]
    fn a_provider_error_code_is_reduced_before_it_is_logged() {
        assert_eq!(loggable_code("access_denied"), "access_denied");
        assert_eq!(loggable_code("x\nINFO forged line"), "xINFOforgedline");
        assert_eq!(loggable_code(&"a".repeat(200)).len(), 64);
    }

    #[test]
    fn refusals_that_could_be_guessing_count_toward_the_lockout() {
        for refusal in [Refusal::ExchangeFailed, Refusal::IdTokenInvalid] {
            assert_eq!(refusal.status(), StatusCode::UNAUTHORIZED, "{}", refusal.code());
        }
        for refusal in [Refusal::StateUnknown, Refusal::BindingMismatch] {
            assert_eq!(refusal.status(), StatusCode::BAD_REQUEST, "{}", refusal.code());
        }
        for refusal in [Refusal::AccessDenied, Refusal::ClaimNotAllowed, Refusal::RoleUnmapped, Refusal::UserDisabled] {
            assert_eq!(refusal.status(), StatusCode::FORBIDDEN, "{}", refusal.code());
        }
    }

    #[test]
    fn a_refused_account_learns_nothing_about_why() {
        let messages: Vec<String> = [Refusal::ClaimNotAllowed, Refusal::RoleUnmapped, Refusal::UserDisabled]
            .iter()
            .map(Refusal::message)
            .collect();
        assert!(
            messages
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "{messages:?}"
        );
    }
}
