use crate::auth::session::{Session, SessionManager, TermsSessionGate};
use crate::auth::session_cookie;
use crate::auth::storage::PasskeyStorage;
use crate::auth::types::UserStatus;
use crate::storage::filesystem::loggable_id;
use axum::{
    Extension, Json,
    extract::{Request, State},
    http::{Method, StatusCode, header::SET_COOKIE},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{debug, warn};

/// Paths that are exempt from session authentication.
/// These include auth flows, health checks, protocol endpoints, and public resources.
const PUBLIC_EXACT_PATHS: &[&str] = &[
    "/v1/terms/applicable",
    "/api/v1/terms/applicable",
    "/v1/terms/provider-health",
    "/api/v1/terms/provider-health",
    "/auth/register/start",
    "/api/auth/register/start",
    "/auth/register/finish",
    "/api/auth/register/finish",
    "/auth/login/start",
    "/api/auth/login/start",
    "/auth/login/finish",
    "/api/auth/login/finish",
    "/auth/check",
    "/api/auth/check",
    "/auth/logout",
    "/api/auth/logout",
    "/saml/login",
    "/api/saml/login",
    "/saml/acs",
    "/api/saml/acs",
    "/saml/metadata",
    "/api/saml/metadata",
    "/saml/logout",
    "/api/saml/logout",
    "/oidc/login",
    "/api/oidc/login",
    "/oidc/callback",
    "/api/oidc/callback",
    "/oidc/initiate",
    "/api/oidc/initiate",
    "/oidc/backchannel-logout",
    "/api/oidc/backchannel-logout",
    "/v1/auth/mode",
    "/api/v1/auth/mode",
];
const CONSENT_PENDING_PATHS: &[&str] = &[
    "/v1/terms/applicable",
    "/api/v1/terms/applicable",
    "/v1/terms/status",
    "/api/v1/terms/status",
    "/v1/terms/acceptances",
    "/api/v1/terms/acceptances",
    "/auth/check",
    "/api/auth/check",
    "/auth/logout",
    "/api/auth/logout",
    "/saml/logout",
    "/api/saml/logout",
];

/// Public prefixes for endpoints that authenticate on their own terms and take
/// writes: any method passes the session gate.
const PUBLIC_PROTOCOL_PATH_PREFIXES: &[&str] = &[
    "/internal/test-support/",   // Internal UI-test auth bootstrap
    "/didcomm",                  // DIDComm protocol endpoints
    "/onboard/",                 // Agent onboarding (external access)
    "/agents-api/v1/verify-jwt", // JWT verification is read-only and safe to expose
    "/agents-api/v1/onboard",    // Agent onboarding (self-registration)
];

/// Public prefixes for read-only documents, probes and assets: only a `GET` or
/// `HEAD` passes the session gate, so a write that shares one of these
/// prefixes is never public.
const PUBLIC_READ_PATH_PREFIXES: &[&str] = &[
    "/v1/alive",              // Liveness check
    "/v1/health",             // Health check
    "/v1/version",            // Version check
    "/v1/permissions/public", // Public permissions for registration
    "/v1/metrics/prometheus", // Prometheus scraping
    "/.well-known/",          // DID resolution / well-known
    "/connection-points/",    // DID web resolution for connection points
    "/dids/",                 // DID:webvh log serving
    "/ws",                    // WebSocket upgrade (has its own auth handling)
    "/api/ws",                // WebSocket when nested under /api prefix
    "/avatars/",              // Static avatar files
    "/uploads/",              // Static uploaded assets (LLM provider logos, etc.)
    "/surface/",              // DID web resolution for channels (did.json)
    "/v1/resolve",            // DID:webvh resolution (no auth required for DID lookup)
    "/api/v1/resolve",        // Same, when identity API is nested under /api prefix
];

/// Returns true if a request for `path` with `method` is public and should
/// bypass session auth.
fn is_public_path(
    method: &Method,
    path: &str,
) -> bool {
    let has_prefix = |prefixes: &[&str]| {
        prefixes
            .iter()
            .any(|prefix| path.starts_with(prefix))
    };
    PUBLIC_EXACT_PATHS.contains(&path)
        || has_prefix(PUBLIC_PROTOCOL_PATH_PREFIXES)
        || ((method == Method::GET || method == Method::HEAD) && has_prefix(PUBLIC_READ_PATH_PREFIXES))
}

/// Extract session token from the request's Authorization header or cookies.
/// Priority: Authorization Bearer header > `session_token` cookie.
fn extract_session_token(request: &Request) -> Option<String> {
    extract_session_token_from_headers(request.headers())
}

/// Public helper: extract session token from request headers only.
/// Priority: Authorization Bearer header > `session_token` cookie.
///
/// Tokens are deliberately never read from the URL query string: a token in the
/// URL leaks into access logs, `Referer` headers, browser history, and proxy
/// caches. Callers must supply the token via the `Authorization` header or the
/// HttpOnly `session_token` cookie.
pub fn extract_session_token_from_headers(headers: &axum::http::HeaderMap) -> Option<String> {
    // 1. Try Authorization header first (preferred — avoids token leaking into logs/URLs)
    if let Some(auth_header) = headers.get(axum::http::header::AUTHORIZATION)
        && let Ok(auth_str) = auth_header.to_str()
        && let Some(token) = auth_str.strip_prefix("Bearer ")
    {
        let token = token.trim();
        if !token.is_empty() {
            return Some(token.to_string());
        }
    }

    // 2. Fall back to cookie (SAML mode sets HttpOnly session_token cookie)
    if let Some(cookie_header) = headers.get(axum::http::header::COOKIE)
        && let Ok(cookie_str) = cookie_header.to_str()
    {
        for cookie in cookie_str.split(';') {
            let parts: Vec<&str> = cookie
                .trim()
                .splitn(2, '=')
                .collect();
            if parts.len() == 2 && parts[0] == "session_token" && !parts[1].is_empty() {
                return Some(parts[1].to_string());
            }
        }
    }

    None
}

/// Combined state required by the global session-auth middleware.
///
/// Holds the session manager (for token validation) and, when available,
/// the passkey/user storage so the middleware can additionally reject
/// requests whose underlying user account has been disabled or removed.
/// The storage is optional to keep test wiring and minimal deployments
/// simple — when `None`, the status check is skipped.
#[derive(Clone)]
pub struct AuthGuardState {
    pub session_manager: Arc<SessionManager>,
    pub user_storage: Option<Arc<PasskeyStorage>>,
    /// Optional fallback authenticator for management access tokens (PATs).
    /// When set, `require_session_auth` accepts a valid access token as the
    /// bearer in place of an interactive session.
    pub pat_authenticator: Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    pub terms_manager: Arc<crate::terms::TermsManager>,
    pub trusted_tenant_header: Option<Arc<crate::tenancy::TrustedTenantHeader>>,
}

/// Marker inserted by `require_session_auth` after a successful validation
/// so downstream middlewares (`extract_user_id`) can short-circuit and avoid
/// re-running `validate_session` (which also writes to disk) plus the user
/// status lookup on every authenticated request. It also carries the caller's
/// user id, so a handler on a globally session-guarded route can read the caller
/// without a route-scoped `extract_user_id` layer via `Option<Extension<AuthGuardOk>>`.
#[derive(Clone)]
pub struct AuthGuardOk(pub String);

impl AuthGuardState {
    pub fn new(
        session_manager: Arc<SessionManager>,
        user_storage: Option<Arc<PasskeyStorage>>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> Self {
        Self {
            session_manager,
            user_storage,
            pat_authenticator: None,
            terms_manager,
            trusted_tenant_header: None,
        }
    }

    /// Attach a management access-token authenticator so `require_session_auth`
    /// accepts a PAT when no valid session is present.
    pub fn with_pat_authenticator(
        mut self,
        authenticator: Option<Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    ) -> Self {
        self.pat_authenticator = authenticator;
        self
    }

    pub fn with_trusted_tenant_header(
        mut self,
        trusted_tenant_header: Option<Arc<crate::tenancy::TrustedTenantHeader>>,
    ) -> Self {
        self.trusted_tenant_header = trusted_tenant_header;
        self
    }
}

/// Global middleware that requires a valid session for all non-public API routes.
/// Public paths (auth flows, health, DIDComm, onboarding, etc.) are exempt.
/// Must be applied via `axum::middleware::from_fn_with_state(AuthGuardState, require_session_auth)`.
pub async fn require_session_auth(
    State(state): State<AuthGuardState>,
    request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request
        .uri()
        .path()
        .to_string();

    let supplied_session_token = extract_session_token(&request);

    if is_public_path(request.method(), &path) {
        debug!("require_session_auth: public path {}, skipping auth", path);
        return Ok(next.run(request).await);
    }

    let session_token = match supplied_session_token {
        Some(token) => token,
        None => {
            warn!("require_session_auth: no session_token for protected path {}", path);
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
    };

    if let Some(session) = state
        .session_manager
        .validate_session_record(&session_token)
        .await
    {
        let user_id = session.user_id.clone();
        if let Some(storage) = state.user_storage.as_ref()
            && !user_is_approved(storage, &user_id).await
        {
            warn!("require_session_auth: session valid but user_id={} is not Approved — rejecting {}", user_id, path);
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        if session.terms_gate == TermsSessionGate::ConsentPending && !CONSENT_PENDING_PATHS.contains(&path.as_str()) {
            let status = state
                .terms_manager
                .status(&user_id, crate::terms::AcceptanceContext::Login)
                .await
                .map_err(IntoResponse::into_response)?;
            if status.consent_required {
                return Err(terms_required_response());
            }
        }

        debug!("require_session_auth: valid session for {}", path);
        let mut request = request;
        request
            .extensions_mut()
            .insert(AuthGuardOk(user_id));

        let mut response = next.run(request).await;

        // Refresh the session cookie so its Max-Age stays in sync with the
        // sliding server-side expiration.  Without this the browser-side cookie
        // expires at login-time + timeout even though the server keeps extending
        // the session on every request, causing WebSocket reconnection storms.
        if let Ok(value) = session_cookie::build_session_cookie(
            &session_token,
            state
                .session_manager
                .timeout_seconds(),
        )
        .parse()
        {
            response
                .headers_mut()
                .append(SET_COOKIE, value);
        }

        return Ok(response);
    }

    // No valid session — try the bearer as a management access token.
    if let Some(authenticator) = state
        .pat_authenticator
        .as_ref()
        && let Some(principal) = authenticator
            .authenticate(&session_token)
            .await
    {
        // The token is bound to a user whose role is its permission ceiling;
        // reject if that user is no longer Approved.
        if let Some(storage) = state.user_storage.as_ref()
            && !user_is_approved(storage, &principal.user_id).await
        {
            warn!(
                "require_session_auth: access token valid but bound user_id={} is not Approved — rejecting {}",
                principal.user_id, path
            );
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }

        let status = state
            .terms_manager
            .status(&principal.user_id, crate::terms::AcceptanceContext::Login)
            .await
            .map_err(IntoResponse::into_response)?;
        if status.consent_required {
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "code": "TERMS_ACCEPTANCE_REQUIRED",
                    "message": "Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."
                })),
            ).into_response());
        }

        if let Some(selector) = principal
            .resource_scope
            .as_ref()
            .and_then(|scope| scope.tenant_selector())
            && !crate::tenancy::header_derived_tenant_permitted(
                selector,
                state
                    .trusted_tenant_header
                    .as_deref(),
            )
        {
            warn!(
                token_id = %principal.token_id,
                header = %selector.header_name,
                "PAT tenant selector is broad and no trusted edge owns the header"
            );
            return Err(StatusCode::FORBIDDEN.into_response());
        }

        // Resource-scope enforcement. First the header gate (required on every
        // call the token makes); then, when the token carries an ID pattern,
        // confine the request to entities whose ID matches. Any rejection here
        // fails closed.
        let evaluated_scope = if let Some(scope) = principal
            .resource_scope
            .as_ref()
        {
            match scope.evaluate(request.headers()) {
                Ok(effective) => Some(effective),
                Err(rej) => {
                    warn!(
                        "require_session_auth: access token {} rejected on {}: {}",
                        principal.token_id,
                        path,
                        rej.message()
                    );
                    return Err(StatusCode::FORBIDDEN.into_response());
                }
            }
        } else {
            None
        };
        let effective_scope = evaluated_scope
            .as_ref()
            .and_then(|evaluated| evaluated.pattern.clone());
        let tenant_id = evaluated_scope.and_then(|evaluated| evaluated.tenant_id);

        if let Some(regex) = effective_scope.as_ref() {
            use crate::auth_manager::pat::{CanonicalPathScope, classify_canonical_resource_path};
            let is_read = matches!(*request.method(), Method::GET | Method::HEAD | Method::OPTIONS);
            match classify_canonical_resource_path(&path) {
                // By-id / sub-resource route: the identifier must match the
                // token's namespace. Reads answer 404 (no existence disclosure);
                // writes answer 403.
                CanonicalPathScope::EnforceId { kind, id } => {
                    let Some(tenant_id) = tenant_id.as_deref() else {
                        warn!(
                            "require_session_auth: canonical scope for access token {} did not resolve a tenant on {}",
                            principal.token_id, path
                        );
                        return Err(StatusCode::FORBIDDEN.into_response());
                    };
                    let targets = crate::tenancy::canonical_resource_targets(tenant_id, kind, &id);
                    if !targets
                        .iter()
                        .any(|candidate| regex.is_match(candidate))
                    {
                        warn!(
                            "require_session_auth: access token {} denied resource '{}' on {}",
                            principal.token_id, targets[0], path
                        );
                        return Err(if is_read {
                            StatusCode::NOT_FOUND.into_response()
                        } else {
                            StatusCode::FORBIDDEN.into_response()
                        });
                    }
                }
                // Create / list / secrets: the handler enforces against the
                // caller-controlled identifier (or filters a listing).
                CanonicalPathScope::HandlerEnforced => {}
                CanonicalPathScope::DenyScoped => {
                    warn!(
                        "require_session_auth: access token {} blocked unsupported scoped route {}",
                        principal.token_id, path
                    );
                    return Err(if is_read {
                        StatusCode::NOT_FOUND.into_response()
                    } else {
                        StatusCode::FORBIDDEN.into_response()
                    });
                }
                // Anything outside the scoped families: reads are governed by the
                // token's `scopes`; mutations fail closed here so a resource-scoped
                // token can never modify a non-namespaceable entity.
                CanonicalPathScope::Unscoped => {
                    if !is_read {
                        warn!(
                            "require_session_auth: access token {} blocked non-scoped mutation on {}",
                            principal.token_id, path
                        );
                        return Err(StatusCode::FORBIDDEN.into_response());
                    }
                }
            }
        }

        debug!("require_session_auth: valid access token {} for {}", principal.token_id, path);
        let delegation_context = crate::auth_manager::pat::PatDelegationContext {
            token_id: principal.token_id,
            delegation_depth: principal.delegation_depth,
            resource_scoped: principal.resource_scoped,
            scopes: principal.scopes.clone(),
        };
        let tenant_context = tenant_id.map(|tenant_id| crate::tenancy::PatTenantContext {
            token_id: delegation_context
                .token_id
                .clone(),
            tenant_id,
        });
        let mut request = request;
        request
            .extensions_mut()
            .insert(AuthGuardOk(principal.user_id));
        request
            .extensions_mut()
            .insert(crate::auth_manager::pat::PatContext(principal.scopes));
        request
            .extensions_mut()
            .insert(delegation_context);
        if let Some(context) = tenant_context {
            request
                .extensions_mut()
                .insert(context);
        }
        if let Some(regex) = effective_scope {
            request
                .extensions_mut()
                .insert(crate::auth_manager::pat::PatResourceScope(regex));
        }
        return Ok(next.run(request).await);
    }

    warn!("require_session_auth: invalid/expired session for {}", path);
    Err(StatusCode::UNAUTHORIZED.into_response())
}

fn terms_required_response() -> Response {
    (
        StatusCode::FORBIDDEN,
        Json(crate::terms::TermsErrorBody {
            code: "TERMS_ACCEPTANCE_REQUIRED".to_string(),
            required_terms: None,
        }),
    )
        .into_response()
}

/// Middleware that extracts user_id from session token and adds it as an Extension.
///
/// Fast path: if `require_session_auth` has already validated the request and
/// stored an `AuthGuardOk` marker in the extensions, reuse that user_id and skip
/// the (otherwise duplicated) session_manager + user_storage round-trip.
pub async fn extract_user_id(
    Extension(session_manager): Extension<Arc<SessionManager>>,
    Extension(user_storage): Extension<Arc<PasskeyStorage>>,
    mut request: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let user_id = if let Some(AuthGuardOk(id)) = request
        .extensions()
        .get::<AuthGuardOk>()
    {
        id.clone()
    } else {
        // Extract session token using the shared helper (header > cookie)
        let session_token = extract_session_token(&request).ok_or(StatusCode::UNAUTHORIZED)?;

        debug!("extract_user_id Validating session token: {}", loggable_id::<Session>(&session_token));
        let (_username, user_id) = session_manager
            .validate_session(&session_token)
            .await
            .ok_or(StatusCode::UNAUTHORIZED)?;

        // Defense in depth: reject if user is no longer Approved.
        if !user_is_approved(&user_storage, &user_id).await {
            warn!("extract_user_id: session valid but user_id={} is not Approved", user_id);
            return Err(StatusCode::UNAUTHORIZED);
        }
        user_id
    };

    request
        .extensions_mut()
        .insert(user_id);

    Ok(next.run(request).await)
}

/// Returns true when the user record exists and has `UserStatus::Approved`.
/// Any other state (New, Disabled, missing, or storage error) is treated
/// as not approved — the safer choice for an auth gate.
async fn user_is_approved(
    storage: &PasskeyStorage,
    user_id: &str,
) -> bool {
    match storage
        .load_user_by_id(user_id)
        .await
    {
        Ok(Some(u)) => u.status == UserStatus::Approved,
        Ok(None) => {
            warn!("user_is_approved: user_id={} not found in storage", user_id);
            false
        }
        Err(e) => {
            warn!("user_is_approved: failed to load user_id={}: {}", user_id, e);
            false
        }
    }
}

/// Shared state captured by `require_feature` so it can be threaded through
/// `from_fn_with_state` (which requires `Clone + Send + Sync + 'static`).
#[derive(Clone)]
pub struct FeatureGuard {
    pub storage: Arc<PasskeyStorage>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
    pub feature: crate::rbac::Feature,
}

/// Route-level RBAC middleware that enforces a `Feature` permission before the
/// handler runs.
///
/// Mount-time: pass into `MethodRouter::layer(...)`. Returns 401 when the
/// request lacks the `AuthGuardOk` marker (global session guard not applied),
/// 403 when the caller lacks the feature, 500 on storage error.
pub fn require_feature(
    storage: Arc<PasskeyStorage>,
    rbac_config: Arc<crate::rbac::RbacConfig>,
    feature: crate::rbac::Feature,
) -> FeatureGuardLayer {
    axum::middleware::from_fn_with_state(FeatureGuard { storage, rbac_config, feature }, feature_guard_middleware)
}

/// Concrete return type of `require_feature`. Aliased to silence
/// `clippy::type_complexity` and to give callers a stable name.
pub type FeatureGuardLayer = axum::middleware::FromFnLayer<
    fn(
        State<FeatureGuard>,
        Request,
        Next,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>>,
    FeatureGuard,
    (State<FeatureGuard>, Request),
>;

fn feature_guard_middleware(
    State(guard): State<FeatureGuard>,
    mut request: Request,
    next: Next,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Response, StatusCode>> + Send>> {
    Box::pin(async move {
        let user_id = match request
            .extensions()
            .get::<AuthGuardOk>()
        {
            Some(AuthGuardOk(id)) => id.clone(),
            None => {
                warn!(feature = ?guard.feature, "require_feature: no AuthGuardOk on request — global session guard not applied");
                return Err(StatusCode::UNAUTHORIZED);
            }
        };
        match guard
            .storage
            .load_user_by_id(&user_id)
            .await
        {
            Ok(Some(user)) => {
                if !guard
                    .rbac_config
                    .has_permission(&user.role, &guard.feature)
                {
                    warn!(
                        user_id = %user_id,
                        role = ?user.role,
                        feature = ?guard.feature,
                        "require_feature: RBAC rejected — insufficient permissions"
                    );
                    return Err(StatusCode::FORBIDDEN);
                }
            }
            Ok(None) => {
                warn!(user_id = %user_id, feature = ?guard.feature, "require_feature: user not found");
                return Err(StatusCode::FORBIDDEN);
            }
            Err(e) => {
                warn!(user_id = %user_id, feature = ?guard.feature, error = %e, "require_feature: failed to load user");
                return Err(StatusCode::INTERNAL_SERVER_ERROR);
            }
        }

        // A management access token narrows its bound user's role to an explicit
        // permission allow-list; absent (session) or None (unscoped token) means
        // no narrowing.
        if !pat_scope_allows(
            request
                .extensions()
                .get::<crate::auth_manager::pat::PatContext>(),
            &guard.feature,
        ) {
            warn!(feature = ?guard.feature, "require_feature: access token scope excludes this permission");
            return Err(StatusCode::FORBIDDEN);
        }

        request
            .extensions_mut()
            .insert(user_id);
        Ok(next.run(request).await)
    })
}

/// An access token restricted to explicit scopes allows only those scopes;
/// a session or an unrestricted token defers to the caller's role. Exposed
/// crate-wide so handler-local `require()` gates (governance, telemetry,
/// drift, teams, members, prompts, enrolment, spend-report) can honour PAT
/// scope the same way route-level `RbacGuard::gate()` does.
pub(crate) fn pat_scope_allows(
    pat: Option<&crate::auth_manager::pat::PatContext>,
    feature: &crate::rbac::Feature,
) -> bool {
    match pat {
        Some(crate::auth_manager::pat::PatContext(Some(scopes))) => scopes
            .iter()
            .any(|scope| scope == feature.as_str()),
        _ => true,
    }
}

#[cfg(test)]
mod pat_scope_allows_tests {
    use super::pat_scope_allows;
    use crate::auth_manager::pat::PatContext;
    use crate::rbac::Feature;

    #[test]
    fn no_pat_defers_to_role() {
        assert!(pat_scope_allows(None, &Feature::GovernanceView));
    }

    #[test]
    fn unscoped_pat_defers_to_role() {
        let pat = PatContext(None);
        assert!(pat_scope_allows(Some(&pat), &Feature::GovernanceView));
    }

    #[test]
    fn scoped_pat_allows_only_listed_features() {
        let pat = PatContext(Some(vec!["metrics.view".to_string()]));
        assert!(pat_scope_allows(Some(&pat), &Feature::MetricsView));
        assert!(!pat_scope_allows(Some(&pat), &Feature::GovernanceView));
        assert!(!pat_scope_allows(Some(&pat), &Feature::DriftView));
    }

    #[test]
    fn scoped_pat_with_empty_list_allows_nothing() {
        let pat = PatContext(Some(Vec::new()));
        assert!(!pat_scope_allows(Some(&pat), &Feature::MetricsView));
    }
}

/// Packaged storage + RBAC config, built once at orchestrator wiring time and
/// cloned into privileged router factories and route-specific guards.
#[derive(Clone)]
pub struct RbacGuard {
    pub storage: Arc<PasskeyStorage>,
    pub rbac_config: Arc<crate::rbac::RbacConfig>,
}

impl RbacGuard {
    pub fn new(
        storage: Arc<PasskeyStorage>,
        rbac_config: Arc<crate::rbac::RbacConfig>,
    ) -> Self {
        Self { storage, rbac_config }
    }

    /// Wrap a `MethodRouter` with a `require_feature` layer. The handler
    /// signature is unchanged; per-route gating keeps reads ungated.
    pub fn gate<S>(
        &self,
        mr: axum::routing::MethodRouter<S>,
        feature: crate::rbac::Feature,
    ) -> axum::routing::MethodRouter<S>
    where
        S: Clone + Send + Sync + 'static,
    {
        mr.layer(require_feature(self.storage.clone(), self.rbac_config.clone(), feature))
    }

    /// Whether the authenticated user holds `feature`, honouring the scopes of
    /// the access token the request used. An unknown user holds nothing.
    pub async fn allows(
        &self,
        user_id: &str,
        pat: Option<&crate::auth_manager::pat::PatContext>,
        feature: crate::rbac::Feature,
    ) -> anyhow::Result<bool> {
        let Some(user) = self
            .storage
            .load_user_by_id(user_id)
            .await?
        else {
            return Ok(false);
        };
        Ok(self
            .rbac_config
            .has_permission(&user.role, &feature)
            && pat_scope_allows(pat, &feature))
    }
}

/// Helper for mixed public/protected router factories. Production privileged
/// router constructors require `RbacGuard`; `None` is reserved for explicit
/// test-only unprotected composition.
pub fn maybe_gate<S>(
    guard: Option<&RbacGuard>,
    mr: axum::routing::MethodRouter<S>,
    feature: crate::rbac::Feature,
) -> axum::routing::MethodRouter<S>
where
    S: Clone + Send + Sync + 'static,
{
    match guard {
        Some(g) => g.gate(mr, feature),
        None => mr,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, routing::get};
    use http_body_util::BodyExt;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// Dummy handler that returns 200 OK — used to verify middleware behaviour.
    async fn ok_handler() -> &'static str {
        "ok"
    }

    /// Build a minimal router with `require_session_auth` applied globally.
    fn test_app(session_manager: Arc<crate::auth::session::SessionManager>) -> Router {
        Router::new()
            // Protected routes (representative sample)
            .route("/v1/settings", get(ok_handler))
            .route("/v1/surfaces", get(ok_handler))
            .route("/v1/pipes", get(ok_handler))
            .route("/v1/pipes/123", get(ok_handler))
            .route("/v1/pipes/123/test", get(ok_handler))
            .route("/v1/pipes-metrics", get(ok_handler))
            .route("/v1/config/reload", get(ok_handler))
            .route("/v1/config/surface-routing", get(ok_handler))
            .route("/v1/dashboard/stats", get(ok_handler))
            .route("/v1/dashboard/delta", get(ok_handler))
            .route("/v1/dashboard/surface/ch1/ucp-operations", get(ok_handler))
            .route("/v1/dashboard/surface/ch1/metrics", get(ok_handler))
            .route("/v1/gateways", get(ok_handler))
            .route("/v1/gateways/123", get(ok_handler))
            .route("/v1/gateways/refresh-surfaces", get(ok_handler))
            .route("/v1/integrations", get(ok_handler))
            .route("/v1/integrations/config", get(ok_handler))
            .route("/v1/connection-points/123/messages", get(ok_handler))
            .route("/v1/mediators", get(ok_handler))
            .route("/v1/trust-registries", get(ok_handler))
            .route("/v1/notifications", get(ok_handler))
            .route("/v1/users", get(ok_handler))
            .route("/v1/users/u1", get(ok_handler))
            .route("/v1/profile", get(ok_handler))
            .route("/v1/permissions", get(ok_handler))
            .route("/v1/identities", get(ok_handler))
            .route("/v1/identities/id1/policy", get(ok_handler))
            .route("/v1/secrets", get(ok_handler))
            .route("/v1/apikeys", get(ok_handler))
            .route("/v1/certificates", get(ok_handler))
            .route("/v1/marketplace/purchase/m1", get(ok_handler))
            .route("/v1/marketplace/purchased", get(ok_handler))
            .route("/v1/identity/resolve-did", get(ok_handler))
            .route("/v1/identity/resolve-did-document", get(ok_handler))
            .route("/v1/metrics/config", get(ok_handler))
            .route("/v1/agents", get(ok_handler))
            .route("/v1/onboard/create-temp-surface", get(ok_handler))
            .route("/v1/secrets/settings", get(ok_handler))
            .route("/v1/prompt-guard/config", get(ok_handler))
            .route("/agents-api/v1/sign-jwt", get(ok_handler))
            // Public routes
            .route("/auth/register/start", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/auth/check", get(ok_handler))
            .route("/auth/logout", get(ok_handler))
            .route("/auth/admin", get(ok_handler))
            .route("/saml/login", get(ok_handler))
            .route("/saml/acs", get(ok_handler))
            .route("/saml/metadata", get(ok_handler))
            .route("/oidc/login", get(ok_handler))
            .route("/oidc/callback", get(ok_handler))
            .route("/oidc/initiate", get(ok_handler))
            .route("/oidc/backchannel-logout", get(ok_handler))
            .route("/saml/admin", get(ok_handler))
            .route("/v1/auth/mode", get(ok_handler))
            .route("/v1/terms/provider-health", get(ok_handler))
            .route("/v1/alive", get(ok_handler))
            .route("/v1/health", get(ok_handler))
            .route("/v1/version", get(ok_handler))
            .route("/v1/permissions/public", get(ok_handler))
            .route("/v1/metrics/prometheus", get(ok_handler))
            .route("/didcomm", get(ok_handler))
            .route("/didcomm/ws", get(ok_handler))
            .route("/internal/test-support/auth/login", get(ok_handler))
            .route("/onboard/uuid1/rpc", get(ok_handler))
            .route("/agents-api/v1/onboard", get(ok_handler))
            .route("/agents-api/v1/verify-jwt", get(ok_handler))
            .route("/.well-known/did.json", get(ok_handler))
            .route("/connection-points/cp1/did.json", get(ok_handler))
            .route("/dids/something", get(ok_handler))
            .route("/avatars/user.png", get(ok_handler))
            .route("/surface/ch1/did.json", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(session_manager, None, std::sync::Arc::new(crate::terms::TermsManager::disabled())),
                require_session_auth,
            ))
    }

    /// Helper: send a GET request to the given path (no session token).
    async fn get_status(
        app: &Router,
        path: &str,
    ) -> u16 {
        let req = axum::http::Request::builder()
            .uri(path)
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// Helper: send a GET request with a session_token query parameter.
    async fn get_status_with_token(
        app: &Router,
        path: &str,
        token: &str,
    ) -> u16 {
        let sep = if path.contains('?') {
            "&"
        } else {
            "?"
        };
        let uri = format!("{}{sep}session_token={token}", path);
        let req = axum::http::Request::builder()
            .uri(&uri)
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    /// Helper: send a GET request with an Authorization Bearer header.
    async fn get_status_with_bearer(
        app: &Router,
        path: &str,
        token: &str,
    ) -> u16 {
        let req = axum::http::Request::builder()
            .uri(path)
            .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        resp.status().as_u16()
    }

    // ── Protected endpoints must return 401 without a session token ──

    #[tokio::test]
    async fn protected_endpoints_return_401_without_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let protected_paths = [
            "/v1/settings",
            "/v1/surfaces",
            "/v1/pipes",
            "/v1/pipes/123",
            "/v1/pipes/123/test",
            "/v1/pipes-metrics",
            "/v1/config/reload",
            "/v1/config/surface-routing",
            "/v1/dashboard/stats",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/dashboard/surface/ch1/metrics",
            "/v1/gateways",
            "/v1/gateways/123",
            "/v1/gateways/refresh-surfaces",
            "/v1/integrations",
            "/v1/integrations/config",
            "/v1/connection-points/123/messages",
            "/v1/mediators",
            "/v1/trust-registries",
            "/v1/notifications",
            "/v1/users",
            "/v1/users/u1",
            "/v1/profile",
            "/v1/permissions",
            "/v1/identities",
            "/v1/identities/id1/policy",
            "/v1/secrets",
            "/v1/apikeys",
            "/v1/certificates",
            "/v1/marketplace/purchase/m1",
            "/v1/marketplace/purchased",
            "/v1/identity/resolve-did?did=did:web:10.0.0.5",
            "/v1/identity/resolve-did-document?did=did:web:10.0.0.5",
            "/v1/metrics/config",
            "/v1/agents",
            "/v1/onboard/create-temp-surface",
            "/v1/secrets/settings",
            "/v1/prompt-guard/config",
            "/agents-api/v1/sign-jwt",
        ];

        for path in &protected_paths {
            let status = get_status(&app, path).await;
            assert_eq!(status, 401, "Expected 401 for protected path {path} without token, got {status}");
        }
    }

    // ── Protected endpoints must return 401 with an invalid token ──

    #[tokio::test]
    async fn protected_endpoints_return_401_with_invalid_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let sample_paths = [
            "/v1/settings",
            "/v1/pipes",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/integrations/config",
            "/v1/secrets",
        ];

        for path in &sample_paths {
            let status = get_status_with_token(&app, path, "bogus-token-xyz").await;
            assert_eq!(status, 401, "Expected 401 for {path} with invalid token, got {status}");
        }
    }

    // ── A token supplied only via the URL query string must be rejected ──
    // Tokens in the URL leak into access logs, Referer headers, browser
    // history, and proxy caches, so the query-string path is not honoured even
    // when the token is otherwise valid. Tokens must arrive via the
    // Authorization header or the HttpOnly session_token cookie.

    #[tokio::test]
    async fn protected_endpoints_reject_valid_token_in_query_param() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let sample_paths = [
            "/v1/settings",
            "/v1/pipes",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/ch1/ucp-operations",
            "/v1/integrations/config",
            "/v1/secrets",
            "/v1/gateways",
            "/v1/surfaces",
        ];

        for path in &sample_paths {
            let status = get_status_with_token(&app, path, &token).await;
            assert_eq!(
                status, 401,
                "Expected 401 for {path} with valid token supplied only via query param, got {status}"
            );
        }
    }

    #[tokio::test]
    async fn unlisted_auth_and_saml_routes_require_authentication() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        for path in ["/auth/admin", "/saml/admin"] {
            let status = get_status(&app, path).await;
            assert_eq!(status, 401, "Expected 401 for unlisted path {path} without token, got {status}");
        }
    }

    // ── Public endpoints must return 200 without any token ──

    #[tokio::test]
    async fn public_endpoints_return_200_without_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let public_paths = [
            "/auth/register/start",
            "/auth/login/start",
            "/auth/check",
            "/auth/logout",
            "/saml/login",
            "/saml/acs",
            "/saml/metadata",
            "/oidc/login",
            "/oidc/callback",
            "/oidc/initiate",
            "/oidc/backchannel-logout",
            "/v1/auth/mode",
            "/v1/terms/provider-health",
            "/v1/alive",
            "/v1/health",
            "/v1/version",
            "/v1/permissions/public",
            "/v1/metrics/prometheus",
            "/didcomm",
            "/didcomm/ws",
            "/internal/test-support/auth/login",
            "/onboard/uuid1/rpc",
            "/agents-api/v1/onboard",
            "/agents-api/v1/verify-jwt",
            "/.well-known/did.json",
            "/connection-points/cp1/did.json",
            "/dids/something",
            "/avatars/user.png",
            "/surface/ch1/did.json",
        ];

        for path in &public_paths {
            let status = get_status(&app, path).await;
            assert_eq!(status, 200, "Expected 200 for public path {path} without token, got {status}");
        }
    }

    /// A read-only public prefix admits only a `GET` or `HEAD`: a write that
    /// shares the prefix still needs a session. Endpoints that authenticate on
    /// their own (DIDComm, onboarding) keep accepting writes.
    #[tokio::test]
    async fn read_only_public_prefixes_admit_only_reads() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let read_only = [
            "/surface/ch1/did.json",
            "/.well-known/did.json",
            "/connection-points/cp1/did.json",
            "/dids/something",
            "/avatars/user.png",
            "/uploads/logo.png",
            "/v1/health",
            "/v1/resolve",
        ];
        let protocol = ["/didcomm", "/onboard/uuid1/rpc", "/agents-api/v1/onboard"];
        let app = read_only
            .iter()
            .chain(protocol.iter())
            .fold(Router::new(), |router, path| router.route(path, axum::routing::any(ok_handler)))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(sess_mgr, None, std::sync::Arc::new(crate::terms::TermsManager::disabled())),
                require_session_auth,
            ));
        let send = |method: axum::http::Method, path: &str| {
            let app = app.clone();
            let request = axum::http::Request::builder()
                .method(method)
                .uri(path)
                .body(Body::empty())
                .unwrap();
            async move {
                app.oneshot(request)
                    .await
                    .unwrap()
                    .status()
                    .as_u16()
            }
        };

        for path in read_only {
            for method in [axum::http::Method::GET, axum::http::Method::HEAD] {
                assert_eq!(send(method.clone(), path).await, 200, "{method} {path} is a public read");
            }
            for method in [axum::http::Method::POST, axum::http::Method::PUT, axum::http::Method::DELETE] {
                assert_eq!(send(method.clone(), path).await, 401, "{method} {path} without a session must be refused");
            }
        }
        for path in protocol {
            assert_eq!(send(axum::http::Method::POST, path).await, 200, "POST {path} authenticates on its own");
        }
    }

    struct TermsTestPat;

    #[async_trait::async_trait]
    impl crate::auth_manager::pat::PatAuthenticator for TermsTestPat {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<crate::auth_manager::pat::PatPrincipal> {
            (token == "terms-test-pat").then(|| crate::auth_manager::pat::PatPrincipal {
                user_id: "user-1".to_string(),
                scopes: None,
                token_id: "test-token".to_string(),
                delegation_depth: 0,
                resource_scoped: false,
                resource_scope: None,
            })
        }
    }

    fn terms_test_app(
        sessions: Arc<SessionManager>,
        manager: Arc<crate::terms::TermsManager>,
    ) -> Router {
        Router::new()
            .route("/v1/settings", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/saml/acs", get(ok_handler))
            .route("/v1/terms/status", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(sessions, None, manager).with_pat_authenticator(Some(Arc::new(TermsTestPat))),
                require_session_auth,
            ))
    }

    #[tokio::test]
    async fn terms_outage_preserves_allowed_sessions_and_public_routes() {
        let temp = tempfile::tempdir().unwrap();
        std::fs::write(
            temp.path()
                .join("acceptances"),
            b"not a directory",
        )
        .unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(true, "appliance".into(), temp.path().into(), None)
                .await
                .unwrap(),
        );
        let sessions = Arc::new(SessionManager::new());
        let app = terms_test_app(sessions.clone(), manager);
        for (gate, expected) in [
            (TermsSessionGate::AllowedAtLogin, 200),
            (TermsSessionGate::LegacyAllowed, 200),
            (TermsSessionGate::ConsentPending, 503),
        ] {
            let token = sessions
                .create_session_with_terms_gate("alice".into(), "user-1".into(), gate, None)
                .await;
            assert_eq!(get_status_with_bearer(&app, "/v1/settings", &token).await, expected);
            for path in ["/auth/login/start", "/saml/acs", "/v1/terms/status"] {
                assert_eq!(get_status_with_bearer(&app, path, &token).await, 200);
            }
        }
        assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, 503);
        assert_eq!(get_status_with_bearer(&app, "/v1/settings", "invalid").await, 401);
    }

    #[tokio::test]
    async fn human_pat_requires_acceptance_and_reconsent_but_disabled_terms_do_not() {
        use crate::terms::*;
        let temp = tempfile::tempdir().unwrap();
        for (enabled, version, expected) in [(false, "1", 200), (true, "1", 403), (true, "2", 403)] {
            let manager = Arc::new(
                TermsManager::open(
                    enabled,
                    "appliance".into(),
                    temp.path().into(),
                    Some(TermsVersion {
                        terms_type: TermsType::Affinidi,
                        document_id: AFFINIDI_TERMS_DOCUMENT_ID.into(),
                        version_id: version.into(),
                        version: version.into(),
                        title: "Terms".into(),
                        url: "https://example.com/terms".into(),
                        requires_reconsent: true,
                        published_at: chrono::Utc::now(),
                        published_by: None,
                    }),
                )
                .await
                .unwrap(),
            );
            let app = terms_test_app(Arc::new(SessionManager::new()), manager.clone());
            assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, expected);
            if enabled {
                let response = app
                    .clone()
                    .oneshot(
                        axum::http::Request::builder()
                            .uri("/v1/settings")
                            .header(axum::http::header::AUTHORIZATION, "Bearer terms-test-pat")
                            .body(Body::empty())
                            .unwrap(),
                    )
                    .await
                    .unwrap();
                assert_eq!(response.status(), StatusCode::FORBIDDEN);
                let body = response
                    .into_body()
                    .collect()
                    .await
                    .unwrap()
                    .to_bytes();
                assert_eq!(
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
                    serde_json::json!({
                        "code": "TERMS_ACCEPTANCE_REQUIRED",
                        "message": "Sign in to Agent Stream as this access token's owner, accept the required Terms and Conditions, then retry."
                    })
                );
                manager
                    .accept(
                        "user-1",
                        AcceptanceContext::Login,
                        AcceptTermsRequest {
                            accepted_terms: vec![AcceptedTermsVersion {
                                terms_type: TermsType::Affinidi,
                                version_id: version.into(),
                                accepted: true,
                            }],
                        },
                    )
                    .await
                    .unwrap();
                assert_eq!(get_status_with_bearer(&app, "/v1/settings", "terms-test-pat").await, 200);
            }
        }
    }

    #[tokio::test]
    async fn consent_pending_session_is_limited_to_exact_recovery_routes() {
        let temp = tempfile::tempdir().unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(
                true,
                "did:web:stream.example".to_string(),
                temp.path().join("terms"),
                Some(crate::terms::TermsVersion {
                    terms_type: crate::terms::TermsType::Affinidi,
                    document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
                    version_id: "terms-v1".to_string(),
                    version: "1".to_string(),
                    title: "Terms".to_string(),
                    url: "https://example.com/terms".to_string(),
                    requires_reconsent: true,
                    published_at: chrono::Utc::now(),
                    published_by: None,
                }),
            )
            .await
            .unwrap(),
        );
        let sessions = Arc::new(crate::auth::session::SessionManager::new());
        let token = sessions
            .create_session_with_terms_gate(
                "alice".to_string(),
                "user-1".to_string(),
                TermsSessionGate::ConsentPending,
                None,
            )
            .await;
        let app = Router::new()
            .route("/v1/terms/status", get(ok_handler))
            .route("/auth/login/start", get(ok_handler))
            .route("/auth/check", get(ok_handler))
            .route("/auth/logout", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(sessions, None, manager),
                require_session_auth,
            ));

        assert_eq!(get_status_with_bearer(&app, "/v1/terms/status", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/check", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/logout", &token).await, 200);
        assert_eq!(get_status_with_bearer(&app, "/auth/login/start", &token).await, 200);
    }

    // ── Session token via cookie should also work ──

    #[tokio::test]
    async fn protected_endpoint_accepts_session_cookie() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let req = axum::http::Request::builder()
            .uri("/v1/settings")
            .header(axum::http::header::COOKIE, format!("session_token={token}"))
            .body(Body::empty())
            .unwrap();
        let resp = app
            .clone()
            .oneshot(req)
            .await
            .unwrap();
        assert_eq!(resp.status().as_u16(), 200, "Cookie-based session should be accepted");
    }

    // ── Session token via Authorization Bearer header should work ──

    #[tokio::test]
    async fn protected_endpoint_accepts_authorization_bearer() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("test-user".into(), "user-001".into())
            .await;
        let app = test_app(sess_mgr);

        let sample_paths = ["/v1/settings", "/v1/pipes", "/v1/dashboard/delta", "/v1/gateways", "/v1/surfaces"];

        for path in &sample_paths {
            let status = get_status_with_bearer(&app, path, &token).await;
            assert_eq!(status, 200, "Expected 200 for {path} with Bearer token, got {status}");
        }
    }

    #[tokio::test]
    async fn protected_endpoint_rejects_invalid_bearer_token() {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let app = test_app(sess_mgr);

        let status = get_status_with_bearer(&app, "/v1/settings", "bogus-token").await;
        assert_eq!(status, 401, "Expected 401 for invalid Bearer token");
    }

    // ── Status-aware session validation (defense in depth) ──
    // The middleware must reject a request whose session is technically
    // valid but whose underlying user account is no longer Approved
    // (disabled, deleted, or pending re-approval).

    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};

    async fn make_storage_with_user(user: UserData) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage_path = tmp
            .path()
            .join("passkeys")
            .to_string_lossy()
            .to_string();
        let avatars_path = tmp
            .path()
            .join("avatars")
            .to_string_lossy()
            .to_string();
        let storage = PasskeyStorage::new(storage_path, avatars_path)
            .await
            .expect("storage init");
        storage
            .save_user(&user)
            .await
            .expect("save user");
        (Arc::new(storage), tmp)
    }

    fn mk_user_data(
        user_id: &str,
        username: &str,
        status: UserStatus,
    ) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: user_id.to_string(),
            username: username.to_string(),
            passkeys: Vec::new(),
            role: UserRole::User,
            status,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc: None,
        }
    }

    /// Build a router whose `require_session_auth` is wired with both a
    /// session manager and a user storage (the production configuration).
    fn test_app_with_storage(
        session_manager: Arc<crate::auth::session::SessionManager>,
        user_storage: Arc<PasskeyStorage>,
    ) -> Router {
        Router::new()
            .route("/v1/settings", get(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(
                    session_manager,
                    Some(user_storage),
                    std::sync::Arc::new(crate::terms::TermsManager::disabled()),
                ),
                require_session_auth,
            ))
    }

    #[tokio::test]
    async fn require_session_auth_rejects_disabled_user() {
        let user = mk_user_data("user-disabled-1", "alice", UserStatus::Disabled);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("alice".into(), "user-disabled-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "Disabled user must be rejected even with valid session token");
    }

    #[tokio::test]
    async fn require_session_auth_rejects_new_user() {
        let user = mk_user_data("user-new-1", "bob", UserStatus::New);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("bob".into(), "user-new-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "New (pending) user must be rejected");
    }

    #[tokio::test]
    async fn require_session_auth_rejects_missing_user() {
        // Token exists but no UserData was saved — covers the
        // "user deleted while session still cached" race.
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = Arc::new(
            PasskeyStorage::new(
                tmp.path()
                    .join("passkeys")
                    .to_string_lossy()
                    .to_string(),
                tmp.path()
                    .join("avatars")
                    .to_string_lossy()
                    .to_string(),
            )
            .await
            .expect("storage init"),
        );

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("ghost".into(), "user-missing-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 401, "Session for non-existent user must be rejected");
    }

    #[tokio::test]
    async fn require_session_auth_accepts_approved_user() {
        let user = mk_user_data("user-ok-1", "carol", UserStatus::Approved);
        let (storage, _tmp) = make_storage_with_user(user).await;

        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("carol".into(), "user-ok-1".into())
            .await;

        let app = test_app_with_storage(sess_mgr, storage);
        let status = get_status_with_bearer(&app, "/v1/settings", &token).await;
        assert_eq!(status, 200, "Approved user with valid session must pass");
    }

    // ── Feature-guard (RBAC) enforcement ──

    fn mk_user_with_role(
        user_id: &str,
        username: &str,
        role: UserRole,
    ) -> UserData {
        let mut user = mk_user_data(user_id, username, UserStatus::Approved);
        user.role = role;
        user
    }

    fn guard_for(storage: Arc<PasskeyStorage>) -> RbacGuard {
        RbacGuard::new(storage, Arc::new(crate::rbac::RbacConfig::default()))
    }

    /// Router with the global session guard plus a single feature-gated route.
    fn feature_gated_app(
        session_manager: Arc<crate::auth::session::SessionManager>,
        user_storage: Arc<PasskeyStorage>,
        gate: Option<RbacGuard>,
        feature: crate::rbac::Feature,
    ) -> Router {
        Router::new()
            .route("/gated", maybe_gate(gate.as_ref(), get(ok_handler), feature))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(
                    session_manager,
                    Some(user_storage),
                    std::sync::Arc::new(crate::terms::TermsManager::disabled()),
                ),
                require_session_auth,
            ))
    }

    #[tokio::test]
    async fn feature_guard_returns_401_without_session() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-1", "root", UserRole::Administrator)).await;
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let guard = guard_for(storage.clone());

        let app = feature_gated_app(sess_mgr, storage, Some(guard), crate::rbac::Feature::SecretsEdit);
        let status = get_status(&app, "/gated").await;
        assert_eq!(status, 401, "Gated route must 401 without a session");
    }

    #[tokio::test]
    async fn feature_guard_denies_insufficient_role() {
        let (storage, _tmp) = make_storage_with_user(mk_user_with_role("user-1", "alice", UserRole::User)).await;
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("alice".into(), "user-1".into())
            .await;
        let guard = guard_for(storage.clone());

        let app = feature_gated_app(sess_mgr, storage, Some(guard), crate::rbac::Feature::SecretsEdit);
        let status = get_status_with_bearer(&app, "/gated", &token).await;
        assert_eq!(status, 403, "User must be denied an administrator-only feature");
    }

    #[tokio::test]
    async fn feature_guard_allows_sufficient_role() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-2", "root", UserRole::Administrator)).await;
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("root".into(), "admin-2".into())
            .await;
        let guard = guard_for(storage.clone());

        let app = feature_gated_app(sess_mgr, storage, Some(guard), crate::rbac::Feature::SecretsEdit);
        let status = get_status_with_bearer(&app, "/gated", &token).await;
        assert_eq!(status, 200, "Administrator must pass the gate");
    }

    #[tokio::test]
    async fn feature_guard_keeps_pipes_user_accessible() {
        let (storage, _tmp) = make_storage_with_user(mk_user_with_role("user-2", "alice", UserRole::User)).await;
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("alice".into(), "user-2".into())
            .await;
        let guard = guard_for(storage.clone());

        let app = feature_gated_app(sess_mgr, storage, Some(guard), crate::rbac::Feature::PipesEdit);
        let status = get_status_with_bearer(&app, "/gated", &token).await;
        assert_eq!(status, 200, "User must keep pipes.edit access (pipes are the pivot)");
    }

    #[tokio::test]
    async fn feature_guard_audit_view_requires_administrator() {
        let (storage_user, _t1) =
            make_storage_with_user(mk_user_with_role("user-audit", "alice", UserRole::User)).await;
        let (storage_admin, _t2) =
            make_storage_with_user(mk_user_with_role("admin-audit", "root", UserRole::Administrator)).await;

        let sess_user = Arc::new(crate::auth::session::SessionManager::new());
        let user_token = sess_user
            .create_session("alice".into(), "user-audit".into())
            .await;
        let app_user = feature_gated_app(
            sess_user,
            storage_user.clone(),
            Some(guard_for(storage_user)),
            crate::rbac::Feature::AuditView,
        );
        assert_eq!(
            get_status_with_bearer(&app_user, "/gated", &user_token).await,
            403,
            "User must be denied audit.view"
        );

        let sess_admin = Arc::new(crate::auth::session::SessionManager::new());
        let admin_token = sess_admin
            .create_session("root".into(), "admin-audit".into())
            .await;
        let app_admin = feature_gated_app(
            sess_admin,
            storage_admin.clone(),
            Some(guard_for(storage_admin)),
            crate::rbac::Feature::AuditView,
        );
        assert_eq!(
            get_status_with_bearer(&app_admin, "/gated", &admin_token).await,
            200,
            "Administrator must pass audit.view"
        );
    }

    #[tokio::test]
    async fn feature_guard_connection_points_require_poweruser() {
        let (storage_user, _t1) = make_storage_with_user(mk_user_with_role("user-3", "alice", UserRole::User)).await;
        let (storage_power, _t2) =
            make_storage_with_user(mk_user_with_role("power-1", "pete", UserRole::PowerUser)).await;

        let sess_user = Arc::new(crate::auth::session::SessionManager::new());
        let user_token = sess_user
            .create_session("alice".into(), "user-3".into())
            .await;
        let app_user = feature_gated_app(
            sess_user,
            storage_user.clone(),
            Some(guard_for(storage_user)),
            crate::rbac::Feature::ConnectionPointsEdit,
        );
        assert_eq!(
            get_status_with_bearer(&app_user, "/gated", &user_token).await,
            403,
            "User must be denied connection_points.edit"
        );

        let sess_power = Arc::new(crate::auth::session::SessionManager::new());
        let power_token = sess_power
            .create_session("pete".into(), "power-1".into())
            .await;
        let app_power = feature_gated_app(
            sess_power,
            storage_power.clone(),
            Some(guard_for(storage_power)),
            crate::rbac::Feature::ConnectionPointsEdit,
        );
        assert_eq!(
            get_status_with_bearer(&app_power, "/gated", &power_token).await,
            200,
            "PowerUser must pass connection_points.edit"
        );
    }

    #[tokio::test]
    async fn maybe_gate_none_skips_enforcement() {
        let (storage, _tmp) = make_storage_with_user(mk_user_with_role("user-4", "alice", UserRole::User)).await;
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let token = sess_mgr
            .create_session("alice".into(), "user-4".into())
            .await;

        let app = feature_gated_app(sess_mgr, storage, None, crate::rbac::Feature::SecretsEdit);
        let status = get_status_with_bearer(&app, "/gated", &token).await;
        assert_eq!(status, 200, "maybe_gate(None) must not enforce any feature");
    }

    #[tokio::test]
    async fn feature_guard_fails_closed_without_auth_marker() {
        // require_feature applied WITHOUT the global session guard: no
        // AuthGuardOk marker is present, so the guard must fail closed (401).
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-3", "root", UserRole::Administrator)).await;
        let guard = guard_for(storage);
        let app =
            Router::new().route("/gated", maybe_gate(Some(&guard), get(ok_handler), crate::rbac::Feature::SecretsEdit));
        let status = get_status(&app, "/gated").await;
        assert_eq!(status, 401, "Feature guard must 401 when no AuthGuardOk marker is present");
    }

    // ── Management access-token (PAT) authentication ──

    struct MockPat {
        token: String,
        user_id: String,
        scopes: Option<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::auth_manager::pat::PatAuthenticator for MockPat {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<crate::auth_manager::pat::PatPrincipal> {
            (token == self.token).then(|| crate::auth_manager::pat::PatPrincipal {
                user_id: self.user_id.clone(),
                scopes: self.scopes.clone(),
                token_id: "tok-test".into(),
                delegation_depth: 0,
                resource_scoped: false,
                resource_scope: None,
            })
        }
    }

    /// Router with a feature-gated route whose auth guard accepts a PAT (no
    /// interactive session is created, so the bearer resolves via the token).
    fn pat_gated_app(
        user_storage: Arc<PasskeyStorage>,
        gate: RbacGuard,
        feature: crate::rbac::Feature,
        authenticator: Arc<dyn crate::auth_manager::pat::PatAuthenticator>,
    ) -> Router {
        pat_gated_app_with_terms(
            user_storage,
            gate,
            feature,
            authenticator,
            Arc::new(crate::terms::TermsManager::disabled()),
        )
    }

    fn pat_gated_app_with_terms(
        user_storage: Arc<PasskeyStorage>,
        gate: RbacGuard,
        feature: crate::rbac::Feature,
        authenticator: Arc<dyn crate::auth_manager::pat::PatAuthenticator>,
        terms_manager: Arc<crate::terms::TermsManager>,
    ) -> Router {
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        let auth_state = AuthGuardState::new(sess_mgr, Some(user_storage), terms_manager)
            .with_pat_authenticator(Some(authenticator));
        Router::new()
            .route("/gated", gate.gate(get(ok_handler), feature))
            .layer(axum::middleware::from_fn_with_state(auth_state, require_session_auth))
    }

    #[tokio::test]
    async fn access_token_authenticates_without_session() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let guard = guard_for(storage.clone());
        let authenticator = Arc::new(MockPat {
            token: "aspat_live".into(),
            user_id: "admin-pat".into(),
            scopes: None,
        });

        let app = pat_gated_app(storage, guard, crate::rbac::Feature::SecretsEdit, authenticator);
        let status = get_status_with_bearer(&app, "/gated", "aspat_live").await;
        assert_eq!(status, 200, "Unscoped access token bound to an admin must pass an admin-only gate");
    }

    #[tokio::test]
    async fn access_token_scope_narrows_below_role() {
        // Bound to an admin (full role) but scoped to pipes.edit only.
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let scoped = || -> Arc<dyn crate::auth_manager::pat::PatAuthenticator> {
            Arc::new(MockPat {
                token: "aspat_scoped".into(),
                user_id: "admin-pat".into(),
                scopes: Some(vec!["pipes.edit".into()]),
            })
        };

        let allowed =
            pat_gated_app(storage.clone(), guard_for(storage.clone()), crate::rbac::Feature::PipesEdit, scoped());
        assert_eq!(
            get_status_with_bearer(&allowed, "/gated", "aspat_scoped").await,
            200,
            "A pipes.edit-scoped token must reach a pipes.edit gate"
        );

        let denied = pat_gated_app(storage.clone(), guard_for(storage), crate::rbac::Feature::SecretsEdit, scoped());
        assert_eq!(
            get_status_with_bearer(&denied, "/gated", "aspat_scoped").await,
            403,
            "The same token must be denied a permission outside its scope, despite the admin ceiling"
        );
    }

    #[tokio::test]
    async fn access_token_metrics_view_scope_gates_the_metrics_boundary() {
        // Positive/negative coverage for the authorization boundary this MR adds:
        // the pipes-metrics route is gated on Feature::MetricsView, so a PAT scoped
        // to exactly metrics.view must reach it, and a PAT without that scope must
        // be denied it (403).
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;

        let with_scope = Arc::new(MockPat {
            token: "aspat_metrics".into(),
            user_id: "admin-pat".into(),
            scopes: Some(vec!["metrics.view".into()]),
        });
        let allowed =
            pat_gated_app(storage.clone(), guard_for(storage.clone()), crate::rbac::Feature::MetricsView, with_scope);
        assert_eq!(
            get_status_with_bearer(&allowed, "/gated", "aspat_metrics").await,
            200,
            "A metrics.view-scoped token must reach the metrics.view gate"
        );

        let without_scope = Arc::new(MockPat {
            token: "aspat_no_metrics".into(),
            user_id: "admin-pat".into(),
            scopes: Some(vec!["pipes.edit".into()]),
        });
        let denied =
            pat_gated_app(storage.clone(), guard_for(storage), crate::rbac::Feature::MetricsView, without_scope);
        assert_eq!(
            get_status_with_bearer(&denied, "/gated", "aspat_no_metrics").await,
            403,
            "A token without metrics.view must be denied the metrics.view gate"
        );
    }

    #[tokio::test]
    async fn access_token_scope_cannot_exceed_role_ceiling() {
        // Bound to a plain User but scoped to an admin-only permission: the
        // bound role is the ceiling, so the scope cannot grant it.
        let (storage, _tmp) = make_storage_with_user(mk_user_with_role("user-pat", "alice", UserRole::User)).await;
        let guard = guard_for(storage.clone());
        let authenticator = Arc::new(MockPat {
            token: "aspat_overreach".into(),
            user_id: "user-pat".into(),
            scopes: Some(vec!["secrets.edit".into()]),
        });

        let app = pat_gated_app(storage, guard, crate::rbac::Feature::SecretsEdit, authenticator);
        assert_eq!(
            get_status_with_bearer(&app, "/gated", "aspat_overreach").await,
            403,
            "A token bound to a User cannot exercise an admin-only permission even if scoped to it"
        );
    }

    #[tokio::test]
    async fn access_token_bound_to_disabled_user_is_rejected() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_data("user-disabled-pat", "alice", UserStatus::Disabled)).await;
        let guard = guard_for(storage.clone());
        let authenticator = Arc::new(MockPat {
            token: "aspat_disabled".into(),
            user_id: "user-disabled-pat".into(),
            scopes: None,
        });

        let app = pat_gated_app(storage, guard, crate::rbac::Feature::PipesView, authenticator);
        assert_eq!(
            get_status_with_bearer(&app, "/gated", "aspat_disabled").await,
            401,
            "A token bound to a disabled user must be rejected"
        );
    }

    #[tokio::test]
    async fn access_token_follows_its_human_owners_terms_status() {
        let (storage, _storage_tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let terms_tmp = tempfile::tempdir().unwrap();
        let manager = Arc::new(
            crate::terms::TermsManager::open(
                true,
                "did:web:stream.example".to_string(),
                terms_tmp.path().join("terms"),
                Some(crate::terms::TermsVersion {
                    terms_type: crate::terms::TermsType::Affinidi,
                    document_id: crate::terms::AFFINIDI_TERMS_DOCUMENT_ID.to_string(),
                    version_id: "terms-v1".to_string(),
                    version: "1".to_string(),
                    title: "Terms".to_string(),
                    url: "https://example.com/terms".to_string(),
                    requires_reconsent: true,
                    published_at: chrono::Utc::now(),
                    published_by: None,
                }),
            )
            .await
            .unwrap(),
        );
        let authenticator = || -> Arc<dyn crate::auth_manager::pat::PatAuthenticator> {
            Arc::new(MockPat {
                token: "aspat_live".into(),
                user_id: "admin-pat".into(),
                scopes: None,
            })
        };

        let blocked = pat_gated_app_with_terms(
            storage.clone(),
            guard_for(storage.clone()),
            crate::rbac::Feature::PipesView,
            authenticator(),
            manager.clone(),
        );
        assert_eq!(get_status_with_bearer(&blocked, "/gated", "aspat_live").await, 403);

        let status = manager
            .status("admin-pat", crate::terms::AcceptanceContext::Login)
            .await
            .unwrap();
        manager
            .accept(
                "admin-pat",
                crate::terms::AcceptanceContext::Login,
                crate::terms::AcceptTermsRequest {
                    accepted_terms: status
                        .required_terms
                        .into_iter()
                        .map(|term| crate::terms::AcceptedTermsVersion {
                            terms_type: term.terms_type,
                            version_id: term.version_id,
                            accepted: true,
                        })
                        .collect(),
                },
            )
            .await
            .unwrap();

        let allowed = pat_gated_app_with_terms(
            storage.clone(),
            guard_for(storage),
            crate::rbac::Feature::PipesView,
            authenticator(),
            manager,
        );
        assert_eq!(get_status_with_bearer(&allowed, "/gated", "aspat_live").await, 200);
    }

    #[tokio::test]
    async fn unknown_access_token_is_unauthorized() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let guard = guard_for(storage.clone());
        let authenticator = Arc::new(MockPat {
            token: "aspat_live".into(),
            user_id: "admin-pat".into(),
            scopes: None,
        });

        let app = pat_gated_app(storage, guard, crate::rbac::Feature::SecretsEdit, authenticator);
        assert_eq!(
            get_status_with_bearer(&app, "/gated", "aspat_wrong").await,
            401,
            "An unrecognised bearer (no session, no matching token) must be 401"
        );
    }

    // ── Resource-scope patterns + required-header interpolation ──

    use crate::auth_manager::resource_scope::{self, RequiredHeader};

    struct ScopedMockPat {
        scope: Arc<crate::auth_manager::resource_scope::CompiledCanonicalResourceScope>,
    }

    #[async_trait::async_trait]
    impl crate::auth_manager::pat::PatAuthenticator for ScopedMockPat {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<crate::auth_manager::pat::PatPrincipal> {
            (token == "aspat_scoped").then(|| crate::auth_manager::pat::PatPrincipal {
                user_id: "admin-pat".into(),
                scopes: None,
                token_id: "tok-scoped".into(),
                delegation_depth: 0,
                resource_scoped: true,
                resource_scope: Some(self.scope.clone()),
            })
        }
    }

    fn rh(
        name: &str,
        pattern: &str,
    ) -> RequiredHeader {
        RequiredHeader {
            name: name.into(),
            pattern: pattern.into(),
        }
    }

    /// App whose global auth layer authenticates a single resource-scoped PAT,
    /// with representative entity routes across the scoped families.
    fn scoped_app(
        user_storage: Arc<PasskeyStorage>,
        pattern: Option<&str>,
        headers: Vec<RequiredHeader>,
    ) -> Router {
        scoped_app_with_trusted_tenant_header(user_storage, pattern, headers, None)
    }

    fn scoped_app_with_trusted_tenant_header(
        user_storage: Arc<PasskeyStorage>,
        pattern: Option<&str>,
        headers: Vec<RequiredHeader>,
        trusted_tenant_header: Option<crate::tenancy::TrustedTenantHeader>,
    ) -> Router {
        let scope = Arc::new(resource_scope::compile_canonical(pattern, &headers).unwrap());
        let authenticator: Arc<dyn crate::auth_manager::pat::PatAuthenticator> = Arc::new(ScopedMockPat { scope });
        let sess_mgr = Arc::new(crate::auth::session::SessionManager::new());
        Router::new()
            .route("/v1/pipes", get(ok_handler).post(ok_handler))
            .route(
                "/v1/pipes/{id}",
                get(ok_handler)
                    .put(ok_handler)
                    .delete(ok_handler),
            )
            .route("/v1/pipes/{id}/execute", axum::routing::post(ok_handler))
            .route("/api/v1/secrets/{id}", axum::routing::delete(ok_handler))
            .route("/v1/gateways", axum::routing::post(ok_handler))
            .route("/v1/settings", axum::routing::post(ok_handler))
            .route("/api/v1/drift/verdict", get(ok_handler))
            .route("/api/v1/drift/baseline", get(ok_handler).post(ok_handler))
            .route("/api/v1/drift/eval/run", axum::routing::post(ok_handler))
            .route("/api/v1/drift/purge", axum::routing::post(ok_handler))
            .layer(axum::middleware::from_fn_with_state(
                AuthGuardState::new(
                    sess_mgr,
                    Some(user_storage),
                    std::sync::Arc::new(crate::terms::TermsManager::disabled()),
                )
                .with_pat_authenticator(Some(authenticator))
                .with_trusted_tenant_header(trusted_tenant_header.map(Arc::new)),
                require_session_auth,
            ))
    }

    async fn scoped_status(
        app: &Router,
        method: Method,
        path: &str,
        headers: &[(&str, &str)],
    ) -> u16 {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header(axum::http::header::AUTHORIZATION, "Bearer aspat_scoped");
        for (k, v) in headers {
            builder = builder.header(*k, *v);
        }
        let resp = app
            .clone()
            .oneshot(
                builder
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        resp.status().as_u16()
    }

    #[tokio::test]
    async fn resource_scope_allows_matching_id_and_denies_others() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:chat-.*"),
            vec![rh("x-external-account", "123456789012")],
        );
        let acct = &[("x-external-account", "123456789012")];

        assert_eq!(
            scoped_status(&app, Method::GET, "/v1/pipes/chat-primary", acct).await,
            200,
            "matching id in-namespace must reach the handler"
        );
        assert_eq!(
            scoped_status(&app, Method::GET, "/v1/pipes/other", acct).await,
            404,
            "reading another account's namespace must 404 (no existence disclosure)"
        );
        assert_eq!(
            scoped_status(&app, Method::PUT, "/v1/pipes/other", acct).await,
            403,
            "writing another account's namespace must 403"
        );
        assert_eq!(
            scoped_status(&app, Method::POST, "/v1/pipes/other/execute", acct).await,
            403,
            "executing another account's surface must 403 (sub-resource enforces the parent id)"
        );
    }

    #[tokio::test]
    async fn resource_scope_requires_valid_header_on_every_call() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", "123456789012")],
        );

        assert_eq!(
            scoped_status(&app, Method::GET, "/v1/pipes/chat", &[]).await,
            403,
            "missing required header must reject even an otherwise-matching id"
        );
        assert_eq!(
            scoped_status(&app, Method::GET, "/v1/pipes/chat", &[("x-external-account", "abc")]).await,
            403,
            "an invalid header value must reject"
        );
    }

    #[tokio::test]
    async fn resource_scope_backstop_denies_non_family_mutation() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", "123456789012")],
        );
        let acct = &[("x-external-account", "123456789012")];

        assert_eq!(
            scoped_status(&app, Method::POST, "/v1/settings", acct).await,
            403,
            "a resource-scoped token cannot mutate a non-namespaceable entity"
        );
    }

    /// The bug this whole change exists for, at the layer it happened.
    ///
    /// `drift` names no resource family, so every `/v1/drift/*` path used to
    /// classify as `Unscoped` — and that arm refuses **every** non-GET from a
    /// resource-scoped token, before scopes or the pattern are consulted. A
    /// tenant-scoped control-plane token could therefore read a drift verdict
    /// and never pin a baseline or start a replay, whatever it had been
    /// granted. The reads working is what made it look like a permissions
    /// problem rather than a routing one.
    ///
    /// Note the pattern below admits only `pipes:` — drift must pass the
    /// middleware on the strength of being handler-enforced, not because the
    /// caller's pattern happens to mention it. The handler then authorizes the
    /// surface it is given (`authorize_surface_scope`).
    #[tokio::test]
    async fn resource_scope_lets_drift_writes_reach_their_handler() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", "123456789012")],
        );
        let acct = &[("x-external-account", "123456789012")];

        assert_eq!(
            scoped_status(&app, Method::GET, "/api/v1/drift/verdict", acct).await,
            200,
            "drift reads must keep working"
        );
        assert_eq!(
            scoped_status(&app, Method::POST, "/api/v1/drift/baseline", acct).await,
            200,
            "pinning a baseline must reach the handler — this was the 403"
        );
        assert_eq!(
            scoped_status(&app, Method::POST, "/api/v1/drift/eval/run", acct).await,
            200,
            "starting a replay must reach the handler — this was the 403"
        );
    }

    /// A drift route nobody has classified stays refused, so adding one without
    /// looking at whether its handler authorizes anything cannot open a hole.
    #[tokio::test]
    async fn an_unclassified_drift_route_is_still_refused() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", "123456789012")],
        );
        let acct = &[("x-external-account", "123456789012")];

        assert_eq!(
            scoped_status(&app, Method::POST, "/api/v1/drift/purge", acct).await,
            403,
            "an unlisted drift route must fail closed for a scoped token"
        );
    }

    #[tokio::test]
    async fn resource_scope_passes_creates_and_secrets_to_handler() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", "123456789012")],
        );
        let acct = &[("x-external-account", "123456789012")];

        assert_eq!(
            scoped_status(&app, Method::POST, "/v1/pipes", acct).await,
            200,
            "a collection create is handler-enforced and must pass the middleware"
        );
        assert_eq!(
            scoped_status(&app, Method::DELETE, "/api/v1/secrets/any-uuid", acct).await,
            200,
            "secrets are handler-enforced (UUID path) and must pass the middleware"
        );
    }

    #[tokio::test]
    async fn header_gate_without_pattern_still_enforced() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        // Header required but no ID pattern: the header gate applies to every
        // call, while non-family routes are otherwise unrestricted.
        let app = scoped_app(storage, None, vec![rh("x-external-account", r"\d{12}")]);

        assert_eq!(
            scoped_status(&app, Method::POST, "/v1/gateways", &[("x-external-account", "123456789012")]).await,
            200,
            "valid header, no pattern ⇒ request proceeds"
        );
        assert_eq!(
            scoped_status(&app, Method::POST, "/v1/gateways", &[]).await,
            403,
            "missing required header ⇒ rejected even without an ID pattern"
        );
    }

    #[tokio::test]
    async fn broad_tenant_selector_fails_closed_without_trusted_edge() {
        let (storage, _tmp) =
            make_storage_with_user(mk_user_with_role("admin-pat", "root", UserRole::Administrator)).await;
        let app = scoped_app(
            storage.clone(),
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", r"[a-z0-9-]+")],
        );
        assert_eq!(
            scoped_status(&app, Method::GET, "/v1/pipes/chat", &[("x-external-account", "tenant-a")]).await,
            403
        );

        let trusted = scoped_app_with_trusted_tenant_header(
            storage,
            Some("TENANT:${x-external-account}:pipes:.*"),
            vec![rh("x-external-account", r"[a-z0-9-]+")],
            Some(crate::tenancy::TrustedTenantHeader {
                header: "x-external-account".into(),
                edge_strips_client_values: true,
            }),
        );
        assert_eq!(
            scoped_status(&trusted, Method::GET, "/v1/pipes/chat", &[("x-external-account", "tenant-a")]).await,
            200
        );
    }
}
