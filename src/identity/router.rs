use axum::{
    Extension, Router,
    http::{HeaderValue, request::Parts as RequestParts},
    middleware,
    routing::{delete, get, post, put},
};
use hyper::header::{AUTHORIZATION, CACHE_CONTROL, CONTENT_SECURITY_POLICY, CONTENT_TYPE, X_CONTENT_TYPE_OPTIONS};
use tower_http::cors::{AllowOrigin, Any, CorsLayer};
use tower_http::services::ServeDir;
use tower_http::set_header::SetResponseHeaderLayer;
use tracing::{debug, error, info};

use crate::auth_manager::middleware::RbacGuard;
use crate::identity::handlers;
use crate::identity::state::IdentityApiState;
use crate::rbac::Feature;

fn create_pre_save_llm_connection_test_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route("/v1/pipes/test-llm-connection", gate.gate(post(handlers::test_llm_connection), Feature::PipesEdit))
}

fn identity_integrations_routes<S>(rbac_guard: &RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    Router::new()
        .route(
            "/v1/identities/integrations",
            rbac_guard.gate(
                get(crate::integrations::identity_integrations_handlers::get_identity_integrations),
                Feature::IdentitiesManage,
            ),
        )
        .route(
            "/v1/identities/integrations",
            rbac_guard.gate(
                put(crate::integrations::identity_integrations_handlers::update_identity_integrations),
                Feature::IntegrationsEdit,
            ),
        )
}

fn create_pipe_template_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    IdentityApiState: axum::extract::FromRef<S>,
{
    use crate::pipe_templates::handlers as templates;
    Router::new()
        .route("/v1/pipe-templates", gate.gate(get(templates::list_templates), Feature::PipesView))
        .route("/v1/pipe-templates", gate.gate(post(templates::create_template), Feature::PipesEdit))
        .route("/v1/pipe-templates/import", gate.gate(post(templates::import_template), Feature::PipesEdit))
        .route("/v1/pipe-templates/{template_id}", gate.gate(get(templates::get_template), Feature::PipesView))
        .route("/v1/pipe-templates/{template_id}", gate.gate(put(templates::update_template), Feature::PipesEdit))
        .route("/v1/pipe-templates/{template_id}", gate.gate(delete(templates::delete_template), Feature::PipesDelete))
        .route(
            "/v1/pipe-templates/{template_id}/export",
            gate.gate(get(templates::export_template), Feature::PipesView),
        )
}

/// A Surface read returns the Surface's full configuration, so it needs
/// `pipes.view`. The budget read returns spend, so it needs `metrics.view`
/// like the other Surface metrics.
fn create_pipe_read_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    IdentityApiState: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/v1/pipes", gate.gate(get(handlers::list_pipes), Feature::PipesView))
        .route("/v1/pipes/{pipe_id}", gate.gate(get(handlers::get_pipe), Feature::PipesView))
        .route(
            "/v1/pipes/{pipe_id}/variants/{alias}/resolved",
            gate.gate(get(handlers::get_resolved_variant), Feature::PipesView),
        )
        .route(
            "/v1/pipes/{pipe_id}/ide-catalog/preview",
            gate.gate(get(handlers::preview_ide_catalog), Feature::PipesView),
        )
        .route(
            "/v1/pipes/{pipe_id}/ide-catalog/bootstrap",
            gate.gate(get(handlers::preview_ide_bootstrap), Feature::PipesView),
        )
        .route("/v1/pipes/{pipe_id}/budget", gate.gate(get(crate::pipes::get_budget_usage), Feature::MetricsView))
}

/// The telemetry export configuration names the collector appliance telemetry
/// goes to and the stored secret that authenticates it, so every route needs
/// `settings.edit`. The configuration save also checks `secrets.view` through
/// the guard it receives as an extension.
fn create_metrics_config_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    IdentityApiState: axum::extract::FromRef<S>,
{
    let settings_edit = Feature::SettingsEdit;
    Router::new()
        .route("/v1/metrics/truncate", gate.gate(post(handlers::truncate_metrics), settings_edit.clone()))
        .route("/v1/metrics/config", gate.gate(get(handlers::get_metrics_config), settings_edit.clone()))
        .route(
            "/v1/metrics/config",
            gate.gate(put(handlers::update_metrics_config).layer(Extension(gate.clone())), settings_edit.clone()),
        )
        .route("/v1/metrics/test-connection", gate.gate(post(handlers::test_otlp_connection), settings_edit))
}

/// Reading the appliance log is `logs.view`. Truncating it destroys evidence,
/// so it needs `settings.edit` rather than a read permission.
fn create_logs_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    IdentityApiState: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/v1/logs/truncate", gate.gate(post(handlers::truncate_old_logs), Feature::SettingsEdit))
        .route("/v1/logs/download", gate.gate(get(handlers::download_logs), Feature::LogsView))
}

/// The connection-point inbox holds decrypted DIDComm messages, so it is gated
/// on `connection_points.edit` rather than `connection_points.view`, which
/// every user holds: reading messages, the unread count, marking a message
/// read and recording a use need `connection_points.edit`, and deleting a
/// message needs `connection_points.delete`.
fn connection_point_inbox_routes(gate: &RbacGuard) -> Router {
    use crate::gateways::connection_points::handlers;
    let edit = Feature::ConnectionPointsEdit;
    Router::new()
        .route(
            "/v1/connection-points/{id}/use",
            gate.gate(
                post(handlers::use_connection_point::<crate::gateways::FileSystemConnectionPointStore>),
                edit.clone(),
            ),
        )
        .route(
            "/v1/connection-points/{id}/messages",
            gate.gate(get(handlers::get_connection_point_messages), edit.clone()),
        )
        .route(
            "/v1/connection-points/{id}/messages/{message_id}",
            gate.gate(get(handlers::get_connection_point_message), edit.clone()),
        )
        .route(
            "/v1/connection-points/{id}/messages/{message_id}/read",
            gate.gate(post(handlers::mark_message_read), edit.clone()),
        )
        .route(
            "/v1/connection-points/{id}/messages/{message_id}",
            gate.gate(delete(handlers::delete_message), Feature::ConnectionPointsDelete),
        )
        .route(
            "/v1/connection-points/{id}/messages/unread-count",
            gate.gate(get(handlers::get_unread_message_count), edit),
        )
}

/// Connection Point reads need `connection_points.view`, so an access token
/// narrowed to other scopes, or a role without the permission, is refused.
/// None of them returns the invitation secret.
fn connection_point_read_routes(gate: &RbacGuard) -> Router {
    use crate::gateways::FileSystemConnectionPointStore as Store;
    use crate::gateways::connection_points::handlers;
    let view = Feature::ConnectionPointsView;
    Router::new()
        .route("/v1/connection-points", gate.gate(get(handlers::list_connection_points::<Store>), view.clone()))
        .route("/v1/connection-points/{id}", gate.gate(get(handlers::get_connection_point::<Store>), view.clone()))
        .route(
            "/v1/connection-points/{id}/metrics",
            gate.gate(get(handlers::get_connection_point_metrics), view.clone()),
        )
        .route(
            "/v1/gateways/{gateway_id}/connection-points",
            gate.gate(get(handlers::list_gateway_connection_points::<Store>), view),
        )
}

/// `GET /v1/agents` returns the agent identities seen on each surface with
/// their latest captured payloads, the same traffic `surfaces.capture`
/// governs on the WebSocket. Agent identities and those payloads span every
/// tenant, so an access token narrowed to a tenant or to resources is refused
/// on these routes, including revoking an identity.
fn create_agents_router<S>(gate: RbacGuard) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
    IdentityApiState: axum::extract::FromRef<S>,
{
    Router::new()
        .route("/v1/agents", gate.gate(get(handlers::get_agents), Feature::SurfacesCapture))
        .route("/v1/agents/{did}/revoke", gate.gate(post(handlers::agents::revoke_agent), Feature::IdentityIssue))
        .route_layer(middleware::from_fn(handlers::agents::refuse_narrowed_tokens))
}

/// The dashboard's HTTP reads need `dashboard.view`. One surface's metrics are
/// confined to a surface the caller may see.
fn dashboard_reads_router(gate: &RbacGuard) -> Router<crate::observability::DashboardState> {
    Router::new()
        .route(
            "/v1/dashboard/surface/{channel_config_id}/metrics",
            gate.gate(get(crate::observability::get_surface_metrics), Feature::DashboardView),
        )
        .route(
            "/v1/dashboard/surface/{channel_config_id}/ucp-operations",
            gate.gate(get(crate::observability::get_ucp_operation_stats), Feature::DashboardView),
        )
        .merge(appliance_wide_dashboard_reads_router(gate))
}

/// Stats and delta cover every surface (leaving out log lines without
/// `logs.view` and captured payloads without `surfaces.capture`), as do the
/// hierarchical connections and callers, and system metrics report the host.
/// They span every tenant, so an access token narrowed to a tenant or to
/// resources is refused on these reads.
fn appliance_wide_dashboard_reads_router(gate: &RbacGuard) -> Router<crate::observability::DashboardState> {
    Router::new()
        .route("/v1/dashboard/stats", gate.gate(get(crate::observability::get_dashboard_stats), Feature::DashboardView))
        .route("/v1/dashboard/delta", gate.gate(get(crate::observability::get_dashboard_delta), Feature::DashboardView))
        .route(
            "/v1/dashboard/metrics/hierarchical",
            gate.gate(get(crate::observability::get_hierarchical_metrics), Feature::DashboardView),
        )
        .route(
            "/v1/dashboard/system-metrics",
            gate.gate(get(crate::observability::get_system_metrics), Feature::DashboardView),
        )
        .route_layer(middleware::from_fn(handlers::agents::refuse_narrowed_tokens))
}

/// The passkey sign-in routes, each start and finish step behind the
/// per-client sign-in throttle and `/auth/check` behind its own budget (see
/// [`crate::auth::throttle`]).
fn passkey_auth_routes(
    auth_state: std::sync::Arc<crate::auth::AuthState>,
    sessions: std::sync::Arc<crate::auth::SessionManager>,
) -> Router {
    Router::new()
        .route(
            "/auth/register/start",
            post(crate::auth::handlers::register_start)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_start)),
        )
        .route(
            "/auth/register/finish",
            post(crate::auth::handlers::register_finish)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_finish)),
        )
        .route(
            "/auth/login/start",
            post(crate::auth::handlers::login_start)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_start)),
        )
        .route(
            "/auth/login/finish",
            post(crate::auth::handlers::login_finish)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_finish)),
        )
        .route(
            "/auth/check",
            get(crate::auth::handlers::check_auth)
                .layer(axum::middleware::from_fn_with_state(sessions, crate::auth::throttle::auth_check)),
        )
        .route("/auth/logout", post(crate::auth::handlers::logout))
        .with_state(auth_state)
}

/// The SAML sign-in routes, with the same per-client throttle as
/// [`passkey_auth_routes`].
fn saml_auth_routes(
    saml_state: std::sync::Arc<crate::auth::saml::SamlState>,
    sessions: std::sync::Arc<crate::auth::SessionManager>,
) -> Router {
    Router::new()
        .route(
            "/saml/login",
            get(crate::auth::saml::saml_login).layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_start)),
        )
        .route(
            "/saml/acs",
            post(crate::auth::saml::saml_acs).layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_finish)),
        )
        .route("/saml/metadata", get(crate::auth::saml::saml_metadata))
        .route("/saml/logout", post(crate::auth::saml::saml_logout))
        .with_state(saml_state)
        .merge(
            Router::new()
                .route(
                    "/auth/check",
                    get(crate::auth::saml::saml_check_auth).layer(axum::middleware::from_fn_with_state(
                        sessions.clone(),
                        crate::auth::throttle::auth_check,
                    )),
                )
                .route("/auth/logout", post(crate::auth::saml::saml_logout_generic))
                .layer(Extension(sessions)),
        )
}

/// The OIDC sign-in routes, with the same per-client throttle as
/// [`passkey_auth_routes`], and the unthrottled back-channel logout route.
/// `/auth/check` behaves as in SAML mode, and `/auth/logout` is the OIDC
/// sign-out.
fn oidc_auth_routes(
    oidc_state: std::sync::Arc<crate::auth::oidc::OidcState>,
    sessions: std::sync::Arc<crate::auth::SessionManager>,
) -> Router {
    // The provider posts logout tokens server to server: no sign-in throttle,
    // which would refuse a burst of legitimate logouts, but a small body limit.
    let backchannel_logout = if oidc_state
        .config
        .logout
        .backchannel
    {
        Router::new().route(
            "/oidc/backchannel-logout",
            post(crate::auth::oidc::oidc_backchannel_logout)
                .layer(axum::extract::DefaultBodyLimit::max(crate::auth::oidc::MAX_BACKCHANNEL_LOGOUT_BYTES)),
        )
    } else {
        Router::new()
    };
    Router::new()
        .route(
            "/oidc/login",
            get(crate::auth::oidc::oidc_login).layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_start)),
        )
        .route(
            "/oidc/callback",
            get(crate::auth::oidc::oidc_callback)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_finish)),
        )
        .route(
            "/oidc/initiate",
            get(crate::auth::oidc::oidc_initiate)
                .post(crate::auth::oidc::oidc_initiate)
                .layer(axum::middleware::from_fn(crate::auth::throttle::sign_in_start)),
        )
        .route("/oidc/logout", post(crate::auth::oidc::oidc_logout))
        .route("/auth/logout", post(crate::auth::oidc::oidc_logout))
        .merge(backchannel_logout)
        .with_state(oidc_state)
        .merge(
            Router::new()
                .route(
                    "/auth/check",
                    get(crate::auth::saml::saml_check_auth).layer(axum::middleware::from_fn_with_state(
                        sessions.clone(),
                        crate::auth::throttle::auth_check,
                    )),
                )
                .layer(Extension(sessions)),
        )
}

/// The internal UI-test sign-in bootstrap. Compiled into debug builds only
/// (`debug_assertions`) so it can never ship in a release binary; even in
/// debug it stays disabled unless AS_TEST_MODE and a non-empty AS_TEST_TOKEN
/// are both set (see TestAuthConfig::from_env). Every sign-in mode stores
/// users in PasskeyStorage and shares one SessionManager, so it mints the same
/// session in any of them.
#[cfg(debug_assertions)]
fn test_support_router(
    storage: std::sync::Arc<crate::auth::storage::PasskeyStorage>,
    sessions: std::sync::Arc<crate::auth::SessionManager>,
    terms_manager: std::sync::Arc<crate::terms::TermsManager>,
) -> Router {
    let test_auth_config = crate::auth::test_auth::TestAuthConfig::from_env();
    if !test_auth_config.enabled {
        return Router::new();
    }
    Router::new()
        .route("/internal/test-support/auth/login", post(crate::auth::test_auth::test_login))
        .with_state(std::sync::Arc::new(crate::auth::test_auth::TestAuthState::new(
            storage,
            sessions,
            terms_manager,
            test_auth_config,
        )))
}

#[cfg(not(debug_assertions))]
fn test_support_router(
    _storage: std::sync::Arc<crate::auth::storage::PasskeyStorage>,
    _sessions: std::sync::Arc<crate::auth::SessionManager>,
    _terms_manager: std::sync::Arc<crate::terms::TermsManager>,
) -> Router {
    Router::new()
}

/// Create the identity API router with all routes configured
pub fn create_identity_api_router(
    state: IdentityApiState,
    ownership_stores: std::sync::Arc<handlers::tenant_ownership::TenantOwnershipStores>,
    dashboard_state: crate::observability::DashboardState,
    auth_state: Option<std::sync::Arc<crate::auth::AuthState>>,
    saml_state: Option<std::sync::Arc<crate::auth::saml::SamlState>>,
    oidc_state: Option<std::sync::Arc<crate::auth::oidc::OidcState>>,
    rbac_guard: RbacGuard,
    gateway_store: Option<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    mediator_store: Option<std::sync::Arc<crate::mediators::FileSystemMediatorStore>>,
    secrets_store: Option<std::sync::Arc<dyn crate::secrets::SecretsStore>>,
    certificate_store: Option<std::sync::Arc<dyn crate::certificates::CertificateStore>>,
    agent_surface_store: Option<std::sync::Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    connection_point_store: Option<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    notification_store: Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>,
    listener_manager: Option<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>,
    message_store: Option<std::sync::Arc<crate::gateways::MessageStore>>,
    pending_connection_store: std::sync::Arc<crate::gateways::PendingConnectionStore>,
    integration_storage: Option<std::sync::Arc<crate::storage::IntegrationStorage>>,
    _pipe_route_manager: Option<std::sync::Arc<crate::pipes::PipeRouteManager>>,
    jwt_verification_strategy_store: Option<std::sync::Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    jwks_client: Option<std::sync::Arc<crate::jwt_bearer::JwksClient>>,
    marketplace_model_store: Option<std::sync::Arc<crate::marketplace_models::FileSystemMarketplaceModelStore>>,
    gateway_policy_manager: std::sync::Arc<crate::policies::GatewayPolicyManager>,
    pat_authenticator: Option<std::sync::Arc<dyn crate::auth_manager::pat::PatAuthenticator>>,
    terms_manager: std::sync::Arc<crate::terms::TermsManager>,
) -> Router {
    // Capture config before moving state into routers
    let avatars_path = state
        .bootstrap_config
        .storage_paths
        .avatars
        .clone();
    let uploads_path = state
        .bootstrap_config
        .storage_paths
        .uploads
        .clone();
    {
        let resolved = std::fs::canonicalize(&avatars_path)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|e| format!("<unresolved: {}>", e));
        let cwd = std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| "?".to_string());
        tracing::info!("[WWW Hosting] avatars dir (path: {} | cwd: {} | resolved: {})", avatars_path, cwd, resolved);
    }

    let rbac_config = state.rbac_config.clone();
    let websocket_require_auth = state
        .bootstrap_config
        .websocket_require_auth;
    let trusted_tenant_header = state
        .bootstrap_config
        .tenancy
        .trusted_tenant_header
        .clone()
        .map(std::sync::Arc::new);

    // Create gateway channel cache
    let gateway_channel_cache = std::sync::Arc::new(crate::gateways::GatewaySurfaceCache::new());

    // Create marketplace cache
    let marketplace_cache = std::sync::Arc::new(crate::gateways::MarketplaceCache::new());

    // Create dashboard routes with dashboard state
    let dashboard_router = dashboard_reads_router(&rbac_guard);

    // Add WebSocket routes conditionally based on auth requirement
    info!(
        "Setting up WebSocket routes: websocket_require_auth={}, auth_state={}, saml_state={}",
        websocket_require_auth,
        auth_state.is_some(),
        saml_state.is_some()
    );

    let dashboard_router = if websocket_require_auth && (auth_state.is_some() || saml_state.is_some()) {
        // Get session manager from whichever auth mode is active
        let session_mgr = if let Some(auth) = auth_state.as_ref() {
            info!("Using passkey session manager for WebSocket authentication");
            auth.session_manager.clone()
        } else if let Some(saml) = saml_state.as_ref() {
            info!("Using SAML session manager for WebSocket authentication");
            saml.session_manager.clone()
        } else {
            unreachable!("Session manager must exist when auth_state or saml_state is Some");
        };

        info!("WebSocket routes configured with authentication required");
        dashboard_router
            .route("/ws/dashboard", get(crate::server::ws_handler_authenticated))
            .route("/ws", get(crate::server::ws_handler_authenticated))
            .with_state(dashboard_state.clone())
            .layer(Extension(session_mgr))
            .layer(Extension(terms_manager.clone()))
    } else {
        // Use unauthenticated handler for backward compatibility
        info!("WebSocket routes configured without authentication");
        dashboard_router
            .route("/ws/dashboard", get(crate::server::ws_handler))
            .route("/ws", get(crate::server::ws_handler))
            .with_state(dashboard_state.clone())
    };
    // The dashboard reads and the WebSocket send log lines only to a caller
    // holding logs.view, and captured payloads only to one holding
    // surfaces.capture.
    let dashboard_router = dashboard_router.layer(Extension(rbac_guard.clone()));

    // Create identity API routes with identity state
    let pipe_reference_stores = std::sync::Arc::new(handlers::pipe_tenancy::PipeReferenceStores {
        secrets: secrets_store.clone(),
        certificates: certificate_store,
        jwt_strategies: jwt_verification_strategy_store.clone(),
        agent_surfaces: agent_surface_store.clone(),
        integrations: integration_storage.clone(),
        oauth_identifiers: crate::oauth_identifiers::global_oauth_identifier_store(),
    });
    let identity_router = Router::new()
        // DIDComm messaging endpoints
        .route("/didcomm", post(handlers::didcomm_endpoint))
        .route("/didcomm/ws", get(handlers::didcomm_ws_endpoint))
        // Identity credential routes
        .route("/v1/identity/issue", rbac_guard.gate(post(handlers::issue_credential), Feature::IdentityIssue))
        .route("/v1/identity/did-document", get(handlers::get_did_document))
        .route("/v1/identity/resolve-did", get(handlers::resolve_did_document))
        .route("/v1/identity/resolve-did-document", get(handlers::resolve_did_document_spec))
        // Health check
        .route("/v1/health", get(handlers::health_check))
        .route("/v1/alive", get(handlers::alive_check))
        // Version check
        .route("/v1/version", get(handlers::get_version))
        // Settings routes (GET/POST/DELETE require explicit settings RBAC features)
        .route("/v1/settings", rbac_guard.gate(get(handlers::get_settings), Feature::SettingsView))
        .route("/v1/terms/applicable", get(crate::terms::handlers::applicable))
        .route("/v1/terms/provider-health", get(crate::terms::handlers::provider_health))
        .route("/v1/terms/status", get(crate::terms::handlers::status))
        .route("/v1/terms/acceptances", post(crate::terms::handlers::accept))
        .route("/v1/terms", rbac_guard.gate(get(crate::terms::handlers::definitions), Feature::TermsView))
        .route("/v1/terms/customer/draft", rbac_guard.gate(put(crate::terms::handlers::save_draft), Feature::TermsEdit))
        .route("/v1/terms/customer/publish", rbac_guard.gate(post(crate::terms::handlers::publish), Feature::TermsEdit))
        .route(
            "/v1/terms/customer/deactivate",
            rbac_guard.gate(post(crate::terms::handlers::deactivate), Feature::TermsEdit),
        )
        // Storage export/backup/restore are registered on the RBAC-gated auth manager router below.
        // Metrics routes
        .route("/v1/metrics/prometheus", get(handlers::prometheus_metrics))
        .merge(create_metrics_config_router(rbac_guard.clone()))
        .merge(create_logs_router(rbac_guard.clone()))
        // Policy-decision (VP) audit evidence (`/api/v1/audit`). Least-privilege; administrator-only in the default
        // RBAC config via `Feature::AuditView`.
        .route("/v1/audit", rbac_guard.gate(get(handlers::audit_log::get_audit_log), Feature::AuditView))
        // Configuration reload routes
        .route("/v1/config/reload", rbac_guard.gate(post(handlers::reload_configuration), Feature::ConfigReload))
        .route(
            "/v1/config/reload/{config_id}",
            rbac_guard.gate(post(handlers::reload_single_channel), Feature::ConfigReload),
        )
        .route("/v1/config/surface-routing", get(handlers::get_surface_routing_config))
        .route("/v1/config/networking", get(handlers::get_networking_config))
        // Appliance resource limits (name/description/limit/current per dimension)
        .route("/v1/limits", get(handlers::list_limits))
        // Policy validation
        .route("/v1/surfaces/validate-policy", rbac_guard.gate(post(handlers::validate_policy), Feature::PoliciesEdit))
        .merge(create_pipe_template_router(rbac_guard.clone()))
        // Pipe management routes
        .merge(create_pipe_read_router(rbac_guard.clone()))
        .route("/v1/pipes", rbac_guard.gate(post(handlers::create_pipe), Feature::PipesEdit))
        .route("/v1/pipes/{pipe_id}", rbac_guard.gate(put(handlers::update_pipe), Feature::PipesEdit))
        .route("/v1/pipes/{pipe_id}", rbac_guard.gate(delete(handlers::delete_pipe), Feature::PipesDelete))
        // Pipe variant administration
        .route("/v1/pipes/{pipe_id}/variants", rbac_guard.gate(post(handlers::create_variant), Feature::PipesEdit))
        .route(
            "/v1/pipes/{pipe_id}/variants/{variant_id}",
            rbac_guard.gate(put(handlers::update_variant), Feature::PipesEdit),
        )
        .route(
            "/v1/pipes/{pipe_id}/variants/{variant_id}",
            rbac_guard.gate(delete(handlers::delete_variant), Feature::PipesDelete),
        )
        .route(
            "/v1/pipes/{pipe_id}/variants/{variant_id}/promote-to-default",
            rbac_guard.gate(post(handlers::promote_variant_to_default), Feature::PipesEdit),
        )
        // The test sends the saved key only to its saved endpoint, a pairing
        // only secrets.view may choose (pipe_secret_bindings), so running the
        // surface is enough.
        .route("/v1/pipes/{pipe_id}/test", rbac_guard.gate(post(handlers::test_pipe), Feature::PipesExecute))
        .merge(create_pre_save_llm_connection_test_router(rbac_guard.clone()))
        .route(
            "/v1/pipes/test-surfaces/delete",
            rbac_guard.gate(post(handlers::delete_test_surfaces), Feature::PipesDelete),
        )
        .route("/v1/test-support/purge", rbac_guard.gate(post(handlers::purge_test_fixtures), Feature::PipesDelete))
        .route("/v1/pipes/{pipe_id}/execute", post(crate::pipes::execute_pipe))
        .route("/v1/pipes/{pipe_id}/execute/stream", post(crate::pipes::execute_pipe_stream))
        .route(
            "/v1/pipes-metrics",
            rbac_guard.gate(get(handlers::pipe_metrics::get_pipe_metrics), Feature::MetricsView),
        )
        // Policy definition routes
        .route("/v1/policy-definitions", rbac_guard.gate(get(handlers::list_policy_definitions), Feature::PoliciesView))
        .route(
            "/v1/policy-definitions",
            rbac_guard.gate(post(handlers::create_policy_definition), Feature::PoliciesEdit),
        )
        .route(
            "/v1/policy-definitions/{policy_id}",
            rbac_guard.gate(get(handlers::get_policy_definition), Feature::PoliciesView),
        )
        .route(
            "/v1/policy-definitions/{policy_id}",
            rbac_guard.gate(put(handlers::update_policy_definition), Feature::PoliciesEdit),
        )
        .route(
            "/v1/policy-definitions/{policy_id}",
            rbac_guard.gate(delete(handlers::delete_policy_definition), Feature::PoliciesDelete),
        )
        // Dry-run / simulate a policy definition against a sample input (read-only)
        .route(
            "/v1/policy-definitions/{policy_id}/simulate",
            rbac_guard.gate(post(handlers::simulate_policy_definition), Feature::PoliciesView),
        )
        // Blast-radius / impact of a policy definition (read-only)
        .route(
            "/v1/policy-definitions/{policy_id}/impact",
            rbac_guard.gate(get(handlers::policy_definition_impact), Feature::PoliciesView),
        )
        // Immutable version history of a policy definition (read-only)
        .route(
            "/v1/policy-definitions/{policy_id}/versions",
            rbac_guard.gate(get(handlers::list_policy_versions), Feature::PoliciesView),
        )
        // Appliance-wide (global) policy assignments
        .route("/v1/policy-assignments", rbac_guard.gate(get(handlers::get_policy_assignments), Feature::PoliciesView))
        .route(
            "/v1/policy-assignments",
            rbac_guard.gate(put(handlers::update_policy_assignments), Feature::PoliciesPublish),
        )
        .route(
            "/v1/tenant-ownership/{kind}/{id}/impact",
            rbac_guard.gate(get(handlers::tenant_ownership::ownership_impact), Feature::TenantOwnershipManage),
        )
        .route(
            "/v1/tenant-ownership/{kind}/{id}",
            rbac_guard.gate(put(handlers::tenant_ownership::reassign_ownership), Feature::TenantOwnershipManage),
        )
        .merge(create_agents_router(rbac_guard.clone()))
        .with_state(state.clone())
        .layer(Extension(pipe_reference_stores))
        .layer(Extension(ownership_stores));

    // Pipe routes are registered in the port listener (proxy/server.rs) like channels and MCP proxies
    // See: proxy/server.rs where LLM pipe routes are registered from network_config.pipe_paths

    // Determine auth mode from what was actually passed to this function:
    // SAML or OIDC state when that mode is on, otherwise passkey.
    let auth_mode = if saml_state.is_some() {
        crate::auth::AuthMode::Saml
    } else if oidc_state.is_some() {
        crate::auth::AuthMode::Oidc
    } else {
        crate::auth::AuthMode::Passkey
    };

    // Create auth routes based on authentication mode
    // Returns: (router, storage_for_manager, session_manager_for_manager)
    let (auth_router, passkey_storage_for_manager, session_manager_for_manager) = match auth_mode {
        crate::auth::AuthMode::Passkey => {
            if let Some(auth_state_arc) = auth_state.clone() {
                let storage = auth_state_arc.storage.clone();
                let session_mgr = auth_state_arc
                    .session_manager
                    .clone();

                let router = Router::new()
                    // Auth mode endpoint (unauthenticated)
                    .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                    .layer(Extension(auth_mode.clone()))
                    .merge(passkey_auth_routes(auth_state_arc.clone(), session_mgr.clone()))
                    .merge(test_support_router(storage.clone(), session_mgr.clone(), terms_manager.clone()));

                (router, Some(storage), Some(session_mgr))
            } else {
                error!("Passkey mode enabled but no auth state available");
                (
                    Router::new()
                        .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                        .layer(Extension(auth_mode.clone())),
                    None,
                    None,
                )
            }
        }
        crate::auth::AuthMode::Saml => {
            // Add SAML routes if saml_state is available
            if let Some(saml_state_arc) = saml_state {
                let session_mgr = saml_state_arc
                    .session_manager
                    .clone();
                let storage = saml_state_arc.storage.clone();

                let router = Router::new()
                    // Auth mode endpoint (unauthenticated)
                    .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                    .layer(Extension(auth_mode.clone()))
                    .merge(saml_auth_routes(saml_state_arc.clone(), session_mgr.clone()))
                    .merge(test_support_router(storage.clone(), session_mgr.clone(), terms_manager.clone()));
                info!("SAML routes registered (login, acs, metadata, logout, check)");

                // Return storage and session manager for auth_manager_router setup
                (router, Some(storage), Some(session_mgr))
            } else {
                error!("SAML mode enabled but no SAML state available");
                (
                    Router::new()
                        .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                        .layer(Extension(auth_mode.clone())),
                    None,
                    None,
                )
            }
        }
        crate::auth::AuthMode::Oidc => match oidc_state {
            Some(oidc_state_arc) => {
                let session_mgr = oidc_state_arc
                    .session_manager
                    .clone();
                let storage = oidc_state_arc.storage.clone();
                let label = crate::auth::mode_handler::SignInLabel(
                    oidc_state_arc
                        .config
                        .label
                        .clone(),
                );
                let router = Router::new()
                    .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                    .layer(Extension(auth_mode.clone()))
                    .layer(Extension(label))
                    .merge(oidc_auth_routes(oidc_state_arc, session_mgr.clone()))
                    .merge(test_support_router(storage.clone(), session_mgr.clone(), terms_manager.clone()));
                info!("OIDC routes registered (login, callback, initiate, logout, back-channel logout, check)");
                (router, Some(storage), Some(session_mgr))
            }
            None => {
                error!("OIDC mode enabled but no OIDC state available");
                (
                    Router::new()
                        .route("/v1/auth/mode", get(crate::auth::mode_handler::get_auth_mode))
                        .layer(Extension(auth_mode.clone())),
                    None,
                    None,
                )
            }
        },
    };

    // Create auth manager routes if passkey storage and session manager are available
    // This works for both Passkey and SAML modes since they both use PasskeyStorage
    let auth_manager_router = if let (Some(storage), Some(sess_mgr)) =
        (passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
    {
        let mut router = Router::new();

        // Add user management routes with session auth middleware.
        // These handlers are auth-mode-agnostic — they need PasskeyStorage,
        // RbacConfig, and MetricsStore (all available in both Passkey and SAML
        // modes), not the Passkey-specific AuthState.
        router = router.merge(
            Router::new()
                .route("/v1/users", get(crate::auth_manager::handlers::list_users))
                .route("/v1/users/{user_id}", get(crate::auth_manager::handlers::get_user))
                .route("/v1/users/{user_id}", put(crate::auth_manager::handlers::update_user))
                .route("/v1/users/{user_id}", delete(crate::auth_manager::handlers::delete_user))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(pat_authenticator.clone()))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(notification_store.clone()))
                .layer(Extension(rbac_config.clone()))
                .layer(Extension(state.metrics_store.clone())),
        );

        // Add profile and permissions routes with session auth middleware.
        // The body limit caps the avatar multipart upload so an oversized file
        // is rejected before it is fully buffered into memory.
        router = router.merge(
            Router::new()
                .route("/v1/profile", get(crate::auth_manager::handlers::get_profile))
                .route("/v1/profile", put(crate::auth_manager::handlers::update_profile))
                .route("/v1/profile/avatar", post(crate::auth_manager::handlers::upload_avatar))
                .route("/v1/permissions", get(crate::auth_manager::permissions::get_permissions))
                .layer(axum::extract::DefaultBodyLimit::max(crate::uploads::MAX_UPLOAD_SIZE + 1024 * 1024))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone())),
        );

        // Generic storage-backed image upload (LLM provider logos, etc.).
        // The body limit caps multipart buffering so an oversized upload is
        // rejected before it is fully read into memory.
        router = router.merge(
            Router::new()
                .route("/v1/uploads/image", post(crate::uploads::upload_image))
                .layer(axum::extract::DefaultBodyLimit::max(crate::uploads::MAX_UPLOAD_SIZE + 1024 * 1024))
                .layer(Extension(crate::uploads::UploadsDir(uploads_path.clone()))),
        );

        // Add unauthenticated permissions endpoint for registration flow
        router = router.merge(
            Router::new()
                .route("/v1/permissions/public", get(crate::auth_manager::permissions::get_permissions_optional))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone())),
        );

        // Add per-user settings routes with session auth middleware
        router = router.merge(
            Router::new()
                .route("/v1/user-settings", get(handlers::get_user_settings))
                .route("/v1/user-settings", post(handlers::update_user_settings))
                .route("/v1/user-settings", delete(handlers::reset_user_settings))
                .route("/v1/user-settings/overrides", get(handlers::get_user_settings_overrides))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .with_state(state.clone()),
        );

        // Add team management routes with session auth middleware. The handlers
        // RBAC-gate on the caller (extract_user_id → Extension<String>) and read
        // PasskeyStorage + RbacConfig; team data lives on IdentityApiState.
        router = router.merge(
            Router::new()
                .route("/v1/teams", get(handlers::list_teams))
                .route("/v1/teams", post(handlers::create_team))
                .route("/v1/teams/{team_id}", get(handlers::get_team))
                .route("/v1/teams/{team_id}", put(handlers::update_team))
                .route("/v1/teams/{team_id}", delete(handlers::delete_team))
                .route("/v1/teams/{team_id}/members", post(handlers::add_member))
                .route("/v1/teams/{team_id}/members/{member_id}", delete(handlers::remove_member))
                .route("/v1/teams/{team_id}/usage", get(handlers::team_usage))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Add member management routes (appliance clients) with session auth.
        // Same RBAC-on-caller pattern as teams; member data lives on
        // IdentityApiState via the member store.
        router = router.merge(
            Router::new()
                .route("/v1/members", get(handlers::list_members))
                .route("/v1/members", post(handlers::create_member))
                .route("/v1/members/{member_id}", get(handlers::get_member))
                .route("/v1/members/{member_id}/usage", get(handlers::get_member_usage))
                .route("/v1/members/{member_id}", put(handlers::update_member))
                .route("/v1/members/{member_id}", delete(handlers::delete_member))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Add member auto-provisioning config routes with session auth. The
        // appliance-level config that governs first-sight member creation and
        // team assignment; gated on the `enrolment.*` RBAC features.
        router = router.merge(
            Router::new()
                .route("/v1/member-provisioning", get(handlers::get_provisioning_config))
                .route("/v1/member-provisioning", put(handlers::update_provisioning_config))
                .route("/v1/member-provisioning/preview", post(handlers::preview_provisioning))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Add prompt-template management routes with session auth. Same
        // RBAC-on-caller pattern; prompt data lives on IdentityApiState via the
        // prompt store. `/render` is the playground preview.
        router = router.merge(
            Router::new()
                .route("/v1/prompts", get(handlers::list_prompts))
                .route("/v1/prompts", post(handlers::create_prompt))
                .route("/v1/prompts/{id}", get(handlers::get_prompt))
                .route("/v1/prompts/{id}", put(handlers::update_prompt))
                .route("/v1/prompts/{id}", delete(handlers::delete_prompt))
                .route("/v1/prompts/{id}/render", post(handlers::render_prompt))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Add read-only usage-telemetry time-series route with session auth.
        // RBAC-gated on `metrics.view`; data is read from the process-wide
        // telemetry store via a global accessor, so no state threading needed.
        router = router.merge(
            Router::new()
                .route("/v1/telemetry/series", get(handlers::telemetry_series))
                .route("/v1/telemetry/rejections", get(handlers::telemetry_rejections))
                .route("/v1/dashboard/ops-series", get(handlers::ops_series))
                .route("/v1/cache/stats", get(handlers::cache_stats))
                .route("/v1/prompt-guard/detector-stats", get(handlers::detector_stats))
                .route("/v1/spend-report", get(handlers::spend_report))
                .route("/v1/governance/surfaces", get(handlers::governance_surfaces))
                .route("/v1/governance/coverage", get(handlers::governance_coverage))
                .route("/v1/governance/records", get(handlers::governance_records))
                .route("/v1/governance/records/{id}", get(handlers::governance_record))
                .route("/v1/governance/verify", get(handlers::governance_verify))
                .route("/v1/drift/series", get(handlers::drift_series))
                .route("/v1/drift/dimensions", get(handlers::drift_dimensions))
                .route("/v1/drift/verdict", get(handlers::drift_verdict))
                .route("/v1/drift/baseline", get(handlers::drift_baseline).post(handlers::drift_capture_baseline))
                .route("/v1/drift/sessions", get(handlers::drift_list_sessions))
                .route("/v1/drift/eval/run", post(handlers::drift_run_eval))
                .route("/v1/drift/eval/cancel", post(handlers::drift_cancel_eval))
                .route("/v1/drift/runs", get(handlers::drift_list_runs))
                .route("/v1/drift/runs/{id}", get(handlers::drift_get_run))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Prompt-guard detector test needs the secrets store (to resolve the
        // detector's API key), so it lives in its own group with that extension.
        router = router.merge(
            Router::new()
                .route(
                    "/v1/prompt-guard/detector-test",
                    rbac_guard.gate(post(handlers::detector_test), Feature::PipesEdit),
                )
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .layer(Extension(secrets_store.clone()))
                .with_state(state.clone()),
        );

        // Add admin-protected system settings write routes (POST/DELETE /v1/settings)
        router = router.merge(
            Router::new()
                .route("/v1/settings", rbac_guard.gate(post(handlers::update_settings), Feature::SettingsEdit))
                .route("/v1/settings", rbac_guard.gate(delete(handlers::reset_settings), Feature::SettingsEdit))
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        // Full-instance storage backup/restore/export routes. These are mounted
        // only when an auth backend exists and are additionally gated on the
        // administrator-only storage.admin feature.
        router = router.merge(
            Router::new()
                .route(
                    "/v1/admin/backup-storage",
                    rbac_guard.gate(post(crate::backup_restore::backup_storage), Feature::StorageAdmin),
                )
                .route(
                    "/v1/admin/restore-storage",
                    rbac_guard.gate(
                        post(crate::backup_restore::restore_storage)
                            .layer(axum::extract::DefaultBodyLimit::max(512 * 1024 * 1024)),
                        Feature::StorageAdmin,
                    ),
                )
                .route(
                    "/v1/debug/export-storage",
                    rbac_guard.gate(post(handlers::export_storage), Feature::StorageAdmin),
                )
                .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
                .layer(Extension(sess_mgr.clone()))
                .layer(Extension(storage.clone()))
                .layer(Extension(rbac_config.clone()))
                .with_state(state.clone()),
        );

        info!("Auth manager routes registered (users, profile, permissions) for {} mode", auth_mode.as_str());

        router
    } else {
        Router::new()
    };

    // Create JWT verification strategy management routes (admin-only)
    let oidc_provider_router = if let (Some(store), Some(storage), Some(sess_mgr)) =
        (jwt_verification_strategy_store, passkey_storage_for_manager.as_ref(), session_manager_for_manager.as_ref())
    {
        let state: crate::jwt_bearer::handlers::JwtVerificationStrategyState = store;
        info!("JWT verification strategy management routes registered");
        let router = crate::jwt_bearer::router::create_jwt_verification_strategies_router(state, rbac_guard.clone())
            .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
            .layer(Extension(sess_mgr.clone()))
            .layer(Extension(storage.clone()))
            .layer(Extension(rbac_config.clone()));
        // Attach the JwksClient Extension when available so the validate-jwks-uri handler can use it.
        if let Some(client) = jwks_client {
            router.layer(Extension(client))
        } else {
            router
        }
    } else {
        Router::new()
    };

    // Create OAuth Identifier management routes (admin-only). The store is read
    // from the process-global accessor (registered by the orchestrator) so the
    // large router signature does not need another parameter.
    let oauth_identifier_router = if let (Some(store), Some(storage), Some(sess_mgr)) = (
        crate::oauth_identifiers::global_oauth_identifier_store(),
        passkey_storage_for_manager.as_ref(),
        session_manager_for_manager.as_ref(),
    ) {
        let state: crate::oauth_identifiers::handlers::OAuthIdentifierState = store;
        info!("OAuth Identifier management routes registered");
        crate::oauth_identifiers::router::create_oauth_identifiers_router(state, rbac_guard.clone())
            .layer(middleware::from_fn(crate::auth_manager::middleware::extract_user_id))
            .layer(Extension(sess_mgr.clone()))
            .layer(Extension(storage.clone()))
            .layer(Extension(rbac_config.clone()))
    } else {
        Router::new()
    };

    // Create gateway routes if store is provided
    let gateway_router = if let Some(ref store) = gateway_store {
        let mut router = Router::new()
            .route("/v1/pipes/config", get(crate::gateways::handlers::get_pipes_config))
            .route(
                "/v1/marketplace/purchase/{model_id}",
                rbac_guard.gate(post(crate::gateways::handlers::post_marketplace_purchase), Feature::PaymentsEdit),
            )
            .route("/v1/marketplace/purchased", get(crate::gateways::handlers::list_purchased_models))
            .route(
                "/v1/marketplace/purchased",
                rbac_guard.gate(post(crate::gateways::handlers::save_purchased_model), Feature::PaymentsEdit),
            )
            .route(
                "/v1/marketplace/purchased/{id}",
                rbac_guard.gate(delete(crate::gateways::handlers::delete_purchased_model), Feature::PaymentsDelete),
            )
            .route("/v1/prompt-guard/config", get(crate::gateways::handlers::get_prompt_guard_config))
            .route(
                "/v1/gateways",
                get(crate::gateways::handlers::list_gateways::<crate::gateways::FileSystemGatewayStore>),
            )
            .route(
                "/v1/gateways",
                rbac_guard.gate(
                    post(crate::gateways::handlers::create_gateway::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/connect-via-oob",
                rbac_guard.gate(
                    post(
                        crate::gateways::handlers::connect_via_oob::<
                            crate::gateways::FileSystemGatewayStore,
                            crate::gateways::FileSystemConnectionPointStore,
                            crate::mediators::FileSystemMediatorStore,
                        >,
                    ),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}",
                get(crate::gateways::handlers::get_gateway::<crate::gateways::FileSystemGatewayStore>),
            )
            .route(
                "/v1/gateways/{id}",
                rbac_guard.gate(
                    put(crate::gateways::handlers::update_gateway::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}/integrations",
                get(crate::integrations::gateway_integrations_handlers::get_gateway_integrations),
            )
            .route(
                "/v1/gateways/{id}/integrations",
                rbac_guard.gate(
                    put(crate::integrations::gateway_integrations_handlers::update_gateway_integrations),
                    Feature::GatewaysEdit,
                ),
            )
            .route(
                "/v1/gateways/{id}/policy",
                get(crate::gateways::handlers::get_gateway_policy::<crate::gateways::FileSystemGatewayStore>),
            )
            .route(
                "/v1/gateways/{id}/policy",
                rbac_guard.gate(
                    put(crate::gateways::handlers::update_gateway_policy::<crate::gateways::FileSystemGatewayStore>),
                    Feature::GatewaysEdit,
                ),
            )
            .layer(Extension(store.clone()))
            .layer(Extension(state.vc_issuer.clone()))
            .layer(Extension(state.bootstrap_config.clone()))
            .layer(Extension(state.network_config.clone()))
            .layer(Extension(pending_connection_store.clone()))
            .layer(Extension(notification_store.clone()))
            // Option-wrapped connection point store so `list_gateways` can derive
            // gateway status from persisted connection-point runtime health even
            // when no store is configured.
            .layer(Extension(connection_point_store.clone()))
            .layer(Extension(Some(gateway_policy_manager.clone())))
            .layer(Extension(
                state
                    .policy_definition_store
                    .clone(),
            ))
            .layer(Extension(integration_storage.clone()))
            .layer(Extension(agent_surface_store.clone()));

        // Add marketplace model store if available
        if let Some(mkt_store) = &marketplace_model_store {
            router = router.layer(Extension(mkt_store.clone()));
        }

        // Add listener manager for marketplace fabric:// forwarding
        if let Some(ref listener_mgr) = listener_manager {
            router = router.layer(Extension(listener_mgr.clone()));
            router = router.layer(Extension(gateway_channel_cache.clone()));
            router = router.layer(Extension(marketplace_cache.clone()));
        }

        // Add connection point store if available (needed for OOB connections and delete)
        if let Some(cp_store) = &connection_point_store {
            router = router.layer(Extension(cp_store.clone()));
        }

        // Add mediator store if available (needed for OOB connections)
        if let Some(med_store) = &mediator_store {
            router = router.layer(Extension(med_store.clone()));
        }

        // Add didwebvh log storage and identity store for OOB connections that use did:webvh
        #[cfg(feature = "didwebvh")]
        {
            router = router
                .layer(Extension(
                    state
                        .didwebvh_log_storage
                        .clone(),
                ))
                .layer(Extension(
                    state
                        .didwebvh_identity_store
                        .clone(),
                ));
        }

        // Add ping route only if we have listener manager
        if let Some(listener_mgr) = &listener_manager {
            router = router
                .route(
                    "/v1/marketplace/models",
                    get(crate::gateways::handlers::get_marketplace_models::<crate::gateways::FileSystemGatewayStore>),
                )
                .route(
                    "/v1/gateways/{id}/ping",
                    post(crate::gateways::handlers::ping_gateway::<crate::gateways::FileSystemGatewayStore>),
                )
                .route(
                    "/v1/gateways/{id}/surfaces",
                    get(crate::gateways::handlers::get_gateway_surfaces::<crate::gateways::FileSystemGatewayStore>),
                )
                .route(
                    "/v1/gateways/{id}/marketplace",
                    get(crate::gateways::handlers::get_gateway_marketplace::<crate::gateways::FileSystemGatewayStore>),
                )
                .route(
                    "/v1/gateways/{id}/exposed-surfaces",
                    rbac_guard.gate(
                        put(crate::gateways::handlers::update_gateway_exposed_surfaces::<
                            crate::gateways::FileSystemGatewayStore,
                        >),
                        Feature::GatewaysEdit,
                    ),
                )
                .route(
                    "/v1/gateways/refresh-surfaces",
                    rbac_guard.gate(
                        post(
                            crate::gateways::handlers::refresh_gateway_surfaces_cache::<
                                crate::gateways::FileSystemGatewayStore,
                            >,
                        ),
                        Feature::GatewaysEdit,
                    ),
                )
                .layer(Extension(store.clone()))
                .layer(Extension(Some(listener_mgr.clone())))
                .layer(Extension(gateway_channel_cache.clone()))
                .layer(Extension(marketplace_cache.clone()))
                .layer(Extension(state.bootstrap_config.clone()));
        }

        // Add approve route only if we have listener manager, connection point store, and mediator store
        if let (Some(listener_mgr), Some(cp_store), Some(med_store)) =
            (&listener_manager, &connection_point_store, &mediator_store)
        {
            router = router
                .route(
                    "/v1/gateways/{id}/approve",
                    rbac_guard.gate(
                        post(
                            crate::gateways::approve::approve_gateway::<
                                crate::gateways::FileSystemGatewayStore,
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        Feature::GatewaysEdit,
                    ),
                )
                .layer(Extension(store.clone()))
                .layer(Extension(cp_store.clone()))
                .layer(Extension(med_store.clone()))
                .layer(Extension(state.vc_issuer.clone()))
                .layer(Extension(state.bootstrap_config.clone()))
                .layer(Extension(state.network_config.clone()))
                .layer(Extension(pending_connection_store.clone()))
                .layer(Extension(Some(listener_mgr.clone())));

            #[cfg(feature = "didwebvh")]
            {
                router = router
                    .layer(Extension(
                        state
                            .didwebvh_log_storage
                            .clone(),
                    ))
                    .layer(Extension(
                        state
                            .didwebvh_identity_store
                            .clone(),
                    ));
            }
        }

        // Add delete route only if we have connection point store and listener manager
        if let (Some(cp_store), Some(listener_mgr)) = (&connection_point_store, &listener_manager) {
            router = router
                .route(
                    "/v1/gateways/{id}",
                    rbac_guard.gate(
                        delete(
                            crate::gateways::handlers::delete_gateway::<
                                crate::gateways::FileSystemGatewayStore,
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                        Feature::GatewaysDelete,
                    ),
                )
                .layer(Extension(store.clone()))
                .layer(Extension(cp_store.clone()))
                .layer(Extension(listener_mgr.clone()))
                .layer(Extension(notification_store.clone()));
        }

        router
    } else {
        Router::new()
    };

    // Clone Arc references before moving them into connection_point_router tuple
    // These clones will be used for the mediator router layers
    let connection_point_store_for_mediator = connection_point_store.clone();
    let listener_manager_for_mediator = listener_manager.clone();

    // Create connection point routes if gateway, connection point, and mediator stores are provided
    let connection_point_router =
        if let (Some(pub_store), Some(gw_store), Some(med_store), Some(listener_mgr), Some(msg_store)) =
            (connection_point_store, gateway_store, mediator_store.clone(), listener_manager, message_store)
        {
            let router = Router::new()
                // DID web endpoint for connection points (standard did:web resolution path)
                .route(
                    "/connection-points/{cp_id}/did.json",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // did:webvh log endpoint for connection points
                .route(
                    "/connection-points/{cp_id}/did.jsonl",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // Also support .well-known variant for compatibility
                .route(
                    "/.well-known/connection-points/{cp_id}/did.json",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                // did:webvh log endpoint (.well-known variant)
                .route(
                    "/.well-known/connection-points/{cp_id}/did.jsonl",
                    get(crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                        crate::gateways::FileSystemConnectionPointStore,
                    >),
                )
                .merge(connection_point_read_routes(&rbac_guard))
                .route(
                    "/v1/connection-points",
                    rbac_guard.gate(
                        post(
                            crate::gateways::connection_points::handlers::create_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::gateways::FileSystemGatewayStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        Feature::ConnectionPointsEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}",
                    rbac_guard.gate(
                        put(crate::gateways::connection_points::handlers::update_connection_point::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        Feature::ConnectionPointsEdit,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}",
                    rbac_guard.gate(
                        delete(
                            crate::gateways::connection_points::handlers::delete_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                        Feature::ConnectionPointsDelete,
                    ),
                )
                .route(
                    "/v1/connection-points/{id}/exposed-surfaces",
                    rbac_guard.gate(
                        put(crate::gateways::connection_points::handlers::update_connection_point_exposed_channels::<
                            crate::gateways::FileSystemConnectionPointStore,
                        >),
                        Feature::ConnectionPointsEdit,
                    ),
                )
                .merge(connection_point_inbox_routes(&rbac_guard))
                .route(
                    "/v1/connection-points/{id}/reconnect",
                    rbac_guard.gate(
                        post(
                            crate::gateways::connection_points::handlers::reconnect_connection_point::<
                                crate::gateways::FileSystemConnectionPointStore,
                                crate::mediators::FileSystemMediatorStore,
                            >,
                        ),
                        Feature::ConnectionPointsEdit,
                    ),
                )
                .layer(Extension(pub_store))
                .layer(Extension(gw_store))
                .layer(Extension(med_store))
                .layer(Extension(state.vc_issuer.clone()))
                .layer(Extension(state.config.clone()))
                .layer(Extension(state.bootstrap_config.clone()))
                .layer(Extension(state.network_config.clone()))
                .layer(Extension(listener_mgr))
                .layer(Extension(msg_store))
                .layer(Extension(notification_store.clone()))
                .layer(Extension(integration_storage.clone()))
                .layer(Extension(agent_surface_store.clone()));

            #[cfg(feature = "didwebvh")]
            let router = router
                .layer(Extension(
                    state
                        .didwebvh_log_storage
                        .clone(),
                ))
                .layer(Extension(
                    state
                        .didwebvh_identity_store
                        .clone(),
                ));

            router
        } else {
            Router::new()
        };

    // Create mediator routes if store is provided
    let mediator_router = if let Some(store) = mediator_store {
        Router::new()
            .route(
                "/v1/mediators",
                get(crate::mediators::handlers::list_mediators::<crate::mediators::FileSystemMediatorStore>),
            )
            .route(
                "/v1/mediators",
                rbac_guard.gate(
                    post(crate::mediators::handlers::create_mediator::<crate::mediators::FileSystemMediatorStore>),
                    Feature::MediatorsEdit,
                ),
            )
            .route(
                "/v1/mediators/compatible",
                get(crate::mediators::handlers::list_compatible_mediators::<crate::mediators::FileSystemMediatorStore>),
            )
            .route(
                "/v1/mediators/check-auth",
                rbac_guard.gate(post(crate::mediators::handlers::check_auth_compatibility), Feature::MediatorsEdit),
            )
            .route(
                "/v1/mediators/{id}",
                get(crate::mediators::handlers::get_mediator::<crate::mediators::FileSystemMediatorStore>),
            )
            .route(
                "/v1/mediators/{id}",
                rbac_guard.gate(
                    put(crate::mediators::handlers::update_mediator::<crate::mediators::FileSystemMediatorStore>),
                    Feature::MediatorsEdit,
                ),
            )
            .route(
                "/v1/mediators/{id}",
                rbac_guard.gate(
                    delete(crate::mediators::handlers::delete_mediator::<crate::mediators::FileSystemMediatorStore>),
                    Feature::MediatorsDelete,
                ),
            )
            .route(
                "/v1/mediators/{id}/trust-ping",
                rbac_guard.gate(
                    post(crate::mediators::handlers::trust_ping_mediator::<crate::mediators::FileSystemMediatorStore>),
                    Feature::MediatorsEdit,
                ),
            )
            .layer(Extension(store))
            .layer(Extension(state.vc_issuer.clone()))
            .layer(Extension(notification_store.clone()))
            .layer(Extension(connection_point_store_for_mediator.clone()))
            .layer(Extension(listener_manager_for_mediator.clone()))
    } else {
        Router::new()
    };

    // Create integration routes if storage is provided
    let integration_router = if let Some(ref storage) = integration_storage {
        crate::storage::integration_handlers::integration_api_router(
            storage.clone(),
            state.config.clone(),
            state.bootstrap_config.clone(),
            secrets_store.clone(),
            crate::secrets::RevealSecretValues(
                state
                    .network_config
                    .secrets
                    .reveal_values,
            ),
            Some(&rbac_guard),
        )
    } else {
        Router::new()
    };

    // Create user integrations routes
    let user_integrations_router = Router::new()
        .route("/v1/users/integrations", get(crate::integrations::user_integrations_handlers::get_user_integrations))
        .route(
            "/v1/users/integrations",
            rbac_guard.gate(
                put(crate::integrations::user_integrations_handlers::update_user_integrations),
                Feature::IntegrationsEdit,
            ),
        )
        .layer(Extension(state.bootstrap_config.clone()))
        .layer(Extension(integration_storage.clone()));

    // Create identity integrations routes
    let identity_integrations_router = identity_integrations_routes(&rbac_guard)
        .layer(Extension(state.bootstrap_config.clone()))
        .layer(Extension(integration_storage.clone()));

    // Create notification routes if store is provided
    let notification_router = if let Some(store) = notification_store {
        let router = Router::new()
            .route(
                "/v1/notifications",
                get(crate::integrations::handlers::list_notifications::<
                    crate::integrations::FileSystemNotificationStore,
                >),
            )
            .route(
                "/v1/notifications",
                rbac_guard.gate(
                    post(
                        crate::integrations::handlers::create_notification::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                    Feature::NotificationsEdit,
                ),
            )
            .route(
                "/v1/notifications/{id}",
                get(
                    crate::integrations::handlers::get_notification::<crate::integrations::FileSystemNotificationStore>,
                ),
            )
            .route(
                "/v1/notifications/{id}",
                rbac_guard.gate(
                    put(crate::integrations::handlers::update_notification::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                    Feature::NotificationsEdit,
                ),
            )
            .route(
                "/v1/notifications/{id}",
                rbac_guard.gate(
                    delete(
                        crate::integrations::handlers::delete_notification::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                    Feature::NotificationsDelete,
                ),
            )
            .route(
                "/v1/notifications/unread/count",
                get(
                    crate::integrations::handlers::get_unread_count::<crate::integrations::FileSystemNotificationStore>,
                ),
            )
            .route(
                "/v1/notifications/user-welcome-template",
                get(crate::integrations::handlers::get_user_welcome_template::<
                    crate::integrations::FileSystemNotificationStore,
                >),
            )
            .route(
                "/v1/notifications/user-welcome-template",
                rbac_guard.gate(
                    put(crate::integrations::handlers::set_user_welcome_template::<
                        crate::integrations::FileSystemNotificationStore,
                    >),
                    Feature::NotificationsEdit,
                ),
            )
            .route(
                "/v1/notifications/send-welcome",
                rbac_guard.gate(
                    post(
                        crate::integrations::handlers::send_user_welcome::<
                            crate::integrations::FileSystemNotificationStore,
                        >,
                    ),
                    Feature::NotificationsEdit,
                ),
            )
            .layer(Extension(store));

        // Add session manager if available (works for both Passkey and SAML modes)
        if let Some(sess_mgr) = &session_manager_for_manager {
            router.layer(Extension(sess_mgr.clone()))
        } else {
            router
        }
    } else {
        Router::new()
    };

    let cors_origins = state
        .network_config
        .cors
        .clone();
    let origins = cors_origins
        .into_iter()
        .map(|origin| {
            origin
                .parse::<HeaderValue>()
                .unwrap()
        })
        .collect::<Vec<HeaderValue>>();

    // Merge the routers - API routes first to ensure they match before fallback
    let didwebvh_router = create_didwebvh_router(state.clone(), rbac_guard.clone());

    // Build the session manager extension for global auth middleware
    let session_mgr_for_global_auth: Option<std::sync::Arc<crate::auth::session::SessionManager>> =
        session_manager_for_manager.clone();

    let mut app = Router::new()
        .merge(didwebvh_router)
        .merge(gateway_router)
        .merge(connection_point_router)
        .merge(mediator_router)
        .merge(integration_router)
        .merge(user_integrations_router)
        .merge(identity_integrations_router)
        .merge(notification_router)
        .merge(auth_manager_router)
        .merge(oidc_provider_router)
        .merge(oauth_identifier_router)
        .merge(identity_router)
        .merge(auth_router)
        .merge(dashboard_router)
        .layer(Extension(terms_manager.clone()))
        .layer(axum::middleware::from_fn(crate::observability::trace_http_request));

    // Apply global session auth middleware when a session manager is available
    if let Some(sess_mgr) = session_mgr_for_global_auth {
        info!("Global session auth middleware enabled for all protected API routes");
        // Expose the caller's RBAC context (user store + config) to handlers that
        // gate conditionally on a permission beyond their route feature — e.g.
        // editing a policy that is enforced appliance-wide requires `policies.publish`.
        app = app.layer(Extension(rbac_config.clone()));
        if let Some(user_storage) = passkey_storage_for_manager.clone() {
            app = app.layer(Extension(user_storage));
        }
        app = app.layer(Extension(sess_mgr.clone()));
        let guard_state = crate::auth_manager::middleware::AuthGuardState::new(
            sess_mgr,
            passkey_storage_for_manager.clone(),
            terms_manager,
        )
        .with_pat_authenticator(pat_authenticator.clone())
        .with_trusted_tenant_header(trusted_tenant_header);
        app = app.layer(axum::middleware::from_fn_with_state(
            guard_state,
            crate::auth_manager::middleware::require_session_auth,
        ));
    } else {
        info!("No session manager available - global session auth middleware NOT enabled");
    }

    app.layer(
        CorsLayer::new()
            .allow_methods(Any)
            .allow_origin(AllowOrigin::async_predicate(
                |origin: HeaderValue, _request_parts: &RequestParts| async move {
                    if origins.is_empty() {
                        // Do not allow any origins if none are configured.
                        // This will only work for the same origin, i.e. served directly by Agent Stream.
                        return false;
                    }
                    debug!("Checking CORS origin: {:?} against allowed origins: {:?}", origin, origins);
                    origins.contains(&origin)
                },
            ))
            .allow_headers([AUTHORIZATION, CONTENT_TYPE]),
    )
    // Serve avatar files with proper MIME types and cache control
    .nest_service(
        "/avatars",
        Router::new()
            .fallback_service(
                ServeDir::new(avatars_path)
                    .precompressed_gzip()
                    .precompressed_br(),
            )
            .layer(SetResponseHeaderLayer::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            )),
    )
    // Serve uploaded dashboard assets (LLM provider logos, etc.) from storage.
    // Hardened against stored-XSS: uploads are raster-only, served with a
    // locked-down CSP and `nosniff` so a stray file can never execute scripts.
    .nest_service(
        "/uploads",
        Router::new()
            .fallback_service(
                ServeDir::new(uploads_path)
                    .precompressed_gzip()
                    .precompressed_br(),
            )
            .layer(SetResponseHeaderLayer::if_not_present(
                CACHE_CONTROL,
                HeaderValue::from_static("public, max-age=31536000, immutable"),
            ))
            .layer(SetResponseHeaderLayer::overriding(
                CONTENT_SECURITY_POLICY,
                HeaderValue::from_static("default-src 'none'; sandbox"),
            ))
            .layer(SetResponseHeaderLayer::overriding(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"))),
    )
}

/// Create a separate router for DID resolution routes at root level
/// These routes need to be at the root level for did:web resolution
pub fn create_did_router(state: IdentityApiState) -> Router {
    let router = Router::new()
        .route("/.well-known/did.json", get(handlers::serve_gateway_did_document))
        // Spec-required path: did:webvh:SCID:host → https://host/.well-known/did/did.jsonl
        .route("/.well-known/did/did.jsonl", get(handlers::serve_gateway_did_jsonl))
        // Legacy path kept for backwards compatibility
        .route("/.well-known/did.jsonl", get(handlers::serve_gateway_did_jsonl))
        .route("/surface/{surface_id}/did.json", get(handlers::serve_agent_did_document))
        .route("/surface/{surface_id}/did.jsonl", get(handlers::serve_surface_did_jsonl))
        .route(crate::identity::status_list::STATUS_LIST_PATH, get(handlers::serve_status_list));

    // NOTE: Root-level /{*path} catch-all for spec-standard DID-to-HTTPS URLs
    // is NOT added here — it would intercept all requests (static assets, API, etc.)
    // and break the SPA. Instead, DID catch-all is wired as a fallback wrapper
    // in proxy/server.rs, so it only fires when no other route matches.

    // Save bootstrap_config before state is moved into .with_state()

    router
        .layer(Extension(state.vc_issuer.clone()))
        .layer(Extension(state.bootstrap_config.clone()))
        .layer(Extension(state.network_config.clone()))
        .with_state(state)
}

#[cfg(feature = "didwebvh")]
pub fn create_didwebvh_router(
    state: IdentityApiState,
    rbac_guard: RbacGuard,
) -> Router {
    use crate::identity::didwebvh::DidWebVhApiState;
    use tracing::info;

    // Create DID:webvh API state if available
    if let (Some(identity_store), Some(log_storage), Some(base_url)) = (
        state
            .didwebvh_identity_store
            .clone(),
        state
            .didwebvh_log_storage
            .clone(),
        state
            .didwebvh_base_url
            .clone(),
    ) {
        let didwebvh_state = DidWebVhApiState {
            identity_store,
            log_storage,
            base_url,
        };

        info!("✓ DID:webvh API routes registered at /v1/identities");
        didwebvh_routes(didwebvh_state, rbac_guard)
    } else {
        tracing::debug!("DID:webvh API routes NOT registered - stores not available");
        Router::new()
    }
}

#[cfg(feature = "didwebvh")]
fn didwebvh_routes(
    didwebvh_state: crate::identity::didwebvh::DidWebVhApiState,
    rbac_guard: RbacGuard,
) -> Router {
    // Identity management reads and writes DID key material, so the whole
    // group requires identities.manage. DID resolution and log serving below
    // are public; DID verification needs a session but no permission.
    let management = Router::new()
        .route("/v1/identities", post(crate::identity::didwebvh::create_identity))
        .route("/v1/identities", get(crate::identity::didwebvh::list_identities))
        .route("/v1/identities/{id}", get(crate::identity::didwebvh::get_identity))
        .route("/v1/identities/{id}", delete(crate::identity::didwebvh::delete_identity))
        .route("/v1/identities/{id}/update", post(crate::identity::didwebvh::update_identity))
        .route("/v1/identities/{id}/rotate-keys", post(crate::identity::didwebvh::rotate_keys))
        .route("/v1/identities/{id}/transfer", post(crate::identity::didwebvh::transfer_ownership))
        .route("/v1/identities/{id}/history", get(crate::identity::didwebvh::get_identity_history))
        .route("/v1/identities/{id}/policy", put(crate::identity::didwebvh::update_policy_config))
        .route("/v1/identities/{id}/policy", get(crate::identity::didwebvh::get_policy_config))
        .layer(crate::auth_manager::middleware::require_feature(
            rbac_guard.storage,
            rbac_guard.rbac_config,
            Feature::IdentitiesManage,
        ));

    management
        .route("/v1/resolve", get(crate::identity::didwebvh::resolve_did))
        .route("/v1/verify/{did}", post(crate::identity::didwebvh::verify_identity))
        .route("/dids/{*path}", get(crate::identity::didwebvh::serve_did_log))
        .with_state(didwebvh_state)
}

#[cfg(not(feature = "didwebvh"))]
pub fn create_didwebvh_router(
    _state: IdentityApiState,
    _rbac_guard: RbacGuard,
) -> Router {
    Router::new()
}

#[cfg(test)]
mod pipe_connection_test_route_tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::{AuthGuardState, require_session_auth};
    use axum::{body::Body, http::Request, middleware};
    use chrono::Utc;
    use std::sync::Arc;
    use tower::ServiceExt;

    async fn auth_for(
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
    ) -> (RbacGuard, AuthGuardState, String, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            PasskeyStorage::new(
                temp.path()
                    .join("users")
                    .to_string_lossy()
                    .into_owned(),
                temp.path()
                    .join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let now = Utc::now();
        storage
            .save_user(&UserData {
                user_id: "admin-1".to_string(),
                username: "admin".to_string(),
                passkeys: Vec::new(),
                role,
                status: UserStatus::Approved,
                is_primary: true,
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
                deleted_at: None,
            })
            .await
            .unwrap();
        let sessions = Arc::new(crate::auth::session::SessionManager::new());
        let token = sessions
            .create_session("admin".to_string(), "admin-1".to_string())
            .await;
        let guard = RbacGuard::new(storage.clone(), Arc::new(rbac));
        (
            guard,
            AuthGuardState::new(sessions, Some(storage), std::sync::Arc::new(crate::terms::TermsManager::disabled())),
            token,
            temp,
        )
    }

    async fn integration_app(role: UserRole) -> (Router, String, String, Vec<tempfile::TempDir>) {
        integration_app_with_pat(role, None).await
    }

    const INTEGRATION_PAT: &str = "aspat_integrations";

    /// A management access token bound to the test user, limited to `scopes`.
    struct IntegrationPat {
        scopes: Option<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl crate::auth_manager::pat::PatAuthenticator for IntegrationPat {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<crate::auth_manager::pat::PatPrincipal> {
            (token == INTEGRATION_PAT).then(|| crate::auth_manager::pat::PatPrincipal {
                user_id: "admin-1".into(),
                scopes: self.scopes.clone(),
                token_id: "tok-test".into(),
                delegation_depth: 0,
                resource_scoped: false,
                resource_scope: None,
            })
        }
    }

    async fn integration_app_with_pat(
        role: UserRole,
        pat_scopes: Option<Option<Vec<String>>>,
    ) -> (Router, String, String, Vec<tempfile::TempDir>) {
        integration_app_with(role, crate::rbac::RbacConfig::default(), pat_scopes, true).await
    }

    async fn integration_app_with(
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
        pat_scopes: Option<Option<Vec<String>>>,
        reveal_secret_values: bool,
    ) -> (Router, String, String, Vec<tempfile::TempDir>) {
        let (guard, auth, token, users) = auth_for(role, rbac).await;
        let auth =
            auth.with_pat_authenticator(pat_scopes.map(|scopes| {
                Arc::new(IntegrationPat { scopes }) as Arc<dyn crate::auth_manager::pat::PatAuthenticator>
            }));
        let store_dir = tempfile::tempdir().unwrap();
        let triggers = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            crate::storage::IntegrationStorage::new(store_dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        let integration = crate::storage::Integration::new(
            "mailer".to_string(),
            String::new(),
            "email".to_string(),
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": "smtp-pass-123" }),
            serde_json::json!({}),
            "active".to_string(),
            Some("general".to_string()),
        );
        storage
            .save(&integration)
            .await
            .unwrap();
        let bootstrap: crate::config::BootstrapConfig = serde_json::from_value(serde_json::json!({
            "tls": { "cert_path": "cert.pem", "key_path": "key.pem" },
            "storage_paths": { "integration_triggers": triggers.path().to_str().unwrap() },
        }))
        .unwrap();
        let app = crate::storage::integration_handlers::integration_api_router(
            storage,
            Arc::new(crate::config::GatewayConfig::default_config()),
            Arc::new(bootstrap),
            Some(Arc::new(crate::secrets::store::memory::MemorySecretsStore::with(vec![
                crate::secrets::store::memory::secret("id-smtp", "smtp-key", "smtp-pass-456", None),
            ]))),
            crate::secrets::RevealSecretValues(reveal_secret_values),
            Some(&guard),
        )
        .layer(middleware::from_fn_with_state(auth, require_session_auth));
        (app, token, integration.id, vec![users, store_dir, triggers])
    }

    async fn send(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
        body: &str,
    ) -> (axum::http::StatusCode, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .header("content-type", "application/json")
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn integration_reads_and_test_are_refused_to_the_base_role() {
        let (app, token, id, _dirs) = integration_app(UserRole::User).await;
        let test_body = format!(r#"{{"type":"email","configuration":{{}},"content":{{}},"integration_id":"{id}"}}"#);

        let trigger_body = r#"{"subject":"s","message":"m"}"#.to_string();
        let trigger_multiple_body = format!(r#"{{"integration_ids":["{id}"],"subject":"s","message":"m"}}"#);

        for (method, path, body) in [
            ("GET", "/v1/integrations".to_string(), String::new()),
            ("GET", format!("/v1/integrations/{id}"), String::new()),
            ("POST", "/v1/integrations/test".to_string(), test_body),
            ("POST", format!("/v1/integrations/{id}/trigger"), trigger_body),
            ("POST", "/v1/integrations/trigger-multiple".to_string(), trigger_multiple_body),
        ] {
            let (status, response) = send(&app, method, &path, &token, &body).await;
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{method} {path}");
            assert!(!response.contains("smtp-pass-123"));
        }
    }

    #[tokio::test]
    async fn integration_reads_answer_an_administrator_without_credentials() {
        let (app, token, id, _dirs) = integration_app(UserRole::Administrator).await;

        for path in ["/v1/integrations".to_string(), format!("/v1/integrations/{id}")] {
            let (status, response) = send(&app, "GET", &path, &token, "").await;
            assert_eq!(status, axum::http::StatusCode::OK, "{path}");
            assert!(response.contains("smtp.example.com"), "{path}: {response}");
            assert!(!response.contains("smtp-pass-123"), "{path}: {response}");
            assert!(!response.contains("smtp_password"), "{path}: {response}");
        }
    }

    #[tokio::test]
    async fn integration_reads_by_access_token_follow_the_role_and_the_scope() {
        let cases = [
            ("base user", UserRole::User, None, axum::http::StatusCode::FORBIDDEN),
            (
                "administrator scoped without integrations.view",
                UserRole::Administrator,
                Some(vec!["pipes.edit".to_string()]),
                axum::http::StatusCode::FORBIDDEN,
            ),
            (
                "administrator scoped to integrations.view",
                UserRole::Administrator,
                Some(vec!["integrations.view".to_string()]),
                axum::http::StatusCode::OK,
            ),
        ];

        for (case, role, scopes, expected) in cases {
            let (app, _token, id, _dirs) = integration_app_with_pat(role, Some(scopes)).await;
            for path in ["/v1/integrations".to_string(), format!("/v1/integrations/{id}")] {
                let (status, response) = send(&app, "GET", &path, INTEGRATION_PAT, "").await;
                assert_eq!(status, expected, "{case}: GET {path}");
                assert!(!response.contains("smtp-pass-123"), "{case}: {response}");
            }
        }
    }

    #[tokio::test]
    async fn integration_triggers_require_integrations_edit() {
        let (app, _token, id, _dirs) =
            integration_app_with_pat(UserRole::Administrator, Some(Some(vec!["integrations.view".to_string()]))).await;
        let (status, _) = send(
            &app,
            "POST",
            &format!("/v1/integrations/{id}/trigger"),
            INTEGRATION_PAT,
            r#"{"subject":"s","message":"m"}"#,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN);

        let (app, token, _id, _dirs) = integration_app(UserRole::Administrator).await;
        let (status, _) =
            send(&app, "POST", "/v1/integrations/missing/trigger", &token, r#"{"subject":"s","message":"m"}"#).await;
        assert_eq!(status, axum::http::StatusCode::NOT_FOUND, "an administrator passes the gate");
    }

    const PAIRING_BODY: &str = r#"{"name":"mailer","description":"","type":"email","category":"general","configuration":{"smtp_host":"93.184.216.34","smtp_password_secret_id":"smtp-key"},"content":{},"status":"active"}"#;

    #[tokio::test]
    async fn a_session_user_needs_secrets_view_to_send_a_stored_secret() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("integrations.edit".to_string(), "user".to_string());
        let (app, token, _id, _dirs) = integration_app_with(UserRole::User, rbac, None, true).await;

        let (status, response) = send(&app, "POST", "/v1/integrations", &token, PAIRING_BODY).await;

        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{response}");
        assert!(response.contains("secrets.view"), "{response}");
    }

    #[tokio::test]
    async fn no_one_sends_a_stored_secret_somewhere_new_while_values_are_not_revealed() {
        let (app, token, _id, _dirs) =
            integration_app_with(UserRole::Administrator, crate::rbac::RbacConfig::default(), None, false).await;

        let (status, response) = send(&app, "POST", "/v1/integrations", &token, PAIRING_BODY).await;
        assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{response}");

        let (status, response) = send(
            &app,
            "POST",
            "/v1/integrations",
            &token,
            r#"{"name":"relay","description":"","type":"email","category":"general","configuration":{"smtp_host":"93.184.216.34"},"content":{},"status":"active"}"#,
        )
        .await;
        assert_eq!(status, axum::http::StatusCode::CREATED, "{response}");
    }

    #[tokio::test]
    async fn an_integration_token_needs_secrets_view_to_send_a_stored_secret() {
        let body = PAIRING_BODY;
        for (scopes, expected) in [
            (vec!["integrations.edit"], axum::http::StatusCode::FORBIDDEN),
            (vec!["integrations.edit", "secrets.view"], axum::http::StatusCode::CREATED),
        ] {
            let scopes = scopes
                .into_iter()
                .map(str::to_string)
                .collect();
            let (app, _token, _id, _dirs) = integration_app_with_pat(UserRole::Administrator, Some(Some(scopes))).await;
            let (status, response) = send(&app, "POST", "/v1/integrations", INTEGRATION_PAT, body).await;
            assert_eq!(status, expected, "{response}");
            assert!(!response.contains("smtp-pass-456"), "{response}");
        }
    }

    #[tokio::test]
    async fn integration_sends_follow_integrations_edit_and_need_a_session() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("integrations.edit".to_string(), "poweruser".to_string());
        let (app, token, _id, _dirs) = integration_app_with(UserRole::PowerUser, rbac, None, true).await;
        let sends = [
            (
                "/v1/integrations/test",
                r#"{"type":"unknown","configuration":{},"content":{}}"#,
                axum::http::StatusCode::BAD_REQUEST,
            ),
            ("/v1/integrations/missing/trigger", r#"{"subject":"s","message":"m"}"#, axum::http::StatusCode::NOT_FOUND),
            (
                "/v1/integrations/trigger-multiple",
                r#"{"integration_ids":["missing"],"subject":"s","message":"m"}"#,
                axum::http::StatusCode::NOT_FOUND,
            ),
        ];

        for (path, body, answer) in sends {
            let (status, _) = send(&app, "POST", path, &token, body).await;
            assert_eq!(status, answer, "a role granted integrations.edit: {path}");

            let (status, _) = send(&app, "POST", path, "", body).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "no session: {path}");
        }
    }

    #[tokio::test]
    async fn pre_save_probe_rejects_stored_secret_reference() {
        let (guard, auth, token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = create_pre_save_llm_connection_test_router(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth));
        let request = Request::post("/v1/pipes/test-llm-connection")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(
                r#"{"provider":"openai","endpoint":"https://attacker.example","secret_id":"provider-key"}"#,
            ))
            .unwrap();

        let response = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn pre_save_probe_allows_credential_free_request() {
        let (guard, auth, token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = create_pre_save_llm_connection_test_router(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth));
        let request = Request::post("/v1/pipes/test-llm-connection")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(r#"{"provider":"unsupported","endpoint":""}"#))
            .unwrap();

        let response = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn pre_save_probe_requires_pipes_edit_permission() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("pipes.edit".to_string(), "administrator".to_string());
        let (guard, auth, token, _temp) = auth_for(UserRole::User, rbac).await;
        let app = create_pre_save_llm_connection_test_router(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth));
        let request = Request::post("/v1/pipes/test-llm-connection")
            .header("content-type", "application/json")
            .header("authorization", format!("Bearer {token}"))
            .body(Body::from(r#"{"provider":"ollama","endpoint":""}"#))
            .unwrap();

        let response = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn pre_save_probe_requires_authentication() {
        let (guard, auth, _token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = create_pre_save_llm_connection_test_router(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth));
        let request = Request::post("/v1/pipes/test-llm-connection")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"provider":"ollama","endpoint":""}"#))
            .unwrap();

        let response = app
            .oneshot(request)
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[cfg(feature = "didwebvh")]
    async fn identity_app(role: UserRole) -> (Router, String, tempfile::TempDir, tempfile::TempDir) {
        identity_app_with(role, crate::rbac::RbacConfig::default()).await
    }

    #[cfg(feature = "didwebvh")]
    async fn identity_app_with(
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
    ) -> (Router, String, tempfile::TempDir, tempfile::TempDir) {
        let (guard, auth, token, temp) = auth_for(role, rbac).await;
        let stores = tempfile::tempdir().unwrap();
        let didwebvh_state = crate::identity::didwebvh::DidWebVhApiState {
            identity_store: Arc::new(
                crate::identity::didwebvh::FileSystemDidWebVhIdentityStore::new_with_encryption(
                    stores
                        .path()
                        .join("identities"),
                    None,
                )
                .await
                .unwrap(),
            ),
            log_storage: Arc::new(crate::storage::FileDidLogStorage::new(stores.path().join("logs"))),
            base_url: "https://example.com".to_string(),
        };
        let app =
            didwebvh_routes(didwebvh_state, guard).layer(middleware::from_fn_with_state(auth, require_session_auth));
        (app, token, temp, stores)
    }

    #[cfg(feature = "didwebvh")]
    async fn identity_status(
        app: &Router,
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> axum::http::StatusCode {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        app.clone()
            .oneshot(
                request
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap()
            .status()
    }

    #[cfg(feature = "didwebvh")]
    fn identity_management_routes() -> Vec<(&'static str, String)> {
        let id = uuid::Uuid::new_v4();
        vec![
            ("POST", "/v1/identities".to_string()),
            ("GET", "/v1/identities".to_string()),
            ("GET", format!("/v1/identities/{id}")),
            ("DELETE", format!("/v1/identities/{id}")),
            ("POST", format!("/v1/identities/{id}/update")),
            ("POST", format!("/v1/identities/{id}/rotate-keys")),
            ("POST", format!("/v1/identities/{id}/transfer")),
            ("GET", format!("/v1/identities/{id}/history")),
            ("PUT", format!("/v1/identities/{id}/policy")),
            ("GET", format!("/v1/identities/{id}/policy")),
        ]
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn identity_management_routes_reject_base_user() {
        let (app, token, _temp, _stores) = identity_app(UserRole::User).await;
        for (method, path) in identity_management_routes() {
            assert_eq!(
                identity_status(&app, method, &path, Some(&token)).await,
                axum::http::StatusCode::FORBIDDEN,
                "{method} {path} must require identities.manage"
            );
        }
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn identity_management_routes_reject_unauthenticated_caller() {
        let (app, _token, _temp, _stores) = identity_app(UserRole::Administrator).await;
        for (method, path) in identity_management_routes() {
            assert_eq!(
                identity_status(&app, method, &path, None).await,
                axum::http::StatusCode::UNAUTHORIZED,
                "{method} {path} must require a session"
            );
        }
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn identity_management_routes_admit_administrator() {
        let (app, token, _temp, _stores) = identity_app(UserRole::Administrator).await;
        assert_eq!(identity_status(&app, "GET", "/v1/identities", Some(&token)).await, axum::http::StatusCode::OK);
        assert_eq!(
            identity_status(&app, "GET", &format!("/v1/identities/{}", uuid::Uuid::new_v4()), Some(&token)).await,
            axum::http::StatusCode::NOT_FOUND
        );
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn did_publication_routes_stay_public() {
        let (app, _token, _temp, _stores) = identity_app(UserRole::User).await;
        for (method, path) in [("GET", "/v1/resolve?did=did:webvh:missing"), ("GET", "/dids/agents/missing/did.jsonl")]
        {
            let status = identity_status(&app, method, path, None).await;
            assert!(
                status != axum::http::StatusCode::UNAUTHORIZED && status != axum::http::StatusCode::FORBIDDEN,
                "{method} {path} must not be gated, got {status}"
            );
        }
    }

    #[cfg(feature = "didwebvh")]
    #[tokio::test]
    async fn identity_management_routes_ignore_identity_issue() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("identity.issue".to_string(), "user".to_string());
        let (app, token, _temp, _stores) = identity_app_with(UserRole::User, rbac).await;
        for (method, path) in identity_management_routes() {
            assert_eq!(
                identity_status(&app, method, &path, Some(&token)).await,
                axum::http::StatusCode::FORBIDDEN,
                "{method} {path} must not be reachable through identity.issue"
            );
        }
    }

    #[tokio::test]
    async fn identity_integrations_read_requires_identities_manage() {
        let (guard, auth, token, _temp) = auth_for(UserRole::User, crate::rbac::RbacConfig::default()).await;
        let app: Router =
            identity_integrations_routes(&guard).layer(middleware::from_fn_with_state(auth, require_session_auth));
        let request = |token: Option<&str>| {
            let mut request = Request::get("/v1/identities/integrations");
            if let Some(token) = token {
                request = request.header("authorization", format!("Bearer {token}"));
            }
            request
                .body(Body::empty())
                .unwrap()
        };

        let denied = app
            .clone()
            .oneshot(request(Some(&token)))
            .await
            .unwrap();
        assert_eq!(denied.status(), axum::http::StatusCode::FORBIDDEN);
        let anonymous = app
            .oneshot(request(None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    /// State that panics when a request reaches a handler reading the identity
    /// state, so a test can tell whether the RBAC gate let the request through.
    #[derive(Clone)]
    struct GateOnly;

    impl axum::extract::FromRef<GateOnly> for IdentityApiState {
        fn from_ref(_: &GateOnly) -> Self {
            panic!("the RBAC gate let the request reach a handler")
        }
    }

    const PIPE_TEMPLATE_ROUTES: [(&str, &str, &str); 7] = [
        ("GET", "/v1/pipe-templates", "pipes.view"),
        ("POST", "/v1/pipe-templates", "pipes.edit"),
        ("POST", "/v1/pipe-templates/import", "pipes.edit"),
        ("GET", "/v1/pipe-templates/template-1", "pipes.view"),
        ("PUT", "/v1/pipe-templates/template-1", "pipes.edit"),
        ("DELETE", "/v1/pipe-templates/template-1", "pipes.delete"),
        ("GET", "/v1/pipe-templates/template-1/export", "pipes.view"),
    ];

    fn pipe_template_request(
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request
            .body(Body::from(r#"{"id":"/tmp/escaped","name":"Escaped"}"#))
            .unwrap()
    }

    #[tokio::test]
    async fn each_pipe_template_route_requires_its_pipe_permission() {
        for (method, path, permission) in PIPE_TEMPLATE_ROUTES {
            let mut rbac = crate::rbac::RbacConfig::default();
            rbac.permissions
                .insert(permission.to_string(), "administrator".to_string());
            let (guard, auth, token, _temp) = auth_for(UserRole::User, rbac).await;
            let app = create_pipe_template_router::<GateOnly>(guard)
                .layer(middleware::from_fn_with_state(auth, require_session_auth))
                .with_state(GateOnly);

            let response = app
                .oneshot(pipe_template_request(method, path, Some(&token)))
                .await
                .unwrap();

            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{method} {path} without {permission}");
        }
    }

    #[tokio::test]
    async fn a_user_with_default_permissions_passes_every_pipe_template_gate() {
        for (method, path, _) in PIPE_TEMPLATE_ROUTES {
            let (guard, auth, token, _temp) = auth_for(UserRole::User, crate::rbac::RbacConfig::default()).await;
            let app = create_pipe_template_router::<GateOnly>(guard)
                .layer(middleware::from_fn_with_state(auth, require_session_auth))
                .with_state(GateOnly);

            let outcome = tokio::spawn(app.oneshot(pipe_template_request(method, path, Some(&token)))).await;

            let panic = match outcome {
                Err(error) if error.is_panic() => error.into_panic(),
                Err(error) => panic!("{method} {path}: {error}"),
                Ok(response) => panic!("{method} {path} stopped at the gate with {:?}", response.map(|r| r.status())),
            };
            let message = panic
                .downcast_ref::<&str>()
                .copied()
                .unwrap_or_default();
            assert!(message.contains("reach a handler"), "{method} {path} panicked: {message:?}");
        }
    }

    #[tokio::test]
    async fn pipe_template_routes_require_authentication() {
        let (guard, auth, _token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = create_pipe_template_router::<GateOnly>(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth))
            .with_state(GateOnly);

        for (method, path, _) in PIPE_TEMPLATE_ROUTES {
            let response = app
                .clone()
                .oneshot(pipe_template_request(method, path, None))
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    const METRICS_CONFIG_ROUTES: [(&str, &str); 4] = [
        ("GET", "/v1/metrics/config"),
        ("PUT", "/v1/metrics/config"),
        ("POST", "/v1/metrics/truncate"),
        ("POST", "/v1/metrics/test-connection"),
    ];

    fn metrics_config_app(
        guard: RbacGuard,
        auth: AuthGuardState,
    ) -> Router {
        create_metrics_config_router::<GateOnly>(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth))
            .with_state(GateOnly)
    }

    fn metrics_config_request(
        method: &str,
        path: &str,
        token: Option<&str>,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request
            .body(Body::from(r#"{"endpoint":"ftp://collector.invalid"}"#))
            .unwrap()
    }

    #[tokio::test]
    async fn base_and_power_users_are_refused_every_metrics_config_route() {
        for role in [UserRole::User, UserRole::PowerUser] {
            for (method, path) in METRICS_CONFIG_ROUTES {
                let (guard, auth, token, _temp) = auth_for(role.clone(), crate::rbac::RbacConfig::default()).await;

                let response = metrics_config_app(guard, auth)
                    .oneshot(metrics_config_request(method, path, Some(&token)))
                    .await
                    .unwrap();

                assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{role:?} {method} {path}");
            }
        }
    }

    #[tokio::test]
    async fn metrics_config_routes_require_authentication() {
        let (guard, auth, _token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = metrics_config_app(guard, auth);

        for (method, path) in METRICS_CONFIG_ROUTES {
            let response = app
                .clone()
                .oneshot(metrics_config_request(method, path, None))
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    /// Send `request` and report whether it got past the RBAC gate to a
    /// handler (which panics on reading the `GateOnly` state).
    async fn reaches_handler(
        app: Router,
        request: Request<Body>,
    ) -> bool {
        match tokio::spawn(app.oneshot(request)).await {
            Err(error) if error.is_panic() => {
                let panic = error.into_panic();
                let message = panic
                    .downcast_ref::<&str>()
                    .copied()
                    .unwrap_or_default();
                assert!(message.contains("reach a handler"), "unexpected panic: {message:?}");
                true
            }
            Err(error) => panic!("{error}"),
            Ok(_) => false,
        }
    }

    #[tokio::test]
    async fn an_administrator_passes_every_metrics_config_gate() {
        for (method, path) in METRICS_CONFIG_ROUTES {
            let (guard, auth, token, _temp) =
                auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
            let app = metrics_config_app(guard, auth);

            assert!(
                reaches_handler(app, metrics_config_request(method, path, Some(&token))).await,
                "{method} {path} stopped at the gate"
            );
        }
    }

    #[tokio::test]
    async fn metrics_configuration_follows_settings_edit() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("settings.edit".to_string(), "poweruser".to_string());
        let (guard, auth, token, _temp) = auth_for(UserRole::PowerUser, rbac).await;

        assert!(
            reaches_handler(
                metrics_config_app(guard, auth),
                metrics_config_request("POST", "/v1/metrics/test-connection", Some(&token))
            )
            .await
        );
    }

    fn logs_request(
        method: &str,
        path: &str,
        token: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    }

    fn logs_app(
        guard: RbacGuard,
        auth: AuthGuardState,
    ) -> Router {
        create_logs_router::<GateOnly>(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth))
            .with_state(GateOnly)
    }

    #[tokio::test]
    async fn base_and_power_users_can_neither_download_nor_truncate_the_log() {
        for role in [UserRole::User, UserRole::PowerUser] {
            for (method, path) in [("GET", "/v1/logs/download"), ("POST", "/v1/logs/truncate")] {
                let (guard, auth, token, _temp) = auth_for(role.clone(), crate::rbac::RbacConfig::default()).await;

                let response = logs_app(guard, auth)
                    .oneshot(logs_request(method, path, &token))
                    .await
                    .unwrap();

                assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{role:?} {method} {path}");
            }
        }
    }

    #[tokio::test]
    async fn reading_the_log_does_not_allow_truncating_it() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("logs.view".to_string(), "user".to_string());

        let (guard, auth, token, _temp) = auth_for(UserRole::User, rbac.clone()).await;
        let truncate = logs_app(guard, auth)
            .oneshot(logs_request("POST", "/v1/logs/truncate", &token))
            .await
            .unwrap();
        assert_eq!(truncate.status(), axum::http::StatusCode::FORBIDDEN);

        let (guard, auth, token, _temp) = auth_for(UserRole::User, rbac).await;
        assert!(reaches_handler(logs_app(guard, auth), logs_request("GET", "/v1/logs/download", &token)).await);
    }

    #[tokio::test]
    async fn an_administrator_passes_both_log_gates() {
        for (method, path) in [("GET", "/v1/logs/download"), ("POST", "/v1/logs/truncate")] {
            let (guard, auth, token, _temp) =
                auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;

            assert!(
                reaches_handler(logs_app(guard, auth), logs_request(method, path, &token)).await,
                "{method} {path}"
            );
        }
    }

    const INBOX_ROUTES: [(&str, &str, &str); 6] = [
        ("POST", "/v1/connection-points/cp-1/use", "connection_points.edit"),
        ("GET", "/v1/connection-points/cp-1/messages", "connection_points.edit"),
        ("GET", "/v1/connection-points/cp-1/messages/msg-1", "connection_points.edit"),
        ("POST", "/v1/connection-points/cp-1/messages/msg-1/read", "connection_points.edit"),
        ("DELETE", "/v1/connection-points/cp-1/messages/msg-1", "connection_points.delete"),
        ("GET", "/v1/connection-points/cp-1/messages/unread-count", "connection_points.edit"),
    ];

    /// Status of `method path` on one group of connection-point routes alone.
    /// A request that passes the gate reaches a handler whose stores are not
    /// wired here, so it fails with 500 rather than 401 or 403.
    async fn connection_point_route_status(
        routes: fn(&RbacGuard) -> Router,
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
        method: &str,
        path: &str,
        signed_in: bool,
    ) -> axum::http::StatusCode {
        let (guard, auth, token, _temp) = auth_for(role, rbac).await;
        let app = routes(&guard).layer(middleware::from_fn_with_state(auth, require_session_auth));
        let mut request = Request::builder()
            .method(method)
            .uri(path);
        if signed_in {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        app.oneshot(
            request
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .status()
    }

    async fn inbox_status(
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
        method: &str,
        path: &str,
        signed_in: bool,
    ) -> axum::http::StatusCode {
        connection_point_route_status(connection_point_inbox_routes, role, rbac, method, path, signed_in).await
    }

    fn passed_the_gate(status: axum::http::StatusCode) -> bool {
        status != axum::http::StatusCode::UNAUTHORIZED && status != axum::http::StatusCode::FORBIDDEN
    }

    #[tokio::test]
    async fn a_base_user_can_neither_read_nor_change_a_connection_point_inbox() {
        for (method, path, _) in INBOX_ROUTES {
            let status = inbox_status(UserRole::User, crate::rbac::RbacConfig::default(), method, path, true).await;
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn each_inbox_route_needs_its_connection_point_permission() {
        for (method, path, permission) in INBOX_ROUTES {
            let default_status =
                inbox_status(UserRole::PowerUser, crate::rbac::RbacConfig::default(), method, path, true).await;
            assert!(passed_the_gate(default_status), "{method} {path}: {default_status}");

            let mut rbac = crate::rbac::RbacConfig::default();
            rbac.permissions
                .insert(permission.to_string(), "administrator".to_string());
            let without = inbox_status(UserRole::PowerUser, rbac, method, path, true).await;
            assert_eq!(without, axum::http::StatusCode::FORBIDDEN, "{method} {path} without {permission}");
        }
    }

    #[tokio::test]
    async fn the_connection_point_inbox_needs_a_session() {
        for (method, path, _) in INBOX_ROUTES {
            let status =
                inbox_status(UserRole::Administrator, crate::rbac::RbacConfig::default(), method, path, false).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    const CONNECTION_POINT_READS: [&str; 4] = [
        "/v1/connection-points",
        "/v1/connection-points/cp-1",
        "/v1/connection-points/cp-1/metrics",
        "/v1/gateways/gw-1/connection-points",
    ];

    async fn read_status(
        role: UserRole,
        rbac: crate::rbac::RbacConfig,
        path: &str,
        signed_in: bool,
    ) -> axum::http::StatusCode {
        connection_point_route_status(connection_point_read_routes, role, rbac, "GET", path, signed_in).await
    }

    #[tokio::test]
    async fn every_role_reads_connection_points_by_default() {
        for role in [UserRole::User, UserRole::PowerUser, UserRole::Administrator] {
            for path in CONNECTION_POINT_READS {
                let status = read_status(role.clone(), crate::rbac::RbacConfig::default(), path, true).await;
                assert!(passed_the_gate(status), "{role:?} GET {path}: {status}");
            }
        }
    }

    #[tokio::test]
    async fn connection_point_reads_need_connection_points_view() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("connection_points.view".to_string(), "administrator".to_string());
        for path in CONNECTION_POINT_READS {
            let status = read_status(UserRole::User, rbac.clone(), path, true).await;
            assert_eq!(status, axum::http::StatusCode::FORBIDDEN, "GET {path}");
        }
    }

    #[tokio::test]
    async fn connection_point_reads_need_a_session() {
        for path in CONNECTION_POINT_READS {
            let status = read_status(UserRole::Administrator, crate::rbac::RbacConfig::default(), path, false).await;
            assert_eq!(status, axum::http::StatusCode::UNAUTHORIZED, "GET {path}");
        }
    }

    fn agents_app(
        guard: RbacGuard,
        auth: AuthGuardState,
    ) -> Router {
        create_agents_router::<GateOnly>(guard)
            .layer(middleware::from_fn_with_state(auth, require_session_auth))
            .with_state(GateOnly)
    }

    fn agents_request(token: Option<&str>) -> Request<Body> {
        let mut request = Request::get("/v1/agents");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn the_agents_list_needs_surfaces_capture() {
        let (guard, auth, token, _temp) = auth_for(UserRole::User, crate::rbac::RbacConfig::default()).await;
        let refused = agents_app(guard, auth)
            .oneshot(agents_request(Some(&token)))
            .await
            .unwrap();
        assert_eq!(refused.status(), axum::http::StatusCode::FORBIDDEN);

        let (guard, auth, _token, _temp) = auth_for(UserRole::PowerUser, crate::rbac::RbacConfig::default()).await;
        let anonymous = agents_app(guard, auth)
            .oneshot(agents_request(None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), axum::http::StatusCode::UNAUTHORIZED);

        let (guard, auth, token, _temp) = auth_for(UserRole::PowerUser, crate::rbac::RbacConfig::default()).await;
        assert!(reaches_handler(agents_app(guard, auth), agents_request(Some(&token))).await);
    }

    async fn dashboard_state(dir: &std::path::Path) -> (crate::observability::DashboardState, tempfile::TempDir) {
        let log_dir = dir.join("logs");
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(
            log_dir.join("agent-stream.log"),
            "{\"timestamp\":\"2026-10-20T10:00:00Z\",\"level\":\"INFO\",\"message\":\"secret log line\"}\n",
        )
        .unwrap();
        let mut config = crate::config::GatewayConfig::default_config();
        config.logging.log_directory = Some(
            log_dir
                .to_string_lossy()
                .into_owned(),
        );
        config.surfaces[0].surface_id = "surface-1".to_string();
        let config = Arc::new(config);
        let bootstrap: crate::config::BootstrapConfig = serde_json::from_value(serde_json::json!({
            "tls": { "cert_path": "cert.pem", "key_path": "key.pem" },
        }))
        .unwrap();
        let network_config: crate::config::NetworkConfig = serde_json::from_value(serde_json::json!({
            "did": { "domain": "gateway.example.com" },
            "webauthn": { "rp_id": "gateway.example.com", "external_origin": "https://gateway.example.com" },
            "integration": { "categories": [], "types": [] },
            "listeners": [],
            "routes": {}
        }))
        .unwrap();
        let (vc_issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let vc_issuer = Arc::new(vc_issuer);
        let metrics_store = Arc::new(crate::metrics::MetricsStore::new(100));
        metrics_store
            .store_latest_channel_payload("surface-1".to_string(), serde_json::json!({ "prompt": "captured secret" }))
            .await;
        let ws_state = Arc::new(crate::server::WsState::new(16));
        let channel_manager = Arc::new(crate::server::SurfaceTaskManager::new(
            config.clone(),
            Arc::new(bootstrap),
            Arc::new(crate::storage::ConfigCache::new(dir.join("cache"))),
            Some(ws_state.clone()),
            Some(vc_issuer.clone()),
            None,
            Arc::new(crate::storage::SettingsStore::new(dir.join("settings"))),
        ));
        let state = crate::observability::DashboardState {
            config,
            network_config: Arc::new(network_config),
            identity_store: Arc::new(crate::identity::test_helpers::MockIdentityStore::new()),
            metrics_store,
            vc_issuer,
            ws_state,
            task_monitor: None,
            channel_manager,
            connection_point_listener_manager: None,
            notification_store: None,
            auth_state: None,
            pipe_store: None,
            system_metrics_store: None,
        };
        (state, issuer_dir)
    }

    /// What a dashboard read returns to `role`: whether it holds the log line
    /// and whether it holds the surface's captured payload.
    async fn dashboard_read(
        role: UserRole,
        path: &str,
    ) -> (bool, bool) {
        let (guard, auth, token, temp) = auth_for(role.clone(), crate::rbac::RbacConfig::default()).await;
        let (state, _issuer_dir) = dashboard_state(temp.path()).await;
        let app = dashboard_reads_router(&guard)
            .with_state(state)
            .layer(Extension(guard))
            .layer(middleware::from_fn_with_state(auth, require_session_auth));

        let response = app
            .oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), axum::http::StatusCode::OK, "{role:?} {path}");
        let body = String::from_utf8(
            axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap()
                .to_vec(),
        )
        .unwrap();
        let json: serde_json::Value = serde_json::from_str(&body).unwrap();
        let channel = if path.ends_with("stats") {
            &json["channels"][0]
        } else {
            &json["changes"]["channels"]["added"][0]
        };
        assert_eq!(channel["config_id"], "surface-1", "{role:?} {path}: {body}");
        (body.contains("secret log line"), body.contains("captured secret"))
    }

    #[tokio::test]
    async fn dashboard_reads_send_logs_and_captured_payloads_only_to_holders_of_their_permissions() {
        for path in ["/v1/dashboard/stats", "/v1/dashboard/delta"] {
            assert_eq!(dashboard_read(UserRole::User, path).await, (false, false), "user {path}");
            assert_eq!(dashboard_read(UserRole::PowerUser, path).await, (false, true), "poweruser {path}");
            assert_eq!(dashboard_read(UserRole::Administrator, path).await, (true, true), "administrator {path}");
        }
    }

    #[tokio::test]
    async fn the_dashboard_delta_reads_the_log_file_only_when_logs_are_included() {
        use std::io::Write;

        let temp = tempfile::tempdir().unwrap();
        let (state, _issuer_dir) = dashboard_state(temp.path()).await;
        let log_path = temp
            .path()
            .join("logs")
            .join("agent-stream.log");
        let mut log = std::fs::OpenOptions::new()
            .append(true)
            .open(log_path)
            .unwrap();
        writeln!(log, r#"{{"timestamp":"2026-10-20T10:00:01Z","level":"INFO","message":"second log line"}}"#).unwrap();

        for since_log_position in [None, Some(0)] {
            let query: crate::observability::DashboardQuery =
                serde_json::from_value(serde_json::json!({ "since_log_position": since_log_position })).unwrap();
            let included = crate::observability::compute_dashboard_delta(&state, &query, None, true)
                .await
                .unwrap();
            let excluded = crate::observability::compute_dashboard_delta(&state, &query, None, false)
                .await
                .unwrap();

            assert!(
                included
                    .changes
                    .logs
                    .is_some(),
                "{since_log_position:?}"
            );
            assert!(
                excluded
                    .changes
                    .logs
                    .is_none(),
                "{since_log_position:?}"
            );
        }
    }

    #[tokio::test]
    async fn dashboard_reads_need_dashboard_view() {
        let mut rbac = crate::rbac::RbacConfig::default();
        rbac.permissions
            .insert("dashboard.view".to_string(), "administrator".to_string());
        for path in [
            "/v1/dashboard/stats",
            "/v1/dashboard/delta",
            "/v1/dashboard/surface/surface-1/metrics",
            "/v1/dashboard/surface/surface-1/ucp-operations",
            "/v1/dashboard/metrics/hierarchical",
            "/v1/dashboard/system-metrics",
        ] {
            let (guard, auth, token, temp) = auth_for(UserRole::User, rbac.clone()).await;
            let (state, _issuer_dir) = dashboard_state(temp.path()).await;
            let app = dashboard_reads_router(&guard)
                .with_state(state)
                .layer(Extension(guard))
                .layer(middleware::from_fn_with_state(auth, require_session_auth));

            let response = app
                .oneshot(
                    Request::get(path)
                        .header("authorization", format!("Bearer {token}"))
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();

            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{path}");
        }
    }

    /// How a dashboard read's access token is narrowed: its tenant and the
    /// resource pattern it carries, if any.
    #[derive(Clone, Copy)]
    struct Narrowing {
        tenant: Option<&'static str>,
        pattern: Option<&'static str>,
    }

    const TENANT_A: Option<Narrowing> = Some(Narrowing {
        tenant: Some("tenant-a"),
        pattern: None,
    });

    const PATTERN_ONLY: Option<Narrowing> = Some(Narrowing {
        tenant: None,
        pattern: Some("^TENANT:tenant-a:pipes:owned-.*$"),
    });

    /// The status and body of a dashboard read by a user session, narrowed as
    /// `narrowing` says, against an appliance whose surfaces `owned-mine` and
    /// `outside-pattern` belong to `tenant-a` and `owned-theirs` to `tenant-b`.
    async fn narrowed_dashboard_read(
        path: &str,
        narrowing: Option<Narrowing>,
    ) -> (axum::http::StatusCode, String) {
        let (guard, auth, token, temp) = auth_for(UserRole::User, crate::rbac::RbacConfig::default()).await;
        let (mut state, _issuer_dir) = dashboard_state(temp.path()).await;
        let pipes = crate::pipes::FileSystemPipeStore::new(
            temp.path()
                .join("pipes")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        for (id, owner) in [("owned-mine", "tenant-a"), ("outside-pattern", "tenant-a"), ("owned-theirs", "tenant-b")] {
            let mut pipe = crate::pipes::PipeConfig::new(
                id.into(),
                id.into(),
                crate::pipes::PipeType::Webhook {
                    endpoint: "https://example.test".into(),
                },
            );
            pipe.tenant_id = Some(owner.into());
            pipes
                .save(pipe)
                .await
                .unwrap();
        }
        state.pipe_store = Some(Arc::new(pipes));
        let app = dashboard_reads_router(&guard)
            .with_state(state)
            .layer(Extension(guard))
            .layer(middleware::from_fn_with_state(auth, require_session_auth))
            .layer(middleware::from_fn(
                move |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                    if let Some(narrowing) = narrowing {
                        request
                            .extensions_mut()
                            .insert(crate::auth_manager::pat::PatDelegationContext {
                                token_id: "pat-1".to_string(),
                                delegation_depth: 0,
                                resource_scoped: narrowing.pattern.is_some(),
                                scopes: None,
                            });
                        if let Some(tenant) = narrowing.tenant {
                            request
                                .extensions_mut()
                                .insert(crate::tenancy::PatTenantContext {
                                    token_id: "pat-1".to_string(),
                                    tenant_id: tenant.to_string(),
                                });
                        }
                        if let Some(pattern) = narrowing.pattern {
                            request
                                .extensions_mut()
                                .insert(crate::auth_manager::pat::PatResourceScope(Arc::new(
                                    regex::Regex::new(pattern).unwrap(),
                                )));
                        }
                    }
                    next.run(request).await
                },
            ));

        let response = app
            .oneshot(
                Request::get(path)
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn surface_metrics_are_confined_to_the_tenant_of_a_narrowed_token() {
        for read in ["metrics", "ucp-operations"] {
            let owned = format!("/v1/dashboard/surface/owned-mine/{read}");
            assert_eq!(
                narrowed_dashboard_read(&owned, TENANT_A)
                    .await
                    .0,
                axum::http::StatusCode::OK,
                "{owned}"
            );

            let foreign =
                narrowed_dashboard_read(&format!("/v1/dashboard/surface/owned-theirs/{read}"), TENANT_A).await;
            let unknown =
                narrowed_dashboard_read(&format!("/v1/dashboard/surface/no-such-surface/{read}"), TENANT_A).await;
            assert_eq!(foreign.0, axum::http::StatusCode::NOT_FOUND, "{read}");
            assert_eq!(foreign, unknown, "{read}: a foreign surface must be indistinguishable from an unknown one");
        }
    }

    #[tokio::test]
    async fn surface_metrics_are_confined_to_the_resource_pattern_of_a_narrowed_token() {
        let scoped = Some(Narrowing {
            tenant: Some("tenant-a"),
            pattern: Some("^TENANT:tenant-a:pipes:owned-.*$"),
        });
        for read in ["metrics", "ucp-operations"] {
            for (surface, expected) in [
                ("owned-mine", axum::http::StatusCode::OK),
                ("outside-pattern", axum::http::StatusCode::NOT_FOUND),
                ("owned-theirs", axum::http::StatusCode::NOT_FOUND),
            ] {
                let path = format!("/v1/dashboard/surface/{surface}/{read}");
                assert_eq!(
                    narrowed_dashboard_read(&path, scoped)
                        .await
                        .0,
                    expected,
                    "{path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn a_token_narrowed_only_by_a_resource_pattern_reads_no_surface_metrics() {
        for read in ["metrics", "ucp-operations"] {
            for surface in ["owned-mine", "owned-theirs"] {
                let path = format!("/v1/dashboard/surface/{surface}/{read}");
                assert_eq!(
                    narrowed_dashboard_read(&path, PATTERN_ONLY)
                        .await
                        .0,
                    axum::http::StatusCode::NOT_FOUND,
                    "{path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn surface_metrics_stay_readable_to_an_appliance_session() {
        for surface in ["owned-mine", "owned-theirs"] {
            for read in ["metrics", "ucp-operations"] {
                let path = format!("/v1/dashboard/surface/{surface}/{read}");
                assert_eq!(
                    narrowed_dashboard_read(&path, None)
                        .await
                        .0,
                    axum::http::StatusCode::OK,
                    "{path}"
                );
            }
        }
    }

    #[tokio::test]
    async fn appliance_wide_dashboard_reads_refuse_a_narrowed_token() {
        for path in [
            "/v1/dashboard/stats",
            "/v1/dashboard/stats?pipe_id=owned-theirs",
            "/v1/dashboard/delta",
            "/v1/dashboard/delta?pipe_id=owned-theirs",
            "/v1/dashboard/metrics/hierarchical",
            "/v1/dashboard/system-metrics",
        ] {
            for narrowing in [TENANT_A, PATTERN_ONLY] {
                assert_eq!(
                    narrowed_dashboard_read(path, narrowing)
                        .await
                        .0,
                    axum::http::StatusCode::FORBIDDEN,
                    "{path}"
                );
            }
            assert_eq!(
                narrowed_dashboard_read(path, None)
                    .await
                    .0,
                axum::http::StatusCode::OK,
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn the_agents_list_refuses_a_token_narrowed_to_a_tenant() {
        let (guard, auth, token, _temp) = auth_for(UserRole::PowerUser, crate::rbac::RbacConfig::default()).await;
        let app = agents_app(guard, auth).layer(middleware::from_fn(
            |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                request
                    .extensions_mut()
                    .insert(crate::tenancy::PatTenantContext {
                        token_id: "pat-1".to_string(),
                        tenant_id: "tenant-a".to_string(),
                    });
                next.run(request).await
            },
        ));

        let response = app
            .oneshot(agents_request(Some(&token)))
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }

    fn revoke_request(token: Option<&str>) -> Request<Body> {
        let mut request = Request::post("/v1/agents/did:example:agent/revoke");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        request
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn revoking_an_agent_needs_identity_issue() {
        for (name, role) in [("user", UserRole::User), ("power user", UserRole::PowerUser)] {
            let (guard, auth, token, _temp) = auth_for(role, crate::rbac::RbacConfig::default()).await;
            let response = agents_app(guard, auth)
                .oneshot(revoke_request(Some(&token)))
                .await
                .unwrap();
            assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN, "{name}");
        }

        let (guard, auth, _token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let anonymous = agents_app(guard, auth)
            .oneshot(revoke_request(None))
            .await
            .unwrap();
        assert_eq!(anonymous.status(), axum::http::StatusCode::UNAUTHORIZED);

        let (guard, auth, token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        assert!(reaches_handler(agents_app(guard, auth), revoke_request(Some(&token))).await);
    }

    #[tokio::test]
    async fn revoking_an_agent_refuses_a_token_narrowed_to_a_tenant() {
        let (guard, auth, token, _temp) = auth_for(UserRole::Administrator, crate::rbac::RbacConfig::default()).await;
        let app = agents_app(guard, auth).layer(middleware::from_fn(
            |mut request: axum::extract::Request, next: axum::middleware::Next| async move {
                request
                    .extensions_mut()
                    .insert(crate::tenancy::PatTenantContext {
                        token_id: "pat-1".to_string(),
                        tenant_id: "tenant-a".to_string(),
                    });
                next.run(request).await
            },
        ));

        let response = app
            .oneshot(revoke_request(Some(&token)))
            .await
            .unwrap();

        assert_eq!(response.status(), axum::http::StatusCode::FORBIDDEN);
    }
}

/// Request-level checks that an access token's scope list is enforced both by
/// handler-local gates and by the pipe-template route gates, not just by the
/// predicates they call.
#[cfg(test)]
mod token_scope_route_tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::{AuthGuardState, extract_user_id, require_session_auth};
    use crate::auth_manager::pat::{PatAuthenticator, PatPrincipal};
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
    };
    use std::sync::Arc;
    use tower::ServiceExt;

    const ADMIN: &str = "admin-1";

    /// Access tokens bound to the administrator, keyed by their scope list.
    struct AdminTokens;

    #[async_trait::async_trait]
    impl PatAuthenticator for AdminTokens {
        async fn authenticate(
            &self,
            token: &str,
        ) -> Option<PatPrincipal> {
            let scopes: Option<&[&str]> = match token {
                "aspat_unscoped" => None,
                "aspat_pipes_view" => Some(&["pipes.view"]),
                "aspat_pipes_edit" => Some(&["pipes.view", "pipes.edit"]),
                "aspat_metrics_view" => Some(&["metrics.view"]),
                "aspat_connection_points_view" => Some(&["connection_points.view"]),
                _ => return None,
            };
            Some(PatPrincipal {
                user_id: ADMIN.to_string(),
                scopes: scopes.map(|scopes| {
                    scopes
                        .iter()
                        .map(|scope| scope.to_string())
                        .collect()
                }),
                token_id: token.to_string(),
                delegation_depth: 0,
                resource_scoped: false,
                resource_scope: None,
            })
        }
    }

    struct Fixture {
        storage: Arc<PasskeyStorage>,
        sessions: Arc<crate::auth::session::SessionManager>,
        session_token: String,
        _temp: tempfile::TempDir,
    }

    async fn admin_fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            PasskeyStorage::new(
                temp.path()
                    .join("users")
                    .to_string_lossy()
                    .into_owned(),
                temp.path()
                    .join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let now = chrono::Utc::now();
        storage
            .save_user(&UserData {
                user_id: ADMIN.to_string(),
                username: "admin".to_string(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
                status: UserStatus::Approved,
                is_primary: true,
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
                deleted_at: None,
            })
            .await
            .unwrap();
        let sessions = Arc::new(crate::auth::session::SessionManager::new());
        let session_token = sessions
            .create_session("admin".to_string(), ADMIN.to_string())
            .await;
        Fixture {
            storage,
            sessions,
            session_token,
            _temp: temp,
        }
    }

    fn auth_layer(fixture: &Fixture) -> AuthGuardState {
        AuthGuardState::new(
            fixture.sessions.clone(),
            Some(fixture.storage.clone()),
            Arc::new(crate::terms::TermsManager::disabled()),
        )
        .with_pat_authenticator(Some(Arc::new(AdminTokens)))
    }

    fn request(
        method: &str,
        path: &str,
        token: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap()
    }

    /// Handler-gated routes mounted with their real handlers and the same
    /// layers the identity router gives them.
    fn handler_gated_app(fixture: &Fixture) -> Router {
        Router::new()
            .route("/v1/users", get(crate::auth_manager::handlers::list_users))
            .route("/v1/drift/dimensions", get(handlers::drift_dimensions))
            .route("/v1/cache/stats", get(handlers::cache_stats))
            .layer(middleware::from_fn(extract_user_id))
            .layer(Extension(fixture.sessions.clone()))
            .layer(Extension(fixture.storage.clone()))
            .layer(Extension(Arc::new(crate::rbac::RbacConfig::default())))
            .layer(middleware::from_fn_with_state(auth_layer(fixture), require_session_auth))
    }

    #[tokio::test]
    async fn handler_gates_enforce_the_token_scope_list() {
        let fixture = admin_fixture().await;
        let app = handler_gated_app(&fixture);
        for path in ["/v1/users", "/v1/drift/dimensions", "/v1/cache/stats"] {
            let status = app
                .clone()
                .oneshot(request("GET", path, "aspat_pipes_view"))
                .await
                .unwrap()
                .status();
            assert_eq!(status, StatusCode::FORBIDDEN, "a pipes.view-scoped administrator token must get 403 on {path}");
        }
        for token in ["aspat_unscoped", fixture.session_token.as_str()] {
            for path in ["/v1/users", "/v1/drift/dimensions"] {
                let status = app
                    .clone()
                    .oneshot(request("GET", path, token))
                    .await
                    .unwrap()
                    .status();
                assert_eq!(status, StatusCode::OK, "an unscoped token or session must reach {path}");
            }
        }
    }

    /// Router state for exercising route gates only. A request that passes its
    /// gate reaches the handler, whose `State` extractor panics here; a request
    /// a gate rejects never gets that far.
    #[derive(Clone)]
    struct GateOnlyState;

    impl axum::extract::FromRef<GateOnlyState> for IdentityApiState {
        fn from_ref(_: &GateOnlyState) -> Self {
            panic!("request passed the route gate and reached the handler")
        }
    }

    /// `Err(())` when the request got past the route gate to the handler,
    /// otherwise the status the gate (or auth) answered with.
    async fn gate_outcome(
        app: &Router,
        method: &str,
        path: &str,
        token: &str,
    ) -> Result<StatusCode, ()> {
        let app = app.clone();
        let request = request(method, path, token);
        match tokio::spawn(async move {
            app.oneshot(request)
                .await
                .unwrap()
                .status()
        })
        .await
        {
            Ok(status) => Ok(status),
            Err(join_error) if join_error.is_panic() => Err(()),
            Err(join_error) => panic!("request task failed: {join_error}"),
        }
    }

    #[tokio::test]
    async fn pipe_template_routes_enforce_the_token_scope_list() {
        let fixture = admin_fixture().await;
        let guard = RbacGuard::new(fixture.storage.clone(), Arc::new(crate::rbac::RbacConfig::default()));
        let app = create_pipe_template_router::<GateOnlyState>(guard)
            .layer(middleware::from_fn_with_state(auth_layer(&fixture), require_session_auth))
            .with_state(GateOnlyState);

        for (method, path) in [
            ("POST", "/v1/pipe-templates"),
            ("POST", "/v1/pipe-templates/import"),
            ("PUT", "/v1/pipe-templates/t1"),
            ("DELETE", "/v1/pipe-templates/t1"),
        ] {
            assert_eq!(
                gate_outcome(&app, method, path, "aspat_pipes_view").await,
                Ok(StatusCode::FORBIDDEN),
                "a pipes.view token must not {method} {path}"
            );
        }
        for (method, path) in
            [("POST", "/v1/pipe-templates"), ("POST", "/v1/pipe-templates/import"), ("PUT", "/v1/pipe-templates/t1")]
        {
            assert_eq!(
                gate_outcome(&app, method, path, "aspat_pipes_edit").await,
                Err(()),
                "a pipes.edit token must pass the gate on {method} {path}"
            );
        }
        assert_eq!(
            gate_outcome(&app, "DELETE", "/v1/pipe-templates/t1", "aspat_pipes_edit").await,
            Ok(StatusCode::FORBIDDEN),
            "deleting a template needs pipes.delete, not pipes.edit"
        );
        for path in ["/v1/pipe-templates", "/v1/pipe-templates/t1", "/v1/pipe-templates/t1/export"] {
            assert_eq!(
                gate_outcome(&app, "GET", path, "aspat_pipes_view").await,
                Err(()),
                "a pipes.view token can read: GET {path}"
            );
        }
    }

    const SURFACE_CONFIG_READS: [&str; 5] = [
        "/v1/pipes",
        "/v1/pipes/p1",
        "/v1/pipes/p1/variants/default/resolved",
        "/v1/pipes/p1/ide-catalog/preview",
        "/v1/pipes/p1/ide-catalog/bootstrap",
    ];
    const SURFACE_BUDGET_READ: &str = "/v1/pipes/p1/budget";

    fn pipe_read_app(
        fixture: &Fixture,
        rbac_config: crate::rbac::RbacConfig,
    ) -> Router {
        let guard = RbacGuard::new(fixture.storage.clone(), Arc::new(rbac_config));
        create_pipe_read_router::<GateOnlyState>(guard)
            .layer(middleware::from_fn_with_state(auth_layer(fixture), require_session_auth))
            .with_state(GateOnlyState)
    }

    #[tokio::test]
    async fn pipe_read_routes_enforce_the_token_scope_list() {
        let fixture = admin_fixture().await;
        let app = pipe_read_app(&fixture, crate::rbac::RbacConfig::default());

        for path in SURFACE_CONFIG_READS {
            assert_eq!(
                gate_outcome(&app, "GET", path, "aspat_metrics_view").await,
                Ok(StatusCode::FORBIDDEN),
                "a metrics.view token must not read Surface configuration: GET {path}"
            );
            for token in ["aspat_pipes_view", "aspat_unscoped", fixture.session_token.as_str()] {
                assert_eq!(
                    gate_outcome(&app, "GET", path, token).await,
                    Err(()),
                    "{token} must pass the gate on GET {path}"
                );
            }
        }

        assert_eq!(
            gate_outcome(&app, "GET", SURFACE_BUDGET_READ, "aspat_pipes_view").await,
            Ok(StatusCode::FORBIDDEN),
            "the budget read needs metrics.view, not pipes.view"
        );
        assert_eq!(
            gate_outcome(&app, "GET", SURFACE_BUDGET_READ, "aspat_metrics_view").await,
            Err(()),
            "a metrics.view token must pass the gate on the budget read"
        );
    }

    #[tokio::test]
    async fn connection_point_read_routes_enforce_the_token_scope_list() {
        let fixture = admin_fixture().await;
        let guard = RbacGuard::new(fixture.storage.clone(), Arc::new(crate::rbac::RbacConfig::default()));
        let app = connection_point_read_routes(&guard)
            .layer(middleware::from_fn_with_state(auth_layer(&fixture), require_session_auth));
        let status = |path: &'static str, token: String| {
            let app = app.clone();
            async move {
                app.oneshot(request("GET", path, &token))
                    .await
                    .unwrap()
                    .status()
            }
        };

        for path in [
            "/v1/connection-points",
            "/v1/connection-points/cp-1",
            "/v1/connection-points/cp-1/metrics",
            "/v1/gateways/gw-1/connection-points",
        ] {
            assert_eq!(
                status(path, "aspat_metrics_view".to_string()).await,
                StatusCode::FORBIDDEN,
                "a metrics.view token must not GET {path}"
            );
            for token in ["aspat_connection_points_view", "aspat_unscoped", fixture.session_token.as_str()] {
                let answered = status(path, token.to_string()).await;
                assert!(
                    answered != StatusCode::UNAUTHORIZED && answered != StatusCode::FORBIDDEN,
                    "{token} must pass the gate on GET {path}: {answered}"
                );
            }
        }
    }

    #[tokio::test]
    async fn pipe_read_routes_enforce_the_role() {
        let fixture = admin_fixture().await;
        let mut base_user = fixture
            .storage
            .load_user_by_id(ADMIN)
            .await
            .unwrap()
            .unwrap();
        base_user.user_id = "user-1".to_string();
        base_user.username = "user".to_string();
        base_user.role = UserRole::User;
        base_user.is_primary = false;
        fixture
            .storage
            .save_user(&base_user)
            .await
            .unwrap();
        let user_session = fixture
            .sessions
            .create_session("user".to_string(), "user-1".to_string())
            .await;

        let mut rbac_config = crate::rbac::RbacConfig::default();
        for permission in ["pipes.view", "metrics.view"] {
            rbac_config
                .permissions
                .insert(permission.to_string(), "administrator".to_string());
        }
        let app = pipe_read_app(&fixture, rbac_config);

        for path in SURFACE_CONFIG_READS
            .into_iter()
            .chain([SURFACE_BUDGET_READ])
        {
            assert_eq!(
                gate_outcome(&app, "GET", path, &user_session).await,
                Ok(StatusCode::FORBIDDEN),
                "a role without the permission must not GET {path}"
            );
            assert_eq!(
                gate_outcome(&app, "GET", path, &fixture.session_token).await,
                Err(()),
                "a role with the permission must pass the gate on GET {path}"
            );
        }
    }
}

/// The throttle sits on the real sign-in routes, in passkey and SAML mode.
#[cfg(test)]
mod auth_throttle_route_tests {
    use super::*;
    use crate::auth::throttle::{AUTH_CHECK_REQUESTS_PER_WINDOW, SIGN_IN_REQUESTS_PER_WINDOW};
    use axum::{
        body::Body,
        extract::ConnectInfo,
        http::{Request, StatusCode},
    };
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tower::ServiceExt;

    /// A request from `peer`; each test uses its own peers, since the
    /// throttle is process-wide.
    fn request(
        method: &str,
        path: &str,
        peer: &str,
        json: Option<&str>,
    ) -> Request<Body> {
        let mut builder = Request::builder()
            .method(method)
            .uri(path);
        if json.is_some() {
            builder = builder.header("content-type", "application/json");
        }
        let mut request = builder
            .body(json.map_or_else(Body::empty, |json| Body::from(json.to_string())))
            .unwrap();
        request
            .extensions_mut()
            .insert(ConnectInfo::<SocketAddr>(peer.parse().unwrap()));
        request
    }

    async fn status(
        app: &Router,
        request: Request<Body>,
    ) -> StatusCode {
        app.clone()
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    async fn assert_auth_check_throttled(
        app: &Router,
        peer: &str,
    ) {
        for _ in 0..AUTH_CHECK_REQUESTS_PER_WINDOW {
            assert_ne!(
                status(app, request("GET", "/auth/check", peer, None)).await,
                StatusCode::TOO_MANY_REQUESTS,
                "/auth/check within its budget reaches the handler"
            );
        }
        assert_eq!(
            status(app, request("GET", "/auth/check", peer, None)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "/auth/check without a session is throttled"
        );
    }

    #[tokio::test]
    async fn passkey_sign_in_routes_are_throttled_per_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let state = Arc::new(
            crate::auth::AuthState::new(
                "example.com".to_string(),
                url::Url::parse("https://example.com").unwrap(),
                path("users"),
                path("avatars"),
                30,
                path("sessions"),
                Arc::new(crate::metrics::MetricsStore::new(16)),
                Arc::new(crate::terms::TermsManager::disabled()),
            )
            .await
            .unwrap(),
        );
        let app = passkey_auth_routes(state.clone(), state.session_manager.clone());
        let login = Some(r#"{"username":"probe"}"#);

        let peer = "192.0.2.41:5000";
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            assert_eq!(status(&app, request("POST", "/auth/login/start", peer, login)).await, StatusCode::OK);
        }
        for path in ["/auth/login/start", "/auth/register/start", "/auth/login/finish", "/auth/register/finish"] {
            assert_eq!(
                status(&app, request("POST", path, peer, Some("{}"))).await,
                StatusCode::TOO_MANY_REQUESTS,
                "{path} spends the client's sign-in budget"
            );
        }
        assert_eq!(
            status(&app, request("POST", "/auth/login/start", "192.0.2.42:5000", login)).await,
            StatusCode::OK,
            "another client is not throttled"
        );

        assert_auth_check_throttled(&app, "192.0.2.43:5000").await;
    }

    #[tokio::test]
    async fn saml_sign_in_routes_are_throttled_per_client() {
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let config: crate::auth::SamlConfig = serde_json::from_value(serde_json::json!({
            "idp_entity_id": "https://idp.example.test",
            "idp_sso_url": "https://idp.example.test/sso",
            "idp_slo_url": null,
            "sp_entity_id": "https://appliance.example.test",
            "sp_acs_url": "https://appliance.example.test/api/saml/acs",
            "idp_cert_path": "unused.pem",
            "sign_requests": false,
            "sp_key_path": null,
            "sp_cert_path": null,
        }))
        .unwrap();
        let sessions = Arc::new(crate::auth::SessionManager::new());
        let saml_state = Arc::new(crate::auth::saml::SamlState {
            saml_service: Arc::new(crate::auth::saml::SamlService::for_route_tests(config)),
            storage: Arc::new(
                crate::auth::storage::PasskeyStorage::new(path("users"), path("avatars"))
                    .await
                    .unwrap(),
            ),
            session_manager: sessions.clone(),
            avatars_storage_path: path("avatars"),
            notification_store: Arc::new(tokio::sync::RwLock::new(None)),
            terms_manager: Arc::new(crate::terms::TermsManager::disabled()),
        });
        let app =
            saml_auth_routes(saml_state, sessions).layer(Extension(Arc::new(crate::terms::TermsManager::disabled())));

        let peer = "192.0.2.51:5000";
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            let login = status(&app, request("GET", "/saml/login", peer, None)).await;
            assert!(login.is_redirection(), "a SAML login redirects to the IdP, got {login}");
        }
        assert_eq!(status(&app, request("GET", "/saml/login", peer, None)).await, StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            status(&app, request("POST", "/saml/acs", peer, None)).await,
            StatusCode::TOO_MANY_REQUESTS,
            "the ACS spends the client's sign-in budget"
        );
        assert!(
            status(&app, request("GET", "/saml/login", "192.0.2.52:5000", None))
                .await
                .is_redirection(),
            "another client is not throttled"
        );

        assert_auth_check_throttled(&app, "192.0.2.53:5000").await;
    }

    fn retry_after(response: &axum::response::Response) -> u64 {
        response
            .headers()
            .get(axum::http::header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse().ok())
            .unwrap()
    }

    #[tokio::test]
    async fn only_oidc_callbacks_whose_code_was_refused_count_toward_the_lockout() {
        use crate::auth::oidc::test_support::{StubProvider, config_for};

        let provider = StubProvider::start().await;
        let _allowed = crate::url_validation::test_service_endpoints::allow(&[
            provider.discovery_url(),
            provider.token_endpoint(),
            provider.jwks_uri(),
        ]);
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        let sessions = Arc::new(crate::auth::SessionManager::new());
        let oidc = Arc::new(
            crate::auth::oidc::OidcState::new(
                config_for(&provider.issuer),
                Arc::new(
                    crate::auth::storage::PasskeyStorage::new(path("users"), path("avatars"))
                        .await
                        .unwrap(),
                ),
                sessions.clone(),
                Arc::new(crate::terms::TermsManager::disabled()),
            )
            .unwrap(),
        );
        let app = oidc_auth_routes(oidc, sessions);

        let unbound = "192.0.2.61:5000";
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            assert_eq!(
                status(&app, request("GET", "/oidc/callback?code=c&state=unknown", unbound, None)).await,
                StatusCode::BAD_REQUEST
            );
        }
        let limited = app
            .clone()
            .oneshot(request("GET", "/oidc/callback?code=c&state=unknown", unbound, None))
            .await
            .unwrap();
        assert_eq!(limited.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after(&limited) <= 60, "rate limited, not locked out");

        let starter = "192.0.2.62:5000";
        let refused = "192.0.2.63:5000";
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            let started = app
                .clone()
                .oneshot(request("GET", "/oidc/login", starter, None))
                .await
                .unwrap();
            let location = url::Url::parse(
                started
                    .headers()
                    .get(axum::http::header::LOCATION)
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
            .unwrap();
            let state = location
                .query_pairs()
                .find(|(name, _)| name == "state")
                .unwrap()
                .1
                .into_owned();
            let mut callback = request("GET", &format!("/oidc/callback?code=c&state={state}"), refused, None);
            callback.headers_mut().insert(
                axum::http::header::COOKIE,
                format!("__Host-oidc_state={state}")
                    .parse()
                    .unwrap(),
            );
            assert_eq!(status(&app, callback).await, StatusCode::UNAUTHORIZED, "invalid_grant");
        }
        let locked = app
            .clone()
            .oneshot(request("GET", "/oidc/callback?code=c&state=unknown", refused, None))
            .await
            .unwrap();
        assert_eq!(locked.status(), StatusCode::TOO_MANY_REQUESTS);
        assert!(retry_after(&locked) > 60, "locked out after refused codes");
    }

    fn oidc_state(
        dir: &tempfile::TempDir,
        sessions: Arc<crate::auth::SessionManager>,
        backchannel: bool,
    ) -> impl std::future::Future<Output = Arc<crate::auth::oidc::OidcState>> {
        let users = dir
            .path()
            .join("users")
            .to_string_lossy()
            .into_owned();
        let avatars = dir
            .path()
            .join("avatars")
            .to_string_lossy()
            .into_owned();
        async move {
            let mut config = crate::auth::oidc::test_support::config_for("https://idp.example.test");
            config.logout.backchannel = backchannel;
            Arc::new(
                crate::auth::oidc::OidcState::new(
                    config,
                    Arc::new(
                        crate::auth::storage::PasskeyStorage::new(users, avatars)
                            .await
                            .unwrap(),
                    ),
                    sessions,
                    Arc::new(crate::terms::TermsManager::disabled()),
                )
                .unwrap(),
            )
        }
    }

    fn form_request(
        path: &str,
        peer: &str,
        form: &str,
    ) -> Request<Body> {
        let mut request = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/x-www-form-urlencoded")
            .body(Body::from(form.to_string()))
            .unwrap();
        request
            .extensions_mut()
            .insert(axum::extract::ConnectInfo(
                peer.parse::<std::net::SocketAddr>()
                    .unwrap(),
            ));
        request
    }

    #[tokio::test]
    async fn oidc_sign_in_routes_are_throttled_per_client_and_back_channel_logout_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Arc::new(crate::auth::SessionManager::new());
        let app = oidc_auth_routes(oidc_state(&dir, sessions.clone(), true).await, sessions)
            .layer(Extension(Arc::new(crate::terms::TermsManager::disabled())));

        let peer = "192.0.2.71:5000";
        for _ in 0..SIGN_IN_REQUESTS_PER_WINDOW {
            let login = status(&app, request("GET", "/oidc/login", peer, None)).await;
            assert_ne!(login, StatusCode::TOO_MANY_REQUESTS);
        }
        for path in ["/oidc/login", "/oidc/initiate"] {
            assert_eq!(
                status(&app, request("GET", path, peer, None)).await,
                StatusCode::TOO_MANY_REQUESTS,
                "{path} spends the client's sign-in budget"
            );
        }
        for _ in 0..=SIGN_IN_REQUESTS_PER_WINDOW {
            assert_eq!(
                status(&app, form_request("/oidc/backchannel-logout", peer, "")).await,
                StatusCode::BAD_REQUEST,
                "the provider's logouts are never throttled"
            );
        }
        assert_auth_check_throttled(&app, "192.0.2.73:5000").await;
    }

    #[tokio::test]
    async fn a_back_channel_logout_body_over_the_limit_is_refused_as_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Arc::new(crate::auth::SessionManager::new());
        let app = oidc_auth_routes(oidc_state(&dir, sessions.clone(), true).await, sessions)
            .layer(Extension(Arc::new(crate::terms::TermsManager::disabled())));
        let oversized = format!("logout_token={}", "a".repeat(crate::auth::oidc::MAX_BACKCHANNEL_LOGOUT_BYTES));

        assert_eq!(
            status(&app, form_request("/oidc/backchannel-logout", "192.0.2.65:5000", &oversized)).await,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn back_channel_logout_is_not_served_when_oidc_json_turns_it_off() {
        let dir = tempfile::tempdir().unwrap();
        let sessions = Arc::new(crate::auth::SessionManager::new());
        let app = oidc_auth_routes(oidc_state(&dir, sessions.clone(), false).await, sessions)
            .layer(Extension(Arc::new(crate::terms::TermsManager::disabled())));

        assert_eq!(
            status(&app, form_request("/oidc/backchannel-logout", "192.0.2.74:5000", "logout_token=x")).await,
            StatusCode::NOT_FOUND
        );
    }
}
