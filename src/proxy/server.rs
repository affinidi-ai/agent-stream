//! Server functions for running proxy port listeners and channel servers

use axum::Router;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};

use crate::config::GatewayConfig;

fn listener_scopes_for_port(
    network_config: &crate::config::NetworkConfig,
    port: u16,
) -> Vec<String> {
    let Some(listener) = network_config
        .listeners
        .iter()
        .find(|l| l.port == port)
    else {
        return Vec::new();
    };

    let mut scopes = vec![crate::pipes::route_manager::canonical_listener_scope(listener)];
    for scope in listener
        .external_urls
        .iter()
        .cloned()
        .chain(std::iter::once(format!("{}:{}", listener.bind_address, listener.port)))
        .chain(std::iter::once(format!("{}://{}:{}", listener.protocol, listener.bind_address, listener.port)))
    {
        let normalized = crate::pipes::route_manager::normalize_listener_scope(&scope);
        if !normalized.is_empty() && !scopes.contains(&normalized) {
            scopes.push(normalized);
        }
    }
    scopes
}

/// Build the AP `listen_address` shown in the Tasks UI by appending the
/// surface route to the listener host. Returns `"fabric"` for fabric-only
/// surfaces (empty host).
pub(crate) fn join_host_and_route(
    host: &str,
    route: &str,
) -> String {
    if host.is_empty() {
        return if route.is_empty() || route == "/" {
            "fabric".to_string()
        } else if route.starts_with('/') {
            format!("fabric{}", route)
        } else {
            format!("fabric/{}", route)
        };
    }
    let host_trim = host.trim_end_matches('/');
    if route.is_empty() || route == "/" {
        host_trim.to_string()
    } else if route.starts_with('/') {
        format!("{}{}", host_trim, route)
    } else {
        format!("{}/{}", host_trim, route)
    }
}

async fn api_route_not_found() -> impl axum::response::IntoResponse {
    (hyper::StatusCode::NOT_FOUND, axum::Json(serde_json::json!({ "error": "Not found" })))
}

/// Mount the management API at `prefix`. Nested under a prefix, a path no API
/// route matches answers `404` instead of inheriting the listener's static
/// fallback, which would answer `200` with the dashboard's `index.html`. At `/`
/// the API shares the root with the data plane and the dashboard, so unmatched
/// paths keep the listener's own fallback.
fn mount_identity_api(
    app: Router,
    prefix: &str,
    identity_router: Router,
) -> Router {
    if prefix == "/" {
        app.merge(identity_router)
    } else {
        app.nest(prefix, identity_router.fallback(api_route_not_found))
    }
}

/// Cache-Control policy for statically served files. Content-hashed build
/// assets under `/static/` never change for a given URL, so they are cached
/// aggressively; everything else (notably the SPA `index.html` entry point) is
/// served `no-cache` so browsers always revalidate and pick up a fresh build
/// immediately instead of holding a stale shell that points at deleted chunks.
async fn static_cache_control(
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let immutable = req
        .uri()
        .path()
        .starts_with("/static/");
    let mut response = next.run(req).await;
    let value = if immutable {
        hyper::http::HeaderValue::from_static("public, max-age=31536000, immutable")
    } else {
        hyper::http::HeaderValue::from_static("no-cache")
    };
    response
        .headers_mut()
        .insert(hyper::header::CACHE_CONTROL, value);
    response
}

/// Serve the axum `app` over TLS using hyper's HTTP/1 connection builder.
///
/// This replaces `axum_server`, which buffers streaming/SSE response bodies
/// until the stream completes; hyper-util flushes each body frame to the
/// socket as it is produced, so Server-Sent Events reach the client
/// incrementally. The TLS listener intentionally serves HTTP/1.1 only so the
/// classic WebSocket `Upgrade` path used by realtime voice remains compatible
/// with proxies that do not support RFC 8441 HTTP/2 WebSockets.
///
/// When `capture_peer_cert` is set (direct client-auth mode), the client
/// certificate presented during the rustls handshake is snapshotted into a
/// [`crate::source_auth::peer_cert::DirectTlsPeerCert`] request extension so
/// the downstream `promote_direct_peer_cert` middleware can consume it
/// exactly as it did under the previous `PeerCertAcceptor`.
async fn serve_app_tls(
    listener: tokio::net::TcpListener,
    tls_acceptor: TlsAcceptor,
    app: Router,
    capture_peer_cert: bool,
) -> std::io::Result<()> {
    use hyper::server::conn::http1;
    use hyper_util::rt::TokioIo;
    use hyper_util::service::TowerToHyperService;
    use tower::{Layer, Service};

    let mut make_service = app.into_make_service_with_connect_info::<SocketAddr>();

    loop {
        let (tcp_stream, remote_addr) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                debug!("HTTPS accept error: {}", e);
                continue;
            }
        };

        // `IntoMakeServiceWithConnectInfo::call` is infallible; it just clones
        // the router and stamps the remote address as `ConnectInfo`.
        let tower_service = match make_service
            .call(remote_addr)
            .await
        {
            Ok(svc) => svc,
            Err(err) => match err {},
        };

        let tls_acceptor = tls_acceptor.clone();
        tokio::spawn(async move {
            let tls_stream = match tls_acceptor
                .accept(tcp_stream)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    debug!("TLS handshake failed from {}: {}", remote_addr, e);
                    return;
                }
            };

            let peer = if capture_peer_cert {
                let (_, server_conn) = tls_stream.get_ref();
                server_conn
                    .peer_certificates()
                    .and_then(crate::source_auth::peer_cert::direct::build_peer_cert_info)
            } else {
                None
            };

            // Inject the (possibly empty) direct-TLS peer cert ahead of the
            // app so the promotion middleware inside the router can read it.
            let svc = axum::Extension(crate::source_auth::peer_cert::DirectTlsPeerCert(peer)).layer(tower_service);
            let hyper_service = TowerToHyperService::new(svc);

            if let Err(e) = http1::Builder::new()
                .serve_connection(TokioIo::new(tls_stream), hyper_service)
                .with_upgrades()
                .await
            {
                debug!("HTTPS connection from {} closed: {}", remote_addr, e);
            }
        });
    }
}

/// Run a listener for a specific port that serves the identity, DID, vault,
/// static, redirect, and pipe routes configured for that port.
pub async fn run_port_server(
    port: u16,
    surfaces: Vec<crate::config::agent_surface::AgentSurface>,
    _tls_acceptor: TlsAcceptor,
    _client: reqwest::Client,
    config: Arc<GatewayConfig>,
    _bootstrap_config: Arc<crate::config::BootstrapConfig>,
    metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
    task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    task_id: Option<String>,
    _ws_state: Option<Arc<crate::server::WsState>>,
    _vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    _listener_manager: Arc<tokio::sync::RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    identity_api_router: Option<axum::Router>,
    did_router: Option<axum::Router>,
    secrets_router: Option<axum::Router>,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    network_config: Arc<crate::config::NetworkConfig>,
    use_tls: bool,
    _policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
    _gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
    pipe_route_manager: Option<Arc<crate::pipes::PipeRouteManager>>,
    _settings_store: Arc<crate::storage::SettingsStore>,
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    direct_client_auth: Option<Arc<crate::server::DirectClientAuth>>,
    #[cfg(feature = "didwebvh")] _didwebvh_identity_store: Option<
        Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    >,
    #[cfg(feature = "didwebvh")] _didwebvh_log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
) -> anyhow::Result<()> {
    let _task_id = task_id.unwrap_or_else(|| format!("port-{}-{}", port, uuid::Uuid::new_v4()));

    info!("Starting port listener on 0.0.0.0:{} for {} channel(s)", port, surfaces.len());

    // Clone metrics store for use in pipe handlers before moving into state
    let metrics_store_for_pipes = metrics_store.clone();

    // Register all enabled pipes in the route manager at startup
    if let (Some(store), Some(route_mgr)) = (&pipe_store, &pipe_route_manager) {
        let pipes = store.list().await;
        let mut registered_count = 0;

        for pipe in &pipes {
            // Register this pipe's route prefix for OpenTelemetry tracing
            if let Some(ref route) = pipe.route {
                crate::observability::register_pipe_prefix(route.clone(), format!("[PIPE] {}", pipe.name));
            }

            if let Err(e) = route_mgr
                .register_pipe(pipe)
                .await
            {
                warn!("Skipped pipe route registration for '{}': {}", pipe.name, e);
            } else {
                registered_count += 1;
            }
        }

        info!("Registered {} pipe routes at startup", registered_count);
    }

    // Build the Axum router from network configuration
    let mut app = Router::new();

    // Note: SPA-route collision validation is performed once at startup in
    // server::orchestrator before any port is spawned, where a hard exit can
    // be issued. We intentionally do NOT re-run it here so a hot-reload that
    // introduces a collision rejects the reload (caller logs the error) but
    // does not kill the live process.

    // Merge DID router first (at root level) to ensure did:web routes are accessible
    if let Some(ref did_router_ref) = did_router {
        info!("Merging DID resolution router at root level");
        app = app.merge(did_router_ref.clone());
    }

    // Note: Secrets/Vault router will be merged AFTER regular routes to take precedence

    // Separate fallback routes from regular routes
    let mut fallback_routes = Vec::new();
    let mut regular_routes = Vec::new();

    for (route_name, route_config) in &network_config.routes {
        if route_config.route_type == crate::config::RouteType::Static && route_config.fallback {
            fallback_routes.push((route_name, route_config));
        } else {
            regular_routes.push((route_name, route_config));
        }
    }

    // Process regular routes first
    for (route_name, route_config) in regular_routes {
        match route_config.route_type {
            crate::config::RouteType::IdentityApi => {
                if let Some(ref identity_router) = identity_api_router {
                    info!("Adding Identity API routes at prefix: {}", route_config.prefix);
                    app = mount_identity_api(app, &route_config.prefix, identity_router.clone());
                } else {
                    info!("Skipping Identity API route '{}': router not provided", route_name);
                }
            }
            crate::config::RouteType::Onboarding => {
                info!("Onboarding route type is deprecated; skipping '{}'", route_name);
            }
            crate::config::RouteType::ConnectionPoint => {
                info!("Adding connection point DID routes '{}' at prefix: {}", route_name, route_config.prefix);

                // Connection point DID documents/logs must be served at the root
                // path the did:webvh / did:web identifiers resolve to
                // (https://<domain>/connection-points/{id}/did.jsonl), NOT under
                // the /api identity prefix — otherwise resolution falls through to
                // the SPA static fallback and returns index.html.
                let cp_store = std::sync::Arc::new(
                    crate::gateways::FileSystemConnectionPointStore::new(std::path::PathBuf::from(
                        &_bootstrap_config
                            .storage_paths
                            .connection_points,
                    ))
                    .await
                    .map_err(|e| anyhow::anyhow!("Failed to create connection point store: {}", e))?,
                );

                let cp_router = Router::new()
                    .route(
                        "/{cp_id}/did.json",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_document::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .route(
                        "/{cp_id}/did.jsonl",
                        axum::routing::get(
                            crate::gateways::connection_points::handlers::serve_connection_point_did_jsonl::<
                                crate::gateways::FileSystemConnectionPointStore,
                            >,
                        ),
                    )
                    .layer(axum::Extension(_bootstrap_config.clone()))
                    .layer(axum::Extension(cp_store));

                app = app.merge(Router::new().nest(&route_config.prefix, cp_router));
            }
            crate::config::RouteType::Redirect => {
                if let Some(ref target) = route_config.target {
                    info!("Adding redirect route '{}': {} -> {}", route_name, route_config.prefix, target);

                    let target_url = target.clone();
                    let redirect_handler = move || async move { axum::response::Redirect::permanent(&target_url) };

                    app = app.route(&route_config.prefix, axum::routing::get(redirect_handler));
                } else {
                    warn!("Redirect route '{}' missing 'target' field", route_name);
                }
            }
            crate::config::RouteType::Static => {
                if let Some(ref static_path) = route_config.path {
                    let resolved = std::fs::canonicalize(static_path)
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|e| format!("<unresolved: {}>", e));
                    let cwd = std::env::current_dir()
                        .map(|p| p.display().to_string())
                        .unwrap_or_else(|_| "?".to_string());
                    info!(
                        "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                        port, route_name, route_config.prefix, static_path, cwd, resolved
                    );

                    use tower_http::services::ServeDir;

                    let serve_dir = Router::new()
                        .fallback_service(
                            ServeDir::new(static_path)
                                .append_index_html_on_directories(true)
                                .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_path))),
                        )
                        .layer(axum::middleware::from_fn(static_cache_control));

                    if route_config.fallback {
                        info!("Setting '{}' as fallback static handler", route_name);
                        app = app.fallback_service(serve_dir);
                    } else if route_config.prefix == "/" {
                        app = app.nest_service("/", serve_dir);
                    } else {
                        app = app.nest_service(&route_config.prefix, serve_dir);
                    }
                } else {
                    warn!("Static route '{}' missing 'path' field", route_name);
                }
            }
        }
    }

    // Add LLM pipe routes from the network configuration (agent-stream.json)
    if let (Some(store), Some(route_mgr), Some(task_mon)) =
        (pipe_store.as_ref(), pipe_route_manager.as_ref(), task_monitor.as_ref())
    {
        // The pipe ingress prefix (e.g. `/llm`) is shared with the dashboard
        // SPA's pipe-editor routes. Resolve the SPA shell so the pipe GET
        // health handler can serve it on a direct browser refresh of those
        // routes instead of returning a "no pipe configured" error.
        let spa_index_path = network_config
            .routes
            .values()
            .find(|rc| rc.route_type == crate::config::RouteType::Static && rc.fallback)
            .and_then(|rc| rc.path.as_ref())
            .map(|p| format!("{}/index.html", p));

        // Register LLM pipe routes from the configured pipe path prefixes
        for path_config in &network_config.pipe_paths {
            let name = path_config.name.as_str();
            let prefix = path_config.prefix.as_str();
            info!("Adding LLM pipe route '{}' at prefix: {}", name, prefix);

            // Register this prefix for OpenTelemetry tracing
            crate::observability::register_pipe_prefix(prefix.to_string(), format!("[PIPE] {}", name));

            // Create metrics store for pipe metrics persistence
            let pipe_metrics_store = Some(Arc::new(crate::pipes::metrics_store::MetricsStore::new()));

            // Get the route_to_pipe HashMap from the route manager
            let route_to_pipe = route_mgr
                .route_to_pipe
                .clone();
            let listener_scopes = listener_scopes_for_port(&network_config, port);

            // Use global pipe caches for consistency across updates
            let pipe_cache = crate::pipes::cache::PIPE_CONFIG_CACHE.clone();
            let executor_cache = crate::pipes::cache::PIPE_EXECUTOR_CACHE.clone();

            let handler_state = crate::pipes::handlers::PipeHandlerState {
                pipe_store: store.clone(),
                task_monitor: task_mon.clone(),
                secrets_store: secrets_store
                    .clone()
                    .expect("Secrets store is required for pipes"),
                metrics_store: pipe_metrics_store,
                global_metrics_store: metrics_store_for_pipes
                    .clone()
                    .expect("Global metrics store is required for pipes"),
                route_to_pipe,
                listener_scopes,
                pipe_cache,
                executor_cache,
                notification_store: notification_store.clone(),
                source_auth_middleware: source_auth_middleware.clone(),
                pipe_policy_manager: Some(crate::pipes::PIPE_POLICY_MANAGER.clone()),
                spa_index_path: spa_index_path.clone(),
            };

            let route_path = format!("{}/{{{}}}", prefix, "*path");
            let variant_route_path = format!("{}${{variant}}/{{*path}}", prefix);
            let pipe_methods = axum::routing::post(crate::pipes::handlers::handle_chat_completions)
                .get(crate::pipes::handlers::handle_pipe_get);
            // The chat handler buffers the whole body via the `Bytes` extractor,
            // which otherwise falls back to axum's 2 MiB default — too small for
            // document uploads (an attached PDF/docx base64-inflates well past
            // 2 MiB). Raise the transport ceiling; the real per-document size cap
            // is governed per surface by `document_ingestion.max_file_bytes`.
            const LLM_MAX_REQUEST_BODY_BYTES: usize = 32 * 1024 * 1024;
            let llm_pipe_router = Router::new()
                .route(&route_path, pipe_methods.clone())
                .route(&variant_route_path, pipe_methods)
                .layer(axum::extract::DefaultBodyLimit::max(LLM_MAX_REQUEST_BODY_BYTES))
                .with_state(handler_state);

            app = app.merge(llm_pipe_router);
        }
    }

    // Merge Secrets/Vault router AFTER all regular routes (to override any wildcards/fallbacks in nested routers)
    // This ensures /api/v1/secrets/ and /api/v1/apikeys/ take precedence over identity router's fallback
    if let Some(ref secrets_router_ref) = secrets_router {
        info!("Merging Secrets/Vault API router (after regular routes, before fallbacks)");
        app = app.merge(secrets_router_ref.clone());
    }

    // Process fallback routes last so they don't override specific routes
    for (route_name, route_config) in fallback_routes {
        if let Some(ref static_path) = route_config.path {
            let resolved = std::fs::canonicalize(static_path)
                .map(|p| p.display().to_string())
                .unwrap_or_else(|e| format!("<unresolved: {}>", e));
            let cwd = std::env::current_dir()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "?".to_string());
            info!(
                "[WWW Hosting on port {}] static file server '{}' at prefix: {} (path: {} | cwd: {} | resolved: {})",
                port, route_name, route_config.prefix, static_path, cwd, resolved
            );

            use tower_http::services::ServeDir;

            let serve_dir = Router::new()
                .fallback_service(
                    ServeDir::new(static_path)
                        .append_index_html_on_directories(true)
                        .fallback(tower_http::services::ServeFile::new(format!("{}/index.html", static_path))),
                )
                .layer(axum::middleware::from_fn(static_cache_control));

            app = app.fallback_service(serve_dir);
        }
    }

    // Add OpenTelemetry tracing middleware for all proxy requests
    let app = app.layer(axum::middleware::from_fn(crate::observability::trace_http_request));

    // Unconditional access log: every inbound request, regardless of routing.
    let app = app.layer(axum::middleware::from_fn(crate::observability::access_log));

    // Forwarded client-cert capture (XFCC etc.) — no-op when
    // `client_auth.trusted_proxies` is empty.
    let app = app.layer(axum::middleware::from_fn_with_state(
        std::sync::Arc::new(config.tls.client_auth.clone()),
        crate::source_auth::peer_cert::forwarded_peer_cert,
    ));

    // Promote a direct-TLS peer cert (captured by PeerCertAcceptor when
    // `client_auth.direct` is enabled) into the canonical PeerCertInfo
    // extension. No-op when the upstream extension is absent.
    let app = app.layer(axum::middleware::from_fn(crate::source_auth::peer_cert::promote_direct_peer_cert));

    let app =
        app.layer(axum::middleware::from_fn_with_state(use_tls, crate::proxy::security_headers::set_security_headers));

    // Bind to 0.0.0.0:{port} to accept connections on all interfaces for this port
    let bind_addr: SocketAddr = format!("0.0.0.0:{}", port)
        .parse()
        .expect("Valid 0.0.0.0:port format");

    info!("Port listener binding to {} for {} pipe surface(s)", bind_addr, surfaces.len());

    // Serve with or without TLS based on protocol
    let result = if use_tls {
        info!("Port {} using TLS (HTTPS)", port);
        // Load TLS config (with optional client auth verifier).
        let tls_config = crate::server::load_server_config(
            &config.tls.cert_path,
            &config.tls.key_path,
            direct_client_auth
                .as_deref()
                .cloned(),
        )?;

        // Serve TLS through hyper-util's connection builder (the same path
        // `axum::serve` uses for plain HTTP) rather than `axum_server`, which
        // buffers streaming/SSE response bodies until completion. This lets
        // Server-Sent Events (e.g. the pipe streaming endpoints) flush each
        // chunk to the client incrementally. When direct client auth is
        // enabled, the presented peer certificate is captured from the rustls
        // connection after the handshake and injected as a request extension,
        // matching the previous `PeerCertAcceptor` behaviour.
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        let tls_acceptor = TlsAcceptor::from(tls_config);
        let capture_peer_cert = direct_client_auth.is_some();
        serve_app_tls(listener, tls_acceptor, app, capture_peer_cert).await
    } else {
        info!("Port {} using plain HTTP (no TLS)", port);
        // Create plain TCP listener
        let listener = tokio::net::TcpListener::bind(bind_addr).await?;
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await
    };

    info!("Port listener {} stopped", port);

    result?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::{get, post};
    use tower::ServiceExt;

    /// A listener with the management API mounted at `prefix`, a top-level
    /// `/api/v1/...` route as the vault router adds one, and, when
    /// `with_dashboard`, the dashboard's static fallback.
    fn listener_app(
        prefix: &str,
        with_dashboard: bool,
    ) -> Router {
        let api = Router::new().route("/v1/known", get(|| async { "known" }));
        let app = mount_identity_api(Router::new(), prefix, api)
            .route("/api/v1/secrets", get(|| async { "secrets" }))
            .route("/llm/{*path}", post(|| async { "pipe" }));
        if with_dashboard {
            app.fallback(|| async { axum::response::Html("<html>dashboard</html>") })
        } else {
            app
        }
    }

    async fn send(
        app: &Router,
        method: Method,
        path: &str,
    ) -> (StatusCode, String, String) {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .method(method)
                    .uri(path)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let status = response.status();
        let content_type = response
            .headers()
            .get(hyper::header::CONTENT_TYPE)
            .map(|value| {
                value
                    .to_str()
                    .unwrap()
                    .to_string()
            })
            .unwrap_or_default();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, content_type, String::from_utf8(body.to_vec()).unwrap())
    }

    #[tokio::test]
    async fn unknown_path_under_a_nested_api_is_not_found_instead_of_the_dashboard() {
        let app = listener_app("/api", true);

        for path in ["/api/v1/definitely-not-a-route", "/api/v1/zzz/qqq", "/api/v1/gateway/config"] {
            let (status, content_type, body) = send(&app, Method::GET, path).await;
            assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(content_type, "application/json", "{path}");
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&body).unwrap(),
                serde_json::json!({ "error": "Not found" }),
                "{path}"
            );
        }
    }

    #[tokio::test]
    async fn nested_api_not_found_leaves_matched_routes_and_the_dashboard_alone() {
        let app = listener_app("/api", true);

        for (method, path, expected) in [
            (Method::GET, "/api/v1/known", "known"),
            (Method::GET, "/api/v1/secrets", "secrets"),
            (Method::POST, "/llm/chat/v1/chat/completions", "pipe"),
            (Method::GET, "/surfaces/llm/new", "<html>dashboard</html>"),
        ] {
            let (status, _, body) = send(&app, method, path).await;
            assert_eq!(status, StatusCode::OK, "{path}");
            assert_eq!(body, expected, "{path}");
        }
    }

    #[tokio::test]
    async fn api_at_the_root_keeps_the_listener_fallback() {
        let (status, _, body) = send(&listener_app("/", true), Method::GET, "/v1/not-a-route").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, "<html>dashboard</html>");

        let (status, _, body) = send(&listener_app("/", false), Method::POST, "/missing/v1/chat/completions").await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(body.is_empty(), "an unpublished route is a plain 404, got {body:?}");

        let (status, _, body) = send(&listener_app("/", false), Method::GET, "/v1/known").await;
        assert_eq!((status, body.as_str()), (StatusCode::OK, "known"));
    }

    #[test]
    fn join_empty_host_empty_route_returns_fabric() {
        assert_eq!(join_host_and_route("", ""), "fabric");
    }

    #[test]
    fn join_empty_host_slash_route_returns_fabric() {
        assert_eq!(join_host_and_route("", "/"), "fabric");
    }

    #[test]
    fn join_empty_host_with_absolute_route() {
        assert_eq!(join_host_and_route("", "/api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_empty_host_with_relative_route() {
        assert_eq!(join_host_and_route("", "api/v1"), "fabric/api/v1");
    }

    #[test]
    fn join_host_with_empty_route() {
        assert_eq!(join_host_and_route("https://example.com", ""), "https://example.com");
    }

    #[test]
    fn join_host_with_slash_route() {
        assert_eq!(join_host_and_route("https://example.com", "/"), "https://example.com");
    }

    #[test]
    fn join_host_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_absolute_route() {
        assert_eq!(join_host_and_route("https://example.com/", "/api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_with_relative_route() {
        assert_eq!(join_host_and_route("https://example.com/", "api/v1"), "https://example.com/api/v1");
    }

    #[test]
    fn join_host_trailing_slash_empty_route() {
        assert_eq!(join_host_and_route("https://example.com/", ""), "https://example.com");
    }
}
