//! Channel task manager for managing proxy channels lifecycle

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::AbortHandle;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;

/// Extract port number from an address string
#[allow(dead_code)]
fn extract_port_from_address(addr: &str) -> Option<u16> {
    let addr_without_protocol = addr
        .trim_start_matches("https://")
        .trim_start_matches("http://");

    let default_port = if addr.starts_with("https://") {
        443
    } else if addr.starts_with("http://") {
        80
    } else {
        0
    };

    if let Some(colon_pos) = addr_without_protocol.rfind(':') {
        let port_str = &addr_without_protocol[colon_pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            return Some(port);
        }
    }

    if default_port > 0 {
        Some(default_port)
    } else {
        None
    }
}

/// Shared state for managing channel tasks and configuration reloading
#[derive(Clone)]
pub struct SurfaceTaskManager {
    /// Handles to running port listener tasks (mapped by port - should NOT be restarted)
    pub(crate) port_listener_handles: Arc<RwLock<HashMap<u16, AbortHandle>>>,
    /// Handles to running channel tasks mapped by channel name (DEPRECATED - channels don't have separate tasks anymore)
    pub(crate) channel_handles: Arc<RwLock<HashMap<String, AbortHandle>>>,
    /// Task IDs mapped by channel name (for unregistering from TaskMonitor)
    pub(crate) task_ids: Arc<RwLock<HashMap<String, String>>>,
    /// Configuration for channels
    config: Arc<RwLock<Arc<GatewayConfig>>>,
    /// Bootstrap configuration
    bootstrap_config: Arc<crate::config::BootstrapConfig>,
    /// Configuration cache for fallback
    config_cache: Arc<crate::storage::ConfigCache>,
    /// WebSocket state for real-time updates (shared across all channels)
    ws_state: Option<Arc<crate::server::WsState>>,
    /// VC issuer for generating agent DIDs
    vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
    /// Connection point listener manager for fabric:// protocol forwarding
    listener_manager: Arc<RwLock<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>>,
    /// Identity API routers for HTTP and HTTPS (to be merged into port listeners during reload)
    identity_http_router: Arc<RwLock<Option<axum::Router>>>,
    identity_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// DID routers for HTTP and HTTPS
    did_http_router: Arc<RwLock<Option<axum::Router>>>,
    did_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// Secrets/Vault routers for HTTP and HTTPS
    vault_http_router: Arc<RwLock<Option<axum::Router>>>,
    vault_https_router: Arc<RwLock<Option<axum::Router>>>,
    /// Secrets store for secrets API
    secrets_store: Arc<RwLock<Option<Arc<dyn crate::secrets::SecretsStore>>>>,
    /// Policy manager for OPA policies
    policy_manager: Arc<RwLock<Option<Arc<crate::policies::SurfacePolicyManager>>>>,
    /// Gateway-level policy manager for gateway-wide OPA policies
    gateway_policy_manager: Arc<RwLock<Option<Arc<crate::policies::GatewayPolicyManager>>>>,
    /// Pipe store for LLM pipes
    pipe_store: Arc<RwLock<Option<Arc<crate::pipes::FileSystemPipeStore>>>>,
    /// Pipe route manager for dynamic pipe route registration
    pipe_route_manager: Arc<RwLock<Option<Arc<crate::pipes::PipeRouteManager>>>>,
    /// Settings store for pipes to access secrets
    settings_store: Arc<crate::storage::SettingsStore>,
    /// Notification store for integration triggering
    notification_store: Arc<RwLock<Option<Arc<crate::integrations::FileSystemNotificationStore>>>>,
    /// Unified source authentication middleware
    source_auth_middleware: Arc<RwLock<Option<Arc<crate::source_auth::SourceAuthMiddleware>>>>,
    /// Direct-TLS inbound client auth (CA bundle + mode) — enables peer-cert capture on listeners
    direct_client_auth: Arc<RwLock<Option<Arc<crate::server::DirectClientAuth>>>>,
    /// DID:webvh identity store for channel DID injection
    #[cfg(feature = "didwebvh")]
    didwebvh_identity_store: Arc<RwLock<Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>>>,
    /// DID:webvh log storage for channel DID log access
    #[cfg(feature = "didwebvh")]
    didwebvh_log_storage: Arc<RwLock<Option<Arc<dyn crate::storage::DidLogStorage>>>>,
}

impl SurfaceTaskManager {
    pub fn new(
        config: Arc<GatewayConfig>,
        bootstrap_config: Arc<crate::config::BootstrapConfig>,
        config_cache: Arc<crate::storage::ConfigCache>,
        ws_state: Option<Arc<crate::server::WsState>>,
        vc_issuer: Option<Arc<crate::identity::VCIssuer>>,
        listener_manager: Option<Arc<crate::gateways::ConnectionPointListenerManager>>,
        settings_store: Arc<crate::storage::SettingsStore>,
    ) -> Self {
        Self {
            port_listener_handles: Arc::new(RwLock::new(HashMap::new())),
            channel_handles: Arc::new(RwLock::new(HashMap::new())),
            task_ids: Arc::new(RwLock::new(HashMap::new())),
            config: Arc::new(RwLock::new(config)),
            bootstrap_config,
            config_cache,
            ws_state,
            vc_issuer,
            listener_manager: Arc::new(RwLock::new(listener_manager)),
            // Initialize router storage as empty - will be set by orchestrator after routers are created
            identity_http_router: Arc::new(RwLock::new(None)),
            identity_https_router: Arc::new(RwLock::new(None)),
            did_http_router: Arc::new(RwLock::new(None)),
            did_https_router: Arc::new(RwLock::new(None)),
            vault_http_router: Arc::new(RwLock::new(None)),
            vault_https_router: Arc::new(RwLock::new(None)),
            secrets_store: Arc::new(RwLock::new(None)),
            policy_manager: Arc::new(RwLock::new(None)),
            gateway_policy_manager: Arc::new(RwLock::new(None)),
            pipe_store: Arc::new(RwLock::new(None)),
            pipe_route_manager: Arc::new(RwLock::new(None)),
            settings_store,
            notification_store: Arc::new(RwLock::new(None)),
            source_auth_middleware: Arc::new(RwLock::new(None)),
            direct_client_auth: Arc::new(RwLock::new(None)),
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: Arc::new(RwLock::new(None)),
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: Arc::new(RwLock::new(None)),
        }
    }

    /// Set the Identity API and supporting routers (called by orchestrator after router creation)
    pub async fn set_identity_routers(
        &self,
        identity_http: Option<axum::Router>,
        identity_https: Option<axum::Router>,
        did_http: Option<axum::Router>,
        did_https: Option<axum::Router>,
        vault_http: Option<axum::Router>,
        vault_https: Option<axum::Router>,
    ) {
        *self
            .identity_http_router
            .write()
            .await = identity_http;
        *self
            .identity_https_router
            .write()
            .await = identity_https;
        *self
            .did_http_router
            .write()
            .await = did_http;
        *self
            .did_https_router
            .write()
            .await = did_https;
        *self
            .vault_http_router
            .write()
            .await = vault_http;
        *self
            .vault_https_router
            .write()
            .await = vault_https;
    }

    /// Set related services (called by orchestrator)
    pub async fn set_services(
        &self,
        secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
        policy_manager: Option<Arc<crate::policies::SurfacePolicyManager>>,
        gateway_policy_manager: Option<Arc<crate::policies::GatewayPolicyManager>>,
    ) {
        *self
            .secrets_store
            .write()
            .await = secrets_store;
        *self
            .policy_manager
            .write()
            .await = policy_manager;
        *self
            .gateway_policy_manager
            .write()
            .await = gateway_policy_manager;
    }

    /// Get the current configuration
    pub async fn get_config(&self) -> Arc<GatewayConfig> {
        self.config
            .read()
            .await
            .clone()
    }

    /// Set the listener manager (called after it's created during startup)
    pub async fn set_listener_manager(
        &self,
        listener_manager: Arc<crate::gateways::ConnectionPointListenerManager>,
    ) {
        let mut mgr = self
            .listener_manager
            .write()
            .await;
        *mgr = Some(listener_manager);
        info!("✓ Listener manager set in SurfaceTaskManager - fabric:// protocol now available");
    }

    /// Set pipe services (called during startup)
    pub async fn set_pipe_services(
        &self,
        pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
        pipe_route_manager: Option<Arc<crate::pipes::PipeRouteManager>>,
    ) {
        *self.pipe_store.write().await = pipe_store;
        *self
            .pipe_route_manager
            .write()
            .await = pipe_route_manager;
        info!("✓ Pipe services set in SurfaceTaskManager");
    }

    /// Set notification store (called during startup)
    pub async fn set_notification_store(
        &self,
        notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    ) {
        *self
            .notification_store
            .write()
            .await = notification_store;
        info!("✓ Notification store set in SurfaceTaskManager");
    }

    /// Set the unified source authentication middleware
    pub async fn set_source_auth_middleware(
        &self,
        source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    ) {
        *self
            .source_auth_middleware
            .write()
            .await = source_auth_middleware;
        info!("✓ Source auth middleware set in SurfaceTaskManager");
    }

    /// Set the direct-TLS inbound client auth (used when starting/reloading listeners)
    pub async fn set_direct_client_auth(
        &self,
        direct_client_auth: Option<Arc<crate::server::DirectClientAuth>>,
    ) {
        *self
            .direct_client_auth
            .write()
            .await = direct_client_auth;
        info!("✓ Direct-TLS client auth set in SurfaceTaskManager");
    }

    /// Set DID:webvh stores (called during startup after identity state is initialized)
    #[cfg(feature = "didwebvh")]
    pub async fn set_didwebvh_stores(
        &self,
        identity_store: Option<Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
        log_storage: Option<Arc<dyn crate::storage::DidLogStorage>>,
    ) {
        *self
            .didwebvh_identity_store
            .write()
            .await = identity_store;
        *self
            .didwebvh_log_storage
            .write()
            .await = log_storage;
        info!("✓ DID:webvh stores set in SurfaceTaskManager");
    }

    /// Update configuration and restart channel tasks
    /// Returns (channels_count, is_fallback, warning_message)
    pub async fn reload_channels(
        &self,
        new_config: Arc<GatewayConfig>,
        tls_acceptor: TlsAcceptor,
        client: reqwest::Client,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(usize, bool, Option<String>)> {
        info!("Reloading channel configuration...");

        // Step 1: Abort all existing port listener tasks
        {
            let mut handles = self
                .channel_handles
                .write()
                .await;
            let mut task_ids_map = self.task_ids.write().await;
            info!("Stopping {} existing per-channel listener tasks", handles.len());

            // Abort all per-channel handles (legacy; usually empty in the
            // port-listener model).
            for (channel_name, handle) in handles.drain() {
                info!("Aborting per-channel listener: {}", channel_name);
                handle.abort();
            }

            // Clear task IDs map
            task_ids_map.clear();
        }

        // Step 1b: Abort the previous port listeners so their TCP sockets
        // are released before we rebind below. Without this the new
        // listeners hit "Address already in use (os error 48)" because
        // the old tasks are still owning 8080/8081/8443.
        {
            let mut port_handles = self
                .port_listener_handles
                .write()
                .await;
            info!("Stopping {} existing port listener task(s)", port_handles.len());
            for (port, handle) in port_handles.drain() {
                info!("Aborting port listener on port {}", port);
                handle.abort();
            }
        }

        // Step 2: Drop stale TaskInfo entries proactively. Aborting a
        // port listener cancels the `axum_server::serve(...).await`
        // point, so the post-await cleanup in `run_port_server` that
        // would normally call `unregister_task` never executes. Without
        // this clear, every reload accumulates duplicate AP rows
        // (their task_ids embed a fresh UUID, so re-registration does
        // not overwrite). Then sleep briefly so the OS releases the
        // listening sockets before we rebind them below.
        if let Some(ref monitor) = task_monitor {
            let cleared = monitor
                .clear_all_tasks()
                .await;
            if cleared > 0 {
                info!("Cleared {} stale task(s) from monitor before reload", cleared);
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;

        // Step 2: Update configuration
        {
            let mut config_lock = self.config.write().await;
            *config_lock = new_config.clone();
        }

        // Step 3: Save successful configuration to cache
        if let Err(e) = self
            .config_cache
            .save(&new_config, "dynamodb")
            .await
        {
            warn!("Failed to save configuration to cache: {}", e);
        }

        // Step 4: Load network configuration and extract ports
        let network_config = self
            .bootstrap_config
            .load_network_config()
            .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

        let configured_ports = network_config.get_ports();
        info!("Using ports from network config: {:?}", configured_ports);

        // Helper function to map external listen_address to internal port
        let map_address_to_port = |listen_addr: &str| -> Option<u16> { network_config.map_url_to_port(listen_addr) };

        // Helper that prefers outbound listeners when mapping outbound addresses
        let _map_outbound_address_to_port = |listen_addr: &str| -> Option<u16> {
            network_config.map_url_to_port_for_type(listen_addr, Some("outbound"))
        };

        let channels_count = new_config.surfaces.len();

        // Group channels by the port they'll use (inbound). Stored as
        // `AgentSurface` so `variants` / `default_variant_id` survive into the
        // runtime listener.
        let mut channels_by_port: HashMap<u16, Vec<crate::config::agent_surface::AgentSurface>> = HashMap::new();
        for surface in new_config.surfaces.iter() {
            let listen_address = surface.listen_address();
            let surface_name = &surface.name;
            // Map channel's listen_address to internal port (inbound traffic)
            if let Some(port) = map_address_to_port(listen_address) {
                // Only include channel if its mapped port is in the configured ports
                if configured_ports.contains(&port) {
                    channels_by_port
                        .entry(port)
                        .or_default()
                        .push(surface.clone());
                } else {
                    warn!(
                        "Channel '{}' maps to port {} which is not in configured ports {:?} - skipping",
                        surface_name, port, configured_ports
                    );
                }
            } else {
                warn!(
                    "Could not map channel '{}' listen_address '{}' to any internal port - skipping",
                    surface_name, listen_address
                );
            }
        }

        // Group outbound-enabled channels by their outbound listener port.
        info!("Grouped {} channels across {} configured ports", channels_count, channels_by_port.len());

        // Store handles for port listeners
        let mut new_port_handles = HashMap::new();

        // Spawn ONE listener task per configured port that handles routing to all channels on that port
        // Iterate over ALL configured ports, not just those with channels

        // Get stored routers for merging into port listeners
        let identity_http_router = self
            .identity_http_router
            .read()
            .await
            .clone();
        let identity_https_router = self
            .identity_https_router
            .read()
            .await
            .clone();
        let did_http_router = self
            .did_http_router
            .read()
            .await
            .clone();
        let did_https_router = self
            .did_https_router
            .read()
            .await
            .clone();
        let vault_http_router = self
            .vault_http_router
            .read()
            .await
            .clone();
        let vault_https_router = self
            .vault_https_router
            .read()
            .await
            .clone();
        let secrets_store = self
            .secrets_store
            .read()
            .await
            .clone();
        let policy_manager = self
            .policy_manager
            .read()
            .await
            .clone();

        for port in configured_ports {
            // Get channels for this port (may be empty)
            let channels = channels_by_port
                .get(&port)
                .cloned()
                .unwrap_or_default();
            let port_task_id = format!("port-{}-{}", port, uuid::Uuid::new_v4());
            let tls_acceptor = tls_acceptor.clone();
            let client = client.clone();
            let config = new_config.clone();
            let bootstrap_config_clone = self.bootstrap_config.clone();
            let metrics = metrics_store.clone();
            let task_mon = task_monitor.clone();
            let task_id_clone = port_task_id.clone();
            let ws_state_clone = self.ws_state.clone();
            let vc_issuer_clone = self.vc_issuer.clone();
            let channels_clone = channels.clone(); // Clone for the async block
            let listener_mgr_clone = self.listener_manager.clone();
            let network_config_clone = Arc::new(network_config.clone());

            // Determine if this port should use TLS based on network config
            let listener_info = network_config
                .listeners
                .iter()
                .find(|l| l.port == port);

            let use_tls = listener_info
                .map(|l| l.protocol.to_lowercase() == "https")
                .unwrap_or(false);

            // Check whether this is an outbound listener.
            let listener_type = listener_info
                .map(|l| l.listener_type.as_str())
                .unwrap_or("inbound");

            if listener_type == "outbound" {
                info!("Outbound listener on port {} is no longer served (pipe-only mode) — skipping", port);
                let handle = tokio::spawn(std::future::pending::<()>());
                new_port_handles.insert(port, handle.abort_handle());
                continue;
            }

            info!(
                "Reloading port listener on 0.0.0.0:{} for {} channel(s), protocol: {}",
                port,
                channels.len(),
                if use_tls {
                    "HTTPS"
                } else {
                    "HTTP"
                }
            );

            // Determine which routers to merge into this port based on TLS setting
            let identity_router = if use_tls {
                identity_https_router.clone()
            } else {
                identity_http_router.clone()
            };
            let did_router = if use_tls {
                did_https_router.clone()
            } else {
                did_http_router.clone()
            };
            let vault_router = if use_tls {
                vault_https_router.clone()
            } else {
                vault_http_router.clone()
            };

            let secrets_store_clone = secrets_store.clone();
            let policy_manager_clone = policy_manager.clone();
            let gateway_policy_manager_clone = self
                .gateway_policy_manager
                .read()
                .await
                .clone();
            let pipe_store_clone = self
                .pipe_store
                .read()
                .await
                .clone();
            let pipe_route_manager_clone = self
                .pipe_route_manager
                .read()
                .await
                .clone();
            let settings_store_clone = self.settings_store.clone();
            let notification_store_clone = self
                .notification_store
                .read()
                .await
                .clone();
            let source_auth_middleware_clone = self
                .source_auth_middleware
                .read()
                .await
                .clone();
            let direct_client_auth_clone = self
                .direct_client_auth
                .read()
                .await
                .clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_identity_store_clone = self
                .didwebvh_identity_store
                .read()
                .await
                .clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_log_storage_clone = self
                .didwebvh_log_storage
                .read()
                .await
                .clone();

            let handle = tokio::spawn(async move {
                if let Err(e) = super::server::run_port_server(
                    port,
                    channels_clone,
                    tls_acceptor,
                    client,
                    config,
                    bootstrap_config_clone,
                    metrics,
                    task_mon.clone(),
                    Some(task_id_clone.clone()),
                    ws_state_clone,
                    vc_issuer_clone,
                    listener_mgr_clone,
                    identity_router,     // Pass Identity API router
                    did_router,          // Pass DID router
                    vault_router,        // Pass Vault router
                    secrets_store_clone, // Pass secrets store
                    network_config_clone,
                    use_tls,
                    policy_manager_clone,         // Pass policy manager
                    gateway_policy_manager_clone, // Pass gateway policy manager
                    pipe_store_clone,             // Pass pipe store
                    pipe_route_manager_clone,     // Pass pipe route manager
                    settings_store_clone,         // Pass settings store
                    notification_store_clone,     // Pass notification store
                    source_auth_middleware_clone, // Pass unified source auth middleware
                    direct_client_auth_clone,     // Pass direct-TLS client auth
                    #[cfg(feature = "didwebvh")]
                    didwebvh_identity_store_clone,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_log_storage_clone,
                )
                .await
                {
                    error!("Port listener error for port {}: {}", port, e);
                }
            });

            // Store the abort handle for this port listener
            new_port_handles.insert(port, handle.abort_handle());

            // Note: Individual channel task IDs are managed by the port listener itself
            // We don't create or track them here - the port listener registers them with the task monitor
        }

        // Step 5: Store new handles
        {
            let mut port_handles = self
                .port_listener_handles
                .write()
                .await;
            *port_handles = new_port_handles;
        }

        // Clear channel handles and task IDs since they're now managed by port listeners
        {
            let mut handles = self
                .channel_handles
                .write()
                .await;
            handles.clear();
        }
        {
            let mut task_ids_map = self.task_ids.write().await;
            task_ids_map.clear();
        }

        // Step 6: Reconcile fabric transit-point (connection-point) listeners so a
        // reload that disabled/deleted a connection point or gateway leaves no
        // stale serving path. Removal only; (re)starting is owned by the CP CRUD
        // handlers and startup auto-start (they resolve the mediator to connect).
        if let Some(listener_mgr) = self
            .listener_manager
            .read()
            .await
            .clone()
        {
            let stopped = listener_mgr
                .reconcile_listeners()
                .await;
            if stopped > 0 {
                info!("Reload reconciliation stopped {} stale transit-point listener(s)", stopped);
            }
        }

        info!("Successfully reloaded {} channels", channels_count);
        Ok((channels_count, false, None))
    }

    /// Reload channels with fallback to cached configuration on failure
    pub async fn reload_channels_with_fallback(
        &self,
        new_config_result: anyhow::Result<Arc<GatewayConfig>>,
        tls_acceptor: TlsAcceptor,
        client: reqwest::Client,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(usize, bool, Option<String>)> {
        match new_config_result {
            Ok(new_config) => {
                // Try to reload with new configuration
                self.reload_channels(new_config, tls_acceptor, client, metrics_store, task_monitor)
                    .await
            }
            Err(load_error) => {
                // Failed to load new config, try to use cached config
                warn!("Failed to load new configuration: {}. Attempting to use cached configuration.", load_error);

                match self.config_cache.load().await {
                    Ok(cached) => {
                        info!(
                            cached_at = %cached.cached_at,
                            channels = cached.config.surfaces.len(),
                            "Using cached configuration as fallback"
                        );

                        let warning = format!(
                            "Failed to load new configuration from DynamoDB. Using cached configuration from {}. Error: {}",
                            cached.cached_at, load_error
                        );

                        // Reload with cached config
                        let new_config = Arc::new(cached.config);
                        match self
                            .reload_channels(new_config, tls_acceptor, client, metrics_store, task_monitor)
                            .await
                        {
                            Ok((channels_count, _, _)) => Ok((channels_count, true, Some(warning))),
                            Err(e) => {
                                error!("Failed to reload even with cached configuration: {}", e);
                                Err(e)
                            }
                        }
                    }
                    Err(cache_error) => {
                        error!(
                            load_error = %load_error,
                            cache_error = %cache_error,
                            "Failed to load new configuration and no cached configuration available"
                        );
                        anyhow::bail!(
                            "Failed to load new configuration: {}. Also failed to load cached configuration: {}",
                            load_error,
                            cache_error
                        )
                    }
                }
            }
        }
    }

    /// Reload a single channel by name
    /// Updates the channel in the running port listener's state WITHOUT restarting the listener
    /// Returns (is_fallback, warning_message)
    pub async fn reload_single_channel(
        &self,
        channel_name: &str,
        new_surface: crate::config::agent_surface::AgentSurface,
        _tls_acceptor: TlsAcceptor,
        _client: reqwest::Client,
        _metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        _task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(bool, Option<String>)> {
        debug!("Reloading single channel: {}", channel_name);

        let surface_name = new_surface.name.clone();
        let surface_listen_address = new_surface
            .listen_address()
            .to_string();

        // Update the surface in the in-memory config and persist to cache.
        // Surface request routing is served from the surface store, so no
        // port-listener restart is required for the change to take effect.
        let port: u16;
        {
            let mut config_lock = self.config.write().await;
            let mut new_config = (**config_lock).clone();

            // Find and replace the channel by config_id, or add it if it doesn't exist
            if let Some(config_id) = new_surface.config_id() {
                if let Some(idx) = new_config
                    .surfaces
                    .iter()
                    .position(|r| r.config_id() == Some(config_id))
                {
                    new_config.surfaces[idx] = new_surface.clone();
                    info!("Updated existing channel with config_id '{}': {}", config_id, surface_name);
                    crate::channel_info!(config_id, "Updated existing channel: {}", surface_name);
                } else {
                    new_config
                        .surfaces
                        .push(new_surface.clone());
                    info!("Added new channel with config_id '{}': {}", config_id, surface_name);
                    crate::channel_info!(config_id, "Added new channel: {}", surface_name);
                }
            } else {
                // All channels MUST have config_id - this should never happen
                error!("Channel '{}' has no config_id - this should never happen!", surface_name);
                return Err(anyhow::anyhow!("Channel '{}' has no config_id", surface_name));
            }

            // Load network configuration to map addresses to ports
            let network_config = self
                .bootstrap_config
                .load_network_config()
                .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

            // Get the port for this channel
            port = network_config
                .map_url_to_port(&surface_listen_address)
                .ok_or_else(|| {
                    anyhow::anyhow!("Could not map channel listen_address to internal port: {}", surface_listen_address)
                })?;

            *config_lock = Arc::new(new_config.clone());

            // Save updated configuration to cache
            if let Err(e) = self
                .config_cache
                .save(&new_config, "single_channel_reload")
                .await
            {
                warn!("Failed to save configuration to cache: {}", e);
            }
        }

        info!("Reloaded surface '{}' configuration (inbound port {})", channel_name, port);
        if let Some(config_id) = new_surface.config_id() {
            crate::channel_info!(config_id, "Reloaded surface configuration");
        }

        Ok((false, None))
    }

    /// Reload a single channel with fallback to cached configuration
    pub async fn reload_single_channel_with_fallback(
        &self,
        channel_name: &str,
        new_surface_result: anyhow::Result<crate::config::agent_surface::AgentSurface>,
        tls_acceptor: TlsAcceptor,
        client: reqwest::Client,
        metrics_store: Option<Arc<crate::metrics::MetricsStore>>,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<(bool, Option<String>)> {
        match new_surface_result {
            Ok(new_surface) => {
                // Try to reload the single channel
                self.reload_single_channel(channel_name, new_surface, tls_acceptor, client, metrics_store, task_monitor)
                    .await
            }
            Err(load_error) => {
                // Failed to load new channel, try to use cached config
                warn!(
                    "Failed to load channel '{}': {}. Attempting to use cached configuration.",
                    channel_name, load_error
                );

                match self.config_cache.load().await {
                    Ok(_cached) => {
                        // This function should not be called without a config_id in the error case
                        // Log error and return the load_error
                        error!(
                            "Cannot use fallback for channel '{}' - original error did not provide config_id",
                            channel_name
                        );
                        Err(load_error)
                    }
                    Err(cache_error) => {
                        error!(
                            load_error = %load_error,
                            cache_error = %cache_error,
                            channel = channel_name,
                            "Failed to load channel and no cached configuration available"
                        );
                        anyhow::bail!(
                            "Failed to load channel '{}': {}. Also failed to load cached configuration: {}",
                            channel_name,
                            load_error,
                            cache_error
                        )
                    }
                }
            }
        }
    }

    /// Remove a single channel by config_id from the running gateway WITHOUT
    /// restarting port listeners.
    ///
    /// Surface request routing is resolved dynamically from the surface store
    /// cache, so dropping the channel from the in-memory config + config cache
    /// and reconciling stale transit-point listeners is sufficient. Returns
    /// `Ok(false)` when the config_id is not present in the current config
    /// (already absent — nothing to do).
    pub async fn remove_single_channel(
        &self,
        config_id: &str,
        _task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
    ) -> anyhow::Result<bool> {
        debug!("Removing single channel: {}", config_id);

        {
            let mut config_lock = self.config.write().await;
            let mut new_config = (**config_lock).clone();
            let Some(idx) = new_config
                .surfaces
                .iter()
                .position(|c| c.config_id() == Some(config_id))
            else {
                debug!("remove_single_channel: config_id '{}' not in current config", config_id);
                return Ok(false);
            };
            new_config
                .surfaces
                .remove(idx);
            *config_lock = Arc::new(new_config.clone());

            if let Err(e) = self
                .config_cache
                .save(&new_config, "single_channel_remove")
                .await
            {
                warn!("Failed to save configuration to cache after removal: {}", e);
            }
        }

        // Stop any stale transit-point listener owned by the removed surface.
        // Removal only; (re)starting is owned by the connection-point CRUD
        // handlers and startup auto-start.
        if let Some(listener_mgr) = self
            .listener_manager
            .read()
            .await
            .clone()
        {
            let stopped = listener_mgr
                .reconcile_listeners()
                .await;
            if stopped > 0 {
                info!("Removal reconciliation stopped {} stale transit-point listener(s)", stopped);
            }
        }

        info!("Removed channel with config_id '{}' from running gateway", config_id);
        Ok(true)
    }
}
