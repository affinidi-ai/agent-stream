use anyhow::Context;
use axum::Router;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::auth::periodic_session_cleanup;
use crate::config::GatewayConfig;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::gateways::filesystem::GatewayStore;
use crate::mediators::filesystem::MediatorStore;
use crate::observability::periodic_metrics_update;

// Re-export SurfaceTaskManager for backward compatibility
pub use crate::proxy::SurfaceTaskManager;

/// Resolve a shipped-default seed directory. Absolute paths are used as-is;
/// relative paths are joined onto the bootstrap config directory (mirroring the
/// LLM-surface template seed-dir resolution) so default-config content lives
/// alongside the other config files, falling back to the raw relative path when
/// no config dir is known.
fn resolve_config_relative(
    config_dir: &Option<PathBuf>,
    raw: &str,
) -> PathBuf {
    let path = std::path::Path::new(raw);
    if path.is_absolute() {
        path.to_path_buf()
    } else if let Some(dir) = config_dir.as_ref() {
        dir.join(path)
    } else {
        path.to_path_buf()
    }
}

/// Initialise the unified [`crate::source_auth::SourceAuthMiddleware`].
///
/// Builds the middleware from the secrets store, API key validator, and JWT strategy
/// store.
///
/// Returns `None` (with a warning) if the JWT verification strategy store cannot be
/// created; the gateway continues to start but source authentication will be unavailable.
async fn init_source_auth_middleware(
    secrets_storage_path: &str,
    http_client: reqwest::Client,
    secrets_store: Option<Arc<dyn crate::secrets::SecretsStore>>,
    secrets_cache: crate::secrets::SecretsCache,
    api_key_validator: Option<Arc<dyn crate::api_keys::ApiKeyValidator>>,
    cert_store: Option<Arc<dyn crate::certificates::CertificateStore>>,
) -> Option<Arc<crate::source_auth::SourceAuthMiddleware>> {
    let storage_path = PathBuf::from(secrets_storage_path)
        .parent()
        .map(|p| p.join("jwt_verification_strategies"))
        .unwrap_or_else(|| PathBuf::from("_storage/jwt_verification_strategies"));

    match crate::jwt_bearer::FileSystemJwtVerificationStrategyStore::new(storage_path.clone()).await {
        Ok(store) => {
            info!("Source auth: JWT verification strategy store initialised at {}", storage_path.display());
            let store_arc: Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage> = Arc::new(store);
            {
                let s = store_arc.clone();
                crate::config::register_counter("credentials.jwt", move || {
                    let s = s.clone();
                    async move {
                        s.list()
                            .await
                            .map(|v| v.len())
                            .unwrap_or(0)
                    }
                });
            }
            let jwks_http = crate::http_client::with_short_timeout().unwrap_or_else(|_| http_client.clone());
            let jwks_client = Arc::new(crate::jwt_bearer::JwksClient::new(jwks_http));
            Some(Arc::new(crate::source_auth::SourceAuthMiddleware::new(
                store_arc,
                jwks_client,
                secrets_store,
                secrets_cache,
                api_key_validator,
                cert_store,
            )))
        }
        Err(e) => {
            warn!(
                "Failed to initialise source auth middleware (JWT strategy store at {}): {}",
                storage_path.display(),
                e
            );
            None
        }
    }
}

/// Register live entity counters for appliance resource-limit enforcement.
///
/// Each counter reports the current number of entities for a leaf dimension so
/// [`crate::config::enforce_add`] can compare against the configured limit at
/// create time. Multi-store umbrellas (`secrets`, `credentials`, `connections`)
/// are summed from their leaves; single-store umbrellas (`surfaces`, `policies`)
/// register a direct total alongside their per-type leaves. Counters for
/// `credentials.jwt` and `secrets.apikeys` are registered at those stores' own
/// construction sites. Stores exposed via process-global accessors
/// (oauth/integrations/teams/members/prompts) are resolved lazily inside the
/// counter closures.
#[allow(clippy::too_many_arguments)]
fn register_resource_limit_counters(
    secrets_store: &Arc<dyn crate::secrets::SecretsStore>,
    certificates_store: &Arc<dyn crate::certificates::CertificateStore>,
    credential_provider_store: &Option<Arc<crate::credential_providers::storage::FileSystemCredentialProviderStore>>,
    delegation_vault_store: &Option<Arc<crate::delegation_vault::storage::FileSystemDelegationVaultStore>>,
    gateway_store: &Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    mediator_store: &Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    connection_point_store: &Option<Arc<crate::gateways::FileSystemConnectionPointStore>>,
    pipe_store: &Option<Arc<crate::pipes::FileSystemPipeStore>>,
    policy_definition_store: &Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>,
) {
    use crate::config::register_counter;
    use crate::credential_providers::storage::CredentialProviderStorage as _;
    use crate::delegation_vault::storage::DelegationVaultStorage as _;

    // secrets.secret — the general secrets vault.
    {
        let s = secrets_store.clone();
        register_counter("secrets.secret", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // secrets.certificates
    {
        let s = certificates_store.clone();
        register_counter("secrets.certificates", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // credentials.oauth — resolved via the global store accessor.
    register_counter("credentials.oauth", || async {
        match crate::oauth_identifiers::global_oauth_identifier_store() {
            Some(s) => s
                .list()
                .await
                .map(|v| v.len())
                .unwrap_or(0),
            None => 0,
        }
    });
    // credentials.providers
    if let Some(store) = credential_provider_store {
        let s = store.clone();
        register_counter("credentials.providers", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // credentials.tokens — delegation-vault tokens (no direct create gate, but
    // counted so the `credentials` umbrella total is accurate).
    if let Some(store) = delegation_vault_store {
        let s = store.clone();
        register_counter("credentials.tokens", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // connections.gateways (excludes the appliance's own self-gateway, which is
    // system infrastructure and must not consume the customer's quota).
    if let Some(store) = gateway_store {
        let s = store.clone();
        register_counter("connections.gateways", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| {
                        v.iter()
                            .filter(|g| g.gateway_type != crate::gateways::types::GatewayType::SelfGateway)
                            .count()
                    })
                    .unwrap_or(0)
            }
        });
    }
    // connections.mediators
    if let Some(store) = mediator_store {
        let s = store.clone();
        register_counter("connections.mediators", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // connections.connectionpoints
    if let Some(store) = connection_point_store {
        let s = store.clone();
        register_counter("connections.connectionpoints", move || {
            let s = s.clone();
            async move {
                s.list_all()
                    .await
                    .map(|v| v.len())
                    .unwrap_or(0)
            }
        });
    }
    // surfaces (+ per-type) — a single store holds every surface type, so the
    // umbrella total counts all non-deleted pipes and the leaves filter by type.
    if let Some(store) = pipe_store {
        let s = store.clone();
        register_counter("surfaces", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| !p.status.is_deleted())
                    .count()
            }
        });
        let s = store.clone();
        register_counter("surfaces.llm", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| !p.status.is_deleted() && matches!(p.pipe_type, crate::pipes::PipeType::LLM { .. }))
                    .count()
            }
        });
        let s = store.clone();
        register_counter("surfaces.ide", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| {
                        !p.status.is_deleted() && matches!(p.pipe_type, crate::pipes::PipeType::IDECatalog { .. })
                    })
                    .count()
            }
        });
    }
    // policies (+ per-type)
    if let Some(store) = policy_definition_store {
        use crate::policies::policy_definitions::PolicyType;
        let s = store.clone();
        register_counter("policies", move || {
            let s = s.clone();
            async move { s.list().await.len() }
        });
        let s = store.clone();
        register_counter("policies.fabric", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| p.policy_type == PolicyType::Appliance)
                    .count()
            }
        });
        let s = store.clone();
        register_counter("policies.llm", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| p.policy_type == PolicyType::Llm)
                    .count()
            }
        });
        let s = store.clone();
        register_counter("policies.ide", move || {
            let s = s.clone();
            async move {
                s.list()
                    .await
                    .into_iter()
                    .filter(|p| p.policy_type == PolicyType::Ide)
                    .count()
            }
        });
    }
    // integrations — resolved via the global storage accessor.
    register_counter("integrations", || async {
        match crate::storage::get_integration_storage() {
            Some(s) => s
                .list()
                .await
                .map(|v| v.len())
                .unwrap_or(0),
            None => 0,
        }
    });
    // teams / members / prompts — resolved via global store accessors. System
    // and deleted records are excluded so seeded fixtures do not consume quota.
    register_counter("teams", || async {
        match crate::teams::store::global_team_store() {
            Some(s) => s
                .list()
                .await
                .into_iter()
                .filter(|t| !t.status.is_deleted() && !t.system)
                .count(),
            None => 0,
        }
    });
    register_counter("members", || async {
        match crate::members::store::global_member_store() {
            Some(s) => s
                .list()
                .await
                .into_iter()
                .filter(|m| !m.status.is_deleted() && !m.system)
                .count(),
            None => 0,
        }
    });
    register_counter("prompts", || async {
        match crate::prompts::global_prompt_store() {
            Some(s) => s
                .list()
                .await
                .into_iter()
                .filter(|p| !p.status.is_deleted())
                .count(),
            None => 0,
        }
    });
}

const ACTIVATION_RELOAD_RETRY_FIRST: std::time::Duration = std::time::Duration::from_millis(500);
const ACTIVATION_RELOAD_RETRY_MAX: std::time::Duration = std::time::Duration::from_secs(30);

type ListenerManager = crate::gateways::connection_points::ws_listener::ConnectionPointListenerManager;
type FabricListeners = (Arc<ListenerManager>, Arc<crate::config::BootstrapConfig>);

/// The integrations an activation migrates and pins before reporting ready.
#[derive(Clone)]
struct ActivationIntegrations {
    storage: Arc<crate::storage::IntegrationStorage>,
    secrets: Option<Arc<dyn crate::secrets::SecretsStore>>,
}

/// The policy stores a promotion re-reads before it reloads Surfaces.
struct ActivationPolicyStores {
    definitions: Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>,
    global: Option<Arc<crate::policies::FileSystemGlobalPolicyStore>>,
    gateways: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for ActivationPolicyStores {
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        if let Some(store) = &self.definitions {
            store
                .refresh_from_disk()
                .await
                .map_err(std::io::Error::other)?;
        }
        if let Some(store) = &self.global {
            store
                .refresh_from_disk()
                .await
                .map_err(std::io::Error::other)?;
        }
        if let Some(store) = &self.gateways {
            store
                .refresh_from_disk()
                .await
                .map_err(std::io::Error::other)?;
        }
        Ok(())
    }
}

/// The Surface routes and policy engines a promotion rebuilds once the policy
/// stores are re-read.
struct ActivationSurfaces {
    pipes: Option<(Arc<crate::pipes::FileSystemPipeStore>, Arc<crate::pipes::PipeRouteManager>)>,
    engines: Option<Arc<crate::identity::handlers::policy_definitions::EngineStores>>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for ActivationSurfaces {
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        if let Some((pipe_store, route_manager)) = &self.pipes {
            pipe_store
                .refresh_from_disk()
                .await
                .map_err(std::io::Error::other)?;
            match route_manager
                .reload_all_pipes(pipe_store)
                .await
            {
                Ok(routes) => info!("Activation reloaded {routes} pipe route(s) from storage"),
                Err(error) => warn!("Promotion pipe route reload failed: {error}"),
            }
        }
        if let Some(engines) = &self.engines {
            crate::identity::handlers::policy_definitions::recompile_policy_engines(
                engines,
                crate::identity::handlers::policy_definitions::EngineScope::All,
            )
            .await?;
        }
        Ok(())
    }
}

/// Run `reload`, retrying with backoff until it succeeds. Returns `false` once
/// a later mode change supersedes `generation`.
async fn reload_until_done(
    reload: &dyn crate::server::mode::ReloadOnPromotion,
    generation: u64,
) -> bool {
    let mut delay = ACTIVATION_RELOAD_RETRY_FIRST;
    while let Err(error) = reload
        .reload_from_storage()
        .await
    {
        error!("Activation cannot reload shared state from storage, retrying in {delay:?}: {error}");
        tokio::time::sleep(delay).await;
        if crate::server::mode::current_activation_generation() != generation {
            return false;
        }
        delay = (delay * 2).min(ACTIVATION_RELOAD_RETRY_MAX);
    }
    true
}

/// What a promotion reloads and reconnects.
#[derive(Clone)]
struct Activation {
    listeners: Option<FabricListeners>,
    pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
    route_manager: Option<Arc<crate::pipes::PipeRouteManager>>,
    policy_stores: Option<Arc<ActivationPolicyStores>>,
    /// Where every policy engine is recompiled from once Surfaces are reloaded.
    policy_engines: Option<Arc<crate::identity::handlers::policy_definitions::EngineStores>>,
    reloads: Vec<Arc<dyn crate::server::mode::ReloadOnPromotion>>,
    integrations: Option<ActivationIntegrations>,
    /// Runs one pipe reload at a time when promotions overlap.
    reload_lock: Arc<tokio::sync::Mutex<()>>,
    /// Set while an integration validation runs, so promotions never stack them.
    validating: Arc<std::sync::atomic::AtomicBool>,
}

impl Activation {
    fn new(
        listeners: Option<FabricListeners>,
        pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
        route_manager: Option<Arc<crate::pipes::PipeRouteManager>>,
    ) -> Self {
        Self {
            listeners,
            pipe_store,
            route_manager,
            policy_stores: None,
            policy_engines: None,
            reloads: Vec::new(),
            integrations: None,
            reload_lock: Arc::new(tokio::sync::Mutex::new(())),
            validating: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        }
    }

    /// Validate the integrations on the blocking pool, since validation resolves
    /// host names synchronously. Returns `None` while an earlier validation is
    /// still running, so repeated promotions never stack them.
    fn start_integration_validation(&self) -> Option<tokio::task::JoinHandle<()>> {
        let integrations = self.integrations.as_ref()?;
        if self
            .validating
            .swap(true, std::sync::atomic::Ordering::AcqRel)
        {
            return None;
        }
        let storage = integrations.storage.clone();
        let validating = self.validating.clone();
        let runtime = tokio::runtime::Handle::current();
        Some(tokio::spawn(async move {
            let validation = tokio::task::spawn_blocking(move || {
                runtime.block_on(crate::integrations::validation::validate_all_integrations(&storage));
            });
            if let Err(error) = validation.await {
                error!("Integration validation stopped unexpectedly: {error}");
            }
            validating.store(false, std::sync::atomic::Ordering::Release);
        }))
    }

    /// Shared state to reload from storage before reporting ready.
    fn with_reloads(
        mut self,
        reloads: impl IntoIterator<Item = Arc<dyn crate::server::mode::ReloadOnPromotion>>,
    ) -> Self {
        self.reloads.extend(reloads);
        self
    }

    /// Policy stores to re-read before Surfaces, and the stores to recompile
    /// every policy engine from after them.
    fn with_policies(
        mut self,
        stores: Arc<ActivationPolicyStores>,
        engines: Arc<crate::identity::handlers::policy_definitions::EngineStores>,
    ) -> Self {
        self.policy_stores = Some(stores);
        self.policy_engines = Some(engines);
        self
    }

    /// Integrations to migrate and pin before reporting ready.
    fn with_integrations(
        mut self,
        storage: Option<Arc<crate::storage::IntegrationStorage>>,
        secrets: Option<Arc<dyn crate::secrets::SecretsStore>>,
    ) -> Self {
        self.integrations = storage.map(|storage| ActivationIntegrations { storage, secrets });
        self
    }

    /// Run every [`Self::with_reloads`] hook, retrying one that fails until it
    /// succeeds. Returns `false` once a later mode change supersedes
    /// `generation`.
    async fn reload_shared_state(
        &self,
        generation: u64,
    ) -> bool {
        for reload in &self.reloads {
            if !reload_until_done(reload.as_ref(), generation).await {
                return false;
            }
        }
        true
    }

    /// Start a promotion for `generation`. The listener manager is armed here,
    /// in the order mode changes arrive, so a later demotion always disarms it;
    /// the reload runs in the background so the caller can handle that
    /// demotion straight away.
    fn begin(
        &self,
        generation: u64,
    ) {
        let listener_epoch = self
            .listeners
            .as_ref()
            .map(|(manager, _)| manager.activate());
        let activation = self.clone();
        tokio::spawn(async move {
            activation
                .activate(generation, listener_epoch)
                .await;
        });
    }

    /// Stop connection-point listeners. Disarming the manager is synchronous,
    /// so an in-flight promotion can no longer start listeners or mark the
    /// instance ready, even while its reload is still running.
    async fn stand_down(&self) {
        if let Some((manager, _)) = &self.listeners {
            manager
                .deactivate_and_stop_all_listeners()
                .await;
        }
    }

    /// Reload surfaces and the [`Self::with_reloads`] state from shared
    /// storage, migrate inline integration credentials and pin integration
    /// destinations, mark the instance ready, then validate integrations and
    /// reconnect connection-point listeners in the background. Readiness does
    /// not wait for mediators, so `/api/v1/health` reports ready once local
    /// configuration is current, whether or not DIDComm consumption has resumed.
    /// A promotion superseded by a later mode change (a demotion or another
    /// promotion) skips the reload, and only the promotion that marks the
    /// instance ready starts listeners, so overlapping promotions never both
    /// start them. Returns whether this promotion made the instance ready.
    async fn activate(
        &self,
        generation: u64,
        listener_epoch: Option<u64>,
    ) -> bool {
        {
            let _reload = self.reload_lock.lock().await;
            if crate::server::mode::current_activation_generation() != generation {
                info!("Activation for generation {generation} was superseded before reloading");
                return false;
            }
            // Policy definitions are read before Surfaces, so every Surface
            // compiled from here on resolves the current Rego.
            if let Some(stores) = &self.policy_stores
                && !reload_until_done(stores.as_ref(), generation).await
            {
                info!("Activation for generation {generation} was superseded while reloading policies");
                return false;
            }
            let surfaces = ActivationSurfaces {
                pipes: self
                    .pipe_store
                    .clone()
                    .zip(self.route_manager.clone()),
                engines: self.policy_engines.clone(),
            };
            if !reload_until_done(&surfaces, generation).await {
                info!("Activation for generation {generation} was superseded while reloading Surfaces");
                return false;
            }
            if !self
                .reload_shared_state(generation)
                .await
            {
                info!("Activation for generation {generation} was superseded while reloading");
                return false;
            }
            if let Some(integrations) = &self.integrations {
                crate::storage::integration_credential_migration::prepare_integrations(
                    &integrations.storage,
                    integrations.secrets.clone(),
                    &|| crate::server::mode::current_activation_generation() == generation,
                )
                .await;
            }
        }
        if !crate::server::mode::mark_activation_ready(generation) {
            info!("Activation for generation {generation} was superseded; connection-point listeners not started");
            return false;
        }
        info!("Activation for generation {generation} complete; instance is ready");
        self.start_integration_validation();
        if let (Some((manager, bootstrap_config)), Some(epoch)) = (self.listeners.clone(), listener_epoch) {
            tokio::spawn(async move {
                manager
                    .start_all_listeners_for_epoch(bootstrap_config, epoch)
                    .await;
            });
        }
        true
    }
}

/// Follow Active/Standby transitions for the lifetime of the process,
/// promoting for the boot generation when the instance starts Active and for
/// every later promotion, and stopping connection-point listeners on demotion.
/// Listeners stay stopped until the instance is ready. A demotion takes effect
/// at once, even while a promotion is still reloading. If the task misses mode
/// changes (a burst larger than the mode channel), it applies the current mode
/// and keeps following later changes.
fn spawn_mode_lifecycle(activation: Activation) {
    if !crate::server::mode::is_ready_to_serve()
        && let Some((manager, _)) = &activation.listeners
    {
        manager.deactivate();
        info!("Connection point listeners stay stopped until activation completes");
    }
    // Subscribe before reading the generation, so a change that lands in
    // between is still received instead of leaving a stale activation.
    let mut mode_rx = crate::server::mode::subscribe_mode_changes();
    let initial_generation = crate::server::mode::current_activation_generation();
    tokio::spawn(async move {
        if crate::server::mode::current_mode() == crate::server::mode::ServerMode::Active {
            info!("Starting Active (generation {initial_generation})");
            activation.begin(initial_generation);
        }
        loop {
            let change = match mode_rx.recv().await {
                Ok(change) => change,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(missed)) => {
                    warn!("Missed {missed} server mode change(s); applying the current mode");
                    crate::server::mode::ModeChange {
                        mode: crate::server::mode::current_mode(),
                        generation: crate::server::mode::current_activation_generation(),
                    }
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            };
            match change.mode {
                crate::server::mode::ServerMode::Active => {
                    info!("Promotion requested (generation {})", change.generation);
                    activation.begin(change.generation);
                }
                crate::server::mode::ServerMode::Standby => {
                    info!("Demotion requested (generation {}); stopping connection-point listeners", change.generation);
                    activation.stand_down().await;
                }
            }
        }
    });
}

/// A surface change to apply to the running gateway (fast path, with a full
/// reload as the fallback slow path).
#[derive(Clone, Copy)]
enum SurfaceChange<'a> {
    /// Create or update — slot the surface into the running config without
    /// restarting port listeners (routing is resolved from the surface store).
    Upsert(&'a crate::config::agent_surface::AgentSurface),
    /// Delete — drop the surface from the running config.
    Delete(&'a str),
}

/// Apply a single surface change with the smallest possible disruption.
///
/// Fast paths (no port listener is restarted):
///   * `Upsert` → `reload_single_channel_with_fallback` (config + cache swap).
///   * `Delete` → `remove_single_channel` (config + cache removal).
///
/// Slow path (`perform_config_reload`, which rebuilds every port listener) is
/// only taken as a safety net when the fast path returns an error. A `Delete`
/// of a surface that is already absent (`Ok(false)`) is a no-op — the surface
/// is gone and there is nothing to serve.
///
/// After an `Upsert`, the surface-derived channel's OPA policy is recompiled
/// via the global surface policy manager so an active policy definition takes
/// effect without a manual reload.
///
/// There is no resolved-surface or agent-card cache to keep in lockstep
/// (routing is resolved dynamically from the surface store), and per-surface /
/// variant-alias routes are not baked into the port listener.
async fn apply_surface_change(
    identity_state: &crate::identity::IdentityApiState,
    change: SurfaceChange<'_>,
) {
    let (action, surface_id) = match change {
        SurfaceChange::Upsert(surface) => (
            "upsert",
            surface
                .config_id()
                .unwrap_or_default()
                .to_string(),
        ),
        SurfaceChange::Delete(id) => ("delete", id.to_string()),
    };

    let fast_result: anyhow::Result<bool> = match change {
        SurfaceChange::Upsert(surface) => {
            let channel_name = surface.name.clone();
            identity_state
                .channel_manager
                .reload_single_channel_with_fallback(
                    &channel_name,
                    Ok(surface.clone()),
                    identity_state
                        .tls_acceptor
                        .clone(),
                    identity_state.client.clone(),
                    Some(
                        identity_state
                            .metrics_store
                            .clone(),
                    ),
                    identity_state
                        .task_monitor
                        .clone(),
                )
                .await
                .map(|_| true)
        }
        SurfaceChange::Delete(id) => {
            identity_state
                .channel_manager
                .remove_single_channel(
                    id,
                    identity_state
                        .task_monitor
                        .clone(),
                )
                .await
        }
    };

    match fast_result {
        Ok(true) => {
            info!("Surface {action} for '{surface_id}' applied via single-channel fast path");
        }
        Ok(false) => {
            debug!("Surface {action} for '{surface_id}' already absent; no in-process change needed");
        }
        Err(e) => {
            warn!("Single-channel {action} for surface '{surface_id}' failed ({e}); falling back to full reload");
            full_reload_after_surface_change(identity_state, action, &surface_id).await;
        }
    }

    // Recompile the surface-derived channel's OPA policy. The reload paths
    // above register the surface with the runtime but do not invoke the
    // SurfacePolicyManager — without this, an active surface with a policy
    // definition would have `opa_enabled=true` but no compiled engine.
    if let SurfaceChange::Upsert(surface) = change
        && let Some(policy_manager) = crate::gateways::get_policy_manager()
        && let Err(e) = policy_manager
            .update_channel_policy(surface)
            .await
    {
        warn!("Failed to compile OPA policy for surface '{surface_id}': {e}");
    }
}

/// Full in-process gateway reload — the slow-path fallback when the per-surface
/// fast path can't apply the change. Rebuilds every port listener.
async fn full_reload_after_surface_change(
    identity_state: &crate::identity::IdentityApiState,
    action: &str,
    surface_id: &str,
) {
    match crate::identity::handlers::config::perform_config_reload(identity_state).await {
        Ok((channels, surfaces, is_fallback, warning)) => {
            info!(
                "Surface {action} for '{surface_id}' triggered full reload: \
                 {channels} channels + {surfaces} surfaces (fallback={is_fallback})"
            );
            if let Some(warn_msg) = warning {
                warn!("Surface reload warning: {warn_msg}");
            }
        }
        Err(e) => {
            error!(
                "Surface {action} for '{surface_id}' persisted to storage but \
                 in-process reload failed: {e}. Operator must call POST /v1/config/reload \
                 for the change to take effect."
            );
        }
    }
}

async fn init_surface_storage_subscription(
    bootstrap_config: &crate::config::BootstrapConfig,
    identity_state: crate::identity::IdentityApiState,
) {
    if !crate::storage::filesystem::cache_refresh_enabled() {
        info!("Agent surface storage subscription skipped because cache refresh is disabled");
        return;
    }

    let surface_store_path = PathBuf::from(
        &bootstrap_config
            .storage_paths
            .agent_surfaces,
    );

    let surface_store = match crate::surfaces::FileSystemAgentSurfaceStore::new(surface_store_path).await {
        Ok(surface_store) => Arc::new(surface_store),
        Err(e) => {
            warn!("Failed to initialize agent surface storage subscription: {}", e);
            return;
        }
    };

    let Some(mut surface_events) = surface_store.subscribe() else {
        warn!("Agent surface store does not support subscriptions");
        return;
    };

    tokio::spawn(async move {
        // Keep the store instance (and its refresh loop + broadcast sender)
        // alive for the lifetime of the subscription task.
        let _surface_store = surface_store;
        loop {
            match surface_events.recv().await {
                Ok(crate::storage::filesystem::StorageEvent::Upsert {
                    entity,
                    source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                    ..
                }) => {
                    apply_surface_change(&identity_state, SurfaceChange::Upsert(&entity)).await;
                }
                Ok(crate::storage::filesystem::StorageEvent::Delete {
                    id,
                    source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                }) => {
                    apply_surface_change(&identity_state, SurfaceChange::Delete(&id)).await;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("Agent surface storage subscriber lagged; skipped {} event(s)", skipped);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    warn!("Agent surface storage subscriber closed");
                    break;
                }
            }
        }
    });

    info!("Agent surface storage subscription initialized");
}

/// A pipe (LLM surface) change to apply to the running node, mirroring the
/// agent-surface `apply_surface_change` per-entity fast path.
#[derive(Clone, Copy)]
enum PipeChange<'a> {
    Upsert(&'a crate::pipes::PipeConfig),
    Delete(&'a str),
}

/// Apply a single pipe change picked up from storage: re-sync its route in the
/// live route table, drop its cached config/executor so the next request reads
/// the fresh config, and recompile (or remove) its OPA policy. Route removal /
/// registration is per-pipe, not a full route-table rebuild.
async fn apply_pipe_change(
    route_manager: &crate::pipes::PipeRouteManager,
    change: PipeChange<'_>,
) {
    match change {
        PipeChange::Upsert(pipe) => {
            if let Err(e) = route_manager
                .sync_pipe(pipe)
                .await
            {
                warn!("Pipe route sync failed for '{}' ({}): {}", pipe.name, pipe.id, e);
            }
            crate::pipes::cache::invalidate_pipe_cache(&pipe.id).await;
            if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
                .update_pipe_policy(pipe)
                .await
            {
                warn!("Failed to recompile OPA policy for pipe '{}': {}", pipe.id, e);
            }
        }
        PipeChange::Delete(id) => {
            route_manager
                .remove_pipe_by_id(id)
                .await;
            crate::pipes::cache::invalidate_pipe_cache(id).await;
            crate::pipes::PIPE_POLICY_MANAGER.remove_pipe(id);
        }
    }
}

/// Subscribe to pipe (LLM surface) storage changes so a pipe added, edited, or
/// deleted by another node on shared storage is mounted into / removed from the
/// live route table within one refresh interval. Only `RemoteWrite` events are
/// handled — this node's own API saves already register their routes and are
/// tagged `LocalWrite`. Runs only when `cache_refresh_interval_secs` is set.
async fn init_pipe_storage_subscription(
    pipe_store: Arc<crate::pipes::FileSystemPipeStore>,
    pipe_route_manager: Arc<crate::pipes::PipeRouteManager>,
) {
    if !crate::storage::filesystem::cache_refresh_enabled() {
        info!("Pipe storage subscription skipped because cache refresh is disabled");
        return;
    }

    let Some(mut pipe_events) = pipe_store.subscribe() else {
        warn!("Pipe store does not support subscriptions");
        return;
    };

    tokio::spawn(async move {
        // Keep the store instance (and its refresh loop + broadcast sender)
        // alive for the lifetime of the subscription task.
        let _pipe_store = pipe_store;
        loop {
            match pipe_events.recv().await {
                Ok(crate::storage::filesystem::StorageEvent::Upsert {
                    entity,
                    source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                    ..
                }) => {
                    apply_pipe_change(&pipe_route_manager, PipeChange::Upsert(&entity)).await;
                }
                Ok(crate::storage::filesystem::StorageEvent::Delete {
                    id,
                    source: crate::storage::filesystem::StorageEventSource::RemoteWrite,
                }) => {
                    apply_pipe_change(&pipe_route_manager, PipeChange::Delete(&id)).await;
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped)) => {
                    warn!("Pipe storage subscriber lagged; skipped {} event(s)", skipped);
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    warn!("Pipe storage subscriber closed");
                    break;
                }
            }
        }
    });

    info!("Pipe storage subscription initialized");
}

#[cfg(feature = "didwebvh")]
async fn sync_raw_did_log_if_missing(
    storage: &Arc<dyn crate::storage::DidLogStorage>,
    did: &str,
    raw_log: &str,
    success_message: &str,
    already_present_message: &str,
    append_error_prefix: &str,
    check_error_prefix: &str,
) {
    match storage
        .load_all_raw(did)
        .await
    {
        Ok(existing) if existing.is_empty() => {
            for line in raw_log.lines() {
                let line = line.trim();
                if !line.is_empty()
                    && let Err(e) = storage
                        .append_raw(did, line)
                        .await
                {
                    warn!("{}: {}", append_error_prefix, e);
                }
            }
            debug!("{}", success_message);
        }
        Ok(_) => debug!("{}", already_present_message),
        Err(e) => warn!("{}: {}", check_error_prefix, e),
    }
}

#[cfg(feature = "didwebvh")]
async fn sync_gateway_did_log(
    storage: &Arc<dyn crate::storage::DidLogStorage>,
    gateway_did: &str,
    log_src: &std::path::Path,
) {
    if !log_src.exists() {
        return;
    }

    match tokio::fs::read_to_string(log_src).await {
        Ok(content) => {
            sync_raw_did_log_if_missing(
                storage,
                gateway_did,
                &content,
                "Gateway DID registered for resolution via /v1/resolve",
                "Gateway DID already present in log storage",
                "Failed to register gateway DID log entry",
                "Could not check gateway DID log storage",
            )
            .await;
        }
        Err(e) => warn!("Could not read gateway DID log for sync: {}", e),
    }
}

/// Start the Axum-based proxy server
pub async fn run_axum_proxy(
    config: GatewayConfig,
    bootstrap_config: crate::config::BootstrapConfig,
    otlp_auth_header: Option<(String, String)>,
) -> anyhow::Result<()> {
    let config = Arc::new(config);
    let bootstrap_config = Arc::new(bootstrap_config);

    crate::identity::identity_hash::initialize_principal_key_secret().await;

    // Load metrics configuration early (needed for OpenTelemetry and CloudWatch)
    let metrics_config = Arc::new(
        crate::config::load_metrics_config(
            &bootstrap_config
                .config_files
                .metrics,
        )
        .unwrap_or_else(|e| {
            warn!(
                "Failed to load metrics config from {}: {}",
                bootstrap_config
                    .config_files
                    .metrics,
                e
            );
            warn!("Continuing with default (disabled) metrics configuration");
            crate::config::MetricsConfig {
                opentelemetry: crate::config::OpenTelemetryConfig {
                    enabled: false,
                    endpoint: "http://localhost:4317".to_string(),
                    protocol: crate::config::metrics_config::OtlpProtocol::default(),
                    auth: None,
                    service_name: env!("CARGO_PKG_NAME").to_string(),
                    environment: "development".to_string(),
                    instance_id: None,
                    traces: crate::config::metrics_config::TracesConfig {
                        enabled: false,
                        sample_rate: 1.0,
                        target_crates: vec!["agent-stream".to_string()],
                    },
                    metrics: crate::config::MetricsExportConfig {
                        enabled: false,
                        export_interval_seconds: 60,
                        batch_max_queue_size: None,
                        batch_scheduled_delay_ms: None,
                        batch_max_export_size: None,
                    },
                    logs: crate::config::metrics_config::LogsConfig {
                        enabled: false,
                        ..Default::default()
                    },
                },
                cloudwatch: crate::config::metrics_config::CloudWatchMetricConfig {
                    enabled: false,
                    region: Some("us-east-1".to_string()),
                    ..Default::default()
                },
                retention: crate::config::RetentionConfig::default(),
                advanced: crate::config::AdvancedConfig::default(),
            }
        }),
    );

    // Load RBAC configuration early
    let rbac_config = Arc::new(
        crate::config::load_rbac_config(
            &bootstrap_config
                .config_files
                .rbac,
        )
        .unwrap_or_else(|e| {
            warn!(
                "Failed to load RBAC config from {}: {}",
                bootstrap_config
                    .config_files
                    .rbac,
                e
            );
            warn!("Continuing with default (empty) RBAC configuration");
            crate::rbac::RbacConfig::default()
        }),
    );

    // Load network configuration early - needed for DID domain and WebAuthn settings
    let network_config = bootstrap_config
        .load_network_config()
        .map_err(|e| anyhow::anyhow!("Failed to load network configuration: {}", e))?;

    info!("Loaded network configuration with {} listener(s)", network_config.listeners.len());
    for listener in &network_config.listeners {
        info!(
            "  {} Listener '{}' on {}:{} with {} external URL(s)",
            listener.listener_type,
            listener.name,
            listener.bind_address,
            listener.port,
            listener.external_urls.len()
        );
    }

    // Initialize settings store and load settings from disk
    info!(
        "Initializing settings store with path: {}",
        bootstrap_config
            .storage_paths
            .settings
    );
    let settings_store = Arc::new(crate::storage::SettingsStore::new(
        &bootstrap_config
            .storage_paths
            .settings,
    ));
    settings_store.load().await?;

    // Register the settings store globally so subsystems without an
    // `Arc<SettingsStore>` (e.g. the policy-decision audit gate) can read the
    // current audit settings and honor runtime Settings › Security toggles.
    crate::storage::settings_store::set_global_settings_store(settings_store.clone());

    // Store settings storage path globally for settings
    crate::storage::init_settings_storage_path(
        bootstrap_config
            .storage_paths
            .settings
            .clone(),
    );

    // Store integration triggers storage path globally for user/gateway integrations
    crate::storage::init_integration_triggers_storage_path(
        bootstrap_config
            .storage_paths
            .integration_triggers
            .clone(),
    );

    crate::gateways::did_cache::init_did_host_policy(
        bootstrap_config
            .did_cache
            .allow_private_hosts,
    );
    if bootstrap_config
        .did_cache
        .allow_private_hosts
    {
        warn!(
            "[did_cache] allow_private_hosts is enabled: did:web / did:webvh resolution may contact private-network hosts"
        );
    }

    // Initialise the process-wide shared DID resolver client (one TLS context
    // + connection pool instead of 7 separate ones — saves ~200-400 MB RSS).
    crate::gateways::did_cache::init_shared_resolver().await?;

    // Get metrics retention minutes from settings (overrides config value if present)
    let metrics_retention_minutes = settings_store.get_metrics_retention_minutes();

    // Initialize WebSocket state for real-time updates (always enabled)
    let ws_state = {
        let state = Arc::new(crate::server::WsState::new(bootstrap_config.websocket_broadcast_buffer));

        // Initialize WebSocket log broadcasting so all log entries are sent via WebSocket
        crate::observability::init_websocket_log_broadcast(state.clone());
        info!("📡 WebSocket log broadcasting initialized");

        Some(state)
    };

    // Initialize task monitor (always enabled, before metrics_store)
    let task_monitor = Some(Arc::new(crate::observability::TaskMonitor::new(Some(settings_store.clone()))));

    // Initialize system metrics store (CPU/memory) with persistent storage
    let system_metrics_store = {
        let store = Arc::new(crate::observability::SystemMetricsStore::new(
            &bootstrap_config
                .storage_paths
                .system_metrics,
        ));
        if let Err(e) = store.load().await {
            warn!("Failed to load system metrics history: {}", e);
        }
        crate::observability::set_global_system_metrics_store(store.clone());
        Some(store)
    };

    // Initialize OpenTelemetry metrics provider if enabled
    let otel_meter_provider = if metrics_config
        .opentelemetry
        .enabled
        && metrics_config
            .opentelemetry
            .metrics
            .enabled
    {
        info!("Initializing OpenTelemetry metrics provider");
        let mut otel_config = crate::observability::OtelConfig::from(&metrics_config.opentelemetry);
        otel_config.auth_header = otlp_auth_header;

        match crate::observability::init_metrics(&otel_config) {
            Ok(provider) => {
                info!("✅ OpenTelemetry metrics provider initialized");
                Some(Arc::new(provider))
            }
            Err(e) => {
                warn!("⚠️  Failed to initialize OpenTelemetry metrics: {}", e);
                None
            }
        }
    } else {
        None
    };

    // Initialize VC issuer early (needed for identity_selector and identity API)
    // Always created now that identity API features are always enabled
    info!("Initializing VC issuer for agent identity management");
    let identity_store: Arc<dyn crate::identity::IdentityStore> = Arc::new(
        crate::identity::FilesystemIdentityStore::new_with_ws(
            &bootstrap_config
                .storage_paths
                .identities,
            ws_state.clone(),
        )
        .await?,
    );

    let vp_challenge_store = Arc::new(crate::identity::VpChallengeStore::default());
    tokio::spawn(Arc::clone(&vp_challenge_store).sweep_periodically());

    let vc_issuer = Some(Arc::new(
        crate::identity::VCIssuer::new(
            &bootstrap_config
                .storage_paths
                .vc_keys,
            &network_config.did.domain,
            identity_store,
            vp_challenge_store,
            None,
            None,
        )
        .await?
        .with_trusted_issuers(
            network_config
                .did
                .trusted_issuers
                .clone(),
        ),
    ));

    // Initialize metrics store (always enabled, after vc_issuer so we can get identity_store)
    let metrics_store = if let Some(ws) = &ws_state {
        let identity_store_opt = vc_issuer
            .as_ref()
            .map(|vc| vc.get_identity_store());
        let cloudwatch_config = if metrics_config
            .cloudwatch
            .enabled
        {
            // Clone the CloudWatch config and merge with top-level AWS settings
            let mut region = metrics_config
                .cloudwatch
                .region
                .clone();
            // Use region from cloudwatch config, or fall back to top-level aws_region
            if region.is_none() {
                region = bootstrap_config
                    .aws_region
                    .clone()
                    .or_else(|| Some("us-east-1".to_string()));
            }
            Some((
                crate::config::metrics_config::CloudWatchMetricConfig {
                    enabled: true,
                    namespace: metrics_config
                        .cloudwatch
                        .namespace
                        .clone(),
                    region,
                    dimensions: metrics_config
                        .cloudwatch
                        .dimensions
                        .clone(),
                },
                bootstrap_config
                    .aws_profile
                    .clone(),
            ))
        } else {
            None
        };
        Some(Arc::new(
            crate::metrics::MetricsStore::new_with_ws_and_retention(
                1000,
                ws.clone(),
                metrics_retention_minutes,
                bootstrap_config
                    .storage_paths
                    .metrics
                    .clone(),
                task_monitor.clone(),
                identity_store_opt,
                cloudwatch_config,
                otel_meter_provider.clone(),
                bootstrap_config.metrics_cache_ttl_seconds,
            )
            .await
            .with_settings_store(settings_store.clone()),
        ))
    } else {
        Some(Arc::new(crate::metrics::MetricsStore::new(1000).with_settings_store(settings_store.clone())))
    };

    // Initialize secrets store
    let secrets_store = crate::secrets::create_secrets_store(Some(
        bootstrap_config
            .storage_paths
            .secrets
            .clone(),
    ))
    .await
    .context("Failed to initialize secrets store")?;
    info!("✓ Secrets store initialized with {} backend", bootstrap_config.secrets_backend);
    crate::identity::identity_hash::initialize_identity_hash_pepper(secrets_store.as_ref())
        .await
        .context("Failed to initialize the identity-hash pepper")?;
    crate::secrets::report_unreferenceable_secrets(secrets_store.as_ref()).await;
    crate::storage::integration_credentials::init_secrets_store(secrets_store.clone());

    // Initialize GW2 VC issuer (separate identity space from GW1)
    // GW2 tracks two types of identities:
    // 1. Caller identity (from GW1 in request extensions)
    // 2. Agent identity (extracted from response extensions)
    // DID cache will be set later after connection point listener is initialized
    if let Some(ref issuer) = vc_issuer {
        crate::gateways::init_vc_issuer(issuer.clone(), None).await;
        info!("✓ GW2 VC issuer initialized for agent identity tracking (DID cache pending)");
    }

    // Wire the GW2 fabric message path to the shared observability state. These
    // globals are read by `process_forward_request`; without these calls metrics,
    // payload-capture broadcasting and byte/throughput tracking silently no-op.
    if let Some(ref ms) = metrics_store {
        crate::gateways::connection_points::message_processor::init_metrics_store(ms.clone()).await;
    }
    if let Some(ref ws) = ws_state {
        crate::gateways::connection_points::message_processor::init_ws_state(ws.clone()).await;
    }
    if let Some(ref tm) = task_monitor {
        crate::gateways::connection_points::message_processor::init_task_monitor(tm.clone()).await;
    }
    // Load TLS configuration for main proxy
    let tls_config = crate::server::load_tls_config(&config.tls.cert_path, &config.tls.key_path)?;
    let tls_acceptor = TlsAcceptor::from(tls_config);

    // Create HTTP client for forwarding requests with robust error handling
    let client = crate::http_client::proxy_with_timeout(std::time::Duration::from_secs(config.a2a.timeout_seconds))?;

    // Initialize configuration cache using path from bootstrap config
    info!(
        "Initializing config cache with path: {}",
        bootstrap_config
            .storage_paths
            .config_cache
    );
    let config_cache = Arc::new(crate::storage::ConfigCache::new(
        &bootstrap_config
            .storage_paths
            .config_cache,
    ));

    // Save initial configuration to cache
    if let Err(e) = config_cache
        .save(&config, "initial")
        .await
    {
        warn!("Failed to save initial configuration to cache: {}", e);
    } else {
        info!("Initial configuration saved to cache");
    }

    // Create shared listener_manager slot that will be populated later
    // This allows channels to access the listener_manager once it's created
    let listener_manager_slot = Arc::new(tokio::sync::RwLock::new(None));

    // Create channel task manager with config cache, shared WebSocket state, and VC issuer
    let channel_manager = Arc::new(SurfaceTaskManager::new(
        config.clone(),
        bootstrap_config.clone(),
        config_cache.clone(),
        ws_state.clone(),
        vc_issuer.clone(),
        None, // We'll set this after listener_manager is created
        settings_store.clone(),
    ));

    // Group channels by port and spawn ONE listener task per port
    // Multiple channels can share the same port if they have different routes
    let mut channel_handles = HashMap::new();
    let mut task_ids_map = HashMap::new();

    // Get configured ports from network config
    let configured_ports = network_config.get_ports();
    info!("Server will bind to ports from network config: {:?}", configured_ports);

    // Helper function to map external listen_address to internal port using network config
    let map_address_to_port = |listen_addr: &str| -> Option<u16> { network_config.map_url_to_port(listen_addr) };

    // Group active channels by the port they'll use.
    // Surfaces are kept as `AgentSurface` end-to-end so that `variants` and
    // `default_variant_id` survive into the runtime listener.
    let mut channels_by_port: HashMap<u16, Vec<crate::config::agent_surface::AgentSurface>> = HashMap::new();
    for surface in config.surfaces.iter() {
        // Skip non-enabled channels at startup (disabled or soft-deleted).
        if !surface.status.is_enabled() {
            info!("Skipping non-enabled channel '{}' at startup", surface.name);
            continue;
        }

        // Map channel's listen_address to internal port
        if let Some(port) = map_address_to_port(surface.listen_address()) {
            // Only include channel if its mapped port is in the configured ports
            if configured_ports.contains(&port) {
                channels_by_port
                    .entry(port)
                    .or_default()
                    .push(surface.clone());
            } else {
                warn!(
                    "Channel '{}' maps to port {} which is not in configured ports {:?} - skipping",
                    surface.name, port, configured_ports
                );
            }
        } else {
            warn!(
                "Could not map channel '{}' listen_address '{}' to any internal port - skipping",
                surface.name,
                surface.listen_address()
            );
        }
    }

    let active_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Enabled)
        .count();
    info!(
        "Initial startup: Mapped {} active channels across {} configured ports",
        active_count,
        channels_by_port.len()
    );

    // Store channels_by_port for later use - will spawn listeners AFTER Identity API router creation
    let channels_by_port_deferred = channels_by_port;

    // Outbound channel bucketing happens later, after the agent surface
    // store has been created, so that surface-derived outbound VCs are
    // included alongside legacy file-based channels.

    // Outbound bucketing happens later (after the agent surface store has
    // been created) so surface-derived outbound VCs are included alongside
    // legacy file-based channels — see `outbound_channels_by_port = { ... }`
    // below.

    // NOTE: Port listener spawning moved to after Identity API router creation (around line 650)
    // This allows us to pass the Identity API router to the port listeners

    // Channel handles and task IDs will be populated after port listeners are spawned

    // Keep track of identity API and monitoring tasks (these don't get reloaded)
    let mut tasks = Vec::new();

    // Start identity API server (always enabled)
    {
        // Use the same metrics store that the channels are using
        let identity_metrics_store = metrics_store
            .clone()
            .unwrap_or_else(|| Arc::new(crate::metrics::MetricsStore::new(1000)));

        // Use the WebSocket state we created earlier
        let ws_state = ws_state.unwrap();

        // Use the vc_issuer we created earlier (should always be present)
        let vc_issuer_for_api = vc_issuer
            .clone()
            .expect("VC issuer should be initialized");

        // Initialize Policy Definition store early so the policy manager can resolve
        // opa_policy_definition_id references when compiling channel policies.
        // (This is later assigned to identity_state.policy_definition_store as well.)
        let early_policy_definition_store: Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>> =
            match crate::policies::FileSystemPolicyDefinitionStore::new(
                bootstrap_config
                    .storage_paths
                    .policy_definitions
                    .clone(),
            )
            .await
            {
                Ok(store) => {
                    info!("Policy definition store initialized (early)");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    warn!("Failed to initialize policy definition store early: {}", e);
                    None
                }
            };

        // Create policy manager and initialize policies from channels
        let policy_manager = Arc::new(crate::policies::SurfacePolicyManager::new());
        if let Some(ref store) = early_policy_definition_store {
            policy_manager.set_policy_definition_store(store.clone());
        }

        // Initialize LLM-surface template store (LLM pipe snapshots).
        // Stored under `[storage_paths] surface_templates`.
        // Builtins are seeded from the directory configured via
        // `[config_files] surface_templates_dir`, resolved relative to
        // the bootstrap config dir when not absolute.
        let llm_surface_template_store = {
            let storage_dir = std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .surface_templates,
            );
            let seed_dir = {
                let raw = std::path::Path::new(
                    &bootstrap_config
                        .config_files
                        .surface_templates_dir,
                );
                if raw.is_absolute() {
                    Some(raw.to_path_buf())
                } else {
                    bootstrap_config
                        .config_dir
                        .as_ref()
                        .map(|d| d.join(raw))
                }
            };
            match crate::pipe_templates::FileSystemPipeTemplateStore::new(storage_dir, seed_dir).await {
                Ok(store) => Some(Arc::new(store)),
                Err(e) => {
                    error!("Failed to initialize LLM-surface template store: {}", e);
                    None
                }
            }
        };

        // Create identity API state
        let identity_state = crate::identity::IdentityApiState {
            vc_issuer: vc_issuer_for_api.clone(),
            config: Arc::clone(&config),
            network_config: Arc::new(network_config.clone()),
            ws_state: ws_state.clone(),
            settings_store: settings_store.clone(),
            user_settings_store: Arc::new(crate::storage::UserSettingsStore::new(
                &bootstrap_config
                    .storage_paths
                    .settings,
            )),
            metrics_store: identity_metrics_store.clone(),
            channel_manager: channel_manager.clone(),
            tls_acceptor: tls_acceptor.clone(),
            client: client.clone(),
            bootstrap_config: bootstrap_config.clone(),
            rbac_config: rbac_config.clone(),
            task_monitor: task_monitor.clone(),
            notification_store: None,      // Will be set after notification_store is initialized
            pipe_store: None,              // Will be set after pipe_store is initialized
            policy_definition_store: None, // Will be set after policy_definition_store is initialized
            global_policy_store: None,     // Will be set after global_policy_store is initialized
            budget_tracker: Arc::new(crate::pipes::budget_tracker::BudgetTracker::new()), // Will be updated with alert service
            pipe_route_manager: None, // Will be set after pipe_route_manager is initialized
            pipe_task_manager: None,  // Will be set after pipe_task_manager is initialized
            llm_surface_template_store: llm_surface_template_store.clone(),

            team_store: None,         // Will be set after team_store is initialized
            member_store: None,       // Will be set after member_store is initialized
            member_provisioner: None, // Will be set after team_store is initialized
            prompt_store: None,       // Will be set after prompt_store is initialized
            team_usage_tracker: None, // Will be set after team_usage_tracker is initialized

            // DID:webvh fields (will be initialized later if feature is enabled)
            #[cfg(feature = "didwebvh")]
            didwebvh_identity_store: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_log_storage: None,
            #[cfg(feature = "didwebvh")]
            didwebvh_base_url: None,
        };

        let terms_manager = if network_config.terms {
            let terms_appliance_id = vc_issuer_for_api
                .get_issuer_did()
                .await
                .context("failed to resolve the stable appliance DID for Terms")?;
            Arc::new(
                crate::terms::TermsManager::open_remote(
                    terms_appliance_id,
                    PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .terms,
                    ),
                    network_config
                        .affinidi_terms_url
                        .clone()
                        .context("affinidi_terms_url is required when Terms are enabled")?,
                )
                .await?,
            )
        } else {
            Arc::new(
                crate::terms::TermsManager::open(
                    false,
                    String::new(),
                    PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .terms,
                    ),
                    None,
                )
                .await?,
            )
        };

        // Initialize authentication based on mode
        let mut auth_state_for_notif: Option<Arc<crate::auth::AuthState>> = None;

        // Use the auth_mode from config
        let auth_mode = bootstrap_config
            .auth_mode
            .clone();

        let (auth_state, saml_state, oidc_state) = match auth_mode {
            crate::auth::AuthMode::Passkey => {
                // Initialize passkey authentication
                match initialize_auth_state(
                    &bootstrap_config,
                    &network_config,
                    metrics_store.clone().unwrap(),
                    terms_manager.clone(),
                )
                .await
                {
                    Ok(state) => {
                        info!("Passkey authentication enabled");
                        let state_arc = Arc::new(state);
                        auth_state_for_notif = Some(state_arc.clone());
                        (Some(state_arc), None, None)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to initialize passkey authentication: {}", e));
                    }
                }
            }
            crate::auth::AuthMode::Saml => {
                // Initialize SAML authentication
                let saml_config = crate::auth::SamlConfig::load_from_file(
                    &bootstrap_config
                        .config_files
                        .saml,
                )
                .map_err(|e| {
                    anyhow::anyhow!(
                        "Failed to load SAML configuration from {}: {}",
                        bootstrap_config
                            .config_files
                            .saml,
                        e
                    )
                })?;

                match initialize_saml_state(&bootstrap_config, &saml_config, terms_manager.clone()).await {
                    Ok(state) => {
                        info!("SAML authentication enabled with IdP: {}", saml_config.idp_entity_id);
                        (None, Some(Arc::new(state)), None)
                    }
                    Err(e) => {
                        return Err(anyhow::anyhow!("Failed to initialize SAML authentication: {}", e));
                    }
                }
            }
            crate::auth::AuthMode::Oidc => {
                let oidc_config_path = &bootstrap_config
                    .config_files
                    .oidc;
                let oidc_config = crate::auth::oidc::OidcConfig::load_from_file(std::path::Path::new(oidc_config_path))
                    .await
                    .map_err(|e| {
                        anyhow::anyhow!("Failed to load OIDC configuration from {}: {}", oidc_config_path, e)
                    })?;
                let (storage, session_manager) = initialize_sso_user_stores(&bootstrap_config).await?;
                let state =
                    crate::auth::oidc::OidcState::new(oidc_config, storage, session_manager, terms_manager.clone())
                        .context("Failed to initialize OIDC authentication")?;
                state.check_provider().await;
                info!("OIDC authentication enabled with issuer: {}", state.config.issuer);
                (None, None, Some(Arc::new(state)))
            }
        };

        // Initialize gateway, mediator, and trust registry stores
        // Get the proxy DID from the VC issuer to use for the self gateway
        let proxy_did = vc_issuer_for_api
            .get_issuer_did()
            .await
            .ok();

        let gateway_store: Option<Arc<crate::gateways::FileSystemGatewayStore>> =
            match crate::gateways::FileSystemGatewayStore::new(
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .gateways,
                ),
                proxy_did,
            )
            .await
            {
                Ok(store) => {
                    info!("Gateway store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize gateway store: {}", e);
                    None
                }
            };

        let mediator_store: Option<Arc<crate::mediators::FileSystemMediatorStore>> =
            match crate::mediators::FileSystemMediatorStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .mediators,
            ))
            .await
            {
                Ok(store) => {
                    info!("Mediator store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize mediator store: {}", e);
                    None
                }
            };

        // ── Credential Delegation stores ──────────────────────────────────
        let credential_provider_store: Option<
            Arc<crate::credential_providers::storage::FileSystemCredentialProviderStore>,
        > = match crate::credential_providers::storage::FileSystemCredentialProviderStore::new(PathBuf::from(
            &bootstrap_config
                .storage_paths
                .credential_providers,
        ))
        .await
        {
            Ok(store) => {
                info!(target: "credential_delegation", "Credential provider store initialized");
                Some(Arc::new(store))
            }
            Err(e) => {
                error!(target: "credential_delegation", "Failed to initialize credential provider store: {}", e);
                None
            }
        };

        let delegation_vault_store: Option<Arc<crate::delegation_vault::storage::FileSystemDelegationVaultStore>> =
            match crate::delegation_vault::storage::FileSystemDelegationVaultStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .delegation_vault,
            ))
            .await
            {
                Ok(store) => {
                    info!(target: "credential_delegation", "Delegation vault store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!(target: "credential_delegation", "Failed to initialize delegation vault store: {}", e);
                    None
                }
            };

        // ── LLM provider catalog store ────────────────────────────────────
        // Seeds `<llm_configuration>/llm.json` from the shipped catalog on first
        // run; the storage copy is authoritative thereafter and never overwritten.
        let llm_provider_catalog: Option<Arc<crate::llm_catalog::LlmProviderCatalog>> =
            match crate::llm_catalog::LlmProviderCatalog::new(
                bootstrap_config.llm_catalog_path(),
                Some(PathBuf::from(bootstrap_config.llm_catalog_seed_path())),
            ) {
                Ok(store) => {
                    info!("LLM provider catalog store initialized");
                    let store = Arc::new(store);
                    crate::llm_catalog::set_global_catalog(store.clone());
                    Some(store)
                }
                Err(e) => {
                    error!("Failed to initialize LLM provider catalog store: {}", e);
                    None
                }
            };

        // Initialize GW2 message processor globals for credential delegation
        if let (Some(cp_store), Some(dv_store)) = (&credential_provider_store, &delegation_vault_store) {
            let base_url = format!("https://{}", network_config.did.domain);
            crate::gateways::connection_points::message_processor::init_credential_provider_store(cp_store.clone())
                .await;
            crate::gateways::connection_points::message_processor::init_delegation_vault_store(dv_store.clone()).await;
            crate::gateways::connection_points::message_processor::init_secrets_store(secrets_store.clone()).await;
            crate::gateways::connection_points::message_processor::init_gateway_base_url(base_url).await;
        }

        // Initialize delegation vault audit logger
        crate::delegation_vault::audit::init_audit_logger(
            bootstrap_config
                .logging
                .log_directory
                .as_deref(),
            bootstrap_config
                .logging
                .audit_identity_binding_vp,
        );

        // Initialize the content-addressed multimedia store: binary attachments
        // (audio / documents / images) a caller sends are persisted here keyed by
        // their SHA-256, encrypted at rest with the same key as the governance
        // log, so a governance record can carry only the hash while the bytes stay
        // retrievable for later verification. Always available (no issuer DID
        // needed); the governance capture path uses it when a surface records.
        crate::governance::init_multimedia_store(crate::governance::MultimediaStore::new(
            PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .multimedia_store,
            ),
            crate::storage::filesystem::global_encryption_service(),
        ));
        info!("Multimedia attachment store initialized");

        // Initialize the shared audio-stream clip store: short pre-generated WAV
        // clips (PCM16 / 24 kHz / mono) the realtime relay streams to a caller
        // during a Gated voice-safety pause instead of dead air. Catalogued by
        // `config_files.audio_streams`; the clip bytes live under
        // `storage_paths.audio_streams`. A missing catalog leaves the store empty.
        crate::pipes::audio_streams::init_audio_stream_store(crate::pipes::audio_streams::AudioStreamStore::load(
            std::path::Path::new(
                &bootstrap_config
                    .config_files
                    .audio_streams,
            ),
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .audio_streams,
            ),
        ));
        info!("Audio-stream clip store initialized");

        // Appliance-wide surface defaults (governance recording / export and `pipe`
        // event integrations applied to every LLM surface, merged with its own).
        crate::pipes::surface_defaults::set_surface_defaults(
            bootstrap_config
                .surface_defaults
                .clone(),
        );

        // Initialize the signed governance-record store: sign records as VCs with
        // the appliance DID + Ed25519 key, encrypt each line at rest, and chain
        // them per surface. Off unless a surface opts in via `governance_recording`.
        match vc_issuer_for_api
            .get_issuer_did()
            .await
        {
            Ok(issuer_did) => {
                let signer = crate::governance::GovernanceSigner::new(issuer_did, vc_issuer_for_api.get_vc_signer());
                let store = crate::governance::GovernanceStore::new(
                    PathBuf::from(
                        &bootstrap_config
                            .storage_paths
                            .governance,
                    ),
                    signer,
                    crate::storage::filesystem::global_encryption_service(),
                );
                crate::governance::init_store(store);
                info!("Governance record store initialized");
            }
            Err(e) => {
                error!("Failed to initialize governance record store (no issuer DID): {}", e);
            }
        }

        let marketplace_model_store: Option<Arc<crate::marketplace_models::FileSystemMarketplaceModelStore>> =
            match crate::marketplace_models::FileSystemMarketplaceModelStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .marketplace_models,
            ))
            .await
            {
                Ok(store) => {
                    info!("Marketplace model store initialized");
                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize marketplace model store: {}", e);
                    None
                }
            };

        // Initialize Pipe store
        let pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>> = match crate::pipes::FileSystemPipeStore::new(
            bootstrap_config
                .storage_paths
                .surfaces
                .clone(),
        )
        .await
        {
            Ok(store) => {
                info!("Pipe store initialized");
                Some(Arc::new(store))
            }
            Err(e) => {
                error!("Failed to initialize Pipe store: {}", e);
                None
            }
        };

        // Policy definition store was already initialized early (above the policy manager).
        // Reuse the same instance to avoid opening the same path twice.
        let policy_definition_store = early_policy_definition_store.clone();

        // Initialize the pipe OPA policy manager from the same definition store
        // and compile every pipe's inbound policy so enforcement is live at boot.
        if let Some(ref store) = early_policy_definition_store {
            crate::pipes::PIPE_POLICY_MANAGER.set_policy_definition_store(store.clone());
        }
        if let Some(ref pipe_store_ref) = pipe_store {
            let pipes = pipe_store_ref.list().await;
            crate::identity::handlers::pipe_secret_bindings::log_stored_bindings(&pipes);
            for pipe in pipes {
                if pipe.opa_enabled()
                    && let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
                        .update_pipe_policy(&pipe)
                        .await
                {
                    warn!("Failed to initialize OPA policy for pipe '{}': {}", pipe.name, e);
                }
            }
        }

        // Appliance-wide (global) policy assignments: compile the global policy
        // sets so they are enforced on every surface of a type from boot.
        let global_policy_store = match crate::policies::FileSystemGlobalPolicyStore::new(
            bootstrap_config
                .storage_paths
                .global_policies
                .clone(),
        )
        .await
        {
            Ok(store) => Some(Arc::new(store)),
            Err(e) => {
                warn!("Failed to initialize global policy store: {}", e);
                None
            }
        };
        if let Some(ref store) = global_policy_store {
            let assignments = store.get().await;
            if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
                .refresh_global(&assignments)
                .await
            {
                warn!("Failed to compile appliance-wide policy sets: {}", e);
            }
        }

        // Create PipeRouteManager for dynamic route registration
        let pipe_route_manager: Option<Arc<crate::pipes::PipeRouteManager>> = pipe_store.as_ref().map(|_| {
            use std::collections::HashMap;
            use std::sync::Arc as StdArc;
            use tokio::sync::RwLock;

            let route_to_pipe = StdArc::new(RwLock::new(HashMap::new()));
            StdArc::new(crate::pipes::PipeRouteManager::new_with_network_config(
                route_to_pipe,
                Arc::new(network_config.clone()),
            ))
        });

        // Initialize and start LLM pipe tasks
        let pipe_task_manager: Option<Arc<crate::pipes::PipeTaskManager>> = if let Some(ref pipe_store_ref) = pipe_store
        {
            match crate::pipes::PipeTaskManager::new(
                pipe_store_ref.clone(),
                task_monitor.clone(),
                bootstrap_config.clone(),
            ) {
                Ok(pipe_manager) => {
                    let pipe_manager = Arc::new(pipe_manager);

                    // Load and start all enabled pipes
                    let pipes = pipe_store_ref.list().await;
                    {
                        let mut started_count = 0;
                        for pipe in pipes {
                            if pipe.status.is_enabled() {
                                if let Err(e) = pipe_manager
                                    .start_pipe(&pipe)
                                    .await
                                {
                                    warn!("Failed to start pipe '{}': {}", pipe.name, e);
                                } else {
                                    started_count += 1;
                                }
                            }
                        }
                        info!("✓ Started {} enabled LLM pipe(s) with health monitoring", started_count);
                    }

                    Some(pipe_manager)
                }
                Err(e) => {
                    error!("Failed to initialize PipeTaskManager: {}", e);
                    None
                }
            }
        } else {
            None
        };

        // Migrate any stored surface policy definitions from the legacy
        // `package channel.policy` to the canonical `package surface.policy`
        // BEFORE compiling surfaces, so the runtime only ever evaluates the
        // canonical query path (`data.surface.policy.allow`). Idempotent.
        if let Some(ref store) = early_policy_definition_store {
            match store
                .migrate_legacy_packages()
                .await
            {
                Ok(0) => {}
                Ok(n) => info!("Migrated {} surface policy definition(s) from `channel.policy` to `surface.policy`", n),
                Err(e) => warn!("Failed to migrate legacy surface policy packages: {}", e),
            }
        }

        // Compile surface-level OPA policies so the GW2 inbound path can
        // enforce them. Mirrors the gateway-level loop above: each enabled
        // surface with OPA configured gets its Rego compiled into the manager
        // before it is published to the global handle.
        for surface in config.surfaces.iter() {
            if !surface.status.is_enabled() {
                continue;
            }
            if surface.opa_enabled()
                && let Err(e) = policy_manager
                    .update_channel_policy(surface)
                    .await
            {
                error!("Failed to compile surface OPA policy for '{}': {}", surface.name, e);
            }
        }

        // Initialize GW2 policy manager for rate limiting and policies on fabric-forwarded requests
        crate::gateways::init_policy_manager(policy_manager.clone()).await;
        info!("✓ GW2 policy manager initialized for rate limiting and policy enforcement");

        // Initialize GW2 HTTP client for outbound requests with policy support
        crate::gateways::init_http_client(client.clone()).await;
        info!("✓ GW2 HTTP client initialized for outbound requests with policy support");

        let connection_point_store: Option<Arc<crate::gateways::FileSystemConnectionPointStore>> =
            match crate::gateways::FileSystemConnectionPointStore::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ))
            .await
            {
                Ok(store) => {
                    info!("Connection point store initialized");

                    // Clean up orphaned connection point directories (those without metadata.json)
                    // These are leftover DID secret folders from failed/incomplete connection attempts
                    match store
                        .cleanup_orphaned_directories()
                        .await
                    {
                        Ok(count) => {
                            if count > 0 {
                                info!(
                                    "Cleaned up {} orphaned connection point director{}",
                                    count,
                                    if count == 1 {
                                        "y"
                                    } else {
                                        "ies"
                                    }
                                );
                            }
                        }
                        Err(e) => {
                            warn!("Failed to cleanup orphaned connection point directories: {}", e);
                            // Don't fail startup due to cleanup errors
                        }
                    }

                    Some(Arc::new(store))
                }
                Err(e) => {
                    error!("Failed to initialize connection point store: {}", e);
                    None
                }
            };

        let notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>> = {
            let auth_storage_ref = auth_state
                .as_ref()
                .map(|state| state.storage.as_ref());
            match crate::integrations::FileSystemNotificationStore::new(
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .notifications,
                ),
                PathBuf::from(
                    &bootstrap_config
                        .storage_paths
                        .notification_templates,
                ),
                auth_storage_ref,
            )
            .await
            {
                Ok(store) => {
                    info!("Notification store initialized");
                    let store_arc = Some(Arc::new(store));

                    // Set notification store in auth state
                    if let Some(auth) = &auth_state_for_notif {
                        let mut notif_store = auth
                            .notification_store
                            .write()
                            .await;
                        *notif_store = store_arc.clone();
                        info!("Notification store set in auth state");
                    }
                    if let Some(saml) = &saml_state {
                        *saml
                            .notification_store
                            .write()
                            .await = store_arc.clone();
                    }
                    if let Some(oidc) = &oidc_state {
                        *oidc
                            .notification_store
                            .write()
                            .await = store_arc.clone();
                    }

                    store_arc
                }
                Err(e) => {
                    error!("Failed to initialize notification store: {}", e);
                    None
                }
            }
        };

        // Update identity_state with notification_store and pipe_store
        let mut identity_state = identity_state;
        identity_state.notification_store = notification_store.clone();
        identity_state.pipe_store = pipe_store.clone();
        identity_state.policy_definition_store = policy_definition_store.clone();
        identity_state.global_policy_store = global_policy_store.clone();
        identity_state.pipe_route_manager = pipe_route_manager.clone();
        identity_state.pipe_task_manager = pipe_task_manager.clone();

        // Initialize gateway-level OPA policy manager
        let gateway_policy_manager = Arc::new(crate::policies::GatewayPolicyManager::new());
        // Inject the definition store so a gateway resolves its referenced
        // policy Rego at compile time (reference-only) before the initial pass.
        if let Some(ref def_store) = policy_definition_store {
            gateway_policy_manager.set_policy_definition_store(def_store.clone());
        }
        if let Some(ref gw_store) = gateway_store
            && let Ok(gateways) = gw_store.list_all().await
        {
            for gateway in &gateways {
                // Track the self-gateway ID
                if gateway.gateway_type == crate::gateways::types::GatewayType::SelfGateway {
                    gateway_policy_manager.set_self_gateway_id(gateway.id.clone());
                }
                if gateway
                    .opa_policy_config
                    .is_some()
                    && let Err(e) = gateway_policy_manager
                        .update_gateway_policy(gateway)
                        .await
                {
                    error!("Failed to initialize OPA policy for gateway {}: {}", gateway.id, e);

                    // OPA policy is critical for request authorization, fail startup if any gateway policies fail to load
                    std::process::exit(1);
                }
            }
        }

        // Initialize GW2 gateway-level OPA policy manager for fabric-forwarded requests
        crate::gateways::init_gateway_policy_manager(gateway_policy_manager.clone()).await;

        // Initialize DID:webvh support if feature is enabled
        #[cfg(feature = "didwebvh")]
        {
            use crate::identity::didwebvh::FileSystemDidWebVhIdentityStore;
            use crate::storage::{DidLogStorage, FileDidLogStorage};

            // Create DID:webvh identity store
            let didwebvh_identity_path = PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .identities,
            )
            .join("didwebvh");
            match FileSystemDidWebVhIdentityStore::new(&didwebvh_identity_path).await {
                Ok(store) => {
                    info!("✓ DID:webvh identity store initialized");
                    identity_state.didwebvh_identity_store =
                        Some(Arc::new(store) as Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>);
                }
                Err(e) => {
                    error!("Failed to initialize DID:webvh identity store: {}", e);
                }
            }

            // Create DID:webvh log storage
            let didwebvh_log_path = PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .identities,
            )
            .join("didwebvh_logs");
            let storage = Arc::new(FileDidLogStorage::new(&didwebvh_log_path)) as Arc<dyn DidLogStorage>;
            info!("✓ DID:webvh log storage initialized");

            // Register the gateway's own DID in log storage so /v1/resolve can find it.
            // The VCIssuer stores the gateway DID at {vc_keys}/did.jsonl, while the resolver
            // uses FileDidLogStorage keyed by DID. Sync once at startup if not already present.
            if let Some(ref issuer) = vc_issuer {
                let gateway_did = issuer
                    .get_issuer_did()
                    .await
                    .unwrap_or_default();
                if gateway_did.starts_with("did:webvh:") {
                    let log_src = issuer
                        .get_storage_path()
                        .await
                        .join("did.jsonl");
                    sync_gateway_did_log(&storage, &gateway_did, &log_src).await;
                }
            }

            identity_state.didwebvh_log_storage = Some(storage.clone());

            // Set base URL from did.domain config (used for DID:webvh identifier domain).
            // Note: webauthn.external_origin is for FIDO2 browser origin validation only,
            // not for embedding in DID identifiers.
            let base_url = format!("https://{}", network_config.did.domain);
            if !network_config
                .did
                .domain
                .contains('.')
            {
                warn!(
                    "did.domain '{}' has no dots — non-compliant with did:webvh v1.0 ABNF (§3.3) \
                     which requires a fully qualified domain name. \
                     Local dev may work, but external DID resolution will fail.",
                    network_config.did.domain
                );
            }
            identity_state.didwebvh_base_url = Some(base_url.clone());
            info!("✓ DID:webvh base URL set to: {}", base_url);
        }

        // Initialize budget tracker with integration-based alert service
        let alert_service = Arc::new(crate::pipes::budget_alerts::BudgetAlertIntegration::new(
            notification_store.clone(),
            pipe_store.clone(),
        ));
        let budget_tracker = Arc::new(
            crate::pipes::budget_tracker::BudgetTracker::persistent(
                bootstrap_config
                    .storage_paths
                    .surface_usage
                    .clone(),
            )
            .await
            .with_alert_service(alert_service),
        );
        identity_state.budget_tracker = budget_tracker.clone();
        crate::pipes::budget_tracker::set_global_budget_tracker(budget_tracker.clone());
        info!("✓ Budget tracker initialized with integration alerts");

        // Register the breach/anomaly detector that activates per-surface
        // usage_alerts (cost/token/error-rate breaches + cost-spike anomalies)
        // at the request boundary.
        crate::pipes::breach_alerts::set_global_breach_detector(Arc::new(
            crate::pipes::breach_alerts::BreachDetector::default(),
        ));
        info!("✓ Breach/anomaly detector initialized");

        // Register the process-wide response cache that serves identical
        // repeat requests without a provider call for surfaces that opt in.
        crate::pipes::response_cache::set_global_response_cache(Arc::new(
            crate::pipes::response_cache::ResponseCache::new(),
        ));
        info!("✓ Response cache initialized");

        // Periodically evict expired response-cache entries so a scope that
        // stops receiving traffic doesn't retain stale entries indefinitely
        // (removal is otherwise lazy, on access / on a scope's next write).
        if let Some(response_cache) = crate::pipes::response_cache::global_response_cache() {
            tokio::spawn(async move {
                let mut ticker = tokio::time::interval(std::time::Duration::from_secs(300));
                ticker.tick().await; // consume the immediate first tick
                loop {
                    ticker.tick().await;
                    let evicted = response_cache.sweep_expired();
                    if evicted > 0 {
                        debug!("Response cache: swept {} expired entries", evicted);
                    }
                }
            });
        }

        // Initialize the member store (the appliance's clients — LLM consumers,
        // distinct from admin users) before the team store, so a legacy-team
        // migration can mint member records and the team store loads only the
        // new member-UUID format. Registered process-wide so the data-plane team
        // gate can resolve a caller's member without threading state through
        // each handler.
        let member_store = match crate::members::FileSystemMemberStore::new(
            bootstrap_config
                .storage_paths
                .members
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                crate::members::set_global_member_store(store.clone());
                identity_state.member_store = Some(store.clone());
                // Seed shipped default members (create-if-absent) from the
                // default-config directory so the attribution gate always has a
                // built-in anonymous identity without hardcoding it in Rust.
                let member_seed_dir = resolve_config_relative(
                    &bootstrap_config.config_dir,
                    &bootstrap_config
                        .storage_paths
                        .default_members,
                );
                match store
                    .seed_defaults(&member_seed_dir)
                    .await
                {
                    Ok(n) if n > 0 => {
                        info!("✓ Seeded {} default member(s) from {}", n, member_seed_dir.display())
                    }
                    Ok(_) => {}
                    Err(e) => error!("Failed to seed default members: {}", e),
                }
                info!("✓ Member store initialized");
                Some(store)
            }
            Err(e) => {
                error!("Failed to initialize member store: {}", e);
                None
            }
        };

        // Initialize the prompt store (versioned prompt templates) and register
        // it process-wide so the data-plane handler can resolve a referenced
        // prompt without threading the store through each surface handler.
        match crate::prompts::FileSystemPromptStore::new(
            bootstrap_config
                .storage_paths
                .prompts
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                crate::prompts::set_global_prompt_store(store.clone());
                identity_state.prompt_store = Some(store);
                info!("✓ Prompt store initialized");
            }
            Err(e) => error!("Failed to initialize prompt store: {}", e),
        }

        // Initialize the OAuth Identifier store (public sign-in profiles
        // referenced by IDE front-door / member upstream / sandbox sign-in) and
        // register it process-wide so reference-resolution sites can reach it
        // without threading the store through each handler. Stored as a sibling
        // of the prompt store under `_storage/oauth_identifiers`.
        {
            let oauth_dir = std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .prompts,
            )
            .parent()
            .map(|p| p.join("oauth_identifiers"))
            .unwrap_or_else(|| std::path::PathBuf::from("_storage/oauth_identifiers"));
            match crate::oauth_identifiers::FileSystemOAuthIdentifierStore::new(oauth_dir.clone()).await {
                Ok(store) => {
                    crate::oauth_identifiers::set_global_oauth_identifier_store(Arc::new(store));
                    info!("✓ OAuth Identifier store initialized at {}", oauth_dir.display());
                }
                Err(e) => error!("Failed to initialize OAuth Identifier store: {}", e),
            }
        }

        if let Some(ref member_store) = member_store {
            match crate::teams::migrate_legacy_teams(
                &bootstrap_config
                    .storage_paths
                    .teams,
                member_store,
            )
            .await
            {
                Ok(n) if n > 0 => info!("✓ Migrated {} legacy team(s) to the member-UUID model", n),
                Ok(_) => {}
                Err(e) => error!("Failed to migrate legacy teams: {}", e),
            }
        }

        // Initialize the team store and cross-surface usage tracker. Both are
        // registered process-wide so the data-plane team gate (in every surface
        // handler) can resolve teams and record usage without threading them
        // through each handler's state.
        match crate::teams::FileSystemTeamStore::new(
            bootstrap_config
                .storage_paths
                .teams
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                crate::teams::set_global_team_store(store.clone());
                // Seed shipped default teams (create-if-absent) from the
                // default-config directory so every caller resolves to the
                // built-in anonymous team without hardcoding it in Rust.
                let team_seed_dir = resolve_config_relative(
                    &bootstrap_config.config_dir,
                    &bootstrap_config
                        .storage_paths
                        .default_teams,
                );
                match store
                    .seed_defaults(&team_seed_dir)
                    .await
                {
                    Ok(n) if n > 0 => {
                        info!("✓ Seeded {} default team(s) from {}", n, team_seed_dir.display())
                    }
                    Ok(_) => {}
                    Err(e) => error!("Failed to seed default teams: {}", e),
                }

                // Initialize the member provisioner (on-the-fly member creation
                // from verified caller identities). Registered process-wide so
                // the data-plane team gate can auto-provision without threading
                // it through each handler, and threaded onto the identity API
                // state for the admin config endpoints. Requires both the member
                // and team stores.
                if let Some(ref member_store) = member_store {
                    let provisioner = Arc::new(
                        crate::members::MemberProvisioner::new(
                            bootstrap_config
                                .storage_paths
                                .member_provisioning
                                .clone(),
                            member_store.clone(),
                            store.clone(),
                        )
                        .await,
                    );
                    crate::members::set_global_member_provisioner(provisioner.clone());
                    identity_state.member_provisioner = Some(provisioner);
                    info!("✓ Member provisioner initialized");
                }

                identity_state.team_store = Some(store);
                info!("✓ Team store initialized");
            }
            Err(e) => error!("Failed to initialize team store: {}", e),
        }
        let team_usage_tracker = Arc::new(
            crate::teams::TeamUsageTracker::new(
                bootstrap_config
                    .storage_paths
                    .team_usage
                    .clone(),
            )
            .await,
        );
        crate::teams::set_global_team_usage_tracker(team_usage_tracker.clone());
        let mut promotion_reloads: Vec<Arc<dyn crate::server::mode::ReloadOnPromotion>> = Vec::new();
        if let Some(store) = &identity_state.member_store {
            promotion_reloads.push(store.clone());
        }
        if let Some(store) = &identity_state.team_store {
            promotion_reloads.push(store.clone());
        }
        if let Some(store) = &identity_state.prompt_store {
            promotion_reloads.push(store.clone());
        }
        if let Some(provisioner) = &identity_state.member_provisioner {
            promotion_reloads.push(provisioner.clone());
        }
        promotion_reloads.push(terms_manager.clone());
        if let Some(state) = &auth_state {
            promotion_reloads.push(state.storage.clone());
            promotion_reloads.push(state.session_manager.clone());
        }
        if let Some(state) = &saml_state {
            promotion_reloads.push(state.storage.clone());
            promotion_reloads.push(state.session_manager.clone());
        }
        promotion_reloads.push(budget_tracker.clone());
        promotion_reloads.push(team_usage_tracker.clone());
        if let Some(store) = &metrics_store {
            promotion_reloads.push(store.clone());
        }
        if let Some(store) = &system_metrics_store {
            promotion_reloads.push(store.clone());
        }
        promotion_reloads.push(settings_store.clone());
        if let Some(issuer) = &vc_issuer {
            promotion_reloads.push(issuer.clone());
        }
        if let Some(store) = crate::governance::store() {
            promotion_reloads.push(Arc::new(store.clone()));
        }
        let activation_policy_stores = Arc::new(ActivationPolicyStores {
            definitions: policy_definition_store.clone(),
            global: global_policy_store.clone(),
            gateways: gateway_store.clone(),
        });
        let activation_policy_engines = Arc::new(crate::identity::handlers::policy_definitions::EngineStores {
            pipe_store: pipe_store.clone(),
            global_policy_store: global_policy_store.clone(),
            agent_surfaces_path: bootstrap_config
                .storage_paths
                .agent_surfaces
                .clone(),
            gateways_path: bootstrap_config
                .storage_paths
                .gateways
                .clone(),
        });
        identity_state.team_usage_tracker = Some(team_usage_tracker);
        info!("✓ Team usage tracker initialized");

        crate::teams::set_global_member_rate_limiter(Arc::new(crate::teams::MemberRateLimiter::new()));
        info!("✓ Member rate limiter initialized");

        let telemetry_path = bootstrap_config
            .storage_paths
            .telemetry
            .clone();
        let telemetry_store = Arc::new(crate::telemetry::TelemetryStore::new(telemetry_path).await);
        promotion_reloads.push(telemetry_store.clone());
        crate::telemetry::set_global_telemetry_store(telemetry_store);
        info!("✓ Usage telemetry store initialized (loaded on boot)");

        let ops_path = bootstrap_config
            .storage_paths
            .ops_telemetry
            .clone();
        let ops_metrics_store = Arc::new(crate::metrics::ops_telemetry::OpsMetricsStore::embedded(ops_path).await);
        promotion_reloads.push(ops_metrics_store.clone());
        crate::metrics::ops_telemetry::set_global_ops_store(ops_metrics_store);
        info!("✓ Operational metrics store initialized");

        let drift_path = bootstrap_config
            .storage_paths
            .drift
            .clone();
        let drift_store = Arc::new(crate::drift::DriftStore::new(drift_path).await);
        promotion_reloads.push(drift_store.clone());
        crate::drift::set_global_drift_store(drift_store);
        info!("✓ Drift dimension store initialized");

        match crate::drift::DriftBaselineStore::new(
            bootstrap_config
                .storage_paths
                .drift_baselines
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                promotion_reloads.push(store.clone());
                crate::drift::set_global_drift_baseline_store(store);
                info!("✓ Drift baseline store initialized");
            }
            Err(e) => tracing::warn!("Drift baseline store init failed: {e}"),
        }

        // Governance retention: each surface's `retention_days` is enforced on
        // write and by this hourly sweep, which reaches surfaces gone quiet.
        if let Some(retention_pipe_store) = pipe_store.clone() {
            tokio::spawn(crate::governance::periodic_retention_sweep(retention_pipe_store));
            info!("✓ Governance retention sweep started");
        }

        // Periodic drift evaluator: raises a `drift.detected` integration alert
        // when a surface enters drift, then re-alerts on the configured cadence
        // (gateway `[drift]` defaults, per-surface overridable). Fire-and-forget;
        // needs the pipe store (to list surfaces) + the notification store.
        if let (Some(drift_pipe_store), Some(drift_notification_store)) =
            (pipe_store.clone(), notification_store.clone())
        {
            let drift_cadence = bootstrap_config.drift.clone();
            tokio::spawn(async move {
                crate::drift::periodic_drift_evaluator(drift_pipe_store, drift_notification_store, drift_cadence).await;
            });
            info!("✓ Drift evaluator started");
        }

        // Appliance-wide drift retention (agent-stream.json `drift`): per-surface
        // count caps + optional age caps, applied by the stores on write and by
        // the periodic sweep.
        let drift_app_cfg = network_config
            .drift
            .clone()
            .unwrap_or_default();
        let run_retention = crate::drift::DriftRetention {
            max_per_surface: drift_app_cfg
                .max_runs_per_surface
                .max(1),
            max_age_days: drift_app_cfg.max_run_age_days,
        };
        let session_retention = crate::drift::DriftRetention {
            max_per_surface: drift_app_cfg
                .max_sessions_per_surface
                .max(1),
            max_age_days: drift_app_cfg.max_session_age_days,
        };

        match crate::drift::RecordedSessionStore::new(
            bootstrap_config
                .storage_paths
                .drift_sessions
                .clone(),
            session_retention,
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                promotion_reloads.push(store.clone());
                crate::drift::set_global_drift_session_store(store);
                info!("✓ Drift session store initialized");
            }
            Err(e) => tracing::warn!("Drift session store init failed: {e}"),
        }

        match crate::drift::DriftRunStore::new(
            bootstrap_config
                .storage_paths
                .drift_runs
                .clone(),
            run_retention,
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                promotion_reloads.push(store.clone());
                crate::drift::set_global_drift_run_store(store);
                info!("✓ Drift run store initialized");
            }
            Err(e) => tracing::warn!("Drift run store init failed: {e}"),
        }

        match crate::drift::DriftEvalStateStore::new(
            bootstrap_config
                .storage_paths
                .drift_eval_state
                .clone(),
        )
        .await
        {
            Ok(store) => {
                let store = Arc::new(store);
                promotion_reloads.push(store.clone());
                crate::drift::set_global_drift_eval_state_store(store);
                info!("✓ Drift eval-state store initialized");
            }
            Err(e) => tracing::warn!("Drift eval-state store init failed: {e}"),
        }

        // Appliance-wide replay-eval runner settings (agent-stream.json `drift`):
        // the auto-suspend threshold, per-session timeout, and per-run cost
        // ceiling, read by the run endpoint + scheduler when building a task.
        crate::drift::set_drift_eval_runtime(crate::drift::DriftEvalRuntime {
            max_failures: drift_app_cfg.eval_max_consecutive_failures,
            session_timeout: std::time::Duration::from_secs(
                drift_app_cfg
                    .eval_session_timeout_secs
                    .clamp(5, 600),
            ),
            max_run_cost_usd: drift_app_cfg
                .eval_max_run_cost_usd
                .filter(|c| *c > 0.0),
        });

        // Periodic retention sweep: re-applies the count + age caps across all
        // surfaces so age-based expiry reaches idle ones too. Only worth spawning
        // when an age cap is configured (the count cap is enforced on write).
        if run_retention.has_age_limit() || session_retention.has_age_limit() {
            tokio::spawn(async move {
                crate::drift::periodic_retention_sweep().await;
            });
            info!("✓ Drift retention sweep started");
        }

        // Periodic drift evaluation scheduler: replays each scheduled surface's
        // captured sessions on its interval, folding the comparison into the
        // drift dimensions. Needs the pipe store to find scheduled surfaces.
        if let Some(scheduler_pipe_store) = pipe_store.clone() {
            let scheduler_state = identity_state.clone();
            tokio::spawn(async move {
                crate::drift::periodic_eval_scheduler(scheduler_pipe_store, scheduler_state).await;
            });
            info!("✓ Drift evaluation scheduler started");
        }

        // Register the rejection-reason taxonomy classifier. It reads the editable
        // config-relative taxonomy file through an mtime-gated cache and falls back
        // to the compiled-in built-in taxonomy when the file is absent or invalid,
        // so rejection classification always works.
        let rejection_taxonomy_path = resolve_config_relative(
            &bootstrap_config.config_dir,
            &bootstrap_config
                .config_files
                .rejection_taxonomy,
        );
        crate::rejection_taxonomy::set_global_rejection_classifier(Arc::new(
            crate::rejection_taxonomy::RejectionClassifier::new(Some(rejection_taxonomy_path.clone())),
        ));
        info!("✓ Rejection taxonomy classifier initialized ({})", rejection_taxonomy_path.display());

        init_surface_storage_subscription(bootstrap_config.as_ref(), identity_state.clone()).await;

        // Subscribe to pipe (LLM surface) storage changes so routes added /
        // edited / deleted on shared storage are mounted live (per-pipe).
        if let (Some(ps), Some(prm)) = (pipe_store.clone(), pipe_route_manager.clone()) {
            init_pipe_storage_subscription(ps, prm).await;
        }

        // Initialize GW2 notification store if available for integration triggers
        if let Some(ref notif_store) = notification_store {
            crate::gateways::init_notification_store(notif_store.clone()).await;
            info!("✓ GW2 notification store initialized for integration triggers");
        }

        // Initialize integration storage
        let integration_storage: Option<Arc<crate::storage::IntegrationStorage>> = {
            let storage = crate::storage::IntegrationStorage::new(PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .integrations,
            ))
            .await
            .expect("Failed to initialize integration storage");
            info!("Notifier storage initialized");
            let storage_arc = Arc::new(storage);

            // Initialize global integration storage
            crate::storage::init_integration_storage(storage_arc.clone()).await;
            info!("✓ Global integration storage initialized");

            Some(storage_arc)
        };

        // Initialize connection point listener manager
        info!("Initializing connection point listener manager");

        // Create message store
        let message_store_path = PathBuf::from(
            &bootstrap_config
                .storage_paths
                .messages,
        );
        let message_store = match crate::gateways::MessageStore::new(message_store_path).await {
            Ok(store) => {
                info!("✓ Message store initialized");
                Some(Arc::new(store))
            }
            Err(e) => {
                error!("Failed to initialize message store: {}", e);
                None
            }
        };

        // Create pending connection store for tracking OOB handshakes
        let pending_conn_storage_path = PathBuf::from(
            &bootstrap_config
                .storage_paths
                .connection_points,
        )
        .join("pending");
        let pending_connection_store =
            match crate::gateways::PendingConnectionStore::new(pending_conn_storage_path).await {
                Ok(store) => {
                    info!("✓ Pending connection store initialized");
                    Arc::new(store)
                }
                Err(e) => {
                    error!("Failed to initialize pending connection store: {}. Using in-memory fallback", e);
                    // Create empty store with temp path as fallback
                    let temp_path = PathBuf::from("_storage/temp/pending");
                    Arc::new(
                        crate::gateways::PendingConnectionStore::new(temp_path)
                            .await
                            .expect("Failed to create fallback pending connection store"),
                    )
                }
            };

        let listener_manager = if let (Some(msg_store), Some(cp_store)) = (&message_store, &connection_point_store) {
            // Configure DID cache from bootstrap config
            let did_cache_config = crate::gateways::did_cache::DIDCacheConfig {
                ttl_seconds: bootstrap_config
                    .did_cache
                    .ttl_seconds,
                max_entries: bootstrap_config
                    .did_cache
                    .max_entries,
                stale_threshold_percent: bootstrap_config
                    .did_cache
                    .stale_threshold_percent,
                storage_path: bootstrap_config
                    .did_cache
                    .storage_path
                    .clone(),
                local_domain: Some(
                    network_config
                        .did
                        .domain
                        .clone(),
                ),
                vc_keys_path: Some(
                    bootstrap_config
                        .storage_paths
                        .vc_keys
                        .clone(),
                ),
                connection_points_storage_path: Some(
                    bootstrap_config
                        .storage_paths
                        .connection_points
                        .clone(),
                ),
            };

            let mut manager = crate::gateways::ConnectionPointListenerManager::new(
                vc_issuer_for_api.clone(),
                msg_store.clone(),
                cp_store.clone(),
                did_cache_config,
            )
            .await?;

            info!(
                "✓ DID cache configured: TTL={}s, max_entries={}, stale_threshold={}%, storage={}, local_domain={}, vc_keys_path={}",
                bootstrap_config
                    .did_cache
                    .ttl_seconds,
                bootstrap_config
                    .did_cache
                    .max_entries,
                bootstrap_config
                    .did_cache
                    .stale_threshold_percent,
                bootstrap_config
                    .did_cache
                    .storage_path,
                network_config.did.domain,
                bootstrap_config
                    .storage_paths
                    .vc_keys
            );

            // Add optional stores for OOB connection handling
            if let Some(ref gw_store) = gateway_store {
                manager = manager.with_gateway_store(gw_store.clone());
            }
            manager = manager.with_pending_connection_store(pending_connection_store.clone());
            if let Some(ref med_store) = mediator_store {
                manager = manager.with_mediator_store(med_store.clone());
            }
            if let Some(ref notif_store) = notification_store {
                manager = manager.with_notification_store(notif_store.clone());
            }
            manager = manager.with_bootstrap_config(bootstrap_config.clone());
            manager = manager.with_network_config(Arc::new(network_config.clone()));

            // Use Arc::new_cyclic to create Arc with weak self-reference in one step
            // This avoids the need for Arc::try_unwrap
            let mut listener_start_rx_opt: Option<
                tokio::sync::mpsc::UnboundedReceiver<
                    crate::gateways::connection_points::ws_listener::ListenerStartCommand,
                >,
            > = None;

            let manager = Arc::new_cyclic(|weak_ref| {
                let (manager_with_channel, rx) = manager.with_self_ref_and_channel(weak_ref.clone());
                listener_start_rx_opt = Some(rx);
                manager_with_channel
            });
            crate::gateways::connection_points::message_processor::init_agent_pay_relay(manager.clone()).await;

            spawn_mode_lifecycle(
                Activation::new(
                    Some((manager.clone(), bootstrap_config.clone())),
                    pipe_store.clone(),
                    pipe_route_manager.clone(),
                )
                .with_policies(activation_policy_stores.clone(), activation_policy_engines.clone())
                .with_reloads(promotion_reloads.clone())
                .with_integrations(
                    integration_storage.clone(),
                    crate::storage::integration_credentials::secrets_store(),
                ),
            );

            let mut listener_start_rx =
                listener_start_rx_opt.ok_or_else(|| anyhow::anyhow!("Failed to initialize listener start channel"))?;

            // Start DID cache maintenance task
            manager.start_cache_maintenance_task();

            // Load cached DIDs from disk
            let did_cache = manager.get_did_cache();
            match did_cache
                .load_from_disk()
                .await
            {
                Ok(count) if count > 0 => {
                    info!(
                        "✓ Loaded {} cached DID documents from {}",
                        count,
                        bootstrap_config
                            .did_cache
                            .storage_path
                    );
                }
                Ok(_) => {
                    debug!("No cached DID documents found on disk");
                }
                Err(e) => {
                    warn!("Failed to load cached DIDs from disk: {}", e);
                }
            }

            // Pre-warm the cache with active gateway and connection point DIDs
            // This reduces CPU usage by avoiding on-demand DID resolution during message processing
            info!("Pre-warming DID cache with active gateway and connection point DIDs...");
            match did_cache
                .prewarm_cache(&gateway_store, &connection_point_store)
                .await
            {
                Ok(count) if count > 0 => {
                    info!("✓ Pre-warmed DID cache with {} entries - reduced latency for message encryption", count);
                }
                Ok(_) => {
                    debug!("No gateways or connection points to pre-warm");
                }
                Err(e) => {
                    warn!("Failed to pre-warm DID cache: {} (will resolve on-demand)", e);
                }
            }

            // Set DID cache on the VC issuer for VP verification caching
            if let Some(ref issuer) = vc_issuer {
                issuer
                    .set_did_cache(did_cache.clone())
                    .await;
                info!("✓ DID cache set on GW2 VC issuer - agent DIDs will be cached");
            }

            // Spawn background task to process listener start requests
            let manager_for_processor = manager.clone();
            let config_for_processor = bootstrap_config.clone();
            tokio::spawn(async move {
                info!("🎧 Listener start request processor started");
                while let Some(cmd) = listener_start_rx.recv().await {
                    info!("📨 Received listener start request for connection point {}", cmd.connection_point.id);
                    let result = manager_for_processor
                        .start_listener(&cmd.connection_point, cmd.mediator_did, config_for_processor.clone())
                        .await;

                    // Notify the caller of completion (success or failure)
                    if let Some(completion_tx) = cmd.completion_tx {
                        let _ = completion_tx.send(
                            result
                                .clone()
                                .map_err(|e| e.to_string()),
                        );
                    }

                    match result {
                        Ok(_) => {
                            info!("✅ Listener started successfully for connection point {}", cmd.connection_point.id);
                        }
                        Err(e) => {
                            error!(
                                "❌ Failed to start listener for connection point {}: {}",
                                cmd.connection_point.id, e
                            );
                        }
                    }
                }
                warn!("⚠️  Listener start request processor stopped");
            });

            // Delete expired connection points left from previous runs. Listener
            // start-up belongs to activation (`Activation::activate`), which skips
            // expired connection points; this only clears them from storage, on an
            // instance that boots Active, as the boot auto-start did before.
            let cp_store_clone = cp_store.clone();
            tokio::spawn(async move {
                if crate::server::mode::current_mode() != crate::server::mode::ServerMode::Active {
                    return;
                }
                let connection_points = match cp_store_clone
                    .list_all()
                    .await
                {
                    Ok(connection_points) => connection_points,
                    Err(e) => {
                        error!("Failed to list connection points for expiry cleanup: {}", e);
                        return;
                    }
                };
                let now = chrono::Utc::now();
                let mut expired_count = 0;
                for cp in &connection_points {
                    // Expiry is either `cp.expires_at` (inviter-side user-created
                    // connection points) or `oob_message.expires_at` (acceptor-side
                    // temporary ones).
                    let is_expired = if let Some(struct_expires_at) = cp.expires_at {
                        struct_expires_at < now
                    } else {
                        cp.oob_message
                            .get("expires_at")
                            .and_then(|value| {
                                serde_json::from_value::<chrono::DateTime<chrono::Utc>>(value.clone()).ok()
                            })
                            .is_some_and(|json_expires_at| json_expires_at < now)
                    };
                    if !is_expired {
                        continue;
                    }
                    info!(
                        "🧹 Cleaning up expired connection point: {} (type: {:?}, ID: {})",
                        cp.name, cp.cp_type, cp.id
                    );
                    if let Err(e) = cp_store_clone
                        .delete(&cp.id)
                        .await
                    {
                        warn!("   Failed to delete expired connection point: {}", e);
                    } else {
                        expired_count += 1;
                    }
                }
                if expired_count > 0 {
                    info!("✓ Cleaned up {} expired connection points", expired_count);
                }
            });

            // Clean up pending OOB gateways from previous sessions
            // Since temporary DID secrets are in-memory only, we cannot restart listeners after server restart
            // These gateways should be cleaned up as they're from incomplete handshakes
            if let Some(ref gw_store) = gateway_store {
                let gw_store_clone = gw_store.clone();
                let pending_store_clone = pending_connection_store.clone();

                tokio::spawn(async move {
                    info!("Checking for pending OOB gateways from previous sessions...");

                    // Small delay after startup
                    tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

                    match gw_store_clone
                        .list_all()
                        .await
                    {
                        Ok(gateways) => {
                            let pending_gateways: Vec<_> = gateways
                                .into_iter()
                                .filter(|gw| gw.status == crate::gateways::types::GatewayStatus::Pending)
                                .collect();

                            if pending_gateways.is_empty() {
                                info!("No pending gateways from previous sessions");
                            } else {
                                warn!("Found {} pending gateway(s) from previous session(s)", pending_gateways.len());
                                warn!("These are from incomplete OOB handshakes that cannot be resumed");

                                for gateway in pending_gateways {
                                    warn!("  - Cleaning up pending gateway: {} (ID: {})", gateway.name, gateway.id);

                                    // Delete the gateway
                                    if let Err(e) = gw_store_clone
                                        .delete(&gateway.id)
                                        .await
                                    {
                                        error!("Failed to delete pending gateway '{}': {}", gateway.name, e);
                                    } else {
                                        info!("  ✓ Deleted pending gateway '{}'", gateway.name);
                                    }

                                    // Also clean up the pending connection if it exists
                                    if let Some(pending_conn) = pending_store_clone
                                        .get_by_temporary_did(&gateway.did)
                                        .await
                                    {
                                        pending_store_clone
                                            .remove(&pending_conn.id)
                                            .await;
                                        info!("  ✓ Cleaned up pending connection state");
                                    }
                                }

                                info!("✓ Pending gateway cleanup complete");
                            }
                        }
                        Err(e) => {
                            error!("Failed to list gateways for pending cleanup: {}", e);
                        }
                    }
                });
            }

            Some(manager)
        } else {
            error!("Cannot initialize listener manager without message store");
            spawn_mode_lifecycle(
                Activation::new(None, pipe_store.clone(), pipe_route_manager.clone())
                    .with_policies(activation_policy_stores.clone(), activation_policy_engines.clone())
                    .with_reloads(promotion_reloads.clone())
                    .with_integrations(
                        integration_storage.clone(),
                        crate::storage::integration_credentials::secrets_store(),
                    ),
            );
            None
        };

        // Update the listener_manager slot so running channels can access it
        if let Some(ref listener_mgr) = listener_manager {
            let mut slot = listener_manager_slot
                .write()
                .await;
            *slot = Some(listener_mgr.clone());
            info!("✓ Listener manager set in shared slot - fabric:// protocol now available for all channels");
        }

        // Update channel manager with listener_manager (for fabric:// protocol support in new channels)
        if let Some(ref listener_mgr) = listener_manager {
            channel_manager
                .set_listener_manager(listener_mgr.clone())
                .await;
        }

        // Create dashboard state (after listener_manager is initialized)
        let dashboard_state = crate::observability::DashboardState {
            config: Arc::clone(&config),
            network_config: Arc::new(network_config.clone()),
            identity_store: vc_issuer_for_api.get_identity_store(),
            metrics_store: identity_metrics_store.clone(),
            vc_issuer: vc_issuer_for_api.clone(),
            ws_state: ws_state.clone(),
            task_monitor: task_monitor.clone(),
            channel_manager: channel_manager.clone(),
            connection_point_listener_manager: listener_manager.clone(),
            notification_store: notification_store.clone(),
            auth_state: auth_state.clone(),
            pipe_store: pipe_store.clone(),
            system_metrics_store: system_metrics_store.clone(),
        };

        // Start periodic delta broadcast: pushes unfiltered dashboard deltas
        // over WebSocket so clients no longer need to HTTP-poll /delta.
        crate::observability::init_dashboard_delta_broadcast(dashboard_state.clone(), 5);

        // Build the unified source authentication middleware
        // First create the api_key_validator since source_auth_middleware depends on it
        let api_keys_storage_path = std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .secrets,
        )
        .parent()
        .map(|p| p.join("api_keys"))
        .unwrap_or_else(|| std::path::PathBuf::from("_storage/api_keys"));
        let api_keys_storage_path_str = api_keys_storage_path
            .to_string_lossy()
            .to_string();
        // Privileged management routers require RBAC. Production startup must
        // fail instead of composing unprotected routes when auth state is absent.
        let vault_rbac_guard = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.storage.clone())
            })
            .or_else(|| {
                oidc_state
                    .as_ref()
                    .map(|oidc| oidc.storage.clone())
            })
            .map(|storage| crate::auth_manager::middleware::RbacGuard::new(storage, rbac_config.clone()))
            .ok_or_else(|| anyhow::anyhow!("RBAC guard unavailable after authentication initialization"))?;
        let agent_surface_store: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>> =
            match crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .agent_surfaces,
            ))
            .await
            {
                Ok(store) => Some(Arc::new(store)),
                Err(error) => {
                    warn!("Failed to initialize Agent Surface ownership store: {}", error);
                    None
                }
            };
        let (api_keys_router, api_key_validator, api_key_management_store) =
            match crate::api_keys::FsApiKeyStore::new(&api_keys_storage_path_str).await {
                Ok(store) => {
                    info!("API Keys store initialized at {}", api_keys_storage_path_str);
                    let store_arc = std::sync::Arc::new(store);
                    let router = Some(crate::api_keys::router::create_api_keys_router(
                        store_arc.clone(),
                        crate::api_keys::parent::ApiKeyParents::new(agent_surface_store.clone(), pipe_store.clone()),
                        vault_rbac_guard.clone(),
                    ));
                    {
                        use crate::api_keys::traits::ApiKeyStore as _;
                        let s = store_arc.clone();
                        crate::config::register_counter("secrets.apikeys", move || {
                            let s = s.clone();
                            async move {
                                s.list_all()
                                    .await
                                    .map(|v| v.len())
                                    .unwrap_or(0)
                            }
                        });
                    }
                    let management_store: std::sync::Arc<dyn crate::api_keys::traits::ApiKeyStore> = store_arc.clone();
                    let validator: std::sync::Arc<dyn crate::api_keys::ApiKeyValidator> = store_arc;
                    (router, Some(validator), Some(management_store))
                }
                Err(e) => {
                    warn!("Failed to initialize API Keys store at {}: {}", api_keys_storage_path_str, e);
                    (None, None, None)
                }
            };

        // Management access tokens (service-account PATs): one filesystem store
        // shared by the identity + vault auth guards (token validation) and the
        // access-token admin router (mint/list/revoke).
        let access_tokens_storage_path = std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .secrets,
        )
        .parent()
        .map(|p| p.join("access_tokens"))
        .unwrap_or_else(|| std::path::PathBuf::from("_storage/access_tokens"));
        let access_tokens_storage_path_str = access_tokens_storage_path
            .to_string_lossy()
            .to_string();
        let (access_tokens_router, pat_authenticator) =
            match crate::access_tokens::FsAccessTokenStore::new(&access_tokens_storage_path_str).await {
                Ok(store) => {
                    info!("Access tokens store initialized at {}", access_tokens_storage_path_str);
                    let store_arc = std::sync::Arc::new(store);
                    let router = crate::access_tokens::router::create_access_tokens_router(
                        store_arc.clone(),
                        rbac_config.clone(),
                        Arc::new(
                            bootstrap_config
                                .tenancy
                                .clone(),
                        ),
                        vault_rbac_guard.clone(),
                    );
                    let authenticator: std::sync::Arc<dyn crate::auth_manager::pat::PatAuthenticator> = store_arc;
                    (Some(router), Some(authenticator))
                }
                Err(e) => {
                    warn!("Failed to initialize access tokens store at {}: {}", access_tokens_storage_path_str, e);
                    (None, None)
                }
            };

        let secrets_cache: crate::secrets::SecretsCache = std::sync::Arc::new(dashmap::DashMap::new());

        // Create certificates store early so source auth middleware can resolve
        // mTLS trust material via certificate IDs.
        let certificates_store: Arc<dyn crate::certificates::CertificateStore> = Arc::new(
            crate::certificates::FilesystemCertificateStore::new(std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .certificates,
            ))
            .await
            .expect("Failed to create certificates store"),
        );
        let certificates_router = crate::certificates::router::create_certificates_router(
            certificates_store.clone(),
            vault_rbac_guard.clone(),
        );

        register_resource_limit_counters(
            &secrets_store,
            &certificates_store,
            &credential_provider_store,
            &delegation_vault_store,
            &gateway_store,
            &mediator_store,
            &connection_point_store,
            &pipe_store,
            &policy_definition_store,
        );

        // users — resolved from the passkey/SAML auth storage (no dedicated
        // store, so it isn't covered by register_resource_limit_counters).
        if let Some(user_storage) = auth_state
            .as_ref()
            .map(|s| s.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|s| s.storage.clone())
            })
            .or_else(|| {
                oidc_state
                    .as_ref()
                    .map(|s| s.storage.clone())
            })
        {
            crate::config::register_counter("users", move || {
                let s = user_storage.clone();
                async move {
                    s.list_users()
                        .await
                        .map(|v| v.len())
                        .unwrap_or(0)
                }
            });
        }

        let source_auth_middleware = init_source_auth_middleware(
            &bootstrap_config
                .storage_paths
                .secrets,
            client.clone(),
            Some(secrets_store.clone()),
            secrets_cache.clone(),
            api_key_validator.clone(),
            Some(certificates_store.clone()),
        )
        .await;

        // Register with the GW2 message processor (global singleton).
        if let Some(ref sa_mw) = source_auth_middleware {
            crate::gateways::connection_points::message_processor::init_source_auth_middleware(sa_mw.clone()).await;
            info!("Source auth middleware registered with GW2 message processor");
        }

        crate::auth::throttle::set_trusted_proxies(
            config
                .tls
                .client_auth
                .trusted_proxies
                .clone(),
        );

        // Resolve inbound client-cert mTLS material once (CA cert DERs) so the
        // listener can build a WebPkiClientVerifier. Shared across inbound
        // and outbound listeners.
        let direct_client_auth: Option<Arc<crate::server::DirectClientAuth>> =
            match crate::source_auth::peer_cert::load_inbound_client_auth(
                Some(&certificates_store),
                &config.tls.client_auth,
            )
            .await
            {
                Ok(Some(da)) => {
                    info!(
                        mode = ?da.mode,
                        ca_count = da.ca_certs.len(),
                        "Inbound mTLS direct client auth enabled"
                    );
                    Some(Arc::new(da))
                }
                Ok(None) => None,
                Err(e) => {
                    if config.tls.client_auth.direct == crate::config::types::DirectClientAuthMode::Required {
                        anyhow::bail!("Inbound mTLS mode is 'required' but client auth failed to initialise: {e}");
                    }
                    error!("Failed to initialise inbound direct client auth: {e}");
                    None
                }
            };

        let jwt_strategy_store_for_api = source_auth_middleware
            .as_ref()
            .map(|middleware| middleware.provider_store());
        let ownership_stores = Arc::new(crate::identity::handlers::tenant_ownership::TenantOwnershipStores {
            gateways: gateway_store.clone(),
            mediators: mediator_store.clone(),
            connection_points: connection_point_store.clone(),
            secrets: Some(secrets_store.clone()),
            certificates: Some(certificates_store.clone()),
            integrations: integration_storage.clone(),
            credential_providers: credential_provider_store.clone(),
            jwt_strategies: jwt_strategy_store_for_api.clone(),
            oauth_identifiers: crate::oauth_identifiers::global_oauth_identifier_store(),
            agent_surfaces: agent_surface_store.clone(),
            api_keys: api_key_management_store,
        });
        let api_router = crate::identity::create_identity_api_router(
            identity_state.clone(),
            ownership_stores,
            dashboard_state,
            auth_state,
            saml_state.clone(),
            oidc_state.clone(),
            vault_rbac_guard.clone(),
            gateway_store,
            mediator_store,
            Some(secrets_store.clone()),
            Some(certificates_store.clone()),
            agent_surface_store.clone(),
            connection_point_store,
            notification_store.clone(),
            listener_manager.clone(),
            message_store.clone(),
            pending_connection_store.clone(),
            integration_storage,
            pipe_route_manager.clone(),
            // Re-use the same store that backs the middleware so hot-reloads are consistent.
            jwt_strategy_store_for_api,
            // Pass the JwksClient so the validate-jwks-uri endpoint can probe URIs.
            source_auth_middleware
                .as_ref()
                .map(|mw| mw.jwks_client()),
            marketplace_model_store,
            gateway_policy_manager.clone(),
            pat_authenticator.clone(),
            terms_manager.clone(),
        );

        let secrets_router = crate::secrets::router::create_secrets_router(
            secrets_store.clone(),
            notification_store.clone(),
            Some(secrets_cache),
            network_config.secrets.clone(),
            vault_rbac_guard.clone(),
        );

        // certificates_store and certificates_router were created earlier so the
        // source auth middleware could be initialised with access to them.

        // Create vault identity router (for generating DIDs for API keys and certificates)
        let vault_identity_router = if let Some(ref vc_issuer) = vc_issuer {
            crate::vault_identity::create_vault_identity_router(vc_issuer.clone(), vault_rbac_guard.clone())
        } else {
            Router::new() // Empty router if identity API is not enabled
        };

        // Create credential delegation routers (credential providers CRUD + delegation vault).
        // Management routes go inside the session-auth boundary; the OAuth callback
        // (browser redirect target) is the only piece that must remain public.
        let (credential_delegation_mgmt_router, credential_delegation_oauth_router) =
            if let (Some(cp_store), Some(dv_store)) = (&credential_provider_store, &delegation_vault_store) {
                let base_url = format!("https://{}", network_config.did.domain);

                let cp_router = crate::credential_providers::router::create_credential_providers_router(
                    cp_store.clone(),
                    secrets_store.clone(),
                    network_config
                        .oauth_callback_route
                        .clone(),
                    vault_rbac_guard.clone(),
                );

                let dv_state = crate::delegation_vault::handlers::DelegationVaultState {
                    vault_store: dv_store.clone(),
                    provider_store: cp_store.clone(),
                    secrets_store: secrets_store.clone(),
                    gateway_base_url: base_url,
                    agent_surface_store: None,
                    oauth_callback_route: network_config
                        .oauth_callback_route
                        .clone(),
                    vc_signer: vc_issuer
                        .as_ref()
                        .map(|issuer| issuer.get_vc_signer()),
                    vc_issuer: vc_issuer.clone(),
                    consent_granted_workload_binding_vp_enabled: false,
                    vault_population_notifier: Some(
                        crate::delegation_vault::notifier::global_vault_population_notifier().clone(),
                    ),
                };
                let dv_mgmt_router = crate::delegation_vault::router::create_delegation_vault_router(
                    dv_state.clone(),
                    vault_rbac_guard.clone(),
                );
                let dv_oauth_router = crate::delegation_vault::router::create_delegation_vault_oauth_router(dv_state);

                info!(target: "credential_delegation", "Credential delegation routes registered");
                (
                    Router::new()
                        .merge(cp_router)
                        .merge(dv_mgmt_router),
                    dv_oauth_router,
                )
            } else {
                warn!(target: "credential_delegation", "Credential delegation disabled — store initialization failed");
                (Router::new(), Router::new())
            };

        // Combine secrets, API keys, certificates, and trust check into vault router
        // Apply session auth middleware to protect vault routes (secrets, apikeys, certificates)
        let session_mgr_for_vault = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.session_manager.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.session_manager.clone())
            })
            .or_else(|| {
                oidc_state
                    .as_ref()
                    .map(|oidc| oidc.session_manager.clone())
            });
        let user_storage_for_vault: Option<Arc<crate::auth::storage::PasskeyStorage>> = auth_state_for_notif
            .as_ref()
            .map(|auth| auth.storage.clone())
            .or_else(|| {
                saml_state
                    .as_ref()
                    .map(|saml| saml.storage.clone())
            })
            .or_else(|| {
                oidc_state
                    .as_ref()
                    .map(|oidc| oidc.storage.clone())
            });

        let vault_router = {
            let mut router = Router::new()
                .merge(secrets_router)
                .merge(certificates_router)
                .merge(vault_identity_router)
                .merge(credential_delegation_mgmt_router);

            if let Some(api_keys_r) = api_keys_router {
                router = router.merge(api_keys_r);
            }

            if let Some(access_tokens_r) = access_tokens_router {
                router = router.merge(access_tokens_r);
            }

            if let Some(ref catalog) = llm_provider_catalog {
                let catalog_refresh_url = network_config
                    .llm_catalog
                    .as_ref()
                    .and_then(|c| {
                        c.refresh_url()
                            .map(str::to_string)
                    });
                let allow_insecure_source = network_config
                    .llm_catalog
                    .as_ref()
                    .is_some_and(|c| c.allow_insecure_source);
                router = router.merge(crate::llm_catalog::router::create_llm_providers_router(
                    catalog.clone(),
                    catalog_refresh_url,
                    allow_insecure_source,
                    vault_rbac_guard.clone(),
                ));
            }

            if let Some(sess_mgr) = session_mgr_for_vault {
                info!("Vault API router protected with session auth middleware");
                let guard_state = crate::auth_manager::middleware::AuthGuardState::new(
                    sess_mgr,
                    user_storage_for_vault.clone(),
                    terms_manager.clone(),
                )
                .with_pat_authenticator(pat_authenticator.clone())
                .with_trusted_tenant_header(
                    bootstrap_config
                        .tenancy
                        .trusted_tenant_header
                        .clone()
                        .map(Arc::new),
                );
                router = router.layer(axum::middleware::from_fn_with_state(
                    guard_state,
                    crate::auth_manager::middleware::require_session_auth,
                ));
            }

            // Public routes merged AFTER the auth layer — these must remain unauthenticated.
            // - credential_delegation_oauth_router: OAuth provider redirects the user's
            //   browser here; there is no session at this point.
            router = router.merge(credential_delegation_oauth_router);

            router
        };

        // Extract DID:webvh stores before identity_state is moved
        #[cfg(feature = "didwebvh")]
        let didwebvh_identity_store_shared = identity_state
            .didwebvh_identity_store
            .clone();
        #[cfg(feature = "didwebvh")]
        let didwebvh_log_storage_shared = identity_state
            .didwebvh_log_storage
            .clone();

        // Create separate DID router for did:web resolution at root level
        let did_router = crate::identity::create_did_router(identity_state);

        // Store the identity API router to be merged into port listeners instead of starting separate servers
        let mut identity_http_router: Option<axum::Router> = None;
        let mut identity_https_router: Option<axum::Router> = None;
        let mut did_http_router: Option<axum::Router> = None;
        let mut did_https_router: Option<axum::Router> = None;
        let mut vault_http_router: Option<axum::Router> = None;
        let mut vault_https_router: Option<axum::Router> = None;

        // Determine which ports to merge the Identity API router into based on network_config listeners
        // Use the first inbound HTTP/HTTPS listeners from gateway.json
        let identity_api_http_port = network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "http" && l.listener_type == "inbound")
            .map(|l| l.port);

        let identity_api_https_port = network_config
            .listeners
            .iter()
            .find(|l| l.protocol.to_lowercase() == "https" && l.listener_type == "inbound")
            .map(|l| l.port);

        if let Some(http_port) = identity_api_http_port {
            info!("Identity API HTTP router will be merged into port {} listener", http_port);
            identity_http_router = Some(api_router.clone());
            did_http_router = Some(did_router.clone());
            vault_http_router = Some(vault_router.clone());
        }

        if let Some(https_port) = identity_api_https_port {
            info!("Identity API HTTPS router will be merged into port {} listener", https_port);
            identity_https_router = Some(api_router.clone());
            did_https_router = Some(did_router.clone());
            vault_https_router = Some(vault_router.clone());
        }

        // Store routers in channel_manager for use during reload
        channel_manager
            .set_identity_routers(
                identity_http_router.clone(),
                identity_https_router.clone(),
                did_http_router.clone(),
                did_https_router.clone(),
                vault_http_router.clone(),
                vault_https_router.clone(),
            )
            .await;

        // Store services in channel_manager for use during reload
        channel_manager
            .set_services(
                Some(secrets_store.clone()),
                Some(policy_manager.clone()),
                Some(gateway_policy_manager.clone()),
            )
            .await;

        // Store pipe services in channel_manager
        channel_manager
            .set_pipe_services(pipe_store.clone(), pipe_route_manager.clone())
            .await;

        // Store notification store in channel_manager
        channel_manager
            .set_notification_store(notification_store.clone())
            .await;

        // Store unified source auth middleware in channel_manager
        channel_manager
            .set_source_auth_middleware(source_auth_middleware.clone())
            .await;

        channel_manager
            .set_direct_client_auth(direct_client_auth.clone())
            .await;

        // Store DID:webvh stores in channel_manager for use during channel startup
        #[cfg(feature = "didwebvh")]
        channel_manager
            .set_didwebvh_stores(didwebvh_identity_store_shared.clone(), didwebvh_log_storage_shared.clone())
            .await;

        // NOW spawn port listeners with Identity API router
        let mut port_listener_handles = HashMap::new();

        // Fail fast on configuration errors that would shadow dashboard SPA
        // routes — admin must rename the offending prefix and restart.
        // Running with these silently would replace dashboard pages with
        // proxy 404s, which is much worse than refusing to start.
        {
            // Surface serving is store-backed (pipe-only gateway); the dead
            // `RouteType::Proxy` category no longer contributes serving prefixes,
            // so only channel prefixes are checked for SPA-route collisions.
            let all_prefixes: Vec<&str> = network_config
                .channels
                .iter()
                .map(|c| c.prefix.as_str())
                .collect();
            let collisions = crate::proxy::paths::check_spa_route_collisions(all_prefixes);
            if !collisions.is_empty() {
                let detail = collisions
                    .iter()
                    .map(|(p, spa)| format!("    - prefix '{}' shadows SPA route '{}'", p, spa))
                    .collect::<Vec<_>>()
                    .join("\n");
                let banner = format!(
                    "\n\
                     ============================================================\n\
                     FATAL: Gateway configuration error\n\
                     ============================================================\n\
                     One or more channel/proxy prefixes collide with reserved\n\
                     dashboard SPA routes. Starting in this state would replace\n\
                     dashboard pages with proxy 404s, so the server is exiting.\n\n\
                     Collisions:\n{}\n\n\
                     Fix: rename each offending prefix (e.g. '/svc/<name>') in\n\
                     your gateway.json and restart.\n\
                     ============================================================\n",
                    detail
                );
                error!("{}", banner);
                eprintln!("{}", banner);
                std::process::exit(2);
            }
        }

        // Iterate over ALL configured ports, not just those with channels
        // This ensures routes from network.json are served even if no channels exist
        for port in configured_ports {
            let listener_info = network_config
                .listeners
                .iter()
                .find(|l| l.port == port);
            let is_outbound = listener_info
                .map(|l| l.listener_type.as_str() == "outbound")
                .unwrap_or(false);

            if is_outbound {
                info!("Outbound listener on port {} is no longer served (pipe-only mode) — skipping", port);
                let handle = tokio::spawn(std::future::pending::<()>());
                port_listener_handles.insert(port, handle.abort_handle());
                continue;
            }

            // Clone pipe services for this port
            let pipe_store_for_port = pipe_store.clone();
            let pipe_route_manager_for_port = pipe_route_manager.clone();
            let settings_store_for_port = settings_store.clone();
            let notification_store_for_port = notification_store.clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_identity_store_for_port = didwebvh_identity_store_shared.clone();
            #[cfg(feature = "didwebvh")]
            let didwebvh_log_storage_for_port = didwebvh_log_storage_shared.clone();

            // Get channels for this port (may be empty)
            let channels = channels_by_port_deferred
                .get(&port)
                .cloned()
                .unwrap_or_default();

            let port_task_id = format!("port-{}-{}", port, uuid::Uuid::new_v4());
            let tls_acceptor = tls_acceptor.clone();
            let client = client.clone();
            let config_clone = Arc::clone(&config);
            let bootstrap_config_clone = Arc::clone(&bootstrap_config);
            let metrics = metrics_store.clone();
            let task_mon = task_monitor.clone();
            let task_id_clone = port_task_id.clone();
            let ws_state_clone = ws_state.clone();
            let vc_issuer_clone = vc_issuer.clone();
            let channels_clone = channels.clone();
            let listener_mgr_slot = listener_manager_slot.clone();
            let network_config_clone = Arc::new(network_config.clone());

            // Determine if this port should get the Identity API router
            let identity_router_for_port = if Some(port) == identity_api_http_port {
                identity_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                identity_https_router.clone()
            } else {
                None
            };

            // Determine if this port should get the DID router
            let did_router_for_port = if Some(port) == identity_api_http_port {
                did_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                did_https_router.clone()
            } else {
                None
            };

            // Determine if this port should get the Secrets router
            let secrets_router_for_port = if Some(port) == identity_api_http_port {
                vault_http_router.clone()
            } else if Some(port) == identity_api_https_port {
                vault_https_router.clone()
            } else {
                None
            };

            // Clone secrets_store for this port
            let secrets_store_for_port = Some(secrets_store.clone());

            // Clone policy_manager for this port
            let policy_mgr_clone = Some(policy_manager.clone());

            // Clone gateway_policy_manager for this port
            let gateway_policy_mgr_clone = Some(gateway_policy_manager.clone());

            // Clone source_auth_middleware for this port
            let source_auth_middleware_for_port = source_auth_middleware.clone();
            let direct_client_auth_for_port = direct_client_auth.clone();

            // Determine if this port should use TLS based on network config
            let use_tls = network_config
                .listeners
                .iter()
                .find(|l| l.port == port)
                .map(|l| l.protocol.to_lowercase() == "https")
                .unwrap_or(false);

            info!(
                "Port {} protocol: {}",
                port,
                if use_tls {
                    "HTTPS (TLS)"
                } else {
                    "HTTP (plain)"
                }
            );
            info!("Starting port listener on 0.0.0.0:{} for {} channel(s)", port, channels.len());
            for surface in &channels {
                info!(
                    "  -> Channel '{}' route: {} -> {}",
                    surface.name, surface.access_point.route, surface.target.endpoint
                );
            }

            let handle = tokio::spawn(async move {
                if let Err(e) = crate::proxy::server::run_port_server(
                    port,
                    channels_clone,
                    tls_acceptor,
                    client,
                    config_clone,
                    bootstrap_config_clone,
                    metrics,
                    task_mon.clone(),
                    Some(task_id_clone.clone()),
                    Some(ws_state_clone),
                    vc_issuer_clone,
                    listener_mgr_slot,
                    identity_router_for_port,
                    did_router_for_port,
                    secrets_router_for_port,
                    secrets_store_for_port,
                    network_config_clone,
                    use_tls,
                    policy_mgr_clone,
                    gateway_policy_mgr_clone,
                    pipe_store_for_port,
                    pipe_route_manager_for_port,
                    settings_store_for_port,
                    notification_store_for_port,
                    source_auth_middleware_for_port,
                    direct_client_auth_for_port,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_identity_store_for_port,
                    #[cfg(feature = "didwebvh")]
                    didwebvh_log_storage_for_port,
                )
                .await
                {
                    error!("Port listener error for port {}: {}", port, e);
                }
            });

            // Store the abort handle for this port listener
            port_listener_handles.insert(port, handle.abort_handle());

            // Store the handle for each channel in this port listener
            for surface in &channels {
                let config_id = surface
                    .config_id()
                    .unwrap_or(surface.name.as_str())
                    .to_string();
                let channel_task_id = format!("task-{}-{}", config_id, uuid::Uuid::new_v4());
                channel_handles.insert(config_id.clone(), handle.abort_handle());
                task_ids_map.insert(config_id, channel_task_id);
            }
        }

        // Store port listener handles in the manager
        {
            let mut handles = channel_manager
                .port_listener_handles
                .write()
                .await;
            *handles = port_listener_handles;
        }
        {
            let mut handles = channel_manager
                .channel_handles
                .write()
                .await;
            *handles = channel_handles;
        }
        {
            let mut task_ids = channel_manager
                .task_ids
                .write()
                .await;
            *task_ids = task_ids_map;
        }

        // Log file watcher is no longer needed - logs are broadcast directly via WebSocketLogLayer
        // when they're written by the tracing system

        // Start periodic metrics update task to ensure UI refreshes even with no traffic
        let ws_state_for_metrics = ws_state.clone();
        let metrics_store_for_periodic = identity_metrics_store.clone();

        let periodic_metrics_task = tokio::spawn(async move {
            periodic_metrics_update(ws_state_for_metrics, metrics_store_for_periodic).await;
        });

        tasks.push(periodic_metrics_task);

        // Start system metrics (CPU/memory) collection task
        if let Some(ref store) = system_metrics_store {
            let store_for_system = store.clone();
            let system_metrics_task = tokio::spawn(async move {
                crate::observability::periodic_system_metrics_collection(
                    store_for_system,
                    crate::observability::SYSTEM_METRICS_INTERVAL_SECS,
                )
                .await;
            });
            tasks.push(system_metrics_task);
        }

        // Start periodic session cleanup task to remove expired sessions
        // This ensures sessions don't accumulate on disk even if the server runs for extended periods
        let sso_sessions_for_cleanup = saml_state
            .as_ref()
            .map(|s| s.session_manager.clone())
            .or_else(|| {
                oidc_state
                    .as_ref()
                    .map(|s| s.session_manager.clone())
            });
        let session_cleanup_task = tokio::spawn(async move {
            periodic_session_cleanup(sso_sessions_for_cleanup).await;
        });

        tasks.push(session_cleanup_task);
    }

    // Wait for all tasks
    for task in tasks {
        task.await?;
    }

    Ok(())
}

/// Initialize passkey authentication state
async fn initialize_auth_state(
    bootstrap_config: &crate::config::BootstrapConfig,
    network_config: &crate::config::NetworkConfig,
    metrics_store: Arc<crate::metrics::MetricsStore>,
    terms_manager: Arc<crate::terms::TermsManager>,
) -> anyhow::Result<crate::auth::AuthState> {
    // Determine RP ID and origin from config
    // rp_id must be just the hostname (no port) to satisfy WebAuthn spec
    let rp_id = network_config
        .webauthn
        .rp_id
        .clone();

    // Use external_origin from config (required for WebAuthn)
    let rp_origin_str = network_config
        .webauthn
        .external_origin
        .clone();

    let rp_origin =
        url::Url::parse(&rp_origin_str).with_context(|| format!("Failed to parse RP origin URL: {}", rp_origin_str))?;

    // Create auth state
    let storage_path = bootstrap_config
        .storage_paths
        .passkeys
        .clone();
    let avatars_path = bootstrap_config
        .storage_paths
        .avatars
        .clone();
    let session_timeout_minutes = bootstrap_config.session_timeout_minutes;
    let sessions_path = bootstrap_config
        .storage_paths
        .sessions
        .clone();
    let auth_state = crate::auth::AuthState::new(
        rp_id,
        rp_origin,
        storage_path,
        avatars_path,
        session_timeout_minutes,
        sessions_path,
        metrics_store,
        terms_manager,
    )
    .await?;

    info!(
        "Initialized passkey authentication for origin: {} with rp_id: {}",
        rp_origin_str, network_config.webauthn.rp_id
    );

    Ok(auth_state)
}

/// The user store and the persisted session manager an SSO sign-in mode
/// (SAML or OIDC) uses: the same user store as passkeys, so users are managed
/// the same way in every mode.
async fn initialize_sso_user_stores(
    bootstrap_config: &crate::config::BootstrapConfig
) -> anyhow::Result<(Arc<crate::auth::storage::PasskeyStorage>, Arc<crate::auth::SessionManager>)> {
    let storage = Arc::new(
        crate::auth::storage::PasskeyStorage::new(
            bootstrap_config
                .storage_paths
                .passkeys
                .clone(),
            bootstrap_config
                .storage_paths
                .avatars
                .clone(),
        )
        .await?,
    );
    let session_manager = Arc::new(
        crate::auth::SessionManager::with_storage(
            bootstrap_config.session_timeout_minutes,
            std::path::PathBuf::from(
                &bootstrap_config
                    .storage_paths
                    .sessions,
            ),
        )
        .await
        .context("Failed to create the session manager")?,
    );
    Ok((storage, session_manager))
}

/// Initialize SAML authentication state
async fn initialize_saml_state(
    bootstrap_config: &crate::config::BootstrapConfig,
    saml_config: &crate::auth::SamlConfig,
    terms_manager: Arc<crate::terms::TermsManager>,
) -> anyhow::Result<crate::auth::saml::SamlState> {
    use std::sync::Arc;

    // Create SAML service
    let saml_service = Arc::new(crate::auth::saml::SamlService::new(saml_config.clone())?);
    let (storage, session_manager) = initialize_sso_user_stores(bootstrap_config).await?;
    let avatars_path = bootstrap_config
        .storage_paths
        .avatars
        .clone();

    // Notification store will be set later (similar to passkey auth)
    let notification_store = Arc::new(tokio::sync::RwLock::new(None));

    info!("Initialized SAML authentication with entity ID: {}", saml_config.sp_entity_id);

    Ok(crate::auth::saml::SamlState {
        saml_service,
        storage,
        session_manager,
        avatars_storage_path: avatars_path,
        notification_store,
        terms_manager,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mode::{self, ServerMode};

    fn run<F: std::future::Future>(future: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(future)
    }

    #[test]
    fn activation_marks_ready_without_fabric_listeners() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Active);
        assert!(!mode::is_ready_to_serve());

        assert!(run(Activation::new(None, None, None).activate(mode::current_activation_generation(), None)));

        assert!(mode::is_ready_to_serve());
    }

    #[test]
    fn activation_compiles_surface_policy_from_definitions_another_instance_stored() {
        use crate::pipes::{FileSystemPipeStore, PIPE_POLICY_MANAGER, PipeConfig, PipeType, config::PipeOpaConfig};
        use crate::policies::FileSystemPolicyDefinitionStore;
        use crate::policies::policy_definitions::{PolicyDefinition, PolicyType};

        /// Restores the process-wide pipe policy manager when the test ends,
        /// even on a panic, so no other test resolves definitions from this
        /// test's store or sees its compiled pipe.
        struct RestorePipePolicyManager(Option<Arc<FileSystemPolicyDefinitionStore>>);

        impl Drop for RestorePipePolicyManager {
            fn drop(&mut self) {
                PIPE_POLICY_MANAGER.replace_policy_definition_store(self.0.take());
                PIPE_POLICY_MANAGER.remove_pipe("promotion-pipe");
            }
        }

        fn definition(name: &str) -> PolicyDefinition {
            PolicyDefinition {
                id: "promotion-gate".to_string(),
                name: name.to_string(),
                description: String::new(),
                policy_type: PolicyType::Llm,
                policy: format!("package llm.policy\nimport rego.v1\n# {name}\ndefault allow := true"),
                enabled: true,
                created_at: "2026-01-01T00:00:00Z".to_string(),
                updated_at: None,
                version: None,
                content_hash: None,
                sample_input: None,
                tenant_id: None,
            }
        }

        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        mode::set_server_mode(ServerMode::Active);

        run(async {
            let definitions = Arc::new(
                FileSystemPolicyDefinitionStore::new(path("policies"))
                    .await
                    .unwrap(),
            );
            definitions
                .save(definition("booted"))
                .await
                .unwrap();
            let pipes = Arc::new(
                FileSystemPipeStore::new(path("pipes"))
                    .await
                    .unwrap(),
            );
            let mut pipe = PipeConfig::new(
                "promotion-pipe".to_string(),
                "Promotion".to_string(),
                PipeType::Webhook {
                    endpoint: "https://example.com".to_string(),
                },
            );
            pipe.opa_policy = Some(PipeOpaConfig {
                enabled: true,
                policy_definition_id: Some("promotion-gate".to_string()),
                policy_definition_ids: Vec::new(),
                log_decisions: false,
            });
            pipes
                .save(pipe.clone())
                .await
                .unwrap();
            let _restore = RestorePipePolicyManager(
                PIPE_POLICY_MANAGER.replace_policy_definition_store(Some(definitions.clone())),
            );
            PIPE_POLICY_MANAGER
                .update_pipe_policy(&pipe)
                .await
                .unwrap();

            FileSystemPolicyDefinitionStore::new(path("policies"))
                .await
                .unwrap()
                .save(definition("edited on the active"))
                .await
                .unwrap();

            let activation = Activation::new(None, Some(pipes.clone()), None).with_policies(
                Arc::new(ActivationPolicyStores {
                    definitions: Some(definitions),
                    global: None,
                    gateways: None,
                }),
                Arc::new(crate::identity::handlers::policy_definitions::EngineStores {
                    pipe_store: Some(pipes),
                    global_policy_store: None,
                    agent_surfaces_path: path("agent_surfaces"),
                    gateways_path: path("gateways"),
                }),
            );
            assert!(
                activation
                    .activate(mode::current_activation_generation(), None)
                    .await
            );

            let evidence = PIPE_POLICY_MANAGER
                .policy_evidence("promotion-pipe", None)
                .expect("the pipe policy is compiled");
            assert_eq!(evidence.name.as_deref(), Some("edited on the active"));
        });
        assert!(mode::is_ready_to_serve());
    }

    #[test]
    fn activation_reloads_members_teams_users_and_sessions_before_reporting_ready() {
        use crate::auth::{SessionManager, UserRole, UserStatus, storage::PasskeyStorage, storage::UserData};
        use crate::members::FileSystemMemberStore;
        use crate::teams::FileSystemTeamStore;

        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let path = |name: &str| {
            dir.path()
                .join(name)
                .to_string_lossy()
                .into_owned()
        };
        mode::set_server_mode(ServerMode::Active);

        run(async {
            let members = Arc::new(
                FileSystemMemberStore::new(path("members"))
                    .await
                    .unwrap(),
            );
            let teams = Arc::new(
                FileSystemTeamStore::new(path("teams"))
                    .await
                    .unwrap(),
            );
            let users = Arc::new(
                PasskeyStorage::new(path("users"), path("avatars"))
                    .await
                    .unwrap(),
            );
            let sessions = Arc::new(
                SessionManager::with_storage(20, path("sessions").into())
                    .await
                    .unwrap(),
            );

            let member: crate::members::Member = serde_json::from_value(serde_json::json!({
                "id": "m1", "status": "enabled",
                "identifiers": [{ "kind": "custom", "value": "m1@x.io" }],
                "created_at": "2024-01-01T00:00:00Z", "updated_at": "2024-01-01T00:00:00Z"
            }))
            .unwrap();
            FileSystemMemberStore::new(path("members"))
                .await
                .unwrap()
                .save(member)
                .await
                .unwrap();
            let team: crate::teams::types::Team = serde_json::from_value(serde_json::json!({
                "id": "t1", "name": "T1", "status": "enabled", "members": ["m1"]
            }))
            .unwrap();
            FileSystemTeamStore::new(path("teams"))
                .await
                .unwrap()
                .save(team)
                .await
                .unwrap();
            let now = chrono::Utc::now();
            PasskeyStorage::new(path("users"), path("avatars"))
                .await
                .unwrap()
                .save_user(&UserData {
                    user_id: "u1".to_string(),
                    username: "alice".to_string(),
                    passkeys: Vec::new(),
                    role: UserRole::User,
                    status: UserStatus::New,
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
                })
                .await
                .unwrap();
            let token = SessionManager::with_storage(20, path("sessions").into())
                .await
                .unwrap()
                .create_session("alice".into(), "u1".into())
                .await;

            let activation = Activation::new(None, None, None).with_reloads([
                members.clone() as Arc<dyn mode::ReloadOnPromotion>,
                teams.clone(),
                users.clone(),
                sessions.clone(),
            ]);
            assert!(
                activation
                    .activate(mode::current_activation_generation(), None)
                    .await
            );

            assert_eq!(
                members
                    .find_for_gate("m1@x.io")
                    .await
                    .map(|m| m.id),
                Some("m1".to_string())
            );
            assert_eq!(
                teams
                    .teams_for_member("m1")
                    .await
                    .len(),
                1
            );
            assert!(
                users
                    .load_user("alice")
                    .await
                    .unwrap()
                    .is_some()
            );
            assert_eq!(
                sessions
                    .validate_session(&token)
                    .await,
                Some(("alice".to_string(), "u1".to_string()))
            );
        });
        assert!(mode::is_ready_to_serve());
    }

    #[test]
    fn activation_reloads_spend_counters_before_reporting_ready() {
        use crate::pipes::budget_tracker::BudgetTracker;
        use crate::teams::TeamUsageTracker;

        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let surface_dir = dir
            .path()
            .join("surface_usage");
        let team_dir = dir.path().join("team_usage");
        mode::set_server_mode(ServerMode::Active);

        run(async {
            let budget = Arc::new(BudgetTracker::persistent(&surface_dir).await);
            let team_usage = Arc::new(TeamUsageTracker::new(&team_dir).await);

            let previous_active = BudgetTracker::persistent(&surface_dir).await;
            previous_active
                .record_llm_usage("p1", 3.0, 30)
                .await;
            previous_active
                .wait_for_persist()
                .await;
            let previous_team_usage = TeamUsageTracker::new(&team_dir).await;
            previous_team_usage
                .record("m1", None, &[], 4.0, 40)
                .await;
            previous_team_usage
                .wait_for_persist()
                .await;

            let activation = Activation::new(None, None, None)
                .with_reloads([budget.clone() as Arc<dyn mode::ReloadOnPromotion>, team_usage.clone()]);
            assert!(
                activation
                    .activate(mode::current_activation_generation(), None)
                    .await
            );

            assert_eq!(
                budget
                    .scope_usage("p1", "cumulative")
                    .await,
                (3.0, 30)
            );
            assert_eq!(
                team_usage
                    .member_usage("m1", None)
                    .await
                    .1
                    .total_cost,
                4.0
            );
        });
        assert!(mode::is_ready_to_serve());
    }

    /// Fails its first `failures` reloads, then succeeds.
    struct FlakyReload {
        failures: std::sync::atomic::AtomicUsize,
        attempts: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl mode::ReloadOnPromotion for FlakyReload {
        async fn reload_from_storage(&self) -> std::io::Result<()> {
            use std::sync::atomic::Ordering;
            self.attempts
                .fetch_add(1, Ordering::SeqCst);
            if self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| n.checked_sub(1))
                .is_ok()
            {
                return Err(std::io::Error::other("storage unavailable"));
            }
            Ok(())
        }
    }

    fn flaky(failures: usize) -> Arc<FlakyReload> {
        Arc::new(FlakyReload {
            failures: failures.into(),
            attempts: 0.into(),
        })
    }

    #[test]
    fn activation_is_not_ready_until_a_failed_reload_succeeds() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Active);
        let reload = flaky(2);
        let activation =
            Activation::new(None, None, None).with_reloads([reload.clone() as Arc<dyn mode::ReloadOnPromotion>]);

        run(async {
            let generation = mode::current_activation_generation();
            let pending = tokio::spawn(async move {
                activation
                    .activate(generation, None)
                    .await
            });
            tokio::time::sleep(ACTIVATION_RELOAD_RETRY_FIRST / 2).await;
            assert!(!mode::is_ready_to_serve(), "a failed reload holds readiness back");
            assert!(pending.await.unwrap());
        });

        assert!(mode::is_ready_to_serve());
        assert_eq!(
            reload
                .attempts
                .load(std::sync::atomic::Ordering::SeqCst),
            3
        );
    }

    #[test]
    fn a_demotion_ends_the_reload_retries() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Active);
        let activation =
            Activation::new(None, None, None).with_reloads([flaky(usize::MAX) as Arc<dyn mode::ReloadOnPromotion>]);

        let made_ready = run(async {
            let generation = mode::current_activation_generation();
            let pending = tokio::spawn(async move {
                activation
                    .activate(generation, None)
                    .await
            });
            tokio::time::sleep(ACTIVATION_RELOAD_RETRY_FIRST / 2).await;
            mode::set_server_mode(ServerMode::Standby);
            pending.await.unwrap()
        });

        assert!(!made_ready);
        assert!(!mode::is_ready_to_serve());
        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn superseded_activation_does_not_mark_ready() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Active);
        let superseded = mode::current_activation_generation();
        mode::set_server_mode(ServerMode::Standby);

        assert!(!run(Activation::new(None, None, None).activate(superseded, None)));

        assert!(!mode::is_ready_to_serve());
        assert_eq!(mode::current_mode(), ServerMode::Standby);

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn only_the_latest_of_repeated_promotions_takes_effect() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let activation = Activation::new(None, None, None);
        mode::set_server_mode(ServerMode::Active);
        let first = mode::current_activation_generation();
        mode::set_server_mode(ServerMode::Active);
        let second = mode::current_activation_generation();

        assert!(!run(activation.activate(first, None)), "a repeated SIGUSR1 supersedes the first promotion");
        assert!(!mode::is_ready_to_serve());
        assert!(run(activation.activate(second, None)), "the latest promotion takes effect");
        assert!(mode::is_ready_to_serve());
    }

    /// A listener manager over an empty connection-point store, so activation
    /// toggles its lifecycle without reaching a mediator.
    async fn fabric_listeners(root: &std::path::Path) -> (FabricListeners, tempfile::TempDir) {
        let (vc_issuer, issuer_dir) = crate::identity::test_helpers::test_vc_issuer().await;
        let manager = ListenerManager::new(
            Arc::new(vc_issuer),
            Arc::new(
                crate::gateways::MessageStore::new(root.join("messages"))
                    .await
                    .unwrap(),
            ),
            Arc::new(
                crate::gateways::FileSystemConnectionPointStore::new(root.join("connection_points"))
                    .await
                    .unwrap(),
            ),
            crate::gateways::did_cache::DIDCacheConfig {
                storage_path: root
                    .join("did_cache")
                    .to_string_lossy()
                    .into_owned(),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let bootstrap_config: crate::config::BootstrapConfig =
            toml::from_str("[tls]\ncert_path = \"cert.pem\"\nkey_path = \"key.pem\"\n").unwrap();
        ((Arc::new(manager), Arc::new(bootstrap_config)), issuer_dir)
    }

    /// Waits up to five seconds for the lifecycle task to reach `condition`.
    async fn wait_until(
        what: &str,
        condition: impl Fn() -> bool,
    ) {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        while !condition() {
            assert!(tokio::time::Instant::now() < deadline, "timed out waiting until {what}");
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }
    }

    #[test]
    fn lifecycle_follows_promote_demote_and_re_promote() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Standby);
        let root = tempfile::tempdir().unwrap();

        run(async {
            let (listeners, _issuer_dir) = fabric_listeners(root.path()).await;
            let manager = listeners.0.clone();
            spawn_mode_lifecycle(Activation::new(Some(listeners), None, None));
            tokio::task::yield_now().await;
            assert!(!mode::is_ready_to_serve(), "a standby boot is not ready");
            assert!(!manager.is_active(), "a standby boot does not start listeners");

            mode::set_server_mode(ServerMode::Active);
            wait_until("promotion is ready", mode::is_ready_to_serve).await;
            assert!(manager.is_active(), "promotion activates listeners");

            mode::set_server_mode(ServerMode::Standby);
            wait_until("demotion stops listeners", || !manager.is_active()).await;
            assert!(!mode::is_ready_to_serve(), "a demoted instance is not ready");

            mode::set_server_mode(ServerMode::Active);
            wait_until("re-promotion is ready", mode::is_ready_to_serve).await;
            assert!(manager.is_active(), "re-promotion activates listeners again");
        });

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn demotion_during_a_slow_promotion_stops_listeners_at_once() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Standby);
        let root = tempfile::tempdir().unwrap();

        run(async {
            let (listeners, _issuer_dir) = fabric_listeners(root.path()).await;
            let manager = listeners.0.clone();
            let activation = Activation::new(Some(listeners), None, None);
            // Hold the reload, as slow shared storage would.
            let reload = activation
                .reload_lock
                .clone()
                .lock_owned()
                .await;
            spawn_mode_lifecycle(activation);

            mode::set_server_mode(ServerMode::Active);
            wait_until("promotion arms the listeners", || manager.is_active()).await;
            assert!(!mode::is_ready_to_serve(), "not ready while the reload is running");

            mode::set_server_mode(ServerMode::Standby);
            wait_until("demotion disarms the listeners before the reload ends", || !manager.is_active()).await;

            drop(reload);
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            assert!(!mode::is_ready_to_serve(), "the superseded promotion does not mark ready");
            assert!(!manager.is_active(), "the superseded promotion does not re-arm listeners");

            mode::set_server_mode(ServerMode::Active);
            wait_until("a later promotion is ready", mode::is_ready_to_serve).await;
            assert!(manager.is_active());
        });

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    /// A filesystem secrets store that counts `list_all` calls, the first call
    /// a migration run makes to the store.
    struct CountingSecrets {
        inner: crate::secrets::FilesystemSecretsStore,
        listings: std::sync::atomic::AtomicUsize,
    }

    impl CountingSecrets {
        fn listings(&self) -> usize {
            self.listings
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    #[async_trait::async_trait]
    impl crate::secrets::SecretsStore for CountingSecrets {
        async fn create(
            &self,
            request: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .create(request)
                .await
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<crate::secrets::Secret>> {
            self.inner.get(id).await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.listings
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.list_all().await
        }

        async fn update(
            &self,
            id: &str,
            request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<crate::secrets::Secret> {
            self.inner
                .update(id, request)
                .await
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner.delete(id).await
        }

        async fn find_by_tag(
            &self,
            tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            self.inner
                .find_by_tag(tag)
                .await
        }
    }

    /// Integration storage holding one email integration with an inline
    /// password, a counting secrets store, and the integration.
    async fn inline_mail_integration(
        root: &std::path::Path
    ) -> (Arc<crate::storage::IntegrationStorage>, Arc<CountingSecrets>, crate::storage::Integration) {
        let storage = Arc::new(
            crate::storage::IntegrationStorage::new(root.join("integrations"))
                .await
                .unwrap(),
        );
        let secrets = Arc::new(CountingSecrets {
            inner: crate::secrets::FilesystemSecretsStore::new_async(
                root.join("secrets")
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
            listings: std::sync::atomic::AtomicUsize::new(0),
        });
        let integration = crate::storage::Integration::new(
            "Mail".to_string(),
            String::new(),
            "email".to_string(),
            serde_json::json!({ "smtp_password": "inline-pass" }),
            serde_json::json!({}),
            "active".to_string(),
            None,
        );
        storage
            .save(&integration)
            .await
            .unwrap();
        (storage, secrets, integration)
    }

    async fn configuration_of(
        storage: &crate::storage::IntegrationStorage,
        integration: &crate::storage::Integration,
    ) -> serde_json::Value {
        storage
            .load(&integration.id)
            .await
            .unwrap()
            .configuration
    }

    #[test]
    fn inline_integration_credentials_are_migrated_on_promotion_and_never_in_standby() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Standby);
        let root = tempfile::tempdir().unwrap();

        run(async {
            let (storage, secrets, integration) = inline_mail_integration(root.path()).await;
            spawn_mode_lifecycle(
                Activation::new(None, None, None).with_integrations(Some(storage.clone()), Some(secrets.clone())),
            );
            // On this single-threaded runtime the lifecycle task runs until it
            // waits for the next mode change.
            for _ in 0..10 {
                tokio::task::yield_now().await;
            }

            assert_eq!(secrets.listings(), 0, "a Standby starts no migration");
            assert_eq!(
                configuration_of(&storage, &integration).await,
                serde_json::json!({ "smtp_password": "inline-pass" })
            );

            mode::set_server_mode(ServerMode::Active);
            wait_until("the promotion is ready", mode::is_ready_to_serve).await;
            assert_eq!(secrets.listings(), 1, "only the promotion migrated");
            assert_eq!(
                configuration_of(&storage, &integration).await,
                serde_json::json!({
                    "smtp_password_secret_id": format!("integration-{}-smtp_password", integration.id)
                })
            );
        });

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn inline_integration_credentials_are_migrated_when_starting_active() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Active);
        let root = tempfile::tempdir().unwrap();

        run(async {
            let (storage, secrets, integration) = inline_mail_integration(root.path()).await;
            spawn_mode_lifecycle(
                Activation::new(None, None, None).with_integrations(Some(storage.clone()), Some(secrets.clone())),
            );

            wait_until("startup activation is ready", mode::is_ready_to_serve).await;
            assert_eq!(secrets.listings(), 1);
            assert_eq!(
                configuration_of(&storage, &integration).await,
                serde_json::json!({
                    "smtp_password_secret_id": format!("integration-{}-smtp_password", integration.id)
                })
            );
        });

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }

    #[test]
    fn integration_validation_never_runs_twice_at_once() {
        let root = tempfile::tempdir().unwrap();

        run(async {
            let (storage, secrets, _) = inline_mail_integration(root.path()).await;
            let activation = Activation::new(None, None, None).with_integrations(Some(storage), Some(secrets.clone()));

            activation
                .validating
                .store(true, std::sync::atomic::Ordering::SeqCst);
            assert!(
                activation
                    .start_integration_validation()
                    .is_none(),
                "a run is already going"
            );

            activation
                .validating
                .store(false, std::sync::atomic::Ordering::SeqCst);
            let validation = activation
                .start_integration_validation()
                .expect("no run is going");
            assert!(
                activation
                    .start_integration_validation()
                    .is_none(),
                "the first run is still going"
            );
            validation.await.unwrap();
            assert!(
                !activation
                    .validating
                    .load(std::sync::atomic::Ordering::SeqCst),
                "a finished run lets the next one start"
            );
        });
    }

    #[test]
    fn lifecycle_keeps_following_the_mode_after_missing_changes() {
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        mode::set_server_mode(ServerMode::Standby);

        run(async {
            spawn_mode_lifecycle(Activation::new(None, None, None));
            // More changes than the mode channel holds, before the task runs,
            // so its first receive reports that it lagged.
            for _ in 0..20 {
                mode::set_server_mode(ServerMode::Active);
                mode::set_server_mode(ServerMode::Standby);
            }
            mode::set_server_mode(ServerMode::Active);
            wait_until("the lagged lifecycle activates the current mode", mode::is_ready_to_serve).await;

            mode::set_server_mode(ServerMode::Standby);
            mode::set_server_mode(ServerMode::Active);
            wait_until("a later promotion is still followed", mode::is_ready_to_serve).await;
        });

        mode::set_server_mode(ServerMode::Active);
        assert!(mode::mark_activation_ready(mode::current_activation_generation()));
    }
}
