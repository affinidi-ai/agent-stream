//! API handlers for pipe management

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info, warn};

use crate::api_keys::parent::ApiKeyParents;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::entity_status::EntityStatus;
use crate::identity::handlers::tenant_ownership::TenantOwnershipStores;
use crate::identity::state::IdentityApiState;
use crate::pipes::handlers::LLMHandler;
use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides, VariantResolveError};
use crate::pipes::{PipeConfig, PipeType};
use crate::source_auth::SourceAuthConfig;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

/// Application error type for pipe handlers
#[derive(Debug)]
pub enum AppError {
    NotFound(String),
    InvalidInput(String),
    Forbidden(String),
    Conflict(String),
    InternalError(String),
}

impl From<AppError> for (StatusCode, String) {
    fn from(error: AppError) -> Self {
        match error {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            AppError::InternalError(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        }
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = <(StatusCode, String)>::from(self);
        (status, Json(ErrorResponse { error: message })).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

/// A saved body never moves a surface to another tenant or owner: both stay
/// as stored.
fn keep_stored_ownership(
    pipe: &mut PipeConfig,
    stored: &PipeConfig,
) {
    pipe.tenant_id = stored.tenant_id.clone();
    pipe.owner_user_id = stored.owner_user_id.clone();
}

/// Refuse a change to `pipe` unless the caller is its owner, an
/// administrator or a token of its tenant (see
/// [`super::pipe_caller::PipeCaller::may_manage`]).
async fn ensure_may_manage(
    caller: &super::pipe_caller::PipeCaller,
    pipe: &PipeConfig,
    context: Option<&PatTenantContext>,
) -> Result<(), AppError> {
    if caller
        .may_manage(pipe, context)
        .await?
    {
        return Ok(());
    }
    warn!(
        target: "security_audit",
        event = "surface_ownership_denied",
        actor_id = caller.user_id().unwrap_or_default(),
        pipe_id = %pipe.id,
        "Refused a change to a surface the caller may not manage"
    );
    Err(AppError::Forbidden("Only the surface's owner or an administrator can change or delete it".into()))
}

fn pipe_allowed(
    pipe: &PipeConfig,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_access(pipe.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Pipes, &pipe.id)
}

/// List all pipes
pub async fn list_pipes(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PipeConfig>>, AppError> {
    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    let context_ref = tenant_context(&context);
    let scope_ref = resource_scope(&scope);
    let pipes = pipe_store
        .list()
        .await
        .into_iter()
        .filter(|p| !p.status.is_deleted())
        .filter(|pipe| pipe_allowed(pipe, context_ref, scope_ref))
        .collect::<Vec<_>>();
    debug!("Listed {} pipes", pipes.len());

    Ok(Json(pipes))
}

/// Get a specific pipe by ID
pub async fn get_pipe(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PipeConfig>, AppError> {
    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    let pipe = pipe_store
        .get(&pipe_id)
        .await
        .filter(|pipe| pipe_allowed(pipe, tenant_context(&context), resource_scope(&scope)))
        .ok_or_else(|| AppError::NotFound(format!("Pipe not found: {}", pipe_id)))?;

    Ok(Json(pipe))
}

/// Validate a client-supplied pipe id. The id is used both as the storage
/// filename and as the prefix of every telemetry series key (`surface:{id}`,
/// `surface:{id}:stage:{stage}`, …), so it must be a non-empty token of safe
/// characters only. Rejecting anything outside `[A-Za-z0-9_-]` closes
/// path-traversal through the filesystem store and key-injection / collision
/// with the `:stage:`-style series-key namespacing.
pub(crate) fn validate_pipe_id(id: &str) -> Result<(), AppError> {
    const MAX_SURFACE_ID_LEN: usize = 128;
    if id.is_empty() {
        return Err(AppError::InvalidInput("Pipe id must not be empty".to_string()));
    }
    if id.len() > MAX_SURFACE_ID_LEN {
        return Err(AppError::InvalidInput(format!("Pipe id too long (max {MAX_SURFACE_ID_LEN} characters)")));
    }
    if !id
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        return Err(AppError::InvalidInput("Pipe id may only contain letters, digits, '-' and '_'".to_string()));
    }
    Ok(())
}

/// The permission checks every surface save runs against what is already
/// stored (`previous`, `None` on create): who may set prices, and who may
/// choose where a stored secret is sent. One call per save path, so a new
/// path cannot run one and forget the other.
async fn authorize_save(
    previous: Option<&PipeConfig>,
    pipe: &PipeConfig,
    stores: &super::pipe_tenancy::PipeReferenceStores,
    context: Option<&PatTenantContext>,
    caller: &super::pipe_caller::PipeCaller,
) -> Result<(), AppError> {
    super::pipe_pricing::authorize_price_change(previous, pipe, context, caller).await?;
    super::pipe_secret_bindings::authorize_secret_binding_change(
        previous,
        pipe,
        stores.secrets.as_deref(),
        context,
        caller,
    )
    .await
}

async fn validate_pipe_route_collisions(
    pipe: &PipeConfig,
    pipe_store: &std::sync::Arc<crate::pipes::FileSystemPipeStore>,
    network_config: &crate::config::NetworkConfig,
) -> Result<(), AppError> {
    let existing = pipe_store.list().await;
    crate::pipes::route_manager::check_pipe_route_collisions(pipe, &existing, Some(network_config))
        .map_err(AppError::InvalidInput)
}

/// Validate an IDE Surface's catalog: structural checks (non-blank ids, unique
/// entries), then each member. A member must be a surface the caller may list
/// (see [`may_list_ide_member`]); one that does not exist and one the caller
/// may not list are refused with the same `403`, so a save never reveals
/// whether, or as what, another user's or tenant's surface exists. Only then
/// must it be an LLM Surface with any pinned variant alias. Discovery and
/// dispatch additionally skip a member that becomes invalid at runtime.
async fn validate_ide_catalog(
    ide_pipe_id: &str,
    config: &crate::pipes::catalog::IdeCatalogConfig,
    previous: Option<&PipeConfig>,
    pipe_store: &std::sync::Arc<crate::pipes::FileSystemPipeStore>,
    caller: &super::pipe_caller::PipeCaller,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), AppError> {
    config
        .validate()
        .map_err(|e| AppError::InvalidInput(format!("Invalid IDE catalog: {}", e)))?;
    let listed: Vec<&str> = match previous.map(|previous| &previous.pipe_type) {
        Some(PipeType::IDECatalog { config: stored }) => stored
            .members
            .iter()
            .map(|member| member.pipe_id.as_str())
            .collect(),
        _ => Vec::new(),
    };
    for member in &config.members {
        let member_pipe = pipe_store
            .get(&member.pipe_id)
            .await;
        let may_list = match &member_pipe {
            Some(member_pipe) => {
                listed.contains(&member.pipe_id.as_str())
                    || may_list_ide_member(member_pipe, caller, context, scope).await?
            }
            None => false,
        };
        let Some(member_pipe) = member_pipe.filter(|_| may_list) else {
            warn!(
                target: "security_audit",
                event = "surface_ownership_denied",
                actor_id = caller.user_id().unwrap_or_default(),
                pipe_id = %member.pipe_id,
                ide_pipe_id,
                "Refused an IDE catalog member that does not exist or that the caller may not list"
            );
            return Err(AppError::Forbidden(format!(
                "An IDE catalog may list only surfaces you may change: '{}' does not exist or is not yours",
                member.pipe_id
            )));
        };
        if !matches!(member_pipe.pipe_type, PipeType::LLM { .. }) {
            return Err(AppError::InvalidInput(format!(
                "IDE catalog member '{}' is not an LLM Surface",
                member.pipe_id
            )));
        }
        if let Some(alias) = &member.variant_alias
            && !member_pipe
                .variants
                .iter()
                .any(|v| &v.alias == alias)
        {
            return Err(AppError::InvalidInput(format!(
                "IDE catalog member '{}' has no variant '${}'",
                member.pipe_id, alias
            )));
        }
    }
    Ok(())
}

/// Whether the caller may add `member` to an IDE catalog. Dispatch through an
/// IDE Surface skips each member's own source authentication, so listing a
/// surface opens it to the IDE Surface's callers: only someone who may manage
/// that surface (see [`ensure_may_manage`]) may do that, and a token only
/// within its tenant and resource scope, as on every other surface route.
async fn may_list_ide_member(
    member: &PipeConfig,
    caller: &super::pipe_caller::PipeCaller,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<bool, AppError> {
    Ok(pipe_allowed(member, context, scope)
        && caller
            .may_manage(member, context)
            .await?)
}

/// Run the LLM configuration check on an LLM surface (base and every
/// variant), as every save path must.
fn validate_llm_config(pipe: &PipeConfig) -> Result<(), AppError> {
    if let PipeType::LLM { .. } = &pipe.pipe_type {
        LLMHandler::validate_config(pipe).map_err(|e| {
            error!("❌ LLM validation failed: {}", e);
            AppError::InvalidInput(format!("Invalid LLM configuration: {}", e))
        })?;
    }
    Ok(())
}

/// An IDE Surface evaluates no presentation itself, so VP evidence on it would
/// only look enforced.
fn refuse_ide_vp_evidence(pipe: &PipeConfig) -> Result<(), AppError> {
    if matches!(pipe.pipe_type, PipeType::IDECatalog { .. }) && pipe.vp_evidence().is_some() {
        return Err(AppError::InvalidInput(
            "An IDE Surface does not evaluate VP evidence; enable it on its member LLM Surfaces".to_string(),
        ));
    }
    Ok(())
}

/// Refuse caller authentication that admits no caller, on the base and on
/// every variant: a JWT bearer check with no accepted audience refuses every
/// token.
fn validate_source_auth(pipe: &PipeConfig) -> Result<(), AppError> {
    for view in super::pipe_tenancy::resolved_views(pipe)? {
        if let Some(SourceAuthConfig::JwtBearer(config)) = &view.source_auth
            && !config.accepts_some_audience()
        {
            return Err(AppError::InvalidInput(
                "JWT caller authentication must list at least one accepted audience, or set \
                 allow_missing_audience for an issuer that emits no aud claim; as configured \
                 it refuses every token"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

/// Create a new pipe
pub async fn create_pipe(
    State(state): State<IdentityApiState>,
    Extension(reference_stores): Extension<Arc<super::pipe_tenancy::PipeReferenceStores>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
    Json(mut pipe): Json<PipeConfig>,
) -> Result<Json<PipeConfig>, AppError> {
    info!("📨 Received create_pipe request - Pipe ID: {}, Name: {}", pipe.id, pipe.name);
    validate_pipe_id(&pipe.id)?;
    pipe.tenant_id = tenant_for_create(pipe.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| AppError::Forbidden(message.to_string()))?;
    pipe.owner_user_id = caller
        .user_id()
        .map(str::to_owned);
    if !pipe_allowed(&pipe, tenant_context(&context), resource_scope(&scope)) {
        return Err(AppError::Forbidden(format!("pipe id '{}' is outside this token's permitted namespace", pipe.id)));
    }
    info!(
        "📋 Pipe config: {}",
        serde_json::to_string_pretty(&pipe).unwrap_or_else(|_| "Failed to serialize".to_string())
    );

    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    // Validate the pipe configuration
    validate_llm_config(&pipe)?;
    validate_source_auth(&pipe)?;

    refuse_ide_vp_evidence(&pipe)?;

    // Validate an IDE Surface catalog (structural + member referential checks).
    if let PipeType::IDECatalog { config } = &pipe.pipe_type {
        info!("🔍 Validating IDE Surface catalog...");
        validate_ide_catalog(
            &pipe.id,
            config,
            None,
            pipe_store,
            &caller,
            tenant_context(&context),
            resource_scope(&scope),
        )
        .await?;
        info!("✅ IDE catalog validation passed");
    }

    // Validate the variant catalog (aliases, uniqueness, default reference)
    pipe.validate_variants()
        .map_err(|e| AppError::InvalidInput(format!("Invalid pipe variants: {}", e)))?;

    // Validate team attribution (surface-type agnostic; only the caller-email
    // locator and enforcement flags are checked here).
    if let Some(attr) = &pipe.team_attribution {
        attr.validate()
            .map_err(|e| AppError::InvalidInput(format!("Invalid team attribution: {}", e)))?;
    }

    super::pipe_tenancy::validate_pipe_references(
        &state,
        &reference_stores,
        &pipe,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    authorize_save(None, &pipe, &reference_stores, tenant_context(&context), &caller).await?;

    // Check if pipe already exists
    if pipe_store
        .exists(&pipe.id)
        .await
    {
        return Err(AppError::InvalidInput(format!("Pipe already exists: {}", pipe.id)));
    }

    // Enforce appliance surface limits (per-type plus the total) before persisting.
    let surface_leaf = match &pipe.pipe_type {
        PipeType::LLM { .. } => "surfaces.llm",
        PipeType::IDECatalog { .. } => "surfaces.ide",
        _ => "surfaces",
    };
    crate::config::enforce_add(surface_leaf)
        .await
        .map_err(|e| AppError::Forbidden(e.message()))?;

    validate_pipe_route_collisions(&pipe, pipe_store, &state.network_config).await?;

    // Save the pipe
    info!("💾 Saving pipe to storage...");
    let pipe_id = pipe.id.clone();
    let pipe_name = pipe.name.clone();
    let response = Json(pipe.clone());
    pipe_store
        .save(pipe.clone())
        .await
        .map_err(|e| {
            error!("❌ Failed to save pipe: {}", e);
            AppError::InternalError(format!("Failed to save pipe: {}", e))
        })?;

    // Save pipe integration triggers using IntegrationStorage
    if let Some(integration_storage) = crate::storage::get_integration_storage() {
        if let Err(e) = integration_storage
            .save_pipe_integrations(&pipe_id, &pipe.integrations)
            .await
        {
            warn!("⚠️  Failed to save pipe integration triggers: {}", e);
        } else {
            info!("✅ Saved {} pipe integration triggers", pipe.integrations.len());
        }
    } else {
        warn!("⚠️  Integration storage not available - integrations will not be triggered");
    }

    // Register the route dynamically
    if let Some(route_manager) = &state.pipe_route_manager {
        if let Err(e) = route_manager
            .register_pipe(&pipe)
            .await
        {
            warn!("⚠️  Failed to register pipe route: {}", e);
        } else {
            info!("🔗 Dynamically registered route for new pipe");
        }
    }

    // Start the pipe task (health monitoring, etc.)
    if let Some(pipe_manager) = &state.pipe_task_manager {
        if let Err(e) = pipe_manager
            .start_pipe(&pipe)
            .await
        {
            warn!("⚠️  Failed to start pipe task: {}", e);
        } else {
            info!("🚀 Started pipe task and registered with TaskMonitor");
        }
    }

    // Compile (or clear) the inbound OPA policy for this pipe.
    if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
        .update_pipe_policy(&pipe)
        .await
    {
        warn!("⚠️  Failed to compile OPA policy for pipe '{}': {}", pipe_name, e);
    }

    // Broadcast dashboard refresh to update task list in UI
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    if let Some(store) = &state.notification_store {
        crate::integrations::trigger_pipe_created(store, &pipe).await;
    }

    info!("✅ Created new pipe: {} ({})", pipe_name, pipe_id);

    Ok(response)
}

/// Update an existing pipe
pub async fn update_pipe(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    Extension(reference_stores): Extension<Arc<super::pipe_tenancy::PipeReferenceStores>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
    body: axum::body::Bytes,
) -> Result<Json<PipeConfig>, AppError> {
    let body_str = String::from_utf8(body.to_vec())
        .map_err(|e| AppError::InvalidInput(format!("Invalid UTF-8 in request body: {}", e)))?;

    let mut pipe: PipeConfig = serde_json::from_str(&body_str)
        .map_err(|e| AppError::InvalidInput(format!("Failed to deserialize pipe config: {}", e)))?;

    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    // Ensure the ID matches
    if pipe.id != pipe_id {
        return Err(AppError::InvalidInput("Pipe ID mismatch".to_string()));
    }
    validate_pipe_id(&pipe_id)?;

    let previous_pipe = pipe_store
        .get(&pipe_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Pipe not found: {}", pipe_id)))?;
    if !pipe_allowed(&previous_pipe, tenant_context(&context), resource_scope(&scope)) {
        return Err(AppError::Forbidden("Pipe is outside this token's permitted scope".into()));
    }
    ensure_may_manage(&caller, &previous_pipe, tenant_context(&context)).await?;
    keep_stored_ownership(&mut pipe, &previous_pipe);

    // Validate the pipe configuration
    validate_llm_config(&pipe)?;
    validate_source_auth(&pipe)?;

    refuse_ide_vp_evidence(&pipe)?;

    // Validate an IDE Surface catalog (structural + member referential checks).
    if let PipeType::IDECatalog { config } = &pipe.pipe_type {
        validate_ide_catalog(
            &pipe.id,
            config,
            Some(&previous_pipe),
            pipe_store,
            &caller,
            tenant_context(&context),
            resource_scope(&scope),
        )
        .await?;
    }

    // Validate the variant catalog (aliases, uniqueness, default reference)
    pipe.validate_variants()
        .map_err(|e| AppError::InvalidInput(format!("Invalid pipe variants: {}", e)))?;

    // Validate team attribution (surface-type agnostic).
    if let Some(attr) = &pipe.team_attribution {
        attr.validate()
            .map_err(|e| AppError::InvalidInput(format!("Invalid team attribution: {}", e)))?;
    }

    super::pipe_tenancy::validate_pipe_references(
        &state,
        &reference_stores,
        &pipe,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    authorize_save(Some(&previous_pipe), &pipe, &reference_stores, tenant_context(&context), &caller).await?;

    validate_pipe_route_collisions(&pipe, pipe_store, &state.network_config).await?;

    // Regression gate: when this surface has opted into drift-regression gating
    // and is currently drifting past its pinned baseline, block the save so a
    // config change can't be shipped over an unacknowledged regression. The
    // operator re-pins the baseline or disables gating to proceed (either is a
    // clean save, so this can't deadlock).
    if let Some(drift) = &pipe.drift
        && drift.enabled
        && drift.gate_on_regression
    {
        let status = crate::drift::gating::surface_drift_status(&pipe.id, &drift.thresholds(), 3_600).await;
        if status == crate::drift::DriftStatus::Drift {
            return Err(AppError::Conflict(format!(
                "Save blocked: surface '{}' has regressed past its drift baseline. Re-pin the baseline or disable regression gating to proceed.",
                pipe.name
            )));
        }
    }

    // Capture the prior config so its route can be unregistered before the new
    // one is registered — this prevents a route change or a transition to a
    // non-enabled status from leaving the surface reachable on its old path.
    // Update timestamp
    pipe.updated_at = Some(chrono::Utc::now().to_rfc3339());

    // Save the updated pipe
    pipe_store
        .save(pipe.clone())
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to update surface: {}", e)))?;

    // Save pipe integration triggers using IntegrationStorage
    if let Some(integration_storage) = crate::storage::get_integration_storage() {
        if let Err(e) = integration_storage
            .save_pipe_integrations(&pipe_id, &pipe.integrations)
            .await
        {
            warn!("⚠️  Failed to save pipe integration triggers: {}", e);
        } else {
            info!("✅ Saved {} pipe integration triggers", pipe.integrations.len());
        }
    } else {
        warn!("⚠️  Integration storage not available - integrations will not be triggered");
    }

    // Invalidate global caches to ensure the updated config is used
    crate::pipes::cache::invalidate_pipe_cache(&pipe_id).await;
    info!("🗑️  Invalidated pipe caches for: {}", pipe_id);

    // Recompile (or clear) the inbound OPA policy for the updated config.
    if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
        .update_pipe_policy(&pipe)
        .await
    {
        warn!("⚠️  Failed to recompile OPA policy for pipe '{}': {}", pipe.name, e);
    }

    // Re-register the route dynamically (in case route changed)
    if let Some(route_manager) = &state.pipe_route_manager {
        // Drop the prior route first so a route change or a transition to a
        // non-enabled status cannot leave the surface reachable on its old path.
        // `register_pipe` itself skips registration for a non-enabled pipe.
        let _ = route_manager
            .unregister_pipe(&previous_pipe)
            .await;
        if let Err(e) = route_manager
            .register_pipe(&pipe)
            .await
        {
            warn!("⚠️  Failed to register pipe route: {}", e);
        } else {
            info!("🔗 Dynamically updated route for pipe");
        }
    }

    // Restart the pipe task to pick up changes
    if let Some(pipe_manager) = &state.pipe_task_manager {
        // Stop the old task
        if let Err(e) = pipe_manager
            .stop_pipe(&pipe_id)
            .await
        {
            warn!("⚠️  Failed to stop pipe task during update: {}", e);
        }

        // Start with new configuration (if enabled)
        if pipe.status.is_enabled() {
            if let Err(e) = pipe_manager
                .start_pipe(&pipe)
                .await
            {
                warn!("⚠️  Failed to restart pipe task: {}", e);
            } else {
                info!("🔄 Restarted pipe task with updated configuration");
            }
        } else {
            info!("💤 Pipe disabled - task not restarted");
        }
    }

    // Broadcast dashboard refresh to update task list in UI
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    if let Some(store) = &state.notification_store {
        crate::integrations::trigger_pipe_updated(store, &previous_pipe, &pipe).await;
    }

    info!("Updated pipe: {} ({})", pipe.name, pipe.id);

    Ok(Json(pipe))
}

/// Delete a pipe
pub async fn delete_pipe(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Extension(ownership_stores): Extension<Arc<TenantOwnershipStores>>,
    caller: super::pipe_caller::PipeCaller,
) -> Result<StatusCode, AppError> {
    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    let pipe = pipe_store
        .get(&pipe_id)
        .await
        .ok_or_else(|| AppError::NotFound(format!("Pipe not found: {}", pipe_id)))?;
    if !pipe_allowed(&pipe, tenant_context(&context), resource_scope(&scope)) {
        return Err(AppError::Forbidden("Pipe is outside this token's permitted scope".into()));
    }
    ensure_may_manage(&caller, &pipe, tenant_context(&context)).await?;

    soft_delete_pipe(&state, &ownership_stores, pipe.clone()).await?;

    if let Some(store) = &state.notification_store {
        crate::integrations::trigger_pipe_deleted(store, &pipe).await;
    }

    // Broadcast dashboard refresh to update task list in UI
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    info!("Deleted pipe: {}", pipe_id);

    Ok(StatusCode::NO_CONTENT)
}

/// Tear down every in-memory/runtime artefact for a pipe: stop its task,
/// unregister its route, drop its compiled inbound OPA policy, invalidate the
/// pipe + executor caches, GC its usage + operational telemetry series, and
/// archive its governance log. Shared by the soft-delete (tombstone) and hard-delete (purge) paths so both
/// leave identical runtime state behind.
async fn teardown_pipe_runtime(
    state: &IdentityApiState,
    pipe: &PipeConfig,
) {
    let pipe_id = pipe.id.clone();

    // Stop the pipe task first (unregister from TaskMonitor)
    if let Some(pipe_manager) = &state.pipe_task_manager {
        if let Err(e) = pipe_manager
            .stop_pipe(&pipe_id)
            .await
        {
            warn!("⚠️  Failed to stop pipe task: {}", e);
        } else {
            info!("🛑 Stopped pipe task and unregistered from TaskMonitor");
        }
    }

    // Unregister the route before deleting
    if let Some(route_manager) = &state.pipe_route_manager {
        if let Err(e) = route_manager
            .unregister_pipe(pipe)
            .await
        {
            warn!("⚠️  Failed to unregister pipe route: {}", e);
        } else {
            info!("🗑️  Unregistered route for deleted pipe");
        }
    }

    // Drop any compiled inbound OPA policy for this pipe.
    crate::pipes::PIPE_POLICY_MANAGER.remove_pipe(&pipe_id);

    // Invalidate the in-memory pipe and executor caches so no stale resolved
    // config or executor survives for a deleted surface.
    crate::pipes::cache::invalidate_pipe_cache(&pipe_id).await;

    // Drop the surface's usage time-series (grand total + per-stage) — the
    // surface is gone, its graphs can never accrue again.
    crate::telemetry::remove_surface_series(&pipe_id).await;

    // Drop the surface's operational metrics series (aggregate + per-surface)
    // so the ops store can't grow forever.
    if let Some(ops) = crate::metrics::ops_telemetry::global_ops_store() {
        ops.remove_surface_series(&pipe_id)
            .await;
    }

    // Drop the surface's drift artefacts — dimension series, pinned baseline,
    // captured sessions, and run history — so a deleted surface leaves no
    // orphaned drift state behind.
    if let Some(drift) = crate::drift::global_drift_store() {
        drift
            .remove_surface_series(&pipe_id)
            .await;
    }
    if let Some(baselines) = crate::drift::global_drift_baseline_store() {
        let _ = baselines
            .delete(&pipe_id)
            .await;
    }
    if let Some(sessions) = crate::drift::global_drift_session_store() {
        sessions
            .delete_for_surface(&pipe_id)
            .await;
    }
    if let Some(runs) = crate::drift::global_drift_run_store() {
        runs.delete_for_surface(&pipe_id)
            .await;
    }
    if let Some(eval_state) = crate::drift::global_drift_eval_state_store() {
        let _ = eval_state
            .delete(&pipe_id)
            .await;
    }

    // Archive the surface's governance log under a name no pipe can take, so a
    // surface created later with the same id starts a chain of its own. The
    // archive stays readable to appliance callers and keeps its retention.
    if let Some(governance) = crate::governance::store() {
        match governance
            .archive(&pipe_id)
            .await
        {
            Ok(Some(archive)) => info!(archive = %archive, "Archived the deleted surface's governance records"),
            Ok(None) => {}
            Err(e) => warn!("⚠️  Failed to archive the deleted surface's governance records: {}", e),
        }
    }
}

/// Soft-delete a single pipe: tear down its runtime artefacts, then tombstone it
/// on disk (status = deleted, retained for historical usage attribution). Does
/// **not** broadcast a dashboard refresh — the caller does so once after one or
/// many deletions.
async fn soft_delete_pipe(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    mut pipe: PipeConfig,
) -> Result<(), AppError> {
    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    teardown_pipe_runtime(state, &pipe).await;

    // Soft-delete: tombstone the surface (status = deleted) but keep it on disk
    // so historical usage attribution survives.
    pipe.status = EntityStatus::Deleted;
    let pipe_id = pipe.id.clone();
    pipe_store
        .save(pipe)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to delete pipe: {}", e)))?;

    delete_orphaned_api_keys(state, stores, &pipe_id).await
}

/// Hard-delete a single pipe: tear down its runtime artefacts, then physically
/// remove the record (including any tombstone) from disk. Used only by the
/// debug-/test-mode-only purge endpoint.
async fn hard_delete_pipe(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    pipe: &PipeConfig,
) -> Result<(), AppError> {
    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    teardown_pipe_runtime(state, pipe).await;

    pipe_store
        .delete(&pipe.id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to purge pipe: {}", e)))?;

    delete_orphaned_api_keys(state, stores, &pipe.id).await
}

/// Delete the managed API keys a deleted Surface leaves without a parent, so
/// no Surface whose `api_key_provider` names it keeps admitting them.
async fn delete_orphaned_api_keys(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    pipe_id: &str,
) -> Result<(), AppError> {
    let Some(keys) = &stores.api_keys else {
        return Ok(());
    };
    let deleted = ApiKeyParents::new(stores.agent_surfaces.clone(), state.pipe_store.clone())
        .delete_orphaned_keys(keys.as_ref(), pipe_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to delete the Surface's API keys: {}", e)))?;
    if deleted > 0 {
        info!(pipe_id = %pipe_id, deleted, "Deleted the API keys of a deleted Surface");
    }
    Ok(())
}

/// Response body for the bulk test-surface cleanup endpoint.
#[derive(Debug, Serialize)]
pub struct DeleteTestSurfacesResponse {
    pub deleted: usize,
    pub ids: Vec<String>,
}

/// Bulk-delete every test-fixture surface (`test_surface == true`) in one call.
///
/// Debug-/test-mode only: returns `404` unless the binary is a debug build
/// **and** test-auth is enabled (`AS_TEST_MODE` + `AS_TEST_TOKEN`), so it is
/// invisible in release/production. Lets the testkit clean up surfaces left
/// behind by a crashed run before a fresh run, and tear its own down after.
pub async fn delete_test_surfaces(
    State(state): State<IdentityApiState>,
    Extension(ownership_stores): Extension<Arc<TenantOwnershipStores>>,
) -> Result<Json<DeleteTestSurfacesResponse>, AppError> {
    // Gate: only available in a debug build with test-auth enabled.
    if !crate::auth::test_auth_enabled() {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    let targets = pipe_store
        .list()
        .await
        .into_iter()
        .filter(|p| p.test_surface && !p.status.is_deleted())
        .collect::<Vec<_>>();

    let mut ids = Vec::with_capacity(targets.len());
    for pipe in targets {
        let pipe_id = pipe.id.clone();
        soft_delete_pipe(&state, &ownership_stores, pipe).await?;
        ids.push(pipe_id);
    }

    if !ids.is_empty() {
        state
            .ws_state
            .broadcast(crate::server::WsUpdate::RefreshDashboard);
    }

    info!("Deleted {} test surface(s)", ids.len());

    Ok(Json(DeleteTestSurfacesResponse { deleted: ids.len(), ids }))
}

/// One entity-family result line in the hard-purge response.
#[derive(Debug, Serialize)]
pub struct PurgeCount {
    pub deleted: usize,
    pub ids: Vec<String>,
}

/// Response body for the debug-only hard-purge endpoint.
#[derive(Debug, Serialize)]
pub struct PurgeTestFixturesResponse {
    pub surfaces: PurgeCount,
    pub members: PurgeCount,
    pub teams: PurgeCount,
}

/// Hard-purge every test fixture left behind by the testkit in one call:
/// physically remove (files actually deleted, not tombstoned) every
/// test-fixture surface (`test_surface == true`, including existing
/// tombstones), every non-system test-fixture member (`test_fixture == true`),
/// and every non-system test-fixture team — GC'ing their telemetry series too.
///
/// Debug-/test-mode only: returns `404` unless the binary is a debug build
/// **and** test-auth is enabled (`AS_TEST_MODE` + `AS_TEST_TOKEN`), so it is
/// invisible in release/production. Distinct from `delete_test_surfaces`, which
/// only *soft*-deletes surfaces; this leaves no trace on disk. System records
/// (the built-in anonymous/sandbox member & team) are never touched.
pub async fn purge_test_fixtures(
    State(state): State<IdentityApiState>,
    Extension(ownership_stores): Extension<Arc<TenantOwnershipStores>>,
) -> Result<Json<PurgeTestFixturesResponse>, AppError> {
    // Gate: only available in a debug build with test-auth enabled.
    if !crate::auth::test_auth_enabled() {
        return Err(AppError::NotFound("Not found".to_string()));
    }

    let pipe_store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?;

    // Surfaces: hard-delete every test-fixture surface, tombstoned or not.
    let surface_targets = pipe_store
        .list()
        .await
        .into_iter()
        .filter(|p| p.test_surface)
        .collect::<Vec<_>>();
    let mut surface_ids = Vec::with_capacity(surface_targets.len());
    for pipe in &surface_targets {
        hard_delete_pipe(&state, &ownership_stores, pipe).await?;
        surface_ids.push(pipe.id.clone());
    }

    // Members: hard-delete every non-system test-fixture member.
    let mut member_ids = Vec::new();
    if let Some(member_store) = &state.member_store {
        let targets = member_store
            .list()
            .await
            .into_iter()
            .filter(|m| m.test_fixture && !m.system)
            .collect::<Vec<_>>();
        for member in &targets {
            member_store
                .delete(&member.id)
                .await
                .map_err(|e| AppError::InternalError(format!("Failed to purge member: {}", e)))?;
            crate::telemetry::remove_member_series(&member.id).await;
            member_ids.push(member.id.clone());
        }
    }

    // Teams: hard-delete every non-system test-fixture team.
    let mut team_ids = Vec::new();
    if let Some(team_store) = &state.team_store {
        let targets = team_store
            .list()
            .await
            .into_iter()
            .filter(|t| t.test_fixture && !t.system)
            .collect::<Vec<_>>();
        for team in &targets {
            team_store
                .delete(&team.id)
                .await
                .map_err(|e| AppError::InternalError(format!("Failed to purge team: {}", e)))?;
            crate::telemetry::remove_team_series(&team.id).await;
            team_ids.push(team.id.clone());
        }
    }

    if !surface_ids.is_empty() || !member_ids.is_empty() || !team_ids.is_empty() {
        state
            .ws_state
            .broadcast(crate::server::WsUpdate::RefreshDashboard);
    }

    info!(
        "Purged test fixtures: {} surface(s), {} member(s), {} team(s)",
        surface_ids.len(),
        member_ids.len(),
        team_ids.len()
    );

    Ok(Json(PurgeTestFixturesResponse {
        surfaces: PurgeCount {
            deleted: surface_ids.len(),
            ids: surface_ids,
        },
        members: PurgeCount {
            deleted: member_ids.len(),
            ids: member_ids,
        },
        teams: PurgeCount {
            deleted: team_ids.len(),
            ids: team_ids,
        },
    }))
}

// ---------------------------------------------------------------------------
// Pipe variant administration
//
// A pipe variant is a `$alias`-addressable full snapshot of the pipe.
// These endpoints let the dashboard create/iterate on variants (test
// changes against the same route) and promote one to default — mirroring
// surface variant administration. All mutating endpoints re-validate the
// variant catalog, persist, invalidate runtime caches, and recompile the
// per-variant OPA policies so the running gateway picks up the change.
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateVariantRequest {
    pub alias: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// When set, the new variant seeds its overrides from this existing
    /// variant alias instead of from the current default / empty.
    #[serde(default)]
    pub source_alias: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct UpdateVariantRequest {
    #[serde(default)]
    pub alias: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
    #[serde(default)]
    pub overrides: Option<PipeVariantOverrides>,
}

#[derive(Debug, Serialize)]
pub struct DeleteVariantResponse {
    pub success: bool,
    pub message: String,
}

/// Load a pipe or return 404, also handing back the store for persistence.
pub(super) async fn load_pipe_or_404(
    state: &IdentityApiState,
    pipe_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(std::sync::Arc<crate::pipes::FileSystemPipeStore>, PipeConfig), AppError> {
    let store = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Pipe store not configured".to_string()))?
        .clone();

    let pipe = store
        .get(pipe_id)
        .await
        .filter(|pipe| pipe_allowed(pipe, context, scope))
        .ok_or_else(|| AppError::NotFound(format!("Pipe not found: {}", pipe_id)))?;

    Ok((store, pipe))
}

/// [`load_pipe_or_404`], then refuse a caller who may not change the pipe
/// ([`ensure_may_manage`]).
async fn load_managed_pipe(
    state: &IdentityApiState,
    pipe_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    caller: &super::pipe_caller::PipeCaller,
) -> Result<(std::sync::Arc<crate::pipes::FileSystemPipeStore>, PipeConfig), AppError> {
    let (store, pipe) = load_pipe_or_404(state, pipe_id, context, scope).await?;
    ensure_may_manage(caller, &pipe, context).await?;
    Ok((store, pipe))
}

/// Validate a surface after a variant change as a full save would: the LLM
/// configuration check (which covers every variant's overrides: headers,
/// prices, Judge and Jury targets) and the variant catalog.
fn validate_variant_change(pipe: &PipeConfig) -> Result<(), AppError> {
    validate_llm_config(pipe)?;
    validate_source_auth(pipe)?;
    pipe.validate_variants()
        .map_err(|e| AppError::InvalidInput(format!("Invalid pipe variants: {}", e)))
}

/// Validate the changed surface (see [`validate_variant_change`]), persist,
/// and refresh the runtime so a variant mutation is picked up without a
/// restart: invalidate cached resolved configs/executors and recompile the
/// per-variant OPA policies.
async fn persist_pipe_variant_change(
    state: &IdentityApiState,
    store: &crate::pipes::FileSystemPipeStore,
    mut pipe: PipeConfig,
) -> Result<PipeConfig, AppError> {
    validate_variant_change(&pipe)?;
    pipe.updated_at = Some(chrono::Utc::now().to_rfc3339());

    store
        .save(pipe.clone())
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to save pipe: {}", e)))?;

    crate::pipes::cache::invalidate_pipe_cache(&pipe.id).await;

    if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
        .update_pipe_policy(&pipe)
        .await
    {
        warn!("⚠️  Failed to recompile OPA policy for pipe '{}': {}", pipe.name, e);
    }

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(pipe)
}

/// `POST /v1/pipes/{pipe_id}/variants`
///
/// Create a new variant on the pipe. When `source_alias` is provided the
/// new variant inherits that variant's overrides as a starting point;
/// otherwise it inherits the current default variant's overrides (if any)
/// and falls back to empty.
pub async fn create_variant(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    Extension(reference_stores): Extension<Arc<super::pipe_tenancy::PipeReferenceStores>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
    Json(body): Json<CreateVariantRequest>,
) -> Result<(StatusCode, Json<PipeVariant>), AppError> {
    let (store, mut pipe) =
        load_managed_pipe(&state, &pipe_id, tenant_context(&context), resource_scope(&scope), &caller).await?;
    let stored = pipe.clone();

    if body.name.trim().is_empty() {
        return Err(AppError::InvalidInput("variant name is required".to_string()));
    }
    PipeVariant::validate_alias(&body.alias).map_err(AppError::InvalidInput)?;

    if pipe
        .variants
        .iter()
        .any(|v| v.alias == body.alias)
    {
        return Err(AppError::InvalidInput(format!(
            "variant alias '{}' already exists on pipe '{}'",
            body.alias, pipe_id
        )));
    }

    let seed_overrides = if let Some(ref src) = body.source_alias {
        match pipe
            .variants
            .iter()
            .find(|v| &v.alias == src)
        {
            Some(v) => v.overrides.clone(),
            None => {
                return Err(AppError::InvalidInput(format!(
                    "source_alias '{}' does not match any variant on pipe '{}'",
                    src, pipe_id
                )));
            }
        }
    } else if let Some(ref default_id) = pipe.default_variant_id {
        pipe.variants
            .iter()
            .find(|v| &v.id == default_id)
            .map(|v| v.overrides.clone())
            .unwrap_or_default()
    } else {
        PipeVariantOverrides::default()
    };

    let new_variant = PipeVariant {
        id: uuid::Uuid::new_v4().to_string(),
        alias: body.alias,
        name: body.name,
        description: body.description,
        enabled: true,
        overrides: seed_overrides,
    };

    pipe.variants
        .push(new_variant.clone());

    super::pipe_tenancy::validate_pipe_references(
        &state,
        &reference_stores,
        &pipe,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    authorize_save(Some(&stored), &pipe, &reference_stores, tenant_context(&context), &caller).await?;

    persist_pipe_variant_change(&state, &store, pipe).await?;

    info!("Created variant '{}' (id={}) on pipe '{}'", new_variant.alias, new_variant.id, pipe_id);

    Ok((StatusCode::CREATED, Json(new_variant)))
}

/// `PUT /v1/pipes/{pipe_id}/variants/{variant_id}`
///
/// Patch an existing variant in place. Fields omitted from the body are
/// preserved. Renaming `alias` enforces global uniqueness within the pipe.
pub async fn update_variant(
    State(state): State<IdentityApiState>,
    Path((pipe_id, variant_id)): Path<(String, String)>,
    Extension(reference_stores): Extension<Arc<super::pipe_tenancy::PipeReferenceStores>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
    Json(body): Json<UpdateVariantRequest>,
) -> Result<Json<PipeVariant>, AppError> {
    let (store, mut pipe) =
        load_managed_pipe(&state, &pipe_id, tenant_context(&context), resource_scope(&scope), &caller).await?;
    let stored = pipe.clone();

    if let Some(ref new_alias) = body.alias {
        PipeVariant::validate_alias(new_alias).map_err(AppError::InvalidInput)?;
        if pipe
            .variants
            .iter()
            .any(|v| v.id != variant_id && &v.alias == new_alias)
        {
            return Err(AppError::InvalidInput(format!(
                "variant alias '{}' already in use on pipe '{}'",
                new_alias, pipe_id
            )));
        }
    }

    if let Some(ref new_name) = body.name
        && new_name.trim().is_empty()
    {
        return Err(AppError::InvalidInput("variant name cannot be empty".to_string()));
    }

    let variant = pipe
        .variants
        .iter_mut()
        .find(|v| v.id == variant_id)
        .ok_or_else(|| AppError::NotFound(format!("Variant '{}' not found on pipe '{}'", variant_id, pipe_id)))?;

    if let Some(alias) = body.alias {
        variant.alias = alias;
    }
    if let Some(name) = body.name {
        variant.name = name;
    }
    if let Some(description) = body.description {
        variant.description = description;
    }
    if let Some(enabled) = body.enabled {
        variant.enabled = enabled;
    }
    if let Some(overrides) = body.overrides {
        variant.overrides = overrides;
    }

    let updated = pipe
        .variants
        .iter()
        .find(|v| v.id == variant_id)
        .cloned()
        .ok_or_else(|| AppError::InternalError("Variant disappeared during update".to_string()))?;

    super::pipe_tenancy::validate_pipe_references(
        &state,
        &reference_stores,
        &pipe,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    authorize_save(Some(&stored), &pipe, &reference_stores, tenant_context(&context), &caller).await?;

    persist_pipe_variant_change(&state, &store, pipe).await?;

    info!("Updated variant '{}' (id={}) on pipe '{}'", updated.alias, updated.id, pipe_id);

    Ok(Json(updated))
}

/// `DELETE /v1/pipes/{pipe_id}/variants/{variant_id}`
///
/// Refuses to delete the variant currently pointed at by
/// `default_variant_id`.
pub async fn delete_variant(
    State(state): State<IdentityApiState>,
    Path((pipe_id, variant_id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
) -> Result<Json<DeleteVariantResponse>, AppError> {
    let (store, mut pipe) =
        load_managed_pipe(&state, &pipe_id, tenant_context(&context), resource_scope(&scope), &caller).await?;

    if pipe
        .default_variant_id
        .as_deref()
        == Some(variant_id.as_str())
    {
        return Err(AppError::InvalidInput(
            "cannot delete the default variant; promote another variant to default first".to_string(),
        ));
    }

    let position = pipe
        .variants
        .iter()
        .position(|v| v.id == variant_id)
        .ok_or_else(|| AppError::NotFound(format!("Variant '{}' not found on pipe '{}'", variant_id, pipe_id)))?;

    let removed = pipe.variants.remove(position);

    persist_pipe_variant_change(&state, &store, pipe).await?;

    info!("Deleted variant '{}' (id={}) from pipe '{}'", removed.alias, removed.id, pipe_id);

    Ok(Json(DeleteVariantResponse {
        success: true,
        message: format!("Variant '{}' deleted from pipe '{}'", variant_id, pipe_id),
    }))
}

/// `POST /v1/pipes/{pipe_id}/variants/{variant_id}/promote-to-default`
///
/// Set the pipe's `default_variant_id` to the given variant. The variant
/// must exist and be enabled (a disabled default would be unreachable).
pub async fn promote_variant_to_default(
    State(state): State<IdentityApiState>,
    Path((pipe_id, variant_id)): Path<(String, String)>,
    Extension(reference_stores): Extension<Arc<super::pipe_tenancy::PipeReferenceStores>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    caller: super::pipe_caller::PipeCaller,
) -> Result<Json<PipeConfig>, AppError> {
    let (store, mut pipe) =
        load_managed_pipe(&state, &pipe_id, tenant_context(&context), resource_scope(&scope), &caller).await?;
    let stored = pipe.clone();

    let variant = pipe
        .variants
        .iter()
        .find(|v| v.id == variant_id)
        .ok_or_else(|| AppError::NotFound(format!("Variant '{}' not found on pipe '{}'", variant_id, pipe_id)))?;

    if !variant.enabled {
        return Err(AppError::InvalidInput(format!(
            "variant '{}' is disabled and cannot be promoted to default",
            variant.alias
        )));
    }

    let alias = variant.alias.clone();
    pipe.default_variant_id = Some(variant_id.clone());

    super::pipe_tenancy::validate_pipe_references(
        &state,
        &reference_stores,
        &pipe,
        tenant_context(&context),
        resource_scope(&scope),
    )
    .await?;
    authorize_save(Some(&stored), &pipe, &reference_stores, tenant_context(&context), &caller).await?;

    let pipe = persist_pipe_variant_change(&state, &store, pipe).await?;

    info!("Promoted variant '{}' (id={}) to default on pipe '{}'", alias, variant_id, pipe_id);

    Ok(Json(pipe))
}

/// `GET /v1/pipes/{pipe_id}/variants/{alias}/resolved`
///
/// Return the fully-materialised `PipeConfig` for a single variant.
/// Read-only — never mutates anything. Powers the dashboard's "show
/// effective config" debug pane.
pub async fn get_resolved_variant(
    State(state): State<IdentityApiState>,
    Path((pipe_id, alias)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PipeConfig>, AppError> {
    let (_store, pipe) = load_pipe_or_404(&state, &pipe_id, tenant_context(&context), resource_scope(&scope)).await?;

    let resolved = pipe
        .resolve_variant(Some(&alias))
        .map_err(|e| match e {
            VariantResolveError::UnknownAlias(a) => {
                AppError::NotFound(format!("Variant '{}' not found on pipe '{}'", a, pipe_id))
            }
            VariantResolveError::DisabledVariant(_) | VariantResolveError::MisconfiguredDefault(_) => {
                AppError::InvalidInput(e.to_string())
            }
        })?;

    Ok(Json(resolved))
}

/// `GET /v1/pipes/{pipe_id}/ide-catalog/preview`
///
/// Return the **unfiltered** IDE catalogue an IDE Surface publishes — the exact
/// `/v1/models` wire shape an IDE client (e.g. the VS Code extension) receives,
/// computed from the saved config but WITHOUT the per-caller gates (source auth
/// / OPA / team / model scope). Powers the IDE editor's Sandbox tab so an admin
/// can inspect the published menu and test which member surface a given model
/// string resolves to. Read-only; live discovery filters per caller, so a real
/// caller may receive a subset.
pub async fn preview_ide_catalog(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<crate::pipes::catalog::IdeModelsResponse>, AppError> {
    let (store, pipe) = load_pipe_or_404(&state, &pipe_id, tenant_context(&context), resource_scope(&scope)).await?;
    if !matches!(pipe.pipe_type, PipeType::IDECatalog { .. }) {
        return Err(AppError::InvalidInput(format!("Pipe '{}' is not an IDE surface", pipe_id)));
    }
    let preview = crate::pipes::handlers::http_handlers::build_ide_catalog_preview(store.as_ref(), &pipe).await;
    Ok(Json(preview))
}

/// The admin-facing view of an IDE Surface's public bootstrap document.
#[derive(Debug, Serialize)]
pub struct IdeBootstrapPreview {
    /// Whether the surface actually serves a bootstrap (i.e. client sign-in is
    /// configured). When `false` the live `.well-known` endpoint 404s.
    pub published: bool,
    /// The public path the data plane serves the bootstrap at.
    pub well_known_path: String,
    /// The bootstrap document exactly as published, or `null` when not published.
    pub bootstrap: Option<crate::pipes::catalog::IdeBootstrapResponse>,
}

/// `GET /v1/pipes/{pipe_id}/ide-catalog/bootstrap`
///
/// Return the **public** `.well-known/agent-stream` bootstrap document an IDE
/// Surface publishes — the exact JSON an IDE client (e.g. the VS Code
/// extension) receives from `GET {route}/.well-known/agent-stream`, computed
/// from the saved config. Powers the IDE editor's Sandbox tab so an admin can
/// inspect the central sign-in identifiers and discovery/dispatch paths without
/// hitting the live route. When the surface has no client sign-in configured the
/// live endpoint 404s, so `published` is `false` and `bootstrap` is `null`.
pub async fn preview_ide_bootstrap(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<IdeBootstrapPreview>, AppError> {
    let (_store, pipe) = load_pipe_or_404(&state, &pipe_id, tenant_context(&context), resource_scope(&scope)).await?;
    let config = match &pipe.pipe_type {
        PipeType::IDECatalog { config } => config,
        _ => return Err(AppError::InvalidInput(format!("Pipe '{}' is not an IDE surface", pipe_id))),
    };
    let route = pipe
        .route
        .clone()
        .unwrap_or_default();
    let bootstrap = match config.client_auth.clone() {
        Some(auth) => {
            // Resolve any referenced OAuth Identifier profile so the preview
            // shows exactly what the live bootstrap publishes.
            let auth = crate::pipes::catalog::resolve_client_auth(auth).await;
            let upstreams = crate::pipes::catalog::resolve_upstreams(config.synthesized_upstreams()).await;
            Some(crate::pipes::catalog::IdeBootstrapResponse::for_client_and_upstreams(auth, upstreams))
        }
        None => None,
    };
    Ok(Json(IdeBootstrapPreview {
        published: bootstrap.is_some(),
        well_known_path: format!("{}/.well-known/agent-stream", route),
        bootstrap,
    }))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestPipeRequest {
    #[allow(dead_code)]
    pub test_message: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TestLLMConnectionRequest {
    pub provider: String,
    pub endpoint: String,
    pub secret_id: Option<String>,
    pub azure_api_version: Option<String>,
    pub region: Option<String>,
}

/// Test an LLM connection before creating the pipe
pub async fn test_llm_connection(
    Extension(actor_id): Extension<String>,
    Json(test_req): Json<TestLLMConnectionRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    if test_req
        .secret_id
        .as_deref()
        .is_some_and(|secret_id| !secret_id.trim().is_empty())
    {
        warn!(
            target: "security_audit",
            event = "llm_connection_test",
            actor_id = %actor_id,
            mode = "pre_save",
            outcome = "rejected_unbound_secret",
            "Rejected LLM connection test with an unbound stored-secret reference"
        );
        return Err(AppError::InvalidInput(
            "Pre-save connection tests cannot use stored secrets; save the LLM Surface and test its bound provider configuration"
                .to_string(),
        ));
    }

    let safe_endpoint = crate::url_validation::redact_url_for_logging(&test_req.endpoint);
    info!(
        target: "security_audit",
        event = "llm_connection_test",
        actor_id = %actor_id,
        mode = "pre_save",
        provider = %test_req.provider,
        endpoint = %safe_endpoint,
        "Testing credential-free LLM connection"
    );

    // SSRF guard: a full-URL endpoint is attacker-supplied and is dialed
    // directly, so reject cloud-metadata targets (including DNS-rebinding to a
    // metadata IP) and non-http(s) schemes before any request is made. A
    // path-style endpoint is ignored here — the request falls back to the
    // trusted provider default base URL.
    if test_req
        .endpoint
        .starts_with("http")
        && let Err(reason) = crate::url_validation::validate_resolved_webhook_url(&test_req.endpoint).await
    {
        warn!("Blocked LLM connection test to unsafe endpoint '{}': {}", safe_endpoint, reason);
        return Ok(Json(serde_json::json!({
            "status": "error",
            "message": format!("Endpoint rejected: {}", reason),
            "provider": test_req.provider,
        })));
    }

    // Credential-free pre-save tests remain available for providers such as
    // Ollama. Credentialed tests use the saved Surface endpoint, which loads
    // only the secret reference persisted with that Surface.
    let api_key = String::new();

    // Build metadata map
    let mut metadata = serde_json::Map::new();
    if let Some(version) = test_req.azure_api_version {
        metadata.insert("azureApiVersion".to_string(), serde_json::Value::String(version));
    }
    if let Some(region) = test_req.region {
        metadata.insert("region".to_string(), serde_json::Value::String(region));
    }

    // Test the connection
    match test_llm_provider(&test_req.provider, &test_req.endpoint, &api_key, &metadata).await {
        Ok(message) => {
            info!(
                target: "security_audit",
                event = "llm_connection_test",
                actor_id = %actor_id,
                mode = "pre_save",
                outcome = "succeeded",
                "LLM connection test succeeded"
            );
            Ok(Json(serde_json::json!({
                "status": "success",
                "message": message,
                "provider": test_req.provider,
            })))
        }
        Err(err) => {
            warn!(
                target: "security_audit",
                event = "llm_connection_test",
                actor_id = %actor_id,
                mode = "pre_save",
                outcome = "failed",
                reason = %err,
                "LLM connection test failed"
            );
            Ok(Json(serde_json::json!({
                "status": "error",
                "message": err,
                "provider": test_req.provider,
            })))
        }
    }
}

/// Test a pipe connection by making an actual API call to the LLM provider
pub async fn test_pipe(
    State(state): State<IdentityApiState>,
    Extension(actor_id): Extension<String>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(_test_req): Json<TestPipeRequest>,
) -> Result<Json<serde_json::Value>, AppError> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;

    let (_pipe_store, pipe) =
        load_pipe_or_404(&state, &pipe_id, tenant_context(&context), resource_scope(&scope)).await?;

    if !pipe.status.is_enabled() {
        return Err(AppError::InvalidInput("Pipe is disabled".to_string()));
    }

    // Only test LLM pipes
    let provider_info = match &pipe.pipe_type {
        crate::pipes::config::PipeType::LLM { provider, .. } => provider,
        _ => {
            return Err(AppError::InvalidInput("Only LLM pipes can be tested".to_string()));
        }
    };

    // Extract provider details from LLMProvider using trait methods
    let provider_type = provider_info.provider_type_str();
    let endpoint = provider_info.get_endpoint();
    let secret_id = provider_info
        .get_api_key()
        .ok_or_else(|| AppError::InvalidInput("API key secret not configured".to_string()))?;

    // Build metadata from provider config for version/api_version info
    let mut metadata = serde_json::Map::new();
    if let crate::pipes::types::llm::LLMProvider::Anthropic { version: Some(ver), .. } = &**provider_info {
        metadata.insert("anthropicVersion".to_string(), serde_json::Value::String(ver.clone()));
    }
    if let crate::pipes::types::llm::LLMProvider::AzureOpenAI { api_version, .. } = &**provider_info {
        metadata.insert("azureApiVersion".to_string(), serde_json::Value::String(api_version.clone()));
    }

    // Load the secret from filesystem
    let secret_store = crate::secrets::FilesystemSecretsStore::new(
        &state
            .bootstrap_config
            .storage_paths
            .secrets,
    )
    .map_err(|e| AppError::InternalError(format!("Failed to initialize secrets store: {}", e)))?;

    // The resolution a request uses (internal id, then public id), re-checked
    // against the surface's tenant, so the test sends the key a call would. A
    // reference to a deleted secret is the surface's configuration, not a
    // server fault, so it is refused like a surface with no key.
    let secret = crate::secrets::SurfaceSecrets::new(Some(Arc::new(secret_store)), pipe.tenant_id.clone())
        .resolve(secret_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to retrieve API key: {}", e)))?
        .ok_or_else(|| AppError::InvalidInput("API key secret not found".to_string()))?;

    let safe_endpoint = crate::url_validation::redact_url_for_logging(&endpoint);
    info!(
        target: "security_audit",
        event = "llm_connection_test",
        actor_id = %actor_id,
        mode = "saved",
        pipe_id = %pipe_id,
        provider = %provider_type,
        endpoint = %safe_endpoint,
        secret_reference_id = %secret_id,
        "Testing saved LLM Surface provider binding"
    );

    // Test the connection
    match test_llm_provider(provider_type, &endpoint, &secret.value, &metadata).await {
        Ok(message) => {
            info!(
                target: "security_audit",
                event = "llm_connection_test",
                actor_id = %actor_id,
                mode = "saved",
                pipe_id = %pipe_id,
                outcome = "succeeded",
                "Saved LLM Surface connection test succeeded"
            );
            Ok(Json(serde_json::json!({
                "status": "success",
                "message": message,
                "provider": provider_type,
                "pipe_id": pipe_id,
            })))
        }
        Err(err) => {
            warn!(
                target: "security_audit",
                event = "llm_connection_test",
                actor_id = %actor_id,
                mode = "saved",
                pipe_id = %pipe_id,
                outcome = "failed",
                reason = %err,
                "Saved LLM Surface connection test failed"
            );
            Ok(Json(serde_json::json!({
                "status": "error",
                "message": err,
                "provider": provider_type,
                "pipe_id": pipe_id,
            })))
        }
    }
}

/// Test connection to an LLM provider with actual API call
pub async fn test_llm_provider(
    provider: &str,
    endpoint: &str,
    api_key: &str,
    metadata: &serde_json::Map<String, serde_json::Value>,
) -> Result<String, String> {
    use crate::pipes::defaults;

    let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
        defaults::HEALTH_CHECK_TIMEOUT_SECS,
    ))
    .map_err(|e| format!("Failed to create HTTP client: {}", e))?;

    // Resolve base URL: if the endpoint is a full URL, extract its base;
    // otherwise it is just a path from the config — fall back to the provider default.
    let resolve_base = |default: &str| -> String {
        if endpoint.starts_with("http") {
            // Full URL — strip /v1/ or /v1beta/ suffix to get the origin
            endpoint
                .split("/v1")
                .next()
                .unwrap_or(endpoint)
                .to_string()
        } else {
            default.to_string()
        }
    };

    match provider {
        // OpenAI-compatible providers: GET /v1/models with Bearer token
        "openai" | "mistral" | "togetherai" | "cohere" | "ollama" => {
            let default_base = match provider {
                "mistral" => defaults::DEFAULT_MISTRAL_BASE_URL,
                "togetherai" => defaults::DEFAULT_TOGETHERAI_BASE_URL,
                "cohere" => defaults::DEFAULT_COHERE_BASE_URL,
                "ollama" => defaults::DEFAULT_OLLAMA_BASE_URL,
                _ => defaults::DEFAULT_OPENAI_BASE_URL,
            };
            let base_url = resolve_base(default_base);
            let test_url = format!("{}/v1/models", base_url);
            crate::url_validation::validate_strict_service_endpoint_url(&test_url)
                .await
                .map_err(|e| format!("Endpoint rejected: {}", e))?;
            let response = client
                .get(&test_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            if response.status().is_success() {
                Ok(format!("Successfully authenticated with {} API", provider))
            } else {
                Err(format!("{} API returned HTTP {}", provider, response.status()))
            }
        }

        // Bedrock Gateway: GET /v1/models with Bearer token; region-aware base URL
        "bedrock" => {
            // Compute the region-derived default URL, then let resolve_base override it
            // with the extracted origin when a full HTTP endpoint was supplied.
            let region = metadata
                .get("region")
                .and_then(|v| v.as_str())
                .unwrap_or(defaults::DEFAULT_BEDROCK_REGION);
            let region_url = defaults::bedrock_gateway_url(region);
            let base_url = resolve_base(&region_url);
            let test_url = format!("{}/v1/models", base_url);
            crate::url_validation::validate_strict_service_endpoint_url(&test_url)
                .await
                .map_err(|e| format!("Endpoint rejected: {}", e))?;
            let response = client
                .get(&test_url)
                .header("Authorization", format!("Bearer {}", api_key))
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            if response.status().is_success() {
                Ok("Successfully authenticated with Bedrock Gateway API".to_string())
            } else {
                Err(format!("Bedrock Gateway API returned HTTP {}", response.status()))
            }
        }

        // Anthropic: GET /v1/models with x-api-key + anthropic-version
        "anthropic" => {
            let version = metadata
                .get("anthropicVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(defaults::DEFAULT_ANTHROPIC_VERSION);

            let base_url = resolve_base("https://api.anthropic.com");
            let test_url = format!("{}/v1/models", base_url);
            crate::url_validation::validate_strict_service_endpoint_url(&test_url)
                .await
                .map_err(|e| format!("Endpoint rejected: {}", e))?;
            let response = client
                .get(&test_url)
                .header("x-api-key", api_key)
                .header("anthropic-version", version)
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            if response.status().is_success() {
                Ok("Successfully authenticated with Anthropic API".to_string())
            } else {
                Err(format!("Anthropic API returned HTTP {}", response.status()))
            }
        }

        // Azure OpenAI: GET /openai/deployments with api-key header
        "azure" => {
            let api_version = metadata
                .get("azureApiVersion")
                .and_then(|v| v.as_str())
                .unwrap_or(defaults::DEFAULT_AZURE_API_VERSION);

            let azure_base = if endpoint.starts_with("http") {
                endpoint
                    .split("/openai/")
                    .next()
                    .unwrap_or(endpoint)
                    .to_string()
            } else {
                // Azure always requires a user-supplied endpoint URL
                return Err("Azure OpenAI requires a full endpoint URL".to_string());
            };
            let test_url = format!("{}/openai/deployments?api-version={}", azure_base, api_version);
            crate::url_validation::validate_strict_service_endpoint_url(&test_url)
                .await
                .map_err(|e| format!("Endpoint rejected: {}", e))?;

            let response = client
                .get(&test_url)
                .header("api-key", api_key)
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            if response.status().is_success() {
                Ok("Successfully authenticated with Azure OpenAI API".to_string())
            } else {
                Err(format!("Azure OpenAI API returned HTTP {}", response.status()))
            }
        }

        // Gemini: GET /v1beta/models with x-goog-api-key header
        "gemini" => {
            let base_url = resolve_base(defaults::DEFAULT_GEMINI_BASE_URL);
            let test_url = format!("{}/v1beta/models", base_url);
            crate::url_validation::validate_strict_service_endpoint_url(&test_url)
                .await
                .map_err(|e| format!("Endpoint rejected: {}", e))?;
            let response = client
                .get(&test_url)
                .header("x-goog-api-key", api_key)
                .send()
                .await
                .map_err(|e| format!("Network error: {}", e))?;

            if response.status().is_success() {
                Ok("Successfully authenticated with Google Gemini API".to_string())
            } else {
                Err(format!("Google Gemini API returned HTTP {}", response.status()))
            }
        }

        _ => Err(format!("Unsupported provider: {}", provider)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_pipe_ids_accepted() {
        for id in ["pipe1", "my-pipe_2", "ABC-123", "a"] {
            assert!(validate_pipe_id(id).is_ok(), "expected {id} to be valid");
        }
    }

    #[test]
    fn pipe_id_rejects_empty() {
        assert!(matches!(validate_pipe_id(""), Err(AppError::InvalidInput(_))));
    }

    #[test]
    fn pipe_id_rejects_traversal_and_separators() {
        // Path-traversal and filesystem separators must never reach the store.
        for id in ["../../etc/passwd", "a/b", "a\\b", ".."] {
            assert!(matches!(validate_pipe_id(id), Err(AppError::InvalidInput(_))), "expected {id} to be rejected");
        }
    }

    #[test]
    fn pipe_id_rejects_series_key_injection() {
        // A colon would collide with the `surface:{id}:stage:{stage}` series-key
        // namespacing; spaces and other punctuation are likewise rejected.
        for id in ["surface:all", "a:stage:llm", "with space", "tab\tchar"] {
            assert!(matches!(validate_pipe_id(id), Err(AppError::InvalidInput(_))), "expected {id} to be rejected");
        }
    }

    #[test]
    fn pipe_id_rejects_overlong() {
        let long = "a".repeat(129);
        assert!(matches!(validate_pipe_id(&long), Err(AppError::InvalidInput(_))));
    }

    #[test]
    fn canonical_pipe_access_combines_tenant_kind_and_id() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope =
            PatResourceScope(std::sync::Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:pipes:pipe-1\z").unwrap()));
        let mut pipe = PipeConfig::new(
            "pipe-1".into(),
            "Pipe 1".into(),
            PipeType::Webhook {
                endpoint: "https://example.com".into(),
            },
        );

        pipe.tenant_id = Some("tenant-a".into());
        assert!(pipe_allowed(&pipe, Some(&context), Some(&scope)));

        pipe.tenant_id = None;
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!pipe_allowed(&pipe, Some(&context), Some(&scope)));

        pipe.tenant_id = Some("tenant-b".into());
        assert!(!pipe_allowed(&pipe, Some(&context), Some(&scope)));

        let wrong_kind =
            PatResourceScope(std::sync::Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:prompts:pipe-1\z").unwrap()));
        pipe.tenant_id = Some("tenant-a".into());
        assert!(!pipe_allowed(&pipe, Some(&context), Some(&wrong_kind)));
    }

    fn webhook(id: &str) -> PipeConfig {
        PipeConfig::new(
            id.into(),
            id.into(),
            PipeType::Webhook {
                endpoint: "https://example.com".into(),
            },
        )
    }

    #[tokio::test]
    async fn changing_another_users_surface_is_forbidden() {
        let mut alices = webhook("pipe-1");
        alices.owner_user_id = Some("alice".into());
        let (alice, _a) =
            super::super::pipe_caller::PipeCaller::for_test("alice", crate::auth::types::UserRole::User, None).await;
        let (bob, _b) =
            super::super::pipe_caller::PipeCaller::for_test("bob", crate::auth::types::UserRole::User, None).await;

        assert!(
            ensure_may_manage(&alice, &alices, None)
                .await
                .is_ok()
        );
        assert!(matches!(ensure_may_manage(&bob, &alices, None).await, Err(AppError::Forbidden(_))));
    }

    #[test]
    fn a_saved_body_keeps_the_stored_tenant_and_owner() {
        let mut stored = webhook("pipe-1");
        stored.tenant_id = Some("tenant-a".into());
        stored.owner_user_id = Some("alice".into());

        let mut takeover = webhook("pipe-1");
        takeover.tenant_id = Some("tenant-b".into());
        takeover.owner_user_id = Some("bob".into());
        keep_stored_ownership(&mut takeover, &stored);
        assert_eq!(takeover.tenant_id.as_deref(), Some("tenant-a"));
        assert_eq!(
            takeover
                .owner_user_id
                .as_deref(),
            Some("alice")
        );

        let mut cleared = webhook("pipe-1");
        keep_stored_ownership(&mut cleared, &stored);
        assert_eq!(
            cleared
                .owner_user_id
                .as_deref(),
            Some("alice")
        );
    }
}

#[cfg(test)]
mod variant_change_tests {
    use super::*;
    use crate::pipes::test_upstreams::CaptureUpstream;
    use crate::pipes::types::llm::{LLMProvider, TargetPricing};
    use crate::secrets::store::memory::{MemorySecretsStore, secret};
    use crate::url_validation::test_service_endpoints;

    /// An OpenAI surface on the operator's provider key, its upstream at `url`.
    fn operator_key_surface(url: &str) -> PipeConfig {
        PipeConfig::new(
            "pipe-variants".to_string(),
            "Variants".to_string(),
            PipeType::LLM {
                provider: Box::new(LLMProvider::OpenAI {
                    provider_type: "openai".to_string(),
                    model: "gpt-4o".to_string(),
                    api_key_secret: Some("openai_api_key".to_string()),
                    organization_id: None,
                    base_url: Some(url.to_string()),
                    temperature: None,
                    max_tokens: None,
                    top_p: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                }),
                endpoint_path: None,
            },
        )
    }

    fn variant(overrides: PipeVariantOverrides) -> PipeVariant {
        PipeVariant {
            id: "variant-1".to_string(),
            alias: "cheap".to_string(),
            name: "Cheap".to_string(),
            description: String::new(),
            enabled: true,
            overrides,
        }
    }

    #[test]
    fn a_negative_price_in_a_variant_api_body_does_not_parse() {
        let body = serde_json::from_value::<UpdateVariantRequest>(serde_json::json!({
            "overrides": { "upstream_pricing": { "input_per_million": -1000000.0, "output_per_million": -1000000.0 } }
        }));
        assert!(body.is_err(), "the variant API accepted a negative price");

        let body = serde_json::from_value::<UpdateVariantRequest>(serde_json::json!({
            "overrides": { "upstream_pricing": { "input_per_million": 0.0, "output_per_million": 0.0 } }
        }));
        assert!(body.is_ok(), "precondition: a zero price parses");
    }

    #[test]
    fn a_variant_change_runs_the_full_configuration_check() {
        let reserved = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "Authorization".to_string(),
            secret_id: "tunnel-key".to_string(),
        }];
        let judge_with_reserved_header: crate::pipes::judge_jury::JudgeConfig =
            serde_json::from_value(serde_json::json!({
                "llm": {
                    "provider_type": "openai",
                    "model": "judge",
                    "endpoint_url": "https://198.51.100.7/v1/chat/completions",
                    "headers": [{ "name": "x-agent-stream-trace", "secret_id": "tunnel-key" }]
                }
            }))
            .unwrap();
        let cases = [
            (
                "a reserved upstream header",
                PipeVariantOverrides {
                    upstream_headers: Some(reserved),
                    ..Default::default()
                },
            ),
            (
                "a reserved Judge header",
                PipeVariantOverrides {
                    judge: Some(judge_with_reserved_header),
                    ..Default::default()
                },
            ),
        ];
        for (label, overrides) in cases {
            let mut pipe = operator_key_surface("https://198.51.100.7/v1/chat/completions");
            pipe.variants = vec![variant(overrides)];
            assert!(
                pipe.validate_variants()
                    .is_ok(),
                "precondition: the catalog check alone accepts {label}"
            );
            assert!(
                matches!(validate_variant_change(&pipe), Err(AppError::InvalidInput(message)) if message.contains("reserved")),
                "a variant change saved {label}"
            );
        }

        let mut clean = operator_key_surface("https://198.51.100.7/v1/chat/completions");
        clean.variants = vec![variant(PipeVariantOverrides {
            request_timeout_seconds: Some(60),
            ..Default::default()
        })];
        validate_variant_change(&clean).expect("a valid variant change saves");
    }

    #[tokio::test]
    async fn a_price_saved_through_the_variant_api_never_bills_below_zero() {
        // No request body can carry a negative price any more; one built in
        // code still bills zero, never a credit against a budget.
        let upstream = CaptureUpstream::answering("an answer").await;
        let _allowed = test_service_endpoints::allow(std::slice::from_ref(&upstream.url));
        let mut pipe = operator_key_surface(&upstream.url);
        pipe.variants = vec![variant(PipeVariantOverrides {
            upstream_pricing: Some(TargetPricing {
                input_per_million: -1_000_000.0,
                output_per_million: -1_000_000.0,
            }),
            ..Default::default()
        })];
        assert!(
            matches!(validate_variant_change(&pipe), Err(AppError::InvalidInput(message)) if message.contains("pricing")),
            "precondition: no save path accepts it"
        );

        let resolved = pipe
            .resolve_variant(Some("cheap"))
            .expect("resolves");
        let store: Arc<dyn crate::secrets::SecretsStore> =
            Arc::new(MemorySecretsStore::with(vec![secret("uuid-op", "openai_api_key", "OPERATOR", None)]));
        let (_, metrics) = crate::pipes::executor::PipeExecutor::new_with_secrets(&resolved, Some(store))
            .execute(serde_json::json!({ "messages": [{ "role": "user", "content": "hi" }] }), None, None, None, None)
            .await
            .expect("answers");

        assert_eq!(upstream.requests(), 1, "precondition: the upstream was called");
        assert_eq!(metrics.cost, 0.0, "one request was billed {} USD", metrics.cost);
    }
}

#[cfg(test)]
mod ide_catalog_validation_tests {
    use super::*;
    use crate::pipes::FileSystemPipeStore;
    use crate::pipes::catalog::{IdeCatalogConfig, IdeCatalogMember};
    use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides};
    use crate::pipes::types::llm::LLMProvider;
    use std::sync::Arc;

    fn llm_pipe(id: &str) -> PipeConfig {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key_secret: Some("sk".to_string()),
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        PipeConfig::new(
            id.to_string(),
            id.to_string(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        )
    }

    fn llm_pipe_with_variant(
        id: &str,
        alias: &str,
    ) -> PipeConfig {
        let mut pipe = llm_pipe(id);
        pipe.variants = vec![PipeVariant {
            id: format!("{id}-{alias}"),
            alias: alias.to_string(),
            name: format!("Variant {alias}"),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides::default(),
        }];
        pipe
    }

    fn member(
        pipe_id: &str,
        alias: Option<&str>,
    ) -> IdeCatalogMember {
        IdeCatalogMember {
            pipe_id: pipe_id.to_string(),
            variant_alias: alias.map(|a| a.to_string()),
            mnemonic: None,
            display_name: None,
            group: None,
            order: 0,
            default: false,
            expose: true,
            metadata: None,
            upstream_oauth_identifier_id: None,
            opa_policy_id: None,
            node_id: None,
        }
    }

    async fn store_with(pipes: Vec<PipeConfig>) -> (Arc<FileSystemPipeStore>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap();
        for p in pipes {
            store.save(p).await.unwrap();
        }
        (Arc::new(store), dir)
    }

    /// Validate `config` as a new IDE Surface `front`, saved by `caller`
    /// through an access token narrowed to `context` and `scope`, if any.
    async fn validate_as(
        config: &IdeCatalogConfig,
        store: &Arc<FileSystemPipeStore>,
        caller: &crate::identity::handlers::pipe_caller::PipeCaller,
        context: Option<&PatTenantContext>,
        scope: Option<&PatResourceScope>,
    ) -> Result<(), AppError> {
        validate_ide_catalog("front", config, None, store, caller, context, scope).await
    }

    /// Validate `config` with no authenticated caller, where every surface may
    /// be listed, so only the catalogue's own checks apply.
    async fn validate(
        config: &IdeCatalogConfig,
        store: &Arc<FileSystemPipeStore>,
    ) -> Result<(), AppError> {
        validate_as(config, store, &crate::identity::handlers::pipe_caller::PipeCaller::default(), None, None).await
    }

    fn catalog(members: Vec<IdeCatalogMember>) -> IdeCatalogConfig {
        IdeCatalogConfig { members, client_auth: None }
    }

    #[tokio::test]
    async fn accepts_existing_llm_member_base_and_variant() {
        let (store, _dir) = store_with(vec![llm_pipe("gpt4o"), llm_pipe_with_variant("claude", "reasoning")]).await;
        let config = catalog(vec![member("gpt4o", None), member("claude", Some("reasoning"))]);
        assert!(
            validate(&config, &store)
                .await
                .is_ok()
        );
    }

    #[test]
    fn vp_evidence_is_refused_on_an_ide_surface_only() {
        let evidence = crate::pipes::config::VpEvidenceConfig {
            enabled: true,
            ..Default::default()
        };
        let (_, mut ide) = ide_surface(Vec::new());
        let mut llm = llm_pipe("member");
        ide.vp_evidence = Some(evidence.clone());
        llm.vp_evidence = Some(evidence);

        let refused = refuse_ide_vp_evidence(&ide);

        assert!(matches!(refused, Err(AppError::InvalidInput(message)) if message.contains("member LLM Surfaces")));
        assert!(refuse_ide_vp_evidence(&llm).is_ok());
        ide.vp_evidence = None;
        assert!(refuse_ide_vp_evidence(&ide).is_ok());
    }

    fn owned_llm_pipe(
        id: &str,
        owner: Option<&str>,
    ) -> PipeConfig {
        let mut pipe = llm_pipe(id);
        pipe.owner_user_id = owner.map(str::to_owned);
        pipe
    }

    fn ide_surface(members: Vec<IdeCatalogMember>) -> (IdeCatalogConfig, PipeConfig) {
        let config = catalog(members);
        let surface =
            PipeConfig::new("front".to_string(), "front".to_string(), PipeType::IDECatalog { config: config.clone() });
        (config, surface)
    }

    #[tokio::test]
    async fn an_ide_catalog_may_not_list_another_users_surface() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let (store, _dir) =
            store_with(vec![owned_llm_pipe("bobs", Some("bob")), owned_llm_pipe("alices", Some("alice"))]).await;
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;

        validate_as(&catalog(vec![member("bobs", None)]), &store, &bob, None, None)
            .await
            .expect("a user lists their own surface");

        let foreign = catalog(vec![member("bobs", None), member("alices", None)]);
        assert!(
            matches!(
                validate_as(&foreign, &store, &bob, None, None).await,
                Err(AppError::Forbidden(message)) if message.contains("alices")
            ),
            "a base user listed another user's surface"
        );

        let (admin, _admins) = PipeCaller::for_test("root", UserRole::Administrator, None).await;
        validate_as(&foreign, &store, &admin, None, None)
            .await
            .expect("an administrator lists any surface");
    }

    /// Every way a member can fail for a surface the caller may not list —
    /// absent, another user's LLM Surface, another user's non-LLM surface, and
    /// another user's LLM Surface with a missing variant — answers the same
    /// error, so a save reveals nothing about surfaces the caller cannot see.
    #[tokio::test]
    async fn a_surface_the_caller_may_not_list_is_indistinguishable_from_a_missing_one() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let mut alices_ide = PipeConfig::new(
            "alices-ide".to_string(),
            "alices-ide".to_string(),
            PipeType::IDECatalog {
                config: IdeCatalogConfig::default(),
            },
        );
        alices_ide.owner_user_id = Some("alice".into());
        let (store, _dir) = store_with(vec![owned_llm_pipe("alices", Some("alice")), alices_ide]).await;
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;

        let mut outcomes = Vec::new();
        for (id, alias) in [("ghost", None), ("alices", None), ("alices-ide", None), ("alices", Some("ghostv"))] {
            let refused = validate_as(&catalog(vec![member(id, alias)]), &store, &bob, None, None).await;
            let Err(AppError::Forbidden(message)) = refused else {
                panic!("{id}: expected Forbidden, got {refused:?}");
            };
            outcomes.push(message.replace(id, "<id>"));
        }
        assert!(
            outcomes
                .windows(2)
                .all(|pair| pair[0] == pair[1]),
            "distinguishable refusals: {outcomes:?}"
        );
    }

    /// An access token may list a surface only within its tenant and its
    /// resource pattern, as on every other surface route.
    #[tokio::test]
    async fn a_token_may_list_only_surfaces_within_its_tenant_and_resource_scope() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let in_tenant = |id: &str, tenant: &str| {
            let mut pipe = owned_llm_pipe(id, Some("alice"));
            pipe.tenant_id = Some(tenant.into());
            pipe
        };
        let (store, _dir) = store_with(vec![
            in_tenant("owned-chat", "tenant-a"),
            in_tenant("other-chat", "tenant-a"),
            in_tenant("owned-theirs", "tenant-b"),
        ])
        .await;
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;
        let context = PatTenantContext {
            token_id: "pat-1".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(regex::Regex::new("^TENANT:tenant-a:pipes:owned-.*$").unwrap()));

        validate_as(&catalog(vec![member("owned-chat", None)]), &store, &bob, Some(&context), Some(&scope))
            .await
            .expect("a surface inside the token's tenant and pattern");
        for refused in ["other-chat", "owned-theirs"] {
            assert!(
                matches!(
                    validate_as(&catalog(vec![member(refused, None)]), &store, &bob, Some(&context), Some(&scope))
                        .await,
                    Err(AppError::Forbidden(_))
                ),
                "{refused} was listed outside the token's scope"
            );
        }
        validate_as(&catalog(vec![member("other-chat", None)]), &store, &bob, Some(&context), None)
            .await
            .expect("a tenant token without a resource pattern lists any surface of its tenant");

        let (admin, _admins) = PipeCaller::for_test("root", UserRole::Administrator, None).await;
        assert!(
            matches!(
                validate_as(&catalog(vec![member("owned-theirs", None)]), &store, &admin, Some(&context), None).await,
                Err(AppError::Forbidden(_))
            ),
            "an administrator's tenant-a token listed a tenant-b surface"
        );
    }

    #[tokio::test]
    async fn an_ide_catalog_keeps_a_member_it_already_lists() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let (store, _dir) = store_with(vec![owned_llm_pipe("alices", Some("alice"))]).await;
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;
        let (config, stored) = ide_surface(vec![member("alices", None)]);

        validate_ide_catalog("front", &config, Some(&stored), &store, &bob, None, None)
            .await
            .expect("keeping a member the stored catalog lists needs nothing");
    }

    #[tokio::test]
    async fn rejects_unknown_member_surface() {
        let (store, _dir) = store_with(vec![llm_pipe("gpt4o")]).await;
        match validate(&catalog(vec![member("ghost", None)]), &store).await {
            Err(AppError::Forbidden(msg)) => {
                assert!(msg.contains("does not exist") && msg.contains("ghost"), "got: {msg}");
            }
            other => panic!("expected Forbidden, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_non_llm_member() {
        let non_llm = PipeConfig::new(
            "front".to_string(),
            "front".to_string(),
            PipeType::IDECatalog {
                config: IdeCatalogConfig::default(),
            },
        );
        let (store, _dir) = store_with(vec![non_llm]).await;
        match validate(&catalog(vec![member("front", None)]), &store).await {
            Err(AppError::InvalidInput(msg)) => {
                assert!(msg.contains("not an LLM Surface"), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_unknown_variant_alias_even_on_variantless_member() {
        // A member pinned to a bogus alias must be rejected even though the
        // referenced surface has no variants at all (resolve_variant would
        // silently fall back to base in that case, so existence is checked
        // directly).
        let (store, _dir) = store_with(vec![llm_pipe("gpt4o")]).await;
        match validate(&catalog(vec![member("gpt4o", Some("ghostv"))]), &store).await {
            Err(AppError::InvalidInput(msg)) => {
                assert!(msg.contains("no variant") && msg.contains("ghostv"), "got: {msg}");
            }
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn rejects_duplicate_members_via_config_validate() {
        let (store, _dir) = store_with(vec![llm_pipe("gpt4o")]).await;
        // Two members resolving to the same model id must be rejected up front
        // by IdeCatalogConfig::validate before any store lookup.
        match validate(&catalog(vec![member("gpt4o", None), member("gpt4o", None)]), &store).await {
            Err(AppError::InvalidInput(msg)) => assert!(msg.contains("Invalid IDE catalog"), "got: {msg}"),
            other => panic!("expected InvalidInput, got {other:?}"),
        }
    }

    /// A named catalogue member (mnemonic set, exposed, base surface).
    fn member_m(
        pipe_id: &str,
        mnemonic: &str,
    ) -> IdeCatalogMember {
        let mut m = member(pipe_id, None);
        m.mnemonic = Some(mnemonic.to_string());
        m
    }

    /// The IDE front-door pipe wrapping the given members, with a fixed route.
    fn ide_pipe(members: Vec<IdeCatalogMember>) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            "front".to_string(),
            "front".to_string(),
            PipeType::IDECatalog {
                config: IdeCatalogConfig { members, client_auth: None },
            },
        );
        pipe.route = Some("ide/front".to_string());
        pipe
    }

    #[tokio::test]
    async fn preview_lists_exposed_llm_members_sorted() {
        let (store, _dir) = store_with(vec![llm_pipe("alpha-surface"), llm_pipe("zeta-surface")]).await;
        let mut m_zeta = member_m("zeta-surface", "zeta");
        m_zeta.order = 10;
        let mut m_alpha = member_m("alpha-surface", "alpha");
        m_alpha.order = 5;
        // Members deliberately supplied out of order; the preview must sort by
        // (order, display name) exactly like the live discovery menu.
        let ide = ide_pipe(vec![m_zeta, m_alpha]);

        let preview = crate::pipes::handlers::http_handlers::build_ide_catalog_preview(store.as_ref(), &ide).await;

        assert_eq!(preview.object, "list");
        let ids: Vec<&str> = preview
            .data
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(ids, vec!["alpha", "zeta"]);

        let alpha = &preview.data[0];
        assert_eq!(alpha.agent_stream.surface_id, "alpha-surface");
        assert_eq!(
            alpha
                .agent_stream
                .display_name,
            "alpha"
        );
        assert_eq!(
            alpha
                .agent_stream
                .model
                .as_deref(),
            Some("gpt-4o")
        );
        assert_eq!(
            alpha
                .agent_stream
                .provider
                .as_deref(),
            Some("openai")
        );
        assert_eq!(alpha.agent_stream.route, "ide/front");
    }

    #[tokio::test]
    async fn preview_excludes_hidden_disabled_missing_and_non_llm() {
        let mut disabled = llm_pipe("disabled-surface");
        disabled.status = crate::entity_status::EntityStatus::Disabled;
        let non_llm = PipeConfig::new(
            "inner-front".to_string(),
            "inner-front".to_string(),
            PipeType::IDECatalog {
                config: IdeCatalogConfig::default(),
            },
        );
        let (store, _dir) = store_with(vec![llm_pipe("ok-surface"), disabled, non_llm]).await;

        let mut hidden = member_m("ok-surface", "hidden");
        hidden.expose = false;
        let ide = ide_pipe(vec![
            member_m("ok-surface", "ok"),        // exposed + enabled + LLM → kept
            hidden,                              // expose=false → dropped
            member_m("disabled-surface", "dis"), // disabled surface → dropped
            member_m("inner-front", "front"),    // non-LLM member → dropped
            member_m("ghost-surface", "ghost"),  // missing surface → dropped
        ]);

        let preview = crate::pipes::handlers::http_handlers::build_ide_catalog_preview(store.as_ref(), &ide).await;

        let ids: Vec<&str> = preview
            .data
            .iter()
            .map(|e| e.id.as_str())
            .collect();
        assert_eq!(ids, vec!["ok"]);
    }

    type AuditEvent = std::collections::HashMap<String, String>;

    /// The `security_audit` events logged on this thread while `run` runs.
    async fn security_audit_events(run: impl std::future::Future) -> Vec<AuditEvent> {
        use std::sync::Mutex;
        use tracing::field::{Field, Visit};
        use tracing_subscriber::layer::{Context, Layer, SubscriberExt};

        struct Fields(AuditEvent);
        impl Visit for Fields {
            fn record_debug(
                &mut self,
                field: &Field,
                value: &dyn std::fmt::Debug,
            ) {
                self.0
                    .insert(field.name().into(), format!("{value:?}"));
            }
            fn record_str(
                &mut self,
                field: &Field,
                value: &str,
            ) {
                self.0
                    .insert(field.name().into(), value.into());
            }
        }
        struct Capture(Arc<Mutex<Vec<AuditEvent>>>);
        impl<S: tracing::Subscriber> Layer<S> for Capture {
            fn on_event(
                &self,
                event: &tracing::Event<'_>,
                _ctx: Context<'_, S>,
            ) {
                if event.metadata().target() == "security_audit" {
                    let mut fields = Fields(AuditEvent::new());
                    event.record(&mut fields);
                    self.0
                        .lock()
                        .unwrap()
                        .push(fields.0);
                }
            }
        }

        let events = Arc::new(Mutex::new(Vec::new()));
        let _subscriber =
            tracing::subscriber::set_default(tracing_subscriber::registry().with(Capture(events.clone())));
        run.await;
        std::mem::take(&mut *events.lock().unwrap())
    }

    #[tokio::test]
    async fn a_refused_surface_change_is_logged_with_its_caller() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let alices = owned_llm_pipe("alices", Some("alice"));
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;
        let (alice, _owners) = PipeCaller::for_test("alice", UserRole::User, None).await;

        let refused = security_audit_events(async {
            assert!(
                ensure_may_manage(&bob, &alices, None)
                    .await
                    .is_err()
            );
        })
        .await;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["event"], "surface_ownership_denied");
        assert_eq!(refused[0]["actor_id"], "bob");
        assert_eq!(refused[0]["pipe_id"], "alices");

        let allowed = security_audit_events(async {
            ensure_may_manage(&alice, &alices, None)
                .await
                .unwrap();
        })
        .await;
        assert!(allowed.is_empty(), "{allowed:?}");
    }

    #[tokio::test]
    async fn a_refused_ide_catalog_member_is_logged_with_its_caller() {
        use crate::auth::types::UserRole;
        use crate::identity::handlers::pipe_caller::PipeCaller;
        let (store, _dir) = store_with(vec![owned_llm_pipe("alices", Some("alice"))]).await;
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;
        let (config, _) = ide_surface(vec![member("alices", None)]);

        let refused = security_audit_events(async {
            assert!(
                validate_as(&config, &store, &bob, None, None)
                    .await
                    .is_err()
            );
        })
        .await;
        assert_eq!(refused.len(), 1, "{refused:?}");
        assert_eq!(refused[0]["event"], "surface_ownership_denied");
        assert_eq!(refused[0]["actor_id"], "bob");
        assert_eq!(refused[0]["pipe_id"], "alices");
        assert_eq!(refused[0]["ide_pipe_id"], "front");
    }

    fn jwt_auth(
        audiences: &[&str],
        allow_missing_audience: bool,
    ) -> SourceAuthConfig {
        SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strategy".into(),
            audiences: audiences
                .iter()
                .map(|audience| audience.to_string())
                .collect(),
            allow_missing_audience,
            ..Default::default()
        })
    }

    fn refuses_every_token(result: Result<(), AppError>) -> bool {
        matches!(result, Err(AppError::InvalidInput(message)) if message.contains("refuses every token"))
    }

    #[test]
    fn jwt_caller_auth_with_no_audience_is_refused_on_save() {
        let mut pipe = llm_pipe("chat");
        pipe.source_auth = Some(jwt_auth(&[], false));

        assert!(refuses_every_token(validate_source_auth(&pipe)));
    }

    #[test]
    fn jwt_caller_auth_with_an_audience_or_the_missing_audience_opt_in_is_saved() {
        let mut pipe = llm_pipe("chat");
        pipe.source_auth = Some(jwt_auth(&["agent-stream"], false));
        assert!(validate_source_auth(&pipe).is_ok());

        pipe.source_auth = Some(jwt_auth(&[], true));
        assert!(validate_source_auth(&pipe).is_ok());

        pipe.source_auth = None;
        assert!(validate_source_auth(&pipe).is_ok());
    }

    #[test]
    fn a_variant_whose_jwt_caller_auth_has_no_audience_is_refused() {
        let mut pipe = llm_pipe_with_variant("chat", "strict");
        pipe.source_auth = Some(jwt_auth(&["agent-stream"], false));
        pipe.variants[0].enabled = false;
        pipe.variants[0]
            .overrides
            .source_auth = Some(jwt_auth(&[], false));

        assert!(refuses_every_token(validate_source_auth(&pipe)));
        assert!(refuses_every_token(validate_variant_change(&pipe)));
    }
}
