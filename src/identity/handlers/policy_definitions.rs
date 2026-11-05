//! Policy Definition API handlers
//!
//! CRUD endpoints for managing reusable OPA policy definitions.

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use super::pipes::AppError;
use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::pipes::{PIPE_POLICY_MANAGER, pipe_references_policy};
use crate::policies::policy_definitions::{
    FileSystemPolicyDefinitionStore, PolicyDefinition, PolicyType, PolicyVersion,
};
use crate::policies::{surface_references_policy, validate_policy_inputs, validate_policy_scope};
use crate::rbac::{Feature, RbacConfig};
use crate::surfaces::store::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

#[derive(Debug, Deserialize, Default)]
pub struct PolicyDefinitionsQuery {
    pub policy_type: Option<String>,
}

fn get_policy_store(state: &IdentityApiState) -> Result<&FileSystemPolicyDefinitionStore, AppError> {
    state
        .policy_definition_store
        .as_ref()
        .map(|s| s.as_ref())
        .ok_or_else(|| AppError::InternalError("Policy definition store not configured".to_string()))
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

fn policy_allowed(
    tenant_id: Option<&str>,
    policy_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    // A policy definition with no tenant is an intentional appliance-wide global
    // policy (see `policies::global_policy`) enforced on every tenant's surfaces,
    // so it is readable by every caller. Tenant-owned definitions stay confined
    // by the fail-closed tenancy gate + the token id-namespace.
    if tenant_id.is_none() {
        return true;
    }
    can_access(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::PolicyDefinitions, policy_id)
}

/// May this caller change or delete the policy, rather than read it?
///
/// [`policy_allowed`] returns `true` for any untenanted definition, and for
/// reading that is deliberate — an appliance-wide global policy is enforced on
/// every tenant's surfaces, so every tenant may see the rules binding them, and
/// a surface may reference one.
///
/// Writing is the opposite case and the same short-circuit was covering both.
/// A global policy rewritten by one tenant is every *other* tenant's guardrail
/// rewritten by them, and because the short-circuit returns before
/// `scope_allows_resource`, the token's resource pattern never got a say either.
/// An untenanted definition is the operator's; a tenant token may change only
/// what carries its own tenant id.
fn policy_writable(
    tenant_id: Option<&str>,
    policy_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_mutate(tenant_id, context) && scope_allows_resource(scope, context, ResourceKind::PolicyDefinitions, policy_id)
}

/// Whether the given principal's role holds `policies.publish`.
async fn user_has_publish(
    uid: &str,
    storage: &PasskeyStorage,
    rbac: &RbacConfig,
) -> bool {
    match storage
        .load_user_by_id(uid)
        .await
    {
        Ok(Some(user)) => rbac.has_permission(&user.role, &Feature::PoliciesPublish),
        _ => false,
    }
}

/// The caller's display name (`username`) for a version's `created_by`, resolved
/// from the `AuthGuardOk` marker the app-wide session guard publishes. Falls
/// back to the raw user id when the user record can't be loaded, and to `None`
/// when there is no authenticated caller (auth disabled).
async fn author_name(
    caller: &Option<Extension<AuthGuardOk>>,
    storage: Option<&Arc<PasskeyStorage>>,
) -> Option<String> {
    let Some(Extension(AuthGuardOk(uid))) = caller else {
        return None;
    };
    if let Some(storage) = storage
        && let Ok(Some(user)) = storage
            .load_user_by_id(uid)
            .await
    {
        return Some(user.username);
    }
    Some(uid.clone())
}

/// Validate that a definition's Rego declares the package expected for its
/// `policy_type` (`appliance`→`agentstream.policy`, `llm`→`llm.policy`,
/// `ide`→`ide.policy`) and reads no input field that requests never carry.
/// Rejects either with `AppError::InvalidInput` (HTTP 400). An empty body is
/// accepted. See [`validate_policy_scope`] and [`validate_policy_inputs`].
fn validate_scope(policy: &PolicyDefinition) -> Result<(), AppError> {
    validate_policy_scope(policy).map_err(AppError::InvalidInput)?;
    validate_policy_inputs(&policy.policy).map_err(AppError::InvalidInput)
}

/// Recompile every runtime OPA engine that references `policy_id` so a
/// reusable policy-definition mutation takes effect on live traffic without a
/// pipe/surface edit or process restart.
///
/// Covers pipe front-door / variant / IDE-member engines (via
/// [`PIPE_POLICY_MANAGER`]) and surface inbound / response engines (via the
/// global surface policy manager). On **delete/disable** the same fan-out
/// evicts stale engines: the recompiler finds the definition gone or disabled
/// and removes the compiled engine, so an old permissive policy can never stay
/// active (fail closed).
///
/// Reporting is via structured logs — one line per refreshed/failed object
/// plus a summary — surfaced in the dashboard Logs tab. Failures never
/// preserve a stale permissive engine (a failed recompile evicts → deny).
async fn refresh_referencing_engines(
    state: &IdentityApiState,
    policy_id: &str,
) {
    if let Err(e) = recompile_policy_engines(
        &EngineStores {
            pipe_store: state.pipe_store.clone(),
            global_policy_store: state
                .global_policy_store
                .clone(),
            agent_surfaces_path: state
                .bootstrap_config
                .storage_paths
                .agent_surfaces
                .clone(),
            gateways_path: state
                .bootstrap_config
                .storage_paths
                .gateways
                .clone(),
        },
        EngineScope::Referencing(policy_id),
    )
    .await
    {
        error!(policy_id = %policy_id, error = %e, "Policy engines referencing the changed definition were not all refreshed");
    }
}

/// Where [`recompile_policy_engines`] reads the objects whose engines it compiles.
pub(crate) struct EngineStores {
    pub pipe_store: Option<Arc<crate::pipes::FileSystemPipeStore>>,
    pub global_policy_store: Option<Arc<crate::policies::FileSystemGlobalPolicyStore>>,
    pub agent_surfaces_path: String,
    pub gateways_path: String,
}

/// Which compiled policy engines [`recompile_policy_engines`] rebuilds.
#[derive(Clone, Copy)]
pub(crate) enum EngineScope<'a> {
    /// Every engine, as at startup. Used when an instance is promoted.
    All,
    /// Only the engines that reference this policy definition.
    Referencing(&'a str),
}

impl<'a> EngineScope<'a> {
    fn label(self) -> &'a str {
        match self {
            Self::All => "*",
            Self::Referencing(id) => id,
        }
    }
}

/// Whether `surface`'s engine is rebuilt for `scope`. A full pass takes every
/// enabled surface, because the policy may come from the default variant or
/// may have been removed, and the manager compiles or evicts accordingly.
fn surface_in_scope(
    surface: &crate::config::agent_surface::AgentSurface,
    scope: EngineScope<'_>,
) -> bool {
    surface.status.is_enabled()
        && match scope {
            EngineScope::All => true,
            EngineScope::Referencing(id) => surface_references_policy(surface, id),
        }
}

/// Whether `gateway`'s engine is rebuilt for `scope`. A full pass takes every
/// gateway, so one whose policy was removed has its engine evicted.
fn gateway_in_scope(
    gateway: &crate::gateways::types::Gateway,
    scope: EngineScope<'_>,
) -> bool {
    match scope {
        EngineScope::All => true,
        EngineScope::Referencing(policy_id) => gateway
            .opa_policy_config
            .as_ref()
            .is_some_and(|c| {
                c.enabled
                    && c.all_policy_definition_ids()
                        .iter()
                        .any(|id| id == policy_id)
            }),
    }
}

/// Recompile the inbound, response and variant engines of every surface in
/// `scope` stored under `surfaces_path`. Returns how many recompiled and how
/// many failed (and were evicted), or an error when the store cannot be read.
async fn recompile_surface_engines(
    policy_manager: &crate::policies::SurfacePolicyManager,
    surfaces_path: &str,
    scope: EngineScope<'_>,
) -> std::io::Result<(usize, usize)> {
    let store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(surfaces_path))
        .await
        .map_err(|e| std::io::Error::other(format!("cannot open surface store: {e}")))?;
    let surfaces = store
        .list_all()
        .await
        .map_err(|e| std::io::Error::other(format!("cannot list surfaces: {e}")))?;
    let policy_id = scope.label();
    let (mut ok, mut failed) = (0usize, 0usize);
    for surface in surfaces
        .iter()
        .filter(|s| surface_in_scope(s, scope))
    {
        match policy_manager
            .update_channel_policy(surface)
            .await
        {
            Ok(()) => {
                ok += 1;
                info!(policy_id = %policy_id, surface = %surface.name, "Recompiled surface OPA engine");
            }
            Err(e) => {
                failed += 1;
                warn!(policy_id = %policy_id, surface = %surface.name, error = %e, "Failed to recompile surface OPA engine");
            }
        }
    }
    Ok((ok, failed))
}

/// Recompile the Trust Fabric engine of every gateway in `scope` stored under
/// `gateways_path`. A gateway references a reusable policy by id, so a
/// definition change recompiles every gateway that references it. Returns how
/// many recompiled and how many failed (and were evicted), or an error when the
/// store cannot be read.
async fn recompile_gateway_engines(
    gw_manager: &crate::policies::GatewayPolicyManager,
    gateways_path: &str,
    scope: EngineScope<'_>,
) -> std::io::Result<(usize, usize)> {
    use crate::gateways::store::GatewayStore as _;
    let store = crate::gateways::FileSystemGatewayStore::new(std::path::PathBuf::from(gateways_path), None)
        .await
        .map_err(|e| std::io::Error::other(format!("cannot open gateway store: {e}")))?;
    let gateways = store
        .list_all()
        .await
        .map_err(|e| std::io::Error::other(format!("cannot list gateways: {e}")))?;
    let policy_id = scope.label();
    let (mut ok, mut failed) = (0usize, 0usize);
    for gateway in gateways
        .iter()
        .filter(|g| gateway_in_scope(g, scope))
    {
        match gw_manager
            .update_gateway_policy(gateway)
            .await
        {
            Ok(()) => {
                ok += 1;
                info!(policy_id = %policy_id, gateway_id = %gateway.id, "Recompiled gateway OPA engine");
            }
            Err(e) => {
                failed += 1;
                warn!(policy_id = %policy_id, gateway_id = %gateway.id, error = %e, "Failed to recompile gateway OPA engine");
            }
        }
    }
    Ok((ok, failed))
}

/// Recompile the pipe, surface, gateway and appliance-wide policy engines in
/// `scope` from the stored definitions. A recompile that fails evicts the
/// engine, so the object denies rather than keeping a stale policy. Returns an
/// error when the surface or gateway store cannot be opened or listed, since
/// their engines were then left as they were; every other class is still
/// recompiled first.
pub(crate) async fn recompile_policy_engines(
    stores: &EngineStores,
    scope: EngineScope<'_>,
) -> std::io::Result<()> {
    let policy_id = scope.label();
    let mut store_error = None;
    // ── Pipes: front-door, variants, IDE members ────────────────────────────
    let (mut pipes_ok, mut pipes_failed) = (0usize, 0usize);
    if let Some(ref pipe_store) = stores.pipe_store {
        let matched: Vec<_> = pipe_store
            .list()
            .await
            .into_iter()
            .filter(|p| match scope {
                EngineScope::All => true,
                EngineScope::Referencing(id) => pipe_references_policy(p, id),
            })
            .collect();
        for pipe in &matched {
            match PIPE_POLICY_MANAGER
                .update_pipe_policy(pipe)
                .await
            {
                Ok(()) => {
                    pipes_ok += 1;
                    info!(policy_id = %policy_id, pipe_id = %pipe.id, "Recompiled pipe OPA engine");
                }
                Err(e) => {
                    pipes_failed += 1;
                    warn!(policy_id = %policy_id, pipe_id = %pipe.id, error = %e, "Failed to recompile pipe OPA engine");
                }
            }
        }
    } else {
        warn!(policy_id = %policy_id, "pipe_store unavailable; pipe OPA engines not refreshed");
    }

    // ── Surfaces: inbound + response + variant overrides ─────────────────────
    let (mut surfaces_ok, mut surfaces_failed) = (0usize, 0usize);
    match crate::gateways::get_policy_manager() {
        Some(policy_manager) => {
            match recompile_surface_engines(&policy_manager, &stores.agent_surfaces_path, scope).await {
                Ok((ok, failed)) => (surfaces_ok, surfaces_failed) = (ok, failed),
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Surface OPA engines not refreshed");
                    store_error = Some(e);
                }
            }
        }
        None => warn!(policy_id = %policy_id, "Surface policy manager unavailable; surface OPA engines not refreshed"),
    }

    // ── Gateways (Trust Fabric): appliance↔appliance policy engines ──────────
    let (mut gateways_ok, mut gateways_failed) = (0usize, 0usize);
    match crate::gateways::get_gateway_policy_manager() {
        Some(gw_manager) => match recompile_gateway_engines(&gw_manager, &stores.gateways_path, scope).await {
            Ok((ok, failed)) => (gateways_ok, gateways_failed) = (ok, failed),
            Err(e) => {
                warn!(policy_id = %policy_id, error = %e, "Gateway OPA engines not refreshed");
                store_error = Some(e);
            }
        },
        None => warn!(policy_id = %policy_id, "Gateway policy manager unavailable; gateway OPA engines not refreshed"),
    }

    // ── Appliance-wide (global) policy assignments ────────────────────────
    // Recompile the global policy sets when the changed definition is enforced
    // appliance-wide, so a mutated/deleted global policy takes effect (or fails
    // closed) on every surface immediately.
    if let Some(ref global_store) = stores.global_policy_store {
        let assignments = global_store.get().await;
        let in_scope = match scope {
            EngineScope::All => true,
            EngineScope::Referencing(id) => assignments.references_policy(id),
        };
        if in_scope {
            match crate::pipes::PIPE_POLICY_MANAGER
                .refresh_global(&assignments)
                .await
            {
                Ok(()) => {
                    info!(policy_id = %policy_id, "Recompiled appliance-wide policy sets")
                }
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Failed to recompile appliance-wide policy sets")
                }
            }
        }
    }

    info!(
        policy_id = %policy_id,
        pipes_refreshed = pipes_ok,
        pipes_failed = pipes_failed,
        surfaces_refreshed = surfaces_ok,
        surfaces_failed = surfaces_failed,
        gateways_refreshed = gateways_ok,
        gateways_failed = gateways_failed,
        "Policy engine recompile: refreshed {} pipe(s), {} surface(s), and {} gateway(s), {} failed",
        pipes_ok,
        surfaces_ok,
        gateways_ok,
        pipes_failed + surfaces_failed + gateways_failed,
    );
    store_error.map_or(Ok(()), Err)
}

/// List all policy definitions, optionally filtered by type
pub async fn list_policy_definitions(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(query): Query<PolicyDefinitionsQuery>,
) -> Result<Json<Vec<PolicyDefinition>>, AppError> {
    let store = get_policy_store(&state)?;

    let context_ref = tenant_context(&context);
    let scope_ref = resource_scope(&scope);
    let mut policies: Vec<PolicyDefinition> = store.list().await;
    if let Some(ref pt) = query.policy_type {
        policies.retain(|p| p.policy_type.to_string() == *pt && p.enabled);
    }
    policies.retain(|policy| policy_allowed(policy.tenant_id.as_deref(), &policy.id, context_ref, scope_ref));
    Ok(Json(policies))
}

/// Get a single policy definition by ID
pub async fn get_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PolicyDefinition>, AppError> {
    let store = get_policy_store(&state)?;

    let policy: PolicyDefinition = store
        .get(&policy_id)
        .await
        .filter(|policy| {
            policy_allowed(policy.tenant_id.as_deref(), &policy.id, tenant_context(&context), resource_scope(&scope))
        })
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;

    Ok(Json(policy))
}

/// Create a new policy definition
pub async fn create_policy_definition(
    State(state): State<IdentityApiState>,
    caller: Option<Extension<AuthGuardOk>>,
    passkey_storage: Option<Extension<Arc<PasskeyStorage>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut policy): Json<PolicyDefinition>,
) -> Result<(StatusCode, Json<PolicyDefinition>), AppError> {
    let store = get_policy_store(&state)?;

    policy.tenant_id = tenant_for_create(policy.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| AppError::Forbidden(message.to_string()))?;
    if !policy_allowed(policy.tenant_id.as_deref(), &policy.id, tenant_context(&context), resource_scope(&scope)) {
        return Err(AppError::Forbidden(format!(
            "policy definition id '{}' is outside this token's permitted namespace",
            policy.id
        )));
    }

    if store.exists(&policy.id).await {
        return Err(AppError::InvalidInput(format!("Policy definition already exists: {}", policy.id)));
    }

    validate_scope(&policy)?;

    let author = author_name(
        &caller,
        passkey_storage
            .as_ref()
            .map(|Extension(s)| s),
    )
    .await;
    info!(author = ?author, "Creating policy definition: {} ({})", policy.name, policy.id);

    let response = policy.clone();
    store
        .save_authored(policy, author, None)
        .await
        .map_err(|e| {
            error!("Failed to save policy definition: {}", e);
            AppError::InternalError(format!("Failed to save policy definition: {}", e))
        })?;

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok((StatusCode::CREATED, Json(response)))
}

/// Editing a policy enforced appliance-wide requires the publish permission:
/// the caller's role must hold `policies.publish` and an access token's scope
/// list, when it has one, must name it (the same check as the
/// `PUT /v1/policy-assignments` route gate). Fails closed: without the caller's
/// authorization context the edit is denied.
async fn require_publish_for_global_policy(
    enforced_globally: bool,
    passkey_storage: &Option<Extension<Arc<PasskeyStorage>>>,
    rbac_config: &Option<Extension<Arc<RbacConfig>>>,
    caller: &Option<Extension<AuthGuardOk>>,
    pat: Option<&PatContext>,
) -> Result<(), AppError> {
    if !enforced_globally {
        return Ok(());
    }
    let (Some(Extension(storage)), Some(Extension(rbac)), Some(Extension(AuthGuardOk(uid)))) =
        (passkey_storage, rbac_config, caller)
    else {
        return Err(AppError::Forbidden(
            "This policy is enforced appliance-wide; editing it requires the publish permission, but the caller's authorization context is unavailable".to_string(),
        ));
    };
    // A role denial and a token-scope denial get the same 403.
    if !user_has_publish(uid, storage, rbac).await
        || !crate::auth_manager::middleware::pat_scope_allows(pat, &Feature::PoliciesPublish)
    {
        return Err(AppError::Forbidden(
            "This policy is enforced appliance-wide; editing it requires the publish permission".to_string(),
        ));
    }
    Ok(())
}

/// Update an existing policy definition
pub async fn update_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    passkey_storage: Option<Extension<Arc<PasskeyStorage>>>,
    rbac_config: Option<Extension<Arc<RbacConfig>>>,
    caller: Option<Extension<AuthGuardOk>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(mut policy): Json<PolicyDefinition>,
) -> Result<Json<PolicyDefinition>, AppError> {
    let store = get_policy_store(&state)?;

    if policy.id != policy_id {
        return Err(AppError::InvalidInput("Policy definition ID mismatch".to_string()));
    }

    let Some(existing) = store.get(&policy_id).await else {
        return Err(AppError::NotFound(format!("Policy definition not found: {}", policy_id)));
    };
    if !policy_writable(existing.tenant_id.as_deref(), &existing.id, tenant_context(&context), resource_scope(&scope)) {
        return Err(AppError::Forbidden("Policy definition is not this token's to change".into()));
    }
    policy.tenant_id = existing.tenant_id.clone();

    // The policy type is immutable after creation: it fixes the Rego package /
    // query path and which surfaces may reference the policy, so a change would
    // silently break bindings.
    if existing.policy_type != policy.policy_type {
        return Err(AppError::InvalidInput("A policy's type cannot be changed after creation".to_string()));
    }

    validate_scope(&policy)?;

    // Separation of duties: editing a policy that is enforced appliance-wide
    // changes behaviour fleet-wide, so require the publish permission on top of
    // the route's edit gate. Fails closed: if this extra check's dependencies
    // cannot be resolved, the edit is denied rather than silently unguarded.
    let enforced_globally = match state
        .global_policy_store
        .as_ref()
    {
        Some(gs) => gs
            .get()
            .await
            .references_policy(&policy_id),
        None => false,
    };
    require_publish_for_global_policy(enforced_globally, &passkey_storage, &rbac_config, &caller, pat.as_deref())
        .await?;

    policy.updated_at = Some(chrono::Utc::now().to_rfc3339());

    let author = author_name(
        &caller,
        passkey_storage
            .as_ref()
            .map(|Extension(s)| s),
    )
    .await;
    info!(author = ?author, "Updating policy definition: {} ({})", policy.name, policy.id);

    let response = policy.clone();
    store
        .save_authored(policy, author, None)
        .await
        .map_err(|e| {
            error!("Failed to update policy definition: {}", e);
            AppError::InternalError(format!("Failed to update policy definition: {}", e))
        })?;

    // Recompile every runtime engine that references this definition so the new
    // enforcement logic takes effect on live traffic immediately.
    refresh_referencing_engines(&state, &policy_id).await;

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(Json(response))
}

/// Delete a policy definition
pub async fn delete_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, AppError> {
    let store = get_policy_store(&state)?;

    let existing = store
        .get(&policy_id)
        .await
        .filter(|policy| {
            policy_writable(policy.tenant_id.as_deref(), &policy.id, tenant_context(&context), resource_scope(&scope))
        })
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    let _ = existing;

    info!("Deleting policy definition: {}", policy_id);

    store
        .delete(&policy_id)
        .await
        .map_err(|e| {
            error!("Failed to delete policy definition: {}", e);
            AppError::InternalError(format!("Failed to delete policy definition: {}", e))
        })?;

    // Fan out AFTER the delete: the recompiler now finds the definition gone
    // and evicts each referencing engine, so an old compiled allow policy can
    // never remain active (fail closed).
    refresh_referencing_engines(&state, &policy_id).await;

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(StatusCode::NO_CONTENT)
}

/// Request body for a policy dry-run.
#[derive(Debug, Deserialize)]
pub struct SimulatePolicyRequest {
    /// The `input` document to evaluate (the PolicyInput contract shape).
    pub input: serde_json::Value,
    /// Optional historical version to evaluate; defaults to the current version.
    /// Ignored when `policy` (a draft body) is supplied.
    #[serde(default)]
    pub version: Option<u32>,
    /// Optional draft Rego to evaluate instead of a stored version — lets an
    /// operator test edits before saving. Evaluated under the definition's
    /// declared type/query (or `policy_type` below, if supplied).
    #[serde(default)]
    pub policy: Option<String>,
    /// Optional policy type (`appliance` / `llm` / `ide`) for a draft body —
    /// used when the type was changed in the editor before saving. Ignored for a
    /// stored version.
    #[serde(default)]
    pub policy_type: Option<String>,
}

/// Result of a policy dry-run.
#[derive(Debug, Serialize)]
pub struct SimulatePolicyResponse {
    /// Whether the policy allowed the sample input.
    pub allow: bool,
    /// The policy's stated reason, when it provides one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The definition's policy type (`appliance` / `llm` / `ide`).
    pub policy_type: String,
    /// The evaluated stored version, or `null` for a draft body.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<u32>,
    /// `sha256:<hex>` hash of the exact Rego evaluated (stored or draft).
    pub content_hash: String,
    /// The Rego query path the engine evaluated.
    pub query: String,
}

/// Maximum draft Rego / sample input sizes accepted by the dry-run, and the
/// wall-clock bound on a single evaluation — dry-run compiles and runs
/// caller-supplied Rego, so it is bounded to keep a pathological policy from
/// tying up a worker.
const MAX_SIMULATE_REGO: usize = 128 * 1024;
const MAX_SIMULATE_INPUT: usize = 256 * 1024;
const SIMULATE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

/// Dry-run a policy definition against a sample input. Compiles the requested
/// version (current by default), or an inline draft body under an optional
/// (unsaved) type, into a throwaway engine and evaluates it — no runtime engine,
/// binding, or live traffic is affected. The draft size, input size, and
/// evaluation time are bounded. Read-only.
pub async fn simulate_policy_definition(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<SimulatePolicyRequest>,
) -> Result<Json<SimulatePolicyResponse>, AppError> {
    if req
        .policy
        .as_deref()
        .is_some_and(|p| p.len() > MAX_SIMULATE_REGO)
    {
        return Err(AppError::InvalidInput("Draft policy is too large to simulate".to_string()));
    }
    if serde_json::to_vec(&req.input)
        .map(|v| v.len())
        .unwrap_or(0)
        > MAX_SIMULATE_INPUT
    {
        return Err(AppError::InvalidInput("Sample input is too large to simulate".to_string()));
    }

    let store = get_policy_store(&state)?;
    let doc = store
        .get_document(&policy_id)
        .await
        .filter(|document| {
            policy_allowed(
                document.tenant_id.as_deref(),
                &document.id,
                tenant_context(&context),
                resource_scope(&scope),
            )
        })
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    let ResolvedSimulation {
        rego,
        query,
        policy_type,
        version,
        content_hash,
    } = resolve_simulation(&doc, req.version, req.policy.as_deref(), req.policy_type.as_deref())?;

    // Compile + evaluate off the async worker, under a wall-clock bound.
    let (rego_eval, query_eval, input) = (rego, query.clone(), req.input);
    let (allow, reason) = match tokio::time::timeout(
        SIMULATE_TIMEOUT,
        tokio::task::spawn_blocking(move || compile_and_eval(&rego_eval, &query_eval, input)),
    )
    .await
    {
        Err(_) => return Err(AppError::InvalidInput("Policy simulation exceeded the time limit".to_string())),
        Ok(Err(_join)) => return Err(AppError::InternalError("Policy simulation task failed".to_string())),
        Ok(Ok(Err(msg))) => return Err(AppError::InvalidInput(msg)),
        Ok(Ok(Ok(decision))) => decision,
    };

    Ok(Json(SimulatePolicyResponse {
        allow,
        reason,
        policy_type,
        version,
        content_hash,
        query,
    }))
}

/// The resolved inputs for a dry-run evaluation.
#[derive(Debug)]
struct ResolvedSimulation {
    rego: String,
    query: String,
    policy_type: String,
    version: Option<u32>,
    content_hash: String,
}

fn parse_policy_type(s: &str) -> Option<PolicyType> {
    match s {
        "appliance" => Some(PolicyType::Appliance),
        "llm" => Some(PolicyType::Llm),
        "ide" => Some(PolicyType::Ide),
        _ => None,
    }
}

/// Resolve the exact Rego + query + attribution for a dry-run: a non-empty draft
/// body (optionally under a supplied, unsaved type), else the requested stored
/// version, else the current version. Pure — touches no engine or live traffic.
fn resolve_simulation(
    doc: &crate::policies::policy_definitions::PolicyDocument,
    version: Option<u32>,
    draft: Option<&str>,
    type_override: Option<&str>,
) -> Result<ResolvedSimulation, AppError> {
    let has_draft = draft.is_some_and(|d| !d.trim().is_empty());
    // A draft may declare a different (unsaved) type than the stored document.
    let effective_type = match type_override {
        Some(t) if has_draft => {
            parse_policy_type(t).ok_or_else(|| AppError::InvalidInput(format!("Unknown policy type: {}", t)))?
        }
        _ => doc.policy_type.clone(),
    };
    let (rego, version, content_hash) = match draft {
        Some(draft) if has_draft => {
            let hash = crate::policies::policy_definitions::content_hash(&effective_type, draft);
            (draft.to_string(), None, hash)
        }
        _ => {
            let v = match version {
                Some(v) => doc
                    .version(v)
                    .ok_or_else(|| AppError::InvalidInput(format!("Version {} not found for policy {}", v, doc.id)))?,
                None => doc
                    .current()
                    .ok_or_else(|| AppError::InternalError(format!("Policy {} has no current version", doc.id)))?,
            };
            (v.policy.clone(), Some(v.version), v.content_hash.clone())
        }
    };
    if rego.trim().is_empty() {
        return Err(AppError::InvalidInput("Policy body is empty; nothing to simulate".to_string()));
    }
    let query = format!("data.{}.allow", effective_type.expected_package());
    Ok(ResolvedSimulation {
        rego,
        query,
        policy_type: effective_type.to_string(),
        version,
        content_hash,
    })
}

/// Compile a throwaway engine and evaluate — returns `(allow, reason)`. Runs on a
/// blocking worker under the dry-run handler's time bound.
fn compile_and_eval(
    rego: &str,
    query: &str,
    input: serde_json::Value,
) -> Result<(bool, Option<String>), String> {
    let engine = crate::policies::OpaEngine::new();
    engine
        .load_policy("simulate", rego)
        .map_err(|e| format!("Policy failed to compile: {}", e))?;
    let decision = engine
        .evaluate_query(query, input)
        .map_err(|e| format!("Policy evaluation error: {}", e))?;
    Ok((decision.allow, decision.reason))
}

/// Synchronous dry-run core used by tests (mirrors the handler without the
/// worker offload / time bound).
#[cfg(test)]
fn run_policy_simulation(
    doc: &crate::policies::policy_definitions::PolicyDocument,
    version: Option<u32>,
    draft: Option<&str>,
    input: serde_json::Value,
) -> Result<SimulatePolicyResponse, AppError> {
    let r = resolve_simulation(doc, version, draft, None)?;
    let (allow, reason) = compile_and_eval(&r.rego, &r.query, input).map_err(AppError::InvalidInput)?;
    Ok(SimulatePolicyResponse {
        allow,
        reason,
        policy_type: r.policy_type,
        version: r.version,
        content_hash: r.content_hash,
        query: r.query,
    })
}

/// The blast radius of a policy definition: how many runtime objects reference
/// it, so a UI can warn before a fleet-wide edit or delete.
#[derive(Debug, Serialize)]
pub struct PolicyImpactResponse {
    pub policy_id: String,
    /// LLM / IDE surfaces (pipes) referencing this policy.
    pub pipes: usize,
    /// Fabric surfaces referencing this policy.
    pub surfaces: usize,
    /// Gateways (Trust Fabric) referencing this policy.
    pub gateways: usize,
    /// Whether the policy is enforced appliance-wide for any type.
    pub globally_enforced: bool,
    /// The surface types (`llm` / `ide`) that enforce it appliance-wide.
    pub global_types: Vec<String>,
    /// Sum across pipes, surfaces, gateways, and global types.
    pub total: usize,
}

/// Report a policy definition's blast radius — every runtime object that
/// references it (LLM/IDE surfaces, fabric surfaces, gateways) plus any
/// appliance-wide (global) enforcement — so an operator can gauge the impact of
/// changing or deleting it before acting. Read-only.
pub async fn policy_definition_impact(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PolicyImpactResponse>, AppError> {
    // The definition must exist so a stale client can't imply a phantom policy.
    let store = get_policy_store(&state)?;
    store
        .get(&policy_id)
        .await
        .filter(|policy| {
            policy_allowed(policy.tenant_id.as_deref(), &policy.id, tenant_context(&context), resource_scope(&scope))
        })
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;

    // Count the three store-backed reference sets concurrently. Each reads the
    // current on-disk state (the codebase's authoritative-disk model), so this
    // overlaps their I/O rather than opening the stores one after another.
    let pipes_fut = async {
        match &state.pipe_store {
            Some(ps) => ps
                .list()
                .await
                .iter()
                .filter(|p| pipe_references_policy(p, &policy_id))
                .count(),
            None => 0,
        }
    };
    let surfaces_fut = async {
        match crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
            &state
                .bootstrap_config
                .storage_paths
                .agent_surfaces,
        ))
        .await
        {
            Ok(surface_store) => match surface_store.list_all().await {
                Ok(list) => list
                    .iter()
                    .filter(|s| surface_references_policy(s, &policy_id))
                    .count(),
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Failed to list surfaces for policy impact");
                    0
                }
            },
            Err(e) => {
                warn!(policy_id = %policy_id, error = %e, "Failed to open surface store for policy impact");
                0
            }
        }
    };
    let gateways_fut = async {
        use crate::gateways::store::GatewayStore as _;
        match crate::gateways::FileSystemGatewayStore::new(
            std::path::PathBuf::from(
                &state
                    .bootstrap_config
                    .storage_paths
                    .gateways,
            ),
            None,
        )
        .await
        {
            Ok(gw_store) => match gw_store.list_all().await {
                Ok(list) => list
                    .iter()
                    .filter(|g| {
                        g.opa_policy_config
                            .as_ref()
                            .is_some_and(|c| {
                                c.all_policy_definition_ids()
                                    .iter()
                                    .any(|id| id == policy_id.as_str())
                            })
                    })
                    .count(),
                Err(e) => {
                    warn!(policy_id = %policy_id, error = %e, "Failed to list gateways for policy impact");
                    0
                }
            },
            Err(e) => {
                warn!(policy_id = %policy_id, error = %e, "Failed to open gateway store for policy impact");
                0
            }
        }
    };
    let (pipes, surfaces, gateways) = tokio::join!(pipes_fut, surfaces_fut, gateways_fut);

    // Appliance-wide (global) enforcement.
    let global_types = match &state.global_policy_store {
        Some(gs) => gs
            .get()
            .await
            .types_enforcing(&policy_id),
        None => Vec::new(),
    };

    let total = pipes + surfaces + gateways + global_types.len();
    Ok(Json(PolicyImpactResponse {
        policy_id,
        pipes,
        surfaces,
        gateways,
        globally_enforced: !global_types.is_empty(),
        global_types,
        total,
    }))
}

/// List a policy definition's immutable version history, newest first — so an
/// operator can review who changed what and resolve any historical revision.
/// Read-only.
pub async fn list_policy_versions(
    State(state): State<IdentityApiState>,
    Path(policy_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PolicyVersion>>, AppError> {
    let store = get_policy_store(&state)?;
    let doc = store
        .get_document(&policy_id)
        .await
        .filter(|document| {
            policy_allowed(
                document.tenant_id.as_deref(),
                &document.id,
                tenant_context(&context),
                resource_scope(&scope),
            )
        })
        .ok_or_else(|| AppError::NotFound(format!("Policy definition not found: {}", policy_id)))?;
    let mut versions = doc.versions;
    versions.sort_by_key(|v| std::cmp::Reverse(v.version));
    Ok(Json(versions))
}

/// Get the appliance-wide (global) policy assignments — which reusable policies
/// are enforced on every surface of a type.
pub async fn get_policy_assignments(
    State(state): State<IdentityApiState>
) -> Result<Json<crate::policies::GlobalPolicyAssignments>, AppError> {
    let store = state
        .global_policy_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Global policy store not configured".to_string()))?;
    Ok(Json(store.get().await))
}

/// Replace the appliance-wide (global) policy assignments and recompile the
/// global policy sets so enforcement takes effect immediately. Each referenced
/// policy must exist and match the surface type it is assigned to.
pub async fn update_policy_assignments(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    Json(assignments): Json<crate::policies::GlobalPolicyAssignments>,
) -> Result<Json<crate::policies::GlobalPolicyAssignments>, AppError> {
    // Appliance-wide enforcement binds every tenant's surfaces, so it is an
    // operator action. The route's `policies.publish` gate mostly covers this —
    // a tenant token is not granted that permission — but "mostly" is a
    // statement about today's grant list, and this endpoint replaces the whole
    // assignment set, so the cost of that list being widened later is every
    // tenant's baseline. Stated here instead, where it does not depend on
    // remembering.
    if context.is_some() {
        return Err(AppError::Forbidden(
            "Appliance-wide policy assignments cannot be changed by a tenant-scoped token".into(),
        ));
    }
    let store = state
        .global_policy_store
        .as_ref()
        .ok_or_else(|| AppError::InternalError("Global policy store not configured".to_string()))?;

    if let Some(def_store) = state
        .policy_definition_store
        .as_ref()
    {
        for (policy_type, list) in &assignments.assignments {
            for a in list {
                match def_store
                    .get(&a.policy_id)
                    .await
                {
                    Some(def) if def.tenant_id.is_some() => {
                        return Err(AppError::InvalidInput(format!(
                            "Tenant-owned policy '{}' cannot be enforced appliance-wide",
                            a.policy_id
                        )));
                    }
                    Some(def) if def.policy_type.to_string() == *policy_type => {}
                    Some(def) => {
                        return Err(AppError::InvalidInput(format!(
                            "Policy '{}' is a {} policy and cannot be enforced on the '{}' surface type",
                            a.policy_id, def.policy_type, policy_type
                        )));
                    }
                    None => {
                        return Err(AppError::InvalidInput(format!("Policy definition not found: {}", a.policy_id)));
                    }
                }
            }
        }
    }

    store
        .save(assignments.clone())
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to save global policy assignments: {}", e)))?;

    if let Err(e) = crate::pipes::PIPE_POLICY_MANAGER
        .refresh_global(&assignments)
        .await
    {
        error!("Failed to recompile appliance-wide policy sets: {}", e);
        return Err(AppError::InternalError(format!(
            "Assignments saved but failed to compile appliance-wide policy sets: {}",
            e
        )));
    }

    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(Json(assignments))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policies::policy_definitions::{PolicyDocument, PolicyType, PolicyVersion};

    const ALLOW_LLM: &str = "package llm.policy\nimport rego.v1\ndefault allow := true";
    const DENY_LLM: &str = "package llm.policy\nimport rego.v1\ndefault allow := false";

    fn definition(policy: &str) -> PolicyDefinition {
        PolicyDefinition {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: String::new(),
            policy_type: PolicyType::Llm,
            policy: policy.to_string(),
            enabled: true,
            created_at: "2026-01-01T00:00:00Z".to_string(),
            updated_at: None,
            version: None,
            content_hash: None,
            sample_input: None,
            tenant_id: None,
        }
    }

    #[test]
    fn saving_a_definition_that_reads_an_unpopulated_input_is_refused() {
        let refused = validate_scope(&definition(&format!("{ALLOW_LLM}\ndeny if input.resource.tool == \"x\"")));
        assert!(
            matches!(&refused, Err(AppError::InvalidInput(message)) if message.contains("input.resource.tool")),
            "{refused:?}"
        );
        assert!(validate_scope(&definition(ALLOW_LLM)).is_ok());
    }

    fn doc(
        policy_type: PolicyType,
        rego: &str,
    ) -> PolicyDocument {
        PolicyDocument {
            id: "p1".to_string(),
            name: "p1".to_string(),
            description: String::new(),
            policy_type,
            enabled: true,
            current_version: 1,
            created_at: "2026-06-07T00:00:00Z".to_string(),
            updated_at: None,
            versions: vec![PolicyVersion {
                version: 1,
                policy: rego.to_string(),
                content_hash: "sha256:seed".to_string(),
                created_at: "2026-06-07T00:00:00Z".to_string(),
                created_by: None,
                note: None,
                name: None,
                description: None,
            }],
            sample_input: None,
            tenant_id: None,
        }
    }

    #[tokio::test]
    async fn global_policy_edit_without_authorization_context_is_denied() {
        let result = require_publish_for_global_policy(true, &None, &None, &None, None).await;
        assert!(matches!(result, Err(AppError::Forbidden(_))));
    }

    #[tokio::test]
    async fn non_global_policy_edit_needs_no_publish_check() {
        require_publish_for_global_policy(false, &None, &None, &None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn global_policy_edit_requires_the_publish_scope_on_an_administrator_token() {
        use crate::auth::storage::UserData;
        use crate::auth::types::{UserRole, UserStatus};

        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp_dir
                .path()
                .join("users")
                .to_string_lossy()
                .to_string(),
            temp_dir
                .path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap();
        let now = chrono::Utc::now();
        storage
            .save_user(&UserData {
                user_id: "policy-admin".to_string(),
                username: "policy-admin".to_string(),
                passkeys: Vec::new(),
                role: UserRole::Administrator,
                status: UserStatus::Approved,
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
        let storage = Some(Extension(Arc::new(storage)));
        let rbac = Some(Extension(Arc::new(RbacConfig::default())));
        let caller = Some(Extension(AuthGuardOk("policy-admin".to_string())));

        let edit_only = PatContext(Some(vec!["policies.edit".to_string()]));
        assert!(
            matches!(
                require_publish_for_global_policy(true, &storage, &rbac, &caller, Some(&edit_only)).await,
                Err(AppError::Forbidden(_))
            ),
            "an administrator token scoped to policies.edit must not edit an appliance-wide policy"
        );

        let with_publish = PatContext(Some(vec!["policies.edit".to_string(), "policies.publish".to_string()]));
        require_publish_for_global_policy(true, &storage, &rbac, &caller, Some(&with_publish))
            .await
            .unwrap();
        let unscoped = PatContext(None);
        require_publish_for_global_policy(true, &storage, &rbac, &caller, Some(&unscoped))
            .await
            .unwrap();
        require_publish_for_global_policy(true, &storage, &rbac, &caller, None)
            .await
            .unwrap();
    }

    #[test]
    fn canonical_policy_access_combines_tenant_kind_and_id() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope =
            PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:policy-definitions:p1\z").unwrap()));
        assert!(policy_allowed(Some("tenant-a"), "p1", Some(&context), Some(&scope)));
        assert!(policy_allowed(None, "p1", Some(&context), Some(&scope)));
        assert!(!policy_allowed(Some("tenant-b"), "p1", Some(&context), Some(&scope)));
        assert!(!policy_allowed(Some("tenant-a"), "p2", Some(&context), Some(&scope)));
    }

    fn sample_input() -> serde_json::Value {
        serde_json::json!({ "http": { "method": "GET", "path": "/x" } })
    }

    #[test]
    fn simulate_current_version_allows_and_reports_query() {
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let resp = run_policy_simulation(&d, None, None, sample_input()).expect("ok");
        assert!(resp.allow);
        assert_eq!(resp.version, Some(1));
        assert_eq!(resp.query, "data.llm.policy.allow");
        assert_eq!(resp.content_hash, "sha256:seed");
        assert_eq!(resp.policy_type, "llm");
    }

    #[test]
    fn simulate_denies() {
        let d = doc(PolicyType::Llm, DENY_LLM);
        let resp = run_policy_simulation(&d, None, None, sample_input()).expect("ok");
        assert!(!resp.allow);
    }

    #[test]
    fn simulate_draft_overrides_stored_version() {
        // The stored policy allows; a draft deny body is evaluated instead.
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let resp = run_policy_simulation(&d, None, Some(DENY_LLM), sample_input()).expect("ok");
        assert!(!resp.allow, "draft body should be evaluated over the stored version");
        assert_eq!(resp.version, None, "a draft simulation is not attributed to a stored version");
        assert!(
            resp.content_hash
                .starts_with("sha256:")
        );
    }

    #[test]
    fn simulate_unknown_version_is_rejected() {
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let err = run_policy_simulation(&d, Some(99), None, sample_input()).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn simulate_appliance_uses_agentstream_query() {
        let d = doc(PolicyType::Appliance, "package agentstream.policy\nimport rego.v1\ndefault allow := true");
        let resp = run_policy_simulation(&d, None, None, sample_input()).expect("ok");
        assert!(resp.allow);
        assert_eq!(resp.query, "data.agentstream.policy.allow");
    }

    #[test]
    fn simulate_broken_rego_is_rejected() {
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let err =
            run_policy_simulation(&d, None, Some("package llm.policy\nthis is not rego"), sample_input()).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    #[test]
    fn simulate_draft_honors_type_override() {
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let r = resolve_simulation(
            &d,
            None,
            Some("package ide.policy\nimport rego.v1\ndefault allow := true"),
            Some("ide"),
        )
        .expect("resolve");
        assert_eq!(r.query, "data.ide.policy.allow");
        assert_eq!(r.policy_type, "ide");
        assert_eq!(r.version, None);
    }

    #[test]
    fn simulate_unknown_type_override_is_rejected() {
        let d = doc(PolicyType::Llm, ALLOW_LLM);
        let err =
            resolve_simulation(&d, None, Some("package x.policy\ndefault allow := true"), Some("bogus")).unwrap_err();
        assert!(matches!(err, AppError::InvalidInput(_)));
    }

    fn variant_policy_surface(def_id: &str) -> crate::config::agent_surface::AgentSurface {
        use crate::config::agent_surface::{AgentSurface, PolicyRef};
        use crate::config::agent_surface_variants::{SurfaceOverrides, SurfaceVariant, TargetOverrides};

        AgentSurface {
            surface_id: "surf-variant".to_string(),
            default_variant_id: Some("v1".to_string()),
            variants: vec![SurfaceVariant {
                id: "v1".to_string(),
                alias: "default".to_string(),
                name: "Default".to_string(),
                description: String::new(),
                enabled: true,
                overrides: SurfaceOverrides {
                    target: Some(TargetOverrides {
                        policy: Some(PolicyRef {
                            policy_definition_id: def_id.to_string(),
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            }],
            ..Default::default()
        }
    }

    fn gateway(policy: Option<crate::gateways::types::GatewayOpaPolicyConfig>) -> crate::gateways::types::Gateway {
        use crate::gateways::types::{Gateway, GatewayCreationType, GatewayStatus, GatewayType};

        Gateway {
            id: "gw-1".to_string(),
            name: "gw".to_string(),
            description: String::new(),
            did: "did:example:gw".to_string(),
            gateway_type: GatewayType::SelfGateway,
            status: GatewayStatus::Active,
            tenant_id: None,
            creation_type: GatewayCreationType::User,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            exposed_channels: Vec::new(),
            opa_policy_config: policy,
        }
    }

    #[test]
    fn full_recompile_includes_every_enabled_surface() {
        let variant_only = variant_policy_surface("def");
        assert!(!variant_only.opa_enabled(), "the base target carries no policy");
        assert!(surface_in_scope(&variant_only, EngineScope::All));

        let no_policy = crate::config::agent_surface::AgentSurface::default();
        assert!(surface_in_scope(&no_policy, EngineScope::All));

        let disabled = crate::config::agent_surface::AgentSurface {
            status: crate::entity_status::EntityStatus::Disabled,
            ..variant_policy_surface("def")
        };
        assert!(!surface_in_scope(&disabled, EngineScope::All));
    }

    #[test]
    fn targeted_recompile_includes_only_referencing_surfaces() {
        let surface = variant_policy_surface("def");
        assert!(surface_in_scope(&surface, EngineScope::Referencing("def")));
        assert!(!surface_in_scope(&surface, EngineScope::Referencing("other")));
    }

    #[test]
    fn full_recompile_includes_gateways_without_a_policy() {
        assert!(gateway_in_scope(&gateway(None), EngineScope::All));
    }

    #[test]
    fn targeted_recompile_includes_only_gateways_enforcing_the_policy() {
        use crate::gateways::types::GatewayOpaPolicyConfig;

        let config = |enabled| GatewayOpaPolicyConfig {
            enabled,
            policy: String::new(),
            policy_definition_id: Some("def".to_string()),
            policy_definition_ids: Vec::new(),
        };
        assert!(gateway_in_scope(&gateway(Some(config(true))), EngineScope::Referencing("def")));
        assert!(!gateway_in_scope(&gateway(Some(config(true))), EngineScope::Referencing("other")));
        assert!(!gateway_in_scope(&gateway(Some(config(false))), EngineScope::Referencing("def")));
        assert!(!gateway_in_scope(&gateway(None), EngineScope::Referencing("def")));
    }

    #[tokio::test]
    async fn engine_recompile_reports_a_store_it_cannot_read() {
        let temp_dir = tempfile::tempdir().unwrap();
        let not_a_dir = temp_dir
            .path()
            .join("not-a-dir");
        std::fs::write(&not_a_dir, "x").unwrap();
        let not_a_dir = not_a_dir
            .to_string_lossy()
            .to_string();

        let surfaces =
            recompile_surface_engines(&crate::policies::SurfacePolicyManager::new(), &not_a_dir, EngineScope::All)
                .await;
        assert!(surfaces.is_err_and(|e| {
            e.to_string()
                .contains("surface store")
        }));
        let gateways =
            recompile_gateway_engines(&crate::policies::GatewayPolicyManager::new(), &not_a_dir, EngineScope::All)
                .await;
        assert!(gateways.is_err_and(|e| {
            e.to_string()
                .contains("gateway store")
        }));
    }

    #[tokio::test]
    async fn engine_recompile_of_empty_stores_succeeds() {
        let temp_dir = tempfile::tempdir().unwrap();
        let dir = |name: &str| {
            temp_dir
                .path()
                .join(name)
                .to_string_lossy()
                .to_string()
        };

        let surfaces = recompile_surface_engines(
            &crate::policies::SurfacePolicyManager::new(),
            &dir("surfaces"),
            EngineScope::All,
        )
        .await;
        assert_eq!(surfaces.unwrap(), (0, 0));
        let gateways = recompile_gateway_engines(
            &crate::policies::GatewayPolicyManager::new(),
            &dir("gateways"),
            EngineScope::Referencing("unused"),
        )
        .await;
        assert_eq!(gateways.unwrap(), (0, 0));
    }
}
