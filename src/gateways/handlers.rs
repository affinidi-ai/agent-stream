use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::{
    mediators::utils::{fetch_mediator_did_from_url, set_acl_to_peer},
    messages::MessageType,
};

use super::GatewayStore;
use super::connection_points::ConnectionPointStore;
use super::connection_points::ws_listener::{ConnectionPointListenerManager, ListenerInfo};
use super::surface_cache::GatewaySurfaceCache;
use super::types::{Gateway, GatewayStatus, GatewayType};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::comm::didcomm::client::DIDCommClient;
use crate::marketplace_models::MarketplaceModelStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, tenant_for_create,
};

/// Request body for creating a gateway
#[derive(Debug, Deserialize)]
pub struct CreateGatewayRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
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

pub(crate) fn gateway_allowed(
    gateway: &Gateway,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(gateway.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Gateways, &gateway.id)
}

/// Request body for updating a gateway
#[derive(Debug, Deserialize)]
pub struct UpdateGatewayRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub status: Option<GatewayStatus>,
}

/// Request body for updating exposed channels
#[derive(Debug, Deserialize)]
pub struct UpdateExposedChannelsRequest {
    pub exposed_channels: Vec<String>,
}

/// Derive the effective status of a remote gateway from its connection points'
/// persisted runtime health (status precedence).
///
/// Precedence: explicit workflow / manual states (AwaitingApproval, Disabled,
/// Pending) are preserved as-is; otherwise a live listener or a `Connected`
/// connection point means Active, any connection point with recorded-but-
/// unhealthy runtime means Failed, and no runtime information yet means Pending.
/// This surfaces broken connectivity as `failed` rather than a misleading
/// `pending`, and is correct on standby nodes (which hold no live listeners)
/// because it reads the persisted connection-point runtime status.
fn effective_remote_gateway_status(
    current: GatewayStatus,
    has_active_listener: bool,
    connection_points: &[crate::gateways::connection_points::types::GatewayConnectionPoint],
) -> GatewayStatus {
    use crate::comm::connection_health::ConnectionStatus;

    // Preserve explicit workflow / manual states.
    if matches!(current, GatewayStatus::AwaitingApproval | GatewayStatus::Disabled | GatewayStatus::Pending) {
        return current;
    }

    if has_active_listener {
        return GatewayStatus::Active;
    }

    // No live listener (broken, or this node is a follower holding none): fall
    // back to the persisted connection-point runtime health.
    let mut any_connected = false;
    let mut any_runtime = false;
    for cp in connection_points {
        if let Some(runtime) = &cp.runtime_status {
            any_runtime = true;
            if matches!(runtime.status, ConnectionStatus::Connected) {
                any_connected = true;
                break;
            }
        }
    }

    if any_connected {
        GatewayStatus::Active
    } else if any_runtime {
        GatewayStatus::Failed
    } else {
        GatewayStatus::Pending
    }
}

/// Pick a representative runtime status for a gateway from its connection
/// points, so the list view can show *why* a gateway is failed even though the
/// underlying OOB/system connection points are hidden from the CP list. Prefers
/// a `Connected` connection point; otherwise the first unhealthy one.
fn representative_runtime_status(
    connection_points: &[crate::gateways::connection_points::types::GatewayConnectionPoint]
) -> Option<crate::comm::connection_health::ConnectionRuntimeStatus> {
    use crate::comm::connection_health::ConnectionStatus;

    let mut fallback = None;
    for cp in connection_points {
        if let Some(runtime) = &cp.runtime_status {
            if matches!(runtime.status, ConnectionStatus::Connected) {
                return Some(runtime.clone());
            }
            if fallback.is_none() {
                fallback = Some(runtime.clone());
            }
        }
    }
    fallback
}

/// A gateway plus its derived connection health for the list view.
///
/// `runtime_status` is derived from the gateway's connection points (including
/// the hidden OOB/system ones) and is not persisted on the gateway record.
#[derive(Debug, Serialize)]
pub struct GatewayListItem {
    #[serde(flatten)]
    pub gateway: Gateway,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_status: Option<crate::comm::connection_health::ConnectionRuntimeStatus>,
}

/// List all gateways
pub async fn list_gateways<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    Extension(cp_store): Extension<Option<Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<GatewayListItem>>, (StatusCode, String)> {
    let mut gateways = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {}", e)))?;
    gateways.retain(|gateway| gateway_allowed(gateway, &context, &scope));

    // Group connection points by gateway once (avoids a per-gateway scan).
    let cps_by_gateway: std::collections::HashMap<String, Vec<_>> = match cp_store.as_ref() {
        Some(store) => {
            let mut map: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for cp in store
                .list_all()
                .await
                .unwrap_or_default()
            {
                map.entry(cp.gateway_id.clone())
                    .or_default()
                    .push(cp);
            }
            map
        }
        None => std::collections::HashMap::new(),
    };

    // Only derive status when the listener infrastructure is present (preserves
    // prior behavior when it is not). Runtime status is attached whenever
    // connection-point health is available.
    let active_listeners = match listener_manager.as_ref() {
        Some(manager) => Some(
            manager
                .get_active_listeners()
                .await,
        ),
        None => None,
    };

    let items = gateways
        .into_iter()
        .map(|mut gateway| {
            // Skip self gateway - it's always considered active.
            if gateway.gateway_type == GatewayType::SelfGateway {
                return GatewayListItem { gateway, runtime_status: None };
            }

            let empty: Vec<crate::gateways::connection_points::types::GatewayConnectionPoint> = Vec::new();
            let cps = cps_by_gateway
                .get(&gateway.id)
                .unwrap_or(&empty)
                .as_slice();
            let runtime_status = representative_runtime_status(cps);

            if let Some(listeners) = active_listeners.as_ref() {
                let has_listener = listeners
                    .iter()
                    .any(|listener| listener.gateway_id == gateway.id);
                gateway.status = effective_remote_gateway_status(gateway.status.clone(), has_listener, cps);
            }

            GatewayListItem { gateway, runtime_status }
        })
        .collect();

    Ok(Json(items))
}

/// Get a gateway by ID
pub async fn get_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    // Trigger gateway.accessed integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway.clone();
        crate::observability::spawn_traced_task("integration.gateway_accessed", async move {
            crate::integrations::trigger_gateway_accessed(notif.as_ref(), &gateway_clone).await;
        });
    }

    Ok(Json(gateway))
}

/// Create a new gateway
pub async fn create_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    if let Err(e) = crate::config::enforce_add("connections.gateways").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    let mut gateway = Gateway::new(req.name, req.description, req.did, GatewayType::Remote);
    gateway.tenant_id = req.tenant_id;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    store
        .create(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store gateway: {}", e)))?;

    // Trigger gateway.created integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway.clone();
        crate::observability::spawn_traced_task("integration.gateway_created", async move {
            crate::integrations::trigger_gateway_created(notif.as_ref(), &gateway_clone).await;
        });
    }

    Ok(Json(gateway))
}

/// Update a gateway
pub async fn update_gateway<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    // Clone old gateway state for integration trigger
    let old_gateway = gateway.clone();

    if let Some(name) = req.name {
        gateway.name = name;
    }
    if let Some(description) = req.description {
        gateway.description = description;
    }
    // DID cannot be changed after creation - ignore req.did
    if let Some(status) = req.status {
        gateway.status = status;
    }

    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    // Trigger gateway.updated integration
    if let Some(notif) = notif_store.as_ref() {
        crate::integrations::trigger_gateway_updated(notif.as_ref(), &old_gateway, &gateway).await;
    }

    Ok(Json(gateway))
}

/// Update exposed channels for a gateway
pub async fn update_gateway_exposed_surfaces<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(surface_store): Extension<Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateExposedChannelsRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    if !req
        .exposed_channels
        .is_empty()
    {
        let surface_store = surface_store
            .as_ref()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Surface store not configured".to_string()))?;
        for surface_id in &req.exposed_channels {
            let surface = surface_store
                .get(surface_id)
                .await
                .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()))?;
            if !can_reference(gateway.tenant_id.as_deref(), surface.tenant_id.as_deref())
                || !scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Surfaces,
                    &surface.surface_id,
                )
            {
                return Err((StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()));
            }
        }
    }

    gateway.exposed_channels = req.exposed_channels;
    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    Ok(Json(gateway))
}

/// Request body for updating a gateway's OPA policy
#[derive(Debug, Deserialize)]
pub struct UpdateGatewayPolicyRequest {
    pub opa_policy_config: Option<crate::gateways::types::GatewayOpaPolicyConfig>,
}

/// Response for gateway policy operations
#[derive(Debug, Serialize)]
pub struct GatewayPolicyResponse {
    pub opa_policy_config: Option<crate::gateways::types::GatewayOpaPolicyConfig>,
}

/// Get the OPA policy for a gateway
pub async fn get_gateway_policy<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayPolicyResponse>, (StatusCode, String)> {
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    Ok(Json(GatewayPolicyResponse {
        opa_policy_config: gateway.opa_policy_config,
    }))
}

/// Update the OPA policy for a gateway
pub async fn update_gateway_policy<S: GatewayStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_policy_manager): Extension<Option<Arc<crate::policies::GatewayPolicyManager>>>,
    Extension(policy_definition_store): Extension<Option<Arc<crate::policies::FileSystemPolicyDefinitionStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateGatewayPolicyRequest>,
) -> Result<Json<GatewayPolicyResponse>, (StatusCode, String)> {
    let mut gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }
    let gateway_policy_manager = gateway_policy_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Gateway policy runtime is unavailable".to_string()))?;

    // A gateway references a reusable policy definition by id; the Rego is
    // resolved at compile time from that definition (the single source of truth)
    // and is never copied into the gateway record. Validate the reference here
    // and drop any stale inline Rego so the stored gateway carries only the id.
    let mut resolved_config = req.opa_policy_config;
    if let Some(ref mut policy_config) = resolved_config
        && policy_config.enabled
    {
        let def_ids = policy_config.all_policy_definition_ids();
        if def_ids.is_empty() {
            // Legacy / hand-authored inline Rego — validate its syntax.
            if !policy_config
                .policy
                .trim()
                .is_empty()
            {
                let test_engine = crate::policies::OpaEngine::new();
                if let Err(e) = crate::policies::validate_policy_inputs(&policy_config.policy)
                    .and_then(|()| test_engine.load_policy("validation_test", &policy_config.policy))
                {
                    return Err((StatusCode::BAD_REQUEST, format!("Invalid Rego policy: {}", e)));
                }
            }
        } else {
            // Reference-only: every referenced definition must exist; the Rego is
            // resolved from the definitions at compile time under deny-overrides.
            let Some(ref def_store) = policy_definition_store else {
                return Err((StatusCode::INTERNAL_SERVER_ERROR, "Policy definition store not configured".to_string()));
            };
            for def_id in &def_ids {
                let definition = def_store
                    .get(def_id)
                    .await
                    .ok_or_else(|| (StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()))?;
                if !can_reference(
                    gateway.tenant_id.as_deref(),
                    definition
                        .tenant_id
                        .as_deref(),
                ) || !scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::PolicyDefinitions,
                    &definition.id,
                ) {
                    return Err((StatusCode::BAD_REQUEST, "Policy definition is not accessible".to_string()));
                }
            }
            // Never persist a copy of any definition's Rego on the gateway.
            policy_config.policy = String::new();
        }
    }

    gateway.opa_policy_config = resolved_config;
    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    gateway_policy_manager
        .update_gateway_policy(&gateway)
        .await
        .map_err(|e| {
            error!(gateway_id = %id, "Failed to update gateway policy engine: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "Gateway policy was saved but runtime enforcement failed; requests will be denied until synchronization succeeds"
                    .to_string(),
            )
        })?;

    info!(gateway_id = %id, "Gateway OPA policy updated");

    Ok(Json(GatewayPolicyResponse {
        opa_policy_config: gateway.opa_policy_config,
    }))
}

/// Delete a gateway
pub async fn delete_gateway<S: GatewayStore, P: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(connection_point_store): Extension<std::sync::Arc<P>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(notif_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Check if this is a self gateway
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    if gateway.gateway_type == GatewayType::SelfGateway {
        return Err((StatusCode::FORBIDDEN, "Cannot delete self gateway".to_string()));
    }

    // Clone gateway for trigger before deletion
    let gateway_for_trigger = gateway.clone();

    // Stop all WebSocket listeners for connection points associated with this gateway
    // and delete system-created connection points (user-created ones are kept)
    match connection_point_store
        .list_by_gateway(&id)
        .await
    {
        Ok(connection_points) => {
            for cp in connection_points {
                // Stop the listener
                if let Err(e) = listener_manager
                    .stop_listener(&cp.id)
                    .await
                {
                    warn!("Failed to stop listener for connection point {}: {}", cp.id, e);
                } else {
                    info!("Stopped listener for connection point {} (gateway {})", cp.id, id);
                }

                // Delete system-created connection points (they're tied to this gateway)
                // Keep user-created connection points (they may be reused)
                if cp.cp_type != crate::gateways::connection_points::ConnectionPointType::User {
                    if let Err(e) = connection_point_store
                        .delete(&cp.id)
                        .await
                    {
                        warn!("Failed to delete system connection point {}: {}", cp.id, e);
                    } else {
                        info!("Deleted system connection point {} for gateway {}", cp.id, id);
                    }
                }
            }
        }
        Err(e) => {
            warn!("Failed to list connection points for gateway {}: {}", id, e);
        }
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete gateway: {}", e)))?;

    info!("Deleted gateway {} and stopped all associated listeners", id);

    // Trigger gateway.deleted integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        let notif = notif.clone();
        let gateway_clone = gateway_for_trigger.clone();
        crate::observability::spawn_traced_task("integration.gateway_deleted", async move {
            crate::integrations::trigger_gateway_deleted(notif.as_ref(), &gateway_clone).await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Request body for connecting to a gateway via OOB
#[derive(Debug, Deserialize)]
pub struct ConnectViaOOBRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub oob_url: String,
    pub secret: String,
    pub name: String,
    pub description: String,
    #[serde(default)]
    pub did_method: Option<crate::gateways::connection_points::types::ConnectionPointDidMethod>,
}

/// Response for connecting to a gateway via OOB
#[derive(Debug, Serialize)]
pub struct ConnectViaOOBResponse {
    pub gateway: Gateway,
}

/// Connect to a remote gateway using an OOB (Out-of-Band) invitation link
pub async fn connect_via_oob<
    S: GatewayStore + 'static,
    P: ConnectionPointStore + 'static,
    M: crate::mediators::MediatorStore,
>(
    Extension(store): Extension<Arc<S>>,
    Extension(cp_store): Extension<Arc<P>>,
    Extension(_mediator_store): Extension<Arc<M>>,
    Extension(_vc_issuer): Extension<Arc<crate::identity::VCIssuer>>,
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(network_config): Extension<Arc<crate::config::NetworkConfig>>,
    Extension(pending_store): Extension<Arc<crate::gateways::PendingConnectionStore>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    #[cfg(feature = "didwebvh")] Extension(log_storage): Extension<
        Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    >,
    #[cfg(feature = "didwebvh")] Extension(identity_store): Extension<
        Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    >,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<ConnectViaOOBRequest>,
) -> Result<Json<ConnectViaOOBResponse>, (StatusCode, String)> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let pending_gateway_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Gateways,
        &pending_gateway_id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }
    let safe_oob_url = crate::url_validation::redact_url_for_logging(&req.oob_url);

    // Enforce the appliance gateway limit before initiating an outbound connection.
    if let Err(e) = crate::config::enforce_add("connections.gateways").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("🔗 Starting OOB connection flow (ACCEPTOR role)");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  OOB URL: {}", safe_oob_url);
    info!("  Gateway Name: {}", req.name);
    info!("  Gateway Description: {}", req.description);
    info!("  IMPORTANT: ACCEPTOR does not need a mediator configured");
    info!("  Messages will be sent to inviter's mediator (from OOB URL)");
    info!("");

    if let Err(e) = crate::url_validation::validate_service_endpoint_url(&req.oob_url).await {
        error!("❌ OOB URL blocked: {}", e);
        return Err((StatusCode::BAD_REQUEST, format!("OOB URL blocked: {}", e)));
    }

    // The DIDComm client for the acceptor's temporary DID is built in Step 6,
    // once that DID and its secrets have been generated. The OOB invitation is
    // retrieved with a self-contained temporary client (Step 2).

    // Step 2: Retrieve the OOB invitation
    info!("📥 Step 2: Retrieving OOB invitation from URL...");
    info!("  URL: {}", safe_oob_url);
    let invitation_message = DIDCommClient::retrieve_oob_invite(&req.oob_url)
        .await
        .map_err(|e| {
            error!("❌ Failed to retrieve OOB invitation: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to retrieve OOB invitation: {}", e))
        })?;

    info!("✓ OOB invitation retrieved successfully");
    info!("  Invitation ID: {}", invitation_message.id);
    info!("  Invitation from: {:?}", invitation_message.from);
    info!("  Invitation type: {}", invitation_message.typ);
    info!("");

    // Step 3: Extract inviter's temporary DID (used for handshake)
    info!("🔍 Step 3: Extracting inviter's temporary DID...");
    let inviter_temporary_did = invitation_message
        .from
        .ok_or_else(|| {
            error!("❌ Invitation missing 'from' field");
            (StatusCode::BAD_REQUEST, "Invitation missing 'from' field".to_string())
        })?;

    info!("✓ Inviter's temporary DID extracted: {}", inviter_temporary_did);
    info!("");

    // Check if already connected
    info!("🔍 Step 4: Checking for existing gateway connection...");
    if let Ok(Some(existing_gateway)) = store
        .get_by_did(&inviter_temporary_did)
        .await
    {
        if !gateway_allowed(&existing_gateway, &context, &scope) {
            return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
        }
        info!("⚠️  Gateway already exists for DID {}", inviter_temporary_did);
        info!("  Gateway ID: {}", existing_gateway.id);
        info!("  Returning existing gateway instead of creating new connection");
        return Ok(Json(ConnectViaOOBResponse { gateway: existing_gateway }));
    }
    info!("✓ No existing gateway found - proceeding with new connection");
    info!("");

    // Step 5: Extract inviter's mediator from OOB URL
    info!("🔍 Step 5: Extracting inviter's mediator endpoint from OOB URL...");
    let their_mediator_endpoint = req
        .oob_url
        .split("/oob")
        .next()
        .ok_or_else(|| {
            error!("❌ Invalid OOB URL format - missing /oob path");
            (StatusCode::BAD_REQUEST, "Invalid OOB URL format".to_string())
        })?
        .to_string();
    info!("  Mediator endpoint: {}", crate::url_validation::redact_url_for_logging(&their_mediator_endpoint));

    // Convert mediator endpoint to DID (replace / with : for did:web format)
    // https://fabric-mediator-1.example.com/mediator/v1 -> did:web:fabric-mediator-1.example.com:mediator:v1:.well-known
    let their_mediator_did = fetch_mediator_did_from_url(&their_mediator_endpoint)
        .await
        .map_err(|e| {
            error!("❌ Failed to fetch inviter's mediator DID from URL: {}", e);
            (StatusCode::BAD_REQUEST, format!("Failed to fetch inviter's mediator DID from URL: {}", e))
        })?;

    info!("✓ Inviter's mediator DID: {}", their_mediator_did);
    info!("");

    // Step 6: Create TWO DIDs for proper OOB flow
    info!("🔑 Step 6: Creating temporary DID for handshake...");
    info!("  DID #1: Temporary (ephemeral) - used only for initial handshake");

    let temp_cp_id = uuid::Uuid::new_v4().to_string();
    info!("  Temporary CP ID: {}", temp_cp_id);
    info!("  Generating identity...");

    let did_method = req
        .did_method
        .as_ref()
        .unwrap_or(&crate::gateways::connection_points::types::ConnectionPointDidMethod::Web);

    let (temporary_did, temp_secrets, _temp_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &temp_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &their_mediator_endpoint,
            did_method,
            #[cfg(feature = "didwebvh")]
            log_storage.clone(),
            #[cfg(feature = "didwebvh")]
            identity_store.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ Failed to generate temporary DID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate temporary DID: {}", e))
        })?;

    info!("✓ Temporary DID created: {}", temporary_did);
    info!("  Number of secrets: {}", temp_secrets.len());

    // Build the DIDComm client for the acceptor's temporary DID (creates the ATM
    // and profile; registration/authentication happens in Step 11). Its resolver
    // cache holds the inviter's DID document for encryption (Step 9.5).
    info!("  Building DIDComm client for temporary DID...");
    let mut client = DIDCommClient::new(
        temporary_did.clone(),
        temp_secrets,
        Some(their_mediator_did.clone()),
        Some(format!("oob-acceptor-{}", temp_cp_id)),
    )
    .await
    .map_err(|e| {
        error!("❌ Failed to build DIDComm client: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build DIDComm client: {}", e))
    })?;
    info!("✓ DIDComm client built for temporary DID (can now sign/encrypt messages)");
    info!("");

    // Step 7: Create secure DID #2 (permanent connection)
    info!("🔑 Step 7: Creating secure DID for permanent connection...");
    info!("  DID #2: Secure (permanent) - used for actual connection after handshake");

    let secure_cp_id = uuid::Uuid::new_v4().to_string();
    info!("  Secure CP ID: {}", secure_cp_id);
    info!("  Generating identity...");

    let (secure_did, _secure_secrets, _secure_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &secure_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &their_mediator_endpoint,
            did_method,
            #[cfg(feature = "didwebvh")]
            log_storage.clone(),
            #[cfg(feature = "didwebvh")]
            identity_store.clone(),
        )
        .await
        .map_err(|e| {
            error!("❌ Failed to generate secure DID: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate secure DID: {}", e))
        })?;

    info!("✓ Secure DID created: {}", secure_did);
    info!("");

    // Step 8: Store pending connection state (so we can complete handshake when connection-accepted arrives)
    info!("💾 Step 8: Storing pending connection state...");
    // Note: We store the inviter's mediator DID (not ours, since we don't have one on ACCEPTOR side)
    let pending_connection = crate::gateways::PendingOOBConnection {
        id: invitation_message.id.clone(),
        invitation_id: invitation_message.id.clone(),
        our_temporary_did: temporary_did.clone(),
        our_secure_did: secure_did.clone(),
        their_temporary_did: inviter_temporary_did.clone(),
        their_secure_did: None, // Will be set when we receive connection-accepted
        mediator_did: their_mediator_did.clone(), // Store inviter's mediator
        connection_point_id: String::new(), // No connection point needed for OOB
        role: crate::gateways::ConnectionRole::Acceptor,
        state: crate::gateways::ConnectionState::WaitingForResponse,
        created_at: chrono::Utc::now(),
        expires_at: chrono::Utc::now() + chrono::Duration::hours(1),
        secure_cp_id: Some(secure_cp_id.clone()),
        temporary_cp_id: Some(temp_cp_id.clone()),
    };

    info!("  Pending connection details:");
    info!("    ID: {}", pending_connection.id);
    info!("    Our temporary DID: {}", pending_connection.our_temporary_did);
    info!("    Our secure DID: {}", pending_connection.our_secure_did);
    info!("    Their temporary DID: {}", pending_connection.their_temporary_did);
    info!("    Mediator DID: {}", pending_connection.mediator_did);
    info!("    Role: {:?}", pending_connection.role);
    info!("    State: {:?}", pending_connection.state);

    pending_store
        .store(pending_connection)
        .await;
    info!("✓ Pending connection state stored");
    info!("");

    // Step 9: Build connection-setup message
    info!("📝 Step 9: Building connection-setup message...");

    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let connection_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ConnectionSetup.to_string(),
        json!({
            "channel_did": secure_did.clone(),
            "secret": req.secret.clone()
        }), // Send SECURE DID and secret for validation
    )
    .from(temporary_did.clone()) // Send FROM temporary DID
    .to(inviter_temporary_did.clone()) // Send TO their temporary DID
    .thid(uuid::Uuid::new_v4().to_string())
    .pthid(invitation_message.id.clone())
    .finalize();

    info!("✓ Connection-setup message built:");
    info!("    Message ID: {}", connection_message.id);
    info!("    Type: {}", connection_message.typ);
    info!("    From: {}", temporary_did);
    info!("    To: {}", inviter_temporary_did);
    info!("    Body: channel_did={}", secure_did);
    info!("    Body: secret=[REDACTED]");
    info!("");

    // Step 9.5: Pre-resolve and cache the inviter's DID document
    info!("🔍 Step 9.5: Pre-resolving inviter's DID document for encryption...");
    info!("  Target DID: {}", inviter_temporary_did);
    info!("  Note: This caches the DID so encryption succeeds even if gateway is temporarily offline");

    // Get DID cache from listener manager
    let did_cache = listener_manager
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Listener manager not available".to_string()))?
        .get_did_cache();

    // Resolve the DID and cache it, also populate ATM's cache
    match did_cache
        .resolve_and_cache_for_atm(&inviter_temporary_did, client.tdk_state())
        .await
    {
        Ok((_, was_cached)) => {
            if was_cached {
                info!("✓ Using cached DID document for {}", inviter_temporary_did);
            } else {
                info!("✓ DID document resolved and cached for {}", inviter_temporary_did);
            }
        }
        Err(e) => {
            error!("❌ Failed to resolve inviter's DID document: {}", e);
            error!("  The remote gateway may be offline or DID unreachable");
            error!("  DID: {}", inviter_temporary_did);
            return Err((
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Cannot resolve inviter's DID document: {}. The gateway may be offline or the DID document is unreachable.",
                    e
                ),
            ));
        }
    }
    info!("");

    // Step 10: Pack message encrypted
    info!("🔒 Step 10: Encrypting message...");
    info!("  To (recipient DID): {}", inviter_temporary_did);
    info!("  From (sender DID): {}", temporary_did);
    info!("  Sign with: {}", temporary_did);
    info!("  Note: Using pre-cached DID document from Step 9.5");

    let packed = client.atm().pack_encrypted(
        &connection_message,
        &inviter_temporary_did,
        Some(&temporary_did),
        Some(&temporary_did),
    ).await
    .map_err(|e| {
        let error_msg = format!("{:?}", e);
        error!("❌ Failed to pack/encrypt message: {}", error_msg);

        // Check for DID resolution errors
        if error_msg.contains("resolve") || error_msg.contains("not found") || error_msg.contains("404") || error_msg.contains("unreachable") {
            error!("  ⚠️  CONNECTION POINT DID COULD NOT BE RESOLVED");
            error!("  The inviter's DID document is unavailable (gateway may be offline)");
            error!("  DID: {}", inviter_temporary_did);
            error!("  This should not happen if Step 9.5 succeeded");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Connection point DID could not be resolved: {}. The gateway may be offline or the DID document is unreachable at its web location.",
                    inviter_temporary_did
                )
            );
        }

        // Check for signing/secret errors
        if error_msg.contains("Secret not found") || error_msg.contains("signer") {
            error!("  ⚠️  SIGNING KEY NOT FOUND");
            error!("  The temporary DID secrets are not available in ATM");
            error!("  This is a configuration issue on the acceptor side");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to sign message: temporary DID secrets not found in ATM: {:?}", e)
            );
        }

        // Generic encryption error
        error!("  Unknown encryption error - check logs for details");
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to pack message: {:?}", e))
    })?;

    info!("✓ Message encrypted and packed ({} bytes)", packed.0.len());
    info!("");

    // Step 11: Create ATM profile with inviter's mediator and send message via WebSocket
    info!("📤 Step 11: Connecting to inviter's mediator and sending message...");
    info!("  Target mediator DID: {}", their_mediator_did);
    info!("  Target recipient DID: {}", inviter_temporary_did);
    info!("  Using ATM SDK with WebSocket (authentication handled automatically)");

    // The ACL update is a Trust Task whose reply only arrives reliably over a
    // live WebSocket. The WebSocket is shut down before the temporary listener
    // starts so the two never compete for connection-accepted.
    info!("  🔐 Registering temp profile with mediator...");
    client
        .enable_websocket()
        .await
        .map_err(|e| {
            error!("❌ Failed to register temp profile with mediator: {}", e);
            error!("  Mediator DID: {}", their_mediator_did);
            error!("  Our DID: {}", temporary_did);
            (StatusCode::UNAUTHORIZED, format!("Failed to register temp profile with mediator: {}", e))
        })?;
    info!("  ✓ temp profile registered with mediator");

    let send_result = async {
        info!("🔐 Restricting temporary DID delivery to the inviter...");
        set_acl_to_peer(client.atm().as_ref(), Arc::clone(client.profile()), &inviter_temporary_did)
            .await
            .map_err(|error| {
                error!("Failed to restrict temporary DID delivery: {error}");
                (StatusCode::BAD_GATEWAY, "Mediator rejected the temporary connection ACL".to_string())
            })?;

        info!("  📨 Sending message via WebSocket...");
        client
            .atm()
            .send_message(
                client.profile(),
                &packed.0,
                &connection_message.id,
                false, // Don't wait for response
                false, // Don't auto-delete
            )
            .await
            .map_err(|e| {
                error!("❌ Failed to send connection-setup via ATM: {:?}", e);
                error!("  Profile DID: {}", client.profile().inner.did);
                error!("  Mediator DID: {}", their_mediator_did);
                error!("  Message ID: {}", connection_message.id);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send connection-setup: {:?}", e))
            })
    }
    .await;

    client
        .atm()
        .graceful_shutdown()
        .await;
    send_result?;

    info!("✓ Connection-setup sent successfully via WebSocket to inviter's mediator");
    info!("");
    info!("⏳ Step 12: Creating pending gateway and temporary connection point listener...");
    info!("  The inviter will receive our connection-setup message");
    info!("  They will send connection-accepted back");

    // Create and store pending gateway FIRST (so we have the ID for the listener)
    let mut pending_gateway =
        Gateway::new(req.name.clone(), req.description.clone(), inviter_temporary_did.clone(), GatewayType::Remote);

    pending_gateway.id = pending_gateway_id;
    pending_gateway.tenant_id = req.tenant_id;
    // Set status to Pending
    pending_gateway.status = GatewayStatus::Pending;

    // Store the pending gateway so it shows up in the gateway list
    store
        .create(&pending_gateway)
        .await
        .map_err(|e| {
            error!("❌ Failed to create pending gateway: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create pending gateway: {}", e))
        })?;

    info!("  ✓ Pending gateway created with ID: {}", pending_gateway.id);

    // Check if listener manager is available
    let listener_mgr = listener_manager.ok_or_else(|| {
        error!("❌ Listener manager not available");
        (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available - cannot start listener".to_string())
    })?;

    // Calculate expiry time from config
    let expiry_hours = bootstrap_config
        .oob_connection
        .pending_expiry_hours;
    let expires_at = chrono::Utc::now() + chrono::Duration::hours(expiry_hours as i64);

    info!("  Creating temporary connection point for receiving connection-accepted...");
    info!("  Expiry: {} hours from now ({})", expiry_hours, expires_at.format("%Y-%m-%d %H:%M:%S UTC"));

    // Create temporary connection point with expiry metadata
    // temp_cp_id (UUID) was set in Step 6 and matches the directory where keys were saved
    let mut temp_connection_point = super::connection_points::types::GatewayConnectionPoint::new(
        pending_gateway.id.clone(),
        their_mediator_did.clone(),
        temporary_did.clone(),
        format!("Temporary listener for pending gateway {}", &pending_gateway.id[..8]),
        format!(
            "Awaiting connection-accepted from {}",
            &inviter_temporary_did[inviter_temporary_did
                .len()
                .saturating_sub(12)..]
        ),
        String::new(),
        String::new(),
        serde_json::json!({
            "expires_at": expires_at,
            "pending_gateway_id": pending_gateway.id,
            "inviter_temporary_did": inviter_temporary_did
        }),
        Some(expires_at),
        super::connection_points::types::ConnectionPointType::System, // Temporary system CP
        String::new(),
    );
    temp_connection_point.id = temp_cp_id.clone();
    temp_connection_point.did_method = did_method.clone();

    // Store the temporary connection point
    cp_store
        .create(&temp_connection_point)
        .await
        .map_err(|e| {
            error!("❌ Failed to create temporary connection point: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create temporary connection point: {}", e))
        })?;

    info!("  ✓ Temporary connection point created: {}", temp_cp_id);

    // Start WebSocket listener for the temporary connection point
    info!("  Starting WebSocket listener (not polling!)...");
    listener_mgr
        .request_start_listener(temp_connection_point, their_mediator_did.clone())
        .map_err(|e| {
            error!("❌ Failed to start temporary listener: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to start temporary listener: {}", e))
        })?;

    info!("  ✓ WebSocket listener started for temporary DID");
    info!("  Listener will automatically stop when connection-accepted is received or after {} hours", expiry_hours);
    info!("");

    // Step 13: Return with pending gateway
    info!("✅ OOB connection initiated successfully!");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("");

    Ok(Json(ConnectViaOOBResponse { gateway: pending_gateway }))
}

/// Response body for gateway ping
#[derive(Debug, Serialize)]
pub struct GatewayPingResponse {
    pub success: bool,
    pub message: String,
    pub round_trip_ms: Option<u64>,
}

/// How long a gateway-ping timeout waits for the mediator to return our own
/// account.
const ACCOUNT_PROBE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

/// The problem-report code a mediator answers with when it no longer has the
/// requesting account.
const ACCOUNT_NOT_FOUND_CODE: &str = "e.p.account.not_found";

type AccountProbe = Result<
    Result<trust_tasks_rs::specs::messaging::account::get::v0_1::Account, affinidi_messaging_sdk::errors::ATMError>,
    tokio::time::error::Elapsed,
>;

/// What a gateway-ping timeout leads to once our own mediator account has been
/// probed.
#[derive(Debug, PartialEq, Eq)]
enum PingTimeoutRecovery {
    /// The remote gateway did not answer, or our account could not be read.
    ReportTimeout,
    /// The mediator no longer has our account: restart the listener so it
    /// re-authenticates and re-applies its ACL.
    RestartListener,
}

fn ping_timeout_recovery(probe: &AccountProbe) -> PingTimeoutRecovery {
    match probe {
        Ok(Err(affinidi_messaging_sdk::errors::ATMError::ProblemReport(code, _, _)))
            if code == ACCOUNT_NOT_FOUND_CODE =>
        {
            PingTimeoutRecovery::RestartListener
        }
        _ => PingTimeoutRecovery::ReportTimeout,
    }
}

/// A gateway-ping timeout is ambiguous: the remote gateway may be down or
/// slow, or the mediator may have lost our account (e.g. a store flush) while
/// the listener's socket stays open, so nothing reaches it any more. Probe our
/// own account and, when the mediator reports it missing, restart the listener
/// in the background so the ping answers without waiting for the reconnect.
async fn recover_after_ping_timeout(
    request_id: uuid::Uuid,
    manager: &Arc<ConnectionPointListenerManager>,
    gateway_listener: &ListenerInfo,
) {
    let probe: AccountProbe = tokio::time::timeout(
        ACCOUNT_PROBE_TIMEOUT,
        gateway_listener
            .client
            .atm()
            .trust_tasks()
            .account_get(
                gateway_listener
                    .client
                    .profile(),
                None,
            ),
    )
    .await;

    match ping_timeout_recovery(&probe) {
        PingTimeoutRecovery::ReportTimeout => {
            debug!("[{request_id}] Mediator account probe after ping timeout: {:?}", probe.map(|r| r.map(|_| ())));
        }
        PingTimeoutRecovery::RestartListener => {
            warn!(
                "[{request_id}] Mediator no longer has the account of connection point '{}'; restarting its listener to re-authenticate",
                gateway_listener.name
            );
            let manager = Arc::clone(manager);
            let connection_point_id = gateway_listener
                .connection_point_id
                .clone();
            let generation = gateway_listener.generation();
            tokio::spawn(async move {
                if let Err(e) = manager
                    .restart_listener_if_current(&connection_point_id, generation)
                    .await
                {
                    warn!("[{request_id}] Connection point restart failed: {}", e);
                }
            });
        }
    }
}

/// Send a ping message to a gateway to test connectivity
pub async fn ping_gateway<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GatewayPingResponse>, (StatusCode, String)> {
    let request_id = uuid::Uuid::new_v4();
    info!("[{request_id}] Ping requested for gateway: {}", id);

    let total_start = std::time::Instant::now();

    // Get gateway
    let gateway = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".into()));
    }

    info!("[{request_id}] Gateway found: {} (DID: {})", gateway.name, gateway.did);

    // Check if gateway is active
    if gateway.status != GatewayStatus::Active {
        warn!("[{request_id}] Gateway is not active (status: {:?})", gateway.status);
        return Ok(Json(GatewayPingResponse {
            success: false,
            message: format!("Gateway is not active (status: {:?})", gateway.status),
            round_trip_ms: None,
        }));
    }

    // Get listener manager
    let manager = listener_manager
        .as_ref()
        .ok_or_else(|| {
            (StatusCode::SERVICE_UNAVAILABLE, "Connection point listener manager not available".to_string())
        })?;

    info!("[{request_id}] Looking for gateway with ID: {}", id);

    // The gateway index points at the gateway's most recently registered
    // listener, so an acceptor's temporary point that is still being removed
    // after pairing is never chosen over its permanent one.
    let gateway_listener = manager
        .get_listener(&id)
        .await
        .ok_or_else(|| {
            error!("[{request_id}] No active connection point listener found for gateway '{}'", id);
            error!("[{request_id}] This usually means:");
            error!("[{request_id}]   1. You accepted an OOB invitation but don't have your own connection point");
            error!("[{request_id}]   2. The remote gateway needs to accept YOUR OOB invitation for bidirectional communication");
            error!("[{request_id}]   3. You need to create a connection point to receive messages");
            (StatusCode::SERVICE_UNAVAILABLE, format!("No active connection point listener found for gateway. Gateway ping requires bidirectional communication. No listener matched gateway ID '{}'. Create an OOB invitation and have the remote gateway accept it to enable bidirectional messaging.", id))
        })?;

    info!(
        "[{request_id}] Using connection point listener: {} (DID: {})",
        gateway_listener.name, gateway_listener.gateway_did
    );

    let start = std::time::Instant::now();

    // Build ping message using MessageType enum
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let ping_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::GatewayPing.to_string(),
        json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(gateway.did.clone())
    .finalize();

    info!("[{request_id}] 🔵 Sending ping message (ID: {})...", ping_message.id);

    // Pre-resolve and cache the gateway DID
    if let Some(listener_mgr) = &listener_manager {
        let did_cache = listener_mgr.get_did_cache();
        let tdk_state = gateway_listener
            .client
            .atm()
            .get_tdk();

        match did_cache
            .resolve_and_cache_for_atm(&gateway.did, tdk_state)
            .await
        {
            Ok((_, was_cached)) => {
                if was_cached {
                    debug!("[{request_id}] Using cached DID document for gateway {}", gateway.did);
                } else {
                    debug!("[{request_id}] DID document resolved and cached for gateway {}", gateway.did);
                }
            }
            Err(e) => {
                warn!("[{request_id}] Failed to pre-resolve gateway DID: {}. Continuing anyway.", e);
            }
        }
    }

    // Pack and send the message
    let packed = gateway_listener
        .client
        .atm()
        .pack_encrypted(
            &ping_message,
            &gateway.did,
            Some(&gateway_listener.gateway_did),
            Some(&gateway_listener.gateway_did),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to pack ping message: {:?}", e)))?;

    info!("[{request_id}] ✓ Message packed ({} bytes)", packed.0.len());

    // Send via ATM
    gateway_listener
        .client
        .atm()
        .send_message(
            gateway_listener
                .client
                .profile(),
            &packed.0,
            &ping_message.id,
            false, // Don't wait for response
            false, // Don't auto-delete
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send ping: {:?}", e)))?;

    info!("[{request_id}] 🟢 Ping sent, waiting for pong via WebSocket...");

    // Wait for pong response via WebSocket (2s timeout)
    let response = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &ping_message.id,
            std::time::Duration::from_secs(2),
            true, // auto_delete
        )
        .await;

    let elapsed = start.elapsed();
    let total_elapsed = total_start.elapsed();

    info!("[{request_id}] WebSocket wait completed after {}ms", elapsed.as_millis());
    info!("🏁 [{request_id}] Gateway ping operation COMPLETE - total time: {}ms", total_elapsed.as_millis());

    match response {
        Ok(Some((pong, _metadata))) => {
            info!("[{request_id}] ✓ Received pong response ({}ms)", elapsed.as_millis());

            // Verify it's a pong message using MessageType enum
            let is_pong = pong.typ == MessageType::GatewayPong.as_str();

            if is_pong {
                Ok(Json(GatewayPingResponse {
                    success: true,
                    message: "Gateway ping successful".to_string(),
                    round_trip_ms: Some(elapsed.as_millis() as u64),
                }))
            } else {
                warn!("[{request_id}] Received unexpected message type: {}", pong.typ);
                Ok(Json(GatewayPingResponse {
                    success: false,
                    message: format!("Received unexpected message type: {}", pong.typ),
                    round_trip_ms: None,
                }))
            }
        }
        Ok(None) => {
            warn!("[{request_id}] ✗ Ping timed out after {}ms", elapsed.as_millis());
            recover_after_ping_timeout(request_id, manager, &gateway_listener).await;
            Ok(Json(GatewayPingResponse {
                success: false,
                message: "Gateway ping timed out - no response received".to_string(),
                round_trip_ms: None,
            }))
        }
        Err(e) => {
            error!("[{request_id}] ✗ Ping failed: {:?}", e);
            Ok(Json(GatewayPingResponse {
                success: false,
                message: format!("Gateway ping failed: {:?}", e),
                round_trip_ms: None,
            }))
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct GetGatewaySurfacesQuery {
    #[serde(default)]
    pub force_refresh: bool,
}

/// Response for getting gateway channels
#[derive(Debug, Serialize)]
pub struct GetGatewaySurfacesResponse {
    pub success: bool,
    pub channels: Vec<SurfaceInfo>,
    pub message: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SurfaceInfo {
    pub config_id: String,
    pub name: String,
    pub description: String,
    pub listen_address: String,
    pub protocol: String,
}

/// Query available channels from a remote gateway
pub async fn get_gateway_surfaces<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Extension(cache): Extension<Arc<GatewaySurfaceCache>>,
    Path(gateway_id): Path<String>,
    Query(query): Query<GetGatewaySurfacesQuery>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<GetGatewaySurfacesResponse>, (StatusCode, String)> {
    let request_id = uuid::Uuid::new_v4().to_string();
    debug!("🔍 [{request_id}] Getting channels for gateway: {} (force_refresh: {})", gateway_id, query.force_refresh);

    let gateway = store
        .get(&gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    // Check cache first (5 minute TTL) unless force_refresh is set
    if !query.force_refresh
        && cache
            .is_fresh(&gateway_id, 300)
            .await
        && let Some(cached) = cache.get(&gateway_id).await
    {
        debug!(
            "[{request_id}] ✓ Using cached channels ({} channels, {} old)",
            cached.channels.len(),
            (chrono::Utc::now() - cached.cached_at).num_seconds()
        );
        return Ok(Json(GetGatewaySurfacesResponse {
            success: true,
            channels: cached.channels,
            message: Some("From cache".to_string()),
        }));
    }

    debug!("[{request_id}] Found gateway: {} (DID: {})", gateway.name, gateway.did);

    // Get listener manager
    let listener_mgr = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    // Get the gateway listener (WebSocket connection)
    let gateway_listener = listener_mgr
        .get_listener(&gateway_id)
        .await
        .ok_or_else(|| {
            debug!("[{request_id}] No active listener found for gateway {}", gateway_id);
            (StatusCode::SERVICE_UNAVAILABLE, "Gateway not connected - no active WebSocket listener".to_string())
        })?;

    debug!("[{request_id}] Found active WebSocket listener for gateway");

    // Build get-channels message
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let get_channels_message = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::GetSurfaces
            .as_str()
            .to_string(),
        json!({
            "request_id": request_id,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(gateway.did.clone())
    .thid(uuid::Uuid::new_v4().to_string())
    .finalize();

    debug!("[{request_id}] 🔵 Sending get-channels query (ID: {})...", get_channels_message.id);

    // Pre-resolve and cache the gateway DID
    let did_cache = listener_mgr.get_did_cache();
    let tdk_state = gateway_listener
        .client
        .atm()
        .get_tdk();

    match did_cache
        .resolve_and_cache_for_atm(&gateway.did, tdk_state)
        .await
    {
        Ok((_, was_cached)) => {
            if was_cached {
                debug!("[{request_id}] Using cached DID document for gateway {}", gateway.did);
            } else {
                debug!("[{request_id}] DID document resolved and cached for gateway {}", gateway.did);
            }
        }
        Err(e) => {
            warn!("[{request_id}] Failed to pre-resolve gateway DID: {}. Continuing anyway.", e);
        }
    }

    // Pack and send the message
    let packed = gateway_listener
        .client
        .atm()
        .pack_encrypted(
            &get_channels_message,
            &gateway.did,
            Some(&gateway_listener.gateway_did),
            Some(&gateway_listener.gateway_did),
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to pack message: {:?}", e)))?;

    gateway_listener
        .client
        .atm()
        .send_message(
            gateway_listener
                .client
                .profile(),
            &packed.0,
            &get_channels_message.id,
            false, // Don't wait for response
            false, // Don't auto-delete
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send get-channels: {:?}", e)))?;

    debug!("[{request_id}] 🟢 Get-channels sent, waiting for response via WebSocket...");

    // Wait for get-channels-response via WebSocket (5s timeout)
    let response = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &get_channels_message.id,
            std::time::Duration::from_secs(5),
            true, // auto_delete
        )
        .await;

    match response {
        Ok(Some((response_msg, _metadata))) => {
            debug!("[{request_id}] ✓ Received get-channels-response");

            // Verify it's a get-channels-response message
            let is_channels_response = response_msg.typ == MessageType::GetSurfacesResponse.as_str();

            if is_channels_response {
                // Extract channels from response body
                let channels: Vec<SurfaceInfo> = if let Some(channels_array) = response_msg
                    .body
                    .get("channels")
                {
                    serde_json::from_value(channels_array.clone()).unwrap_or_else(|e| {
                        warn!("[{request_id}] Failed to parse channels from response: {}", e);
                        Vec::new()
                    })
                } else {
                    warn!("[{request_id}] Response missing 'channels' field");
                    Vec::new()
                };

                debug!("[{request_id}] Successfully retrieved {} channels", channels.len());

                // Cache the result
                cache
                    .set(gateway_id.clone(), channels.clone())
                    .await;

                Ok(Json(GetGatewaySurfacesResponse {
                    success: true,
                    channels,
                    message: None,
                }))
            } else {
                warn!("[{request_id}] Received unexpected message type: {}", response_msg.typ);
                Ok(Json(GetGatewaySurfacesResponse {
                    success: false,
                    channels: Vec::new(),
                    message: Some(format!("Received unexpected message type: {}", response_msg.typ)),
                }))
            }
        }
        Ok(None) => {
            debug!(
                "[{request_id}] Get-channels timed out - gateway did not respond within 5s (may be offline or slow)"
            );

            // Cache the error
            cache
                .set_error(gateway_id.clone(), "Request timed out".to_string())
                .await;

            Ok(Json(GetGatewaySurfacesResponse {
                success: false,
                channels: Vec::new(),
                message: Some("Request timed out - gateway did not respond".to_string()),
            }))
        }
        Err(e) => {
            error!("[{request_id}] ✗ Get-channels failed: {:?}", e);

            // Cache the error
            cache
                .set_error(gateway_id.clone(), format!("Request failed: {:?}", e))
                .await;

            Ok(Json(GetGatewaySurfacesResponse {
                success: false,
                channels: Vec::new(),
                message: Some(format!("Request failed: {:?}", e)),
            }))
        }
    }
}

/// Refresh channel cache for all connected gateways
/// This queries all gateways that have active WebSocket connections
pub async fn refresh_gateway_surfaces_cache<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    Extension(cache): Extension<Arc<GatewaySurfaceCache>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    const COOLDOWN_SECONDS: i64 = 5;

    // Check cooldown first - prevent refreshes within 5 seconds of last refresh
    if !cache
        .can_refresh(COOLDOWN_SECONDS)
        .await
    {
        debug!("⏱️ Gateway channel cache refresh in cooldown period ({}s), skipping", COOLDOWN_SECONDS);
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Refresh in cooldown period",
            "refreshed": [],
            "skipped": [],
            "failed": []
        })));
    }

    // Try to acquire the refresh lock
    let acquired = cache.try_acquire_refresh_lock();
    debug!("🔐 Refresh lock acquisition attempt: acquired={}", acquired);

    if !acquired {
        debug!("⏭️ Gateway channel cache refresh already in progress, skipping");
        return Ok(Json(serde_json::json!({
            "success": true,
            "message": "Refresh already in progress",
            "refreshed": [],
            "skipped": [],
            "failed": []
        })));
    }

    // Ensure lock is released when function exits
    let cache_clone = cache.clone();
    let _guard = scopeguard::guard((), move |_| {
        tokio::spawn(async move {
            cache_clone
                .release_refresh_lock()
                .await;
        });
    });

    debug!("🔄 Refreshing exported entity cache for all connected appliances");

    let listener_mgr = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    // Get all gateways
    let gateways = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {}", e)))?
        .into_iter()
        .filter(|gateway| gateway_allowed(gateway, &context, &scope));

    let mut refreshed = Vec::new();
    let mut skipped = Vec::new();
    let mut failed = Vec::new();

    for gateway in gateways {
        // Skip self-gateway
        if gateway.gateway_type == GatewayType::SelfGateway {
            skipped.push(gateway.id.clone());
            continue;
        }

        // Check if gateway has active listener (is connected)
        if listener_mgr
            .get_listener(&gateway.id)
            .await
            .is_none()
        {
            debug!("Skipping gateway {} - not connected", gateway.name);
            skipped.push(gateway.id.clone());
            continue;
        }

        // Query channels for this gateway
        debug!("Querying channels for gateway {}", gateway.name);

        // Call get_gateway_channels but force refresh by clearing cache first
        cache.clear(&gateway.id).await;

        // Make a recursive call to get_gateway_channels (it will query and cache)
        match get_gateway_surfaces(
            Extension(store.clone()),
            Extension(Some(listener_mgr.clone())),
            Extension(cache.clone()),
            Path(gateway.id.clone()),
            Query(GetGatewaySurfacesQuery { force_refresh: true }),
            context.clone(),
            scope.clone(),
        )
        .await
        {
            Ok(response) => {
                if response.0.success {
                    refreshed.push(gateway.id.clone());
                    debug!("✓ Refreshed {} channels for gateway {}", response.0.channels.len(), gateway.name);
                } else {
                    failed.push(gateway.id.clone());
                    debug!("✗ Failed to refresh channels for gateway {}: {:?}", gateway.name, response.0.message);
                }
            }
            Err(e) => {
                failed.push(gateway.id.clone());
                warn!("✗ Error refreshing channels for gateway {}: {:?}", gateway.name, e);
            }
        }
    }

    info!(
        "✓ Cache refresh complete: {} refreshed, {} skipped, {} failed",
        refreshed.len(),
        skipped.len(),
        failed.len()
    );

    Ok(Json(serde_json::json!({
        "success": true,
        "refreshed": refreshed,
        "skipped": skipped,
        "failed": failed,
    })))
}

/// Get pipes configuration (LLM provider catalog).
///
/// Reads the editable provider catalog from the `llm_configuration` storage
/// directory and returns it wrapped as `{ "llm": { "providers": [...] } }` for
/// the dashboard pipe editor. Falls back to the shipped seed catalog when the
/// storage copy is not yet present.
pub async fn get_pipes_config(
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Prefer the process-wide catalog store: it serves the **merged** view
    // (built-in `llm.json` + valid custom providers from `custom_llm.json`), so
    // custom providers appear in every dashboard picker exactly like built-in
    // ones. A bad custom file is ignored by the store, so this can never break.
    if let Some(catalog) = crate::llm_catalog::global_catalog() {
        let mut providers = (*catalog.cached_providers()).clone();
        crate::llm_catalog::retain_enabled_models(&mut providers);
        return Ok(Json(serde_json::json!({
            "llm": { "providers": providers },
            "input_modalities": crate::pipes::modality::supported_input_modalities(),
            "audio_streams": crate::pipes::audio_streams::published_catalog(),
        })));
    }

    let catalog_path = bootstrap_config.llm_catalog_path();

    let config_content = match tokio::fs::read_to_string(&catalog_path).await {
        Ok(contents) => contents,
        Err(_) => {
            // Storage copy missing — fall back to the shipped seed catalog.
            let seed_path = bootstrap_config.llm_catalog_seed_path();
            tokio::fs::read_to_string(seed_path)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to read LLM provider catalog from {} or seed {}: {}",
                            catalog_path.display(),
                            seed_path,
                            e
                        ),
                    )
                })?
        }
    };

    let catalog: serde_json::Value = serde_json::from_str(&config_content)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse LLM provider catalog: {}", e)))?;

    // Normalize to the `{ "llm": { "providers": [...] } }` shape the pipe editor
    // expects, accepting either a bare `{ "providers": [...] }` catalog or a
    // legacy `{ "llm": { "providers": [...] } }` document.
    let mut providers = catalog
        .get("providers")
        .or_else(|| {
            catalog
                .get("llm")
                .and_then(|llm| llm.get("providers"))
        })
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();

    // Models flagged `"enabled": false` in the catalog are never offered to the
    // dashboard for selection — enforcement does not depend on the client.
    crate::llm_catalog::retain_enabled_models(&mut providers);

    Ok(Json(serde_json::json!({
        "llm": { "providers": providers },
        "input_modalities": crate::pipes::modality::supported_input_modalities(),
        "audio_streams": crate::pipes::audio_streams::published_catalog(),
    })))
}

/// Proxy marketplace model catalog.
///
/// Iterates the **gateway store** (not the channel cache) to find all connected
/// remote gateways, checks each one's cached channel list for a
/// `marketplace-catalog` channel, and fetches models via DIDComm fabric.
///
/// Results are cached with a configurable TTL (`marketplace_cache_ttl` in
/// config.toml, default 300 s / 5 min) so that repeated browser requests don't
/// trigger outbound DIDComm calls to every gateway.
///
/// Each model in the response includes a `gateway_id` so purchases can be
/// routed to the correct gateway.
fn filter_marketplace_models(
    models: Vec<serde_json::Value>,
    allowed_gateway_ids: &std::collections::HashSet<String>,
    restricted: bool,
) -> Vec<serde_json::Value> {
    if !restricted {
        return models;
    }
    models
        .into_iter()
        .filter(|model| {
            model
                .get("gateway_id")
                .and_then(serde_json::Value::as_str)
                .is_some_and(|gateway_id| allowed_gateway_ids.contains(gateway_id))
        })
        .collect()
}

pub async fn get_marketplace_models<S: GatewayStore>(
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(store): Extension<Arc<S>>,
    Extension(surface_cache): Extension<Arc<GatewaySurfaceCache>>,
    Extension(marketplace_cache): Extension<Arc<crate::gateways::MarketplaceCache>>,
    listener_manager: Option<Extension<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    query: axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let force_refresh = query
        .get("refresh")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let ttl = bootstrap_config.marketplace_cache_ttl;
    let restricted = context.is_some() || scope.is_some();
    let gateways: Vec<_> = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list gateways: {}", e)))?
        .into_iter()
        .filter(|gateway| gateway_allowed(gateway, &context, &scope))
        .collect();
    let allowed_gateway_ids: std::collections::HashSet<_> = gateways
        .iter()
        .map(|gateway| gateway.id.clone())
        .collect();

    // 1. Return cached data if fresh (skip if force refresh)
    if !force_refresh
        && let Some(models) = marketplace_cache
            .get_if_fresh(ttl)
            .await
    {
        return Ok(Json(serde_json::Value::Array(filter_marketplace_models(models, &allowed_gateway_ids, restricted))));
    }

    // 2. Try to acquire the refresh lock — if someone else is refreshing,
    //    return stale data (or empty) rather than blocking.
    if !restricted && !marketplace_cache.try_lock_refresh() {
        debug!("Marketplace cache refresh already in progress, returning stale data");
        let stale = marketplace_cache
            .get_if_fresh(u64::MAX)
            .await
            .unwrap_or_default();
        return Ok(Json(serde_json::Value::Array(stale)));
    }

    // 3. Fetch from all connected gateways that expose marketplace channels
    let mut all_models: Vec<serde_json::Value> = Vec::new();

    let listener_mgr = match listener_manager {
        Some(Extension(ref mgr)) => Some(mgr.clone()),
        None => None,
    };

    if let Some(ref listener_mgr) = listener_mgr {
        for gateway in &gateways {
            // Skip self-gateway and non-active gateways
            if gateway.gateway_type == GatewayType::SelfGateway
                || gateway.status != crate::gateways::types::GatewayStatus::Active
            {
                continue;
            }

            // Check if this gateway is connected (has an active listener)
            if listener_mgr
                .get_listener(&gateway.id)
                .await
                .is_none()
            {
                continue;
            }

            // Check channel cache for a marketplace-catalog channel
            // If cache is empty (None), assume the gateway might have marketplace
            // channels — we can't know without asking, and the fabric forward
            // will fail fast if it doesn't.
            let has_marketplace = match surface_cache
                .get(&gateway.id)
                .await
            {
                Some(cached) => cached
                    .channels
                    .iter()
                    .any(|ch| ch.config_id == "marketplace-catalog" || ch.protocol == "marketplace"),
                None => true, // Cache not populated yet — try anyway
            };

            if !has_marketplace {
                continue;
            }

            // Fetch catalog via DIDComm fabric
            let fabric_url = format!("fabric://{}/marketplace-catalog", gateway.id);
            match crate::fabric_marketplace::fabric_forward(
                listener_mgr,
                &fabric_url,
                "GET",
                "/api/models",
                std::collections::HashMap::new(),
                &[],
            )
            .await
            {
                Ok(resp) if resp.status < 300 => {
                    if let Ok(body) = serde_json::from_str::<serde_json::Value>(&resp.body)
                        && let Some(models) = body.as_array()
                    {
                        for model in models {
                            let mut m = model.clone();
                            m["gateway_id"] = serde_json::Value::String(gateway.id.clone());
                            m["gateway_name"] = serde_json::Value::String(gateway.name.clone());
                            m["marketplace_id"] = serde_json::Value::String(gateway.id.clone());
                            all_models.push(m);
                        }
                        info!(
                            "Marketplace: fetched {} models from gateway {} ({})",
                            models.len(),
                            gateway.name,
                            gateway.id
                        );
                    }
                }
                Ok(resp) => {
                    warn!("Marketplace gateway {} returned status {}", gateway.name, resp.status);
                }
                Err(e) => {
                    warn!("Failed to reach marketplace on gateway {}: {}", gateway.name, e);
                }
            }
        }
    }

    // 4. Cache the result (even if empty) and release the lock
    if !restricted {
        marketplace_cache
            .set(all_models.clone())
            .await;
    }

    Ok(Json(serde_json::Value::Array(all_models)))
}

/// Get marketplace models from a specific gateway.
/// Used by the gateway detail page's Marketplace tab.
pub async fn get_gateway_marketplace<S: GatewayStore>(
    Extension(store): Extension<Arc<S>>,
    Extension(surface_cache): Extension<Arc<GatewaySurfaceCache>>,
    Extension(listener_manager): Extension<Option<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let gateway = store
        .get(&gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }

    let listener_mgr = listener_manager
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()))?;

    // Verify the gateway has an active connection
    if listener_mgr
        .get_listener(&gateway_id)
        .await
        .is_none()
    {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Gateway not connected".to_string()));
    }

    // Check if gateway has marketplace channels
    // If cache is empty, try anyway — cache may not be populated yet
    let has_marketplace = match surface_cache
        .get(&gateway_id)
        .await
    {
        Some(cached) => cached
            .channels
            .iter()
            .any(|ch| ch.config_id == "marketplace-catalog" || ch.protocol == "marketplace"),
        None => true, // Cache not populated yet — try anyway
    };

    if !has_marketplace {
        return Ok(Json(serde_json::Value::Array(Vec::new())));
    }

    let fabric_url = format!("fabric://{}/marketplace-catalog", gateway_id);
    match crate::fabric_marketplace::fabric_forward(
        &listener_mgr,
        &fabric_url,
        "GET",
        "/api/models",
        std::collections::HashMap::new(),
        &[],
    )
    .await
    {
        Ok(resp) if resp.status < 300 => {
            if let Ok(body) = serde_json::from_str::<serde_json::Value>(&resp.body)
                && let Some(models) = body.as_array()
            {
                let tagged: Vec<serde_json::Value> = models
                    .iter()
                    .map(|model| {
                        let mut m = model.clone();
                        m["gateway_id"] = serde_json::Value::String(gateway.id.clone());
                        m["gateway_name"] = serde_json::Value::String(gateway.name.clone());
                        m["marketplace_id"] = serde_json::Value::String(gateway.id.clone());
                        m
                    })
                    .collect();
                return Ok(Json(serde_json::Value::Array(tagged)));
            }
            Ok(Json(serde_json::Value::Array(Vec::new())))
        }
        Ok(resp) => Err((StatusCode::BAD_GATEWAY, format!("Remote gateway returned status {}", resp.status))),
        Err(e) => Err((StatusCode::BAD_GATEWAY, format!("Failed to reach gateway marketplace: {}", e))),
    }
}

/// Proxy a marketplace purchase request.
/// Routes the purchase to the correct gateway based on `gateway_id` query parameter
/// (set automatically from auto-discovery). Falls back to pipes.json for backward
/// compatibility when no `gateway_id` is provided.
///
/// Transparently forwards the request to the gateway's `marketplace-purchase`
/// channel and returns its response.
pub async fn post_marketplace_purchase(
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    listener_manager: Option<Extension<Arc<crate::gateways::ConnectionPointListenerManager>>>,
    Path(model_id): Path<String>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let purchase_path = format!("/api/purchase/{}", model_id);

    let mut fwd_headers = std::collections::HashMap::new();
    fwd_headers.insert("CONTENT-TYPE".to_string(), "application/json".to_string());

    // === Primary: route via gateway_id (auto-discovery) ===
    if let Some(gateway_id) = params.get("gateway_id") {
        let Some(Extension(listener_mgr)) = listener_manager else {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()));
        };

        let fabric_url = format!("fabric://{}/marketplace-purchase", gateway_id);
        info!("Marketplace purchase: routing to gateway {} for model {}", gateway_id, model_id);

        let result = crate::fabric_marketplace::fabric_forward(
            &listener_mgr,
            &fabric_url,
            "POST",
            &purchase_path,
            fwd_headers,
            &body,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Fabric forward failed: {}", e)))?;

        return build_purchase_response(result);
    }

    // === Fallback: pipes.json marketplace_url/marketplace_purchase_url ===
    let config_path = std::path::Path::new(
        &bootstrap_config
            .config_files
            .llm,
    );
    let config_content = tokio::fs::read_to_string(config_path)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to read pipes config: {}", e)))?;

    let config: serde_json::Value = serde_json::from_str(&config_content)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse pipes config: {}", e)))?;

    let requested_mp_id = params.get("marketplace_id");

    let marketplace_provider = config["llm"]["providers"]
        .as_array()
        .and_then(|providers| {
            let mp_providers: Vec<&serde_json::Value> = providers
                .iter()
                .filter(|p| p["api_schema"].as_str() == Some("marketplace"))
                .collect();
            if let Some(mp_id) = requested_mp_id {
                mp_providers
                    .iter()
                    .find(|p| p["enum_value"].as_str() == Some(mp_id.as_str()))
                    .or(mp_providers.first())
                    .copied()
            } else {
                mp_providers.first().copied()
            }
        })
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No marketplace provider configured".to_string()))?;

    let marketplace_url = marketplace_provider
        .get("marketplace_purchase_url")
        .and_then(|v| v.as_str())
        .or_else(|| {
            marketplace_provider
                .get("marketplace_url")
                .and_then(|v| v.as_str())
        })
        .ok_or_else(|| (StatusCode::NOT_FOUND, "No marketplace URL configured".to_string()))?
        .to_string();

    if marketplace_url.starts_with("fabric://") {
        let Some(Extension(listener_mgr)) = listener_manager else {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Listener manager not available".to_string()));
        };

        let result = crate::fabric_marketplace::fabric_forward(
            &listener_mgr,
            &marketplace_url,
            "POST",
            &purchase_path,
            fwd_headers,
            &body,
        )
        .await
        .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Fabric forward failed: {}", e)))?;

        build_purchase_response(result)
    } else {
        // HTTP marketplace (backward compatible)
        crate::url_validation::validate_resolved_webhook_url(&marketplace_url)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Marketplace URL blocked: {}", e)))?;
        let purchase_url = format!("{}{}", marketplace_url.trim_end_matches('/'), purchase_path);
        crate::url_validation::validate_resolved_webhook_url(&purchase_url)
            .await
            .map_err(|e| (StatusCode::BAD_REQUEST, format!("Marketplace purchase URL blocked: {}", e)))?;
        debug!("Proxying marketplace purchase to: {}", crate::url_validation::redact_url_for_logging(&purchase_url));

        let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
            crate::http_client::EXTERNAL_TIMEOUT_SECS,
        ))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("HTTP client error: {}", e)))?;

        let mut req = client
            .post(&purchase_url)
            .header("Content-Type", "application/json");
        if !body.is_empty() {
            req = req.body(body.to_vec());
        }

        let response = req
            .send()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to reach marketplace: {}", e)))?;

        let builder = axum::http::Response::builder()
            .status(response.status().as_u16())
            .header("Content-Type", "application/json");

        let resp_bytes = response
            .bytes()
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to read marketplace response: {}", e)))?;

        builder
            .body(axum::body::Body::from(resp_bytes.to_vec()))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Response build error: {}", e)))
    }
}

/// Build an axum Response from a FabricForwardResult (shared by purchase paths)
fn build_purchase_response(
    result: crate::fabric_marketplace::FabricForwardResult
) -> Result<axum::response::Response, (StatusCode, String)> {
    let mut builder = axum::http::Response::builder().status(result.status);
    for (key, value) in &result.headers {
        if let Ok(header_name) = axum::http::HeaderName::try_from(key.as_str())
            && let Ok(header_value) = axum::http::HeaderValue::try_from(value.as_str())
        {
            builder = builder.header(header_name, header_value);
        }
    }
    builder = builder
        .header("Access-Control-Expose-Headers", "PAYMENT-REQUIRED")
        .header("Content-Type", "application/json");
    builder
        .body(axum::body::Body::from(result.body))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Response build error: {}", e)))
}

/// List all purchased marketplace models
pub async fn list_purchased_models(
    Extension(store): Extension<Arc<crate::marketplace_models::FileSystemMarketplaceModelStore>>
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let models = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list purchased models: {}", e)))?;
    let value = serde_json::to_value(&models)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialisation error: {}", e)))?;
    Ok(Json(value))
}

/// Save a purchased marketplace model
pub async fn save_purchased_model(
    Extension(store): Extension<Arc<crate::marketplace_models::FileSystemMarketplaceModelStore>>,
    Json(model): Json<crate::marketplace_models::types::MarketplaceModel>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    store
        .create(&model)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save purchased model: {}", e)))?;
    let value = serde_json::to_value(&model)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Serialisation error: {}", e)))?;
    Ok(Json(value))
}

/// Delete a purchased marketplace model
pub async fn delete_purchased_model(
    Extension(store): Extension<Arc<crate::marketplace_models::FileSystemMarketplaceModelStore>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete purchased model: {}", e)))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Get prompt guard definitions (serves the loaded prompt-guard.json pattern definitions)
pub async fn get_prompt_guard_config() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let defs = crate::pipes::prompt_guard::get_definitions()
        .ok_or_else(|| (StatusCode::SERVICE_UNAVAILABLE, "Prompt guard definitions not loaded".to_string()))?;

    let value = serde_json::to_value(defs).map_err(|e| {
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize prompt guard definitions: {}", e))
    })?;

    Ok(Json(value))
}

#[cfg(test)]
mod ping_timeout_recovery_tests {
    use super::{ACCOUNT_NOT_FOUND_CODE, AccountProbe, PingTimeoutRecovery, ping_timeout_recovery};
    use affinidi_messaging_sdk::errors::ATMError;

    fn probe_error(error: ATMError) -> AccountProbe {
        Ok(Err(error))
    }

    fn problem_report(code: &str) -> AccountProbe {
        probe_error(ATMError::ProblemReport(code.into(), "comment".into(), "NONE".into()))
    }

    #[test]
    fn a_missing_account_restarts_the_listener() {
        assert_eq!(
            ping_timeout_recovery(&problem_report(ACCOUNT_NOT_FOUND_CODE)),
            PingTimeoutRecovery::RestartListener
        );
    }

    #[test]
    fn other_probe_failures_only_report_the_timeout() {
        assert_eq!(
            ping_timeout_recovery(&problem_report("e.p.access_list.denied")),
            PingTimeoutRecovery::ReportTimeout
        );
        assert_eq!(
            ping_timeout_recovery(&problem_report("e.p.account.not_found_else")),
            PingTimeoutRecovery::ReportTimeout
        );
        assert_eq!(
            ping_timeout_recovery(&probe_error(ATMError::TransportError("account.not_found".into()))),
            PingTimeoutRecovery::ReportTimeout
        );
    }

    #[test]
    fn a_readable_account_only_reports_the_timeout() {
        let account: AccountProbe = Ok(Ok(serde_json::from_value(serde_json::json!({
            "did": "did:example:connection-point",
            "accountType": "standard",
            "acl": { "accessListMode": "explicitAllow" }
        }))
        .unwrap()));
        assert_eq!(ping_timeout_recovery(&account), PingTimeoutRecovery::ReportTimeout);
    }

    #[tokio::test]
    async fn a_probe_that_times_out_only_reports_the_timeout() {
        let timed_out: AccountProbe =
            Err(tokio::time::timeout(std::time::Duration::ZERO, std::future::pending::<()>())
                .await
                .unwrap_err());
        assert_eq!(ping_timeout_recovery(&timed_out), PingTimeoutRecovery::ReportTimeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Body, http::Request, routing::put};
    use tower::ServiceExt;

    #[test]
    fn canonical_gateway_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:gateways:gateway-1\z").unwrap(),
        ))));
        let mut gateway = Gateway::new("Gateway".into(), String::new(), "did:web:gateway".into(), GatewayType::Remote);
        gateway.id = "gateway-1".into();

        gateway.tenant_id = Some("tenant-a".into());
        assert!(gateway_allowed(&gateway, &context, &scope));

        gateway.tenant_id = None;
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!gateway_allowed(&gateway, &context, &scope));

        gateway.tenant_id = Some("tenant-b".into());
        assert!(!gateway_allowed(&gateway, &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:pipes:gateway-1\z").unwrap(),
        ))));
        gateway.tenant_id = Some("tenant-a".into());
        assert!(!gateway_allowed(&gateway, &context, &wrong_kind));
    }

    #[test]
    fn marketplace_cache_projection_filters_only_restricted_callers() {
        let models = vec![
            serde_json::json!({ "id": "allowed", "gateway_id": "gateway-1" }),
            serde_json::json!({ "id": "denied", "gateway_id": "gateway-2" }),
            serde_json::json!({ "id": "legacy" }),
        ];
        let allowed = std::collections::HashSet::from(["gateway-1".to_string()]);

        let restricted = filter_marketplace_models(models.clone(), &allowed, true);
        assert_eq!(restricted, vec![serde_json::json!({ "id": "allowed", "gateway_id": "gateway-1" })]);

        assert_eq!(filter_marketplace_models(models.clone(), &allowed, false), models);
    }

    #[tokio::test]
    async fn gateway_policy_update_rejects_missing_runtime_manager() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(dir.path().to_path_buf(), None)
                .await
                .unwrap(),
        );
        let gateway = store
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .find(|gateway| gateway.gateway_type == GatewayType::SelfGateway)
            .unwrap();
        let app = Router::new()
            .route("/v1/gateways/{id}/policy", put(update_gateway_policy::<crate::gateways::FileSystemGatewayStore>))
            .layer(Extension(store))
            .layer(Extension(Option::<Arc<crate::policies::GatewayPolicyManager>>::None))
            .layer(Extension(Option::<Arc<crate::policies::FileSystemPolicyDefinitionStore>>::None));

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/gateways/{}/policy", gateway.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "opa_policy_config": {
                                "enabled": true,
                                "policy": "package agentstream.policy\ndefault allow = false"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn gateway_policy_update_synchronizes_runtime_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(dir.path().to_path_buf(), None)
                .await
                .unwrap(),
        );
        let gateway = store
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .find(|gateway| gateway.gateway_type == GatewayType::SelfGateway)
            .unwrap();
        let manager = Arc::new(crate::policies::GatewayPolicyManager::new());
        let app = Router::new()
            .route("/v1/gateways/{id}/policy", put(update_gateway_policy::<crate::gateways::FileSystemGatewayStore>))
            .layer(Extension(store))
            .layer(Extension(Some(manager.clone())))
            .layer(Extension(Option::<Arc<crate::policies::FileSystemPolicyDefinitionStore>>::None));

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/gateways/{}/policy", gateway.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "opa_policy_config": {
                                "enabled": true,
                                "policy": "package agentstream.policy\ndefault allow = false"
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert!(manager.is_enforced(&gateway.id));
        assert!(
            !manager
                .evaluate_policy(&gateway.id, serde_json::json!({}))
                .unwrap()
        );
    }

    #[tokio::test]
    async fn inline_gateway_rego_reading_an_unpopulated_input_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            crate::gateways::FileSystemGatewayStore::new(dir.path().to_path_buf(), None)
                .await
                .unwrap(),
        );
        let gateway = store
            .list_all()
            .await
            .unwrap()
            .into_iter()
            .find(|gateway| gateway.gateway_type == GatewayType::SelfGateway)
            .unwrap();
        let manager = Arc::new(crate::policies::GatewayPolicyManager::new());
        let app = Router::new()
            .route("/v1/gateways/{id}/policy", put(update_gateway_policy::<crate::gateways::FileSystemGatewayStore>))
            .layer(Extension(store.clone()))
            .layer(Extension(Some(manager.clone())))
            .layer(Extension(Option::<Arc<crate::policies::FileSystemPolicyDefinitionStore>>::None));

        let response = app
            .oneshot(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/v1/gateways/{}/policy", gateway.id))
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({
                            "opa_policy_config": {
                                "enabled": true,
                                "policy": "package agentstream.policy\ndefault allow := true\ndeny if input.mcp.tool_name == \"x\""
                            }
                        })
                        .to_string(),
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert!(!manager.is_enforced(&gateway.id));
        assert!(
            !store
                .get(&gateway.id)
                .await
                .unwrap()
                .unwrap()
                .opa_policy_config
                .is_some_and(|config| config.enabled),
            "the refused policy was stored"
        );
    }

    #[test]
    fn effective_remote_gateway_status_derivation() {
        use crate::comm::connection_health::{ConnectionRuntimeStatus, ConnectionStatus};
        use crate::gateways::connection_points::types::{ConnectionPointType, GatewayConnectionPoint};

        fn cp(runtime: Option<ConnectionStatus>) -> GatewayConnectionPoint {
            let mut c = GatewayConnectionPoint::new(
                "gw".to_string(),
                "med".to_string(),
                "did".to_string(),
                "name".to_string(),
                "desc".to_string(),
                "oob".to_string(),
                "url".to_string(),
                serde_json::json!({}),
                None,
                ConnectionPointType::User,
                String::new(),
            );
            c.runtime_status = runtime.map(|status| ConnectionRuntimeStatus {
                status,
                ..ConnectionRuntimeStatus::default()
            });
            c
        }

        // Explicit workflow / manual states are preserved regardless of runtime.
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::AwaitingApproval, false, &[]),
            GatewayStatus::AwaitingApproval
        );
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Pending, false, &[]), GatewayStatus::Pending);
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Disabled, true, &[]), GatewayStatus::Disabled);

        // A live listener means Active.
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Active, true, &[]), GatewayStatus::Active);

        // No listener: derive from connection-point runtime health.
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Connected))]),
            GatewayStatus::Active
        );
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Failed))]),
            GatewayStatus::Failed
        );
        assert_eq!(
            effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(Some(ConnectionStatus::Reconnecting))]),
            GatewayStatus::Failed
        );
        // No runtime recorded yet -> Pending (still connecting / never attempted).
        assert_eq!(effective_remote_gateway_status(GatewayStatus::Active, false, &[cp(None)]), GatewayStatus::Pending);
    }

    #[tokio::test]
    async fn a_marketplace_purchase_is_not_proxied_to_a_url_that_rebinds_to_loopback() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("purchased").await;
        let marketplace_url = upstream
            .url
            .replace("127.0.0.1", "market.rebind.test")
            .replace("/v1/chat/completions", "");
        let dir = tempfile::tempdir().unwrap();
        let llm_config = dir.path().join("llm.json");
        std::fs::write(
            &llm_config,
            serde_json::json!({ "llm": { "providers": [{
                "api_schema": "marketplace",
                "marketplace_url": marketplace_url,
            }]}})
            .to_string(),
        )
        .unwrap();
        let bootstrap: crate::config::BootstrapConfig = serde_json::from_value(serde_json::json!({
            "tls": { "cert_path": "cert.pem", "key_path": "key.pem" },
            "config_files": { "llm": llm_config.to_str().unwrap() },
        }))
        .unwrap();
        let public = std::net::IpAddr::from([93, 184, 215, 14]);
        let dns =
            crate::url_validation::test_dns::answer("market.rebind.test", &[public, public, [127, 0, 0, 1].into()]);

        let result = post_marketplace_purchase(
            Extension(Arc::new(bootstrap)),
            None,
            Path("model-1".to_string()),
            Query(std::collections::HashMap::new()),
            axum::body::Bytes::from_static(b"{}"),
        )
        .await;

        assert_eq!(
            result
                .map(|response| response.status())
                .map_err(|(status, _)| status),
            Err(StatusCode::BAD_GATEWAY)
        );
        assert_eq!(dns.lookups(), 3, "both URL checks and the connect-time check must resolve the host");
        assert_eq!(upstream.requests(), 0);
    }
}
