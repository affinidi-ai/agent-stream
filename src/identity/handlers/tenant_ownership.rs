use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};

use crate::api_keys::traits::ApiKeyStore;
use crate::auth_manager::pat::{PatDelegationContext, PatResourceScope};
use crate::certificates::CertificateStore;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::gateways::GatewayStore;
use crate::gateways::connection_points::ConnectionPointStore;
use crate::identity::state::IdentityApiState;
use crate::jwt_bearer::JwtVerificationStrategyStorage;
use crate::mediators::MediatorStore;
use crate::oauth_identifiers::OAuthIdentifierStorage;
use crate::pipe_templates::filesystem::PipeTemplateStore;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, validate_tenant_id,
};

#[derive(Clone)]
pub(crate) struct TenantOwnershipStores {
    pub(crate) gateways: Option<Arc<crate::gateways::FileSystemGatewayStore>>,
    pub(crate) mediators: Option<Arc<crate::mediators::FileSystemMediatorStore>>,
    pub(crate) connection_points: Option<Arc<crate::gateways::FileSystemConnectionPointStore>>,
    pub(crate) secrets: Option<Arc<dyn SecretsStore>>,
    pub(crate) certificates: Option<Arc<dyn CertificateStore>>,
    pub(crate) integrations: Option<Arc<crate::storage::IntegrationStorage>>,
    pub(crate) credential_providers:
        Option<Arc<crate::credential_providers::storage::FileSystemCredentialProviderStore>>,
    pub(crate) jwt_strategies: Option<Arc<dyn JwtVerificationStrategyStorage>>,
    pub(crate) oauth_identifiers: Option<Arc<dyn OAuthIdentifierStorage>>,
    pub(crate) agent_surfaces: Option<Arc<dyn AgentSurfaceStore>>,
    pub(crate) api_keys: Option<Arc<dyn ApiKeyStore>>,
}

#[derive(Debug)]
pub(crate) enum OwnershipApiError {
    BadRequest(String),
    Forbidden(String),
    NotFound(String),
    Conflict(OwnershipConflictResponse),
    Internal(String),
}

impl IntoResponse for OwnershipApiError {
    fn into_response(self) -> Response {
        match self {
            Self::BadRequest(message) => {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::Forbidden(message) => {
                (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::NotFound(message) => {
                (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": message }))).into_response()
            }
            Self::Conflict(response) => (StatusCode::CONFLICT, Json(response)).into_response(),
            Self::Internal(message) => {
                tracing::error!(%message, "Tenant ownership operation failed");
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({ "error": "Tenant ownership operation failed" })),
                )
                    .into_response()
            }
        }
    }
}

#[derive(Debug, Deserialize)]
pub(crate) struct ReassignOwnershipRequest {
    pub tenant_id: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipEndpoint {
    pub kind: String,
    pub id: String,
    #[serde(skip)]
    scope_id: String,
    pub tenant_id: Option<String>,
    pub exists: bool,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipReference {
    pub source: OwnershipEndpoint,
    pub target: OwnershipEndpoint,
    pub context: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipConflict {
    pub direction: String,
    pub source: OwnershipEndpoint,
    pub target: OwnershipEndpoint,
    pub context: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipImpactResponse {
    pub kind: String,
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
    pub immutable: bool,
    pub incoming: Vec<OwnershipReference>,
    pub outgoing: Vec<OwnershipReference>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipConflictResponse {
    pub error: &'static str,
    pub kind: String,
    pub id: String,
    pub requested_tenant_id: Option<String>,
    pub conflicts: Vec<OwnershipConflict>,
}

#[derive(Debug, Clone, Serialize)]
pub(crate) struct OwnershipReassignmentResponse {
    pub kind: String,
    pub id: String,
    pub previous_tenant_id: Option<String>,
    pub tenant_id: Option<String>,
}

#[derive(Clone)]
struct OwnedResource {
    kind: ResourceKind,
    id: String,
    scope_id: String,
    name: String,
    tenant_id: Option<String>,
    immutable: bool,
}

pub(crate) async fn ownership_impact(
    State(state): State<IdentityApiState>,
    Extension(stores): Extension<Arc<TenantOwnershipStores>>,
    Path((raw_kind, id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<OwnershipImpactResponse>, OwnershipApiError> {
    let kind = parse_owned_kind(&raw_kind)?;
    let resource = load_owned_resource(&state, &stores, kind, &id)
        .await?
        .ok_or_else(|| missing(kind, &id))?;
    let context = context
        .as_ref()
        .map(|Extension(context)| context);
    let scope = scope
        .as_ref()
        .map(|Extension(scope)| scope);
    if !endpoint_visible(&endpoint_from_owned(&resource), context, scope) {
        return Err(missing(kind, &id));
    }
    let references = collect_references(&state, &stores).await?;
    let incoming = references
        .iter()
        .filter(|reference| {
            endpoint_matches(&reference.target, kind, &id) && reference_visible(reference, context, scope)
        })
        .cloned()
        .collect();
    let outgoing = references
        .iter()
        .filter(|reference| {
            endpoint_matches(&reference.source, kind, &id) && reference_visible(reference, context, scope)
        })
        .cloned()
        .collect();

    Ok(Json(OwnershipImpactResponse {
        kind: kind.to_string(),
        id,
        name: resource.name,
        tenant_id: resource.tenant_id,
        immutable: resource.immutable,
        incoming,
        outgoing,
    }))
}

pub(crate) async fn reassign_ownership(
    State(state): State<IdentityApiState>,
    Extension(stores): Extension<Arc<TenantOwnershipStores>>,
    Path((raw_kind, id)): Path<(String, String)>,
    delegation: Option<Extension<PatDelegationContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ReassignOwnershipRequest>,
) -> Result<Json<OwnershipReassignmentResponse>, OwnershipApiError> {
    if context.is_some()
        || scope.is_some()
        || delegation
            .as_ref()
            .is_some_and(|Extension(delegation)| delegation.resource_scoped)
    {
        return Err(OwnershipApiError::Forbidden(
            "Resource-scoped access tokens cannot reassign tenant ownership".to_string(),
        ));
    }
    if let Some(tenant_id) = request.tenant_id.as_deref() {
        validate_tenant_id(tenant_id).map_err(|message| OwnershipApiError::BadRequest(message.to_string()))?;
    }
    let kind = parse_owned_kind(&raw_kind)?;
    let resource = load_owned_resource(&state, &stores, kind, &id)
        .await?
        .ok_or_else(|| missing(kind, &id))?;
    if resource.immutable {
        return Err(conflict_response(
            kind,
            &id,
            request.tenant_id,
            vec![OwnershipConflict {
                direction: "immutable".to_string(),
                source: endpoint_from_owned(&resource),
                target: endpoint_from_owned(&resource),
                context: "resource".to_string(),
                reason: "This system-owned resource cannot be reassigned".to_string(),
            }],
        ));
    }
    let references = collect_references(&state, &stores).await?;
    let conflicts = reassignment_conflicts(&references, kind, &id, request.tenant_id.as_deref());
    if !conflicts.is_empty() {
        return Err(conflict_response(kind, &id, request.tenant_id, conflicts));
    }
    let previous_tenant_id = resource.tenant_id;
    persist_tenant_id(&state, &stores, kind, &id, request.tenant_id.clone()).await?;
    Ok(Json(OwnershipReassignmentResponse {
        kind: kind.to_string(),
        id,
        previous_tenant_id,
        tenant_id: request.tenant_id,
    }))
}

fn reassignment_conflicts(
    references: &[OwnershipReference],
    kind: ResourceKind,
    id: &str,
    requested_tenant_id: Option<&str>,
) -> Vec<OwnershipConflict> {
    references
        .iter()
        .filter_map(|reference| {
            let incoming = endpoint_matches(&reference.target, kind, id);
            let outgoing = endpoint_matches(&reference.source, kind, id);
            if !incoming && !outgoing {
                return None;
            }
            let source_tenant = if outgoing {
                requested_tenant_id
            } else {
                reference
                    .source
                    .tenant_id
                    .as_deref()
            };
            let target_tenant = if incoming {
                requested_tenant_id
            } else {
                reference
                    .target
                    .tenant_id
                    .as_deref()
            };
            let reason = if !reference.target.exists {
                Some("Referenced resource does not exist".to_string())
            } else if !can_reference(source_tenant, target_tenant) {
                Some("The proposed tenant would make this reference cross-tenant".to_string())
            } else {
                None
            }?;
            Some(OwnershipConflict {
                direction: if incoming {
                    "incoming"
                } else {
                    "outgoing"
                }
                .to_string(),
                source: reference.source.clone(),
                target: reference.target.clone(),
                context: reference.context.clone(),
                reason,
            })
        })
        .collect()
}

fn endpoint(
    kind: ResourceKind,
    id: &str,
    tenant_id: Option<String>,
    exists: bool,
) -> OwnershipEndpoint {
    OwnershipEndpoint {
        kind: kind.to_string(),
        id: id.to_string(),
        scope_id: id.to_string(),
        tenant_id,
        exists,
    }
}

fn endpoint_from_owned(resource: &OwnedResource) -> OwnershipEndpoint {
    OwnershipEndpoint {
        kind: resource.kind.to_string(),
        id: resource.id.clone(),
        scope_id: resource.scope_id.clone(),
        tenant_id: resource.tenant_id.clone(),
        exists: true,
    }
}

fn endpoint_matches(
    endpoint: &OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
) -> bool {
    endpoint.kind == kind.as_str() && endpoint.id == id
}

fn endpoint_visible(
    endpoint: &OwnershipEndpoint,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    if context.is_none() && scope.is_none() {
        return true;
    }
    let Some(kind) = ResourceKind::from_path_family(&endpoint.kind) else {
        return false;
    };
    can_access(endpoint.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, kind, &endpoint.scope_id)
}

fn reference_visible(
    reference: &OwnershipReference,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    endpoint_visible(&reference.source, context, scope) && endpoint_visible(&reference.target, context, scope)
}

fn conflict_response(
    kind: ResourceKind,
    id: &str,
    requested_tenant_id: Option<String>,
    conflicts: Vec<OwnershipConflict>,
) -> OwnershipApiError {
    OwnershipApiError::Conflict(OwnershipConflictResponse {
        error: "tenant_ownership_conflict",
        kind: kind.to_string(),
        id: id.to_string(),
        requested_tenant_id,
        conflicts,
    })
}

async fn collect_references(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
) -> Result<Vec<OwnershipReference>, OwnershipApiError> {
    let mut references = Vec::new();

    if let Some(store) = state.pipe_store.as_ref() {
        for pipe in store.list().await {
            let source = endpoint(ResourceKind::Pipes, &pipe.id, pipe.tenant_id.clone(), true);
            for reference in super::pipe_tenancy::collect_pipe_reference_keys(&pipe).map_err(|error| {
                OwnershipApiError::Internal(format!("Failed to inspect Pipe references: {:?}", error))
            })? {
                add_reference(
                    state,
                    stores,
                    &mut references,
                    source.clone(),
                    reference.kind,
                    &reference.id,
                    "Pipe configuration",
                )
                .await?;
            }
        }
    }

    if let Some(store) = stores.agent_surfaces.as_ref() {
        for surface in store
            .list_all()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::Surfaces, &surface.surface_id, surface.tenant_id.clone(), true);
            for reference in super::surface_tenancy::collect_surface_reference_keys(&surface).map_err(|error| {
                OwnershipApiError::Internal(format!("Failed to inspect Surface references: {}", error))
            })? {
                add_reference(
                    state,
                    stores,
                    &mut references,
                    source.clone(),
                    reference.kind,
                    &reference.id,
                    "Surface configuration",
                )
                .await?;
            }
        }
    }

    if let Some(store) = stores.gateways.as_ref() {
        for gateway in store
            .list_all()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::Gateways, &gateway.id, gateway.tenant_id.clone(), true);
            if let Some(config) = &gateway.opa_policy_config {
                for id in config.all_policy_definition_ids() {
                    add_reference(
                        state,
                        stores,
                        &mut references,
                        source.clone(),
                        ResourceKind::PolicyDefinitions,
                        &id,
                        "Gateway policy",
                    )
                    .await?;
                }
            }
            for id in &gateway.exposed_channels {
                add_reference(
                    state,
                    stores,
                    &mut references,
                    source.clone(),
                    ResourceKind::Surfaces,
                    id,
                    "Gateway exposed Surface",
                )
                .await?;
            }
            collect_gateway_integrations(state, stores, &mut references, &gateway, source).await?;
        }
    }

    collect_connection_point_references(state, stores, &mut references).await?;
    collect_credential_references(state, stores, &mut references).await?;
    collect_team_references(state, stores, &mut references).await?;
    collect_global_references(state, stores, &mut references).await?;
    Ok(references)
}

async fn collect_connection_point_references(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    let Some(store) = stores
        .connection_points
        .as_ref()
    else {
        return Ok(());
    };
    for connection_point in store
        .list_all()
        .await
        .map_err(internal)?
    {
        let Some(gateway) =
            load_owned_resource(state, stores, ResourceKind::Gateways, &connection_point.gateway_id).await?
        else {
            continue;
        };
        let source = endpoint_from_owned(&gateway);
        let prefix = format!("Connection Point {}", connection_point.id);
        add_reference(
            state,
            stores,
            references,
            source.clone(),
            ResourceKind::Mediators,
            &connection_point.mediator_id,
            &format!("{} Mediator", prefix),
        )
        .await?;
        for id in connection_point
            .integration_id
            .iter()
            .chain(
                connection_point
                    .integrations
                    .iter()
                    .map(|integration| &integration.integration_id),
            )
        {
            add_reference(
                state,
                stores,
                references,
                source.clone(),
                ResourceKind::Integrations,
                id,
                &format!("{} Integration", prefix),
            )
            .await?;
        }
        for id in &connection_point.exposed_channels {
            add_reference(
                state,
                stores,
                references,
                source.clone(),
                ResourceKind::Surfaces,
                id,
                &format!("{} exposed Surface", prefix),
            )
            .await?;
        }
    }
    Ok(())
}

async fn collect_gateway_integrations(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
    gateway: &crate::gateways::types::Gateway,
    source: OwnershipEndpoint,
) -> Result<(), OwnershipApiError> {
    let path = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway.id);
    let storage = crate::integrations::GatewayIntegrationsStorage::new(path)
        .await
        .map_err(internal)?;
    for assignment in storage
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            stores,
            references,
            source.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "Gateway Integration assignment",
        )
        .await?;
    }
    Ok(())
}

async fn collect_credential_references(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    if let Some(store) = stores
        .credential_providers
        .as_ref()
    {
        for provider in store
            .list()
            .await
            .map_err(internal)?
        {
            let source = endpoint(ResourceKind::CredentialProviders, &provider.id, provider.tenant_id.clone(), true);
            for id in [
                provider
                    .client_id_secret_ref
                    .as_deref(),
                provider
                    .client_secret_secret_ref
                    .as_deref(),
                provider
                    .api_key_secret_ref
                    .as_deref(),
            ]
            .into_iter()
            .flatten()
            {
                add_reference(
                    state,
                    stores,
                    references,
                    source.clone(),
                    ResourceKind::Secrets,
                    id,
                    "Credential Provider Secret",
                )
                .await?;
            }
        }
    }
    Ok(())
}

async fn collect_team_references(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    let Some(store) = state.team_store.as_ref() else {
        return Ok(());
    };
    for team in store.list().await {
        let source = endpoint(ResourceKind::Teams, &team.id, team.tenant_id.clone(), true);
        for member_id in &team.members {
            add_reference(
                state,
                stores,
                references,
                source.clone(),
                ResourceKind::Members,
                member_id,
                "Team membership",
            )
            .await?;
        }
    }
    Ok(())
}

async fn collect_global_references(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
) -> Result<(), OwnershipApiError> {
    let appliance = OwnershipEndpoint {
        kind: "appliance".to_string(),
        id: "global".to_string(),
        scope_id: "global".to_string(),
        tenant_id: None,
        exists: true,
    };
    if let Some(store) = state
        .global_policy_store
        .as_ref()
    {
        for (plane, assignments) in store.get().await.assignments {
            for assignment in assignments {
                add_reference(
                    state,
                    stores,
                    references,
                    appliance.clone(),
                    ResourceKind::PolicyDefinitions,
                    &assignment.policy_id,
                    &format!("Global {} policy assignment", plane),
                )
                .await?;
            }
        }
    }
    let root = std::path::PathBuf::from(
        &state
            .bootstrap_config
            .storage_paths
            .integration_triggers,
    );
    let users = crate::integrations::UserIntegrationsStorage::new(root.join("users"))
        .await
        .map_err(internal)?;
    for assignment in users
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            stores,
            references,
            appliance.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "Global user Integration assignment",
        )
        .await?;
    }
    let identities = crate::integrations::IdentityIntegrationsStorage::new(root.join("identities"))
        .await
        .map_err(internal)?;
    for assignment in identities
        .load()
        .await
        .map_err(internal)?
        .integration_integrations
    {
        add_reference(
            state,
            stores,
            references,
            appliance.clone(),
            ResourceKind::Integrations,
            &assignment.integration_id,
            "Global identity Integration assignment",
        )
        .await?;
    }
    Ok(())
}

async fn add_reference(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    references: &mut Vec<OwnershipReference>,
    source: OwnershipEndpoint,
    kind: ResourceKind,
    id: &str,
    context: &str,
) -> Result<(), OwnershipApiError> {
    if id.trim().is_empty() {
        return Ok(());
    }
    let resource = if kind == ResourceKind::Secrets {
        let store = stores
            .secrets
            .as_ref()
            .ok_or_else(|| unavailable(kind))?;
        // The resolution a request uses (internal id, then public id), keyed
        // by the secret's internal id, so a reference by either id names the
        // secret a request would send.
        crate::secrets::resolve_reference(store.as_ref(), id)
            .await
            .map_err(internal)?
            .map(|resource| {
                owned_with_scope_id(kind, resource.id, resource.secret_id, resource.name, resource.tenant_id, false)
            })
    } else if kind == ResourceKind::ApiKeys {
        let key = match stores.api_keys.as_ref() {
            Some(store) => store
                .list_all()
                .await
                .map_err(internal)?
                .into_iter()
                .find(|key| key.key_id == id),
            None => None,
        };
        match key {
            Some(key) => match load_owned_resource(state, stores, ResourceKind::Surfaces, &key.agent_id).await? {
                Some(parent) => Some(parent),
                None => load_owned_resource(state, stores, ResourceKind::Pipes, &key.agent_id).await?,
            },
            None => None,
        }
    } else {
        load_owned_resource(state, stores, kind, id).await?
    };
    let target = match resource {
        Some(resource) => endpoint_from_owned(&resource),
        None => endpoint(kind, id, None, false),
    };
    references.push(OwnershipReference {
        source,
        target,
        context: context.to_string(),
    });
    Ok(())
}

fn parse_owned_kind(raw: &str) -> Result<ResourceKind, OwnershipApiError> {
    let kind = ResourceKind::from_path_family(raw)
        .ok_or_else(|| OwnershipApiError::BadRequest(format!("Unsupported resource kind: {}", raw)))?;
    if matches!(kind, ResourceKind::ApiKeys | ResourceKind::ConnectionPoints) {
        return Err(OwnershipApiError::BadRequest(format!(
            "{} ownership is inherited from its parent and cannot be reassigned directly",
            kind
        )));
    }
    Ok(kind)
}

async fn load_owned_resource(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    kind: ResourceKind,
    id: &str,
) -> Result<Option<OwnedResource>, OwnershipApiError> {
    let resource = match kind {
        ResourceKind::Secrets => stores
            .secrets
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| {
                owned_with_scope_id(kind, resource.id, resource.secret_id, resource.name, resource.tenant_id, false)
            }),
        ResourceKind::Certificates => stores
            .certificates
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(OwnershipApiError::Internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::Pipes => state
            .pipe_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::Surfaces => stores
            .agent_surfaces
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.surface_id, resource.name, resource.tenant_id, false)),
        ResourceKind::Gateways => stores
            .gateways
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| {
                let immutable = resource.gateway_type == crate::gateways::types::GatewayType::SelfGateway;
                owned(kind, resource.id, resource.name, resource.tenant_id, immutable)
            }),
        ResourceKind::Mediators => stores
            .mediators
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::Integrations => match stores.integrations.as_ref() {
            Some(store) => store
                .load(id)
                .await
                .ok()
                .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
            None => return Err(unavailable(kind)),
        },
        ResourceKind::PolicyDefinitions => state
            .policy_definition_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::PipeTemplates => state
            .llm_surface_template_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| {
                let immutable = resource.builtin;
                owned(kind, resource.id, resource.name, resource.tenant_id, immutable)
            }),
        ResourceKind::CredentialProviders => stores
            .credential_providers
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::JwtVerificationStrategies => stores
            .jwt_strategies
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::OauthIdentifiers => stores
            .oauth_identifiers
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map_err(internal)?
            .map(|resource| owned(kind, resource.id, resource.name, resource.owner_tenant_id, false)),
        ResourceKind::Prompts => state
            .prompt_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, false)),
        ResourceKind::Members => state
            .member_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| {
                let name = resource.display_label();
                owned(kind, resource.id, name, resource.tenant_id, resource.system)
            }),
        ResourceKind::Teams => state
            .team_store
            .as_ref()
            .ok_or_else(|| unavailable(kind))?
            .get(id)
            .await
            .map(|resource| owned(kind, resource.id, resource.name, resource.tenant_id, resource.system)),
        ResourceKind::ApiKeys | ResourceKind::ConnectionPoints => None,
    };
    Ok(resource)
}

async fn persist_tenant_id(
    state: &IdentityApiState,
    stores: &TenantOwnershipStores,
    kind: ResourceKind,
    id: &str,
    tenant_id: Option<String>,
) -> Result<(), OwnershipApiError> {
    match kind {
        ResourceKind::Secrets => {
            stores
                .secrets
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Certificates => {
            stores
                .certificates
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(OwnershipApiError::Internal)?;
        }
        ResourceKind::Pipes => {
            let store = state
                .pipe_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = Some(chrono::Utc::now().to_rfc3339());
            store
                .save(resource)
                .await
                .map_err(internal)?;
            crate::pipes::cache::invalidate_pipe_cache(id).await;
        }
        ResourceKind::Surfaces => {
            let store = stores
                .agent_surfaces
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .save(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Gateways => {
            let store = stores
                .gateways
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Mediators => {
            let store = stores
                .mediators
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Integrations => {
            let store = stores
                .integrations
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .load(id)
                .await
                .map_err(internal)?;
            ensure_integration_may_be_owned(&resource, tenant_id.as_deref())?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now().to_rfc3339();
            store
                .update(id, &resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::PolicyDefinitions => {
            state
                .policy_definition_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?
                .set_tenant_id(id, tenant_id)
                .await
                .map_err(internal)?;
        }
        ResourceKind::PipeTemplates => {
            let store = state
                .llm_surface_template_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = Some(chrono::Utc::now().to_rfc3339());
            store
                .save(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::CredentialProviders => {
            let store = stores
                .credential_providers
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::JwtVerificationStrategies => {
            let store = stores
                .jwt_strategies
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::OauthIdentifiers => {
            let store = stores
                .oauth_identifiers
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .map_err(internal)?
                .ok_or_else(|| missing(kind, id))?;
            resource.owner_tenant_id = tenant_id;
            store
                .update(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Prompts => {
            let store = state
                .prompt_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            resource.updated_at = chrono::Utc::now();
            store
                .save(&resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Members => {
            let store = state
                .member_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .save(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::Teams => {
            let store = state
                .team_store
                .as_ref()
                .ok_or_else(|| unavailable(kind))?;
            let mut resource = store
                .get(id)
                .await
                .ok_or_else(|| missing(kind, id))?;
            resource.tenant_id = tenant_id;
            store
                .save(resource)
                .await
                .map_err(internal)?;
        }
        ResourceKind::ApiKeys | ResourceKind::ConnectionPoints => {
            return Err(OwnershipApiError::BadRequest(format!("{} cannot be reassigned directly", kind)));
        }
    }
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);
    Ok(())
}

fn owned(
    kind: ResourceKind,
    id: String,
    name: String,
    tenant_id: Option<String>,
    immutable: bool,
) -> OwnedResource {
    OwnedResource {
        kind,
        scope_id: id.clone(),
        id,
        name,
        tenant_id,
        immutable,
    }
}

fn owned_with_scope_id(
    kind: ResourceKind,
    id: String,
    scope_id: String,
    name: String,
    tenant_id: Option<String>,
    immutable: bool,
) -> OwnedResource {
    OwnedResource {
        kind,
        id,
        scope_id,
        name,
        tenant_id,
        immutable,
    }
}

/// Governance audit integrations receive appliance-wide audit evidence, so they
/// stay appliance-global.
fn ensure_integration_may_be_owned(
    integration: &crate::storage::Integration,
    tenant_id: Option<&str>,
) -> Result<(), OwnershipApiError> {
    if tenant_id.is_some() && crate::integrations::audit_integration_triggers::is_audit_integration(integration) {
        return Err(OwnershipApiError::BadRequest(
            "Governance audit integrations are appliance-wide and cannot belong to a tenant".to_string(),
        ));
    }
    Ok(())
}

fn unavailable(kind: ResourceKind) -> OwnershipApiError {
    OwnershipApiError::Internal(format!("{} store not configured", kind))
}

fn missing(
    kind: ResourceKind,
    id: &str,
) -> OwnershipApiError {
    OwnershipApiError::NotFound(format!("{} '{}' not found", kind, id))
}

fn internal(error: impl std::fmt::Display) -> OwnershipApiError {
    OwnershipApiError::Internal(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_integrations_stay_appliance_global() {
        let integration = |category: &str| {
            crate::storage::Integration::new(
                "Integration".to_string(),
                String::new(),
                "stream".to_string(),
                serde_json::json!({}),
                serde_json::json!({}),
                "active".to_string(),
                Some(category.to_string()),
            )
        };
        assert!(matches!(
            ensure_integration_may_be_owned(&integration("audit"), Some("tenant-a")),
            Err(OwnershipApiError::BadRequest(_))
        ));
        assert!(ensure_integration_may_be_owned(&integration("audit"), None).is_ok());
        assert!(ensure_integration_may_be_owned(&integration("gateway"), Some("tenant-a")).is_ok());
    }

    #[test]
    fn inherited_resource_kinds_cannot_be_reassigned() {
        for kind in ["api-keys", "connection-points"] {
            assert!(matches!(parse_owned_kind(kind), Err(OwnershipApiError::BadRequest(_))));
        }
        assert_eq!(parse_owned_kind("pipes").unwrap(), ResourceKind::Pipes);
        assert!(matches!(parse_owned_kind("notifications"), Err(OwnershipApiError::BadRequest(_))));
    }

    #[test]
    fn tenant_ids_are_validated_before_reassignment() {
        assert!(validate_tenant_id("tenant-a").is_ok());
        assert!(validate_tenant_id("tenant/a").is_err());
    }

    fn reference(
        source_tenant: Option<&str>,
        target_tenant: Option<&str>,
        target_exists: bool,
    ) -> OwnershipReference {
        OwnershipReference {
            source: endpoint(ResourceKind::Pipes, "pipe-1", source_tenant.map(str::to_string), true),
            target: endpoint(ResourceKind::Secrets, "secret-1", target_tenant.map(str::to_string), target_exists),
            context: "Pipe configuration".into(),
        }
    }

    #[test]
    fn reassignment_detects_outgoing_and_incoming_conflicts() {
        let outgoing = reference(Some("tenant-a"), Some("tenant-a"), true);
        let conflicts = reassignment_conflicts(&[outgoing], ResourceKind::Pipes, "pipe-1", Some("tenant-b"));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].direction, "outgoing");

        let incoming = reference(Some("tenant-a"), None, true);
        let conflicts = reassignment_conflicts(&[incoming], ResourceKind::Secrets, "secret-1", Some("tenant-b"));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].direction, "incoming");
    }

    #[test]
    fn reassignment_allows_compatible_links_and_rejects_missing_targets() {
        let compatible = reference(Some("tenant-a"), None, true);
        assert!(reassignment_conflicts(&[compatible], ResourceKind::Pipes, "pipe-1", Some("tenant-a")).is_empty());

        let missing = reference(Some("tenant-a"), None, false);
        let conflicts = reassignment_conflicts(&[missing], ResourceKind::Pipes, "pipe-1", Some("tenant-a"));
        assert_eq!(conflicts.len(), 1);
        assert_eq!(conflicts[0].reason, "Referenced resource does not exist");
    }
}
