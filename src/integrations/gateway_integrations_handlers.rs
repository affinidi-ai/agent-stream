use axum::{Extension, extract::Path, http::StatusCode, response::Json};
use serde_json::{Value, json};
use std::sync::Arc;
use tracing::{error, info};

use crate::auth_manager::pat::PatResourceScope;
use crate::config::BootstrapConfig;
use crate::gateways::GatewayStore;
use crate::integrations::gateway_integrations_storage::{GatewayIntegrationsConfig, GatewayIntegrationsStorage};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource};

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

async fn load_gateway(
    gateway_store: &crate::gateways::FileSystemGatewayStore,
    gateway_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    mutation: bool,
) -> Result<crate::gateways::types::Gateway, (StatusCode, Json<Value>)> {
    let gateway = gateway_store
        .get(gateway_id)
        .await
        .map_err(|error| {
            error!(%gateway_id, %error, "Failed to load gateway for integration assignment");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Failed to load gateway" })))
        })?
        .ok_or_else(|| (StatusCode::NOT_FOUND, Json(json!({ "error": "Gateway not found" }))))?;
    let allowed = can_access(gateway.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Gateways, &gateway.id);
    if !allowed {
        let status = if mutation {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::NOT_FOUND
        };
        return Err((status, Json(json!({ "error": "Gateway not accessible" }))));
    }
    Ok(gateway)
}

/// GET /api/v1/gateways/:id/integrations
/// Get the gateway integrations configuration for a specific gateway
pub async fn get_gateway_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Path(gateway_id): Path<String>,
    Extension(gateway_store): Extension<Arc<crate::gateways::FileSystemGatewayStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    load_gateway(gateway_store.as_ref(), &gateway_id, &context, &scope, false).await?;
    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway_id);

    let storage = GatewayIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create gateway integrations storage for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    let config = storage
        .load()
        .await
        .map_err(|e| {
            error!("Failed to load gateway integrations for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to load gateway integrations"
                })),
            )
        })?;

    Ok(Json(json!(config)))
}

/// PUT /api/v1/gateways/:id/integrations
/// Update the gateway integrations configuration for a specific gateway
pub async fn update_gateway_integrations(
    Extension(config): Extension<Arc<BootstrapConfig>>,
    Extension(gateway_store): Extension<Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(integration_store): Extension<Option<Arc<crate::storage::IntegrationStorage>>>,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(payload): Json<GatewayIntegrationsConfig>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let gateway = load_gateway(gateway_store.as_ref(), &gateway_id, &context, &scope, true).await?;
    let integration_store = integration_store.ok_or_else(|| {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({ "error": "Integration store not configured" })))
    })?;
    for assignment in &payload.integration_integrations {
        let integration = integration_store
            .load(&assignment.integration_id)
            .await
            .map_err(|_| {
                (StatusCode::BAD_REQUEST, Json(json!({ "error": "Integration reference is not accessible" })))
            })?;
        if !can_reference(
            gateway.tenant_id.as_deref(),
            integration
                .tenant_id
                .as_deref(),
        ) || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::Integrations,
            &integration.id,
        ) {
            return Err((StatusCode::BAD_REQUEST, Json(json!({ "error": "Integration reference is not accessible" }))));
        }
        if crate::integrations::audit_integration_triggers::is_audit_integration(&integration) {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(
                    json!({ "error": crate::integrations::audit_integration_triggers::AUDIT_INTEGRATION_NOT_LINKABLE }),
                ),
            ));
        }
    }
    info!(
        "Updating gateway integrations for gateway {} with {} integrations",
        gateway_id,
        payload
            .integration_integrations
            .len()
    );

    // Log each integration's event_types for debugging
    for (idx, integration) in payload
        .integration_integrations
        .iter()
        .enumerate()
    {
        info!(
            "Integration {}: integration_id={}, event_types={:?}, variables={:?}",
            idx,
            integration.integration_id,
            integration.event_types,
            integration.variables.keys()
        );
    }

    let storage_path = std::path::PathBuf::from(
        &config
            .storage_paths
            .integration_triggers,
    )
    .join("gateways")
    .join(&gateway_id);

    let storage = GatewayIntegrationsStorage::new(storage_path)
        .await
        .map_err(|e| {
            error!("Failed to create gateway integrations storage for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to initialize storage"
                })),
            )
        })?;

    storage
        .save(&payload)
        .await
        .map_err(|e| {
            error!("Failed to save gateway integrations for gateway {}: {}", gateway_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": "Failed to save gateway integrations"
                })),
            )
        })?;

    info!("Successfully saved gateway integrations for gateway {}", gateway_id);
    Ok(Json(json!({
        "message": "Gateway integrations updated successfully",
        "integration_integrations": payload.integration_integrations
    })))
}
