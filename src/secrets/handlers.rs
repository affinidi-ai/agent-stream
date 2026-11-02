//! Secrets API handlers

use super::{CreateSecretRequest, RevealSecretValues, SecretListItem, SecretsStore, UpdateSecretRequest};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::config::network::SecretsConfig;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::error;

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

/// The secret types the dashboard offers and whether stored values can be read
/// back (`secrets` in agent-stream.json, as loaded at startup).
pub async fn get_secrets_settings(Extension(settings): Extension<Arc<SecretsConfig>>) -> Json<SecretsConfig> {
    Json(settings.as_ref().clone())
}

/// List all secrets (without sensitive values). A resource-scoped token sees
/// only the secrets whose `secret_id` is inside its namespace.
pub async fn list_secrets(
    State(store): State<Arc<dyn SecretsStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.list_all().await {
        Ok(mut secrets) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            secrets.retain(|secret| {
                can_access(secret.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
            });
            (StatusCode::OK, Json(secrets)).into_response()
        }
        Err(e) => {
            error!("Failed to list secrets: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// Get a specific secret by ID. The stored value is included only while
/// `secrets.reveal_values` is on; off, the record is answered without it.
pub async fn get_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(RevealSecretValues(reveal_values)): Extension<RevealSecretValues>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.get(&id).await {
        Ok(Some(secret))
            if can_access(secret.tenant_id.as_deref(), tenant_context(&context))
                && scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Secrets,
                    &secret.secret_id,
                ) =>
        {
            if reveal_values {
                (StatusCode::OK, Json(secret)).into_response()
            } else {
                (StatusCode::OK, Json(SecretListItem::from(secret))).into_response()
            }
        }
        Ok(Some(_)) => (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, "Secret not found").into_response(),
        Err(e) => {
            error!("Failed to get secret {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}

/// Create a new secret
pub async fn create_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateSecretRequest>,
) -> impl IntoResponse {
    request.tenant_id = match tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => {
            return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": message }))).into_response();
        }
    };
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::Secrets,
        &request.secret_id,
    ) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "message": "secret_id is outside this token's permitted namespace" })),
        )
            .into_response();
    }
    if let Err(message) = super::validate_secret_id(&request.secret_id) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "message": message }))).into_response();
    }
    // Enforce appliance secret limits (per-type plus the cross-store total).
    if let Err(e) = crate::config::enforce_add("secrets.secret").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": e.message() }))).into_response();
    }
    match store.create(request).await {
        Ok(secret) => {
            // Trigger integration event (without sensitive value)
            let trigger_secret = crate::integrations::secrets_integration_triggers::Secret {
                id: secret.id.clone(),
                name: secret.name.clone(),
                description: secret
                    .description
                    .clone()
                    .unwrap_or_default(),
                tags: secret.tags.clone(),
                created_at: secret.created_at.to_rfc3339(),
                updated_at: secret.updated_at.to_rfc3339(),
            };
            if let Some(store) = notification_store {
                tokio::spawn(async move {
                    crate::integrations::trigger_secret_created(&store, &trigger_secret).await;
                });
            }

            (StatusCode::CREATED, Json(secret)).into_response()
        }
        Err(e) => {
            error!("Failed to create secret: {}", e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

/// Update an existing secret
pub async fn update_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(secrets_cache): Extension<Option<crate::secrets::SecretsCache>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateSecretRequest>,
) -> impl IntoResponse {
    // Get old secret first for triggers
    let old_secret_result = store.get(&id).await;

    // A resource-scoped token may not modify a secret outside its namespace. A
    // lookup failure must fail closed too — falling through to the update
    // would otherwise let a scoped token mutate a secret it could not be
    // confirmed to own.
    let context_ref = tenant_context(&context);
    let scope_ref = resource_scope(&scope);
    match &old_secret_result {
        Ok(Some(existing))
            if !can_access(existing.tenant_id.as_deref(), context_ref)
                || !scope_allows_resource(scope_ref, context_ref, ResourceKind::Secrets, &existing.secret_id) =>
        {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "secret is outside this token's permitted namespace" })),
            )
                .into_response();
        }
        Err(e) if scope_ref.is_some() || context_ref.is_some() => {
            error!("Failed to look up secret {} for scope check: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "failed to verify resource scope" })),
            )
                .into_response();
        }
        _ => {}
    }

    match store
        .update(&id, request)
        .await
    {
        Ok(secret) => {
            // Trigger integration event if we have the old secret
            if let Ok(Some(old_secret)) = old_secret_result {
                let old_trigger = crate::integrations::secrets_integration_triggers::Secret {
                    id: old_secret.id.clone(),
                    name: old_secret.name.clone(),
                    description: old_secret
                        .description
                        .clone()
                        .unwrap_or_default(),
                    tags: old_secret.tags.clone(),
                    created_at: old_secret
                        .created_at
                        .to_rfc3339(),
                    updated_at: old_secret
                        .updated_at
                        .to_rfc3339(),
                };
                let new_trigger = crate::integrations::secrets_integration_triggers::Secret {
                    id: secret.id.clone(),
                    name: secret.name.clone(),
                    description: secret
                        .description
                        .clone()
                        .unwrap_or_default(),
                    tags: secret.tags.clone(),
                    created_at: secret.created_at.to_rfc3339(),
                    updated_at: secret.updated_at.to_rfc3339(),
                };
                if let Some(store) = notification_store {
                    tokio::spawn(async move {
                        crate::integrations::trigger_secret_updated(&store, &old_trigger, &new_trigger).await;
                    });
                }
            }

            if let Some(cache) = secrets_cache {
                crate::secrets::clear_secret_cache(&secret, &cache);
            }
            crate::pipes::cache::invalidate_executors().await;

            (StatusCode::OK, Json(secret)).into_response()
        }
        Err(e) => {
            error!("Failed to update secret {}: {}", id, e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

/// Delete a secret
pub async fn delete_secret(
    State(store): State<Arc<dyn SecretsStore>>,
    Extension(notification_store): Extension<Option<Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(secrets_cache): Extension<Option<crate::secrets::SecretsCache>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    // Get secret before deletion for triggers
    let secret_result = store.get(&id).await;

    // A resource-scoped token may not delete a secret outside its namespace. A
    // lookup failure must fail closed too, for the same reason as update_secret.
    let context_ref = tenant_context(&context);
    let scope_ref = resource_scope(&scope);
    match &secret_result {
        Ok(Some(existing))
            if !can_access(existing.tenant_id.as_deref(), context_ref)
                || !scope_allows_resource(scope_ref, context_ref, ResourceKind::Secrets, &existing.secret_id) =>
        {
            return (
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({ "message": "secret is outside this token's permitted namespace" })),
            )
                .into_response();
        }
        Err(e) if scope_ref.is_some() || context_ref.is_some() => {
            error!("Failed to look up secret {} for scope check: {}", id, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "message": "failed to verify resource scope" })),
            )
                .into_response();
        }
        _ => {}
    }

    match store.delete(&id).await {
        Ok(_) => {
            // Trigger integration event if we have the secret
            if let Ok(Some(secret)) = secret_result {
                let trigger_secret = crate::integrations::secrets_integration_triggers::Secret {
                    id: secret.id.clone(),
                    name: secret.name.clone(),
                    description: secret
                        .description
                        .clone()
                        .unwrap_or_default(),
                    tags: secret.tags.clone(),
                    created_at: secret.created_at.to_rfc3339(),
                    updated_at: secret.updated_at.to_rfc3339(),
                };
                if let Some(store) = notification_store {
                    tokio::spawn(async move {
                        crate::integrations::trigger_secret_deleted(&store, &trigger_secret).await;
                    });
                }

                if let Some(cache) = secrets_cache {
                    crate::secrets::clear_secret_cache(&secret, &cache);
                }
            }
            crate::pipes::cache::invalidate_executors().await;

            (StatusCode::NO_CONTENT, "").into_response()
        }
        Err(e) => {
            error!("Failed to delete secret {}: {}", id, e);
            let error_message = e.to_string();
            let error_json = serde_json::json!({
                "message": error_message
            });
            (StatusCode::BAD_REQUEST, Json(error_json)).into_response()
        }
    }
}

/// Search secrets by tag. A resource-scoped token sees only matches inside its
/// namespace.
pub async fn find_by_tag(
    State(store): State<Arc<dyn SecretsStore>>,
    Path(tag): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match store.find_by_tag(&tag).await {
        Ok(mut secrets) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            secrets.retain(|secret| {
                can_access(secret.tenant_id.as_deref(), context)
                    && scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
            });
            (StatusCode::OK, Json(secrets)).into_response()
        }
        Err(e) => {
            error!("Failed to search secrets by tag {}: {}", tag, e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
        }
    }
}
