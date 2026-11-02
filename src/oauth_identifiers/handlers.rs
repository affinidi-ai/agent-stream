//! OAuth Identifier CRUD HTTP handlers.
//!
//! All endpoints require the caller to hold the matching `oauth_identifiers.*`
//! RBAC feature (view for reads, edit for create/update, delete for delete).

use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::oauth_identifiers::{
    OAuthIdentifierStorage,
    models::{OAuthIdentifier, OAuthIdentifierShape},
};
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

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

fn identifier_allowed(
    identifier: &OAuthIdentifier,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(
        identifier
            .owner_tenant_id
            .as_deref(),
        tenant_context(context),
    ) && scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::OauthIdentifiers,
        &identifier.id,
    )
}

/// Axum state type for OAuth Identifier handlers.
pub type OAuthIdentifierState = Arc<dyn OAuthIdentifierStorage>;

/// Body for `POST`/`PUT`. `id`, `created_at`, `updated_at` are server-managed.
#[derive(Debug, Deserialize)]
pub struct OAuthIdentifierRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Provider-specific authority shape (flattened `provider` tag + fields).
    #[serde(flatten)]
    pub shape: OAuthIdentifierShape,
    pub client_id: String,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub owner_tenant_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

impl ErrorBody {
    fn json(msg: impl Into<String>) -> Json<Self> {
        Json(Self { error: msg.into() })
    }
}

async fn require_permission(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
    feature: &Feature,
) -> Result<(), (StatusCode, Json<ErrorBody>)> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| {
            error!("Failed to load user {} for RBAC check: {}", user_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Internal server error"))
        })?
        .ok_or_else(|| (StatusCode::UNAUTHORIZED, ErrorBody::json("User not found")))?;

    if !rbac_config.has_permission(&user.role, feature) {
        warn!(
            user_id = %user_id,
            feature = %feature.as_str(),
            "OAuth Identifier CRUD rejected — insufficient permissions"
        );
        return Err((StatusCode::FORBIDDEN, ErrorBody::json("Insufficient permissions")));
    }
    Ok(())
}

/// Trim blank scopes so a textarea with trailing newlines round-trips cleanly.
fn clean_scopes(scopes: Vec<String>) -> Vec<String> {
    scopes
        .into_iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// `POST /v1/oauth-identifiers` — create a new profile.
pub async fn create_identifier(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<OAuthIdentifierState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut body): Json<OAuthIdentifierRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::OauthIdentifiersEdit).await {
        return e.into_response();
    }

    if let Err(e) = crate::config::enforce_add("credentials.oauth").await {
        return (StatusCode::FORBIDDEN, ErrorBody::json(e.message())).into_response();
    }

    body.owner_tenant_id = match tenant_for_create(body.owner_tenant_id.take(), pat.is_some(), tenant_context(&context))
    {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, ErrorBody::json(message)).into_response(),
    };

    let profile = OAuthIdentifier {
        id: uuid::Uuid::new_v4().to_string(),
        name: body.name,
        description: body.description,
        shape: body.shape,
        client_id: body.client_id,
        scopes: clean_scopes(body.scopes),
        owner_tenant_id: body.owner_tenant_id,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    if !identifier_allowed(&profile, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("profile is outside this token's permitted scope"))
            .into_response();
    }

    if let Err(msg) = profile.validate() {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(msg)).into_response();
    }

    match store.create(profile).await {
        Ok(created) => {
            info!(id = %created.id, name = %created.name, "OAuth Identifier created");
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => {
            error!("Failed to create OAuth Identifier: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to create profile")).into_response()
        }
    }
}

/// `GET /v1/oauth-identifiers` — list all profiles.
pub async fn list_identifiers(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<OAuthIdentifierState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::OauthIdentifiersView).await {
        return e.into_response();
    }

    match store.list().await {
        Ok(mut profiles) => {
            profiles.retain(|profile| identifier_allowed(profile, &context, &scope));
            profiles.sort_by(|a, b| {
                b.created_at
                    .cmp(&a.created_at)
            });
            (StatusCode::OK, Json(profiles)).into_response()
        }
        Err(e) => {
            error!("Failed to list OAuth Identifiers: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to list profiles")).into_response()
        }
    }
}

/// `GET /v1/oauth-identifiers/{id}` — get a profile by UUID.
pub async fn get_identifier(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<OAuthIdentifierState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::OauthIdentifiersView).await {
        return e.into_response();
    }

    match store.get(&id).await {
        Ok(Some(profile)) if identifier_allowed(&profile, &context, &scope) => {
            (StatusCode::OK, Json(profile)).into_response()
        }
        Ok(Some(_)) => (StatusCode::NOT_FOUND, ErrorBody::json(format!("Profile '{}' not found", id))).into_response(),
        Ok(None) => (StatusCode::NOT_FOUND, ErrorBody::json(format!("Profile '{}' not found", id))).into_response(),
        Err(e) => {
            error!("Failed to get OAuth Identifier {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to get profile")).into_response()
        }
    }
}

/// `PUT /v1/oauth-identifiers/{id}` — update a profile. The `id` cannot change.
pub async fn update_identifier(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<OAuthIdentifierState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(body): Json<OAuthIdentifierRequest>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::OauthIdentifiersEdit).await {
        return e.into_response();
    }

    let existing = match store.get(&id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Profile '{}' not found", id))).into_response();
        }
        Err(e) => {
            error!("Failed to load OAuth Identifier {} for update: {}", id, e);
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to load profile")).into_response();
        }
    };
    if !identifier_allowed(&existing, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("profile is outside this token's permitted scope"))
            .into_response();
    }

    let updated = OAuthIdentifier {
        id: existing.id.clone(),
        name: body.name,
        description: body.description,
        shape: body.shape,
        client_id: body.client_id,
        scopes: clean_scopes(body.scopes),
        owner_tenant_id: existing.owner_tenant_id,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now(),
    };

    if let Err(msg) = updated.validate() {
        return (StatusCode::BAD_REQUEST, ErrorBody::json(msg)).into_response();
    }

    match store.update(updated).await {
        Ok(profile) => {
            info!(id = %profile.id, name = %profile.name, "OAuth Identifier updated");
            (StatusCode::OK, Json(profile)).into_response()
        }
        Err(e) => {
            error!("Failed to update OAuth Identifier {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to update profile")).into_response()
        }
    }
}

/// `DELETE /v1/oauth-identifiers/{id}` — delete a profile.
pub async fn delete_identifier(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    axum::extract::State(store): axum::extract::State<OAuthIdentifierState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(e) = require_permission(&user_id, &passkey_storage, &rbac_config, &Feature::OauthIdentifiersDelete).await
    {
        return e.into_response();
    }

    let existing = match store.get(&id).await {
        Ok(Some(profile)) => profile,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, ErrorBody::json(format!("Profile '{}' not found", id))).into_response();
        }
        Err(error) => {
            error!(%error, "Failed to load OAuth Identifier before deletion");
            return (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to load profile")).into_response();
        }
    };
    if !identifier_allowed(&existing, &context, &scope) {
        return (StatusCode::FORBIDDEN, ErrorBody::json("profile is outside this token's permitted scope"))
            .into_response();
    }

    match store.delete(&id).await {
        Ok(()) => {
            info!(id = %id, "OAuth Identifier deleted");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(e) => {
            error!("Failed to delete OAuth Identifier {}: {}", id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, ErrorBody::json("Failed to delete profile")).into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identifier(owner_tenant_id: Option<&str>) -> OAuthIdentifier {
        OAuthIdentifier {
            id: "identifier-1".into(),
            name: "Identifier".into(),
            description: String::new(),
            shape: OAuthIdentifierShape::Entra {
                tenant_id: "entra-authority-tenant".into(),
            },
            client_id: "client-id".into(),
            scopes: vec!["openid".into()],
            owner_tenant_id: owner_tenant_id.map(str::to_string),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn canonical_identifier_access_uses_owner_not_authority_tenant() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:oauth-identifiers:identifier-1\z").unwrap(),
        ))));

        assert!(identifier_allowed(&identifier(Some("tenant-a")), &context, &scope));
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!identifier_allowed(&identifier(None), &context, &scope));
        assert!(!identifier_allowed(&identifier(Some("tenant-b")), &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:jwt-verification-strategies:identifier-1\z").unwrap(),
        ))));
        assert!(!identifier_allowed(&identifier(Some("tenant-a")), &context, &wrong_kind));
    }
}
