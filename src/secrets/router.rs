//! Secrets API router

use super::{RevealSecretValues, SecretsStore, handlers};
use crate::auth_manager::middleware::RbacGuard;
use crate::config::network::SecretsConfig;
use crate::rbac::Feature;
use axum::{
    Extension, Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

/// Create the secrets API router.
///
/// Every route is gated on the corresponding `secrets.*` RBAC feature because
/// read endpoints expose secret inventory and detail can expose the stored
/// secret value.
pub fn create_secrets_router(
    secrets_store: Arc<dyn SecretsStore>,
    notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    secrets_cache: Option<crate::secrets::SecretsCache>,
    settings: SecretsConfig,
    gate: RbacGuard,
) -> Router {
    Router::new()
        .route("/api/v1/secrets", gate.gate(get(handlers::list_secrets), Feature::SecretsView))
        .route("/api/v1/secrets/", gate.gate(get(handlers::list_secrets), Feature::SecretsView))
        .route("/api/v1/secrets/new", gate.gate(post(handlers::create_secret), Feature::SecretsEdit))
        .route("/api/v1/secrets/settings", gate.gate(get(handlers::get_secrets_settings), Feature::SecretsEdit))
        .route("/api/v1/secrets/{id}", gate.gate(get(handlers::get_secret), Feature::SecretsView))
        .route("/api/v1/secrets/{id}", gate.gate(put(handlers::update_secret), Feature::SecretsEdit))
        .route("/api/v1/secrets/{id}", gate.gate(delete(handlers::delete_secret), Feature::SecretsDelete))
        .route("/api/v1/secrets/tag/{tag}", gate.gate(get(handlers::find_by_tag), Feature::SecretsView))
        .layer(Extension(notification_store))
        .layer(Extension(secrets_cache))
        .layer(Extension(RevealSecretValues(settings.reveal_values)))
        .layer(Extension(Arc::new(settings)))
        .with_state(secrets_store)
}
