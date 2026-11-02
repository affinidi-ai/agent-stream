//! Credential providers API router

use super::{handlers, storage::CredentialProviderStorage};
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;

/// Create the credential providers API router
pub fn create_credential_providers_router(
    store: Arc<dyn CredentialProviderStorage>,
    secrets_store: Arc<dyn crate::secrets::SecretsStore>,
    oauth_callback_route: String,
    gate: RbacGuard,
) -> Router {
    let state = handlers::CredentialProviderState {
        store,
        secrets_store,
        oauth_callback_route,
    };
    Router::new()
        .route(
            "/api/v1/credential-providers/validate",
            gate.gate(post(handlers::validate_provider), Feature::CredentialProvidersEdit),
        )
        .route(
            "/api/v1/credential-providers",
            gate.gate(post(handlers::create_provider), Feature::CredentialProvidersEdit),
        )
        .route(
            "/api/v1/credential-providers",
            gate.gate(get(handlers::list_providers), Feature::CredentialProvidersView),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            gate.gate(get(handlers::get_provider), Feature::CredentialProvidersView),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            gate.gate(put(handlers::update_provider), Feature::CredentialProvidersEdit),
        )
        .route(
            "/api/v1/credential-providers/{id}",
            gate.gate(delete(handlers::delete_provider), Feature::CredentialProvidersDelete),
        )
        .with_state(state)
}
