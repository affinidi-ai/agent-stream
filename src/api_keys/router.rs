//! API Key router

use axum::{
    Extension, Router,
    routing::{delete, get, post},
};
use std::sync::Arc;

use super::handlers::{self, ApiKeyState};
use super::parent::ApiKeyParents;
use super::traits::ApiKeyStore;
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;

/// Create the API keys router
///
/// Mounts the following routes:
/// - GET    /api/v1/api-keys                         - List all keys across all agents
/// - GET    /api/v1/api-keys/{agent_id}             - List keys for an agent
/// - POST   /api/v1/api-keys/{agent_id}             - Create key
/// - GET    /api/v1/api-keys/{agent_id}/{key_id}    - Get key metadata
/// - POST   /api/v1/api-keys/{agent_id}/{key_id}/revoke  - Revoke key
/// - POST   /api/v1/api-keys/{agent_id}/{key_id}/rotate  - Rotate key
/// - DELETE /api/v1/api-keys/{agent_id}/{key_id}    - Delete key
///
/// Every route is gated on the corresponding `api_keys.*` RBAC feature because
/// key metadata and key detail are secret-bearing control-plane data.
pub fn create_api_keys_router<S: ApiKeyStore + 'static>(
    store: Arc<S>,
    parents: ApiKeyParents,
    gate: RbacGuard,
) -> Router {
    let state: ApiKeyState = store;

    Router::new()
        .route("/api/v1/api-keys", gate.gate(get(handlers::list_all_keys), Feature::ApiKeysView))
        .route("/api/v1/api-keys/{agent_id}", gate.gate(get(handlers::list_keys), Feature::ApiKeysView))
        .route("/api/v1/api-keys/{agent_id}", gate.gate(post(handlers::create_key), Feature::ApiKeysEdit))
        .route("/api/v1/api-keys/{agent_id}/{key_id}", gate.gate(get(handlers::get_key), Feature::ApiKeysView))
        .route(
            "/api/v1/api-keys/{agent_id}/{key_id}/revoke",
            gate.gate(post(handlers::revoke_key), Feature::ApiKeysEdit),
        )
        .route(
            "/api/v1/api-keys/{agent_id}/{key_id}/rotate",
            gate.gate(post(handlers::rotate_key), Feature::ApiKeysEdit),
        )
        .route("/api/v1/api-keys/{agent_id}/{key_id}", gate.gate(delete(handlers::delete_key), Feature::ApiKeysDelete))
        .layer(Extension(parents))
        .with_state(state)
}
