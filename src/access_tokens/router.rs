//! Router for the management access-token admin API. Every route is RBAC-gated
//! (`access_tokens.*`, administrator by default). The `RbacConfig` is layered so
//! the create handler can validate requested scopes against known permissions.

use std::sync::Arc;

use axum::routing::{delete, get, post, put};
use axum::{Extension, Router};

use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::{Feature, RbacConfig};

use super::handlers;
use super::store::FsAccessTokenStore;

pub fn create_access_tokens_router(
    store: Arc<FsAccessTokenStore>,
    rbac_config: Arc<RbacConfig>,
    tenancy_config: Arc<crate::tenancy::TenancyConfig>,
    gate: RbacGuard,
) -> Router {
    let user_storage = gate.storage.clone();
    Router::new()
        .route("/api/v1/access-tokens", gate.gate(get(handlers::list_access_tokens), Feature::AccessTokensView))
        .route("/api/v1/access-tokens", gate.gate(post(handlers::create_access_token), Feature::AccessTokensEdit))
        .route("/api/v1/access-tokens/{id}", gate.gate(get(handlers::get_access_token), Feature::AccessTokensView))
        .route("/api/v1/access-tokens/{id}", gate.gate(put(handlers::update_access_token), Feature::AccessTokensEdit))
        .route(
            "/api/v1/access-tokens/{id}/rotate",
            gate.gate(post(handlers::rotate_access_token), Feature::AccessTokensEdit),
        )
        .route(
            "/api/v1/access-tokens/{id}",
            gate.gate(delete(handlers::revoke_access_token), Feature::AccessTokensDelete),
        )
        .layer(Extension(tenancy_config))
        .layer(Extension(rbac_config))
        .layer(Extension(user_storage))
        .with_state(store)
}
