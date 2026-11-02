// Router for vault identity endpoints

use super::handlers::*;
use crate::auth_manager::middleware::RbacGuard;
use crate::identity::VCIssuer;
use crate::rbac::Feature;
use axum::{Router, routing::post};
use std::sync::Arc;

/// Create the vault identity router
pub fn create_vault_identity_router(
    vc_issuer: Arc<VCIssuer>,
    gate: RbacGuard,
) -> Router {
    Router::new()
        .route("/api/v1/vault/identity/generate", gate.gate(post(generate_identity), Feature::VaultIdentitiesEdit))
        .with_state(vc_issuer)
}
