//! Delegation vault API router

use super::handlers::{self, DelegationVaultState};
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;
use axum::{
    Router,
    routing::{delete, get},
};

/// Create the delegation vault management API router.
/// Management routes only — must be mounted inside the session-auth boundary.
pub fn create_delegation_vault_router(
    state: DelegationVaultState,
    gate: RbacGuard,
) -> Router {
    Router::new()
        .route("/api/v1/delegation-vault", gate.gate(get(handlers::list_tokens), Feature::DelegationVaultView))
        .route("/api/v1/delegation-vault/{id}", gate.gate(get(handlers::get_token), Feature::DelegationVaultView))
        .route(
            "/api/v1/delegation-vault/{id}",
            gate.gate(delete(handlers::revoke_token), Feature::DelegationVaultDelete),
        )
        .route(
            "/api/v1/delegation-vault/by-user/{user_hash}",
            gate.gate(delete(handlers::revoke_user_tokens), Feature::DelegationVaultDelete),
        )
        .route("/api/v1/delegation-audit", gate.gate(get(handlers::list_audit_events), Feature::AuditView))
        .with_state(state)
}

/// Create the OAuth callback router.
/// This is the only delegation-vault route that must remain public, because
/// the user's browser is redirected here from the OAuth provider.
pub fn create_delegation_vault_oauth_router(state: DelegationVaultState) -> Router {
    let callback_route = format!("{}/{{provider_id}}", state.oauth_callback_route);
    Router::new()
        .route(&callback_route, get(handlers::oauth_callback))
        .with_state(state)
}
