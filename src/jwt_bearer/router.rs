//! JWT verification strategy router
//!
//! Registers the five CRUD endpoints under `/api/v1/jwt-verification-strategies`.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use super::handlers::{self, JwtVerificationStrategyState};
use crate::auth_manager::middleware::{RbacGuard, maybe_gate};
use crate::rbac::Feature;

/// Create the JWT verification strategies router.
///
/// **Important:** the caller must `.layer` the session-auth middleware and the
/// `Extension<Arc<PasskeyStorage>>` / `Extension<Arc<RbacConfig>>` /
/// `Extension<Arc<JwksClient>>` extensions before merging this router (follow
/// the same pattern used for user-management routes in `src/identity/router.rs`).
pub fn create_jwt_verification_strategies_router(
    state: JwtVerificationStrategyState,
    gate: RbacGuard,
) -> Router {
    create_router(state, Some(&gate))
}

#[cfg(test)]
pub(crate) fn create_unprotected_jwt_verification_strategies_router(state: JwtVerificationStrategyState) -> Router {
    create_router(state, None)
}

fn create_router(
    state: JwtVerificationStrategyState,
    gate: Option<&RbacGuard>,
) -> Router {
    Router::new()
        // validate-jwks-uri must be registered BEFORE /{id} to avoid path conflicts
        .route(
            "/v1/jwt-verification-strategies/validate-jwks-uri",
            maybe_gate(gate, post(handlers::validate_jwks_uri), Feature::JwtVerificationStrategiesEdit),
        )
        .route(
            "/v1/jwt-verification-strategies",
            maybe_gate(gate, post(handlers::create_strategy), Feature::JwtVerificationStrategiesEdit),
        )
        .route(
            "/v1/jwt-verification-strategies",
            maybe_gate(gate, get(handlers::list_strategies), Feature::JwtVerificationStrategiesView),
        )
        .route(
            "/v1/jwt-verification-strategies/{id}",
            maybe_gate(gate, get(handlers::get_strategy), Feature::JwtVerificationStrategiesView),
        )
        .route(
            "/v1/jwt-verification-strategies/{id}",
            maybe_gate(gate, put(handlers::update_strategy), Feature::JwtVerificationStrategiesEdit),
        )
        .route(
            "/v1/jwt-verification-strategies/{id}",
            maybe_gate(gate, delete(handlers::delete_strategy), Feature::JwtVerificationStrategiesDelete),
        )
        .with_state(state)
}
