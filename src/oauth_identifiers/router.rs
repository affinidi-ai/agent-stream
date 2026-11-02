//! OAuth Identifier router — CRUD endpoints under `/api/v1/oauth-identifiers`.

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use super::handlers::{self, OAuthIdentifierState};
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;

/// Create the OAuth Identifiers router.
///
/// **Important:** the caller must `.layer` the session-auth middleware and the
/// `Extension<Arc<PasskeyStorage>>` / `Extension<Arc<RbacConfig>>` extensions
/// before merging this router (same pattern as the JWT verification strategy
/// routes in `src/identity/router.rs`).
pub fn create_oauth_identifiers_router(
    state: OAuthIdentifierState,
    gate: RbacGuard,
) -> Router {
    Router::new()
        .route("/v1/oauth-identifiers", gate.gate(post(handlers::create_identifier), Feature::OauthIdentifiersEdit))
        .route("/v1/oauth-identifiers", gate.gate(get(handlers::list_identifiers), Feature::OauthIdentifiersView))
        .route("/v1/oauth-identifiers/{id}", gate.gate(get(handlers::get_identifier), Feature::OauthIdentifiersView))
        .route("/v1/oauth-identifiers/{id}", gate.gate(put(handlers::update_identifier), Feature::OauthIdentifiersEdit))
        .route(
            "/v1/oauth-identifiers/{id}",
            gate.gate(delete(handlers::delete_identifier), Feature::OauthIdentifiersDelete),
        )
        .with_state(state)
}
