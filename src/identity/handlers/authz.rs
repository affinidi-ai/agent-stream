//! Handler-local authorization shared by routes that gate inside the handler
//! (rather than with `RbacGuard::gate` on the route).

use axum::http::StatusCode;

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::PatContext;
use crate::rbac::{Feature, RbacConfig};

/// Require `feature` for the caller: the caller's role must hold it and, when the
/// request carries an access token with an explicit scope list, that list must
/// name it. Every handler-local gate calls this one function, so a route cannot
/// check the role and forget the token's scope.
pub(crate) async fn require_feature(
    caller_id: &str,
    storage: &PasskeyStorage,
    rbac: &RbacConfig,
    pat: Option<&PatContext>,
    feature: &Feature,
) -> Result<(), (StatusCode, String)> {
    let caller = storage
        .load_user_by_id(caller_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load caller: {e}")))?
        .ok_or((StatusCode::UNAUTHORIZED, "Caller not found".to_string()))?;
    // A role denial and a token-scope denial get the same 403, as with the
    // route-level `RbacGuard` gates.
    if !rbac.has_permission(&caller.role, feature) || !crate::auth_manager::middleware::pat_scope_allows(pat, feature) {
        return Err((StatusCode::FORBIDDEN, "Insufficient permissions".to_string()));
    }
    Ok(())
}
