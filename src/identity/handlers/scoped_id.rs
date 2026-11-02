//! Shared tenant-ownership check for read endpoints that take a surface/pipe id
//! from the QUERY STRING (`?surface_id=` / `?pipe_id=`).
//!
//! Families such as `/v1/governance/*`, `/v1/drift/*`, `/v1/telemetry/*`,
//! `/v1/spend-report` and `/v1/pipes-metrics` are classified `Unscoped` by the
//! canonical-path classifier (`auth_manager::pat::classify_canonical_resource_path`)
//! because the identifier is in the query, not the path. As a result
//! `require_session_auth` does NOT enforce a resource-scoped token's namespace on
//! them, so a tenant-scoped PAT can read another tenant's records by naming a
//! foreign id. The tenant-owned resource behind a `surface_id`/`pipe_id` is the
//! Pipe (in stream the tenant-facing surface *is* the pipe), so the check
//! resolves the pipe and confirms the caller may access it — the same rule the
//! by-id pipe routes apply in `pipes::pipe_allowed`.
//!
//! Fails closed with 404 (never 403) on any mismatch, so a foreign id and an
//! unknown id are indistinguishable — no cross-tenant existence oracle.

use axum::Extension;
use axum::http::StatusCode;

use crate::auth_manager::pat::PatResourceScope;
use crate::pipes::FileSystemPipeStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

/// Borrow the tenant context out of the optional extractor.
pub fn tenant_ctx(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(c)| c)
}

/// Borrow the resource scope out of the optional extractor.
pub fn res_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(s)| s)
}

/// Authorize a caller for a surface/pipe referenced by id from the query string.
///
/// * An appliance session or appliance-wide token (`context` and `scope` both
///   `None`) is unrestricted — returns `Ok(())` without touching the store.
/// * Otherwise the pipe is resolved and BOTH tenant ownership (`can_access`) and
///   the token's id-namespace (`scope_allows_resource`) must hold. Any failure —
///   pipe store absent, unknown pipe, foreign tenant, or out-of-namespace id —
///   returns `404 Not Found` (fail closed, no existence oracle).
pub async fn authorize_surface_scope(
    surface_id: &str,
    pipe_store: Option<&FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, String)> {
    // Appliance caller: no tenant confinement applies.
    if context.is_none() && scope.is_none() {
        return Ok(());
    }
    // A tenant/resource-scoped caller must resolve the referenced surface to a
    // pipe we can tenant-check. Without a store we cannot verify ownership, so
    // fail closed.
    let Some(store) = pipe_store else {
        return Err((StatusCode::NOT_FOUND, "Not found".to_string()));
    };
    let Some(pipe) = store.get(surface_id).await else {
        return Err((StatusCode::NOT_FOUND, "Not found".to_string()));
    };
    if can_access(pipe.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Pipes, &pipe.id)
    {
        Ok(())
    } else {
        Err((StatusCode::NOT_FOUND, "Not found".to_string()))
    }
}

/// Authorize one telemetry / ops **series key** for a query-string caller.
///
/// Series keys embed the entity id: `surface:{id}`, `surface:{id}:stage:{s}`,
/// `rejection:surface:{id}[:stage:{s}]`, and non-surface `member:{id}`,
/// `team:{id}`, `surfaces:all`, `ops:*`, `rejection:all`. For an appliance
/// caller every key is allowed. For a tenant/resource-scoped caller only a
/// **surface** key whose pipe the caller owns is allowed; member/team/appliance
/// aggregate keys cross tenants and are denied (404, fail closed).
pub async fn authorize_series_key(
    key: &str,
    pipe_store: Option<&FileSystemPipeStore>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, String)> {
    if context.is_none() && scope.is_none() {
        return Ok(());
    }
    match surface_id_from_series_key(key) {
        Some(id) => authorize_surface_scope(id, pipe_store, context, scope).await,
        // Attributed (member/team) or appliance-wide aggregate key: a
        // tenant-scoped caller may not read cross-tenant aggregates.
        None => Err((StatusCode::NOT_FOUND, "Not found".to_string())),
    }
}

/// The surface id embedded in a series key, when the key is surface-scoped.
/// Handles `surface:{id}`, `surface:{id}:stage:{stage}`,
/// `rejection:surface:{id}` and `rejection:surface:{id}:stage:{stage}`.
fn surface_id_from_series_key(key: &str) -> Option<&str> {
    let rest = key
        .strip_prefix("surface:")
        .or_else(|| key.strip_prefix("rejection:surface:"))?;
    // The id runs up to the next ':' (the `:stage:` suffix) or to the end.
    Some(
        rest.split(':')
            .next()
            .unwrap_or(rest),
    )
}
