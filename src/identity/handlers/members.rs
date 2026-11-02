//! API handlers for member management.
//!
//! Members are the appliance's **clients** — callers that consume LLM (or any
//! future surface) capacity, identified by a configurable credential and kept
//! distinct from the administrator users who sign in to operate the appliance.
//! CRUD is admin-gated via the `members.*` RBAC features. The server assigns
//! each member a UUID id; teams reference members by that id.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::entity_status::EntityStatus;
use crate::identity::state::IdentityApiState;
use crate::members::FileSystemMemberStore;
use crate::members::types::Member;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Resolve the configured member store or fail.
fn store(state: &IdentityApiState) -> ApiResult<Arc<FileSystemMemberStore>> {
    state
        .member_store
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Member store not configured".to_string()))
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn member_allowed(
    member: &Member,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(member.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Members, &member.id)
}

/// `GET /v1/members` — list all members.
pub async fn list_members(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<Member>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersView).await?;
    let members = store(&state)?
        .list()
        .await
        .into_iter()
        .filter(|m| !m.status.is_deleted())
        .filter(|member| member_allowed(member, &context, &scope))
        .collect();
    Ok(Json(members))
}

/// `GET /v1/members/{id}` — fetch a single member.
pub async fn get_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(member_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Member>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersView).await?;
    store(&state)?
        .get(&member_id)
        .await
        .filter(|member| member_allowed(member, &context, &scope))
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, format!("Member not found: {member_id}")))
}

/// `GET /v1/members/{id}/usage` - the member's spend and tokens in its current
/// budget period, as the enforcement gate counts them.
pub async fn get_member_usage(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(member_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<crate::identity::handlers::teams::MemberUsageReport>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersView).await?;
    let member = store(&state)?
        .get(&member_id)
        .await
        .filter(|member| !member.status.is_deleted())
        .filter(|member| member_allowed(member, &context, &scope))
        .ok_or((StatusCode::NOT_FOUND, format!("Member not found: {member_id}")))?;
    let tracker = state
        .team_usage_tracker
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team usage tracker not configured".to_string()))?;
    Ok(Json(crate::identity::handlers::teams::MemberUsageReport::for_member(&tracker, &member.id, Some(&member)).await))
}

/// `POST /v1/members` — create a member. The server assigns the UUID id; any id
/// in the request body is ignored.
pub async fn create_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut member): Json<Member>,
) -> ApiResult<Json<Member>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersEdit).await?;
    let member_store = store(&state)?;

    crate::config::enforce_add("members")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;

    member.id = uuid::Uuid::new_v4().to_string();
    // `system` is server-controlled: only the default-config seeder may mint a
    // protected record, never an API client.
    member.system = false;
    member.tenant_id = tenant_for_create(member.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    if !member_allowed(&member, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Member is outside this token's permitted scope".into()));
    }
    member
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid member: {e}")))?;

    if member_store
        .identifier_in_use(&member.match_value(), None)
        .await
    {
        return Err((
            StatusCode::CONFLICT,
            format!("A member with identifier '{}' already exists", member.match_value()),
        ));
    }

    let now = chrono::Utc::now();
    member.created_at = now;
    member.updated_at = now;
    member_store
        .save(member.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save member: {e}")))?;

    member_store
        .get(&member.id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Member disappeared after save".to_string()))
}

/// `PUT /v1/members/{id}` — replace a member's configuration.
pub async fn update_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(member_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(mut member): Json<Member>,
) -> ApiResult<Json<Member>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersEdit).await?;
    let member_store = store(&state)?;

    let existing = member_store
        .get(&member_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Member not found: {member_id}")))?;
    if !member_allowed(&existing, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Member is outside this token's permitted scope".into()));
    }

    member.id = member_id.clone();
    member
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid member: {e}")))?;

    if member_store
        .identifier_in_use(&member.match_value(), Some(&member_id))
        .await
    {
        return Err((
            StatusCode::CONFLICT,
            format!("A member with identifier '{}' already exists", member.match_value()),
        ));
    }

    member.created_at = existing.created_at;
    // `system` is server-controlled and cannot be flipped via the API.
    member.system = existing.system;
    member.tenant_id = existing.tenant_id;
    member_store
        .save(member.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save member: {e}")))?;

    member_store
        .get(&member_id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Member disappeared after save".to_string()))
}

/// `DELETE /v1/members/{id}` — soft-delete a member by marking its status
/// `deleted`. The record is retained on disk so historical usage attribution
/// survives. Refuses while the member still belongs to a team so quotas never
/// reference a dangling id.
pub async fn delete_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(member_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<StatusCode> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::MembersDelete).await?;
    let member_store = store(&state)?;

    let mut member = member_store
        .get(&member_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Member not found: {member_id}")))?;
    if !member_allowed(&member, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Member is outside this token's permitted scope".into()));
    }

    // Built-in system members (e.g. the anonymous fallback identity) must always
    // exist. Admins disable them (not delete them) to reject unrecognised
    // callers.
    if member.system {
        return Err((
            StatusCode::BAD_REQUEST,
            "This is a built-in system member and cannot be deleted. Disable it instead.".to_string(),
        ));
    }

    if let Some(team_store) = state.team_store.clone() {
        let teams = team_store
            .teams_referencing_member(&member_id)
            .await;
        if !teams.is_empty() {
            let names: Vec<String> = teams
                .iter()
                .map(|t| t.name.clone())
                .collect();
            return Err((
                StatusCode::CONFLICT,
                format!("Member belongs to team(s): {}. Remove them first.", names.join(", ")),
            ));
        }
    }

    member.status = EntityStatus::Deleted;
    member.updated_at = chrono::Utc::now();
    member_store
        .save(member)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete member: {e}")))?;
    // Drop the member's usage time-series — the record is tombstoned, its graph
    // can never accrue again.
    crate::telemetry::remove_member_series(&member_id).await;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::types::MemberIdentifier;

    fn member(tenant_id: Option<&str>) -> Member {
        Member {
            id: "member-1".into(),
            name: Some("Member".into()),
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: tenant_id.map(str::to_string),
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Custom { value: "member-1".into() }],
            monthly_budget_usd: None,
            monthly_token_cap: None,
            budget_period_anchor: None,
            requests_per_minute: None,
            tokens_per_minute: None,
            allowed_models: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn canonical_member_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:members:member-1\z").unwrap(),
        ))));

        assert!(member_allowed(&member(Some("tenant-a")), &context, &scope));
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!member_allowed(&member(None), &context, &scope));
        assert!(!member_allowed(&member(Some("tenant-b")), &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:teams:member-1\z").unwrap(),
        ))));
        assert!(!member_allowed(&member(Some("tenant-a")), &context, &wrong_kind));
    }
}
