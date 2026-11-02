//! API handlers for team management.
//!
//! Teams group appliance members (by their server-assigned UUID) so their spend
//! and token usage across **any** surface type can be aggregated and capped
//! together. CRUD is admin-gated via the `teams.*` RBAC features; usage is read
//! from the process-wide [`crate::teams::TeamUsageTracker`].

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::entity_status::EntityStatus;
use crate::identity::state::IdentityApiState;
use crate::members::FileSystemMemberStore;
use crate::rbac::{Feature, RbacConfig};
use crate::teams::types::Team;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, tenant_for_create,
};

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Resolve the configured team store or fail.
fn store(state: &IdentityApiState) -> ApiResult<Arc<crate::teams::FileSystemTeamStore>> {
    state
        .team_store
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team store not configured".to_string()))
}

/// Resolve the configured member store or fail.
fn member_store(state: &IdentityApiState) -> ApiResult<Arc<FileSystemMemberStore>> {
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

fn team_allowed(
    team: &Team,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(team.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Teams, &team.id)
}

fn member_allowed(
    member: &crate::members::types::Member,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(member.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Members, &member.id)
}

/// Ensure every member id referenced by a team exists in the registry.
async fn validate_member_references(
    member_store: &FileSystemMemberStore,
    owner_tenant_id: Option<&str>,
    member_ids: &[String],
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> ApiResult<()> {
    for id in member_ids {
        let member = member_store
            .get(id)
            .await
            .filter(|member| !member.status.is_deleted())
            .ok_or((StatusCode::BAD_REQUEST, "Member reference is not accessible".to_string()))?;
        if !can_reference(owner_tenant_id, member.tenant_id.as_deref()) || !member_allowed(&member, context, scope) {
            return Err((StatusCode::BAD_REQUEST, "Member reference is not accessible".to_string()));
        }
    }
    Ok(())
}

/// `GET /v1/teams` — list all teams.
pub async fn list_teams(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<Team>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsView).await?;
    let teams = store(&state)?
        .list()
        .await
        .into_iter()
        .filter(|t| !t.status.is_deleted())
        .filter(|team| team_allowed(team, &context, &scope))
        .collect();
    Ok(Json(teams))
}

/// `GET /v1/teams/{id}` — fetch a single team.
pub async fn get_team(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(team_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Team>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsView).await?;
    store(&state)?
        .get(&team_id)
        .await
        .filter(|team| team_allowed(team, &context, &scope))
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))
}

/// `POST /v1/teams` — create a team. The server assigns the UUID id; any id in
/// the request body is ignored.
pub async fn create_team(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut team): Json<Team>,
) -> ApiResult<Json<Team>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsEdit).await?;
    let team_store = store(&state)?;
    let member_store = member_store(&state)?;

    crate::config::enforce_add("teams")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;

    team.id = uuid::Uuid::new_v4().to_string();
    // `system` is server-controlled: only the default-config seeder may mint a
    // protected record, never an API client.
    team.system = false;
    team.tenant_id = tenant_for_create(team.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    if !team_allowed(&team, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Team is outside this token's permitted scope".into()));
    }
    team.normalize();
    team.validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid team: {e}")))?;
    validate_member_references(&member_store, team.tenant_id.as_deref(), &team.members, &context, &scope).await?;

    let now = chrono::Utc::now();
    team.created_at = now;
    team.updated_at = now;
    team_store
        .save(team.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save team: {e}")))?;

    team_store
        .get(&team.id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team disappeared after save".to_string()))
}

/// `PUT /v1/teams/{id}` — replace a team's configuration.
pub async fn update_team(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(team_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(mut team): Json<Team>,
) -> ApiResult<Json<Team>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsEdit).await?;
    let team_store = store(&state)?;
    let member_store = member_store(&state)?;

    let existing = team_store
        .get(&team_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))?;
    if !team_allowed(&existing, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Team is outside this token's permitted scope".into()));
    }

    team.id = team_id.clone();
    team.tenant_id = existing.tenant_id.clone();
    team.normalize();
    team.validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid team: {e}")))?;
    validate_member_references(&member_store, team.tenant_id.as_deref(), &team.members, &context, &scope).await?;

    team.created_at = existing.created_at;
    // `system` is server-controlled and cannot be flipped via the API.
    team.system = existing.system;
    team.tenant_id = existing.tenant_id;
    team_store
        .save(team.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save team: {e}")))?;

    team_store
        .get(&team_id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team disappeared after save".to_string()))
}

/// `DELETE /v1/teams/{id}` — soft-delete a team by marking its status
/// `deleted`. The record is retained on disk so historical usage attribution
/// survives; a deleted team no longer contributes quotas or blocks member
/// deletion.
pub async fn delete_team(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(team_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<StatusCode> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsDelete).await?;
    let team_store = store(&state)?;

    let mut team = team_store
        .get(&team_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))?;
    if !team_allowed(&team, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Team is outside this token's permitted scope".into()));
    }

    // Built-in system teams (e.g. the anonymous default team) must always exist.
    // Admins disable them (not delete them) to require explicit team membership.
    if team.system {
        return Err((
            StatusCode::BAD_REQUEST,
            "This is a built-in system team and cannot be deleted. Disable it instead.".to_string(),
        ));
    }

    team.status = EntityStatus::Deleted;
    team.updated_at = chrono::Utc::now();
    team_store
        .save(team)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete team: {e}")))?;
    // Drop the team's usage time-series — the record is tombstoned, its graph
    // can never accrue again.
    crate::telemetry::remove_team_series(&team_id).await;
    Ok(StatusCode::NO_CONTENT)
}

/// Request body for adding a member to a team by member id.
#[derive(Debug, Deserialize)]
pub struct AddMemberRequest {
    pub member_id: String,
}

/// `POST /v1/teams/{id}/members` — add a member to the team by member id.
pub async fn add_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(team_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(req): Json<AddMemberRequest>,
) -> ApiResult<Json<Team>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsEdit).await?;
    let team_store = store(&state)?;
    let member_store = member_store(&state)?;

    let mut team = team_store
        .get(&team_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))?;
    if !team_allowed(&team, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Team is outside this token's permitted scope".into()));
    }
    validate_member_references(
        &member_store,
        team.tenant_id.as_deref(),
        std::slice::from_ref(&req.member_id),
        &context,
        &scope,
    )
    .await?;

    if !team.has_member(&req.member_id) {
        team.members
            .push(req.member_id.clone());
    }
    team.normalize();
    team.validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid team: {e}")))?;
    team_store
        .save(team.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save team: {e}")))?;

    team_store
        .get(&team_id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team disappeared after save".to_string()))
}

/// `DELETE /v1/teams/{id}/members/{member_id}` — remove a member from the team.
pub async fn remove_member(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path((team_id, member_id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Team>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsEdit).await?;
    let team_store = store(&state)?;

    let mut team = team_store
        .get(&team_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))?;
    if !team_allowed(&team, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Team is outside this token's permitted scope".into()));
    }
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Members, &member_id) {
        return Err((StatusCode::FORBIDDEN, "Member is outside this token's permitted scope".into()));
    }

    let before = team.members.len();
    team.members
        .retain(|m| m != &member_id);
    if team.members.len() == before {
        return Err((StatusCode::NOT_FOUND, format!("Member not found: {member_id}")));
    }

    team_store
        .save(team.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save team: {e}")))?;

    team_store
        .get(&team_id)
        .await
        .map(Json)
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team disappeared after save".to_string()))
}

/// Per-member usage row in a team usage report.
#[derive(Debug, Serialize)]
pub struct MemberUsageReport {
    pub member_id: String,
    pub label: String,
    pub total_cost: f64,
    pub total_tokens: u64,
    pub monthly_budget_usd: Option<f64>,
    pub monthly_token_cap: Option<u64>,
    pub period_start: chrono::DateTime<chrono::Utc>,
    pub period_end: chrono::DateTime<chrono::Utc>,
}

impl MemberUsageReport {
    pub async fn for_member(
        tracker: &crate::teams::TeamUsageTracker,
        member_id: &str,
        member: Option<&crate::members::Member>,
    ) -> Self {
        let (period, usage) = tracker
            .member_usage(member_id, member.and_then(|m| m.budget_period_anchor))
            .await;
        Self {
            member_id: member_id.to_string(),
            label: member.map_or_else(|| member_id.to_string(), |m| m.display_label()),
            total_cost: usage.total_cost,
            total_tokens: usage.total_tokens,
            monthly_budget_usd: member.and_then(|m| m.monthly_budget_usd),
            monthly_token_cap: member.and_then(|m| m.monthly_token_cap),
            period_start: period.start,
            period_end: period.end,
        }
    }
}

/// Current-month usage report for a team and its members.
#[derive(Debug, Serialize)]
pub struct TeamUsageReport {
    pub team_id: String,
    pub name: String,
    pub total_cost: f64,
    pub total_tokens: u64,
    pub monthly_budget_usd: Option<f64>,
    pub monthly_token_cap: Option<u64>,
    pub members: Vec<MemberUsageReport>,
}

/// `GET /v1/teams/{id}/usage` — aggregated and per-member usage for the month.
pub async fn team_usage(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(team_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<TeamUsageReport>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::TeamsView).await?;
    let team = store(&state)?
        .get(&team_id)
        .await
        .ok_or((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")))?;
    if !team_allowed(&team, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, format!("Team not found: {team_id}")));
    }
    let member_store = member_store(&state)?;

    let tracker = state
        .team_usage_tracker
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Team usage tracker not configured".to_string()))?;

    let agg = tracker
        .team_usage(&team_id)
        .await;
    let mut members = Vec::with_capacity(team.members.len());
    for member_id in &team.members {
        let resolved = member_store
            .get(member_id)
            .await;
        if resolved
            .as_ref()
            .is_some_and(|member| !member_allowed(member, &context, &scope))
        {
            continue;
        }
        members.push(MemberUsageReport::for_member(&tracker, member_id, resolved.as_ref()).await);
    }

    Ok(Json(TeamUsageReport {
        team_id: team.id,
        name: team.name,
        total_cost: agg.total_cost,
        total_tokens: agg.total_tokens,
        monthly_budget_usd: team.monthly_budget_usd,
        monthly_token_cap: team.monthly_token_cap,
        members,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::types::{Member, MemberIdentifier};

    fn team(tenant_id: Option<&str>) -> Team {
        Team {
            id: "team-1".into(),
            name: "Team".into(),
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: tenant_id.map(str::to_string),
            test_fixture: false,
            monthly_budget_usd: None,
            monthly_token_cap: None,
            members: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    fn member(
        id: &str,
        tenant_id: Option<&str>,
    ) -> Member {
        Member {
            id: id.into(),
            name: Some(id.into()),
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: tenant_id.map(str::to_string),
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Custom { value: id.into() }],
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

    #[tokio::test]
    async fn a_member_usage_report_follows_the_members_own_period() {
        let dir = std::env::temp_dir().join(format!("member_usage_report_{}", uuid::Uuid::new_v4()));
        let tracker = crate::teams::TeamUsageTracker::new(dir).await;
        let anchor = chrono::Utc::now() - chrono::Duration::days(2);
        let mut anchored = member("m1", None);
        anchored.budget_period_anchor = Some(anchor);
        anchored.monthly_budget_usd = Some(10.0);
        tracker
            .record("m1", Some(anchor), &[], 3.5, 12)
            .await;

        let report = MemberUsageReport::for_member(&tracker, "m1", Some(&anchored)).await;
        assert_eq!(report.period_start, anchor);
        assert_eq!(report.total_cost, 3.5);
        assert_eq!(report.total_tokens, 12);
        assert_eq!(report.monthly_budget_usd, Some(10.0));

        let unknown = MemberUsageReport::for_member(&tracker, "ghost", None).await;
        assert_eq!(unknown.label, "ghost");
        assert_eq!(unknown.total_cost, 0.0);
        assert_eq!(
            unknown.period_start,
            crate::members::BudgetPeriod::containing(None, chrono::Utc::now()).start,
            "without a member record the calendar month applies"
        );
    }

    fn pat_context() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    fn pat_scope() -> Option<Extension<PatResourceScope>> {
        Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:(?:teams:team-1|members:member-(?:same|global))\z").unwrap(),
        ))))
    }

    #[tokio::test]
    async fn team_access_and_member_references_enforce_tenant_kind_and_id() {
        let context = pat_context();
        let scope = pat_scope();
        assert!(team_allowed(&team(Some("tenant-a")), &context, &scope));
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!team_allowed(&team(None), &context, &scope));
        assert!(!team_allowed(&team(Some("tenant-b")), &context, &scope));

        let temp = tempfile::tempdir().unwrap();
        let member_store = FileSystemMemberStore::new(
            temp.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        member_store
            .save(member("member-same", Some("tenant-a")))
            .await
            .unwrap();
        member_store
            .save(member("member-global", None))
            .await
            .unwrap();
        member_store
            .save(member("member-foreign", Some("tenant-b")))
            .await
            .unwrap();

        assert!(
            validate_member_references(&member_store, Some("tenant-a"), &["member-same".into()], &context, &scope,)
                .await
                .is_ok()
        );
        // member-global (untenanted/legacy) is no longer referenceable by a tenant
        // PAT — fail-closed hardening (a global member is not a tenant resource).
        assert!(
            validate_member_references(&member_store, Some("tenant-a"), &["member-global".into()], &context, &scope,)
                .await
                .is_err()
        );
        assert!(
            validate_member_references(&member_store, Some("tenant-a"), &["member-foreign".into()], &context, &scope,)
                .await
                .is_err()
        );
        let team_only_scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:teams:team-1\z").unwrap(),
        ))));
        assert!(
            validate_member_references(
                &member_store,
                Some("tenant-a"),
                &["member-same".into()],
                &context,
                &team_only_scope,
            )
            .await
            .is_err()
        );
    }
}
