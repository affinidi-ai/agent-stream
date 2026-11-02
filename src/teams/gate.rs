//! Data-plane team gate.
//!
//! A single, surface-type agnostic entry point used by every surface handler to
//! (1) decide whether a request must be blocked because the caller may not use
//! the surface, is over a per-minute rate, or has reached a team or member
//! token cap, (2) hand the request the budgets its platform-key model calls are
//! checked against (see [`crate::teams::call_budget`]), and (3) record the
//! execution's spend and tokens against the caller's member and teams
//! afterwards. It reads the process-wide member store, team store, and usage
//! tracker, so it degrades to a no-op when teams are not configured.

use crate::members::global_member_provisioner;
use crate::members::store::global_member_store;
use crate::members::types::{ANONYMOUS_MEMBER_ID, Member};
use crate::source_auth::AuthenticatedIdentity;
use crate::teams::TeamAttributionConfig;
use crate::teams::call_budget::CallBudget;
use crate::teams::caller_identity::extract_first_caller_identity;
use crate::teams::global_member_rate_limiter;
use crate::teams::store::global_team_store;
use crate::teams::types::{ANONYMOUS_TEAM_ID, Team};
use crate::teams::usage_tracker::global_team_usage_tracker;
use axum::http::{HeaderMap, StatusCode};
use std::sync::Arc;

/// Details of a member auto-provisioned during a request, so the handler can
/// emit a `member.auto_provisioned` integration event off the response path.
#[derive(Debug, Clone)]
pub struct ProvisionedInfo {
    pub member_id: String,
    pub member_label: String,
    /// The primary identifier the caller was recognised by.
    pub identifier: String,
    pub team_ids: Vec<String>,
    pub team_names: Vec<String>,
}

/// The member and teams a recorded execution should be attributed to.
#[derive(Debug, Clone)]
pub struct TeamUsageContext {
    pub member_id: String,
    pub budget_period_anchor: Option<chrono::DateTime<chrono::Utc>>,
    pub teams: Vec<Team>,
    /// `Some` only when this request auto-provisioned a **new** member, so the
    /// handler can fire the `member.auto_provisioned` event once.
    pub provisioned: Option<ProvisionedInfo>,
    /// The budgets this request's platform-key calls are checked against, on a
    /// surface that enforces quotas; `None` when nothing is enforced. Run the
    /// execution inside [`crate::teams::call_budget::scope`] with it.
    pub call_budget: Option<Arc<CallBudget>>,
}

/// Outcome of the pre-execution team check.
pub enum TeamGateDecision {
    /// No attribution applies (disabled, or stores not configured). Proceed
    /// with the request; nothing to record.
    Skip,
    /// Proceed and record usage against this context after execution.
    Allow(TeamUsageContext),
    /// Block the request with the given HTTP status, machine code, and a
    /// human-readable reason. `FORBIDDEN` is an access denial (disabled member,
    /// missing/unpermitted team); `TOO_MANY_REQUESTS` is a per-minute rate or a
    /// token cap. A spent budget never blocks here: it refuses the request's
    /// platform-key calls instead (see [`crate::teams::call_budget`]).
    Block { status: StatusCode, code: &'static str, reason: String },
}

/// Resolve the caller's member and teams and decide whether the request may
/// proceed.
///
/// Resolution is special-case free: every request is mapped to a member (the
/// built-in anonymous member when the caller can't be matched) and to a team
/// (the built-in anonymous team when the member belongs to no other enabled
/// team). An admin controls access purely by toggling entity status — disabling
/// the anonymous member rejects unrecognised callers, disabling the anonymous
/// team requires explicit team membership — with no code path of its own.
///
/// `body` should be the parsed request body (or `Value::Null` when not
/// available); it is only consulted for a
/// [`crate::teams::caller_identity::CallerIdentitySource::BodyJsonPath`] source.
pub async fn team_pre_check(
    attribution: Option<&TeamAttributionConfig>,
    headers: &HeaderMap,
    identity: Option<&AuthenticatedIdentity>,
    body: &serde_json::Value,
) -> TeamGateDecision {
    let Some(attr) = attribution else {
        return TeamGateDecision::Skip;
    };
    if !attr.enabled {
        return TeamGateDecision::Skip;
    }
    let Some(member_store) = global_member_store() else {
        return gate_unavailable(attr, "the member store is not configured");
    };
    let Some(team_store) = global_team_store() else {
        return gate_unavailable(attr, "the team store is not configured");
    };

    // Resolve the caller to a member, falling back to the built-in anonymous
    // member when the caller can't be extracted or matched. When the caller is
    // unrecognised but verified and the surface opts into auto-provisioning, a
    // member may be minted on first sight instead.
    let extracted = extract_first_caller_identity(&attr.caller_identity_sources, headers, identity, body);
    let resolved = match &extracted {
        Some(value) => {
            member_store
                .find_for_gate(value)
                .await
        }
        None => None,
    };
    let (member, provisioned) = match resolved {
        Some(m) => (m, None),
        None => match maybe_auto_provision(attr, identity).await {
            Some((m, info)) => (m, info),
            None => match member_store
                .get(ANONYMOUS_MEMBER_ID)
                .await
            {
                Some(m) => (m, None),
                // Anonymous member not seeded: the team system is off, which
                // a surface that enforces usage may not run without.
                None => return gate_unavailable(attr, "the anonymous member is not seeded"),
            },
        },
    };

    // Resolve the caller's enabled teams, falling back to the anonymous team.
    let mut teams = team_store
        .teams_for_member(&member.id)
        .await;
    if teams.is_empty()
        && let Some(anon_team) = team_store
            .get(ANONYMOUS_TEAM_ID)
            .await
        && anon_team.status.is_enabled()
    {
        teams.push(anon_team);
    }

    // Access control (status-driven, special-case free): a disabled member, a
    // caller with no enabled team, or a caller whose teams aren't permitted on
    // this surface are all denied with HTTP 403.
    if let Some((status, code, reason)) = evaluate_access(attr, &member, &teams) {
        return TeamGateDecision::Block { status, code, reason };
    }

    // Per-member model allow-list (the "virtual key" scope). Enforced after
    // access control: a recognised, permitted caller may still be restricted to
    // a subset of models. A request that omits `model` is surface-controlled and
    // never blocked here.
    let requested_model = body
        .get("model")
        .and_then(|m| m.as_str());
    if !member.model_allowed(requested_model) {
        return TeamGateDecision::Block {
            status: StatusCode::FORBIDDEN,
            code: "model_not_allowed",
            reason: format!("model '{}' is not permitted for this caller", requested_model.unwrap_or("")),
        };
    }

    // Per-member per-minute rate limits ("virtual key" RPM/TPM). Opt-in per
    // member (None = unlimited). Enforced alongside the monthly caps (only when
    // the surface enforces) so a single member's short-term burst rate is
    // bounded across every team and surface. Recorded on allow below.
    if attr.enforce
        && let Some(limiter) = global_member_rate_limiter()
        && let Err(reason) = limiter.check(&member.id, member.requests_per_minute, member.tokens_per_minute)
    {
        return TeamGateDecision::Block {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "member_rate_limit_exceeded",
            reason,
        };
    }

    // Token caps, independent of access control above. They count every
    // token, on any key, so they are checked once per request.
    if attr.enforce
        && let Some(tracker) = global_team_usage_tracker()
        && let Some(reason) = tracker
            .token_block_reason(&member, &teams, attr.allow_individual_overage)
            .await
    {
        return TeamGateDecision::Block {
            status: StatusCode::TOO_MANY_REQUESTS,
            code: "team_quota_exceeded",
            reason,
        };
    }

    // Budgets count billed cost, which only a platform-key call adds, so they
    // are not checked here: each platform-key call checks them before it is
    // sent, and a call on the caller's or the customer's own key always runs.
    let call_budget = attr
        .enforce
        .then(|| Arc::new(CallBudget::new(member.clone(), teams.clone(), attr.allow_individual_overage)));

    // Record the allowed request against the per-minute window (RPM). Tokens are
    // recorded after execution via `record_team_usage`.
    if let Some(limiter) = global_member_rate_limiter() {
        limiter.record_request(&member.id);
    }

    TeamGateDecision::Allow(TeamUsageContext {
        budget_period_anchor: member.budget_period_anchor,
        member_id: member.id,
        teams,
        provisioned,
        call_budget,
    })
}

/// The machine code of a request refused because usage enforcement cannot
/// run (see [`gate_unavailable`]).
pub const TEAM_GATE_UNAVAILABLE: &str = "team_gate_unavailable";

/// The decision when the gate cannot resolve the caller to a member (a store
/// is missing, or the caller matches no member and the anonymous member is
/// not seeded): skipped where attribution only tracks usage, and refused with
/// 503 where the surface enforces it. A skipped gate puts no budget in scope,
/// so on an enforcing surface every platform-key call would run unmetered and
/// unrefused (unmetered endpoints, realtime sessions, unpriced models) and
/// none of the request's spend would be recorded. The refusal is logged here;
/// the handlers record it as a `team_gate` block like any other.
fn gate_unavailable(
    attr: &TeamAttributionConfig,
    why: &str,
) -> TeamGateDecision {
    if !attr.enforce {
        return TeamGateDecision::Skip;
    }
    tracing::error!(why, "team gate cannot run on a surface that enforces usage: request refused");
    TeamGateDecision::Block {
        status: StatusCode::SERVICE_UNAVAILABLE,
        code: TEAM_GATE_UNAVAILABLE,
        reason: format!("Usage enforcement is unavailable on this surface ({why}), so the request was not sent"),
    }
}

/// Attempt to auto-provision an unrecognised but **verified** caller into a
/// member. Returns the resolved member and — only when a *new* member was
/// created — the [`ProvisionedInfo`] for the handler's integration event.
/// Returns `None` (falling through to the anonymous fallback) when the surface
/// doesn't opt in, the caller isn't authenticated, no provisioner is
/// registered, or a guardrail blocks creation.
async fn maybe_auto_provision(
    attr: &TeamAttributionConfig,
    identity: Option<&AuthenticatedIdentity>,
) -> Option<(Member, Option<ProvisionedInfo>)> {
    if !attr.auto_provision {
        return None;
    }
    let identity = identity?;
    let provisioner = global_member_provisioner()?;
    let outcome = provisioner
        .provision(identity)
        .await?;
    let info = if outcome.created {
        Some(ProvisionedInfo {
            member_id: outcome.member.id.clone(),
            member_label: outcome.member.display_label(),
            identifier: outcome.member.match_value(),
            team_ids: outcome
                .teams
                .iter()
                .map(|t| t.id.clone())
                .collect(),
            team_names: outcome
                .teams
                .iter()
                .map(|t| t.name.clone())
                .collect(),
        })
    } else {
        None
    };
    Some((outcome.member, info))
}

/// The caller's natural identifier from an authenticated identity (JWT subject,
/// API-key name, or mTLS principal), used to resolve a member for standalone
/// model-scoping when no team attribution is configured.
fn identity_natural_value(identity: &AuthenticatedIdentity) -> Option<String> {
    match identity {
        AuthenticatedIdentity::JwtBearer { subject, .. } => Some(subject.clone()),
        AuthenticatedIdentity::ApiKey { key_name } => Some(key_name.clone()),
        AuthenticatedIdentity::Mtls { principal, .. } => Some(principal.clone()),
    }
}

/// Standalone per-member model allow-list ("virtual key" scope) check for
/// surfaces that authenticate the caller (source auth) but do **not** configure
/// team attribution — where [`team_pre_check`] would otherwise skip. Resolves
/// the member from the authenticated identity's natural value and applies its
/// `allowed_models` list. Returns `true` (allowed) when there is no identity,
/// no member store, no matching member, or the model is permitted; `false`
/// only when a resolved member restricts the requested model.
///
/// POSTURE: this is **fail-open by design**. The allow-list is an opt-in scope
/// that governs only *resolved, registered* members; an anonymous or
/// unregistered caller is not subject to it here (surface-level source auth and
/// OPA remain responsible for whether an unrecognised caller reaches the surface
/// at all). If a deployment needs "registered callers only", disable the
/// anonymous member and drive access through team attribution rather than
/// tightening this check — keeping this fail-open avoids locking out legitimate
/// unregistered callers on surfaces that never opted into member governance.
pub async fn model_scope_allows(
    caller_identity: Option<&AuthenticatedIdentity>,
    requested_model: Option<&str>,
) -> bool {
    let Some(identity) = caller_identity else {
        return true;
    };
    let Some(value) = identity_natural_value(identity) else {
        return true;
    };
    let Some(store) = global_member_store() else {
        return true;
    };
    match store
        .find_for_gate(&value)
        .await
    {
        Some(member) => member.model_allowed(requested_model),
        None => true,
    }
}

/// Pure access-control decision for a resolved caller. Returns the block
/// `(status, code, reason)` when the request must be denied, or `None` to allow
/// it through to quota enforcement. Kept free of store/global access so the
/// status-driven branching can be unit-tested directly.
///
/// `teams` is the caller's already-resolved enabled team set (with the
/// anonymous-team fallback already applied by the caller).
fn evaluate_access(
    attr: &TeamAttributionConfig,
    member: &Member,
    teams: &[Team],
) -> Option<(StatusCode, &'static str, String)> {
    // A disabled member is denied. A disabled *anonymous* member is how an
    // admin enforces "recognised callers only".
    if !member.status.is_enabled() {
        let reason = if member.is_anonymous() {
            "unrecognised callers are not permitted on this surface".to_string()
        } else {
            format!("member '{}' is disabled", member.display_label())
        };
        return Some((StatusCode::FORBIDDEN, "member_not_permitted", reason));
    }

    // A caller with no enabled team is denied. A disabled anonymous team is how
    // an admin requires explicit team membership.
    if teams.is_empty() {
        return Some((
            StatusCode::FORBIDDEN,
            "team_required",
            "caller is not a member of any enabled team".to_string(),
        ));
    }

    // Surface→team mapping: when the surface restricts which teams may use it,
    // the caller must belong to at least one permitted team.
    if !attr.allowed_teams.is_empty()
        && !teams.iter().any(|t| {
            attr.allowed_teams
                .contains(&t.id)
        })
    {
        return Some((
            StatusCode::FORBIDDEN,
            "team_not_permitted",
            "caller's team is not permitted to use this surface".to_string(),
        ));
    }

    None
}

/// Record one execution's spend and tokens against the caller's member and
/// teams.
pub async fn record_team_usage(
    ctx: &TeamUsageContext,
    cost: f64,
    tokens: u64,
) {
    if let Some(tracker) = global_team_usage_tracker() {
        tracker
            .record(&ctx.member_id, ctx.budget_period_anchor, &ctx.teams, cost, tokens)
            .await;
    }
    // Feed the per-minute token window (TPM) for the caller's virtual key.
    if let Some(limiter) = global_member_rate_limiter() {
        limiter.record_tokens(&ctx.member_id, tokens);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_status::EntityStatus;
    use crate::members::types::MemberIdentifier;
    use crate::teams::caller_identity::CallerIdentitySource;

    fn attr(allowed_teams: Vec<&str>) -> TeamAttributionConfig {
        TeamAttributionConfig {
            enabled: true,
            caller_identity_sources: vec![CallerIdentitySource::Header { name: "x-caller".to_string() }],
            auto_provision: false,
            enforce: false,
            allow_individual_overage: false,
            allowed_teams: allowed_teams
                .into_iter()
                .map(String::from)
                .collect(),
        }
    }

    fn member(
        id: &str,
        status: EntityStatus,
    ) -> Member {
        Member {
            id: id.to_string(),
            name: None,
            description: None,
            status,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Custom { value: id.to_string() }],
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

    fn team(id: &str) -> Team {
        Team {
            id: id.to_string(),
            name: format!("team-{id}"),
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            monthly_budget_usd: None,
            monthly_token_cap: None,
            members: Vec::new(),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn allows_enabled_member_with_team_and_no_restriction() {
        let decision = evaluate_access(&attr(vec![]), &member("m1", EntityStatus::Enabled), &[team("t1")]);
        assert!(decision.is_none());
    }

    #[test]
    fn blocks_disabled_member_with_403() {
        let (status, code, _) =
            evaluate_access(&attr(vec![]), &member("m1", EntityStatus::Disabled), &[team("t1")]).unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "member_not_permitted");
    }

    #[test]
    fn disabled_anonymous_member_reports_unrecognised_callers() {
        let anon = member(ANONYMOUS_MEMBER_ID, EntityStatus::Disabled);
        let (status, code, reason) = evaluate_access(&attr(vec![]), &anon, &[team("t1")]).unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "member_not_permitted");
        assert!(reason.contains("unrecognised"));
    }

    #[test]
    fn blocks_caller_with_no_team_with_403() {
        let (status, code, _) = evaluate_access(&attr(vec![]), &member("m1", EntityStatus::Enabled), &[]).unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "team_required");
    }

    #[test]
    fn blocks_when_team_not_in_allowed_list() {
        let (status, code, _) =
            evaluate_access(&attr(vec!["engineering"]), &member("m1", EntityStatus::Enabled), &[team("marketing")])
                .unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert_eq!(code, "team_not_permitted");
    }

    #[tokio::test]
    async fn an_enforcing_surface_is_refused_when_the_gate_cannot_run() {
        // No test registers the process-wide member store, so the gate cannot
        // resolve any caller here.
        assert!(global_member_store().is_none(), "precondition: no member store");
        let headers = HeaderMap::new();
        let mut tracking = attr(vec![]);
        assert!(matches!(
            team_pre_check(Some(&tracking), &headers, None, &serde_json::Value::Null).await,
            TeamGateDecision::Skip
        ));

        tracking.enforce = true;
        let TeamGateDecision::Block { status, code, reason } =
            team_pre_check(Some(&tracking), &headers, None, &serde_json::Value::Null).await
        else {
            panic!("an enforcing surface ran without its gate");
        };
        assert_eq!((status, code), (StatusCode::SERVICE_UNAVAILABLE, TEAM_GATE_UNAVAILABLE));
        assert!(reason.contains("member store"), "{reason}");

        // The same rule for a caller with no member and no anonymous member.
        assert!(matches!(
            gate_unavailable(&tracking, "the anonymous member is not seeded"),
            TeamGateDecision::Block {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..
            }
        ));
        tracking.enforce = false;
        assert!(matches!(gate_unavailable(&tracking, "the anonymous member is not seeded"), TeamGateDecision::Skip));
    }

    #[test]
    fn allows_when_one_team_is_in_allowed_list() {
        let decision = evaluate_access(
            &attr(vec!["engineering"]),
            &member("m1", EntityStatus::Enabled),
            &[team("marketing"), team("engineering")],
        );
        assert!(decision.is_none());
    }
}
