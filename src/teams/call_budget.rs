//! The member and team budgets, checked at each model call by the source of
//! its key.
//!
//! A call on an owned key (the caller's own or the customer's stored key)
//! costs the account nothing, so it always runs. A call on a platform key bills
//! its cost, so it is refused while the member's budget, or a budget of one of
//! the member's teams, is spent. The request-start team gate checks access,
//! rate limits and token caps only; budgets are checked here, by each call that
//! would spend one.
//!
//! The team gate builds one [`CallBudget`] per request on a surface that
//! enforces quotas, and the request runs inside [`scope`]. Every model call
//! asks [`refusal`] just before it is sent. The buckets are read once, when the
//! request makes its first platform-key call, and that answer holds for the
//! rest of the request: a request that started spending the budget runs to
//! completion and records all of it, as every request did when the budget was
//! checked at request start, and a request refused once is refused on every
//! later platform-key call. A call outside a scope, or in a request with no
//! budget to enforce, is never refused.
//!
//! What a refusal does depends on the call (see
//! [`crate::pipes::executor::BudgetedCall`]): an upstream that serves the
//! request becomes unavailable, a safety or decision stage refuses the request,
//! and an embedder is skipped and counted with [`record_skip`].

use std::cell::RefCell;
use std::future::Future;
use std::sync::Arc;

use crate::members::types::Member;
use crate::pipes::key_source::KeySource;
use crate::teams::types::Team;
use crate::teams::usage_tracker::global_team_usage_tracker;

tokio::task_local! {
    static CALL_BUDGET: RefCell<Option<Arc<CallBudget>>>;
}

/// The budgets one request's platform-key calls are checked against.
#[derive(Debug)]
pub struct CallBudget {
    member: Member,
    teams: Vec<Team>,
    allow_individual_overage: bool,
    /// The request's answer, read from the buckets at its first platform-key
    /// call: `Some(reason)` when refused.
    decision: tokio::sync::OnceCell<Option<String>>,
}

impl CallBudget {
    /// The budgets of `member` and its `teams`. `allow_individual_overage`
    /// waives the member's own budget, as on the surface's team attribution.
    pub fn new(
        member: Member,
        teams: Vec<Team>,
        allow_individual_overage: bool,
    ) -> Self {
        Self {
            member,
            teams,
            allow_individual_overage,
            decision: tokio::sync::OnceCell::new(),
        }
    }

    /// The same budgets for another request, which reads the buckets afresh.
    pub fn for_next_request(&self) -> Self {
        Self::new(self.member.clone(), self.teams.clone(), self.allow_individual_overage)
    }

    /// Why a call on a key from `source` may not run, `None` when it may. An
    /// owned key is never refused and never reads the buckets.
    pub async fn refusal(
        &self,
        source: KeySource,
    ) -> Option<String> {
        if source.owned() {
            return None;
        }
        self.decision
            .get_or_init(|| async {
                match global_team_usage_tracker() {
                    Some(tracker) => {
                        tracker
                            .budget_block_reason(&self.member, &self.teams, self.allow_individual_overage)
                            .await
                    }
                    None => None,
                }
            })
            .await
            .clone()
    }
}

/// Run `fut` with `budget` as the budget its model calls are checked against.
pub async fn scope<F: Future>(
    budget: Option<Arc<CallBudget>>,
    fut: F,
) -> F::Output {
    CALL_BUDGET
        .scope(RefCell::new(budget), fut)
        .await
}

/// Set the current scope's budget, once the team gate has resolved it. A no-op
/// outside a [`scope`].
pub fn set(budget: Option<Arc<CallBudget>>) {
    let _ = CALL_BUDGET.try_with(|current| *current.borrow_mut() = budget);
}

/// The current scope's budget; `None` outside a scope or when none applies.
pub fn current() -> Option<Arc<CallBudget>> {
    CALL_BUDGET
        .try_with(|current| current.borrow().clone())
        .ok()
        .flatten()
}

/// Why the current request may not make a call on a key from `source`, `None`
/// when it may (see [`CallBudget::refusal`]).
pub async fn refusal(source: KeySource) -> Option<String> {
    if source.owned() {
        return None;
    }
    current()?
        .refusal(source)
        .await
}

/// Work skipped because the budget refused its platform-key call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetSkip {
    /// A semantic-cache embedding: the request runs without a semantic lookup.
    CacheEmbedding,
    /// A drift embedding: the replayed session gets no semantic-distance sample.
    DriftEmbedding,
    /// A drift replay session: the run stops before replaying it.
    DriftReplay,
}

impl BudgetSkip {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CacheEmbedding => "cache_embedding",
            Self::DriftEmbedding => "drift_embedding",
            Self::DriftReplay => "drift_replay",
        }
    }
}

/// Count one piece of work skipped for budget (the Prometheus counter
/// `agent_stream_budget_skipped_total{kind}`) and log the running total.
/// `context` names where it was skipped (a surface id).
pub fn record_skip(
    kind: BudgetSkip,
    context: &str,
) {
    let total = crate::metrics::backends::prometheus::track_budget_skipped(kind.as_str());
    tracing::info!(
        skipped = kind.as_str(),
        surface = ?context,
        skipped_total = total,
        "budget spent: skipped a platform-key call that has no safety role"
    );
}

/// How many times `kind` has been skipped for budget since the process
/// started.
#[cfg(test)]
pub fn skipped(kind: BudgetSkip) -> u64 {
    crate::metrics::backends::prometheus::BUDGET_SKIPPED
        .with_label_values(&[kind.as_str()])
        .get()
}

/// Budgets for tests, against the process-wide usage tracker.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::entity_status::EntityStatus;
    use crate::members::types::MemberIdentifier;
    use crate::teams::usage_tracker::{TeamUsageTracker, set_global_team_usage_tracker};

    /// The process-wide usage tracker, registered on first use.
    pub(crate) async fn tracker() -> Arc<TeamUsageTracker> {
        if global_team_usage_tracker().is_none() {
            let dir = std::env::temp_dir().join(format!("call_budget_{}", uuid::Uuid::new_v4()));
            set_global_team_usage_tracker(Arc::new(TeamUsageTracker::new(dir).await));
        }
        global_team_usage_tracker().expect("a usage tracker is registered")
    }

    /// A member of its own with a monthly budget of `budget` dollars.
    pub(crate) fn member(budget: Option<f64>) -> Member {
        Member {
            id: format!("m-{}", uuid::Uuid::new_v4()),
            name: None,
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Custom { value: "caller".to_string() }],
            monthly_budget_usd: budget,
            monthly_token_cap: None,
            budget_period_anchor: None,
            requests_per_minute: None,
            tokens_per_minute: None,
            allowed_models: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    /// A one-dollar budget already spent: the member has no credit left.
    pub(crate) async fn spent() -> Arc<CallBudget> {
        let member = member(Some(1.0));
        tracker()
            .await
            .record(&member.id, None, &[], 1.0, 0)
            .await;
        Arc::new(CallBudget::new(member, Vec::new(), false))
    }

    /// A hundred-dollar budget with nothing spent.
    pub(crate) fn unspent() -> Arc<CallBudget> {
        Arc::new(CallBudget::new(member(Some(100.0)), Vec::new(), false))
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::*;
    use super::*;

    #[tokio::test]
    async fn no_scope_or_no_budget_refuses_nothing() {
        assert!(
            refusal(KeySource::Platform)
                .await
                .is_none()
        );
        assert!(
            scope(None, refusal(KeySource::Platform))
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn the_budget_set_inside_a_scope_is_the_one_its_calls_see() {
        let budget = Arc::new(CallBudget::new(member(Some(1.0)), Vec::new(), false));
        let seen = scope(None, async {
            assert!(current().is_none());
            set(Some(budget.clone()));
            current()
        })
        .await;
        assert!(seen.is_some_and(|b| Arc::ptr_eq(&b, &budget)));
        assert!(current().is_none(), "the budget never outlives its scope");
    }

    #[tokio::test]
    async fn owned_keys_are_never_refused() {
        let budget = CallBudget::new(member(Some(1.0)), Vec::new(), false);
        budget
            .decision
            .set(Some("spent".to_string()))
            .unwrap();
        assert!(
            budget
                .refusal(KeySource::Client)
                .await
                .is_none()
        );
        assert!(
            budget
                .refusal(KeySource::Customer)
                .await
                .is_none()
        );
        assert_eq!(
            budget
                .refusal(KeySource::Platform)
                .await
                .as_deref(),
            Some("spent")
        );
        assert!(
            budget
                .for_next_request()
                .decision
                .get()
                .is_none(),
            "the next request reads the buckets afresh"
        );
    }

    #[tokio::test]
    async fn a_spent_budget_refuses_platform_calls_and_its_answer_holds_for_the_request() {
        let spent = spent().await;
        assert!(
            spent
                .refusal(KeySource::Platform)
                .await
                .is_some_and(|reason| reason.contains("monthly budget $1.00 reached"))
        );
        assert!(
            spent
                .refusal(KeySource::Customer)
                .await
                .is_none()
        );

        // A request that started spending keeps its answer when another
        // request spends the rest of the budget, as when the budget was checked
        // once at request start; the next request sees the spend.
        let member = member(Some(1.0));
        let request = CallBudget::new(member.clone(), Vec::new(), false);
        assert!(
            request
                .refusal(KeySource::Platform)
                .await
                .is_none(),
            "precondition: credit left"
        );
        tracker()
            .await
            .record(&member.id, None, &[], 1.0, 0)
            .await;
        assert!(
            request
                .refusal(KeySource::Platform)
                .await
                .is_none(),
            "the request's answer is fixed at its first platform call"
        );
        assert!(
            request
                .for_next_request()
                .refusal(KeySource::Platform)
                .await
                .is_some(),
            "the next request is refused"
        );
    }

    #[tokio::test]
    async fn a_team_budget_refuses_too_unless_only_the_members_own_is_waived() {
        let member = member(None);
        let mut team = crate::teams::types::Team {
            id: format!("t-{}", uuid::Uuid::new_v4()),
            name: "Team".to_string(),
            description: None,
            status: crate::entity_status::EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            monthly_budget_usd: Some(1.0),
            monthly_token_cap: None,
            members: vec![member.id.clone()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        tracker()
            .await
            .record(&member.id, None, std::slice::from_ref(&team), 1.0, 0)
            .await;
        let overage = CallBudget::new(member.clone(), vec![team.clone()], true);
        assert!(
            overage
                .refusal(KeySource::Platform)
                .await
                .is_some_and(|reason| reason.contains("team")),
            "individual overage never waives a team budget"
        );
        team.monthly_budget_usd = None;
        let mut own = member;
        own.monthly_budget_usd = Some(0.5);
        let waived = CallBudget::new(own, vec![team], true);
        assert!(
            waived
                .refusal(KeySource::Platform)
                .await
                .is_none(),
            "individual overage waives the member's own budget"
        );
    }

    #[test]
    fn skips_are_counted_per_kind() {
        let before = skipped(BudgetSkip::DriftEmbedding);
        record_skip(BudgetSkip::DriftEmbedding, "surface-1");
        assert!(skipped(BudgetSkip::DriftEmbedding) > before);
    }
}
