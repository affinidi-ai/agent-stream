//! Cross-surface team usage tracker.
//!
//! Accumulates spend and tokens against two bucket families: `team:{team_id}`
//! (the aggregate of every member) and `member:{member_id}` (one member's
//! combined share across **every** team and surface). Unlike the per-stage
//! [`crate::pipes::budget_tracker::BudgetTracker`], this tracker is keyed by
//! team and member rather than by pipe/stage, so it spans **every** surface a
//! caller touches regardless of surface type. Per-member ceilings are global
//! and live on the [`crate::members::Member`] entity.
//!
//! Each bucket records the start of the budget period it is counting. A team
//! counts the UTC calendar month; a member counts its
//! [`crate::members::BudgetPeriod`], which is the calendar month unless the
//! member carries a `budget_period_anchor`. A bucket whose start is before the
//! current period's start is spent: reads report zero and the next record
//! restarts it. Moving an anchor forward therefore starts a fresh period at
//! once, while a bucket already inside the new period keeps counting.
//!
//! Buckets are authoritative in memory. What this process recorded is written
//! to its own file under `storage_paths.team_usage`, and the buckets the other
//! files there hold are added to it at startup, on promotion, and after each of
//! its own writes, so quotas survive a restart and every instance of an
//! Active/Standby group enforces the sum of what all of them recorded. The
//! single `usage.json` an earlier release wrote counts as one more file, and a
//! legacy `{YYYY-MM}.json` snapshot for the current month is counted when no
//! `usage.json` exists.

use crate::members::{BudgetPeriod, Member};
use crate::server::mode::ReloadOnPromotion;
use crate::storage::usage_shards::{ShardedCounters, UsageShards, month_key};
use crate::teams::types::Team;
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tracing::error;

/// Process-wide team usage tracker, registered at startup so request handlers
/// across every surface record against the same buckets.
static GLOBAL_TEAM_USAGE_TRACKER: OnceLock<Arc<TeamUsageTracker>> = OnceLock::new();

/// The one snapshot file releases before per-instance files wrote.
const SINGLE_SNAPSHOT_FILE: &str = "usage.json";

/// No budget period is longer than 31 days, so a bucket that started longer ago
/// than this can never be current again.
const STALE_AFTER_DAYS: i64 = 35;

/// Register the process-wide team usage tracker. First write wins.
pub fn set_global_team_usage_tracker(tracker: Arc<TeamUsageTracker>) {
    let _ = GLOBAL_TEAM_USAGE_TRACKER.set(tracker);
}

/// Access the process-wide team usage tracker, if one has been registered.
pub fn global_team_usage_tracker() -> Option<Arc<TeamUsageTracker>> {
    GLOBAL_TEAM_USAGE_TRACKER
        .get()
        .cloned()
}

/// Accumulated spend and tokens for one bucket within its period.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScopeUsage {
    pub total_cost: f64,
    pub total_tokens: u64,
}

impl std::ops::Add for ScopeUsage {
    type Output = Self;

    fn add(
        self,
        other: Self,
    ) -> Self {
        Self {
            total_cost: self.total_cost + other.total_cost,
            total_tokens: self.total_tokens + other.total_tokens,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct Bucket {
    period_start: DateTime<Utc>,
    total_cost: f64,
    total_tokens: u64,
}

impl Bucket {
    fn empty(period_start: DateTime<Utc>) -> Self {
        Self {
            period_start,
            total_cost: 0.0,
            total_tokens: 0,
        }
    }

    fn usage_in(
        &self,
        period: BudgetPeriod,
    ) -> ScopeUsage {
        if self.period_start >= period.start && self.period_start < period.end {
            ScopeUsage {
                total_cost: self.total_cost,
                total_tokens: self.total_tokens,
            }
        } else {
            ScopeUsage::default()
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    buckets: HashMap<String, Bucket>,
}

#[derive(Debug, Deserialize)]
struct LegacySnapshot {
    month: String,
    buckets: HashMap<String, ScopeUsage>,
}

#[derive(Debug, Default)]
struct Inner {
    buckets: HashMap<String, Bucket>,
    pruned_at: Option<DateTime<Utc>>,
}

/// What this process recorded, and every other instance's buckets that may
/// still be current.
#[derive(Default)]
struct Counters {
    own: RwLock<Inner>,
    others: RwLock<HashMap<String, Vec<Bucket>>>,
    legacy: Option<Snapshot>,
}

impl Counters {
    fn usage(
        own: &Inner,
        others: &HashMap<String, Vec<Bucket>>,
        key: &str,
        period: BudgetPeriod,
    ) -> ScopeUsage {
        own.buckets
            .get(key)
            .into_iter()
            .chain(
                others
                    .get(key)
                    .into_iter()
                    .flatten(),
            )
            .map(|b| b.usage_in(period))
            .fold(ScopeUsage::default(), |total, usage| total + usage)
    }
}

#[async_trait::async_trait]
impl ShardedCounters for Counters {
    type Shard = Snapshot;

    async fn own_shard(&self) -> Snapshot {
        Snapshot {
            buckets: self
                .own
                .read()
                .await
                .buckets
                .clone(),
        }
    }

    /// Keep the buckets that may still be current. One whose period has not
    /// started yet (a peer with a skewed clock, a hand-edited file) is ignored.
    async fn set_other_shards(
        &self,
        shards: Vec<Snapshot>,
    ) {
        let now = Utc::now();
        let cutoff = now - Duration::days(STALE_AFTER_DAYS);
        let mut others: HashMap<String, Vec<Bucket>> = HashMap::new();
        for (key, bucket) in shards
            .into_iter()
            .chain(self.legacy.clone())
            .flat_map(|shard| shard.buckets)
        {
            if bucket.period_start >= cutoff && bucket.period_start <= now {
                others
                    .entry(key)
                    .or_default()
                    .push(bucket);
            }
        }
        *self.others.write().await = others;
    }
}

/// Tracks team and per-member usage across all surfaces.
pub struct TeamUsageTracker {
    counters: Arc<Counters>,
    shards: Arc<UsageShards>,
}

fn team_key(team_id: &str) -> String {
    format!("team:{team_id}")
}

fn member_key(member_id: &str) -> String {
    format!("member:{member_id}")
}

fn add(
    buckets: &mut HashMap<String, Bucket>,
    key: String,
    period: BudgetPeriod,
    cost: f64,
    tokens: u64,
) {
    let bucket = buckets
        .entry(key)
        .or_insert_with(|| Bucket::empty(period.start));
    if bucket.period_start < period.start {
        *bucket = Bucket::empty(period.start);
    }
    bucket.total_cost += crate::pipes::types::llm::billable_cost(cost);
    bucket.total_tokens += tokens;
}

async fn load_legacy(storage_dir: &std::path::Path) -> HashMap<String, Bucket> {
    let now = Utc::now();
    let month = month_key(now);
    let Ok(bytes) = tokio::fs::read(storage_dir.join(format!("{month}.json"))).await else {
        return HashMap::new();
    };
    let Ok(legacy) = serde_json::from_slice::<LegacySnapshot>(&bytes) else {
        return HashMap::new();
    };
    if legacy.month != month {
        return HashMap::new();
    }
    let period_start = BudgetPeriod::containing(None, now).start;
    legacy
        .buckets
        .into_iter()
        .map(|(key, usage)| {
            (
                key,
                Bucket {
                    period_start,
                    total_cost: usage.total_cost,
                    total_tokens: usage.total_tokens,
                },
            )
        })
        .collect()
}

#[async_trait::async_trait]
impl ReloadOnPromotion for TeamUsageTracker {
    /// Re-read what the other instances stored, so this one enforces it.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.shards
            .reload(&*self.counters)
            .await
    }
}

impl TeamUsageTracker {
    /// Construct a tracker that persists under `storage_dir` and counts what
    /// is already stored there.
    pub async fn new(storage_dir: impl Into<PathBuf>) -> Self {
        let storage_dir = storage_dir.into();
        let shards = UsageShards::open(storage_dir.clone()).await;
        let legacy = match tokio::fs::try_exists(storage_dir.join(SINGLE_SNAPSHOT_FILE)).await {
            Ok(false) => Some(Snapshot {
                buckets: load_legacy(&storage_dir).await,
            }),
            _ => None,
        };
        let tracker = Self {
            counters: Arc::new(Counters { legacy, ..Counters::default() }),
            shards: Arc::new(shards),
        };
        if let Err(e) = tracker
            .reload_from_storage()
            .await
        {
            error!("Member and Team usage not loaded at startup: {e}");
        }
        tracker
    }

    /// Wait until every recorded change has been written.
    #[cfg(test)]
    pub async fn wait_for_persist(&self) {
        self.shards.wait_idle().await;
    }

    /// Drop buckets that can never be current again. At most hourly. Caller
    /// must hold the write lock.
    fn prune(
        inner: &mut Inner,
        now: DateTime<Utc>,
    ) {
        if inner
            .pruned_at
            .is_some_and(|at| now - at < Duration::hours(1))
        {
            return;
        }
        let cutoff = now - Duration::days(STALE_AFTER_DAYS);
        inner
            .buckets
            .retain(|_, b| b.period_start >= cutoff);
        inner.pruned_at = Some(now);
    }

    /// Record one execution's spend and tokens against the member's bucket (in
    /// the member's own budget period) and every team the member belongs to.
    pub async fn record(
        &self,
        member_id: &str,
        budget_period_anchor: Option<DateTime<Utc>>,
        teams: &[Team],
        cost: f64,
        tokens: u64,
    ) {
        if member_id.is_empty() {
            return;
        }
        let now = Utc::now();
        {
            let mut inner = self
                .counters
                .own
                .write()
                .await;
            Self::prune(&mut inner, now);
            add(
                &mut inner.buckets,
                member_key(member_id),
                BudgetPeriod::containing(budget_period_anchor, now),
                cost,
                tokens,
            );
            let month = BudgetPeriod::containing(None, now);
            for team in teams {
                add(&mut inner.buckets, team_key(&team.id), month, cost, tokens);
            }
        }
        self.shards
            .sync(&self.counters);
    }

    async fn usage(
        &self,
        key: &str,
        period: BudgetPeriod,
    ) -> ScopeUsage {
        let own = self.counters.own.read().await;
        let others = self
            .counters
            .others
            .read()
            .await;
        Counters::usage(&own, &others, key, period)
    }

    /// Current calendar-month usage for a team aggregate bucket.
    pub async fn team_usage(
        &self,
        team_id: &str,
    ) -> ScopeUsage {
        self.usage(&team_key(team_id), BudgetPeriod::containing(None, Utc::now()))
            .await
    }

    /// A member's usage across all teams and surfaces in the budget period
    /// containing now, with that period.
    pub async fn member_usage(
        &self,
        member_id: &str,
        budget_period_anchor: Option<DateTime<Utc>>,
    ) -> (BudgetPeriod, ScopeUsage) {
        let period = BudgetPeriod::containing(budget_period_anchor, Utc::now());
        let usage = self
            .usage(&member_key(member_id), period)
            .await;
        (period, usage)
    }

    /// The first reason `member` may not spend more: the member's own monthly
    /// budget, or the monthly budget of one of the caller's `teams`. When
    /// `allow_individual_overage` is set, the member's personal budget is not
    /// enforced (the surface owner permits individuals to exceed it while the
    /// team budgets still apply).
    ///
    /// Buckets hold billed cost only, so this is the check a call on a platform
    /// key must pass (see [`crate::teams::call_budget`]); a call on an owned key
    /// never consults it.
    pub async fn budget_block_reason(
        &self,
        member: &Member,
        teams: &[Team],
        allow_individual_overage: bool,
    ) -> Option<String> {
        self.limit_reason(member, teams, allow_individual_overage, Limit::Budget)
            .await
    }

    /// The first reason `member` may not start another request: the member's
    /// own monthly token cap, or the token cap of one of the caller's `teams`.
    /// `allow_individual_overage` waives the member's personal cap, as for
    /// [`Self::budget_block_reason`]. Token caps count every token, on any key.
    pub async fn token_block_reason(
        &self,
        member: &Member,
        teams: &[Team],
        allow_individual_overage: bool,
    ) -> Option<String> {
        self.limit_reason(member, teams, allow_individual_overage, Limit::Tokens)
            .await
    }

    async fn limit_reason(
        &self,
        member: &Member,
        teams: &[Team],
        allow_individual_overage: bool,
        limit: Limit,
    ) -> Option<String> {
        let now = Utc::now();
        let own = self.counters.own.read().await;
        let others = self
            .counters
            .others
            .read()
            .await;
        let usage = |key: String, period: BudgetPeriod| Counters::usage(&own, &others, &key, period);

        if !allow_individual_overage {
            let member_usage = usage(member_key(&member.id), member.budget_period(now));
            let label = member.display_label();
            match limit {
                Limit::Budget => {
                    if let Some(budget) = member.monthly_budget_usd
                        && budget > 0.0
                        && member_usage.total_cost >= budget
                    {
                        return Some(format!(
                            "member '{}' monthly budget ${:.2} reached (spent ${:.2})",
                            label, budget, member_usage.total_cost
                        ));
                    }
                }
                Limit::Tokens => {
                    if let Some(cap) = member.monthly_token_cap
                        && cap > 0
                        && member_usage.total_tokens >= cap
                    {
                        return Some(format!(
                            "member '{}' monthly token cap {} reached (used {})",
                            label, cap, member_usage.total_tokens
                        ));
                    }
                }
            }
        }

        let month = BudgetPeriod::containing(None, now);
        for team in teams {
            let team_usage = usage(team_key(&team.id), month);
            match limit {
                Limit::Budget => {
                    if let Some(budget) = team.monthly_budget_usd
                        && budget > 0.0
                        && team_usage.total_cost >= budget
                    {
                        return Some(format!(
                            "team '{}' monthly budget ${:.2} reached (spent ${:.2})",
                            team.name, budget, team_usage.total_cost
                        ));
                    }
                }
                Limit::Tokens => {
                    if let Some(cap) = team.monthly_token_cap
                        && cap > 0
                        && team_usage.total_tokens >= cap
                    {
                        return Some(format!(
                            "team '{}' monthly token cap {} reached (used {})",
                            team.name, cap, team_usage.total_tokens
                        ));
                    }
                }
            }
        }
        None
    }
}

/// Which monthly limit [`TeamUsageTracker::limit_reason`] checks.
#[derive(Debug, Clone, Copy)]
enum Limit {
    /// Billed spend against `monthly_budget_usd`.
    Budget,
    /// Tokens against `monthly_token_cap`.
    Tokens,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::members::types::MemberIdentifier;

    fn member_with(
        id: &str,
        budget: Option<f64>,
    ) -> Member {
        Member {
            id: id.to_string(),
            name: Some(format!("Member {id}")),
            description: None,
            status: crate::entity_status::EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Email { email: format!("{id}@x.com") }],
            monthly_budget_usd: budget,
            monthly_token_cap: None,
            budget_period_anchor: None,
            requests_per_minute: None,
            tokens_per_minute: None,
            allowed_models: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn team_with(
        id: &str,
        budget: Option<f64>,
        member_id: &str,
    ) -> Team {
        Team {
            id: id.to_string(),
            name: format!("Team {id}"),
            description: None,
            status: crate::entity_status::EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            monthly_budget_usd: budget,
            monthly_token_cap: None,
            members: vec![member_id.to_string()],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        std::env::temp_dir().join(format!("team_usage_{tag}_{}", uuid::Uuid::new_v4()))
    }

    async fn tracker() -> TeamUsageTracker {
        TeamUsageTracker::new(temp_dir("test")).await
    }

    fn period(
        start: DateTime<Utc>,
        days: i64,
    ) -> BudgetPeriod {
        BudgetPeriod {
            start,
            end: start + Duration::days(days),
        }
    }

    #[tokio::test]
    async fn record_accumulates_team_and_member() {
        let tracker = tracker().await;
        let team = team_with("t1", Some(100.0), "m1");
        tracker
            .record("m1", None, std::slice::from_ref(&team), 3.0, 50)
            .await;
        tracker
            .record("m1", None, std::slice::from_ref(&team), 2.0, 25)
            .await;
        let tu = tracker.team_usage("t1").await;
        assert_eq!(tu.total_cost, 5.0);
        assert_eq!(tu.total_tokens, 75);
        let (_, mu) = tracker
            .member_usage("m1", None)
            .await;
        assert_eq!(mu.total_cost, 5.0);
        assert_eq!(mu.total_tokens, 75);
    }

    #[tokio::test]
    async fn only_billed_spend_counts_toward_the_member_budget() {
        use crate::pipes::config::StageUsage;
        use crate::pipes::key_source::KeySource;
        // The data plane records each execution's billed cost: zero for a call
        // on the caller's or the customer's own key, its cost on a platform key.
        let tracker = tracker().await;
        let member = member_with("m-byok", Some(1.0));
        let own = StageUsage::call(1000, 1000, 5.0, 0, KeySource::Customer);
        let caller = StageUsage::call(1000, 1000, 5.0, 0, KeySource::Client);
        tracker
            .record("m-byok", None, &[], own.billed_cost, own.total_tokens())
            .await;
        tracker
            .record("m-byok", None, &[], caller.billed_cost, caller.total_tokens())
            .await;
        assert!(
            tracker
                .budget_block_reason(&member, &[], false)
                .await
                .is_none(),
            "spend on owned keys never reaches the budget"
        );

        let platform = StageUsage::call(1000, 1000, 5.0, 0, KeySource::Platform);
        tracker
            .record("m-byok", None, &[], platform.billed_cost, platform.total_tokens())
            .await;
        let reason = tracker
            .budget_block_reason(&member, &[], false)
            .await
            .expect("platform spend trips the budget");
        assert!(reason.contains("spent $5.00"), "only the platform call was counted: {reason}");
    }

    #[tokio::test]
    async fn budgets_and_token_caps_are_checked_apart() {
        let tracker = tracker().await;
        let mut member = member_with("m1", Some(2.0));
        member.monthly_token_cap = Some(100);
        let mut team = team_with("t1", Some(50.0), "m1");
        team.monthly_token_cap = Some(1_000);

        tracker
            .record("m1", None, std::slice::from_ref(&team), 3.0, 10)
            .await;
        let teams = std::slice::from_ref(&team);
        assert!(
            tracker
                .budget_block_reason(&member, teams, false)
                .await
                .is_some_and(|r| r.contains("budget"))
        );
        assert!(
            tracker
                .token_block_reason(&member, teams, false)
                .await
                .is_none(),
            "a spent budget is not a token cap"
        );

        tracker
            .record("m1", None, teams, 0.0, 2_000)
            .await;
        member.monthly_budget_usd = None;
        team.monthly_budget_usd = None;
        let teams = std::slice::from_ref(&team);
        assert!(
            tracker
                .budget_block_reason(&member, teams, false)
                .await
                .is_none(),
            "a reached token cap is not a budget"
        );
        assert!(
            tracker
                .token_block_reason(&member, teams, false)
                .await
                .is_some_and(|r| r.contains("member") && r.contains("token cap"))
        );
        assert!(
            tracker
                .token_block_reason(&member, teams, true)
                .await
                .is_some_and(|r| r.contains("team") && r.contains("token cap")),
            "overage waives only the member's own cap"
        );
    }

    #[tokio::test]
    async fn budget_block_reason_trips_on_team_budget() {
        let tracker = tracker().await;
        let member = member_with("m1", None);
        let team = team_with("t1", Some(5.0), "m1");
        tracker
            .record("m1", None, std::slice::from_ref(&team), 5.0, 0)
            .await;
        let reason = tracker
            .budget_block_reason(&member, std::slice::from_ref(&team), false)
            .await;
        assert!(
            reason
                .unwrap()
                .contains("team")
        );
    }

    #[tokio::test]
    async fn budget_block_reason_trips_on_member_budget() {
        let tracker = tracker().await;
        let member = member_with("m1", Some(2.0));
        let team = team_with("t1", None, "m1");
        tracker
            .record("m1", None, std::slice::from_ref(&team), 2.0, 0)
            .await;
        let reason = tracker
            .budget_block_reason(&member, std::slice::from_ref(&team), false)
            .await;
        assert!(
            reason
                .unwrap()
                .contains("member")
        );
    }

    #[tokio::test]
    async fn allow_individual_overage_skips_member_cap() {
        let tracker = tracker().await;
        let member = member_with("m1", Some(2.0));
        let team = team_with("t1", None, "m1");
        tracker
            .record("m1", None, std::slice::from_ref(&team), 5.0, 0)
            .await;
        let reason = tracker
            .budget_block_reason(&member, std::slice::from_ref(&team), true)
            .await;
        assert!(reason.is_none());
    }

    #[tokio::test]
    async fn member_cap_enforced_without_teams() {
        let tracker = tracker().await;
        let member = member_with("m1", Some(2.0));
        tracker
            .record("m1", None, &[], 3.0, 0)
            .await;
        let reason = tracker
            .budget_block_reason(&member, &[], false)
            .await;
        assert!(
            reason
                .unwrap()
                .contains("member")
        );
    }

    #[tokio::test]
    async fn an_anchor_moved_to_now_starts_a_fresh_period() {
        let tracker = tracker().await;
        let mut member = member_with("m1", Some(2.0));
        tracker
            .record("m1", None, &[], 3.0, 0)
            .await;
        assert!(
            tracker
                .budget_block_reason(&member, &[], false)
                .await
                .is_some()
        );
        member.budget_period_anchor = Some(Utc::now());
        assert!(
            tracker
                .budget_block_reason(&member, &[], false)
                .await
                .is_none(),
            "a period that starts after the spend carries none of it"
        );
        tracker
            .record("m1", member.budget_period_anchor, &[], 1.0, 0)
            .await;
        let (p, mu) = tracker
            .member_usage("m1", member.budget_period_anchor)
            .await;
        assert_eq!(mu.total_cost, 1.0);
        assert_eq!(Some(p.start), member.budget_period_anchor);
    }

    #[tokio::test]
    async fn an_anchored_member_does_not_reset_with_the_calendar() {
        let tracker = tracker().await;
        let anchor = Utc::now() - Duration::days(3);
        tracker
            .record("m1", Some(anchor), &[], 4.0, 40)
            .await;
        let (p, mu) = tracker
            .member_usage("m1", Some(anchor))
            .await;
        assert_eq!(p.start, anchor);
        assert_eq!(mu.total_cost, 4.0);
    }

    #[test]
    fn a_bucket_counts_only_inside_its_period() {
        let start = DateTime::parse_from_rfc3339("2026-09-27T09:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let bucket = Bucket {
            period_start: start,
            total_cost: 5.0,
            total_tokens: 9,
        };
        assert_eq!(
            bucket
                .usage_in(period(start, 30))
                .total_cost,
            5.0
        );
        assert_eq!(
            bucket
                .usage_in(period(start - Duration::days(10), 30))
                .total_cost,
            5.0,
            "a bucket that began inside a longer-running period still counts in it"
        );
        assert_eq!(
            bucket
                .usage_in(period(start + Duration::days(30), 30))
                .total_cost,
            0.0,
            "the next period starts empty"
        );
    }

    #[test]
    fn a_spent_bucket_restarts_on_the_next_record() {
        let mut buckets = HashMap::new();
        let first = DateTime::parse_from_rfc3339("2026-09-01T00:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        add(&mut buckets, "member:m1".into(), period(first, 30), 3.0, 30);
        add(&mut buckets, "member:m1".into(), period(first + Duration::days(30), 31), 1.0, 10);
        let b = &buckets["member:m1"];
        assert_eq!(b.period_start, first + Duration::days(30));
        assert_eq!(b.total_cost, 1.0);
        assert_eq!(b.total_tokens, 10);
    }

    #[tokio::test]
    async fn stale_buckets_are_pruned() {
        let tracker = tracker().await;
        {
            let mut inner = tracker
                .counters
                .own
                .write()
                .await;
            inner
                .buckets
                .insert("member:gone".into(), Bucket::empty(Utc::now() - Duration::days(STALE_AFTER_DAYS + 1)));
        }
        tracker
            .record("m1", None, &[], 1.0, 0)
            .await;
        let inner = tracker
            .counters
            .own
            .read()
            .await;
        assert!(
            !inner
                .buckets
                .contains_key("member:gone")
        );
        assert!(
            inner
                .buckets
                .contains_key("member:m1")
        );
    }

    #[test]
    fn a_written_snapshot_parses_back() {
        let raw =
            r#"{"buckets":{"team:t1":{"period_start":"2026-09-01T00:00:00Z","total_cost":7.0,"total_tokens":10}}}"#;
        let parsed: Snapshot = serde_json::from_str(raw).expect("the snapshot format must round-trip");
        assert_eq!(parsed.buckets["team:t1"].total_tokens, 10);
    }

    #[tokio::test]
    async fn snapshot_survives_reload() {
        let dir = temp_dir("reload");
        let team = team_with("t1", Some(100.0), "m1");
        {
            let tracker = TeamUsageTracker::new(dir.clone()).await;
            tracker
                .record("m1", None, std::slice::from_ref(&team), 7.0, 10)
                .await;
            tracker
                .wait_for_persist()
                .await;
        }
        let reloaded = TeamUsageTracker::new(dir).await;
        let tu = reloaded
            .team_usage("t1")
            .await;
        assert_eq!(tu.total_cost, 7.0);
        assert_eq!(tu.total_tokens, 10);
    }

    #[tokio::test]
    async fn a_promoted_standby_enforces_usage_the_active_recorded() {
        let dir = temp_dir("promotion");
        let team = team_with("t1", Some(5.0), "m1");
        let standby = TeamUsageTracker::new(dir.clone()).await;
        let active = TeamUsageTracker::new(dir).await;
        active
            .record("m1", None, std::slice::from_ref(&team), 6.0, 10)
            .await;
        active
            .wait_for_persist()
            .await;
        let member = member_with("m1", None);

        assert!(
            standby
                .budget_block_reason(&member, std::slice::from_ref(&team), false)
                .await
                .is_none(),
            "a standby holds what it loaded at startup"
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert!(
            standby
                .budget_block_reason(&member, std::slice::from_ref(&team), false)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn usage_recorded_by_every_instance_adds_up() {
        let dir = temp_dir("sum");
        let team = team_with("t1", None, "m1");
        let standby = TeamUsageTracker::new(dir.clone()).await;
        let active = TeamUsageTracker::new(dir.clone()).await;
        active
            .record("m1", None, std::slice::from_ref(&team), 7.0, 70)
            .await;
        active
            .wait_for_persist()
            .await;

        standby
            .record("m1", None, std::slice::from_ref(&team), 1.0, 1)
            .await;
        standby
            .wait_for_persist()
            .await;

        let expected = ScopeUsage {
            total_cost: 8.0,
            total_tokens: 71,
        };
        assert_eq!(standby.team_usage("t1").await, expected);
        assert_eq!(
            TeamUsageTracker::new(dir)
                .await
                .team_usage("t1")
                .await,
            expected
        );
    }

    #[tokio::test]
    async fn a_stored_period_that_has_not_started_is_ignored() {
        let dir = temp_dir("future");
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let future = Snapshot {
            buckets: HashMap::from([("team:t1".to_string(), Bucket::empty(Utc::now() + Duration::days(400)))]),
        };
        tokio::fs::write(dir.join("usage.peer.json"), serde_json::to_vec(&future).unwrap())
            .await
            .unwrap();
        let tracker = TeamUsageTracker::new(dir).await;
        let team = team_with("t1", Some(1.0), "m1");

        tracker
            .record("m1", None, std::slice::from_ref(&team), 2.0, 2)
            .await;

        assert!(
            tracker
                .budget_block_reason(&member_with("m1", None), std::slice::from_ref(&team), false)
                .await
                .is_some(),
            "current-period spend still counts"
        );
        assert!(
            !tracker
                .counters
                .others
                .read()
                .await
                .contains_key("team:t1")
        );
    }

    #[tokio::test]
    async fn the_single_snapshot_of_an_earlier_release_still_counts() {
        let dir = temp_dir("single_snapshot");
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let month = BudgetPeriod::containing(None, Utc::now());
        let earlier = Snapshot {
            buckets: HashMap::from([(
                "team:t1".to_string(),
                Bucket {
                    period_start: month.start,
                    total_cost: 3.0,
                    total_tokens: 30,
                },
            )]),
        };
        tokio::fs::write(dir.join(SINGLE_SNAPSHOT_FILE), serde_json::to_vec(&earlier).unwrap())
            .await
            .unwrap();
        let team = team_with("t1", None, "m1");

        let tracker = TeamUsageTracker::new(dir.clone()).await;
        tracker
            .record("m1", None, std::slice::from_ref(&team), 1.0, 1)
            .await;
        tracker
            .wait_for_persist()
            .await;

        assert_eq!(
            tracker
                .team_usage("t1")
                .await
                .total_cost,
            4.0
        );
        assert_eq!(
            tokio::fs::read(dir.join(SINGLE_SNAPSHOT_FILE))
                .await
                .unwrap(),
            serde_json::to_vec(&earlier).unwrap(),
            "the earlier snapshot is never written over"
        );
    }

    #[tokio::test]
    async fn a_legacy_monthly_snapshot_is_carried_over() {
        let dir = temp_dir("legacy");
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let month = month_key(Utc::now());
        let legacy = serde_json::json!({
            "month": month,
            "buckets": { "team:t1": { "total_cost": 2.5, "total_tokens": 4 }, "member:m1": { "total_cost": 1.5, "total_tokens": 2 } }
        });
        tokio::fs::write(dir.join(format!("{month}.json")), legacy.to_string())
            .await
            .unwrap();
        let tracker = TeamUsageTracker::new(dir).await;
        assert_eq!(
            tracker
                .team_usage("t1")
                .await
                .total_cost,
            2.5
        );
        assert_eq!(
            tracker
                .member_usage("m1", None)
                .await
                .1
                .total_cost,
            1.5
        );
    }

    #[tokio::test]
    async fn a_legacy_snapshot_from_another_month_is_ignored() {
        let dir = temp_dir("legacy_old");
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let month = month_key(Utc::now());
        let legacy = serde_json::json!({ "month": "1999-01", "buckets": { "team:t1": { "total_cost": 9.0, "total_tokens": 1 } } });
        tokio::fs::write(dir.join(format!("{month}.json")), legacy.to_string())
            .await
            .unwrap();
        let tracker = TeamUsageTracker::new(dir).await;
        assert_eq!(
            tracker
                .team_usage("t1")
                .await
                .total_cost,
            0.0
        );
    }
}
