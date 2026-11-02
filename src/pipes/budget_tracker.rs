//! Budget tracking and alerting for LLM pipe usage
//!
//! Counters are authoritative in memory. A tracker built with
//! [`BudgetTracker::persistent`] also writes what this process recorded to its
//! own file under `storage_paths.surface_usage` after each recorded call, and
//! adds what the other files there hold: at startup, on promotion, and after
//! each of its own writes. Spend therefore survives a restart, and every
//! instance of an Active/Standby group enforces the sum of what all of them
//! recorded this month.

use crate::pipes::config::{CUMULATIVE_SCOPE_KEY, PipeConfig, UsageLimit, UsageStage};
use crate::server::mode::ReloadOnPromotion;
use crate::storage::usage_shards::{ShardedCounters, UsageShards, month_key};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

/// Process-wide budget tracker, registered at startup so stages that run
/// outside the request handler (judge/jury LLM calls) can record their own
/// spend and tokens against the same monthly buckets the boundary enforces.
static GLOBAL_BUDGET_TRACKER: OnceLock<Arc<BudgetTracker>> = OnceLock::new();

/// Register the process-wide budget tracker. First write wins.
pub fn set_global_budget_tracker(tracker: Arc<BudgetTracker>) {
    let _ = GLOBAL_BUDGET_TRACKER.set(tracker);
}

/// Access the process-wide budget tracker, if one has been registered.
pub fn global_budget_tracker() -> Option<Arc<BudgetTracker>> {
    GLOBAL_BUDGET_TRACKER
        .get()
        .cloned()
}

/// Record a surface's **main-LLM stage** spend and tokens against the
/// process-wide tracker, so the next call's usage-limit check sees them.
/// Every caller that drives a surface's LLM stage to completion — the gateway
/// front door, the Sandbox execute API, and the drift replay runner — goes
/// through here, so no execution path can spend without metering. Judge, Jury
/// and Decider record their own buckets from inside their executors, so this
/// takes the LLM stage alone and never the execution's grand total.
pub async fn record_surface_llm_usage(
    pipe_id: &str,
    cost: f64,
    tokens: u64,
) {
    if let Some(tracker) = global_budget_tracker() {
        tracker
            .record_llm_usage(pipe_id, cost, tokens)
            .await;
    }
}

/// Record a live execution's main-LLM spend against the surface's monthly cost
/// budget (`cost_tracking`), raising `pipe.budget.threshold_reached` /
/// `pipe.budget.exceeded` once each per month. A no-op when the surface has no
/// budget configured or the cost is zero. Every live path calls this next to
/// [`record_surface_llm_usage`]; the alert itself is dispatched on a spawned
/// task, so the caller's response path is not held up.
pub async fn record_surface_budget_cost(
    pipe: &PipeConfig,
    cost: f64,
) {
    if cost <= 0.0 {
        return;
    }
    let Some(cost_config) = pipe
        .cost_tracking
        .as_ref()
        .filter(|c| c.enabled)
    else {
        return;
    };
    if let Some(tracker) = global_budget_tracker()
        && let Err(e) = tracker
            .record_cost(
                pipe.id.clone(),
                pipe.name.clone(),
                cost,
                cost_config.monthly_budget_usd,
                cost_config.alert_threshold_percent,
            )
            .await
    {
        warn!("[PIPE:{}] Failed to record budget usage: {}", pipe.id, e);
    }
}

/// Monthly budget usage tracker
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonthlyBudgetUsage {
    pub pipe_id: String,
    pub month: String, // Format: "2026-01"
    pub total_spent: f64,
    pub budget_limit: f64,
    pub alert_threshold_percent: u8,
    pub alert_sent: bool,
    /// Whether the `pipe.budget.exceeded` alert has been raised this month.
    #[serde(default)]
    pub exceeded_alert_sent: bool,
    pub last_updated: DateTime<Utc>,
}

impl MonthlyBudgetUsage {
    pub fn new(
        pipe_id: String,
        budget_limit: f64,
        alert_threshold_percent: u8,
    ) -> Self {
        let now = Utc::now();
        Self {
            pipe_id,
            month: month_key(now),
            total_spent: 0.0,
            budget_limit,
            alert_threshold_percent,
            alert_sent: false,
            exceeded_alert_sent: false,
            last_updated: now,
        }
    }

    pub fn add_cost(
        &mut self,
        cost: f64,
    ) {
        self.total_spent += crate::pipes::types::llm::billable_cost(cost);
        self.last_updated = Utc::now();
    }

    pub fn usage_percentage(&self) -> f64 {
        if self.budget_limit == 0.0 {
            return 0.0;
        }
        (self.total_spent / self.budget_limit) * 100.0
    }

    pub fn should_alert(&self) -> bool {
        !self.alert_sent && self.usage_percentage() >= self.alert_threshold_percent as f64
    }

    /// Whether the budget is exceeded and its `pipe.budget.exceeded` alert has
    /// not been raised yet this month.
    pub fn should_alert_exceeded(&self) -> bool {
        !self.exceeded_alert_sent && self.budget_exceeded()
    }

    pub fn budget_exceeded(&self) -> bool {
        self.total_spent >= self.budget_limit
    }

    pub fn remaining_budget(&self) -> f64 {
        (self.budget_limit - self.total_spent).max(0.0)
    }

    /// Add another instance's usage of the same month: spend adds up, an alert
    /// either side raised stays raised, and the budget recorded last applies.
    fn absorb(
        &mut self,
        other: &MonthlyBudgetUsage,
    ) {
        self.total_spent += other.total_spent;
        self.alert_sent |= other.alert_sent;
        self.exceeded_alert_sent |= other.exceeded_alert_sent;
        if other.last_updated > self.last_updated {
            self.budget_limit = other.budget_limit;
            self.alert_threshold_percent = other.alert_threshold_percent;
            self.last_updated = other.last_updated;
        }
    }
}

/// Budget tracker for all pipes
pub struct BudgetTracker {
    counters: Arc<Counters>,
    /// Integration service for sending alerts
    integration_service: Option<Arc<dyn AlertService>>,
    shards: Option<Arc<UsageShards>>,
}

/// Accumulated spend and tokens for one (pipe, scope) bucket within a month,
/// used to enforce [`UsageLimit`]s.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScopeUsage {
    pub total_cost: f64,
    pub total_tokens: u64,
    pub month: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Snapshot {
    /// Budget usage by pipe id.
    #[serde(default)]
    budgets: HashMap<String, MonthlyBudgetUsage>,
    /// Usage-limit buckets keyed by `"{pipe_id}|{scope_key}"`.
    #[serde(default)]
    limits: HashMap<String, ScopeUsage>,
}

impl Snapshot {
    fn into_month(
        mut self,
        month: &str,
    ) -> Self {
        self.budgets
            .retain(|_, u| u.month == month);
        self.limits
            .retain(|_, u| u.month == month);
        self
    }
}

/// What this process recorded, and the current-month sum of what every other
/// instance stored.
#[derive(Default)]
struct Counters {
    own: RwLock<Snapshot>,
    others: RwLock<Snapshot>,
}

#[async_trait::async_trait]
impl ShardedCounters for Counters {
    type Shard = Snapshot;

    async fn own_shard(&self) -> Snapshot {
        self.own
            .read()
            .await
            .clone()
            .into_month(&month_key(Utc::now()))
    }

    async fn set_other_shards(
        &self,
        shards: Vec<Snapshot>,
    ) {
        let month = month_key(Utc::now());
        let mut sum = Snapshot::default();
        for shard in shards {
            let shard = shard.into_month(&month);
            for (key, usage) in shard.budgets {
                match sum.budgets.get_mut(&key) {
                    Some(total) => total.absorb(&usage),
                    None => {
                        sum.budgets.insert(key, usage);
                    }
                }
            }
            for (key, usage) in shard.limits {
                let total = sum
                    .limits
                    .entry(key)
                    .or_insert_with(|| ScopeUsage {
                        month: month.clone(),
                        ..ScopeUsage::default()
                    });
                total.total_cost += usage.total_cost;
                total.total_tokens += usage.total_tokens;
            }
        }
        *self.others.write().await = sum;
    }
}

/// This process's budget usage for `month` plus every other instance's.
fn current_budget(
    own: Option<&MonthlyBudgetUsage>,
    others: Option<&MonthlyBudgetUsage>,
    month: &str,
) -> Option<MonthlyBudgetUsage> {
    let mut current: Option<MonthlyBudgetUsage> = None;
    for usage in [own, others]
        .into_iter()
        .flatten()
        .filter(|u| u.month == month)
    {
        match &mut current {
            Some(total) => total.absorb(usage),
            None => current = Some(usage.clone()),
        }
    }
    current
}

/// This process's (cost, tokens) for `month` plus every other instance's.
fn current_scope(
    own: Option<&ScopeUsage>,
    others: Option<&ScopeUsage>,
    month: &str,
) -> (f64, u64) {
    [own, others]
        .into_iter()
        .flatten()
        .filter(|u| u.month == month)
        .fold((0.0, 0), |(cost, tokens), u| (cost + u.total_cost, tokens + u.total_tokens))
}

#[async_trait::async_trait]
pub trait AlertService: Send + Sync {
    async fn send_budget_alert(
        &self,
        pipe_id: &str,
        usage: &MonthlyBudgetUsage,
    ) -> Result<(), String>;
}

#[async_trait::async_trait]
impl ReloadOnPromotion for BudgetTracker {
    /// Re-read what the other instances stored, so this one enforces it.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        match &self.shards {
            Some(shards) => {
                shards
                    .reload(&*self.counters)
                    .await
            }
            None => Ok(()),
        }
    }
}

impl BudgetTracker {
    pub fn new() -> Self {
        Self {
            counters: Arc::default(),
            integration_service: None,
            shards: None,
        }
    }

    /// A tracker that persists its counters under `storage_dir` and counts
    /// what is already stored there.
    pub async fn persistent(storage_dir: impl Into<PathBuf>) -> Self {
        let tracker = Self {
            shards: Some(Arc::new(UsageShards::open(storage_dir).await)),
            ..Self::new()
        };
        if let Err(e) = tracker
            .reload_from_storage()
            .await
        {
            error!("Surface spend counters not loaded at startup: {e}");
        }
        tracker
    }

    fn persist(&self) {
        if let Some(shards) = &self.shards {
            shards.sync(&self.counters);
        }
    }

    /// Wait until every recorded change has been written.
    #[cfg(test)]
    pub async fn wait_for_persist(&self) {
        if let Some(shards) = &self.shards {
            shards.wait_idle().await;
        }
    }

    pub fn with_alert_service(
        mut self,
        service: Arc<dyn AlertService>,
    ) -> Self {
        self.integration_service = Some(service);
        self
    }

    /// Record a cost and check for budget alerts
    pub async fn record_cost(
        &self,
        pipe_id: String,
        _pipe_name: String, // Stored for future use in alerts
        cost: f64,
        budget_limit: Option<f64>,
        alert_threshold_percent: Option<u8>,
    ) -> Result<(), String> {
        // Skip if no budget configured
        let (budget, threshold) = match (budget_limit, alert_threshold_percent) {
            (Some(b), Some(t)) if b > 0.0 => (b, t),
            _ => return Ok(()), // No budget tracking for this pipe
        };

        let current_month = month_key(Utc::now());
        let mut own = self
            .counters
            .own
            .write()
            .await;
        let entry = own
            .budgets
            .entry(pipe_id.clone())
            .or_insert_with(|| MonthlyBudgetUsage::new(pipe_id.clone(), budget, threshold));
        if entry.month != current_month {
            *entry = MonthlyBudgetUsage::new(pipe_id.clone(), budget, threshold);
        }
        entry.budget_limit = budget;
        entry.alert_threshold_percent = threshold;
        entry.add_cost(cost);

        let others = self
            .counters
            .others
            .read()
            .await;
        let Some(mut usage) = current_budget(Some(&*entry), others.budgets.get(&pipe_id), &current_month) else {
            return Ok(());
        };
        drop(others);

        // Each alert (threshold reached, budget exceeded) is raised once per
        // month across every instance. A cost that crosses both thresholds at
        // once raises only the more severe `exceeded` alert and retires the
        // threshold one too.
        let mut alerts = Vec::new();
        if usage.should_alert_exceeded() {
            usage.alert_sent = true;
            usage.exceeded_alert_sent = true;
            entry.alert_sent = true;
            entry.exceeded_alert_sent = true;
            info!("Budget exceeded for pipe {}: ${:.2}/{:.2}", pipe_id, usage.total_spent, usage.budget_limit);
            alerts.push(usage);
        } else if usage.should_alert() {
            usage.alert_sent = true;
            entry.alert_sent = true;
            alerts.push(usage);
        }
        drop(own);
        self.persist();

        for usage_clone in alerts {
            if let Some(service) = &self.integration_service {
                let service = service.clone();
                let pipe_id = pipe_id.clone();
                tokio::spawn(async move {
                    if let Err(e) = service
                        .send_budget_alert(&pipe_id, &usage_clone)
                        .await
                    {
                        warn!("Failed to send budget alert for pipe {}: {}", pipe_id, e);
                    }
                });
            } else {
                warn!(
                    "Budget alert for pipe {}: ${:.2}/{:.2} ({:.1}%), but no alert service configured",
                    pipe_id,
                    usage_clone.total_spent,
                    usage_clone.budget_limit,
                    usage_clone.usage_percentage()
                );
            }
        }

        Ok(())
    }

    /// The current month's budget usage for a pipe, across every instance.
    pub async fn get_usage(
        &self,
        pipe_id: &str,
    ) -> Option<MonthlyBudgetUsage> {
        let own = self.counters.own.read().await;
        let others = self
            .counters
            .others
            .read()
            .await;
        current_budget(own.budgets.get(pipe_id), others.budgets.get(pipe_id), &month_key(Utc::now()))
    }

    /// Map key for a (pipe, scope) usage-limit bucket.
    fn limit_key(
        pipe_id: &str,
        scope_key: &str,
    ) -> String {
        format!("{pipe_id}|{scope_key}")
    }

    /// Record actual spend and tokens against a (pipe, scope) bucket. Buckets
    /// reset when the calendar month rolls over. Pass `0.0`/`0` for a dimension
    /// the stage does not track.
    pub async fn record_usage(
        &self,
        pipe_id: &str,
        scope_key: &str,
        cost: f64,
        tokens: u64,
    ) {
        let current_month = month_key(Utc::now());
        let key = Self::limit_key(pipe_id, scope_key);

        {
            let mut own = self
                .counters
                .own
                .write()
                .await;
            let entry = own
                .limits
                .entry(key)
                .or_insert_with(|| ScopeUsage {
                    total_cost: 0.0,
                    total_tokens: 0,
                    month: current_month.clone(),
                });
            if entry.month != current_month {
                *entry = ScopeUsage {
                    total_cost: 0.0,
                    total_tokens: 0,
                    month: current_month.clone(),
                };
            }
            entry.total_cost += crate::pipes::types::llm::billable_cost(cost);
            entry.total_tokens += tokens;
        }
        self.persist();
    }

    /// Current-month (cost, tokens) accumulated for a (pipe, scope) bucket
    /// across every instance.
    #[allow(dead_code)]
    pub async fn scope_usage(
        &self,
        pipe_id: &str,
        scope_key: &str,
    ) -> (f64, u64) {
        let key = Self::limit_key(pipe_id, scope_key);
        let own = self.counters.own.read().await;
        let others = self
            .counters
            .others
            .read()
            .await;
        current_scope(own.limits.get(&key), others.limits.get(&key), &month_key(Utc::now()))
    }

    /// Return the first reason a call should be blocked, if any usage limit
    /// governing `active_scope_key` has reached its monthly cost or token cap.
    /// A limit governs the active scope when it is cumulative (caps every stage)
    /// or its own scope key matches the one about to run.
    pub async fn limit_block_reason(
        &self,
        pipe_id: &str,
        active_scope_key: &str,
        limits: &[UsageLimit],
    ) -> Option<String> {
        let current_month = month_key(Utc::now());
        let own = self.counters.own.read().await;
        let others = self
            .counters
            .others
            .read()
            .await;

        for limit in limits {
            if !limit.enabled {
                continue;
            }
            let governs = matches!(limit.scope, crate::pipes::config::UsageScope::Cumulative)
                || limit.scope_key() == active_scope_key;
            if !governs {
                continue;
            }
            let key = Self::limit_key(pipe_id, &limit.scope_key());
            let (cost, tokens) = current_scope(own.limits.get(&key), others.limits.get(&key), &current_month);

            if let Some(budget) = limit.monthly_budget_usd
                && budget > 0.0
                && cost >= budget
            {
                return Some(format!(
                    "monthly budget ${:.2} reached for scope '{}' (spent ${:.2})",
                    budget,
                    limit.scope_key(),
                    cost
                ));
            }
            if let Some(cap) = limit.monthly_token_cap
                && cap > 0
                && tokens >= cap
            {
                return Some(format!(
                    "monthly token cap {} reached for scope '{}' (used {})",
                    cap,
                    limit.scope_key(),
                    tokens
                ));
            }
        }
        None
    }

    /// Return the first configured usage-limit reason blocking any stage this
    /// pipe can execute during one request.
    pub async fn pipe_limit_block_reason(
        &self,
        pipe_id: &str,
        pipe: &PipeConfig,
    ) -> Option<String> {
        let mut scope_keys = vec![
            UsageStage::Llm
                .scope_key()
                .to_string(),
        ];
        if pipe
            .judge
            .as_ref()
            .is_some_and(|judge| judge.enabled)
        {
            scope_keys.push(
                UsageStage::Judge
                    .scope_key()
                    .to_string(),
            );
        }
        if pipe
            .decider
            .as_ref()
            .is_some_and(|decider| decider.enabled)
        {
            scope_keys.push(
                UsageStage::Decider
                    .scope_key()
                    .to_string(),
            );
        }
        if let Some(jury) = pipe
            .jury
            .as_ref()
            .filter(|jury| jury.enabled)
        {
            for (index, juror) in jury.jurors.iter().enumerate() {
                if juror.enabled {
                    scope_keys.push(format!("stage:juror:{index}"));
                }
            }
        }

        for scope_key in scope_keys {
            if let Some(reason) = self
                .limit_block_reason(pipe_id, &scope_key, &pipe.usage_limits)
                .await
            {
                return Some(reason);
            }
        }
        None
    }

    /// Record main-LLM usage in both its stage bucket and the cumulative bucket.
    pub async fn record_llm_usage(
        &self,
        pipe_id: &str,
        cost: f64,
        tokens: u64,
    ) {
        if cost <= 0.0 && tokens == 0 {
            return;
        }
        self.record_usage(pipe_id, UsageStage::Llm.scope_key(), cost, tokens)
            .await;
        self.record_usage(pipe_id, CUMULATIVE_SCOPE_KEY, cost, tokens)
            .await;
    }
}

impl Default for BudgetTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod limit_tests {
    use super::*;
    use crate::pipes::config::{UsageLimit, UsageScope, UsageStage};

    fn cumulative_budget(budget: f64) -> UsageLimit {
        UsageLimit {
            id: "ul-cum".to_string(),
            enabled: true,
            scope: UsageScope::Cumulative,
            stage: None,
            juror_index: None,
            monthly_budget_usd: Some(budget),
            monthly_token_cap: None,
        }
    }

    fn stage_token_cap(
        stage: UsageStage,
        cap: u64,
    ) -> UsageLimit {
        UsageLimit {
            id: "ul-stage".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: Some(stage),
            juror_index: None,
            monthly_budget_usd: None,
            monthly_token_cap: Some(cap),
        }
    }

    fn juror_token_cap(
        juror_index: u32,
        cap: u64,
    ) -> UsageLimit {
        UsageLimit {
            id: "ul-juror".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: Some(UsageStage::Jury),
            juror_index: Some(juror_index),
            monthly_budget_usd: None,
            monthly_token_cap: Some(cap),
        }
    }

    #[tokio::test]
    async fn llm_usage_meters_both_its_stage_and_the_cumulative_bucket() {
        let tracker = BudgetTracker::new();
        tracker
            .record_llm_usage("p1", 0.75, 200)
            .await;

        // Every caller that drives a surface's LLM stage — the gateway, the
        // Sandbox, and the drift replay runner — lands in these two buckets, so
        // spend from one path is visible to the limit check on the next call.
        assert_eq!(
            tracker
                .scope_usage("p1", "stage:llm")
                .await,
            (0.75, 200)
        );
        assert_eq!(
            tracker
                .scope_usage("p1", "cumulative")
                .await,
            (0.75, 200)
        );
    }

    #[tokio::test]
    async fn metered_llm_spend_trips_the_next_limit_check() {
        let tracker = BudgetTracker::new();
        let limits = vec![cumulative_budget(1.0)];

        // Nothing spent yet ⇒ the next call is allowed.
        assert!(
            tracker
                .limit_block_reason("p1", "stage:llm", &limits)
                .await
                .is_none()
        );

        // Spend recorded by any path — including an evaluation replay — must
        // close the budget for the ones that follow.
        tracker
            .record_llm_usage("p1", 1.25, 10)
            .await;
        let reason = tracker
            .limit_block_reason("p1", "stage:llm", &limits)
            .await
            .expect("budget exhausted");
        assert!(reason.contains("monthly budget"), "unexpected reason: {reason}");
    }

    #[tokio::test]
    async fn record_usage_accumulates_per_scope() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "cumulative", 1.5, 100)
            .await;
        tracker
            .record_usage("p1", "cumulative", 0.5, 50)
            .await;
        tracker
            .record_usage("p1", "stage:jury", 0.25, 25)
            .await;

        assert_eq!(
            tracker
                .scope_usage("p1", "cumulative")
                .await,
            (2.0, 150)
        );
        assert_eq!(
            tracker
                .scope_usage("p1", "stage:jury")
                .await,
            (0.25, 25)
        );
        assert_eq!(
            tracker
                .scope_usage("p1", "stage:llm")
                .await,
            (0.0, 0)
        );
    }

    #[tokio::test]
    async fn no_block_when_under_cap() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "cumulative", 5.0, 0)
            .await;
        let limits = vec![cumulative_budget(10.0)];
        assert!(
            tracker
                .limit_block_reason("p1", UsageStage::Llm.scope_key(), &limits)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn blocks_when_cumulative_budget_reached() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "cumulative", 10.0, 0)
            .await;
        let limits = vec![cumulative_budget(10.0)];
        // Cumulative limit governs every stage.
        assert!(
            tracker
                .limit_block_reason("p1", UsageStage::Jury.scope_key(), &limits)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn stage_token_cap_only_blocks_its_stage() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "stage:jury", 0.0, 1000)
            .await;
        let limits = vec![stage_token_cap(UsageStage::Jury, 1000)];
        assert!(
            tracker
                .limit_block_reason("p1", UsageStage::Jury.scope_key(), &limits)
                .await
                .is_some()
        );
        // The same cap must not block a different stage.
        assert!(
            tracker
                .limit_block_reason("p1", UsageStage::Llm.scope_key(), &limits)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn disabled_limit_is_ignored() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "cumulative", 100.0, 0)
            .await;
        let mut limit = cumulative_budget(10.0);
        limit.enabled = false;
        assert!(
            tracker
                .limit_block_reason("p1", UsageStage::Llm.scope_key(), &[limit])
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn juror_token_cap_only_blocks_its_juror() {
        let tracker = BudgetTracker::new();
        tracker
            .record_usage("p1", "stage:juror:1", 0.0, 500)
            .await;
        let limits = vec![juror_token_cap(1, 500)];
        // Juror 1's own cap is reached.
        assert!(
            tracker
                .limit_block_reason("p1", "stage:juror:1", &limits)
                .await
                .is_some()
        );
        // A different juror is unaffected by juror 1's cap.
        assert!(
            tracker
                .limit_block_reason("p1", "stage:juror:0", &limits)
                .await
                .is_none()
        );
    }

    /// Records the (exceeded?) flag of every alert it is asked to send.
    pub(super) struct Recorder(pub(super) std::sync::Mutex<Vec<bool>>);

    #[async_trait::async_trait]
    impl AlertService for Recorder {
        async fn send_budget_alert(
            &self,
            _pipe_id: &str,
            usage: &MonthlyBudgetUsage,
        ) -> Result<(), String> {
            self.0
                .lock()
                .unwrap()
                .push(usage.budget_exceeded());
            Ok(())
        }
    }

    async fn spend(
        tracker: &BudgetTracker,
        cost: f64,
    ) {
        tracker
            .record_cost("p1".into(), "P1".into(), cost, Some(10.0), Some(80))
            .await
            .unwrap();
        // The alert is dispatched on a spawned task.
        tokio::task::yield_now().await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }

    #[tokio::test]
    async fn threshold_then_exceeded_alert_each_fire_once() {
        let rec = Arc::new(Recorder(Default::default()));
        let tracker = BudgetTracker::new().with_alert_service(rec.clone());
        spend(&tracker, 5.0).await; // 50%: nothing
        spend(&tracker, 3.5).await; // 85%: threshold
        spend(&tracker, 1.0).await; // 95%: already alerted
        spend(&tracker, 2.0).await; // 115%: exceeded
        spend(&tracker, 2.0).await; // still exceeded: no repeat
        assert_eq!(*rec.0.lock().unwrap(), vec![false, true]);
    }

    #[tokio::test]
    async fn crossing_both_at_once_raises_only_exceeded() {
        let rec = Arc::new(Recorder(Default::default()));
        let tracker = BudgetTracker::new().with_alert_service(rec.clone());
        spend(&tracker, 11.0).await;
        spend(&tracker, 1.0).await;
        assert_eq!(*rec.0.lock().unwrap(), vec![true]);
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::limit_tests::Recorder;
    use super::*;
    use crate::pipes::config::{UsageLimit, UsageScope};

    fn cumulative_budget(budget: f64) -> Vec<UsageLimit> {
        vec![UsageLimit {
            id: "ul-cum".to_string(),
            enabled: true,
            scope: UsageScope::Cumulative,
            stage: None,
            juror_index: None,
            monthly_budget_usd: Some(budget),
            monthly_token_cap: None,
        }]
    }

    async fn flushed(tracker: &BudgetTracker) {
        tracker
            .wait_for_persist()
            .await;
    }

    async fn record_budget_cost(
        tracker: &BudgetTracker,
        cost: f64,
        budget: f64,
    ) {
        tracker
            .record_cost("p1".into(), "P1".into(), cost, Some(budget), Some(80))
            .await
            .unwrap();
    }

    async fn is_blocked(
        tracker: &BudgetTracker,
        budget: f64,
    ) -> bool {
        tracker
            .limit_block_reason("p1", "stage:llm", &cumulative_budget(budget))
            .await
            .is_some()
    }

    fn write_peer(
        dir: &std::path::Path,
        snapshot: &Snapshot,
    ) {
        std::fs::write(dir.join("usage.peer.json"), serde_json::to_vec(snapshot).unwrap()).unwrap();
    }

    fn own_file(tracker: &BudgetTracker) -> Snapshot {
        let path = tracker
            .shards
            .as_ref()
            .unwrap()
            .own_path();
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    fn limit_in(
        month: &str,
        cost: f64,
        tokens: u64,
    ) -> Snapshot {
        Snapshot {
            budgets: HashMap::new(),
            limits: HashMap::from([(
                BudgetTracker::limit_key("p1", "cumulative"),
                ScopeUsage {
                    total_cost: cost,
                    total_tokens: tokens,
                    month: month.to_string(),
                },
            )]),
        }
    }

    #[tokio::test]
    async fn spend_recorded_before_a_restart_still_counts_after_it() {
        let dir = tempfile::tempdir().unwrap();
        {
            let tracker = BudgetTracker::persistent(dir.path()).await;
            tracker
                .record_llm_usage("p1", 1.25, 300)
                .await;
            record_budget_cost(&tracker, 9.0, 10.0).await;
            flushed(&tracker).await;
        }

        let restarted = BudgetTracker::persistent(dir.path()).await;

        assert_eq!(
            restarted
                .scope_usage("p1", "cumulative")
                .await,
            (1.25, 300)
        );
        assert!(is_blocked(&restarted, 1.0).await, "the usage limit stays reached");
        let budget = restarted
            .get_usage("p1")
            .await
            .expect("budget usage reloaded");
        assert_eq!(budget.total_spent, 9.0);
        assert!(budget.alert_sent, "the threshold alert is not raised again");

        restarted
            .record_llm_usage("p1", 0.75, 100)
            .await;
        flushed(&restarted).await;
        assert_eq!(
            BudgetTracker::persistent(dir.path())
                .await
                .scope_usage("p1", "cumulative")
                .await,
            (2.0, 400),
            "a second restart counts both runs"
        );
    }

    #[tokio::test]
    async fn an_in_memory_tracker_keeps_nothing_across_instances() {
        let tracker = BudgetTracker::new();
        tracker
            .record_llm_usage("p1", 1.25, 300)
            .await;
        tracker
            .reload_from_storage()
            .await
            .unwrap();

        assert!(!is_blocked(&BudgetTracker::new(), 1.0).await);
        assert_eq!(
            tracker
                .scope_usage("p1", "cumulative")
                .await,
            (1.25, 300)
        );
    }

    #[tokio::test]
    async fn a_promoted_standby_enforces_spend_the_active_recorded() {
        let dir = tempfile::tempdir().unwrap();
        let standby = BudgetTracker::persistent(dir.path()).await;
        let active = BudgetTracker::persistent(dir.path()).await;
        active
            .record_llm_usage("p1", 2.0, 50)
            .await;
        record_budget_cost(&active, 8.5, 10.0).await;
        flushed(&active).await;

        assert!(!is_blocked(&standby, 2.0).await, "a standby holds what it loaded at startup");

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert!(is_blocked(&standby, 2.0).await);
        assert_eq!(
            standby
                .get_usage("p1")
                .await
                .map(|u| u.total_spent),
            Some(8.5)
        );
    }

    #[tokio::test]
    async fn spend_recorded_by_every_instance_adds_up() {
        let dir = tempfile::tempdir().unwrap();
        let standby = BudgetTracker::persistent(dir.path()).await;
        let active = BudgetTracker::persistent(dir.path()).await;
        active
            .record_llm_usage("p1", 5.0, 500)
            .await;
        flushed(&active).await;

        standby
            .record_llm_usage("p1", 0.5, 5)
            .await;
        flushed(&standby).await;

        assert_eq!(
            standby
                .scope_usage("p1", "cumulative")
                .await,
            (5.5, 505),
            "a write also picks up what the others stored"
        );
        assert_eq!(
            BudgetTracker::persistent(dir.path())
                .await
                .scope_usage("p1", "cumulative")
                .await,
            (5.5, 505)
        );
        active
            .reload_from_storage()
            .await
            .unwrap();
        assert_eq!(
            active
                .scope_usage("p1", "cumulative")
                .await,
            (5.5, 505),
            "the Active counts the spend a Standby drift job recorded"
        );
    }

    #[tokio::test]
    async fn a_budget_alert_counts_every_instance_and_is_raised_once() {
        let dir = tempfile::tempdir().unwrap();
        let active_alerts = Arc::new(Recorder(Default::default()));
        let standby_alerts = Arc::new(Recorder(Default::default()));
        let active = BudgetTracker::persistent(dir.path())
            .await
            .with_alert_service(active_alerts.clone());
        let standby = BudgetTracker::persistent(dir.path())
            .await
            .with_alert_service(standby_alerts.clone());

        record_budget_cost(&active, 5.0, 10.0).await;
        flushed(&active).await;
        standby
            .reload_from_storage()
            .await
            .unwrap();
        record_budget_cost(&standby, 3.5, 10.0).await;
        flushed(&standby).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert_eq!(
            *standby_alerts
                .0
                .lock()
                .unwrap(),
            vec![false],
            "8.5 of 10 crosses the 80% threshold"
        );

        active
            .reload_from_storage()
            .await
            .unwrap();
        record_budget_cost(&active, 0.5, 10.0).await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(
            active_alerts
                .0
                .lock()
                .unwrap()
                .is_empty(),
            "the threshold alert another instance raised is not raised again"
        );
    }

    #[tokio::test]
    async fn a_stored_previous_month_does_not_count_and_is_not_written() {
        let dir = tempfile::tempdir().unwrap();
        let mut old = limit_in("2000-01", 500.0, 9_000);
        old.budgets.insert(
            "p1".to_string(),
            MonthlyBudgetUsage {
                pipe_id: "p1".to_string(),
                month: "2000-01".to_string(),
                total_spent: 500.0,
                budget_limit: 10.0,
                alert_threshold_percent: 80,
                alert_sent: true,
                exceeded_alert_sent: true,
                last_updated: Utc::now(),
            },
        );
        write_peer(dir.path(), &old);

        let tracker = BudgetTracker::persistent(dir.path()).await;

        assert!(!is_blocked(&tracker, 1.0).await, "last month's spend does not count");
        assert!(
            tracker
                .get_usage("p1")
                .await
                .is_none()
        );

        record_budget_cost(&tracker, 1.0, 10.0).await;
        flushed(&tracker).await;
        let budget = tracker
            .get_usage("p1")
            .await
            .unwrap();
        assert_eq!(budget.total_spent, 1.0);
        assert_eq!(budget.month, month_key(Utc::now()));
        assert!(!budget.alert_sent, "a new month starts with its alerts unraised");
        assert!(
            own_file(&tracker)
                .limits
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_month_that_ended_while_running_is_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let tracker = BudgetTracker::persistent(dir.path()).await;
        *tracker
            .counters
            .own
            .write()
            .await = limit_in("2000-01", 50.0, 5_000);

        assert!(!is_blocked(&tracker, 1.0).await, "the ended month no longer counts");
        tracker
            .record_llm_usage("p1", 0.25, 10)
            .await;
        flushed(&tracker).await;

        assert_eq!(
            tracker
                .scope_usage("p1", "cumulative")
                .await,
            (0.25, 10),
            "the new month starts from zero"
        );
        let stored = own_file(&tracker);
        assert!(
            stored
                .limits
                .values()
                .all(|u| u.month == month_key(Utc::now())),
            "only the current month is written: {stored:?}"
        );
    }

    #[tokio::test]
    async fn a_stored_future_month_does_not_disable_enforcement() {
        let dir = tempfile::tempdir().unwrap();
        write_peer(dir.path(), &limit_in("2999-01", 0.0, 0));

        let tracker = BudgetTracker::persistent(dir.path()).await;
        tracker
            .record_llm_usage("p1", 2.0, 2)
            .await;
        flushed(&tracker).await;

        assert!(is_blocked(&tracker, 1.0).await, "current-month spend still counts");
        assert!(
            is_blocked(&BudgetTracker::persistent(dir.path()).await, 1.0).await,
            "and still counts after a restart"
        );
    }

    #[tokio::test]
    async fn a_corrupt_file_is_set_aside_and_never_written_over() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path()
                .join("usage.peer.json"),
            b"not json",
        )
        .unwrap();

        let tracker = BudgetTracker::persistent(dir.path()).await;
        tracker
            .record_llm_usage("p1", 1.0, 1)
            .await;
        flushed(&tracker).await;

        let aside: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .file_name()
                    .into_string()
                    .unwrap()
            })
            .filter(|n| n.starts_with("usage.peer.json.corrupt-"))
            .collect();
        assert_eq!(aside.len(), 1);
        assert_eq!(std::fs::read(dir.path().join(&aside[0])).unwrap(), b"not json");
        assert!(is_blocked(&BudgetTracker::persistent(dir.path()).await, 1.0).await);
    }

    #[tokio::test]
    async fn the_budget_follows_the_current_configuration() {
        let tracker = BudgetTracker::new();
        record_budget_cost(&tracker, 1.0, 10.0).await;
        record_budget_cost(&tracker, 1.0, 20.0).await;

        let budget = tracker
            .get_usage("p1")
            .await
            .unwrap();
        assert_eq!(budget.budget_limit, 20.0);
        assert_eq!(budget.total_spent, 2.0);
    }

    #[test]
    fn combined_budget_usage_adds_spend_and_keeps_raised_alerts() {
        let month = month_key(Utc::now());
        let own = MonthlyBudgetUsage {
            total_spent: 4.0,
            ..MonthlyBudgetUsage::new("p1".to_string(), 10.0, 80)
        };
        let others = MonthlyBudgetUsage {
            total_spent: 5.0,
            alert_sent: true,
            budget_limit: 20.0,
            last_updated: own.last_updated - chrono::Duration::minutes(1),
            ..MonthlyBudgetUsage::new("p1".to_string(), 20.0, 80)
        };

        let usage = current_budget(Some(&own), Some(&others), &month).unwrap();

        assert_eq!(usage.total_spent, 9.0);
        assert!(usage.alert_sent);
        assert_eq!(usage.budget_limit, 10.0, "the budget recorded last applies");
        assert!(current_budget(None, None, &month).is_none());
    }
}
