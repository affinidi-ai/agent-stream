//! Replay-based surface evaluation: re-run a drift-monitored surface's captured
//! "indicative" sessions through the same governed path a live request takes,
//! compare each new answer to the originally-captured one, and fold the
//! comparison into the surface's drift dimensions (semantic distance, latency,
//! response length, …). Called on demand by the run endpoint and periodically by
//! the scheduler; runs sessions sequentially to keep load predictable.
//!
//! A replay is a real upstream call billed to the target surface's provider key,
//! so every session's spend is metered exactly where a live request's would be:
//! the main-LLM stage against the target surface's monthly usage buckets (Judge,
//! Jury and Decider record their own from inside their executors), the whole
//! execution against the **owning member's** monthly quota, and the same
//! execution into the usage time-series under that member.
//!
//! That last part is the point: a replay is the tenant's own money, so it has to
//! count against the tenant's own budget. See [`meter_replay`] for what charging
//! it to a synthetic identity instead used to cost.
//!
//! Two guards bound a run — the target surface's own usage limits, re-checked
//! between sessions, and a per-run cost ceiling — and tripping either stops the
//! run part-way rather than spending past it.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use super::baseline::global_drift_baseline_store;
use super::config::DriftEvalConfig;
use super::dimension::{DriftDimension, surface_dimension_key};
use super::eval_state::global_drift_eval_state_store;
use super::record::is_refusal;
use super::run::{DriftRun, RunHandle, RunStatus, RunTrigger, deregister_run, global_drift_run_store};
use super::session_store::global_drift_session_store;
use super::store::{DriftSample, global_drift_store};
use super::verdict::{DimensionVerdict, DriftThresholds, evaluate_dimension};
use crate::members::types::DRIFT_MEMBER_ID;
use crate::pipes::PipeConfig;
use crate::pipes::budget_tracker::{global_budget_tracker, record_surface_llm_usage};
use crate::pipes::config::{CacheEmbedder, StageUsage};
use crate::pipes::executor::{ExecutionMetrics, PipeError, PipeExecutor, RejectedExecutionUsage};
use crate::teams::call_budget::CallBudget;
use crate::teams::gate::TeamUsageContext;

/// Attribution identity for evaluation traffic, so replay runs stay
/// distinguishable from live traffic in both the execution metrics and the
/// usage time-series.
pub const DRIFT_RUNNER_IDENTITY: &str = DRIFT_MEMBER_ID;

/// Default cap on how many captured sessions one evaluation replays, when the
/// surface's config doesn't set its own — bounds a run's upstream cost.
const DEFAULT_MAX_REPLAY_SESSIONS: usize = 50;
/// Hard ceiling on replayed sessions regardless of config.
const MAX_REPLAY_SESSIONS: usize = 200;
/// A replayed answer within this cosine distance of the originally-captured one
/// counts as "stable" (folded into the quality/stability rate).
const SEMANTIC_STABLE_THRESHOLD: f64 = 0.2;

/// One sample's result.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SampleOutcome {
    pub input: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub tags: Vec<String>,
}

/// Everything a spawned replay-evaluation task owns to run to completion (so it
/// can be `tokio::spawn`ed and outlive the request that started it). Built by
/// the run endpoint (manual) and the scheduler (scheduled).
pub struct EvalTask {
    /// The target's prepared executor (variant resolved), shared into the task.
    pub executor: Arc<PipeExecutor>,
    pub default_path: Option<String>,
    pub model: String,
    /// Source surface: owns the captured sessions, the folding key + baseline.
    pub source_surface_id: String,
    pub source_surface_name: String,
    /// The source surface's tenant: its eval embedder's key is resolved for it.
    pub source_tenant_id: Option<String>,
    /// Target surface the sessions run through (defaults to the source).
    pub target_surface_id: String,
    /// Variant alias resolved on the target (an experiment), when set.
    pub variant: Option<String>,
    /// Fold into the source's drift dimensions (baseline self-run only).
    pub fold_into_series: bool,
    /// Source surface's eval config (embeddings provider + session cap).
    pub eval: DriftEvalConfig,
    /// The target surface's resolved config, re-checked against the budget
    /// tracker between sessions so a run stops when the surface's own usage
    /// limits trip part-way through.
    pub target_config: Arc<PipeConfig>,
    /// Ceiling on this run's provider spend (USD), resolved from the source
    /// surface's eval config over the appliance default. `None` = no ceiling.
    pub max_run_cost_usd: Option<f64>,
    pub trigger: RunTrigger,
    /// Registry id + shared handle (live progress + cooperative cancel flag).
    pub run_id: String,
    pub handle: Arc<RunHandle>,
    /// Per-session wall-clock cap so one wedged upstream can't hang the run.
    pub session_timeout: Duration,
    /// Consecutive failed runs before the scheduler auto-suspends (`0` = off).
    pub max_failures: u32,
    /// The target surface's drift thresholds, for the eval-vs-baseline verdict.
    pub target_warn_threshold: Option<f64>,
    pub target_drift_threshold: Option<f64>,
}

impl EvalTask {
    /// The target/variant to record on the run — `None` for a plain self-run.
    fn experiment_target(&self) -> Option<String> {
        (self.target_surface_id != self.source_surface_id).then(|| self.target_surface_id.clone())
    }
}

/// Spend consumed by one replayed session, per pipeline stage. Built from a
/// successful execution's metrics or from the usage a rejected execution had
/// already incurred, so both are metered the same way — a Judge-blocked replay
/// still burned real provider tokens.
#[derive(Debug, Clone, Default)]
struct ReplaySpend {
    llm: StageUsage,
    judge: StageUsage,
    jury: StageUsage,
    decider: StageUsage,
}

impl ReplaySpend {
    fn total_cost(&self) -> f64 {
        self.llm.cost + self.judge.cost + self.jury.cost + self.decider.cost
    }

    /// The part of [`Self::total_cost`] billed to the owner: calls on its own
    /// keys bill nothing (see [`StageUsage::billed_cost`]).
    fn total_billed_cost(&self) -> f64 {
        self.llm.billed_cost + self.judge.billed_cost + self.jury.billed_cost + self.decider.billed_cost
    }

    fn total_tokens(&self) -> u64 {
        self.llm.total_tokens() + self.judge.total_tokens() + self.jury.total_tokens() + self.decider.total_tokens()
    }
}

impl From<&ExecutionMetrics> for ReplaySpend {
    fn from(m: &ExecutionMetrics) -> Self {
        Self {
            llm: m.llm_usage,
            judge: m.judge_usage,
            jury: m.jury_usage,
            decider: m.decider_usage,
        }
    }
}

impl From<&RejectedExecutionUsage> for ReplaySpend {
    fn from(u: &RejectedExecutionUsage) -> Self {
        Self {
            llm: u.llm,
            judge: u.judge,
            jury: u.jury,
            decider: u.decider,
        }
    }
}

/// Meter one replayed session's spend against the **target** surface — the one
/// whose provider key was actually charged, which is the experiment target on an
/// A/B run, not the source.
///
/// The identifier a surface's owning member is registered under.
///
/// Only an **api-key** source auth yields one, and deliberately so: that secret
/// id is the `key_name` a control plane registers as the member's identifier,
/// which is what makes the member resolvable without a request to extract a
/// credential from. The other schemes identify a *caller* per request — a JWT
/// subject, a client certificate — and a replay has no caller, so there is
/// nothing stable to look a member up by.
fn owner_identifier(config: &PipeConfig) -> Option<String> {
    match config.source_auth.as_ref()? {
        crate::source_auth::SourceAuthConfig::ApiKey(api_key) => {
            let id = api_key.secret_id.trim();
            (!id.is_empty()).then(|| id.to_string())
        }
        _ => None,
    }
}

/// The member and teams a replay's telemetry is filed under.
///
/// Falls back to the synthetic drift-runner member when nothing claims the
/// surface, so an appliance that does not use the member model at all keeps the
/// behaviour it had rather than losing the sample entirely.
fn attribution(owner: Option<&TeamUsageContext>) -> (&str, Vec<String>) {
    match owner {
        Some(ctx) => (
            ctx.member_id.as_str(),
            ctx.teams
                .iter()
                .map(|t| t.id.clone())
                .collect(),
        ),
        None => (DRIFT_MEMBER_ID, Vec::new()),
    }
}

/// Whose spend a replay is, resolved once per run.
///
/// A replay is a server-side caller: there is no inbound request, so nothing
/// carries a credential for the attribution gate to extract. The surface itself
/// names its owner, though — an `api_key` source-auth secret id is exactly the
/// `key_name` a control plane registers as that account's member identifier —
/// so the same member the surface's live callers are charged to can be looked
/// up from the target's own config.
///
/// `None` when the surface has no api-key source auth, or no member claims it:
/// a deployment that does not use the member model at all still runs replays,
/// it just has no quota for them to count against.
async fn replay_owner(config: &PipeConfig) -> Option<TeamUsageContext> {
    let secret_id = owner_identifier(config)?;
    let member = crate::members::store::global_member_store()?
        .find_by_identifier(&secret_id)
        .await?;
    // Teams matter as much as the member: a team budget is charged through the
    // member's memberships, so omitting them would meter half the quota.
    let teams = match crate::teams::store::global_team_store() {
        Some(store) => {
            store
                .teams_for_member(&member.id)
                .await
        }
        None => Vec::new(),
    };
    let call_budget = replay_call_budget(config, &member, &teams);
    Some(TeamUsageContext {
        // Same anchor as live traffic, so replay spend lands in the same budget period.
        budget_period_anchor: member.budget_period_anchor,
        member_id: member.id,
        teams,
        // Nothing was auto-provisioned: this resolved an existing member or none.
        provisioned: None,
        call_budget,
    })
}

/// The budgets a replay on `config` is held to: the ones a live request on the
/// surface is held to, when the surface enforces its members' quotas. Each
/// replayed session's platform-key calls are refused once they are spent.
fn replay_call_budget(
    config: &PipeConfig,
    member: &crate::members::types::Member,
    teams: &[crate::teams::types::Team],
) -> Option<Arc<CallBudget>> {
    config
        .team_attribution
        .as_ref()
        .filter(|attr| attr.enabled && attr.enforce)
        .map(|attr| Arc::new(CallBudget::new(member.clone(), teams.to_vec(), attr.allow_individual_overage)))
}

/// Meter one replayed session against everything a live request would hit.
///
/// The main-LLM stage goes into the target's monthly usage buckets; Judge, Jury
/// and Decider are deliberately left out because each records its own bucket
/// from inside its executor, and folding them in here would double-count them.
///
/// # Why the owning member is charged
///
/// This used to attribute the whole execution to the built-in `drift-runner`
/// member, to keep evaluation spend separable from live callers in the usage
/// views. It cost more than it bought. Replay spend is real provider spend on
/// the tenant's own key, and attributing it to a synthetic identity meant:
///
///   * the monthly quota tracker never saw it, so the `team_quota_exceeded`
///     gate could not count it — a tenant could burn a month's budget on
///     evaluations and never be stopped; and
///   * a control plane reading `spend-report?scope=member` for that account saw
///     a balance that ignored every replay it had run.
///
/// So the spend is charged where it belongs. Replays stay separable without a
/// fake identity: they are the surface's own `member:{id}:surface:{pipe}`
/// series, and each run record carries its `cost_usd`.
async fn meter_replay(
    target_surface_id: &str,
    spend: &ReplaySpend,
    owner: Option<&TeamUsageContext>,
) {
    // A replay that spent nothing — an error raised before any billable call —
    // has nothing to meter, and emitting a zero sample would only add a
    // meaningless point to the surface's usage series.
    if spend.total_cost() <= 0.0 && spend.total_tokens() == 0 {
        return;
    }
    record_surface_llm_usage(target_surface_id, spend.llm.cost, spend.llm.total_tokens()).await;
    // The quota tracker the `team_quota_exceeded` gate reads. Charged with the
    // grand total billed, as the inbound path does: the surface's whole billed
    // cost, not just its LLM stage.
    if let Some(ctx) = owner {
        crate::teams::record_team_usage(ctx, spend.total_billed_cost(), spend.total_tokens()).await;
    }
    let (member_id, team_ids) = attribution(owner);
    crate::telemetry::record_pipe_execution(
        target_surface_id,
        &spend.llm,
        &spend.judge,
        &spend.jury,
        &spend.decider,
        spend.llm.key_sources.sole(),
        Some(member_id),
        &team_ids,
    )
    .await;
}

/// The effective per-run cost ceiling: the surface's own `max_run_cost_usd` when
/// set, else the appliance default. An explicit `0` on the surface opts that
/// surface out of the ceiling (its usage limits and session cap still bound it).
pub fn resolve_run_cost_ceiling(
    surface: Option<f64>,
    appliance: Option<f64>,
) -> Option<f64> {
    match surface {
        Some(c) if c > 0.0 => Some(c),
        Some(_) => None,
        None => appliance.filter(|c| *c > 0.0),
    }
}

/// Why the next session must not run, checked **before** spending on it so a run
/// can overshoot its ceiling by at most the session already in flight.
fn cost_stop_reason(
    spent: f64,
    ceiling: Option<f64>,
) -> Option<String> {
    ceiling
        .filter(|c| spent >= *c)
        .map(|c| format!("run cost ceiling ${c:.2} reached (spent ${spent:.2})"))
}

/// Whether the target surface's own usage limits now block another session. Runs
/// between sessions so a limit that trips mid-run stops the replay instead of
/// spending past it, matching the check the request path makes per call.
async fn limit_stop_reason(
    target_surface_id: &str,
    target_config: &PipeConfig,
) -> Option<String> {
    let tracker = global_budget_tracker()?;
    tracker
        .pipe_limit_block_reason(target_surface_id, target_config)
        .await
        .map(|reason| format!("target surface usage limit reached: {reason}"))
}

/// Why the next session must not run, or `None` to keep replaying. Checks this
/// run's own ceiling first so an already-exhausted run skips the limit lookup.
async fn next_session_stop_reason(
    task: &EvalTask,
    run_cost: f64,
) -> Option<String> {
    match cost_stop_reason(run_cost, task.max_run_cost_usd) {
        Some(reason) => Some(reason),
        None => limit_stop_reason(&task.target_surface_id, &task.target_config).await,
    }
}

/// Resolve a finished run's terminal status: cancelled on operator request,
/// stopped when a cost guard halted it part-way, failed when there was nothing
/// to replay or every replayed session errored, otherwise completed.
fn terminal_run_status(
    cancelled: bool,
    stopped: bool,
    total: usize,
    errors: usize,
) -> RunStatus {
    if cancelled {
        RunStatus::Cancelled
    } else if stopped {
        RunStatus::Stopped
    } else if total == 0 || errors == total {
        RunStatus::Failed
    } else {
        RunStatus::Completed
    }
}

/// Whether a finished run should be silently discarded. A **scheduled** run that
/// found nothing to replay is pure noise — the surface has no captured sessions
/// (no traffic yet, or retention purged them) — so it is not persisted and never
/// touches eval health. A manual run always records, so the operator who asked
/// for it still gets feedback.
fn skip_empty_scheduled(
    total: usize,
    trigger: RunTrigger,
) -> bool {
    total == 0 && trigger == RunTrigger::Scheduled
}

/// Compare the run's measured per-dimension means against the **target surface's**
/// pinned baseline, producing the verdict the Evaluation tab plots. Only
/// dimensions the run actually observed are included.
async fn build_eval_verdicts(
    target_surface_id: &str,
    warn: Option<f64>,
    drift: Option<f64>,
    dims: &[(DriftDimension, &[f64])],
) -> Vec<DimensionVerdict> {
    let baseline = match global_drift_baseline_store() {
        Some(store) => store
            .get(target_surface_id)
            .await
            .map(|b| b.dimensions),
        None => None,
    };
    let thresholds = DriftThresholds::resolved(warn, drift);
    dims.iter()
        .filter(|(_, obs)| !obs.is_empty())
        .map(|(dim, obs)| {
            let mean = obs.iter().sum::<f64>() / obs.len() as f64;
            let base = baseline
                .as_ref()
                .and_then(|b| b.get(dim.as_str()).copied());
            evaluate_dimension(*dim, base, Some((mean, obs.len() as u64)), &thresholds)
        })
        .collect()
}

/// Run a replay-evaluation task to completion: replay the source surface's
/// captured sessions through the target executor (respecting a per-session
/// timeout + a cooperative cancel), compare each new answer to the
/// originally-captured one, (optionally) fold the comparison into the source's
/// drift dimensions, fold the outcome into the surface's eval health
/// (auto-suspend on `N` consecutive failures), and persist the terminal
/// [`DriftRun`]. Progress is served live from the registry, so it is safe to
/// `spawn` and let outlive the request that started it.
pub async fn run_eval_task(task: EvalTask) {
    let executor = &task.executor;
    let default_path = task.default_path.clone();
    let model = task.model.as_str();
    let eval = &task.eval;

    // No session store ⇒ nothing to replay (a startup misconfig); flows through
    // as an empty completed run rather than a hard error.
    let sessions = if let Some(session_store) = global_drift_session_store() {
        let cap = eval
            .max_sessions
            .unwrap_or(DEFAULT_MAX_REPLAY_SESSIONS)
            .clamp(1, MAX_REPLAY_SESSIONS);
        let mut s = session_store
            .list_for_surface(&task.source_surface_id)
            .await;
        s.truncate(cap);
        s
    } else {
        Vec::new()
    };
    task.handle
        .total
        .store(sessions.len(), Ordering::Relaxed);

    // A scheduled run with nothing to replay is discarded silently — no persisted
    // run, no eval-state change (so it can't trip auto-suspend), no alert.
    if skip_empty_scheduled(sessions.len(), task.trigger) {
        deregister_run(&task.run_id);
        tracing::debug!(
            "[DRIFT] scheduled eval for {} skipped: no captured sessions to replay",
            task.source_surface_id
        );
        return;
    }

    // The embedder is the source surface's, so its key is resolved for the
    // source surface's tenant.
    let embedder_secrets = crate::secrets::SurfaceSecrets::new(
        executor
            .surface_secrets()
            .store()
            .cloned(),
        task.source_tenant_id.clone(),
    );
    let mut outcomes = Vec::with_capacity(sessions.len());
    let mut passed = 0usize;
    let mut errors = 0usize;
    let mut quality_obs: Vec<f64> = Vec::new();
    let mut distance_obs: Vec<f64> = Vec::new();
    let mut latency_obs: Vec<f64> = Vec::new();
    let mut char_len_obs: Vec<f64> = Vec::new();
    let mut output_tokens_obs: Vec<f64> = Vec::new();
    let mut cost_obs: Vec<f64> = Vec::new();
    let mut refusal_obs: Vec<f64> = Vec::new();
    let mut safety_obs: Vec<f64> = Vec::new();
    let mut schema_obs: Vec<f64> = Vec::new();

    let mut cancelled = false;
    // Provider spend this run has consumed so far (grand total across stages),
    // persisted on the run record and checked against the run's cost ceiling.
    let mut run_cost = 0.0f64;
    let mut stop_reason: Option<String> = None;
    // Resolved once: a member lookup per replayed session would be a store read
    // per session to answer the same question.
    let owner = replay_owner(&task.target_config).await;
    if owner.is_none() {
        tracing::debug!(
            "[DRIFT] eval {} for {}: no member claims the target surface, so replay spend counts against no quota",
            task.run_id,
            task.target_surface_id
        );
    }
    for session in &sessions {
        // Cooperative cancel, checked between sessions (the replay is sequential).
        if task
            .handle
            .cancelled
            .load(Ordering::Relaxed)
        {
            cancelled = true;
            break;
        }
        // Cost guards, both checked before spending on the next session: this
        // run's own ceiling, then the target surface's usage limits (which the
        // spend metered below feeds, so a run can exhaust its own budget).
        if let Some(reason) = next_session_stop_reason(&task, run_cost).await {
            tracing::warn!(
                "[DRIFT] eval {} for {} stopped after {} session(s): {}",
                task.run_id,
                task.source_surface_id,
                outcomes.len(),
                reason
            );
            stop_reason = Some(reason);
            break;
        }
        let input = messages_summary(&session.messages);
        // Each replayed session is one request against the owner's budgets:
        // its platform-key calls, and its drift embeddings, are refused once
        // they are spent, and its owned-key calls still run.
        let session_budget = owner
            .as_ref()
            .and_then(|o| o.call_budget.as_ref())
            .map(|b| Arc::new(b.for_next_request()));
        // Per-session timeout so one wedged upstream can't hang the whole run.
        let replay = tokio::time::timeout(
            task.session_timeout,
            crate::teams::call_budget::scope(
                session_budget.clone(),
                Box::pin(replay_session(executor, default_path.clone(), model, &session.messages)),
            ),
        )
        .await;
        let r = match replay {
            Ok(Ok(r)) => r,
            Ok(Err(failure)) if failure.refusal.is_some() => {
                // A spent budget, or a platform key on a path whose spend is
                // not metered, refuses every later session the same way, and
                // a drift replay has no safety role: stop here, as a cost
                // ceiling does, rather than count failures toward suspension.
                run_cost += failure.spend.total_cost();
                meter_replay(&task.target_surface_id, &failure.spend, owner.as_ref()).await;
                crate::teams::call_budget::record_skip(
                    crate::teams::call_budget::BudgetSkip::DriftReplay,
                    &task.target_surface_id,
                );
                let reason = match failure.refusal {
                    Some(crate::pipes::executor::PlatformRefusal::NotMetered(unmetered)) => {
                        format!("not metered: {}", unmetered.code())
                    }
                    refusal => format!(
                        "budget spent: {}",
                        refusal
                            .map(|refusal| refusal.to_string())
                            .unwrap_or_default()
                    ),
                };
                tracing::warn!(
                    "[DRIFT] eval {} for {} stopped after {} session(s): {}",
                    task.run_id,
                    task.source_surface_id,
                    outcomes.len(),
                    reason
                );
                stop_reason = Some(reason);
                break;
            }
            Ok(Err(failure)) => {
                // A rejected or failed execution can still have burned provider
                // tokens (a Judge/Jury block, or a failure after the LLM call);
                // meter that before moving on, or the spend is lost.
                run_cost += failure.spend.total_cost();
                meter_replay(&task.target_surface_id, &failure.spend, owner.as_ref()).await;
                errors += 1;
                task.handle
                    .progress
                    .fetch_add(1, Ordering::Relaxed);
                outcomes.push(SampleOutcome {
                    input,
                    output: None,
                    passed: false,
                    error: Some(failure.message),
                    tags: vec!["replay".to_string()],
                });
                continue;
            }
            Err(_) => {
                // Timed out waiting on the upstream: the execution was dropped
                // mid-flight, so no metrics came back and any spend it incurred
                // is unknowable here. Judge/Jury calls that completed before the
                // timeout still recorded their own buckets from inside their
                // executors.
                errors += 1;
                task.handle
                    .progress
                    .fetch_add(1, Ordering::Relaxed);
                outcomes.push(SampleOutcome {
                    input,
                    output: None,
                    passed: false,
                    error: Some(format!("replay timed out after {}s", task.session_timeout.as_secs())),
                    tags: vec!["replay".to_string(), "timeout".to_string()],
                });
                continue;
            }
        };

        run_cost += r.spend.total_cost();
        meter_replay(&task.target_surface_id, &r.spend, owner.as_ref()).await;

        latency_obs.push(r.latency_ms as f64);
        output_tokens_obs.push(r.output_tokens as f64);
        cost_obs.push(r.cost);
        safety_obs.push(if r.safety_flagged {
            1.0
        } else {
            0.0
        });
        if let Some(valid) = r.schema_valid {
            schema_obs.push(if valid { 1.0 } else { 0.0 });
        }
        let output = r.output.unwrap_or_default();
        char_len_obs.push(output.chars().count() as f64);
        refusal_obs.push(if is_refusal(&output) {
            1.0
        } else {
            0.0
        });

        // Semantic distance of the replayed answer from the originally-captured
        // one — the primary "did the output drift" signal.
        let mut distance: Option<f64> = None;
        if let Some(embedder) = eval
            .embeddings
            .as_ref()
            .filter(|_| {
                embedder_secrets
                    .store()
                    .is_some()
            })
        {
            match crate::teams::call_budget::scope(
                session_budget.clone(),
                embed_distance(embedder, &embedder_secrets, &output, &session.output, &task.source_surface_id),
            )
            .await
            {
                Some(d) => {
                    distance_obs.push(d);
                    distance = Some(d);
                }
                None => tracing::warn!(
                    "[DRIFT] semantic_distance skipped for {}: embedding call failed (endpoint {})",
                    task.source_surface_id,
                    embedder.endpoint_url
                ),
            }
        }

        // "Stable" when the replay stayed close to the captured answer (or when
        // no embedder is configured to measure it).
        let stable = distance
            .map(|d| d <= SEMANTIC_STABLE_THRESHOLD)
            .unwrap_or(true);
        quality_obs.push(if stable { 1.0 } else { 0.0 });
        if stable {
            passed += 1;
        }
        outcomes.push(SampleOutcome {
            input,
            output: Some(output),
            passed: stable,
            error: None,
            tags: vec!["replay".to_string()],
        });
        task.handle
            .progress
            .fetch_add(1, Ordering::Relaxed);
    }

    // Sessions actually attempted — equal to the planned count on a full run,
    // and the smaller truncated count when a cancel or a cost guard ended the
    // run early, so the recorded quality is a rate over what really ran.
    let total = outcomes.len();
    let quality = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    let mean_opt = |v: &[f64]| (!v.is_empty()).then(|| v.iter().sum::<f64>() / v.len() as f64);
    let semantic_distance = mean_opt(&distance_obs);

    // Terminal status: cancelled if the operator asked; failed if there was
    // nothing to replay or every replayed session errored (a broken surface /
    // upstream); otherwise completed.
    let status = terminal_run_status(cancelled, stop_reason.is_some(), total, errors);

    // Fold measured dimensions into the source's drift store — only for a
    // completed baseline self-run, so a cancelled / failed run never disturbs the
    // series and an experiment stays inspect-only.
    if status == RunStatus::Completed
        && task.fold_into_series
        && let Some(store) = global_drift_store()
    {
        let sid = task
            .source_surface_id
            .as_str();
        let mut samples: Vec<(String, DriftSample)> = Vec::new();
        fold_dim(&mut samples, sid, DriftDimension::Quality, &quality_obs);
        fold_dim(&mut samples, sid, DriftDimension::SemanticDistance, &distance_obs);
        fold_dim(&mut samples, sid, DriftDimension::LatencyMs, &latency_obs);
        fold_dim(&mut samples, sid, DriftDimension::ResponseLength, &char_len_obs);
        fold_dim(&mut samples, sid, DriftDimension::OutputTokens, &output_tokens_obs);
        fold_dim(&mut samples, sid, DriftDimension::Cost, &cost_obs);
        fold_dim(&mut samples, sid, DriftDimension::RefusalRate, &refusal_obs);
        fold_dim(&mut samples, sid, DriftDimension::SafetyFlagRate, &safety_obs);
        fold_dim(&mut samples, sid, DriftDimension::SchemaValidRate, &schema_obs);
        if !samples.is_empty() {
            store
                .record_many(samples, chrono::Utc::now())
                .await;
        }
    }

    // Fold the outcome into the surface's eval health (auto-suspend on N
    // consecutive failures). A cancellation is an operator action, not a failure.
    let mut failure_reason = match status {
        RunStatus::Failed if total == 0 => Some("no sessions to replay".to_string()),
        RunStatus::Failed => Some(format!("all {total} replayed sessions failed")),
        RunStatus::Cancelled => Some("cancelled by operator".to_string()),
        RunStatus::Stopped => stop_reason.clone(),
        _ => None,
    };
    // A cancellation is an operator action and a cost stop is a budget decision;
    // neither says the surface's evaluation is broken, so neither counts toward
    // the consecutive-failure tally that auto-suspends it.
    if !matches!(status, RunStatus::Cancelled | RunStatus::Stopped)
        && let Some(state_store) = global_drift_eval_state_store()
    {
        let new_state = state_store
            .record_outcome(
                &task.source_surface_id,
                status == RunStatus::Completed,
                failure_reason.clone(),
                task.max_failures,
            )
            .await;
        if new_state.suspended {
            tracing::warn!(
                "[DRIFT] eval auto-suspended for {} after {} consecutive failure(s)",
                task.source_surface_id,
                new_state.consecutive_failures
            );
            failure_reason = new_state
                .suspended_reason
                .or(failure_reason);
        }
    }

    // Verdict of the measured means against the TARGET surface's baseline — the
    // "would this replay count as drift?" comparison shown on the Evaluation tab.
    let dimension_verdicts = if status == RunStatus::Completed {
        build_eval_verdicts(
            &task.target_surface_id,
            task.target_warn_threshold,
            task.target_drift_threshold,
            &[
                (DriftDimension::Quality, &quality_obs),
                (DriftDimension::SemanticDistance, &distance_obs),
                (DriftDimension::LatencyMs, &latency_obs),
                (DriftDimension::ResponseLength, &char_len_obs),
                (DriftDimension::OutputTokens, &output_tokens_obs),
                (DriftDimension::Cost, &cost_obs),
                (DriftDimension::RefusalRate, &refusal_obs),
                (DriftDimension::SafetyFlagRate, &safety_obs),
                (DriftDimension::SchemaValidRate, &schema_obs),
            ],
        )
        .await
    } else {
        Vec::new()
    };

    // Persist the terminal run so an operator can review history over time.
    if let Some(run_store) = global_drift_run_store() {
        let record = DriftRun {
            id: task.run_id.clone(),
            suite_id: task.source_surface_id.clone(),
            suite_name: task
                .source_surface_name
                .clone(),
            surface_id: task.source_surface_id.clone(),
            ran_at: chrono::Utc::now().to_rfc3339(),
            trigger: task.trigger,
            total,
            passed,
            errors,
            quality,
            self_consistency: None,
            semantic_distance,
            target_surface_id: task.experiment_target(),
            variant: task.variant.clone(),
            status,
            progress_done: task
                .handle
                .progress
                .load(Ordering::Relaxed),
            started_at: Some(task.handle.started_at.clone()),
            failure_reason,
            cost_usd: run_cost,
            dimension_verdicts,
            samples: outcomes,
        };
        if let Err(e) = run_store.save(&record).await {
            tracing::warn!("[DRIFT] failed to persist eval run {}: {}", record.id, e);
        }
    }

    // Drop the in-flight registry entry — the run is now served from the store.
    deregister_run(&task.run_id);
    tracing::info!(
        "[DRIFT] eval {} for {} finished {:?}: {}/{} stable, {} error(s), ${:.6} spent",
        task.run_id,
        task.source_surface_id,
        status,
        passed,
        total,
        errors,
        run_cost
    );
}

/// Fold a dimension's observations into the batch under its surface key.
fn fold_dim(
    samples: &mut Vec<(String, DriftSample)>,
    surface_id: &str,
    dim: DriftDimension,
    obs: &[f64],
) {
    if obs.is_empty() {
        return;
    }
    let key = surface_dimension_key(surface_id, dim);
    for o in obs {
        samples.push((key.clone(), DriftSample::observation(*o)));
    }
}

/// The result of replaying one captured session through the surface.
struct ReplayOutcome {
    output: Option<String>,
    latency_ms: u64,
    output_tokens: u64,
    cost: f64,
    safety_flagged: bool,
    schema_valid: Option<bool>,
    /// Per-stage spend this replay consumed, for metering.
    spend: ReplaySpend,
}

/// A replay that produced no answer, carrying any spend the execution had
/// already incurred before it failed — a Judge/Jury block or a late
/// infrastructure failure still burns real provider tokens, and dropping that
/// here would leave it unmetered.
struct ReplayFailure {
    message: String,
    spend: ReplaySpend,
    /// Why one of the replay's platform-key calls was refused before it was
    /// sent (a spent budget or unmetered spend), when it was.
    refusal: Option<crate::pipes::executor::PlatformRefusal>,
}

/// Pull the spend a failed execution already incurred out of its error, so it
/// can be metered even though there is no answer to compare.
fn incurred_spend(e: &PipeError) -> ReplaySpend {
    match e {
        PipeError::PromptGuardRejected { usage: Some(usage), .. } => ReplaySpend::from(usage.as_ref()),
        PipeError::WithIncurredUsage { usage, .. } => ReplaySpend::from(usage.as_ref()),
        _ => ReplaySpend::default(),
    }
}

/// Replay a captured session's `messages` through the surface, returning the new
/// answer plus the re-measured execution metrics. Errors are stringified (with
/// the spend they incurred) so a failed replay doesn't abort the run.
async fn replay_session(
    executor: &PipeExecutor,
    default_path: Option<String>,
    model: &str,
    messages: &Value,
) -> Result<ReplayOutcome, ReplayFailure> {
    let body = json!({ "model": model, "messages": messages });
    let trace_id = uuid::Uuid::new_v4().to_string();
    match executor
        .execute_with_path_and_auth(
            body,
            default_path,
            crate::pipes::key_source::CallerCredentials::default(),
            None,
            Some(trace_id),
            None,
            Some(DRIFT_RUNNER_IDENTITY.to_string()),
            None,
        )
        .await
    {
        Ok((resp, metrics)) => Ok(ReplayOutcome {
            output: extract_content(&resp),
            latency_ms: metrics.latency_ms,
            output_tokens: metrics
                .llm_usage
                .output_tokens,
            cost: metrics.cost,
            safety_flagged: !metrics
                .redrive_rejections
                .is_empty(),
            schema_valid: metrics.schema_valid,
            spend: ReplaySpend::from(&metrics),
        }),
        Err(e) => Err(ReplayFailure {
            message: e.to_string(),
            spend: incurred_spend(&e),
            refusal: e.platform_refusal(),
        }),
    }
}

/// A short, human-readable summary of a captured request's messages — the last
/// user turn's text, else the last message's — for the run-history display.
fn messages_summary(messages: &Value) -> String {
    let arr = messages.as_array();
    let text = arr
        .and_then(|a| {
            a.iter()
                .rev()
                .find(|m| {
                    m.get("role")
                        .and_then(|r| r.as_str())
                        == Some("user")
                })
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
        })
        .or_else(|| {
            arr.and_then(|a| a.last())
                .and_then(|m| m.get("content"))
                .and_then(|c| c.as_str())
        })
        .unwrap_or("")
        .trim();
    if text.chars().count() > 200 {
        format!(
            "{}…",
            text.chars()
                .take(200)
                .collect::<String>()
        )
    } else {
        text.to_string()
    }
}

/// Cosine distance (`1 - similarity`) between a sample's answer and its
/// reference, via the shared embedder. `None` when either embed call fails, so
/// a flaky embedder degrades to "no semantic-distance sample" rather than an
/// error.
async fn embed_distance(
    embedder: &CacheEmbedder,
    secrets: &crate::secrets::SurfaceSecrets,
    output: &str,
    ideal: &str,
    surface_id: &str,
) -> Option<f64> {
    use crate::pipes::cache_embedder::EmbedError;
    let out = match crate::pipes::cache_embedder::embed_text(embedder, output, secrets).await {
        Ok(v) => v,
        Err(EmbedError::BudgetRefused(_)) => {
            crate::teams::call_budget::record_skip(crate::teams::call_budget::BudgetSkip::DriftEmbedding, surface_id);
            return None;
        }
        Err(e) => {
            tracing::warn!("[DRIFT] embed(answer) failed at {}: {e}", embedder.endpoint_url);
            return None;
        }
    };
    let reference = match crate::pipes::cache_embedder::embed_text(embedder, ideal, secrets).await {
        Ok(v) => v,
        Err(EmbedError::BudgetRefused(_)) => {
            crate::teams::call_budget::record_skip(crate::teams::call_budget::BudgetSkip::DriftEmbedding, surface_id);
            return None;
        }
        Err(e) => {
            tracing::warn!("[DRIFT] embed(reference) failed at {}: {e}", embedder.endpoint_url);
            return None;
        }
    };
    let sim = crate::pipes::response_cache::cosine_similarity(&out, &reference) as f64;
    Some((1.0 - sim).clamp(0.0, 2.0))
}

/// Pull the assistant text out of an OpenAI-shaped completion.
fn extract_content(resp: &Value) -> Option<String> {
    resp.get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::source_auth::models::{ApiKeyAuthConfig, CredentialExtraction};

    fn surface_with_auth(auth: Option<crate::source_auth::SourceAuthConfig>) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            "surf-1".into(),
            "Surface".into(),
            crate::pipes::PipeType::Webhook {
                endpoint: "https://example.test".into(),
            },
        );
        pipe.source_auth = auth;
        pipe
    }

    fn api_key_auth(secret_id: &str) -> crate::source_auth::SourceAuthConfig {
        crate::source_auth::SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "x-api-key".to_string() },
            secret_id: secret_id.to_string(),
        })
    }

    fn team(id: &str) -> crate::teams::types::Team {
        crate::teams::types::Team {
            id: id.to_string(),
            name: format!("team-{id}"),
            description: None,
            status: crate::entity_status::EntityStatus::Enabled,
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

    /// The surface's api-key secret id is what a control plane registers as the
    /// owning member's identifier, so it is the only thing here that can resolve
    /// a member without a request to extract a credential from.
    #[test]
    fn only_an_api_key_surface_names_its_owner() {
        assert_eq!(
            owner_identifier(&surface_with_auth(Some(api_key_auth("acct-inbound-key")))),
            Some("acct-inbound-key".to_string())
        );
        // No source auth at all, and a blank id, both resolve to nobody rather
        // than to an empty lookup that would match whatever sorts first.
        assert_eq!(owner_identifier(&surface_with_auth(None)), None);
        assert_eq!(owner_identifier(&surface_with_auth(Some(api_key_auth("   ")))), None);
    }

    /// Replay spend is the tenant's own money, so it is filed under the member
    /// their live traffic is filed under — that is what makes the quota gate
    /// count it and a control plane's spend report include it.
    #[test]
    fn a_replay_is_charged_to_the_surfaces_own_member() {
        let ctx = TeamUsageContext {
            member_id: "acct-member".to_string(),
            teams: vec![team("team-a"), team("team-b")],
            provisioned: None,
            budget_period_anchor: None,
            call_budget: None,
        };
        let (member_id, team_ids) = attribution(Some(&ctx));
        assert_eq!(member_id, "acct-member", "not the synthetic drift-runner member");
        assert_eq!(team_ids, vec!["team-a".to_string(), "team-b".to_string()], "team budgets are charged too");
    }

    /// An appliance that does not use the member model still runs replays. The
    /// sample must not be dropped — it is the surface's spend either way — so it
    /// keeps the synthetic identity it always had.
    #[test]
    fn an_unclaimed_surface_falls_back_rather_than_losing_the_sample() {
        let (member_id, team_ids) = attribution(None);
        assert_eq!(member_id, DRIFT_MEMBER_ID);
        assert!(team_ids.is_empty());
    }

    #[test]
    fn extracts_openai_completion_content() {
        let resp = json!({ "choices": [{ "message": { "role": "assistant", "content": "Paris" } }] });
        assert_eq!(extract_content(&resp).as_deref(), Some("Paris"));
        assert_eq!(extract_content(&json!({ "choices": [] })), None);
        assert_eq!(extract_content(&json!({})), None);
    }

    #[test]
    fn summarises_last_user_message() {
        let messages = json!([
            { "role": "system", "content": "be brief" },
            { "role": "user", "content": "hello there" },
        ]);
        assert_eq!(messages_summary(&messages), "hello there");
        // Falls back to the last message when there's no user turn.
        assert_eq!(messages_summary(&json!([{ "role": "assistant", "content": "hi" }])), "hi");
        // Non-array / non-text content degrades to empty rather than panicking.
        assert_eq!(messages_summary(&json!("nope")), "");
    }

    #[test]
    fn terminal_status_marks_empty_and_all_errored_runs_failed() {
        // Nothing to replay is a failure, not a silent success.
        assert_eq!(terminal_run_status(false, false, 0, 0), RunStatus::Failed);
        // Every replayed session errored ⇒ failed.
        assert_eq!(terminal_run_status(false, false, 5, 5), RunStatus::Failed);
        // Some usable results ⇒ completed (even if graded poorly).
        assert_eq!(terminal_run_status(false, false, 5, 0), RunStatus::Completed);
        assert_eq!(terminal_run_status(false, false, 5, 2), RunStatus::Completed);
        // An operator cancel wins over everything.
        assert_eq!(terminal_run_status(true, false, 0, 0), RunStatus::Cancelled);
        assert_eq!(terminal_run_status(true, true, 5, 0), RunStatus::Cancelled);
    }

    #[test]
    fn terminal_status_marks_cost_stopped_runs_stopped() {
        // A cost guard halted the run part-way: not a failure of the surface.
        assert_eq!(terminal_run_status(false, true, 3, 0), RunStatus::Stopped);
        // Stopped before the first session even ran — still Stopped, not the
        // "nothing to replay" failure, so the operator sees the real reason.
        assert_eq!(terminal_run_status(false, true, 0, 0), RunStatus::Stopped);
        // Stopped after every attempted session errored is still a cost stop.
        assert_eq!(terminal_run_status(false, true, 2, 2), RunStatus::Stopped);
    }

    #[test]
    fn run_cost_ceiling_prefers_surface_over_appliance() {
        // The surface's own ceiling wins when it sets one.
        assert_eq!(resolve_run_cost_ceiling(Some(2.5), Some(5.0)), Some(2.5));
        // No surface ceiling ⇒ the appliance default applies.
        assert_eq!(resolve_run_cost_ceiling(None, Some(5.0)), Some(5.0));
        // An explicit zero on the surface opts out of the ceiling entirely,
        // even when the appliance sets one.
        assert_eq!(resolve_run_cost_ceiling(Some(0.0), Some(5.0)), None);
        // A non-positive appliance default is no ceiling either.
        assert_eq!(resolve_run_cost_ceiling(None, Some(0.0)), None);
        assert_eq!(resolve_run_cost_ceiling(None, None), None);
    }

    #[test]
    fn cost_stop_triggers_only_at_the_ceiling() {
        // Under the ceiling ⇒ keep replaying.
        assert!(cost_stop_reason(1.0, Some(5.0)).is_none());
        // No ceiling configured ⇒ never stops on cost.
        assert!(cost_stop_reason(1_000.0, None).is_none());
        // At or past the ceiling ⇒ stop, naming both figures for the operator.
        let reason = cost_stop_reason(5.0, Some(5.0)).expect("ceiling reached");
        assert!(reason.contains("$5.00"), "reason should name the ceiling: {reason}");
        assert!(cost_stop_reason(7.25, Some(5.0)).is_some());
    }

    #[test]
    fn replay_spend_totals_every_stage() {
        let spend = ReplaySpend {
            llm: StageUsage {
                input_tokens: 10,
                output_tokens: 5,
                cost: 0.10,
                latency_ms: 0,
                ..Default::default()
            },
            judge: StageUsage {
                input_tokens: 4,
                output_tokens: 1,
                cost: 0.02,
                latency_ms: 0,
                ..Default::default()
            },
            jury: StageUsage {
                input_tokens: 2,
                output_tokens: 1,
                cost: 0.01,
                latency_ms: 0,
                ..Default::default()
            },
            decider: StageUsage {
                input_tokens: 1,
                output_tokens: 1,
                cost: 0.005,
                latency_ms: 0,
                ..Default::default()
            },
        };
        // The run's cost accumulator must see every stage, not just the LLM.
        assert!((spend.total_cost() - 0.135).abs() < 1e-9);
        assert_eq!(spend.total_tokens(), 25);
    }

    #[test]
    fn rejected_executions_surrender_their_incurred_spend() {
        let incurred = RejectedExecutionUsage {
            llm: StageUsage {
                input_tokens: 20,
                output_tokens: 8,
                cost: 0.25,
                latency_ms: 0,
                ..Default::default()
            },
            judge: StageUsage {
                input_tokens: 5,
                output_tokens: 2,
                cost: 0.05,
                latency_ms: 0,
                ..Default::default()
            },
            jury: StageUsage::default(),
            decider: StageUsage::default(),
        };
        // A Judge/Jury block still burned tokens — the runner must meter them.
        let guarded = PipeError::PromptGuardRejected {
            status_code: 403,
            body: "blocked".to_string(),
            content_type: "application/json".to_string(),
            rejection: None,
            usage: Some(Box::new(incurred.clone())),
        };
        let spend = incurred_spend(&guarded);
        assert!((spend.llm.cost - 0.25).abs() < 1e-9);
        assert!((spend.total_cost() - 0.30).abs() < 1e-9);

        // So does a failure that struck after billable stages had completed.
        let late = PipeError::WithIncurredUsage {
            inner: Box::new(PipeError::RequestFailed("upstream down".to_string())),
            usage: Box::new(incurred),
        };
        assert!((incurred_spend(&late).total_cost() - 0.30).abs() < 1e-9);

        // An error raised before anything was spent meters nothing.
        let early = PipeError::RateLimitExceeded("slow down".to_string());
        assert_eq!(incurred_spend(&early).total_cost(), 0.0);
        assert_eq!(incurred_spend(&early).total_tokens(), 0);

        // A rejection that carries no usage detail is likewise free.
        let no_usage = PipeError::PromptGuardRejected {
            status_code: 403,
            body: "blocked".to_string(),
            content_type: "application/json".to_string(),
            rejection: None,
            usage: None,
        };
        assert_eq!(incurred_spend(&no_usage).total_cost(), 0.0);
    }

    // ── The owner's budget ──

    mod budget {
        use super::*;
        use crate::pipes::test_upstreams::CaptureUpstream;
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        use crate::teams::call_budget::{self, BudgetSkip, test_support};
        use crate::url_validation::test_service_endpoints;

        fn store() -> Arc<dyn crate::secrets::SecretsStore> {
            Arc::new(MemorySecretsStore::with(vec![
                secret("uuid-operator", "model-key", "OPERATOR", None),
                secret("uuid-own", "own-key", "OWN", Some("tenant-a")),
            ]))
        }

        /// Tenant A's surface on `url`, sending `key`.
        fn surface(
            url: &str,
            key: &str,
        ) -> PipeConfig {
            let mut config = PipeConfig::new(
                "surf-replay".into(),
                "Replay".into(),
                crate::pipes::PipeType::LLM {
                    provider: Box::new(crate::pipes::types::llm::LLMProvider::OpenAI {
                        provider_type: "openai".to_string(),
                        model: "gpt-4o".to_string(),
                        api_key_secret: Some(key.to_string()),
                        organization_id: None,
                        base_url: Some(url.to_string()),
                        temperature: None,
                        max_tokens: None,
                        top_p: None,
                        frequency_penalty: None,
                        presence_penalty: None,
                    }),
                    endpoint_path: None,
                },
            );
            config.tenant_id = Some("tenant-a".to_string());
            config
        }

        async fn replay(
            config: &PipeConfig,
            budget: Arc<CallBudget>,
        ) -> Result<ReplayOutcome, ReplayFailure> {
            let executor = PipeExecutor::new_with_secrets(config, Some(store()));
            let messages = json!([{ "role": "user", "content": "hello" }]);
            call_budget::scope(Some(budget), replay_session(&executor, None, "gpt-4o", &messages)).await
        }

        #[tokio::test]
        async fn a_replayed_session_on_a_platform_key_is_refused_once_the_owners_budget_is_spent() {
            let upstream = CaptureUpstream::answering("replayed").await;
            let _allowed = test_service_endpoints::allow(std::slice::from_ref(&upstream.url));

            let refused = replay(&surface(&upstream.url, "model-key"), test_support::spent().await).await;
            let Err(failure) = refused else {
                panic!("a platform-key replay ran on a spent budget");
            };
            assert!(
                failure
                    .refusal
                    .is_some_and(|r| r
                        .to_string()
                        .contains("monthly budget"))
            );
            assert_eq!(failure.spend.total_cost(), 0.0, "nothing was spent");
            assert_eq!(upstream.requests(), 0);

            let owned = replay(&surface(&upstream.url, "own-key"), test_support::spent().await)
                .await
                .unwrap_or_else(|f| panic!("an owned-key replay is never refused: {}", f.message));
            assert_eq!(owned.output.as_deref(), Some("replayed"));
            assert_eq!(owned.spend.llm.billed_cost, 0.0);
            assert_eq!(upstream.requests(), 1);
        }

        #[tokio::test]
        async fn a_drift_embedding_on_a_platform_key_is_skipped_and_counted() {
            let upstream = CaptureUpstream::answering("not an embedding").await;
            let _allowed = test_service_endpoints::allow(std::slice::from_ref(&upstream.url));
            let embedder = CacheEmbedder {
                endpoint_url: upstream.url.clone(),
                model: "embed".to_string(),
                api_key_secret: Some("model-key".to_string()),
            };
            let secrets = crate::secrets::SurfaceSecrets::new(Some(store()), Some("tenant-a".to_string()));
            let before = call_budget::skipped(BudgetSkip::DriftEmbedding);

            let distance = call_budget::scope(
                Some(test_support::spent().await),
                embed_distance(&embedder, &secrets, "answer", "reference", "surf-replay"),
            )
            .await;

            assert_eq!(distance, None);
            assert_eq!(upstream.requests(), 0, "the platform embedder was not called");
            assert!(call_budget::skipped(BudgetSkip::DriftEmbedding) > before, "the skip is counted");
        }

        #[test]
        fn a_replay_is_held_to_the_budget_only_where_live_traffic_is() {
            let member = test_support::member(Some(1.0));
            let mut config = surface("https://example.test", "model-key");
            assert!(replay_call_budget(&config, &member, &[]).is_none(), "no attribution, no budget");

            let mut attribution: crate::teams::TeamAttributionConfig = serde_json::from_value(json!({
                "enabled": true,
                "caller_identity_sources": [],
                "enforce": false
            }))
            .expect("attribution");
            config.team_attribution = Some(attribution.clone());
            assert!(replay_call_budget(&config, &member, &[]).is_none(), "usage recorded, never enforced");

            attribution.enforce = true;
            config.team_attribution = Some(attribution);
            assert!(replay_call_budget(&config, &member, &[]).is_some());
        }
    }

    #[test]
    fn skips_only_empty_scheduled_runs() {
        // A scheduled run with nothing to replay is discarded silently.
        assert!(skip_empty_scheduled(0, RunTrigger::Scheduled));
        // A manual empty run still records (the operator asked for it).
        assert!(!skip_empty_scheduled(0, RunTrigger::Manual));
        // A scheduled run with sessions runs normally.
        assert!(!skip_empty_scheduled(3, RunTrigger::Scheduled));
    }
}
