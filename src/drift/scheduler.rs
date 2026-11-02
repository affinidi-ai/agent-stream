//! Replay-evaluation scheduler: on a timer, run every drift-monitored surface
//! whose eval `schedule` is enabled and whose interval has elapsed, replaying
//! its captured sessions and folding the comparison into the drift dimensions.
//! Off the request path — mirrors the drift evaluator. Runs are sequential so a
//! burst of due surfaces can't stampede the upstream.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tracing::{info, warn};

use super::config::DriftEvalConfig;
use super::run::RunHandle;
use super::session_store::global_drift_session_store;
use super::{
    EvalTask, RunTrigger, drift_eval_runtime, global_drift_eval_state_store, register_run, resolve_run_cost_ceiling,
    run_eval_task,
};
use crate::identity::IdentityApiState;
use crate::pipes::FileSystemPipeStore;

/// How often the scheduler wakes to check for due surfaces.
const TICK_SECS: u64 = 60;
/// Floor on the interval a scheduled evaluation can request (a run replays every
/// captured session — an upstream call each).
const MIN_INTERVAL_SECS: u64 = 300;

/// Run the evaluation scheduler forever. Holds the last-run instant per surface
/// in memory, so on restart each scheduled surface runs once on the first tick.
pub async fn periodic_eval_scheduler(
    pipe_store: Arc<FileSystemPipeStore>,
    state: IdentityApiState,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(TICK_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!("Starting periodic drift evaluation scheduler (tick: {TICK_SECS}s)");

    let last_run: DashMap<String, Instant> = DashMap::new();
    loop {
        interval.tick().await;
        run_due_surfaces(&pipe_store, &state, &last_run).await;
    }
}

/// Run every scheduled surface whose interval has elapsed since its last run.
async fn run_due_surfaces(
    pipe_store: &FileSystemPipeStore,
    state: &IdentityApiState,
    last_run: &DashMap<String, Instant>,
) {
    let now = Instant::now();
    for pipe in pipe_store.list().await {
        let Some(eval) = pipe
            .drift
            .as_ref()
            .filter(|d| d.enabled)
            .and_then(|d| d.eval.as_ref())
            .filter(|e| e.enabled)
        else {
            continue;
        };
        let Some(schedule) = eval
            .schedule
            .as_ref()
            .filter(|s| s.enabled)
        else {
            continue;
        };
        let interval = effective_interval(schedule.interval_secs);
        if !is_due(
            last_run
                .get(&pipe.id)
                .map(|t| *t),
            now,
            interval,
        ) {
            continue;
        }
        // Skip an auto-suspended surface (a prior scheduled run failed N times in
        // a row); an operator's manual run un-suspends it on success.
        if let Some(state_store) = global_drift_eval_state_store()
            && state_store
                .is_suspended(&pipe.id)
                .await
        {
            continue;
        }
        last_run.insert(pipe.id.clone(), now);
        run_one(state, &pipe.id, &pipe.name, eval).await;
    }
}

/// The interval a scheduled evaluation actually runs at (its request, floored).
fn effective_interval(interval_secs: u64) -> Duration {
    Duration::from_secs(interval_secs.max(MIN_INTERVAL_SECS))
}

/// Whether a surface is due: never run, or its interval has elapsed.
fn is_due(
    last: Option<Instant>,
    now: Instant,
    interval: Duration,
) -> bool {
    last.map(|t| now.duration_since(t) >= interval)
        .unwrap_or(true)
}

/// Prepare the surface's executor and run the replay evaluation through it. Runs
/// inline (the scheduler loop is already sequential); `run_eval_task` folds the
/// outcome into the surface's eval health, auto-suspending on repeated failure.
async fn run_one(
    state: &IdentityApiState,
    surface_id: &str,
    surface_name: &str,
    eval: &DriftEvalConfig,
) {
    // Nothing to replay ⇒ don't dispatch a scheduled run at all. A surface with
    // no captured sessions (no traffic yet, or retention purged them) would only
    // produce empty, noisy runs — skip silently before doing any work.
    if let Some(store) = global_drift_session_store()
        && store
            .count_for_surface(surface_id)
            .await
            == 0
    {
        tracing::debug!("[DRIFT] scheduled eval for {surface_id} skipped: no captured sessions to replay");
        return;
    }
    match crate::pipes::api::prepare_pipe_execution(state, surface_id, None).await {
        Ok((pipe_config, executor, default_path)) => {
            let model = match &pipe_config.pipe_type {
                crate::pipes::config::PipeType::LLM { provider, .. } => provider
                    .model_name()
                    .to_string(),
                _ => String::new(),
            };
            let runtime = drift_eval_runtime();
            let run_id = uuid::Uuid::new_v4().to_string();
            let handle = register_run(
                &run_id,
                RunHandle {
                    surface_id: surface_id.to_string(),
                    surface_name: surface_name.to_string(),
                    target_surface_id: None,
                    variant: None,
                    trigger: RunTrigger::Scheduled,
                    started_at: chrono::Utc::now().to_rfc3339(),
                    total: AtomicUsize::new(0),
                    progress: AtomicUsize::new(0),
                    cancelled: AtomicBool::new(false),
                },
            );
            run_eval_task(EvalTask {
                executor,
                default_path,
                model,
                source_surface_id: surface_id.to_string(),
                source_surface_name: surface_name.to_string(),
                source_tenant_id: pipe_config.tenant_id.clone(),
                target_surface_id: surface_id.to_string(),
                variant: None,
                fold_into_series: true,
                max_run_cost_usd: resolve_run_cost_ceiling(eval.max_run_cost_usd, runtime.max_run_cost_usd),
                eval: eval.clone(),
                target_config: pipe_config.clone(),
                trigger: RunTrigger::Scheduled,
                run_id,
                handle,
                session_timeout: runtime.session_timeout,
                max_failures: runtime.max_failures,
                target_warn_threshold: pipe_config
                    .drift
                    .as_ref()
                    .and_then(|d| d.warn_threshold),
                target_drift_threshold: pipe_config
                    .drift
                    .as_ref()
                    .and_then(|d| d.drift_threshold),
            })
            .await;
        }
        Err((_, msg)) => warn!("[DRIFT] scheduled eval {} skipped: {}", surface_id, msg),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interval_is_floored_to_the_minimum() {
        assert_eq!(effective_interval(60), Duration::from_secs(MIN_INTERVAL_SECS));
        assert_eq!(effective_interval(3600), Duration::from_secs(3600));
    }

    #[test]
    fn due_when_never_run_or_interval_elapsed() {
        let now = Instant::now();
        // Never run → due.
        assert!(is_due(None, now, Duration::from_secs(300)));
        // Just ran → not due.
        assert!(!is_due(Some(now), now, Duration::from_secs(300)));
        // Ran longer ago than the interval → due.
        let past = now - Duration::from_secs(600);
        assert!(is_due(Some(past), now, Duration::from_secs(300)));
    }
}
