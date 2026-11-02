//! Persisted evaluation-suite run history. Each run of a suite (on-demand or
//! scheduled) is saved as a `DriftRun` — the pass rate plus the per-sample
//! outcomes — so an operator can review how a surface's graded quality has
//! moved over successive runs. Stored like the suite/baseline stores, keyed by
//! run id, and capped per suite so history can't grow without bound.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};

use super::retention::DriftRetention;
use super::runner::SampleOutcome;
use super::verdict::DimensionVerdict;
use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};

/// What triggered a run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunTrigger {
    /// An operator pressed **Run** in the LLM Drift page.
    Manual,
    /// The scheduler ran the suite on its interval.
    Scheduled,
}

/// Lifecycle of an async replay-evaluation run.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Accepted, not yet started replaying.
    Pending,
    /// Replaying sessions.
    Running,
    /// Finished; results are final.
    Completed,
    /// Aborted by an error (e.g. every session errored, or auto-suspended).
    Failed,
    /// Cancelled by an operator.
    Cancelled,
    /// Halted part-way by a cost guard — the target surface hit a usage limit,
    /// or the run reached its cost ceiling. Whatever was replayed before the
    /// stop is kept for inspection but, like a cancellation, is a truncated
    /// sample and so never folds into the drift series.
    Stopped,
}

/// Legacy run records (pre-async) have no `status`; they are completed history.
fn default_run_status() -> RunStatus {
    RunStatus::Completed
}

/// A persisted record of one evaluation-suite run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftRun {
    pub id: String,
    pub suite_id: String,
    pub suite_name: String,
    pub surface_id: String,
    /// RFC3339 timestamp the run completed.
    pub ran_at: String,
    pub trigger: RunTrigger,
    pub total: usize,
    pub passed: usize,
    pub errors: usize,
    pub quality: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_consistency: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_distance: Option<f64>,
    /// The surface the sessions ran through, when it differs from the source (an
    /// experiment); absent for a plain self-run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_surface_id: Option<String>,
    /// The variant alias the sessions ran through, when set (an experiment).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Lifecycle status of the (async) run. Legacy records default to completed.
    #[serde(default = "default_run_status")]
    pub status: RunStatus,
    /// Sessions replayed so far; equals `total` on a completed run.
    #[serde(default)]
    pub progress_done: usize,
    /// When the run started (RFC3339); absent for legacy records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,
    /// Why the run failed, stopped or was cancelled, when applicable
    /// (operator-facing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failure_reason: Option<String>,
    /// Provider spend this run consumed, in USD — the grand total across every
    /// stage of every replayed session, including the sessions replayed before a
    /// cost guard stopped the run. `0.0` on legacy records (spend was not
    /// measured before evaluation runs were metered).
    #[serde(default)]
    pub cost_usd: f64,
    /// Per-dimension verdict of the run's measured means against the **target
    /// surface's** pinned baseline — the "did this replay drift from baseline?"
    /// comparison the Evaluation tab plots. Empty for a failed / legacy run.
    #[serde(default)]
    pub dimension_verdicts: Vec<DimensionVerdict>,
    pub samples: Vec<SampleOutcome>,
}

impl StorableEntity for DriftRun {
    fn id(&self) -> &str {
        &self.id
    }
}

/// File-backed store of evaluation-suite run records.
pub struct DriftRunStore {
    storage: Box<dyn StorageBackend<DriftRun>>,
    retention: DriftRetention,
}

impl DriftRunStore {
    pub async fn new(
        storage_dir: String,
        retention: DriftRetention,
    ) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "drift_run").await?;
        Ok(Self { storage, retention })
    }

    pub async fn get(
        &self,
        id: &str,
    ) -> Option<DriftRun> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    async fn list(&self) -> Vec<DriftRun> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Save a run, then prune that suite's history to the configured retention
    /// (newest N per surface + any older than the age cap) so it can't grow.
    pub async fn save(
        &self,
        run: &DriftRun,
    ) -> Result<()> {
        self.storage.save(run).await?;
        self.prune_suite(&run.suite_id)
            .await;
        Ok(())
    }

    /// A surface's runs, newest first.
    pub async fn list_for_surface(
        &self,
        surface_id: &str,
    ) -> Vec<DriftRun> {
        let mut runs: Vec<DriftRun> = self
            .list()
            .await
            .into_iter()
            .filter(|r| r.surface_id == surface_id)
            .collect();
        runs.sort_by(|a, b| b.ran_at.cmp(&a.ran_at));
        runs
    }

    /// The most recent runs across **all** surfaces, newest first, capped at
    /// `limit` (the History tab's default cross-surface view).
    pub async fn list_recent(
        &self,
        limit: usize,
    ) -> Vec<DriftRun> {
        let mut runs = self.list().await;
        runs.sort_by(|a, b| b.ran_at.cmp(&a.ran_at));
        runs.truncate(limit);
        runs
    }

    /// Delete every run bound to `surface_id` (surface soft-delete cleanup).
    pub async fn delete_for_surface(
        &self,
        surface_id: &str,
    ) {
        for run in self.list().await {
            if run.surface_id == surface_id {
                let _ = self
                    .storage
                    .delete(&run.id)
                    .await;
            }
        }
    }

    /// Apply the retention policy to one suite's runs: keep the newest
    /// `max_per_surface` and drop any older than the age cap.
    async fn prune_suite(
        &self,
        suite_id: &str,
    ) {
        let mut runs: Vec<DriftRun> = self
            .list()
            .await
            .into_iter()
            .filter(|r| r.suite_id == suite_id)
            .collect();
        runs.sort_by(|a, b| b.ran_at.cmp(&a.ran_at));
        let cutoff = self.retention.age_cutoff();
        for (idx, run) in runs.iter().enumerate() {
            if idx >= self.retention.max_per_surface || DriftRetention::is_expired(&run.ran_at, cutoff) {
                let _ = self
                    .storage
                    .delete(&run.id)
                    .await;
            }
        }
    }

    /// Re-apply the retention policy to every surface (the periodic sweep), so
    /// age-based expiry also reaches surfaces that have gone idle.
    pub async fn prune_all(&self) {
        let ids: HashSet<String> = self
            .list()
            .await
            .iter()
            .map(|r| r.suite_id.clone())
            .collect();
        for id in ids {
            self.prune_suite(&id).await;
        }
    }
}

static GLOBAL: OnceLock<Arc<DriftRunStore>> = OnceLock::new();

/// Register the process-wide run store (orchestrator, once).
pub fn set_global_drift_run_store(store: Arc<DriftRunStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide run store, if registered.
pub fn global_drift_run_store() -> Option<Arc<DriftRunStore>> {
    GLOBAL.get().cloned()
}

/// In-flight run bookkeeping: live progress + a cooperative cancel flag, held in
/// memory only (a run lives in one process). Terminal runs are persisted to the
/// [`DriftRunStore`]; in-flight ones are served from this registry, so progress
/// costs no disk I/O and a crash leaves no orphaned "running" record behind.
pub struct RunHandle {
    pub surface_id: String,
    pub surface_name: String,
    pub target_surface_id: Option<String>,
    pub variant: Option<String>,
    pub trigger: RunTrigger,
    pub started_at: String,
    pub total: AtomicUsize,
    pub progress: AtomicUsize,
    pub cancelled: AtomicBool,
}

impl RunHandle {
    /// A "running" snapshot of this in-flight run for the read API.
    fn running_view(
        &self,
        run_id: &str,
    ) -> DriftRun {
        DriftRun {
            id: run_id.to_string(),
            suite_id: self.surface_id.clone(),
            suite_name: self.surface_name.clone(),
            surface_id: self.surface_id.clone(),
            ran_at: self.started_at.clone(),
            trigger: self.trigger,
            total: self
                .total
                .load(Ordering::Relaxed),
            passed: 0,
            errors: 0,
            quality: 0.0,
            self_consistency: None,
            semantic_distance: None,
            target_surface_id: self.target_surface_id.clone(),
            variant: self.variant.clone(),
            status: RunStatus::Running,
            progress_done: self
                .progress
                .load(Ordering::Relaxed),
            started_at: Some(self.started_at.clone()),
            failure_reason: None,
            // Spend is totalled by the runner and lands on the terminal record;
            // an in-flight snapshot does not carry a partial figure.
            cost_usd: 0.0,
            dimension_verdicts: Vec::new(),
            samples: Vec::new(),
        }
    }
}

static RUN_REGISTRY: OnceLock<DashMap<String, Arc<RunHandle>>> = OnceLock::new();

fn run_registry() -> &'static DashMap<String, Arc<RunHandle>> {
    RUN_REGISTRY.get_or_init(DashMap::new)
}

/// Register an in-flight run; returns the shared handle the runner updates.
pub fn register_run(
    run_id: &str,
    handle: RunHandle,
) -> Arc<RunHandle> {
    let handle = Arc::new(handle);
    run_registry().insert(run_id.to_string(), handle.clone());
    handle
}

/// Drop an in-flight run from the registry (on any terminal state).
pub fn deregister_run(run_id: &str) {
    run_registry().remove(run_id);
}

/// Request cooperative cancellation of an in-flight run. Returns whether a
/// matching in-flight run was found (so the caller can 404 an unknown/finished
/// run rather than silently succeed).
pub fn cancel_run(run_id: &str) -> bool {
    if let Some(h) = run_registry().get(run_id) {
        h.cancelled
            .store(true, Ordering::Relaxed);
        true
    } else {
        false
    }
}

/// A "running" view of an in-flight run, if it is still in the registry.
pub fn running_run_view(run_id: &str) -> Option<DriftRun> {
    run_registry()
        .get(run_id)
        .map(|h| h.running_view(run_id))
}

/// Running views for a surface's in-flight runs.
pub fn running_runs_for_surface(surface_id: &str) -> Vec<DriftRun> {
    run_registry()
        .iter()
        .filter(|e| e.value().surface_id == surface_id)
        .map(|e| {
            e.value()
                .running_view(e.key())
        })
        .collect()
}

/// Running views for every in-flight run, across all surfaces.
pub fn all_running_views() -> Vec<DriftRun> {
    run_registry()
        .iter()
        .map(|e| {
            e.value()
                .running_view(e.key())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(
        total: usize,
        progress: usize,
    ) -> RunHandle {
        RunHandle {
            surface_id: "s".to_string(),
            surface_name: "S".to_string(),
            target_surface_id: None,
            variant: None,
            trigger: RunTrigger::Manual,
            started_at: "2026-01-01T00:00:00Z".to_string(),
            total: AtomicUsize::new(total),
            progress: AtomicUsize::new(progress),
            cancelled: AtomicBool::new(false),
        }
    }

    #[test]
    fn registry_view_reflects_progress_and_cancel() {
        let run_id = format!("test-{}", uuid::Uuid::new_v4());
        let h = register_run(&run_id, handle(3, 1));

        // The running view reflects live progress + total from the atomics.
        let v = running_run_view(&run_id).expect("in-flight run should have a view");
        assert_eq!(v.status, RunStatus::Running);
        assert_eq!(v.total, 3);
        assert_eq!(v.progress_done, 1);
        assert_eq!(v.id, run_id);

        // Cancelling trips the shared flag; an unknown id reports not-found.
        assert!(cancel_run(&run_id));
        assert!(
            h.cancelled
                .load(Ordering::Relaxed)
        );
        assert!(!cancel_run("no-such-run-id"));

        // Deregistering removes it from the in-flight view.
        deregister_run(&run_id);
        assert!(running_run_view(&run_id).is_none());
    }

    #[test]
    fn legacy_records_default_to_completed() {
        // A record persisted before the async rework has no `status` field.
        let json = r#"{"id":"r1","suite_id":"s","suite_name":"S","surface_id":"s","ran_at":"t","trigger":"manual","total":2,"passed":2,"errors":0,"quality":1.0,"samples":[]}"#;
        let run: DriftRun = serde_json::from_str(json).unwrap();
        assert_eq!(run.status, RunStatus::Completed);
        assert_eq!(run.progress_done, 0);
    }
}
