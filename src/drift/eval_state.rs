//! Per-surface drift-evaluation health: a consecutive-failure counter and an
//! auto-suspend flag. When a surface's replay evaluation fails `N` times in a
//! row (a broken embeddings endpoint, a wedged upstream), the scheduler
//! auto-suspends it so it stops re-running a known-broken surface; a successful
//! run (typically an operator's manual retry) clears it. Kept out of the
//! surface's `PipeConfig` so an eval failure never rewrites the surface config
//! (no hot-reload churn), and persisted so a suspension survives a restart.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};

/// Resolved appliance-wide replay-eval runner settings (from `agent-stream.json`
/// `drift`), set once at startup and read by the run endpoint + scheduler.
#[derive(Debug, Clone, Copy)]
pub struct DriftEvalRuntime {
    /// Consecutive failed runs before auto-suspend (`0` disables auto-suspend).
    pub max_failures: u32,
    /// Per-session replay timeout.
    pub session_timeout: Duration,
    /// Appliance-wide ceiling on the provider spend (USD) one evaluation run may
    /// consume, used when a surface sets no ceiling of its own. `None` (or a
    /// surface override of `0`) leaves a run bounded only by its session cap and
    /// the target surface's usage limits.
    pub max_run_cost_usd: Option<f64>,
}

impl Default for DriftEvalRuntime {
    fn default() -> Self {
        Self {
            max_failures: 3,
            session_timeout: Duration::from_secs(30),
            max_run_cost_usd: None,
        }
    }
}

static RUNTIME: OnceLock<DriftEvalRuntime> = OnceLock::new();

/// Install the resolved runner settings (orchestrator, once).
pub fn set_drift_eval_runtime(rt: DriftEvalRuntime) {
    let _ = RUNTIME.set(rt);
}

/// The resolved runner settings, or built-in defaults before startup wiring.
pub fn drift_eval_runtime() -> DriftEvalRuntime {
    RUNTIME
        .get()
        .copied()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh() -> DriftEvalState {
        DriftEvalState {
            surface_id: "s".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn auto_suspends_at_n_then_success_clears() {
        // Two failures under a threshold of 3: not yet suspended.
        let s = apply_outcome(fresh(), false, Some("boom".into()), 3);
        assert_eq!(s.consecutive_failures, 1);
        assert!(!s.suspended);
        let s = apply_outcome(s, false, Some("boom".into()), 3);
        assert_eq!(s.consecutive_failures, 2);
        assert!(!s.suspended);
        // Third consecutive failure trips the suspension.
        let s = apply_outcome(s, false, Some("boom".into()), 3);
        assert_eq!(s.consecutive_failures, 3);
        assert!(s.suspended);
        assert_eq!(s.suspended_reason.as_deref(), Some("boom"));
        // A success resets the counter and lifts the suspension.
        let s = apply_outcome(s, true, None, 3);
        assert_eq!(s.consecutive_failures, 0);
        assert!(!s.suspended);
        assert!(s.suspended_reason.is_none());
    }

    #[test]
    fn zero_threshold_never_suspends() {
        let mut s = fresh();
        for _ in 0..5 {
            s = apply_outcome(s, false, None, 0);
        }
        assert_eq!(s.consecutive_failures, 5);
        assert!(!s.suspended);
    }

    #[test]
    fn default_reason_is_synthesised_when_absent() {
        let s = apply_outcome(fresh(), false, None, 1);
        assert!(s.suspended);
        assert!(
            s.suspended_reason
                .as_deref()
                .unwrap()
                .contains("consecutive failures")
        );
    }
}

/// A surface's drift-eval health.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DriftEvalState {
    pub surface_id: String,
    /// Failed runs since the last success. Reset to 0 on a successful run.
    #[serde(default)]
    pub consecutive_failures: u32,
    /// Whether the scheduler skips this surface (auto-suspended on `N` failures).
    #[serde(default)]
    pub suspended: bool,
    /// Why it was suspended (operator-facing).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_reason: Option<String>,
    /// RFC3339 timestamp of the last state change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
}

impl StorableEntity for DriftEvalState {
    fn id(&self) -> &str {
        &self.surface_id
    }
}

/// File-backed store of per-surface drift-eval health.
pub struct DriftEvalStateStore {
    storage: Box<dyn StorageBackend<DriftEvalState>>,
}

impl DriftEvalStateStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "drift_eval_state").await?;
        Ok(Self { storage })
    }

    pub async fn get(
        &self,
        surface_id: &str,
    ) -> Option<DriftEvalState> {
        self.storage
            .get(surface_id)
            .await
            .ok()
            .flatten()
    }

    /// Whether a surface's eval is currently auto-suspended (scheduler check).
    pub async fn is_suspended(
        &self,
        surface_id: &str,
    ) -> bool {
        self.get(surface_id)
            .await
            .map(|s| s.suspended)
            .unwrap_or(false)
    }

    async fn save(
        &self,
        state: &DriftEvalState,
    ) -> Result<()> {
        self.storage.save(state).await
    }

    /// Fold a terminal run outcome into the surface's health. A success clears
    /// the counter and any suspension; a failure increments it and auto-suspends
    /// once `max_failures` (`> 0`) consecutive failures are reached. Returns the
    /// new state (so a caller can report a fresh suspension).
    pub async fn record_outcome(
        &self,
        surface_id: &str,
        success: bool,
        reason: Option<String>,
        max_failures: u32,
    ) -> DriftEvalState {
        let prior = self
            .get(surface_id)
            .await
            .unwrap_or_else(|| DriftEvalState {
                surface_id: surface_id.to_string(),
                ..Default::default()
            });
        let state = apply_outcome(prior, success, reason, max_failures);
        if let Err(e) = self.save(&state).await {
            tracing::warn!("[DRIFT] failed to persist eval state for {surface_id}: {e}");
        }
        state
    }

    /// Drop a surface's eval state (surface-delete cleanup).
    pub async fn delete(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        self.storage
            .delete(surface_id)
            .await
    }
}

/// Pure state transition for a run outcome (unit-testable without the store).
fn apply_outcome(
    mut state: DriftEvalState,
    success: bool,
    reason: Option<String>,
    max_failures: u32,
) -> DriftEvalState {
    if success {
        state.consecutive_failures = 0;
        state.suspended = false;
        state.suspended_reason = None;
    } else {
        state.consecutive_failures = state
            .consecutive_failures
            .saturating_add(1);
        if max_failures > 0 && state.consecutive_failures >= max_failures {
            state.suspended = true;
            state.suspended_reason = Some(reason.unwrap_or_else(|| {
                format!("auto-suspended after {} consecutive failures", state.consecutive_failures)
            }));
        }
    }
    state.updated_at = Some(chrono::Utc::now().to_rfc3339());
    state
}

static GLOBAL: OnceLock<Arc<DriftEvalStateStore>> = OnceLock::new();

/// Register the process-wide drift-eval-state store (orchestrator, once).
pub fn set_global_drift_eval_state_store(store: Arc<DriftEvalStateStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide drift-eval-state store, if registered.
pub fn global_drift_eval_state_store() -> Option<Arc<DriftEvalStateStore>> {
    GLOBAL.get().cloned()
}
