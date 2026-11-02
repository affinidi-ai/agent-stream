#![allow(dead_code)]
//! LLM drift detection.
//!
//! Tracks how an LLM Surface's behaviour changes over time as a set of
//! independent **drift dimensions**, each stored as its own gauge time series in
//! a dedicated store ([`DriftStore`]) and served by a dedicated endpoint, so the
//! drift graphs are structurally confined to the LLM Drift page and never leak
//! onto the main dashboard (which reads the usage / ops series instead).
//!
//! P1 acquires dimensions from **production sampling** — deriving them from the
//! `ExecutionMetrics` and rejection outcome already produced on the request path
//! — so the graphs fill from real traffic with no dataset authoring. Probe
//! suites and graded quality land in later phases (see `docs/LLM_DRIFT.md`).

pub mod baseline;
pub mod config;
pub mod dimension;
pub mod eval_state;
pub mod evaluator;
pub mod gating;
pub mod record;
pub mod retention;
pub mod run;
pub mod runner;
pub mod scheduler;
pub mod session_store;
pub mod store;
pub mod verdict;

pub use baseline::{DriftBaseline, DriftBaselineStore, global_drift_baseline_store, set_global_drift_baseline_store};
pub use config::DriftConfig;
pub use dimension::DriftDimension;
pub use eval_state::{
    DriftEvalRuntime, DriftEvalStateStore, drift_eval_runtime, global_drift_eval_state_store, set_drift_eval_runtime,
    set_global_drift_eval_state_store,
};
pub use evaluator::periodic_drift_evaluator;
pub use record::{DriftSignals, record_interaction};
pub use retention::{DriftRetention, periodic_retention_sweep};
pub use run::{
    DriftRun, DriftRunStore, RunTrigger, all_running_views, cancel_run, global_drift_run_store, register_run,
    running_run_view, running_runs_for_surface, set_global_drift_run_store,
};
pub use runner::{EvalTask, resolve_run_cost_ceiling, run_eval_task};
pub use scheduler::periodic_eval_scheduler;
pub use session_store::{
    RecordedSession, RecordedSessionStore, global_drift_session_store, set_global_drift_session_store,
};
pub use store::{DriftSeriesResponse, DriftStore, global_drift_store, set_global_drift_store};
pub use verdict::{DimensionVerdict, DriftStatus, DriftThresholds, evaluate_dimension, overall_status, window_mean};
