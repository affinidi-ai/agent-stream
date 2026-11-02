//! Per-surface drift-monitoring configuration. Off by default; when enabled, a
//! configurable fraction of the surface's production traffic is sampled and its
//! drift dimensions recorded. Attached to [`crate::pipes::config::PipeConfig`]
//! as an optional block (like `governance_recording`).

use serde::{Deserialize, Serialize};

use super::verdict::DriftThresholds;
use crate::pipes::config::CacheEmbedder;

fn default_sample_rate() -> f64 {
    1.0
}

/// Optional automatic scheduling for a surface's replay evaluation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct EvalSchedule {
    /// Whether the scheduler auto-runs the evaluation.
    pub enabled: bool,
    /// How often to run, in seconds (the scheduler clamps a minimum).
    pub interval_secs: u64,
}

/// Replay-based drift evaluation for a surface: periodically re-runs the
/// surface's captured "indicative" sessions and compares each new answer to the
/// originally-captured one, folding the comparison into the drift dimensions
/// (semantic distance, latency, response length, …). Off by default; enabling it
/// needs an embeddings provider to measure semantic distance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DriftEvalConfig {
    /// Whether replay evaluation is enabled for this surface.
    #[serde(default)]
    pub enabled: bool,
    /// When present + enabled, the scheduler runs the evaluation on an interval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<EvalSchedule>,
    /// Embeddings provider used to measure the semantic distance of a replayed
    /// answer from the originally-captured one. Chosen from the model catalog in
    /// the surface builder (never a hand-typed URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embeddings: Option<CacheEmbedder>,
    /// Cap on how many captured sessions a single evaluation replays. Absent ⇒
    /// the runner's built-in cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_sessions: Option<usize>,
    /// Ceiling on the provider spend (USD) one evaluation run may consume before
    /// it stops part-way. Absent ⇒ the appliance-wide default from the
    /// `agent-stream.json` `drift` block; `0` disables the ceiling for this
    /// surface (the session cap and the surface's usage limits still bound it).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_run_cost_usd: Option<f64>,
}

/// Per-surface overrides for the `drift.detected` alert cadence. Absent fields
/// fall back to the gateway `[drift]` defaults.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct DriftAlertCadence {
    /// Minutes between re-alerts while the surface stays drifting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub re_alert_interval_mins: Option<u64>,
    /// Max alerts fired per surface per baseline (`0` = unlimited).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_alerts: Option<u32>,
}

/// Drift monitoring for one LLM Surface.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DriftConfig {
    /// Master switch. When `false` the surface emits no drift data (zero overhead).
    #[serde(default)]
    pub enabled: bool,
    /// Fraction of interactions to sample for production drift, `0.0..=1.0`.
    /// Defaults to sampling every interaction.
    #[serde(default = "default_sample_rate")]
    pub sample_rate: f64,
    /// Relative-change fraction at which a dimension is flagged `warn`. Absent ⇒
    /// the built-in default (0.25).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warn_threshold: Option<f64>,
    /// Relative-change fraction at which a dimension is flagged `drift` (and an
    /// alert fires). Absent ⇒ the built-in default (0.50).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift_threshold: Option<f64>,
    /// Block a surface save when a monitored dimension has regressed past its
    /// baseline into `drift` (regression gating). Off by default.
    #[serde(default)]
    pub gate_on_regression: bool,
    /// Replay-based evaluation config (captured-session re-run). Off by default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub eval: Option<DriftEvalConfig>,
    /// Per-surface overrides for the `drift.detected` alert cadence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_cadence: Option<DriftAlertCadence>,
    /// Integration ids the `drift.detected` alert fires to. Absent/empty ⇒ the
    /// surface's own integration mappings for the event.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alert_integrations: Option<Vec<String>>,
}

impl Default for DriftConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            sample_rate: default_sample_rate(),
            warn_threshold: None,
            drift_threshold: None,
            gate_on_regression: false,
            eval: None,
            alert_cadence: None,
            alert_integrations: None,
        }
    }
}

impl DriftConfig {
    /// Whether this interaction should contribute a drift observation — enabled
    /// and inside the sampled fraction. A `sample_rate >= 1.0` always samples;
    /// `<= 0.0` never does.
    pub fn should_sample(&self) -> bool {
        if !self.enabled || self.sample_rate <= 0.0 {
            return false;
        }
        self.sample_rate >= 1.0 || rand::random::<f64>() < self.sample_rate
    }

    /// The surface's drift verdict thresholds, resolving operator overrides
    /// against the built-in defaults.
    pub fn thresholds(&self) -> DriftThresholds {
        DriftThresholds::resolved(self.warn_threshold, self.drift_threshold)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disabled_never_samples() {
        let cfg = DriftConfig {
            enabled: false,
            sample_rate: 1.0,
            ..Default::default()
        };
        assert!(!cfg.should_sample());
    }

    #[test]
    fn zero_rate_never_samples_full_rate_always_samples() {
        assert!(
            !DriftConfig {
                enabled: true,
                sample_rate: 0.0,
                ..Default::default()
            }
            .should_sample()
        );
        assert!(
            DriftConfig {
                enabled: true,
                sample_rate: 1.0,
                ..Default::default()
            }
            .should_sample()
        );
    }

    #[test]
    fn default_is_off() {
        assert!(!DriftConfig::default().enabled);
    }

    #[test]
    fn thresholds_resolve_from_overrides() {
        let cfg = DriftConfig {
            enabled: true,
            warn_threshold: Some(0.15),
            drift_threshold: Some(0.4),
            ..Default::default()
        };
        let t = cfg.thresholds();
        assert_eq!((t.warn, t.drift), (0.15, 0.4));
        // Absent overrides → the built-in defaults.
        assert_eq!(
            DriftConfig::default()
                .thresholds()
                .warn,
            0.25
        );
    }
}
