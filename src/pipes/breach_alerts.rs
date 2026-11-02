//! Breach and anomaly alerting for LLM surfaces.
//!
//! Activates a surface's `usage_alerts` at the request boundary: each recorded
//! execution feeds a small per-pipe rolling window, and any tripped
//! [`UsageAlert`] fires through the existing integration/notification system.
//!
//! Four alert types are evaluated (`AlertType`):
//! - `CostThreshold` — a single execution's cost (USD) exceeds the threshold.
//! - `TokenThreshold` — a single execution's total tokens exceed the threshold.
//! - `ErrorRate` — the rolling error rate over the window exceeds the threshold
//!   (a fraction in `(0, 1]`).
//! - `CostSpike` — the execution's cost exceeds `threshold ×` the rolling mean
//!   cost (anomaly detection; `threshold` is a multiplier `> 1`).
//!
//! Detection state is an in-memory ring per pipe (no external store), so the
//! evaluator is deterministic and unit-testable. Alerts are dispatched off the
//! response path; the rolling window is the breach detector's own, independent
//! of the usage/ops time-series stores.

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};

use dashmap::DashMap;

use crate::integrations::FileSystemNotificationStore;
use crate::integrations::pipe_integration_triggers::UsageAlertEvent;
use crate::pipes::config::{AlertType, PipeIntegrationMapping, UsageAlert};

/// Rolling window length (seconds) used for error-rate and cost-spike baselines.
const WINDOW_SECS: i64 = 300;
/// Hard cap on retained samples per pipe, guarding memory under high traffic.
const MAX_SAMPLES: usize = 200;
/// Minimum baseline samples before a cost-spike alert can fire, so a single
/// early outlier is not flagged against an empty history.
const MIN_BASELINE_SAMPLES: usize = 5;
/// Minimum samples in the window before an error-rate alert can fire.
const MIN_ERROR_SAMPLES: usize = 5;

/// One execution's signal used for breach/anomaly evaluation.
#[derive(Debug, Clone)]
pub struct ExecutionSignal {
    pub cost: f64,
    pub total_tokens: u64,
    pub success: bool,
    /// Unix epoch seconds the execution completed.
    pub at: i64,
}

/// A tripped alert, ready to dispatch.
#[derive(Debug, Clone)]
pub struct AlertBreach {
    pub alert_type: AlertType,
    pub threshold: f64,
    pub observed: f64,
    pub baseline: Option<f64>,
    pub message: String,
    pub channels: Vec<String>,
}

impl AlertBreach {
    /// Integration event type this breach dispatches under.
    pub fn event_type(&self) -> &'static str {
        match self.alert_type {
            AlertType::CostSpike => "pipe.cost_spike",
            _ => "pipe.usage_alert",
        }
    }

    fn alert_type_label(&self) -> &'static str {
        match self.alert_type {
            AlertType::CostThreshold => "cost_threshold",
            AlertType::TokenThreshold => "token_threshold",
            AlertType::ErrorRate => "error_rate",
            AlertType::CostSpike => "cost_spike",
        }
    }
}

/// Per-pipe rolling window of recent execution signals.
#[derive(Default)]
struct PipeWindow {
    samples: VecDeque<ExecutionSignal>,
}

impl PipeWindow {
    fn prune(
        &mut self,
        now: i64,
    ) {
        let cutoff = now - WINDOW_SECS;
        while let Some(front) = self.samples.front() {
            if front.at < cutoff {
                self.samples.pop_front();
            } else {
                break;
            }
        }
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }
    }

    /// Mean cost across the retained samples (the baseline), with the count.
    fn baseline_cost(&self) -> (f64, usize) {
        let count = self.samples.len();
        if count == 0 {
            return (0.0, 0);
        }
        let sum: f64 = self
            .samples
            .iter()
            .map(|s| s.cost)
            .sum();
        (sum / count as f64, count)
    }

    /// Fraction of failed executions across the retained samples, with the count.
    fn error_rate(&self) -> (f64, usize) {
        let count = self.samples.len();
        if count == 0 {
            return (0.0, 0);
        }
        let failed = self
            .samples
            .iter()
            .filter(|s| !s.success)
            .count();
        (failed as f64 / count as f64, count)
    }
}

/// Process-wide breach detector holding each pipe's rolling window.
#[derive(Default)]
pub struct BreachDetector {
    windows: DashMap<String, PipeWindow>,
}

static GLOBAL_BREACH_DETECTOR: OnceLock<Arc<BreachDetector>> = OnceLock::new();

/// Register the process-wide breach detector. First write wins.
pub fn set_global_breach_detector(detector: Arc<BreachDetector>) {
    let _ = GLOBAL_BREACH_DETECTOR.set(detector);
}

/// Access the process-wide breach detector, if one has been registered.
pub fn global_breach_detector() -> Option<Arc<BreachDetector>> {
    GLOBAL_BREACH_DETECTOR
        .get()
        .cloned()
}

impl BreachDetector {
    /// Evaluate the configured alerts against this execution, then fold the
    /// execution into the pipe's rolling window. The baseline (cost-spike) and
    /// error-rate are computed from the window state *before* this sample is
    /// added, so an execution is never compared against itself.
    pub fn evaluate_and_record(
        &self,
        pipe_id: &str,
        alerts: &[UsageAlert],
        signal: &ExecutionSignal,
    ) -> Vec<AlertBreach> {
        let mut window = self
            .windows
            .entry(pipe_id.to_string())
            .or_default();
        window.prune(signal.at);
        let baseline = window.baseline_cost();
        // Error-rate folds the current sample in so a fresh failure is reflected.
        let prior = window.error_rate();
        let error_rate = fold_error_rate(prior, signal.success);

        let breaches = evaluate(alerts, signal, baseline, error_rate);

        window
            .samples
            .push_back(signal.clone());
        window.prune(signal.at);
        breaches
    }
}

/// Fold one more execution outcome into a prior `(rate, count)` error-rate.
fn fold_error_rate(
    prior: (f64, usize),
    success: bool,
) -> (f64, usize) {
    let (rate, count) = prior;
    let failed = (rate * count as f64).round() as usize + usize::from(!success);
    let new_count = count + 1;
    (failed as f64 / new_count as f64, new_count)
}

/// Pure alert evaluation over one execution given the rolling baseline and
/// error-rate. Returns every tripped alert.
pub fn evaluate(
    alerts: &[UsageAlert],
    signal: &ExecutionSignal,
    baseline_cost: (f64, usize),
    error_rate: (f64, usize),
) -> Vec<AlertBreach> {
    let mut breaches = Vec::new();
    for alert in alerts {
        match alert.alert_type {
            AlertType::CostThreshold => {
                if signal.cost > alert.threshold {
                    breaches.push(AlertBreach {
                        alert_type: AlertType::CostThreshold,
                        threshold: alert.threshold,
                        observed: signal.cost,
                        baseline: None,
                        message: format!(
                            "execution cost ${:.6} exceeded alert threshold ${:.6}",
                            signal.cost, alert.threshold
                        ),
                        channels: alert
                            .notification_channels
                            .clone(),
                    });
                }
            }
            AlertType::TokenThreshold => {
                let observed = signal.total_tokens as f64;
                if observed > alert.threshold {
                    breaches.push(AlertBreach {
                        alert_type: AlertType::TokenThreshold,
                        threshold: alert.threshold,
                        observed,
                        baseline: None,
                        message: format!(
                            "execution used {} tokens, exceeding alert threshold {:.0}",
                            signal.total_tokens, alert.threshold
                        ),
                        channels: alert
                            .notification_channels
                            .clone(),
                    });
                }
            }
            AlertType::ErrorRate => {
                let (rate, count) = error_rate;
                if count >= MIN_ERROR_SAMPLES && rate > alert.threshold {
                    breaches.push(AlertBreach {
                        alert_type: AlertType::ErrorRate,
                        threshold: alert.threshold,
                        observed: rate,
                        baseline: None,
                        message: format!(
                            "error rate {:.1}% over the last {} executions exceeded alert threshold {:.1}%",
                            rate * 100.0,
                            count,
                            alert.threshold * 100.0
                        ),
                        channels: alert
                            .notification_channels
                            .clone(),
                    });
                }
            }
            AlertType::CostSpike => {
                let (mean, count) = baseline_cost;
                if count >= MIN_BASELINE_SAMPLES && mean > 0.0 && signal.cost > mean * alert.threshold {
                    breaches.push(AlertBreach {
                        alert_type: AlertType::CostSpike,
                        threshold: alert.threshold,
                        observed: signal.cost,
                        baseline: Some(mean),
                        message: format!(
                            "execution cost ${:.6} is {:.1}× the ${:.6} baseline (alert at {:.1}×)",
                            signal.cost,
                            signal.cost / mean,
                            mean,
                            alert.threshold
                        ),
                        channels: alert
                            .notification_channels
                            .clone(),
                    });
                }
            }
        }
    }
    breaches
}

/// Evaluate the surface's alerts against one execution and dispatch any tripped
/// alerts off the response path. No-op when no alerts are configured or no
/// detector is registered.
pub fn spawn_breach_checks(
    notification_store: Option<Arc<FileSystemNotificationStore>>,
    integrations: Vec<PipeIntegrationMapping>,
    pipe_id: String,
    pipe_name: String,
    alerts: Vec<UsageAlert>,
    signal: ExecutionSignal,
) {
    if alerts.is_empty() {
        return;
    }
    let Some(detector) = global_breach_detector() else {
        return;
    };
    let breaches = detector.evaluate_and_record(&pipe_id, &alerts, &signal);
    if breaches.is_empty() {
        return;
    }
    let tenant_id = crate::observability::request_context::current().and_then(|ctx| ctx.usage.tenant_id);
    tokio::spawn(async move {
        let Some(store) = notification_store else {
            return;
        };
        for breach in breaches {
            let event = UsageAlertEvent {
                currency: crate::integrations::pipe_integration_triggers::usd_currency(),
                pipe_id: pipe_id.clone(),
                pipe_name: pipe_name.clone(),
                event_type: breach
                    .event_type()
                    .to_string(),
                alert_type: breach
                    .alert_type_label()
                    .to_string(),
                threshold: breach.threshold,
                observed: breach.observed,
                baseline: breach.baseline,
                message: breach.message.clone(),
                tenant_id: tenant_id.clone(),
                channels: breach.channels.clone(),
                integrations: integrations.clone(),
            };
            crate::integrations::trigger_pipe_usage_alert(&store, &event).await;
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(
        alert_type: AlertType,
        threshold: f64,
    ) -> UsageAlert {
        UsageAlert {
            alert_type,
            threshold,
            notification_channels: vec!["chan-1".to_string()],
        }
    }

    fn sig(
        cost: f64,
        tokens: u64,
        success: bool,
    ) -> ExecutionSignal {
        ExecutionSignal {
            cost,
            total_tokens: tokens,
            success,
            at: 1000,
        }
    }

    #[test]
    fn cost_threshold_fires_above_and_not_at_or_below() {
        let alerts = vec![alert(AlertType::CostThreshold, 0.10)];
        let over = evaluate(&alerts, &sig(0.11, 10, true), (0.0, 0), (0.0, 0));
        assert_eq!(over.len(), 1);
        assert_eq!(over[0].observed, 0.11);
        let under = evaluate(&alerts, &sig(0.10, 10, true), (0.0, 0), (0.0, 0));
        assert!(under.is_empty());
    }

    #[test]
    fn token_threshold_fires_above() {
        let alerts = vec![alert(AlertType::TokenThreshold, 1000.0)];
        let over = evaluate(&alerts, &sig(0.0, 1001, true), (0.0, 0), (0.0, 0));
        assert_eq!(over.len(), 1);
        let under = evaluate(&alerts, &sig(0.0, 1000, true), (0.0, 0), (0.0, 0));
        assert!(under.is_empty());
    }

    #[test]
    fn error_rate_needs_minimum_samples() {
        let alerts = vec![alert(AlertType::ErrorRate, 0.5)];
        // Rate above threshold but too few samples.
        let few = evaluate(&alerts, &sig(0.0, 0, false), (0.0, 0), (0.9, 3));
        assert!(few.is_empty());
        // Enough samples and above threshold.
        let many = evaluate(&alerts, &sig(0.0, 0, false), (0.0, 0), (0.9, 8));
        assert_eq!(many.len(), 1);
        assert!((many[0].observed - 0.9).abs() < f64::EPSILON);
    }

    #[test]
    fn cost_spike_requires_baseline_and_multiplier() {
        let alerts = vec![alert(AlertType::CostSpike, 3.0)];
        // Below the multiplier.
        let calm = evaluate(&alerts, &sig(0.20, 0, true), (0.10, 10), (0.0, 0));
        assert!(calm.is_empty());
        // 5× the baseline, plenty of samples.
        let spike = evaluate(&alerts, &sig(0.50, 0, true), (0.10, 10), (0.0, 0));
        assert_eq!(spike.len(), 1);
        assert_eq!(spike[0].baseline, Some(0.10));
        // Same spike but baseline too sparse.
        let sparse = evaluate(&alerts, &sig(0.50, 0, true), (0.10, 3), (0.0, 0));
        assert!(sparse.is_empty());
    }

    #[test]
    fn fold_error_rate_increments_count_and_failures() {
        // Prior: 1 failure in 4 (0.25). Add a failure → 2 in 5 (0.4).
        let (rate, count) = fold_error_rate((0.25, 4), false);
        assert_eq!(count, 5);
        assert!((rate - 0.4).abs() < 1e-9);
        // Add a success → 1 in 5 (0.2).
        let (rate, count) = fold_error_rate((0.25, 4), true);
        assert_eq!(count, 5);
        assert!((rate - 0.2).abs() < 1e-9);
    }

    #[test]
    fn detector_excludes_current_sample_from_baseline() {
        let detector = BreachDetector::default();
        let alerts = vec![alert(AlertType::CostSpike, 3.0)];
        // Seed a baseline of cheap calls.
        for _ in 0..6 {
            let b = detector.evaluate_and_record("p", &alerts, &sig(0.10, 0, true));
            assert!(b.is_empty());
        }
        // A pricey call should now spike against the ~0.10 baseline.
        let spike = detector.evaluate_and_record("p", &alerts, &sig(0.50, 0, true));
        assert_eq!(spike.len(), 1);
        assert_eq!(spike[0].alert_type.clone() as u8, AlertType::CostSpike as u8);
    }
}
