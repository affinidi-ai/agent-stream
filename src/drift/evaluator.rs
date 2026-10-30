//! Periodic drift evaluator: on a timer, judge every drift-monitored surface
//! against its pinned baseline and raise a `drift.detected` integration alert
//! when it enters drift, then re-alert on a configurable cadence while it stays
//! drifting (capped per baseline). Off the request path.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use tokio::time::Duration;
use tracing::{info, warn};

use super::dimension::surface_dimension_key;
use super::verdict::{DimensionVerdict, evaluate_dimension, overall_status, window_mean};
use super::{DriftDimension, DriftStatus, global_drift_baseline_store, global_drift_store};
use crate::config::types::DriftBootstrapConfig;
use crate::integrations::{DriftDimensionReport, DriftEvaluation, FileSystemNotificationStore};
use crate::pipes::FileSystemPipeStore;

/// How often to re-evaluate every drift-monitored surface.
const EVAL_INTERVAL_SECS: u64 = 300;
/// The trailing window whose behaviour is compared to the baseline.
const EVAL_WINDOW_SECS: i64 = 3_600;

/// Per-surface alert bookkeeping for the current drift episode (reset when the
/// surface recovers out of drift).
#[derive(Clone, Copy)]
struct AlertState {
    status: DriftStatus,
    alerts_fired: u32,
    last_alert: Option<Instant>,
}

/// Run the drift evaluator forever. Holds per-surface alert bookkeeping in
/// memory so it alerts on entry to drift, then re-alerts on the configured
/// cadence while it stays drifting (capped per baseline).
pub async fn periodic_drift_evaluator(
    pipe_store: Arc<FileSystemPipeStore>,
    notification_store: Arc<FileSystemNotificationStore>,
    cadence_defaults: DriftBootstrapConfig,
) {
    let mut interval = tokio::time::interval(Duration::from_secs(EVAL_INTERVAL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    info!("Starting periodic drift evaluator (interval: {EVAL_INTERVAL_SECS}s)");

    let state: DashMap<String, AlertState> = DashMap::new();
    loop {
        interval.tick().await;
        // Only the Active instance raises drift alerts, so a Standby neither
        // duplicates them nor evaluates against its stale baselines.
        if !crate::server::mode::is_ready_to_serve() {
            continue;
        }
        evaluate_once(&pipe_store, &notification_store, &state, &cadence_defaults).await;
    }
}

/// One evaluation pass over all drift-monitored surfaces.
async fn evaluate_once(
    pipe_store: &FileSystemPipeStore,
    notification_store: &FileSystemNotificationStore,
    alert_state: &DashMap<String, AlertState>,
    cadence_defaults: &DriftBootstrapConfig,
) {
    let (Some(drift_store), Some(baseline_store)) = (global_drift_store(), global_drift_baseline_store()) else {
        return;
    };
    let to = chrono::Utc::now().timestamp();
    let from = to - EVAL_WINDOW_SECS;

    for pipe in pipe_store
        .list()
        .await
        .into_iter()
        .map(|p| p.with_global_surface_defaults())
    {
        let drift_enabled = pipe
            .drift
            .as_ref()
            .map(|d| d.enabled)
            .unwrap_or(false);
        if !drift_enabled {
            continue;
        }
        // Per-surface thresholds (operator overrides, else the built-in default).
        let thresholds = pipe
            .drift
            .as_ref()
            .map(|d| d.thresholds())
            .unwrap_or_default();
        // No baseline ⇒ nothing to judge against yet.
        let Some(baseline) = baseline_store
            .get(&pipe.id)
            .await
        else {
            continue;
        };

        let keys: Vec<String> = DriftDimension::ALL
            .iter()
            .map(|d| surface_dimension_key(&pipe.id, *d))
            .collect();
        let series = drift_store
            .range_many(&keys, from, to, 500, None)
            .await;
        let by_key: HashMap<&str, &_> = series
            .iter()
            .map(|s| (s.key.as_str(), s))
            .collect();

        let verdicts: Vec<DimensionVerdict> = DriftDimension::ALL
            .iter()
            .map(|dim| {
                let current = by_key
                    .get(surface_dimension_key(&pipe.id, *dim).as_str())
                    .and_then(|s| window_mean(&s.points));
                let base = baseline
                    .dimensions
                    .get(dim.as_str())
                    .copied();
                evaluate_dimension(*dim, base, current, &thresholds)
            })
            .collect();
        let status = overall_status(&verdicts);

        // Resolve this surface's alert cadence: per-surface override, else the
        // gateway `[drift]` default.
        let cadence = pipe
            .drift
            .as_ref()
            .and_then(|d| d.alert_cadence.as_ref());
        let interval_mins = cadence
            .and_then(|c| c.re_alert_interval_mins)
            .unwrap_or(cadence_defaults.re_alert_interval_mins)
            .max(1);
        let re_alert = Duration::from_secs(interval_mins * 60);
        let max_alerts = cadence
            .and_then(|c| c.max_alerts)
            .unwrap_or(cadence_defaults.max_alerts);

        let now = Instant::now();
        let prev = alert_state
            .get(&pipe.id)
            .map(|r| *r);
        let (fire, next) = decide_alert(prev, status, now, re_alert, max_alerts);
        alert_state.insert(pipe.id.clone(), next);

        let alert_integrations = pipe
            .drift
            .as_ref()
            .and_then(|d| {
                d.alert_integrations
                    .as_deref()
            });
        let evaluation = DriftEvaluation {
            tenant_id: pipe.tenant_id.clone(),
            ..build_evaluation(&verdicts, status, EVAL_WINDOW_SECS)
        };

        if drift_resolved(prev, status) {
            info!("[DRIFT] surface {} left drift (now {})", pipe.id, evaluation.status);
            crate::integrations::trigger_pipe_drift_resolved(
                notification_store,
                &pipe.integrations,
                alert_integrations,
                &pipe.id,
                &pipe.name,
                &evaluation,
            )
            .await;
        }

        if !fire {
            continue;
        }
        let Some(worst) = worst_drift_dimension(&verdicts) else {
            continue;
        };
        warn!(
            "[DRIFT] surface {} drifted on {}: baseline={:?} current={:?} (alert {})",
            pipe.id, worst.label, worst.baseline, worst.current, next.alerts_fired
        );
        let headline = dimension_report(worst);
        crate::integrations::trigger_pipe_drift_detected(
            notification_store,
            &pipe.integrations,
            alert_integrations,
            &pipe.id,
            &pipe.name,
            &headline,
            &evaluation,
        )
        .await;
    }
}

/// One verdict as an event dimension: unknown values stay `None` (`null` on the wire).
fn dimension_report(v: &DimensionVerdict) -> DriftDimensionReport {
    let unit = DriftDimension::ALL
        .iter()
        .find(|d| d.as_str() == v.dimension)
        .map(|d| d.unit())
        .unwrap_or("");
    DriftDimensionReport {
        id: v.dimension.clone(),
        label: v.label.clone(),
        unit: unit.to_string(),
        status: status_str(v.status).to_string(),
        baseline: v.baseline,
        current: v.current,
        delta: v.delta,
    }
}

fn status_str(s: DriftStatus) -> &'static str {
    match s {
        DriftStatus::Stable => "stable",
        DriftStatus::Warn => "warn",
        DriftStatus::Drift => "drift",
        DriftStatus::Unknown => "unknown",
    }
}

/// The full evaluation (every dimension, overall status, window) behind a drift event.
fn build_evaluation(
    verdicts: &[DimensionVerdict],
    status: DriftStatus,
    window_seconds: i64,
) -> DriftEvaluation {
    DriftEvaluation {
        status: status_str(status).to_string(),
        window_seconds,
        dimensions: verdicts
            .iter()
            .map(dimension_report)
            .collect(),
        tenant_id: None,
    }
}

/// True when the surface was drifting on the previous pass and no longer is.
fn drift_resolved(
    prev: Option<AlertState>,
    status: DriftStatus,
) -> bool {
    status != DriftStatus::Drift
        && prev
            .map(|p| p.status == DriftStatus::Drift)
            .unwrap_or(false)
}

/// Decide whether to fire a drift alert this pass, and the surface's next alert
/// bookkeeping. Fires on entry to drift, then re-alerts once `re_alert` has
/// elapsed while it stays drifting, capped at `max_alerts` (`0` = unlimited).
/// Leaving drift resets the episode.
fn decide_alert(
    prev: Option<AlertState>,
    status: DriftStatus,
    now: Instant,
    re_alert: Duration,
    max_alerts: u32,
) -> (bool, AlertState) {
    if status != DriftStatus::Drift {
        return (
            false,
            AlertState {
                status,
                alerts_fired: 0,
                last_alert: None,
            },
        );
    }
    let was_drift = prev
        .map(|p| p.status == DriftStatus::Drift)
        .unwrap_or(false);
    let fired = prev
        .map(|p| p.alerts_fired)
        .unwrap_or(0);
    let last = prev.and_then(|p| p.last_alert);
    if !was_drift {
        // Just entered drift → the first alert.
        return (
            true,
            AlertState {
                status,
                alerts_fired: 1,
                last_alert: Some(now),
            },
        );
    }
    let under_cap = max_alerts == 0 || fired < max_alerts;
    let due = last
        .map(|t| now.duration_since(t) >= re_alert)
        .unwrap_or(true);
    if under_cap && due {
        (
            true,
            AlertState {
                status,
                alerts_fired: fired + 1,
                last_alert: Some(now),
            },
        )
    } else {
        (
            false,
            AlertState {
                status,
                alerts_fired: fired,
                last_alert: last,
            },
        )
    }
}

/// The drifted dimension with the largest relative change (the alert headline).
fn worst_drift_dimension(verdicts: &[DimensionVerdict]) -> Option<&DimensionVerdict> {
    verdicts
        .iter()
        .filter(|v| v.status == DriftStatus::Drift)
        .max_by(|a, b| {
            a.relative_change
                .unwrap_or(0.0)
                .partial_cmp(
                    &b.relative_change
                        .unwrap_or(0.0),
                )
                .unwrap_or(std::cmp::Ordering::Equal)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decides_alert_on_entry_and_re_alerts_on_cadence() {
        let now = Instant::now();
        let re = Duration::from_secs(3600);
        // Enters drift with no prior state → fire (the first alert).
        let (fire, st) = decide_alert(None, DriftStatus::Drift, now, re, 5);
        assert!(fire && st.alerts_fired == 1);
        // Still drifting, interval not elapsed → no re-alert.
        assert!(!decide_alert(Some(st), DriftStatus::Drift, now, re, 5).0);
        // Still drifting, interval elapsed → re-alert (count 2).
        let later = now + Duration::from_secs(3601);
        let (fire3, st3) = decide_alert(Some(st), DriftStatus::Drift, later, re, 5);
        assert!(fire3 && st3.alerts_fired == 2);
        // At the cap → no more alerts even when due.
        let capped = AlertState {
            status: DriftStatus::Drift,
            alerts_fired: 5,
            last_alert: Some(now),
        };
        assert!(!decide_alert(Some(capped), DriftStatus::Drift, later, re, 5).0);
        // `max_alerts = 0` → unlimited.
        assert!(decide_alert(Some(capped), DriftStatus::Drift, later, re, 0).0);
        // Recovery resets the episode (no alert, count 0).
        let (fire_r, st_r) = decide_alert(Some(st3), DriftStatus::Stable, later, re, 5);
        assert!(!fire_r && st_r.alerts_fired == 0);
    }

    #[test]
    fn resolved_only_when_leaving_drift() {
        let st = |status| AlertState {
            status,
            alerts_fired: 1,
            last_alert: None,
        };
        assert!(drift_resolved(Some(st(DriftStatus::Drift)), DriftStatus::Stable));
        assert!(drift_resolved(Some(st(DriftStatus::Drift)), DriftStatus::Warn));
        assert!(drift_resolved(Some(st(DriftStatus::Drift)), DriftStatus::Unknown));
        assert!(!drift_resolved(Some(st(DriftStatus::Drift)), DriftStatus::Drift));
        assert!(!drift_resolved(Some(st(DriftStatus::Stable)), DriftStatus::Stable));
        assert!(!drift_resolved(None, DriftStatus::Stable));
    }

    #[test]
    fn evaluation_lists_every_dimension_with_null_for_unknown() {
        let t = super::super::verdict::DriftThresholds::default();
        let verdicts = vec![
            evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1600.0, 10)), &t),
            evaluate_dimension(DriftDimension::Quality, None, None, &t),
        ];
        let eval = build_evaluation(&verdicts, DriftStatus::Drift, 3600);
        assert_eq!(eval.status, "drift");
        assert_eq!(eval.window_seconds, 3600);
        let json = serde_json::to_value(&eval.dimensions).unwrap();
        assert_eq!(json[0]["id"], "latency_ms");
        assert_eq!(json[0]["unit"], "ms");
        assert_eq!(json[0]["status"], "drift");
        assert_eq!(json[0]["delta"], 600.0);
        assert_eq!(json[1]["status"], "unknown");
        assert!(json[1]["baseline"].is_null() && json[1]["current"].is_null() && json[1]["delta"].is_null());
    }

    #[test]
    fn worst_dimension_is_the_largest_relative_change() {
        let mk = |label: &str, status: DriftStatus, rel: f64| DimensionVerdict {
            dimension: label.to_string(),
            label: label.to_string(),
            status,
            baseline: Some(1.0),
            current: Some(2.0),
            delta: Some(1.0),
            relative_change: Some(rel),
            sample_count: 10,
        };
        let verdicts = vec![
            mk("latency", DriftStatus::Drift, 0.6),
            mk("length", DriftStatus::Drift, 0.9),
            mk("refusal", DriftStatus::Warn, 2.0),
        ];
        // The Warn dimension has the biggest rel but isn't drifting; the worst
        // *drifting* dimension is `length` (0.9).
        assert_eq!(
            worst_drift_dimension(&verdicts)
                .unwrap()
                .label,
            "length"
        );
        assert!(worst_drift_dimension(&[]).is_none());
    }
}
