//! Drift verdict: compare a surface's recent per-dimension behaviour against a
//! captured baseline and classify how far it has moved. Pure functions — the
//! current means come from the drift store and the baseline from the baseline
//! store; nothing here does I/O, so it is cheap to test.

use serde::{Deserialize, Serialize};

use super::dimension::DriftDimension;
use super::store::DriftSeriesPoint;

/// How far a dimension has moved from its baseline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftStatus {
    /// Within the warn threshold of baseline.
    Stable,
    /// Past the warn threshold but not the drift threshold.
    Warn,
    /// Past the drift threshold.
    Drift,
    /// No baseline, or no samples in the window — can't judge.
    Unknown,
}

impl DriftStatus {
    /// Severity rank for folding per-dimension verdicts into a surface verdict.
    /// Only the three *judged* statuses are ranked; [`DriftStatus::Unknown`] is
    /// not a severity — it means "couldn't measure" — and is filtered out by
    /// [`overall_status`] before ranking rather than competing here.
    fn rank(self) -> u8 {
        match self {
            DriftStatus::Stable | DriftStatus::Unknown => 0,
            DriftStatus::Warn => 1,
            DriftStatus::Drift => 2,
        }
    }
}

/// Relative-change thresholds (fraction of the baseline magnitude) at which a
/// dimension is warned / declared drifted. Symmetric — any large change counts,
/// since drift is "behaviour moved", regardless of direction.
#[derive(Debug, Clone, Copy)]
pub struct DriftThresholds {
    pub warn: f64,
    pub drift: f64,
}

impl Default for DriftThresholds {
    fn default() -> Self {
        Self { warn: 0.25, drift: 0.5 }
    }
}

impl DriftThresholds {
    /// Build validated thresholds from operator-supplied fractions, falling back
    /// to the defaults when a value is absent and keeping `drift >= warn > 0` so
    /// a mis-ordered pair can't invert the severity ladder.
    pub fn resolved(
        warn: Option<f64>,
        drift: Option<f64>,
    ) -> Self {
        let d = Self::default();
        let warn = warn
            .filter(|w| w.is_finite() && *w > 0.0)
            .unwrap_or(d.warn);
        let drift = drift
            .filter(|v| v.is_finite() && *v > 0.0)
            .unwrap_or(d.drift)
            .max(warn);
        Self { warn, drift }
    }
}

/// One dimension's verdict, ready to serialize onto the LLM Drift page.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DimensionVerdict {
    pub dimension: String,
    pub label: String,
    pub status: DriftStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub baseline: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delta: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relative_change: Option<f64>,
    pub sample_count: u64,
}

/// Count-weighted mean over a drift series' buckets, plus the total sample
/// count. `None` when the window carries no observations. Because each bucket
/// already holds a mean and a count, `mean·count` recovers the bucket's sum, so
/// the window mean is `Σsum / Σcount`.
pub fn window_mean(points: &[DriftSeriesPoint]) -> Option<(f64, u64)> {
    let total: u64 = points
        .iter()
        .map(|p| p.count)
        .sum();
    if total == 0 {
        return None;
    }
    let weighted: f64 = points
        .iter()
        .map(|p| p.mean * p.count as f64)
        .sum();
    Some((weighted / total as f64, total))
}

/// Classify one dimension given its baseline mean and the current window mean
/// (+ sample count). Relative change is measured against the baseline magnitude
/// floored by [`DriftDimension::baseline_floor`] so a near-zero baseline can't
/// read as infinite drift.
pub fn evaluate_dimension(
    dim: DriftDimension,
    baseline: Option<f64>,
    current: Option<(f64, u64)>,
    thresholds: &DriftThresholds,
) -> DimensionVerdict {
    let (cur, count) = match current {
        Some((m, c)) => (Some(m), c),
        None => (None, 0),
    };
    let (status, delta, rel) = match (baseline, cur) {
        (Some(b), Some(c)) => {
            let delta = c - b;
            let rel = delta.abs()
                / b.abs()
                    .max(dim.baseline_floor());
            let status = if rel >= thresholds.drift {
                DriftStatus::Drift
            } else if rel >= thresholds.warn {
                DriftStatus::Warn
            } else {
                DriftStatus::Stable
            };
            (status, Some(delta), Some(rel))
        }
        _ => (DriftStatus::Unknown, None, None),
    };
    DimensionVerdict {
        dimension: dim.as_str().to_string(),
        label: dim.label().to_string(),
        status,
        baseline,
        current: cur,
        delta,
        relative_change: rel,
        sample_count: count,
    }
}

/// The surface's overall verdict — the worst of the dimensions that could
/// actually be **judged** against the baseline.
///
/// A dimension is `Unknown` when it has no baseline value or no samples in the
/// window, which is ordinary: `schema_valid_rate` only records for
/// structured-output requests, and `quality` / `semantic_distance` only once a
/// replay evaluation has run. Those are "not measured here", not "worse than
/// stable", so they are excluded from the fold — otherwise a single unmeasurable
/// dimension would report a fully-baselined, stable surface as having no
/// baseline at all. `Unknown` is returned only when **no** dimension could be
/// judged, which is the genuine "nothing to compare against" case.
pub fn overall_status(verdicts: &[DimensionVerdict]) -> DriftStatus {
    verdicts
        .iter()
        .map(|v| v.status)
        .filter(|s| *s != DriftStatus::Unknown)
        .max_by_key(|s| s.rank())
        .unwrap_or(DriftStatus::Unknown)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn window_mean_is_count_weighted() {
        let pts =
            vec![DriftSeriesPoint { t: 0, mean: 100.0, count: 1 }, DriftSeriesPoint { t: 30, mean: 300.0, count: 3 }];
        // (100*1 + 300*3) / 4 = 1000/4 = 250
        assert_eq!(window_mean(&pts), Some((250.0, 4)));
        assert_eq!(window_mean(&[]), None);
    }

    #[test]
    fn stable_warn_drift_by_relative_change() {
        let t = DriftThresholds::default();
        // latency baseline 1000ms: +200 = 20% → stable; +300 = 30% → warn; +600 = 60% → drift.
        let stable = evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1200.0, 10)), &t);
        assert_eq!(stable.status, DriftStatus::Stable);
        let warn = evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1300.0, 10)), &t);
        assert_eq!(warn.status, DriftStatus::Warn);
        let drift = evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1600.0, 10)), &t);
        assert_eq!(drift.status, DriftStatus::Drift);
    }

    #[test]
    fn near_zero_baseline_uses_floor_not_infinity() {
        let t = DriftThresholds::default();
        // refusal baseline 0.0, current 0.10: rel = 0.10 / max(0, 0.05) = 2.0 → drift (not inf/NaN).
        let v = evaluate_dimension(DriftDimension::RefusalRate, Some(0.0), Some((0.10, 20)), &t);
        assert_eq!(v.status, DriftStatus::Drift);
        assert!(
            v.relative_change
                .unwrap()
                .is_finite()
        );
        // A 0.02 change is within the floor → stable.
        let v2 = evaluate_dimension(DriftDimension::RefusalRate, Some(0.0), Some((0.01, 20)), &t);
        assert_eq!(v2.status, DriftStatus::Stable);
    }

    #[test]
    fn no_baseline_or_no_samples_is_unknown() {
        let t = DriftThresholds::default();
        assert_eq!(
            evaluate_dimension(DriftDimension::LatencyMs, None, Some((100.0, 5)), &t).status,
            DriftStatus::Unknown
        );
        assert_eq!(evaluate_dimension(DriftDimension::LatencyMs, Some(100.0), None, &t).status, DriftStatus::Unknown);
    }

    #[test]
    fn overall_is_the_worst_dimension() {
        let t = DriftThresholds::default();
        let vs = vec![
            evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1000.0, 5)), &t),
            evaluate_dimension(DriftDimension::ResponseLength, Some(100.0), Some((160.0, 5)), &t),
        ];
        assert_eq!(overall_status(&vs), DriftStatus::Drift);
    }

    #[test]
    fn unmeasurable_dimension_does_not_hide_a_pinned_baseline() {
        let t = DriftThresholds::default();
        // The common shape: a surface with a pinned baseline whose traffic sends
        // no structured output, so `schema_valid_rate` has neither a baseline
        // entry nor samples. It must not report the whole surface as unbaselined.
        let vs = vec![
            evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1010.0, 50)), &t),
            evaluate_dimension(DriftDimension::ResponseLength, Some(100.0), Some((102.0, 50)), &t),
            evaluate_dimension(DriftDimension::SchemaValidRate, None, None, &t),
        ];
        assert_eq!(overall_status(&vs), DriftStatus::Stable);
    }

    #[test]
    fn unmeasurable_dimension_never_masks_a_real_verdict() {
        let t = DriftThresholds::default();
        // A dimension that drifted still wins over both stable and unknown ones.
        let drifted = vec![
            evaluate_dimension(DriftDimension::SchemaValidRate, None, None, &t),
            evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1000.0, 5)), &t),
            evaluate_dimension(DriftDimension::ResponseLength, Some(100.0), Some((160.0, 5)), &t),
        ];
        assert_eq!(overall_status(&drifted), DriftStatus::Drift);
        // And a warn is still surfaced alongside an unmeasurable dimension.
        let warned = vec![
            evaluate_dimension(DriftDimension::Quality, None, None, &t),
            evaluate_dimension(DriftDimension::LatencyMs, Some(1000.0), Some((1300.0, 5)), &t),
        ];
        assert_eq!(overall_status(&warned), DriftStatus::Warn);
    }

    #[test]
    fn overall_is_unknown_only_when_nothing_can_be_judged() {
        let t = DriftThresholds::default();
        // No baseline at all: every dimension is unknown ⇒ the genuine
        // "nothing to compare against" case the badge is meant to report.
        let vs = vec![
            evaluate_dimension(DriftDimension::LatencyMs, None, Some((1000.0, 5)), &t),
            evaluate_dimension(DriftDimension::SchemaValidRate, None, None, &t),
        ];
        assert_eq!(overall_status(&vs), DriftStatus::Unknown);
        // An empty verdict list is likewise unknown.
        assert_eq!(overall_status(&[]), DriftStatus::Unknown);
    }

    #[test]
    fn resolved_thresholds_fall_back_and_keep_order() {
        // Both absent → defaults.
        let d = DriftThresholds::resolved(None, None);
        assert_eq!((d.warn, d.drift), (0.25, 0.5));
        // Operator overrides honoured.
        let o = DriftThresholds::resolved(Some(0.1), Some(0.3));
        assert_eq!((o.warn, o.drift), (0.1, 0.3));
        // drift < warn is lifted to warn so the ladder can't invert.
        let inv = DriftThresholds::resolved(Some(0.4), Some(0.2));
        assert_eq!((inv.warn, inv.drift), (0.4, 0.4));
        // Non-finite / non-positive values fall back to the default.
        let bad = DriftThresholds::resolved(Some(-1.0), Some(f64::NAN));
        assert_eq!((bad.warn, bad.drift), (0.25, 0.5));
    }
}
