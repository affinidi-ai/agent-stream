//! Regression gating: compute a surface's current overall drift status from the
//! global drift + baseline stores, so a surface save (or variant promotion) can
//! be blocked when the surface has regressed past its baseline into `drift`.
//!
//! Default-safe: a missing store, a surface with no pinned baseline, or a window
//! with no samples all resolve to [`DriftStatus::Unknown`] — never `Drift` — so
//! gating can only block on a *positive* regression signal.

use std::collections::HashMap;

use super::dimension::{DriftDimension, surface_dimension_key};
use super::verdict::{DriftStatus, DriftThresholds, evaluate_dimension, overall_status, window_mean};
use super::{global_drift_baseline_store, global_drift_store};

/// The surface's overall drift status over the trailing `window_secs`, compared
/// to its pinned baseline with `thresholds`.
pub async fn surface_drift_status(
    surface_id: &str,
    thresholds: &DriftThresholds,
    window_secs: i64,
) -> DriftStatus {
    let (Some(drift_store), Some(baseline_store)) = (global_drift_store(), global_drift_baseline_store()) else {
        return DriftStatus::Unknown;
    };
    let Some(baseline) = baseline_store
        .get(surface_id)
        .await
    else {
        return DriftStatus::Unknown;
    };
    let to = chrono::Utc::now().timestamp();
    let from = to - window_secs.max(1);
    let keys: Vec<String> = DriftDimension::ALL
        .iter()
        .map(|d| surface_dimension_key(surface_id, *d))
        .collect();
    let series = drift_store
        .range_many(&keys, from, to, 500, None)
        .await;
    let by_key: HashMap<&str, _> = series
        .iter()
        .map(|s| (s.key.as_str(), s))
        .collect();
    let verdicts: Vec<_> = DriftDimension::ALL
        .iter()
        .map(|dim| {
            let current = by_key
                .get(surface_dimension_key(surface_id, *dim).as_str())
                .and_then(|s| window_mean(&s.points));
            let base = baseline
                .dimensions
                .get(dim.as_str())
                .copied();
            evaluate_dimension(*dim, base, current, thresholds)
        })
        .collect();
    overall_status(&verdicts)
}
