//! The drift dimension time-series store: a thin domain wrapper over the shared
//! embedded RRD engine ([`crate::timeseries::RrdStore`]), parameterised with
//! [`DriftSample`]. Mirrors [`crate::telemetry::TelemetryStore`] and
//! [`crate::metrics::ops_telemetry::OpsMetricsStore`], so a scaled / HA
//! deployment can swap in an external time-series backend without touching a
//! call site.
//!
//! A dimension is a **gauge**: the per-bucket value we want is the mean of the
//! observations in that bucket. The RRD engine only knows how to *sum* buckets
//! when it rolls a fine tier up into a coarse one, so each sample carries a
//! running `{ sum, count }` and the read layer divides to recover the mean —
//! the same trick `OpsSample` uses for average latency.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::timeseries::{KeyMatch, RrdRange, RrdSample, RrdStore, TimeSeriesBackend};

/// A per-bucket gauge accumulator: the running sum of observations and their
/// count. The bucket mean is `sum / count`. Both fields are additive, so a
/// coarse RRD bucket equals the merge of the finer buckets it spans.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct DriftSample {
    pub sum: f64,
    pub count: u64,
}

impl RrdSample for DriftSample {
    fn merge(
        &mut self,
        other: &Self,
    ) {
        self.sum += other.sum;
        self.count += other.count;
    }
}

impl DriftSample {
    /// A single observation of `value`.
    pub fn observation(value: f64) -> Self {
        Self { sum: value, count: 1 }
    }

    /// The bucket mean, or `0.0` when there are no observations.
    pub fn mean(&self) -> f64 {
        if self.count == 0 {
            0.0
        } else {
            self.sum / self.count as f64
        }
    }
}

/// One point of a drift series: bucket start (unix seconds), the bucket mean,
/// and how many observations it summarises.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DriftSeriesPoint {
    pub t: i64,
    pub mean: f64,
    pub count: u64,
}

/// A single drift series' range-query result: which tier served it plus points.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct DriftSeriesResponse {
    pub key: String,
    pub resolution: String,
    pub step_secs: i64,
    pub points: Vec<DriftSeriesPoint>,
}

/// Drift dimension store backed by a swappable [`TimeSeriesBackend<DriftSample>`].
pub struct DriftStore {
    backend: Arc<dyn TimeSeriesBackend<DriftSample>>,
}

impl DriftStore {
    /// Wrap an arbitrary backend (embedded RRD engine or an external adapter).
    pub fn with_backend(backend: Arc<dyn TimeSeriesBackend<DriftSample>>) -> Self {
        Self { backend }
    }

    /// Build the default embedded RRD-backed store rooted at `storage_dir`.
    pub async fn new(storage_dir: impl Into<PathBuf>) -> Self {
        Self::with_backend(Arc::new(RrdStore::<DriftSample>::new(storage_dir).await))
    }

    /// Record a batch of `(series_key, sample)` observations at instant `ts`.
    pub async fn record_many(
        &self,
        samples: Vec<(String, DriftSample)>,
        ts: DateTime<Utc>,
    ) {
        if samples.is_empty() {
            return;
        }
        self.backend
            .record_many(samples, ts)
            .await;
    }

    /// Resolve many drift series in one call (single read-lock acquisition on
    /// the embedded backend), mapping each bucket to its mean.
    pub async fn range_many(
        &self,
        keys: &[String],
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> Vec<DriftSeriesResponse> {
        self.backend
            .range_many(keys, from, to, max_points, force_tier)
            .await
            .into_iter()
            .map(to_series_response)
            .collect()
    }

    /// Drop a surface's drift series on soft-delete (every dimension child).
    pub async fn remove_surface_series(
        &self,
        surface_id: &str,
    ) {
        self.backend
            .delete_series_matching(&KeyMatch::Prefix(format!("drift:surface:{surface_id}:")))
            .await;
    }

    /// Synchronously persist all pending state (graceful shutdown).
    pub async fn flush(&self) {
        self.backend.flush().await;
    }

    /// Single-key convenience used by tests; production reads go through
    /// [`range_many`](Self::range_many).
    #[cfg(test)]
    pub async fn range(
        &self,
        key: &str,
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> DriftSeriesResponse {
        to_series_response(
            self.backend
                .range(key, from, to, max_points, force_tier)
                .await,
        )
    }
}

/// Map the backend's generic range result onto the drift-facing wire shape,
/// converting each bucket's `{ sum, count }` accumulator into its mean.
fn to_series_response(range: RrdRange<DriftSample>) -> DriftSeriesResponse {
    DriftSeriesResponse {
        key: range.key,
        resolution: range.resolution,
        step_secs: range.step_secs,
        points: range
            .points
            .into_iter()
            .map(|p| DriftSeriesPoint {
                t: p.t,
                mean: p.value.mean(),
                count: p.value.count,
            })
            .collect(),
    }
}

static GLOBAL: OnceLock<Arc<DriftStore>> = OnceLock::new();

/// Register the process-wide drift store (called once by the orchestrator).
pub fn set_global_drift_store(store: Arc<DriftStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide drift store, if one has been registered.
pub fn global_drift_store() -> Option<Arc<DriftStore>> {
    GLOBAL.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(epoch: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(epoch, 0)
            .unwrap()
    }

    #[test]
    fn mean_is_sum_over_count() {
        let mut s = DriftSample::observation(10.0);
        s.merge(&DriftSample::observation(20.0));
        s.merge(&DriftSample::observation(30.0));
        assert_eq!(s.count, 3);
        assert_eq!(s.mean(), 20.0);
        assert_eq!(DriftSample::default().mean(), 0.0);
    }

    #[tokio::test]
    async fn record_and_range_returns_bucket_mean() {
        let dir = std::env::temp_dir().join(format!("drift-{}", uuid::Uuid::new_v4()));
        let store = DriftStore::new(&dir).await;
        let now = Utc::now().timestamp();
        let key = "drift:surface:p1:latency_ms".to_string();
        store
            .record_many(vec![(key.clone(), DriftSample::observation(100.0))], at(now))
            .await;
        store
            .record_many(vec![(key.clone(), DriftSample::observation(300.0))], at(now))
            .await;

        let resp = store
            .range(&key, now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.points.len(), 1);
        assert_eq!(resp.points[0].mean, 200.0);
        assert_eq!(resp.points[0].count, 2);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
