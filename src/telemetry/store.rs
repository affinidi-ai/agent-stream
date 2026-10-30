//! Usage telemetry store: additive cost/token/request counters per series.
//!
//! A thin typed facade over the shared embedded RRD engine
//! ([`crate::timeseries::RrdStore`]) parameterised with [`Sample`], mirroring
//! [`crate::metrics::OpsMetricsStore`]. The resolution-tier pyramid, retention,
//! snapshotting, and prefix/suffix GC all live in the backend-neutral engine so
//! the usage and operational stores share one implementation. Series are a
//! surface, a pipeline stage, a member, or a team.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::{DateTime, Utc};

use super::types::{Sample, SeriesPoint, SeriesResponse};
use crate::timeseries::{KeyMatch, RrdRange, RrdStore, TimeSeriesBackend};

static GLOBAL: OnceLock<Arc<TelemetryStore>> = OnceLock::new();

/// Register the process-wide telemetry store (called once by the orchestrator).
pub fn set_global_telemetry_store(store: Arc<TelemetryStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide telemetry store, if one has been registered.
pub fn global_telemetry_store() -> Option<Arc<TelemetryStore>> {
    GLOBAL.get().cloned()
}

/// Usage telemetry store backed by a swappable [`TimeSeriesBackend<Sample>`].
/// Defaults to the embedded [`RrdStore`]; an external TSDB adapter can be
/// injected via [`with_backend`](Self::with_backend) without touching callers.
pub struct TelemetryStore {
    backend: Arc<dyn TimeSeriesBackend<Sample>>,
}

impl TelemetryStore {
    /// Build a store, loading any per-tier snapshot files found in `storage_dir`.
    pub async fn new(storage_dir: impl Into<PathBuf>) -> Self {
        Self::with_backend(Arc::new(RrdStore::<Sample>::new(storage_dir).await))
    }

    /// Wrap an arbitrary backend (embedded RRD engine or an external adapter).
    pub fn with_backend(backend: Arc<dyn TimeSeriesBackend<Sample>>) -> Self {
        Self { backend }
    }

    /// Record a batch of `(series_key, cost, tokens)` samples at instant `ts`.
    /// Each sample adds to every tier's bucket covering `ts` and increments that
    /// bucket's request count by one.
    pub async fn record_many(
        &self,
        samples: &[(String, f64, u64)],
        ts: DateTime<Utc>,
    ) {
        if samples.is_empty() {
            return;
        }
        let mapped: Vec<(String, Sample)> = samples
            .iter()
            .map(|(key, cost, tokens)| {
                (
                    key.clone(),
                    Sample {
                        cost: *cost,
                        tokens: *tokens,
                        requests: 1,
                        ..Default::default()
                    },
                )
            })
            .collect();
        self.record_samples(mapped, ts)
            .await;
    }

    /// Record a batch of fully formed samples at instant `ts`, each added to
    /// every tier's bucket covering `ts`.
    pub async fn record_samples(
        &self,
        samples: Vec<(String, Sample)>,
        ts: DateTime<Utc>,
    ) {
        if samples.is_empty() {
            return;
        }
        self.backend
            .record_many(samples, ts)
            .await;
    }

    /// Return the series' points over `[from, to]` (unix seconds). When
    /// `force_tier` names a known tier label that exact resolution is served;
    /// otherwise the engine auto-selects the finest tier that fits `max_points`
    /// and covers `from`. Single-key convenience used by tests; production reads
    /// go through [`range_many`](Self::range_many).
    #[cfg(test)]
    pub async fn range(
        &self,
        key: &str,
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> SeriesResponse {
        to_series_response(
            self.backend
                .range(key, from, to, max_points, force_tier)
                .await,
        )
    }

    /// Resolve many series in one call. The embedded backend takes its read lock
    /// once for the whole batch, so the dashboard's multi-series fetch (up to a
    /// few hundred member/team keys) is a single lock acquisition.
    pub async fn range_many(
        &self,
        keys: &[String],
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> Vec<SeriesResponse> {
        self.backend
            .range_many(keys, from, to, max_points, force_tier)
            .await
            .into_iter()
            .map(to_series_response)
            .collect()
    }

    /// Remove every series whose key satisfies `spec` (memory + disk). Used for
    /// prefix/suffix GC: a soft-deleted member drops its grand-total and all
    /// `member:{id}:surface:*` series; a soft-deleted surface drops its
    /// grand-total, per-stage, and every `member:*:surface:{pipe}` series.
    pub async fn delete_series_matching(
        &self,
        spec: &KeyMatch,
    ) {
        self.backend
            .delete_series_matching(spec)
            .await;
    }

    /// Synchronously persist every tier, bypassing the snapshot throttle. Called
    /// on graceful shutdown and after a deletion.
    pub async fn flush(&self) {
        self.backend.flush().await;
    }
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for TelemetryStore {
    /// Continue the usage series the previous Active wrote instead of
    /// overwriting them with this instance's startup copy.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.backend.reload().await;
        Ok(())
    }
}

/// Map the backend's generic range result onto the usage-facing wire shape.
fn to_series_response(range: RrdRange<Sample>) -> SeriesResponse {
    SeriesResponse {
        key: range.key,
        resolution: range.resolution,
        step_secs: range.step_secs,
        points: range
            .points
            .into_iter()
            .map(|p| SeriesPoint {
                t: p.t,
                cost: p.value.cost,
                billed_cost: p.value.billed_cost(),
                tokens: p.value.tokens,
                requests: p.value.requests,
                requests_by_key_source: p.value.key_sources,
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(epoch: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(epoch, 0)
            .unwrap()
    }

    #[tokio::test]
    async fn record_and_range_single_bucket() {
        let dir = std::env::temp_dir().join(format!("tlm-single-{}", uuid::Uuid::new_v4()));
        let store = TelemetryStore::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(&[("surface:p1".to_string(), 0.25, 100)], at(now))
            .await;

        let resp = store
            .range("surface:p1", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.resolution, "30s");
        assert_eq!(resp.points.len(), 1);
        assert_eq!(resp.points[0].cost, 0.25);
        assert_eq!(resp.points[0].tokens, 100);
        assert_eq!(resp.points[0].requests, 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_coarsens_wide_window_when_data_is_dense() {
        let dir = std::env::temp_dir().join(format!("tlm-dense-{}", uuid::Uuid::new_v4()));
        let store = TelemetryStore::new(&dir).await;
        let step = 30;
        let base = (Utc::now().timestamp() / step) * step - 150 * step;
        let to = base + 149 * step;
        // Dense traffic: 150 consecutive 30s buckets. The finest tier's *actual*
        // in-range bucket count (150) exceeds max_points, so a coarser tier is
        // chosen — the actual-count fit still bounds the returned points.
        for k in 0..150 {
            store
                .record_many(&[("member:dense".to_string(), 0.1, 1)], at(base + k * step))
                .await;
        }
        let resp = store
            .range("member:dense", base, to, 100, None)
            .await;
        assert_eq!(resp.resolution, "1m");
        assert!(!resp.points.is_empty());
        assert!(resp.points.len() <= 100);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn snapshot_roundtrips_across_reload() {
        let dir = std::env::temp_dir().join(format!("tlm-persist-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        {
            let store = TelemetryStore::new(&dir).await;
            store
                .record_many(&[("team:t9".to_string(), 4.0, 40)], at(now))
                .await;
            store.flush().await;
        }
        let reloaded = TelemetryStore::new(&dir).await;
        let resp = reloaded
            .range("team:t9", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.points.len(), 1);
        assert_eq!(resp.points[0].cost, 4.0);
        assert_eq!(resp.points[0].tokens, 40);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_keeps_fine_tier_when_data_is_sparse() {
        let dir = std::env::temp_dir().join(format!("tlm-sparse-{}", uuid::Uuid::new_v4()));
        let store = TelemetryStore::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(&[("surface:sparse".to_string(), 1.0, 1)], at(now))
            .await;
        // A one-year window with a single old sample: the 30s tier holds that one
        // bucket (nothing evicted), so its *actual* in-range count fits max_points
        // and it still covers `from`. It must be kept at the finest resolution so
        // the old point stays visible, not downgraded to a coarser tier that never
        // recorded it.
        let resp = store
            .range("surface:sparse", now - 365 * 86_400, now, 500, None)
            .await;
        assert_eq!(resp.resolution, "30s");
        assert_eq!(resp.points.len(), 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_honours_forced_tier_over_window_auto_pick() {
        let dir = std::env::temp_dir().join(format!("tlm-forced-{}", uuid::Uuid::new_v4()));
        let store = TelemetryStore::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(&[("surface:forced".to_string(), 0.5, 5)], at(now))
            .await;

        // A 1-year window would auto-pick a coarse tier, but an explicit "1h"
        // override must be served verbatim regardless of the window width.
        let resp = store
            .range("surface:forced", now - 365 * 86_400, now, 500, Some("1h"))
            .await;
        assert_eq!(resp.resolution, "1h");
        assert_eq!(resp.step_secs, 3_600);
        assert_eq!(resp.points.len(), 1);

        // An unknown label falls back to the auto-selected tier.
        let auto = store
            .range("surface:forced", now - 60, now + 60, 500, Some("nonsense"))
            .await;
        assert_eq!(auto.resolution, "30s");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_series_removes_memory_and_disk() {
        let dir = std::env::temp_dir().join(format!("tlm-del-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let store = TelemetryStore::new(&dir).await;
        store
            .record_many(&[("member:gone".to_string(), 2.0, 20)], at(now))
            .await;
        store.flush().await;
        store
            .delete_series_matching(&KeyMatch::Exact("member:gone".to_string()))
            .await;
        // Gone from memory.
        let resp = store
            .range("member:gone", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.points.len(), 0);
        // Gone from disk too: a fresh load doesn't resurrect it.
        let reloaded = TelemetryStore::new(&dir).await;
        let resp2 = reloaded
            .range("member:gone", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp2.points.len(), 0);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_series_matching_drops_prefix_and_keeps_others() {
        let dir = std::env::temp_dir().join(format!("tlm-match-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let store = TelemetryStore::new(&dir).await;
        store
            .record_many(
                &[
                    ("member:m1".to_string(), 1.0, 10),
                    ("member:m1:surface:p1".to_string(), 1.0, 10),
                    ("member:m10".to_string(), 9.0, 90), // must NOT match `member:m1`
                    ("team:t1".to_string(), 2.0, 20),
                ],
                at(now),
            )
            .await;
        let exact = "member:m1".to_string();
        let prefix = format!("{exact}:");
        store
            .delete_series_matching(&KeyMatch::Any(vec![KeyMatch::Exact(exact), KeyMatch::Prefix(prefix)]))
            .await;
        // Member grand total and its per-surface series are gone.
        assert_eq!(
            store
                .range("member:m1", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        assert_eq!(
            store
                .range("member:m1:surface:p1", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        // A different member whose id merely shares a prefix is untouched.
        assert_eq!(
            store
                .range("member:m10", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            1
        );
        // Unrelated series survive.
        assert_eq!(
            store
                .range("team:t1", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            1
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
