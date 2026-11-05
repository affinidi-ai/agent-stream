//! Embedded, snapshot-backed multi-resolution RRD store — the default
//! [`super::TimeSeriesBackend`] adapter for a single appliance.
//!
//! Every series is held as one [`BTreeMap`] per [`Tier`], keyed by bucket start.
//! A write fans out to every tier (folding the sample via [`RrdSample::merge`]),
//! so coarse buckets are always the exact merge of the finer ones. Per-tier
//! retention evicts the oldest bucket once the cap is hit. The structure is
//! periodically snapshotted to one JSON file per tier so history survives a
//! restart. This is generic over the sample type so usage telemetry and
//! operational metrics share one engine; an external TSDB implements the same
//! [`super::TimeSeriesBackend`] trait instead of using this store.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use tracing::warn;

use super::tiers::{TIERS, Tier};
use super::{KeyMatch, RrdPoint, RrdRange, RrdSample, TimeSeriesBackend};
use tokio::sync::RwLock;

/// Minimum seconds between background snapshots of the finest tier.
const SNAPSHOT_THROTTLE_SECS: i64 = 10;
/// Upper bound on a tier's snapshot cadence. Coarse tiers (12h/24h/1y) span
/// days, so persisting them more often than this just rewrites slow-moving
/// files; a crash loses at most one cadence of in-flight accumulation.
const SNAPSHOT_INTERVAL_CAP_SECS: i64 = 3_600;

/// How often a tier is persisted: its own bucket width, floored at the global
/// throttle and capped at [`SNAPSHOT_INTERVAL_CAP_SECS`]. Fine tiers snapshot
/// every few seconds; coarse tiers at most hourly — avoiding per-request
/// rewrites of the slow-moving files.
fn snapshot_interval(tier: &Tier) -> i64 {
    tier.step_secs
        .clamp(SNAPSHOT_THROTTLE_SECS, SNAPSHOT_INTERVAL_CAP_SECS)
}

/// Drop snapshot rows that can't be real before they enter the store: future-
/// dated buckets (which sort last and would resist eviction) and any excess
/// beyond the tier's retention cap (keeping the newest). `_storage/` is
/// operator-controlled but otherwise unvalidated input, so a corrupted or
/// hand-edited file can't poison the in-memory store on reload.
fn sanitize_loaded_buckets<S>(
    buckets: &mut BTreeMap<i64, S>,
    tier: &Tier,
    now: i64,
) {
    buckets.retain(|&bucket, _| bucket <= now);
    while buckets.len() > tier.retain {
        let Some(&oldest) = buckets.keys().next() else {
            break;
        };
        buckets.remove(&oldest);
    }
}

/// One `BTreeMap` per tier (same order as [`TIERS`]).
type SeriesTiers<S> = Vec<BTreeMap<i64, S>>;
/// On-disk shape of a single tier file: series key → its buckets.
type TierMap<S> = HashMap<String, BTreeMap<i64, S>>;

fn empty_tiers<S>() -> SeriesTiers<S> {
    TIERS
        .iter()
        .map(|_| BTreeMap::new())
        .collect()
}

/// A prepared snapshot write for one tier: replace the file with fresh bytes, or
/// remove it because the tier is now empty.
enum TierWrite {
    Write(Vec<u8>),
    Remove,
}

/// Serialise each requested tier straight from borrowed live data into bytes,
/// avoiding a deep clone of every series' buckets. Runs under the caller's read
/// lock. A tier with no non-empty series yields [`TierWrite::Remove`]; a tier
/// that fails to serialise is dropped from the result (its file is left as-is).
fn serialize_tiers<S: RrdSample>(
    inner: &HashMap<String, SeriesTiers<S>>,
    tier_indices: &[usize],
) -> Vec<(usize, TierWrite)> {
    tier_indices
        .iter()
        .filter_map(|&idx| {
            // Borrow each series' buckets for this tier — no per-bucket clone.
            // BTreeMap keys order the output deterministically; the JSON shape
            // matches the owned `TierMap<S>` read back by `load_from_disk`.
            let view: BTreeMap<&str, &BTreeMap<i64, S>> = inner
                .iter()
                .filter(|(_, tiers)| !tiers[idx].is_empty())
                .map(|(key, tiers)| (key.as_str(), &tiers[idx]))
                .collect();
            if view.is_empty() {
                return Some((idx, TierWrite::Remove));
            }
            match serde_json::to_vec(&view) {
                Ok(bytes) => Some((idx, TierWrite::Write(bytes))),
                Err(e) => {
                    warn!("Failed to serialise time-series snapshot {}: {e}", TIERS[idx].label);
                    None
                }
            }
        })
        .collect()
}

/// Resolve a window query against one series' tiers without touching the store
/// lock. Shared by [`RrdStore::range`] and [`RrdStore::range_many`] so the
/// single-key and batched paths pick the same tier and emit identical points.
fn compute_range<S: RrdSample>(
    series: Option<&SeriesTiers<S>>,
    key: &str,
    from: i64,
    to: i64,
    max_points: usize,
    force_tier: Option<&str>,
) -> RrdRange<S> {
    let span = to.saturating_sub(from).max(0);
    let forced = force_tier.and_then(|label| {
        TIERS
            .iter()
            .position(|t| t.label == label)
    });
    let chosen = forced.unwrap_or_else(|| {
        // "Below retention cap" is not the same as "covers the query window".
        // Every record fans to every tier, so under steady state all tiers
        // hold the same events at different resolutions — but if a fine tier
        // was truncated (partial persistence across a restart, snapshot
        // cadence mismatch, or a burst that evicted more than a coarser tier),
        // its oldest retained bucket can be well *after* `from` while a
        // coarser tier still has the earlier history. The picker must reason
        // from the tier's oldest retained bucket, not its fill level, to
        // choose the finest tier that actually covers the window.
        //
        // With no series recorded yet, no tier holds anything, so fall back to
        // whatever fits `max_points` at the theoretical bucket count for the
        // window.
        match series {
            Some(tiers) => {
                let covers = |idx: usize| -> bool {
                    match tiers[idx].keys().next() {
                        Some(&oldest) => oldest <= from,
                        None => false,
                    }
                };
                let count = |idx: usize| {
                    tiers[idx]
                        .range(from..=to)
                        .count()
                };
                let fits = |idx: usize| count(idx) <= max_points;
                let best_covering = (0..TIERS.len()).find(|&idx| covers(idx) && fits(idx));
                let best_with_data = (0..TIERS.len()).find(|&idx| fits(idx) && count(idx) > 0);

                match (best_covering, best_with_data) {
                    (Some(cover_idx), Some(data_idx)) if data_idx < cover_idx => {
                        let oldest = tiers[data_idx]
                            .keys()
                            .next()
                            .copied()
                            .unwrap_or(from);
                        let coverage_gap = oldest.saturating_sub(from);
                        let small_gap = TIERS[data_idx]
                            .step_secs
                            .saturating_mul(2);
                        if coverage_gap <= small_gap {
                            data_idx
                        } else {
                            cover_idx
                        }
                    }
                    (Some(cover_idx), _) => cover_idx,
                    (None, Some(data_idx)) => data_idx,
                    (None, None) => TIERS.len() - 1,
                }
            }
            None => (0..TIERS.len())
                .find(|&idx| (span / TIERS[idx].step_secs) as usize <= max_points)
                .unwrap_or(TIERS.len() - 1),
        }
    });
    // The auto-picked tier can be empty for this window even though a finer
    // tier still holds the data — e.g. a coarse rollup lost its most recent,
    // not-yet-snapshotted buckets across a restart (coarse tiers snapshot at
    // most hourly), or its bucket boundary falls outside a narrow window.
    // Recent activity must stay visible at every zoom level, so when the
    // chosen tier has nothing in range, drop to the finest tier that does.
    let chosen = match series {
        Some(tiers)
            if forced.is_none()
                && tiers[chosen]
                    .range(from..=to)
                    .next()
                    .is_none() =>
        {
            (0..TIERS.len())
                .find(|&idx| {
                    tiers[idx]
                        .range(from..=to)
                        .next()
                        .is_some()
                })
                .unwrap_or(chosen)
        }
        _ => chosen,
    };
    let tier = &TIERS[chosen];
    let mut points = Vec::new();
    if let Some(tiers) = series {
        for (&t, s) in tiers[chosen].range(from..=to) {
            points.push(RrdPoint { t, value: s.clone() });
        }
    }
    RrdRange {
        key: key.to_string(),
        resolution: tier.label.to_string(),
        step_secs: tier.step_secs,
        points,
    }
}

/// Embedded RRD store generic over its per-bucket sample type.
pub struct RrdStore<S: RrdSample> {
    inner: Arc<RwLock<HashMap<String, SeriesTiers<S>>>>,
    storage_dir: PathBuf,
    /// Per-tier timestamp of the last snapshot write (same order as [`TIERS`]).
    last_snapshot: Vec<AtomicI64>,
    /// Per-tier dirty flag: set when a record touches the tier, cleared when the
    /// tier is snapshotted. A tier whose buckets haven't changed since its last
    /// snapshot is skipped, so idle/low-traffic series never rewrite their files.
    dirty: Vec<std::sync::atomic::AtomicBool>,
}

impl<S: RrdSample> RrdStore<S> {
    /// Build a store, loading any per-tier snapshot files found in `storage_dir`.
    pub async fn new(storage_dir: impl Into<PathBuf>) -> Self {
        Self::build(storage_dir).await
    }

    async fn build(storage_dir: impl Into<PathBuf>) -> Self {
        let storage_dir = storage_dir.into();
        let now = Utc::now().timestamp();
        let inner = Self::load_from_disk(&storage_dir)
            .await
            .unwrap_or_else(|e| {
                warn!("Starting with empty time series, cannot read {}: {e}", storage_dir.display());
                HashMap::new()
            });
        let _ = tokio::fs::create_dir_all(&storage_dir).await;
        Self {
            inner: Arc::new(RwLock::new(inner)),
            storage_dir,
            // Back-date each tier's clock by one cadence cap so the first event
            // after boot persists every tier file at once; otherwise coarse tiers
            // first snapshot 30m–1h in and never survive a short-lived process.
            last_snapshot: TIERS
                .iter()
                .map(|_| AtomicI64::new(now - SNAPSHOT_INTERVAL_CAP_SECS))
                .collect(),
            dirty: TIERS
                .iter()
                .map(|_| std::sync::atomic::AtomicBool::new(false))
                .collect(),
        }
    }

    /// Read every per-tier snapshot file from `storage_dir` into a fresh map,
    /// sanitising each tier's buckets. A missing or unparseable tier file loads
    /// as empty; any other read error is returned.
    async fn load_from_disk(storage_dir: &Path) -> std::io::Result<HashMap<String, SeriesTiers<S>>> {
        let mut inner: HashMap<String, SeriesTiers<S>> = HashMap::new();
        let now = Utc::now().timestamp();
        for (idx, tier) in TIERS.iter().enumerate() {
            let path = storage_dir.join(format!("{}.json", tier.label));
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(std::io::Error::new(e.kind(), format!("{}: {e}", path.display()))),
            };
            let map = match serde_json::from_slice::<TierMap<S>>(&bytes) {
                Ok(map) => map,
                Err(e) => {
                    warn!("Ignoring unparseable time series tier {}: {e}", path.display());
                    continue;
                }
            };
            for (series, mut buckets) in map {
                sanitize_loaded_buckets(&mut buckets, tier, now);
                if buckets.is_empty() {
                    continue;
                }
                inner
                    .entry(series)
                    .or_insert_with(empty_tiers)[idx] = buckets;
            }
        }
        Ok(inner)
    }

    fn maybe_snapshot(
        &self,
        now: i64,
    ) {
        let mut due = Vec::new();
        for (idx, tier) in TIERS.iter().enumerate() {
            let last = self.last_snapshot[idx].load(Ordering::Relaxed);
            if now - last >= snapshot_interval(tier) {
                self.last_snapshot[idx].store(now, Ordering::Relaxed);
                // Only rewrite a tier that actually changed since its last
                // snapshot; an idle tier keeps its existing file untouched.
                if self.dirty[idx].swap(false, Ordering::Relaxed) {
                    due.push(idx);
                }
            }
        }
        if due.is_empty() {
            return;
        }
        let inner = self.inner.clone();
        let dir = self.storage_dir.clone();
        tokio::spawn(async move {
            // Serialise only the due tiers, and do it straight from borrowed live
            // data — no deep clone of every series' buckets. The finest tier
            // persists every ~30s while the eight coarser tiers are due far less
            // often, so the common snapshot serialises one tier's borrowed
            // buckets instead of cloning all ten.
            let writes = {
                let guard = inner.read().await;
                serialize_tiers(&guard, &due)
            };
            Self::write_tier_bytes(&dir, writes).await;
        });
    }

    /// Persist prebuilt tier snapshots, one atomic file per tier. An emptied
    /// tier has its file removed so a reload can't resurrect GC'd data; a tier
    /// that failed to serialise is left untouched (skipped, never removed).
    async fn write_tier_bytes(
        dir: &Path,
        writes: Vec<(usize, TierWrite)>,
    ) {
        if tokio::fs::create_dir_all(dir)
            .await
            .is_err()
        {
            return;
        }
        for (idx, write) in writes {
            let tier = &TIERS[idx];
            let path = dir.join(format!("{}.json", tier.label));
            match write {
                TierWrite::Remove => {
                    let _ = tokio::fs::remove_file(&path).await;
                }
                TierWrite::Write(bytes) => {
                    let tmp = dir.join(format!("{}.json.tmp", tier.label));
                    if let Err(e) = tokio::fs::write(&tmp, &bytes).await {
                        warn!("Failed to write time-series snapshot {}: {e}", tier.label);
                        continue;
                    }
                    if let Err(e) = tokio::fs::rename(&tmp, &path).await {
                        warn!("Failed to commit time-series snapshot {}: {e}", tier.label);
                    }
                }
            }
        }
    }
}

#[async_trait]
impl<S: RrdSample> TimeSeriesBackend<S> for RrdStore<S> {
    async fn record_many(
        &self,
        samples: Vec<(String, S)>,
        ts: DateTime<Utc>,
    ) {
        if samples.is_empty() {
            return;
        }
        let epoch = ts.timestamp();
        {
            let mut inner = self.inner.write().await;
            for (key, sample) in &samples {
                let tiers = inner
                    .entry(key.clone())
                    .or_insert_with(empty_tiers);
                for (idx, tier) in TIERS.iter().enumerate() {
                    let bucket = epoch - epoch.rem_euclid(tier.step_secs);
                    let entry = tiers[idx]
                        .entry(bucket)
                        .or_default();
                    entry.merge(sample);
                    while tiers[idx].len() > tier.retain {
                        let Some(&oldest) = tiers[idx].keys().next() else {
                            break;
                        };
                        if oldest == bucket {
                            break; // never evict the bucket we just wrote
                        }
                        tiers[idx].remove(&oldest);
                    }
                }
            }
        }
        // A record touches every tier, so every tier now has unsnapshotted
        // changes. The next due snapshot consults these flags and skips any
        // tier that hasn't changed since it was last written.
        for d in &self.dirty {
            d.store(true, Ordering::Relaxed);
        }
        self.maybe_snapshot(epoch);
    }

    async fn range(
        &self,
        key: &str,
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> RrdRange<S> {
        let inner = self.inner.read().await;
        compute_range(inner.get(key), key, from, to, max_points, force_tier)
    }

    async fn range_many(
        &self,
        keys: &[String],
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> Vec<RrdRange<S>> {
        // Take the read lock once for the whole batch rather than once per key:
        // the dashboard fetches up to a few hundred member/team series at a time.
        let inner = self.inner.read().await;
        keys.iter()
            .map(|key| compute_range(inner.get(key.as_str()), key, from, to, max_points, force_tier))
            .collect()
    }

    async fn delete_series_matching(
        &self,
        spec: &KeyMatch,
    ) {
        let matched: Vec<String> = {
            let inner = self.inner.read().await;
            inner
                .keys()
                .filter(|k| spec.matches(k))
                .cloned()
                .collect()
        };
        if matched.is_empty() {
            return;
        }
        {
            let mut inner = self.inner.write().await;
            for key in &matched {
                inner.remove(key);
            }
        }
        self.flush().await;
    }

    async fn flush(&self) {
        let all: Vec<usize> = (0..TIERS.len()).collect();
        let writes = {
            let guard = self.inner.read().await;
            serialize_tiers(&guard, &all)
        };
        Self::write_tier_bytes(&self.storage_dir, writes).await;
        let now = Utc::now().timestamp();
        for slot in &self.last_snapshot {
            slot.store(now, Ordering::Relaxed);
        }
        // The forced flush just persisted every tier, so nothing is pending.
        for d in &self.dirty {
            d.store(false, Ordering::Relaxed);
        }
    }

    async fn reload(&self) -> std::io::Result<()> {
        let mut inner = self.inner.write().await;
        *inner = Self::load_from_disk(&self.storage_dir).await?;
        for d in &self.dirty {
            d.store(false, Ordering::Relaxed);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use serde::{Deserialize, Serialize};

    /// Minimal additive sample used to exercise the generic engine.
    #[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
    struct Counter {
        n: u64,
        peak: u64,
    }

    impl RrdSample for Counter {
        fn merge(
            &mut self,
            other: &Self,
        ) {
            self.n += other.n;
            self.peak = self.peak.max(other.peak);
        }
    }

    fn at(epoch: i64) -> DateTime<Utc> {
        Utc.timestamp_opt(epoch, 0)
            .unwrap()
    }

    fn tier_index(label: &str) -> usize {
        TIERS
            .iter()
            .position(|t| t.label == label)
            .unwrap()
    }

    #[tokio::test]
    async fn record_and_range_single_bucket() {
        let dir = std::env::temp_dir().join(format!("rrd-single-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(vec![("ops:all".to_string(), Counter { n: 5, peak: 5 })], at(now))
            .await;

        let resp = store
            .range("ops:all", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.resolution, "30s");
        assert_eq!(resp.points.len(), 1);
        assert_eq!(resp.points[0].value, Counter { n: 5, peak: 5 });
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_keeps_fine_tier_when_data_is_sparse() {
        let dir = std::env::temp_dir().join(format!("rrd-sparse-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(vec![("ops:all".to_string(), Counter { n: 1, peak: 1 })], at(now))
            .await;
        // A one-year window with a single old sample: the 30s tier holds that one
        // bucket (nothing evicted), so its *actual* in-range count fits max_points
        // and it still covers `from`. It must be kept at the finest resolution so
        // the old point stays visible, not downgraded to a coarser tier that never
        // recorded it.
        let resp = store
            .range("ops:all", now - 365 * 86_400, now, 500, None)
            .await;
        assert_eq!(resp.resolution, "30s");
        assert_eq!(resp.points.len(), 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn merge_is_additive_with_peak() {
        let dir = std::env::temp_dir().join(format!("rrd-merge-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let base = Utc::now().timestamp();
        store
            .record_many(vec![("ops:all".to_string(), Counter { n: 1, peak: 1 })], at(base))
            .await;
        store
            .record_many(vec![("ops:all".to_string(), Counter { n: 2, peak: 9 })], at(base + 1))
            .await;
        store
            .record_many(vec![("ops:all".to_string(), Counter { n: 3, peak: 4 })], at(base + 2))
            .await;

        // All three land in the same coarse bucket: counts sum, peak is the max.
        let hour = tier_index("1h");
        let resp = store
            .range("ops:all", base - 3_600, base + 3_600, 10, Some(TIERS[hour].label))
            .await;
        assert_eq!(resp.resolution, "1h");
        let total: u64 = resp
            .points
            .iter()
            .map(|p| p.value.n)
            .sum();
        let peak: u64 = resp
            .points
            .iter()
            .map(|p| p.value.peak)
            .max()
            .unwrap();
        assert_eq!(total, 6);
        assert_eq!(peak, 9);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn retention_evicts_oldest_keeps_newest() {
        let dir = std::env::temp_dir().join(format!("rrd-retain-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let finest = &TIERS[0];
        let step = finest.step_secs;
        let base = (Utc::now().timestamp() / step) * step;
        // Write one bucket per step, exceeding the finest tier's retention.
        let total = finest.retain + 5;
        for i in 0..total {
            store
                .record_many(vec![("ops:all".to_string(), Counter { n: 1, peak: 1 })], at(base + (i as i64) * step))
                .await;
        }
        let from = base;
        let to = base + (total as i64) * step;
        let resp = store
            .range("ops:all", from, to, 100_000, Some(finest.label))
            .await;
        assert_eq!(resp.points.len(), finest.retain);
        // The newest bucket survived; the oldest was evicted.
        let newest = base + ((total - 1) as i64) * step;
        let oldest_kept = base + (5_i64) * step;
        assert_eq!(resp.points.last().unwrap().t, newest);
        assert_eq!(resp.points.first().unwrap().t, oldest_kept);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_series_removes_data() {
        let dir = std::env::temp_dir().join(format!("rrd-del-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record_many(vec![("ops:a".to_string(), Counter { n: 1, peak: 1 })], at(now))
            .await;
        store
            .record_many(vec![("ops:b".to_string(), Counter { n: 1, peak: 1 })], at(now))
            .await;
        store
            .delete_series_matching(&KeyMatch::Exact("ops:a".to_string()))
            .await;

        let a = store
            .range("ops:a", now - 60, now + 60, 500, None)
            .await;
        let b = store
            .range("ops:b", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(a.points.len(), 0);
        assert_eq!(b.points.len(), 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn delete_series_matching_prefix() {
        let dir = std::env::temp_dir().join(format!("rrd-delmatch-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        for key in ["surface:p1", "surface:p1:stage:llm", "surface:p10"] {
            store
                .record_many(vec![(key.to_string(), Counter { n: 1, peak: 1 })], at(now))
                .await;
        }
        // Anchored match must not catch surface:p10.
        store
            .delete_series_matching(&KeyMatch::Any(vec![
                KeyMatch::Exact("surface:p1".to_string()),
                KeyMatch::Prefix("surface:p1:".to_string()),
            ]))
            .await;

        assert_eq!(
            store
                .range("surface:p1", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        assert_eq!(
            store
                .range("surface:p1:stage:llm", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        assert_eq!(
            store
                .range("surface:p10", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            1
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_prefers_finer_tier_when_coverage_gap_is_small() {
        let dir = std::env::temp_dir().join(format!("rrd-small-gap-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        let fine_idx = tier_index("30s");
        let coarse_idx = tier_index("5m");
        let fine = &TIERS[fine_idx];
        let coarse = &TIERS[coarse_idx];

        let newest_fine = now - now.rem_euclid(fine.step_secs);
        let oldest_fine = newest_fine - fine.step_secs;
        let from = oldest_fine - fine.step_secs * 2;

        {
            let mut inner = store.inner.write().await;
            let series = inner
                .entry("ops:all".to_string())
                .or_insert_with(empty_tiers);

            series[fine_idx].insert(oldest_fine, Counter { n: 1, peak: 1 });
            series[fine_idx].insert(newest_fine, Counter { n: 1, peak: 1 });

            let coarse_bucket = now - now.rem_euclid(coarse.step_secs);
            series[coarse_idx].insert(coarse_bucket, Counter { n: 2, peak: 1 });
        }

        let resp = store
            .range("ops:all", from, now, 300, None)
            .await;
        assert_eq!(resp.resolution, "30s");
        assert_eq!(resp.points.len(), 2);

        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn range_prefers_coarser_tier_when_finer_lost_data() {
        // Regression: a tier picker must route to whichever tier actually
        // covers the query window, not the finest tier that fits max_points.
        // After a restart (or any partial-persistence event), a finer tier
        // can hold fewer buckets than a coarser one, with its oldest bucket
        // *newer* than the query's `from`. The picker must check whether a
        // tier's oldest retained bucket reaches back to `from` before routing
        // there, not just whether it's below its retention cap.
        let dir = std::env::temp_dir().join(format!("rrd-covers-{}", uuid::Uuid::new_v4()));
        let store = RrdStore::<Counter>::new(&dir).await;
        let now = Utc::now().timestamp();
        let fine_idx = tier_index("30s");
        let coarse_idx = tier_index("5m");
        let fine = &TIERS[fine_idx];
        let coarse = &TIERS[coarse_idx];
        {
            let mut inner = store.inner.write().await;
            let series = inner
                .entry("ops:all".to_string())
                .or_insert_with(empty_tiers);
            // 30s tier: 100 buckets in the *most recent* 50 minutes
            // (now - 3000s to now). Below its 240 cap, but oldest bucket is
            // well *after* the query window's start (7h back).
            for i in 0..100i64 {
                let t = (now - i * fine.step_secs) / fine.step_secs * fine.step_secs;
                if t >= now - 3000 {
                    series[fine_idx].insert(t, Counter { n: 1, peak: 1 });
                }
            }
            // 5m tier: 86 buckets spanning the last ~24h (below its 288 cap).
            // The oldest bucket is ~24h back, reaching well *before* the query
            // window's start. This tier holds the real history.
            for i in 0..86i64 {
                let t = (now - i * coarse.step_secs) / coarse.step_secs * coarse.step_secs;
                series[coarse_idx].insert(t, Counter { n: 1, peak: 1 });
            }
        }
        // Query the last 7 hours. The 30s tier's oldest bucket is at ~now - 3000s
        // (50min), which is > from (now - 25200s), so it does NOT cover. The 5m
        // tier's oldest is ~24h back, which is < from, so it DOES cover.
        // Picker must choose 5m, not 30s.
        let from = now - 7 * 3600;
        let resp = store
            .range("ops:all", from, now, 300, None)
            .await;
        assert_eq!(resp.resolution, "5m");
        assert!(resp.points.len() > 10, "expected many 5m buckets covering 7h, got {}", resp.points.len());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn snapshot_survives_reload() {
        let dir = std::env::temp_dir().join(format!("rrd-reload-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        {
            let store = RrdStore::<Counter>::new(&dir).await;
            store
                .record_many(vec![("ops:all".to_string(), Counter { n: 7, peak: 3 })], at(now))
                .await;
            store.flush().await;
        }
        let reloaded = RrdStore::<Counter>::new(&dir).await;
        let resp = reloaded
            .range("ops:all", now - 60, now + 60, 500, None)
            .await;
        assert_eq!(resp.points.len(), 1);
        assert_eq!(resp.points[0].value, Counter { n: 7, peak: 3 });
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_from_unreadable_storage_fails_and_keeps_series() {
        let dir = std::env::temp_dir().join(format!("rrd-unreadable-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let store = RrdStore::<Counter>::new(&dir).await;
        store
            .record_many(vec![("surface:a".to_string(), Counter { n: 2, peak: 0 })], at(now))
            .await;
        store.flush().await;
        let tier_file = dir.join(format!("{}.json", TIERS[0].label));
        tokio::fs::remove_file(&tier_file)
            .await
            .unwrap();
        tokio::fs::create_dir(&tier_file)
            .await
            .unwrap();

        assert!(store.reload().await.is_err(), "a read error is not read as an empty tier");

        let resp = store
            .range("surface:a", now - 600, now + 60, 500, None)
            .await;
        assert_eq!(resp.points.len(), 1);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_skips_an_unparseable_tier() {
        let dir = std::env::temp_dir().join(format!("rrd-unparseable-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let store = RrdStore::<Counter>::new(&dir).await;
        store
            .record_many(vec![("surface:a".to_string(), Counter { n: 2, peak: 0 })], at(now))
            .await;
        store.flush().await;
        for tier in TIERS {
            tokio::fs::write(dir.join(format!("{}.json", tier.label)), "not json")
                .await
                .unwrap();
        }

        store.reload().await.unwrap();

        let resp = store
            .range("surface:a", now - 600, now + 60, 500, None)
            .await;
        assert!(resp.points.is_empty());
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_keeps_series_another_instance_persisted() {
        let dir = std::env::temp_dir().join(format!("rrd-promote-{}", uuid::Uuid::new_v4()));
        let now = Utc::now().timestamp();
        let standby = RrdStore::<Counter>::new(&dir).await;
        {
            let active = RrdStore::<Counter>::new(&dir).await;
            active
                .record_many(vec![("surface:a".to_string(), Counter { n: 5, peak: 0 })], at(now - 120))
                .await;
            active.flush().await;
        }

        standby
            .reload()
            .await
            .unwrap();
        standby
            .record_many(vec![("surface:b".to_string(), Counter { n: 1, peak: 0 })], at(now))
            .await;
        standby.flush().await;

        let restarted = RrdStore::<Counter>::new(&dir).await;
        for key in ["surface:a", "surface:b"] {
            let resp = restarted
                .range(key, now - 600, now + 60, 500, None)
                .await;
            assert_eq!(resp.points.len(), 1, "{key} survives");
        }
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
