//! Backend-neutral time-series **port** plus the embedded RRD adapter.
//!
//! This module is the seam that lets a single appliance use the in-process,
//! snapshot-backed RRD store while a scaled / HA deployment swaps in an external
//! time-series database **without touching a single call site**. Every dataset
//! that needs history — usage telemetry (cost / tokens) and operational metrics
//! (connections, throughput, latency) — records and queries through
//! [`TimeSeriesBackend`]. The default [`engine::RrdStore`] is the embedded
//! implementation; an external adapter (VictoriaMetrics, InfluxDB, Timescale,
//! Prometheus remote-write/read, …) implements the same trait and is selected
//! by configuration at boot.
//!
//! Push vs pull: a repository/push backend (VictoriaMetrics / Influx / Timescale
//! / Prometheus remote-write) maps `record_many` → write and `range` → read. A
//! classic pull-Prometheus adapter maps `range` → remote-read / PromQL and makes
//! `record_many` a no-op, exposing a `/metrics` endpoint scraped out of band.

pub mod engine;
pub mod tiers;

use async_trait::async_trait;
use chrono::{DateTime, Utc};

pub use engine::RrdStore;

/// A per-bucket accumulator. The RRD rollups need exactly one operation from a
/// sample: additive merge of a finer/equal bucket into a coarser one. Domain
/// types (usage cost/tokens, operational counters + latency histogram) decide
/// how their fields combine — sum counters, merge histograms, track min/max —
/// so the engine stays entirely domain-agnostic.
pub trait RrdSample: Default + Clone + serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static {
    /// Fold `other` into `self`. Must be associative and commutative so a coarse
    /// bucket equals the merge of the finer buckets it spans regardless of order.
    fn merge(
        &mut self,
        other: &Self,
    );
}

/// One point of a range result: bucket start (unix seconds) + the bucket value.
#[derive(Debug, Clone, PartialEq)]
pub struct RrdPoint<S> {
    pub t: i64,
    pub value: S,
}

/// A single series' range-query result: which tier served it plus the points.
#[derive(Debug, Clone, PartialEq)]
pub struct RrdRange<S> {
    pub key: String,
    pub resolution: String,
    pub step_secs: i64,
    pub points: Vec<RrdPoint<S>>,
}

/// A declarative series-key matcher for bulk GC. Owned (no closures, no
/// lifetimes) so the same spec a single appliance evaluates in-process can be
/// translated by an external adapter into a label/regex delete query. Covers
/// the exact/prefix/anchored patterns the soft-delete GC needs (a surface drops
/// its grand-total and every per-surface child via `Any([Exact, Prefix])`).
#[derive(Debug, Clone, PartialEq)]
pub enum KeyMatch {
    /// Matches a key equal to this string.
    Exact(String),
    /// Matches a key starting with this string.
    Prefix(String),
    /// Matches a key ending with this string (anchored suffix GC, e.g. a
    /// surface dropping every `member:*:surface:{id}` breakdown series).
    Suffix(String),
    /// Matches if any inner matcher matches (logical OR).
    Any(Vec<KeyMatch>),
}

impl KeyMatch {
    /// Whether `key` satisfies this matcher.
    pub fn matches(
        &self,
        key: &str,
    ) -> bool {
        match self {
            KeyMatch::Exact(s) => key == s,
            KeyMatch::Prefix(p) => key.starts_with(p.as_str()),
            KeyMatch::Suffix(s) => key.ends_with(s.as_str()),
            KeyMatch::Any(parts) => parts
                .iter()
                .any(|p| p.matches(key)),
        }
    }
}

/// Backend-neutral time-series store. Implemented by the embedded
/// [`RrdStore`] today; an external TSDB adapter implements the same contract.
///
/// Methods are async so a network-backed adapter drops in without changing any
/// call site — the embedded adapter simply resolves immediately over its
/// in-memory `RwLock`. Recording seams already run fire-and-forget, so the
/// `.await` never sits on a request's hot path.
#[async_trait]
pub trait TimeSeriesBackend<S: RrdSample>: Send + Sync {
    /// Record a batch of `(series_key, sample)` events at instant `ts`. Each
    /// sample is the delta for one event; the backend folds it into every
    /// resolution covering `ts`.
    async fn record_many(
        &self,
        samples: Vec<(String, S)>,
        ts: DateTime<Utc>,
    );

    /// Return the series' points over `[from, to]` (unix seconds). `force_tier`
    /// names an exact resolution label; `None` lets the backend pick the finest
    /// tier that fits `max_points` and actually covers `from`.
    async fn range(
        &self,
        key: &str,
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> RrdRange<S>;

    /// Return ranges for many keys at once. The embedded adapter overrides this
    /// to take its read lock **once** for the whole batch instead of once per
    /// key (the dashboard fetches up to a few hundred member/team series per
    /// request). The default fans out to [`range`](Self::range) so a network
    /// adapter that has no cheaper batch path still works unchanged.
    async fn range_many(
        &self,
        keys: &[String],
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> Vec<RrdRange<S>> {
        let mut out = Vec::with_capacity(keys.len());
        for key in keys {
            out.push(
                self.range(key, from, to, max_points, force_tier)
                    .await,
            );
        }
        out
    }

    /// Remove every series whose key satisfies `spec` (exact/prefix/anchored GC).
    async fn delete_series_matching(
        &self,
        spec: &KeyMatch,
    );

    /// Synchronously persist all pending state (graceful shutdown, post-delete).
    async fn flush(&self);

    /// Replace in-memory state with what is persisted now, so an instance
    /// promoted to Active continues the series the previous Active wrote. A
    /// storage error leaves the in-memory state unchanged. A backend whose
    /// state is not held in this process has nothing to reload.
    async fn reload(&self) -> std::io::Result<()> {
        Ok(())
    }
}
