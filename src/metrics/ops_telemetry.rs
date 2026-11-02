//! Operational metrics time-series — persistent, multi-resolution history for
//! the dashboard's connection / throughput / token / latency charts.
//!
//! This is the operational counterpart to [`crate::telemetry`] (usage cost /
//! tokens). Both ride the backend-neutral [`crate::timeseries`] port, so a
//! single appliance keeps history in the embedded RRD store while a scaled / HA
//! deployment swaps in an external time-series database by constructing
//! [`OpsMetricsStore`] over a different [`TimeSeriesBackend`] — no call site
//! changes. The recording seam lives in [`crate::metrics::store::MetricsStore`]
//! (connection / pipe / rule events); reads are served by a windowed dashboard
//! endpoint.

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use serde::{Deserialize, Serialize};

use crate::metrics::types::{ConnectionDirection, ConnectionMetric, ConnectionStatus, MetricType};
use crate::timeseries::{KeyMatch, RrdSample, RrdStore, TimeSeriesBackend};

/// Histogram bucket upper bounds in milliseconds. A latency observation lands in
/// the first bucket whose bound is `>=` the value; values above the last bound
/// fall in a trailing overflow bucket. Buckets are additive, so percentiles can
/// be approximated from a merged (rolled-up) histogram even though percentiles
/// themselves are not additive.
pub const LATENCY_BUCKET_BOUNDS_MS: &[u64] =
    &[1, 2, 5, 10, 25, 50, 100, 250, 500, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000];

/// The histogram bucket index a latency value falls into.
fn latency_bucket_index(ms: u64) -> usize {
    for (i, &bound) in LATENCY_BUCKET_BOUNDS_MS
        .iter()
        .enumerate()
    {
        if ms <= bound {
            return i;
        }
    }
    LATENCY_BUCKET_BOUNDS_MS.len()
}

/// Additive per-bucket operational counters plus a latency histogram. Every
/// field merges additively (min/max excepted) so a coarse RRD bucket equals the
/// merge of the finer buckets it spans.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct OpsSample {
    /// Completed round-trips (counted once per request, never on the response leg).
    pub connections: u64,
    /// Round-trips that ended in a non-gateway failure.
    pub failed: u64,
    /// Round-trips rejected by the gateway.
    pub gateway_faults: u64,
    /// Rule-validation accepts in this bucket.
    pub rule_accepts: u64,
    /// Rule-validation denies in this bucket.
    pub rule_denies: u64,
    /// Request-direction bytes transferred.
    pub request_bytes: u64,
    /// Response-direction bytes transferred.
    pub response_bytes: u64,
    /// LLM input tokens consumed (pipe executions).
    pub input_tokens: u64,
    /// LLM output tokens produced (pipe executions).
    pub output_tokens: u64,
    /// Sum of observed latencies (ms) — divide by `latency_count` for the mean.
    pub latency_sum_ms: u64,
    /// Number of latency observations folded in.
    pub latency_count: u64,
    /// Minimum observed latency (ms). `None` until the first observation.
    pub latency_min_ms: Option<u64>,
    /// Maximum observed latency (ms).
    pub latency_max_ms: u64,
    /// Additive latency histogram, indexed per [`LATENCY_BUCKET_BOUNDS_MS`].
    #[serde(default)]
    pub latency_hist: Vec<u64>,
    /// Requests served from the response cache (a subset of `connections`).
    #[serde(default)]
    pub cache_hits: u64,
    /// Provider spend avoided by cache hits, in micro-dollars (÷1e6 for USD).
    /// Kept as an integer so the sample stays additively mergeable.
    #[serde(default)]
    pub cache_saved_cost_micros: u64,
}

impl OpsSample {
    /// Fold a single latency observation into the histogram and min/max/sum.
    pub fn observe_latency(
        &mut self,
        ms: u64,
    ) {
        self.latency_sum_ms = self
            .latency_sum_ms
            .saturating_add(ms);
        self.latency_count += 1;
        self.latency_min_ms = Some(
            self.latency_min_ms
                .map_or(ms, |m| m.min(ms)),
        );
        self.latency_max_ms = self.latency_max_ms.max(ms);
        let idx = latency_bucket_index(ms);
        if self.latency_hist.len() <= idx {
            self.latency_hist
                .resize(idx + 1, 0);
        }
        self.latency_hist[idx] += 1;
    }

    /// Mean latency (ms), or `0.0` when there are no observations.
    pub fn avg_latency_ms(&self) -> f64 {
        if self.latency_count == 0 {
            0.0
        } else {
            self.latency_sum_ms as f64 / self.latency_count as f64
        }
    }

    /// Approximate the `q` quantile (0.0..=1.0) from the latency histogram with
    /// linear interpolation inside the chosen bucket. Returns `0` when no
    /// observations exist; clamps to the observed min/max.
    pub fn latency_percentile(
        &self,
        q: f64,
    ) -> u64 {
        let total: u64 = self.latency_hist.iter().sum();
        if total == 0 {
            return 0;
        }
        let target = (q * total as f64)
            .ceil()
            .max(1.0) as u64;
        let mut cum = 0u64;
        for (i, &count) in self
            .latency_hist
            .iter()
            .enumerate()
        {
            if count == 0 {
                continue;
            }
            cum += count;
            if cum >= target {
                let lower = if i == 0 {
                    0
                } else {
                    LATENCY_BUCKET_BOUNDS_MS[i - 1]
                };
                let upper = LATENCY_BUCKET_BOUNDS_MS
                    .get(i)
                    .copied()
                    .unwrap_or_else(|| {
                        self.latency_max_ms
                            .max(LATENCY_BUCKET_BOUNDS_MS[LATENCY_BUCKET_BOUNDS_MS.len() - 1])
                    });
                // Fraction of the way through this bucket the target lands.
                let into = (target - (cum - count)) as f64;
                let frac = into / count as f64;
                let est = lower as f64 + (upper.saturating_sub(lower)) as f64 * frac;
                let est = est.round() as u64;
                let lo = self
                    .latency_min_ms
                    .unwrap_or(0);
                return est.clamp(lo, self.latency_max_ms.max(lo));
            }
        }
        self.latency_max_ms
    }
}

impl RrdSample for OpsSample {
    fn merge(
        &mut self,
        other: &Self,
    ) {
        self.connections += other.connections;
        self.failed += other.failed;
        self.gateway_faults += other.gateway_faults;
        self.rule_accepts += other.rule_accepts;
        self.rule_denies += other.rule_denies;
        self.request_bytes += other.request_bytes;
        self.response_bytes += other.response_bytes;
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cache_hits += other.cache_hits;
        self.cache_saved_cost_micros += other.cache_saved_cost_micros;
        self.latency_sum_ms = self
            .latency_sum_ms
            .saturating_add(other.latency_sum_ms);
        self.latency_count += other.latency_count;
        self.latency_min_ms = match (self.latency_min_ms, other.latency_min_ms) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, b) => b,
        };
        self.latency_max_ms = self
            .latency_max_ms
            .max(other.latency_max_ms);
        if !other.latency_hist.is_empty() {
            if self.latency_hist.len() < other.latency_hist.len() {
                self.latency_hist
                    .resize(other.latency_hist.len(), 0);
            }
            for (slot, add) in self
                .latency_hist
                .iter_mut()
                .zip(other.latency_hist.iter())
            {
                *slot += add;
            }
        }
    }
}

/// Appliance-wide operational series (every connection / pipe / rule event).
pub const OPS_ALL_KEY: &str = "ops:all";

/// Per-surface operational series key (`ops:surface:{id}`).
pub fn ops_surface_key(surface_id: &str) -> String {
    format!("ops:surface:{surface_id}")
}

/// Build the `(key, sample)` fan-out for one connection datapoint. Connection
/// counts, status and latency are recorded once per round-trip (on the request
/// leg only) to avoid double counting; bytes and tokens accrue from whichever
/// leg carries them. Latency is observed for pipe executions only, matching the
/// dashboard's LLM-latency chart.
pub fn samples_for_connection(metric: &ConnectionMetric) -> Vec<(String, OpsSample)> {
    let mut sample = OpsSample {
        request_bytes: metric
            .request_bytes
            .unwrap_or(0),
        response_bytes: metric
            .response_bytes
            .unwrap_or(0),
        input_tokens: metric
            .llm_input_tokens
            .unwrap_or(0),
        output_tokens: metric
            .llm_output_tokens
            .unwrap_or(0),
        ..Default::default()
    };
    if metric.direction == ConnectionDirection::Request {
        sample.connections = 1;
        match metric.status {
            ConnectionStatus::Failed => sample.failed = 1,
            ConnectionStatus::GatewayFault => sample.gateway_faults = 1,
            ConnectionStatus::Success => {}
        }
        if metric.cache_hit {
            sample.cache_hits = 1;
            sample.cache_saved_cost_micros = (metric
                .cache_saved_cost
                .unwrap_or(0.0)
                .max(0.0)
                * 1_000_000.0) as u64;
        }
        if metric.metric_type == MetricType::Pipe
            && let Some(ms) = metric.latency_ms
        {
            sample.observe_latency(ms);
        }
    }
    let surface_id = metric
        .pipe_id
        .clone()
        .unwrap_or_else(|| {
            metric
                .channel_config_id
                .clone()
        });
    vec![(OPS_ALL_KEY.to_string(), sample.clone()), (ops_surface_key(&surface_id), sample)]
}

/// Build the `(key, sample)` fan-out for one rule-validation event.
pub fn samples_for_rule(
    channel_config_id: &str,
    accepted: bool,
) -> Vec<(String, OpsSample)> {
    let mut sample = OpsSample::default();
    if accepted {
        sample.rule_accepts = 1;
    } else {
        sample.rule_denies = 1;
    }
    vec![(OPS_ALL_KEY.to_string(), sample.clone()), (ops_surface_key(channel_config_id), sample)]
}

/// The operational series a streaming surface fans progress + completion samples
/// out to: the appliance-wide aggregate, the surface's own series, and — when
/// the request was dispatched through an IDE Surface front door — the front
/// door's series too (dual attribution, mirroring the buffered path).
pub fn stream_ops_keys(
    surface_id: &str,
    front_door_id: Option<&str>,
) -> Vec<String> {
    let mut keys = vec![OPS_ALL_KEY.to_string(), ops_surface_key(surface_id)];
    if let Some(ide_id) = front_door_id {
        keys.push(ops_surface_key(ide_id));
    }
    keys
}

/// Record a mid-stream progress heartbeat: the request/response bytes and
/// tokens that have accrued since the last flush. Carries **no** connection
/// count, status, or latency — those are recorded once at completion — so the
/// running stream's throughput and token charts update live without inflating
/// the request count. Request bytes are known up-front, so the handler flushes
/// them on the first heartbeat (at stream start) rather than at completion.
/// No-op when nothing accrued or the ops store is not registered.
pub async fn record_stream_progress(
    keys: &[String],
    delta_request_bytes: u64,
    delta_response_bytes: u64,
    delta_input_tokens: u64,
    delta_output_tokens: u64,
) {
    if delta_request_bytes == 0 && delta_response_bytes == 0 && delta_input_tokens == 0 && delta_output_tokens == 0 {
        return;
    }
    let Some(store) = global_ops_store() else {
        return;
    };
    let sample = OpsSample {
        request_bytes: delta_request_bytes,
        response_bytes: delta_response_bytes,
        input_tokens: delta_input_tokens,
        output_tokens: delta_output_tokens,
        ..Default::default()
    };
    let samples: Vec<(String, OpsSample)> = keys
        .iter()
        .map(|k| (k.clone(), sample.clone()))
        .collect();
    store.record(samples).await;
}

/// Build the terminal ops sample for a completed (or aborted) stream: the single
/// connection, its final status and latency, the request bytes, and whatever
/// response bytes / tokens the progress heartbeats have **not** already flushed
/// (so the surface totals reconcile to the true amount without double counting).
pub fn stream_final_sample(
    status: ConnectionStatus,
    latency_ms: u64,
    request_bytes: u64,
    remaining_response_bytes: u64,
    remaining_input_tokens: u64,
    remaining_output_tokens: u64,
) -> OpsSample {
    let mut sample = OpsSample {
        connections: 1,
        request_bytes,
        response_bytes: remaining_response_bytes,
        input_tokens: remaining_input_tokens,
        output_tokens: remaining_output_tokens,
        ..Default::default()
    };
    match status {
        ConnectionStatus::Failed => sample.failed = 1,
        ConnectionStatus::GatewayFault => sample.gateway_faults = 1,
        ConnectionStatus::Success => {}
    }
    sample.observe_latency(latency_ms);
    sample
}

/// One materialised point of an operational series, flattened for JSON. Carries
/// every field the dashboard's four time-series charts read, so a single series
/// drives connections, throughput, tokens and latency.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OpsSeriesPoint {
    pub t: i64,
    pub connections: u64,
    pub failed: u64,
    pub gateway_faults: u64,
    pub rule_accepts: u64,
    pub rule_denies: u64,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub latency_samples: u64,
    pub cache_hits: u64,
    pub cache_saved_cost: f64,
}

impl OpsSeriesPoint {
    fn from_sample(
        t: i64,
        s: &OpsSample,
    ) -> Self {
        Self {
            t,
            connections: s.connections,
            failed: s.failed,
            gateway_faults: s.gateway_faults,
            rule_accepts: s.rule_accepts,
            rule_denies: s.rule_denies,
            request_bytes: s.request_bytes,
            response_bytes: s.response_bytes,
            input_tokens: s.input_tokens,
            output_tokens: s.output_tokens,
            avg_latency_ms: s.avg_latency_ms(),
            p50_latency_ms: s.latency_percentile(0.50),
            p95_latency_ms: s.latency_percentile(0.95),
            p99_latency_ms: s.latency_percentile(0.99),
            min_latency_ms: s.latency_min_ms.unwrap_or(0),
            max_latency_ms: s.latency_max_ms,
            latency_samples: s.latency_count,
            cache_hits: s.cache_hits,
            cache_saved_cost: s.cache_saved_cost_micros as f64 / 1_000_000.0,
        }
    }
}

/// A single operational series' windowed range result.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct OpsSeriesResponse {
    pub key: String,
    pub resolution: String,
    pub step_secs: i64,
    pub points: Vec<OpsSeriesPoint>,
}

/// Operational metrics store: a thin domain wrapper over a swappable
/// [`TimeSeriesBackend`]. The embedded RRD store is the default; an external
/// adapter is dropped in by constructing with [`OpsMetricsStore::new`].
pub struct OpsMetricsStore {
    backend: Arc<dyn TimeSeriesBackend<OpsSample>>,
}

impl OpsMetricsStore {
    /// Wrap an arbitrary backend (embedded or external).
    pub fn new(backend: Arc<dyn TimeSeriesBackend<OpsSample>>) -> Self {
        Self { backend }
    }

    /// Build the default embedded RRD-backed store rooted at `storage_dir`.
    pub async fn embedded(storage_dir: impl Into<PathBuf>) -> Self {
        let store = RrdStore::<OpsSample>::new(storage_dir).await;
        Self::new(Arc::new(store))
    }

    /// Record a pre-built `(key, sample)` fan-out at the current instant.
    pub async fn record(
        &self,
        samples: Vec<(String, OpsSample)>,
    ) {
        self.backend
            .record_many(samples, Utc::now())
            .await;
    }

    /// Query one series over `[from, to]`, materialising flattened points.
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
    ) -> OpsSeriesResponse {
        let r = self
            .backend
            .range(key, from, to, max_points, force_tier)
            .await;
        OpsSeriesResponse {
            key: r.key,
            resolution: r.resolution,
            step_secs: r.step_secs,
            points: r
                .points
                .iter()
                .map(|p| OpsSeriesPoint::from_sample(p.t, &p.value))
                .collect(),
        }
    }

    /// Query several series over `[from, to]` in a single backend call, taking
    /// the store's read lock once rather than once per key.
    pub async fn range_many(
        &self,
        keys: &[String],
        from: i64,
        to: i64,
        max_points: usize,
        force_tier: Option<&str>,
    ) -> Vec<OpsSeriesResponse> {
        self.backend
            .range_many(keys, from, to, max_points, force_tier)
            .await
            .into_iter()
            .map(|r| OpsSeriesResponse {
                key: r.key,
                resolution: r.resolution,
                step_secs: r.step_secs,
                points: r
                    .points
                    .iter()
                    .map(|p| OpsSeriesPoint::from_sample(p.t, &p.value))
                    .collect(),
            })
            .collect()
    }

    /// Drop a surface's operational series (and its children) on soft-delete.
    pub async fn remove_surface_series(
        &self,
        surface_id: &str,
    ) {
        let base = ops_surface_key(surface_id);
        let child_prefix = format!("{base}:");
        self.backend
            .delete_series_matching(&KeyMatch::Any(vec![KeyMatch::Exact(base), KeyMatch::Prefix(child_prefix)]))
            .await;
    }

    /// Synchronously persist all pending state (graceful shutdown).
    pub async fn flush(&self) {
        self.backend.flush().await;
    }
}

static GLOBAL_OPS: OnceLock<Arc<OpsMetricsStore>> = OnceLock::new();

/// Register the process-wide operational metrics store (orchestrator, once).
pub fn set_global_ops_store(store: Arc<OpsMetricsStore>) {
    let _ = GLOBAL_OPS.set(store);
}

/// Access the process-wide operational metrics store, if registered.
pub fn global_ops_store() -> Option<Arc<OpsMetricsStore>> {
    GLOBAL_OPS.get().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pipe_metric(
        latency_ms: u64,
        status: ConnectionStatus,
    ) -> ConnectionMetric {
        ConnectionMetric {
            timestamp: Utc::now(),
            channel_config_id: "p1".to_string(),
            source: "pipe".to_string(),
            destination: "openai".to_string(),
            status,
            latency_ms: Some(latency_ms),
            identity_hash: None,
            direction: ConnectionDirection::Request,
            trace_id: "t".to_string(),
            ucp_operation: None,
            variant_alias: None,
            metric_type: MetricType::Pipe,
            pipe_id: Some("p1".to_string()),
            pipe_name: None,
            llm_provider: Some("openai".to_string()),
            llm_model: Some("gpt".to_string()),
            llm_input_tokens: Some(100),
            llm_output_tokens: Some(50),
            llm_total_tokens: Some(150),
            llm_cost: Some(0.01),
            pipe_gateway_processing_ms: None,
            pipe_target_processing_ms: None,
            channel_request_latency_ms: None,
            channel_response_latency_ms: None,
            total_latency_ms: latency_ms,
            correlation_id: None,
            agent_identity: None,
            request_bytes: Some(200),
            response_bytes: Some(300),
            retry_count: None,
            stage_usage: None,
            cache_hit: false,
            cache_saved_cost: None,
            cache_saved_tokens: None,
        }
    }

    #[test]
    fn bucket_index_boundaries() {
        assert_eq!(latency_bucket_index(0), 0);
        assert_eq!(latency_bucket_index(1), 0);
        assert_eq!(latency_bucket_index(2), 1);
        assert_eq!(latency_bucket_index(100), 6);
        assert_eq!(latency_bucket_index(60_000), LATENCY_BUCKET_BOUNDS_MS.len() - 1);
        assert_eq!(latency_bucket_index(120_000), LATENCY_BUCKET_BOUNDS_MS.len());
    }

    #[test]
    fn observe_and_avg() {
        let mut s = OpsSample::default();
        s.observe_latency(10);
        s.observe_latency(30);
        assert_eq!(s.latency_count, 2);
        assert_eq!(s.latency_sum_ms, 40);
        assert_eq!(s.avg_latency_ms(), 20.0);
        assert_eq!(s.latency_min_ms, Some(10));
        assert_eq!(s.latency_max_ms, 30);
    }

    #[test]
    fn percentile_is_monotonic_and_bounded() {
        let mut s = OpsSample::default();
        for ms in [5u64, 10, 20, 40, 80, 160, 320, 640, 1280, 2560] {
            s.observe_latency(ms);
        }
        let p50 = s.latency_percentile(0.50);
        let p95 = s.latency_percentile(0.95);
        let p99 = s.latency_percentile(0.99);
        assert!(p50 <= p95, "p50 {p50} <= p95 {p95}");
        assert!(p95 <= p99, "p95 {p95} <= p99 {p99}");
        assert!(p99 <= s.latency_max_ms, "p99 {p99} <= max {}", s.latency_max_ms);
        assert!(p50 >= s.latency_min_ms.unwrap());
    }

    #[test]
    fn merge_sums_counters_and_histogram() {
        let mut a = OpsSample {
            connections: 2,
            failed: 1,
            request_bytes: 100,
            input_tokens: 10,
            ..Default::default()
        };
        a.observe_latency(50);
        let mut b = OpsSample {
            connections: 3,
            gateway_faults: 1,
            request_bytes: 200,
            input_tokens: 5,
            ..Default::default()
        };
        b.observe_latency(10);
        a.merge(&b);
        assert_eq!(a.connections, 5);
        assert_eq!(a.failed, 1);
        assert_eq!(a.gateway_faults, 1);
        assert_eq!(a.request_bytes, 300);
        assert_eq!(a.input_tokens, 15);
        assert_eq!(a.latency_count, 2);
        assert_eq!(a.latency_min_ms, Some(10));
        assert_eq!(a.latency_max_ms, 50);
        let hist_total: u64 = a.latency_hist.iter().sum();
        assert_eq!(hist_total, 2);
    }

    #[test]
    fn connection_samples_count_once_on_request() {
        let req = pipe_metric(120, ConnectionStatus::Success);
        let samples = samples_for_connection(&req);
        assert_eq!(samples.len(), 2);
        assert_eq!(samples[0].0, OPS_ALL_KEY);
        assert_eq!(samples[1].0, "ops:surface:p1");
        let all = &samples[0].1;
        assert_eq!(all.connections, 1);
        assert_eq!(all.input_tokens, 100);
        assert_eq!(all.output_tokens, 50);
        assert_eq!(all.request_bytes, 200);
        assert_eq!(all.latency_count, 1);
        assert_eq!(all.latency_min_ms, Some(120));
    }

    #[test]
    fn response_leg_does_not_count_connection() {
        let mut resp = pipe_metric(120, ConnectionStatus::Success);
        resp.direction = ConnectionDirection::Response;
        let samples = samples_for_connection(&resp);
        let all = &samples[0].1;
        assert_eq!(all.connections, 0);
        // Bytes still accrue from the response leg.
        assert_eq!(all.response_bytes, 300);
        assert_eq!(all.latency_count, 0);
    }

    #[test]
    fn rule_samples_split_accept_deny() {
        let accept = samples_for_rule("c1", true);
        assert_eq!(accept[0].1.rule_accepts, 1);
        assert_eq!(accept[0].1.rule_denies, 0);
        let deny = samples_for_rule("c1", false);
        assert_eq!(deny[0].1.rule_accepts, 0);
        assert_eq!(deny[0].1.rule_denies, 1);
    }

    #[test]
    fn stream_ops_keys_include_front_door_when_dispatched() {
        let plain = stream_ops_keys("p1", None);
        assert_eq!(plain, vec![OPS_ALL_KEY.to_string(), "ops:surface:p1".to_string()]);
        let dispatched = stream_ops_keys("p1", Some("ide1"));
        assert_eq!(
            dispatched,
            vec![OPS_ALL_KEY.to_string(), "ops:surface:p1".to_string(), "ops:surface:ide1".to_string()]
        );
    }

    #[test]
    fn stream_final_sample_records_remainder_and_status() {
        // A completed stream that flushed some bytes/tokens via heartbeats: the
        // final sample carries the connection, latency, request bytes, and only
        // the un-flushed remainder.
        let ok = stream_final_sample(ConnectionStatus::Success, 250, 200, 40, 0, 12);
        assert_eq!(ok.connections, 1);
        assert_eq!(ok.failed, 0);
        assert_eq!(ok.request_bytes, 200);
        assert_eq!(ok.response_bytes, 40);
        assert_eq!(ok.output_tokens, 12);
        assert_eq!(ok.latency_count, 1);
        assert_eq!(ok.latency_max_ms, 250);

        // An aborted stream is a Failed connection.
        let aborted = stream_final_sample(ConnectionStatus::Failed, 90, 200, 0, 0, 0);
        assert_eq!(aborted.connections, 1);
        assert_eq!(aborted.failed, 1);
    }

    #[test]
    fn heartbeats_plus_final_reconcile_to_full_totals() {
        // Two heartbeats (deltas) plus the completion remainder must sum to the
        // true response bytes / output tokens, proving no double counting.
        let mut acc = OpsSample::default();
        let h1 = OpsSample {
            response_bytes: 120,
            output_tokens: 20,
            ..Default::default()
        };
        let h2 = OpsSample {
            response_bytes: 80,
            output_tokens: 15,
            ..Default::default()
        };
        acc.merge(&h1);
        acc.merge(&h2);
        // flushed = 200 bytes / 35 output tokens; totals = 260 bytes / 50 tokens.
        let remaining = stream_final_sample(ConnectionStatus::Success, 100, 10, 260 - 200, 0, 50 - 35);
        acc.merge(&remaining);
        assert_eq!(acc.response_bytes, 260);
        assert_eq!(acc.output_tokens, 50);
        assert_eq!(acc.connections, 1);
        assert_eq!(acc.request_bytes, 10);
    }

    #[tokio::test]
    async fn record_stream_progress_no_ops_on_zero_delta() {
        // A zero-delta heartbeat is a no-op even with no store registered.
        record_stream_progress(&["ops:all".to_string()], 0, 0, 0, 0).await;
    }

    #[tokio::test]
    async fn store_records_and_ranges() {
        let dir = std::env::temp_dir().join(format!("ops-store-{}", uuid::Uuid::new_v4()));
        let store = OpsMetricsStore::embedded(&dir).await;
        let req = pipe_metric(120, ConnectionStatus::Success);
        store
            .record(samples_for_connection(&req))
            .await;
        store
            .record(samples_for_connection(&req))
            .await;

        let now = Utc::now().timestamp();
        let resp = store
            .range(OPS_ALL_KEY, now - 120, now + 120, 500, None)
            .await;
        assert_eq!(resp.points.len(), 1);
        let p = &resp.points[0];
        assert_eq!(p.connections, 2);
        assert_eq!(p.input_tokens, 200);
        assert_eq!(p.latency_samples, 2);
        assert!(p.p95_latency_ms >= p.p50_latency_ms);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn remove_surface_series_drops_children() {
        let dir = std::env::temp_dir().join(format!("ops-gc-{}", uuid::Uuid::new_v4()));
        let store = OpsMetricsStore::embedded(&dir).await;
        let now = Utc::now().timestamp();
        store
            .record(vec![
                (
                    ops_surface_key("p1"),
                    OpsSample {
                        connections: 1,
                        ..Default::default()
                    },
                ),
                (
                    format!("{}:stage:llm", ops_surface_key("p1")),
                    OpsSample {
                        connections: 1,
                        ..Default::default()
                    },
                ),
                (
                    ops_surface_key("p10"),
                    OpsSample {
                        connections: 1,
                        ..Default::default()
                    },
                ),
            ])
            .await;
        store
            .remove_surface_series("p1")
            .await;
        assert_eq!(
            store
                .range("ops:surface:p1", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        assert_eq!(
            store
                .range("ops:surface:p1:stage:llm", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            0
        );
        // Anchored: p10 must survive.
        assert_eq!(
            store
                .range("ops:surface:p10", now - 60, now + 60, 500, None)
                .await
                .points
                .len(),
            1
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
