//! Pipe metrics API handlers

use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::debug;

use crate::auth_manager::pat::PatResourceScope;
use crate::identity::state::IdentityApiState;
use crate::metrics::ConnectionStatus;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

#[derive(Debug, Deserialize)]
pub struct MetricsQueryParams {
    #[serde(default = "default_time_range")]
    pub time_range: String, // "1h", "24h", "7d", "30d"
    pub pipe_id: Option<String>,
}

fn default_time_range() -> String {
    "24h".to_string()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PipeMetricsSummary {
    pub pipe_id: String,
    pub pipe_name: String,
    pub provider: String,
    pub model: String,
    pub total_requests: u64,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_tokens: u64,
    pub total_cost: f64,
    pub avg_latency_ms: f64,
    pub error_count: u64,
    pub success_rate: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub requests: u64,
    pub cost: f64,
    /// Request-direction bytes sent to the pipe target within this interval.
    pub request_bytes: u64,
    /// Response-direction bytes returned from the pipe target within this interval.
    pub response_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PipeMetricsResponse {
    pub summaries: Vec<PipeMetricsSummary>,
    pub time_series: Vec<TimeSeriesPoint>,
    pub total_cost: f64,
    pub total_tokens: u64,
    pub total_requests: u64,
}

/// Compute pipe metrics from the given stores.
/// Extracted so it can be called from both the HTTP handler and the WS broadcast.
pub async fn compute_pipe_metrics(
    metrics_store: &crate::metrics::MetricsStore,
    pipe_store: Option<&crate::pipes::FileSystemPipeStore>,
    time_range: &str,
    pipe_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> PipeMetricsResponse {
    // Parse time range
    let duration = match time_range {
        "1h" => Duration::hours(1),
        "24h" => Duration::hours(24),
        "7d" => Duration::days(7),
        "30d" => Duration::days(30),
        _ => Duration::hours(24),
    };

    let cutoff_time = Utc::now() - duration;

    // Get all recent connections from metrics store (limit to last 10000)
    let connections = metrics_store
        .get_recent_connections(10000)
        .await;

    // Filter for pipe-related metrics within time range (using metric_type)
    let pipe_metrics: Vec<_> = connections
        .into_iter()
        .filter(|m| {
            m.timestamp >= cutoff_time
                && m.metric_type == crate::metrics::MetricType::Pipe
                && (pipe_id.is_none() || m.pipe_id.as_deref() == pipe_id)
        })
        .collect();

    // Group by pipe_id
    let mut pipe_groups: HashMap<String, Vec<_>> = HashMap::new();
    for metric in pipe_metrics {
        let pid = metric
            .pipe_id
            .clone()
            .unwrap_or_default();
        pipe_groups
            .entry(pid)
            .or_default()
            .push(metric);
    }

    // Resolve each pipe against the live store once. A deleted pipe leaves stale
    // metric records behind; when the store is available and no longer knows the
    // pipe, drop it entirely so it is excluded from the summaries, totals, and
    // time series (rather than surfacing as a bare UUID or inflating counts).
    // Without a store we cannot verify liveness, so nothing is dropped.
    let mut pipe_configs: HashMap<String, crate::pipes::PipeConfig> = HashMap::new();
    if let Some(store) = pipe_store {
        let pids: Vec<String> = pipe_groups
            .keys()
            .cloned()
            .collect();
        for pid in pids {
            if let Some(cfg) = store.get(&pid).await
                && can_access(cfg.tenant_id.as_deref(), context)
                && scope_allows_resource(scope, context, ResourceKind::Pipes, &cfg.id)
            {
                pipe_configs.insert(pid, cfg);
            }
        }
        pipe_groups.retain(|pid, _| pipe_configs.contains_key(pid));
    } else if context.is_some() || scope.is_some() {
        pipe_groups.clear();
    }

    // Calculate summaries for each pipe
    let mut summaries = Vec::new();
    for (pid, metrics) in &pipe_groups {
        let total_requests = metrics.len() as u64;
        let successful = metrics
            .iter()
            .filter(|m| matches!(m.status, ConnectionStatus::Success))
            .count() as u64;
        let error_count = total_requests - successful;
        let success_rate = if total_requests > 0 {
            (successful as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        let total_input_tokens: u64 = metrics
            .iter()
            .filter_map(|m| m.llm_input_tokens)
            .sum();
        let total_output_tokens: u64 = metrics
            .iter()
            .filter_map(|m| m.llm_output_tokens)
            .sum();
        let total_tokens = total_input_tokens + total_output_tokens;
        let total_cost: f64 = metrics
            .iter()
            .filter_map(|m| m.llm_cost)
            .sum();

        let latencies: Vec<u64> = metrics
            .iter()
            .filter_map(|m| m.latency_ms)
            .collect();
        let avg_latency_ms = if !latencies.is_empty() {
            latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
        } else {
            0.0
        };

        let total_requests = metrics.len() as u64;

        // Names/provider/model come from the pre-resolved live config. Deleted
        // pipes were already dropped from `pipe_groups` above; the `None` arm
        // only applies when no store was supplied (liveness unknown).
        let (pipe_name, provider, model) = match pipe_configs.get(pid) {
            Some(pipe_config) => {
                let (prov, mod_name) = match &pipe_config.pipe_type {
                    crate::pipes::PipeType::LLM { provider, .. } => (
                        "OpenAI".to_string(),
                        provider
                            .model_name()
                            .to_string(),
                    ),
                    crate::pipes::PipeType::Webhook { .. } => ("Webhook".to_string(), "N/A".to_string()),
                    crate::pipes::PipeType::IDECatalog { .. } => ("IDE".to_string(), "N/A".to_string()),
                };
                (pipe_config.name.clone(), prov, mod_name)
            }
            None => (pid.clone(), "Unknown".to_string(), "Unknown".to_string()),
        };

        summaries.push(PipeMetricsSummary {
            pipe_id: pid.clone(),
            pipe_name,
            provider,
            model,
            total_requests,
            total_input_tokens,
            total_output_tokens,
            total_tokens,
            total_cost,
            avg_latency_ms,
            error_count,
            success_rate,
        });
    }

    // Deterministic ordering so the dashboard's token-distribution chart and
    // performance table do not reshuffle on every refresh. Sort by pipe name,
    // with the pipe id as a stable tiebreaker.
    summaries.sort_by(|a, b| {
        a.pipe_name
            .cmp(&b.pipe_name)
            .then_with(|| a.pipe_id.cmp(&b.pipe_id))
    });

    // Generate time series data
    let time_series = generate_time_series(&pipe_groups, &duration);

    // Calculate totals
    let total_cost: f64 = summaries
        .iter()
        .map(|s| s.total_cost)
        .sum();
    let total_tokens: u64 = summaries
        .iter()
        .map(|s| s.total_tokens)
        .sum();
    let total_requests: u64 = summaries
        .iter()
        .map(|s| s.total_requests)
        .sum();

    PipeMetricsResponse {
        summaries,
        time_series,
        total_cost,
        total_tokens,
        total_requests,
    }
}

/// Get aggregated pipe metrics
pub async fn get_pipe_metrics(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Query(params): Query<MetricsQueryParams>,
) -> Result<Json<PipeMetricsResponse>, StatusCode> {
    debug!("Fetching pipe metrics with time_range: {}", params.time_range);

    // A query-string `pipe_id` is an unscoped cross-tenant read vector: confine
    // it to a pipe the caller owns (fail closed -> 404). An appliance caller
    // (no tenant/scope) is unrestricted.
    if let Some(pipe_id) = params.pipe_id.as_deref() {
        super::scoped_id::authorize_surface_scope(
            pipe_id,
            state.pipe_store.as_deref(),
            super::scoped_id::tenant_ctx(&context),
            super::scoped_id::res_scope(&scope),
        )
        .await
        .map_err(|(code, _)| code)?;
    }

    let response = compute_pipe_metrics(
        &state.metrics_store,
        state.pipe_store.as_deref(),
        &params.time_range,
        params.pipe_id.as_deref(),
        super::scoped_id::tenant_ctx(&context),
        super::scoped_id::res_scope(&scope),
    )
    .await;

    Ok(Json(response))
}

fn generate_time_series(
    pipe_groups: &HashMap<String, Vec<crate::metrics::ConnectionMetric>>,
    duration: &Duration,
) -> Vec<TimeSeriesPoint> {
    let now = Utc::now();
    let bucket_count = if duration.num_hours() <= 1 {
        12 // 5-minute buckets for 1h
    } else if duration.num_hours() <= 24 {
        24 // 1-hour buckets for 24h
    } else if duration.num_days() <= 7 {
        168 // 1-hour buckets for 7d
    } else {
        30 // 1-day buckets for 30d
    };

    let bucket_size = duration.num_seconds() / bucket_count;
    // Align so the last bucket ends at `now`
    let start_time = now - Duration::seconds(bucket_size * bucket_count);

    let mut buckets: Vec<TimeSeriesPoint> = Vec::new();

    for i in 0..bucket_count {
        let bucket_start = start_time + Duration::seconds(bucket_size * i);
        let bucket_end = bucket_start + Duration::seconds(bucket_size);

        let mut input_tokens = 0u64;
        let mut output_tokens = 0u64;
        let mut requests = 0u64;
        let mut cost = 0.0f64;
        let mut request_bytes = 0u64;
        let mut response_bytes = 0u64;

        for metrics in pipe_groups.values() {
            for metric in metrics {
                if metric.timestamp >= bucket_start && metric.timestamp < bucket_end {
                    requests += 1;
                    input_tokens += metric
                        .llm_input_tokens
                        .unwrap_or(0);
                    output_tokens += metric
                        .llm_output_tokens
                        .unwrap_or(0);
                    cost += metric.llm_cost.unwrap_or(0.0);
                    request_bytes += metric
                        .request_bytes
                        .unwrap_or(0);
                    response_bytes += metric
                        .response_bytes
                        .unwrap_or(0);
                }
            }
        }

        let timestamp = bucket_end.to_rfc3339();

        buckets.push(TimeSeriesPoint {
            timestamp,
            input_tokens,
            output_tokens,
            requests,
            cost,
            request_bytes,
            response_bytes,
        });
    }

    buckets
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::{MetricType, MetricsStore};
    use crate::pipes::{FileSystemPipeStore, PipeConfig, PipeType};
    use crate::tenancy::PatTenantContext;

    fn api_pipe(
        id: &str,
        name: &str,
    ) -> PipeConfig {
        PipeConfig::new(
            id.to_string(),
            name.to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        )
    }

    async fn record_one(
        store: &MetricsStore,
        pipe_id: &str,
        name: &str,
    ) {
        store
            .record_pipe_execution(
                pipe_id.to_string(),
                Some(name.to_string()),
                "openai".to_string(),
                "gpt-4o".to_string(),
                ConnectionStatus::Success,
                5,
                None,
                None,
                10,
                20,
                0.01,
                Some("trace".to_string()),
                None,
                None,
                100,
                200,
                0,
                None,
            )
            .await;
    }

    async fn wait_for_landed(
        store: &MetricsStore,
        expected: usize,
    ) {
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = store
                .get_recent_connections(10000)
                .await
                .iter()
                .filter(|c| c.metric_type == MetricType::Pipe)
                .count();
            if landed >= expected {
                break;
            }
        }
    }

    #[tokio::test]
    async fn compute_pipe_metrics_excludes_deleted_and_sorts() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pipe_store = FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("pipe store");
        // Only two pipes still exist on the live store; "pipe-ghost" was deleted.
        pipe_store
            .save(api_pipe("pipe-beta", "Beta"))
            .await
            .expect("save beta");
        pipe_store
            .save(api_pipe("pipe-alpha", "Alpha"))
            .await
            .expect("save alpha");

        let metrics_store = MetricsStore::new(100);
        // Insertion order is intentionally not alphabetical, and the deleted
        // pipe's metric records still linger between the live ones.
        record_one(&metrics_store, "pipe-beta", "Beta").await;
        record_one(&metrics_store, "pipe-ghost", "Ghost").await;
        record_one(&metrics_store, "pipe-alpha", "Alpha").await;
        wait_for_landed(&metrics_store, 3).await;

        let response = compute_pipe_metrics(&metrics_store, Some(&pipe_store), "24h", None, None, None).await;

        // The deleted pipe is excluded entirely; survivors are sorted by name.
        let names: Vec<_> = response
            .summaries
            .iter()
            .map(|s| s.pipe_name.clone())
            .collect();
        assert_eq!(names, vec!["Alpha".to_string(), "Beta".to_string()]);
        assert!(
            !response
                .summaries
                .iter()
                .any(|s| s.pipe_id == "pipe-ghost"),
            "deleted pipe must not appear"
        );
        // Totals reflect only the two live pipes (one request each).
        assert_eq!(response.total_requests, 2);
        // The time series is built from the same filtered set, so the deleted
        // pipe's historical activity is gone too and reconciles with the totals.
        let series_requests: u64 = response
            .time_series
            .iter()
            .map(|p| p.requests)
            .sum();
        assert_eq!(series_requests, 2);
    }

    #[tokio::test]
    async fn compute_pipe_metrics_without_store_keeps_all_sorted() {
        let metrics_store = MetricsStore::new(100);
        record_one(&metrics_store, "pipe-b", "pipe-b").await;
        record_one(&metrics_store, "pipe-a", "pipe-a").await;
        wait_for_landed(&metrics_store, 2).await;

        // Without a store we cannot verify liveness, so nothing is excluded but
        // ordering is still deterministic.
        let response = compute_pipe_metrics(&metrics_store, None, "24h", None, None, None).await;

        let ids: Vec<_> = response
            .summaries
            .iter()
            .map(|s| s.pipe_id.clone())
            .collect();
        assert_eq!(ids, vec!["pipe-a".to_string(), "pipe-b".to_string()]);
        assert_eq!(response.total_requests, 2);
    }

    #[tokio::test]
    async fn compute_pipe_metrics_filters_tenant_scoped_aggregate() {
        let dir = tempfile::tempdir().expect("tempdir");
        let pipe_store = FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("pipe store");
        let mut owned = api_pipe("pipe-owned", "Owned");
        owned.tenant_id = Some("tenant-a".to_string());
        pipe_store
            .save(owned)
            .await
            .expect("save owned pipe");
        let mut foreign = api_pipe("pipe-foreign", "Foreign");
        foreign.tenant_id = Some("tenant-b".to_string());
        pipe_store
            .save(foreign)
            .await
            .expect("save foreign pipe");

        let metrics_store = MetricsStore::new(100);
        record_one(&metrics_store, "pipe-owned", "Owned").await;
        record_one(&metrics_store, "pipe-foreign", "Foreign").await;
        wait_for_landed(&metrics_store, 2).await;

        let context = PatTenantContext {
            token_id: "token-a".to_string(),
            tenant_id: "tenant-a".to_string(),
        };
        let response = compute_pipe_metrics(&metrics_store, Some(&pipe_store), "24h", None, Some(&context), None).await;

        assert_eq!(response.summaries.len(), 1);
        assert_eq!(response.summaries[0].pipe_id, "pipe-owned");
        assert_eq!(response.total_requests, 1);
        assert_eq!(
            response
                .time_series
                .iter()
                .map(|point| point.requests)
                .sum::<u64>(),
            1
        );
    }
}
