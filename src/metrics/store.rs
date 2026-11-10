//! Metrics store implementation

#![allow(dead_code)]

use chrono::{DateTime, Utc};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::trace;

use crate::metrics::types::*;

/// Mutable accumulator for a single time-series bucket. Collects connection
/// counts and rule outcomes alongside per-interval transferred bytes and LLM
/// tokens so every `get_time_series*` function shares one consistent shape.
#[derive(Clone, Default)]
struct TimeBucketAccum {
    count: usize,
    rule_accepts: usize,
    rule_denies: usize,
    failed: usize,
    gateway_faults: usize,
    request_bytes: u64,
    response_bytes: u64,
    input_tokens: u64,
    output_tokens: u64,
}

impl TimeBucketAccum {
    /// Accumulate transferred bytes and LLM tokens from one connection
    /// datapoint. Called for BOTH directions of a channel round-trip so the
    /// request and response byte counts (carried on opposite datapoints) both
    /// land in the bucket. Pipes emit a single datapoint carrying both.
    fn add_transfer(
        &mut self,
        conn: &ConnectionMetric,
    ) {
        self.request_bytes += conn
            .request_bytes
            .unwrap_or(0);
        self.response_bytes += conn
            .response_bytes
            .unwrap_or(0);
        self.input_tokens += conn
            .llm_input_tokens
            .unwrap_or(0);
        self.output_tokens += conn
            .llm_output_tokens
            .unwrap_or(0);
    }

    /// Count one connection per round-trip and tally its terminal status. Must
    /// be skipped for the Response side of a channel round-trip to avoid double
    /// counting (the Response datapoint carries the same status as the Request).
    fn add_connection(
        &mut self,
        status: ConnectionStatus,
    ) {
        self.count += 1;
        match status {
            ConnectionStatus::Failed => self.failed += 1,
            ConnectionStatus::GatewayFault => self.gateway_faults += 1,
            ConnectionStatus::Success => {}
        }
    }

    /// Materialise the accumulated bucket into a serialisable point.
    fn into_point(
        self,
        timestamp: String,
    ) -> TimeSeriesPoint {
        TimeSeriesPoint {
            timestamp,
            count: self.count,
            rule_accepts: self.rule_accepts,
            rule_denies: self.rule_denies,
            failed: self.failed,
            gateway_faults: self.gateway_faults,
            request_bytes: self.request_bytes,
            response_bytes: self.response_bytes,
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
        }
    }
}

pub struct MetricsStore {
    /// Recent connections (limited to last 1000)
    connections: Arc<RwLock<Vec<ConnectionMetric>>>,
    /// Maximum number of connections to keep in memory
    max_connections: usize,
    /// Optional WebSocket state for broadcasting updates
    ws_state: Option<Arc<crate::server::WsState>>,
    /// Path to metrics storage file
    storage_path: Option<std::path::PathBuf>,
    /// Rule validation metrics per channel
    rule_metrics: Arc<RwLock<HashMap<String, RuleMetric>>>,
    /// Timestamped rule validation events (limited to last 1000)
    rule_validation_events: Arc<RwLock<Vec<RuleValidationEvent>>>,
    /// Metrics retention time in minutes
    metrics_retention_minutes: u64,
    /// Last connection status by channel name
    last_status_by_channel: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
    /// Settings store for configurable windows
    settings_store: Option<Arc<crate::storage::SettingsStore>>,
    /// Last captured payload by identity hash
    last_payloads: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Latest payload by channel name (for display in channel list)
    latest_channel_payloads: Arc<RwLock<HashMap<String, serde_json::Value>>>,
    /// Backend for persisting metrics
    backend: Option<Arc<dyn crate::metrics::backends::MetricsBackend>>,
    /// Handle for the periodic save task
    save_task_handle: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    /// Flag indicating metrics have changed since last save
    dirty: Arc<tokio::sync::RwLock<bool>>,
    /// Cached aggregated pipe stats to avoid re-computing on every read
    cached_pipe_stats: Arc<RwLock<Vec<PipeStats>>>,
    /// Timestamp of last pipe stats cache update
    pipe_stats_cache_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached channel stats
    cached_channel_stats: Arc<RwLock<Vec<SurfaceStats>>>,
    /// Timestamp of last channel stats cache update
    channel_stats_cache_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached identity channel stats
    cached_identity_channel_stats: Arc<RwLock<Vec<IdentityChannelStats>>>,
    /// Timestamp of last identity channel stats cache update
    identity_channel_stats_cache_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached scalar metrics (total connections, latencies)
    cached_total_connections: Arc<RwLock<usize>>,
    cached_avg_request_latency: Arc<RwLock<Option<f64>>>,
    cached_avg_response_latency: Arc<RwLock<Option<f64>>>,
    cached_avg_pipe_gateway_processing_ms: Arc<RwLock<Option<f64>>>,
    cached_avg_pipe_target_processing_ms: Arc<RwLock<Option<f64>>>,
    cached_scalar_metrics_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Cached time series data for dashboard (configurable TTL via config.toml)
    cached_time_series: Arc<RwLock<Vec<TimeSeriesPoint>>>,
    cached_time_series_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    cached_time_series_interval: Arc<RwLock<i64>>,
    /// Cached recent connections (configurable TTL via config.toml)
    cached_recent_connections: Arc<RwLock<Vec<ConnectionMetric>>>,
    cached_recent_connections_time: Arc<RwLock<Option<DateTime<Utc>>>>,
    /// Channel for batching metrics writes to avoid lock contention
    metrics_tx: tokio::sync::mpsc::UnboundedSender<ConnectionMetric>,
    /// Cache TTL in milliseconds (configurable)
    cache_ttl_ms: i64,
}

impl MetricsStore {
    /// Create a new metrics store
    pub fn new(max_connections: usize) -> Self {
        // Create channel for batching metrics writes
        let (metrics_tx, metrics_rx) = tokio::sync::mpsc::unbounded_channel();

        let connections = Arc::new(RwLock::new(Vec::new()));
        let last_status = Arc::new(RwLock::new(HashMap::new()));
        let dirty = Arc::new(tokio::sync::RwLock::new(false));

        // Spawn background worker to batch process metrics
        let connections_clone = connections.clone();
        let last_status_clone = last_status.clone();
        let dirty_clone = dirty.clone();
        tokio::spawn(Self::metrics_batch_worker(
            metrics_rx,
            connections_clone,
            last_status_clone,
            dirty_clone,
            max_connections,
        ));

        Self {
            connections,
            max_connections,
            ws_state: None,
            storage_path: None,
            rule_metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_validation_events: Arc::new(RwLock::new(Vec::new())),
            metrics_retention_minutes: 360, // Default 6 hours in minutes
            last_status_by_channel: last_status,
            settings_store: None,
            last_payloads: Arc::new(RwLock::new(HashMap::new())),
            latest_channel_payloads: Arc::new(RwLock::new(HashMap::new())),
            backend: None,
            save_task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            dirty,
            cached_pipe_stats: Arc::new(RwLock::new(Vec::new())),
            pipe_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_channel_stats: Arc::new(RwLock::new(Vec::new())),
            channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_identity_channel_stats: Arc::new(RwLock::new(Vec::new())),
            identity_channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_total_connections: Arc::new(RwLock::new(0)),
            cached_avg_request_latency: Arc::new(RwLock::new(None)),
            cached_avg_response_latency: Arc::new(RwLock::new(None)),
            cached_avg_pipe_gateway_processing_ms: Arc::new(RwLock::new(None)),
            cached_avg_pipe_target_processing_ms: Arc::new(RwLock::new(None)),
            cached_scalar_metrics_time: Arc::new(RwLock::new(None)),
            cached_time_series: Arc::new(RwLock::new(Vec::new())),
            cached_time_series_time: Arc::new(RwLock::new(None)),
            cached_time_series_interval: Arc::new(RwLock::new(10)),
            cached_recent_connections: Arc::new(RwLock::new(Vec::new())),
            cached_recent_connections_time: Arc::new(RwLock::new(None)),
            metrics_tx,
            cache_ttl_ms: 1000, // Default 1 second
        }
    }

    /// Store the last captured payload for an identity
    ///
    /// Capped to 100 entries to bound memory usage. When full, the oldest
    /// entry (by insertion order) is evicted.
    pub async fn store_last_payload(
        &self,
        identity_hash: String,
        payload: serde_json::Value,
    ) {
        let mut payloads = self
            .last_payloads
            .write()
            .await;
        payloads.insert(identity_hash, payload);

        // Evict oldest entries if over capacity
        const MAX_PAYLOAD_ENTRIES: usize = 100;
        if payloads.len() > MAX_PAYLOAD_ENTRIES {
            let excess = payloads.len() - MAX_PAYLOAD_ENTRIES;
            let keys_to_remove: Vec<String> = payloads
                .keys()
                .take(excess)
                .cloned()
                .collect();
            for key in keys_to_remove {
                payloads.remove(&key);
            }
        }
    }

    /// Get the last captured payload for an identity
    pub async fn get_last_payload(
        &self,
        identity_hash: &str,
    ) -> Option<serde_json::Value> {
        let payloads = self
            .last_payloads
            .read()
            .await;
        payloads
            .get(identity_hash)
            .cloned()
    }

    /// Store the latest payload for a channel (most recent regardless of identity)
    pub async fn store_latest_channel_payload(
        &self,
        channel_config_id: String,
        payload: serde_json::Value,
    ) {
        let mut payloads = self
            .latest_channel_payloads
            .write()
            .await;
        payloads.insert(channel_config_id, payload);
    }

    /// Get the latest payload for a channel
    pub async fn get_latest_channel_payload(
        &self,
        channel_config_id: &str,
    ) -> Option<serde_json::Value> {
        let payloads = self
            .latest_channel_payloads
            .read()
            .await;
        payloads
            .get(channel_config_id)
            .cloned()
    }

    /// Create a new metrics store with WebSocket broadcasting
    pub async fn new_with_ws(
        max_connections: usize,
        ws_state: Arc<crate::server::WsState>,
        storage_path: String,
    ) -> Self {
        Self::new_with_ws_and_retention(max_connections, ws_state, 6, storage_path, None, None, None, None, 1).await
    }

    /// Create a new metrics store with WebSocket broadcasting and custom retention
    pub async fn new_with_ws_and_retention(
        max_connections: usize,
        ws_state: Arc<crate::server::WsState>,
        retention_minutes: u64,
        storage_dir: String,
        task_monitor: Option<Arc<crate::observability::TaskMonitor>>,
        identity_store: Option<Arc<dyn crate::identity::IdentityStore>>,
        cloudwatch_config: Option<(crate::config::metrics_config::CloudWatchMetricConfig, Option<String>)>,
        otel_meter_provider: Option<Arc<opentelemetry_sdk::metrics::SdkMeterProvider>>,
        cache_ttl_seconds: u64,
    ) -> Self {
        // Treat storage_dir as a directory and append metrics.json
        let mut storage_path_buf = std::path::PathBuf::from(storage_dir);
        storage_path_buf.push("metrics.json");
        let storage_path = Some(storage_path_buf.clone());

        // Create multi-backend with File, Prometheus, and optionally CloudWatch
        let file_backend = Arc::new(crate::metrics::backends::FileMetricsBackend::new(storage_path_buf.clone()));
        let prometheus_backend = match (task_monitor.clone(), identity_store.clone()) {
            (Some(tm), Some(is)) => Arc::new(
                crate::metrics::backends::PrometheusMetricsBackend::with_task_monitor_and_identity_store(tm, is),
            ),
            _ => Arc::new(crate::metrics::backends::PrometheusMetricsBackend::new()),
        };

        let mut multi_backend = crate::metrics::backends::MultiBackend::new()
            .add_backend(file_backend)
            .add_backend(prometheus_backend);

        // Add CloudWatch backend if enabled

        if let Some((cw_config, aws_profile)) = cloudwatch_config
            && cw_config.enabled
        {
            tracing::info!("CloudWatch metrics enabled - namespace: {}", cw_config.namespace);
            let mut cloudwatch_backend = crate::metrics::backends::CloudWatchMetricsBackend::new(
                cw_config.namespace,
                cw_config.dimensions.clone(),
            )
            .with_enabled(true)
            .with_region(cw_config.region)
            .with_profile(aws_profile);

            // Add task_monitor and identity_store if available (same as Prometheus)
            if let Some(tm) = task_monitor.clone() {
                cloudwatch_backend = cloudwatch_backend.with_task_monitor(tm);
            }
            if let Some(is) = identity_store {
                cloudwatch_backend = cloudwatch_backend.with_identity_store(is);
            }

            let cloudwatch_backend = Arc::new(
                cloudwatch_backend
                    .with_aws_client()
                    .await,
            );
            multi_backend = multi_backend.add_backend(cloudwatch_backend);
        }

        // Add OpenTelemetry backend if provided
        if let Some(meter_provider) = otel_meter_provider {
            tracing::info!("OpenTelemetry metrics backend enabled");
            let otel_backend = Arc::new(crate::metrics::backends::OpenTelemetryMetricsBackend::new(&meter_provider));
            multi_backend = multi_backend.add_backend(otel_backend);
        }

        // Create channel for batching metrics writes
        let (metrics_tx, metrics_rx) = tokio::sync::mpsc::unbounded_channel();

        let connections = Arc::new(RwLock::new(Vec::new()));
        let last_status = Arc::new(RwLock::new(HashMap::new()));
        let dirty = Arc::new(tokio::sync::RwLock::new(false));

        // Spawn background worker to batch process metrics
        let connections_clone = connections.clone();
        let last_status_clone = last_status.clone();
        let dirty_clone = dirty.clone();
        tokio::spawn(Self::metrics_batch_worker(
            metrics_rx,
            connections_clone,
            last_status_clone,
            dirty_clone,
            max_connections,
        ));

        let store = Self {
            connections,
            max_connections,
            ws_state: Some(ws_state),
            storage_path,
            rule_metrics: Arc::new(RwLock::new(HashMap::new())),
            rule_validation_events: Arc::new(RwLock::new(Vec::new())),
            metrics_retention_minutes: retention_minutes,
            last_status_by_channel: last_status,
            settings_store: None,
            last_payloads: Arc::new(RwLock::new(HashMap::new())),
            latest_channel_payloads: Arc::new(RwLock::new(HashMap::new())),
            backend: Some(Arc::new(multi_backend)),
            save_task_handle: Arc::new(tokio::sync::Mutex::new(None)),
            dirty,
            cached_pipe_stats: Arc::new(RwLock::new(Vec::new())),
            pipe_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_channel_stats: Arc::new(RwLock::new(Vec::new())),
            channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_identity_channel_stats: Arc::new(RwLock::new(Vec::new())),
            identity_channel_stats_cache_time: Arc::new(RwLock::new(None)),
            cached_total_connections: Arc::new(RwLock::new(0)),
            cached_avg_request_latency: Arc::new(RwLock::new(None)),
            cached_avg_response_latency: Arc::new(RwLock::new(None)),
            cached_avg_pipe_gateway_processing_ms: Arc::new(RwLock::new(None)),
            cached_avg_pipe_target_processing_ms: Arc::new(RwLock::new(None)),
            cached_scalar_metrics_time: Arc::new(RwLock::new(None)),
            cached_time_series: Arc::new(RwLock::new(Vec::new())),
            cached_time_series_time: Arc::new(RwLock::new(None)),
            cached_time_series_interval: Arc::new(RwLock::new(10)),
            cached_recent_connections: Arc::new(RwLock::new(Vec::new())),
            cached_recent_connections_time: Arc::new(RwLock::new(None)),
            metrics_tx,
            cache_ttl_ms: (cache_ttl_seconds * 1000) as i64,
        };

        // Load existing metrics from backend
        if let Some(ref backend) = store.backend {
            match backend.load().await {
                Ok(snapshot) => {
                    *store
                        .connections
                        .write()
                        .await = snapshot.connections;
                    *store
                        .rule_validation_events
                        .write()
                        .await = snapshot.rule_validation_events;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to load metrics from {}: {}", backend.name(), e);
                }
            }
        }

        // Start periodic save task (every 5 seconds)
        store.start_periodic_save(std::time::Duration::from_secs(5));

        store
    }

    /// Set the settings store for configurable windows
    pub fn with_settings_store(
        mut self,
        settings_store: Arc<crate::storage::SettingsStore>,
    ) -> Self {
        self.settings_store = Some(settings_store);
        self
    }

    /// Background worker that batches metrics writes to reduce lock contention
    async fn metrics_batch_worker(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<ConnectionMetric>,
        connections: Arc<RwLock<Vec<ConnectionMetric>>>,
        last_status: Arc<RwLock<HashMap<String, ConnectionStatus>>>,
        dirty: Arc<tokio::sync::RwLock<bool>>,
        max_connections: usize,
    ) {
        const MAX_BATCH_SIZE: usize = 100;
        const BATCH_TIMEOUT_MICROS: u64 = 100;

        while let Some(metric) = rx.recv().await {
            let mut batch = vec![metric];

            // Drain channel for batching (up to MAX_BATCH_SIZE or until empty)
            // Use try_recv() for zero latency - no timeouts, no waiting
            while batch.len() < MAX_BATCH_SIZE {
                match rx.try_recv() {
                    Ok(m) => batch.push(m),
                    Err(_) => break, // Channel empty or closed
                }
            }

            // Process batch with ALL locks acquired once
            let mut connections_guard = connections.write().await;
            let mut status_map = last_status.write().await;

            // Add all metrics from batch
            for metric in &batch {
                connections_guard.push(metric.clone());
                // Update last status - channel_config_id is the pipe_id for pipe metrics
                status_map.insert(
                    metric
                        .channel_config_id
                        .clone(),
                    metric.status,
                );
            }

            // Enforce max connections limit
            if connections_guard.len() > max_connections {
                let to_remove = connections_guard.len() - max_connections;
                connections_guard.drain(0..to_remove);
            }

            drop(status_map);
            drop(connections_guard);

            // Mark as dirty
            *dirty.write().await = true;

            // Invalidate all caches after writing new data
            // This prevents read operations from acquiring locks to recompute
            // Next read will see stale cache and recompute with fresh data
            // Note: We don't update caches here to avoid complexity - let readers do it
        }
    }

    /// Record a new connection
    pub async fn record_connection(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            None, // ucp_operation
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with UCP operation tracking
    pub async fn record_connection_with_ucp(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        ucp_operation: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_bytes_and_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            0, // bytes_sent
            0, // bytes_received
            ucp_operation,
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with bytes tracking for throughput
    pub async fn record_connection_with_bytes(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_with_bytes_and_ucp(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            bytes_sent,
            bytes_received,
            None, // ucp_operation
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Record a new connection with bytes and UCP operation tracking
    pub async fn record_connection_with_bytes_and_ucp(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        ucp_operation: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        self.record_connection_full(
            channel_config_id,
            source,
            destination,
            status,
            latency_ms,
            identity_hash,
            direction,
            trace_id,
            bytes_sent,
            bytes_received,
            ucp_operation,
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            variant_alias,
        )
        .await;
    }

    /// Fire-and-forget recording of operational time-series samples into the
    /// global ops store. No-ops when the ops store is not registered (metrics
    /// disabled). Kept off the hot path via `tokio::spawn`.
    fn spawn_ops_record(samples: Vec<(String, crate::metrics::ops_telemetry::OpsSample)>) {
        if samples.is_empty() {
            return;
        }
        if let Some(store) = crate::metrics::ops_telemetry::global_ops_store() {
            tokio::spawn(async move {
                store.record(samples).await;
            });
        }
    }

    /// Internal recorder used by all `record_connection_*` variants.
    #[allow(clippy::too_many_arguments)]
    async fn record_connection_full(
        &self,
        channel_config_id: String,
        source: String,
        destination: String,
        status: ConnectionStatus,
        latency_ms: Option<u64>,
        identity_hash: Option<String>,
        direction: ConnectionDirection,
        trace_id: String,
        bytes_sent: u64,
        bytes_received: u64,
        ucp_operation: Option<String>,
        channel_request_latency_ms: Option<u64>,
        channel_response_latency_ms: Option<u64>,
        total_latency_ms: u64,
        variant_alias: Option<String>,
    ) {
        let metric = ConnectionMetric {
            timestamp: Utc::now(),
            channel_config_id: channel_config_id.clone(),
            source: source.clone(),
            destination: destination.clone(),
            status,
            trace_id: trace_id.clone(),
            latency_ms,
            direction,
            identity_hash: identity_hash.clone(),
            ucp_operation: ucp_operation.clone(),
            variant_alias,
            metric_type: crate::metrics::MetricType::Channel,
            // Pipe-specific fields (None for non-pipe connections)
            pipe_id: None,
            pipe_name: None,
            llm_provider: None,
            llm_model: None,
            llm_input_tokens: None,
            llm_output_tokens: None,
            llm_total_tokens: None,
            llm_cost: None,
            // Pipe-specific latency (None for channels)
            pipe_gateway_processing_ms: None,
            pipe_target_processing_ms: None,
            // Channel-specific latency
            channel_request_latency_ms,
            channel_response_latency_ms,
            total_latency_ms,
            // Enhanced distributed tracing (None for non-pipe connections)
            correlation_id: None,
            agent_identity: None,
            // Enhanced metrics
            request_bytes: Some(bytes_sent),
            response_bytes: Some(bytes_received),
            retry_count: None,
            stage_usage: None,
            cache_hit: false,
            cache_saved_cost: None,
            cache_saved_tokens: None,
        };

        let ops_samples = crate::metrics::ops_telemetry::samples_for_connection(&metric);

        let connections_len = {
            let mut connections = self.connections.write().await;

            // Deduplicate: Check if we just recorded this exact same request within the last 100ms.
            // This prevents duplicate recordings from the same request being processed twice.
            // We include trace_id so that distinct requests with the same parameters are counted.
            let is_duplicate = connections
                .iter()
                .rev()
                .take(10)
                .any(|existing| {
                    existing.trace_id == trace_id
                        && existing.direction == direction
                        && (metric.timestamp - existing.timestamp)
                            .num_milliseconds()
                            .abs()
                            < 100
                });

            if is_duplicate {
                // Skip recording this duplicate
                return;
            }

            connections.push(metric);

            // Retention (time window) and the count cap are enforced in bulk by
            // the periodic cleanup task (`start_periodic_save`, every 5s). Doing
            // the same O(n) `retain` + front-`drain` on *every* record duplicates
            // that work and, at high RPS, dominates this critical section. Here we
            // only guard against unbounded growth between cleanup passes: once the
            // buffer crosses a high-water mark (2× the cap) we compact in one shot,
            // amortising the O(n) work to O(1) per record while bounding memory at
            // ~2× `max_connections`.
            if connections.len()
                > self
                    .max_connections
                    .saturating_mul(2)
            {
                let retention_cutoff = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);
                connections.retain(|conn| conn.timestamp >= retention_cutoff);
                if connections.len() > self.max_connections {
                    let to_remove = connections.len() - self.max_connections;
                    connections.drain(0..to_remove);
                }
            }

            // Mark metrics as dirty since we added a new connection
            *self.dirty.write().await = true;

            connections.len()
        };

        Self::spawn_ops_record(ops_samples);

        // Track in Prometheus metrics (real-time counters only)
        // Note: We only update counters here for real-time tracking.
        // Gauge metrics (active_connections, unique_identities, etc.) are updated
        // periodically via the backend persist() method to avoid inconsistencies.
        crate::metrics::backends::prometheus::track_connection(status, latency_ms, bytes_sent, bytes_received);

        // Update last status for this channel
        {
            let mut last_status = self
                .last_status_by_channel
                .write()
                .await;
            last_status.insert(channel_config_id, status);
        }

        // Broadcast metrics update via WebSocket if available
        if let Some(ws_state) = &self.ws_state {
            ws_state.broadcast(crate::server::WsUpdate::MetricsUpdated {
                metrics: serde_json::json!({
                    "total_connections": connections_len,
                    "latest": {
                        "timestamp": Utc::now().to_rfc3339(),
                    }
                }),
            });
        }

        trace!("Recorded connection (total: {})", connections_len);
    }

    pub async fn record_user_login(
        &self,
        user_role: &str,
    ) {
        // Track user login events in Prometheus
        crate::metrics::backends::prometheus::track_user_login(user_role);
        *self.dirty.write().await = true;
    }

    pub async fn record_user_event(
        &self,
        event: &str,
        user_role: &str,
    ) {
        crate::metrics::backends::prometheus::track_user_event(event, user_role);
        *self.dirty.write().await = true;
    }

    /// Record pipe execution metrics with LLM-specific data
    pub async fn record_pipe_execution(
        &self,
        pipe_id: String,
        pipe_name: Option<String>,
        provider: String,
        model: String,
        status: ConnectionStatus,
        latency_ms: u64,
        pipe_gateway_processing_ms: Option<u64>,
        pipe_target_processing_ms: Option<u64>,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        request_bytes: u64,
        response_bytes: u64,
        retry_count: u32,
        stage_usage: Option<crate::metrics::PipeStageUsage>,
    ) {
        let metric = Self::build_pipe_metric(
            pipe_id,
            pipe_name,
            provider,
            model,
            status,
            latency_ms,
            pipe_gateway_processing_ms,
            pipe_target_processing_ms,
            input_tokens,
            output_tokens,
            cost,
            trace_id,
            correlation_id,
            agent_identity,
            request_bytes,
            response_bytes,
            retry_count,
            stage_usage,
            false,
            None,
        );

        let ops_samples = crate::metrics::ops_telemetry::samples_for_connection(&metric);
        self.commit_pipe_metric(metric, ops_samples);
    }

    /// Record a response-cache hit as successful pipe traffic at `$0` provider
    /// spend, tagged `cache_hit` with the avoided cost, so dashboards show the
    /// hit as activity and can total cumulative savings. No upstream call ran.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_pipe_cache_hit(
        &self,
        pipe_id: String,
        pipe_name: Option<String>,
        provider: String,
        model: String,
        latency_ms: u64,
        request_bytes: u64,
        response_bytes: u64,
        saved_cost: f64,
        saved_tokens: u64,
        trace_id: Option<String>,
    ) {
        let mut metric = Self::build_pipe_metric(
            pipe_id,
            pipe_name,
            provider,
            model,
            ConnectionStatus::Success,
            latency_ms,
            None,
            None,
            0,
            0,
            0.0,
            trace_id,
            None,
            None,
            request_bytes,
            response_bytes,
            0,
            None,
            true,
            Some(saved_cost),
        );
        metric.cache_saved_tokens = Some(saved_tokens);
        let ops_samples = crate::metrics::ops_telemetry::samples_for_connection(&metric);
        self.commit_pipe_metric(metric, ops_samples);
    }

    /// Record the terminal metrics for a **streamed** pipe execution.
    ///
    /// Streaming feeds the operational time-series *incrementally* while the
    /// stream runs (via [`crate::metrics::ops_telemetry::record_stream_progress`]),
    /// so the request/response bytes and tokens already flushed by those
    /// heartbeats must be subtracted here to avoid double counting — the
    /// connection metric (activity log, dashboard aggregate, Prometheus,
    /// per-stage latency) still records the **full** totals, while the ops
    /// fan-out records only the connection count, final status, latency, and the
    /// *un-flushed remainder* of the request/response bytes and tokens. Request
    /// bytes are known up-front, so the handler flushes them on the first
    /// heartbeat and passes `flushed_request_bytes == request_bytes` here (ops
    /// remainder `0`); a caller that does not pre-flush passes `0` and the full
    /// request bytes land in this terminal sample. A partial/aborted stream
    /// passes `status = Failed` with whatever was delivered.
    #[allow(clippy::too_many_arguments)]
    pub async fn record_pipe_stream_completion(
        &self,
        pipe_id: String,
        pipe_name: Option<String>,
        provider: String,
        model: String,
        status: ConnectionStatus,
        latency_ms: u64,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        request_bytes: u64,
        response_bytes: u64,
        stage_usage: Option<crate::metrics::PipeStageUsage>,
        flushed_request_bytes: u64,
        flushed_response_bytes: u64,
        flushed_input_tokens: u64,
        flushed_output_tokens: u64,
    ) {
        let metric = Self::build_pipe_metric(
            pipe_id.clone(),
            pipe_name,
            provider,
            model,
            status,
            latency_ms,
            None,
            None,
            input_tokens,
            output_tokens,
            cost,
            None,
            None,
            None,
            request_bytes,
            response_bytes,
            0,
            stage_usage,
            false,
            None,
        );

        // Only the remainder the progress heartbeats have not already flushed.
        let remaining_request_bytes = request_bytes.saturating_sub(flushed_request_bytes);
        let remaining_response_bytes = response_bytes.saturating_sub(flushed_response_bytes);
        let remaining_input_tokens = input_tokens.saturating_sub(flushed_input_tokens);
        let remaining_output_tokens = output_tokens.saturating_sub(flushed_output_tokens);
        let ops_sample = crate::metrics::ops_telemetry::stream_final_sample(
            status,
            latency_ms,
            remaining_request_bytes,
            remaining_response_bytes,
            remaining_input_tokens,
            remaining_output_tokens,
        );
        let ops_samples = vec![
            (crate::metrics::ops_telemetry::OPS_ALL_KEY.to_string(), ops_sample.clone()),
            (crate::metrics::ops_telemetry::ops_surface_key(&pipe_id), ops_sample),
        ];

        self.commit_pipe_metric(metric, ops_samples);
    }

    /// Construct the pipe `ConnectionMetric` shared by the buffered and streamed
    /// completion recorders.
    #[allow(clippy::too_many_arguments)]
    fn build_pipe_metric(
        pipe_id: String,
        pipe_name: Option<String>,
        provider: String,
        model: String,
        status: ConnectionStatus,
        latency_ms: u64,
        pipe_gateway_processing_ms: Option<u64>,
        pipe_target_processing_ms: Option<u64>,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        request_bytes: u64,
        response_bytes: u64,
        retry_count: u32,
        stage_usage: Option<crate::metrics::PipeStageUsage>,
        cache_hit: bool,
        cache_saved_cost: Option<f64>,
    ) -> ConnectionMetric {
        ConnectionMetric {
            timestamp: Utc::now(),
            channel_config_id: pipe_id.clone(),
            source: "pipe".to_string(),
            destination: provider.clone(),
            status,
            trace_id: trace_id.unwrap_or_else(|| "unknown".to_string()),
            latency_ms: Some(latency_ms),
            direction: ConnectionDirection::Request,
            identity_hash: None,
            ucp_operation: None,
            variant_alias: None,
            metric_type: crate::metrics::MetricType::Pipe,
            // Pipe-specific LLM fields
            pipe_id: Some(pipe_id.clone()),
            pipe_name,
            llm_provider: Some(provider.clone()),
            llm_model: Some(model),
            llm_input_tokens: Some(input_tokens),
            llm_output_tokens: Some(output_tokens),
            llm_total_tokens: Some(input_tokens + output_tokens),
            llm_cost: Some(cost),
            // Pipe-specific latency breakdown
            pipe_gateway_processing_ms,
            pipe_target_processing_ms,
            // Channel latency (N/A for pipes)
            channel_request_latency_ms: None,
            channel_response_latency_ms: None,
            total_latency_ms: latency_ms,
            // Enhanced distributed tracing
            correlation_id,
            agent_identity,
            // Enhanced metrics
            request_bytes: Some(request_bytes),
            response_bytes: Some(response_bytes),
            retry_count: Some(retry_count),
            stage_usage,
            cache_hit,
            cache_saved_cost,
            cache_saved_tokens: None,
        }
    }

    /// Send a pipe `ConnectionMetric` to the batch worker, fan its ops samples
    /// into the operational store, and update the Prometheus counters. Shared by
    /// the buffered and streamed completion recorders.
    fn commit_pipe_metric(
        &self,
        metric: ConnectionMetric,
        ops_samples: Vec<(String, crate::metrics::ops_telemetry::OpsSample)>,
    ) {
        let status = metric.status;
        let latency_ms = metric.latency_ms;
        let request_bytes = metric
            .request_bytes
            .unwrap_or(0);
        let response_bytes = metric
            .response_bytes
            .unwrap_or(0);

        // Send to batch worker channel (non-blocking, microseconds)
        // The worker batches metrics and acquires write locks once per batch
        // This eliminates lock contention when 10+ concurrent executions happen
        let _ = self.metrics_tx.send(metric);

        Self::spawn_ops_record(ops_samples);

        // Track in Prometheus metrics (fast atomic operations)
        crate::metrics::backends::prometheus::track_connection(status, latency_ms, request_bytes, response_bytes);

        // NOTE: We DON'T broadcast individual pipe executions via WebSocket
        // This was causing 500ms+ overhead when UX is connected.
        // Instead, the dashboard polls /delta which returns cached pipe_stats (1s TTL)
        // This eliminates the WebSocket bottleneck while keeping the UX responsive.
    }

    /// Get time series data for connections (grouped by time interval)
    pub async fn get_time_series(
        &self,
        interval_minutes: i64,
    ) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        if connections.is_empty() && events.is_empty() {
            return vec![];
        }

        // Filter to connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Group connections by time interval (only within window)
        let mut time_buckets: HashMap<String, TimeBucketAccum> = HashMap::new();

        for conn in connections.iter() {
            // Skip connections outside window
            if conn.timestamp < window_start {
                continue;
            }

            // Round timestamp to interval
            let minutes_since_epoch = conn.timestamp.timestamp() / 60;
            let bucket_minutes = (minutes_since_epoch / interval_minutes) * interval_minutes;
            let bucket_time = DateTime::from_timestamp(bucket_minutes * 60, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_default();

            // Transferred bytes/tokens accrue from every datapoint: the Request
            // and Response sides of a round-trip carry different byte fields.
            entry.add_transfer(conn);

            // Count one event per round-trip, not per directional datapoint. A
            // channel round-trip records a Request and a Response datapoint with
            // identical status, so only the Request side increments the counts.
            // Pipes only emit a Request datapoint.
            if conn.direction == ConnectionDirection::Response {
                continue;
            }
            entry.add_connection(conn.status);
        }

        // Add rule validation events to time buckets
        for event in events.iter() {
            // Skip events outside window
            if event.timestamp < window_start {
                continue;
            }

            let minutes_since_epoch = event.timestamp.timestamp() / 60;
            let bucket_minutes = (minutes_since_epoch / interval_minutes) * interval_minutes;
            let bucket_time = DateTime::from_timestamp(bucket_minutes * 60, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_default();
            if event.accepted {
                entry.rule_accepts += 1;
            } else {
                entry.rule_denies += 1;
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, accum)| accum.into_point(timestamp))
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Get time series data with automatic interval selection based on data range
    pub async fn get_time_series_auto(&self) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;

        if connections.is_empty() {
            return vec![];
        }

        // Use connections_window to limit the time range we're bucketing
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Filter connections to window and find actual data range
        let windowed_connections: Vec<_> = connections
            .iter()
            .filter(|c| c.timestamp >= window_start)
            .collect();

        if windowed_connections.is_empty() {
            drop(connections);
            return vec![];
        }

        // Calculate time range of windowed data
        let oldest = windowed_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or(now);
        let newest = windowed_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or(now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_minutes = if duration_minutes < 10 {
            // Less than 10 minutes: use 30-second intervals
            drop(connections);
            return self
                .get_time_series_seconds(30)
                .await;
        } else if duration_minutes < 60 {
            // 10 minutes to 1 hour: use 1-minute intervals
            1
        } else {
            // More than 1 hour: use 5-minute intervals
            5
        };

        drop(connections);
        self.get_time_series(interval_minutes)
            .await
    }

    /// Get time series data for connections (grouped by second interval)
    /// Uses epoch-aligned time buckets with automatic interval selection
    pub async fn get_time_series_seconds(
        &self,
        interval_seconds: i64,
    ) -> Vec<TimeSeriesPoint> {
        // Protect against division by zero
        if interval_seconds <= 0 {
            eprintln!("ERROR: Invalid interval_seconds={}, must be > 0", interval_seconds);
            return vec![];
        }

        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_time_series_time
                .read()
                .await;
            let cached_interval = *self
                .cached_time_series_interval
                .read()
                .await;
            if let Some(last_update) = *cache_time
                && cached_interval == interval_seconds
                && (Utc::now() - last_update).num_milliseconds() < self.cache_ttl_ms
            {
                return self
                    .cached_time_series
                    .read()
                    .await
                    .clone();
            }
        }

        // Cache miss - compute time series
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        if connections.is_empty() && events.is_empty() {
            return vec![];
        }

        // Use connections window instead of all data
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Calculate bucket boundaries aligned to fixed epoch positions.
        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;
        let window_start = DateTime::from_timestamp(aligned_start, 0).unwrap_or_else(Utc::now);

        // Initialize all buckets with zeros, using fixed epoch-aligned timestamps
        let mut time_buckets: HashMap<String, TimeBucketAccum> = HashMap::new();

        for i in 0..num_buckets {
            let bucket_seconds = aligned_start + (i as i64 * interval_seconds);
            let bucket_time_aligned = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
            let bucket_key = bucket_time_aligned.to_rfc3339();
            time_buckets.insert(bucket_key, TimeBucketAccum::default());
        }

        // Populate buckets with actual connection data
        for conn in connections.iter() {
            // Skip connections outside window
            if conn.timestamp < window_start {
                continue;
            }

            // Round timestamp to interval
            let seconds_since_epoch = conn.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            if let Some(entry) = time_buckets.get_mut(&bucket_key) {
                // Bytes/tokens accrue from every datapoint (both round-trip sides).
                entry.add_transfer(conn);

                // Count one event per round-trip (see get_time_series): skip the
                // Response side so throughput is not doubled.
                if conn.direction == ConnectionDirection::Response {
                    continue;
                }
                entry.add_connection(conn.status);
            }
        }

        // Add rule validation events to time buckets
        for event in events.iter() {
            // Skip events outside window
            if event.timestamp < window_start {
                continue;
            }

            let seconds_since_epoch = event.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            if let Some(entry) = time_buckets.get_mut(&bucket_key) {
                if event.accepted {
                    entry.rule_accepts += 1;
                } else {
                    entry.rule_denies += 1;
                }
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, accum)| accum.into_point(timestamp))
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        drop(connections);
        drop(events);

        // Update cache
        *self
            .cached_time_series
            .write()
            .await = time_series.clone();
        *self
            .cached_time_series_time
            .write()
            .await = Some(Utc::now());
        *self
            .cached_time_series_interval
            .write()
            .await = interval_seconds;

        time_series
    }

    /// Get statistics by channel
    pub async fn get_channel_stats(&self) -> Vec<SurfaceStats> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .channel_stats_cache_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    // Cache is fresh, return it
                    return self
                        .cached_channel_stats
                        .read()
                        .await
                        .clone();
                }
            }
        }

        // Cache miss or stale - recompute
        let connections = self.connections.read().await;

        #[allow(clippy::type_complexity)]
        let mut channel_map: HashMap<
            String,
            (usize, usize, usize, usize, u64, u64, Option<chrono::DateTime<chrono::Utc>>),
        > = HashMap::new();

        for conn in connections.iter() {
            let entry = channel_map
                .entry(conn.channel_config_id.clone())
                .or_insert((0, 0, 0, 0, 0, 0, None));
            // Accumulate transferred bytes across every datapoint. A channel
            // round-trip records a Request datapoint (carrying request_bytes)
            // and a Response datapoint (carrying response_bytes), so summing
            // both fields across all datapoints yields the directional totals.
            entry.4 += conn
                .request_bytes
                .unwrap_or(0);
            entry.5 += conn
                .response_bytes
                .unwrap_or(0);
            // Update last_activity to the most recent timestamp
            if entry.6.is_none() || entry.6.unwrap() < conn.timestamp {
                entry.6 = Some(conn.timestamp);
            }
            // Count one connection per round-trip, not per directional
            // datapoint: only the Request side increments the connection and
            // status tallies (Response carries the same status). Pipes emit a
            // single Request datapoint.
            if conn.direction == ConnectionDirection::Response {
                continue;
            }
            entry.0 += 1; // total
            match conn.status {
                ConnectionStatus::Success => entry.1 += 1,
                ConnectionStatus::Failed => entry.2 += 1,
                ConnectionStatus::GatewayFault => entry.3 += 1,
            }
        }
        drop(connections); // Release lock

        let stats: Vec<_> = channel_map
            .into_iter()
            .map(
                |(
                    channel_config_id,
                    (total, success, failed, gateway_faults, request_bytes, response_bytes, last_activity),
                )| SurfaceStats {
                    channel_config_id,
                    total_connections: total,
                    successful: success,
                    failed,
                    gateway_faults,
                    total_request_bytes: request_bytes,
                    total_response_bytes: response_bytes,
                    last_activity,
                },
            )
            .collect();

        // Update cache
        {
            let mut cache = self
                .cached_channel_stats
                .write()
                .await;
            *cache = stats.clone();
            let mut cache_time = self
                .channel_stats_cache_time
                .write()
                .await;
            *cache_time = Some(Utc::now());
        }

        stats
    }

    /// Get connection counts by source-destination pairs
    pub async fn get_source_dest_stats(&self) -> Vec<SourceDestStats> {
        let connections = self.connections.read().await;

        #[derive(Default)]
        struct Stats {
            total: usize,
            successful: usize,
            failed: usize,
        }

        let mut stats_map: HashMap<(String, String, String), Stats> = HashMap::new();

        for conn in connections.iter() {
            let key = (conn.channel_config_id.clone(), conn.source.clone(), conn.destination.clone());
            let stats = stats_map
                .entry(key)
                .or_default();
            stats.total += 1;
            match conn.status {
                super::types::ConnectionStatus::Success => stats.successful += 1,
                super::types::ConnectionStatus::Failed | super::types::ConnectionStatus::GatewayFault => {
                    stats.failed += 1
                }
            }
        }

        stats_map
            .into_iter()
            .map(|((channel_config_id, source, destination), stats)| SourceDestStats {
                channel_config_id,
                source,
                destination,
                total_connections: stats.total,
                successful: stats.successful,
                failed: stats.failed,
                count: stats.total,
            })
            .collect()
    }

    /// Get connection statistics by identity hash and channel
    pub async fn get_identity_channel_stats(&self) -> Vec<IdentityChannelStats> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .identity_channel_stats_cache_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    // Cache is fresh, return it
                    return self
                        .cached_identity_channel_stats
                        .read()
                        .await
                        .clone();
                }
            }
        }

        // Cache miss or stale - recompute
        let connections = self.connections.read().await;

        // Group by (identity_hash, channel_config_id) and count success/deny/fault
        let mut stats_map: HashMap<(String, String), (usize, usize, usize)> = HashMap::new();

        for conn in connections.iter() {
            if let Some(ref identity) = conn.identity_hash {
                let key = (identity.clone(), conn.channel_config_id.clone());
                let entry = stats_map
                    .entry(key)
                    .or_insert((0, 0, 0));

                match conn.status {
                    ConnectionStatus::Success => entry.0 += 1,
                    ConnectionStatus::Failed => entry.1 += 1,
                    ConnectionStatus::GatewayFault => entry.2 += 1,
                }
            }
        }
        drop(connections); // Release lock

        let stats: Vec<_> = stats_map
            .into_iter()
            .map(|((identity_hash, channel_config_id), (success, deny, fault))| IdentityChannelStats {
                identity_hash,
                channel_config_id,
                total_count: success + deny + fault,
                success_count: success,
                deny_count: deny,
                fault_count: fault,
            })
            .collect();

        // Update cache
        {
            let mut cache = self
                .cached_identity_channel_stats
                .write()
                .await;
            *cache = stats.clone();
            let mut cache_time = self
                .identity_channel_stats_cache_time
                .write()
                .await;
            *cache_time = Some(Utc::now());
        }

        stats
    }

    /// Get statistics for LLM pipe executions
    pub async fn get_pipe_stats(&self) -> Vec<super::types::PipeStats> {
        // Check cache first - refresh every 1 second
        {
            let cache_time = self
                .pipe_stats_cache_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < 1000 {
                    // Cache is fresh, return it
                    return self
                        .cached_pipe_stats
                        .read()
                        .await
                        .clone();
                }
            }
        }

        // Cache miss or stale - recompute (but minimize lock time)
        let connections_snapshot: Vec<_> = {
            let connections = self.connections.read().await;
            connections
                .iter()
                .filter(|c| c.metric_type == super::types::MetricType::Pipe && c.pipe_id.is_some())
                .cloned()
                .collect()
        };

        // Process outside the lock
        #[allow(clippy::type_complexity)]
        let mut pipe_map: HashMap<
            String,
            (
                String,                                // provider
                String,                                // model
                Option<String>,                        // pipe_name
                usize,                                 // total
                usize,                                 // successful
                usize,                                 // failed
                u64,                                   // total_input_tokens
                u64,                                   // total_output_tokens
                f64,                                   // total_cost
                Vec<u64>,                              // latencies
                Vec<u64>,                              // request_latencies (time to first token)
                Vec<u64>,                              // response_latencies (streaming time)
                Vec<u64>,                              // request_bytes
                Vec<u64>,                              // response_bytes
                Option<chrono::DateTime<chrono::Utc>>, // last_activity
            ),
        > = HashMap::new();

        // Parallel per-stage accumulator keyed by pipe_id. Each stage slot is
        // [input_tokens, output_tokens, latency_sum_ms, count] plus a cost; kept
        // separate from `pipe_map` to avoid widening the tuple further.
        #[allow(clippy::type_complexity)]
        let mut stage_map: HashMap<String, [(u64, u64, f64, u64, u64); 4]> = HashMap::new();
        // Cache-hit tally per pipe (hit count, cumulative saved cost), kept
        // separate from `pipe_map` for the same tuple-width reason as stage_map.
        let mut cache_map: HashMap<String, (usize, f64, u64)> = HashMap::new();

        for conn in connections_snapshot.iter() {
            if let Some(ref pipe_id) = conn.pipe_id {
                let provider = conn
                    .llm_provider
                    .clone()
                    .unwrap_or_default();
                let model = conn
                    .llm_model
                    .clone()
                    .unwrap_or_default();
                let pipe_name = conn.pipe_name.clone();

                let entry = pipe_map
                    .entry(pipe_id.clone())
                    .or_insert((
                        provider.clone(),
                        model.clone(),
                        pipe_name.clone(),
                        0,
                        0,
                        0,
                        0,
                        0,
                        0.0,
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        Vec::new(),
                        None,
                    ));

                // Update pipe_name if we have one (prefer non-None values)
                if pipe_name.is_some() {
                    entry.2 = pipe_name;
                }

                // Update counts
                entry.3 += 1; // total
                match conn.status {
                    ConnectionStatus::Success => entry.4 += 1, // successful
                    _ => entry.5 += 1,                         // failed
                }

                // Accumulate tokens and cost
                if let Some(input_tokens) = conn.llm_input_tokens {
                    entry.6 += input_tokens;
                }
                if let Some(output_tokens) = conn.llm_output_tokens {
                    entry.7 += output_tokens;
                }
                if let Some(cost) = conn.llm_cost {
                    entry.8 += cost;
                }

                // Collect latencies and bytes for averaging
                if let Some(latency) = conn.latency_ms {
                    entry.9.push(latency);
                }
                if let Some(req_latency) = conn.pipe_gateway_processing_ms {
                    entry.10.push(req_latency);
                }
                if let Some(resp_latency) = conn.pipe_target_processing_ms {
                    entry.11.push(resp_latency);
                }
                if let Some(req_bytes) = conn.request_bytes {
                    entry.12.push(req_bytes);
                }
                if let Some(resp_bytes) = conn.response_bytes {
                    entry.13.push(resp_bytes);
                }

                // Update last_activity
                if entry.14.is_none() || entry.14.unwrap() < conn.timestamp {
                    entry.14 = Some(conn.timestamp);
                }

                // Accumulate per-stage usage (LLM / Judge / Jury / Decider)
                if let Some(ref su) = conn.stage_usage {
                    let acc = stage_map
                        .entry(pipe_id.clone())
                        .or_default();
                    for (slot, stage) in acc
                        .iter_mut()
                        .zip([&su.llm, &su.judge, &su.jury, &su.decider])
                    {
                        slot.0 += stage.input_tokens;
                        slot.1 += stage.output_tokens;
                        slot.2 += stage.cost;
                        if stage.latency_ms > 0 {
                            slot.3 += stage.latency_ms;
                            slot.4 += 1;
                        }
                    }
                }

                if conn.cache_hit {
                    let entry = cache_map
                        .entry(pipe_id.clone())
                        .or_default();
                    entry.0 += 1;
                    entry.1 += conn
                        .cache_saved_cost
                        .unwrap_or(0.0);
                    entry.2 += conn
                        .cache_saved_tokens
                        .unwrap_or(0);
                }
            }
        }

        let mut stats: Vec<_> = pipe_map
            .into_iter()
            .map(
                |(
                    pipe_id,
                    (
                        provider,
                        model,
                        pipe_name,
                        total,
                        successful,
                        failed,
                        input_tokens,
                        output_tokens,
                        cost,
                        latencies,
                        req_latencies,
                        resp_latencies,
                        req_bytes,
                        resp_bytes,
                        last_activity,
                    ),
                )| {
                    let avg_latency = if !latencies.is_empty() {
                        latencies.iter().sum::<u64>() as f64 / latencies.len() as f64
                    } else {
                        0.0
                    };

                    let avg_request_latency_ms = if !req_latencies.is_empty() {
                        req_latencies
                            .iter()
                            .sum::<u64>() as f64
                            / req_latencies.len() as f64
                    } else {
                        0.0
                    };

                    let avg_response_latency_ms = if !resp_latencies.is_empty() {
                        resp_latencies
                            .iter()
                            .sum::<u64>() as f64
                            / resp_latencies.len() as f64
                    } else {
                        0.0
                    };

                    let avg_request_bytes = if !req_bytes.is_empty() {
                        req_bytes.iter().sum::<u64>() / req_bytes.len() as u64
                    } else {
                        0
                    };

                    let avg_response_bytes = if !resp_bytes.is_empty() {
                        resp_bytes.iter().sum::<u64>() / resp_bytes.len() as u64
                    } else {
                        0
                    };

                    let total_request_bytes = req_bytes.iter().sum::<u64>();
                    let total_response_bytes = resp_bytes.iter().sum::<u64>();

                    let stage_slots = stage_map
                        .get(&pipe_id)
                        .copied()
                        .unwrap_or_default();
                    let to_agg = |s: (u64, u64, f64, u64, u64)| super::types::StageAggregate {
                        total_input_tokens: s.0,
                        total_output_tokens: s.1,
                        total_cost: s.2,
                        avg_latency_ms: if s.4 > 0 {
                            s.3 as f64 / s.4 as f64
                        } else {
                            0.0
                        },
                    };
                    let stage_usage = super::types::PipeStageStats {
                        llm: to_agg(stage_slots[0]),
                        judge: to_agg(stage_slots[1]),
                        jury: to_agg(stage_slots[2]),
                        decider: to_agg(stage_slots[3]),
                    };
                    let (cache_hits, cache_saved_cost, cache_saved_tokens) = cache_map
                        .get(&pipe_id)
                        .copied()
                        .unwrap_or_default();

                    super::types::PipeStats {
                        pipe_id: pipe_id.clone(),
                        pipe_name,
                        provider,
                        model,
                        total_requests: total,
                        successful_requests: successful,
                        failed_requests: failed,
                        total_input_tokens: input_tokens,
                        total_output_tokens: output_tokens,
                        total_cost: cost,
                        avg_latency_ms: avg_latency,
                        avg_gateway_processing_ms: avg_request_latency_ms,
                        avg_target_processing_ms: avg_response_latency_ms,
                        avg_request_bytes,
                        avg_response_bytes,
                        total_request_bytes,
                        total_response_bytes,
                        stage_usage,
                        cache_hits,
                        cache_saved_cost,
                        cache_saved_tokens,
                        last_activity,
                    }
                },
            )
            .collect();

        // Deterministic ordering so dashboard consumers (counts, charts, tables)
        // do not reshuffle on every refresh. Sort by pipe name, with the pipe id
        // as a stable tiebreaker.
        stats.sort_by(|a, b| {
            a.pipe_name
                .cmp(&b.pipe_name)
                .then_with(|| a.pipe_id.cmp(&b.pipe_id))
        });

        // Update cache
        {
            let mut cache = self
                .cached_pipe_stats
                .write()
                .await;
            *cache = stats.clone();
            let mut cache_time = self
                .pipe_stats_cache_time
                .write()
                .await;
            *cache_time = Some(Utc::now());
        }

        stats
    }

    /// Get UCP operation statistics for a specific channel
    pub async fn get_ucp_operation_stats(
        &self,
        channel_config_id: &str,
    ) -> Vec<super::types::UcpOperationStats> {
        let connections = self.connections.read().await;

        // Filter for this channel and count operations
        let mut operation_map: HashMap<String, (usize, usize, usize)> = HashMap::new();
        let mut total_ucp_requests = 0;

        for conn in connections.iter() {
            if conn.channel_config_id == channel_config_id
                && let Some(ref ucp_op) = conn.ucp_operation
            {
                total_ucp_requests += 1;
                let operation = ucp_op.clone();
                let entry = operation_map
                    .entry(operation)
                    .or_insert((0, 0, 0));
                entry.0 += 1; // total count

                match conn.status {
                    ConnectionStatus::Success => entry.1 += 1,
                    ConnectionStatus::Failed | ConnectionStatus::GatewayFault => entry.2 += 1,
                }
            }
        }

        // Convert to UcpOperationStats with percentages
        operation_map
            .into_iter()
            .map(|(operation, (count, successful, failed))| {
                let percentage = if total_ucp_requests > 0 {
                    (count as f64 / total_ucp_requests as f64) * 100.0
                } else {
                    0.0
                };

                super::types::UcpOperationStats {
                    operation,
                    count,
                    successful,
                    failed,
                    percentage,
                }
            })
            .collect()
    }

    /// Get total connection count
    pub async fn get_total_connections(&self) -> usize {
        // Check cache first (5 second TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < 5000 {
                    return *self
                        .cached_total_connections
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_total_connections
            .read()
            .await
    }

    /// Get average latency for the configured window (backward compatibility - returns request latency)
    pub async fn get_average_latency(&self) -> Option<f64> {
        self.get_average_request_latency()
            .await
    }

    /// Get average request latency (client to target) for the configured window
    pub async fn get_average_request_latency(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_request_latency
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_request_latency
            .read()
            .await
    }

    /// Get average response latency (target to client) for the configured window
    pub async fn get_average_response_latency(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_response_latency
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_response_latency
            .read()
            .await
    }

    /// Get average pipe gateway processing time across all pipes for the configured window
    pub async fn get_average_pipe_gateway_processing_ms(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_pipe_gateway_processing_ms
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_pipe_gateway_processing_ms
            .read()
            .await
    }

    /// Get average pipe target processing time across all pipes for the configured window
    pub async fn get_average_pipe_target_processing_ms(&self) -> Option<f64> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_scalar_metrics_time
                .read()
                .await;
            if let Some(last_update) = *cache_time {
                let age = Utc::now() - last_update;
                if age.num_milliseconds() < self.cache_ttl_ms {
                    return *self
                        .cached_avg_pipe_target_processing_ms
                        .read()
                        .await;
                }
            }
        }

        // Cache miss - compute and cache all scalar metrics together
        self.refresh_scalar_metrics_cache()
            .await;
        *self
            .cached_avg_pipe_target_processing_ms
            .read()
            .await
    }

    /// Refresh scalar metrics cache (called internally when cache is stale)
    async fn refresh_scalar_metrics_cache(&self) {
        let connections = self.connections.read().await;

        // Get configurable windows from settings
        let conn_window_minutes = if let Some(ref store) = self.settings_store {
            store
                .get()
                .connections_window_minutes
        } else {
            60
        };

        let latency_window_minutes = if let Some(ref store) = self.settings_store {
            store
                .get()
                .latency_window_minutes
        } else {
            60
        };

        let conn_cutoff = Utc::now() - chrono::Duration::minutes(conn_window_minutes as i64);
        let latency_cutoff = Utc::now() - chrono::Duration::minutes(latency_window_minutes as i64);

        // Calculate total connections
        let total = connections
            .iter()
            .filter(|conn| conn.timestamp >= conn_cutoff)
            .count();

        // Calculate average request latency
        let request_latencies: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter_map(|conn| conn.latency_ms)
            .collect();

        let avg_request = if !request_latencies.is_empty() {
            let sum: u64 = request_latencies.iter().sum();
            Some(sum as f64 / request_latencies.len() as f64)
        } else {
            None
        };

        // Calculate average response latency (from channel_response_latency_ms field)
        let response_latencies: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter_map(|conn| conn.channel_response_latency_ms)
            .collect();

        let avg_response = if !response_latencies.is_empty() {
            let sum: u64 = response_latencies
                .iter()
                .sum();
            Some(sum as f64 / response_latencies.len() as f64)
        } else {
            None
        };

        // Calculate average pipe gateway processing time
        let pipe_gateway_processing: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter(|conn| conn.metric_type == crate::metrics::MetricType::Pipe)
            .filter_map(|conn| conn.pipe_gateway_processing_ms)
            .collect();

        let avg_pipe_gateway = if !pipe_gateway_processing.is_empty() {
            let sum: u64 = pipe_gateway_processing
                .iter()
                .sum();
            Some(sum as f64 / pipe_gateway_processing.len() as f64)
        } else {
            None
        };

        // Calculate average pipe target processing time
        let pipe_target_processing: Vec<u64> = connections
            .iter()
            .filter(|conn| conn.timestamp >= latency_cutoff)
            .filter(|conn| conn.metric_type == crate::metrics::MetricType::Pipe)
            .filter_map(|conn| conn.pipe_target_processing_ms)
            .collect();

        let avg_pipe_target = if !pipe_target_processing.is_empty() {
            let sum: u64 = pipe_target_processing
                .iter()
                .sum();
            Some(sum as f64 / pipe_target_processing.len() as f64)
        } else {
            None
        };

        drop(connections); // Release lock before updating cache

        // Update all cached values
        *self
            .cached_total_connections
            .write()
            .await = total;
        *self
            .cached_avg_request_latency
            .write()
            .await = avg_request;
        *self
            .cached_avg_response_latency
            .write()
            .await = avg_response;
        *self
            .cached_avg_pipe_gateway_processing_ms
            .write()
            .await = avg_pipe_gateway;
        *self
            .cached_avg_pipe_target_processing_ms
            .write()
            .await = avg_pipe_target;
        *self
            .cached_scalar_metrics_time
            .write()
            .await = Some(Utc::now());
    }

    /// Get current connections window setting
    pub fn get_connections_window_minutes(&self) -> u64 {
        if let Some(ref store) = self.settings_store {
            store
                .get()
                .connections_window_minutes
        } else {
            60 // Default to 60 minutes
        }
    }

    /// Get configured bucket interval in seconds
    pub fn get_bucket_seconds(&self) -> i64 {
        if let Some(ref store) = self.settings_store {
            store.get().bucket_seconds as i64
        } else {
            30 // Default to 30 seconds
        }
    }

    /// Get current latency window setting
    pub fn get_latency_window_minutes(&self) -> u64 {
        if let Some(ref store) = self.settings_store {
            store
                .get()
                .latency_window_minutes
        } else {
            60 // Default to 60 minutes
        }
    }

    /// Get recent connections (last N)
    pub async fn get_recent_connections(
        &self,
        limit: usize,
    ) -> Vec<ConnectionMetric> {
        // Check cache first (configurable TTL)
        {
            let cache_time = self
                .cached_recent_connections_time
                .read()
                .await;
            if let Some(last_update) = *cache_time
                && (Utc::now() - last_update).num_milliseconds() < self.cache_ttl_ms
            {
                return self
                    .cached_recent_connections
                    .read()
                    .await
                    .clone();
            }
        }

        // Cache miss - fetch and update
        let connections = self.connections.read().await;
        let start = if connections.len() > limit {
            connections.len() - limit
        } else {
            0
        };
        let recent = connections[start..].to_vec();
        drop(connections);

        // Update cache
        *self
            .cached_recent_connections
            .write()
            .await = recent.clone();
        *self
            .cached_recent_connections_time
            .write()
            .await = Some(Utc::now());

        recent
    }

    /// Get timestamps of connections matching filters
    pub async fn get_matching_timestamps(
        &self,
        channel_id: Option<&str>,
        gateway_id: Option<&str>,
        identity_did: Option<&str>,
    ) -> std::collections::HashSet<i64> {
        let connections = self.connections.read().await;
        let mut matching_timestamps = std::collections::HashSet::new();

        for conn in connections.iter() {
            let mut matches = true;

            // Apply channel filter
            if let Some(channel_id) = channel_id
                && conn.channel_config_id != channel_id
            {
                matches = false;
            }

            // Apply gateway filter (check source or destination)
            if let Some(gateway_id) = gateway_id
                && conn.source != gateway_id
                && conn.destination != gateway_id
            {
                matches = false;
            }

            // Apply identity filter
            if let Some(identity_did) = identity_did {
                if let Some(ref hash) = conn.identity_hash {
                    if hash != identity_did {
                        matches = false;
                    }
                } else {
                    matches = false;
                }
            }

            if matches {
                matching_timestamps.insert(conn.timestamp.timestamp());
            }
        }

        matching_timestamps
    }

    /// Build time series from connections matching the specified filters
    pub async fn get_filtered_time_series(
        &self,
        interval_seconds: i64,
        channel_id: Option<&str>,
        _gateway_id: Option<&str>,
        identity_did: Option<&str>,
        pipe_id: Option<&str>,
    ) -> Vec<TimeSeriesPoint> {
        // Protect against division by zero
        if interval_seconds <= 0 {
            eprintln!("ERROR: Invalid interval_seconds={}, must be > 0", interval_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        // Filter connections based on criteria
        let filtered_connections: Vec<_> = connections
            .iter()
            .filter(|conn| {
                // When pipe_id is specified, only include pipe metrics
                if let Some(pid) = pipe_id {
                    return conn.metric_type == super::types::MetricType::Pipe
                        && conn
                            .pipe_id
                            .as_ref()
                            .is_some_and(|id| id == pid);
                }

                // When channel_id is specified, only include channel metrics
                let channel_match = channel_id.is_none_or(|id| {
                    conn.metric_type == super::types::MetricType::Channel && conn.channel_config_id == id
                });
                // Note: gateway_id filtering not supported as ConnectionMetric doesn't track gateway
                let identity_match = identity_did.is_none_or(|did| {
                    conn.identity_hash
                        .as_ref()
                        .is_some_and(|hash| hash == did)
                });
                channel_match && identity_match
            })
            .collect();

        // Filter events based on channel
        let filtered_events: Vec<_> = events
            .iter()
            .filter(|event| channel_id.is_none_or(|id| event.channel_config_id == id))
            .collect();

        if filtered_connections.is_empty() && filtered_events.is_empty() {
            return vec![];
        }

        // Use connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Initialize empty buckets
        let mut buckets = vec![TimeBucketAccum::default(); num_buckets];

        // Populate connection counts
        for conn in filtered_connections.iter() {
            let conn_epoch = conn.timestamp.timestamp();
            // Allow connections up to now, not just aligned_end (which is the current bucket start)
            if conn_epoch < aligned_start || conn_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((conn_epoch - aligned_start) / interval_seconds) as usize;
            if bucket_index < num_buckets {
                // Bytes/tokens accrue from every datapoint (both round-trip sides).
                buckets[bucket_index].add_transfer(conn);

                // Count one event per round-trip (see get_time_series): skip the
                // Response side so throughput is not doubled.
                if conn.direction == ConnectionDirection::Response {
                    continue;
                }
                buckets[bucket_index].add_connection(conn.status);
            }
        }

        // Add rule validation events
        for event in filtered_events.iter() {
            let event_epoch = event.timestamp.timestamp();
            // Allow events up to now, not just aligned_end
            if event_epoch < aligned_start || event_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((event_epoch - aligned_start) / interval_seconds) as usize;
            if bucket_index < num_buckets {
                if event.accepted {
                    buckets[bucket_index].rule_accepts += 1;
                } else {
                    buckets[bucket_index].rule_denies += 1;
                }
            }
        }

        // Convert to TimeSeriesPoint
        buckets
            .into_iter()
            .enumerate()
            .map(|(i, accum)| {
                let bucket_epoch = aligned_start + (i as i64 * interval_seconds);
                let timestamp = DateTime::from_timestamp(bucket_epoch, 0)
                    .unwrap_or_else(Utc::now)
                    .to_rfc3339();

                accum.into_point(timestamp)
            })
            .collect()
    }

    /// Get latency statistics by channel and source-destination pairs
    pub async fn get_latency_stats(&self) -> Vec<LatencyStats> {
        let connections = self.connections.read().await;

        // Group connections by (channel_config_id, source, destination)
        let mut latency_map: HashMap<(String, String, String), Vec<u64>> = HashMap::new();

        for conn in connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let key = (conn.channel_config_id.clone(), conn.source.clone(), conn.destination.clone());
                latency_map
                    .entry(key)
                    .or_default()
                    .push(latency);
            }
        }

        // Calculate statistics for each group
        latency_map
            .into_iter()
            .map(|((channel_config_id, source, destination), mut latencies)| {
                latencies.sort_unstable();

                let count = latencies.len();
                let sum: u64 = latencies.iter().sum();
                let avg = if count > 0 {
                    sum as f64 / count as f64
                } else {
                    0.0
                };

                let min = *latencies
                    .first()
                    .unwrap_or(&0);
                let max = *latencies.last().unwrap_or(&0);

                let p50 = percentile(&latencies, 50);
                let p95 = percentile(&latencies, 95);
                let p99 = percentile(&latencies, 99);

                LatencyStats {
                    channel_config_id,
                    source,
                    destination,
                    avg_latency_ms: avg,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    sample_count: count,
                }
            })
            .collect()
    }

    /// Build filtered latency time series from connections matching the specified filters
    pub async fn get_filtered_latency_time_series(
        &self,
        bucket_seconds: i64,
        channel_id: Option<&str>,
        _gateway_id: Option<&str>,
        identity_did: Option<&str>,
        pipe_id: Option<&str>,
    ) -> Vec<LatencyTimeSeriesPoint> {
        // Protect against division by zero
        if bucket_seconds <= 0 {
            eprintln!("ERROR: Invalid bucket_seconds={}, must be > 0", bucket_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;

        // Filter connections based on criteria
        let filtered_connections: Vec<_> = connections
            .iter()
            .filter(|conn| {
                // When pipe_id is specified, only include pipe metrics
                if let Some(pid) = pipe_id {
                    return conn.metric_type == super::types::MetricType::Pipe
                        && conn
                            .pipe_id
                            .as_ref()
                            .is_some_and(|id| id == pid)
                        && conn.latency_ms.is_some();
                }

                // When channel_id is specified, only include channel metrics
                let channel_match = channel_id.is_none_or(|id| {
                    conn.metric_type == super::types::MetricType::Channel && conn.channel_config_id == id
                });
                // Note: gateway_id filtering not supported as ConnectionMetric doesn't track gateway
                let identity_match = identity_did.is_none_or(|did| {
                    conn.identity_hash
                        .as_ref()
                        .is_some_and(|hash| hash == did)
                });
                channel_match && identity_match && conn.latency_ms.is_some()
            })
            .collect();

        if filtered_connections.is_empty() {
            return vec![];
        }

        // Use connections window
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / bucket_seconds) * bucket_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / bucket_seconds;
        let aligned_start = aligned_end - (desired_buckets * bucket_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Group latencies by bucket
        let mut bucket_latencies: Vec<Vec<u64>> = vec![Vec::new(); num_buckets];

        for conn in filtered_connections.iter() {
            let conn_epoch = conn.timestamp.timestamp();
            // Allow connections up to now, not just aligned_end (which is the current bucket start)
            if conn_epoch < aligned_start || conn_epoch > now_epoch {
                continue;
            }

            let bucket_index = ((conn_epoch - aligned_start) / bucket_seconds) as usize;
            if bucket_index < num_buckets
                && let Some(latency) = conn.latency_ms
            {
                bucket_latencies[bucket_index].push(latency);
            }
        }

        // Calculate percentiles for each bucket
        bucket_latencies
            .into_iter()
            .enumerate()
            .map(|(i, mut latencies)| {
                let bucket_epoch = aligned_start + (i as i64 * bucket_seconds);
                let timestamp = DateTime::from_timestamp(bucket_epoch, 0)
                    .unwrap_or_else(Utc::now)
                    .to_rfc3339();

                if latencies.is_empty() {
                    LatencyTimeSeriesPoint {
                        timestamp,
                        avg_latency_ms: 0.0,
                        p50_latency_ms: 0,
                        p95_latency_ms: 0,
                        p99_latency_ms: 0,
                        min_latency_ms: 0,
                        max_latency_ms: 0,
                        sample_count: 0,
                    }
                } else {
                    latencies.sort_unstable();
                    let sum: u64 = latencies.iter().sum();
                    let avg = sum as f64 / latencies.len() as f64;
                    LatencyTimeSeriesPoint {
                        timestamp,
                        avg_latency_ms: avg,
                        p50_latency_ms: percentile(&latencies, 50),
                        p95_latency_ms: percentile(&latencies, 95),
                        p99_latency_ms: percentile(&latencies, 99),
                        min_latency_ms: *latencies
                            .first()
                            .unwrap_or(&0),
                        max_latency_ms: *latencies.last().unwrap_or(&0),
                        sample_count: latencies.len(),
                    }
                }
            })
            .collect()
    }

    /// Latency time series for LLM surface (pipe) executions only.
    ///
    /// The dashboard latency chart shows LLM latency over time, so only
    /// `MetricType::Pipe` connections are aggregated here; channel/gateway
    /// connections are excluded.
    pub async fn get_pipe_latency_time_series(
        &self,
        bucket_seconds: i64,
    ) -> Vec<LatencyTimeSeriesPoint> {
        // Protect against division by zero
        if bucket_seconds <= 0 {
            eprintln!("ERROR: Invalid bucket_seconds={}, must be > 0", bucket_seconds);
            return vec![];
        }

        let connections = self.connections.read().await;

        if connections.is_empty() {
            return vec![];
        }

        // Use connections window instead of all historical data
        let now = Utc::now();
        let window_minutes = self.get_connections_window_minutes();
        let window_start = now - chrono::Duration::minutes(window_minutes as i64);

        // Filter connections to window, LLM/pipe executions only
        let windowed_connections: Vec<_> = connections
            .iter()
            .filter(|c| c.timestamp >= window_start && c.metric_type == super::types::MetricType::Pipe)
            .collect();

        if windowed_connections.is_empty() {
            return vec![];
        }

        // Use the provided bucket_seconds instead of calculating
        let interval_seconds = bucket_seconds;

        // Derive aligned_start from aligned_end so both edges move in lockstep,
        // producing a stable number of buckets and preventing graph jitter.
        let now_epoch = now.timestamp();
        let aligned_end = (now_epoch / interval_seconds) * interval_seconds;
        let desired_buckets = (window_minutes as i64 * 60) / interval_seconds;
        let aligned_start = aligned_end - (desired_buckets * interval_seconds);
        let num_buckets = (desired_buckets + 1) as usize;

        // Pre-create all buckets with empty latency vectors, using fixed epoch-aligned timestamps
        let mut time_buckets: Vec<(i64, Vec<u64>)> = Vec::with_capacity(num_buckets);
        for i in 0..num_buckets {
            let bucket_seconds = aligned_start + (i as i64 * interval_seconds);
            time_buckets.push((bucket_seconds, Vec::new()));
        }

        // Populate buckets with latencies from connections in window
        for conn in windowed_connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let seconds_since_epoch = conn.timestamp.timestamp();
                let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;

                // Find the bucket and add latency
                if let Some(bucket) = time_buckets
                    .iter_mut()
                    .find(|(bs, _)| *bs == bucket_seconds)
                {
                    bucket.1.push(latency);
                }
            }
        }

        // Calculate statistics for each bucket
        let time_series: Vec<LatencyTimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(bucket_seconds, mut latencies)| {
                let (avg, p50, p95, p99, min, max, count) = if latencies.is_empty() {
                    // Empty bucket - all zeros
                    (0.0, 0, 0, 0, 0, 0, 0)
                } else {
                    latencies.sort_unstable();

                    let count = latencies.len();
                    let sum: u64 = latencies.iter().sum();
                    let avg = sum as f64 / count as f64;

                    let min = *latencies.first().unwrap();
                    let max = *latencies.last().unwrap();

                    let p50 = percentile(&latencies, 50);
                    let p95 = percentile(&latencies, 95);
                    let p99 = percentile(&latencies, 99);

                    (avg, p50, p95, p99, min, max, count)
                };

                let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
                let timestamp = bucket_time.to_rfc3339();

                LatencyTimeSeriesPoint {
                    timestamp,
                    avg_latency_ms: avg,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    sample_count: count,
                }
            })
            .collect();

        time_series
    }

    /// Get time series data filtered by channel config ID
    pub async fn get_time_series_by_channel(
        &self,
        channel_config_id: &str,
    ) -> Vec<TimeSeriesPoint> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;

        // Filter connections by channel
        let channel_connections: Vec<&ConnectionMetric> = connections
            .iter()
            .filter(|conn| conn.channel_config_id == channel_config_id)
            .collect();

        // Filter events by channel
        let channel_events: Vec<&RuleValidationEvent> = events
            .iter()
            .filter(|event| event.channel_config_id == channel_config_id)
            .collect();

        if channel_connections.is_empty() && channel_events.is_empty() {
            return vec![];
        }

        // Calculate time range
        let oldest = channel_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let newest = channel_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_seconds = if duration_minutes < 10 {
            30 // Less than 10 minutes: 30-second intervals
        } else if duration_minutes < 60 {
            60 // 10-60 minutes: 1-minute intervals
        } else {
            300 // Over 1 hour: 5-minute intervals
        };

        // Group connections by time bucket
        let mut time_buckets: HashMap<String, TimeBucketAccum> = HashMap::new();

        for conn in channel_connections.iter() {
            let seconds_since_epoch = conn.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_default();

            // Bytes/tokens accrue from every datapoint (both round-trip sides).
            entry.add_transfer(conn);

            // Count one event per round-trip (see get_time_series): skip the
            // Response side so throughput is not doubled.
            if conn.direction == ConnectionDirection::Response {
                continue;
            }
            entry.add_connection(conn.status);
        }

        // Add rule validation events to time buckets
        for event in channel_events.iter() {
            let seconds_since_epoch = event.timestamp.timestamp();
            let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
            let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);

            let bucket_key = bucket_time.to_rfc3339();
            let entry = time_buckets
                .entry(bucket_key)
                .or_default();
            if event.accepted {
                entry.rule_accepts += 1;
            } else {
                entry.rule_denies += 1;
            }
        }

        // Convert to sorted vector
        let mut time_series: Vec<TimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(timestamp, accum)| accum.into_point(timestamp))
            .collect();

        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Get latency time series filtered by channel config ID
    pub async fn get_latency_time_series_by_channel(
        &self,
        channel_config_id: &str,
    ) -> Vec<LatencyTimeSeriesPoint> {
        let connections = self.connections.read().await;

        // Filter connections by channel
        let channel_connections: Vec<&ConnectionMetric> = connections
            .iter()
            .filter(|conn| conn.channel_config_id == channel_config_id)
            .collect();

        if channel_connections.is_empty() {
            return vec![];
        }

        // Calculate time range
        let oldest = channel_connections
            .first()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let newest = channel_connections
            .last()
            .map(|c| c.timestamp)
            .unwrap_or_else(Utc::now);
        let duration_minutes = (newest - oldest).num_minutes();

        // Select interval based on data range
        let interval_seconds = if duration_minutes < 10 {
            30 // Less than 10 minutes: 30-second intervals
        } else if duration_minutes < 60 {
            60 // 10-60 minutes: 1-minute intervals
        } else {
            300 // Over 1 hour: 5-minute intervals
        };

        // Group latencies by time bucket
        let mut time_buckets: HashMap<i64, Vec<u64>> = HashMap::new();

        for conn in channel_connections.iter() {
            if let Some(latency) = conn.latency_ms {
                let seconds_since_epoch = conn.timestamp.timestamp();
                let bucket_seconds = (seconds_since_epoch / interval_seconds) * interval_seconds;
                time_buckets
                    .entry(bucket_seconds)
                    .or_default()
                    .push(latency);
            }
        }

        // Calculate statistics for each bucket
        let mut time_series: Vec<LatencyTimeSeriesPoint> = time_buckets
            .into_iter()
            .map(|(bucket_seconds, mut latencies)| {
                latencies.sort_unstable();

                let count = latencies.len();
                let sum: u64 = latencies.iter().sum();
                let avg = if count > 0 {
                    sum as f64 / count as f64
                } else {
                    0.0
                };

                let min = *latencies
                    .first()
                    .unwrap_or(&0);
                let max = *latencies.last().unwrap_or(&0);

                let p50 = percentile(&latencies, 50);
                let p95 = percentile(&latencies, 95);
                let p99 = percentile(&latencies, 99);

                let bucket_time = DateTime::from_timestamp(bucket_seconds, 0).unwrap_or_else(Utc::now);
                let timestamp = bucket_time.to_rfc3339();

                LatencyTimeSeriesPoint {
                    timestamp,
                    avg_latency_ms: avg,
                    p50_latency_ms: p50,
                    p95_latency_ms: p95,
                    p99_latency_ms: p99,
                    min_latency_ms: min,
                    max_latency_ms: max,
                    sample_count: count,
                }
            })
            .collect();

        // Sort by timestamp
        time_series.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        time_series
    }

    /// Start periodic background task to save metrics and cleanup old data
    fn start_periodic_save(
        &self,
        interval: std::time::Duration,
    ) {
        let connections = self.connections.clone();
        let rule_metrics = self.rule_metrics.clone();
        let rule_validation_events = self
            .rule_validation_events
            .clone();
        let backend = self.backend.clone();
        let handle_mutex = self.save_task_handle.clone();
        let dirty = self.dirty.clone();
        let retention_minutes = self.metrics_retention_minutes;
        let max_connections = self.max_connections;

        let handle = tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            loop {
                interval_timer.tick().await;

                // Cleanup old connections and enforce count cap
                {
                    let retention_cutoff = Utc::now() - chrono::Duration::minutes(retention_minutes as i64);
                    let mut conns = connections.write().await;
                    let before_len = conns.len();
                    conns.retain(|conn| conn.timestamp >= retention_cutoff);
                    // Enforce count cap after time-based cleanup
                    if conns.len() > max_connections {
                        let to_remove = conns.len() - max_connections;
                        conns.drain(0..to_remove);
                    }
                    // Shrink the Vec if it has significant excess capacity
                    // to return memory to the allocator
                    if conns.capacity() > conns.len() * 2 + 100 {
                        let shrink_to = conns.len() + 100; // Keep some extra capacity to avoid frequent shrinking
                        conns.shrink_to(shrink_to);
                    }
                    let after_len = conns.len();
                    if before_len != after_len {
                        trace!("Cleaned up {} old connection metrics", before_len - after_len);
                    }
                }

                // Only persist if data has changed (dirty flag is set), and only
                // on the Active instance, which owns the shared file.
                let is_dirty = *dirty.read().await;
                if !is_dirty || !crate::server::mode::is_ready_to_serve() {
                    continue;
                }

                if let Some(ref backend) = backend {
                    let connections_snap = connections
                        .read()
                        .await
                        .clone();
                    let metrics_snap = rule_metrics
                        .read()
                        .await
                        .clone();
                    let events_snap = rule_validation_events
                        .read()
                        .await
                        .clone();

                    match backend
                        .persist(&connections_snap, &metrics_snap, &events_snap)
                        .await
                    {
                        Ok(_) => {
                            // Clear dirty flag after successful save (for file backends)
                            if is_dirty {
                                *dirty.write().await = false;
                            }
                        }
                        Err(e) => {
                            eprintln!("Warning: Failed to persist metrics to {}: {}", backend.name(), e);
                            // Keep dirty flag set so we retry on next interval
                        }
                    }
                }
            }
        });

        // Store the handle so we can cancel it later if needed
        tokio::spawn(async move {
            *handle_mutex.lock().await = Some(handle);
        });
    }

    /// Save metrics to file
    async fn save_to_file(
        path: &std::path::Path,
        connections: &[ConnectionMetric],
        _rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> std::io::Result<()> {
        use tokio::io::AsyncWriteExt;

        // Create directory if it doesn't exist
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }

        // Convert flat data to hierarchical format organized by channel
        let mut connections_map: HashMap<String, SurfaceMetricsData> = HashMap::new();

        // Add connections organized by source -> identity -> destination -> trace_id
        // For both requests and responses, we want them grouped by the CLIENT source IP
        for conn in connections {
            // Determine the actual client source IP
            // Request: source = client, dest = target -> use source as-is
            // Response: source = target, dest = client -> swap to use client as "source"
            let (client_source, target_dest) = if conn.direction == ConnectionDirection::Response {
                // Response: source is target, dest is client - swap them
                (conn.destination.clone(), conn.source.clone())
            } else {
                // Request: source is client, dest is target - use as-is
                (conn.source.clone(), conn.destination.clone())
            };

            let channel_data = connections_map
                .entry(conn.channel_config_id.clone())
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            let source_map = channel_data
                .sources
                .entry(client_source)
                .or_default();
            let identity_key = conn
                .identity_hash
                .clone()
                .unwrap_or_else(|| "anonymous".to_string());
            let identity_map = source_map
                .entry(identity_key)
                .or_default();
            let dest_map = identity_map
                .entry(target_dest)
                .or_default();
            let trace_vec = dest_map
                .entry(conn.trace_id.clone())
                .or_default();
            trace_vec.push(ConnectionDataPoint {
                timestamp: conn.timestamp,
                status: conn.status,
                latency_ms: conn.latency_ms,
                identity_hash: conn.identity_hash.clone(),
                direction: conn.direction,
                ucp_operation: conn.ucp_operation.clone(),
                variant_alias: conn.variant_alias.clone(),
                metric_type: conn.metric_type,
                pipe_id: conn.pipe_id.clone(),
                pipe_name: conn.pipe_name.clone(),
                llm_provider: conn.llm_provider.clone(),
                llm_model: conn.llm_model.clone(),
                llm_input_tokens: conn.llm_input_tokens,
                llm_output_tokens: conn.llm_output_tokens,
                llm_total_tokens: conn.llm_total_tokens,
                llm_cost: conn.llm_cost,
                correlation_id: conn.correlation_id.clone(),
                agent_identity: conn.agent_identity.clone(),
                pipe_gateway_processing_ms: conn.pipe_gateway_processing_ms,
                pipe_target_processing_ms: conn.pipe_target_processing_ms,
                channel_request_latency_ms: conn.channel_request_latency_ms,
                channel_response_latency_ms: conn.channel_response_latency_ms,
                request_bytes: conn.request_bytes,
                response_bytes: conn.response_bytes,
                retry_count: conn.retry_count,
                stage_usage: conn.stage_usage.clone(),
                total_latency_ms: conn.total_latency_ms,
                cache_hit: conn.cache_hit,
                cache_saved_cost: conn.cache_saved_cost,
                cache_saved_tokens: conn.cache_saved_tokens,
            });
        }

        // Add rule triggers to their respective channels
        for event in rule_validation_events {
            let channel_data = connections_map
                .entry(
                    event
                        .channel_config_id
                        .clone(),
                )
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            channel_data
                .rule_triggers
                .push(RuleValidationDataPoint {
                    timestamp: event.timestamp,
                    accepted: event.accepted,
                });
        }

        // Package all metrics data in hierarchical format
        let metrics_data = MetricsData { connections: connections_map };

        // Serialize to JSON
        let json = serde_json::to_string_pretty(&metrics_data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Write to temporary file first, then atomically rename
        let temp_path = path.with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&temp_path).await?;
        file.write_all(json.as_bytes())
            .await?;
        file.flush().await?;
        drop(file); // Close file before rename

        // Atomic rename
        tokio::fs::rename(&temp_path, path).await?;

        Ok(())
    }

    /// Load metrics from file (synchronous version for constructor)
    fn load_from_file_sync(
        &mut self,
        path: &std::path::Path,
    ) -> std::io::Result<()> {
        use std::io::Read;

        if !path.exists() {
            return Ok(()); // No file yet, not an error
        }

        let mut file = std::fs::File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let cutoff_time = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);

        let metrics_data = serde_json::from_str::<MetricsData>(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        // Load hierarchical format - convert to flat for in-memory storage
        if let Ok(mut connections) = self.connections.try_write() {
            for (channel_id, channel_data) in &metrics_data.connections {
                for (source, identities) in &channel_data.sources {
                    for (identity, destinations) in identities {
                        for (destination, traces) in destinations {
                            for (trace_id, data_points) in traces {
                                for point in data_points {
                                    if point.timestamp >= cutoff_time {
                                        connections.push(ConnectionMetric {
                                            timestamp: point.timestamp,
                                            channel_config_id: channel_id.clone(),
                                            source: source.clone(),
                                            destination: destination.clone(),
                                            status: point.status,
                                            latency_ms: point.latency_ms,
                                            identity_hash: if identity == "anonymous" {
                                                None
                                            } else {
                                                Some(identity.clone())
                                            },
                                            direction: point.direction,
                                            trace_id: trace_id.clone(),
                                            ucp_operation: point.ucp_operation.clone(),
                                            variant_alias: point.variant_alias.clone(),
                                            metric_type: point.metric_type,
                                            pipe_id: point.pipe_id.clone(),
                                            pipe_name: point.pipe_name.clone(),
                                            llm_provider: point.llm_provider.clone(),
                                            llm_model: point.llm_model.clone(),
                                            llm_input_tokens: point.llm_input_tokens,
                                            llm_output_tokens: point.llm_output_tokens,
                                            llm_total_tokens: point.llm_total_tokens,
                                            llm_cost: point.llm_cost,
                                            correlation_id: point.correlation_id.clone(),
                                            agent_identity: point.agent_identity.clone(),
                                            pipe_gateway_processing_ms: point.pipe_gateway_processing_ms,
                                            pipe_target_processing_ms: point.pipe_target_processing_ms,
                                            channel_request_latency_ms: point.channel_request_latency_ms,
                                            channel_response_latency_ms: point.channel_response_latency_ms,
                                            request_bytes: point.request_bytes,
                                            response_bytes: point.response_bytes,
                                            retry_count: point.retry_count,
                                            stage_usage: point.stage_usage.clone(),
                                            total_latency_ms: point.total_latency_ms,
                                            cache_hit: point.cache_hit,
                                            cache_saved_cost: point.cache_saved_cost,
                                            cache_saved_tokens: point.cache_saved_tokens,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Trim to max_connections if needed
            if connections.len() > self.max_connections {
                let excess = connections.len() - self.max_connections;
                connections.drain(0..excess);
            }
        }

        // Load rule triggers and rebuild rule_metrics
        if let Ok(mut events) = self
            .rule_validation_events
            .try_write()
        {
            for (channel_id, channel_data) in &metrics_data.connections {
                for validation in &channel_data.rule_triggers {
                    if validation.timestamp >= cutoff_time {
                        events.push(RuleValidationEvent {
                            timestamp: validation.timestamp,
                            channel_config_id: channel_id.clone(),
                            accepted: validation.accepted,
                        });
                    }
                }
            }

            // Trim to max_connections if needed
            if events.len() > self.max_connections {
                let excess = events.len() - self.max_connections;
                events.drain(0..excess);
            }
        }

        // Rebuild rule_metrics from rule_triggers
        if let Ok(mut rule_metrics) = self.rule_metrics.try_write() {
            rule_metrics.clear();
            for (channel_id, channel_data) in &metrics_data.connections {
                let mut accept_count = 0;
                let mut deny_count = 0;
                for validation in &channel_data.rule_triggers {
                    if validation.accepted {
                        accept_count += 1;
                    } else {
                        deny_count += 1;
                    }
                }
                if accept_count > 0 || deny_count > 0 {
                    rule_metrics.insert(
                        channel_id.clone(),
                        RuleMetric {
                            channel_config_id: channel_id.clone(),
                            accept_count,
                            deny_count,
                        },
                    );
                }
            }
        }

        Ok(())
    }

    /// Record a rule validation result (accept or deny)
    pub async fn record_rule_validation(
        &self,
        channel_config_id: String,
        accepted: bool,
    ) {
        let ops_samples = crate::metrics::ops_telemetry::samples_for_rule(&channel_config_id, accepted);
        Self::spawn_ops_record(ops_samples);

        // Update aggregate counters
        let mut metrics = self
            .rule_metrics
            .write()
            .await;
        let metric = metrics
            .entry(channel_config_id.clone())
            .or_insert(RuleMetric {
                channel_config_id: channel_config_id.clone(),
                accept_count: 0,
                deny_count: 0,
            });

        if accepted {
            metric.accept_count += 1;
        } else {
            metric.deny_count += 1;
        }
        drop(metrics);

        // Track in Prometheus metrics
        crate::metrics::backends::prometheus::track_rule_validation(accepted);

        // Store timestamped event
        let event = RuleValidationEvent {
            timestamp: Utc::now(),
            channel_config_id,
            accepted,
        };

        let mut events = self
            .rule_validation_events
            .write()
            .await;
        events.push(event);

        // Keep only the most recent events
        if events.len() > self.max_connections {
            let excess = events.len() - self.max_connections;
            events.drain(0..excess);
        }
        drop(events);

        // Mark metrics as dirty
        *self.dirty.write().await = true;

        // Metrics are now saved periodically by the background task
    }

    /// Get rule validation metrics for a specifi (includes rule_triggers per channel)
    pub async fn get_hierarchical_connections(&self) -> HashMap<String, SurfaceMetricsData> {
        let connections = self.connections.read().await;
        let events = self
            .rule_validation_events
            .read()
            .await;
        let mut hierarchical: HashMap<String, SurfaceMetricsData> = HashMap::new();

        // Add connections organized by: channel -> source -> identity -> destination -> trace_id
        for conn in connections.iter() {
            let channel_data = hierarchical
                .entry(conn.channel_config_id.clone())
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            let source_map = channel_data
                .sources
                .entry(conn.source.clone())
                .or_default();
            let identity_key = conn
                .identity_hash
                .clone()
                .unwrap_or_else(|| "anonymous".to_string());
            let identity_map = source_map
                .entry(identity_key)
                .or_default();
            let dest_map = identity_map
                .entry(conn.destination.clone())
                .or_default();
            let trace_vec = dest_map
                .entry(conn.trace_id.clone())
                .or_default();
            trace_vec.push(ConnectionDataPoint {
                timestamp: conn.timestamp,
                status: conn.status,
                latency_ms: conn.latency_ms,
                identity_hash: conn.identity_hash.clone(),
                direction: conn.direction,
                ucp_operation: conn.ucp_operation.clone(),
                variant_alias: conn.variant_alias.clone(),
                metric_type: conn.metric_type,
                pipe_id: conn.pipe_id.clone(),
                pipe_name: conn.pipe_name.clone(),
                llm_provider: conn.llm_provider.clone(),
                llm_model: conn.llm_model.clone(),
                llm_input_tokens: conn.llm_input_tokens,
                llm_output_tokens: conn.llm_output_tokens,
                llm_total_tokens: conn.llm_total_tokens,
                llm_cost: conn.llm_cost,
                correlation_id: conn.correlation_id.clone(),
                agent_identity: conn.agent_identity.clone(),
                pipe_gateway_processing_ms: conn.pipe_gateway_processing_ms,
                pipe_target_processing_ms: conn.pipe_target_processing_ms,
                channel_request_latency_ms: conn.channel_request_latency_ms,
                channel_response_latency_ms: conn.channel_response_latency_ms,
                request_bytes: conn.request_bytes,
                response_bytes: conn.response_bytes,
                retry_count: conn.retry_count,
                stage_usage: conn.stage_usage.clone(),
                total_latency_ms: conn.total_latency_ms,
                cache_hit: conn.cache_hit,
                cache_saved_cost: conn.cache_saved_cost,
                cache_saved_tokens: conn.cache_saved_tokens,
            });
        }

        // Add rule triggers to their channels
        for event in events.iter() {
            let channel_data = hierarchical
                .entry(
                    event
                        .channel_config_id
                        .clone(),
                )
                .or_insert_with(|| SurfaceMetricsData {
                    sources: HashMap::new(),
                    rule_triggers: Vec::new(),
                });
            channel_data
                .rule_triggers
                .push(RuleValidationDataPoint {
                    timestamp: event.timestamp,
                    accepted: event.accepted,
                });
        }

        hierarchical
    }

    /// Get rule validation metrics for a specific channel
    pub async fn get_rule_metrics(
        &self,
        channel_config_id: &str,
    ) -> Option<RuleMetric> {
        let metrics = self.rule_metrics.read().await;
        metrics
            .get(channel_config_id)
            .cloned()
    }

    /// Get all rule validation metrics
    pub async fn get_all_rule_metrics(&self) -> Vec<RuleMetric> {
        let metrics = self.rule_metrics.read().await;
        metrics
            .values()
            .cloned()
            .collect()
    }

    /// Get the last connection status for a specific channel
    pub async fn get_last_status(
        &self,
        channel_config_id: &str,
    ) -> Option<ConnectionStatus> {
        let last_status = self
            .last_status_by_channel
            .read()
            .await;
        last_status
            .get(channel_config_id)
            .cloned()
    }

    /// Truncate metrics older than retention period and return stats
    pub async fn truncate_old_metrics(&self) -> Result<TruncateMetricsResult, String> {
        let cutoff_time = Utc::now() - chrono::Duration::minutes(self.metrics_retention_minutes as i64);

        let connections_removed;
        let connections_retained;
        let events_removed;
        let events_retained;

        // Filter connections
        {
            let mut connections = self.connections.write().await;
            let original_len = connections.len();
            connections.retain(|c| c.timestamp >= cutoff_time);
            connections_removed = original_len - connections.len();
            connections_retained = connections.len();
        }

        // Filter rule validation events
        {
            let mut events = self
                .rule_validation_events
                .write()
                .await;
            let original_len = events.len();
            events.retain(|e| e.timestamp >= cutoff_time);
            events_removed = original_len - events.len();
            events_retained = events.len();
        }

        // Save the filtered metrics to disk
        if let Some(path) = &self.storage_path {
            let connections = self
                .connections
                .read()
                .await
                .clone();
            let rule_metrics = self
                .rule_metrics
                .read()
                .await
                .clone();
            let events = self
                .rule_validation_events
                .read()
                .await
                .clone();
            let path_clone = path.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::save_to_file(&path_clone, &connections, &rule_metrics, &events).await {
                    eprintln!("Failed to save truncated metrics: {}", e);
                }
            });
        }

        Ok(TruncateMetricsResult {
            connections_removed,
            connections_retained,
            events_removed,
            events_retained,
        })
    }
}

/// Calculate percentile from sorted latencies
fn percentile(
    sorted_latencies: &[u64],
    p: u8,
) -> u64 {
    if sorted_latencies.is_empty() {
        return 0;
    }

    let index = ((p as f64 / 100.0) * (sorted_latencies.len() as f64 - 1.0)).round() as usize;
    sorted_latencies[index.min(sorted_latencies.len() - 1)]
}

impl Default for MetricsStore {
    fn default() -> Self {
        Self::new(1000)
    }
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for MetricsStore {
    /// Continue the request log the previous Active wrote instead of
    /// overwriting it with this instance's startup copy. A storage error is
    /// returned so the reload is retried; a log that cannot be parsed starts
    /// empty, as at startup.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        let Some(ref backend) = self.backend else {
            return Ok(());
        };
        let snapshot = match backend.load().await {
            Ok(snapshot) => snapshot,
            Err(e) => {
                if let Some(io) = e.downcast_ref::<std::io::Error>()
                    && io.kind() != std::io::ErrorKind::NotFound
                {
                    return Err(std::io::Error::new(io.kind(), format!("metrics from {}: {e}", backend.name())));
                }
                tracing::warn!("Failed to reload metrics from {}: {}", backend.name(), e);
                crate::metrics::backends::types::MetricsSnapshot {
                    connections: Vec::new(),
                    rule_validation_events: Vec::new(),
                }
            }
        };
        *self.connections.write().await = snapshot.connections;
        *self
            .rule_validation_events
            .write()
            .await = snapshot.rule_validation_events;
        *self.dirty.write().await = false;
        for cache_time in [
            &self.pipe_stats_cache_time,
            &self.channel_stats_cache_time,
            &self.identity_channel_stats_cache_time,
            &self.cached_scalar_metrics_time,
            &self.cached_time_series_time,
            &self.cached_recent_connections_time,
        ] {
            *cache_time.write().await = None;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::MetricsStore;
    use crate::metrics::{ConnectionDirection, ConnectionStatus};

    #[tokio::test]
    async fn record_user_login_increments_prometheus_counter() {
        let store = MetricsStore::new(10);
        let role = "store_test_login_role";

        let before = crate::metrics::backends::prometheus::USER_LOGINS
            .with_label_values(&[role])
            .get();

        store
            .record_user_login(role)
            .await;

        let after = crate::metrics::backends::prometheus::USER_LOGINS
            .with_label_values(&[role])
            .get();

        assert_eq!(after, before + 1);
    }

    #[tokio::test]
    async fn reload_picks_up_the_log_another_instance_saved() {
        use crate::metrics::backends::MetricsBackend;
        use crate::server::mode::ReloadOnPromotion;

        let dir = tempfile::tempdir().unwrap();
        let standby = store_in(dir.path());
        let active = store_in(dir.path());
        record_channel_round_trip(&active, "ch-promoted", "t1", 10, 20, ConnectionStatus::Success).await;
        let connections = recorded_connections(&active, 2).await;
        crate::metrics::backends::FileMetricsBackend::new(
            dir.path()
                .join("metrics.json"),
        )
        .persist(&connections, &std::collections::HashMap::new(), &[])
        .await
        .unwrap();
        assert!(
            standby
                .connections
                .read()
                .await
                .is_empty()
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        let reloaded = standby
            .connections
            .read()
            .await
            .clone();
        assert_eq!(reloaded.len(), 2);
        assert!(
            reloaded
                .iter()
                .all(|c| c.channel_config_id == "ch-promoted")
        );
    }

    async fn recorded_connections(
        store: &MetricsStore,
        count: usize,
    ) -> Vec<crate::metrics::ConnectionMetric> {
        loop {
            let connections = store
                .connections
                .read()
                .await
                .clone();
            if connections.len() == count {
                return connections;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// A store backed by `dir/metrics.json` through the same multi-backend the
    /// server uses, without the periodic save, so nothing but the test writes
    /// the file.
    fn store_in(dir: &std::path::Path) -> MetricsStore {
        let file = std::sync::Arc::new(crate::metrics::backends::FileMetricsBackend::new(dir.join("metrics.json")));
        MetricsStore {
            backend: Some(std::sync::Arc::new(crate::metrics::backends::MultiBackend::new().add_backend(file))),
            ..MetricsStore::new(100)
        }
    }

    #[tokio::test]
    async fn reload_from_unreadable_storage_fails_and_keeps_the_log() {
        use crate::server::mode::ReloadOnPromotion;

        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        record_channel_round_trip(&store, "ch-kept", "t1", 10, 20, ConnectionStatus::Success).await;
        recorded_connections(&store, 2).await;
        std::fs::create_dir(
            dir.path()
                .join("metrics.json"),
        )
        .unwrap();

        let result = store
            .reload_from_storage()
            .await;

        assert!(result.is_err(), "a read error is retried, not read as an empty log");
        assert_eq!(
            store
                .connections
                .read()
                .await
                .len(),
            2
        );
    }

    #[tokio::test]
    async fn reload_from_an_unparseable_log_starts_empty() {
        use crate::server::mode::ReloadOnPromotion;

        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        record_channel_round_trip(&store, "ch-dropped", "t1", 10, 20, ConnectionStatus::Success).await;
        recorded_connections(&store, 2).await;
        std::fs::write(
            dir.path()
                .join("metrics.json"),
            "not json",
        )
        .unwrap();

        store
            .reload_from_storage()
            .await
            .unwrap();

        assert!(
            store
                .connections
                .read()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reload_from_a_log_that_is_not_utf8_starts_empty() {
        use crate::server::mode::ReloadOnPromotion;

        let dir = tempfile::tempdir().unwrap();
        let store = store_in(dir.path());
        record_channel_round_trip(&store, "ch-dropped", "t1", 10, 20, ConnectionStatus::Success).await;
        recorded_connections(&store, 2).await;
        std::fs::write(
            dir.path()
                .join("metrics.json"),
            [0xff, 0xfe, 0xfd],
        )
        .unwrap();

        store
            .reload_from_storage()
            .await
            .expect("an unparseable log does not hold readiness back");

        assert!(
            store
                .connections
                .read()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reload_without_a_backend_is_a_no_op() {
        use crate::server::mode::ReloadOnPromotion;

        let store = MetricsStore::new(10);
        store
            .reload_from_storage()
            .await
            .unwrap();
        assert!(
            store
                .connections
                .read()
                .await
                .is_empty()
        );
    }

    // Records one channel round-trip: a Request datapoint carrying
    // `request_bytes` and a Response datapoint carrying `response_bytes`,
    // mirroring how the message processor records inbound/outbound hops.
    async fn record_channel_round_trip(
        store: &MetricsStore,
        channel: &str,
        trace: &str,
        request_bytes: u64,
        response_bytes: u64,
        status: ConnectionStatus,
    ) {
        store
            .record_connection_with_bytes(
                channel.to_string(),
                "caller".to_string(),
                "target".to_string(),
                status,
                Some(1),
                None,
                ConnectionDirection::Request,
                format!("{trace}-req"),
                request_bytes,
                0,
                None,
                None,
                1,
                None,
            )
            .await;
        store
            .record_connection_with_bytes(
                channel.to_string(),
                "target".to_string(),
                "caller".to_string(),
                status,
                Some(1),
                None,
                ConnectionDirection::Response,
                format!("{trace}-resp"),
                0,
                response_bytes,
                None,
                None,
                1,
                None,
            )
            .await;
    }

    #[tokio::test]
    async fn channel_stats_sum_directional_bytes() {
        let store = MetricsStore::new(100);
        record_channel_round_trip(&store, "chan-a", "t1", 100, 250, ConnectionStatus::Success).await;
        record_channel_round_trip(&store, "chan-a", "t2", 50, 70, ConnectionStatus::Success).await;

        let stats = store
            .get_channel_stats()
            .await;
        let a = stats
            .iter()
            .find(|s| s.channel_config_id == "chan-a")
            .expect("chan-a stats present");

        assert_eq!(a.total_request_bytes, 150);
        assert_eq!(a.total_response_bytes, 320);
        assert_eq!(a.successful, 2);
    }

    #[tokio::test]
    async fn time_series_counts_round_trip_once() {
        let store = MetricsStore::new(100);
        // Three round-trips => six directional datapoints. Throughput must
        // report three connections, not six (Response side is not counted).
        for i in 0..3 {
            record_channel_round_trip(&store, "chan-b", &format!("t{i}"), 10, 20, ConnectionStatus::Success).await;
        }

        let series = store.get_time_series(1).await;
        let total: usize = series
            .iter()
            .map(|p| p.count)
            .sum();
        assert_eq!(total, 3, "expected one count per round-trip, got {total}");
    }

    #[tokio::test]
    async fn time_series_aggregates_directional_bytes() {
        let store = MetricsStore::new(100);
        // Two round-trips: request bytes land on the Request datapoint, response
        // bytes on the Response datapoint. The series must sum both directions
        // while still counting one connection per round-trip.
        record_channel_round_trip(&store, "chan-c", "t1", 100, 250, ConnectionStatus::Success).await;
        record_channel_round_trip(&store, "chan-c", "t2", 50, 70, ConnectionStatus::Success).await;

        let series = store.get_time_series(1).await;
        let req: u64 = series
            .iter()
            .map(|p| p.request_bytes)
            .sum();
        let resp: u64 = series
            .iter()
            .map(|p| p.response_bytes)
            .sum();
        let count: usize = series
            .iter()
            .map(|p| p.count)
            .sum();

        assert_eq!(req, 150, "request bytes summed across both round-trips");
        assert_eq!(resp, 320, "response bytes summed across both round-trips");
        assert_eq!(count, 2, "one connection counted per round-trip");
    }

    #[tokio::test]
    async fn filtered_time_series_sums_pipe_bytes_and_tokens() {
        let store = MetricsStore::new(100);
        for (req, resp, inp, out) in [(200u64, 800u64, 10u64, 40u64), (100, 300, 5, 20)] {
            store
                .record_pipe_execution(
                    "pipe-ts".to_string(),
                    Some("Pipe TS".to_string()),
                    "openai".to_string(),
                    "gpt-4o".to_string(),
                    ConnectionStatus::Success,
                    5,
                    None,
                    None,
                    inp,
                    out,
                    0.01,
                    Some("trace".to_string()),
                    None,
                    None,
                    req,
                    resp,
                    0,
                    None,
                )
                .await;
        }

        // Pipe executions dispatch to an async batch worker; wait until both land.
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = {
                let connections = store.connections.read().await;
                connections
                    .iter()
                    .filter(|c| c.pipe_id.as_deref() == Some("pipe-ts"))
                    .count()
            };
            if landed >= 2 {
                break;
            }
        }

        let series = store
            .get_filtered_time_series(30, None, None, None, Some("pipe-ts"))
            .await;

        let req: u64 = series
            .iter()
            .map(|p| p.request_bytes)
            .sum();
        let resp: u64 = series
            .iter()
            .map(|p| p.response_bytes)
            .sum();
        let inp: u64 = series
            .iter()
            .map(|p| p.input_tokens)
            .sum();
        let out: u64 = series
            .iter()
            .map(|p| p.output_tokens)
            .sum();
        let count: usize = series
            .iter()
            .map(|p| p.count)
            .sum();

        assert_eq!(req, 300, "pipe request bytes summed");
        assert_eq!(resp, 1100, "pipe response bytes summed");
        assert_eq!(inp, 15, "pipe input tokens summed");
        assert_eq!(out, 60, "pipe output tokens summed");
        assert_eq!(count, 2, "two pipe executions counted");
    }

    #[tokio::test]
    async fn pipe_stats_sum_and_average_bytes() {
        let store = MetricsStore::new(100);
        for (req, resp, inp, out) in [(200u64, 800u64, 10u64, 40u64), (100, 300, 5, 20)] {
            store
                .record_pipe_execution(
                    "pipe-x".to_string(),
                    Some("Pipe X".to_string()),
                    "openai".to_string(),
                    "gpt-4o".to_string(),
                    ConnectionStatus::Success,
                    5,
                    None,
                    None,
                    inp,
                    out,
                    0.01,
                    Some("trace".to_string()),
                    None,
                    None,
                    req,
                    resp,
                    0,
                    None,
                )
                .await;
        }

        // record_pipe_execution dispatches to an async batch worker, and
        // get_pipe_stats caches its result for ~1s. Yield until the worker has
        // drained the channel BEFORE the first stats call so the cached value
        // is computed from landed data rather than an empty snapshot.
        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = {
                let connections = store.connections.read().await;
                connections
                    .iter()
                    .filter(|c| c.pipe_id.as_deref() == Some("pipe-x"))
                    .count()
            };
            if landed >= 2 {
                break;
            }
        }
        let stats = store.get_pipe_stats().await;

        let x = stats
            .iter()
            .find(|s| s.pipe_id == "pipe-x")
            .expect("pipe-x stats present");

        assert_eq!(x.total_requests, 2);
        assert_eq!(x.total_request_bytes, 300);
        assert_eq!(x.total_response_bytes, 1100);
        assert_eq!(x.avg_request_bytes, 150);
        assert_eq!(x.avg_response_bytes, 550);
        assert_eq!(x.total_input_tokens, 15);
        assert_eq!(x.total_output_tokens, 60);
    }

    #[tokio::test]
    async fn pipe_stats_aggregates_per_stage_usage() {
        use crate::metrics::{PipeStageUsage, StageUsageMetric};
        let store = MetricsStore::new(100);
        // Two executions; per-stage tokens/cost sum, latency averages over the
        // executions that report a non-zero latency for that stage.
        let runs = [
            PipeStageUsage {
                llm: StageUsageMetric {
                    input_tokens: 10,
                    output_tokens: 20,
                    cost: 0.10,
                    latency_ms: 100,
                    ..Default::default()
                },
                judge: StageUsageMetric {
                    input_tokens: 4,
                    output_tokens: 2,
                    cost: 0.02,
                    latency_ms: 40,
                    ..Default::default()
                },
                jury: StageUsageMetric {
                    input_tokens: 6,
                    output_tokens: 3,
                    cost: 0.03,
                    latency_ms: 60,
                    ..Default::default()
                },
                decider: StageUsageMetric {
                    input_tokens: 5,
                    output_tokens: 1,
                    cost: 0.04,
                    latency_ms: 50,
                    ..Default::default()
                },
                key_source: None,
            },
            PipeStageUsage {
                llm: StageUsageMetric {
                    input_tokens: 30,
                    output_tokens: 10,
                    cost: 0.20,
                    latency_ms: 300,
                    ..Default::default()
                },
                judge: StageUsageMetric::default(),
                jury: StageUsageMetric {
                    input_tokens: 2,
                    output_tokens: 1,
                    cost: 0.01,
                    latency_ms: 20,
                    ..Default::default()
                },
                decider: StageUsageMetric::default(),
                key_source: None,
            },
        ];
        for su in runs {
            store
                .record_pipe_execution(
                    "pipe-stage".to_string(),
                    Some("Pipe Stage".to_string()),
                    "openai".to_string(),
                    "gpt-4o".to_string(),
                    ConnectionStatus::Success,
                    5,
                    None,
                    None,
                    0,
                    0,
                    0.0,
                    Some("trace".to_string()),
                    None,
                    None,
                    0,
                    0,
                    0,
                    Some(su),
                )
                .await;
        }

        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = {
                let connections = store.connections.read().await;
                connections
                    .iter()
                    .filter(|c| c.pipe_id.as_deref() == Some("pipe-stage"))
                    .count()
            };
            if landed >= 2 {
                break;
            }
        }
        let stats = store.get_pipe_stats().await;
        let s = stats
            .iter()
            .find(|s| s.pipe_id == "pipe-stage")
            .expect("pipe-stage stats present");

        // LLM: tokens/cost summed, latency averaged across both runs.
        assert_eq!(
            s.stage_usage
                .llm
                .total_input_tokens,
            40
        );
        assert_eq!(
            s.stage_usage
                .llm
                .total_output_tokens,
            30
        );
        assert!((s.stage_usage.llm.total_cost - 0.30).abs() < 1e-9);
        assert!(
            (s.stage_usage
                .llm
                .avg_latency_ms
                - 200.0)
                .abs()
                < 1e-9
        );

        // Judge: only the first run reported usage, so the second (zero-latency)
        // run is excluded from the latency average.
        assert_eq!(
            s.stage_usage
                .judge
                .total_input_tokens,
            4
        );
        assert_eq!(
            s.stage_usage
                .judge
                .total_output_tokens,
            2
        );
        assert!(
            (s.stage_usage
                .judge
                .avg_latency_ms
                - 40.0)
                .abs()
                < 1e-9
        );

        // Jury: tokens/cost summed, latency averaged across both runs.
        assert_eq!(
            s.stage_usage
                .jury
                .total_input_tokens,
            8
        );
        assert_eq!(
            s.stage_usage
                .jury
                .total_output_tokens,
            4
        );
        assert!(
            (s.stage_usage
                .jury
                .avg_latency_ms
                - 40.0)
                .abs()
                < 1e-9
        );

        // Decider: only the first run reported usage, so the second (zero-latency)
        // run is excluded from the latency average.
        assert_eq!(
            s.stage_usage
                .decider
                .total_input_tokens,
            5
        );
        assert_eq!(
            s.stage_usage
                .decider
                .total_output_tokens,
            1
        );
        assert!(
            (s.stage_usage
                .decider
                .total_cost
                - 0.04)
                .abs()
                < 1e-9
        );
        assert!(
            (s.stage_usage
                .decider
                .avg_latency_ms
                - 50.0)
                .abs()
                < 1e-9
        );
    }

    #[tokio::test]
    async fn pipe_stats_stage_usage_zero_without_stage_data() {
        let store = MetricsStore::new(100);
        store
            .record_pipe_execution(
                "pipe-nostage".to_string(),
                Some("Pipe NoStage".to_string()),
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

        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = {
                let connections = store.connections.read().await;
                connections
                    .iter()
                    .filter(|c| c.pipe_id.as_deref() == Some("pipe-nostage"))
                    .count()
            };
            if landed >= 1 {
                break;
            }
        }
        let stats = store.get_pipe_stats().await;
        let s = stats
            .iter()
            .find(|s| s.pipe_id == "pipe-nostage")
            .expect("pipe-nostage stats present");

        assert_eq!(
            s.stage_usage
                .llm
                .total_input_tokens,
            0
        );
        assert_eq!(
            s.stage_usage
                .llm
                .avg_latency_ms,
            0.0
        );
        assert_eq!(
            s.stage_usage
                .judge
                .total_output_tokens,
            0
        );
        assert_eq!(s.stage_usage.jury.total_cost, 0.0);
    }

    #[tokio::test]
    async fn pipe_stats_sorted_deterministically_by_name() {
        let store = MetricsStore::new(100);
        // Insertion order is intentionally not alphabetical.
        for (pid, name) in [("pipe-z", "Zebra"), ("pipe-a", "Alpha"), ("pipe-m", "Mango")] {
            store
                .record_pipe_execution(
                    pid.to_string(),
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

        for _ in 0..200 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            let landed = {
                let connections = store.connections.read().await;
                connections
                    .iter()
                    .filter(|c| c.metric_type == crate::metrics::MetricType::Pipe)
                    .count()
            };
            if landed >= 3 {
                break;
            }
        }

        let names: Vec<_> = store
            .get_pipe_stats()
            .await
            .into_iter()
            .filter_map(|s| s.pipe_name)
            .collect();

        assert_eq!(names, vec!["Alpha".to_string(), "Mango".to_string(), "Zebra".to_string()]);
    }
}
