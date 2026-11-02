use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use anyhow::Result;

use crate::metrics::{ConnectionMetric, RuleMetric, RuleValidationEvent, ConnectionStatus, ConnectionDirection};
use crate::observability::TaskMonitor;
use crate::identity::IdentityStore;
use super::types::{MetricsBackend, MetricsSnapshot};

/// Centralized metrics aggregator to ensure consistent calculations across all backends
#[derive(Debug, Clone)]
pub struct MetricsAggregator {
    pub total_requests: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub gateway_fault_count: u64,
    pub avg_request_latency_ms: f64,
    pub request_latency_sample_count: usize,
    pub avg_response_latency_ms: f64,
    pub response_latency_sample_count: usize,
    pub unique_identity_count: usize,
    pub rule_accept_count: u64,
    pub rule_reject_count: u64,
    pub active_connections: usize,
    pub throughput_bytes_per_sec: f64,
    pub connections_per_minute: f64,
}

impl MetricsAggregator {
    /// Aggregate metrics from raw connection data and rule metrics
    /// This is the single source of truth for all metric calculations
    pub async fn from_data(
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        task_monitor: Option<&Arc<TaskMonitor>>,
        identity_store: Option<&Arc<dyn IdentityStore>>,
    ) -> Self {
        // Calculate aggregates from connections (only count requests, not responses)
        let mut success_count = 0u64;
        let mut failure_count = 0u64;
        let mut gateway_fault_count = 0u64;
        let mut total_request_latency_ms = 0u64;
        let mut request_latency_count = 0usize;
        let mut total_response_latency_ms = 0u64;
        let mut response_latency_count = 0usize;
        let mut unique_identities = std::collections::HashSet::new();
        
        for conn in connections {
            // Count by direction
            if conn.direction == ConnectionDirection::Request {
                match conn.status {
                    ConnectionStatus::Success => success_count += 1,
                    ConnectionStatus::Failed => failure_count += 1,
                    ConnectionStatus::GatewayFault => gateway_fault_count += 1,
                }
                
                if let Some(latency) = conn.latency_ms {
                    total_request_latency_ms += latency;
                    request_latency_count += 1;
                }
                
                if let Some(ref identity) = conn.identity_hash {
                    unique_identities.insert(identity.clone());
                }
            } else if conn.direction == ConnectionDirection::Response {
                // Track response latency separately
                if let Some(latency) = conn.latency_ms {
                    total_response_latency_ms += latency;
                    response_latency_count += 1;
                }
            }
        }
        
        let total_requests = success_count + failure_count + gateway_fault_count;
        let avg_request_latency_ms = if request_latency_count > 0 {
            (total_request_latency_ms as f64) / (request_latency_count as f64)
        } else {
            0.0
        };
        let avg_response_latency_ms = if response_latency_count > 0 {
            (total_response_latency_ms as f64) / (response_latency_count as f64)
        } else {
            0.0
        };
        
        // Get unique identity count from identity_store (authoritative source)
        let unique_identity_count = if let Some(store) = identity_store {
            match store.list_all().await {
                Ok(identities) => identities.len(),
                Err(e) => {
                    tracing::warn!("Failed to get identity count: {}", e);
                    unique_identities.len() // Fallback to connection-based count
                }
            }
        } else {
            unique_identities.len()
        };
        
        // Calculate rule validation metrics
        let mut rule_accept_count = 0u64;
        let mut rule_reject_count = 0u64;
        for metric in rule_metrics.values() {
            rule_accept_count += metric.accept_count;
            rule_reject_count += metric.deny_count;
        }
        
        // Get real-time metrics from task monitor if available
        let (active_connections, throughput_bytes_per_sec, connections_per_minute) = 
            if let Some(monitor) = task_monitor {
                let summary = monitor.get_summary().await;
                let all_metrics = monitor.get_all_metrics().await;
                
                let mut total_throughput = 0.0;
                let mut total_connections_per_min = 0.0;
                for metric in &all_metrics {
                    total_throughput += metric.throughput_bytes_per_sec;
                    total_connections_per_min += metric.connections_per_minute;
                }
                
                tracing::debug!(
                    "MetricsAggregator::from_data - {} tasks, total_throughput={:.2} B/s, metrics: {:?}",
                    all_metrics.len(),
                    total_throughput,
                    all_metrics.iter().map(|m| (m.task_id.as_str(), m.throughput_bytes_per_sec)).collect::<Vec<_>>()
                );
                
                (summary.total_active_connections, total_throughput, total_connections_per_min)
            } else {
                (0, 0.0, 0.0)
            };
        
        Self {
            total_requests,
            success_count,
            failure_count,
            gateway_fault_count,
            avg_request_latency_ms,
            request_latency_sample_count: request_latency_count,
            avg_response_latency_ms,
            response_latency_sample_count: response_latency_count,
            unique_identity_count,
            rule_accept_count,
            rule_reject_count,
            active_connections: active_connections as usize,
            throughput_bytes_per_sec,
            connections_per_minute,
        }
    }
}

/// File-based metrics backend (detailed history for local debugging)
pub struct FileMetricsBackend {
    path: PathBuf,
}

impl FileMetricsBackend {
    pub fn new(path: PathBuf) -> Self {
        Self { path }
    }
}

#[async_trait::async_trait]
impl MetricsBackend for FileMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        use tokio::io::AsyncWriteExt;
        
        // Create directory if it doesn't exist
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        
        // Convert to hierarchical format (reuse existing logic)
        let metrics_data = crate::metrics::build_hierarchical_metrics(
            connections,
            rule_metrics,
            rule_validation_events,
        );
        
        // Serialize to JSON
        let json = serde_json::to_string_pretty(&metrics_data)?;
        
        // Write to temporary file first, then atomically rename
        let temp_path = self.path.with_extension("json.tmp");
        let mut file = tokio::fs::File::create(&temp_path).await?;
        file.write_all(json.as_bytes()).await?;
        file.flush().await?;
        drop(file); // Close file before rename
        
        // Atomic rename
        tokio::fs::rename(&temp_path, &self.path).await?;
        
        Ok(())
    }
    
    async fn load(&self) -> Result<MetricsSnapshot> {
        if !self.path.exists() {
            return Ok(MetricsSnapshot {
                connections: vec![],
                rule_validation_events: vec![],
            });
        }
        
        let contents = tokio::fs::read_to_string(&self.path).await?;
        let metrics_data: crate::metrics::MetricsData = serde_json::from_str(&contents)?;
        
        // Flatten hierarchical format back to flat metrics
        let (connections, rule_validation_events) = 
            crate::metrics::flatten_hierarchical_metrics(&metrics_data);
        
        Ok(MetricsSnapshot {
            connections,
            rule_validation_events,
        })
    }
    
    fn name(&self) -> &str {
        "file"
    }
}

/// Prometheus metrics backend (lightweight aggregates exposed via /metrics endpoint)
pub struct PrometheusMetricsBackend {
    task_monitor: Option<Arc<TaskMonitor>>,
    identity_store: Option<Arc<dyn crate::identity::IdentityStore>>,
}

impl PrometheusMetricsBackend {
    pub fn new() -> Self {
        Self {
            task_monitor: None,
            identity_store: None,
        }
    }
    
    pub fn with_task_monitor_and_identity_store(
        task_monitor: Arc<TaskMonitor>,
        identity_store: Arc<dyn crate::identity::IdentityStore>,
    ) -> Self {
        Self {
            task_monitor: Some(task_monitor),
            identity_store: Some(identity_store),
        }
    }
}

#[async_trait::async_trait]
impl MetricsBackend for PrometheusMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        _rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        // Use centralized aggregator to compute all metrics consistently
        let aggregator = MetricsAggregator::from_data(
            connections,
            rule_metrics,
            self.task_monitor.as_ref(),
            self.identity_store.as_ref(),
        ).await;
        
        // Update Prometheus metrics from aggregated values
        use crate::metrics::backends::prometheus::{
            ACTIVE_CONNECTIONS, UNIQUE_IDENTITIES, THROUGHPUT_BYTES_PER_SEC, 
            CONNECTIONS_PER_MINUTE, AVG_REQUEST_LATENCY_MS, AVG_RESPONSE_LATENCY_MS,
        };
        
        // Set gauge values from aggregator (these reflect current state)
        ACTIVE_CONNECTIONS.set(aggregator.active_connections as f64);
        UNIQUE_IDENTITIES.set(aggregator.unique_identity_count as i64);
        THROUGHPUT_BYTES_PER_SEC.set(aggregator.throughput_bytes_per_sec);
        CONNECTIONS_PER_MINUTE.set(aggregator.connections_per_minute);
        AVG_REQUEST_LATENCY_MS.set(aggregator.avg_request_latency_ms);
        AVG_RESPONSE_LATENCY_MS.set(aggregator.avg_response_latency_ms);
        
        // Note: We do NOT update counters here to avoid double-counting.
        // Counters (REQUEST_COUNTER, SUCCESS_COUNTER, FAILURE_COUNTER, etc.) are only
        // incremented in real-time when connections occur via track_connection().
        // This persist() method only updates gauge metrics from aggregated state.
        
        tracing::debug!(
            "Prometheus metrics updated: active_conns={}, unique_ids={}, throughput={:.2}, conn_per_min={:.2}",
            aggregator.active_connections,
            aggregator.unique_identity_count,
            aggregator.throughput_bytes_per_sec,
            aggregator.connections_per_minute
        );
        
        Ok(())
    }
    
    async fn load(&self) -> Result<MetricsSnapshot> {
        // Prometheus doesn't support loading historical data
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }
    
    fn name(&self) -> &str {
        "prometheus"
    }
}

/// CloudWatch metrics backend (pushes aggregates to AWS CloudWatch)
pub struct CloudWatchMetricsBackend {
    namespace: String,
    enabled: bool,
    client: Option<aws_sdk_cloudwatch::Client>,
    region: Option<String>,
    profile: Option<String>,
    task_monitor: Option<Arc<TaskMonitor>>,
    identity_store: Option<Arc<dyn IdentityStore>>,
    last_sent: Arc<tokio::sync::RwLock<Option<MetricsAggregator>>>,
}

impl CloudWatchMetricsBackend {
    pub fn new(namespace: String) -> Self {
        Self {
            namespace,
            enabled: false,
            client: None,
            region: None,
            profile: None,
            task_monitor: None,
            identity_store: None,
            last_sent: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }
    
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }
    
    pub fn with_region(mut self, region: Option<String>) -> Self {
        self.region = region;
        self
    }
    
    pub fn with_profile(mut self, profile: Option<String>) -> Self {
        self.profile = profile;
        self
    }
    
    pub fn with_task_monitor(mut self, task_monitor: Arc<TaskMonitor>) -> Self {
        self.task_monitor = Some(task_monitor);
        self
    }
    
    pub fn with_identity_store(mut self, identity_store: Arc<dyn IdentityStore>) -> Self {
        self.identity_store = Some(identity_store);
        self
    }
    
    pub async fn with_aws_client(mut self) -> Self {
        if self.enabled {
            let mut config_loader = aws_config::from_env();
            
            // Set profile if specified
            if let Some(ref profile) = self.profile {
                config_loader = config_loader.profile_name(profile);
                tracing::info!("CloudWatch configured with AWS profile: {}", profile);
            }
            
            // Set region if specified
            if let Some(ref region) = self.region {
                config_loader = config_loader.region(aws_sdk_cloudwatch::config::Region::new(region.clone()));
                tracing::info!("CloudWatch configured with region: {}", region);
            }
            
            let config = config_loader.load().await;
            self.client = Some(aws_sdk_cloudwatch::Client::new(&config));
            
            tracing::info!(
                "CloudWatch client initialized for namespace: {}", 
                self.namespace
            );
        }
        self
    }
}

#[async_trait::async_trait]
impl MetricsBackend for CloudWatchMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        _rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        if !self.enabled {
            return Ok(()); // Skip if not enabled
        }
        
        let client = match &self.client {
            Some(c) => c,
            None => {
                tracing::warn!("CloudWatch client not initialized");
                return Ok(());
            }
        };
        
        let now = chrono::Utc::now();
        let timestamp = aws_sdk_cloudwatch::primitives::DateTime::from_millis(now.timestamp_millis());
        
        // Use centralized aggregator for gauge metrics (active connections, throughput, latency)
        // But use Prometheus counters for cumulative totals to match Prometheus exactly
        let aggregator = MetricsAggregator::from_data(
            connections,
            rule_metrics,
            self.task_monitor.as_ref(),
            self.identity_store.as_ref(),
        ).await;
        
        // Get cumulative counter values from Prometheus (source of truth for totals)
        use crate::metrics::backends::prometheus::{
            REQUEST_COUNTER, SUCCESS_COUNTER, FAILURE_COUNTER, GATEWAY_FAULT_COUNTER,
            RULE_ACCEPT_COUNTER, RULE_REJECT_COUNTER,
        };
        
        let total_requests = REQUEST_COUNTER.get() as u64;
        let success_count = SUCCESS_COUNTER.get() as u64;
        let failure_count = FAILURE_COUNTER.get() as u64;
        let gateway_fault_count = GATEWAY_FAULT_COUNTER.get() as u64;
        let rule_accept_count = RULE_ACCEPT_COUNTER.get() as u64;
        let rule_reject_count = RULE_REJECT_COUNTER.get() as u64;
        
        // Check if data has changed since last send
        // We only check counters (cumulative totals) for change detection, not gauges
        // Gauges like throughput/active_connections decay to zero naturally, causing unnecessary pushes
        let last_sent = self.last_sent.read().await;
        if let Some(ref last) = *last_sent {
            let counters_unchanged = last.total_requests == total_requests
                && last.success_count == success_count
                && last.failure_count == failure_count
                && last.gateway_fault_count == gateway_fault_count
                && last.rule_accept_count == rule_accept_count
                && last.rule_reject_count == rule_reject_count;
            
            let latency_unchanged = last.request_latency_sample_count == aggregator.request_latency_sample_count
                && last.response_latency_sample_count == aggregator.response_latency_sample_count
                && (last.avg_request_latency_ms - aggregator.avg_request_latency_ms).abs() < 0.01
                && (last.avg_response_latency_ms - aggregator.avg_response_latency_ms).abs() < 0.01;
            
            // Skip if counters and latency haven't changed (ignore gauge fluctuations)
            if counters_unchanged && latency_unchanged {
                tracing::debug!(
                    "CloudWatch metrics unchanged (counters + latency) - skipping to save costs"
                );
                drop(last_sent);
                return Ok(());
            } else {
                tracing::debug!(
                    "CloudWatch metrics changed - requests: {} -> {}, success: {} -> {}, failure: {} -> {}, gateway_fault: {} -> {}, rule_accept: {} -> {}, rule_reject: {} -> {}",
                    last.total_requests, total_requests,
                    last.success_count, success_count,
                    last.failure_count, failure_count,
                    last.gateway_fault_count, gateway_fault_count,
                    last.rule_accept_count, rule_accept_count,
                    last.rule_reject_count, rule_reject_count
                );
            }
        } else {
            tracing::debug!("CloudWatch - first send, no previous data to compare");
        }
        drop(last_sent);
        
        // Create updated aggregator with Prometheus counter values for change tracking
        let updated_aggregator = MetricsAggregator {
            total_requests,
            success_count,
            failure_count,
            gateway_fault_count,
            avg_request_latency_ms: aggregator.avg_request_latency_ms,
            request_latency_sample_count: aggregator.request_latency_sample_count,
            avg_response_latency_ms: aggregator.avg_response_latency_ms,
            response_latency_sample_count: aggregator.response_latency_sample_count,
            unique_identity_count: aggregator.unique_identity_count,
            rule_accept_count,
            rule_reject_count,
            active_connections: aggregator.active_connections,
            throughput_bytes_per_sec: aggregator.throughput_bytes_per_sec,
            connections_per_minute: aggregator.connections_per_minute,
        };
        
        // 
        // Build metric data from updated aggregator (with Prometheus counter values)
        let mut metric_data = vec![];
        
        // Request count metrics (use Prometheus counter values)
        if total_requests > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("RequestCount")
                    .value(total_requests as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        if success_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("SuccessCount")
                    .value(success_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        if failure_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("FailureCount")
                    .value(failure_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        if gateway_fault_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("GatewayFaultCount")
                    .value(gateway_fault_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Success rate percentage (use Prometheus counter values)
        if total_requests > 0 {
            let success_rate = (success_count as f64 / total_requests as f64) * 100.0;
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("SuccessRate")
                    .value(success_rate)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Percent)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Request latency metrics
        if aggregator.request_latency_sample_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("AverageRequestLatency")
                    .value(aggregator.avg_request_latency_ms)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Milliseconds)
                    .timestamp(timestamp)
                    .build()
            );
            
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("RequestLatencySampleCount")
                    .value(aggregator.request_latency_sample_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Response latency metrics
        if aggregator.response_latency_sample_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("AverageResponseLatency")
                    .value(aggregator.avg_response_latency_ms)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Milliseconds)
                    .timestamp(timestamp)
                    .build()
            );
            
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("ResponseLatencySampleCount")
                    .value(aggregator.response_latency_sample_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Active connections
        if aggregator.active_connections > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("ActiveConnections")
                    .value(aggregator.active_connections as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Throughput
        if aggregator.throughput_bytes_per_sec > 0.0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("ThroughputBytesPerSec")
                    .value(aggregator.throughput_bytes_per_sec)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::BytesSecond)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Connections per minute
        if aggregator.connections_per_minute > 0.0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("ConnectionsPerMinute")
                    .value(aggregator.connections_per_minute)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::CountSecond)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Unique identities (single source of truth from aggregator)
        if aggregator.unique_identity_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("UniqueIdentities")
                    .value(aggregator.unique_identity_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Rule validation metrics (use Prometheus counter values)
        if rule_accept_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("RuleAcceptCount")
                    .value(rule_accept_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        if rule_reject_count > 0 {
            metric_data.push(
                aws_sdk_cloudwatch::types::MetricDatum::builder()
                    .metric_name("RuleRejectCount")
                    .value(rule_reject_count as f64)
                    .unit(aws_sdk_cloudwatch::types::StandardUnit::Count)
                    .timestamp(timestamp)
                    .build()
            );
        }
        
        // Send metrics to CloudWatch (max 1000 per request, we're well under)
        if !metric_data.is_empty() {
            let metric_count = metric_data.len();
            
            let start = std::time::Instant::now();
            match client
                .put_metric_data()
                .namespace(&self.namespace)
                .set_metric_data(Some(metric_data))
                .send()
                .await
            {
                Ok(response) => {
                    // tracing::info!(
                    //     namespace = %self.namespace,
                    //     metrics_count = metric_count,
                    //     response_time_ms = start.elapsed().as_millis(),
                    //     "✓ CloudWatch API call successful - pushed {} metrics in {}ms. Response: {:?}",
                    //     metric_count,
                    //     start.elapsed().as_millis(),
                    //     response
                    // );
                    
                    // Store updated values (with Prometheus counter values) as last sent
                    let mut last_sent = self.last_sent.write().await;
                    *last_sent = Some(updated_aggregator);
                }
                Err(e) => {
                    tracing::error!("CloudWatch metrics push failed: {}", e);
                    tracing::debug!(
                        error = ?e,
                        error_type = ?std::any::type_name_of_val(&e),
                        namespace = %self.namespace,
                        "CloudWatch error details: {:#?}",
                        e
                    );
                    // Store attempted values as last sent even on failure
                    // This prevents "first send" messages on every retry
                    let mut last_sent = self.last_sent.write().await;
                    *last_sent = Some(updated_aggregator);
                }
            }
        } else {
            tracing::debug!("No CloudWatch metrics to send (all values are zero)");
        }
        
        Ok(())
    }
    
    async fn load(&self) -> Result<MetricsSnapshot> {
        // CloudWatch doesn't support loading historical data this way
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }
    
    fn name(&self) -> &str {
        "cloudwatch"
    }
}

/// Multi-backend wrapper that broadcasts to all configured backends
pub struct MultiBackend {
    backends: Vec<Arc<dyn MetricsBackend>>,
}

impl MultiBackend {
    pub fn new() -> Self {
        Self {
            backends: Vec::new(),
        }
    }
    
    pub fn add_backend(mut self, backend: Arc<dyn MetricsBackend>) -> Self {
        self.backends.push(backend);
        self
    }
}

#[async_trait::async_trait]
impl MetricsBackend for MultiBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        // Broadcast to all backends in parallel
        let futures: Vec<_> = self.backends.iter().map(|backend| {
            let backend = backend.clone();
            let connections = connections.to_vec();
            let rule_metrics = rule_metrics.clone();
            let rule_validation_events = rule_validation_events.to_vec();
            async move {
                if let Err(e) = backend.persist(&connections, &rule_metrics, &rule_validation_events).await {
                    eprintln!("Warning: {} backend failed to persist metrics: {}", backend.name(), e);
                }
            }
        }).collect();
        
        futures::future::join_all(futures).await;
        
        Ok(())
    }
    
    async fn load(&self) -> Result<MetricsSnapshot> {
        // Load from the first backend that supports it (typically file backend)
        for backend in &self.backends {
            if let Ok(snapshot) = backend.load().await {
                if !snapshot.connections.is_empty() || !snapshot.rule_validation_events.is_empty() {
                    return Ok(snapshot);
                }
            }
        }
        
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }
    
    fn name(&self) -> &str {
        "multi"
    }
}
