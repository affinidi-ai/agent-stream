//! Persistent metrics storage
//!
//! Stores execution metrics for historical analysis and aggregation
//! Note: SQLite implementation available with 'sqlx' feature flag

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info};

use super::config::StageUsage;
use super::executor::ExecutionMetrics;

const MAX_STORED_METRICS: usize = 10000; // Keep last 10k records in memory

/// Stored execution record
#[derive(Debug, Clone)]
#[allow(dead_code)]
struct ExecutionRecord {
    pipe_id: String,
    timestamp: DateTime<Utc>,
    metrics: ExecutionMetrics,
    success: bool,
}

/// Aggregated metrics over a time period
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AggregatedMetrics {
    pub pipe_id: String,
    pub period_start: DateTime<Utc>,
    pub period_end: DateTime<Utc>,
    pub total_requests: i64,
    pub successful_requests: i64,
    pub failed_requests: i64,
    pub total_input_tokens: i64,
    pub total_output_tokens: i64,
    pub total_tokens: i64,
    pub total_cost: f64,
    pub avg_latency_ms: f64,
    pub min_latency_ms: i64,
    pub max_latency_ms: i64,
    pub p50_latency_ms: Option<f64>,
    pub p95_latency_ms: Option<f64>,
    pub p99_latency_ms: Option<f64>,
}

/// In-memory metrics storage (use SQLite for production with 'sqlx' feature)
pub struct MetricsStore {
    records: Arc<RwLock<VecDeque<ExecutionRecord>>>,
    records_tx: tokio::sync::mpsc::UnboundedSender<ExecutionRecord>,
}

impl MetricsStore {
    /// Create a new in-memory metrics store (synchronous)
    pub fn new() -> Self {
        info!("Using in-memory metrics store (enable 'sqlx' feature for persistent storage)");

        // Create channel for batched writes
        let (records_tx, records_rx) = tokio::sync::mpsc::unbounded_channel();
        let records = Arc::new(RwLock::new(VecDeque::with_capacity(MAX_STORED_METRICS)));

        // Spawn background worker to batch process records
        let records_clone = records.clone();
        tokio::spawn(Self::records_batch_worker(records_rx, records_clone));

        Self { records, records_tx }
    }

    /// Create a new in-memory metrics store
    #[allow(dead_code)]
    pub async fn new_async(_database_path: &str) -> Result<Self, String> {
        info!("Using in-memory metrics store (enable 'sqlx' feature for persistent storage)");
        Ok(Self::new())
    }

    /// Create an in-memory metrics store
    #[allow(dead_code)]
    pub async fn new_in_memory() -> Result<Self, String> {
        Ok(Self::new())
    }

    /// Background worker that batches record writes to reduce lock contention
    async fn records_batch_worker(
        mut rx: tokio::sync::mpsc::UnboundedReceiver<ExecutionRecord>,
        records: Arc<RwLock<VecDeque<ExecutionRecord>>>,
    ) {
        const MAX_BATCH_SIZE: usize = 50;

        while let Some(record) = rx.recv().await {
            let mut batch = vec![record];

            // Drain channel for batching (up to MAX_BATCH_SIZE or until empty)
            // Use try_recv() for zero latency - no timeouts, no waiting
            while batch.len() < MAX_BATCH_SIZE {
                match rx.try_recv() {
                    Ok(r) => batch.push(r),
                    Err(_) => break, // Channel empty or closed
                }
            }

            // Single write lock for entire batch
            let mut records_guard = records.write().await;

            for record in batch {
                // Remove oldest if at capacity
                if records_guard.len() >= MAX_STORED_METRICS {
                    records_guard.pop_front();
                }
                records_guard.push_back(record);
            }

            drop(records_guard);
        }
    }

    /// Record a successful execution
    pub async fn record_execution(
        &self,
        pipe_id: &str,
        metrics: &ExecutionMetrics,
    ) -> Result<(), String> {
        // Send to batch worker (non-blocking)
        let record = ExecutionRecord {
            pipe_id: pipe_id.to_string(),
            timestamp: Utc::now(),
            metrics: metrics.clone(),
            success: true,
        };

        self.records_tx
            .send(record)
            .map_err(|e| format!("Failed to send record to batch worker: {}", e))?;

        debug!("Queued execution record for pipe {}", pipe_id);

        Ok(())
    }

    /// Record a failed execution
    #[allow(dead_code)]
    pub async fn record_failure(
        &self,
        pipe_id: &str,
        trace_id: &str,
        latency_ms: u64,
    ) -> Result<(), String> {
        // Send to batch worker (non-blocking)
        let record = ExecutionRecord {
            pipe_id: pipe_id.to_string(),
            timestamp: Utc::now(),
            metrics: ExecutionMetrics {
                input_tokens: 0,
                output_tokens: 0,
                total_tokens: 0,
                cost: 0.0,
                llm_usage: StageUsage::default(),
                judge_usage: StageUsage::default(),
                jury_usage: StageUsage::default(),
                decider_usage: StageUsage::default(),
                latency_ms,
                provider: "".to_string(),
                model: "".to_string(),
                trace_id: trace_id.to_string(),
                correlation_id: None,
                agent_identity: None,
                request_bytes: 0,
                response_bytes: 0,
                time_to_first_token_ms: None,
                retry_count: 0,
                redrive_rejections: Vec::new(),
                cached_tokens: 0,
                cache_write_tokens: 0,
                reasoning_tokens: 0,
                schema_valid: None,
                conversation_id: None,
                stages: Vec::new(),
                cache_hit: false,
                cache_saved_cost: 0.0,
                billed_cost: 0.0,
                key_source: None,
            },
            success: false,
        };

        self.records_tx
            .send(record)
            .map_err(|e| format!("Failed to send failure record to batch worker: {}", e))?;

        debug!("Queued failure record for pipe {}", pipe_id);

        Ok(())
    }

    /// Get aggregated metrics for a pipe over a time period
    #[allow(dead_code)]
    pub async fn get_aggregated_metrics(
        &self,
        pipe_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> Result<AggregatedMetrics, String> {
        let records = self.records.read().await;

        // Filter records for this pipe and time range
        let filtered: Vec<&ExecutionRecord> = records
            .iter()
            .filter(|r| r.pipe_id == pipe_id && r.timestamp >= start && r.timestamp <= end)
            .collect();

        if filtered.is_empty() {
            return Ok(AggregatedMetrics {
                pipe_id: pipe_id.to_string(),
                period_start: start,
                period_end: end,
                total_requests: 0,
                successful_requests: 0,
                failed_requests: 0,
                total_input_tokens: 0,
                total_output_tokens: 0,
                total_tokens: 0,
                total_cost: 0.0,
                avg_latency_ms: 0.0,
                min_latency_ms: 0,
                max_latency_ms: 0,
                p50_latency_ms: None,
                p95_latency_ms: None,
                p99_latency_ms: None,
            });
        }

        let total_requests = filtered.len() as i64;
        let successful_requests = filtered
            .iter()
            .filter(|r| r.success)
            .count() as i64;
        let failed_requests = total_requests - successful_requests;

        let total_input_tokens: u64 = filtered
            .iter()
            .map(|r| r.metrics.input_tokens)
            .sum();
        let total_output_tokens: u64 = filtered
            .iter()
            .map(|r| r.metrics.output_tokens)
            .sum();
        let total_tokens: u64 = filtered
            .iter()
            .map(|r| r.metrics.total_tokens)
            .sum();
        let total_cost: f64 = filtered
            .iter()
            .map(|r| r.metrics.cost)
            .sum();

        let latencies: Vec<u64> = filtered
            .iter()
            .map(|r| r.metrics.latency_ms)
            .collect();
        let sum_latency: u64 = latencies.iter().sum();
        let avg_latency_ms = if !latencies.is_empty() {
            sum_latency as f64 / latencies.len() as f64
        } else {
            0.0
        };

        let min_latency_ms = latencies
            .iter()
            .min()
            .copied()
            .unwrap_or(0) as i64;
        let max_latency_ms = latencies
            .iter()
            .max()
            .copied()
            .unwrap_or(0) as i64;

        // Calculate percentiles
        let mut sorted_latencies = latencies.clone();
        sorted_latencies.sort_unstable();

        let len = sorted_latencies.len();
        let p50 = if len > 0 {
            Some(sorted_latencies[len * 50 / 100] as f64)
        } else {
            None
        };
        let p95 = if len > 0 {
            Some(sorted_latencies[len * 95 / 100] as f64)
        } else {
            None
        };
        let p99 = if len > 0 {
            Some(sorted_latencies[len * 99 / 100] as f64)
        } else {
            None
        };

        Ok(AggregatedMetrics {
            pipe_id: pipe_id.to_string(),
            period_start: start,
            period_end: end,
            total_requests,
            successful_requests,
            failed_requests,
            total_input_tokens: total_input_tokens as i64,
            total_output_tokens: total_output_tokens as i64,
            total_tokens: total_tokens as i64,
            total_cost,
            avg_latency_ms,
            min_latency_ms,
            max_latency_ms,
            p50_latency_ms: p50,
            p95_latency_ms: p95,
            p99_latency_ms: p99,
        })
    }

    /// Clean up old records (retention policy)
    #[allow(dead_code)]
    pub async fn cleanup_old_records(
        &self,
        days_to_keep: i64,
    ) -> Result<u64, String> {
        let cutoff = Utc::now() - chrono::Duration::days(days_to_keep);
        let mut records = self.records.write().await;

        let original_len = records.len();
        records.retain(|r| r.timestamp >= cutoff);
        let removed = (original_len - records.len()) as u64;

        if removed > 0 {
            info!("Cleaned up {} old metric records (older than {} days)", removed, days_to_keep);
        }

        Ok(removed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[tokio::test]
    #[ignore] // FIXME: failing test
    async fn test_metrics_store_persistence() {
        let store = MetricsStore::new_in_memory()
            .await
            .unwrap();

        let metrics = ExecutionMetrics {
            input_tokens: 100,
            output_tokens: 50,
            total_tokens: 150,
            cost: 0.015,
            llm_usage: StageUsage {
                input_tokens: 100,
                output_tokens: 50,
                cost: 0.015,
                latency_ms: 250,
                ..Default::default()
            },
            judge_usage: StageUsage::default(),
            jury_usage: StageUsage::default(),
            decider_usage: StageUsage::default(),
            latency_ms: 250,
            provider: "openai".to_string(),
            model: "gpt-4".to_string(),
            trace_id: "test-trace-123".to_string(),
            correlation_id: None,
            agent_identity: None,
            request_bytes: 500,
            response_bytes: 1000,
            time_to_first_token_ms: None,
            retry_count: 0,
            redrive_rejections: Vec::new(),
            cached_tokens: 0,
            cache_write_tokens: 0,
            reasoning_tokens: 0,
            schema_valid: None,
            conversation_id: None,
            stages: Vec::new(),
            cache_hit: false,
            cache_saved_cost: 0.0,
            billed_cost: 0.0,
            key_source: None,
        };

        store
            .record_execution("pipe-1", &metrics)
            .await
            .unwrap();

        let start = Utc::now() - chrono::Duration::hours(1);
        let end = Utc::now();

        let aggregated = store
            .get_aggregated_metrics("pipe-1", start, end)
            .await
            .unwrap();

        assert_eq!(aggregated.total_requests, 1);
        assert_eq!(aggregated.total_cost, 0.015);
        assert_eq!(aggregated.total_tokens, 150);
    }
}
