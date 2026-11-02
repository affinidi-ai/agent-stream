//! Type definitions for metrics tracking

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Type alias for trace ID to datapoints mapping
pub type TraceDataPoints = HashMap<String, Vec<ConnectionDataPoint>>;

/// Type alias for destination to trace datapoints mapping
pub type DestinationTraceMap = HashMap<String, TraceDataPoints>;

/// Type alias for identity to destination mapping
pub type IdentityDestinationMap = HashMap<String, DestinationTraceMap>;

/// Type alias for source to identity mapping
pub type SourceIdentityMap = HashMap<String, IdentityDestinationMap>;

/// Direction of the connection flow
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionDirection {
    /// Request from source to target
    Request,
    /// Response from target to source
    Response,
}

fn default_direction() -> ConnectionDirection {
    ConnectionDirection::Request
}

/// Type of metric being recorded
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum MetricType {
    /// Metrics from channel (agent-to-agent) communication
    Channel,
    /// Metrics from pipe (agent-to-external-service) execution
    Pipe,
}

fn default_metric_type() -> MetricType {
    MetricType::Channel
}

/// Connection status
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum ConnectionStatus {
    Success,
    Failed,
    GatewayFault,
}

/// Per-stage token, cost and latency usage captured for a single pipe
/// execution. Attached to a pipe `ConnectionMetric`/`ConnectionDataPoint` so the
/// surface monitoring view can break LLM / Judge / Jury usage out of the grand
/// totals.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct StageUsageMetric {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost: f64,
    pub latency_ms: u64,
    /// The part of `cost` billed to the account (zero for calls on owned
    /// keys). Absent on metrics recorded without the split.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billed_cost: Option<f64>,
    /// The stage's model calls, by the source of the key each one sent.
    #[serde(default, skip_serializing_if = "crate::pipes::key_source::KeySourceCounts::is_empty")]
    pub key_sources: crate::pipes::key_source::KeySourceCounts,
}

/// LLM / Judge / Jury / Decider per-stage usage for one pipe execution.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PipeStageUsage {
    pub llm: StageUsageMetric,
    pub judge: StageUsageMetric,
    pub jury: StageUsageMetric,
    pub decider: StageUsageMetric,
    /// Source of the key the execution's main call sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<crate::pipes::key_source::KeySource>,
}

impl From<crate::pipes::config::StageUsage> for StageUsageMetric {
    fn from(u: crate::pipes::config::StageUsage) -> Self {
        Self {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cost: u.cost,
            latency_ms: u.latency_ms,
            billed_cost: Some(u.billed_cost),
            key_sources: u.key_sources,
        }
    }
}

/// Aggregated usage for one pipeline stage across many executions of a pipe,
/// surfaced on `PipeStats` for the surface monitoring cards.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct StageAggregate {
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost: f64,
    pub avg_latency_ms: f64,
}

/// Per-stage aggregates (LLM / Judge / Jury / Decider) for a single pipe.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipeStageStats {
    pub llm: StageAggregate,
    pub judge: StageAggregate,
    pub jury: StageAggregate,
    pub decider: StageAggregate,
}

/// Connection metrics entry (legacy format for in-memory)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetric {
    pub timestamp: DateTime<Utc>,
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub status: ConnectionStatus,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
    #[serde(default = "default_direction")]
    pub direction: ConnectionDirection,
    pub trace_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ucp_operation: Option<String>, // UCP operation type
    /// Active surface variant alias. Identifies which variant of the
    /// channel handled the connection so dashboards can slice
    /// per-variant. `None` for channels with no variants or recorders
    /// that don't supply one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variant_alias: Option<String>,
    #[serde(default = "default_metric_type")]
    pub metric_type: MetricType,
    // Pipe-specific metrics (LLM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_cost: Option<f64>,
    // Latency breakdown (request=gateway processing, response=target processing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_gateway_processing_ms: Option<u64>, // Gateway request preparation/processing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_target_processing_ms: Option<u64>, // Target (LLM) processing time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_request_latency_ms: Option<u64>, // Gateway pre-processing time (auth, policy, extensions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_response_latency_ms: Option<u64>, // Gateway response processing time (URL rewrite, VP injection, validation)
    // Total latency from receiving request to returning response
    #[serde(default)]
    pub total_latency_ms: u64,
    // Enhanced distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
    // Enhanced metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
    /// Per-stage (LLM/Judge/Jury) token, cost and latency usage for this
    /// pipe execution. `None` for non-pipe metrics or failures.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stage_usage: Option<PipeStageUsage>,
    /// Whether this pipe execution was served from the response cache (no
    /// upstream call). A cache hit is successful traffic at `$0` provider spend.
    #[serde(default)]
    pub cache_hit: bool,
    /// Provider spend avoided by a cache hit (what the upstream call would have
    /// cost). `None` for non-cache metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_saved_cost: Option<f64>,
    /// Tokens avoided by a cache hit (the prompt + completion tokens the
    /// upstream call would have consumed). `None` for non-cache metrics.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_saved_tokens: Option<u64>,
}

/// Hierarchical connection data point for storage efficiency
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionDataPoint {
    pub timestamp: DateTime<Utc>,
    pub status: ConnectionStatus,
    pub latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_hash: Option<String>,
    #[serde(default = "default_direction")]
    pub direction: ConnectionDirection,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ucp_operation: Option<String>, // UCP operation type (e.g., "discovery", "checkout", "payment")
    /// Active surface variant alias. See `ConnectionMetric::variant_alias`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub variant_alias: Option<String>,
    #[serde(default = "default_metric_type")]
    pub metric_type: MetricType,
    // Pipe-specific metrics (LLM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_input_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_output_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_total_tokens: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_cost: Option<f64>,
    // Latency breakdown (request=gateway processing, response=target processing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_gateway_processing_ms: Option<u64>, // Gateway request preparation/processing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pipe_target_processing_ms: Option<u64>, // Target (LLM) processing time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_request_latency_ms: Option<u64>, // Gateway pre-processing time (auth, policy, extensions)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_response_latency_ms: Option<u64>, // Gateway response processing time (URL rewrite, VP injection, validation)
    // Total latency from receiving request to returning response
    #[serde(default)]
    pub total_latency_ms: u64,
    // Enhanced distributed tracing
    #[serde(skip_serializing_if = "Option::is_none")]
    pub correlation_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity: Option<String>,
    // Enhanced metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_count: Option<u32>,
    /// Per-stage (LLM/Judge/Jury) usage for this pipe execution. See
    /// `ConnectionMetric::stage_usage`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stage_usage: Option<PipeStageUsage>,
    /// See `ConnectionMetric::cache_hit`.
    #[serde(default)]
    pub cache_hit: bool,
    /// See `ConnectionMetric::cache_saved_cost`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_saved_cost: Option<f64>,
    /// See `ConnectionMetric::cache_saved_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_saved_tokens: Option<u64>,
}

/// Rule validation data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationDataPoint {
    pub timestamp: DateTime<Utc>,
    pub accepted: bool,
}

/// Time-series data point for graphing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesPoint {
    pub timestamp: String,
    pub count: usize,
    pub rule_accepts: usize,
    pub rule_denies: usize,
    pub failed: usize,
    pub gateway_faults: usize,
    /// Request-direction bytes transferred within this interval (per-interval
    /// sum of `request_bytes` across every datapoint in the bucket).
    pub request_bytes: u64,
    /// Response-direction bytes transferred within this interval (per-interval
    /// sum of `response_bytes` across every datapoint in the bucket).
    pub response_bytes: u64,
    /// LLM input tokens consumed within this interval (pipe datapoints only).
    pub input_tokens: u64,
    /// LLM output tokens produced within this interval (pipe datapoints only).
    pub output_tokens: u64,
}

/// Latency time-series data point
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyTimeSeriesPoint {
    pub timestamp: String,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub sample_count: usize,
}

/// Channel connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceStats {
    pub channel_config_id: String,
    pub total_connections: usize,
    pub successful: usize,
    pub failed: usize,
    pub gateway_faults: usize,
    /// Total request-direction bytes received from callers across all
    /// connections (sum of `request_bytes`).
    pub total_request_bytes: u64,
    /// Total response-direction bytes returned to callers across all
    /// connections (sum of `response_bytes`).
    pub total_response_bytes: u64,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Identity-channel connection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentityChannelStats {
    pub identity_hash: String,
    pub channel_config_id: String,
    pub total_count: usize,
    pub success_count: usize,
    pub deny_count: usize,
    pub fault_count: usize,
}

/// Pipe (LLM) execution statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeStats {
    pub pipe_id: String,
    pub pipe_name: Option<String>,
    pub provider: String,
    pub model: String,
    pub total_requests: usize,
    pub successful_requests: usize,
    pub failed_requests: usize,
    pub total_input_tokens: u64,
    pub total_output_tokens: u64,
    pub total_cost: f64,
    pub avg_latency_ms: f64,
    pub avg_gateway_processing_ms: f64, // Average gateway processing time
    pub avg_target_processing_ms: f64,  // Average target (LLM) processing time
    pub avg_request_bytes: u64,
    pub avg_response_bytes: u64,
    /// Total request bytes sent upstream across all executions (sum of
    /// `request_bytes`). Complements the average for cumulative volume.
    pub total_request_bytes: u64,
    /// Total response bytes received from upstream across all executions
    /// (sum of `response_bytes`).
    pub total_response_bytes: u64,
    /// Per-stage (LLM/Judge/Jury) aggregates driving the surface monitoring
    /// cards.
    #[serde(default)]
    pub stage_usage: PipeStageStats,
    /// Number of executions served from the response cache (no upstream call).
    #[serde(default)]
    pub cache_hits: usize,
    /// Cumulative provider spend avoided by cache hits.
    #[serde(default)]
    pub cache_saved_cost: f64,
    /// Cumulative tokens avoided by cache hits.
    #[serde(default)]
    pub cache_saved_tokens: u64,
    pub last_activity: Option<chrono::DateTime<chrono::Utc>>,
}

/// Latency statistics by channel and source-destination pair
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStats {
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub avg_latency_ms: f64,
    pub min_latency_ms: u64,
    pub max_latency_ms: u64,
    pub p50_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub p99_latency_ms: u64,
    pub sample_count: usize,
}

/// Rule validation metrics per channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleMetric {
    pub channel_config_id: String,
    pub accept_count: u64,
    pub deny_count: u64,
}

/// Timestamped rule validation event
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleValidationEvent {
    pub timestamp: DateTime<Utc>,
    pub channel_config_id: String,
    pub accepted: bool,
}

/// Channel metrics data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceMetricsData {
    #[serde(default)]
    pub sources: SourceIdentityMap, // source -> identity -> destination -> trace_id -> datapoints
    #[serde(default)]
    pub rule_triggers: Vec<RuleValidationDataPoint>,
}

/// Complete metrics data for persistence (hierarchical format)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsData {
    #[serde(default)]
    pub connections: HashMap<String, SurfaceMetricsData>,
}

/// Result of truncating old metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TruncateMetricsResult {
    pub connections_removed: usize,
    pub events_removed: usize,
    pub connections_retained: usize,
    pub events_retained: usize,
}

/// Source-destination statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceDestStats {
    pub channel_config_id: String,
    pub source: String,
    pub destination: String,
    pub total_connections: usize,
    pub successful: usize,
    pub failed: usize,
    pub count: usize, // Alias for total_connections
}

/// UCP operation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UcpOperationStats {
    pub operation: String, // e.g., "discovery", "checkout", "payment"
    pub count: usize,
    pub successful: usize,
    pub failed: usize,
    pub percentage: f64, // Percentage of total UCP traffic
}
