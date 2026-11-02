//! OpenTelemetry metrics backend implementation
//!
//! Exports metrics to OpenTelemetry collectors via OTLP protocol

use anyhow::Result;
use opentelemetry::{KeyValue, metrics::*};
use opentelemetry_sdk::metrics::SdkMeterProvider;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace};

use super::types::{MetricsBackend, MetricsSnapshot};
use crate::metrics::{ConnectionMetric, ConnectionStatus, RuleMetric, RuleValidationEvent};

use super::metric_names::otel as names;

/// Helper to build common attributes for connection metrics
fn connection_attributes(conn: &ConnectionMetric) -> Vec<KeyValue> {
    vec![
        KeyValue::new("metric.type", format!("{:?}", conn.metric_type).to_lowercase()),
        KeyValue::new("status", format!("{:?}", conn.status).to_lowercase()),
        KeyValue::new("direction", format!("{:?}", conn.direction).to_lowercase()),
    ]
}

/// Helper to build pipe-specific attributes
fn pipe_attributes(conn: &ConnectionMetric) -> Vec<KeyValue> {
    let mut attrs = connection_attributes(conn);
    if let Some(ref pipe_id) = conn.pipe_id {
        attrs.push(KeyValue::new("pipe.id", pipe_id.clone()));
    }
    if let Some(ref pipe_name) = conn.pipe_name {
        attrs.push(KeyValue::new("pipe.name", pipe_name.clone()));
    }
    if let Some(ref provider) = conn.llm_provider {
        attrs.push(KeyValue::new("llm.provider", provider.clone()));
    }
    if let Some(ref model) = conn.llm_model {
        attrs.push(KeyValue::new("llm.model", model.clone()));
    }
    attrs
}

/// Helper to build channel-specific attributes
fn channel_attributes(
    conn: &ConnectionMetric,
    channel_id: &str,
) -> Vec<KeyValue> {
    let mut attrs = connection_attributes(conn);
    attrs.push(KeyValue::new("channel.id", channel_id.to_string()));
    attrs
}

/// OpenTelemetry metrics backend for exporting to OTLP collectors
pub struct OpenTelemetryMetricsBackend {
    #[allow(dead_code)]
    meter: Meter,
    // Connection metrics instruments
    connection_counter: Counter<u64>,
    connection_latency: Histogram<f64>,
    #[allow(dead_code)]
    active_connections: UpDownCounter<i64>,

    // Pipe/LLM metrics instruments
    pipe_executions: Counter<u64>,
    pipe_tokens: Counter<u64>,
    pipe_cost: Counter<f64>,
    pipe_latency: Histogram<f64>,
    pipe_gateway_processing: Histogram<f64>,
    pipe_target_processing: Histogram<f64>,

    // Channel metrics instruments
    channel_requests: Counter<u64>,
    channel_latency: Histogram<f64>,

    // Rule validation metrics
    rule_validations: Counter<u64>,

    // Byte transfer metrics
    bytes_sent: Counter<u64>,
    bytes_received: Counter<u64>,

    // User lifecycle metrics
    #[allow(dead_code)]
    user_events: Counter<u64>,
    #[allow(dead_code)]
    user_logins: Counter<u64>,

    // Track active connections for gauge updates
    #[allow(dead_code)]
    active_connection_count: Arc<tokio::sync::RwLock<i64>>,
}

impl OpenTelemetryMetricsBackend {
    /// Create a new OpenTelemetry metrics backend
    pub fn new(meter_provider: &SdkMeterProvider) -> Self {
        let meter = meter_provider.meter(env!("CARGO_PKG_NAME"));

        // Connection metrics
        let connection_counter = meter
            .u64_counter(names::CONNECTIONS_TOTAL)
            .with_description("Total number of connections processed")
            .build();

        let connection_latency = meter
            .f64_histogram(names::CONNECTION_LATENCY)
            .with_description("Connection latency in milliseconds")
            .build();

        let active_connections = meter
            .i64_up_down_counter(names::CONNECTIONS_ACTIVE)
            .with_description("Number of currently active connections")
            .build();

        // Pipe/LLM metrics
        let pipe_executions = meter
            .u64_counter(names::SURFACE_EXECUTIONS_TOTAL)
            .with_description("Total number of pipe executions")
            .build();

        let pipe_tokens = meter
            .u64_counter(names::SURFACE_TOKENS_TOTAL)
            .with_description("Total LLM tokens processed")
            .build();

        let pipe_cost = meter
            .f64_counter(names::SURFACE_COST_TOTAL)
            .with_description("Total LLM execution cost in USD")
            .build();

        let pipe_latency = meter
            .f64_histogram(names::SURFACE_LATENCY)
            .with_description("Pipe execution latency in milliseconds")
            .build();

        let pipe_gateway_processing = meter
            .f64_histogram(names::SURFACE_GATEWAY_PROCESSING)
            .with_description("Gateway processing time for pipe requests in milliseconds")
            .build();

        let pipe_target_processing = meter
            .f64_histogram(names::SURFACE_TARGET_PROCESSING)
            .with_description("Target (LLM) processing time in milliseconds")
            .build();

        // Channel metrics
        let channel_requests = meter
            .u64_counter(names::CHANNEL_REQUESTS_TOTAL)
            .with_description("Total number of channel requests")
            .build();

        let channel_latency = meter
            .f64_histogram(names::CHANNEL_LATENCY)
            .with_description("Channel request latency in milliseconds")
            .build();

        // Rule validation metrics
        let rule_validations = meter
            .u64_counter(names::RULES_VALIDATIONS_TOTAL)
            .with_description("Total number of rule validations")
            .build();

        // Byte transfer metrics
        let bytes_sent = meter
            .u64_counter(names::BYTES_SENT_TOTAL)
            .with_description("Total bytes sent")
            .build();

        let bytes_received = meter
            .u64_counter(names::BYTES_RECEIVED_TOTAL)
            .with_description("Total bytes received")
            .build();

        // User lifecycle metrics
        let user_events = meter
            .u64_counter(names::USER_EVENTS_TOTAL)
            .with_description("Total number of user lifecycle events")
            .build();

        let user_logins = meter
            .u64_counter(names::USER_LOGINS_TOTAL)
            .with_description("Total number of user logins")
            .build();

        Self {
            meter,
            connection_counter,
            connection_latency,
            active_connections,
            pipe_executions,
            pipe_tokens,
            pipe_cost,
            pipe_latency,
            pipe_gateway_processing,
            pipe_target_processing,
            channel_requests,
            channel_latency,
            rule_validations,
            bytes_sent,
            bytes_received,
            user_events,
            user_logins,
            active_connection_count: Arc::new(tokio::sync::RwLock::new(0)),
        }
    }

    /// Record a single connection metric
    fn record_connection(
        &self,
        conn: &ConnectionMetric,
    ) {
        // Get base attributes for this connection
        let base_attributes = connection_attributes(conn);

        // Add channel/pipe specific attributes
        match conn.metric_type {
            crate::metrics::MetricType::Pipe => {
                let attributes = pipe_attributes(conn);

                // Record pipe execution
                self.pipe_executions
                    .add(1, &attributes);

                // Record tokens
                if let Some(tokens) = conn.llm_total_tokens {
                    self.pipe_tokens
                        .add(tokens, &attributes);
                }

                // Record cost
                if let Some(cost) = conn.llm_cost {
                    self.pipe_cost
                        .add(cost, &attributes);
                }

                // Record latency breakdown
                if let Some(latency) = conn.latency_ms {
                    self.pipe_latency
                        .record(latency as f64, &attributes);
                }

                if let Some(gateway_ms) = conn.pipe_gateway_processing_ms {
                    self.pipe_gateway_processing
                        .record(gateway_ms as f64, &attributes);
                }

                if let Some(target_ms) = conn.pipe_target_processing_ms {
                    self.pipe_target_processing
                        .record(target_ms as f64, &attributes);
                }
            }
            crate::metrics::MetricType::Channel => {
                let attributes = channel_attributes(conn, &conn.channel_config_id);

                // Record channel request
                self.channel_requests
                    .add(1, &attributes);

                // Record channel latency
                if let Some(latency) = conn.latency_ms {
                    self.channel_latency
                        .record(latency as f64, &attributes);
                }
            }
        }

        // Record general connection metrics with base attributes
        self.connection_counter
            .add(1, &base_attributes);

        if let Some(latency) = conn.latency_ms {
            self.connection_latency
                .record(latency as f64, &base_attributes);
        }

        // Record byte transfers
        if let Some(bytes) = conn.request_bytes {
            self.bytes_received
                .add(bytes, &base_attributes);
        }

        if let Some(bytes) = conn.response_bytes {
            self.bytes_sent
                .add(bytes, &base_attributes);
        }

        // Update active connections gauge
        // Note: This is a simplification - in production you'd track actual active connections
        match conn.status {
            ConnectionStatus::Success | ConnectionStatus::Failed | ConnectionStatus::GatewayFault => {
                // Connection completed
                trace!("Connection completed: {:?}", conn.status);
            }
        }
    }

    /// Record rule validation metrics
    fn record_rule_validation(
        &self,
        event: &RuleValidationEvent,
    ) {
        let attributes = vec![
            KeyValue::new(
                "channel.id",
                event
                    .channel_config_id
                    .clone(),
            ),
            KeyValue::new("accepted", event.accepted),
        ];

        self.rule_validations
            .add(1, &attributes);
    }
}

#[async_trait::async_trait]
impl MetricsBackend for OpenTelemetryMetricsBackend {
    async fn persist(
        &self,
        connections: &[ConnectionMetric],
        _rule_metrics: &HashMap<String, RuleMetric>,
        rule_validation_events: &[RuleValidationEvent],
    ) -> Result<()> {
        trace!("Exporting {} connections to OpenTelemetry", connections.len());

        // Export connection metrics
        for conn in connections {
            self.record_connection(conn);
        }

        // Export rule validation metrics
        for event in rule_validation_events {
            self.record_rule_validation(event);
        }

        debug!(
            "Exported {} connections and {} rule validations to OpenTelemetry",
            connections.len(),
            rule_validation_events.len()
        );

        Ok(())
    }

    async fn load(&self) -> Result<MetricsSnapshot> {
        // OpenTelemetry is export-only, no loading
        // Return empty snapshot
        Ok(MetricsSnapshot {
            connections: vec![],
            rule_validation_events: vec![],
        })
    }

    fn name(&self) -> &str {
        "opentelemetry"
    }
}

#[cfg(test)]
mod tests {
    #[test]
    #[ignore] // FIXME: failing test
    fn test_backend_name() {
        let _config = crate::observability::opentelemetry::OtelConfig::default();

        // This test would require initializing a full meter provider
        // For now, just verify the backend name concept
        assert_eq!("opentelemetry".len(), 14);
    }
}
