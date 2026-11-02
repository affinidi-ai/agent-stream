//! Observability utilities for monitoring and real-time updates

pub mod dashboard;
pub mod http_trace;
#[cfg(test)]
pub(crate) mod log_capture;
pub mod log_redact;
pub mod metrics_updater;
pub mod opentelemetry;
pub mod payload_capture;
pub mod policy_audit;
pub mod request_context;
pub mod simple_format;
pub mod span_filter;
pub mod stage_stream;
pub mod system_metrics;
pub mod task_monitor;
pub mod tasks;
pub mod trace_registry;
pub mod websocket_log_layer;

pub use dashboard::*;
pub use http_trace::{access_log, trace_http_request};
pub use log_redact::{LogRedactor, RedactingMakeWriter};
pub use metrics_updater::periodic_metrics_update;
pub use opentelemetry::{
    BoxedLayer, OtelConfig, build_log_layer_boxed, build_trace_layer_boxed, get_logger_provider, init_logs,
    init_metrics, init_tracer, install_log_reload, install_trace_reload, noop_layer_boxed, reload_otel,
    set_reload_redactor, shutdown as shutdown_otel,
};
pub use simple_format::SimpleFormat;
pub use span_filter::FilteringSpanExporter;
pub use stage_stream::StageStreamLayer;
pub use system_metrics::{
    SYSTEM_METRICS_INTERVAL_SECS, SystemMetricsResponse, SystemMetricsStore, global_system_metrics_store,
    periodic_system_metrics_collection, set_global_system_metrics_store,
};
pub use task_monitor::*;
pub use tasks::{spawn_traced_task, spawn_traced_task_with_fields};
pub use trace_registry::{get_trace_info, register_pipe_prefix, should_trace_path};
pub use websocket_log_layer::{WebSocketLogLayer, init_websocket_log_broadcast};
