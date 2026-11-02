//! Pipe metrics tracking

use crate::metrics::{ConnectionStatus, MetricsStore};
use crate::pipes::config::{PipeConfig, PipeType};
use crate::pipes::types::llm::LLMMetrics;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// Derive the `(provider, model)` labels used for pipe metrics. LLM pipes report
/// their provider/model; other pipe types report a static label and an empty
/// model.
fn pipe_metric_labels(pipe_type: &PipeType) -> (String, String) {
    match pipe_type {
        PipeType::LLM { provider, .. } => (
            provider
                .provider_type()
                .to_string(),
            provider
                .model_name()
                .to_string(),
        ),
        PipeType::Webhook { .. } => ("webhook".to_string(), String::new()),
        PipeType::IDECatalog { .. } => ("ide_catalog".to_string(), String::new()),
    }
}

/// Record a failed pipe execution in the global metrics store.
///
/// Rejections (rate limit, circuit breaker, upstream/execution errors) return
/// an error response without an `ExecutionMetrics`, so they would otherwise
/// never reach the time series and the error-rate graph would stay at zero.
/// Recording is fire-and-forget on a detached task, mirroring the success path.
/// Callers own the `enable_metrics` gating decision.
pub fn spawn_pipe_failure_metric(
    metrics_store: Arc<MetricsStore>,
    pipe: &PipeConfig,
    pipe_id: String,
    pipe_name: String,
) {
    let (provider, model) = pipe_metric_labels(&pipe.pipe_type);
    spawn_pipe_failure_metric_labeled(metrics_store, pipe_id, pipe_name, provider, model);
}

/// Record a failed pipe execution under an explicit id + provider/model label.
///
/// Used to mirror a member-surface failure onto an IDE Surface front door (which
/// carries no `PipeConfig` at the failure site), so the front door's own
/// error-rate / traffic graphs reflect the failed call. Same fire-and-forget
/// discipline as [`spawn_pipe_failure_metric`].
pub fn spawn_pipe_failure_metric_labeled(
    metrics_store: Arc<MetricsStore>,
    pipe_id: String,
    pipe_name: String,
    provider: String,
    model: String,
) {
    tokio::spawn(async move {
        metrics_store
            .record_pipe_execution(
                pipe_id,
                Some(pipe_name),
                provider,
                model,
                ConnectionStatus::Failed,
                0,
                None,
                None,
                0,
                0,
                0.0,
                None,
                None,
                None,
                0,
                0,
                0,
                None,
            )
            .await;
    });
}

/// Pipe-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct PipeMetrics {
    pub pipe_id: String,
    pub timestamp: DateTime<Utc>,

    // Generic metrics
    pub requests: u64,
    pub successes: u64,
    pub failures: u64,
    pub avg_latency_ms: f64,

    // LLM-specific metrics (when pipe type is LLM)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub llm_metrics: Option<LLMMetrics>,
}

impl PipeMetrics {
    #[allow(dead_code)]
    pub fn new(pipe_id: String) -> Self {
        Self {
            pipe_id,
            timestamp: Utc::now(),
            requests: 0,
            successes: 0,
            failures: 0,
            avg_latency_ms: 0.0,
            llm_metrics: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::pipe_metric_labels;
    use crate::pipes::config::PipeType;
    use crate::pipes::types::llm::LLMProvider;

    #[test]
    fn llm_labels_report_provider_and_model() {
        let pipe_type = PipeType::LLM {
            provider: Box::new(LLMProvider::OpenAI {
                provider_type: "openai".to_string(),
                model: "gpt-4o".to_string(),
                api_key_secret: None,
                organization_id: None,
                base_url: None,
                temperature: None,
                max_tokens: None,
                top_p: None,
                frequency_penalty: None,
                presence_penalty: None,
            }),
            endpoint_path: None,
        };

        assert_eq!(pipe_metric_labels(&pipe_type), ("openai".to_string(), "gpt-4o".to_string()));
    }

    #[test]
    fn non_llm_labels_use_static_provider_and_empty_model() {
        assert_eq!(
            pipe_metric_labels(&PipeType::Webhook {
                endpoint: "https://hook.test".to_string()
            }),
            ("webhook".to_string(), String::new())
        );
    }
}
