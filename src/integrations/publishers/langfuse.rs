//! Langfuse observability publisher.
//!
//! Emits an LLM **trace + generation** to a Langfuse project via its public
//! ingestion API (`POST {host}/api/public/ingestion`, HTTP basic auth with the
//! project's public/secret key pair). Unlike the generic webhook, this captures
//! the LLM call as a first-class Langfuse generation with token usage, cost, and
//! (when the surface enabled `log_requests` / `log_responses`) the request and
//! response **content**.
//!
//! Configuration (`integration.configuration`):
//! - `host` — Langfuse base URL (default `https://cloud.langfuse.com`)
//! - `public_key` — project public key (basic-auth username)
//! - `secret_key` — project secret key (basic-auth password)

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::{Value, json};
use std::collections::HashMap;
use tracing::{error, info};

use super::IntegrationPublisher;
use crate::storage::Integration;

const DEFAULT_LANGFUSE_HOST: &str = "https://cloud.langfuse.com";

pub struct LangfusePublisher;

/// Parse a string variable into `u64`, defaulting to `0`.
fn u64_var(
    variables: &HashMap<String, String>,
    key: &str,
) -> u64 {
    variables
        .get(key)
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(0)
}

/// Interpret a captured content string as JSON when possible, else as a plain
/// string. Empty/absent content becomes JSON `null`.
fn content_value(
    variables: &HashMap<String, String>,
    key: &str,
) -> Value {
    match variables
        .get(key)
        .filter(|s| !s.is_empty())
    {
        None => Value::Null,
        Some(raw) => serde_json::from_str::<Value>(raw).unwrap_or_else(|_| Value::String(raw.clone())),
    }
}

impl LangfusePublisher {
    /// Build the Langfuse ingestion batch (a trace-create plus a
    /// generation-create) from the pipe-execution runtime variables.
    fn build_batch(variables: &HashMap<String, String>) -> Value {
        let empty = String::new();
        let trace_id = variables
            .get("TRACE_ID")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        let name = variables
            .get("SURFACE_NAME")
            .unwrap_or(&empty)
            .clone();
        let model = variables
            .get("SURFACE_MODEL")
            .unwrap_or(&empty)
            .clone();
        let provider = variables
            .get("SURFACE_PROVIDER")
            .unwrap_or(&empty)
            .clone();
        let timestamp = variables
            .get("TIMESTAMP")
            .cloned()
            .unwrap_or_else(|| chrono::Utc::now().to_rfc3339());
        let input = content_value(variables, "REQUEST_CONTENT");
        let output = content_value(variables, "RESPONSE_CONTENT");
        let cost_usd = variables
            .get("COST_USD")
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0);

        let metadata = json!({
            "provider": provider,
            "cost_usd": cost_usd,
            "latency_ms": u64_var(variables, "LATENCY_MS"),
            "pipe_id": variables.get("SURFACE_ID").cloned().unwrap_or_default(),
            "source": "agent-stream",
        });

        let usage = json!({
            "input": u64_var(variables, "INPUT_TOKENS"),
            "output": u64_var(variables, "OUTPUT_TOKENS"),
            "total": u64_var(variables, "TOTAL_TOKENS"),
            "unit": "TOKENS",
        });

        json!({
            "batch": [
                {
                    "id": uuid::Uuid::new_v4().to_string(),
                    "type": "trace-create",
                    "timestamp": timestamp,
                    "body": {
                        "id": trace_id,
                        "name": name,
                        "input": input,
                        "output": output,
                        "metadata": metadata,
                    }
                },
                {
                    "id": uuid::Uuid::new_v4().to_string(),
                    "type": "generation-create",
                    "timestamp": timestamp,
                    "body": {
                        "id": uuid::Uuid::new_v4().to_string(),
                        "traceId": trace_id,
                        "name": name,
                        "model": model,
                        "input": input,
                        "output": output,
                        "usage": usage,
                        "metadata": metadata,
                    }
                }
            ]
        })
    }
}

#[async_trait]
impl IntegrationPublisher for LangfusePublisher {
    fn name(&self) -> &str {
        "langfuse"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["llm_tracing", "io_capture"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["public_key", "secret_key"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        config
            .get("public_key")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Missing public_key in Langfuse configuration"))?;
        config
            .get("secret_key")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("Missing secret_key in Langfuse configuration"))?;
        if let Some(host) = config
            .get("host")
            .and_then(|v| v.as_str())
        {
            crate::url_validation::validate_resolved_webhook_url_blocking(host).map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok(())
    }

    async fn publish(
        &self,
        integration: &Integration,
        _subject: &str,
        _message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        let host = integration
            .configuration
            .get("host")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .unwrap_or(DEFAULT_LANGFUSE_HOST)
            .trim_end_matches('/');
        let public_key = integration.configuration["public_key"]
            .as_str()
            .context("Missing public_key in Langfuse configuration")?;
        let secret_key = integration.configuration["secret_key"]
            .as_str()
            .context("Missing secret_key in Langfuse configuration")?;

        let url = format!("{host}/api/public/ingestion");
        crate::url_validation::validate_resolved_webhook_url(&url)
            .await
            .map_err(|e| anyhow::anyhow!(e))?;

        let payload = Self::build_batch(variables);

        let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(15))?;

        let response = client
            .post(&url)
            .basic_auth(public_key, Some(secret_key))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .context("Failed to send Langfuse ingestion request")?;

        if response.status().is_success() {
            info!("Langfuse trace sent via integration: {}", integration.name);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            error!("Langfuse ingestion failed with status {}: {}", status, body);
            Err(anyhow::anyhow!("Langfuse ingestion failed: {} - {}", status, body))
        }
    }

    async fn test(
        &self,
        config: &Value,
        _content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        self.validate_config(config)?;
        let _ = Self::build_batch(variables);
        Ok("Langfuse configuration valid".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_batch_shapes_trace_and_generation() {
        let mut vars = HashMap::new();
        vars.insert("TRACE_ID".to_string(), "trace-123".to_string());
        vars.insert("SURFACE_NAME".to_string(), "my-surface".to_string());
        vars.insert("SURFACE_MODEL".to_string(), "gpt-4o".to_string());
        vars.insert("INPUT_TOKENS".to_string(), "100".to_string());
        vars.insert("OUTPUT_TOKENS".to_string(), "50".to_string());
        vars.insert("TOTAL_TOKENS".to_string(), "150".to_string());
        vars.insert("REQUEST_CONTENT".to_string(), r#"{"messages":[{"role":"user","content":"hi"}]}"#.to_string());
        vars.insert("RESPONSE_CONTENT".to_string(), r#"{"choices":[]}"#.to_string());

        let batch = LangfusePublisher::build_batch(&vars);
        let events = batch["batch"]
            .as_array()
            .expect("batch array");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["type"], "trace-create");
        assert_eq!(events[0]["body"]["id"], "trace-123");
        assert_eq!(events[1]["type"], "generation-create");
        assert_eq!(events[1]["body"]["traceId"], "trace-123");
        assert_eq!(events[1]["body"]["model"], "gpt-4o");
        assert_eq!(events[1]["body"]["usage"]["total"], 150);
        // Content is parsed back into JSON when it is valid JSON.
        assert!(events[1]["body"]["input"]["messages"].is_array());
    }

    #[test]
    fn content_value_handles_plain_and_absent() {
        let mut vars = HashMap::new();
        vars.insert("RESPONSE_CONTENT".to_string(), "not json".to_string());
        assert_eq!(content_value(&vars, "RESPONSE_CONTENT"), Value::String("not json".to_string()));
        assert_eq!(content_value(&vars, "MISSING"), Value::Null);
    }
}
