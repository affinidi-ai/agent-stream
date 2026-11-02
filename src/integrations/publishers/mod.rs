use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::storage::Integration;

mod email;
mod langfuse;
mod slack;
mod stream;
mod webhook;

pub use email::EmailPublisher;
pub use langfuse::LangfusePublisher;
pub use slack::SlackPublisher;
pub use stream::StreamPublisher;
pub use webhook::WebhookPublisher;

/// How much of a refusal's response body the log keeps.
const LOGGED_BODY_BYTES: usize = 256;

/// At most [`LOGGED_BODY_BYTES`] of `body`, cut on a character boundary.
fn truncated_body(body: &str) -> &str {
    if body.len() <= LOGGED_BODY_BYTES {
        return body;
    }
    let mut end = LOGGED_BODY_BYTES;
    while !body.is_char_boundary(end) {
        end -= 1;
    }
    &body[..end]
}

/// The error for a destination that answered `status`. Its body can echo the
/// request, a secret URL's path or token included, so the body is logged and
/// left out of the error, which a trigger or test answers to its caller. The
/// log keeps the start of the body as an escaped field, so a reply cannot
/// forge log lines, and names no URL.
pub(crate) fn refused_by_destination(
    what: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> anyhow::Error {
    tracing::error!(what, %status, body = ?truncated_body(body), "destination refused the delivery");
    anyhow::anyhow!("{what} failed with status {status}. The appliance log has the response.")
}

/// Trait for integration publishing implementations
#[async_trait]
pub trait IntegrationPublisher: Send + Sync {
    /// Get the name of this publisher
    #[allow(dead_code)]
    fn name(&self) -> &str;

    /// Get supported features for this publisher
    #[allow(dead_code)]
    fn supported_features(&self) -> Vec<&str> {
        vec![]
    }

    /// Get required configuration fields
    #[allow(dead_code)]
    fn required_config_fields(&self) -> Vec<&str> {
        vec![]
    }

    /// Validate configuration
    fn validate_config(
        &self,
        _config: &Value,
    ) -> Result<()> {
        Ok(())
    }

    /// Validate content template
    fn validate_content(
        &self,
        _content: &Value,
    ) -> Result<()> {
        Ok(())
    }

    /// Publish a notification through the integration
    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()>;

    /// Publish multiple notifications in batch (default: sequential)
    #[allow(dead_code)]
    async fn publish_batch(
        &self,
        integration: &Integration,
        items: Vec<(&str, &str, &HashMap<String, String>)>,
    ) -> Result<Vec<Result<()>>> {
        let mut results = Vec::new();
        for (subject, message, variables) in items {
            results.push(
                self.publish(integration, subject, message, variables)
                    .await,
            );
        }
        Ok(results)
    }

    /// Test the integration configuration
    #[allow(dead_code)]
    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String>;
}

/// Registry for managing integration publishers
pub struct PublisherRegistry {
    publishers: HashMap<String, Arc<dyn IntegrationPublisher>>,
}

impl PublisherRegistry {
    /// Create a new registry with all available publishers
    pub fn new() -> Self {
        let mut publishers: HashMap<String, Arc<dyn IntegrationPublisher>> = HashMap::new();

        publishers.insert("email".to_string(), Arc::new(EmailPublisher));
        publishers.insert("slack".to_string(), Arc::new(SlackPublisher));
        publishers.insert("webhook".to_string(), Arc::new(WebhookPublisher));
        publishers.insert("stream".to_string(), Arc::new(StreamPublisher));
        publishers.insert("langfuse".to_string(), Arc::new(LangfusePublisher));

        Self { publishers }
    }

    /// Get a publisher by integration type
    pub fn get(
        &self,
        integration_type: &str,
    ) -> Option<Arc<dyn IntegrationPublisher>> {
        self.publishers
            .get(integration_type)
            .cloned()
    }

    /// Register a custom publisher (for extensibility)
    #[allow(dead_code)]
    pub fn register(
        &mut self,
        integration_type: String,
        publisher: Arc<dyn IntegrationPublisher>,
    ) {
        self.publishers
            .insert(integration_type, publisher);
    }

    /// List all registered integration types
    #[allow(dead_code)]
    pub fn available_types(&self) -> Vec<String> {
        self.publishers
            .keys()
            .cloned()
            .collect()
    }
}

impl Default for PublisherRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Global registry instance
lazy_static::lazy_static! {
    pub static ref INTEGRATION_REGISTRY: PublisherRegistry = PublisherRegistry::new();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_refusal_keeps_the_status_and_leaves_the_response_body_out() {
        let refused =
            refused_by_destination("Webhook", reqwest::StatusCode::NOT_FOUND, "Cannot POST /in/T000/B000/secret-token")
                .to_string();

        assert_eq!(refused, "Webhook failed with status 404 Not Found. The appliance log has the response.");
    }

    #[test]
    fn a_logged_body_is_cut_to_its_limit_on_a_character_boundary() {
        assert_eq!(truncated_body("short"), "short");

        let exact = "a".repeat(LOGGED_BODY_BYTES);
        assert_eq!(truncated_body(&exact), exact);

        let long = format!("{}tail", "a".repeat(LOGGED_BODY_BYTES));
        assert_eq!(truncated_body(&long), "a".repeat(LOGGED_BODY_BYTES));

        let straddling = format!("{}é", "a".repeat(LOGGED_BODY_BYTES - 1));
        assert_eq!(truncated_body(&straddling), "a".repeat(LOGGED_BODY_BYTES - 1));
    }
}
