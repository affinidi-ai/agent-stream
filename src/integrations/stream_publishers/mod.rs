use anyhow::Result;
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

mod kafka;
mod kinesis;
mod pulsar;
mod redis_streams;

pub use kafka::KafkaPublisher;
pub use kinesis::KinesisPublisher;
pub use pulsar::PulsarPublisher;
pub use redis_streams::RedisPublisher;

/// Trait for stream publishing implementations
#[async_trait]
pub trait StreamPublisher: Send + Sync {
    /// Publish an event to the stream of a saved integration. The destination
    /// is checked again on every delivery, as `test_connection` checks it, since
    /// a name or secret that passed when it was saved can point elsewhere later.
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        integration_id: &str,
    ) -> Result<()>;

    /// Publish multiple events as a batch (optional optimization)
    #[allow(dead_code)]
    async fn publish_batch(
        &self,
        topic: &str,
        events: &[Value],
        config: &Value,
        integration_id: &str,
    ) -> Result<Vec<Result<()>>> {
        // Default implementation: publish sequentially
        let mut results = Vec::new();
        for event in events {
            let result = self
                .publish(topic, event, config, integration_id)
                .await;
            results.push(result);
        }
        Ok(results)
    }

    /// Send a test event with a configuration that may not be saved yet. A
    /// publisher that dials a host the configuration names checks it against
    /// the strict outbound policy first (see `integrations::destinations`).
    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String>;
}

/// Registry for managing stream publishers
pub struct PublisherRegistry {
    publishers: HashMap<String, Arc<dyn StreamPublisher>>,
}

impl PublisherRegistry {
    /// Create a new registry with all available publishers
    pub fn new() -> Self {
        let mut publishers: HashMap<String, Arc<dyn StreamPublisher>> = HashMap::new();

        publishers.insert("kafka".to_string(), Arc::new(KafkaPublisher));
        publishers.insert("kinesis".to_string(), Arc::new(KinesisPublisher));
        publishers.insert("pulsar".to_string(), Arc::new(PulsarPublisher));
        publishers.insert("redis".to_string(), Arc::new(RedisPublisher));

        Self { publishers }
    }

    /// Get a publisher by platform name
    pub fn get(
        &self,
        platform: &str,
    ) -> Option<Arc<dyn StreamPublisher>> {
        self.publishers
            .get(platform)
            .cloned()
    }

    /// Register a custom publisher (for extensibility)
    #[allow(dead_code)]
    pub fn register(
        &mut self,
        platform: String,
        publisher: Arc<dyn StreamPublisher>,
    ) {
        self.publishers
            .insert(platform, publisher);
    }

    /// List all registered platforms
    #[allow(dead_code)]
    pub fn available_platforms(&self) -> Vec<String> {
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
    pub static ref PUBLISHER_REGISTRY: PublisherRegistry = PublisherRegistry::new();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::integrations::destinations::DestinationError;
    use serde_json::json;

    #[tokio::test]
    async fn test_every_platform_refuses_an_internal_destination_before_connecting() {
        let cases = [
            ("kafka", json!({ "brokers": "10.0.0.5:9092" })),
            ("pulsar", json!({ "brokers": "pulsar://127.0.0.1:6650" })),
            ("redis", json!({ "redis_url": "redis://169.254.169.254:6379" })),
            ("redis", json!({ "redis_url": "unix:///var/run/redis.sock" })),
        ];

        for (platform, config) in cases {
            let publisher = match PUBLISHER_REGISTRY.get(platform) {
                Some(publisher) => publisher,
                None => panic!("{platform} is not registered"),
            };
            let tested = publisher
                .test_connection("events", &json!({}), &config)
                .await
                .map(|_| ());
            let delivered = publisher
                .publish("events", &json!({}), &config, "integration-1")
                .await;
            for (send, sent) in [("test", tested), ("delivery", delivered)] {
                match sent {
                    Err(error) => assert!(
                        error
                            .downcast_ref::<DestinationError>()
                            .is_some(),
                        "{platform} {send} {config}: {error:#}"
                    ),
                    Ok(()) => panic!("{platform} {send} {config} was not refused"),
                }
            }
        }
    }
}
