use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::StreamPublisher;
use crate::integrations::destinations::{self, DestinationError};

pub struct KafkaPublisher;

/// The `brokers` list, every broker checked and the list rebuilt from them,
/// for a test or a delivery alike.
async fn checked_brokers(config: &Value) -> Result<String> {
    let brokers = config
        .get("brokers")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DestinationError::Invalid("brokers is required".to_string()))?;
    Ok(destinations::kafka_brokers(brokers).await?)
}

#[async_trait]
impl StreamPublisher for KafkaPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        integration_id: &str,
    ) -> Result<()> {
        let brokers = checked_brokers(config).await?;

        info!("Publishing to Kafka topic '{}' on brokers '{}'", topic, brokers);

        use rdkafka::config::ClientConfig;
        use rdkafka::producer::{FutureProducer, FutureRecord};

        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", &brokers);
        kafka_config.set("message.timeout.ms", "30000");

        // Configure connection retry behavior with exponential backoff
        kafka_config.set("reconnect.backoff.ms", "1000"); // Start with 1 second
        kafka_config.set("reconnect.backoff.max.ms", "60000"); // Max 60 seconds
        kafka_config.set("socket.connection.setup.timeout.ms", "10000"); // 10s connection timeout
        kafka_config.set("socket.timeout.ms", "60000"); // 60s socket timeout
        kafka_config.set("metadata.max.age.ms", "180000"); // Refresh metadata every 3 min
        kafka_config.set("log_level", "3"); // Reduce log verbosity (warn level)

        // Add authentication if configured
        if let Some(auth_type) = config
            .get("auth_type")
            .and_then(|v| v.as_str())
            && auth_type == "sasl"
            && let Some(username) = config
                .get("sasl_username")
                .and_then(|v| v.as_str())
        {
            kafka_config.set("security.protocol", "SASL_PLAINTEXT");
            kafka_config.set("sasl.mechanism", "PLAIN");
            kafka_config.set("sasl.username", username);
            if let Some(password) = config
                .get("sasl_password")
                .and_then(|v| v.as_str())
            {
                kafka_config.set("sasl.password", password);
            }
        }

        let producer: FutureProducer = kafka_config
            .create()
            .context("Failed to create Kafka producer")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        let record = FutureRecord::to(topic)
            .payload(&event_json)
            .key(integration_id);

        producer
            .send(record, std::time::Duration::from_secs(30))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Failed to send event to Kafka: {:?}", e))?;

        info!("Successfully published event to Kafka topic '{}'", topic);
        Ok(())
    }

    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String> {
        let brokers = checked_brokers(config).await?;

        info!("Testing Kafka connection to brokers: {}", brokers);

        use rdkafka::config::ClientConfig;
        use rdkafka::producer::{FutureProducer, FutureRecord};

        let mut kafka_config = ClientConfig::new();
        kafka_config.set("bootstrap.servers", &brokers);
        kafka_config.set("message.timeout.ms", "30000");

        // Configure connection retry behavior with exponential backoff
        kafka_config.set("reconnect.backoff.ms", "1000"); // Start with 1 second
        kafka_config.set("reconnect.backoff.max.ms", "60000"); // Max 60 seconds
        kafka_config.set("socket.connection.setup.timeout.ms", "10000"); // 10s connection timeout
        kafka_config.set("socket.timeout.ms", "60000"); // 60s socket timeout
        kafka_config.set("metadata.max.age.ms", "180000"); // Refresh metadata every 3 min
        kafka_config.set("log_level", "3"); // Reduce log verbosity (warn level)

        // Add authentication if configured
        if let Some(auth_type) = config
            .get("auth_type")
            .and_then(|v| v.as_str())
            && auth_type == "sasl"
            && let Some(username) = config
                .get("sasl_username")
                .and_then(|v| v.as_str())
        {
            kafka_config.set("security.protocol", "SASL_PLAINTEXT");
            kafka_config.set("sasl.mechanism", "PLAIN");
            kafka_config.set("sasl.username", username);
            if let Some(password) = config
                .get("sasl_password")
                .and_then(|v| v.as_str())
            {
                kafka_config.set("sasl.password", password);
            }
        }

        let producer: FutureProducer = kafka_config
            .create()
            .context("Failed to create Kafka producer")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        let record = FutureRecord::to(topic)
            .payload(&event_json)
            .key("test-key");

        producer
            .send(record, std::time::Duration::from_secs(30))
            .await
            .map_err(|(e, _)| anyhow::anyhow!("Failed to send test event to Kafka: {:?}", e))?;

        info!("Test event sent to Kafka topic '{}' successfully", topic);
        Ok(format!("Test event sent to Kafka topic '{}' successfully", topic))
    }
}
