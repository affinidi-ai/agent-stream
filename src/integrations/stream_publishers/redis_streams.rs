use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use tracing::info;

use super::StreamPublisher;
use crate::integrations::destinations::{self, DestinationError};

pub struct RedisPublisher;

/// The connection settings of `redis_url`, checked and pinned to the checked
/// address, for a test or a delivery alike.
async fn checked_connection(config: &Value) -> Result<redis::ConnectionInfo> {
    let redis_url = config
        .get("redis_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| DestinationError::Invalid("redis_url is required".to_string()))?;
    Ok(destinations::redis(redis_url).await?)
}

#[async_trait]
impl StreamPublisher for RedisPublisher {
    async fn publish(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
        _integration_id: &str,
    ) -> Result<()> {
        let connection = checked_connection(config).await?;

        info!("Publishing to Redis Stream '{}' at '{}'", topic, connection.addr());

        use redis::AsyncCommands;

        let client = redis::Client::open(connection).context("Failed to create Redis client")?;

        let mut con = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        // Convert event payload to Redis Stream items (field-value pairs)
        let event_json = serde_json::to_string(event).context("Failed to serialize event payload")?;

        // Use XADD to add entry to Redis Stream
        // Redis Streams store entries as field-value pairs, we'll use a single "data" field
        let _stream_id: String = con
            .xadd(topic, "*", &[("data", event_json.as_str())])
            .await
            .context("Failed to add event to Redis Stream")?;

        info!("Successfully published event to Redis Stream '{}'", topic);
        Ok(())
    }

    async fn test_connection(
        &self,
        topic: &str,
        event: &Value,
        config: &Value,
    ) -> Result<String> {
        let connection = checked_connection(config).await?;

        info!("Testing Redis Streams connection to: {}", connection.addr());

        use redis::AsyncCommands;

        let client = redis::Client::open(connection).context("Failed to create Redis client")?;

        let mut con = client
            .get_multiplexed_async_connection()
            .await
            .context("Failed to connect to Redis")?;

        let event_json = serde_json::to_string(event).context("Failed to serialize event")?;

        let _stream_id: String = con
            .xadd(topic, "*", &[("data", event_json.as_str())])
            .await
            .context("Failed to add test event to Redis Stream")?;

        info!("Test event sent to Redis Stream '{}' successfully", topic);
        Ok(format!("Test event sent to Redis Stream '{}' successfully", topic))
    }
}
