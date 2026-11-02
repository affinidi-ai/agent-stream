use super::filesystem::FileSystemNotificationStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Channel {
    pub id: String,
    pub name: String,
    pub prefix: String,
    pub description: Option<String>,
    pub enabled: Option<bool>,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

/// Trigger integrations when a channel is created
#[allow(dead_code)]
pub async fn trigger_channel_created(
    integration_store: &FileSystemNotificationStore,
    channel: &Channel,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&channel).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "channel.created".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add channel-specific variables
    runtime_values.insert("CHANNEL_ID".to_string(), channel.id.clone());
    runtime_values.insert("CHANNEL_NAME".to_string(), channel.name.clone());
    runtime_values.insert("CHANNEL_PREFIX".to_string(), channel.prefix.clone());
    runtime_values.insert(
        "CHANNEL_ENABLED".to_string(),
        channel
            .enabled
            .unwrap_or(true)
            .to_string(),
    );

    trigger_channel_integrations(integration_store, &runtime_values, "channel.created").await;
}

/// Trigger integrations when a channel is updated
#[allow(dead_code)]
pub async fn trigger_channel_updated(
    integration_store: &FileSystemNotificationStore,
    old_channel: &Channel,
    new_channel: &Channel,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&old_channel).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&new_channel).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "channel.updated".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add channel-specific variables (using new channel state)
    runtime_values.insert("CHANNEL_ID".to_string(), new_channel.id.clone());
    runtime_values.insert("CHANNEL_NAME".to_string(), new_channel.name.clone());
    runtime_values.insert("CHANNEL_PREFIX".to_string(), new_channel.prefix.clone());
    runtime_values.insert(
        "CHANNEL_ENABLED".to_string(),
        new_channel
            .enabled
            .unwrap_or(true)
            .to_string(),
    );

    trigger_channel_integrations(integration_store, &runtime_values, "channel.updated").await;
}

/// Trigger integrations when a channel is deleted
#[allow(dead_code)]
pub async fn trigger_channel_deleted(
    integration_store: &FileSystemNotificationStore,
    channel: &Channel,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&channel).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "channel.deleted".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add channel-specific variables
    runtime_values.insert("CHANNEL_ID".to_string(), channel.id.clone());
    runtime_values.insert("CHANNEL_NAME".to_string(), channel.name.clone());
    runtime_values.insert("CHANNEL_PREFIX".to_string(), channel.prefix.clone());
    runtime_values.insert(
        "CHANNEL_ENABLED".to_string(),
        channel
            .enabled
            .unwrap_or(true)
            .to_string(),
    );

    trigger_channel_integrations(integration_store, &runtime_values, "channel.deleted").await;
}

/// Trigger integrations when a channel is accessed
#[allow(dead_code)]
pub async fn trigger_channel_accessed(
    integration_store: &FileSystemNotificationStore,
    channel: &Channel,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&channel).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "channel.accessed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add channel-specific variables
    runtime_values.insert("CHANNEL_ID".to_string(), channel.id.clone());
    runtime_values.insert("CHANNEL_NAME".to_string(), channel.name.clone());
    runtime_values.insert("CHANNEL_PREFIX".to_string(), channel.prefix.clone());
    runtime_values.insert(
        "CHANNEL_ENABLED".to_string(),
        channel
            .enabled
            .unwrap_or(true)
            .to_string(),
    );

    trigger_channel_integrations(integration_store, &runtime_values, "channel.accessed").await;
}

/// Trigger integrations when an error occurs in a channel
#[allow(dead_code)]
pub async fn trigger_channel_error(
    integration_store: &FileSystemNotificationStore,
    channel: &Channel,
    error_message: &str,
) {
    let mut runtime_values = HashMap::new();

    // Include error in the NEW_STATE
    let mut state_map = serde_json::to_value(channel).unwrap_or_default();
    if let Some(obj) = state_map.as_object_mut() {
        obj.insert("error".to_string(), serde_json::Value::String(error_message.to_string()));
    }

    runtime_values.insert("OLD_STATE".to_string(), serde_json::to_string(&channel).unwrap_or_default());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&state_map).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "channel.error".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add channel-specific variables
    runtime_values.insert("CHANNEL_ID".to_string(), channel.id.clone());
    runtime_values.insert("CHANNEL_NAME".to_string(), channel.name.clone());
    runtime_values.insert("CHANNEL_PREFIX".to_string(), channel.prefix.clone());
    runtime_values.insert(
        "CHANNEL_ENABLED".to_string(),
        channel
            .enabled
            .unwrap_or(true)
            .to_string(),
    );
    runtime_values.insert("ERROR_MESSAGE".to_string(), error_message.to_string());

    trigger_channel_integrations(integration_store, &runtime_values, "channel.error").await;
}

/// Internal helper to trigger integrations with the 'channel' category
async fn trigger_channel_integrations(
    _integration_store: &FileSystemNotificationStore,
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    use tracing::{error, info, warn};

    // Get integration storage to list all integrations
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => storage,
        None => {
            warn!("Integration storage not initialized for {}; skipping integration trigger", event_type);
            return;
        }
    };

    // Get all integrations
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(e) => {
            error!("Failed to list integrations for {}: {}", event_type, e);
            return;
        }
    };

    // Filter to channel and general category integrations that are active
    let channel_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|n| {
            let matches_category = n.category.as_deref() == Some("channel") || n.category.as_deref() == Some("general");
            let is_active = n.status == "active";
            matches_category && is_active
        })
        .collect();

    if channel_integrations.is_empty() {
        info!("No active channel integrations configured for {}", event_type);
        return;
    }

    info!("Found {} active channel integrations to trigger for {}", channel_integrations.len(), event_type);

    // Trigger each integration
    for integration in channel_integrations {
        info!(
            "Triggering channel integration: {} (type: {}) for {}",
            integration.name, integration.integration_type, event_type
        );

        // Build subject and message from event
        let subject = format!("Channel Event: {}", event_type);
        let message = format!("Channel event '{}' occurred", event_type);

        // Use the integration trigger service with runtime variables
        if let Err(e) = crate::integrations::integration_service::trigger_integration_with_variables(
            &integration.id,
            &subject,
            &message,
            runtime_values,
        )
        .await
        {
            error!("Failed to trigger integration {} for {}: {}", integration.name, event_type, e);
        } else {
            info!("Successfully triggered channel integration: {}", integration.name);
        }
    }
}
