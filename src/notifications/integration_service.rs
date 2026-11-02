use anyhow::{Context, Result};
use tracing::warn;

use crate::storage::get_integration_storage;
use super::publishers::INTEGRATION_REGISTRY;

/// Trigger a integration by ID with the given event data and optional template variables
pub async fn trigger_integration(integration_id: &str, subject: &str, message: &str) -> Result<()> {
    trigger_integration_with_variables(integration_id, subject, message, &std::collections::HashMap::new()).await
}

/// Trigger a integration by ID with template variable substitution
pub async fn trigger_integration_with_variables(
    integration_id: &str, 
    subject: &str, 
    message: &str,
    variables: &std::collections::HashMap<String, String>
) -> Result<()> {
    let storage = get_integration_storage()
        .context("Notifier storage not initialized")?;
    
    let integration = storage.load(integration_id)
        .map_err(|e| anyhow::anyhow!("Failed to get integration: {}", e))?;
    
    if integration.status != "active" {
        warn!("Notifier {} is not active, skipping notification", integration_id);
        return Ok(());
    }
    
    // Get the publisher from the registry
    let publisher = INTEGRATION_REGISTRY.get(&integration.integration_type)
        .ok_or_else(|| anyhow::anyhow!("Unknown integration type: {}", integration.integration_type))?;
    
    // Use the publisher to send the notification
    publisher.publish(&integration, subject, message, variables).await
}

/// Trigger multiple integrations by their IDs
pub async fn trigger_integrations(integration_ids: &[String], subject: &str, message: &str) -> Result<Vec<(String, Result<()>)>> {
    let mut results = Vec::with_capacity(integration_ids.len());
    
    for integration_id in integration_ids {
        let result = trigger_integration(integration_id, subject, message).await;
        results.push((integration_id.clone(), result));
    }
    
    Ok(results)
}

/// Trigger all active integrations of a specific type
#[allow(dead_code)]
pub async fn trigger_integrations_by_type(integration_type: &str, subject: &str, message: &str) -> Result<Vec<(String, Result<()>)>> {
    let storage = get_integration_storage()
        .context("Notifier storage not initialized")?;
    
    let all_notifiers = storage.list()
        .map_err(|e| anyhow::anyhow!("Failed to list integrations: {}", e))?;
    
    let filtered: Vec<_> = all_notifiers
        .into_iter()
        .filter(|n| n.integration_type == integration_type && n.status == "active")
        .collect();
    
    let mut results = Vec::with_capacity(filtered.len());
    let variables = std::collections::HashMap::new(); // Empty variables for this API
    
    // Get the publisher from the registry
    let publisher = INTEGRATION_REGISTRY.get(integration_type)
        .ok_or_else(|| anyhow::anyhow!("Unknown integration type: {}", integration_type))?;
    
    for integration in filtered {
        let result = publisher.publish(&integration, subject, message, &variables).await;
        results.push((integration.id.clone(), result));
    }
    
    Ok(results)
}

