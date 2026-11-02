use super::publishers::INTEGRATION_REGISTRY;
use crate::storage::IntegrationStorage;
/// Configuration validation for integrations on every switch to Active
use tracing::{error, info, warn};

/// Validate all active integrations once the instance reports ready.
/// Logs warnings for invalid configurations and never changes readiness.
pub async fn validate_all_integrations(storage: &IntegrationStorage) {
    info!("Starting integration configuration validation...");

    let integrations = match storage.list().await {
        Ok(list) => list,
        Err(e) => {
            error!("Failed to list integrations for validation: {}", e);
            return;
        }
    };

    let active_integrations: Vec<_> = integrations
        .iter()
        .filter(|i| i.status == "active")
        .collect();

    info!("Validating {} active integration(s)", active_integrations.len());

    let mut valid_count = 0;
    let mut invalid_count = 0;

    for integration in active_integrations {
        // Get the publisher for this integration type
        let publisher = match INTEGRATION_REGISTRY.get(&integration.integration_type) {
            Some(p) => p,
            None => {
                warn!(
                    "Integration '{}' (id: {}) has unknown type '{}' - skipping validation",
                    integration.name, integration.id, integration.integration_type
                );
                invalid_count += 1;
                continue;
            }
        };

        let validated = crate::storage::integration_credentials::with_resolved_secrets(integration)
            .await
            .and_then(|resolved| publisher.validate_config(&resolved.configuration));
        if let Err(e) = validated {
            warn!("Integration '{}' (id: {}) has invalid configuration: {}", integration.name, integration.id, e);
            invalid_count += 1;
        } else {
            valid_count += 1;
        }

        // Validate content template if the publisher supports it
        if let Err(e) = publisher.validate_content(&integration.content) {
            warn!("Integration '{}' (id: {}) has invalid content template: {}", integration.name, integration.id, e);
            // Don't count this as invalid since validate_content is optional
        }
    }

    if invalid_count == 0 {
        info!("✓ Integration validation complete: all {} active integration(s) have valid configurations", valid_count);
    } else {
        warn!(
            "⚠ Integration validation complete: {}/{} active integration(s) have valid configurations, {} invalid",
            valid_count,
            valid_count + invalid_count,
            invalid_count
        );
        warn!("  Invalid integrations will be skipped when triggered");
    }
}
