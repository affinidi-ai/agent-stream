use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use tokio::task::JoinError;
use tokio_retry::RetryIf;
use tokio_retry::strategy::{ExponentialBackoff, jitter};
use tracing::{debug, error, instrument, warn};

use super::cache::get_cached_integration;
use super::errors::{IntegrationError, Result};
use super::publishers::INTEGRATION_REGISTRY;
use crate::storage::{Integration, IntegrationStorage, get_integration_storage};

/// Trigger a integration by ID with the given event data and optional template variables
#[allow(dead_code)]
pub async fn trigger_integration(
    integration_id: &str,
    subject: &str,
    message: &str,
) -> Result<()> {
    trigger_integration_with_variables(integration_id, subject, message, &std::collections::HashMap::new()).await
}

/// Trigger a integration by ID with template variable substitution.
///
/// Refuses governance audit integrations: they receive only the records the
/// VP Audit Log dispatcher forwards, so an event trigger or a connection
/// point cannot push its own, possibly caller-supplied, values into the
/// audit stream.
#[instrument(skip(variables), fields(integration_id = %integration_id))]
pub async fn trigger_integration_with_variables(
    integration_id: &str,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let integration = load_integration(integration_id).await?;
    refuse_audit_integration(&integration)?;
    publish_integration_with_variables(&integration, subject, message, variables).await
}

fn refuse_audit_integration(integration: &Integration) -> Result<()> {
    if super::audit_integration_triggers::is_audit_integration(integration) {
        return Err(IntegrationError::AuditOnly(integration.id.clone()));
    }
    Ok(())
}

/// Trigger any integration by ID, governance audit ones included. Only for
/// callers that already required `audit.view` for an audit integration, such
/// as the manual trigger endpoints.
#[instrument(skip(variables), fields(integration_id = %integration_id))]
pub async fn trigger_authorized_integration(
    integration_id: &str,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let integration = load_integration(integration_id).await?;
    publish_integration_with_variables(&integration, subject, message, variables).await
}

/// Load an integration (cache first, then storage) without publishing to it.
pub(crate) async fn load_integration(integration_id: &str) -> Result<Integration> {
    load_integration_for_trigger(integration_id, get_integration_storage()).await
}

/// Publish to an already-loaded integration (inactive integrations are refused).
pub(crate) async fn publish_to_integration(
    integration: &Integration,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    publish_integration_with_variables(integration, subject, message, variables).await
}

async fn load_integration_for_trigger(
    integration_id: &str,
    storage: Option<Arc<IntegrationStorage>>,
) -> Result<Integration> {
    match get_cached_integration(integration_id).await {
        Ok(cached) => Ok((*cached).clone()),
        Err(cache_error) => {
            debug!(integration_id = %integration_id, error = %cache_error, "Integration cache lookup failed; falling back to storage");
            let storage = storage.ok_or_else(|| {
                warn!(integration_id = %integration_id, "Integration storage unavailable; skipping integration trigger");
                IntegrationError::StorageError("Integration storage not initialized".to_string())
            })?;

            storage
                .load(integration_id)
                .await
                .map_err(|e| {
                    let message = e.to_string();
                    if message.contains("Integration not found") {
                        IntegrationError::NotFound(integration_id.to_string())
                    } else {
                        IntegrationError::StorageError(message)
                    }
                })
        }
    }
}

async fn publish_integration_with_variables(
    integration: &Integration,
    subject: &str,
    message: &str,
    variables: &std::collections::HashMap<String, String>,
) -> Result<()> {
    let start = Instant::now();
    let integration_id = integration.id.as_str();

    debug!(
        integration_id = %integration_id,
        integration_type = %integration.integration_type,
        integration_name = %integration.name,
        "Publishing event to integration"
    );

    if integration.status != "active" {
        warn!(
            integration_id = %integration_id,
            integration_type = %integration.integration_type,
            integration_name = %integration.name,
            status = %integration.status,
            "Inactive integration skipped"
        );
        return Err(IntegrationError::Inactive(integration.id.clone(), integration.status.clone()));
    }

    let publisher = INTEGRATION_REGISTRY
        .get(&integration.integration_type)
        .ok_or_else(|| {
            IntegrationError::UnknownType(
                integration
                    .integration_type
                    .clone(),
            )
        })?;

    let retry_strategy = ExponentialBackoff::from_millis(1000)
        .max_delay(Duration::from_secs(16))
        .take(5)
        .map(jitter);

    let integration_clone = integration.clone();
    let subject_clone = subject.to_string();
    let message_clone = message.to_string();
    let variables_clone = variables.clone();
    let publisher_clone = publisher.clone();
    let retry_integration_id = integration.id.clone();
    let retry_integration_type = integration
        .integration_type
        .clone();

    let publish_result = RetryIf::spawn(
        retry_strategy,
        || {
            let integration = integration_clone.clone();
            let subject = subject_clone.clone();
            let message = message_clone.clone();
            let variables = variables_clone.clone();
            let publisher = publisher_clone.clone();

            async move {
                let integration = crate::storage::integration_credentials::with_resolved_secrets(&integration).await?;
                publisher
                    .publish(&integration, &subject, &message, &variables)
                    .await
            }
        },
        |e: &anyhow::Error| {
            let retryable = is_retryable_publisher_error(e);
            if retryable {
                warn!(
                    integration_id = %retry_integration_id,
                    integration_type = %retry_integration_type,
                    error = %e,
                    "Retryable integration publisher failure"
                );
            } else {
                error!(
                    integration_id = %retry_integration_id,
                    integration_type = %retry_integration_type,
                    error = %e,
                    "Non-retryable integration publisher failure"
                );
            }
            retryable
        },
    )
    .await;

    if let Err(e) = publish_result {
        error!(
            integration_id = %integration_id,
            integration_type = %integration.integration_type,
            integration_name = %integration.name,
            duration_ms = start.elapsed().as_millis(),
            error = %e,
            "Integration publisher failed"
        );
        return Err(IntegrationError::PublisherError(e));
    }

    tracing::info!(
        integration_id = %integration_id,
        integration_type = %integration.integration_type,
        duration_ms = start.elapsed().as_millis(),
        status = "success",
        "Integration triggered successfully"
    );

    Ok(())
}

fn is_retryable_publisher_error(error: &anyhow::Error) -> bool {
    let message = format!("{error:#}").to_ascii_lowercase();
    message.contains("timeout") || message.contains("connection") || message.contains("network")
}

/// Trigger multiple integrations by their IDs (executed in parallel). The
/// caller must already have authorised each ID, audit integrations included.
#[instrument(skip(integration_ids))]
pub async fn trigger_integrations(
    integration_ids: &[String],
    subject: &str,
    message: &str,
) -> anyhow::Result<Vec<(String, Result<()>)>> {
    use futures::future::join_all;

    let subject = subject.to_string();
    let message = message.to_string();
    let variables = std::collections::HashMap::new();

    // Execute all integrations in parallel
    let tasks: Vec<_> = integration_ids
        .iter()
        .map(|id| {
            let id = id.clone();
            let subject = subject.clone();
            let message = message.clone();
            let variables = variables.clone();

            tokio::spawn(async move {
                let result = trigger_authorized_integration(&id, &subject, &message, &variables).await;
                (id, result)
            })
        })
        .collect();

    // Wait for all tasks to complete
    let results = join_all(tasks).await;

    Ok(results
        .into_iter()
        .map(|r| r.unwrap_or_else(join_error_result))
        .collect())
}

fn join_error_result(join_error: JoinError) -> (String, Result<()>) {
    let reason = if join_error.is_panic() {
        "panic"
    } else if join_error.is_cancelled() {
        "cancelled"
    } else {
        "join_error"
    };
    error!(reason, error = %join_error, "Integration task failed");
    ("unknown".to_string(), Err(IntegrationError::TaskJoinError(format!("{reason}: {join_error}"))))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn event_triggers_refuse_audit_integrations_only() {
        let integration = |category: Option<&str>| {
            Integration::new(
                "i".to_string(),
                String::new(),
                "webhook".to_string(),
                serde_json::json!({}),
                serde_json::json!({}),
                "active".to_string(),
                category.map(str::to_string),
            )
        };
        let audit = integration(Some("audit"));
        assert!(matches!(refuse_audit_integration(&audit), Err(IntegrationError::AuditOnly(id)) if id == audit.id));
        for category in [None, Some("general"), Some("pipe")] {
            assert!(refuse_audit_integration(&integration(category)).is_ok());
        }
    }

    fn active_integration(
        integration_type: &str,
        configuration: serde_json::Value,
        content: serde_json::Value,
    ) -> Integration {
        Integration::new(
            "test integration".to_string(),
            "test".to_string(),
            integration_type.to_string(),
            configuration,
            content,
            "active".to_string(),
            Some("general".to_string()),
        )
    }

    #[test]
    fn a_transient_secrets_store_error_is_retried_and_a_missing_secret_is_not() {
        let store_error = anyhow::anyhow!("connection reset by peer")
            .context("the secret referenced by smtp_password_secret_id could not be used");
        assert!(is_retryable_publisher_error(&store_error));

        let missing = anyhow::anyhow!("the secret referenced by smtp_password_secret_id is not available");
        assert!(!is_retryable_publisher_error(&missing));
    }

    #[tokio::test]
    async fn missing_integration_storage_returns_typed_error() {
        let err = load_integration_for_trigger("missing-storage-test", None)
            .await
            .expect_err("missing storage must fail");
        assert!(matches!(err, IntegrationError::StorageError(_)));
        assert!(
            err.to_string()
                .contains("Integration storage not initialized")
        );
    }

    #[tokio::test]
    async fn malformed_publisher_config_returns_error_without_panic() {
        let integration = active_integration("webhook", serde_json::json!({}), serde_json::Value::Null);
        let err = publish_integration_with_variables(&integration, "subject", "message", &HashMap::new())
            .await
            .expect_err("malformed config must fail");
        assert!(matches!(err, IntegrationError::PublisherError(_)));
        assert!(
            err.to_string()
                .contains("Missing url")
        );
    }

    #[tokio::test]
    async fn missing_publisher_secret_returns_error_without_panic() {
        let integration =
            active_integration("langfuse", serde_json::json!({ "public_key": "pk_test" }), serde_json::Value::Null);
        let err = publish_integration_with_variables(&integration, "subject", "message", &HashMap::new())
            .await
            .expect_err("missing secret must fail");
        assert!(matches!(err, IntegrationError::PublisherError(_)));
        assert!(
            err.to_string()
                .contains("Missing secret_key")
        );
    }

    #[tokio::test]
    async fn publisher_failure_returns_error_without_panic() {
        let integration = active_integration(
            "webhook",
            serde_json::json!({ "url": "http://169.254.169.254/hook", "method": "POST" }),
            serde_json::json!({ "message": "redacted" }),
        );
        let err = publish_integration_with_variables(&integration, "subject", "message", &HashMap::new())
            .await
            .expect_err("publisher failure must fail deterministically");
        assert!(matches!(err, IntegrationError::PublisherError(_)));
        assert!(
            err.to_string()
                .contains("metadata")
                || err
                    .to_string()
                    .contains("link-local")
        );
    }
}
