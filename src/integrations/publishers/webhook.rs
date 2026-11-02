use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::{debug, error, info};

use super::IntegrationPublisher;
use crate::integrations::runtime_variables::{substitute_variables, substitute_variables_in_json};
use crate::storage::Integration;

pub struct WebhookPublisher;

fn payload_kind(payload: &Value) -> &'static str {
    match payload {
        Value::Array(_) => "array",
        Value::Object(_) => "object",
        Value::String(_) => "string",
        Value::Number(_) => "number",
        Value::Bool(_) => "bool",
        Value::Null => "null",
    }
}

#[async_trait]
impl IntegrationPublisher for WebhookPublisher {
    fn name(&self) -> &str {
        "webhook"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["hmac_signing", "custom_headers", "templates", "variables"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["url"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        let url = config
            .get("url")
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow::anyhow!("Missing url in webhook configuration"))?;
        crate::url_validation::validate_resolved_webhook_url_blocking(url)
            .map_err(|e| anyhow::anyhow!("Invalid webhook URL: {}", e))?;
        Ok(())
    }

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        info!("Triggering webhook integration: {}", integration.name);

        let webhook_url = integration.configuration["url"]
            .as_str()
            .context("Missing url in webhook configuration")?;
        crate::url_validation::validate_resolved_webhook_url(webhook_url)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let method = integration
            .configuration
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();

        // Get signing secret if provided (for HMAC authentication)
        let signing_secret = integration
            .configuration
            .get("signing_secret")
            .and_then(|v| v.as_str());

        // Build webhook payload from content template with variable substitution
        let payload = if !integration.content.is_null()
            && integration
                .content
                .is_object()
        {
            // Use JSON-safe variable substitution to preserve JSON structure
            substitute_variables_in_json(
                &integration.content,
                integration
                    .category
                    .as_deref(),
                variables,
            )
        } else {
            // Default payload with standard fields
            serde_json::json!({
                "subject": subject,
                "message": message,
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "integration_id": integration.id,
                "integration_name": integration.name,
            })
        };

        debug!(payload_kind = %payload_kind(&payload), "Prepared webhook payload");

        // Convert payload to JSON string for body and signing
        let payload_json = serde_json::to_string(&payload).context("Failed to serialize payload")?;

        // Send HTTP request
        let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
            crate::http_client::EXTERNAL_TIMEOUT_SECS,
        ))?;

        let mut request = match method.as_str() {
            "POST" => client.post(webhook_url),
            "PUT" => client.put(webhook_url),
            "PATCH" => client.patch(webhook_url),
            _ => {
                return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method));
            }
        };

        // Add timestamp for replay attack prevention
        let timestamp = chrono::Utc::now()
            .timestamp()
            .to_string();
        request = request.header("X-Webhook-Timestamp", &timestamp);

        // Add HMAC signature if signing secret is provided
        if let Some(secret) = signing_secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            // Create HMAC signature: HMAC-SHA256(secret, timestamp + "." + payload)
            let signed_content = format!("{}.{}", timestamp, payload_json);

            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
            mac.update(signed_content.as_bytes());
            let signature = mac.finalize();
            let signature_hex = hex::encode(signature.into_bytes());

            // Send signature in header (following GitHub/Stripe webhook pattern)
            request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));

            info!("Added HMAC-SHA256 signature to webhook request");
        }

        // Add custom headers if provided in configuration (after built-in headers)
        if let Some(headers) = integration
            .configuration
            .get("headers")
            .and_then(|v| v.as_object())
        {
            for (key, value) in headers {
                if let Some(value_str) = value.as_str() {
                    // Substitute variables in header values
                    let substituted_value = substitute_variables(
                        value_str,
                        integration
                            .category
                            .as_deref(),
                        variables,
                    );
                    request = request.header(key, substituted_value);
                }
            }
        }

        let response = request
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await
            .map_err(|e| {
                let e = e.without_url();
                error!(
                    "Failed to send webhook to {}: {} (timeout: {}, connect: {})",
                    crate::url_validation::webhook_host(webhook_url),
                    e,
                    e.is_timeout(),
                    e.is_connect()
                );
                e
            })
            .context("Failed to send webhook")?;

        if response.status().is_success() {
            info!("Webhook notification sent successfully via integration: {}", integration.name);
            Ok(())
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            Err(super::refused_by_destination("Webhook", status, &body))
        }
    }

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        let webhook_url = config
            .get("url")
            .and_then(|v| v.as_str())
            .context("Missing url in configuration")?;
        crate::url_validation::validate_resolved_webhook_url(webhook_url)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;

        let method = config
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("POST")
            .to_uppercase();

        let signing_secret = config
            .get("signing_secret")
            .and_then(|v| v.as_str());

        // Build test payload
        let payload = if !content.is_null() && content.is_object() {
            substitute_variables_in_json(content, None, variables)
        } else {
            serde_json::json!({
                "test": true,
                "message": "This is a test webhook",
                "timestamp": chrono::Utc::now().to_rfc3339(),
            })
        };

        let payload_json = serde_json::to_string(&payload).context("Failed to serialize payload")?;

        let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
            crate::http_client::EXTERNAL_TIMEOUT_SECS,
        ))?;

        let mut request = match method.as_str() {
            "POST" => client.post(webhook_url),
            "PUT" => client.put(webhook_url),
            "PATCH" => client.patch(webhook_url),
            _ => {
                return Err(anyhow::anyhow!("Unsupported HTTP method: {}", method));
            }
        };

        let timestamp = chrono::Utc::now()
            .timestamp()
            .to_string();
        request = request.header("X-Webhook-Timestamp", &timestamp);

        if let Some(secret) = signing_secret {
            use hmac::{Hmac, Mac};
            use sha2::Sha256;

            let signed_content = format!("{}.{}", timestamp, payload_json);

            type HmacSha256 = Hmac<Sha256>;
            let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).context("Invalid HMAC key")?;
            mac.update(signed_content.as_bytes());
            let signature = mac.finalize();
            let signature_hex = hex::encode(signature.into_bytes());

            request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));
        }

        if let Some(headers) = config
            .get("headers")
            .and_then(|v| v.as_object())
        {
            for (key, value) in headers {
                if let Some(value_str) = value.as_str() {
                    let substituted_value = substitute_variables(value_str, None, variables);
                    request = request.header(key, substituted_value);
                }
            }
        }

        let response = request
            .header("Content-Type", "application/json")
            .body(payload_json)
            .send()
            .await
            .map_err(reqwest::Error::without_url)
            .context("Failed to send test webhook")?;

        if response.status().is_success() {
            Ok(test_success_message(webhook_url, response.status()))
        } else {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            Err(super::refused_by_destination("Webhook test", status, &body))
        }
    }
}

/// Names only the webhook's host, since the rest of its URL can carry a token.
fn test_success_message(
    webhook_url: &str,
    status: reqwest::StatusCode,
) -> String {
    format!("Test webhook sent successfully to {} ({})", crate::url_validation::webhook_host(webhook_url), status)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_test_success_names_only_the_webhook_host() {
        let message =
            test_success_message("https://user:pw@hooks.example.com/in/secret-path?token=t1", reqwest::StatusCode::OK);

        assert_eq!(message, "Test webhook sent successfully to hooks.example.com (200 OK)");
    }

    fn make_config(url: &str) -> Value {
        serde_json::json!({ "url": url })
    }

    fn publisher() -> WebhookPublisher {
        WebhookPublisher
    }

    #[test]
    fn validate_config_rejects_aws_metadata_ip() {
        let result = publisher().validate_config(&make_config("http://169.254.169.254/hook"));
        assert!(result.is_err(), "should reject AWS metadata IP");
    }

    #[test]
    fn validate_config_rejects_loopback() {
        let result = publisher().validate_config(&make_config("http://127.0.0.1/hook"));
        assert!(result.is_err(), "should reject loopback");
    }

    #[test]
    fn validate_config_rejects_private_ip() {
        let result = publisher().validate_config(&make_config("http://10.0.0.1/hook"));
        assert!(result.is_err(), "should reject private IP");
    }

    #[test]
    fn validate_config_rejects_embedded_credentials() {
        let result = publisher().validate_config(&make_config("http://user:pass@example.com/hook"));
        assert!(result.is_err(), "should reject embedded credentials");
    }

    #[test]
    fn validate_config_rejects_non_http_scheme() {
        let result = publisher().validate_config(&make_config("file:///etc/passwd"));
        assert!(result.is_err(), "should reject non-http scheme");
    }

    #[test]
    fn validate_config_accepts_public_url() {
        let result = publisher().validate_config(&make_config("https://198.51.100.1/webhook"));
        assert!(result.is_ok(), "should accept public webhook URL: {:?}", result.err());
    }

    #[tokio::test]
    async fn a_url_that_rebinds_to_loopback_is_not_sent_to() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("ok").await;
        let config = make_config(
            &upstream
                .url
                .replace("127.0.0.1", "hooks.rebind.test"),
        );
        let integration = Integration::new(
            "webhook".into(),
            String::new(),
            "webhook".into(),
            config.clone(),
            serde_json::json!({}),
            "active".into(),
            None,
        );

        let dns = crate::url_validation::test_dns::rebind_to_loopback("hooks.rebind.test");
        let published = publisher()
            .publish(&integration, "subject", "message", &HashMap::new())
            .await;
        assert!(published.is_err(), "a rebound webhook URL must be refused");
        assert_eq!(dns.lookups(), 2, "the address must be checked again at connect time");
        drop(dns);

        let dns = crate::url_validation::test_dns::rebind_to_loopback("hooks.rebind.test");
        let tested = publisher()
            .test(&config, &serde_json::json!({}), &HashMap::new())
            .await;
        assert!(tested.is_err(), "a rebound webhook URL must be refused");
        assert_eq!(dns.lookups(), 2, "the address must be checked again at connect time");

        assert_eq!(upstream.requests(), 0);
    }
}
