use anyhow::{Context, Result};
use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use tracing::info;

use super::IntegrationPublisher;
use crate::integrations::email_service::{SmtpConfig, send_email};
use crate::integrations::runtime_variables::substitute_variables;
use crate::storage::Integration;

pub struct EmailPublisher;

#[async_trait]
impl IntegrationPublisher for EmailPublisher {
    fn name(&self) -> &str {
        "email"
    }

    fn supported_features(&self) -> Vec<&str> {
        vec!["html", "templates", "variables"]
    }

    fn required_config_fields(&self) -> Vec<&str> {
        vec!["smtp_host", "smtp_port", "smtp_username", "from", "to"]
    }

    fn validate_config(
        &self,
        config: &Value,
    ) -> Result<()> {
        SmtpConfig::from_json(config)
            .map(|_| ())
            .context("Invalid SMTP configuration")
    }

    async fn publish(
        &self,
        integration: &Integration,
        subject: &str,
        message: &str,
        variables: &HashMap<String, String>,
    ) -> Result<()> {
        info!("Triggering email integration: {}", integration.name);

        // Parse SMTP config from integration configuration
        let smtp_config =
            SmtpConfig::from_json(&integration.configuration).context("Failed to parse SMTP configuration")?;

        // Use content template if provided, otherwise use passed message
        let subject_template = integration
            .content
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or(subject);

        let body_template = integration
            .content
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or(message);

        // Perform template variable substitution
        let actual_subject = substitute_variables(
            subject_template,
            integration
                .category
                .as_deref(),
            variables,
        );
        let actual_body = substitute_variables(
            body_template,
            integration
                .category
                .as_deref(),
            variables,
        );

        // Check format from content, default to plain text
        // If format is "html" or body contains HTML tags, treat as HTML
        let format = integration
            .content
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("plain");

        let is_html = format == "html" || actual_body.contains("<html") || actual_body.contains("<body");

        // Send the email
        send_email(&smtp_config, &actual_subject, &actual_body, is_html)
            .await
            .context("Failed to send email")?;

        info!("Email notification sent successfully via integration: {}", integration.name);
        Ok(())
    }

    async fn test(
        &self,
        config: &Value,
        content: &Value,
        variables: &HashMap<String, String>,
    ) -> Result<String> {
        use crate::integrations::email_service::{SmtpConfig, send_email};

        let smtp_config = SmtpConfig::from_json(config).context("Failed to parse SMTP configuration")?;

        let subject = content
            .get("subject")
            .and_then(|v| v.as_str())
            .unwrap_or("Test Email");

        let body = content
            .get("body")
            .and_then(|v| v.as_str())
            .unwrap_or("This is a test email from the integration system.");

        // Perform template variable substitution
        let actual_subject = substitute_variables(subject, None, variables);
        let actual_body = substitute_variables(body, None, variables);

        let format = content
            .get("format")
            .and_then(|v| v.as_str())
            .unwrap_or("plain");

        let is_html = format == "html" || actual_body.contains("<html") || actual_body.contains("<body");

        send_email(&smtp_config, &actual_subject, &actual_body, is_html)
            .await
            .context("Failed to send test email")?;

        Ok(format!("Test email sent successfully to {}", smtp_config.to.join(", ")))
    }
}
