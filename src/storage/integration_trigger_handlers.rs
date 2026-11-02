use axum::{Extension, Json, extract::Path, http::StatusCode, response::IntoResponse};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tracing::warn;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::integrations::audit_integration_triggers::is_audit_integration;
use crate::integrations::destinations::DestinationError;
use crate::integrations::errors::IntegrationError;
use crate::integrations::integration_service::trigger_authorized_integration;
use crate::integrations::stream_publishers::PUBLISHER_REGISTRY;
use crate::integrations::trigger_integrations;
use crate::secrets::{RevealSecretValues, SecretsStore};
use crate::storage::integration_credentials::{
    NewCredentials, PINNED_DESTINATION, apply_credential_rules, destination_moved, hidden_url_refusal,
    hide_url_refusal, referenced_url_key, resolve_authorized_references, same_destination,
};
use crate::storage::integration_handlers::AuditCaller;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};
use crate::url_validation::UrlRefusal;

const DEFAULT_VARIABLE_PATTERN: &str = r"\$\{([A-Za-z0-9_]+)(?::([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)";

fn default_variable_regex() -> Regex {
    match Regex::new(DEFAULT_VARIABLE_PATTERN) {
        Ok(regex) => regex,
        Err(e) => panic!("default integration trigger variable regex must compile: {e}"),
    }
}

/// Global storage for variable pattern from config
static VARIABLE_REGEX: Lazy<RwLock<Regex>> = Lazy::new(|| RwLock::new(default_variable_regex()));

/// Update the variable pattern from config (called during startup)
pub fn set_variable_pattern(pattern: String) -> Result<(), String> {
    let regex = Regex::new(&pattern).map_err(|e| format!("invalid integration trigger variable pattern: {e}"))?;
    *VARIABLE_REGEX
        .write()
        .map_err(|_| "integration trigger variable regex lock poisoned".to_string())? = regex;
    Ok(())
}

/// Substitute template variables in a string
fn substitute_variables(
    template: &str,
    variables: &std::collections::HashMap<String, String>,
) -> String {
    let mut result = template.to_string();
    let re = VARIABLE_REGEX
        .read()
        .map(|regex| regex.clone())
        .unwrap_or_else(|_| {
            warn!("Integration trigger variable regex lock poisoned; using default pattern");
            default_variable_regex()
        });

    for cap in re.captures_iter(template) {
        let var_name = cap
            .get(1)
            .or_else(|| cap.get(3))
            .or_else(|| cap.get(2))
            .map(|m| m.as_str().trim());
        let Some(var_name) = var_name else {
            continue;
        };
        let placeholder = &cap[0];

        if let Some(value) = crate::integrations::runtime_variables::variable_value(var_name, variables) {
            result = result.replace(placeholder, &value);
        }
    }

    result
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TriggerNotifierRequest {
    pub subject: String,
    pub message: String,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TriggerNotifiersRequest {
    pub integration_ids: Vec<String>,
    pub subject: String,
    pub message: String,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
}

#[derive(Debug, Serialize)]
pub struct TriggerResponse {
    pub success: bool,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct TriggerMultipleResponse {
    pub results: Vec<IntegrationResult>,
}

#[derive(Debug, Serialize)]
pub struct IntegrationResult {
    pub integration_id: String,
    pub success: bool,
    pub error: Option<String>,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

async fn require_integration_access(
    storage: &crate::storage::IntegrationStorage,
    integration_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    audit_caller: &AuditCaller<'_>,
) -> Result<crate::storage::Integration, (StatusCode, String)> {
    let integration = storage
        .load(integration_id)
        .await
        .map_err(|_| (StatusCode::NOT_FOUND, "Integration not found".to_string()))?;
    if !can_access(
        integration
            .tenant_id
            .as_deref(),
        tenant_context(context),
    ) || !scope_allows_resource(
        resource_scope(scope),
        tenant_context(context),
        ResourceKind::Integrations,
        &integration.id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Integration is outside this token's permitted scope".to_string()));
    }
    if is_audit_integration(&integration) {
        audit_caller
            .require_audit_access()
            .await?;
    }
    Ok(integration)
}

/// Trigger a single integration by ID
pub async fn trigger_integration_handler(
    Extension(storage): Extension<Arc<crate::storage::IntegrationStorage>>,
    Extension(reveal_secret_values): Extension<RevealSecretValues>,
    Path(integration_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(payload): Json<TriggerNotifierRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    require_integration_access(storage.as_ref(), &integration_id, &context, &scope, &audit_caller).await?;
    let reveals_detail = audit_caller
        .reveals_secret_detail(reveal_secret_values)
        .await?;
    match trigger_authorized_integration(&integration_id, &payload.subject, &payload.message, &payload.variables).await
    {
        Ok(_) => Ok((
            StatusCode::OK,
            Json(TriggerResponse {
                success: true,
                message: format!("Notifier {} triggered successfully", integration_id),
            }),
        )),
        Err(e) => Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to trigger integration: {}", trigger_failure(&e, reveals_detail)),
        )),
    }
}

const TRIGGER_FAILED: &str = "the appliance log has the reason";

/// Why a trigger failed, as answered. A delivery or task failure can say where
/// a secret resolves or whether it still exists, and the copy delivered may
/// not be the one the caller was checked against, so unless `reveals_detail`
/// it gets one fixed answer whatever the integration references; the
/// integration service logs the error. Errors that describe no secret (not
/// found, inactive, audit only, unknown type, storage) are answered as they
/// are.
fn trigger_failure(
    error: &IntegrationError,
    reveals_detail: bool,
) -> String {
    let describes_no_secret = matches!(
        error,
        IntegrationError::NotFound(_)
            | IntegrationError::Inactive(..)
            | IntegrationError::AuditOnly(_)
            | IntegrationError::UnknownType(_)
            | IntegrationError::StorageError(_)
    );
    if reveals_detail || describes_no_secret {
        error.to_string()
    } else {
        TRIGGER_FAILED.to_string()
    }
}

/// Trigger multiple integrations
pub async fn trigger_multiple_notifiers_handler(
    Extension(storage): Extension<Arc<crate::storage::IntegrationStorage>>,
    Extension(reveal_secret_values): Extension<RevealSecretValues>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(payload): Json<TriggerNotifiersRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    for integration_id in &payload.integration_ids {
        require_integration_access(storage.as_ref(), integration_id, &context, &scope, &audit_caller).await?;
    }
    let reveals_detail = audit_caller
        .reveals_secret_detail(reveal_secret_values)
        .await?;
    let results = trigger_integrations(&payload.integration_ids, &payload.subject, &payload.message)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to trigger integrations: {}", e)))?;

    let integration_results: Vec<IntegrationResult> = results
        .into_iter()
        .map(|(integration_id, result)| {
            let error = result
                .err()
                .map(|e| trigger_failure(&e, reveals_detail));
            IntegrationResult {
                integration_id,
                success: error.is_none(),
                error,
            }
        })
        .collect();

    Ok((StatusCode::OK, Json(TriggerMultipleResponse { results: integration_results })))
}

/// Test a integration configuration without saving it
#[derive(Debug, Deserialize)]
pub struct TestNotifierRequest {
    #[serde(rename = "type")]
    pub integration_type: String,
    pub configuration: serde_json::Value,
    pub content: serde_json::Value,
    #[serde(default)]
    pub variables: std::collections::HashMap<String, String>,
    /// The saved integration being tested. Its stored credentials fill in any
    /// credential `configuration` leaves out, and a test that keeps its saved
    /// type and destination is delivered like a trigger, which checks the
    /// destination again.
    #[serde(default)]
    pub integration_id: Option<String>,
}

/// Applies the credential rules to a test request and resolves its secret
/// references, sending the values the reference check approved. With
/// `integration_id`, the saved integration, loaded through the same tenant,
/// scope and audit checks as a trigger, supplies the credentials the request
/// leaves out and owns its references; without one, the caller's tenant does.
/// Returns the saved integration when the test keeps its type and destination,
/// which chooses no new destination.
async fn prepare_test_credentials(
    storage: &crate::storage::IntegrationStorage,
    secrets_store: Option<Arc<dyn SecretsStore>>,
    reveal_secret_values: RevealSecretValues,
    payload: &mut TestNotifierRequest,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    audit_caller: &AuditCaller<'_>,
) -> Result<Option<crate::storage::Integration>, (StatusCode, String)> {
    let stored = match payload
        .integration_id
        .as_deref()
    {
        Some(integration_id) => {
            Some(require_integration_access(storage, integration_id, context, scope, audit_caller).await?)
        }
        None => None,
    };
    if let Some(stored) = &stored {
        audit_caller
            .require_secret_pairing_view(
                &payload.integration_type,
                &payload.configuration,
                stored,
                NewCredentials::InlineAllowed,
            )
            .await?;
    }
    apply_credential_rules(
        &payload.integration_type,
        &mut payload.configuration,
        stored.as_ref(),
        NewCredentials::InlineAllowed,
    )?;
    // Before any reference is resolved, so a caller without secrets.view cannot
    // tell from the answer which secrets exist.
    audit_caller
        .require_secret_pairing_access(
            reveal_secret_values,
            &payload.integration_type,
            &payload.configuration,
            stored.as_ref(),
        )
        .await?;
    let keeps_destination = stored
        .as_ref()
        .is_some_and(|stored| same_destination(&payload.integration_type, &payload.configuration, stored));
    let owner_tenant_id = match &stored {
        Some(stored) => stored.tenant_id.clone(),
        None => tenant_context(context).map(|context| context.tenant_id.clone()),
    };
    let approved = match resolve_authorized_references(
        &payload.configuration,
        secrets_store.as_ref(),
        owner_tenant_id.as_deref(),
        tenant_context(context),
        resource_scope(scope),
    )
    .await
    {
        Ok(approved) => approved,
        Err(refusal) => {
            if refusal.0 == StatusCode::BAD_REQUEST {
                audit_caller
                    .require_moved_destination_view()
                    .await?;
            }
            return Err(refusal);
        }
    };
    // The request keeps its references until the moved-destination check
    // passes, so a refused test holds no resolved value.
    let mut filled = payload.configuration.clone();
    approved
        .fill(&mut filled)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    if let Some(stored) = &stored {
        let moved = match destination_moved(
            &payload.configuration,
            &filled,
            stored
                .configuration
                .get(PINNED_DESTINATION),
        ) {
            Ok(moved) => moved,
            Err(e) => {
                audit_caller
                    .require_moved_destination_view()
                    .await?;
                return Err(hide_url_refusal(
                    reveal_secret_values.0,
                    &payload.configuration,
                    (StatusCode::BAD_REQUEST, e.to_string()),
                ));
            }
        };
        if moved {
            audit_caller
                .require_moved_destination_access(
                    reveal_secret_values,
                    &payload.integration_type,
                    &payload.configuration,
                    stored,
                )
                .await?;
        }
    }
    payload.configuration = filled;
    Ok(stored.filter(|_| keeps_destination))
}

const TEST_DELIVERY_FAILED: &str = "The test message could not be delivered. The appliance log has the reason.";

/// The answer for a failed test delivery. A refused destination is the
/// caller's to fix and says why; every other failure (refused, timed out,
/// rejected by the server) gets one answer with the detail logged, so the test
/// cannot tell one network outcome from another.
fn test_delivery_error(
    integration_type: &str,
    error: anyhow::Error,
) -> (StatusCode, String) {
    if let Some(refused) = error.downcast_ref::<DestinationError>() {
        return (StatusCode::BAD_REQUEST, refused.to_string());
    }
    tracing::error!("Test {} delivery failed: {:#}", integration_type, error);
    (StatusCode::BAD_GATEWAY, TEST_DELIVERY_FAILED.to_string())
}

/// [`hidden_url_refusal`] for `key`, with the reason logged under the key and
/// not the URL, so the operator can still learn it.
fn hidden_test_refusal(
    key: &str,
    reason: &str,
) -> (StatusCode, String) {
    tracing::warn!(key, reason, "Test refused the URL a secret reference holds");
    hidden_url_refusal(key)
}

/// Checks a Slack or webhook test URL. A value that is not an http or https URL
/// gets one fixed answer naming the setting, and a URL that came from a secret
/// reference the caller may not see refused (`hidden_url_key`) gets
/// [`hidden_url_refusal`] whatever the reason, so no answer describes what a
/// stored secret holds or where it resolves.
async fn check_test_url(
    setting: &str,
    label: &str,
    url: &str,
    hidden_url_key: Option<&str>,
) -> Result<(), (StatusCode, String)> {
    let Err(refusal) = crate::url_validation::check_resolved_webhook_url(url).await else {
        return Ok(());
    };
    if let Some(key) = hidden_url_key {
        return Err(hidden_test_refusal(key, &String::from(refusal)));
    }
    Err(match refusal {
        UrlRefusal::NotHttpUrl(_) => (StatusCode::BAD_REQUEST, format!("{setting} must be an http or https URL")),
        UrlRefusal::Refused(reason) => (StatusCode::BAD_REQUEST, format!("{label} rejected: {reason}")),
    })
}

/// The answer for a test the destination refused: its status, with the body
/// logged and left out, since it can echo a secret URL's path.
fn destination_refused_test(
    what: &str,
    status: reqwest::StatusCode,
    body: &str,
) -> (StatusCode, String) {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::integrations::publishers::refused_by_destination(what, status, body).to_string(),
    )
}

pub async fn test_notifier_handler(
    Extension(storage): Extension<Arc<crate::storage::IntegrationStorage>>,
    Extension(secrets_store): Extension<Option<Arc<dyn SecretsStore>>>,
    Extension(reveal_secret_values): Extension<RevealSecretValues>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    guard: Option<Extension<RbacGuard>>,
    caller: Option<Extension<AuthGuardOk>>,
    pat: Option<Extension<PatContext>>,
    Json(mut payload): Json<TestNotifierRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    use crate::integrations::email_service::{SmtpConfig, send_email};

    let audit_caller = AuditCaller::new(&guard, &caller, &pat);
    let url_reference = referenced_url_key(&payload.configuration);
    let saved = prepare_test_credentials(
        storage.as_ref(),
        secrets_store,
        reveal_secret_values,
        &mut payload,
        &context,
        &scope,
        &audit_caller,
    )
    .await?;
    let hidden_url_key = match url_reference {
        Some(key)
            if !audit_caller
                .reveals_secret_detail(reveal_secret_values)
                .await? =>
        {
            Some(key)
        }
        _ => None,
    };

    tracing::info!("Test integration handler called for type: {}", payload.integration_type);

    match payload
        .integration_type
        .as_str()
    {
        "email" => {
            tracing::info!("Testing email integration");

            let smtp_config = SmtpConfig::from_json(&payload.configuration).map_err(|e| {
                tracing::error!("Invalid SMTP configuration: {}", e);
                (StatusCode::BAD_REQUEST, format!("Invalid SMTP configuration: {}", e))
            })?;

            tracing::info!("SMTP config parsed, sending test email...");

            // Use content template if provided
            let subject_template = payload
                .content
                .get("subject")
                .and_then(|v| v.as_str())
                .unwrap_or("Test Notification from Agent Stream");

            let body_template = payload
                .content
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("This is a test email to verify your SMTP configuration is working correctly.");

            // Perform template variable substitution
            let subject = substitute_variables(subject_template, &payload.variables);
            let body = substitute_variables(body_template, &payload.variables);

            // Check format from content, default to plain text
            let format = payload
                .content
                .get("format")
                .and_then(|v| v.as_str())
                .unwrap_or("plain");

            let is_html = format == "html" || body.contains("<html") || body.contains("<body");

            send_email(&smtp_config, &subject, &body, is_html)
                .await
                .map_err(|e| test_delivery_error("email", e))?;

            tracing::info!("Test email sent successfully");

            Ok((
                StatusCode::OK,
                Json(TriggerResponse {
                    success: true,
                    message: "Test email sent successfully".to_string(),
                }),
            ))
        }
        "slack" => {
            tracing::info!("Testing Slack integration");

            let webhook_url = payload.configuration["webhook_url"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing webhook_url in Slack configuration");
                    (StatusCode::BAD_REQUEST, "Missing webhook_url in Slack configuration".to_string())
                })?;

            check_test_url("webhook_url", "webhook_url", webhook_url, hidden_url_key).await?;

            // Use content template if provided
            let text_template = if let Some(template_text) = payload
                .content
                .get("text")
                .and_then(|v| v.as_str())
            {
                template_text.to_string()
            } else {
                "*Test Notification from Agent Stream*\nYour Slack integration is configured correctly! 🎉".to_string()
            };

            // Perform template variable substitution
            let text = substitute_variables(&text_template, &payload.variables);

            let bot_name = payload
                .content
                .get("bot_name")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    payload
                        .configuration
                        .get("bot_name")
                        .and_then(|v| v.as_str())
                })
                .unwrap_or("Agent Stream");

            let icon_emoji = payload
                .content
                .get("icon_emoji")
                .and_then(|v| v.as_str())
                .or_else(|| {
                    payload
                        .configuration
                        .get("icon_emoji")
                        .and_then(|v| v.as_str())
                })
                .unwrap_or(":robot_face:");

            // Build test Slack message payload
            let mut slack_payload = serde_json::json!({
                "text": text,
                "username": bot_name,
                "icon_emoji": icon_emoji
            });

            // Add channel if specified in content
            if let Some(channel) = payload
                .content
                .get("channel")
                .and_then(|v| v.as_str())
            {
                slack_payload["channel"] = serde_json::json!(channel);
            }

            tracing::info!(
                "Sending HTTP POST to Slack webhook host: {}",
                crate::url_validation::webhook_host(webhook_url)
            );

            // Send HTTP POST to Slack webhook with timeout
            let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
                crate::http_client::EXTERNAL_TIMEOUT_SECS,
            ))
            .map_err(|e| {
                tracing::error!("Failed to build HTTP client: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build HTTP client: {}", e))
            })?;

            let response = client
                .post(webhook_url)
                .json(&slack_payload)
                .send()
                .await
                .map_err(|e| {
                    let e = e.without_url();
                    tracing::error!(
                        "Failed to send Slack webhook to {}: {} (is_timeout: {}, is_connect: {}, is_request: {})",
                        crate::url_validation::webhook_host(webhook_url),
                        e,
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_request()
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to send Slack webhook: {} (timeout: {}, connect: {})",
                            e,
                            e.is_timeout(),
                            e.is_connect()
                        ),
                    )
                })?;

            tracing::info!("Slack webhook response status: {}", response.status());

            if response.status().is_success() {
                tracing::info!("Test Slack notification sent successfully");
                Ok((
                    StatusCode::OK,
                    Json(TriggerResponse {
                        success: true,
                        message: "Test Slack notification sent successfully".to_string(),
                    }),
                ))
            } else {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_default();
                Err(destination_refused_test("Slack webhook", status, &body))
            }
        }
        "webhook" => {
            tracing::info!("Testing webhook integration");

            // Get webhook URL from configuration
            let webhook_url = payload.configuration["url"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing url in webhook configuration");
                    (StatusCode::BAD_REQUEST, "Missing url in webhook configuration".to_string())
                })?;

            check_test_url("url", "webhook URL", webhook_url, hidden_url_key).await?;

            let method = payload
                .configuration
                .get("method")
                .and_then(|v| v.as_str())
                .unwrap_or("POST")
                .to_uppercase();

            let signing_secret = payload
                .configuration
                .get("signing_secret")
                .and_then(|v| v.as_str());

            // Build test payload from content template with test variables
            let test_payload = if !payload.content.is_null() && payload.content.is_object() {
                payload.content.clone()
            } else {
                // Default test payload
                serde_json::json!({
                    "subject": "Test Notification",
                    "message": "*Test Notification from Agent Stream*\nYour webhook integration is configured correctly! 🎉",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "test": true
                })
            };

            // Substitute variables in the test payload
            let payload_str = serde_json::to_string(&test_payload)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize payload: {}", e)))?;

            // Perform variable substitution
            let substituted_payload_str = substitute_variables(&payload_str, &payload.variables);

            let final_payload: serde_json::Value = serde_json::from_str(&substituted_payload_str).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse substituted payload: {}", e))
            })?;

            let payload_json = serde_json::to_string(&final_payload).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize final payload: {}", e))
            })?;

            tracing::info!(
                "Sending HTTP {} to webhook host: {}",
                method,
                crate::url_validation::webhook_host(webhook_url)
            );

            // Send HTTP request to webhook with timeout
            let client = crate::http_client::with_strict_validating_resolver(std::time::Duration::from_secs(
                crate::http_client::EXTERNAL_TIMEOUT_SECS,
            ))
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build HTTP client: {}", e)))?;

            let mut request = match method.as_str() {
                "POST" => client.post(webhook_url),
                "PUT" => client.put(webhook_url),
                "PATCH" => client.patch(webhook_url),
                _ => {
                    return Err((StatusCode::BAD_REQUEST, format!("Unsupported HTTP method: {}", method)));
                }
            };

            // Add timestamp header
            let timestamp = chrono::Utc::now()
                .timestamp()
                .to_string();
            request = request.header("X-Webhook-Timestamp", &timestamp);

            // Add HMAC signature if signing secret is provided
            if let Some(secret) = signing_secret {
                use hmac::{Hmac, Mac};
                use sha2::Sha256;

                let signed_content = format!("{}.{}", timestamp, payload_json);

                type HmacSha256 = Hmac<Sha256>;
                let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
                    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Invalid HMAC key: {}", e)))?;
                mac.update(signed_content.as_bytes());
                let signature = mac.finalize();
                let signature_hex = hex::encode(signature.into_bytes());

                request = request.header("X-Webhook-Signature-256", format!("sha256={}", signature_hex));

                tracing::info!("Added HMAC-SHA256 signature to test webhook request");
            }

            // Add custom headers if provided
            if let Some(headers) = payload
                .configuration
                .get("headers")
                .and_then(|v| v.as_object())
            {
                for (key, value) in headers {
                    if let Some(value_str) = value.as_str() {
                        // Substitute variables in header values
                        let substituted_value = substitute_variables(value_str, &payload.variables);
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
                    tracing::error!(
                        "Failed to send webhook to {}: {} (is_timeout: {}, is_connect: {}, is_request: {})",
                        crate::url_validation::webhook_host(webhook_url),
                        e,
                        e.is_timeout(),
                        e.is_connect(),
                        e.is_request()
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!(
                            "Failed to send webhook: {} (timeout: {}, connect: {})",
                            e,
                            e.is_timeout(),
                            e.is_connect()
                        ),
                    )
                })?;

            tracing::info!("Webhook response status: {}", response.status());

            if response.status().is_success() {
                tracing::info!("Test webhook notification sent successfully");
                Ok((
                    StatusCode::OK,
                    Json(TriggerResponse {
                        success: true,
                        message: "Test webhook notification sent successfully".to_string(),
                    }),
                ))
            } else {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_default();
                Err(destination_refused_test("Webhook", status, &body))
            }
        }
        "stream" => {
            tracing::info!("Testing stream integration");

            let platform = payload.configuration["platform"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing platform in stream configuration");
                    (StatusCode::BAD_REQUEST, "Missing platform in stream configuration".to_string())
                })?;

            let topic = payload.configuration["topic"]
                .as_str()
                .ok_or_else(|| {
                    tracing::error!("Missing topic in stream configuration");
                    (StatusCode::BAD_REQUEST, "Missing topic in stream configuration".to_string())
                })?;

            // Build test event payload from content template
            let test_event = if !payload.content.is_null() && payload.content.is_object() {
                payload.content.clone()
            } else {
                serde_json::json!({
                    "event_type": "test.notification",
                    "timestamp": chrono::Utc::now().to_rfc3339(),
                    "message": "Test event from Agent Stream",
                    "test": true
                })
            };

            // Substitute variables in the test event
            let event_str = serde_json::to_string(&test_event)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize event: {}", e)))?;

            let substituted_event_str = substitute_variables(&event_str, &payload.variables);

            let final_event: serde_json::Value = serde_json::from_str(&substituted_event_str).map_err(|e| {
                (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to parse substituted event: {}", e))
            })?;

            tracing::info!("Stream platform: {}, topic: {}", platform, topic);

            // Get the publisher from the registry
            let publisher = PUBLISHER_REGISTRY
                .get(platform)
                .ok_or_else(|| {
                    tracing::error!("Unknown stream platform: {}", platform);
                    (StatusCode::BAD_REQUEST, format!("Unknown stream platform: {}", platform))
                })?;

            let delivered = match &saved {
                Some(integration) => publisher
                    .publish(topic, &final_event, &payload.configuration, &integration.id)
                    .await
                    .map(|()| format!("Test event sent to {platform} topic '{topic}'")),
                None => {
                    publisher
                        .test_connection(topic, &final_event, &payload.configuration)
                        .await
                }
            };
            let message = delivered.map_err(|e| match (test_delivery_error("stream", e), hidden_url_key) {
                ((StatusCode::BAD_REQUEST, reason), Some(key)) => hidden_test_refusal(key, &reason),
                (refusal, _) => refusal,
            })?;

            Ok((StatusCode::OK, Json(TriggerResponse { success: true, message })))
        }
        _ => {
            tracing::error!("Unknown integration type: {}", payload.integration_type);
            Err((StatusCode::BAD_REQUEST, format!("Unknown integration type: {}", payload.integration_type)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::UserRole;
    use crate::secrets::store::memory::{MemorySecretsStore, secret};
    use crate::storage::integration_credentials::MASKED_CREDENTIAL;
    use crate::storage::integration_handlers::test_caller::{TestCaller, signed_in};
    use crate::storage::{Integration, IntegrationStorage};
    use crate::url_validation::test_service_endpoints;
    use std::net::TcpListener;
    use std::time::{Duration, Instant};

    const SMTP_PASSWORD: &str = "smtp-pass-123";

    async fn storage_with(
        category: &str,
        tenant_id: Option<&str>,
    ) -> (tempfile::TempDir, IntegrationStorage, Integration) {
        let dir = tempfile::tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let mut integration = Integration::new(
            "mailer".into(),
            String::new(),
            "email".into(),
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": SMTP_PASSWORD }),
            serde_json::json!({}),
            "active".into(),
            Some(category.into()),
        );
        integration.tenant_id = tenant_id.map(str::to_string);
        storage
            .save(&integration)
            .await
            .unwrap();
        (dir, storage, integration)
    }

    fn test_request(
        integration_id: Option<&str>,
        configuration: serde_json::Value,
    ) -> TestNotifierRequest {
        TestNotifierRequest {
            integration_type: "email".into(),
            configuration,
            content: serde_json::json!({}),
            variables: Default::default(),
            integration_id: integration_id.map(str::to_string),
        }
    }

    fn tenant(tenant_id: &str) -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: tenant_id.into(),
        }))
    }

    fn scope(pattern: &str) -> Option<Extension<PatResourceScope>> {
        Some(Extension(PatResourceScope(Arc::new(Regex::new(pattern).unwrap()))))
    }

    fn secrets() -> Option<Arc<dyn SecretsStore>> {
        Some(Arc::new(MemorySecretsStore::with(vec![
            secret("id-global", "smtp-global", "global-pass", None),
            secret("id-tenant-b", "smtp-b", "tenant-b-pass", Some("tenant-b")),
            secret("id-hook", "hook-url", "https://hooks.example.com/in", None),
            secret("id-moved", "moved-hook", "https://attacker.example/in", None),
            secret("id-private", "private-hook", "http://10.0.0.5/in", None),
            secret("id-internal-redis", "internal-redis", "redis://10.0.0.5:6379", None),
        ])))
    }

    #[tokio::test]
    async fn with_values_hidden_a_test_answers_every_refused_referenced_url_alike() {
        let (_dir, storage) = storage().await;
        let administrator = signed_in(UserRole::Administrator).await;

        for (integration_type, key, extra) in [
            ("webhook", "url", serde_json::json!({})),
            ("slack", "webhook_url", serde_json::json!({})),
            ("stream", "redis_url", serde_json::json!({ "platform": "redis", "topic": "events" })),
        ] {
            let mut answers = std::collections::BTreeSet::new();
            for reference in ["smtp-global", "private-hook", "internal-redis"] {
                let mut configuration = extra.clone();
                configuration[format!("{key}_secret_id")] = serde_json::json!(reference);
                let request = TestNotifierRequest {
                    integration_type: integration_type.into(),
                    configuration,
                    content: serde_json::json!({}),
                    variables: Default::default(),
                    integration_id: None,
                };
                let refused = test_notifier_handler(
                    Extension(storage.clone()),
                    Extension(secrets()),
                    Extension(RevealSecretValues(false)),
                    None,
                    None,
                    administrator.guard.clone(),
                    administrator.caller.clone(),
                    None,
                    Json(request),
                )
                .await
                .map(|_| ())
                .unwrap_err();
                assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{integration_type} {reference}: {}", refused.1);
                answers.insert(refused.1);
            }
            assert_eq!(
                answers
                    .into_iter()
                    .collect::<Vec<_>>(),
                [format!("{key}_secret_id does not name a destination this integration may send to")],
                "{integration_type}"
            );
        }
    }

    async fn saved_webhook(url_reference: &str) -> (tempfile::TempDir, IntegrationStorage, Integration) {
        let dir = tempfile::tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let saved = Integration::new(
            "hook".into(),
            String::new(),
            "webhook".into(),
            serde_json::json!({
                "url_secret_id": url_reference,
                "signing_secret": "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61",
                "pinned_destination": { "url": "hooks.example.com:443" },
            }),
            serde_json::json!({}),
            "active".into(),
            Some("general".into()),
        );
        storage
            .save(&saved)
            .await
            .unwrap();
        (dir, storage, saved)
    }

    fn webhook_test_of(saved: &Integration) -> TestNotifierRequest {
        let mut payload =
            test_request(Some(&saved.id), serde_json::json!({ "url_secret_id": saved.configuration["url_secret_id"] }));
        payload.integration_type = "webhook".into();
        payload
    }

    #[tokio::test]
    async fn testing_a_saved_integration_whose_url_secret_moved_needs_secrets_view() {
        let (_dir, storage, saved) = saved_webhook("moved-hook").await;

        let refused = prepare_as(UserRole::PowerUser, &storage, &mut webhook_test_of(&saved), None)
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            refused
                .1
                .contains("references changed"),
            "{}",
            refused.1
        );

        let mut confirmed = webhook_test_of(&saved);
        prepare_as(UserRole::Administrator, &storage, &mut confirmed, None)
            .await
            .unwrap();
        assert_eq!(confirmed.configuration["url"], "https://attacker.example/in");

        let mut unrevealed = webhook_test_of(&saved);
        let refused = prepare_revealing(false, UserRole::Administrator, &storage, &mut unrevealed, None)
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            refused
                .1
                .contains("not revealed"),
            "{}",
            refused.1
        );
        assert!(
            unrevealed
                .configuration
                .get("url")
                .is_none()
        );

        let mut own_signing_secret = webhook_test_of(&saved);
        own_signing_secret.configuration["signing_secret"] =
            serde_json::json!("whsec-callers-own-7b4d-4e8a-9c61-0d5f2b7e");
        prepare_revealing(false, UserRole::Administrator, &storage, &mut own_signing_secret, None)
            .await
            .unwrap();
        assert_eq!(own_signing_secret.configuration["url"], "https://attacker.example/in");
        assert_eq!(own_signing_secret.configuration["signing_secret"], "whsec-callers-own-7b4d-4e8a-9c61-0d5f2b7e");
    }

    #[tokio::test]
    async fn with_values_hidden_a_test_at_the_pinned_destination_keeps_the_saved_signing_secret() {
        let (_dir, storage, saved) = saved_webhook("hook-url").await;
        let mut payload = webhook_test_of(&saved);

        prepare_revealing(false, UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap();

        assert_eq!(payload.configuration["url"], "https://hooks.example.com/in");
        assert_eq!(payload.configuration["signing_secret"], "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61");
    }

    #[tokio::test]
    async fn with_values_hidden_a_moved_url_carrying_another_secret_is_refused_before_anything_is_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let stale = Integration::new(
            "hook".into(),
            String::new(),
            "webhook".into(),
            serde_json::json!({
                "url_secret_id": "moved-hook",
                "headers_secret_id": { "Authorization": "smtp-global" },
                "pinned_destination": { "url": "hooks.example.com:443" },
            }),
            serde_json::json!({}),
            "active".into(),
            Some("general".into()),
        );
        storage
            .save(&stale)
            .await
            .unwrap();
        let sent = serde_json::json!({
            "url_secret_id": "moved-hook",
            "headers_secret_id": { "Authorization": "smtp-global" },
        });
        let mut payload = test_request(Some(&stale.id), sent.clone());
        payload.integration_type = "webhook".into();

        let refused = prepare_revealing(false, UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            refused
                .1
                .contains("not revealed"),
            "{}",
            refused.1
        );
        assert_eq!(payload.configuration, sent);
        let answered = format!("{} {}", refused.1, payload.configuration);
        for value in ["attacker.example", "global-pass"] {
            assert!(!answered.contains(value), "{answered}");
        }
    }

    #[tokio::test]
    async fn a_test_at_the_pinned_destination_answers_a_url_secret_that_is_no_url_without_its_shape_while_hidden() {
        let (_dir, storage, saved) = saved_webhook("smtp-global").await;

        let hidden = prepare_revealing(false, UserRole::Administrator, &storage, &mut webhook_test_of(&saved), None)
            .await
            .unwrap_err();
        assert_eq!(
            hidden,
            (StatusCode::BAD_REQUEST, "url_secret_id does not name a destination this integration may send to".into())
        );

        let revealed = prepare_as(UserRole::Administrator, &storage, &mut webhook_test_of(&saved), None)
            .await
            .unwrap_err();
        assert_eq!(revealed.0, StatusCode::BAD_REQUEST, "{}", revealed.1);
        assert!(
            revealed
                .1
                .contains("does not hold a URL"),
            "{}",
            revealed.1
        );
        assert!(
            !revealed
                .1
                .contains("global-pass"),
            "{}",
            revealed.1
        );
    }

    #[tokio::test]
    async fn without_secrets_view_a_test_at_the_pinned_destination_gets_one_answer_whatever_the_url_secret_now_holds() {
        for reveal_values in [true, false] {
            let mut answers = std::collections::BTreeSet::new();
            for reference in ["moved-hook", "smtp-global", "private-hook", "no-such-secret"] {
                let (_dir, storage, saved) = saved_webhook(reference).await;
                let refused =
                    prepare_revealing(reveal_values, UserRole::PowerUser, &storage, &mut webhook_test_of(&saved), None)
                        .await
                        .unwrap_err();
                assert_eq!(refused.0, StatusCode::FORBIDDEN, "{reveal_values} {reference}: {}", refused.1);
                answers.insert(refused.1);
            }
            assert_eq!(answers.len(), 1, "{reveal_values}: {answers:?}");
        }

        let (_dir, storage, saved) = saved_webhook("no-such-secret").await;
        let refused = prepare_as(UserRole::Administrator, &storage, &mut webhook_test_of(&saved), None)
            .await
            .unwrap_err();
        assert_eq!(
            refused,
            (StatusCode::BAD_REQUEST, "url_secret_id does not name a secret this integration may use".into())
        );
    }

    #[tokio::test]
    async fn without_secrets_view_a_test_at_a_new_destination_gets_one_answer_whether_a_credential_is_kept() {
        let mut answers = Vec::new();
        for kept in [
            serde_json::json!({}),
            serde_json::json!({ "headers": { "Authorization": "Bearer saved-inline-token" } }),
            serde_json::json!({ "signing_secret": "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61" }),
        ] {
            let (_dir, storage) = storage().await;
            let mut configuration = serde_json::json!({
                "url_secret_id": "hook-url",
                "pinned_destination": { "url": "hooks.example.com:443" },
            });
            configuration
                .as_object_mut()
                .unwrap()
                .extend(
                    kept.as_object()
                        .unwrap()
                        .clone(),
                );
            let saved = save(&storage, "webhook", configuration).await;
            for reveal_values in [true, false] {
                let mut payload = test_request(Some(&saved.id), serde_json::json!({ "url_secret_id": "moved-hook" }));
                payload.integration_type = "webhook".into();
                answers.push(
                    prepare_revealing(reveal_values, UserRole::PowerUser, &storage, &mut payload, None)
                        .await
                        .unwrap_err(),
                );
            }
        }

        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert!(
            answers
                .iter()
                .all(|answer| answer == &answers[0]),
            "{answers:?}"
        );
    }

    #[tokio::test]
    async fn testing_a_saved_integration_at_its_pinned_destination_needs_no_secrets_view() {
        let (_dir, storage, saved) = saved_webhook("hook-url").await;
        let mut payload = webhook_test_of(&saved);

        prepare_as(UserRole::PowerUser, &storage, &mut payload, None)
            .await
            .unwrap();

        assert_eq!(payload.configuration["url"], "https://hooks.example.com/in");
        assert_eq!(payload.configuration["signing_secret"], "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61");
    }

    async fn prepare(
        storage: &IntegrationStorage,
        payload: &mut TestNotifierRequest,
        context: Option<Extension<PatTenantContext>>,
        scope: Option<Extension<PatResourceScope>>,
    ) -> Result<(), (StatusCode, String)> {
        prepare_test_credentials(
            storage,
            secrets(),
            RevealSecretValues(true),
            payload,
            &context,
            &scope,
            &AuditCaller::new(&None, &None, &None),
        )
        .await
        .map(|_| ())
    }

    async fn prepare_as(
        role: UserRole,
        storage: &IntegrationStorage,
        payload: &mut TestNotifierRequest,
        context: Option<Extension<PatTenantContext>>,
    ) -> Result<(), (StatusCode, String)> {
        prepare_revealing(true, role, storage, payload, context).await
    }

    async fn prepare_revealing(
        reveal_values: bool,
        role: UserRole,
        storage: &IntegrationStorage,
        payload: &mut TestNotifierRequest,
        context: Option<Extension<PatTenantContext>>,
    ) -> Result<(), (StatusCode, String)> {
        let caller = signed_in(role).await;
        prepare_test_credentials(
            storage,
            secrets(),
            RevealSecretValues(reveal_values),
            payload,
            &context,
            &None,
            &caller.audit_caller(),
        )
        .await
        .map(|_| ())
    }

    #[tokio::test]
    async fn a_left_out_credential_is_filled_from_the_saved_integration() {
        let (_dir, storage, saved) = storage_with("general", None).await;
        let mut payload = test_request(Some(&saved.id), serde_json::json!({ "smtp_host": "smtp.example.com" }));

        prepare(&storage, &mut payload, None, None)
            .await
            .unwrap();

        assert_eq!(payload.configuration["smtp_password"], SMTP_PASSWORD);
    }

    #[tokio::test]
    async fn a_request_without_an_integration_id_tests_what_it_sends() {
        let (_dir, storage, _saved) = storage_with("general", None).await;
        let mut payload =
            test_request(None, serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": "typed" }));

        prepare(&storage, &mut payload, None, None)
            .await
            .unwrap();

        assert_eq!(payload.configuration["smtp_password"], "typed");
    }

    #[tokio::test]
    async fn the_old_placeholder_is_refused() {
        let (_dir, storage, saved) = storage_with("general", None).await;
        let mut payload = test_request(
            Some(&saved.id),
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password": MASKED_CREDENTIAL }),
        );

        let refused = prepare(&storage, &mut payload, None, None)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            refused
                .1
                .contains("smtp_password"),
            "{}",
            refused.1
        );
    }

    #[tokio::test]
    async fn saved_credentials_are_refused_outside_the_callers_reach() {
        let (_dir, storage, saved) = storage_with("general", Some("tenant-b")).await;
        let (_audit_dir, audit_storage, audit) = storage_with("audit", None).await;

        let cases = [
            ("unknown id", &storage, "missing-id".to_string(), None, None, StatusCode::NOT_FOUND),
            ("other tenant", &storage, saved.id.clone(), tenant("tenant-a"), None, StatusCode::FORBIDDEN),
            (
                "outside token scope",
                &storage,
                saved.id.clone(),
                tenant("tenant-b"),
                scope(r"\ATENANT:tenant-b:integrations:someone-else\z"),
                StatusCode::FORBIDDEN,
            ),
            ("audit without audit.view", &audit_storage, audit.id.clone(), None, None, StatusCode::FORBIDDEN),
        ];

        for (case, storage, id, context, scope, expected) in cases {
            let mut payload = test_request(Some(&id), serde_json::json!({ "smtp_host": "smtp.example.com" }));
            let refused = prepare(storage, &mut payload, context, scope)
                .await
                .unwrap_err();
            assert_eq!(refused.0, expected, "{case}");
            assert!(
                payload
                    .configuration
                    .get("smtp_password")
                    .is_none(),
                "{case}"
            );
        }
    }

    #[tokio::test]
    async fn a_saved_credential_is_not_sent_to_a_new_host() {
        let (_dir, storage, saved) = storage_with("general", None).await;
        let mut payload = test_request(Some(&saved.id), serde_json::json!({ "smtp_host": "smtp.attacker.example" }));

        let refused = prepare(&storage, &mut payload, None, None)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST);
        assert!(
            !payload
                .configuration
                .to_string()
                .contains(SMTP_PASSWORD)
        );
    }

    #[tokio::test]
    async fn a_swapped_url_reference_is_not_tested_with_the_saved_signing_secret() {
        let dir = tempfile::tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let saved = Integration::new(
            "hook".into(),
            String::new(),
            "webhook".into(),
            serde_json::json!({ "url_secret_id": "smtp-global", "signing_secret": "whsec-saved" }),
            serde_json::json!({}),
            "active".into(),
            Some("general".into()),
        );
        storage
            .save(&saved)
            .await
            .unwrap();
        let mut payload = test_request(Some(&saved.id), serde_json::json!({ "url_secret_id": "smtp-b" }));
        payload.integration_type = "webhook".into();

        let refused = prepare(&storage, &mut payload, None, None)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            !payload
                .configuration
                .to_string()
                .contains("whsec-saved")
        );

        let mut payload = test_request(Some(&saved.id), serde_json::json!({ "url_secret_id": "smtp-b" }));
        payload.integration_type = "webhook".into();
        let refused = prepare_as(UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap_err();

        assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{}", refused.1);
        assert!(
            !payload
                .configuration
                .to_string()
                .contains("whsec-saved")
        );
    }

    #[tokio::test]
    async fn a_secret_reference_resolves_for_the_saved_integrations_tenant() {
        let (_dir, storage, saved) = storage_with("general", Some("tenant-b")).await;
        let mut payload = test_request(
            Some(&saved.id),
            serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password_secret_id": "smtp-b" }),
        );

        prepare_as(UserRole::Administrator, &storage, &mut payload, tenant("tenant-b"))
            .await
            .unwrap();

        assert_eq!(payload.configuration["smtp_password"], "tenant-b-pass");
        assert!(
            payload
                .configuration
                .get("smtp_password_secret_id")
                .is_none()
        );
    }

    #[tokio::test]
    async fn testing_a_stored_secret_against_a_host_of_choice_needs_secrets_view() {
        let (_dir, storage, _saved) = storage_with("general", None).await;
        let configuration = serde_json::json!({
            "smtp_host": "smtp.attacker.example",
            "smtp_password_secret_id": "smtp-global",
        });

        let mut payload = test_request(None, configuration.clone());
        let refused = prepare_as(UserRole::PowerUser, &storage, &mut payload, None)
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            !payload
                .configuration
                .to_string()
                .contains("global-pass")
        );

        let mut payload = test_request(None, configuration.clone());
        let refused = prepare_revealing(false, UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap_err();
        assert_eq!(refused.0, StatusCode::FORBIDDEN, "{}", refused.1);
        assert!(
            !payload
                .configuration
                .to_string()
                .contains("global-pass")
        );

        let mut payload = test_request(None, configuration);
        prepare_as(UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap();
        assert_eq!(payload.configuration["smtp_password"], "global-pass");
    }

    #[tokio::test]
    async fn with_values_hidden_a_test_may_reference_only_the_url_its_type_delivers_to() {
        let (_dir, storage, _saved) = storage_with("general", None).await;

        for (case, integration_type, configuration) in [
            ("a redis url on a webhook", "webhook", serde_json::json!({ "redis_url_secret_id": "hook-url" })),
            ("a webhook url on slack", "slack", serde_json::json!({ "url_secret_id": "hook-url" })),
            (
                "a url and a routing header",
                "webhook",
                serde_json::json!({ "url_secret_id": "hook-url", "headers": { "Host": "attacker.example" } }),
            ),
        ] {
            let mut payload = test_request(None, configuration.clone());
            payload.integration_type = integration_type.into();
            let refused = prepare_revealing(false, UserRole::Administrator, &storage, &mut payload, None)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::FORBIDDEN, "{case}: {}", refused.1);
            assert!(
                refused
                    .1
                    .contains("not revealed"),
                "{case}: {}",
                refused.1
            );
            assert_eq!(payload.configuration, configuration, "{case}");
        }

        let mut payload = test_request(None, serde_json::json!({ "url_secret_id": "hook-url" }));
        payload.integration_type = "webhook".into();
        prepare_revealing(false, UserRole::Administrator, &storage, &mut payload, None)
            .await
            .unwrap();
        assert_eq!(payload.configuration["url"], "https://hooks.example.com/in");
    }

    #[tokio::test]
    async fn without_secrets_view_testing_a_missing_or_an_existing_secret_gets_the_same_answer() {
        let (_dir, storage, _saved) = storage_with("general", None).await;

        let mut answers = Vec::new();
        for reference in ["smtp-global", "no-such-secret"] {
            let mut payload = test_request(
                None,
                serde_json::json!({ "smtp_host": "smtp.attacker.example", "smtp_password_secret_id": reference }),
            );
            answers.push(
                prepare_as(UserRole::PowerUser, &storage, &mut payload, None)
                    .await
                    .unwrap_err(),
            );
        }

        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert_eq!(answers[0], answers[1]);
    }

    #[tokio::test]
    async fn a_secret_reference_outside_the_owners_tenant_is_refused() {
        let (_dir, storage, _saved) = storage_with("general", None).await;
        let cases = [
            ("another tenant's secret", tenant("tenant-a"), "smtp-b"),
            ("tenant secret for an appliance-wide owner", None, "smtp-b"),
            ("unknown secret", None, "missing"),
        ];

        for (case, context, reference) in cases {
            let mut payload = test_request(
                None,
                serde_json::json!({ "smtp_host": "smtp.example.com", "smtp_password_secret_id": reference }),
            );
            let refused = prepare_as(UserRole::Administrator, &storage, &mut payload, context)
                .await
                .unwrap_err();
            assert_eq!(refused.0, StatusCode::BAD_REQUEST, "{case}");
            assert!(
                payload
                    .configuration
                    .get("smtp_password")
                    .is_none(),
                "{case}"
            );
        }
    }

    async fn storage() -> (tempfile::TempDir, Arc<IntegrationStorage>) {
        let dir = tempfile::tempdir().expect("storage directory");
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .expect("integration storage");
        (dir, Arc::new(storage))
    }

    async fn save(
        storage: &IntegrationStorage,
        integration_type: &str,
        configuration: serde_json::Value,
    ) -> Integration {
        let integration = Integration::new(
            "saved".to_string(),
            String::new(),
            integration_type.to_string(),
            configuration,
            serde_json::json!({}),
            "active".to_string(),
            Some("general".to_string()),
        );
        storage
            .save(&integration)
            .await
            .expect("save the integration");
        integration
    }

    async fn test_response(
        storage: Arc<IntegrationStorage>,
        integration_type: &str,
        configuration: serde_json::Value,
        integration_id: Option<&str>,
    ) -> (StatusCode, String) {
        let request = TestNotifierRequest {
            integration_type: integration_type.to_string(),
            configuration,
            content: serde_json::json!({}),
            variables: Default::default(),
            integration_id: integration_id.map(str::to_string),
        };
        match test_notifier_handler(
            Extension(storage),
            Extension(None),
            Extension(RevealSecretValues(true)),
            None,
            None,
            None,
            None,
            None,
            Json(request),
        )
        .await
        {
            Ok(response) => (
                response
                    .into_response()
                    .status(),
                String::new(),
            ),
            Err(refused) => refused,
        }
    }

    fn smtp_configuration(
        host: &str,
        port: u16,
    ) -> serde_json::Value {
        serde_json::json!({
            "smtp_host": host,
            "smtp_port": port,
            "smtp_username": "mailer",
            "smtp_password": "smtp-pass-123",
            "from": "agent-stream@example.com",
            "to": ["ops@example.com"],
            "use_tls": false,
            "use_starttls": false,
        })
    }

    fn redis_configuration(redis_url: &str) -> serde_json::Value {
        serde_json::json!({ "platform": "redis", "topic": "events", "redis_url": redis_url })
    }

    fn loopback_listener() -> (TcpListener, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback listener");
        listener
            .set_nonblocking(true)
            .expect("make the listener non-blocking");
        let port = listener
            .local_addr()
            .expect("listener address")
            .port();
        (listener, port)
    }

    fn was_dialled(listener: &TcpListener) -> bool {
        match listener.accept() {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => false,
            Err(error) => panic!("listener failed: {error}"),
        }
    }

    /// Accept one connection within ten seconds and close it at once, so the
    /// client fails fast; reports whether a connection arrived.
    fn accept_once(listener: TcpListener) -> std::thread::JoinHandle<bool> {
        std::thread::spawn(move || {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if was_dialled(&listener) {
                    return true;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            false
        })
    }

    #[tokio::test]
    async fn test_an_internal_smtp_host_is_refused_without_dialling_or_naming_its_address() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();

        let (status, message) = test_response(storage, "email", smtp_configuration("localhost", port), None).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(message, DestinationError::NotPublic.to_string());
        assert!(!message.contains("127.0.0.1") && !message.contains("::1"), "{message}");
        assert!(!was_dialled(&listener));
    }

    #[tokio::test]
    async fn test_an_allowed_smtp_server_is_dialled_and_a_failure_is_not_described() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();
        let _allowed = test_service_endpoints::allow(&[format!("http://127.0.0.1:{port}")]);
        let accepted = accept_once(listener);

        let (status, message) = test_response(storage, "email", smtp_configuration("127.0.0.1", port), None).await;

        assert_eq!((status, message.as_str()), (StatusCode::BAD_GATEWAY, TEST_DELIVERY_FAILED));
        assert!(
            accepted
                .join()
                .expect("listener thread"),
            "the SMTP server was not dialled"
        );
    }

    #[tokio::test]
    async fn test_internal_or_socket_stream_destinations_are_refused() {
        let cases = [
            (redis_configuration("redis://169.254.169.254:6379"), true),
            (redis_configuration("unix:///var/run/redis.sock"), false),
            (redis_configuration("redis+unix:///var/run/redis.sock"), false),
            (serde_json::json!({ "platform": "kafka", "brokers": "93.184.216.34:9092,10.0.0.5:9092" }), true),
            (serde_json::json!({ "platform": "pulsar", "brokers": "pulsar://127.0.0.1:6650" }), true),
        ];

        for (mut configuration, internal) in cases {
            let (_dir, storage) = storage().await;
            configuration["topic"] = serde_json::json!("events");
            let (status, message) = test_response(storage, "stream", configuration.clone(), None).await;

            assert_eq!(status, StatusCode::BAD_REQUEST, "{configuration}: {message}");
            assert_eq!(message == DestinationError::NotPublic.to_string(), internal, "{configuration}: {message}");
        }
    }

    #[tokio::test]
    async fn test_an_allowed_redis_server_is_dialled() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();
        let _allowed = test_service_endpoints::allow(&[format!("http://127.0.0.1:{port}")]);
        let accepted = accept_once(listener);

        let (status, message) =
            test_response(storage, "stream", redis_configuration(&format!("redis://127.0.0.1:{port}")), None).await;

        assert_eq!((status, message.as_str()), (StatusCode::BAD_GATEWAY, TEST_DELIVERY_FAILED));
        assert!(
            accepted
                .join()
                .expect("listener thread"),
            "the Redis server was not dialled"
        );
    }

    #[tokio::test]
    async fn test_a_saved_internal_destination_is_refused_when_it_delivers() {
        for integration_type in ["email", "stream"] {
            let (_dir, storage) = storage().await;
            let (listener, port) = loopback_listener();
            let configuration = match integration_type {
                "email" => smtp_configuration("127.0.0.1", port),
                _ => redis_configuration(&format!("redis://127.0.0.1:{port}")),
            };
            let saved = save(&storage, integration_type, configuration.clone()).await;

            let (status, message) = test_response(storage, integration_type, configuration, Some(&saved.id)).await;

            assert_eq!(
                (status, message),
                (StatusCode::BAD_REQUEST, DestinationError::NotPublic.to_string()),
                "{integration_type}"
            );
            assert!(!was_dialled(&listener), "{integration_type}: the saved internal destination was dialled");
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn test_a_saved_redis_socket_is_refused_when_it_delivers() {
        let (dir, storage) = storage().await;
        let socket = dir.path().join("redis.sock");
        let listener = std::os::unix::net::UnixListener::bind(&socket).expect("bind a Unix socket");
        listener
            .set_nonblocking(true)
            .expect("make the socket non-blocking");
        let configuration = redis_configuration(&format!("unix://{}", socket.display()));
        let saved = save(&storage, "stream", configuration.clone()).await;

        let (status, _) = test_response(storage, "stream", configuration, Some(&saved.id)).await;

        assert_eq!(status, StatusCode::BAD_REQUEST);
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            other => panic!("the saved Unix socket was dialled: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_a_test_that_changes_a_saved_destination_is_checked() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();
        let saved = save(&storage, "email", smtp_configuration("93.184.216.34", port)).await;

        let (status, message) =
            test_response(storage, "email", smtp_configuration("127.0.0.1", port), Some(&saved.id)).await;

        assert_eq!((status, message), (StatusCode::BAD_REQUEST, DestinationError::NotPublic.to_string()));
        assert!(!was_dialled(&listener));
    }

    #[tokio::test]
    async fn test_a_saved_integration_of_another_type_does_not_exempt_a_test() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();
        let webhook = save(&storage, "webhook", smtp_configuration("127.0.0.1", port)).await;

        let (status, message) =
            test_response(storage, "email", smtp_configuration("127.0.0.1", port), Some(&webhook.id)).await;

        assert_eq!((status, message), (StatusCode::BAD_REQUEST, DestinationError::NotPublic.to_string()));
        assert!(!was_dialled(&listener));
    }

    #[tokio::test]
    async fn test_a_saved_integration_outside_the_callers_tenant_is_refused() {
        let (_dir, storage) = storage().await;
        let (listener, port) = loopback_listener();
        let configuration = smtp_configuration("127.0.0.1", port);
        let mut other_tenants = Integration::new(
            "theirs".to_string(),
            String::new(),
            "email".to_string(),
            configuration.clone(),
            serde_json::json!({}),
            "active".to_string(),
            Some("general".to_string()),
        );
        other_tenants.tenant_id = Some("tenant-b".to_string());
        storage
            .save(&other_tenants)
            .await
            .expect("save the integration");
        let request = TestNotifierRequest {
            integration_type: "email".to_string(),
            configuration,
            content: serde_json::json!({}),
            variables: Default::default(),
            integration_id: Some(other_tenants.id.clone()),
        };
        let caller = Some(Extension(PatTenantContext {
            token_id: "asat_test".to_string(),
            tenant_id: "tenant-a".to_string(),
        }));

        let refused = test_notifier_handler(
            Extension(storage),
            Extension(None),
            Extension(RevealSecretValues(true)),
            caller,
            None,
            None,
            None,
            None,
            Json(request),
        )
        .await
        .map(|_| ());

        assert_eq!(refused.map_err(|(status, _)| status), Err(StatusCode::FORBIDDEN));
        assert!(!was_dialled(&listener));
    }

    #[tokio::test]
    async fn test_a_test_naming_an_unknown_integration_is_not_found() {
        let (_dir, storage) = storage().await;

        let (status, _) =
            test_response(storage, "email", smtp_configuration("93.184.216.34", 25), Some("missing")).await;

        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_slack_and_webhook_tests_refuse_a_url_that_rebinds_to_loopback() {
        for (integration_type, url_key) in [("slack", "webhook_url"), ("webhook", "url")] {
            let (_dir, storage) = storage().await;
            let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("ok").await;
            let dns = crate::url_validation::test_dns::rebind_to_loopback("hooks.rebind.test");
            let configuration = serde_json::json!({ url_key: upstream.url.replace("127.0.0.1", "hooks.rebind.test") });

            let (status, message) = test_response(storage, integration_type, configuration, None).await;

            assert_ne!(status, StatusCode::OK, "{integration_type}: {message}");
            assert_eq!(dns.lookups(), 2, "{integration_type}: the address must be checked again at connect time");
            assert_eq!(upstream.requests(), 0, "{integration_type}");
        }
    }

    #[tokio::test]
    async fn slack_and_webhook_tests_refuse_a_value_that_is_not_an_http_url_without_describing_it() {
        for (integration_type, url_key) in [("slack", "webhook_url"), ("webhook", "url")] {
            for value in ["admin:hunter2", "global-token", "ftp://files.example.com/in"] {
                let (_dir, storage) = storage().await;

                let (status, message) =
                    test_response(storage, integration_type, serde_json::json!({ url_key: value }), None).await;

                assert_eq!(status, StatusCode::BAD_REQUEST, "{integration_type} {value}: {message}");
                assert_eq!(message, format!("{url_key} must be an http or https URL"), "{integration_type} {value}");
            }
        }
    }

    #[tokio::test]
    async fn with_values_hidden_a_caller_without_secrets_view_cannot_tell_whether_a_test_keeps_a_credential() {
        let mut answers = Vec::new();
        for kept in [
            serde_json::json!({}),
            serde_json::json!({ "headers": { "Authorization": "Bearer saved-inline-token" } }),
            serde_json::json!({ "signing_secret": "whsec-saved-3f2c1a9e-7b4d-4e8a-9c61" }),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let storage = IntegrationStorage::new(dir.path().to_path_buf())
                .await
                .unwrap();
            let mut configuration = serde_json::json!({
                "url_secret_id": "moved-hook",
                "pinned_destination": { "url": "hooks.example.com:443" },
            });
            configuration
                .as_object_mut()
                .unwrap()
                .extend(
                    kept.as_object()
                        .unwrap()
                        .clone(),
                );
            let saved = save(&storage, "webhook", configuration).await;
            let mut payload = webhook_test_of(&saved);
            answers.push(
                prepare_revealing(false, UserRole::PowerUser, &storage, &mut payload, None)
                    .await
                    .unwrap_err(),
            );
        }

        assert_eq!(answers[0].0, StatusCode::FORBIDDEN, "{}", answers[0].1);
        assert!(
            answers[0]
                .1
                .contains("secrets.view"),
            "{}",
            answers[0].1
        );
        assert!(
            answers
                .iter()
                .all(|answer| answer == &answers[0]),
            "{answers:?}"
        );
    }

    #[tokio::test]
    async fn a_referenced_test_url_is_refused_with_its_reason_only_to_secrets_view_while_values_are_revealed() {
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;

        for (integration_type, key) in [("webhook", "url"), ("slack", "webhook_url")] {
            let (_dir, storage) = storage().await;
            let reference = format!("{key}_secret_id");
            let saved = save(
                &storage,
                integration_type,
                serde_json::json!({ reference.clone(): "private-hook", "pinned_destination": { key: "10.0.0.5:80" } }),
            )
            .await;
            let respond = |caller: &TestCaller, reveal_values: bool, configuration: serde_json::Value, saved_id| {
                let storage = storage.clone();
                let guard = caller.guard.clone();
                let caller = caller.caller.clone();
                async move {
                    test_notifier_handler(
                        Extension(storage),
                        Extension(secrets()),
                        Extension(RevealSecretValues(reveal_values)),
                        None,
                        None,
                        guard,
                        caller,
                        None,
                        Json(TestNotifierRequest {
                            integration_type: integration_type.into(),
                            configuration,
                            content: serde_json::json!({}),
                            variables: Default::default(),
                            integration_id: saved_id,
                        }),
                    )
                    .await
                    .map(|_| ())
                    .unwrap_err()
                }
            };
            let referenced = serde_json::json!({ reference.clone(): "private-hook" });
            let hidden = (
                StatusCode::BAD_REQUEST,
                format!("{key}_secret_id does not name a destination this integration may send to"),
            );

            for (caller, reveal_values) in [(&poweruser, true), (&poweruser, false), (&administrator, false)] {
                let refused = respond(caller, reveal_values, referenced.clone(), Some(saved.id.clone())).await;
                assert_eq!(refused, hidden, "{integration_type} {reveal_values}");
            }

            let revealed = respond(&administrator, true, referenced.clone(), Some(saved.id.clone())).await;
            assert_eq!(revealed.0, StatusCode::BAD_REQUEST, "{integration_type}: {}", revealed.1);
            assert!(
                revealed
                    .1
                    .contains("rejected"),
                "{integration_type}: {}",
                revealed.1
            );

            let unsaved = respond(&administrator, true, referenced, None).await;
            assert!(unsaved.1.contains("rejected"), "{integration_type}: {}", unsaved.1);

            let inline = respond(&administrator, true, serde_json::json!({ key: "http://10.0.0.5/in" }), None).await;
            assert_eq!(inline.0, StatusCode::BAD_REQUEST, "{integration_type}: {}", inline.1);
            assert!(inline.1.contains("rejected"), "{integration_type}: {}", inline.1);
        }
    }

    #[tokio::test]
    async fn a_referenced_redis_url_at_its_pinned_destination_is_refused_with_its_reason_only_to_secrets_view() {
        let (_dir, storage) = storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;
        let referenced = serde_json::json!({
            "platform": "redis",
            "topic": "events",
            "redis_url_secret_id": "internal-redis",
        });
        let mut configuration = referenced.clone();
        configuration["pinned_destination"] = serde_json::json!({ "redis_url": "10.0.0.5:6379" });
        let saved = save(&storage, "stream", configuration).await;
        let respond = |caller: &TestCaller, reveal_values: bool| {
            let storage = storage.clone();
            let guard = caller.guard.clone();
            let caller = caller.caller.clone();
            let configuration = referenced.clone();
            let integration_id = Some(saved.id.clone());
            async move {
                test_notifier_handler(
                    Extension(storage),
                    Extension(secrets()),
                    Extension(RevealSecretValues(reveal_values)),
                    None,
                    None,
                    guard,
                    caller,
                    None,
                    Json(TestNotifierRequest {
                        integration_type: "stream".into(),
                        configuration,
                        content: serde_json::json!({}),
                        variables: Default::default(),
                        integration_id,
                    }),
                )
                .await
                .map(|_| ())
                .unwrap_err()
            }
        };

        for (caller, reveal_values) in [(&poweruser, true), (&poweruser, false), (&administrator, false)] {
            assert_eq!(
                respond(caller, reveal_values).await,
                (
                    StatusCode::BAD_REQUEST,
                    "redis_url_secret_id does not name a destination this integration may send to".to_string()
                ),
                "{reveal_values}"
            );
        }
        assert_eq!(
            respond(&administrator, true).await,
            (StatusCode::BAD_REQUEST, DestinationError::NotPublic.to_string())
        );
    }

    #[test]
    fn a_failed_delivery_is_described_only_to_a_caller_who_may_see_secrets() {
        let publisher = || {
            IntegrationError::PublisherError(anyhow::anyhow!(
                "DNS resolution for 'hooks.internal.example' returned 10.0.0.5"
            ))
        };
        let task = || IntegrationError::TaskJoinError("panic: task 7 panicked with message \"10.0.0.5\"".into());

        for error in [publisher(), task()] {
            assert_eq!(trigger_failure(&error, false), TRIGGER_FAILED, "{error}");
            assert_eq!(trigger_failure(&error, true), error.to_string());
        }
        for error in [
            IntegrationError::NotFound("hook".into()),
            IntegrationError::Inactive("hook".into(), "disabled".into()),
            IntegrationError::AuditOnly("hook".into()),
            IntegrationError::UnknownType("fax".into()),
            IntegrationError::StorageError("Integration storage not initialized".into()),
        ] {
            assert_eq!(trigger_failure(&error, false), error.to_string());
        }
    }

    const PRIVATE_HOOK: &str = "http://10.0.0.5/in";

    /// A webhook to an address every delivery refuses, saved in `storage` and
    /// cached where a trigger loads it.
    async fn cached_webhook(
        storage: &IntegrationStorage,
        configuration: serde_json::Value,
        status: &str,
    ) -> Integration {
        let integration = Integration::new(
            "hook".into(),
            String::new(),
            "webhook".into(),
            configuration,
            serde_json::json!({}),
            status.into(),
            Some("general".into()),
        );
        storage
            .save(&integration)
            .await
            .unwrap();
        // The save invalidates the cache entry from a spawned task; let it run first.
        for _ in 0..3 {
            tokio::task::yield_now().await;
        }
        crate::integrations::cache::INTEGRATION_CACHE
            .insert(integration.id.clone(), Arc::new(integration.clone()))
            .await;
        integration
    }

    fn referencing_a_missing_secret() -> serde_json::Value {
        serde_json::json!({
            "url": PRIVATE_HOOK,
            "headers_secret_id": { "Authorization": "trigger-test-missing-secret" },
        })
    }

    #[tokio::test]
    async fn a_failed_trigger_answers_why_only_to_a_caller_who_may_see_secrets() {
        let (_dir, storage) = storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;
        let referenced = cached_webhook(&storage, referencing_a_missing_secret(), "active").await;
        let inline = cached_webhook(&storage, serde_json::json!({ "url": PRIVATE_HOOK }), "active").await;
        let inactive = cached_webhook(&storage, referencing_a_missing_secret(), "disabled").await;
        let trigger = |caller: &TestCaller, reveal_values: bool, integration_id: &str| {
            let storage = storage.clone();
            let guard = caller.guard.clone();
            let caller = caller.caller.clone();
            let integration_id = integration_id.to_string();
            async move {
                trigger_integration_handler(
                    Extension(storage),
                    Extension(RevealSecretValues(reveal_values)),
                    Path(integration_id),
                    None,
                    None,
                    guard,
                    caller,
                    None,
                    Json(TriggerNotifierRequest {
                        subject: "subject".into(),
                        message: "message".into(),
                        variables: Default::default(),
                    }),
                )
                .await
                .map(|_| ())
                .unwrap_err()
            }
        };

        for integration_id in [&referenced.id, &inline.id] {
            for (caller, reveal_values) in [(&poweruser, true), (&poweruser, false), (&administrator, false)] {
                assert_eq!(
                    trigger(caller, reveal_values, integration_id).await,
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to trigger integration: {TRIGGER_FAILED}")),
                    "{integration_id} {reveal_values}"
                );
            }
        }
        let revealed = trigger(&administrator, true, &referenced.id).await;
        assert_eq!(revealed.0, StatusCode::INTERNAL_SERVER_ERROR, "{}", revealed.1);
        assert!(
            revealed
                .1
                .contains("not available"),
            "{}",
            revealed.1
        );
        let revealed = trigger(&administrator, true, &inline.id).await;
        assert!(
            revealed
                .1
                .contains("10.0.0.5"),
            "{}",
            revealed.1
        );

        let disabled = trigger(&poweruser, false, &inactive.id).await;
        assert!(
            disabled
                .1
                .contains("is not active"),
            "{}",
            disabled.1
        );
    }

    #[tokio::test]
    async fn trigger_multiple_answers_each_failed_entry_only_to_a_caller_who_may_see_secrets() {
        let (_dir, storage) = storage().await;
        let poweruser = signed_in(UserRole::PowerUser).await;
        let administrator = signed_in(UserRole::Administrator).await;
        let referenced = cached_webhook(&storage, referencing_a_missing_secret(), "active").await;
        let inline = cached_webhook(&storage, serde_json::json!({ "url": PRIVATE_HOOK }), "active").await;
        let ids = vec![referenced.id.clone(), inline.id.clone(), referenced.id.clone()];
        let trigger = |caller: &TestCaller| {
            let storage = storage.clone();
            let guard = caller.guard.clone();
            let caller = caller.caller.clone();
            let integration_ids = ids.clone();
            async move {
                let response = trigger_multiple_notifiers_handler(
                    Extension(storage),
                    Extension(RevealSecretValues(true)),
                    None,
                    None,
                    guard,
                    caller,
                    None,
                    Json(TriggerNotifiersRequest {
                        integration_ids,
                        subject: "subject".into(),
                        message: "message".into(),
                        variables: Default::default(),
                    }),
                )
                .await
                .unwrap()
                .into_response();
                assert_eq!(response.status(), StatusCode::OK);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                serde_json::from_slice::<serde_json::Value>(&body).unwrap()["results"].clone()
            }
        };

        let results = trigger(&poweruser).await;
        let results = results.as_array().unwrap();
        assert_eq!(results.len(), ids.len());
        for (entry, id) in results.iter().zip(&ids) {
            assert_eq!(entry["integration_id"], id.as_str());
            assert_eq!(entry["success"], false, "{entry}");
        }
        for entry in results {
            assert_eq!(entry["error"], TRIGGER_FAILED, "{entry}");
        }

        let revealed = trigger(&administrator).await;
        assert!(
            revealed[0]["error"]
                .as_str()
                .unwrap()
                .contains("not available"),
            "{}",
            revealed[0]
        );
        assert!(
            revealed[1]["error"]
                .as_str()
                .unwrap()
                .contains("10.0.0.5"),
            "{}",
            revealed[1]
        );
    }

    #[test]
    fn a_refused_test_answers_the_status_and_not_the_response_body() {
        let (status, message) = destination_refused_test(
            "Slack webhook",
            reqwest::StatusCode::FORBIDDEN,
            "Cannot POST /services/T000/B000/secret-token",
        );

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(message, "Slack webhook failed with status 403 Forbidden. The appliance log has the response.");
    }
}
