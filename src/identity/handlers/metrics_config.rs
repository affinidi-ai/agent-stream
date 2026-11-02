//! Handlers for metrics configuration management via API

use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::fs;
use tracing::{debug, error, info, warn};
use url::Url;

use crate::auth_manager::middleware::{AuthGuardOk, RbacGuard};
use crate::auth_manager::pat::PatContext;
use crate::config::metrics_config::MetricsConfig;
use crate::identity::state::IdentityApiState;
use crate::rbac::Feature;

/// Application error type for metrics config handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
    PermissionDenied(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
            AppError::PermissionDenied(msg) => {
                warn!("API Permission Denied: {}", msg);
                (StatusCode::FORBIDDEN, "Permission Denied", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Get current metrics configuration, without the collector auth secret reference
pub async fn get_metrics_config(State(state): State<IdentityApiState>) -> Result<Json<MetricsConfig>, AppError> {
    info!("Fetching metrics configuration");

    let config_path = &state
        .bootstrap_config
        .config_files
        .metrics;

    let config = read_metrics_config(config_path)?;

    debug!("Successfully loaded metrics configuration from {}", config_path);
    Ok(Json(without_secret_reference(config)))
}

fn read_metrics_config(config_path: &str) -> Result<MetricsConfig, AppError> {
    let config_str = fs::read_to_string(config_path)
        .map_err(|e| AppError::InternalError(format!("Failed to read metrics config: {}", e)))?;

    serde_json::from_str(&config_str)
        .map_err(|e| AppError::InternalError(format!("Failed to parse metrics config: {}", e)))
}

fn without_secret_reference(mut config: MetricsConfig) -> MetricsConfig {
    if let Some(auth) = config
        .opentelemetry
        .auth
        .as_mut()
    {
        auth.secret_id.clear();
    }
    config
}

/// Update metrics configuration
pub async fn update_metrics_config(
    Extension(guard): Extension<RbacGuard>,
    Extension(AuthGuardOk(user_id)): Extension<AuthGuardOk>,
    pat: Option<Extension<PatContext>>,
    tenant: Option<Extension<crate::tenancy::PatTenantContext>>,
    State(state): State<IdentityApiState>,
    Json(mut new_config): Json<MetricsConfig>,
) -> Result<Json<UpdateResponse>, AppError> {
    info!("Updating metrics configuration");

    // Validate the configuration
    validate_metrics_config(&new_config)?;

    let config_path = &state
        .bootstrap_config
        .config_files
        .metrics;

    // An unreadable stored file counts as nothing stored, so every target in
    // the request is checked.
    let stored = read_metrics_config(config_path).ok();
    let may_choose_secret = guard
        .allows(
            &user_id,
            pat.as_ref()
                .map(|Extension(pat)| pat),
            Feature::SecretsView,
        )
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to check permissions: {}", e)))?;
    prepare_save(
        &mut new_config,
        stored.as_ref(),
        may_choose_secret,
        tenant
            .as_ref()
            .map(|Extension(tenant)| tenant),
    )
    .await?;

    // Serialize with pretty printing
    let config_json = serde_json::to_string_pretty(&new_config)
        .map_err(|e| AppError::InternalError(format!("Failed to serialize metrics config: {}", e)))?;

    // Write to file
    fs::write(config_path, config_json)
        .map_err(|e| AppError::InternalError(format!("Failed to write metrics config: {}", e)))?;

    info!(
        user_id = %user_id,
        endpoint = %crate::url_validation::redact_url_for_logging(&new_config.opentelemetry.endpoint),
        enabled = new_config.opentelemetry.enabled,
        "Updated metrics configuration"
    );

    // Apply the new configuration live (no restart) by rebuilding and swapping
    // the OpenTelemetry pipeline in place. The file is already persisted, so a
    // reload failure is surfaced in the message rather than failing the request.
    let message = match apply_otel_reload(&state, &new_config).await {
        Ok(()) => "Metrics configuration updated and applied immediately.".to_string(),
        Err(e) => {
            warn!("Metrics config saved but live OpenTelemetry reload failed: {e:#}");
            "Metrics configuration saved, but applying it live failed (see the appliance log); a restart may be \
             required."
                .to_string()
        }
    };

    Ok(Json(UpdateResponse { success: true, message }))
}

/// Resolve the optional OTLP auth header from the secrets store and hot-reload
/// the OpenTelemetry pipeline so a metrics-config save takes effect without a
/// restart.
async fn apply_otel_reload(
    state: &IdentityApiState,
    new_config: &MetricsConfig,
) -> anyhow::Result<()> {
    let otel = &new_config.opentelemetry;

    // Resolve the auth header the same way startup does, when configured.
    let auth_header = if otel.enabled
        && let Some(auth) = otel.auth.as_ref()
    {
        let store = crate::secrets::create_secrets_store(Some(
            state
                .bootstrap_config
                .storage_paths
                .secrets
                .clone(),
        ))
        .await?;
        Some(crate::config::metrics_config::resolve_otel_auth_header(auth, &store).await?)
    } else {
        None
    };

    crate::observability::reload_otel(otel, auth_header).await
}

/// Response for update operation
#[derive(Debug, Serialize)]
pub struct UpdateResponse {
    pub success: bool,
    pub message: String,
}

/// Complete and check a configuration save against the stored configuration:
/// an omitted auth `secret_id` keeps the stored one, only a caller who may view
/// secrets chooses which secret is sent to which collector, and a changed
/// export target must be a public collector. An unchanged target passes, so a
/// collector set in `metrics.json` on disk keeps working when other settings
/// are saved.
async fn prepare_save(
    new_config: &mut MetricsConfig,
    stored: Option<&MetricsConfig>,
    may_choose_secret: bool,
    tenant: Option<&crate::tenancy::PatTenantContext>,
) -> Result<(), AppError> {
    // metrics.json is appliance-wide and names a secret resolved with no
    // tenant check, so an access token bound to a tenant cannot change it.
    if !crate::tenancy::can_mutate(None, tenant) {
        return Err(AppError::PermissionDenied(
            "Metrics configuration is appliance-wide; an access token bound to a tenant cannot change it".to_string(),
        ));
    }
    keep_stored_secret_reference(new_config, stored)?;

    let destination = credential_destination(new_config);
    if !may_choose_secret && destination.is_some() && destination != stored.and_then(credential_destination) {
        return Err(AppError::PermissionDenied(
            "Choosing the secret sent to a collector requires the secrets.view permission".to_string(),
        ));
    }

    let Some(endpoint) = export_target(new_config) else {
        return Ok(());
    };
    if stored.and_then(export_target) == Some(endpoint) {
        return Ok(());
    }
    if let Err(reason) = crate::url_validation::validate_resolved_webhook_url(endpoint).await {
        warn!(
            endpoint = %crate::url_validation::redact_url_for_logging(endpoint),
            reason = %reason,
            "Refused OpenTelemetry endpoint"
        );
        return Err(refused_endpoint());
    }
    Ok(())
}

fn keep_stored_secret_reference(
    new_config: &mut MetricsConfig,
    stored: Option<&MetricsConfig>,
) -> Result<(), AppError> {
    let Some(auth) = new_config
        .opentelemetry
        .auth
        .as_mut()
    else {
        return Ok(());
    };
    if !auth
        .secret_id
        .trim()
        .is_empty()
    {
        return Ok(());
    }
    auth.secret_id = stored
        .and_then(|stored| {
            stored
                .opentelemetry
                .auth
                .as_ref()
        })
        .map(|stored_auth| stored_auth.secret_id.clone())
        .filter(|secret_id| !secret_id.is_empty())
        .ok_or_else(|| AppError::BadRequest("Select the secret that holds the collector credential".to_string()))?;
    Ok(())
}

/// The endpoint telemetry is exported to, while OpenTelemetry is enabled.
fn export_target(config: &MetricsConfig) -> Option<&str> {
    let otel = &config.opentelemetry;
    otel.enabled
        .then_some(otel.endpoint.as_str())
}

/// The collector the auth secret is sent to, paired with that secret.
fn credential_destination(config: &MetricsConfig) -> Option<(&str, &str)> {
    let auth = config
        .opentelemetry
        .auth
        .as_ref()?;
    Some((export_target(config)?, auth.secret_id.as_str()))
}

/// Validate metrics configuration before saving
fn validate_metrics_config(config: &MetricsConfig) -> Result<(), AppError> {
    // Validate OpenTelemetry config
    if config.opentelemetry.enabled {
        if config
            .opentelemetry
            .endpoint
            .is_empty()
        {
            return Err(AppError::BadRequest("OpenTelemetry endpoint cannot be empty when enabled".to_string()));
        }

        // Basic URL validation for gRPC endpoint
        if !config
            .opentelemetry
            .endpoint
            .starts_with("http://")
            && !config
                .opentelemetry
                .endpoint
                .starts_with("https://")
        {
            return Err(AppError::BadRequest("OpenTelemetry endpoint must start with http:// or https://".to_string()));
        }

        // Validate service name
        if config
            .opentelemetry
            .service_name
            .is_empty()
        {
            return Err(AppError::BadRequest("Service name cannot be empty when OpenTelemetry is enabled".to_string()));
        }

        // Validate sampling rate
        if config
            .opentelemetry
            .traces
            .sample_rate
            < 0.0
            || config
                .opentelemetry
                .traces
                .sample_rate
                > 1.0
        {
            return Err(AppError::BadRequest("Trace sample rate must be between 0.0 and 1.0".to_string()));
        }

        // Validate export interval
        if config
            .opentelemetry
            .metrics
            .export_interval_seconds
            == 0
        {
            return Err(AppError::BadRequest("Metrics export interval must be greater than 0".to_string()));
        }
    }

    // Validate CloudWatch config
    if config.cloudwatch.enabled {
        if config
            .cloudwatch
            .region
            .clone()
            .unwrap_or("".to_string())
            .is_empty()
        {
            return Err(AppError::BadRequest("CloudWatch region cannot be empty when enabled".to_string()));
        }

        if config
            .cloudwatch
            .namespace
            .is_empty()
        {
            return Err(AppError::BadRequest("CloudWatch namespace cannot be empty when enabled".to_string()));
        }
    }

    // Validate retention config
    if config
        .retention
        .local_logs_hours
        == 0
    {
        return Err(AppError::BadRequest("Local logs retention hours must be greater than 0".to_string()));
    }

    if config
        .retention
        .collector_log_mb
        == 0
    {
        return Err(AppError::BadRequest("Collector log size must be greater than 0 MB".to_string()));
    }

    // Validate advanced config
    if config.advanced.batch_size == 0 {
        return Err(AppError::BadRequest("Batch size must be greater than 0".to_string()));
    }

    if config.advanced.batch_delay_ms == 0 {
        return Err(AppError::BadRequest("Batch delay must be greater than 0 ms".to_string()));
    }

    if config
        .advanced
        .batch_queue_size
        == 0
    {
        return Err(AppError::BadRequest("Batch queue size must be greater than 0".to_string()));
    }

    Ok(())
}

/// Test OpenTelemetry connection
#[derive(Debug, Deserialize)]
pub struct TestConnectionRequest {
    pub endpoint: String,
}

/// Whether the collector accepted a connection. A refused and a timed-out
/// connection give the same answer, with no timing or error detail, so the
/// test cannot map which ports are open, closed or filtered.
#[derive(Debug, Serialize)]
pub struct TestConnectionResponse {
    pub success: bool,
    pub message: String,
}

const CONNECTION_TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

pub async fn test_otlp_connection(
    State(state): State<IdentityApiState>,
    Json(request): Json<TestConnectionRequest>,
) -> Result<Json<TestConnectionResponse>, AppError> {
    let stored = read_metrics_config(
        &state
            .bootstrap_config
            .config_files
            .metrics,
    )
    .ok();
    probe_collector(&request.endpoint, stored.as_ref(), CONNECTION_TEST_TIMEOUT)
        .await
        .map(Json)
}

/// Open one TCP connection to the collector. Only a public address may be
/// tested, except the endpoint telemetry is exported to in `metrics.json`
/// (with export enabled), which the operator chose and may be a local or
/// private collector. The connection goes to the addresses that were checked,
/// so DNS cannot change between the check and the connection. Every
/// not-reachable answer comes only once `timeout` has passed, so a refused
/// port cannot be told from a filtered one by timing.
async fn probe_collector(
    endpoint: &str,
    stored: Option<&MetricsConfig>,
    timeout: std::time::Duration,
) -> Result<TestConnectionResponse, AppError> {
    let endpoint = endpoint.trim();
    let invalid = || AppError::BadRequest("Endpoint must be an http:// or https:// URL with a host".to_string());
    let url = Url::parse(endpoint).map_err(|_| invalid())?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(invalid());
    }
    let host = match url.host() {
        Some(url::Host::Domain(domain)) if !domain.is_empty() => domain.to_string(),
        Some(url::Host::Ipv4(ip)) => ip.to_string(),
        Some(url::Host::Ipv6(ip)) => ip.to_string(),
        _ => return Err(invalid()),
    };
    let port = url
        .port()
        .unwrap_or(if url.scheme() == "https" {
            443
        } else {
            4317
        });
    let target = format!(
        "{}:{}",
        url.host_str()
            .unwrap_or_default(),
        port
    );

    let stored = stored
        .and_then(export_target)
        .map(str::trim)
        == Some(endpoint);
    if !stored && let Err(reason) = crate::url_validation::validate_resolved_webhook_url(endpoint).await {
        warn!(
            endpoint = %crate::url_validation::redact_url_for_logging(endpoint),
            reason = %reason,
            "Refused OpenTelemetry connection test target"
        );
        return Err(refused_endpoint());
    }
    let deadline = tokio::time::Instant::now() + timeout;
    let addresses: Vec<std::net::SocketAddr> =
        tokio::time::timeout_at(deadline, tokio::net::lookup_host((host.as_str(), port)))
            .await
            .ok()
            .and_then(Result::ok)
            .map(Iterator::collect)
            .unwrap_or_default();
    if !stored
        && addresses
            .iter()
            .any(|address| crate::url_validation::is_blocked_resolved_webhook_ip(address.ip()))
    {
        return Err(refused_endpoint());
    }

    let reached = !addresses.is_empty()
        && match tokio::time::timeout_at(deadline, tokio::net::TcpStream::connect(&addresses[..])).await {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => {
                debug!(target = %target, error = %e, "OpenTelemetry collector refused the connection test");
                false
            }
            Err(_) => {
                debug!(target = %target, "OpenTelemetry collector connection test timed out");
                false
            }
        };
    info!(target = %target, reached, "Tested OpenTelemetry collector connection");
    if !reached {
        tokio::time::sleep_until(deadline).await;
    }
    Ok(if reached {
        TestConnectionResponse {
            success: true,
            message: format!(
                "Reached the collector at {target}. This checks that it accepts connections, not that it speaks OTLP."
            ),
        }
    } else {
        TestConnectionResponse {
            success: false,
            message: format!("Could not reach the collector at {target}."),
        }
    })
}

fn refused_endpoint() -> AppError {
    AppError::BadRequest(
        "OpenTelemetry endpoint must resolve to a public collector address; private, loopback, link-local and cloud \
         metadata targets are refused"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::metrics_config::OtlpAuthConfig;

    const PUBLIC_COLLECTOR: &str = "https://93.184.216.34:4317";
    const OTHER_PUBLIC_COLLECTOR: &str = "https://93.184.216.35:4317";

    fn example_config() -> MetricsConfig {
        serde_json::from_str(include_str!("../../../config/examples/metrics.example.json")).unwrap()
    }

    fn exporting(
        endpoint: &str,
        secret_id: Option<&str>,
    ) -> MetricsConfig {
        let mut config = example_config();
        config.opentelemetry.enabled = true;
        config.opentelemetry.endpoint = endpoint.to_string();
        config.opentelemetry.auth = secret_id.map(|secret_id| OtlpAuthConfig {
            header_name: "Authorization".to_string(),
            secret_id: secret_id.to_string(),
            header_format: "Bearer {value}".to_string(),
        });
        config
    }

    fn secret_id(config: &MetricsConfig) -> &str {
        &config
            .opentelemetry
            .auth
            .as_ref()
            .unwrap()
            .secret_id
    }

    #[test]
    fn config_read_names_the_auth_header_but_not_its_secret() {
        let returned = without_secret_reference(exporting(PUBLIC_COLLECTOR, Some("otel-token")));

        let json = serde_json::to_value(&returned).unwrap();
        let auth = &json["opentelemetry"]["auth"];
        assert_eq!(auth["header_name"], "Authorization");
        assert_eq!(auth["header_format"], "Bearer {value}");
        assert!(
            auth.get("secret_id")
                .is_none(),
            "secret_id must not be returned: {auth}"
        );
        assert!(
            !json
                .to_string()
                .contains("otel-token")
        );
    }

    #[tokio::test]
    async fn save_without_a_secret_id_keeps_the_stored_secret() {
        let stored = exporting(PUBLIC_COLLECTOR, Some("otel-token"));
        let mut saved = exporting(PUBLIC_COLLECTOR, Some(""));

        prepare_save(&mut saved, Some(&stored), false, None)
            .await
            .unwrap();

        assert_eq!(secret_id(&saved), "otel-token");
    }

    #[tokio::test]
    async fn save_without_a_secret_id_and_no_stored_secret_is_refused() {
        let mut saved = exporting(PUBLIC_COLLECTOR, Some(""));

        let result = prepare_save(&mut saved, Some(&example_config()), true, None).await;

        assert!(matches!(result, Err(AppError::BadRequest(message)) if message.contains("Select the secret")));
    }

    #[tokio::test]
    async fn sending_the_stored_secret_to_another_collector_requires_secrets_view() {
        let stored = exporting(PUBLIC_COLLECTOR, Some("otel-token"));

        let mut refused = exporting(OTHER_PUBLIC_COLLECTOR, Some(""));
        let result = prepare_save(&mut refused, Some(&stored), false, None).await;
        assert!(matches!(result, Err(AppError::PermissionDenied(message)) if message.contains("secrets.view")));

        let mut allowed = exporting(OTHER_PUBLIC_COLLECTOR, Some(""));
        prepare_save(&mut allowed, Some(&stored), true, None)
            .await
            .unwrap();
        assert_eq!(secret_id(&allowed), "otel-token");
    }

    #[tokio::test]
    async fn choosing_another_secret_or_enabling_auth_requires_secrets_view() {
        let stored_with_auth = exporting(PUBLIC_COLLECTOR, Some("otel-token"));
        let mut other_secret = exporting(PUBLIC_COLLECTOR, Some("admin-api-key"));
        assert!(matches!(
            prepare_save(&mut other_secret, Some(&stored_with_auth), false, None).await,
            Err(AppError::PermissionDenied(_))
        ));

        let stored_without_auth = exporting(PUBLIC_COLLECTOR, None);
        let mut new_auth = exporting(PUBLIC_COLLECTOR, Some("admin-api-key"));
        assert!(matches!(
            prepare_save(&mut new_auth, Some(&stored_without_auth), false, None).await,
            Err(AppError::PermissionDenied(_))
        ));

        let mut disabled = stored_with_auth.clone();
        disabled.opentelemetry.enabled = false;
        let mut re_enabled = stored_with_auth.clone();
        assert!(matches!(
            prepare_save(&mut re_enabled, Some(&disabled), false, None).await,
            Err(AppError::PermissionDenied(_))
        ));
    }

    #[tokio::test]
    async fn an_unchanged_destination_or_removing_auth_needs_no_secrets_view() {
        let stored = exporting(PUBLIC_COLLECTOR, Some("otel-token"));

        let mut unchanged = exporting(PUBLIC_COLLECTOR, Some(""));
        unchanged
            .retention
            .local_logs_hours = 48;
        prepare_save(&mut unchanged, Some(&stored), false, None)
            .await
            .unwrap();

        let mut without_auth = exporting(OTHER_PUBLIC_COLLECTOR, None);
        prepare_save(&mut without_auth, Some(&stored), false, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_new_export_target_must_be_a_public_collector() {
        for endpoint in [
            "http://localhost:4317",
            "http://127.0.0.1:4317",
            "http://[::1]:4317",
            "http://0.0.0.0:4317",
            "http://10.0.0.5:4317",
            "http://172.16.0.9:4317",
            "http://192.168.1.10:4317",
            "http://169.254.10.1:4317",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal:4317",
            "http://[fd00::1]:4317",
            "http://[fe80::1]:4317",
            "http://[::ffff:10.0.0.5]:4317",
            "http://user:pass@93.184.216.34:4317",
        ] {
            let mut saved = exporting(endpoint, None);
            let result = prepare_save(&mut saved, None, true, None).await;
            assert!(
                matches!(&result, Err(AppError::BadRequest(message)) if message.contains("public collector")),
                "{endpoint} must be refused, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_public_collector_is_accepted() {
        let mut saved = exporting(PUBLIC_COLLECTOR, Some("otel-token"));

        prepare_save(&mut saved, None, true, None)
            .await
            .unwrap();

        assert_eq!(secret_id(&saved), "otel-token");
    }

    #[tokio::test]
    async fn an_unchanged_stored_target_is_not_rechecked() {
        let stored = exporting("http://localhost:4317", None);
        let mut saved = exporting("http://localhost:4317", None);
        saved.advanced.batch_size = 1024;

        prepare_save(&mut saved, Some(&stored), false, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn enabling_export_to_the_stored_disabled_endpoint_is_checked() {
        let stored = example_config();
        assert!(!stored.opentelemetry.enabled);
        let mut saved = exporting(&stored.opentelemetry.endpoint, None);

        let result = prepare_save(&mut saved, Some(&stored), true, None).await;

        assert!(matches!(result, Err(AppError::BadRequest(_))));
    }

    #[tokio::test]
    async fn a_disabled_exporter_keeps_any_endpoint() {
        let mut saved = example_config();
        saved.opentelemetry.endpoint = "http://10.0.0.5:4317".to_string();

        prepare_save(&mut saved, None, false, None)
            .await
            .unwrap();
    }

    async fn listening_collector() -> (tokio::net::TcpListener, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        (listener, endpoint)
    }

    const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    #[tokio::test]
    async fn the_stored_collector_can_be_tested_on_a_local_address() {
        let (_listener, endpoint) = listening_collector().await;

        let response = probe_collector(&endpoint, Some(&exporting(&endpoint, None)), TEST_TIMEOUT)
            .await
            .unwrap();

        assert!(response.success);
        let target = endpoint.trim_start_matches("http://");
        assert_eq!(
            response.message,
            format!(
                "Reached the collector at {target}. This checks that it accepts connections, not that it speaks OTLP."
            )
        );
    }

    #[tokio::test]
    async fn a_local_address_other_than_the_stored_collector_is_refused() {
        let (_listener, endpoint) = listening_collector().await;

        for stored in [None, Some(exporting("http://127.0.0.1:4317", None))] {
            let result = probe_collector(&endpoint, stored.as_ref(), TEST_TIMEOUT).await;
            assert!(
                matches!(&result, Err(AppError::BadRequest(message)) if message.contains("public collector")),
                "stored {stored:?}: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_collector_saved_with_export_disabled_is_not_exempt_from_the_address_check() {
        let mut saved = example_config();
        saved.opentelemetry.endpoint = "http://10.0.0.5:4317".to_string();
        prepare_save(&mut saved, None, false, None)
            .await
            .unwrap();

        let result = probe_collector("http://10.0.0.5:4317", Some(&saved), TEST_TIMEOUT).await;

        assert!(
            matches!(&result, Err(AppError::BadRequest(message)) if message.contains("public collector")),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn the_stored_local_collector_is_exempt_only_while_export_is_enabled() {
        let (_listener, endpoint) = listening_collector().await;
        let mut stored = exporting(&endpoint, None);
        stored.opentelemetry.enabled = false;

        let result = probe_collector(&endpoint, Some(&stored), TEST_TIMEOUT).await;

        assert!(matches!(result, Err(AppError::BadRequest(_))), "{result:?}");
    }

    #[tokio::test]
    async fn internal_test_targets_are_refused_before_connecting() {
        for endpoint in [
            "http://localhost:4317",
            "http://127.0.0.1:22",
            "http://[::1]:4317",
            "http://10.0.0.5:6379",
            "http://172.16.0.9:4317",
            "http://192.168.1.10:4317",
            "http://169.254.10.1:4317",
            "http://169.254.169.254/latest/meta-data",
            "http://metadata.google.internal:80",
            "http://[fd00::1]:4317",
            "http://[::ffff:10.0.0.5]:4317",
        ] {
            let result = probe_collector(endpoint, None, TEST_TIMEOUT).await;
            assert!(
                matches!(&result, Err(AppError::BadRequest(message)) if message.contains("public collector")),
                "{endpoint} must be refused, got {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn a_malformed_test_endpoint_is_refused() {
        for endpoint in ["", "collector:4317", "ftp://93.184.216.34", "http://"] {
            let result = probe_collector(endpoint, None, TEST_TIMEOUT).await;
            assert!(
                matches!(&result, Err(AppError::BadRequest(message)) if message.contains("http:// or https://")),
                "{endpoint:?}: {result:?}"
            );
        }
    }

    const SHORT_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(300);

    #[tokio::test]
    async fn a_refused_connection_answers_only_after_the_full_timeout() {
        let (listener, closed) = listening_collector().await;
        drop(listener);

        let started = std::time::Instant::now();
        let refused = probe_collector(&closed, Some(&exporting(&closed, None)), SHORT_TIMEOUT)
            .await
            .unwrap();

        assert!(!refused.success);
        assert!(started.elapsed() >= SHORT_TIMEOUT, "answered after {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn a_reached_collector_answers_without_waiting_for_the_timeout() {
        let (_listener, endpoint) = listening_collector().await;

        let started = std::time::Instant::now();
        let response = probe_collector(&endpoint, Some(&exporting(&endpoint, None)), TEST_TIMEOUT)
            .await
            .unwrap();

        assert!(response.success);
        assert!(started.elapsed() < TEST_TIMEOUT, "answered after {:?}", started.elapsed());
    }

    #[tokio::test]
    async fn refused_and_timed_out_connections_give_the_same_answer() {
        let (listener, closed) = listening_collector().await;
        drop(listener);
        let refused = probe_collector(&closed, Some(&exporting(&closed, None)), SHORT_TIMEOUT)
            .await
            .unwrap();

        // Nothing answers on this unrouted private address, so the connection
        // times out (or fails at once where no route exists).
        let silent = "http://10.255.255.1:4317";
        let timed_out = probe_collector(silent, Some(&exporting(silent, None)), SHORT_TIMEOUT)
            .await
            .unwrap();

        assert!(!refused.success);
        assert!(!timed_out.success);
        assert_eq!(
            refused
                .message
                .replace(closed.trim_start_matches("http://"), "<target>"),
            "Could not reach the collector at <target>."
        );
        assert_eq!(timed_out.message, "Could not reach the collector at 10.255.255.1:4317.");
        let json = serde_json::to_value(&refused).unwrap();
        let mut fields: Vec<&String> = json
            .as_object()
            .unwrap()
            .keys()
            .collect();
        fields.sort();
        assert_eq!(fields, ["message", "success"]);
    }

    #[tokio::test]
    async fn an_access_token_bound_to_a_tenant_cannot_change_the_metrics_configuration() {
        let stored = exporting(PUBLIC_COLLECTOR, Some("otel-token"));
        let tenant = crate::tenancy::PatTenantContext {
            token_id: "pat-1".to_string(),
            tenant_id: "tenant-a".to_string(),
        };
        let mut saved = exporting(OTHER_PUBLIC_COLLECTOR, Some("tenant-b-key"));

        let result = prepare_save(&mut saved, Some(&stored), true, Some(&tenant)).await;

        assert!(
            matches!(&result, Err(AppError::PermissionDenied(message)) if message.contains("appliance-wide")),
            "{result:?}"
        );
    }
}
