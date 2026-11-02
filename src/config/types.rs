//! Type definitions for configuration

use crate::config::EncryptionConfig;
use crate::config::metrics_config::{LogsConfig, TracesConfig};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Default Affinidi agent identity extension URI
pub const AFFINIDI_AGENT_IDENTITY_EXTENSION: &str = "https://fabric.affinidi.io/extensions/agent-identity/v1";
pub const AFFINIDI_AGENT_METADATA_EXTENSION: &str = "https://fabric.affinidi.io/extensions/custom-metadata/v1";
/// Agent identity credential extension - contains VP with VC signed by agent DID
pub const AFFINIDI_AGENT_IDENTITY_CREDENTIAL_EXTENSION: &str =
    "https://fabric.affinidi.io/extensions/agent-identity-credential/v1";
/// Trust Registry extension - contains trust registry verification parameters
pub const TRUST_REGISTRY_EXTENSION: &str = "https://fabric.affinidi.io/extensions/trust-registry";

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum TrustRegistryVerificationMode {
    /// Validate the source (sender) agent from message extensions
    #[default]
    Source,
    /// Validate the target (recipient) agent by fetching their agent card
    Target,
}

/// Trust Registry Verification Configuration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct TrustRegistryVerificationConfig {
    /// Whether trust registry verification is enabled
    #[serde(default)]
    pub enabled: bool,

    /// Mode of verification (source or target)
    #[serde(default)]
    pub mode: TrustRegistryVerificationMode,
}

/// OpenTelemetry observability configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct ObservabilityConfig {
    /// Whether OpenTelemetry is enabled
    #[serde(default)]
    pub enable_opentelemetry: bool,

    /// OTLP endpoint (gRPC)
    #[serde(default = "default_otlp_endpoint")]
    pub otlp_endpoint: String,

    /// Service name for distributed tracing
    #[serde(default = "default_service_name")]
    pub service_name: String,

    /// Deployment environment (production, staging, development, etc.)
    #[serde(default = "default_deployment_environment")]
    pub deployment_environment: String,

    /// Traces configuration
    #[serde(default)]
    pub traces: TracesConfig,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: OtelMetricsConfig,

    /// Logs configuration
    #[serde(default)]
    pub logs: LogsConfig,
}

impl Default for ObservabilityConfig {
    fn default() -> Self {
        Self {
            enable_opentelemetry: false,
            otlp_endpoint: default_otlp_endpoint(),
            service_name: default_service_name(),
            deployment_environment: default_deployment_environment(),
            traces: TracesConfig::default(),
            metrics: OtelMetricsConfig::default(),
            logs: LogsConfig::default(),
        }
    }
}

/// Metrics configuration for OpenTelemetry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct OtelMetricsConfig {
    /// Whether metrics export is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Export interval in seconds
    #[serde(default = "default_export_interval")]
    pub export_interval_seconds: u64,
}

impl Default for OtelMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            export_interval_seconds: default_export_interval(),
        }
    }
}

#[allow(dead_code)]
fn default_otlp_endpoint() -> String {
    "http://localhost:4317".to_string()
}

#[allow(dead_code)]
fn default_service_name() -> String {
    env!("CARGO_PKG_NAME").to_string()
}

#[allow(dead_code)]
fn default_deployment_environment() -> String {
    "development".to_string()
}

#[allow(dead_code)]
fn default_export_interval() -> u64 {
    60
}

fn default_true() -> bool {
    true
}

/// integration type definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationType {
    /// Unique identifier for this integration type (e.g., "email", "slack")
    pub enum_value: String,

    /// Human-readable name
    pub name: String,

    /// Description of this integration type
    pub description: String,

    /// Metadata specific to this integration type (field definitions, etc.)
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// integration category definition with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationCategory {
    /// Unique identifier for this category (e.g., "general", "connection_point")
    pub enum_value: String,

    /// Human-readable name
    pub name: String,

    /// Description of this category
    pub description: String,

    /// Metadata specific to this category
    #[serde(default)]
    pub metadata: serde_json::Value,
}

/// Event type definition for integrations
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventType {
    /// Event type identifier (e.g., "user.created", "user.login")
    pub event_type: String,

    /// Human-readable name
    pub name: String,

    /// Description of when this event is triggered
    pub description: String,
}

/// integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrationConfig {
    /// Regex pattern for matching template variables in ${VARIABLE} or ${VARIABLE:Label} format
    #[serde(default = "default_variable_pattern")]
    pub variable_pattern: String,

    /// Description of the variable pattern
    #[serde(default)]
    pub variable_pattern_description: Option<String>,

    /// Prefix for custom variables (default: "_")
    #[serde(default = "default_custom_variable_prefix")]
    pub custom_variable_prefix: String,

    /// Valid integration types with metadata
    pub types: Vec<IntegrationType>,

    /// Valid integration categories with metadata
    pub categories: Vec<IntegrationCategory>,
}

fn default_variable_pattern() -> String {
    r"\$\{([A-Za-z0-9_]+)(?::([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)".to_string()
}

fn default_custom_variable_prefix() -> String {
    "_".to_string()
}

impl IntegrationConfig {
    /// Create a default integration configuration with standard types and categories
    /// This is used as a fallback when constructing configs programmatically
    pub fn default_config() -> Self {
        Self {
            variable_pattern: default_variable_pattern(),
            variable_pattern_description: Some("Matches ${VARIABLE}, ${VARIABLE:Label}, or $VARIABLE format.".to_string()),
            custom_variable_prefix: default_custom_variable_prefix(),
            types: vec![
                IntegrationType {
                    enum_value: "email".to_string(),
                    name: "Email".to_string(),
                    description: "Send notifications via SMTP email".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "subject", "label": "Subject", "type": "string", "required": true},
                            {"name": "body", "label": "Body", "type": "text", "required": true},
                            {"name": "from_address", "label": "From Address", "type": "string", "required": true},
                            {"name": "to_addresses", "label": "To Addresses", "type": "string", "required": true},
                            {"name": "smtp_host", "label": "SMTP Host", "type": "string", "required": true},
                            {"name": "smtp_port", "label": "SMTP Port", "type": "number", "required": true},
                            {"name": "smtp_username", "label": "SMTP Username", "type": "string", "required": false},
                            {"name": "smtp_password", "label": "SMTP Password", "type": "password", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "slack".to_string(),
                    name: "Slack".to_string(),
                    description: "Send notifications to Slack channels via webhook".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "webhook_url", "label": "Webhook URL", "type": "string", "required": true},
                            {"name": "message", "label": "Message", "type": "text", "required": true},
                            {"name": "channel", "label": "Channel", "type": "string", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "webhook".to_string(),
                    name: "Webhook".to_string(),
                    description: "Send HTTP POST requests to custom endpoints".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "url", "label": "Webhook URL", "type": "string", "required": true},
                            {"name": "payload", "label": "Payload Template", "type": "text", "required": true},
                            {"name": "headers", "label": "Custom Headers (JSON)", "type": "text", "required": false}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "langfuse".to_string(),
                    name: "Langfuse".to_string(),
                    description: "Send LLM traces (with token usage, cost, and captured I/O) to a Langfuse project".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "host", "label": "Host", "type": "string", "required": false},
                            {"name": "public_key", "label": "Public Key", "type": "string", "required": true},
                            {"name": "secret_key", "label": "Secret Key", "type": "password", "required": true}
                        ]
                    }),
                },
                IntegrationType {
                    enum_value: "stream".to_string(),
                    name: "Stream".to_string(),
                    description: "Stream events to Kafka, Kinesis, Pulsar, or Redis Streams".to_string(),
                    metadata: serde_json::json!({
                        "fields": [
                            {"name": "phone_number", "label": "To Phone Number", "type": "string", "required": true},
                            {"name": "message", "label": "Message", "type": "text", "required": true},
                            {"name": "from_number", "label": "From Number", "type": "string", "required": true},
                            {"name": "provider_api_key", "label": "Provider API Key", "type": "password", "required": true}
                        ]
                    }),
                },
            ],
            categories: vec![
                IntegrationCategory {
                    enum_value: "general".to_string(),
                    name: "General".to_string(),
                    description: "General purpose notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "connection_point".to_string(),
                    name: "Connection Point".to_string(),
                    description: "Notifications related to connection point events".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "user".to_string(),
                    name: "User".to_string(),
                    description: "User-specific notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "gateway".to_string(),
                    name: "Gateway".to_string(),
                    description: "Gateway system notifications".to_string(),
                    metadata: serde_json::json!({}),
                },
                IntegrationCategory {
                    enum_value: "llm_governance".to_string(),
                    name: "LLM Governance".to_string(),
                    description: "Signed governance records exported from LLM surfaces (prompt, processing stages, completion, metrics) as tamper-evident W3C Verifiable Credentials".to_string(),
                    metadata: serde_json::json!({
                        "event_types": [
                            {"event": "governance.record", "description": "A signed governance record was produced for an interaction on an LLM surface"}
                        ]
                    }),
                },
                IntegrationCategory {
                    enum_value: "llm_drift".to_string(),
                    name: "LLM Drift".to_string(),
                    description: "Behavioural drift alerts for LLM surfaces (raised when a monitored surface's dimensions move past their pinned baseline)".to_string(),
                    metadata: serde_json::json!({
                        "event_types": [
                            {"event": "drift.detected", "description": "A surface's behaviour drifted past its baseline (raised once on the transition into drift); carries every evaluated dimension in new_state.dimensions"},
                            {"event": "drift.resolved", "description": "A surface left drift (its overall status is no longer drift); new_state carries the evaluation that cleared it"}
                        ]
                    }),
                },
                crate::integrations::audit_integration_triggers::audit_integration_category(),
            ],
        }
    }
}

/// OOB (Out-of-Band) connection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OobConnectionConfig {
    /// How long (in hours) a pending OOB connection request remains valid
    /// After this time, the temporary listener will be stopped and cleaned up
    #[serde(default = "default_pending_expiry_hours")]
    pub pending_expiry_hours: u64,
}

impl Default for OobConnectionConfig {
    fn default() -> Self {
        Self {
            pending_expiry_hours: default_pending_expiry_hours(),
        }
    }
}

fn default_pending_expiry_hours() -> u64 {
    1
}

/// TLS certificate configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
    /// Path to the TLS certificate file (PEM format)
    pub cert_path: PathBuf,

    /// Path to the TLS private key file (PEM format)
    pub key_path: PathBuf,

    /// Whether to verify upstream TLS certificates
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Inbound client authentication configuration (mTLS).
    ///
    /// Controls whether the gateway requests/requires client certificates
    /// during the TLS handshake and/or trusts forwarded client certs from
    /// upstream proxies. See [`ClientAuthConfig`].
    ///
    /// Default = disabled — no behavioural change for existing deployments.
    #[serde(default)]
    pub client_auth: ClientAuthConfig,
}

/// Inbound client-certificate authentication configuration.
///
/// Two independent capture paths:
///
/// 1. **Direct TLS termination** ([`Self::direct`]): the gateway itself asks
///    for a client certificate during the TLS handshake via rustls'
///    `WebPkiClientVerifier`.
/// 2. **Forwarded client cert** ([`Self::trusted_proxies`] + [`Self::forwarded_header`]):
///    an upstream L7 LB terminates TLS and forwards the client cert in a
///    header. Only honoured when the connecting peer IP matches a trusted
///    proxy CIDR.
///
/// Either or both may be enabled. Per-channel `MtlsAuthConfig` decides
/// whether forwarded certs are acceptable on that channel.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ClientAuthConfig {
    /// Direct-TLS client-cert handshake mode.
    #[serde(default)]
    pub direct: DirectClientAuthMode,

    /// Trusted proxy CIDRs allowed to provide forwarded client certs.
    /// Empty disables the forwarded path.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<ipnet::IpNet>,

    /// Forwarded-client-cert header configuration. Ignored when
    /// `trusted_proxies` is empty.
    #[serde(default)]
    pub forwarded_header: ForwardedHeaderConfig,
}

/// Whether the TLS handshake requests/requires client certificates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectClientAuthMode {
    /// Don't request a client cert during the TLS handshake. (Default.)
    #[default]
    Disabled,
    /// Request a client cert; accept connections with or without one.
    /// Channels with `Mtls` source auth still reject missing certs at the
    /// middleware layer.
    Optional,
    /// Require a client cert at handshake time. TLS handshake fails for
    /// connections that don't present one. Only safe on listeners where
    /// every channel uses mTLS.
    Required,
}

/// Format of the inbound forwarded-client-cert header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForwardedHeaderConfig {
    /// Header name to read.
    #[serde(default = "default_forwarded_header_name")]
    pub header_name: String,

    /// Header value format.
    #[serde(default)]
    pub format: ForwardedHeaderFormat,
}

impl Default for ForwardedHeaderConfig {
    fn default() -> Self {
        Self {
            header_name: default_forwarded_header_name(),
            format: ForwardedHeaderFormat::default(),
        }
    }
}

/// Wire format of the forwarded-client-cert header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForwardedHeaderFormat {
    /// Envoy XFCC grammar:
    /// `By=<spiffe>;Hash=<hex>;Cert="<url-enc-pem>";Chain="<url-enc-pem>";Subject="<rfc4514>";URI=<uri>;DNS=<dns>`
    #[default]
    EnvoyXfcc,
    /// nginx `ssl_client_escaped_cert`-style: URL-encoded PEM as the entire
    /// header value.
    UrlEncodedPem,
}

fn default_forwarded_header_name() -> String {
    "x-forwarded-client-cert".to_string()
}

/// A2A protocol specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aConfig {
    /// Default A2A protocol version to use
    #[serde(default = "default_a2a_version")]
    pub default_version: String,

    /// Whether to validate A2A protocol messages
    #[serde(default = "default_true")]
    pub validate_messages: bool,

    /// Maximum request body size in bytes
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Request timeout in seconds
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,

    /// Fabric gateway request timeout in milliseconds (for fabric:// flows)
    /// This is how long GW1 will wait for a response from GW2
    #[serde(default = "default_fabric_timeout_ms")]
    pub fabric_gateway_timeout_ms: u64,

    /// Message expiration time in seconds (TTL for DIDComm messages)
    /// Messages older than this will be dropped by the recipient.
    /// MUST be strictly greater (in ms) than `fabric_gateway_timeout_ms`,
    /// otherwise the mediator can silently drop a response while GW1 still
    /// waits for it. Enforced by [`A2aConfig::validate`].
    #[serde(default = "default_message_expires_seconds")]
    pub message_expires_seconds: u64,

    /// Maximum number of fabric request dispatches a single connection-point
    /// listener will process concurrently. Acts as a back-pressure bound when
    /// many ForwardRequests arrive at once.
    #[serde(default = "default_max_inflight_dispatches")]
    pub max_inflight_dispatches: usize,

    /// Maximum number of unprocessed messages the underlying DIDComm SDK
    /// inbound cache holds before it stops draining the websocket. The SDK
    /// default of 100 is too small under load; raising it prevents
    /// mediator-side back-pressure cascades.
    #[serde(default = "default_sdk_inbound_cache_count")]
    pub sdk_inbound_cache_count: u32,

    /// Maximum total bytes the SDK inbound cache holds before applying
    /// back-pressure on the websocket reader. Default 100 MiB.
    #[serde(default = "default_sdk_inbound_cache_bytes")]
    pub sdk_inbound_cache_bytes: u64,
}

impl Default for A2aConfig {
    fn default() -> Self {
        Self {
            default_version: default_a2a_version(),
            validate_messages: true,
            max_body_size: default_max_body_size(),
            timeout_seconds: default_timeout(),
            fabric_gateway_timeout_ms: default_fabric_timeout_ms(),
            message_expires_seconds: default_message_expires_seconds(),
            max_inflight_dispatches: default_max_inflight_dispatches(),
            sdk_inbound_cache_count: default_sdk_inbound_cache_count(),
            sdk_inbound_cache_bytes: default_sdk_inbound_cache_bytes(),
        }
    }
}

impl A2aConfig {
    /// Validate runtime invariants. Called by `GatewayConfig::from_file`.
    pub fn validate(&self) -> Result<(), String> {
        let expires_ms = (self.message_expires_seconds as u128).saturating_mul(1000);
        if expires_ms <= self.fabric_gateway_timeout_ms as u128 {
            return Err(format!(
                "a2a.message_expires_seconds ({}s = {}ms) must be strictly greater than \
                 a2a.fabric_gateway_timeout_ms ({}ms) — otherwise the mediator will silently \
                 drop responses while GW1 is still waiting.",
                self.message_expires_seconds, expires_ms, self.fabric_gateway_timeout_ms
            ));
        }
        if self.max_inflight_dispatches == 0 {
            return Err("a2a.max_inflight_dispatches must be > 0".to_string());
        }
        if self.sdk_inbound_cache_count == 0 {
            return Err("a2a.sdk_inbound_cache_count must be > 0".to_string());
        }
        if self.sdk_inbound_cache_bytes == 0 {
            return Err("a2a.sdk_inbound_cache_bytes must be > 0".to_string());
        }
        Ok(())
    }
}

/// MCP (Model Context Protocol) specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpConfig {
    /// Default MCP protocol version to use
    #[serde(default = "default_mcp_version")]
    pub default_version: String,

    /// Whether to validate MCP protocol messages
    #[serde(default = "default_true")]
    pub validate_messages: bool,

    /// Maximum tool execution timeout in seconds
    #[serde(default = "default_tool_timeout")]
    pub tool_timeout_seconds: u64,

    /// Resource cache TTL in seconds
    #[serde(default = "default_resource_cache_ttl")]
    pub resource_cache_ttl: u64,

    /// Enable SSE (Server-Sent Events) transport
    #[serde(default = "default_true")]
    pub enable_sse: bool,

    /// Enable stdio transport
    #[serde(default)]
    pub enable_stdio: bool,

    /// Fabric gateway request timeout in milliseconds (for mcp:// flows)
    #[serde(default = "default_fabric_timeout_ms")]
    pub fabric_gateway_timeout_ms: u64,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            default_version: default_mcp_version(),
            validate_messages: true,
            tool_timeout_seconds: default_tool_timeout(),
            resource_cache_ttl: default_resource_cache_ttl(),
            enable_sse: true,
            enable_stdio: false,
            fabric_gateway_timeout_ms: default_fabric_timeout_ms(),
        }
    }
}

/// A single log redaction rule: a regex pattern and its replacement string.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogRedactionRule {
    /// Human-readable label for this rule (e.g. "JWT tokens")
    #[serde(default)]
    pub name: String,

    /// Regex pattern to match (case-insensitive by default)
    pub pattern: String,

    /// Replacement string (may contain capture group references like $1)
    pub replacement: String,
}

/// Log redaction configuration — loaded from gateway.json `logging.redaction`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LogRedactionConfig {
    /// Master switch — when false, no redaction is performed
    #[serde(default)]
    pub enabled: bool,

    /// Ordered list of regex→replacement rules applied to every log line
    #[serde(default)]
    pub rules: Vec<LogRedactionRule>,
}

/// Logging configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Log level (trace, debug, info, warn, error)
    #[serde(default = "default_log_level")]
    pub level: String,

    /// Whether to output logs in JSON format
    #[serde(default)]
    pub json: bool,

    /// Directory to write log files (optional, logs to stdout if not set)
    pub log_directory: Option<String>,

    /// PII / secret redaction rules applied to all log output
    #[serde(default)]
    pub redaction: LogRedactionConfig,

    /// When true, every injection of the channel's AgentIdentityCredential
    /// (identity-binding VP) emits a `vp_injected` row into the credential
    /// audit log. Defaults to false because these events are not credential
    /// delegations and can be noisy. Credential-delegation events
    /// (TokenIssued, ConsentRequired, …) are always recorded regardless.
    #[serde(default)]
    pub audit_identity_binding_vp: bool,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            json: false,
            log_directory: None,
            redaction: LogRedactionConfig::default(),
            audit_identity_binding_vp: false,
        }
    }
}

/// Extension inspection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInspectionConfig {
    /// Whether extension inspection is enabled
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// List of extension URIs to watch for and display
    #[serde(default)]
    pub watch_extensions: Vec<String>,
}

impl Default for ExtensionInspectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            watch_extensions: vec![AFFINIDI_AGENT_IDENTITY_EXTENSION.to_string()],
        }
    }
}

/// Type of channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum SurfaceType {
    /// User-created channel
    #[default]
    User,
    /// Temporary onboarding channel
    Onboarding,
    /// System-managed channel
    System,
    /// A transit channel for inter-gateway comms
    Transit,
}

/// Protocol used by the channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/src/generated/", rename_all = "lowercase"))]
pub enum ChannelProtocol {
    /// Agent-to-Agent protocol
    #[default]
    A2a,
    /// Model Context Protocol
    Mcp,
    /// DIDComm for transit gateways
    DIDComm,
    /// Marketplace protocol — embedded model catalog and model purchase
    Marketplace,
}

impl std::fmt::Display for ChannelProtocol {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            ChannelProtocol::A2a => write!(f, "a2a"),
            ChannelProtocol::Mcp => write!(f, "mcp"),
            ChannelProtocol::DIDComm => write!(f, "didcomm"),
            ChannelProtocol::Marketplace => write!(f, "marketplace"),
        }
    }
}

/// Target authentication configuration for proxy injection
///
/// Configures how the gateway injects credentials into requests
/// to external target services/agents. This is used when the gateway
/// needs to authenticate WITH external endpoints on behalf of managed agents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TargetAuthConfig {
    /// Method for obtaining credentials
    pub method: TargetAuthMethod,

    /// UI hint for which auth preset was selected (bearer, basic, api_key, custom).
    /// Not used by the pipeline — purely for round-tripping through the UI without inference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_type: Option<String>,

    /// Target identifier for credential lookup (used with CredentialLookup method)
    /// For StaticSecret method, this field is optional/unused.
    #[serde(default)]
    pub target_identifier: Option<String>,

    /// Fallback behavior when credentials are not found
    #[serde(default)]
    pub fallback: TargetAuthFallback,
}

/// Method for obtaining target authentication credentials
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthMethod {
    /// Look up credentials by target_identifier (not yet implemented)
    CredentialLookup,
    /// Use a static secret from the secrets store
    StaticSecret {
        /// Secret ID (secret_id field, not UUID) containing the credential value
        secret_id: String,
        /// Header name to inject (e.g., "Authorization", "X-API-Key")
        header_name: String,
        /// Header value format (e.g., "Bearer {value}", "{value}")
        /// The placeholder {value} will be replaced with the secret value
        #[serde(default = "default_header_format")]
        header_format: String,
    },
}

fn default_header_format() -> String {
    "{value}".to_string()
}

/// Fallback behavior when target credentials are not found
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum TargetAuthFallback {
    /// Reject the request with 502 Bad Gateway
    #[default]
    Reject,
    /// Pass through the request without injecting credentials
    Passthrough,
}

// ── Outbound Credential Delegation types ─────────────────────────────────────

// ── Outbound Credential Binding types ────────────────────────────────────────

/// Binds a credential provider to a channel for outbound delegation.
/// When the gateway detects an outbound request needs credentials, it checks the
/// delegation vault and either injects a cached token or initiates consent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutboundCredentialBinding {
    /// FK to a configured CredentialProvider
    pub credential_provider_id: String,

    /// OAuth scopes to request (empty = use provider defaults)
    #[serde(default)]
    pub scopes: Vec<String>,

    /// When this credential is required
    #[serde(default)]
    pub required_for: CredentialRequirement,

    /// How to handle missing tokens
    #[serde(default)]
    pub consent_mode: ConsentMode,

    /// How to inject the token into outbound requests
    #[serde(default)]
    pub inject_as: CredentialInjection,

    /// Only used when `consent_mode = elicit`. How long the gateway waits for
    /// the user to respond to an MCP `elicitation/create` request (and/or for
    /// the OAuth callback to populate the vault) before failing the in-flight
    /// tool call. Default: 300s.
    #[serde(default = "default_elicit_timeout_secs")]
    pub elicit_timeout_secs: u64,

    /// Only used when `consent_mode = elicit`. What to do when the MCP client
    /// did not advertise the `elicitation` capability during `initialize`.
    #[serde(default)]
    pub elicit_fallback: ElicitFallback,
}

fn default_elicit_timeout_secs() -> u64 {
    300
}

/// When outbound credentials are required
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CredentialRequirement {
    /// Every outbound request on this channel
    #[default]
    All,
    /// Only for specific MCP tools
    Tools(Vec<String>),
}

/// How to handle missing delegation tokens
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConsentMode {
    /// Return a `consent_required` HTTP 401 + `application/problem+json` to
    /// the caller, including the authorization URL(s). This is the legacy
    /// behaviour and remains the default for backward compatibility. It is
    /// **not** the MCP elicitation spec — the caller is expected to interpret
    /// our custom payload out-of-band.
    #[default]
    OnDemand,
    /// Block channel access entirely until every binding's token already
    /// exists in the vault. Sessions that lack any required credential are
    /// refused at bind/initialize time with the authorization URL(s). Once
    /// granted, runtime traffic never sees a consent prompt.
    PreAuthorize,
    /// Spec-compliant MCP elicitation. When a tool call needs a credential
    /// that is missing, the gateway issues an `elicitation/create` request
    /// back to the MCP client over the open Streamable HTTP / SSE stream,
    /// referencing the authorization URL in the message, and waits for the
    /// user to either complete OAuth (vault populated via callback) or to
    /// `decline`/`cancel`. Requires the MCP client to have advertised the
    /// `elicitation` capability during `initialize`; see `elicit_fallback`.
    Elicit,
}

/// What to do when `consent_mode = elicit` but the MCP client did not declare
/// the `elicitation` capability during the `initialize` handshake.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ElicitFallback {
    /// Degrade to the legacy on-demand behaviour (HTTP 401 + consent_required).
    #[default]
    OnDemand,
    /// Fail the in-flight tool call with a JSON-RPC error.
    Fail,
}

/// How to inject delegated credentials into outbound requests
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CredentialInjection {
    /// Authorization: Bearer {token}
    #[default]
    BearerHeader,
    /// Custom header with format string: e.g. { "name": "X-GitHub-Token", "format": "token {value}" }
    CustomHeader { name: String, format: String },
    /// JSON-RPC _meta field injection
    Meta { field: String },
}

/// Rate limit configuration for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    /// Maximum number of requests
    pub requests: u32,

    /// Time window in seconds
    pub window_secs: u64,

    /// Optional burst size (defaults to requests if not specified)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub burst: Option<u32>,
}

/// Timeout configuration for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// Request timeout in seconds (overall request duration)
    #[serde(default = "default_request_timeout")]
    pub request_secs: u64,

    /// Connection timeout in seconds (time to establish connection)
    #[serde(default = "default_connect_timeout")]
    pub connect_secs: u64,

    /// Idle timeout in seconds (time between data frames)
    #[serde(default = "default_idle_timeout")]
    pub idle_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            request_secs: default_request_timeout(),
            connect_secs: default_connect_timeout(),
            idle_secs: default_idle_timeout(),
        }
    }
}

fn default_request_timeout() -> u64 {
    30
}

fn default_connect_timeout() -> u64 {
    10
}

fn default_idle_timeout() -> u64 {
    60
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    /// Maximum number of retry attempts
    #[serde(default = "default_max_retries")]
    pub max_attempts: u32,

    /// Initial backoff delay in milliseconds
    #[serde(default = "default_initial_backoff")]
    pub initial_backoff_ms: u64,

    /// Maximum backoff delay in milliseconds
    #[serde(default = "default_max_backoff")]
    pub max_backoff_ms: u64,

    /// Backoff multiplier (exponential backoff)
    #[serde(default = "default_backoff_multiplier")]
    pub backoff_multiplier: f64,

    /// HTTP status codes that should trigger a retry
    #[serde(default = "default_retryable_statuses")]
    pub retryable_status_codes: Vec<u16>,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_retries(),
            initial_backoff_ms: default_initial_backoff(),
            max_backoff_ms: default_max_backoff(),
            backoff_multiplier: default_backoff_multiplier(),
            retryable_status_codes: default_retryable_statuses(),
        }
    }
}

fn default_max_retries() -> u32 {
    3
}

fn default_initial_backoff() -> u64 {
    100
}

fn default_max_backoff() -> u64 {
    5000
}

fn default_backoff_multiplier() -> f64 {
    2.0
}

fn default_retryable_statuses() -> Vec<u16> {
    vec![408, 429, 500, 502, 503, 504]
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,

    /// Number of consecutive successes to close the circuit from half-open
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,

    /// Time in seconds to wait before attempting to close an open circuit (half-open state)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    /// Time window in seconds for counting failures
    #[serde(default = "default_window_secs")]
    pub window_secs: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_secs: default_timeout_secs(),
            window_secs: default_window_secs(),
        }
    }
}

fn default_failure_threshold() -> u32 {
    5
}

fn default_success_threshold() -> u32 {
    2
}

fn default_timeout_secs() -> u64 {
    60
}

fn default_window_secs() -> u64 {
    60
}

/// Traffic mirroring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirrorConfig {
    /// Mirror endpoint URL
    pub endpoint: String,

    /// Percentage of traffic to mirror (0-100)
    #[serde(default = "default_mirror_percentage")]
    pub percentage: u8,

    /// Whether to wait for mirror response (false = fire-and-forget)
    #[serde(default = "default_false")]
    pub wait_for_response: bool,

    /// Timeout for mirror requests in seconds
    #[serde(default = "default_mirror_timeout")]
    pub timeout_secs: u64,
}

fn default_mirror_percentage() -> u8 {
    100
}

fn default_mirror_timeout() -> u64 {
    5
}

/// Extension validation rules for a channel
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtensionRules {
    /// JSON Schema for structural validation and identity extraction
    /// - Validates the entire extension payload structure
    /// - Fields marked with "x-identity": true are used for computing identity hash
    #[serde(skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// Custom field matching rules
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<ValidationRule>,
}

/// Custom metadata injection target (for MCP protocol)
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum MetadataInjectionTarget {
    /// Inject into JSON-RPC _meta field (protocol-level, transport-agnostic)
    Meta,
    /// Inject as HTTP headers (transport-level, HTTP only)
    Headers,
    /// Inject into both _meta field and HTTP headers
    #[default]
    Both,
}

/// Custom metadata for a channel
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetadata {
    /// Whether extension metadata is enabled for this channel
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// JSON Schema for the metadata structure
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Where to inject metadata for MCP protocol (meta, headers, or both)
    /// Default: both (for maximum compatibility)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection_target: Option<MetadataInjectionTarget>,
}

/// Trust Registry extension injection configuration for a channel
/// When enabled, the gateway will inject trust registry extension in agent cards
/// and outbound A2A messages. The agent_did is automatically extracted from
/// the AFFINIDI_AGENT_IDENTITY_EXTENSION in the message/agent card.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrustRegistryInjection {
    /// Whether trust registry extension injection is enabled for this channel
    #[serde(default = "default_false")]
    pub enabled: bool,

    /// Trust Registry DID to include in the trust registry extension.
    /// Must reference a trust registry stored in the gateway's trust registry store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_registry_did: Option<String>,

    /// Provider DID to include in the trust registry extension
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_did: Option<String>,

    /// Authority DID — the authority that governs the department (provider)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authority_did: Option<String>,
}

/// A single validation rule
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ValidationRule {
    /// Check if a field equals a specific value
    Equals {
        /// JSON path to the field (e.g., "agentIdentity.provisioningInfo.cloudProvider")
        path: String,
        /// Expected value
        value: serde_json::Value,
    },
    /// Check if a field does not equal a specific value
    NotEquals {
        /// JSON path to the field
        path: String,
        /// Value that should not match
        value: serde_json::Value,
    },
    /// Check if a field matches a regex pattern
    Regex {
        /// JSON path to the field
        path: String,
        /// Regex pattern
        pattern: String,
    },
    /// Check if a field exists
    Exists {
        /// JSON path to the field
        path: String,
    },
    /// Check if a field is within a range (for numbers)
    Range {
        /// JSON path to the field
        path: String,
        /// Minimum value (inclusive, optional)
        min: Option<f64>,
        /// Maximum value (inclusive, optional)
        max: Option<f64>,
    },
    /// Check if a field is in a list of allowed values
    OneOf {
        /// JSON path to the field
        path: String,
        /// List of allowed values
        values: Vec<serde_json::Value>,
    },
    /// Check if all array elements match a specific type and optionally specific values
    ArrayAll {
        /// JSON path to the field
        path: String,
        /// Required type for all elements ("string", "number", "boolean")
        element_type: String,
        /// Optional: specific values that all elements must match
        values: Option<Vec<serde_json::Value>>,
    },
    /// Check if any array element matches a specific type and optionally specific values
    ArrayAny {
        /// JSON path to the field
        path: String,
        /// Required type for matching elements ("string", "number", "boolean")
        element_type: String,
        /// Optional: specific values that at least one element must match
        values: Option<Vec<serde_json::Value>>,
    },
    /// Check array length constraints
    ArrayLength {
        /// JSON path to the field
        path: String,
        /// Minimum array length (inclusive, optional)
        min: Option<usize>,
        /// Maximum array length (inclusive, optional)
        max: Option<usize>,
    },
}

/// Configuration for the Agent Stream server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    /// Active runtime agent surfaces, populated by the agent-surface store after
    /// gateway.json is parsed. Never serialised — surfaces live in their own
    /// per-surface store on disk.
    #[serde(default, skip)]
    pub surfaces: Vec<crate::config::agent_surface::AgentSurface>,

    /// TLS certificate configuration
    pub tls: TlsConfig,

    /// A2A protocol specific settings
    #[serde(default)]
    pub a2a: A2aConfig,

    /// MCP protocol specific settings
    #[serde(default)]
    pub mcp: McpConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Extension inspection configuration
    #[serde(default)]
    pub extension_inspection: ExtensionInspectionConfig,

    /// integration configuration
    pub integration: IntegrationConfig,
}

/// Configuration file paths (all JSON config files)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigFilePaths {
    /// Agent-stream gateway configuration file path - defines ports, bind addresses, and available routes
    #[serde(default = "default_agent_stream_config_path")]
    pub agent_stream: String,

    /// Metrics configuration file path - defines OpenTelemetry and CloudWatch settings
    #[serde(default = "default_metrics_config_path")]
    pub metrics: String,

    /// RBAC configuration file path - defines role-based permissions
    #[serde(default = "default_rbac_config_path")]
    pub rbac: String,

    /// Resource-limits configuration file path - defines per-dimension caps on
    /// how many entities the appliance will hold (secrets, surfaces, …).
    #[serde(default = "default_limits_config_path")]
    pub limits: String,

    /// LLM pipes configuration file path (LLM providers and MCP proxies)
    #[serde(default = "default_llm_config_path")]
    pub llm: String,

    /// SAML configuration file path (Azure AD or other SAML IdP configuration)
    #[serde(default = "crate::auth::auth_config::default_saml_config_path")]
    pub saml: String,

    /// Prompt guard configuration file path - defines built-in PII pattern definitions
    #[serde(default = "default_prompt_guard_config_path")]
    pub prompt_guard: String,

    /// Marketplace models catalog file path - defines available models for the embedded marketplace
    #[serde(default = "default_marketplace_models_config_path")]
    pub marketplace_models: String,

    /// Editable rejection-reason taxonomy JSON file mapping raw
    /// provider/judge/jury reason tokens onto canonical categories. Resolved
    /// relative to the bootstrap config dir; falls back to the compiled-in
    /// built-in taxonomy when absent or invalid.
    #[serde(default = "default_rejection_taxonomy_path")]
    pub rejection_taxonomy: String,

    /// Directory (relative to the config dir, or absolute) scanned at
    /// startup for `.json` LLM-surface (LLM pipe) starter templates.
    /// Files found here are seeded into the on-disk LLM-surface template
    /// store as builtins.
    #[serde(default = "default_surface_templates_dir")]
    pub surface_templates_dir: String,

    /// Audio-stream catalog file path — the catalog of pre-generated voice
    /// clips (id → text/label/duration) the realtime relay can stream to a
    /// caller while a reply is being vetted (Gated voice safety) instead of
    /// dead air. The clip bytes live under `storage_paths.audio_streams`.
    /// Resolved relative to the bootstrap config dir when not absolute.
    #[serde(default = "default_audio_streams_config_path")]
    pub audio_streams: String,
}

impl Default for ConfigFilePaths {
    fn default() -> Self {
        Self {
            agent_stream: default_agent_stream_config_path(),
            metrics: default_metrics_config_path(),
            rbac: default_rbac_config_path(),
            limits: default_limits_config_path(),
            llm: default_llm_config_path(),
            saml: crate::auth::auth_config::default_saml_config_path(),
            prompt_guard: default_prompt_guard_config_path(),
            marketplace_models: default_marketplace_models_config_path(),
            rejection_taxonomy: default_rejection_taxonomy_path(),
            surface_templates_dir: default_surface_templates_dir(),
            audio_streams: default_audio_streams_config_path(),
        }
    }
}

/// Storage paths (all directories where data is persisted)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoragePaths {
    /// Path to store last-known good configuration cache
    #[serde(default = "default_config_cache_path")]
    pub config_cache: String,

    /// Identity records storage path - stores DID identity information
    #[serde(default = "default_identity_storage_path")]
    pub identities: String,

    /// Path to store settings data (badge threshold, metrics retention, etc.)
    #[serde(default = "default_settings_storage_path")]
    pub settings: String,

    /// Path to store notifications
    #[serde(default = "default_notifications_storage_path")]
    pub notifications: String,

    /// Path to store notification templates (admin and user welcome messages)
    #[serde(default = "default_notification_templates_storage_path")]
    pub notification_templates: String,

    /// Storage path for connection points
    #[serde(default = "default_connection_points_storage_path")]
    pub connection_points: String,

    /// Secrets storage path (for filesystem backend)
    #[serde(default = "default_secrets_storage_path")]
    pub secrets: String,

    /// API keys storage path
    #[serde(default = "default_apikeys_storage_path")]
    pub apikeys: String,

    /// Certificates storage path
    #[serde(default = "default_certificates_storage_path")]
    pub certificates: String,

    /// Path to store LLM surface (LLM pipe) configurations
    #[serde(default = "default_surfaces_storage_path")]
    pub surfaces: String,

    /// Directory holding the editable LLM provider catalog (`llm.json`).
    /// Seeded at startup from the shipped catalog (`config_files.llm`) when absent.
    #[serde(default = "default_llm_configuration_storage_path")]
    pub llm_configuration: String,

    /// Path to store Integration definitions (notifiers)
    #[serde(default = "default_integrations_storage_path")]
    pub integrations: String,

    /// Path to store Integration triggers (user and gateway integrations)
    #[serde(default = "default_integration_triggers_storage_path")]
    pub integration_triggers: String,

    /// Path to store Webhook configurations
    #[serde(default = "default_webhooks_storage_path")]
    pub webhooks: String,

    /// Storage path for VC issuer keys and DID documents
    #[serde(default = "default_vc_keys_path")]
    pub vc_keys: String,

    /// Storage path for metrics data
    #[serde(default = "default_metrics_storage_path")]
    pub metrics: String,

    /// Path to store passkey credentials (used when auth_mode = passkey)
    #[serde(default = "crate::auth::auth_config::default_passkey_storage_path")]
    pub passkeys: String,

    /// Path to store Customer Terms definitions and acceptance records
    #[serde(default = "default_terms_storage_path")]
    pub terms: String,

    /// Path to store user avatars
    #[serde(default = "crate::auth::auth_config::default_avatars_storage_path")]
    pub avatars: String,

    /// Path to store generic uploaded dashboard assets (LLM provider logos, etc.)
    #[serde(default = "default_uploads_storage_path")]
    pub uploads: String,

    /// Path to store gateway configurations
    #[serde(default = "default_gateways_storage_path")]
    pub gateways: String,

    /// Path to store mediator configurations
    #[serde(default = "default_mediators_storage_path")]
    pub mediators: String,

    /// Path to store messages
    #[serde(default = "default_messages_storage_path")]
    pub messages: String,

    /// Path to store session data (persistent sessions across restarts)
    #[serde(default = "default_sessions_storage_path")]
    pub sessions: String,

    /// Path to store marketplace model configurations (purchased models)
    #[serde(default = "default_marketplace_models_storage_path")]
    pub marketplace_models: String,

    /// Path to persist system metrics (CPU/memory) history
    #[serde(default = "default_system_metrics_storage_path")]
    pub system_metrics: String,

    /// Path to store reusable OPA policy definitions
    #[serde(default = "default_policy_definitions_storage_path")]
    pub policy_definitions: String,

    /// Path to store the appliance-wide (global) policy assignments document
    /// — which reusable policies are enforced across every surface of a type.
    #[serde(default = "default_global_policies_storage_path")]
    pub global_policies: String,

    /// Path to store OAuth credential provider configurations
    #[serde(default = "default_credential_providers_storage_path")]
    pub credential_providers: String,

    /// Path to store delegation vault tokens (encrypted OAuth tokens per agent+user+provider)
    #[serde(default = "default_delegation_vault_storage_path")]
    pub delegation_vault: String,

    /// Path to store signed governance records (per-surface hash-chained,
    /// encrypted append-only logs of LLM-surface interactions).
    #[serde(default = "default_governance_storage_path")]
    pub governance: String,

    /// Directory of the content-addressed multimedia store: binary attachments
    /// (audio, documents, images) a caller sends are persisted here keyed by the
    /// SHA-256 of their bytes, so a governance record can carry only the hash and
    /// the bytes remain retrievable for later verification.
    #[serde(default = "default_multimedia_store_storage_path")]
    pub multimedia_store: String,

    /// Directory of the shared **audio-stream** clip store: short pre-generated
    /// WAV clips (PCM16 / 24 kHz / mono) the realtime relay streams to a caller
    /// while a reply is being vetted (Gated voice safety), instead of dead air.
    /// The clips are catalogued by id in the `audio_streams` config file.
    #[serde(default = "default_audio_streams_storage_path")]
    pub audio_streams: String,

    /// Path to store Agent Surface configurations
    #[serde(default = "default_agent_surfaces_storage_path")]
    pub agent_surfaces: String,

    /// Path to store LLM-surface (LLM pipe) templates. Builtins are
    /// seeded from `<config_dir>/surface_templates/*.json` at startup.
    #[serde(default = "default_surface_templates_storage_path")]
    pub surface_templates: String,

    /// Path for backup/restore working files (backup.asbak, local_backups/)
    #[serde(default = "default_backup_restore_storage_path")]
    pub backup_restore: String,

    /// Path to store team configurations (groups of members, by UUID)
    #[serde(default = "default_teams_storage_path")]
    pub teams: String,

    /// Path to store member configurations (appliance clients, the LLM consumers)
    #[serde(default = "default_members_storage_path")]
    pub members: String,

    /// Path to store versioned prompt templates (one `{id}.json` per prompt)
    #[serde(default = "default_prompts_storage_path")]
    pub prompts: String,

    /// Path to store monthly team/member usage snapshots
    #[serde(default = "default_team_usage_storage_path")]
    pub team_usage: String,

    /// Path to store the monthly Surface budget and usage-limit counters
    #[serde(default = "default_surface_usage_storage_path")]
    pub surface_usage: String,

    /// Directory holding the appliance-level member auto-provisioning config
    /// (`member_provisioning.json`). Governs on-the-fly member creation from
    /// verified caller identities. Absent ⇒ provisioning starts disabled.
    #[serde(default = "default_member_provisioning_storage_path")]
    pub member_provisioning: String,

    /// Directory of shipped default **member** records (one `*.json` per member,
    /// e.g. the built-in anonymous member). Copied into `members` at startup for
    /// any id not already present. Resolved relative to the bootstrap config dir
    /// when not absolute.
    #[serde(default = "default_default_members_path")]
    pub default_members: String,

    /// Directory of shipped default **team** records (one `*.json` per team, e.g.
    /// the built-in anonymous team). Copied into `teams` at startup for any id
    /// not already present. Resolved relative to the bootstrap config dir when
    /// not absolute.
    #[serde(default = "default_default_teams_path")]
    pub default_teams: String,

    /// Path to store multi-resolution usage telemetry snapshots (one JSON file
    /// per resolution tier) backing the dashboard usage-over-time graphs
    #[serde(default = "default_telemetry_storage_path")]
    pub telemetry: String,

    /// Path to store multi-resolution operational metrics snapshots (one JSON
    /// file per resolution tier) backing the dashboard operational graphs
    /// (connections, throughput, tokens, latency) under a shared drag rail
    #[serde(default = "default_ops_telemetry_storage_path")]
    pub ops_telemetry: String,

    /// Path to store multi-resolution LLM-drift dimension snapshots (one JSON
    /// file per resolution tier) backing the LLM Drift page's drift-over-time
    /// graphs. Kept in its own store so drift series never surface on the main
    /// dashboard.
    #[serde(default = "default_drift_storage_path")]
    pub drift: String,

    /// Path to store per-surface drift baselines (the captured "normal"
    /// dimension means a drift verdict is measured against).
    #[serde(default = "default_drift_baselines_storage_path")]
    pub drift_baselines: String,

    /// Path to store persisted evaluation-suite run records (per-run pass rate +
    /// per-sample outcomes), so an operator can review run history over time.
    #[serde(default = "default_drift_runs_storage_path")]
    pub drift_runs: String,

    /// Path to store captured surface sessions ("indicative surface data" — the
    /// prompt/response pairs a drift replay evaluation re-runs).
    #[serde(default = "default_drift_sessions_storage_path")]
    pub drift_sessions: String,

    /// Path to store per-surface drift-eval health (consecutive-failure counter
    /// + auto-suspend flag), so a suspension survives a restart.
    #[serde(default = "default_drift_eval_state_storage_path")]
    pub drift_eval_state: String,
}

impl Default for StoragePaths {
    fn default() -> Self {
        Self {
            config_cache: default_config_cache_path(),
            identities: default_identity_storage_path(),
            settings: default_settings_storage_path(),
            notifications: default_notifications_storage_path(),
            notification_templates: default_notification_templates_storage_path(),
            connection_points: default_connection_points_storage_path(),
            secrets: default_secrets_storage_path(),
            apikeys: default_apikeys_storage_path(),
            certificates: default_certificates_storage_path(),
            surfaces: default_surfaces_storage_path(),
            llm_configuration: default_llm_configuration_storage_path(),
            integrations: default_integrations_storage_path(),
            integration_triggers: default_integration_triggers_storage_path(),
            webhooks: default_webhooks_storage_path(),
            vc_keys: default_vc_keys_path(),
            metrics: default_metrics_storage_path(),
            passkeys: crate::auth::auth_config::default_passkey_storage_path(),
            terms: default_terms_storage_path(),
            avatars: crate::auth::auth_config::default_avatars_storage_path(),
            uploads: default_uploads_storage_path(),
            gateways: default_gateways_storage_path(),
            mediators: default_mediators_storage_path(),
            messages: default_messages_storage_path(),
            sessions: default_sessions_storage_path(),
            marketplace_models: default_marketplace_models_storage_path(),
            system_metrics: default_system_metrics_storage_path(),
            policy_definitions: default_policy_definitions_storage_path(),
            global_policies: default_global_policies_storage_path(),
            credential_providers: default_credential_providers_storage_path(),
            delegation_vault: default_delegation_vault_storage_path(),
            governance: default_governance_storage_path(),
            multimedia_store: default_multimedia_store_storage_path(),
            audio_streams: default_audio_streams_storage_path(),
            agent_surfaces: default_agent_surfaces_storage_path(),
            surface_templates: default_surface_templates_storage_path(),
            backup_restore: default_backup_restore_storage_path(),
            teams: default_teams_storage_path(),
            members: default_members_storage_path(),
            prompts: default_prompts_storage_path(),
            team_usage: default_team_usage_storage_path(),
            surface_usage: default_surface_usage_storage_path(),
            member_provisioning: default_member_provisioning_storage_path(),
            default_members: default_default_members_path(),
            default_teams: default_default_teams_path(),
            telemetry: default_telemetry_storage_path(),
            ops_telemetry: default_ops_telemetry_storage_path(),
            drift: default_drift_storage_path(),
            drift_baselines: default_drift_baselines_storage_path(),
            drift_runs: default_drift_runs_storage_path(),
            drift_sessions: default_drift_sessions_storage_path(),
            drift_eval_state: default_drift_eval_state_storage_path(),
        }
    }
}

impl StoragePaths {
    /// Every storage path, for passes that must treat all of them alike (for
    /// example resolving them against the config directory). The destructuring
    /// is exhaustive, so a new field does not compile until it is listed here.
    pub fn paths_mut(&mut self) -> Vec<&mut String> {
        let Self {
            config_cache,
            identities,
            settings,
            notifications,
            notification_templates,
            connection_points,
            secrets,
            apikeys,
            certificates,
            surfaces,
            llm_configuration,
            integrations,
            integration_triggers,
            webhooks,
            vc_keys,
            metrics,
            passkeys,
            terms,
            avatars,
            uploads,
            gateways,
            mediators,
            messages,
            sessions,
            marketplace_models,
            system_metrics,
            policy_definitions,
            global_policies,
            credential_providers,
            delegation_vault,
            governance,
            multimedia_store,
            audio_streams,
            agent_surfaces,
            surface_templates,
            backup_restore,
            teams,
            members,
            prompts,
            team_usage,
            surface_usage,
            member_provisioning,
            default_members,
            default_teams,
            telemetry,
            ops_telemetry,
            drift,
            drift_baselines,
            drift_runs,
            drift_sessions,
            drift_eval_state,
        } = self;
        vec![
            config_cache,
            identities,
            settings,
            notifications,
            notification_templates,
            connection_points,
            secrets,
            apikeys,
            certificates,
            surfaces,
            llm_configuration,
            integrations,
            integration_triggers,
            webhooks,
            vc_keys,
            metrics,
            passkeys,
            terms,
            avatars,
            uploads,
            gateways,
            mediators,
            messages,
            sessions,
            marketplace_models,
            system_metrics,
            policy_definitions,
            global_policies,
            credential_providers,
            delegation_vault,
            governance,
            multimedia_store,
            audio_streams,
            agent_surfaces,
            surface_templates,
            backup_restore,
            teams,
            members,
            prompts,
            team_usage,
            surface_usage,
            member_provisioning,
            default_members,
            default_teams,
            telemetry,
            ops_telemetry,
            drift,
            drift_baselines,
            drift_runs,
            drift_sessions,
            drift_eval_state,
        ]
    }
}

/// Reconnect policy for connection-point DIDComm links.
///
/// A failed connection is retried with exponential backoff up to
/// `max_backoff_seconds`, after which it retries at that fixed interval
/// (e.g. 30s → 60s → … → 1800s, then every 1800s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconnectPolicyConfig {
    /// Initial backoff after the first failed attempt.
    #[serde(default = "default_reconnect_initial_backoff_seconds")]
    pub initial_backoff_seconds: u64,

    /// Cap on the backoff; also the fixed cadence once the cap is reached.
    #[serde(default = "default_reconnect_max_backoff_seconds")]
    pub max_backoff_seconds: u64,

    /// Multiplier applied to the backoff after each failure. `<= 1.0` disables
    /// growth (constant `initial_backoff_seconds`).
    #[serde(default = "default_reconnect_backoff_multiplier")]
    pub backoff_multiplier: f64,
}

impl Default for ReconnectPolicyConfig {
    fn default() -> Self {
        Self {
            initial_backoff_seconds: default_reconnect_initial_backoff_seconds(),
            max_backoff_seconds: default_reconnect_max_backoff_seconds(),
            backoff_multiplier: default_reconnect_backoff_multiplier(),
        }
    }
}

impl ReconnectPolicyConfig {
    /// Convert to the runtime [`crate::comm::connection_health::ReconnectPolicy`].
    pub fn to_policy(&self) -> crate::comm::connection_health::ReconnectPolicy {
        crate::comm::connection_health::ReconnectPolicy {
            initial_backoff_seconds: self.initial_backoff_seconds,
            max_backoff_seconds: self.max_backoff_seconds,
            backoff_multiplier: self.backoff_multiplier,
        }
    }

    /// Validate the policy: backoff bounds must be non-zero and the cap must be
    /// at least the initial backoff.
    pub fn validate(&self) -> Result<(), String> {
        if self.initial_backoff_seconds == 0 {
            return Err("reconnect_policy.initial_backoff_seconds must be > 0".to_string());
        }
        if self.max_backoff_seconds < self.initial_backoff_seconds {
            return Err("reconnect_policy.max_backoff_seconds must be >= initial_backoff_seconds".to_string());
        }
        Ok(())
    }
}

fn default_reconnect_initial_backoff_seconds() -> u64 {
    30
}

fn default_reconnect_max_backoff_seconds() -> u64 {
    1800
}

fn default_reconnect_backoff_multiplier() -> f64 {
    2.0
}

/// LLM drift alert-cadence defaults (gateway config `[drift]`). A per-surface
/// Drift Harness (`DriftConfig.alert_cadence`) can override these; absent, the
/// drift evaluator falls back here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBootstrapConfig {
    /// Minutes between re-alerts while a surface stays drifting.
    #[serde(default = "default_drift_re_alert_interval_mins")]
    pub re_alert_interval_mins: u64,
    /// Max drift alerts fired per surface per baseline (`0` = unlimited).
    #[serde(default = "default_drift_max_alerts")]
    pub max_alerts: u32,
}

impl Default for DriftBootstrapConfig {
    fn default() -> Self {
        Self {
            re_alert_interval_mins: default_drift_re_alert_interval_mins(),
            max_alerts: default_drift_max_alerts(),
        }
    }
}

fn default_drift_re_alert_interval_mins() -> u64 {
    60
}

fn default_drift_max_alerts() -> u32 {
    5
}

/// Bootstrap configuration - loaded from file to determine how to load full config
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapConfig {
    /// Configuration source type: "dynamodb" or "file"
    #[serde(default = "default_channel_config_source")]
    pub channel_config_source: String,

    /// DynamoDB table name (required if channel_config_source is "dynamodb")
    pub dynamodb_table: Option<String>,

    /// AWS region (optional, uses default credential chain region if not specified)
    pub aws_region: Option<String>,

    /// AWS profile name (optional, uses default profile if not specified)
    /// This corresponds to the profile name in ~/.aws/credentials and ~/.aws/config
    pub aws_profile: Option<String>,

    /// TLS configuration (required)
    pub tls: TlsConfig,

    /// Encryption at rest configuration
    #[serde(default)]
    pub encryption: EncryptionConfig,

    /// A2A protocol specific settings
    #[serde(default)]
    pub a2a: A2aConfig,

    /// MCP protocol specific settings
    #[serde(default)]
    pub mcp: McpConfig,

    /// OOB connection configuration
    #[serde(default)]
    pub oob_connection: OobConnectionConfig,

    /// Reconnect policy for connection-point DIDComm links
    #[serde(default)]
    pub reconnect_policy: ReconnectPolicyConfig,

    /// Logging configuration
    #[serde(default)]
    pub logging: LoggingConfig,

    /// Extension inspection configuration
    #[serde(default)]
    pub extension_inspection: ExtensionInspectionConfig,

    /// RBAC (Role-Based Access Control) configuration
    #[serde(default)]
    pub rbac: crate::rbac::RbacConfig,

    /// DID document cache configuration for resilient gateway communication
    #[serde(default)]
    pub did_cache: DIDCacheBootstrapConfig,

    /// Configuration file paths (all JSON config files)
    #[serde(default)]
    pub config_files: ConfigFilePaths,

    /// Storage paths (all directories where data is persisted)
    #[serde(default)]
    pub storage_paths: StoragePaths,

    /// Secrets backend type; only `filesystem` is supported
    #[serde(default = "default_secrets_backend")]
    pub secrets_backend: String,

    /// Cache TTL for metrics aggregations in seconds (default: 1)
    #[serde(default = "default_metrics_cache_ttl")]
    pub metrics_cache_ttl_seconds: u64,

    /// Require authentication for WebSocket connections (default: true)
    #[serde(default = "default_true")]
    pub websocket_require_auth: bool,

    /// Session timeout in minutes (applies to both passkey and SAML)
    #[serde(default = "default_session_timeout_minutes")]
    pub session_timeout_minutes: u64,

    /// WebSocket broadcast channel buffer size (default: 500)
    #[serde(default = "default_websocket_broadcast_buffer")]
    pub websocket_broadcast_buffer: usize,

    /// How long to keep metrics in minutes (default: 360 = 6 hours)
    #[serde(default = "default_metrics_retention_minutes")]
    pub metrics_retention_minutes: u64,

    /// Cache TTL for metrics aggregations in seconds (default: 1)
    #[serde(default = "default_metrics_cache_ttl")]
    pub metrics_cache_ttl_seconds_legacy: u64,

    /// Authentication mode (passkey or saml)
    #[serde(default)]
    pub auth_mode: crate::auth::auth_config::AuthMode,

    /// Marketplace catalog cache TTL in seconds (default: 300 = 5 minutes)
    /// Controls how long marketplace model data is cached before re-querying connected gateways
    #[serde(default = "default_marketplace_cache_ttl")]
    pub marketplace_cache_ttl: u64,

    /// Required for backup and encrypted restore (64 hex chars = 32-byte AES-256 key).
    #[serde(default)]
    pub backup_encryption_key: Option<String>,

    /// Optional source resolving to up to four ordered, comma-separated previous backup keys.
    #[serde(default)]
    pub legacy_backup_encryption_keys: Option<String>,

    /// LLM drift alert-cadence defaults (per-surface Drift Harness can override).
    #[serde(default)]
    pub drift: DriftBootstrapConfig,

    /// Appliance-wide defaults applied to every LLM surface: governance
    /// recording on for surfaces without their own setting, and default
    /// governance export and `pipe` event integrations merged with each
    /// surface's own.
    #[serde(default)]
    pub surface_defaults: crate::pipes::surface_defaults::SurfaceDefaultsConfig,

    /// Tenant-header provenance for broad management PAT selectors.
    #[serde(default)]
    pub tenancy: crate::tenancy::TenancyConfig,

    /// Directory the bootstrap config.toml was loaded from. Populated
    /// by `BootstrapConfig::from_file` and used by services that need
    /// to resolve sibling resource folders (e.g. the LLM surface
    /// template seeder scanning `<config_dir>/surface_templates`).
    #[serde(skip)]
    pub config_dir: Option<PathBuf>,

    /// Initial server mode. SIGUSR1 promotes to Active and SIGUSR2 steps down to Standby.
    #[serde(default)]
    pub server_mode: crate::server::mode::ServerMode,

    /// Interval in seconds for cached filesystem stores to reconcile with shared storage.
    /// Zero disables periodic reconciliation.
    #[serde(default)]
    pub cache_refresh_interval_secs: u64,

    /// Warnings found while loading `config.toml` (for example settings that are
    /// no longer read). Logged once logging is initialised.
    #[serde(skip)]
    pub load_warnings: Vec<String>,
}

/// DID document cache configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDCacheBootstrapConfig {
    /// Time-to-live for DID cache entries in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_did_cache_ttl_seconds")]
    pub ttl_seconds: i64,

    /// Maximum number of entries in the DID cache (default: 1000)
    #[serde(default = "default_did_cache_max_entries")]
    pub max_entries: usize,

    /// Percentage of TTL after which entries are considered stale (default: 80%)
    #[serde(default = "default_did_cache_stale_threshold_percent")]
    pub stale_threshold_percent: u8,

    /// Path to store cached DID documents (default: _storage/cache/did)
    #[serde(default = "default_did_cache_storage_path")]
    pub storage_path: String,

    /// Let did:web and did:webvh resolution contact hosts that are, or resolve
    /// to, loopback, private-network or link-local addresses, cloud metadata
    /// included, plus the local names each method refuses (default: false,
    /// public hosts only). Startup-only; meant for local stacks.
    #[serde(default)]
    pub allow_private_hosts: bool,
}

impl Default for DIDCacheBootstrapConfig {
    fn default() -> Self {
        Self {
            ttl_seconds: default_did_cache_ttl_seconds(),
            max_entries: default_did_cache_max_entries(),
            stale_threshold_percent: default_did_cache_stale_threshold_percent(),
            storage_path: default_did_cache_storage_path(),
            allow_private_hosts: false,
        }
    }
}

#[cfg(test)]
mod did_cache_bootstrap_config_tests {
    use super::DIDCacheBootstrapConfig;

    #[test]
    fn allow_private_hosts_defaults_to_false() {
        let config: DIDCacheBootstrapConfig = toml::from_str("ttl_seconds = 60").unwrap();
        assert!(!config.allow_private_hosts);
        assert!(!DIDCacheBootstrapConfig::default().allow_private_hosts);
    }

    #[test]
    fn allow_private_hosts_parses_true() {
        let config: DIDCacheBootstrapConfig = toml::from_str("allow_private_hosts = true").unwrap();
        assert!(config.allow_private_hosts);
        assert_eq!(config.ttl_seconds, 86400);
    }
}

// Default value functions
fn default_channel_config_source() -> String {
    "local".to_string()
}

pub fn default_false() -> bool {
    false
}

fn default_a2a_version() -> String {
    "0.3".to_string()
}

fn default_mcp_version() -> String {
    "2024-11-05".to_string()
}

fn default_max_body_size() -> usize {
    10 * 1024 * 1024 // 10MB
}

fn default_timeout() -> u64 {
    30
}

fn default_tool_timeout() -> u64 {
    30 // 30 seconds
}

fn default_resource_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_fabric_timeout_ms() -> u64 {
    60000 // 60 seconds for fabric gateway requests (allows for slow LLM responses)
}

fn default_message_expires_seconds() -> u64 {
    // Must be strictly greater than default_fabric_timeout_ms (60s) so the
    // mediator does not drop a response while GW1 is still waiting.
    90
}

fn default_max_inflight_dispatches() -> usize {
    256
}

fn default_sdk_inbound_cache_count() -> u32 {
    1024
}

fn default_sdk_inbound_cache_bytes() -> u64 {
    100 * 1024 * 1024 // 100 MiB
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_identity_storage_path() -> String {
    "../_storage/identities".to_string()
}

fn default_vc_keys_path() -> String {
    "../_storage/vc_keys".to_string()
}

fn default_metrics_storage_path() -> String {
    "../_storage/metrics".to_string()
}

fn default_system_metrics_storage_path() -> String {
    "../_storage/system_metrics".to_string()
}

fn default_config_cache_path() -> String {
    "../_storage/cache".to_string()
}

fn default_settings_storage_path() -> String {
    "../_storage/settings".to_string()
}

fn default_terms_storage_path() -> String {
    "../_storage/terms".to_string()
}

fn default_notifications_storage_path() -> String {
    "../_storage/notifications".to_string()
}

fn default_notification_templates_storage_path() -> String {
    "../_storage/notifications/templates".to_string()
}

fn default_connection_points_storage_path() -> String {
    "../_storage/connection_points".to_string()
}

#[allow(dead_code)]
fn default_channel_config_file() -> Option<String> {
    None // Deprecated, no longer used by default
}

#[allow(dead_code)]
fn default_passkey_storage_path() -> String {
    "../_storage/passkeys".to_string()
}

#[allow(dead_code)]
fn default_avatars_storage_path() -> String {
    "../_storage/avatars".to_string()
}

fn default_uploads_storage_path() -> String {
    "../_storage/uploads".to_string()
}

fn default_agent_stream_config_path() -> String {
    "agent-stream.json".to_string()
}

fn default_llm_config_path() -> String {
    "llm.json".to_string()
}

#[allow(dead_code)]
fn default_session_timeout_minutes() -> u64 {
    20 // 20 minutes
}

fn default_websocket_broadcast_buffer() -> usize {
    500
}

fn default_metrics_retention_minutes() -> u64 {
    360 // 6 hours
}

pub(crate) const SUPPORTED_SECRETS_BACKEND: &str = "filesystem";

fn default_secrets_backend() -> String {
    SUPPORTED_SECRETS_BACKEND.to_string()
}

fn default_credential_providers_storage_path() -> String {
    "../_storage/credential_providers".to_string()
}

fn default_delegation_vault_storage_path() -> String {
    "../_storage/delegation_vault".to_string()
}

fn default_governance_storage_path() -> String {
    "../_storage/governance".to_string()
}

fn default_multimedia_store_storage_path() -> String {
    "../_storage/multimedia_store".to_string()
}

fn default_audio_streams_storage_path() -> String {
    "../_storage/audio_streams".to_string()
}

fn default_audio_streams_config_path() -> String {
    "audio_streams.json".to_string()
}

fn default_agent_surfaces_storage_path() -> String {
    "../_storage/agent_surfaces".to_string()
}

fn default_surface_templates_storage_path() -> String {
    "../_storage/surface_templates".to_string()
}

fn default_secrets_storage_path() -> String {
    "../_storage/secrets".to_string()
}

fn default_apikeys_storage_path() -> String {
    "../_storage/apikeys".to_string()
}

fn default_certificates_storage_path() -> String {
    "../_storage/certificates".to_string()
}

fn default_integrations_storage_path() -> String {
    "../_storage/integrations/definitions".to_string()
}

fn default_integration_triggers_storage_path() -> String {
    "../_storage/integrations/triggers".to_string()
}

fn default_webhooks_storage_path() -> String {
    "../_storage/webhooks".to_string()
}

fn default_surfaces_storage_path() -> String {
    "../_storage/surfaces".to_string()
}

fn default_teams_storage_path() -> String {
    "../_storage/teams".to_string()
}

fn default_members_storage_path() -> String {
    "../_storage/members".to_string()
}

fn default_prompts_storage_path() -> String {
    "../_storage/prompts".to_string()
}

fn default_team_usage_storage_path() -> String {
    "../_storage/team_usage".to_string()
}

fn default_surface_usage_storage_path() -> String {
    "../_storage/surface_usage".to_string()
}

fn default_member_provisioning_storage_path() -> String {
    "../_storage/enrolment".to_string()
}

fn default_default_members_path() -> String {
    "defaults/default_members".to_string()
}

fn default_default_teams_path() -> String {
    "defaults/default_teams".to_string()
}

fn default_telemetry_storage_path() -> String {
    "../_storage/telemetry".to_string()
}

fn default_ops_telemetry_storage_path() -> String {
    "../_storage/ops_telemetry".to_string()
}

fn default_drift_storage_path() -> String {
    "../_storage/drift".to_string()
}

fn default_drift_baselines_storage_path() -> String {
    "../_storage/drift_baselines".to_string()
}

fn default_drift_runs_storage_path() -> String {
    "../_storage/drift_runs".to_string()
}

fn default_drift_sessions_storage_path() -> String {
    "../_storage/drift_sessions".to_string()
}

fn default_drift_eval_state_storage_path() -> String {
    "../_storage/drift_eval_state".to_string()
}

fn default_rejection_taxonomy_path() -> String {
    "rejection_categories.json".to_string()
}

fn default_llm_configuration_storage_path() -> String {
    "../_storage/llm_configuration".to_string()
}

fn default_gateways_storage_path() -> String {
    "../_storage/gateways".to_string()
}

fn default_mediators_storage_path() -> String {
    "../_storage/mediators".to_string()
}

fn default_messages_storage_path() -> String {
    "../_storage/messages".to_string()
}

fn default_sessions_storage_path() -> String {
    "../_storage/sessions".to_string()
}

fn default_marketplace_models_storage_path() -> String {
    "../_storage/marketplace_models".to_string()
}

fn default_policy_definitions_storage_path() -> String {
    "../_storage/policy_definitions".to_string()
}

fn default_global_policies_storage_path() -> String {
    "../_storage/global_policies".to_string()
}

fn default_backup_restore_storage_path() -> String {
    "../_backup_restore".to_string()
}

fn default_metrics_config_path() -> String {
    "metrics.json".to_string()
}

fn default_rbac_config_path() -> String {
    "rbac.json".to_string()
}

fn default_limits_config_path() -> String {
    "limits.json".to_string()
}

fn default_did_cache_ttl_seconds() -> i64 {
    86400 // 24 hours
}

fn default_did_cache_max_entries() -> usize {
    1000
}

fn default_metrics_cache_ttl() -> u64 {
    1
}

fn default_marketplace_cache_ttl() -> u64 {
    300 // 5 minutes
}

fn default_did_cache_stale_threshold_percent() -> u8 {
    80 // 80% of TTL
}

fn default_did_cache_storage_path() -> String {
    "../_storage/cache/did".to_string()
}

#[allow(dead_code)]
fn default_identity_api_cors_origins() -> Vec<String> {
    vec![]
}

fn default_prompt_guard_config_path() -> String {
    "prompt-guard.json".to_string()
}

fn default_marketplace_models_config_path() -> String {
    "marketplace-models.json".to_string()
}

fn default_surface_templates_dir() -> String {
    "surface_templates".to_string()
}

/// How to inject a DID identity into outgoing requests
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum DidInjectionMode {
    /// Inject DID in X-DID-Identity HTTP header
    #[default]
    Header,
    /// Inject signed DID document in X-DID-Signed-Identity header
    SignedHeader,
    /// Inject DID into protocol-native location (A2A extension, MCP _meta)
    ProtocolNative,
}

/// DID:webvh identity configuration for channels
#[cfg(feature = "didwebvh")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityConfig {
    /// UUID of the DID:webvh identity to use for this channel
    pub identity_id: uuid::Uuid,

    /// Whether to auto-create the identity if it doesn't exist
    #[serde(default)]
    pub auto_create: bool,

    /// Optional DID path override (by default uses identity manager's DID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_path: Option<String>,

    /// How to inject the DID identity into outgoing requests
    #[serde(default)]
    pub injection_mode: DidInjectionMode,
}

#[cfg(test)]
mod outbound_config_tests {
    use serde_json::json;

    // ── Listener backward-compat ─────────────────────────────────────────────

    #[test]
    fn listener_without_listener_type_defaults_to_inbound() {
        let v = json!({
            "id": "l1",
            "name": "Main",
            "bind_address": "0.0.0.0",
            "port": 8443,
            "protocol": "https",
            "external_urls": []
        });
        let listener: crate::config::network::Listener =
            serde_json::from_value(v).expect("must deserialize without listener_type");
        assert_eq!(listener.listener_type, "inbound");
    }

    #[test]
    fn listener_with_listener_type_outbound() {
        let v = json!({
            "id": "l2",
            "name": "Outbound",
            "bind_address": "127.0.0.1",
            "port": 9000,
            "protocol": "http",
            "external_urls": [],
            "listener_type": "outbound"
        });
        let listener: crate::config::network::Listener =
            serde_json::from_value(v).expect("must deserialize with listener_type=outbound");
        assert_eq!(listener.listener_type, "outbound");
    }
}

#[cfg(test)]
mod a2a_validate_tests {
    use super::*;

    fn cfg(
        timeout_ms: u64,
        expires_s: u64,
    ) -> A2aConfig {
        A2aConfig {
            fabric_gateway_timeout_ms: timeout_ms,
            message_expires_seconds: expires_s,
            ..A2aConfig::default()
        }
    }

    #[test]
    fn validate_ok_when_expires_strictly_greater_than_timeout() {
        let c = cfg(60_000, 90);
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_equal_values() {
        let c = cfg(60_000, 60);
        let err = c.validate().unwrap_err();
        assert!(err.contains("strictly greater"), "got: {err}");
    }

    #[test]
    fn validate_rejects_expires_less_than_timeout() {
        let c = cfg(60_000, 30);
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_zero_inflight() {
        let mut c = cfg(60_000, 90);
        c.max_inflight_dispatches = 0;
        let err = c.validate().unwrap_err();
        assert!(err.contains("max_inflight_dispatches"), "got: {err}");
    }

    #[test]
    fn validate_rejects_zero_sdk_cache_bytes_or_count() {
        let mut c = cfg(60_000, 90);
        c.sdk_inbound_cache_count = 0;
        assert!(c.validate().is_err());
        let mut c = cfg(60_000, 90);
        c.sdk_inbound_cache_bytes = 0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_handles_overflow_via_saturating_mul() {
        // huge expires must not panic
        let c = cfg(u64::MAX, u64::MAX);
        // With saturating arithmetic, expires_ms saturates to u128::MAX which
        // exceeds any u64 timeout, so this must succeed.
        assert!(c.validate().is_ok());
    }

    #[test]
    fn defaults_satisfy_validate() {
        assert!(
            A2aConfig::default()
                .validate()
                .is_ok()
        );
    }
}

#[cfg(test)]
mod example_config_tests {
    use super::{ConfigFilePaths, StoragePaths};
    use std::collections::BTreeMap;

    const EXAMPLE: &str = include_str!("../../config/examples/config.example.toml");

    fn example_section(name: &str) -> BTreeMap<String, String> {
        let example: toml::Value = toml::from_str(EXAMPLE).expect("config.example.toml must parse");
        example
            .get(name)
            .and_then(toml::Value::as_table)
            .unwrap_or_else(|| panic!("config.example.toml has no [{name}] section"))
            .iter()
            .map(|(key, value)| {
                (
                    key.clone(),
                    value
                        .as_str()
                        .unwrap_or_default()
                        .to_string(),
                )
            })
            .collect()
    }

    fn code_defaults<T: serde::Serialize>(defaults: T) -> BTreeMap<String, String> {
        serde_json::from_value(serde_json::to_value(defaults).unwrap()).unwrap()
    }

    #[test]
    fn example_storage_paths_match_the_defaults() {
        assert_eq!(example_section("storage_paths"), code_defaults(StoragePaths::default()));
    }

    #[test]
    fn paths_mut_lists_every_storage_path() {
        let mut paths = StoragePaths::default();

        assert_eq!(paths.paths_mut().len(), code_defaults(StoragePaths::default()).len());
    }

    #[test]
    fn example_config_files_match_the_defaults() {
        assert_eq!(example_section("config_files"), code_defaults(ConfigFilePaths::default()));
    }
}
