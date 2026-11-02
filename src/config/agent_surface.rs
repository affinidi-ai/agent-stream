//! Agent Surface configuration types.
//!
//! An Agent Surface is the configuration and runtime entity for a managed agent
//! reached over the fabric. It represents a single logical agent — one that Agent
//! Stream manages, secures, and
//! mediates on behalf of — and fully describes that agent's inbound surface, outbound
//! targets, identity, and policies.

use serde::{Deserialize, Serialize};
use tracing::warn;

use super::types::{
    CircuitBreakerConfig, CustomMetadata, ExtensionRules, MirrorConfig, OutboundCredentialBinding, RateLimitConfig,
    RetryConfig, TargetAuthConfig, TimeoutConfig, TrustRegistryInjection, TrustRegistryVerificationConfig,
};
use crate::source_auth::SourceAuthConfig;
use crate::storage::filesystem::StorableEntity;

// ─── Top-Level Entity ───────────────────────────────────────────────────────

/// The primary configuration entity. Represents a single managed agent's full
/// surface area: how it's reached, where it routes, what identity it carries,
/// and what it can call out to.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AgentSurface {
    /// Unique identifier (UUID). Assigned at creation time.
    #[serde(default)]
    pub surface_id: String,

    /// Human-readable name (e.g., "sales-agent", "research-assistant").
    pub name: String,

    /// Optional description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Lifecycle status.
    #[serde(default)]
    pub status: SurfaceStatus,

    /// The agent's DID. Gateway-managed (computed from identity resolution)
    /// or externally provided.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,

    /// Management-plane tenant ownership for PAT authorization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Tags for grouping, filtering, search.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// The inbound configuration — how callers reach this agent.
    pub access_point: AccessPoint,

    /// The single upstream destination — the managed agent itself.
    pub target: Target,

    /// Opaque UI-only blob persisted on behalf of the management dashboard:
    /// canvas node positions, decorative NPC/human/caller nodes, and any
    /// other layout state. The runtime never reads this; the backend stores
    /// it verbatim so the dashboard can round-trip the visual builder
    /// without polluting the runtime surface config.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas: Option<serde_json::Value>,

    /// Surface-level variant catalog. Each variant is a sparse
    /// delta over this surface's base form; resolution is performed by
    /// `AgentSurface::resolve_variant`. The legacy `Target::variants` field
    /// has been removed — these surface-level variants are the sole source
    /// of variant data and are consumed by the runtime (e.g. the fabric
    /// message processor).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<crate::config::agent_surface_variants::SurfaceVariant>,

    /// Id (not alias) of the variant addressed by the unmarked URL.
    /// `None` when the surface has no variants.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_variant_id: Option<String>,

    /// Credential providers bound to this surface for outbound delegation
    /// (consent_required signalling, OAuth token injection, etc.). These
    /// apply at the surface level and survive direct outbound calls.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub outbound_credentials: Vec<OutboundCredentialBinding>,

    /// Three independent identity slots, one per edge in the request/response
    /// pipeline. Each slot owns its own extraction config (`payload_extraction`,
    /// `from_api_key`, `from_mtls`, `static`).
    #[serde(default, skip_serializing_if = "SurfaceIdentitySlots::is_empty")]
    pub identity_slots: SurfaceIdentitySlots,
}

/// Three independent identity slots covering the proxy pipeline edges.
///
/// * `inbound`   — CA → AP request: extract caller agent identity from the inbound request body.
/// * `protected` — MA → AP response: extract the protected (managed) agent identity from the response body.
/// * `external`  — EXT → TP response: extract the external agent identity from an outbound response.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SurfaceIdentitySlots {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<crate::source_auth::ManagedIdentityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected: Option<crate::source_auth::ManagedIdentityConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<crate::source_auth::ManagedIdentityConfig>,
}

impl SurfaceIdentitySlots {
    pub fn is_empty(&self) -> bool {
        self.inbound.is_none() && self.protected.is_none() && self.external.is_none()
    }
}

/// Lifecycle status of an Agent Surface.
///
/// Shares the workspace-wide [`EntityStatus`] soft-delete model
/// (`enabled` | `disabled` | `deleted`); re-exported under the legacy
/// `SurfaceStatus` name for call-site stability.
pub use crate::entity_status::EntityStatus as SurfaceStatus;

// ─── Access Point ───────────────────────────────────────────────────────────

/// Defines the front door of an Agent Surface — how callers discover,
/// authenticate with, and reach this agent through the Gateway.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AccessPoint {
    /// Friendly display name shown in the dashboard (e.g. monitoring
    /// slice picker). Free text; empty / absent renders as "Access
    /// Point". Never used for routing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Network address to bind (e.g., "0.0.0.0:8443").
    pub listen_address: String,

    /// Path prefix distinguishing this surface from others on the same port.
    /// Forms part of the base URL: `https://{host}:{port}{route}`.
    pub route: String,

    /// Agent protocol used for inbound AND Target communication.
    /// The Gateway does not translate between protocols.
    pub protocol: SurfaceProtocol,

    /// How to verify the caller's identity at the transport level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_authentication: Option<CallerAuthentication>,

    /// What we need to know about the caller.
    ///
    /// Deprecated: enforcement is derived from `caller_authentication` presence.
    /// Retained for backward compatibility with stored surfaces.
    #[serde(default, skip_serializing_if = "is_default_caller_context")]
    pub caller_context: CallerContext,

    /// How to derive the agent DID from the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_resolution: Option<IdentityResolution>,

    /// Access-point-level OPA policy (runs before Target pipeline).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_policy: Option<PolicyRef>,

    /// Inbound rate limiting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimitConfig>,

    /// Schema validation on inbound request payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_validation: Option<ExtensionRules>,

    /// Verify the caller against a trust registry.
    #[serde(default, skip_serializing_if = "is_default_trust_registry_verification")]
    pub trust_registry_verification: TrustRegistryVerificationConfig,

    /// Whether to publish this surface to the Gateway's DID document.
    #[serde(default)]
    pub publish_to_did_document: bool,

    /// A2A supported extensions (advertised in agent card).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_extensions: Vec<String>,

    /// Primary A2A extension URI (used for UI display / metrics grouping).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub primary_extension: Option<String>,

    /// Override agent card location path (relative to base URL).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_card_path: Option<String>,

    /// Response custom metadata injection at access-point level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    /// did:webvh managed identity configuration (feature-gated).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub didwebvh_identity: Option<DidWebVhIdentityConfig>,
}

/// Agent protocol declared on a surface.
///
/// Agent Stream does **not** own A2A/MCP protocol runtime behaviour — that belongs to
/// Agent Gateway. This value is retained only for Gateway interoperability
/// (shaping metadata/`_meta`/DID injection on forwarded traffic), observability
/// and audit grouping, policy context, and latent fabric/DIDComm support. It is
/// **not** a switch that selects a protocol engine, and the only runtime use of
/// the protocol family is the safe boundary check in the fabric forward path
/// (see [`crate::protocols::channel_protocol_family`]) that rejects a request
/// whose JSON-RPC shape contradicts this declaration before forwarding.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/src/generated/", rename_all = "lowercase"))]
pub enum SurfaceProtocol {
    /// Agent-to-Agent protocol (JSON-RPC 2.0 with A2A extensions).
    #[default]
    A2a,
    /// Model Context Protocol (JSON-RPC 2.0 with `_meta`).
    Mcp,
    /// DIDComm messaging protocol (for transit gateways).
    #[serde(rename = "didcomm")]
    #[cfg_attr(test, ts(rename = "didcomm"))]
    DIDComm,
    /// Marketplace protocol (embedded model catalog and model purchase).
    Marketplace,
}

/// Caller authentication configuration.
/// Multiple methods can be configured; the Gateway tries them in order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CallerAuthentication {
    /// Ordered list of authentication methods. First success wins.
    pub methods: Vec<SourceAuthConfig>,
}

/// What the Gateway needs to know about the caller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct CallerContext {
    /// Caller identity requirement mode.
    #[serde(default)]
    pub mode: CallerContextMode,
}

/// How strictly caller identity is required.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum CallerContextMode {
    /// Caller MUST be identifiable. Request rejected if identity cannot be resolved.
    #[default]
    Required,
    /// Gateway attempts to resolve identity but proceeds if it cannot.
    Optional,
    /// No identity extraction at all.
    Anonymous,
}

/// How the Gateway derives the agent DID from the request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "strategy", rename_all = "snake_case")]
pub enum IdentityResolution {
    /// Extract identity fields from the request body. Fields are hashed into a DID.
    FromPayload {
        /// Dot-notation field paths to extract (e.g., "agentIdentity.name").
        fields: Vec<String>,
        /// Hash algorithm (default: sha256).
        #[serde(default = "default_hash_algorithm")]
        hash_algorithm: String,
    },
    /// Derive DID from the client certificate CN/SAN.
    FromMtls,
    /// Map API key to a pre-registered agent DID.
    FromApiKey,
    /// Extract DID from JWT claims.
    FromJwtClaims {
        /// Claim name containing the DID or identity (e.g., "sub").
        claim: String,
    },
    /// Fixed DID assigned by the admin.
    Static {
        /// The DID to use for all requests through this surface.
        did: String,
    },
    /// No agent DID resolved.
    None,
}

fn default_hash_algorithm() -> String {
    "sha256".to_string()
}

/// Used by `serde(skip_serializing_if = ...)` so a disabled default
/// `trust_registry_verification` block is omitted from the wire payload
/// instead of leaking a phantom "Trust Registry" element into the UI.
fn is_default_trust_registry_verification(v: &TrustRegistryVerificationConfig) -> bool {
    !v.enabled && v == &TrustRegistryVerificationConfig::default()
}

/// Used by `serde(skip_serializing_if = ...)` so the deprecated
/// `caller_context` block is omitted when it carries no information.
fn is_default_caller_context(v: &CallerContext) -> bool {
    v == &CallerContext::default()
}

/// Reference to an OPA policy definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyRef {
    /// ID of the policy definition in the policy store.
    pub policy_definition_id: String,
}

/// Payment enforcement for a paid surface. The Agent Pay surface at
/// `fabric://{payment_gateway_id}/{payment_surface_id}` verifies and settles
/// the payment; this appliance only lets a request through to the target once
/// Agent Pay has accepted it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PaymentPolicy {
    pub provider: PaymentProvider,
    /// Peer appliance that hosts the Agent Pay surface.
    pub payment_gateway_id: String,
    /// Agent Pay surface on `payment_gateway_id`.
    pub payment_surface_id: String,
}

/// Who verifies and settles a surface's payments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentProvider {
    AgentPay,
}

// ─── Target ─────────────────────────────────────────────────────────────────

/// The single upstream destination — the actual managed agent.
/// Traffic arriving at `{base}/...` is forwarded here.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Upstream endpoint (https://, fabric://{gw}/{surface}).
    pub endpoint: String,

    /// Service-level credentials (Gateway → Target).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<TargetAuthConfig>,

    /// Request-side OPA policy ("is this caller allowed this operation?").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<PolicyRef>,

    /// Response-side OPA policy ("is this response allowed for this caller?").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_policy: Option<PolicyRef>,

    /// Payment enforcement; set on a paid surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payment_policy: Option<PaymentPolicy>,

    /// Networking configuration (timeout, retry, circuit breaker, mirror).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub networking: Option<NetworkingConfig>,

    /// Identity injection (VP binding).
    #[serde(default)]
    pub identity_injection: IdentityInjectionConfig,

    /// Trust registry extension injection on outbound requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_registry_injection: Option<TrustRegistryInjection>,

    /// Trust registry extension validation on inbound responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trust_registry_injection_inbound: Option<TrustRegistryInjection>,

    /// Response extension validation (schema-based).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<ExtensionRules>,

    /// Custom metadata injection (request and/or response).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_metadata: Option<CustomMetadata>,

    /// Response custom metadata injection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_custom_metadata: Option<CustomMetadata>,

    /// Display name for fabric:// endpoints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fabric_target_name: Option<String>,

    /// Auto-pay MPP challenges for fabric:// targets.
    #[serde(default)]
    pub mpp_auto_pay: bool,

    /// Maximum amount per auto-pay request (safety cap).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mpp_auto_pay_max_amount: Option<String>,
}

// ─── Target Variants (legacy, removed) ──────────────────────────────────────
// Legacy `TargetVariant` deleted; variants now live on `AgentSurface.variants`
// as `SurfaceVariant` (see agent_surface_variants.rs).
/// Networking configuration (composes timeout, retry, circuit breaker, mirror).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct NetworkingConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<TimeoutConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetryConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mirror: Option<MirrorConfig>,
}

/// Identity injection (VP binding) configuration.
///
/// In addition to the legacy `inject_vp` flag, this struct persists the
/// agent-identity definition the management UI sends as `target.agent_identity`
/// (the API translation layer renames it to `identity_injection` on the wire).
/// The runtime currently only consults `inject_vp`; the remaining fields are
/// stored verbatim so they round-trip cleanly to and from the dashboard until
/// the request pipeline learns to honour them.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentityInjectionConfig {
    /// Whether to inject a signed VP into outbound requests.
    #[serde(default)]
    pub inject_vp: bool,

    /// Identity extraction strategy: `from_payload`, `from_api_key`,
    /// `from_mtls`, or `static`.
    #[serde(default, rename = "type", skip_serializing_if = "Option::is_none")]
    pub identity_type: Option<String>,

    /// API key id (when `identity_type = "from_api_key"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_id: Option<String>,

    /// Certificate id (when `identity_type = "from_mtls"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate_id: Option<String>,

    /// Static DID (when `identity_type = "static"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub static_did: Option<String>,

    /// Top-level payload field that the identity object is read from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub meta_field: Option<String>,

    /// Dot-notation paths concatenated and hashed to derive the agent DID
    /// (used by `from_payload`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,

    /// JSON Schema describing the expected identity object on the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// Strip the raw identity field from the forwarded MCP `_meta` after the
    /// verified credential is injected. Round-trips to the dashboard
    /// and is honoured at runtime via `PayloadExtractionConfig::strip_raw_meta`.
    #[serde(default)]
    pub strip_raw_meta: bool,
}

// ─── DID:webvh Identity ─────────────────────────────────────────────────────

/// did:webvh managed identity configuration.
/// When configured, the gateway manages a did:webvh DID lifecycle for this surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityConfig {
    /// The managed identity ID (references an identity in the identity store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_id: Option<String>,

    /// Auto-create the identity if it doesn't exist.
    #[serde(default)]
    pub auto_create: bool,

    /// Custom path segment for the DID (default: derived from surface name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub did_path: Option<String>,

    /// How the DID identity is injected into outbound requests.
    #[serde(default)]
    pub injection_mode: DidInjectionMode,
}

/// How did:webvh identity is injected.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum DidInjectionMode {
    /// X-DID-Identity header.
    #[default]
    Header,
    /// X-DID-Signed-Identity header (signed).
    SignedHeader,
    /// Protocol-native injection (A2A extension / MCP `_meta`).
    ProtocolNative,
}

// ─── StorableEntity implementation ──────────────────────────────────────────

impl StorableEntity for AgentSurface {
    fn id(&self) -> &str {
        &self.surface_id
    }

    /// Strip removed fields from stored surfaces so they still load under
    /// `deny_unknown_fields`. Idempotent.
    ///
    /// * `department_id` is dropped.
    /// * A `payment_policy` this appliance verified and settled itself (one
    ///   that does not delegate to Agent Pay) is dropped from the target and
    ///   from each variant's target overrides, and the surface is disabled so
    ///   a surface that required payment is not served unpaid. It stays in the
    ///   store so an operator can review, edit or delete it.
    fn migrate_raw_json(value: &mut serde_json::Value) -> anyhow::Result<bool> {
        let Some(obj) = value.as_object_mut() else {
            return Ok(false);
        };
        let mut changed = obj
            .remove("department_id")
            .is_some();

        let mut had_payment_policy = strip_local_payment_policy(obj.get_mut("target"));
        if let Some(variants) = obj
            .get_mut("variants")
            .and_then(serde_json::Value::as_array_mut)
        {
            for variant in variants {
                had_payment_policy |= strip_local_payment_policy(variant.pointer_mut("/overrides/target"));
            }
        }

        if had_payment_policy {
            let surface_id = obj
                .get("surface_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or_default()
                .to_string();
            let deleted = obj
                .get("status")
                .and_then(serde_json::Value::as_str)
                == Some("deleted");
            if !deleted {
                obj.insert("status".to_string(), serde_json::Value::from("disabled"));
            }
            warn!(
                surface_id = %surface_id,
                "Removed unsupported x402 payment_policy from surface and disabled it; review the surface before enabling it again"
            );
            changed = true;
        }

        Ok(changed)
    }
}

/// Remove `target.payment_policy` when it does not delegate to Agent Pay.
/// Returns whether one was removed.
fn strip_local_payment_policy(target: Option<&mut serde_json::Value>) -> bool {
    let Some(target) = target.and_then(serde_json::Value::as_object_mut) else {
        return false;
    };
    let local = target
        .get("payment_policy")
        .is_some_and(|policy| policy.get("provider") != Some(&serde_json::Value::from("agent_pay")));
    local
        && target
            .remove("payment_policy")
            .is_some()
}

// ─── Display ────────────────────────────────────────────────────────────────

impl std::fmt::Display for SurfaceProtocol {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::A2a => write!(f, "a2a"),
            Self::Mcp => write!(f, "mcp"),
            Self::DIDComm => write!(f, "didcomm"),
            Self::Marketplace => write!(f, "marketplace"),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimal_agent_surface_deserializes() {
        let json = r#"{
            "surface_id": "surf-001",
            "name": "calculator",
            "description": "",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/calc",
                "protocol": "mcp"
            },
            "target": {
                "endpoint": "https://calc.internal:4000/mcp"
            }
        }"#;

        let surface: AgentSurface = serde_json::from_str(json).unwrap();
        assert_eq!(surface.surface_id, "surf-001");
        assert_eq!(surface.name, "calculator");
        assert_eq!(surface.access_point.protocol, SurfaceProtocol::Mcp);
        assert_eq!(surface.target.endpoint, "https://calc.internal:4000/mcp");
        assert_eq!(surface.status, SurfaceStatus::Enabled);
    }

    #[test]
    fn migrate_raw_json_strips_legacy_department_id_and_is_idempotent() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{
                "surface_id": "surf-legacy",
                "name": "calculator",
                "department_id": "dept-001",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/agents/calc",
                    "protocol": "mcp"
                },
                "target": {
                    "endpoint": "https://calc.internal:4000/mcp"
                }
            }"#,
        )
        .unwrap();

        assert!(AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(surface.surface_id, "surf-legacy");

        assert!(!AgentSurface::migrate_raw_json(&mut value).unwrap());
    }

    #[test]
    fn marketplace_surface_without_payment_policy_deserializes() {
        let json = r#"{
            "surface_id": "surf-marketplace",
            "name": "marketplace",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/marketplace",
                "protocol": "marketplace"
            },
            "target": {
                "endpoint": "embedded://marketplace"
            }
        }"#;

        let surface: AgentSurface = serde_json::from_str(json).unwrap();
        assert_eq!(surface.access_point.protocol, SurfaceProtocol::Marketplace);
        assert_eq!(surface.target.endpoint, "embedded://marketplace");
    }

    #[test]
    fn local_payment_policy_on_target_is_rejected() {
        let json = r#"{
            "surface_id": "surf-paid",
            "name": "marketplace",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/marketplace",
                "protocol": "marketplace"
            },
            "target": {
                "endpoint": "embedded://marketplace",
                "payment_policy": { "type": "x402", "payment_requirements": [] }
            }
        }"#;

        let err = serde_json::from_str::<AgentSurface>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `type`"),
            "{err}"
        );
    }

    const AGENT_PAY_POLICY: &str =
        r#"{ "provider": "agent_pay", "payment_gateway_id": "gw-pay", "payment_surface_id": "pay-surface" }"#;

    fn paid_surface_json(
        target_policy: &str,
        variant_policy: &str,
    ) -> serde_json::Value {
        serde_json::from_str(&format!(
            r#"{{
                "surface_id": "surf-paid",
                "name": "calculator",
                "status": "enabled",
                "access_point": {{
                    "listen_address": "0.0.0.0:8443",
                    "route": "/agents/calc",
                    "protocol": "mcp"
                }},
                "target": {{
                    "endpoint": "https://calc.internal:4000/mcp",
                    "payment_policy": {target_policy}
                }},
                "variants": [{{
                    "id": "v-paid",
                    "alias": "paid",
                    "name": "Paid",
                    "overrides": {{ "target": {{ "payment_policy": {variant_policy} }} }}
                }}]
            }}"#
        ))
        .unwrap()
    }

    #[test]
    fn agent_pay_payment_policy_round_trips() {
        let surface: AgentSurface =
            serde_json::from_value(paid_surface_json(AGENT_PAY_POLICY, AGENT_PAY_POLICY)).unwrap();

        assert_eq!(
            surface.target.payment_policy,
            Some(PaymentPolicy {
                provider: PaymentProvider::AgentPay,
                payment_gateway_id: "gw-pay".to_string(),
                payment_surface_id: "pay-surface".to_string(),
            })
        );
        let value = serde_json::to_value(&surface).unwrap();
        assert_eq!(value["target"]["payment_policy"]["provider"], "agent_pay");
        let back: AgentSurface = serde_json::from_value(value).unwrap();
        assert_eq!(back.target.payment_policy, surface.target.payment_policy);
    }

    #[test]
    fn agent_pay_payment_policy_without_its_surface_is_rejected() {
        let mut value = paid_surface_json(AGENT_PAY_POLICY, AGENT_PAY_POLICY);
        value["target"]["payment_policy"]
            .as_object_mut()
            .unwrap()
            .remove("payment_surface_id");

        let err = serde_json::from_value::<AgentSurface>(value).unwrap_err();
        assert!(
            err.to_string()
                .contains("payment_surface_id"),
            "{err}"
        );
    }

    #[test]
    fn migrate_raw_json_keeps_agent_pay_payment_policy_and_the_surface_enabled() {
        let mut value = paid_surface_json(AGENT_PAY_POLICY, AGENT_PAY_POLICY);

        assert!(!AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value).unwrap();
        assert_eq!(surface.status, SurfaceStatus::Enabled);
        assert!(
            surface
                .target
                .payment_policy
                .is_some()
        );
        assert!(
            surface.variants[0]
                .overrides
                .target
                .as_ref()
                .and_then(|target| target.payment_policy.as_ref())
                .is_some()
        );
    }

    #[test]
    fn migrate_raw_json_strips_only_the_local_payment_policy_and_disables_the_surface() {
        let mut value = paid_surface_json(AGENT_PAY_POLICY, r#"{ "type": "x402", "payment_requirements": [] }"#);

        assert!(AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value).unwrap();
        assert_eq!(surface.status, SurfaceStatus::Disabled);
        assert!(
            surface
                .target
                .payment_policy
                .is_some()
        );
        assert!(
            surface.variants[0]
                .overrides
                .target
                .as_ref()
                .is_none_or(|target| target
                    .payment_policy
                    .is_none())
        );
    }

    #[test]
    fn migrate_raw_json_strips_payment_policy_and_disables_surface() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{
                "surface_id": "surf-paid",
                "name": "marketplace",
                "status": "enabled",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/marketplace",
                    "protocol": "marketplace"
                },
                "target": {
                    "endpoint": "embedded://marketplace",
                    "payment_policy": { "type": "x402", "payment_requirements": [] }
                },
                "variants": [{
                    "id": "v-paid",
                    "alias": "paid",
                    "name": "Paid",
                    "overrides": {
                        "target": {
                            "payment_policy": { "type": "x402", "payment_requirements": [] }
                        }
                    }
                }],
                "default_variant_id": "v-paid"
            }"#,
        )
        .unwrap();

        assert!(AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(surface.status, SurfaceStatus::Disabled);
        assert_eq!(surface.variants.len(), 1);

        assert!(!AgentSurface::migrate_raw_json(&mut value).unwrap());
    }

    #[test]
    fn migrate_raw_json_disables_surface_with_payment_policy_only_on_variant() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{
                "surface_id": "surf-variant-paid",
                "name": "calculator",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/agents/calc",
                    "protocol": "mcp"
                },
                "target": { "endpoint": "https://calc.internal:4000/mcp" },
                "variants": [{
                    "id": "v-paid",
                    "alias": "paid",
                    "name": "Paid",
                    "overrides": {
                        "target": {
                            "payment_policy": { "type": "x402", "payment_requirements": [] }
                        }
                    }
                }]
            }"#,
        )
        .unwrap();

        assert!(AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value).unwrap();
        assert_eq!(surface.status, SurfaceStatus::Disabled);
    }

    #[test]
    fn migrate_raw_json_keeps_deleted_surface_deleted() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{
                "surface_id": "surf-deleted",
                "name": "marketplace",
                "status": "deleted",
                "access_point": {
                    "listen_address": "0.0.0.0:8443",
                    "route": "/marketplace",
                    "protocol": "marketplace"
                },
                "target": {
                    "endpoint": "embedded://marketplace",
                    "payment_policy": { "type": "x402", "payment_requirements": [] }
                }
            }"#,
        )
        .unwrap();

        assert!(AgentSurface::migrate_raw_json(&mut value).unwrap());
        let surface: AgentSurface = serde_json::from_value(value).unwrap();
        assert_eq!(surface.status, SurfaceStatus::Deleted);
    }

    #[test]
    fn unsupported_mcp_tool_policy_fields_are_rejected() {
        let json = r#"{
            "surface_id": "surf-mcp-policy",
            "name": "calculator",
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/calc",
                "protocol": "mcp"
            },
            "target": {
                "endpoint": "https://calc.internal:4000/mcp",
                "mcp_tool_policies_enabled": true
            }
        }"#;

        let err = serde_json::from_str::<AgentSurface>(json).unwrap_err();
        assert!(
            err.to_string()
                .contains("unknown field `mcp_tool_policies_enabled`")
        );
    }

    #[test]
    fn test_full_agent_surface_deserializes() {
        let json = r#"{
            "surface_id": "surf-002",
            "name": "research-agent",
            "description": "Handles research requests",
            "status": "enabled",
            "tags": ["research", "production"],
            "access_point": {
                "listen_address": "0.0.0.0:8443",
                "route": "/agents/research",
                "protocol": "a2a",
                "caller_context": { "mode": "required" },
                "identity_resolution": {
                    "strategy": "from_payload",
                    "fields": ["agentIdentity.name", "agentIdentity.provider"],
                    "hash_algorithm": "sha256"
                },
                "inbound_policy": { "policy_definition_id": "pol-research-access" },
                "rate_limit": { "requests": 200, "window_secs": 60 }
            },
            "target": {
                "endpoint": "https://research.internal:5000/a2a",
                "auth": {
                    "method": { "static_secret": { "secret_id": "research-token", "header_name": "Authorization", "header_format": "Bearer {value}" } },
                    "fallback": "reject"
                },
                "policy": { "policy_definition_id": "pol-research-methods" },
                "identity_injection": { "inject_vp": true },
                "networking": {
                    "timeout": { "request_secs": 120, "connect_secs": 10, "idle_secs": 60 },
                    "retry": { "max_attempts": 2, "initial_backoff_ms": 500, "max_backoff_ms": 5000, "backoff_multiplier": 2.0, "retryable_status_codes": [502, 503] }
                }
            }
        }"#;

        let surface: AgentSurface = serde_json::from_str(json).unwrap();
        assert_eq!(surface.name, "research-agent");
        assert_eq!(surface.tenant_id, None);
        assert_eq!(surface.tags, vec!["research", "production"]);
        assert_eq!(
            surface
                .access_point
                .caller_context
                .mode,
            CallerContextMode::Required
        );
        assert!(
            surface
                .target
                .policy
                .is_some()
        );
        assert!(
            surface
                .target
                .identity_injection
                .inject_vp
        );
    }
}
