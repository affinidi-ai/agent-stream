//! Channel-shaped accessors on [`AgentSurface`].
//!
//! These methods read the surface's nested config (`target.*`,
//! `access_point.*`, `target.networking.*`) through flat, one-line
//! accessors, and map the access-point protocol onto the
//! [`ChannelProtocol`] enum that stored configs and the dashboard DTOs
//! still use.
//!
//! They are the canonical channel-shaped read API for an [`AgentSurface`]:
//! a caller that wants a single nested field should prefer these over
//! re-deriving the access path inline.

use super::agent_surface::{AgentSurface, NetworkingConfig, SurfaceProtocol};
use super::types::{
    ChannelProtocol, CircuitBreakerConfig, CustomMetadata, MirrorConfig, RetryConfig, TargetAuthConfig, TimeoutConfig,
    TrustRegistryInjection,
};

impl AgentSurface {
    // ── Identity / addressing ───────────────────────────────────────────────

    /// `Some(surface_id)` — surface IDs are non-optional, but callers
    /// reading this field expect an `Option`.
    #[inline]
    pub fn config_id(&self) -> Option<&str> {
        Some(&self.surface_id)
    }

    /// Access-point listen address (e.g. `0.0.0.0:8443`).
    #[inline]
    pub fn listen_address(&self) -> &str {
        &self
            .access_point
            .listen_address
    }

    /// Access-point route (URL prefix).
    #[inline]
    pub fn route(&self) -> &str {
        &self.access_point.route
    }

    /// Target upstream endpoint.
    #[inline]
    pub fn target_endpoint(&self) -> &str {
        &self.target.endpoint
    }

    // ── Protocol mapping ────────────────────────────────────────────────────

    /// Maps the access-point protocol onto the [`ChannelProtocol`] enum
    /// used by stored configs and the dashboard DTOs.
    ///
    /// The returned value is descriptive metadata for Gateway interoperability,
    /// observability, and policy context — not a runtime protocol-engine
    /// selector. Its only runtime effect is metadata/`_meta`/DID injection shape
    /// and the fabric-forward boundary check
    /// ([`crate::protocols::channel_protocol_family`]).
    #[inline]
    pub fn channel_protocol(&self) -> ChannelProtocol {
        match self.access_point.protocol {
            SurfaceProtocol::A2a => ChannelProtocol::A2a,
            SurfaceProtocol::Mcp => ChannelProtocol::Mcp,
            SurfaceProtocol::DIDComm => ChannelProtocol::DIDComm,
            SurfaceProtocol::Marketplace => ChannelProtocol::Marketplace,
        }
    }

    // ── Target shorthands ───────────────────────────────────────────────────

    /// First caller-authentication method on the access point (callers
    /// that read a single `source_auth` expect only the first configured
    /// method).
    #[inline]
    pub fn source_auth(&self) -> Option<&crate::source_auth::SourceAuthConfig> {
        self.access_point
            .caller_authentication
            .as_ref()
            .and_then(|ca| ca.methods.first())
    }

    /// Lifts the surface `target.identity_injection` into the
    /// `ManagedIdentityConfig` shape used by the proxy/MCP pipelines.
    /// Returns `None` when the injection has no recognized type.
    ///
    /// Prefer the slot-specific accessor [`Self::protected_identity`]; this
    /// falls back to the injection projection when no protected slot is set.
    #[inline]
    pub fn managed_identity(&self) -> Option<crate::source_auth::ManagedIdentityConfig> {
        self.protected_identity()
            .cloned()
            .or_else(|| {
                crate::config::agent_surface_compat::identity_injection_to_managed_identity(
                    &self.target.identity_injection,
                )
            })
    }

    /// Slot 2 — protected agent identity extracted from response (MA → AP).
    #[inline]
    pub fn protected_identity(&self) -> Option<&crate::source_auth::ManagedIdentityConfig> {
        self.identity_slots
            .protected
            .as_ref()
    }

    /// Outbound credential bindings for delegation/consent.
    pub fn outbound_credentials(&self) -> Vec<crate::config::types::OutboundCredentialBinding> {
        self.outbound_credentials
            .clone()
    }

    /// Target service-level credentials.
    #[inline]
    pub fn target_auth(&self) -> Option<&TargetAuthConfig> {
        self.target.auth.as_ref()
    }

    /// Target custom-metadata injection (request side).
    #[inline]
    pub fn custom_metadata(&self) -> Option<&CustomMetadata> {
        self.target
            .custom_metadata
            .as_ref()
    }

    /// Target custom-metadata injection (response side).
    #[inline]
    pub fn response_custom_metadata(&self) -> Option<&CustomMetadata> {
        self.target
            .response_custom_metadata
            .as_ref()
    }

    /// Trust-registry injection on outbound requests.
    #[inline]
    pub fn trust_registry_injection(&self) -> Option<&TrustRegistryInjection> {
        self.target
            .trust_registry_injection
            .as_ref()
    }

    // ── Networking shorthands ───────────────────────────────────────────────

    #[inline]
    fn networking(&self) -> Option<&NetworkingConfig> {
        self.target
            .networking
            .as_ref()
    }

    #[inline]
    pub fn timeout(&self) -> Option<&TimeoutConfig> {
        self.networking()
            .and_then(|n| n.timeout.as_ref())
    }

    #[inline]
    pub fn retry(&self) -> Option<&RetryConfig> {
        self.networking()
            .and_then(|n| n.retry.as_ref())
    }

    #[inline]
    pub fn circuit_breaker(&self) -> Option<&CircuitBreakerConfig> {
        self.networking()
            .and_then(|n| n.circuit_breaker.as_ref())
    }

    #[inline]
    pub fn mirror(&self) -> Option<&MirrorConfig> {
        self.networking()
            .and_then(|n| n.mirror.as_ref())
    }

    // ── Policy ──────────────────────────────────────────────────────────────

    /// Whether OPA enforcement is enabled at the target (request side).
    #[inline]
    pub fn opa_enabled(&self) -> bool {
        self.target.policy.is_some()
    }

    /// Request-side OPA policy definition ID, if any.
    #[inline]
    pub fn opa_policy_definition_id(&self) -> Option<&str> {
        self.target
            .policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            })
    }

    /// Response-side OPA policy definition ID, if any.
    #[inline]
    pub fn response_policy_definition_id(&self) -> Option<&str> {
        self.target
            .response_policy
            .as_ref()
            .map(|p| {
                p.policy_definition_id
                    .as_str()
            })
    }

    // ── Access-point shorthands ─────────────────────────────────────────────

    /// True when the access point overrides the default agent card
    /// location.
    #[inline]
    pub fn override_agent_card_location(&self) -> bool {
        self.access_point
            .agent_card_path
            .is_some()
    }

    /// Access-point agent card path override, if any.
    #[inline]
    pub fn agent_card_location_path(&self) -> Option<&str> {
        self.access_point
            .agent_card_path
            .as_deref()
    }

    /// Access-point trust-registry verification config.
    #[inline]
    pub fn trust_registry_verification(&self) -> &crate::config::types::TrustRegistryVerificationConfig {
        &self
            .access_point
            .trust_registry_verification
    }

    // ── Target shorthands ───────────────────────────────────────────────────

    // ── Protocol / extension helpers ────────────────────────────────────────

    // ── Tags-derived flags ──────────────────────────────────────────────────

    /// Derives the [`SurfaceType`](super::types::SurfaceType) from the
    /// surface tag set.
    #[inline]
    pub fn channel_type(&self) -> super::types::SurfaceType {
        if self
            .tags
            .iter()
            .any(|t| t == "system:onboarding")
        {
            super::types::SurfaceType::Onboarding
        } else if self
            .tags
            .iter()
            .any(|t| t == "system")
        {
            super::types::SurfaceType::System
        } else {
            super::types::SurfaceType::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_surface::{AccessPoint, IdentityInjectionConfig, SurfaceStatus, Target};
    use crate::config::types::TrustRegistryVerificationConfig;

    fn surface(protocol: SurfaceProtocol) -> AgentSurface {
        AgentSurface {
            surface_id: "surf-1".to_string(),
            name: "test".to_string(),
            description: String::new(),
            status: SurfaceStatus::Enabled,
            agent_did: None,
            tenant_id: None,
            tags: Vec::new(),
            access_point: AccessPoint {
                name: None,
                listen_address: "0.0.0.0:8443".to_string(),
                route: "/api".to_string(),
                protocol,
                caller_authentication: None,
                caller_context: Default::default(),
                identity_resolution: None,
                inbound_policy: None,
                rate_limit: None,
                extension_validation: None,
                trust_registry_verification: TrustRegistryVerificationConfig::default(),
                publish_to_did_document: false,
                supported_extensions: vec![],
                primary_extension: None,
                agent_card_path: None,
                response_custom_metadata: None,
                #[cfg(feature = "didwebvh")]
                didwebvh_identity: None,
            },
            target: Target {
                endpoint: "https://upstream:9000".to_string(),
                auth: None,
                policy: None,
                response_policy: None,
                payment_policy: None,
                networking: None,
                identity_injection: IdentityInjectionConfig::default(),
                trust_registry_injection: None,
                trust_registry_injection_inbound: None,
                extension_rules: None,
                custom_metadata: None,
                response_custom_metadata: None,
                fabric_target_name: None,
                mpp_auto_pay: false,
                mpp_auto_pay_max_amount: None,
            },
            canvas: None,
            variants: vec![],
            default_variant_id: None,
            outbound_credentials: vec![],
            identity_slots: Default::default(),
        }
    }

    #[test]
    fn protocol_maps_through() {
        let s = surface(SurfaceProtocol::Mcp);
        assert_eq!(s.channel_protocol(), ChannelProtocol::Mcp);
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.channel_protocol(), ChannelProtocol::A2a);
    }

    #[test]
    fn config_id_wraps_surface_id() {
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.config_id(), Some("surf-1"));
    }

    #[test]
    fn target_endpoint_borrowed() {
        let s = surface(SurfaceProtocol::A2a);
        assert_eq!(s.target_endpoint(), "https://upstream:9000");
    }

    #[test]
    fn opa_enabled_derived_from_policy() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(!s.opa_enabled());
        s.target.policy = Some(crate::config::agent_surface::PolicyRef {
            policy_definition_id: "pd-1".to_string(),
        });
        assert!(s.opa_enabled());
        assert_eq!(s.opa_policy_definition_id(), Some("pd-1"));
    }

    #[test]
    fn networking_helpers_drill_into_nested_struct() {
        let mut s = surface(SurfaceProtocol::A2a);
        assert!(s.timeout().is_none());
        assert!(s.retry().is_none());
        assert!(s.mirror().is_none());
        s.target.networking = Some(NetworkingConfig {
            timeout: Some(TimeoutConfig::default()),
            retry: None,
            circuit_breaker: None,
            mirror: None,
        });
        assert!(s.timeout().is_some());
        assert!(s.retry().is_none());
    }
}
