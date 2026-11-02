//! Source authentication data models
//!
//! Defines the unified authentication configuration that replaces the old
//! `source_authentication_strategy` and `identity_config` fields on channels.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::jwt_bearer::models::JwtBearerAuthConfig;

// ── Source authentication configuration ──────────────────────────────────────

/// Unified source authentication configuration attached to a channel.
///
/// Replaces the old `AuthenticationStrategy` enum (JWT-only) and the
/// `IdentityConfig` struct (apikey / mtls modes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SourceAuthConfig {
    /// Validate inbound bearer tokens against a JWT verification strategy.
    JwtBearer(JwtBearerAuthConfig),

    /// Validate an API key extracted from the request against a secret in the secrets store.
    ApiKey(ApiKeyAuthConfig),

    /// Validate an API key extracted from the request against the API Key Provider.
    ApiKeyProvider(ApiKeyProviderAuthConfig),

    /// Validate via mutual TLS client certificate. Supports both directly
    /// terminated TLS handshakes and forwarded peer certs (XFCC). See
    /// [`MtlsAuthConfig`].
    Mtls(MtlsAuthConfig),
}

/// API Key authentication configuration (backed by SecretsStore).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyAuthConfig {
    /// Where to extract the API key credential from the inbound request.
    pub extraction: CredentialExtraction,
    /// Secret ID in the secrets store containing valid API keys (comma-separated).
    pub secret_id: String,
}

/// API Key Provider authentication configuration (backed by ApiKeyValidator).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ApiKeyProviderAuthConfig {
    /// Where to extract the API key credential from the inbound request.
    pub extraction: CredentialExtraction,
    /// Agent ID to validate keys against in the API Key Provider.
    pub agent_id: String,
}

/// mTLS authentication configuration.
///
/// Two-dimensional model:
/// - `trust` — how the presented client certificate is trusted (pinned to
///   exact certs, or chain-validated against one or more CAs).
/// - `identity_binding` — how the verified certificate is converted into a
///   stable principal string for downstream OPA / audit / metrics use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MtlsAuthConfig {
    /// How to establish trust in the presented client certificate.
    pub trust: MtlsTrust,

    /// How to derive the caller's principal from the verified cert.
    pub identity_binding: MtlsIdentityBinding,

    /// Optional principal allow-list (post-binding, supports `*` glob).
    /// Empty list = allow any principal that passes the trust check.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allowed_subjects: Vec<String>,

    /// Whether this channel accepts certificates that came in via a
    /// forwarded-client-cert header (XFCC or similar). Defaults to `true`.
    /// Set to `false` to require that this channel only honour
    /// directly-terminated TLS client certs even on a listener that allows
    /// XFCC.
    #[serde(default = "default_true")]
    pub allow_forwarded: bool,
}

fn default_true() -> bool {
    true
}

/// How to verify trust in an inbound client certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MtlsTrust {
    /// Accept only these exact certificates, matched by SHA-256
    /// fingerprint of the stored leaf DER. No chain verification.
    /// `certificate_ids` references entries in the certificates store
    /// whose `kind == ClientLeaf`.
    Pinned { certificate_ids: Vec<String> },

    /// Verify the presented leaf chains to one of the configured CAs.
    /// `ca_certificate_ids` references entries in the certificates store
    /// whose `kind == Ca`.
    Ca {
        ca_certificate_ids: Vec<String>,
        /// Require the leaf certificate to carry the TLS Client
        /// Authentication EKU (1.3.6.1.5.5.7.3.2). Defaults `true`.
        #[serde(default = "default_true")]
        require_client_auth_eku: bool,
        /// CRL checking (not yet implemented — `true` is rejected at
        /// authentication time with a clear error).
        #[serde(default)]
        check_crl: bool,
        /// OCSP stapling (not yet implemented — `true` is rejected at
        /// authentication time with a clear error).
        #[serde(default)]
        require_ocsp: bool,
    },
}

/// How to derive a principal string from a verified client certificate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MtlsIdentityBinding {
    /// Lowercase hex SHA-256 fingerprint of the leaf DER. Always available.
    Fingerprint,
    /// Subject Common Name (CN). Errors at runtime if the cert has no CN.
    SubjectCn,
    /// First DNS SubjectAltName. Errors if absent.
    DnsSan,
    /// First URI SubjectAltName. Errors if absent. (SPIFFE IDs flow
    /// through this binding mode.)
    UriSan,
    /// First IP SubjectAltName, rendered canonically (`1.2.3.4` or `::1`).
    /// Errors if absent.
    IpSan,
    /// Take an arbitrary RDN by OID from the Subject DN (e.g. UID =
    /// `0.9.2342.19200300.100.1.1`). Errors if the RDN is not present.
    SubjectRdn { oid: String },
}

impl SourceAuthConfig {
    /// Returns the HTTP header name that this source auth extracts credentials
    /// from, if any. Used to strip the header before forwarding upstream — the
    /// source credential is consumed by the gateway and must not leak.
    pub fn credential_header_name(&self) -> Option<&str> {
        match self {
            SourceAuthConfig::JwtBearer(c) => Some(c.token_header.as_str()),
            SourceAuthConfig::ApiKey(c) => extraction_header(&c.extraction),
            SourceAuthConfig::ApiKeyProvider(c) => extraction_header(&c.extraction),
            SourceAuthConfig::Mtls(_) => None,
        }
    }

    /// Whether this source auth reads its credential from the header `name`
    /// (compared case-insensitively).
    pub fn reads_header(
        &self,
        name: &str,
    ) -> bool {
        self.credential_header_name()
            .is_some_and(|header| header.eq_ignore_ascii_case(name))
    }

    /// Whether `candidate` is the credential the request presented to this
    /// source auth: the value of the header it reads, as sent or without its
    /// scheme (`Bearer <token>`). Compared in constant time.
    pub fn presents_credential(
        &self,
        headers: &axum::http::HeaderMap,
        candidate: &str,
    ) -> bool {
        use subtle::ConstantTimeEq;

        let Some(presented) = self
            .credential_header_name()
            .and_then(|name| headers.get(name))
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        let without_scheme = presented
            .split_once(' ')
            .map(|(_, token)| token.trim());
        std::iter::once(presented)
            .chain(without_scheme)
            .any(|value| {
                bool::from(
                    value
                        .as_bytes()
                        .ct_eq(candidate.as_bytes()),
                )
            })
    }
}

fn extraction_header(extraction: &CredentialExtraction) -> Option<&str> {
    match extraction {
        CredentialExtraction::HttpHeader { field } => Some(field.as_str()),
        CredentialExtraction::McpMeta | CredentialExtraction::A2aExtension => None,
    }
}

// ── Credential extraction ────────────────────────────────────────────────────

/// Describes where to extract a credential from the inbound request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CredentialExtraction {
    /// Extract from an HTTP header.
    HttpHeader {
        /// Header field name (e.g. `X-API-Key`, `Authorization`).
        field: String,
    },

    /// Extract from MCP `_meta` object. Requires request body parsing.
    McpMeta,

    /// Extract from A2A message extension. Requires request body parsing.
    A2aExtension,
}

// ── Authenticated identity (result of authentication) ────────────────────────

/// The identity extracted after successful source authentication.
#[derive(Debug, Clone, PartialEq)]
pub enum AuthenticatedIdentity {
    /// JWT Bearer authentication succeeded.
    JwtBearer {
        /// The `sub` claim from the token.
        subject: String,
        /// All decoded claims.
        claims: Value,
    },

    /// API Key authentication succeeded.
    ApiKey {
        /// The human-readable name of the validated key.
        key_name: String,
    },

    /// mTLS authentication succeeded. Populated by [`MtlsAuthConfig`]
    /// after the presented client certificate has been verified against
    /// the configured trust policy and the identity binding has been
    /// applied.
    Mtls {
        /// Principal derived per [`MtlsIdentityBinding`].
        principal: String,
        /// Lowercase hex SHA-256 of the leaf DER. Always populated.
        fingerprint: String,
        /// Subject DN as an RFC 4514 string.
        subject_dn: String,
        /// Issuer DN. Empty for [`MtlsTrust::Pinned`] (no chain verified).
        issuer_dn: String,
        /// SANs captured from the leaf, for audit / OPA visibility even
        /// when they are not used as the principal.
        sans: MtlsSans,
        /// Where the certificate was captured from (direct TLS handshake
        /// vs forwarded-client-cert header).
        source: PeerCertSource,
    },
}

/// SubjectAltName values lifted off a verified leaf certificate.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MtlsSans {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dns: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uri: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub email: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
}

/// Where the inbound client certificate was captured from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerCertSource {
    /// Captured from the rustls TLS handshake on this gateway.
    DirectTls,
    /// Parsed out of a trusted forwarded-client-cert header (XFCC etc.).
    Forwarded,
}

impl PeerCertSource {
    /// Stable low-cardinality string used in metrics labels, structured
    /// logs and the audit record. Kept in sync with the serde rename.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerCertSource::DirectTls => "direct_tls",
            PeerCertSource::Forwarded => "forwarded",
        }
    }
}

impl std::fmt::Display for PeerCertSource {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A raw inbound client certificate captured by the listener layer and
/// stashed into request extensions for the source-auth middleware to
/// consume. This type intentionally carries only the wire bytes — all
/// parsing, trust checks, and identity binding happen in
/// [`crate::source_auth::mtls`].
#[derive(Debug, Clone)]
pub struct PeerCertInfo {
    /// Leaf certificate DER bytes.
    pub leaf_der: Vec<u8>,
    /// Intermediate certificates the peer offered, in chain order (closest
    /// to the leaf first, root last). Excludes the leaf — it lives in
    /// `leaf_der`. May be empty if the peer sent only the leaf or if the
    /// capture path (e.g. XFCC) does not carry intermediates.
    pub chain_der: Vec<Vec<u8>>,
    /// Where this certificate came from.
    pub source: PeerCertSource,
}

// ── Managed identity configuration ──────────────────────────────────────────

/// Configuration for deriving the *upstream* agent identity that a Surface
/// represents. This is logically distinct from `SourceAuthConfig` (which
/// authenticates the inbound caller); it tells the runtime where to find
/// the identity of the agent on the other side of the Target.
///
/// Today the proxy pipeline acts on `PayloadExtraction` only — the other
/// variants are persisted faithfully so the dashboard does not silently drop
/// user configuration. Runtime support for the remaining variants is added
/// incrementally; the tag string matches the surface's
/// `IdentityInjectionConfig.identity_type` discriminator
/// (`from_payload` / `from_api_key` / `from_mtls` / `static`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ManagedIdentityConfig {
    /// Extract identity from a field in the request payload metadata.
    /// Serialized tag is `payload_extraction` for backward compatibility
    /// with channel JSON written by older builds; `from_payload` is
    /// accepted on the wire to match the dashboard's
    /// `IdentityInjectionConfig.identity_type` discriminator.
    #[serde(alias = "from_payload")]
    PayloadExtraction(PayloadExtractionConfig),

    /// Use an API key (presented by the caller or bound to the surface)
    /// to look up the upstream agent identity.
    FromApiKey {
        /// API key identifier (matches a stored key in the secret store).
        api_key_id: String,
    },

    /// Take the upstream agent identity from the TLS client certificate.
    FromMtls {
        /// Stored certificate identifier.
        certificate_id: String,
    },

    /// Always present a fixed DID as the upstream agent identity (test
    /// fixtures, stub agents).
    Static {
        /// The DID to present as the upstream agent.
        did: String,
    },
}

/// Configuration for payload-based identity extraction.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct PayloadExtractionConfig {
    /// The field name in the payload metadata to extract identity from.
    pub meta_field: String,

    /// Dot-notation paths inside the extracted identity object that are
    /// concatenated and hashed to derive the agent DID. Mirrors the
    /// dashboard's `IdentityInjectionConfig.fields` — persisted here so
    /// the wire format is the source of truth instead of relying on the
    /// opaque per-surface canvas blob.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<String>,

    /// JSON Schema describing the expected identity object on the wire.
    /// Generated by the dashboard's identity onboarding flow and used
    /// (by extension validation) to reject malformed identity payloads
    /// before extraction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json_schema: Option<serde_json::Value>,

    /// Validation rules for the `agent-identity/v1` extension payload.
    /// When present, the identity extension is validated against these rules
    /// before extraction, flattening, hashing, and DID issuance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extension_rules: Option<crate::config::ExtensionRules>,

    /// Strip the raw identity field (`meta_field`) from the forwarded MCP
    /// request `_meta` after the gateway has extracted the caller identity and
    /// injected the verified credential — so the target only ever sees the
    /// signed representation, not the raw identity block. Defaults to `false`
    /// so existing surfaces retain their current pass-through behaviour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub strip_raw_meta: bool,
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_auth_config_jwt_bearer_roundtrip() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec!["aud1".to_string()],
            ..Default::default()
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn jwt_bearer_legacy_json_defaults_to_authorization_bearer() {
        // Stored surfaces created before token_header/token_scheme existed must
        // still deserialise and behave like the canonical Authorization: Bearer.
        let legacy = r#"{
            "type": "jwt_bearer",
            "jwt_verification_strategy_id": "strat-1",
            "audiences": []
        }"#;
        let cfg: SourceAuthConfig = serde_json::from_str(legacy).unwrap();
        match cfg {
            SourceAuthConfig::JwtBearer(c) => {
                assert_eq!(c.token_header, "Authorization");
                assert_eq!(c.token_scheme, "Bearer");
            }
            _ => panic!("expected JwtBearer"),
        }
    }

    #[test]
    fn jwt_bearer_custom_header_and_scheme_roundtrip() {
        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec![],
            allow_missing_audience: false,
            token_header: "X-Auth-Token".to_string(),
            token_scheme: String::new(),
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn the_credential_header_is_the_one_the_front_door_reads() {
        let jwt = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            token_header: "X-Auth-Token".to_string(),
            ..Default::default()
        });
        assert_eq!(jwt.credential_header_name(), Some("X-Auth-Token"));
        assert!(jwt.reads_header("x-auth-token"));
        assert!(!jwt.reads_header("authorization"));
        assert!(SourceAuthConfig::JwtBearer(JwtBearerAuthConfig::default()).reads_header("authorization"));
    }

    #[test]
    fn a_presented_credential_matches_with_or_without_its_scheme() {
        let api_key = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "x-api-key".to_string() },
            secret_id: "s".to_string(),
        });
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("x-api-key", axum::http::HeaderValue::from_static("front-door-key"));
        assert!(api_key.presents_credential(&headers, "front-door-key"));
        assert!(!api_key.presents_credential(&headers, "sk-provider"));

        let jwt = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig::default());
        headers.insert(axum::http::header::AUTHORIZATION, axum::http::HeaderValue::from_static("Bearer eyJ.jwt"));
        assert!(jwt.presents_credential(&headers, "eyJ.jwt"));
        assert!(jwt.presents_credential(&headers, "Bearer eyJ.jwt"));
        assert!(!jwt.presents_credential(&axum::http::HeaderMap::new(), "eyJ.jwt"));
    }

    #[test]
    fn source_auth_config_apikey_roundtrip() {
        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn source_auth_config_apikey_provider_roundtrip() {
        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn source_auth_config_mtls_roundtrip() {
        let config = SourceAuthConfig::Mtls(MtlsAuthConfig {
            trust: crate::source_auth::models::MtlsTrust::Pinned {
                certificate_ids: vec!["cert-1".to_string()],
            },
            identity_binding: crate::source_auth::models::MtlsIdentityBinding::Fingerprint,
            allowed_subjects: Vec::new(),
            allow_forwarded: true,
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: SourceAuthConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_payload_extraction_roundtrip() {
        let config = ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: false,
        });
        let json = serde_json::to_string(&config).unwrap();
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_payload_extraction_legacy_tag() {
        // Channel JSON written by previous builds uses `payload_extraction`
        // as the discriminator. Verify the tag stays stable so disk state
        // continues to deserialize after the enum was extended.
        let json = r#"{"type":"payload_extraction","meta_field":"agentIdentity"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            })
        );
    }

    #[test]
    fn managed_identity_payload_extraction_from_payload_alias() {
        // Dashboard sends the `IdentityInjectionConfig.identity_type` tag
        // (`from_payload`) for identity slots; accept it as an alias.
        let json = r#"{"type":"from_payload","meta_field":"agentIdentity"}"#;
        let back: ManagedIdentityConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            back,
            ManagedIdentityConfig::PayloadExtraction(PayloadExtractionConfig {
                meta_field: "agentIdentity".to_string(),
                fields: Vec::new(),
                json_schema: None,
                extension_rules: None,
                strip_raw_meta: false,
            })
        );
    }

    #[test]
    fn managed_identity_from_api_key_roundtrip() {
        let config = ManagedIdentityConfig::FromApiKey {
            api_key_id: "key-1".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"from_api_key\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_from_mtls_roundtrip() {
        let config = ManagedIdentityConfig::FromMtls {
            certificate_id: "cert-1".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"from_mtls\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn managed_identity_static_roundtrip() {
        let config = ManagedIdentityConfig::Static {
            did: "did:example:42".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("\"type\":\"static\""));
        let back: ManagedIdentityConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, config);
    }

    #[test]
    fn credential_extraction_http_header_roundtrip() {
        let extraction = CredentialExtraction::HttpHeader {
            field: "X-Custom-Header".to_string(),
        };
        let json = serde_json::to_string(&extraction).unwrap();
        let back: CredentialExtraction = serde_json::from_str(&json).unwrap();
        assert_eq!(back, extraction);
    }

    #[test]
    fn payload_extraction_config_persists_fields_and_json_schema() {
        let cfg = PayloadExtractionConfig {
            meta_field: "agentIdentity".to_string(),
            fields: vec!["a.b".to_string(), "a.c".to_string()],
            json_schema: Some(serde_json::json!({"type": "object"})),
            extension_rules: None,
            strip_raw_meta: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("\"fields\":[\"a.b\",\"a.c\"]"));
        assert!(json.contains("\"json_schema\":{"));
        let back: PayloadExtractionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn payload_extraction_config_omits_empty_fields_and_schema() {
        let cfg = PayloadExtractionConfig {
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: false,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("\"fields\""));
        assert!(!json.contains("\"json_schema\""));
        let back: PayloadExtractionConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back, cfg);
    }

    #[test]
    fn payload_extraction_strip_raw_meta_roundtrip() {
        // strip_raw_meta=true must serialize and round-trip.
        let cfg = PayloadExtractionConfig {
            meta_field: "agentIdentity".to_string(),
            fields: Vec::new(),
            json_schema: None,
            extension_rules: None,
            strip_raw_meta: true,
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(json.contains("strip_raw_meta"), "strip_raw_meta=true must appear in serialized JSON");
        let back: PayloadExtractionConfig = serde_json::from_str(&json).unwrap();
        assert!(back.strip_raw_meta);
    }

    #[test]
    fn payload_extraction_strip_raw_meta_defaults_false() {
        // Stored surfaces without the field must default to false (skip-serialized).
        let json = r#"{"meta_field":"agentIdentity"}"#;
        let cfg: PayloadExtractionConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.strip_raw_meta, "strip_raw_meta must default to false");
        let out = serde_json::to_string(&cfg).unwrap();
        assert!(!out.contains("strip_raw_meta"), "false strip_raw_meta must be omitted from JSON");
    }
}
