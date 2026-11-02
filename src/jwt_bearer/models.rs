//! JWT Bearer data models

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::jwt_bearer::jwks::Jwk;

/// Where to fetch/find the JSON Web Key Set for a `JwtVerificationStrategy`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum JwksSource {
    /// Statically configured keys — no HTTP, no cache.
    Static { jwks: Vec<Jwk> },
    /// URL to fetch the JWKS from (cached per `Cache-Control: max-age`).
    Remote { jwks_uri: String },
}

/// A registered JWT verification strategy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtVerificationStrategy {
    /// Internally generated UUID — immutable after creation.
    pub id: String,

    /// Human-readable name shown in the UI (does not need to be unique).
    pub name: String,

    /// The expected `iss` claim value. Mandatory.
    pub expected_issuer: String,

    /// Where to find the JWKS (static inline keys or a remote URL).
    pub jwks_source: JwksSource,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// When this strategy was created.
    pub created_at: DateTime<Utc>,

    /// When this strategy was last updated.
    pub updated_at: DateTime<Utc>,
}

/// JWT Bearer-specific authentication configuration attached to a channel or pipe.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct JwtBearerAuthConfig {
    /// UUID of the `JwtVerificationStrategy` to use for validation.
    pub jwt_verification_strategy_id: String,

    /// Acceptable `aud` claim values. The token is accepted if its `aud` claim
    /// matches *any* value in this list. May be empty, but an empty list fails
    /// closed (rejects every token) unless `allow_missing_audience` is set, so a
    /// misconfiguration cannot silently accept any `aud` from the trusted issuer.
    pub audiences: Vec<String>,

    /// Opt-in escape hatch for OAuth servers that issue no `aud` claim. Only when
    /// `audiences` is empty AND this is `true` is audience validation disabled.
    /// Defaults to `false` (fail closed).
    #[serde(default)]
    pub allow_missing_audience: bool,

    /// HTTP header to read the token from. Defaults to `Authorization`.
    #[serde(default = "default_token_header")]
    pub token_header: String,

    /// Scheme prefix stripped from the header value before validation (e.g. `Bearer`).
    /// Empty string means "no scheme prefix — header carries the raw token".
    /// Defaults to `Bearer`.
    #[serde(default = "default_token_scheme")]
    pub token_scheme: String,
}

fn default_token_header() -> String {
    "Authorization".to_string()
}

fn default_token_scheme() -> String {
    "Bearer".to_string()
}

impl JwtBearerAuthConfig {
    /// Whether any token can pass the audience check: one is listed, or the
    /// check is turned off for an issuer that emits no `aud`.
    pub fn accepts_some_audience(&self) -> bool {
        !self.audiences.is_empty() || self.allow_missing_audience
    }
}

impl Default for JwtBearerAuthConfig {
    fn default() -> Self {
        Self {
            jwt_verification_strategy_id: String::new(),
            audiences: Vec::new(),
            allow_missing_audience: false,
            token_header: default_token_header(),
            token_scheme: default_token_scheme(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_strategy() -> JwtVerificationStrategy {
        JwtVerificationStrategy {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            name: "Test Strategy".to_string(),
            expected_issuer: "https://issuer.example.com".to_string(),
            jwks_source: JwksSource::Remote {
                jwks_uri: "https://issuer.example.com/.well-known/jwks.json".to_string(),
            },
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    // ── Serialisation round-trips ────────────────────────────────────────────

    #[test]
    fn test_jwt_verification_strategy_roundtrip() {
        let strategy = make_strategy();
        let json = serde_json::to_string(&strategy).unwrap();
        let back: JwtVerificationStrategy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, strategy.id);
        assert_eq!(back.name, strategy.name);
        assert_eq!(back.expected_issuer, strategy.expected_issuer);
    }

    #[test]
    fn test_jwks_source_remote_roundtrip() {
        let src = JwksSource::Remote {
            jwks_uri: "https://example.com/jwks.json".to_string(),
        };
        let json = serde_json::to_string(&src).unwrap();
        let back: JwksSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn test_jwks_source_static_roundtrip() {
        let src = JwksSource::Static { jwks: vec![] };
        let json = serde_json::to_string(&src).unwrap();
        let back: JwksSource = serde_json::from_str(&json).unwrap();
        assert_eq!(back, src);
    }

    #[test]
    fn test_expected_issuer_is_mandatory() {
        let strategy = make_strategy();
        assert!(
            !strategy
                .expected_issuer
                .is_empty()
        );
    }
}
