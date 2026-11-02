//! Caller-identity extraction for team attribution.
//!
//! A surface that participates in team quotas must locate the caller's identity
//! in the inbound request. The location is surface-type agnostic — every surface
//! has request headers, an optional authenticated identity, and a request body —
//! so the same extractor serves LLM surfaces, IDE surfaces, and any future
//! surface type.
//!
//! The extracted value is a normalised **identifier string** (e.g. an email, a
//! JWT subject, an API-key name, or an mTLS CN). It is matched against a
//! [`crate::members::Member`]'s identifier list to resolve the caller.

use crate::members::types::normalize_identifier;
use crate::source_auth::AuthenticatedIdentity;
use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};

/// Which field of an mTLS client certificate carries the caller identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MtlsCallerBinding {
    /// First `email` SubjectAltName on the leaf certificate.
    EmailSan,
    /// `CN=` component of the certificate subject DN.
    SubjectCn,
}

/// Where a surface should look for the caller's identity.
///
/// The `#[serde(tag = "type")]` discriminant values (`header`, `jwt_claim`,
/// `body_json_path`, `mtls`, `api_key`) are the stable wire form and are shared
/// with the frontend.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CallerIdentitySource {
    /// A request header, e.g. `X-Caller-Email`. **Spoofable** by the caller
    /// unless a trusted proxy sets it — never used for auto-provisioning.
    Header { name: String },
    /// A claim on the authenticated JWT bearer token, e.g. `email` or `oid`.
    JwtClaim { claim: String },
    /// A JSON Pointer (RFC 6901) into the request body, e.g. `/user/email`.
    /// **Spoofable** — never used for auto-provisioning.
    BodyJsonPath { path: String },
    /// A field of the verified mTLS client certificate.
    Mtls { binding: MtlsCallerBinding },
    /// The validated API key's name is treated as the caller identifier. The
    /// key must be named with the member's identifier for matching to work.
    ApiKey,
}

impl CallerIdentitySource {
    /// Validate the source configuration in isolation.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            CallerIdentitySource::Header { name } if name.trim().is_empty() => {
                Err("caller identity header name must not be empty".to_string())
            }
            CallerIdentitySource::JwtClaim { claim } if claim.trim().is_empty() => {
                Err("caller identity JWT claim must not be empty".to_string())
            }
            CallerIdentitySource::BodyJsonPath { path } if !path.starts_with('/') => {
                Err("caller identity body path must be a JSON pointer starting with '/'".to_string())
            }
            _ => Ok(()),
        }
    }

    /// Whether this source reads from a **verified** credential (JWT / mTLS /
    /// API key) rather than a caller-controlled header or request body. Only
    /// verified sources are trusted to seed an auto-provisioned member.
    #[allow(dead_code)]
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            CallerIdentitySource::JwtClaim { .. } | CallerIdentitySource::Mtls { .. } | CallerIdentitySource::ApiKey
        )
    }
}

/// Pull the `CN=` component out of an RFC 4514 subject DN.
fn cn_from_subject_dn(subject_dn: &str) -> Option<String> {
    subject_dn
        .split(',')
        .map(str::trim)
        .find_map(|rdn| {
            rdn.strip_prefix("CN=")
                .or_else(|| rdn.strip_prefix("cn="))
        })
        .map(|s| s.to_string())
}

/// Extract the caller identity per `source`, returning a normalised value or
/// `None` when it cannot be located. `body` should be the parsed request body
/// (or `Value::Null` when unavailable).
pub fn extract_caller_identity(
    source: &CallerIdentitySource,
    headers: &HeaderMap,
    identity: Option<&AuthenticatedIdentity>,
    body: &serde_json::Value,
) -> Option<String> {
    let raw = match source {
        CallerIdentitySource::Header { name } => headers
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        CallerIdentitySource::JwtClaim { claim } => match identity {
            Some(AuthenticatedIdentity::JwtBearer { claims, .. }) => claims
                .get(claim)
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            _ => None,
        },
        CallerIdentitySource::BodyJsonPath { path } => body
            .pointer(path)
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        CallerIdentitySource::Mtls { binding } => match identity {
            Some(AuthenticatedIdentity::Mtls { subject_dn, sans, .. }) => match binding {
                MtlsCallerBinding::EmailSan => sans.email.first().cloned(),
                MtlsCallerBinding::SubjectCn => cn_from_subject_dn(subject_dn),
            },
            _ => None,
        },
        CallerIdentitySource::ApiKey => match identity {
            Some(AuthenticatedIdentity::ApiKey { key_name }) => Some(key_name.clone()),
            _ => None,
        },
    };

    raw.map(|s| normalize_identifier(&s))
        .filter(|s| !s.is_empty())
}

/// Extract the caller identity from the **first** source in `sources` that
/// yields a non-empty value. Returns `None` when no source matches. This is the
/// ordered-fallback used by the team gate so a surface can try, e.g.,
/// `[jwt_claim(oid), jwt_claim(email), api_key]` and use whichever the caller
/// actually presents.
pub fn extract_first_caller_identity(
    sources: &[CallerIdentitySource],
    headers: &HeaderMap,
    identity: Option<&AuthenticatedIdentity>,
    body: &serde_json::Value,
) -> Option<String> {
    sources
        .iter()
        .find_map(|source| extract_caller_identity(source, headers, identity, body))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_auth::AuthenticatedIdentity;

    #[test]
    fn header_source_reads_and_normalizes() {
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-caller-email",
            "  Alice@Example.COM "
                .parse()
                .unwrap(),
        );
        let source = CallerIdentitySource::Header {
            name: "x-caller-email".to_string(),
        };
        assert_eq!(
            extract_caller_identity(&source, &headers, None, &serde_json::Value::Null),
            Some("alice@example.com".to_string())
        );
    }

    #[test]
    fn jwt_claim_source_reads_claim() {
        let identity = AuthenticatedIdentity::JwtBearer {
            subject: "sub-1".to_string(),
            claims: serde_json::json!({ "email": "bob@example.com" }),
        };
        let source = CallerIdentitySource::JwtClaim { claim: "email".to_string() };
        assert_eq!(
            extract_caller_identity(&source, &HeaderMap::new(), Some(&identity), &serde_json::Value::Null),
            Some("bob@example.com".to_string())
        );
    }

    #[test]
    fn body_json_path_source_reads_pointer() {
        let body = serde_json::json!({ "user": { "email": "carol@example.com" } });
        let source = CallerIdentitySource::BodyJsonPath {
            path: "/user/email".to_string(),
        };
        assert_eq!(
            extract_caller_identity(&source, &HeaderMap::new(), None, &body),
            Some("carol@example.com".to_string())
        );
    }

    #[test]
    fn mtls_email_san_source_reads_first_san() {
        let identity = AuthenticatedIdentity::Mtls {
            principal: "p".to_string(),
            fingerprint: "fp".to_string(),
            subject_dn: "CN=dave,O=Acme".to_string(),
            issuer_dn: String::new(),
            sans: crate::source_auth::models::MtlsSans {
                email: vec!["dave@example.com".to_string()],
                ..Default::default()
            },
            source: crate::source_auth::models::PeerCertSource::DirectTls,
        };
        let source = CallerIdentitySource::Mtls {
            binding: MtlsCallerBinding::EmailSan,
        };
        assert_eq!(
            extract_caller_identity(&source, &HeaderMap::new(), Some(&identity), &serde_json::Value::Null),
            Some("dave@example.com".to_string())
        );
    }

    #[test]
    fn mtls_subject_cn_source_parses_dn() {
        assert_eq!(cn_from_subject_dn("CN=erin@example.com,O=Acme"), Some("erin@example.com".to_string()));
    }

    #[test]
    fn api_key_source_uses_key_name() {
        let identity = AuthenticatedIdentity::ApiKey {
            key_name: "frank@example.com".to_string(),
        };
        let source = CallerIdentitySource::ApiKey;
        assert_eq!(
            extract_caller_identity(&source, &HeaderMap::new(), Some(&identity), &serde_json::Value::Null),
            Some("frank@example.com".to_string())
        );
    }

    #[test]
    fn missing_value_returns_none() {
        let source = CallerIdentitySource::Header {
            name: "x-caller-email".to_string(),
        };
        assert_eq!(extract_caller_identity(&source, &HeaderMap::new(), None, &serde_json::Value::Null), None);
    }

    #[test]
    fn validate_rejects_bad_pointer() {
        assert!(
            CallerIdentitySource::BodyJsonPath { path: "user/email".to_string() }
                .validate()
                .is_err()
        );
    }

    #[test]
    fn first_source_falls_through_to_second() {
        // First source (a JWT claim) yields nothing; the second (a header) wins.
        let mut headers = HeaderMap::new();
        headers.insert(
            "x-user",
            "grace@example.com"
                .parse()
                .unwrap(),
        );
        let sources = vec![
            CallerIdentitySource::JwtClaim { claim: "email".to_string() },
            CallerIdentitySource::Header { name: "x-user".to_string() },
        ];
        assert_eq!(
            extract_first_caller_identity(&sources, &headers, None, &serde_json::Value::Null),
            Some("grace@example.com".to_string())
        );
    }

    #[test]
    fn is_verified_flags_only_trusted_sources() {
        assert!(CallerIdentitySource::JwtClaim { claim: "oid".to_string() }.is_verified());
        assert!(
            CallerIdentitySource::Mtls {
                binding: MtlsCallerBinding::EmailSan
            }
            .is_verified()
        );
        assert!(CallerIdentitySource::ApiKey.is_verified());
        assert!(!CallerIdentitySource::Header { name: "x".to_string() }.is_verified());
        assert!(!CallerIdentitySource::BodyJsonPath { path: "/x".to_string() }.is_verified());
    }
}
