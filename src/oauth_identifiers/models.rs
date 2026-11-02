//! OAuth Identifier data models.
//!
//! An **OAuth Identifier** is a named, reusable set of **public** OAuth 2.0 /
//! OIDC sign-in identifiers (never secrets) that other surfaces reference by id:
//! the IDE Surface front-door sign-in (`client_auth`), a member's upstream
//! sign-in slot, and the dashboard sandbox "Sign in to test" flow all resolve a
//! profile to the same `{ authority, client_id, scopes }` tuple. Editing the
//! profile once updates every referencing surface (central management), and the
//! values are safe to publish unauthenticated in the IDE bootstrap.
//!
//! The identifiers are **shape-tagged** rather than Entra-assuming: `tenant_id`
//! is an Entra-only field, so it lives inside the `Entra` variant. Okta and
//! generic OIDC carry their own issuer-shaped fields.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Provider-specific sign-in shape. `client_id` and `scopes` are common to all
/// OAuth2 flows and live on the parent [`OAuthIdentifier`]; only the fields that
/// describe the **authority / issuer** differ per provider, so they are carried
/// here. Serialised with a `provider` tag (`entra` | `okta` | `oidc`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "provider", rename_all = "snake_case")]
pub enum OAuthIdentifierShape {
    /// Microsoft Entra ID (Azure AD). Authority is
    /// `https://login.microsoftonline.com/{tenant_id}`.
    Entra {
        /// Directory (tenant) id — a GUID, verified domain, or `common` /
        /// `organizations`. Entra-only; not shared with other shapes.
        tenant_id: String,
    },
    /// Okta. Authority is `https://{domain}/oauth2/{authorization_server_id}`
    /// (or `.../oauth2/default` when the server id is omitted).
    Okta {
        /// Okta org domain, e.g. `dev-123456.okta.com`.
        domain: String,
        /// Custom authorization server id. Defaults to `default` when blank.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        authorization_server_id: Option<String>,
    },
    /// Generic OpenID Connect provider. Authority is the issuer URL verbatim.
    Oidc {
        /// The issuer URL, e.g. `https://accounts.example.com`.
        issuer: String,
    },
}

impl OAuthIdentifierShape {
    /// Resolve the OAuth authority base URL from the shape, or an error message
    /// when a required field is blank. Consumers append the provider's own
    /// `/oauth2/v2.0/authorize` / `/token` (or discovery) paths.
    pub fn authority(&self) -> Result<String, String> {
        match self {
            OAuthIdentifierShape::Entra { tenant_id } => {
                let t = tenant_id.trim();
                if t.is_empty() {
                    return Err("entra shape requires a tenant_id".to_string());
                }
                Ok(format!("https://login.microsoftonline.com/{t}"))
            }
            OAuthIdentifierShape::Okta {
                domain,
                authorization_server_id,
            } => {
                let d = domain
                    .trim()
                    .trim_end_matches('/');
                if d.is_empty() {
                    return Err("okta shape requires a domain".to_string());
                }
                let asid = authorization_server_id
                    .as_deref()
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .unwrap_or("default");
                Ok(format!("https://{d}/oauth2/{asid}"))
            }
            OAuthIdentifierShape::Oidc { issuer } => {
                let i = issuer
                    .trim()
                    .trim_end_matches('/');
                if i.is_empty() {
                    return Err("oidc shape requires an issuer".to_string());
                }
                Ok(i.to_string())
            }
        }
    }

    /// Validate the shape-specific fields are present.
    pub fn validate(&self) -> Result<(), String> {
        self.authority().map(|_| ())
    }
}

/// A registered OAuth Identifier — a named, reusable set of public sign-in
/// identifiers. All fields are **public** OAuth identifiers; no secret is ever
/// stored here.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OAuthIdentifier {
    /// Internally generated UUID — immutable after creation.
    pub id: String,

    /// Human-readable name shown in the UI (does not need to be unique).
    pub name: String,

    /// Optional free-text description of what this profile is for.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Provider-specific authority shape (Entra / Okta / OIDC).
    #[serde(flatten)]
    pub shape: OAuthIdentifierShape,

    /// Public client (application) id used to request tokens.
    pub client_id: String,

    /// Scopes the client requests, e.g. `api://<api-app-id>/access_as_user` or a
    /// set of Microsoft Graph scopes.
    #[serde(default)]
    pub scopes: Vec<String>,

    /// Management-plane PAT ownership. Named distinctly because the flattened
    /// Entra provider shape already uses `tenant_id` for its authority tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_tenant_id: Option<String>,

    /// When this profile was created.
    pub created_at: DateTime<Utc>,

    /// When this profile was last updated.
    pub updated_at: DateTime<Utc>,
}

impl OAuthIdentifier {
    /// Validate the profile: a non-blank name, a valid shape, a non-blank
    /// `client_id`, and at least one non-blank scope.
    pub fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty() {
            return Err("name must not be empty".to_string());
        }
        self.shape.validate()?;
        if self
            .client_id
            .trim()
            .is_empty()
        {
            return Err("client_id must not be empty".to_string());
        }
        if !self
            .scopes
            .iter()
            .any(|s| !s.trim().is_empty())
        {
            return Err("at least one non-blank scope is required".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entra() -> OAuthIdentifier {
        OAuthIdentifier {
            id: "00000000-0000-0000-0000-000000000001".to_string(),
            name: "Entra – Copilot".to_string(),
            description: String::new(),
            shape: OAuthIdentifierShape::Entra {
                tenant_id: "tenant-abc".to_string(),
            },
            client_id: "client-xyz".to_string(),
            scopes: vec!["https://graph.microsoft.com/Sites.Read.All".to_string()],
            owner_tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn entra_roundtrip_and_authority() {
        let mut p = entra();
        p.owner_tenant_id = Some("owner-a".into());
        let json = serde_json::to_string(&p).unwrap();
        // The shape is flattened, so `provider` sits alongside `client_id`.
        assert!(json.contains("\"provider\":\"entra\""));
        assert!(json.contains("\"tenant_id\":\"tenant-abc\""));
        assert!(json.contains("\"owner_tenant_id\":\"owner-a\""));
        assert!(json.contains("\"tenant_id\":\"tenant-abc\""));
        let back: OAuthIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
        assert_eq!(
            back.shape
                .authority()
                .unwrap(),
            "https://login.microsoftonline.com/tenant-abc"
        );
    }

    #[test]
    fn okta_authority_defaults_to_default_server() {
        let shape = OAuthIdentifierShape::Okta {
            domain: "dev-1.okta.com".to_string(),
            authorization_server_id: None,
        };
        assert_eq!(shape.authority().unwrap(), "https://dev-1.okta.com/oauth2/default");
        let shape2 = OAuthIdentifierShape::Okta {
            domain: "dev-1.okta.com/".to_string(),
            authorization_server_id: Some("aus123".to_string()),
        };
        assert_eq!(shape2.authority().unwrap(), "https://dev-1.okta.com/oauth2/aus123");
    }

    #[test]
    fn oidc_authority_trims_trailing_slash() {
        let shape = OAuthIdentifierShape::Oidc {
            issuer: "https://accounts.example.com/".to_string(),
        };
        assert_eq!(shape.authority().unwrap(), "https://accounts.example.com");
    }

    #[test]
    fn validate_rejects_blank_fields() {
        let mut p = entra();
        p.name = "  ".to_string();
        assert!(p.validate().is_err());

        let mut p = entra();
        p.client_id = String::new();
        assert!(p.validate().is_err());

        let mut p = entra();
        p.scopes = vec!["  ".to_string()];
        assert!(p.validate().is_err());

        let mut p = entra();
        p.shape = OAuthIdentifierShape::Entra { tenant_id: String::new() };
        assert!(p.validate().is_err());
    }

    #[test]
    fn okta_and_oidc_roundtrip() {
        for shape in [
            OAuthIdentifierShape::Okta {
                domain: "dev-1.okta.com".to_string(),
                authorization_server_id: Some("aus123".to_string()),
            },
            OAuthIdentifierShape::Oidc {
                issuer: "https://accounts.example.com".to_string(),
            },
        ] {
            let tag = match &shape {
                OAuthIdentifierShape::Entra { .. } => "entra",
                OAuthIdentifierShape::Okta { .. } => "okta",
                OAuthIdentifierShape::Oidc { .. } => "oidc",
            };
            let mut p = entra();
            p.shape = shape;
            let json = serde_json::to_string(&p).unwrap();
            assert!(json.contains(&format!("\"provider\":\"{tag}\"")));
            let back: OAuthIdentifier = serde_json::from_str(&json).unwrap();
            assert_eq!(back, p);
        }
    }
}
