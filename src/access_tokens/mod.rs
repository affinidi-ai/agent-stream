//! Management access tokens (PATs): long-lived bearer credentials that let a
//! service account (e.g. an external control plane) authenticate to the
//! management API without an interactive session.
//!
//! Distinct from `api_keys`, which authenticate agents on the **data plane**.
//! A management token is bound to an admin user (its permission ceiling) and
//! optionally narrowed by a scope allow-list of RBAC permission names, so a
//! leaked token is individually revocable and least-privilege.

pub mod handlers;
pub mod router;
pub mod store;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub use store::FsAccessTokenStore;

use crate::auth_manager::resource_scope::RequiredHeader;

/// Wire prefix identifying a management access-token secret.
pub const TOKEN_PREFIX: &str = "aspat_";
/// Prefix of secrets issued before the rename to `TOKEN_PREFIX`; still accepted.
pub const LEGACY_TOKEN_PREFIX: &str = "atgpat_";
/// Prefix of a token record id. Records created earlier keep their `atgat_` id.
pub const TOKEN_ID_PREFIX: &str = "asat_";
pub const MAX_DELEGATION_DEPTH: u32 = 3;

pub(crate) fn has_token_prefix(token: &str) -> bool {
    token.starts_with(TOKEN_PREFIX) || token.starts_with(LEGACY_TOKEN_PREFIX)
}

fn is_zero(value: &u32) -> bool {
    *value == 0
}

/// A persisted management access token. The raw secret is never stored — only
/// its SHA-256 hash — and is returned to the caller exactly once, at creation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessToken {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// SHA-256 hex of the full presented token secret.
    pub token_hash: String,
    /// The admin user this token acts as; its role is the token's ceiling.
    pub user_id: String,
    /// Permission-name allow-list; empty = inherit the bound user's full role.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional anchored regex the ID of every entity this token manages must
    /// match. May embed `${header-name}` placeholders resolved from
    /// `required_headers` per request. Empty/absent = no ID restriction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_pattern: Option<String>,
    /// Headers this token must present on every call, each validated against its
    /// own anchored regex. Referenced by `${name}` placeholders in
    /// `resource_pattern`. Empty = no header requirement.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_headers: Vec<RequiredHeader>,
    pub created_by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub delegation_depth: u32,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub rotation_generation: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotated_by: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_used_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    pub fn is_expired(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.expires_at
            .map(|e| now >= e)
            .unwrap_or(false)
    }

    pub fn is_active(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.revoked_at.is_none() && !self.is_expired(now)
    }

    pub fn is_resource_scoped(&self) -> bool {
        self.resource_pattern
            .is_some()
            || !self
                .required_headers
                .is_empty()
    }
}

/// Public view of a token — never includes the hash.
#[derive(Debug, Clone, Serialize)]
pub struct AccessTokenMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub user_id: String,
    pub scopes: Vec<String>,
    pub resource_pattern: Option<String>,
    pub required_headers: Vec<RequiredHeader>,
    pub created_by: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_token_id: Option<String>,
    #[serde(skip_serializing_if = "is_zero")]
    pub delegation_depth: u32,
    #[serde(skip_serializing_if = "is_zero")]
    pub rotation_generation: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_at: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rotated_by: Option<String>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub active: bool,
}

impl AccessTokenMeta {
    pub fn from_token(
        t: &AccessToken,
        now: DateTime<Utc>,
    ) -> Self {
        Self {
            id: t.id.clone(),
            name: t.name.clone(),
            description: t.description.clone(),
            user_id: t.user_id.clone(),
            scopes: t.scopes.clone(),
            resource_pattern: t.resource_pattern.clone(),
            required_headers: t.required_headers.clone(),
            created_by: t.created_by.clone(),
            parent_token_id: t.parent_token_id.clone(),
            delegation_depth: t.delegation_depth,
            rotation_generation: t.rotation_generation,
            rotated_at: t.rotated_at,
            rotated_by: t.rotated_by.clone(),
            created_at: t.created_at,
            last_used_at: t.last_used_at,
            expires_at: t.expires_at,
            revoked_at: t.revoked_at,
            active: t.is_active(now),
        }
    }
}

/// Generate a new record id and a raw token secret. The secret is a 256-bit
/// CSPRNG value shown to the operator exactly once.
pub fn generate_token() -> (String, String) {
    let id = format!("{TOKEN_ID_PREFIX}{}", uuid::Uuid::new_v4().as_simple());
    (id, generate_secret())
}

pub(crate) fn generate_secret() -> String {
    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("{}{}", TOKEN_PREFIX, URL_SAFE_NO_PAD.encode(bytes))
}
