//! API Keys management
//!
//! Provides storage and validation for API keys used in channel authentication

pub mod filesystem;
pub mod handlers;
pub mod router;
pub mod store;
pub use store::ApiKeyStore;

use crate::storage::filesystem::StorableEntity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// API Key record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    /// Unique identifier (UUID)
    pub id: String,

    /// Human-readable name
    pub name: String,

    /// The identifier/key value (can be UUID or custom)
    pub key: String,

    /// Optional description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Tags for organization
    #[serde(default)]
    pub tags: Vec<String>,

    /// When the key was created
    pub created_at: DateTime<Utc>,

    /// When the key was last updated
    pub updated_at: DateTime<Utc>,

    /// Whether the key is currently active
    #[serde(default = "default_active")]
    pub active: bool,

    /// Optional DID associated with this API key for identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<String>,
}

impl StorableEntity for ApiKey {
    fn id(&self) -> &str {
        &self.id
    }
}

fn default_active() -> bool {
    true
}

/// API Key list item (without the actual key value for security)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKeyListItem {
    pub id: String,
    pub name: String,
    /// The API key ID (same as id, for consistency with secrets/certificates)
    pub key_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub active: bool,
}

/// Request to create a new API key
#[derive(Debug, Clone, Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub key: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default = "default_active")]
    pub active: bool,
    #[serde(default)]
    pub identity_did: Option<String>,
}

/// Request to update an existing API key
#[derive(Debug, Clone, Deserialize)]
pub struct UpdateApiKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<String>,
}
