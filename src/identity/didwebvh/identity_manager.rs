//! DID:webvh Identity Manager
//!
//! Manages UUID-based identity records for DID:webvh identities, providing
//! storage and retrieval operations for identities with their associated metadata.

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use super::types::{DidDocument, KeyPair};

use crate::encryption::EncryptionService;
use crate::storage::filesystem::global_encryption_service;

/// Metadata for a DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentity {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The DID:webvh string (e.g., did:webvh:example.com:alice)
    pub did: String,

    /// Signing key pair for this identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_pair: Option<KeyPair>,

    /// Current version number
    pub version: u64,

    /// Timestamp when created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Optional metadata about the agent
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// Whether this identity is active
    #[serde(default = "default_true")]
    pub active: bool,

    /// User who created the identity through the management API. `None` for
    /// identities the appliance created itself or that predate ownership.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
}

fn default_true() -> bool {
    true
}

/// Metadata key naming the connection point an identity was created for. Its
/// keys also live in the connection point's own key files, so the management
/// API treats such an identity as read-only.
pub(crate) const CONNECTION_POINT_METADATA_KEY: &str = "connection_point_id";

impl DidWebVhIdentity {
    pub(crate) fn is_connection_point_identity(&self) -> bool {
        self.metadata
            .contains_key(CONNECTION_POINT_METADATA_KEY)
    }
}

/// Whether `user_id` may manage an identity with this owner: the owner may,
/// and an identity without an owner is open to every caller holding
/// `identities.manage`.
pub(crate) fn may_manage(
    owner_user_id: Option<&str>,
    user_id: &str,
) -> bool {
    owner_user_id.is_none_or(|owner| owner == user_id)
}

fn extract_path_from_did(did: &str) -> Option<String> {
    let parsed = super::identifier::parse_did_webvh(did).ok()?;
    if parsed.path.is_empty() {
        return None;
    }

    Some(parsed.path.join("/"))
}

/// Create request for a new DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidRequest {
    /// Optional custom DID path (if not provided, UUID will be used)
    #[serde(alias = "path")]
    pub did_path: Option<String>,

    /// Agent metadata (code, model, deployment info, etc.)
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// Optional existing key pair (if not provided, new keys will be generated)
    pub key_pair: Option<KeyPair>,
}

/// Response from creating a DID:webvh identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateDidResponse {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The created DID:webvh string
    pub did: String,

    /// The initial DID document
    pub did_document: DidDocument,

    /// Timestamp when created
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// List item for DID:webvh identities (without sensitive key material)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DidWebVhIdentityListItem {
    /// Internal UUID identifier
    pub id: Uuid,

    /// The DID:webvh string
    pub did: String,

    /// Current version
    pub version: u64,

    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Last update timestamp
    pub updated_at: chrono::DateTime<chrono::Utc>,

    /// Whether active
    pub active: bool,

    /// Metadata summary (without sensitive data)
    #[serde(default)]
    pub metadata: HashMap<String, serde_json::Value>,

    /// Owning user, absent for an identity without an owner
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
}

impl From<DidWebVhIdentity> for DidWebVhIdentityListItem {
    fn from(identity: DidWebVhIdentity) -> Self {
        let DidWebVhIdentity {
            id,
            did,
            key_pair: _,
            version,
            created_at,
            updated_at,
            metadata,
            active,
            owner_user_id,
        } = identity;
        Self {
            id,
            did,
            version,
            created_at,
            updated_at,
            active,
            metadata,
            owner_user_id,
        }
    }
}

/// API view of a single DID:webvh identity.
///
/// It has no field for the private key, so key material cannot reach a
/// response. The exhaustive destructuring in the `From` impl makes a new field
/// on [`DidWebVhIdentity`] a compile error here, forcing a decision about
/// whether it may be exposed.
#[derive(Debug, Clone, Serialize)]
pub struct DidWebVhIdentityResponse {
    pub id: Uuid,
    pub did: String,
    /// Public key in JWK format
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_type: Option<String>,
    pub version: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub metadata: HashMap<String, serde_json::Value>,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,
}

impl From<DidWebVhIdentity> for DidWebVhIdentityResponse {
    fn from(identity: DidWebVhIdentity) -> Self {
        let DidWebVhIdentity {
            id,
            did,
            key_pair,
            version,
            created_at,
            updated_at,
            metadata,
            active,
            owner_user_id,
        } = identity;
        let (public_key, key_type) = match key_pair {
            Some(KeyPair {
                public_key,
                private_key: _,
                key_type,
            }) => (Some(super::create::strip_jwk_private_key(&public_key)), Some(key_type)),
            None => (None, None),
        };
        Self {
            id,
            did,
            public_key,
            key_type,
            version,
            created_at,
            updated_at,
            metadata,
            active,
            owner_user_id,
        }
    }
}

/// Trait for DID:webvh identity storage operations
#[async_trait]
pub trait DidWebVhIdentityStore: Send + Sync {
    /// Create a new DID:webvh identity
    async fn create(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()>;

    /// Get an identity by UUID
    async fn get(
        &self,
        id: &Uuid,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// Get an identity by DID string
    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// Get an identity by path (e.g., "agents/123" or "alice")
    async fn get_by_path(
        &self,
        path: &str,
    ) -> Result<Option<DidWebVhIdentity>>;

    /// List all identities
    async fn list(&self) -> Result<Vec<DidWebVhIdentityListItem>>;

    /// Update an existing identity
    async fn update(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()>;

    /// Delete an identity
    async fn delete(
        &self,
        id: &Uuid,
    ) -> Result<()>;
}

/// Filesystem-based implementation of DidWebVhIdentityStore
pub struct FileSystemDidWebVhIdentityStore {
    storage_path: PathBuf,
    cache: Arc<RwLock<HashMap<Uuid, DidWebVhIdentity>>>,
    did_index: Arc<RwLock<HashMap<String, Uuid>>>,  // DID -> UUID mapping
    path_index: Arc<RwLock<HashMap<String, Uuid>>>, // Path -> UUID mapping (e.g., "agents/123" -> UUID)
    encryption: Option<EncryptionService>,
}

impl FileSystemDidWebVhIdentityStore {
    /// Create a new filesystem-based identity store using the globally
    /// configured encryption service (when encryption at rest is enabled).
    pub async fn new(storage_path: impl AsRef<std::path::Path>) -> Result<Self> {
        Self::new_with_encryption(storage_path, global_encryption_service()).await
    }

    /// Create a new filesystem-based identity store with an explicit file-level
    /// encryption service. `None` (or a disabled service) persists plaintext.
    pub async fn new_with_encryption(
        storage_path: impl AsRef<std::path::Path>,
        encryption: Option<EncryptionService>,
    ) -> Result<Self> {
        let storage_path = storage_path
            .as_ref()
            .to_path_buf();

        // Create directory if it doesn't exist
        tokio::fs::create_dir_all(&storage_path)
            .await
            .context("Failed to create identity storage directory")?;

        let store = Self {
            storage_path,
            cache: Arc::new(RwLock::new(HashMap::new())),
            did_index: Arc::new(RwLock::new(HashMap::new())),
            path_index: Arc::new(RwLock::new(HashMap::new())),
            encryption,
        };

        // Load existing identities into cache
        store.load_all().await?;

        Ok(store)
    }

    /// Path for the plaintext on-disk representation.
    fn raw_path(
        &self,
        id: &Uuid,
    ) -> PathBuf {
        self.storage_path
            .join(format!("{}.json", id))
    }

    /// Path for the encrypted on-disk representation.
    fn enc_path(
        &self,
        id: &Uuid,
    ) -> PathBuf {
        self.storage_path
            .join(format!("{}.json.enc", id))
    }

    /// The active encryption service, only when it is enabled.
    fn active_encryption(&self) -> Option<&EncryptionService> {
        self.encryption
            .as_ref()
            .filter(|service| service.is_enabled())
    }

    /// Load all identities from disk into cache
    async fn load_all(&self) -> Result<()> {
        let mut entries = tokio::fs::read_dir(&self.storage_path).await?;
        let mut count = 0;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();

            let ext = path
                .extension()
                .and_then(|s| s.to_str());
            let is_encrypted = ext == Some("enc");
            let is_plaintext = ext == Some("json");

            // When an encrypted sibling already exists, the stale plaintext file
            // is skipped (the encrypted representation is authoritative).
            if is_plaintext
                && path
                    .with_extension("json.enc")
                    .exists()
            {
                continue;
            }

            if is_encrypted || is_plaintext {
                match self
                    .load_identity_from_file(&path)
                    .await
                {
                    Ok(identity) => {
                        // Migrate a legacy plaintext file to encryption at rest.
                        if is_plaintext
                            && self
                                .active_encryption()
                                .is_some()
                            && let Err(e) = self
                                .save_identity(&identity)
                                .await
                        {
                            warn!("Failed to migrate identity {} to encrypted storage: {}", identity.id, e);
                        }
                        let id = identity.id;
                        let did = identity.did.clone();
                        let path = extract_path_from_did(&did);

                        self.cache
                            .write()
                            .await
                            .insert(id, identity);
                        self.did_index
                            .write()
                            .await
                            .insert(did, id);
                        if let Some(path) = path {
                            self.path_index
                                .write()
                                .await
                                .insert(path, id);
                        }
                        count += 1;
                    }
                    Err(e) => {
                        error!("Failed to load identity from {:?}: {}", path, e);
                        crate::metrics::backends::prometheus::track_storage_load_error(
                            "didwebvh_identity",
                            identity_load_failure_reason(&e),
                        );
                    }
                }
            }
        }

        info!("Loaded {} DID:webvh identities from {}", count, self.storage_path.display());
        Ok(())
    }

    /// Load a single identity from file, decrypting when the on-disk content is
    /// an encrypted envelope.
    async fn load_identity_from_file(
        &self,
        path: &PathBuf,
    ) -> Result<DidWebVhIdentity> {
        let content = tokio::fs::read_to_string(path)
            .await
            .context("Failed to read identity file")?;

        let json = if content
            .trim_start()
            .starts_with("ENC[")
        {
            let service = self
                .active_encryption()
                .context("Encrypted identity file present but encryption is not configured")?;
            service
                .decrypt_string(content)
                .context("Failed to decrypt identity file")?
        } else {
            content
        };

        let identity: DidWebVhIdentity = serde_json::from_str(&json).context("Failed to parse identity JSON")?;

        Ok(identity)
    }

    /// Save an identity to disk, encrypting the whole file when encryption at
    /// rest is enabled.
    async fn save_identity(
        &self,
        identity: &DidWebVhIdentity,
    ) -> Result<()> {
        let content = serde_json::to_string_pretty(identity).context("Failed to serialize identity")?;

        if let Some(service) = self.active_encryption() {
            let encrypted = service
                .encrypt_string(content)
                .context("Failed to encrypt identity")?;
            let enc_path = self.enc_path(&identity.id);
            tokio::fs::write(&enc_path, encrypted)
                .await
                .context("Failed to write identity file")?;

            // Remove any stale plaintext file left from before encryption.
            let raw_path = self.raw_path(&identity.id);
            if raw_path.exists() {
                let _ = tokio::fs::remove_file(&raw_path).await;
            }

            debug!("Saved encrypted DID:webvh identity {} to {:?}", identity.did, enc_path);
        } else {
            let raw_path = self.raw_path(&identity.id);
            tokio::fs::write(&raw_path, content)
                .await
                .context("Failed to write identity file")?;

            debug!("Saved DID:webvh identity {} to {:?}", identity.did, raw_path);
        }

        Ok(())
    }
}

#[async_trait]
impl DidWebVhIdentityStore for FileSystemDidWebVhIdentityStore {
    async fn create(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()> {
        let id = identity.id;
        let did = identity.did.clone();

        // Check if ID already exists
        if self
            .cache
            .read()
            .await
            .contains_key(&id)
        {
            anyhow::bail!("Identity with ID {} already exists", id);
        }

        // Check if DID already exists
        if self
            .did_index
            .read()
            .await
            .contains_key(&did)
        {
            anyhow::bail!("Identity with DID {} already exists", did);
        }

        // Save to disk
        self.save_identity(&identity)
            .await?;

        // Extract path from DID for path index
        let path = extract_path_from_did(&did);

        // Update cache
        self.cache
            .write()
            .await
            .insert(id, identity);
        self.did_index
            .write()
            .await
            .insert(did.clone(), id);
        if let Some(path) = path {
            self.path_index
                .write()
                .await
                .insert(path, id);
        }

        info!("Created DID:webvh identity {}", id);
        Ok(())
    }

    async fn get(
        &self,
        id: &Uuid,
    ) -> Result<Option<DidWebVhIdentity>> {
        Ok(self
            .cache
            .read()
            .await
            .get(id)
            .cloned())
    }

    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<DidWebVhIdentity>> {
        let id = self
            .did_index
            .read()
            .await
            .get(did)
            .cloned();

        match id {
            Some(id) => self.get(&id).await,
            None => Ok(None),
        }
    }

    async fn get_by_path(
        &self,
        path: &str,
    ) -> Result<Option<DidWebVhIdentity>> {
        let id = self
            .path_index
            .read()
            .await
            .get(path)
            .cloned();

        match id {
            Some(id) => self.get(&id).await,
            None => Ok(None),
        }
    }

    async fn list(&self) -> Result<Vec<DidWebVhIdentityListItem>> {
        let cache = self.cache.read().await;
        let mut items: Vec<DidWebVhIdentityListItem> = cache
            .values()
            .map(|identity| identity.clone().into())
            .collect();

        // Sort by creation time (newest first)
        items.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(items)
    }

    async fn update(
        &self,
        identity: DidWebVhIdentity,
    ) -> Result<()> {
        let id = identity.id;
        let did = identity.did.clone();

        // Check if identity exists
        if !self
            .cache
            .read()
            .await
            .contains_key(&id)
        {
            anyhow::bail!("Identity with ID {} not found", id);
        }

        // Save to disk
        self.save_identity(&identity)
            .await?;

        // Update cache
        let old_did = self
            .cache
            .write()
            .await
            .insert(id, identity.clone());

        // Update DID and path indexes if DID changed
        if let Some(old_identity) = old_did
            && old_identity.did != did
        {
            // Remove old DID from index
            self.did_index
                .write()
                .await
                .remove(&old_identity.did);

            // Remove old path from index
            if let Some(old_path) = extract_path_from_did(&old_identity.did) {
                self.path_index
                    .write()
                    .await
                    .remove(&old_path);
            }

            // Add new DID to index
            self.did_index
                .write()
                .await
                .insert(did.clone(), id);

            // Add new path to index
            if let Some(new_path) = extract_path_from_did(&did) {
                self.path_index
                    .write()
                    .await
                    .insert(new_path, id);
            }
        }

        debug!("Updated DID:webvh identity {}", id);
        Ok(())
    }

    async fn delete(
        &self,
        id: &Uuid,
    ) -> Result<()> {
        // Get identity to find DID
        let identity = self
            .cache
            .read()
            .await
            .get(id)
            .cloned();

        if let Some(identity) = identity {
            // Remove whichever on-disk representation exists.
            for path in [self.enc_path(id), self.raw_path(id)] {
                if path.exists() {
                    tokio::fs::remove_file(&path)
                        .await
                        .context("Failed to delete identity file")?;
                }
            }

            // Remove from cache and indexes
            self.cache
                .write()
                .await
                .remove(id);
            self.did_index
                .write()
                .await
                .remove(&identity.did);

            // Remove path from index
            if let Some(path) = extract_path_from_did(&identity.did) {
                self.path_index
                    .write()
                    .await
                    .remove(&path);
            }

            info!("Deleted DID:webvh identity {}", id);
            Ok(())
        } else {
            anyhow::bail!("Identity with ID {} not found", id);
        }
    }
}

/// The `agent_stream_storage_load_errors_total` reason for an identity file
/// that failed to load with `error`: reading, parsing, or else decrypting it.
fn identity_load_failure_reason(error: &anyhow::Error) -> &'static str {
    match error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
    {
        Some(io) if io.kind() == std::io::ErrorKind::InvalidData => "parse_failed",
        Some(_) => "read_failed",
        None if error
            .chain()
            .any(|cause| cause.is::<serde_json::Error>()) =>
        {
            "parse_failed"
        }
        None => "decrypt_failed",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn identity_load_failure_reason_classifies_the_cause() {
        let read = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
            .context("Failed to read identity file");
        let parse = anyhow::Error::from(serde_json::from_str::<DidWebVhIdentity>("not json").unwrap_err())
            .context("Failed to parse identity JSON");
        let decrypt = anyhow::anyhow!("bad ciphertext").context("Failed to decrypt identity file");

        assert_eq!(identity_load_failure_reason(&read), "read_failed");
        assert_eq!(identity_load_failure_reason(&parse), "parse_failed");
        assert_eq!(identity_load_failure_reason(&decrypt), "decrypt_failed");
        let not_utf8 = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::InvalidData))
            .context("Failed to read identity file");
        assert_eq!(identity_load_failure_reason(&not_utf8), "parse_failed");
    }

    #[tokio::test]
    async fn an_unreadable_identity_file_is_skipped_and_counted() {
        let load_errors = |reason: &str| {
            crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
                .with_label_values(&["didwebvh_identity", reason])
                .get()
        };
        let dir = TempDir::new().unwrap();
        std::fs::write(dir.path().join("broken.json"), "not json").unwrap();
        let before = load_errors("parse_failed");

        let manager = FileSystemDidWebVhIdentityStore::new_with_encryption(dir.path(), None)
            .await
            .unwrap();

        assert!(load_errors("parse_failed") > before);
        drop(manager);
    }

    #[test]
    fn test_didwebvh_fix_create_request_accepts_legacy_path_alias() {
        let request: CreateDidRequest = serde_json::from_value(serde_json::json!({
            "path": "agents/test"
        }))
        .expect("legacy path alias should deserialize");

        assert_eq!(request.did_path.as_deref(), Some("agents/test"));
    }

    #[tokio::test]
    async fn test_private_key_is_encrypted_at_rest() {
        use crate::encryption::{EncryptionService, KeySource};

        let temp_dir = TempDir::new().unwrap();
        let service = EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap();

        let store = FileSystemDidWebVhIdentityStore::new_with_encryption(temp_dir.path(), Some(service.clone()))
            .await
            .unwrap();

        let secret = "super-secret-private-key-material";
        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:secret-agent".to_string(),
            key_pair: Some(KeyPair {
                public_key: serde_json::json!({ "kty": "OKP", "crv": "Ed25519", "x": "public-part" }),
                private_key: serde_json::json!(secret),
                key_type: "Ed25519".to_string(),
            }),
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        let enc_path = temp_dir
            .path()
            .join(format!("{}.json.enc", id));
        let raw_path = temp_dir
            .path()
            .join(format!("{}.json", id));
        assert!(enc_path.exists(), "encrypted file should be written");
        assert!(!raw_path.exists(), "plaintext file must not exist");

        let on_disk = std::fs::read_to_string(&enc_path).unwrap();
        assert!(on_disk.starts_with("ENC["), "on-disk content must be an encrypted envelope");
        assert!(!on_disk.contains(secret), "private key must not appear in plaintext on disk");

        // Reload from a fresh store instance and confirm the secret round-trips.
        let reloaded = FileSystemDidWebVhIdentityStore::new_with_encryption(temp_dir.path(), Some(service))
            .await
            .unwrap();
        let got = reloaded
            .get(&id)
            .await
            .unwrap()
            .expect("identity should reload");
        let private_key = got
            .key_pair
            .expect("key pair should be present")
            .private_key;
        assert_eq!(private_key, serde_json::json!(secret));
    }

    #[tokio::test]
    async fn test_create_and_get_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().did, identity.did);
    }

    #[tokio::test]
    async fn test_get_by_did() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:bob".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        let retrieved = store
            .get_by_did(&identity.did)
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, identity.id);
    }

    #[tokio::test]
    async fn test_get_by_path() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let identity = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:agents:123".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        // Test path lookup - "agents:123" -> "agents/123"
        let retrieved = store
            .get_by_path("agents/123")
            .await
            .unwrap();
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().id, identity.id);

        // Test simple path
        let identity2 = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:example.com:alice".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity2.clone())
            .await
            .unwrap();

        let retrieved2 = store
            .get_by_path("alice")
            .await
            .unwrap();
        assert!(retrieved2.is_some());
        assert_eq!(retrieved2.unwrap().id, identity2.id);

        // Test SCID-based format: did:webvh:<scid>:<domain>:<path>
        // The SCID (valid multihash) should be skipped so path = "agents/456"
        let identity3 = DidWebVhIdentity {
            id: Uuid::new_v4(),
            did: "did:webvh:QmYwAPJzv5CZsnAzt8auVZRnGzr1sM4KroPvLoM6P6sQKz:localhost%3A8080:agents:456".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };
        store
            .create(identity3.clone())
            .await
            .unwrap();
        let retrieved3 = store
            .get_by_path("agents/456")
            .await
            .unwrap();
        assert!(retrieved3.is_some(), "SCID-based DID must be findable by its path component");
        assert_eq!(retrieved3.unwrap().id, identity3.id);
    }

    #[tokio::test]
    async fn test_list_identities() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        for i in 0..3 {
            let identity = DidWebVhIdentity {
                id: Uuid::new_v4(),
                did: format!("did:webvh:example.com:user{}", i),
                key_pair: None,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
                active: true,
                owner_user_id: None,
            };
            store
                .create(identity)
                .await
                .unwrap();
        }

        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 3);
    }

    #[tokio::test]
    async fn test_update_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let mut identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:charlie".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity.clone())
            .await
            .unwrap();

        identity.version = 2;
        identity.updated_at = chrono::Utc::now();
        store
            .update(identity.clone())
            .await
            .unwrap();

        let retrieved = store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retrieved.version, 2);
    }

    #[tokio::test]
    async fn test_delete_identity() {
        let temp_dir = TempDir::new().unwrap();
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();

        let id = Uuid::new_v4();
        let identity = DidWebVhIdentity {
            id,
            did: "did:webvh:example.com:dave".to_string(),
            key_pair: None,
            version: 1,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            metadata: HashMap::new(),
            active: true,
            owner_user_id: None,
        };

        store
            .create(identity)
            .await
            .unwrap();
        store
            .delete(&id)
            .await
            .unwrap();

        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let id = Uuid::new_v4();

        {
            let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
                .await
                .unwrap();
            let identity = DidWebVhIdentity {
                id,
                did: "did:webvh:example.com:eve".to_string(),
                key_pair: None,
                version: 1,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                metadata: HashMap::new(),
                active: true,
                owner_user_id: None,
            };
            store
                .create(identity)
                .await
                .unwrap();
        }

        // Create new store instance to test loading from disk
        let store = FileSystemDidWebVhIdentityStore::new(temp_dir.path())
            .await
            .unwrap();
        let retrieved = store.get(&id).await.unwrap();
        assert!(retrieved.is_some());
    }
}
