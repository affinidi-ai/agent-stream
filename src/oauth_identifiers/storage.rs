//! OAuth Identifier storage.
//!
//! Defines the [`OAuthIdentifierStorage`] trait and the default
//! [`FileSystemOAuthIdentifierStore`] implementation, plus a process-global
//! accessor so reference-resolution sites (IDE bootstrap, sandbox) can reach the
//! store without threading it through every call.
//!
//! # Storage layout (filesystem)
//! ```text
//! _storage/
//! └── oauth_identifiers/
//!     ├── {uuid}.json
//!     └── ...
//! ```

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use tracing::info;
use uuid::Uuid;

use crate::oauth_identifiers::models::OAuthIdentifier;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

// ── Trait ────────────────────────────────────────────────────────────────────

/// Storage backend for OAuth Identifier profiles. Thread-safe, concurrent.
#[async_trait]
pub trait OAuthIdentifierStorage: Send + Sync {
    /// Create a new profile. `id`, `created_at`, `updated_at` are populated
    /// automatically; any supplied values are ignored.
    async fn create(
        &self,
        profile: OAuthIdentifier,
    ) -> Result<OAuthIdentifier>;

    /// Retrieve a profile by its UUID.
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<OAuthIdentifier>>;

    /// List all registered profiles.
    async fn list(&self) -> Result<Vec<OAuthIdentifier>>;

    /// Update an existing profile. Returns `Err` if it does not exist. `id` and
    /// `created_at` are preserved; `updated_at` is refreshed.
    async fn update(
        &self,
        profile: OAuthIdentifier,
    ) -> Result<OAuthIdentifier>;

    /// Delete a profile by its UUID. Silently succeeds if absent.
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
}

// ── Global accessor ────────────────────────────────────────────────────────────

static GLOBAL_OAUTH_IDENTIFIER_STORE: OnceLock<Arc<dyn OAuthIdentifierStorage>> = OnceLock::new();

/// Register the process-wide OAuth Identifier store. Idempotent — the first call
/// wins (subsequent calls are ignored).
pub fn set_global_oauth_identifier_store(store: Arc<dyn OAuthIdentifierStorage>) {
    let _ = GLOBAL_OAUTH_IDENTIFIER_STORE.set(store);
}

/// Access the process-wide OAuth Identifier store, if registered.
pub fn global_oauth_identifier_store() -> Option<Arc<dyn OAuthIdentifierStorage>> {
    GLOBAL_OAUTH_IDENTIFIER_STORE
        .get()
        .cloned()
}

// ── Filesystem implementation ─────────────────────────────────────────────────

/// OAuth Identifier profiles are keyed on their UUID for filesystem storage.
impl StorableEntity for OAuthIdentifier {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Filesystem-backed OAuth Identifier store. Each profile is persisted as
/// `{storage_dir}/{id}.json` through the generic storage backend (inheriting
/// encryption at rest and atomic writes); the backend's in-memory cache serves
/// all reads.
pub struct FileSystemOAuthIdentifierStore {
    storage: Box<dyn StorageBackend<OAuthIdentifier>>,
}

impl FileSystemOAuthIdentifierStore {
    /// Create (or open) the store at `storage_dir`, loading all existing profiles.
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "oauth_identifier")
            .await
            .context("Failed to open OAuth Identifier storage")?;
        let store = Self { storage };
        info!(
            "Initialised FileSystemOAuthIdentifierStore with {} profile(s)",
            store
                .storage
                .list_all()
                .await?
                .len()
        );
        Ok(store)
    }
}

#[async_trait]
impl OAuthIdentifierStorage for FileSystemOAuthIdentifierStore {
    async fn create(
        &self,
        mut profile: OAuthIdentifier,
    ) -> Result<OAuthIdentifier> {
        let now = Utc::now();
        if profile.id.is_empty() {
            profile.id = Uuid::new_v4().to_string();
        }
        profile.created_at = now;
        profile.updated_at = now;

        self.storage
            .save(&profile)
            .await?;
        info!("Created OAuth Identifier {} ({})", profile.name, profile.id);
        Ok(profile)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<OAuthIdentifier>> {
        self.storage.get(id).await
    }

    async fn list(&self) -> Result<Vec<OAuthIdentifier>> {
        let mut profiles = self
            .storage
            .list_all()
            .await?;
        profiles.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
        });
        Ok(profiles)
    }

    async fn update(
        &self,
        mut profile: OAuthIdentifier,
    ) -> Result<OAuthIdentifier> {
        let existing = self
            .storage
            .get(&profile.id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("OAuth Identifier not found: {}", profile.id))?;

        profile.created_at = existing.created_at;
        profile.updated_at = Utc::now();

        self.storage
            .save(&profile)
            .await?;
        info!("Updated OAuth Identifier {} ({})", profile.name, profile.id);
        Ok(profile)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage
            .delete(id)
            .await?;
        info!("Deleted OAuth Identifier {}", id);
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oauth_identifiers::models::{OAuthIdentifier, OAuthIdentifierShape};
    use tempfile::TempDir;

    async fn make_store() -> (FileSystemOAuthIdentifierStore, TempDir) {
        let tmp = TempDir::new().unwrap();
        let store = FileSystemOAuthIdentifierStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        (store, tmp)
    }

    fn sample() -> OAuthIdentifier {
        OAuthIdentifier {
            id: String::new(),
            name: "Test Entra".to_string(),
            description: String::new(),
            shape: OAuthIdentifierShape::Entra {
                tenant_id: "tenant-1".to_string(),
            },
            client_id: "client-1".to_string(),
            scopes: vec!["scope-a".to_string()],
            owner_tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn create_assigns_uuid_and_persists() {
        let (store, _tmp) = make_store().await;
        let p = store
            .create(sample())
            .await
            .unwrap();
        assert!(Uuid::parse_str(&p.id).is_ok());
        let found = store
            .get(&p.id)
            .await
            .unwrap();
        assert_eq!(found.unwrap().name, "Test Entra");
    }

    #[tokio::test]
    async fn create_preserves_preassigned_id() {
        let (store, _tmp) = make_store().await;
        let mut profile = sample();
        profile.id = "preauthorized-id".into();

        let created = store
            .create(profile)
            .await
            .unwrap();

        assert_eq!(created.id, "preauthorized-id");
        assert!(
            store
                .get("preauthorized-id")
                .await
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn update_preserves_created_at_and_refreshes_updated() {
        let (store, _tmp) = make_store().await;
        let mut p = store
            .create(sample())
            .await
            .unwrap();
        let created_at = p.created_at;
        p.name = "Renamed".to_string();
        let updated = store.update(p).await.unwrap();
        assert_eq!(updated.created_at, created_at);
        assert!(updated.updated_at >= created_at);
        assert_eq!(updated.name, "Renamed");
    }

    #[tokio::test]
    async fn update_missing_errors() {
        let (store, _tmp) = make_store().await;
        let mut p = sample();
        p.id = "missing".to_string();
        assert!(store.update(p).await.is_err());
    }

    #[tokio::test]
    async fn list_sorted_and_delete_removes() {
        let (store, _tmp) = make_store().await;
        let a = store
            .create(sample())
            .await
            .unwrap();
        let b = store
            .create(sample())
            .await
            .unwrap();
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 2);
        store
            .delete(&a.id)
            .await
            .unwrap();
        let list = store.list().await.unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, b.id);
    }

    #[tokio::test]
    async fn reload_from_disk_after_new_store() {
        let tmp = TempDir::new().unwrap();
        let created = {
            let store = FileSystemOAuthIdentifierStore::new(tmp.path().to_path_buf())
                .await
                .unwrap();
            store
                .create(sample())
                .await
                .unwrap()
        };
        // A fresh store over the same dir reloads the persisted profile.
        let store2 = FileSystemOAuthIdentifierStore::new(tmp.path().to_path_buf())
            .await
            .unwrap();
        let found = store2
            .get(&created.id)
            .await
            .unwrap();
        assert_eq!(found.unwrap().id, created.id);
    }

    fn encrypted_store_config() -> crate::storage::filesystem::StorageConfig {
        let service =
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap();
        crate::storage::filesystem::StorageConfig::default().with_encryption_service(service)
    }

    async fn encrypted_store(dir: PathBuf) -> FileSystemOAuthIdentifierStore {
        let storage = crate::storage::filesystem::cached_storage_with_config::<OAuthIdentifier>(
            dir,
            "oauth_identifier",
            encrypted_store_config(),
        )
        .await
        .unwrap();
        let storage: Box<dyn StorageBackend<OAuthIdentifier>> = Box::new(storage);
        FileSystemOAuthIdentifierStore { storage }
    }

    #[tokio::test]
    async fn encrypts_at_rest_and_reads_back() {
        let tmp = TempDir::new().unwrap();
        let store = encrypted_store(tmp.path().to_path_buf()).await;

        let created = store
            .create(sample())
            .await
            .unwrap();

        let enc_path = tmp
            .path()
            .join(format!("{}.json.enc", created.id));
        let raw_path = tmp
            .path()
            .join(format!("{}.json", created.id));
        assert!(enc_path.exists(), "encrypted sibling must be written");
        assert!(!raw_path.exists(), "plaintext sibling must not be written");

        let on_disk = std::fs::read(&enc_path).unwrap();
        assert!(
            !on_disk
                .windows(b"client-1".len())
                .any(|w| w == b"client-1"),
            "client_id must not appear in plaintext on disk"
        );

        let reopened = encrypted_store(tmp.path().to_path_buf()).await;
        let found = reopened
            .get(&created.id)
            .await
            .unwrap();
        assert_eq!(found.unwrap().client_id, "client-1");
    }

    #[tokio::test]
    async fn reads_legacy_plaintext_when_encryption_enabled() {
        let tmp = TempDir::new().unwrap();

        let mut profile = sample();
        profile.id = Uuid::new_v4().to_string();
        profile.created_at = Utc::now();
        profile.updated_at = Utc::now();
        let plaintext_path = tmp
            .path()
            .join(format!("{}.json", profile.id));
        std::fs::write(&plaintext_path, serde_json::to_string(&profile).unwrap()).unwrap();

        let store = encrypted_store(tmp.path().to_path_buf()).await;
        let found = store
            .get(&profile.id)
            .await
            .unwrap();
        assert_eq!(found.unwrap().name, "Test Entra");

        assert!(
            tmp.path()
                .join(format!("{}.json.enc", profile.id))
                .exists(),
            "legacy plaintext must be migrated to an encrypted file on load"
        );
        assert!(!plaintext_path.exists(), "legacy plaintext must be removed after migration");
    }
}
