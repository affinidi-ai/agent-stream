//! Filesystem-based secrets storage
//!
//! Stores secrets as encrypted JSON files in the filesystem
//! Uses UncachedFilesystemStorage to ensure secrets are never cached in memory

use crate::secrets::EncryptedSecret;
use crate::storage::filesystem::{StorageBackend, uncached_storage};

use super::{CreateSecretRequest, Secret, SecretListItem, SecretsStore, UpdateSecretRequest};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use std::path::PathBuf;
use tracing::info;
use uuid::Uuid;

/// Filesystem-based secrets store using uncached storage for security
pub struct FilesystemSecretsStore {
    storage: Box<dyn StorageBackend<EncryptedSecret>>,
    secret_id_index: DashMap<String, String>,
}

impl FilesystemSecretsStore {
    /// Create a new filesystem secrets store using uncached storage
    pub async fn new_async(path: &str) -> Result<Self> {
        let storage_path = PathBuf::from(path);
        let storage = uncached_storage(storage_path, "secret").await?;

        Ok(Self {
            storage,
            secret_id_index: DashMap::new(),
        })
    }

    /// Create a new filesystem secrets store (synchronous wrapper)
    pub fn new(path: &str) -> Result<Self> {
        // Use tokio runtime to call async version
        tokio::task::block_in_place(|| tokio::runtime::Handle::current().block_on(Self::new_async(path)))
    }

    /// Load a secret from disk and decrypt
    async fn load(
        &self,
        id: &str,
    ) -> Result<Option<Secret>> {
        if let Some(encrypted_secret) = self.storage.get(id).await? {
            let secret = Secret::from(encrypted_secret);
            Ok(Some(secret))
        } else {
            Ok(None)
        }
    }

    /// Encrypt and save a secret to disk
    async fn save(
        &self,
        secret: &Secret,
    ) -> Result<()> {
        let encrypted_secret = EncryptedSecret::from(secret.clone());
        self.storage
            .save(&encrypted_secret)
            .await
    }

    async fn rebuild_secret_id_index(&self) -> Result<()> {
        let secrets = self
            .storage
            .list_all()
            .await?;

        self.secret_id_index.clear();
        for secret in secrets {
            self.secret_id_index
                .insert(secret.secret_id, secret.id);
        }

        Ok(())
    }

    async fn load_by_secret_id_index(
        &self,
        secret_id: &str,
    ) -> Result<Option<Secret>> {
        let Some(internal_id) = self
            .secret_id_index
            .get(secret_id)
            .map(|entry| entry.value().clone())
        else {
            return Ok(None);
        };

        match self
            .load(&internal_id)
            .await?
        {
            Some(secret) if secret.secret_id == secret_id => Ok(Some(secret)),
            Some(_) | None => {
                self.secret_id_index
                    .remove(secret_id);
                Ok(None)
            }
        }
    }
}

#[async_trait]
impl SecretsStore for FilesystemSecretsStore {
    async fn create(
        &self,
        request: CreateSecretRequest,
    ) -> Result<Secret> {
        super::validate_secret_id(&request.secret_id).map_err(|message| anyhow::anyhow!(message))?;
        // Check if secret_id already exists
        if self
            .get_by_secret_id(&request.secret_id)
            .await?
            .is_some()
        {
            return Err(anyhow::anyhow!("A secret with secret_id '{}' already exists", request.secret_id));
        }

        let now = Utc::now();
        let secret = Secret {
            id: Uuid::new_v4().to_string(),
            name: request.name,
            secret_id: request.secret_id,
            description: request.description,
            value: request.value,
            secret_type: request.secret_type,
            tags: request.tags,
            tenant_id: request.tenant_id,
            created_at: now,
            updated_at: now,
        };

        self.save(&secret).await?;
        self.secret_id_index
            .insert(secret.secret_id.clone(), secret.id.clone());

        info!("Created secret: {} ({}) with secret_id: {}", secret.name, secret.id, secret.secret_id);

        Ok(secret)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Secret>> {
        self.load(id).await
    }

    async fn get_by_secret_id(
        &self,
        secret_id: &str,
    ) -> Result<Option<Secret>> {
        if let Some(secret) = self
            .load_by_secret_id_index(secret_id)
            .await?
        {
            return Ok(Some(secret));
        }

        self.rebuild_secret_id_index()
            .await?;
        self.load_by_secret_id_index(secret_id)
            .await
    }

    async fn list_all(&self) -> Result<Vec<SecretListItem>> {
        let encrypted_secrets = self
            .storage
            .list_all()
            .await?;
        let mut secrets: Vec<SecretListItem> = encrypted_secrets
            .into_iter()
            .map(|encrypted| Secret::from(encrypted).into())
            .collect();

        // Sort by name
        secrets.sort_by(|a, b| a.name.cmp(&b.name));

        Ok(secrets)
    }

    async fn update(
        &self,
        id: &str,
        request: UpdateSecretRequest,
    ) -> Result<Secret> {
        // Load the original secret (with decrypted value) for comparison and return
        let original_secret = self
            .load(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Secret not found: {}", id))?;

        let mut secret = original_secret.clone();
        let mut has_changes = false;

        if let Some(name) = request.name
            && secret.name != name
        {
            secret.name = name;
            has_changes = true;
        }
        if secret.description != request.description {
            secret.description = request.description;
            has_changes = true;
        }
        if request
            .update_value
            .unwrap_or(false)
            && let Some(value) = request.value
        {
            secret.value = value;
            has_changes = true;
        }
        if let Some(tags) = request.tags
            && secret.tags != tags
        {
            secret.tags = tags;
            has_changes = true;
        }
        if let Some(secret_type) = request.secret_type
            && secret.secret_type != secret_type
        {
            secret.secret_type = secret_type;
            has_changes = true;
        }

        if !has_changes {
            info!("No changes detected for secret: {} ({})", secret.name, secret.id);
            return Ok(secret);
        }

        secret.updated_at = Utc::now();

        self.save(&secret)
            .await
            .context("Failed to write secret file")?;

        Ok(secret)
    }

    async fn set_tenant_id(
        &self,
        id: &str,
        tenant_id: Option<String>,
    ) -> Result<Secret> {
        let mut secret = self
            .load(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Secret not found: {}", id))?;
        secret.tenant_id = tenant_id;
        secret.updated_at = Utc::now();
        self.save(&secret)
            .await
            .context("Failed to write secret file")?;
        Ok(secret)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let secret = self
            .load(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Secret not found: {}", id))?;

        self.storage
            .delete(id)
            .await?;
        self.secret_id_index
            .remove(&secret.secret_id);

        info!("Deleted secret: {}", id);

        Ok(())
    }

    async fn find_by_tag(
        &self,
        tag: &str,
    ) -> Result<Vec<SecretListItem>> {
        let all_secrets = self.list_all().await?;

        Ok(all_secrets
            .into_iter()
            .filter(|s| {
                s.tags
                    .iter()
                    .any(|t| t == tag)
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_get_by_secret_id_returns_secret_with_distinct_internal_id() {
        let dir = tempdir().unwrap();
        let store = FilesystemSecretsStore::new_async(dir.path().to_str().unwrap())
            .await
            .unwrap();

        let created = store
            .create(CreateSecretRequest {
                name: "BDD Secret".to_string(),
                secret_id: "bdd-secret".to_string(),
                description: None,
                value: "top-secret".to_string(),
                secret_type: "General".to_string(),
                tags: vec![],
                tenant_id: Some("tenant-a".into()),
            })
            .await
            .unwrap();

        assert_ne!(created.id, created.secret_id);

        let loaded = store
            .get_by_secret_id("bdd-secret")
            .await
            .unwrap()
            .unwrap();

        assert_eq!(loaded.id, created.id);
        assert_eq!(loaded.secret_id, "bdd-secret");
        assert_eq!(loaded.value, "top-secret");
        assert_eq!(loaded.tenant_id.as_deref(), Some("tenant-a"));
    }

    #[tokio::test]
    async fn update_changes_updated_at_for_metadata_and_value_edits() {
        let dir = tempdir().unwrap();
        let store = FilesystemSecretsStore::new_async(dir.path().to_str().unwrap())
            .await
            .unwrap();

        let created = store
            .create(CreateSecretRequest {
                name: "Timestamped secret".to_string(),
                secret_id: "timestamped-secret".to_string(),
                description: None,
                value: "initial-value".to_string(),
                secret_type: "General".to_string(),
                tags: vec![],
                tenant_id: None,
            })
            .await
            .unwrap();

        let metadata_updated = store
            .update(
                &created.id,
                UpdateSecretRequest {
                    name: Some("Renamed secret".to_string()),
                    description: None,
                    value: None,
                    update_value: None,
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(metadata_updated.created_at, created.created_at);
        assert!(metadata_updated.updated_at > created.updated_at);

        let no_op = store
            .update(
                &created.id,
                UpdateSecretRequest {
                    name: None,
                    description: None,
                    value: None,
                    update_value: None,
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(no_op.updated_at, metadata_updated.updated_at);

        let value_updated = store
            .update(
                &created.id,
                UpdateSecretRequest {
                    name: None,
                    description: None,
                    value: Some("rotated-value".to_string()),
                    update_value: Some(true),
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .unwrap();

        assert_eq!(value_updated.value, "rotated-value");
        assert_eq!(value_updated.created_at, created.created_at);
        assert!(value_updated.updated_at > metadata_updated.updated_at);
    }

    fn create_request(secret_id: &str) -> CreateSecretRequest {
        CreateSecretRequest {
            name: secret_id.to_string(),
            secret_id: secret_id.to_string(),
            description: None,
            value: "value".to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
            tenant_id: None,
        }
    }

    #[tokio::test]
    async fn every_secret_id_the_store_accepts_is_referenceable() {
        let root = tempdir().unwrap();
        let store = store_at(&root.path().join("secrets")).await;

        for secret_id in ["acct:key", "my key", "team/key", "key@corp", "key+1"] {
            assert!(
                store
                    .create(create_request(secret_id))
                    .await
                    .is_err(),
                "the store created {secret_id:?}, which no reference can name"
            );
        }
        assert!(
            store
                .list_all()
                .await
                .unwrap()
                .is_empty(),
            "a refused secret was stored"
        );

        let created = store
            .create(create_request("acct-key.v1"))
            .await
            .expect("an id-shaped secret_id is accepted");
        let resolved = crate::secrets::resolve_reference(&store, "acct-key.v1")
            .await
            .unwrap()
            .expect("an accepted secret_id resolves");
        assert_eq!(resolved.id, created.id);
    }

    async fn store_at(dir: &std::path::Path) -> FilesystemSecretsStore {
        std::fs::create_dir_all(dir).unwrap();
        FilesystemSecretsStore::new_async(dir.to_str().unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn a_reference_never_reaches_a_file_outside_the_store() {
        let root = tempdir().unwrap();
        let store_dir = root.path().join("secrets");
        let elsewhere_dir = root.path().join("elsewhere");
        let store = store_at(&store_dir).await;
        let elsewhere = store_at(&elsewhere_dir).await;
        let outside = elsewhere
            .create(CreateSecretRequest {
                name: "Outside".to_string(),
                secret_id: "outside".to_string(),
                description: None,
                value: "outside-value".to_string(),
                secret_type: "General".to_string(),
                tags: vec![],
                tenant_id: None,
            })
            .await
            .unwrap();
        let references = [
            format!("../elsewhere/{}", outside.id),
            elsewhere_dir
                .join(&outside.id)
                .to_string_lossy()
                .to_string(),
        ];

        for reference in &references {
            assert!(
                crate::secrets::resolve_reference(&store, reference)
                    .await
                    .unwrap()
                    .is_none(),
                "{reference:?} resolved to a secret outside the store"
            );
            assert!(
                store
                    .get(reference)
                    .await
                    .unwrap()
                    .is_none(),
                "the store loaded {reference:?} from outside its directory"
            );
        }
        assert!(
            elsewhere
                .get(&outside.id)
                .await
                .unwrap()
                .is_some(),
            "precondition: the outside secret exists"
        );
        assert!(
            store
                .delete(&references[0])
                .await
                .is_err(),
            "a delete must refuse a path"
        );
        assert!(
            elsewhere
                .get(&outside.id)
                .await
                .unwrap()
                .is_some(),
            "a delete through a path removed a secret outside the store"
        );
    }
}
