//! Filesystem-based API key storage

use super::{ApiKey, ApiKeyListItem, ApiKeyStore, CreateApiKeyRequest, UpdateApiKeyRequest};
use crate::storage::filesystem::{StorageBackend, cached_storage};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use tracing::info;
use uuid::Uuid;

/// Filesystem-based API key store
pub struct FilesystemApiKeyStore {
    storage: Box<dyn StorageBackend<ApiKey>>,
}

impl FilesystemApiKeyStore {
    /// Create a new filesystem API key store
    pub fn new(path: &str) -> Result<Self> {
        let storage_path = PathBuf::from(path);

        // Create directory if it doesn't exist
        std::fs::create_dir_all(&storage_path).context("Failed to create API keys storage directory")?;

        info!("Initialized filesystem API key store at: {}", storage_path.display());

        // Use tokio runtime to call async storage initialization
        let storage = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { cached_storage(storage_path, "api_key").await })
        })?;

        Ok(Self { storage })
    }
}

#[async_trait]
impl ApiKeyStore for FilesystemApiKeyStore {
    async fn create(
        &self,
        request: CreateApiKeyRequest,
    ) -> Result<ApiKey> {
        // Check if key already exists
        if self
            .validate_key(&request.key)
            .await?
            .is_some()
        {
            return Err(anyhow::anyhow!("An API key with this value already exists"));
        }

        let now = Utc::now();
        let key = ApiKey {
            id: Uuid::new_v4().to_string(),
            name: request.name,
            key: request.key,
            description: request.description,
            tags: request.tags,
            created_at: now,
            updated_at: now,
            active: request.active,
            identity_did: request.identity_did,
        };

        self.storage
            .save(&key)
            .await?;
        info!("Created API key: {} (id={})", key.name, key.id);

        Ok(key)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<ApiKey>> {
        self.storage.get(id).await
    }

    async fn validate_key(
        &self,
        key_value: &str,
    ) -> Result<Option<ApiKey>> {
        let all_keys = self
            .storage
            .list_all()
            .await?;

        for stored_key in all_keys {
            if stored_key.key == key_value && stored_key.active {
                return Ok(Some(stored_key));
            }
        }

        Ok(None)
    }

    async fn list_all(&self) -> Result<Vec<ApiKeyListItem>> {
        let keys = self
            .storage
            .list_all()
            .await?;
        let items = keys
            .into_iter()
            .map(|key| ApiKeyListItem {
                id: key.id.clone(),
                name: key.name,
                key_id: key.id,
                description: key.description,
                tags: key.tags,
                created_at: key.created_at,
                updated_at: key.updated_at,
                active: key.active,
            })
            .collect();

        Ok(items)
    }

    async fn update(
        &self,
        id: &str,
        request: UpdateApiKeyRequest,
    ) -> Result<ApiKey> {
        let mut key = self
            .storage
            .get(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("API key not found"))?;

        // Check if new key value conflicts with existing keys
        if let Some(ref new_key) = request.key
            && let Some(existing) = self
                .validate_key(new_key)
                .await?
            && existing.id != id
        {
            return Err(anyhow::anyhow!("An API key with this value already exists"));
        }

        if let Some(name) = request.name {
            key.name = name;
        }
        if let Some(new_key) = request.key {
            key.key = new_key;
        }
        if let Some(description) = request.description {
            key.description = Some(description);
        }
        if let Some(tags) = request.tags {
            key.tags = tags;
        }
        if let Some(active) = request.active {
            key.active = active;
        }

        if request.identity_did.is_some() {
            key.identity_did = request.identity_did;
        }
        key.updated_at = Utc::now();
        self.storage
            .save(&key)
            .await?;

        info!("Updated API key: {} (id={})", key.name, key.id);

        Ok(key)
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        if !self
            .storage
            .exists(id)
            .await?
        {
            return Err(anyhow::anyhow!("API key not found"));
        }

        self.storage
            .delete(id)
            .await?;
        info!("Deleted API key: id={}", id);

        Ok(())
    }
}
