//! Filesystem-based API key storage
//!
//! Stores API keys as JSON files organized by agent:
//! ```text
//! _storage/api_keys/{agent_id}/{key_id}.json
//! ```

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use tokio::fs;
use tokio::time::{Duration, interval};
use tracing::{debug, info, warn};

use super::errors::{ApiKeyError, ApiKeyResult};
use super::generator::{constant_time_compare, hash_secret};
use super::models::{ApiKeyCreated, ApiKeyIssuer, ApiKeyMeta, ApiKeyRecord, ApiKeyStatus};
use super::traits::{ApiKeyStore, ApiKeyValidator};

/// Filesystem-based API key store
///
/// Uses a nested DashMap for lock-free concurrent access:
/// - Outer map: agent_id -> inner map
/// - Inner map: key_id -> ApiKeyRecord
pub struct FsApiKeyStore {
    /// Base storage directory
    storage_dir: PathBuf,
    /// In-memory cache: agent_id -> (key_id -> record)
    cache: Arc<DashMap<String, DashMap<String, ApiKeyRecord>>>,
    /// Per-agent secret-hash lookup: agent_id -> (secret_hash -> key_id).
    /// Legacy records without a hash are absent and must be rotated.
    hash_index: Arc<DashMap<String, DashMap<String, String>>>,
}

impl FsApiKeyStore {
    /// Create a new filesystem API key store
    ///
    /// # Arguments
    /// * `storage_path` - Base directory for API key storage
    pub async fn new(storage_path: &str) -> ApiKeyResult<Self> {
        let storage_dir = PathBuf::from(storage_path);

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_dir).await?;

        let store = Self {
            storage_dir,
            cache: Arc::new(DashMap::new()),
            hash_index: Arc::new(DashMap::new()),
        };

        // Load existing keys into cache
        store.load_all().await?;

        // NOTE: it is custom storage, with different logic compared to generic storage backend
        if crate::storage::filesystem::cache_refresh_enabled() {
            store.spawn_refresh_loop();
        }

        info!("Initialized FsApiKeyStore at: {}", store.storage_dir.display());

        Ok(store)
    }

    /// Get the directory path for an agent's keys
    fn agent_dir(
        &self,
        agent_id: &str,
    ) -> PathBuf {
        self.storage_dir
            .join(agent_id)
    }

    /// Get the file path for a specific key
    fn key_path(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> PathBuf {
        self.agent_dir(agent_id)
            .join(format!("{}.json", key_id))
    }

    /// Load all keys from disk into cache
    async fn load_all(&self) -> ApiKeyResult<()> {
        let mut entries = match fs::read_dir(&self.storage_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.is_dir()
                && let Some(agent_id) = path
                    .file_name()
                    .and_then(|n| n.to_str())
                && let Err(e) = self
                    .load_agent_keys(agent_id)
                    .await
            {
                warn!("Failed to load keys for agent {}: {}", agent_id, e);
            }
        }

        Ok(())
    }

    /// Load all keys for a specific agent
    async fn load_agent_keys(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<()> {
        let agent_dir = self.agent_dir(agent_id);
        let mut entries = match fs::read_dir(&agent_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e.into()),
        };

        let agent_cache = self
            .cache
            .entry(agent_id.to_string())
            .or_default();

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .and_then(|s| s.to_str())
                == Some("json")
            {
                match self
                    .load_key_file(&path)
                    .await
                {
                    Ok(record) => {
                        agent_cache.insert(record.key_id.clone(), record.clone());
                        self.index_secret_hash(&record);
                    }
                    Err(e) => {
                        warn!("Failed to load key file {:?}: {}", path, e);
                    }
                }
            }
        }

        debug!("Loaded {} keys for agent {}", agent_cache.len(), agent_id);

        Ok(())
    }

    /// Load a single key file
    async fn load_key_file(
        &self,
        path: &PathBuf,
    ) -> ApiKeyResult<ApiKeyRecord> {
        Self::load_key_file_static(path).await
    }

    async fn load_key_file_static(path: &PathBuf) -> ApiKeyResult<ApiKeyRecord> {
        let content = fs::read_to_string(path).await?;
        let mut value: serde_json::Value = serde_json::from_str(&content)?;
        let had_legacy_secret = value
            .as_object_mut()
            .and_then(|obj| obj.remove("secret"))
            .is_some();
        let record: ApiKeyRecord = serde_json::from_value(value)?;

        if had_legacy_secret {
            let sanitized = serde_json::to_string_pretty(&record)?;
            fs::write(path, sanitized).await?;
            warn!(
                key_id = %record.key_id,
                agent_id = %record.agent_id,
                "Removed legacy plaintext API key secret; key now requires rotation"
            );
        }

        Ok(record)
    }

    fn spawn_refresh_loop(&self) {
        let interval_secs = crate::storage::filesystem::cache_refresh_interval_secs();
        let storage_dir = self.storage_dir.clone();
        let cache = self.cache.clone();
        let hash_index = self.hash_index.clone();

        info!("spawning cache refresh loop for api_key at: {} (interval={}s)", storage_dir.display(), interval_secs);

        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(interval_secs));
            loop {
                ticker.tick().await;
                if let Err(e) =
                    FsApiKeyStore::refresh_cache_from_disk(&storage_dir, cache.clone(), hash_index.clone()).await
                {
                    warn!("Failed to refresh api_key cache from filesystem at {}: {}", storage_dir.display(), e);
                }
            }
        });
    }

    async fn refresh_cache_from_disk(
        storage_dir: &PathBuf,
        cache: Arc<DashMap<String, DashMap<String, ApiKeyRecord>>>,
        hash_index: Arc<DashMap<String, DashMap<String, String>>>,
    ) -> ApiKeyResult<()> {
        let mut next_cache: HashMap<String, HashMap<String, ApiKeyRecord>> = HashMap::new();

        let mut agent_entries = match fs::read_dir(storage_dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                cache.clear();
                hash_index.clear();
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        while let Some(agent_entry) = agent_entries
            .next_entry()
            .await?
        {
            let agent_path = agent_entry.path();
            if !agent_path.is_dir() {
                continue;
            }

            let Some(agent_id) = agent_path
                .file_name()
                .and_then(|n| n.to_str())
            else {
                continue;
            };

            let mut key_entries = match fs::read_dir(&agent_path).await {
                Ok(entries) => entries,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };

            let mut keys_for_agent: HashMap<String, ApiKeyRecord> = HashMap::new();
            while let Some(key_entry) = key_entries
                .next_entry()
                .await?
            {
                let key_path = key_entry.path();
                if key_path
                    .extension()
                    .and_then(|s| s.to_str())
                    != Some("json")
                {
                    continue;
                }

                match FsApiKeyStore::load_key_file_static(&key_path).await {
                    Ok(record) => {
                        keys_for_agent.insert(record.key_id.clone(), record);
                    }
                    Err(e) => {
                        warn!("Failed to load key file {:?}: {}", key_path, e);
                    }
                }
            }

            if !keys_for_agent.is_empty() {
                next_cache.insert(agent_id.to_string(), keys_for_agent);
            }
        }

        cache.clear();
        hash_index.clear();

        for (agent_id, keys_for_agent) in next_cache {
            let agent_cache: DashMap<String, ApiKeyRecord> = DashMap::new();
            let agent_hash_index: DashMap<String, String> = DashMap::new();

            for (key_id, record) in keys_for_agent {
                if let Some(secret_hash) = record.secret_hash.clone() {
                    agent_hash_index.insert(secret_hash, key_id.clone());
                }
                agent_cache.insert(key_id, record);
            }

            cache.insert(agent_id.clone(), agent_cache);
            if !agent_hash_index.is_empty() {
                hash_index.insert(agent_id, agent_hash_index);
            }
        }

        Ok(())
    }

    /// Save a key to disk and update cache
    async fn save_key(
        &self,
        record: &ApiKeyRecord,
    ) -> ApiKeyResult<()> {
        let agent_dir = self.agent_dir(&record.agent_id);
        fs::create_dir_all(&agent_dir).await?;

        let path = self.key_path(&record.agent_id, &record.key_id);
        let content = serde_json::to_string_pretty(record)?;
        fs::write(&path, content).await?;

        // Update cache
        let agent_cache = self
            .cache
            .entry(record.agent_id.clone())
            .or_default();
        if let Some(previous) = agent_cache.insert(record.key_id.clone(), record.clone())
            && let Some(previous_hash) = previous.secret_hash
        {
            self.unindex_secret_hash(&previous.agent_id, &previous_hash);
        }
        self.index_secret_hash(record);

        Ok(())
    }

    /// Delete a key from disk and cache
    async fn delete_key_file(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        let path = self.key_path(agent_id, key_id);

        if path.exists() {
            fs::remove_file(&path).await?;
        }

        // Update cache
        if let Some(agent_cache) = self.cache.get(agent_id)
            && let Some((_, record)) = agent_cache.remove(key_id)
            && let Some(secret_hash) = record.secret_hash
        {
            self.unindex_secret_hash(agent_id, &secret_hash);
        }

        Ok(())
    }

    /// Get a key record from cache (metadata plus secret verifier)
    fn get_from_cache(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> Option<ApiKeyRecord> {
        self.cache
            .get(agent_id)
            .and_then(|agent_cache| {
                agent_cache
                    .get(key_id)
                    .map(|r| r.clone())
            })
    }

    /// Insert or replace this record's `secret_hash -> key_id` entry.
    fn index_secret_hash(
        &self,
        record: &ApiKeyRecord,
    ) {
        if let Some(ref hash) = record.secret_hash {
            self.hash_index
                .entry(record.agent_id.clone())
                .or_default()
                .insert(hash.clone(), record.key_id.clone());
        }
    }

    /// Remove a single `secret_hash` entry from an agent's index.
    fn unindex_secret_hash(
        &self,
        agent_id: &str,
        secret_hash: &str,
    ) {
        if let Some(index) = self.hash_index.get(agent_id) {
            index.remove(secret_hash);
        }
    }

    /// Find a key by secret value (for validation) via the hash index.
    fn find_by_secret(
        &self,
        agent_id: &str,
        secret: &str,
    ) -> Option<ApiKeyRecord> {
        let presented_hash = hash_secret(secret);
        let key_id = self
            .hash_index
            .get(agent_id)
            .and_then(|index| {
                index
                    .get(&presented_hash)
                    .map(|entry| entry.value().clone())
            })?;

        let record = self.get_from_cache(agent_id, &key_id)?;
        match record.secret_hash {
            Some(ref stored_hash) if constant_time_compare(stored_hash, &presented_hash) => Some(record),
            _ => None,
        }
    }
}

#[async_trait]
impl ApiKeyStore for FsApiKeyStore {
    async fn create_with_material_and_expiry(
        &self,
        agent_id: &str,
        key_id: String,
        secret: String,
        client_id: &str,
        labels: Option<HashMap<String, String>>,
        actor: &str,
        expires_at: Option<DateTime<Utc>>,
    ) -> ApiKeyResult<ApiKeyCreated> {
        // Validate inputs
        if agent_id.is_empty() {
            return Err(ApiKeyError::validation("agent_id cannot be empty"));
        }
        if client_id.is_empty() {
            return Err(ApiKeyError::validation("client_id cannot be empty"));
        }
        if key_id.is_empty() || secret.is_empty() {
            return Err(ApiKeyError::validation("key material cannot be empty"));
        }

        let now = Utc::now();

        let record = ApiKeyRecord {
            key_id: key_id.clone(),
            agent_id: agent_id.to_string(),
            client_id: client_id.to_string(),
            secret_hash: Some(hash_secret(&secret)),
            status: ApiKeyStatus::Active,
            created_at: now,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            labels: labels.unwrap_or_default(),
            issuer: ApiKeyIssuer {
                actor: actor.to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };

        self.save_key(&record).await?;

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            client_id = %client_id,
            actor = %actor,
            "Created API key"
        );

        Ok(ApiKeyCreated {
            key_id,
            secret,
            agent_id: agent_id.to_string(),
            client_id: client_id.to_string(),
            created_at: now,
            expires_at,
            rotated_from: None,
        })
    }

    async fn list(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let keys: Vec<ApiKeyMeta> = self
            .cache
            .get(agent_id)
            .map(|agent_cache| {
                agent_cache
                    .iter()
                    .map(|entry| ApiKeyMeta::from(entry.value().clone()))
                    .collect()
            })
            .unwrap_or_default();

        Ok(keys)
    }

    async fn get(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyMeta>> {
        Ok(self
            .get_from_cache(agent_id, key_id)
            .map(ApiKeyMeta::from))
    }

    async fn revoke(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()> {
        let mut record = self
            .get_from_cache(agent_id, key_id)
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        if record.status == ApiKeyStatus::Revoked {
            return Err(ApiKeyError::AlreadyRevoked { key_id: key_id.to_string() });
        }

        record.status = ApiKeyStatus::Revoked;
        record.revoked_at = Some(Utc::now());

        self.save_key(&record).await?;

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            actor = %actor,
            "Revoked API key"
        );

        Ok(())
    }

    async fn rotate_with_material(
        &self,
        agent_id: &str,
        key_id: &str,
        new_key_id: String,
        new_secret: String,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        let old_record = self
            .get_from_cache(agent_id, key_id)
            .ok_or_else(|| ApiKeyError::not_found(key_id))?;

        if old_record.status == ApiKeyStatus::Revoked {
            return Err(ApiKeyError::AlreadyRevoked { key_id: key_id.to_string() });
        }

        // Revoke old key
        let mut revoked_record = old_record.clone();
        revoked_record.status = ApiKeyStatus::Revoked;
        revoked_record.revoked_at = Some(Utc::now());
        self.save_key(&revoked_record)
            .await?;

        let now = Utc::now();

        // Preserve the original key's intended lifetime on rotation: the new key
        // gets the same relative TTL measured from now (so rotating never yields
        // an already-expired key, and a non-expiring key stays non-expiring).
        let expires_at = old_record
            .expires_at
            .map(|old_expiry| now + (old_expiry - old_record.created_at));

        let new_record = ApiKeyRecord {
            key_id: new_key_id.clone(),
            agent_id: agent_id.to_string(),
            client_id: old_record.client_id.clone(),
            secret_hash: Some(hash_secret(&new_secret)),
            status: ApiKeyStatus::Active,
            created_at: now,
            expires_at,
            revoked_at: None,
            last_used_at: None,
            labels: old_record.labels.clone(),
            issuer: ApiKeyIssuer {
                actor: actor.to_string(),
                method: "rotation".to_string(),
            },
            rotated_from: Some(key_id.to_string()),
        };

        self.save_key(&new_record)
            .await?;

        info!(
            agent_id = %agent_id,
            old_key_id = %key_id,
            new_key_id = %new_key_id,
            actor = %actor,
            "Rotated API key"
        );

        Ok(ApiKeyCreated {
            key_id: new_key_id,
            secret: new_secret,
            agent_id: agent_id.to_string(),
            client_id: old_record.client_id,
            created_at: now,
            expires_at,
            rotated_from: Some(key_id.to_string()),
        })
    }

    async fn delete(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        if self
            .get_from_cache(agent_id, key_id)
            .is_none()
        {
            return Err(ApiKeyError::not_found(key_id));
        }

        self.delete_key_file(agent_id, key_id)
            .await?;

        info!(
            agent_id = %agent_id,
            key_id = %key_id,
            "Deleted API key"
        );

        Ok(())
    }

    async fn touch_usage(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        if let Some(mut record) = self.get_from_cache(agent_id, key_id) {
            record.last_used_at = Some(Utc::now());
            // Best-effort update, don't fail on error
            if let Err(e) = self.save_key(&record).await {
                debug!("Failed to update last_used_at for {}: {}", key_id, e);
            }
        }
        Ok(())
    }

    async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        let mut all = Vec::new();
        for agent_entry in self.cache.iter() {
            for key_entry in agent_entry.value().iter() {
                all.push(ApiKeyMeta::from(key_entry.value().clone()));
            }
        }
        all.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });
        Ok(all)
    }
}

#[async_trait]
impl ApiKeyValidator for FsApiKeyStore {
    async fn validate(
        &self,
        agent_id: &str,
        presented_key: &str,
    ) -> ApiKeyResult<Option<ApiKeyMeta>> {
        if let Some(record) = self.find_by_secret(agent_id, presented_key)
            && record.status == ApiKeyStatus::Active
            && !record.is_expired(Utc::now())
        {
            // Update last_used_at in background
            let store = self.cache.clone();
            let agent_id = agent_id.to_string();
            let key_id = record.key_id.clone();
            tokio::spawn(async move {
                if let Some(agent_cache) = store.get(&agent_id)
                    && let Some(mut entry) = agent_cache.get_mut(&key_id)
                {
                    entry.last_used_at = Some(Utc::now());
                }
            });

            return Ok(Some(ApiKeyMeta::from(record)));
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    async fn create_test_store() -> (FsApiKeyStore, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = FsApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        (store, temp_dir)
    }

    #[tokio::test]
    async fn test_create_and_list_keys() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        assert!(!created.key_id.is_empty());
        assert!(!created.secret.is_empty());
        assert_eq!(created.agent_id, "agent-1");
        assert_eq!(created.client_id, "client-1");

        let keys = store
            .list("agent-1")
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, created.key_id);
        assert_eq!(keys[0].status, ApiKeyStatus::Active);
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        store
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let key = store
            .get("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(key.status, ApiKeyStatus::Revoked);
        assert!(key.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_rotate_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        let rotated = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        assert_ne!(rotated.key_id, created.key_id);
        assert_ne!(rotated.secret, created.secret);
        assert_eq!(rotated.client_id, created.client_id);
        assert_eq!(rotated.rotated_from, Some(created.key_id.clone()));

        // Old key should be revoked
        let old_key = store
            .get("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(old_key.status, ApiKeyStatus::Revoked);
    }

    #[tokio::test]
    async fn test_validate_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        // Valid key
        let result = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert!(result.is_some());
        assert_eq!(result.unwrap().key_id, created.key_id);

        // Invalid key
        let result = store
            .validate("agent-1", "invalid-secret")
            .await
            .unwrap();
        assert!(result.is_none());

        // Revoked key
        store
            .revoke("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();
        let result = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_key() {
        let (store, _temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        store
            .delete("agent-1", &created.key_id)
            .await
            .unwrap();

        let key = store
            .get("agent-1", &created.key_id)
            .await
            .unwrap();
        assert!(key.is_none());
    }

    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        let created_secret = {
            let store = FsApiKeyStore::new(path)
                .await
                .unwrap();
            store
                .create("agent-1", "client-1", None, "test-actor")
                .await
                .unwrap()
                .secret
        };

        {
            let store = FsApiKeyStore::new(path)
                .await
                .unwrap();
            let keys = store
                .list("agent-1")
                .await
                .unwrap();
            assert_eq!(keys.len(), 1);

            let validated = store
                .validate("agent-1", &created_secret)
                .await
                .unwrap();
            assert!(validated.is_some());
        }
    }

    #[tokio::test]
    async fn test_created_key_persists_hash_only() {
        let (store, temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        let path = temp_dir
            .path()
            .join("agent-1")
            .join(format!("{}.json", created.key_id));
        let content = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(value.get("secret").is_none(), "raw secret must not be persisted");
        assert_eq!(
            value["secret_hash"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_ne!(
            value["secret_hash"]
                .as_str()
                .unwrap(),
            created.secret
        );
    }

    #[tokio::test]
    async fn test_rotated_key_persists_hash_only_and_validates_new_secret() {
        let (store, temp_dir) = create_test_store().await;

        let created = store
            .create("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();
        let rotated = store
            .rotate("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        assert!(
            store
                .validate("agent-1", &created.secret)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .validate("agent-1", &rotated.secret)
                .await
                .unwrap()
                .is_some()
        );

        let path = temp_dir
            .path()
            .join("agent-1")
            .join(format!("{}.json", rotated.key_id));
        let content = std::fs::read_to_string(path).unwrap();
        let value: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(value.get("secret").is_none(), "rotated raw secret must not be persisted");
        assert_eq!(
            value["secret_hash"]
                .as_str()
                .unwrap()
                .len(),
            64
        );
        assert_ne!(
            value["secret_hash"]
                .as_str()
                .unwrap(),
            rotated.secret
        );
    }

    #[tokio::test]
    async fn test_legacy_plaintext_record_is_sanitized_and_requires_rotation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();
        let legacy_file = agent_dir.join("legacy-key.json");
        std::fs::write(
            &legacy_file,
            r#"{
  "key_id": "legacy-key",
  "agent_id": "agent-1",
  "client_id": "client-1",
  "secret": "legacy-secret",
  "status": "active",
  "created_at": "2026-01-01T00:00:00Z",
  "expires_at": null,
  "revoked_at": null,
  "last_used_at": null,
  "labels": {},
  "issuer": { "actor": "legacy", "method": "migration" },
  "rotated_from": null
}"#,
        )
        .unwrap();

        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();
        let key = store
            .get("agent-1", "legacy-key")
            .await
            .unwrap()
            .unwrap();
        assert!(key.needs_rotation);
        assert!(
            store
                .validate("agent-1", "legacy-secret")
                .await
                .unwrap()
                .is_none()
        );

        let sanitized = std::fs::read_to_string(&legacy_file).unwrap();
        let value: serde_json::Value = serde_json::from_str(&sanitized).unwrap();
        assert!(value.get("secret").is_none(), "legacy raw secret must be removed on load");
        assert!(
            value
                .get("secret_hash")
                .is_none(),
            "legacy plaintext must not be converted into a verifier after exposure"
        );
    }

    #[tokio::test]
    async fn test_corrupted_json_file_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write a corrupted JSON file
        let corrupted_file = agent_dir.join("corrupted-key.json");
        std::fs::write(&corrupted_file, "{ invalid json }").unwrap();

        // Write a valid JSON file
        let valid_record = ApiKeyRecord {
            key_id: "valid-key".to_string(),
            agent_id: "agent-1".to_string(),
            client_id: "client-1".to_string(),
            secret_hash: Some(hash_secret("secret")),
            status: ApiKeyStatus::Active,
            created_at: Utc::now(),
            expires_at: None,
            revoked_at: None,
            last_used_at: None,
            labels: HashMap::new(),
            issuer: ApiKeyIssuer {
                actor: "test".to_string(),
                method: "api".to_string(),
            },
            rotated_from: None,
        };
        let valid_file = agent_dir.join("valid-key.json");
        std::fs::write(&valid_file, serde_json::to_string_pretty(&valid_record).unwrap()).unwrap();

        // Store should load successfully, skipping corrupted file
        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // Only the valid key should be loaded
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].key_id, "valid-key");
    }

    #[tokio::test]
    async fn test_expired_key_fails_validation() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();
        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();

        // A key that expired an hour ago must not authenticate.
        let past = Utc::now() - chrono::Duration::hours(1);
        let created = store
            .create_with_expiry("agent-1", "client-1", None, "test-actor", Some(past))
            .await
            .unwrap();
        let result = store
            .validate("agent-1", &created.secret)
            .await
            .unwrap();
        assert!(result.is_none(), "expired key must fail validation");

        // A key expiring in the future still authenticates.
        let future = Utc::now() + chrono::Duration::hours(1);
        let live = store
            .create_with_expiry("agent-1", "client-2", None, "test-actor", Some(future))
            .await
            .unwrap();
        let ok = store
            .validate("agent-1", &live.secret)
            .await
            .unwrap();
        assert!(ok.is_some(), "unexpired key must authenticate");
        assert_eq!(live.expires_at, Some(future));
    }

    #[tokio::test]
    async fn test_empty_file_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write an empty file
        let empty_file = agent_dir.join("empty-key.json");
        std::fs::write(&empty_file, "").unwrap();

        // Store should load successfully, skipping empty file
        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded from empty file
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_missing_required_fields_skipped() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write JSON with missing required fields
        let partial_json = r#"{"key_id": "partial", "agent_id": "agent-1"}"#;
        let partial_file = agent_dir.join("partial-key.json");
        std::fs::write(&partial_file, partial_json).unwrap();

        // Store should load successfully, skipping invalid file
        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_non_json_files_ignored() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir
            .path()
            .to_str()
            .unwrap();

        // Create agent directory
        let agent_dir = temp_dir
            .path()
            .join("agent-1");
        std::fs::create_dir_all(&agent_dir).unwrap();

        // Write files with different extensions
        std::fs::write(agent_dir.join("key.txt"), "not json").unwrap();
        std::fs::write(agent_dir.join(".hidden"), "hidden file").unwrap();
        std::fs::write(agent_dir.join("readme.md"), "# readme").unwrap();

        // Store should load successfully, ignoring non-json files
        let store = FsApiKeyStore::new(path)
            .await
            .unwrap();
        let keys = store
            .list("agent-1")
            .await
            .unwrap();

        // No keys should be loaded
        assert_eq!(keys.len(), 0);
    }

    #[tokio::test]
    async fn test_concurrent_operations() {
        let (store, _temp_dir) = create_test_store().await;
        let store = Arc::new(store);

        // Create multiple keys concurrently
        let mut handles = Vec::new();
        for i in 0..10 {
            let store_clone = store.clone();
            let client_id = format!("client-{}", i);
            handles.push(tokio::spawn(async move {
                store_clone
                    .create("agent-1", &client_id, None, "test-actor")
                    .await
            }));
        }

        // Wait for all to complete
        let results: Vec<_> = futures::future::join_all(handles).await;
        for result in results {
            assert!(result.unwrap().is_ok());
        }

        // Verify all keys were created
        let keys = store
            .list("agent-1")
            .await
            .unwrap();
        assert_eq!(keys.len(), 10);
    }

    #[tokio::test]
    async fn test_validation_empty_inputs() {
        let (store, _temp_dir) = create_test_store().await;

        // Empty agent_id should fail
        let result = store
            .create("", "client-1", None, "test-actor")
            .await;
        assert!(result.is_err());

        // Empty client_id should fail
        let result = store
            .create("agent-1", "", None, "test-actor")
            .await;
        assert!(result.is_err());
    }
}
