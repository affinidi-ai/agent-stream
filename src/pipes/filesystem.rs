//! Pipe storage backend
//!
//! Uses RwLockFilesystemStorage for async-friendly cached storage

use crate::pipes::PipeConfig;
use crate::storage::filesystem::{StorageBackend, StorageEvent, cached_storage};
use anyhow::Result;
use std::path::PathBuf;

/// File-based storage for pipe configurations.
///
/// Backed by the DashMap-cached storage so it participates in the shared-storage
/// cache refresh (`cache_refresh_interval_secs`): the refresh loop picks up on-disk changes
/// (another node writing to shared storage) and emits [`StorageEvent`]s that
/// the orchestrator's pipe subscription applies to the live route table.
pub struct FileSystemPipeStore {
    storage: Box<dyn StorageBackend<PipeConfig>>,
}

impl FileSystemPipeStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = cached_storage(storage_path, "pipe").await?;

        Ok(Self { storage })
    }

    /// Subscribe to storage change events. `RemoteWrite` events are emitted by
    /// the cache-refresh loop when the on-disk pipe set changes;
    /// `LocalWrite` events are emitted by this node's own saves.
    pub fn subscribe(&self) -> Option<tokio::sync::broadcast::Receiver<StorageEvent<PipeConfig>>> {
        self.storage.subscribe()
    }

    /// Get a pipe by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<PipeConfig> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// List all pipes
    pub async fn list(&self) -> Vec<PipeConfig> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Save a pipe
    pub async fn save(
        &self,
        pipe: PipeConfig,
    ) -> Result<()> {
        // Update timestamp before saving
        let mut pipe = pipe;
        pipe.updated_at = Some(chrono::Utc::now().to_rfc3339());

        self.storage.save(&pipe).await
    }

    /// Check if a pipe exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> bool {
        self.storage
            .exists(id)
            .await
            .unwrap_or(false)
    }

    /// Hard-delete a pipe by id: physically remove it from the cache and disk.
    /// Distinct from the soft-delete handler (which tombstones with
    /// `status = deleted`); used only by the debug-/test-mode-only purge path.
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }
}
