//! Prompt storage backend.
//!
//! File-backed, cached storage for [`Prompt`] records, mirroring
//! [`crate::members::store::FileSystemMemberStore`]. Stored under
//! `_storage/prompts` (one `{id}.json` per prompt), authoritative cache in
//! memory, immediate disk writes.

use crate::prompts::types::Prompt;
use crate::storage::filesystem::{StorageBackend, rwlock_storage};
use anyhow::Result;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

/// Process-wide prompt store, registered at startup so the data-plane handler
/// can resolve a referenced prompt without threading the store through every
/// surface handler.
static GLOBAL_PROMPT_STORE: OnceLock<Arc<FileSystemPromptStore>> = OnceLock::new();

/// Register the process-wide prompt store. First write wins.
pub fn set_global_prompt_store(store: Arc<FileSystemPromptStore>) {
    let _ = GLOBAL_PROMPT_STORE.set(store);
}

/// Access the process-wide prompt store, if one has been registered.
pub fn global_prompt_store() -> Option<Arc<FileSystemPromptStore>> {
    GLOBAL_PROMPT_STORE
        .get()
        .cloned()
}

/// File-based storage for prompt records.
pub struct FileSystemPromptStore {
    storage: Box<dyn StorageBackend<Prompt>>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for FileSystemPromptStore {
    /// Re-read the Prompts another instance stored, so a promoted standby serves their current versions.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)
    }
}

impl FileSystemPromptStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = rwlock_storage(storage_path, "prompt").await?;
        Ok(Self { storage })
    }

    /// Get a prompt by id (including tombstoned ones).
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<Prompt> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// Get a prompt by id only when it is not tombstoned — the resolution used
    /// by the data-plane handler.
    pub async fn get_active(
        &self,
        id: &str,
    ) -> Option<Prompt> {
        self.get(id)
            .await
            .filter(|p| p.status.is_enabled())
    }

    /// List every prompt (including tombstoned ones).
    pub async fn list(&self) -> Vec<Prompt> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// List only non-tombstoned prompts.
    pub async fn list_active(&self) -> Vec<Prompt> {
        self.list()
            .await
            .into_iter()
            .filter(|p| p.status.is_enabled())
            .collect()
    }

    /// Create or update a prompt.
    pub async fn save(
        &self,
        prompt: &Prompt,
    ) -> Result<()> {
        self.storage
            .save(prompt)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mode::ReloadOnPromotion;

    #[tokio::test]
    async fn reload_picks_up_prompts_another_instance_stored() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .to_string_lossy()
            .into_owned();
        let standby = FileSystemPromptStore::new(path.clone())
            .await
            .unwrap();
        let prompt: Prompt = serde_json::from_value(serde_json::json!({ "id": "p1", "name": "Greeting" })).unwrap();
        FileSystemPromptStore::new(path)
            .await
            .unwrap()
            .save(&prompt)
            .await
            .unwrap();
        assert!(
            standby
                .get("p1")
                .await
                .is_none()
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert_eq!(
            standby
                .get("p1")
                .await
                .map(|p| p.name),
            Some("Greeting".to_string())
        );
    }
}
