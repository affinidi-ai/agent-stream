//! Per-surface drift baseline store: a small file-backed record of "what normal
//! looks like" for a surface — the mean of each drift dimension over a captured
//! window. Mirrors [`crate::prompts::store::FileSystemPromptStore`]. Baselines
//! are aggregate numbers (means), not sensitive content, so they are stored in
//! their own directory keyed by surface id.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};

use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};

/// A captured baseline for one surface: the mean of each drift dimension over
/// the window that was current when it was pinned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftBaseline {
    pub surface_id: String,
    /// RFC3339 timestamp the baseline was captured.
    pub captured_at: String,
    /// Width (seconds) of the window the baseline means were computed over.
    pub window_secs: i64,
    /// Dimension id → mean over the captured window.
    pub dimensions: HashMap<String, f64>,
}

impl StorableEntity for DriftBaseline {
    fn id(&self) -> &str {
        &self.surface_id
    }
}

/// File-backed store of per-surface drift baselines.
pub struct DriftBaselineStore {
    storage: Box<dyn StorageBackend<DriftBaseline>>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for DriftBaselineStore {
    /// Re-read the drift baselines another instance stored.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)
    }
}

impl DriftBaselineStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "drift_baseline").await?;
        Ok(Self { storage })
    }

    /// The baseline for a surface, if one has been pinned.
    pub async fn get(
        &self,
        surface_id: &str,
    ) -> Option<DriftBaseline> {
        self.storage
            .get(surface_id)
            .await
            .ok()
            .flatten()
    }

    /// Pin (create or replace) a surface's baseline.
    pub async fn save(
        &self,
        baseline: &DriftBaseline,
    ) -> Result<()> {
        self.storage
            .save(baseline)
            .await
    }

    /// Drop a surface's baseline (on surface delete or a clear action).
    pub async fn delete(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        self.storage
            .delete(surface_id)
            .await
    }
}

static GLOBAL: OnceLock<Arc<DriftBaselineStore>> = OnceLock::new();

/// Register the process-wide drift baseline store (orchestrator, once).
pub fn set_global_drift_baseline_store(store: Arc<DriftBaselineStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide drift baseline store, if registered.
pub fn global_drift_baseline_store() -> Option<Arc<DriftBaselineStore>> {
    GLOBAL.get().cloned()
}
