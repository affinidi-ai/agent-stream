//! Team storage backend.
//!
//! File-backed, DashMap-cached storage for [`Team`] configurations, mirroring
//! [`crate::pipes::filesystem::FileSystemPipeStore`]. Stored under
//! `_storage/teams`, authoritative cache in memory, immediate disk writes.

use crate::server::mode::ReloadOnPromotion;
use crate::storage::filesystem::{StorageBackend, rwlock_storage};
use crate::teams::types::Team;
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::warn;

/// Process-wide team store, registered at startup so the data-plane team gate
/// can resolve a caller's teams without threading the store through every
/// surface handler.
static GLOBAL_TEAM_STORE: OnceLock<Arc<FileSystemTeamStore>> = OnceLock::new();

/// Register the process-wide team store. First write wins.
pub fn set_global_team_store(store: Arc<FileSystemTeamStore>) {
    let _ = GLOBAL_TEAM_STORE.set(store);
}

/// Access the process-wide team store, if one has been registered.
pub fn global_team_store() -> Option<Arc<FileSystemTeamStore>> {
    GLOBAL_TEAM_STORE
        .get()
        .cloned()
}

/// File-based storage for team configurations.
pub struct FileSystemTeamStore {
    storage: Box<dyn StorageBackend<Team>>,
}

impl FileSystemTeamStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = rwlock_storage(storage_path, "team").await?;
        Ok(Self { storage })
    }

    /// Get a team by id.
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<Team> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// List all teams.
    pub async fn list(&self) -> Vec<Team> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Create or update a team. De-duplicates member ids and stamps
    /// `updated_at` before persisting.
    pub async fn save(
        &self,
        mut team: Team,
    ) -> Result<()> {
        team.normalize();
        team.updated_at = chrono::Utc::now();
        self.storage.save(&team).await
    }

    /// Whether a team with `id` exists.
    pub async fn exists(
        &self,
        id: &str,
    ) -> bool {
        self.storage
            .exists(id)
            .await
            .unwrap_or(false)
    }

    /// Hard-delete a team by id: physically remove the record from the cache and
    /// disk. Distinct from the soft-delete handler (which tombstones with
    /// `status = deleted`); used only by the debug-/test-mode-only purge path.
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    /// Seed team records from the default-config directory, creating each only
    /// when a team with the same id is absent so an admin's status/cap/membership
    /// edits are never overwritten on restart. Every `*.json` file is parsed and
    /// validated; the built-in anonymous team (and any future system team) is
    /// shipped here rather than hardcoded. Returns the number newly created.
    pub async fn seed_defaults(
        &self,
        seed_dir: &Path,
    ) -> Result<usize> {
        if !seed_dir.exists() {
            warn!("Team seed directory {} not found; no default teams seeded", seed_dir.display());
            return Ok(0);
        }
        let mut entries = tokio::fs::read_dir(seed_dir)
            .await
            .with_context(|| format!("reading team seed dir {}", seed_dir.display()))?;
        let mut seeded = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("scanning team seed dir {}", seed_dir.display()))?
        {
            let path = entry.path();
            if !path.is_file()
                || path
                    .extension()
                    .and_then(|e| e.to_str())
                    != Some("json")
            {
                continue;
            }
            let raw = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("reading team seed {}", path.display()))?;
            let team: Team =
                serde_json::from_str(&raw).with_context(|| format!("parsing team seed {}", path.display()))?;
            team.validate()
                .map_err(|e| anyhow::anyhow!("invalid team seed {}: {e}", path.display()))?;
            if self.exists(&team.id).await {
                continue;
            }
            self.save(team).await?;
            seeded += 1;
        }
        Ok(seeded)
    }

    /// Return every enabled team that `member_id` belongs to. Used at the
    /// request boundary to resolve which quotas a caller contributes to.
    pub async fn teams_for_member(
        &self,
        member_id: &str,
    ) -> Vec<Team> {
        self.list()
            .await
            .into_iter()
            .filter(|t| t.status.is_enabled() && t.has_member(member_id))
            .collect()
    }

    /// Return every non-deleted team that references `member_id`. Used when
    /// deleting a member so callers can detach it from its teams first. Deleted
    /// teams are tombstones and never block member deletion.
    pub async fn teams_referencing_member(
        &self,
        member_id: &str,
    ) -> Vec<Team> {
        self.list()
            .await
            .into_iter()
            .filter(|t| !t.status.is_deleted() && t.has_member(member_id))
            .collect()
    }
}

#[async_trait::async_trait]
impl ReloadOnPromotion for FileSystemTeamStore {
    /// Re-read the teams another instance stored, so a promoted standby
    /// gates callers on their current membership.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_status::EntityStatus;
    use crate::members::types::ANONYMOUS_MEMBER_ID;
    use crate::teams::types::ANONYMOUS_TEAM_ID;

    async fn store() -> FileSystemTeamStore {
        let dir = std::env::temp_dir().join(format!("team_store_{}", uuid::Uuid::new_v4()));
        FileSystemTeamStore::new(
            dir.to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap()
    }

    async fn seed_dir_with_anonymous() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("team_seed_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let json = r#"{"id":"anonymous","name":"Anonymous","status":"enabled","system":true,"members":["anonymous"]}"#;
        tokio::fs::write(dir.join("anonymous.json"), json)
            .await
            .unwrap();
        dir
    }

    #[tokio::test]
    async fn seed_defaults_creates_missing_system_team() {
        let store = store().await;
        let dir = seed_dir_with_anonymous().await;

        let n = store
            .seed_defaults(&dir)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let seeded = store
            .get(ANONYMOUS_TEAM_ID)
            .await
            .expect("anonymous team seeded");
        assert!(seeded.status.is_enabled());
        assert!(seeded.system);
        assert!(seeded.has_member(ANONYMOUS_MEMBER_ID));
    }

    #[tokio::test]
    async fn seed_defaults_does_not_overwrite_admin_edits() {
        let store = store().await;
        let dir = seed_dir_with_anonymous().await;
        store
            .seed_defaults(&dir)
            .await
            .unwrap();

        // Admin disables the anonymous team.
        let mut disabled = store
            .get(ANONYMOUS_TEAM_ID)
            .await
            .unwrap();
        disabled.status = EntityStatus::Disabled;
        store
            .save(disabled)
            .await
            .unwrap();

        // A second seed must not overwrite the admin's change.
        let n = store
            .seed_defaults(&dir)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let after = store
            .get(ANONYMOUS_TEAM_ID)
            .await
            .unwrap();
        assert_eq!(after.status, EntityStatus::Disabled);
    }

    #[tokio::test]
    async fn teams_for_member_excludes_disabled_team() {
        let store = store().await;
        store
            .seed_defaults(&seed_dir_with_anonymous().await)
            .await
            .unwrap();
        // Anonymous team is enabled ⇒ resolves for its member.
        assert_eq!(
            store
                .teams_for_member(ANONYMOUS_MEMBER_ID)
                .await
                .len(),
            1
        );
        // Disable it ⇒ no longer resolves.
        let mut disabled = store
            .get(ANONYMOUS_TEAM_ID)
            .await
            .unwrap();
        disabled.status = EntityStatus::Disabled;
        store
            .save(disabled)
            .await
            .unwrap();
        assert!(
            store
                .teams_for_member(ANONYMOUS_MEMBER_ID)
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn reload_picks_up_membership_another_instance_stored() {
        let dir = std::env::temp_dir().join(format!("team_shared_{}", uuid::Uuid::new_v4()));
        let path = dir
            .to_string_lossy()
            .to_string();
        let standby = FileSystemTeamStore::new(path.clone())
            .await
            .unwrap();
        let active = FileSystemTeamStore::new(path)
            .await
            .unwrap();
        active
            .seed_defaults(&seed_dir_with_anonymous().await)
            .await
            .unwrap();
        assert!(
            standby
                .teams_for_member(ANONYMOUS_MEMBER_ID)
                .await
                .is_empty()
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert_eq!(
            standby
                .teams_for_member(ANONYMOUS_MEMBER_ID)
                .await
                .len(),
            1
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
