pub use super::ConnectionPointStore;
use anyhow::Result;
use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use subtle::ConstantTimeEq;
use tokio::sync::Mutex;
use tracing::info;

use super::store::InvitationConsumeError;
use super::types::{ConnectionPointType, GatewayConnectionPoint};
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// File system implementation of ConnectionPointStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemConnectionPointStore {
    base_path: PathBuf,
    storage: Box<dyn StorageBackend<GatewayConnectionPoint>>,
    invitation_mutation: Mutex<()>,
}

impl FileSystemConnectionPointStore {
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        let storage = cached_storage(base_path.clone(), "connection_point").await?;
        info!(
            "Loaded {} connection point(s) from {}",
            storage
                .list_all()
                .await?
                .len(),
            base_path.display()
        );
        Ok(Self {
            base_path,
            storage,
            invitation_mutation: Mutex::new(()),
        })
    }

    /// Clean up orphaned connection point directories (those without metadata.json)
    /// These are leftover DID secret folders from failed or incomplete connection attempts
    pub async fn cleanup_orphaned_directories(&self) -> Result<usize> {
        use tracing::{info, warn};

        let mut cleaned = 0;
        let mut dir = tokio::fs::read_dir(&self.base_path).await?;

        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            let dir_name = entry.file_name();

            // Skip the special "pending" directory and JSON files
            if dir_name == "pending"
                || path
                    .extension()
                    .and_then(|s| s.to_str())
                    == Some("json")
            {
                continue;
            }

            // Only process directories
            if path.is_dir() {
                let metadata_path = self
                    .base_path
                    .join(format!("{}.json", dir_name.to_string_lossy()));

                // Check if a corresponding {id}.json file exists at the base level
                // (new format stores metadata as {id}.json, keys in {id}/ subdirectory)
                let base_json = self
                    .base_path
                    .join(format!("{}.json", dir_name.to_string_lossy()));

                // If no metadata.json inside AND no {id}.json at base level, this is orphaned
                if !metadata_path.exists() && !base_json.exists() {
                    info!("Cleaning up orphaned connection point directory: {:?}", dir_name);

                    match tokio::fs::remove_dir_all(&path).await {
                        Ok(_) => {
                            cleaned += 1;
                        }
                        Err(e) => {
                            warn!("Failed to remove orphaned directory {:?}: {}", dir_name, e);
                        }
                    }
                }
            }
        }

        if cleaned > 0 {
            info!(
                "✓ Cleaned up {} orphaned connection point director{}",
                cleaned,
                if cleaned == 1 {
                    "y"
                } else {
                    "ies"
                }
            );
        }

        Ok(cleaned)
    }
}

#[async_trait]
impl ConnectionPointStore for FileSystemConnectionPointStore {
    async fn create(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        self.storage
            .save(connection_point)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<GatewayConnectionPoint>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn list_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>> {
        let mut connection_points = self
            .storage
            .list_all()
            .await?;
        connection_points.retain(|cp| cp.gateway_id == gateway_id);

        // Sort by creation date (newest first)
        connection_points.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(connection_points)
    }

    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()> {
        // Update is the same as store
        self.storage
            .save(connection_point)
            .await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    async fn consume_invitation(
        &self,
        id: &str,
        parent_thread_id: &str,
        presented_capability: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<GatewayConnectionPoint, InvitationConsumeError> {
        let _guard = self
            .invitation_mutation
            .lock()
            .await;
        let mut connection_point = self
            .storage
            .get(id)
            .await
            .map_err(|error| InvitationConsumeError::Storage(error.to_string()))?
            .ok_or(InvitationConsumeError::NotFound)?;

        if connection_point.cp_type != ConnectionPointType::User || !connection_point.enabled {
            return Err(InvitationConsumeError::InvalidState);
        }
        if connection_point
            .expires_at
            .is_some_and(|expires_at| expires_at <= now)
        {
            return Err(InvitationConsumeError::Expired);
        }
        if connection_point.use_count > 0
            || connection_point
                .secret
                .is_empty()
        {
            return Err(InvitationConsumeError::AlreadyConsumed);
        }
        let expected_thread = connection_point
            .oob_message
            .get("id")
            .and_then(|value| value.as_str())
            .filter(|value| !value.is_empty())
            .unwrap_or(&connection_point.oob_id);
        if expected_thread.is_empty() || expected_thread != parent_thread_id {
            return Err(InvitationConsumeError::ThreadMismatch);
        }

        let expected_hash = Sha256::digest(
            connection_point
                .secret
                .as_bytes(),
        );
        let presented_hash = Sha256::digest(presented_capability.as_bytes());
        if !bool::from(
            expected_hash
                .as_slice()
                .ct_eq(presented_hash.as_slice()),
        ) {
            return Err(InvitationConsumeError::InvalidCapability);
        }

        connection_point.use_count = connection_point
            .use_count
            .saturating_add(1);
        connection_point.last_used_at = Some(now);
        self.storage
            .save_atomic(&connection_point)
            .await
            .map_err(|error| InvitationConsumeError::Storage(error.to_string()))?;
        Ok(connection_point)
    }

    async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn invitation(now: chrono::DateTime<chrono::Utc>) -> GatewayConnectionPoint {
        GatewayConnectionPoint::new(
            "gateway-1".to_string(),
            "mediator-1".to_string(),
            "did:example:inviter".to_string(),
            "Invitation".to_string(),
            String::new(),
            "mediator-oob-1".to_string(),
            String::new(),
            serde_json::json!({"id": "invitation-message-1"}),
            Some(now + chrono::Duration::minutes(5)),
            ConnectionPointType::User,
            "correct-secret".to_string(),
        )
    }

    async fn store() -> (tempfile::TempDir, Arc<FileSystemConnectionPointStore>) {
        let dir = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FileSystemConnectionPointStore::new(dir.path().to_path_buf())
                .await
                .unwrap(),
        );
        (dir, store)
    }

    #[tokio::test]
    async fn valid_capability_is_consumed_once() {
        let (_dir, store) = store().await;
        let now = chrono::Utc::now();
        let invitation = invitation(now);
        store
            .create(&invitation)
            .await
            .unwrap();

        let consumed = store
            .consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now)
            .await
            .unwrap();
        assert_eq!(consumed.use_count, 1);
        assert_eq!(consumed.secret, "correct-secret");
        assert!(matches!(
            store
                .consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now)
                .await,
            Err(InvitationConsumeError::AlreadyConsumed)
        ));
    }

    #[tokio::test]
    async fn invalid_state_thread_and_capability_do_not_consume() {
        let (_dir, store) = store().await;
        let now = chrono::Utc::now();
        let mut invitation = invitation(now);
        store
            .create(&invitation)
            .await
            .unwrap();

        assert!(matches!(
            store
                .consume_invitation(&invitation.id, "wrong-thread", "correct-secret", now)
                .await,
            Err(InvitationConsumeError::ThreadMismatch)
        ));
        assert!(matches!(
            store
                .consume_invitation(&invitation.id, "invitation-message-1", "wrong-secret", now)
                .await,
            Err(InvitationConsumeError::InvalidCapability)
        ));

        invitation.enabled = false;
        store
            .update(&invitation)
            .await
            .unwrap();
        assert!(matches!(
            store
                .consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now)
                .await,
            Err(InvitationConsumeError::InvalidState)
        ));
    }

    #[tokio::test]
    async fn expired_capability_is_rejected() {
        let (_dir, store) = store().await;
        let now = chrono::Utc::now();
        let mut invitation = invitation(now);
        invitation.expires_at = Some(now - chrono::Duration::seconds(1));
        store
            .create(&invitation)
            .await
            .unwrap();

        assert!(matches!(
            store
                .consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now)
                .await,
            Err(InvitationConsumeError::Expired)
        ));
    }

    #[tokio::test]
    async fn concurrent_consumption_has_one_winner() {
        let (_dir, store) = store().await;
        let now = chrono::Utc::now();
        let invitation = invitation(now);
        store
            .create(&invitation)
            .await
            .unwrap();

        let first = store.consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now);
        let second = store.consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", now);
        let (first, second) = tokio::join!(first, second);
        assert_eq!(usize::from(first.is_ok()) + usize::from(second.is_ok()), 1);
    }
}
