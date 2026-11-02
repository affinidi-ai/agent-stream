pub use super::GatewayStore;
use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use super::types::{Gateway, GatewayType};
use crate::storage::filesystem::{StorageBackend, cached_storage};

/// Filesystem-based implementation of GatewayStore with in-memory cache
///
/// This implementation uses the generic `CachedFilesystemStorage` for all
/// file operations and caching, eliminating code duplication.
pub struct FileSystemGatewayStore {
    storage: Box<dyn StorageBackend<Gateway>>,
}

impl FileSystemGatewayStore {
    /// Create a new FileSystemGatewayStore with in-memory cache
    pub async fn new(
        storage_dir: PathBuf,
        proxy_did: Option<String>,
    ) -> Result<Self> {
        let storage = cached_storage(storage_dir, "gateway").await?;
        let store = Self { storage };

        let all_gateways = store.list_all().await?;
        if all_gateways.is_empty() {
            // First boot: create the self-gateway with the current proxy DID
            let did = proxy_did.unwrap_or_else(|| "did:web:localhost:8443".to_string());
            let self_gateway = Gateway::new(
                "This Gateway (Local)".to_string(),
                "This local Agent Stream instance".to_string(),
                did,
                GatewayType::SelfGateway,
            );
            store
                .create(&self_gateway)
                .await?;
        } else if let Some(new_did) = proxy_did {
            // Subsequent boots: sync the self-gateway DID if it was migrated (e.g. did:web → did:webvh)
            if let Some(mut self_gw) = all_gateways
                .into_iter()
                .find(|g| g.gateway_type == GatewayType::SelfGateway)
                && self_gw.did != new_did
            {
                tracing::info!("Updating self-gateway DID: {} → {}", self_gw.did, new_did);
                self_gw.did = new_did;
                store.update(&self_gw).await?;
            }
        }

        Ok(store)
    }
}

#[async_trait]
impl GatewayStore for FileSystemGatewayStore {
    async fn create(
        &self,
        gateway: &Gateway,
    ) -> Result<()> {
        self.storage
            .save(gateway)
            .await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Gateway>> {
        self.storage.get(id).await
    }

    async fn get_by_did(
        &self,
        did: &str,
    ) -> Result<Option<Gateway>> {
        let all = self
            .storage
            .list_all()
            .await?;
        Ok(all
            .into_iter()
            .find(|g| g.did == did))
    }

    async fn list_all(&self) -> Result<Vec<Gateway>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.storage.delete(id).await
    }

    async fn update(
        &self,
        gateway: &Gateway,
    ) -> Result<()> {
        // Update is the same as create for filesystem implementation
        self.storage
            .save(gateway)
            .await
    }
}
