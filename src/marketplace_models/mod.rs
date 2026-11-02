pub mod types;

use anyhow::Result;
use async_trait::async_trait;
use std::path::PathBuf;

use crate::storage::filesystem::{StorageBackend, cached_storage};
pub use types::MarketplaceModel;

/// Trait for storing marketplace model configurations
#[async_trait]
#[allow(dead_code)]
pub trait MarketplaceModelStore: Send + Sync {
    async fn create(
        &self,
        model: &MarketplaceModel,
    ) -> Result<()>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<MarketplaceModel>>;
    async fn list_all(&self) -> Result<Vec<MarketplaceModel>>;
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;
    async fn update(
        &self,
        model: &MarketplaceModel,
    ) -> Result<()>;
}

/// Filesystem-based marketplace model store
pub struct FileSystemMarketplaceModelStore {
    storage: Box<dyn StorageBackend<MarketplaceModel>>,
}

impl FileSystemMarketplaceModelStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let storage = cached_storage(storage_dir, "marketplace_model").await?;
        Ok(Self { storage })
    }
}

#[async_trait]
impl MarketplaceModelStore for FileSystemMarketplaceModelStore {
    async fn create(
        &self,
        model: &MarketplaceModel,
    ) -> Result<()> {
        self.storage.save(model).await
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<MarketplaceModel>> {
        self.storage.get(id).await
    }

    async fn list_all(&self) -> Result<Vec<MarketplaceModel>> {
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
        model: &MarketplaceModel,
    ) -> Result<()> {
        self.storage.save(model).await
    }
}
