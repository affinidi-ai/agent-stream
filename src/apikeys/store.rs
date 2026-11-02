//! API Key Store Trait

use async_trait::async_trait;

use super::{ApiKey, ApiKeyListItem, CreateApiKeyRequest, UpdateApiKeyRequest};

/// Trait for API key storage backends
#[async_trait]
pub trait ApiKeyStore: Send + Sync {
    /// Create a new API key
    async fn create(
        &self,
        request: CreateApiKeyRequest,
    ) -> anyhow::Result<ApiKey>;

    /// Get an API key by ID
    async fn get(
        &self,
        id: &str,
    ) -> anyhow::Result<Option<ApiKey>>;

    /// Validate an API key (check if it exists and is active)
    async fn validate_key(
        &self,
        key: &str,
    ) -> anyhow::Result<Option<ApiKey>>;

    /// List all API keys (returns list items without full key values)
    async fn list_all(&self) -> anyhow::Result<Vec<ApiKeyListItem>>;

    /// Update an API key
    async fn update(
        &self,
        id: &str,
        request: UpdateApiKeyRequest,
    ) -> anyhow::Result<ApiKey>;

    /// Delete an API key
    async fn delete(
        &self,
        id: &str,
    ) -> anyhow::Result<()>;
}
