//! API Key service layer
//!
//! Provides business logic, audit logging, and metrics for API key operations.

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{info, warn};

use super::errors::ApiKeyResult;
use super::models::{ApiKeyCreated, ApiKeyMeta};
use super::traits::ApiKeyStore;

/// API Key service with audit logging and metrics
#[allow(unused)]
pub struct ApiKeyService<S: ApiKeyStore> {
    store: Arc<S>,
}

impl<S: ApiKeyStore> ApiKeyService<S> {
    /// Create a new API key service
    #[allow(dead_code)]
    pub fn new(store: Arc<S>) -> Self {
        Self { store }
    }

    /// Create a new API key
    ///
    /// Returns the key with its secret (shown only once).
    #[allow(unused)]
    pub async fn create_key(
        &self,
        agent_id: &str,
        client_id: &str,
        labels: Option<HashMap<String, String>>,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        let result = self
            .store
            .create(agent_id, client_id, labels, actor)
            .await;

        match &result {
            Ok(created) => {
                info!(
                    agent_id = %agent_id,
                    client_id = %client_id,
                    key_id = %created.key_id,
                    actor = %actor,
                    action = "api_key_created",
                    "API key created successfully"
                );
                // TODO: Emit metrics counter api_key_creations_total
            }
            Err(e) => {
                warn!(
                    agent_id = %agent_id,
                    client_id = %client_id,
                    actor = %actor,
                    error = %e,
                    action = "api_key_create_failed",
                    "Failed to create API key"
                );
            }
        }

        result
    }

    /// List all keys for an agent (metadata only)
    #[allow(unused)]
    pub async fn list_keys(
        &self,
        agent_id: &str,
    ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
        self.store
            .list(agent_id)
            .await
    }

    /// Get a specific key's metadata
    #[allow(unused)]
    pub async fn get_key(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<Option<ApiKeyMeta>> {
        self.store
            .get(agent_id, key_id)
            .await
    }

    /// Revoke a key
    #[allow(unused)]
    pub async fn revoke_key(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<()> {
        let result = self
            .store
            .revoke(agent_id, key_id, actor)
            .await;

        match &result {
            Ok(()) => {
                info!(
                    agent_id = %agent_id,
                    key_id = %key_id,
                    actor = %actor,
                    action = "api_key_revoked",
                    "API key revoked successfully"
                );
                // TODO: Emit metrics counter api_key_revocations_total
            }
            Err(e) => {
                warn!(
                    agent_id = %agent_id,
                    key_id = %key_id,
                    actor = %actor,
                    error = %e,
                    action = "api_key_revoke_failed",
                    "Failed to revoke API key"
                );
            }
        }

        result
    }

    /// Rotate a key (revoke old, create new with same client_id)
    #[allow(unused)]
    pub async fn rotate_key(
        &self,
        agent_id: &str,
        key_id: &str,
        actor: &str,
    ) -> ApiKeyResult<ApiKeyCreated> {
        let result = self
            .store
            .rotate(agent_id, key_id, actor)
            .await;

        match &result {
            Ok(created) => {
                info!(
                    agent_id = %agent_id,
                    old_key_id = %key_id,
                    new_key_id = %created.key_id,
                    actor = %actor,
                    action = "api_key_rotated",
                    "API key rotated successfully"
                );
                // TODO: Emit metrics counter api_key_rotations_total
            }
            Err(e) => {
                warn!(
                    agent_id = %agent_id,
                    key_id = %key_id,
                    actor = %actor,
                    error = %e,
                    action = "api_key_rotate_failed",
                    "Failed to rotate API key"
                );
            }
        }

        result
    }

    /// Delete a key permanently
    #[allow(unused)]
    pub async fn delete_key(
        &self,
        agent_id: &str,
        key_id: &str,
    ) -> ApiKeyResult<()> {
        let result = self
            .store
            .delete(agent_id, key_id)
            .await;

        if result.is_ok() {
            info!(
                agent_id = %agent_id,
                key_id = %key_id,
                action = "api_key_deleted",
                "API key deleted"
            );
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::FsApiKeyStore;
    use tempfile::TempDir;

    async fn create_test_service() -> (ApiKeyService<FsApiKeyStore>, TempDir) {
        let temp_dir = TempDir::new().unwrap();
        let store = FsApiKeyStore::new(
            temp_dir
                .path()
                .to_str()
                .unwrap(),
        )
        .await
        .unwrap();
        let service = ApiKeyService::new(Arc::new(store));
        (service, temp_dir)
    }

    #[tokio::test]
    async fn test_service_create_and_list() {
        let (service, _temp_dir) = create_test_service().await;

        let created = service
            .create_key("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        assert!(!created.key_id.is_empty());
        assert!(!created.secret.is_empty());

        let keys = service
            .list_keys("agent-1")
            .await
            .unwrap();
        assert_eq!(keys.len(), 1);
    }

    #[tokio::test]
    async fn test_service_revoke() {
        let (service, _temp_dir) = create_test_service().await;

        let created = service
            .create_key("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        service
            .revoke_key("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        let key = service
            .get_key("agent-1", &created.key_id)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(key.status, crate::api_keys::ApiKeyStatus::Revoked);
    }

    #[tokio::test]
    async fn test_service_rotate() {
        let (service, _temp_dir) = create_test_service().await;

        let created = service
            .create_key("agent-1", "client-1", None, "test-actor")
            .await
            .unwrap();

        let rotated = service
            .rotate_key("agent-1", &created.key_id, "test-actor")
            .await
            .unwrap();

        assert_ne!(rotated.key_id, created.key_id);
        assert_eq!(rotated.rotated_from, Some(created.key_id));
    }
}
