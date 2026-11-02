//! Secrets Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

/// Secrets storage backend trait
#[async_trait]
pub trait SecretsStore: Send + Sync {
    /// Create a new secret
    async fn create(
        &self,
        request: CreateSecretRequest,
    ) -> Result<Secret>;

    /// Get a secret by internal storage ID (includes sensitive value)
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Secret>>;

    /// Get a secret by its public `secret_id` identifier.
    async fn get_by_secret_id(
        &self,
        secret_id: &str,
    ) -> Result<Option<Secret>> {
        let Some(secret) = self
            .list_all()
            .await?
            .into_iter()
            .find(|secret| secret.secret_id == secret_id)
        else {
            return Ok(None);
        };

        self.get(secret.id.as_str())
            .await
    }

    /// List all secrets (without sensitive values)
    async fn list_all(&self) -> Result<Vec<SecretListItem>>;

    /// Update a secret
    async fn update(
        &self,
        id: &str,
        request: UpdateSecretRequest,
    ) -> Result<Secret>;

    /// Change management-plane tenant ownership without exposing secret value mutation.
    async fn set_tenant_id(
        &self,
        _id: &str,
        _tenant_id: Option<String>,
    ) -> Result<Secret> {
        Err(anyhow::anyhow!("Tenant reassignment is not supported by this Secrets store"))
    }

    /// Delete a secret
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Search secrets by tag
    async fn find_by_tag(
        &self,
        tag: &str,
    ) -> Result<Vec<SecretListItem>>;
}

/// An in-memory secrets store for tests that need secrets resolved by internal
/// id and by public `secret_id` without a filesystem or encryption key.
#[cfg(test)]
pub(crate) mod memory {
    use super::*;
    use crate::secrets::Secret;

    #[derive(Default)]
    pub(crate) struct MemorySecretsStore {
        secrets: std::sync::Mutex<Vec<Secret>>,
    }

    impl MemorySecretsStore {
        pub(crate) fn with(secrets: Vec<Secret>) -> Self {
            Self {
                secrets: std::sync::Mutex::new(secrets),
            }
        }
    }

    /// A secret with the given internal id, public id, value and owner.
    pub(crate) fn secret(
        id: &str,
        secret_id: &str,
        value: &str,
        tenant_id: Option<&str>,
    ) -> Secret {
        let now = chrono::Utc::now();
        Secret {
            id: id.to_string(),
            name: secret_id.to_string(),
            secret_id: secret_id.to_string(),
            description: None,
            value: value.to_string(),
            secret_type: "General".to_string(),
            tags: Vec::new(),
            tenant_id: tenant_id.map(str::to_string),
            created_at: now,
            updated_at: now,
        }
    }

    #[async_trait]
    impl SecretsStore for MemorySecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not supported by the in-memory test store")
        }

        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<Secret>> {
            Ok(self
                .secrets
                .lock()
                .expect("store lock")
                .iter()
                .find(|secret| secret.id == id)
                .cloned())
        }

        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(self
                .secrets
                .lock()
                .expect("store lock")
                .iter()
                .cloned()
                .map(SecretListItem::from)
                .collect())
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not supported by the in-memory test store")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            anyhow::bail!("not supported by the in-memory test store")
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(Vec::new())
        }
    }
}
