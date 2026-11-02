use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use std::path::PathBuf;
use uuid::Uuid;

use crate::encryption::EncryptionService;
use crate::storage::filesystem::{StorableEntity, StorageBackend, global_encryption_service, uncached_storage};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Integration {
    pub id: String,
    pub name: String,
    pub description: String,
    #[serde(rename = "type")]
    pub integration_type: String,
    /// Category determines which runtime variables are available (general, connection_point, user, gateway, channel)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Connection/authentication configuration (SMTP settings, webhook URLs, etc.)
    pub configuration: JsonValue,
    /// Message content template (subject, body, text, etc. with ${VARIABLE} placeholders)
    pub content: JsonValue,
    pub status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl StorableEntity for Integration {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Integration {
    pub fn new(
        name: String,
        description: String,
        integration_type: String,
        configuration: JsonValue,
        content: JsonValue,
        status: String,
        category: Option<String>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            id: Uuid::new_v4().to_string(),
            name,
            description,
            integration_type,
            category,
            configuration,
            content,
            status,
            tenant_id: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

pub struct IntegrationStorage {
    storage: Box<dyn StorageBackend<Integration>>,
    storage_path: PathBuf,
    encryption: Option<EncryptionService>,
}

impl IntegrationStorage {
    pub async fn new(storage_path: PathBuf) -> Result<Self> {
        Self::new_with_encryption(storage_path, global_encryption_service()).await
    }

    pub async fn new_with_encryption(
        storage_path: PathBuf,
        encryption: Option<EncryptionService>,
    ) -> Result<Self> {
        let storage = uncached_storage(storage_path.clone(), "integration").await?;
        Ok(Self {
            storage,
            storage_path,
            encryption,
        })
    }

    fn active_encryption(&self) -> Option<&EncryptionService> {
        self.encryption
            .as_ref()
            .filter(|service| service.is_enabled())
    }

    #[allow(dead_code)]
    pub fn get_storage_path(&self) -> &PathBuf {
        &self.storage_path
    }

    pub async fn save(
        &self,
        integration: &Integration,
    ) -> Result<()> {
        self.storage
            .save(integration)
            .await?;

        // Invalidate cache for this integration
        tokio::spawn({
            let id = integration.id.clone();
            async move {
                crate::integrations::cache::invalidate_integration_cache(&id).await;
            }
        });

        Ok(())
    }

    pub async fn load(
        &self,
        id: &str,
    ) -> Result<Integration> {
        self.find(id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("Integration not found: {}", id))
    }

    /// The integration with `id`, or `None` when no such integration exists.
    pub async fn find(
        &self,
        id: &str,
    ) -> Result<Option<Integration>> {
        self.storage.get(id).await
    }

    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        // Check existence first for a clear error
        if !self
            .storage
            .exists(id)
            .await?
        {
            anyhow::bail!("Integration not found: {}", id);
        }

        self.storage
            .delete(id)
            .await?;

        // Invalidate cache for this integration
        tokio::spawn({
            let id = id.to_string();
            async move {
                crate::integrations::cache::invalidate_integration_cache(&id).await;
            }
        });

        Ok(())
    }

    pub async fn list(&self) -> Result<Vec<Integration>> {
        let mut integrations = self
            .storage
            .list_all()
            .await?;

        // Sort by created_at descending (newest first)
        integrations.sort_by(|a, b| {
            b.created_at
                .cmp(&a.created_at)
        });

        Ok(integrations)
    }

    pub async fn update(
        &self,
        id: &str,
        integration: &Integration,
    ) -> Result<()> {
        // Verify the integration exists first
        if !self
            .storage
            .exists(id)
            .await?
        {
            anyhow::bail!("Integration not found: {}", id);
        }

        // Save will also invalidate cache
        self.save(integration).await
    }

    /// Save pipe integration triggers to the triggers storage
    pub async fn save_pipe_integrations(
        &self,
        pipe_id: &str,
        integrations: &[crate::pipes::config::PipeIntegrationMapping],
    ) -> Result<(), String> {
        // Get triggers/pipes directory under the integration storage path
        // storage_path is _storage/integrations/definitions
        // We need _storage/integrations/triggers/pipes
        let triggers_base = self
            .storage_path
            .parent()
            .ok_or_else(|| "Invalid storage path".to_string())?
            .join("triggers")
            .join("pipes");

        tokio::fs::create_dir_all(&triggers_base)
            .await
            .map_err(|e| format!("Failed to create triggers/pipes directory: {}", e))?;

        // Create pipe-specific directory
        let pipe_dir = triggers_base.join(pipe_id);
        tokio::fs::create_dir_all(&pipe_dir)
            .await
            .map_err(|e| format!("Failed to create surface directory: {}", e))?;

        // Convert pipe integrations to the trigger format
        let trigger_config = serde_json::json!({
            "integration_integrations": integrations
        });

        // Save the integrations file
        let integrations_path = pipe_dir.join("integrations.json");
        let json = serde_json::to_string_pretty(&trigger_config)
            .map_err(|e| format!("Failed to serialize integrations: {}", e))?;
        let content = match self.active_encryption() {
            Some(service) => service
                .encrypt_string(json)
                .map_err(|e| format!("Failed to encrypt integrations: {}", e))?,
            None => json,
        };
        tokio::fs::write(&integrations_path, content)
            .await
            .map_err(|e| format!("Failed to write integrations file: {}", e))?;

        tracing::info!(
            "✅ Saved {} integration triggers for pipe {} to {:?}",
            integrations.len(),
            pipe_id,
            integrations_path
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_notifier_creation() {
        let config = serde_json::json!({
            "to": ["admin@example.com"],
            "from": "gateway@example.com"
        });

        let integration = Integration::new(
            "Test Integration".to_string(),
            "Test description".to_string(),
            "email".to_string(),
            config.clone(),
            serde_json::json!({}),
            "active".to_string(),
            None,
        );

        assert_eq!(integration.name, "Test Integration");
        assert_eq!(integration.integration_type, "email");
        assert_eq!(integration.configuration, config);
        assert_eq!(integration.tenant_id, None);
        assert!(!integration.id.is_empty());
    }

    #[tokio::test]
    async fn test_storage_operations() {
        let dir = tempdir().unwrap();
        let storage = IntegrationStorage::new(dir.path().to_path_buf())
            .await
            .unwrap();

        let config = serde_json::json!({"key": "value"});
        let mut integration = Integration::new(
            "Test".to_string(),
            "Desc".to_string(),
            "email".to_string(),
            config,
            serde_json::json!({}),
            "active".to_string(),
            None,
        );
        integration.tenant_id = Some("tenant-a".into());

        // Save
        storage
            .save(&integration)
            .await
            .unwrap();

        // Load
        let loaded = storage
            .load(&integration.id)
            .await
            .unwrap();
        assert_eq!(loaded.name, integration.name);
        assert_eq!(loaded.tenant_id.as_deref(), Some("tenant-a"));

        // List
        let all = storage.list().await.unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        storage
            .delete(&integration.id)
            .await
            .unwrap();
        assert!(
            storage
                .load(&integration.id)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn enabled_encryption_writes_ciphertext_for_pipe_integrations() {
        use crate::encryption::{EncryptionService, KeySource};

        let dir = tempdir().unwrap();
        let storage_path = dir.path().join("definitions");
        let service = EncryptionService::new(KeySource::Raw { key: [7u8; 32] }).unwrap();
        let storage = IntegrationStorage::new_with_encryption(storage_path, Some(service))
            .await
            .unwrap();

        let mapping = crate::pipes::config::PipeIntegrationMapping {
            integration_id: "secret-integration-id".to_string(),
            event_types: vec!["pipe.executed".to_string()],
            variables: serde_json::json!({ "SMTP_PASSWORD": "super-secret-value" }),
        };

        storage
            .save_pipe_integrations("pipe-1", std::slice::from_ref(&mapping))
            .await
            .unwrap();

        let integrations_path = dir
            .path()
            .join("triggers")
            .join("pipes")
            .join("pipe-1")
            .join("integrations.json");
        let on_disk = tokio::fs::read_to_string(&integrations_path)
            .await
            .unwrap();

        assert!(on_disk.starts_with("ENC["), "expected encrypted envelope, got: {on_disk}");
        assert!(!on_disk.contains("secret-integration-id"));
        assert!(!on_disk.contains("super-secret-value"));
    }
}
