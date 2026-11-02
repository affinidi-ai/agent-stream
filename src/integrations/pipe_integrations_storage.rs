//! Storage for pipe-specific integration configurations
//!
//! Manages which integrations are attached to which pipes and what events trigger them.

use crate::storage::StorageBackend;
use crate::storage::filesystem::{StorableEntity, cached_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeIntegrationMapping {
    pub integration_id: String,
    pub event_types: Vec<String>,
    pub variables: HashMap<String, String>,
}

/// Wrapper for per-pipe integration config, keyed by pipe_id
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeIntegrationsConfig {
    pub pipe_id: String,
    pub integrations: Vec<PipeIntegrationMapping>,
}

impl StorableEntity for PipeIntegrationsConfig {
    fn id(&self) -> &str {
        &self.pipe_id
    }
}

/// Storage for pipe integration configurations
#[allow(dead_code)]
pub struct PipeIntegrationsStorage {
    storage: Box<dyn StorageBackend<PipeIntegrationsConfig>>,
}

#[allow(dead_code)]
impl PipeIntegrationsStorage {
    pub async fn new(base_path: PathBuf) -> Result<Self> {
        let storage = cached_storage(base_path, "pipe_integrations").await?;
        Ok(Self { storage })
    }

    /// Save integration configuration for a pipe
    pub async fn save_pipe_integrations(
        &self,
        pipe_id: &str,
        integrations: &[PipeIntegrationMapping],
    ) -> Result<()> {
        let config = PipeIntegrationsConfig {
            pipe_id: pipe_id.to_string(),
            integrations: integrations.to_vec(),
        };
        self.storage
            .save(&config)
            .await
    }

    /// Load integration configuration for a pipe
    pub async fn load_pipe_integrations(
        &self,
        pipe_id: &str,
    ) -> Result<Vec<PipeIntegrationMapping>> {
        Ok(self
            .storage
            .get(pipe_id)
            .await?
            .map(|c| c.integrations)
            .unwrap_or_default())
    }

    /// Get event types for a specific integration (for filtering)
    pub async fn get_integration_event_types(
        &self,
        integration_id: &str,
    ) -> Result<Vec<String>> {
        let mut all_event_types = Vec::new();

        let all_configs = self
            .storage
            .list_all()
            .await?;
        for config in all_configs {
            for integration in config.integrations {
                if integration.integration_id == integration_id {
                    all_event_types.extend(integration.event_types);
                }
            }
        }

        all_event_types.sort();
        all_event_types.dedup();
        Ok(all_event_types)
    }

    /// Get custom variables for a specific integration
    pub async fn get_integration_variables(
        &self,
        integration_id: &str,
    ) -> Result<HashMap<String, String>> {
        let mut all_variables = HashMap::new();

        let all_configs = self
            .storage
            .list_all()
            .await?;
        for config in all_configs {
            for integration in config.integrations {
                if integration.integration_id == integration_id {
                    all_variables.extend(integration.variables);
                }
            }
        }

        Ok(all_variables)
    }

    /// Delete integration configuration for a pipe
    pub async fn delete_pipe_integrations(
        &self,
        pipe_id: &str,
    ) -> Result<()> {
        self.storage
            .delete(pipe_id)
            .await
    }
}
