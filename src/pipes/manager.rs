//! Pipe task manager for lifecycle management of LLM pipes

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::task::AbortHandle;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

use crate::observability::{TaskInfo, TaskMonitor, TaskStatus};
use crate::pipes::{FileSystemPipeStore, PipeConfig};

use crate::config::BootstrapConfig;
use crate::secrets::{FilesystemSecretsStore, SecretsStore};

/// Manages the lifecycle of pipe tasks (health checks, initialization)
#[derive(Clone)]
pub struct PipeTaskManager {
    /// Handles to running pipe health check tasks
    pipe_handles: Arc<RwLock<HashMap<String, AbortHandle>>>,
    /// Task IDs mapped by pipe ID (for TaskMonitor)
    task_ids: Arc<RwLock<HashMap<String, String>>>,
    /// Pipe store for accessing pipe configurations
    #[allow(dead_code)]
    pipe_store: Arc<FileSystemPipeStore>,
    /// Task monitor for tracking pipe status
    task_monitor: Option<Arc<TaskMonitor>>,
    /// Secrets store for loading API keys during health checks
    secrets_store: Arc<FilesystemSecretsStore>,
    /// Health check interval in seconds
    health_check_interval_secs: u64,
}

impl PipeTaskManager {
    pub fn new(
        pipe_store: Arc<FileSystemPipeStore>,
        task_monitor: Option<Arc<TaskMonitor>>,
        bootstrap_config: Arc<BootstrapConfig>,
    ) -> anyhow::Result<Self> {
        let secrets_store = FilesystemSecretsStore::new(
            &bootstrap_config
                .storage_paths
                .secrets,
        )
        .map_err(|e| anyhow::anyhow!("Failed to initialize secrets store: {}", e))?;

        Ok(Self {
            pipe_handles: Arc::new(RwLock::new(HashMap::new())),
            task_ids: Arc::new(RwLock::new(HashMap::new())),
            pipe_store,
            task_monitor,
            secrets_store: Arc::new(secrets_store),
            health_check_interval_secs: 60, // Default: check every 60 seconds
        })
    }

    /// Start monitoring a pipe (register task and start health checks)
    pub async fn start_pipe(
        &self,
        pipe: &PipeConfig,
    ) -> anyhow::Result<()> {
        if !pipe.status.is_enabled() {
            debug!("Skipping disabled pipe: {}", pipe.name);
            return Ok(());
        }

        let pipe_id = pipe.id.clone();
        let task_id = format!("pipe-{}", pipe_id);

        // Register with TaskMonitor if available
        if let Some(ref monitor) = self.task_monitor {
            let (provider, model, _endpoint) = self.extract_pipe_info(pipe);

            let initial_status = TaskStatus::Starting;

            // Present the surface's ingress as "<listen_address><route>" (e.g.
            // "0.0.0.0:8080/llm") so the Tasks view shows where the surface
            // accepts requests instead of a hardcoded "N/A". Fall back gracefully
            // when either part is unset.
            let listen_address = match (
                pipe.listen_address
                    .as_deref()
                    .filter(|s| !s.is_empty()),
                pipe.route
                    .as_deref()
                    .filter(|s| !s.is_empty()),
            ) {
                (Some(addr), Some(route)) => format!("{}{}", addr, route),
                (Some(addr), None) => addr.to_string(),
                (None, Some(route)) => route.to_string(),
                (None, None) => "N/A".to_string(),
            };

            let task_info = TaskInfo {
                task_id: task_id.clone(),
                config_id: Some(pipe_id.clone()),
                channel_name: pipe.name.clone(),
                listen_address,
                target_endpoint: format!("{}:{}", provider, model),
                started_at: Utc::now(),
                status: initial_status,
                total_connections: 0,
                active_connections: 0,
                bytes_sent: 0,
                bytes_received: 0,
                last_activity: None,
                error_count: 0,
                recent_bytes_sent: 0,
                recent_bytes_received: 0,
                recent_window_start: Utc::now(),
            };

            monitor
                .register_task(task_info)
                .await;
            info!("Registered pipe '{}' ({}) with TaskMonitor", pipe.name, provider);
        }

        // Store task ID
        {
            let mut task_ids = self.task_ids.write().await;
            task_ids.insert(pipe_id.clone(), task_id.clone());
        }

        // Start health check task
        let abort_handle = self
            .spawn_health_check_task(pipe.clone())
            .await;

        // Store abort handle
        {
            let mut handles = self
                .pipe_handles
                .write()
                .await;
            handles.insert(pipe_id.clone(), abort_handle);
        }

        info!("Started pipe: {} (id: {})", pipe.name, pipe_id);
        Ok(())
    }

    /// Stop monitoring a pipe (unregister and stop health checks)
    #[allow(dead_code)]
    pub async fn stop_pipe(
        &self,
        pipe_id: &str,
    ) -> anyhow::Result<()> {
        // Abort health check task
        {
            let mut handles = self
                .pipe_handles
                .write()
                .await;
            if let Some(handle) = handles.remove(pipe_id) {
                handle.abort();
                debug!("Aborted health check task for pipe: {}", pipe_id);
            }
        }

        // Unregister from TaskMonitor
        if let Some(ref monitor) = self.task_monitor {
            let task_ids = self.task_ids.read().await;
            if let Some(task_id) = task_ids.get(pipe_id) {
                monitor
                    .unregister_task(task_id)
                    .await;
                debug!("Unregistered pipe from TaskMonitor: {}", pipe_id);
            }
        }

        // Remove task ID
        {
            let mut task_ids = self.task_ids.write().await;
            task_ids.remove(pipe_id);
        }

        info!("Stopped pipe: {}", pipe_id);
        Ok(())
    }

    /// Restart a pipe (useful when configuration changes)
    #[allow(dead_code)]
    pub async fn restart_pipe(
        &self,
        pipe: &PipeConfig,
    ) -> anyhow::Result<()> {
        info!("Restarting pipe: {} (id: {})", pipe.name, pipe.id);
        self.stop_pipe(&pipe.id)
            .await?;
        self.start_pipe(pipe).await?;
        Ok(())
    }

    /// Stop all pipes
    #[allow(dead_code)]
    pub async fn stop_all(&self) {
        let pipe_ids: Vec<String> = {
            let handles = self.pipe_handles.read().await;
            handles
                .keys()
                .cloned()
                .collect()
        };

        for pipe_id in pipe_ids {
            if let Err(e) = self.stop_pipe(&pipe_id).await {
                error!("Failed to stop pipe {}: {}", pipe_id, e);
            }
        }
    }

    /// Spawn a background task for periodic health checks
    async fn spawn_health_check_task(
        &self,
        pipe: PipeConfig,
    ) -> AbortHandle {
        let pipe_id = pipe.id.clone();
        let pipe_name = pipe.name.clone();
        let task_monitor = self.task_monitor.clone();
        let secrets = crate::secrets::SurfaceSecrets::new(
            Some(self.secrets_store.clone() as Arc<dyn SecretsStore>),
            pipe.tenant_id.clone(),
        );
        let check_interval = self.health_check_interval_secs;
        let task_ids = self.task_ids.clone();

        tokio::spawn(async move {
            let mut interval_timer = interval(Duration::from_secs(check_interval));
            interval_timer.tick().await; // Skip first immediate tick

            loop {
                interval_timer.tick().await;

                // Perform health check
                let health_result = perform_pipe_health_check(&pipe, &secrets).await;

                // Update TaskMonitor status
                if let Some(ref monitor) = task_monitor {
                    let task_ids_read = task_ids.read().await;
                    if let Some(task_id) = task_ids_read.get(&pipe_id) {
                        let new_status = if health_result.is_ok() {
                            TaskStatus::Running
                        } else {
                            TaskStatus::Error
                        };

                        monitor
                            .update_status(task_id, new_status)
                            .await;

                        if let Err(ref e) = health_result {
                            warn!("Pipe '{}' health check failed: {}", pipe_name, e);
                            monitor
                                .increment_errors(task_id)
                                .await;
                        } else {
                            debug!("Pipe '{}' health check passed", pipe_name);
                        }
                    }
                }
            }
        })
        .abort_handle()
    }

    /// Extract provider, model, and endpoint from pipe config
    fn extract_pipe_info(
        &self,
        pipe: &PipeConfig,
    ) -> (String, String, String) {
        use crate::pipes::PipeType;
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        match &pipe.pipe_type {
            PipeType::LLM { provider, .. } => {
                let endpoint = provider.get_endpoint();
                (
                    provider
                        .provider_type_str()
                        .to_string(),
                    provider
                        .model_name()
                        .to_string(),
                    endpoint,
                )
            }
            PipeType::Webhook { .. } => ("Webhook".to_string(), "N/A".to_string(), "N/A".to_string()),
            PipeType::IDECatalog { .. } => ("IDE".to_string(), "N/A".to_string(), "N/A".to_string()),
        }
    }
}

/// The key a pipe's health check sends: its provider's API key secret,
/// resolved for the pipe's own tenant exactly as a request resolves it.
/// `None` when the provider names no key (a local provider such as Ollama).
async fn health_check_key(
    provider: &crate::pipes::types::llm::LLMProvider,
    secrets: &crate::secrets::SurfaceSecrets,
) -> Result<Option<String>, String> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;

    let Some(reference) = provider
        .get_api_key()
        .filter(|reference| !reference.is_empty())
    else {
        return Ok(None);
    };
    match secrets
        .resolve(reference)
        .await
        .map_err(|e| format!("Secret {reference:?} cannot be used: {e}"))?
    {
        Some(secret) => Ok(Some(secret.value)),
        None => Err(format!("Secret not found: {reference:?}")),
    }
}

/// Perform a health check on a pipe by testing its connection
async fn perform_pipe_health_check(
    pipe: &PipeConfig,
    secrets: &crate::secrets::SurfaceSecrets,
) -> Result<(), String> {
    use crate::pipes::PipeType;
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;

    // Only perform health checks for LLM pipes
    let provider_info = match &pipe.pipe_type {
        PipeType::LLM { provider, .. } => provider,
        _ => return Ok(()), // Skip health checks for non-LLM pipes
    };

    let Some(api_key) = health_check_key(provider_info, secrets).await? else {
        return Ok(());
    };

    // Get provider type and endpoint from trait methods
    let provider_type = provider_info
        .provider_type_str()
        .to_string();
    let endpoint = provider_info.get_endpoint();

    // Build metadata from provider config
    let mut metadata = serde_json::Map::new();
    if let crate::pipes::types::llm::LLMProvider::Anthropic { version: Some(ver), .. } = &**provider_info {
        metadata.insert("anthropicVersion".to_string(), serde_json::Value::String(ver.clone()));
    }
    if let crate::pipes::types::llm::LLMProvider::AzureOpenAI { api_version, .. } = &**provider_info {
        metadata.insert("azureApiVersion".to_string(), serde_json::Value::String(api_version.clone()));
    }

    // Delegate to the shared test_llm_provider function
    crate::identity::handlers::pipes::test_llm_provider(&provider_type, &endpoint, &api_key, &metadata)
        .await
        .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::types::llm::LLMProvider;
    use crate::secrets::store::memory::{MemorySecretsStore, secret};

    fn provider(key: Option<&str>) -> LLMProvider {
        LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key_secret: key.map(str::to_string),
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        }
    }

    #[tokio::test]
    async fn the_health_check_resolves_its_key_as_a_request_would() {
        let store: Arc<dyn SecretsStore> = Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-operator", "openai_api_key", "OPERATOR", None),
            secret("uuid-b", "b-key", "B-VALUE", Some("tenant-b")),
        ]));
        let tenant_a = crate::secrets::SurfaceSecrets::new(Some(store), Some("tenant-a".to_string()));

        for reference in ["openai_api_key", "uuid-operator"] {
            assert_eq!(
                health_check_key(&provider(Some(reference)), &tenant_a).await,
                Ok(Some("OPERATOR".to_string())),
                "{reference:?} did not resolve"
            );
        }
        assert!(
            health_check_key(&provider(Some("b-key")), &tenant_a)
                .await
                .is_err(),
            "the health check sent another tenant's secret"
        );
        assert!(
            health_check_key(&provider(Some("missing")), &tenant_a)
                .await
                .is_err()
        );
        assert_eq!(health_check_key(&provider(None), &tenant_a).await, Ok(None));
    }
}
