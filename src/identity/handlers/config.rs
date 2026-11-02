use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use std::sync::Arc;
use tracing::{debug, error, info, warn};

use crate::config::GatewayConfig;
use crate::identity::state::IdentityApiState;
use crate::storage::ConfigurationStore;
use crate::surfaces::AgentSurfaceStore;

/// Application error type for config handlers
#[derive(Debug)]
#[allow(dead_code)]
pub enum AppError {
    BadRequest(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Response for configuration reload
#[derive(Debug, Serialize)]
pub struct ReloadConfigResponse {
    pub channels_count: usize,
    pub surfaces_count: usize,
    pub is_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Reload configuration from DynamoDB
pub async fn reload_configuration(
    State(state): State<IdentityApiState>
) -> Result<Json<ReloadConfigResponse>, AppError> {
    let (channels_count, surfaces_count, is_fallback, warning) = perform_config_reload(&state)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to reload channels: {}", e)))?;

    Ok(Json(ReloadConfigResponse {
        channels_count,
        surfaces_count,
        is_fallback,
        warning,
    }))
}

/// Reusable reload routine: rebuilds the gateway config from the configured
/// source (DynamoDB or local surface store) and tells the channel manager to
/// swap channels in-place.
///
/// Used by the explicit `POST /v1/config/reload` endpoint and by the
/// `/v1/surfaces` mutation handlers to make surface changes visible to the
/// running proxy without a manual reload.
///
/// Returns `(channels_count, surfaces_count, is_fallback, warning)`.
pub(crate) async fn perform_config_reload(
    state: &IdentityApiState
) -> anyhow::Result<(usize, usize, bool, Option<String>)> {
    info!("Configuration reload requested");

    // Migrate stored surface policy definitions from the legacy
    // `package channel.policy` to the canonical `package surface.policy` before
    // surfaces are (re)compiled, so the runtime only ever evaluates
    // `data.surface.policy.allow`. Idempotent; mirrors the startup migration.
    if let Some(ref store) = state.policy_definition_store {
        match store
            .migrate_legacy_packages()
            .await
        {
            Ok(0) => {}
            Ok(n) => {
                info!("Migrated {} surface policy definition(s) from `channel.policy` to `surface.policy` on reload", n)
            }
            Err(e) => warn!("Failed to migrate legacy surface policy packages on reload: {}", e),
        }
    }

    let new_config_result = load_base_gateway_config(state).await;
    let (new_config_result, surfaces_count) = inject_surfaces_into_config(state, new_config_result).await;

    let (channels_count, is_fallback, warning) = state
        .channel_manager
        .reload_channels_with_fallback(
            new_config_result,
            state.tls_acceptor.clone(),
            state.client.clone(),
            Some(state.metrics_store.clone()),
            state.task_monitor.clone(),
        )
        .await?;

    if is_fallback {
        warn!("Using cached configuration as fallback after DynamoDB load failure");
    } else {
        info!("Successfully reloaded {} channels + {} surfaces", channels_count, surfaces_count);
    }

    Ok((channels_count, surfaces_count, is_fallback, warning))
}

/// Build the base `GatewayConfig` from the configured channel source
/// (DynamoDB or the local filesystem channel store).
async fn load_base_gateway_config(state: &IdentityApiState) -> anyhow::Result<Arc<GatewayConfig>> {
    match state
        .bootstrap_config
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = match state
                .bootstrap_config
                .dynamodb_table
                .as_ref()
            {
                Some(name) => name,
                None => {
                    return Err(anyhow::anyhow!("DynamoDB table name not specified"));
                }
            };

            info!("Reloading channels from DynamoDB table: {}", table_name);

            async {
                let store = crate::storage::DynamoDbConfigStore::new(
                    table_name.clone(),
                    state
                        .bootstrap_config
                        .aws_region
                        .clone(),
                    state
                        .bootstrap_config
                        .aws_profile
                        .clone(),
                )
                .await?;

                let mut config = store.load_config().await?;

                info!("Using TLS, A2A, logging, and extension inspection configurations from bootstrap config");
                config.tls = state
                    .bootstrap_config
                    .tls
                    .clone();
                config.a2a = state
                    .bootstrap_config
                    .a2a
                    .clone();
                config.logging = state
                    .bootstrap_config
                    .logging
                    .clone();
                config.extension_inspection = state
                    .bootstrap_config
                    .extension_inspection
                    .clone();
                Ok(Arc::new(config))
            }
            .await
        }
        "file" => {
            Err(anyhow::anyhow!("File-based configuration loading is deprecated. Use DynamoDB configuration source."))
        }
        "local" => {
            info!(
                "Reloading local configuration from agent-surface storage: {}",
                state
                    .bootstrap_config
                    .storage_paths
                    .agent_surfaces
            );

            async {
                let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
                    &state
                        .bootstrap_config
                        .storage_paths
                        .agent_surfaces,
                ))
                .await?;

                let channels: Vec<crate::config::agent_surface::AgentSurface> = agent_surface_store
                    .list_all()
                    .await?;
                info!("Reloaded {} surface(s) from local storage", channels.len());

                let config = GatewayConfig {
                    surfaces: channels,
                    tls: state
                        .bootstrap_config
                        .tls
                        .clone(),
                    a2a: state
                        .bootstrap_config
                        .a2a
                        .clone(),
                    mcp: state
                        .bootstrap_config
                        .mcp
                        .clone(),
                    logging: state
                        .bootstrap_config
                        .logging
                        .clone(),
                    extension_inspection: state
                        .bootstrap_config
                        .extension_inspection
                        .clone(),
                    integration: state
                        .config
                        .integration
                        .clone(),
                };

                Ok(Arc::new(config))
            }
            .await
        }
        other => Err(anyhow::anyhow!("Unsupported configuration source: {}", other)),
    }
}

/// Returns the config result and the number of surfaces that were injected.
/// Surfaces are already the runtime config shape, so this is a pass-through.
async fn inject_surfaces_into_config(
    _state: &IdentityApiState,
    config_result: anyhow::Result<Arc<GatewayConfig>>,
) -> (anyhow::Result<Arc<GatewayConfig>>, usize) {
    let surfaces_count = 0;
    let result = config_result;
    (result, surfaces_count)
}

/// Response for single channel reload
#[derive(Debug, Serialize)]
pub struct ReloadSingleChannelResponse {
    pub channel_name: String,
    pub is_fallback: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warning: Option<String>,
}

/// Reload a single channel configuration from DynamoDB
pub async fn reload_single_channel(
    Path(config_id): Path<String>,
    State(state): State<IdentityApiState>,
) -> Result<Json<ReloadSingleChannelResponse>, AppError> {
    info!("Single channel reload requested for config_id: {}", config_id);

    let new_channel_result = match state
        .bootstrap_config
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = match state
                .bootstrap_config
                .dynamodb_table
                .as_ref()
            {
                Some(name) => name,
                None => {
                    return Err(AppError::InternalError("DynamoDB table name not specified".to_string()));
                }
            };

            info!("Reloading channel with config_id '{}' from DynamoDB table: {}", config_id, table_name);

            async {
                let store = crate::storage::DynamoDbConfigStore::new(
                    table_name.clone(),
                    state
                        .bootstrap_config
                        .aws_region
                        .clone(),
                    state
                        .bootstrap_config
                        .aws_profile
                        .clone(),
                )
                .await?;

                store
                    .load_single_channel_by_config_id(&config_id)
                    .await
            }
            .await
        }
        "file" => {
            Err(anyhow::anyhow!("File-based configuration loading is deprecated. Use DynamoDB configuration source."))
        }
        "local" => {
            async {
                let agent_surface_store = crate::surfaces::FileSystemAgentSurfaceStore::new(std::path::PathBuf::from(
                    &state
                        .bootstrap_config
                        .storage_paths
                        .agent_surfaces,
                ))
                .await?;

                agent_surface_store
                    .get(&config_id)
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("Surface with config_id '{}' not found in local storage", config_id))
            }
            .await
        }
        other => Err(anyhow::anyhow!("Unsupported configuration source: {}", other)),
    };

    // Extract channel name for logging (if available)
    let channel_name = new_channel_result
        .as_ref()
        .ok()
        .map(|ch| ch.name.clone())
        .unwrap_or_else(|| config_id.clone());

    let (is_fallback, warning) = state
        .channel_manager
        .reload_single_channel_with_fallback(
            &channel_name,
            new_channel_result,
            state.tls_acceptor.clone(),
            state.client.clone(),
            Some(state.metrics_store.clone()),
            state.task_monitor.clone(),
        )
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to reload channel '{}': {}", channel_name, e)))?;

    if is_fallback {
        warn!("Using cached configuration as fallback for channel '{}'", channel_name);
    } else {
        debug!("Successfully reloaded channel '{}' from DynamoDB", channel_name);
    }

    Ok(Json(ReloadSingleChannelResponse {
        channel_name,
        is_fallback,
        warning,
    }))
}

/// Channel prefix configuration for UI
#[derive(Debug, Serialize, Clone)]
pub struct ChannelPrefixInfo {
    pub id: String,
    pub name: String,
    pub prefix: String,
}

/// Channel routing configuration response
#[derive(Debug, Serialize)]
pub struct ChannelRoutingConfigResponse {
    /// Available listen addresses (external URLs from network config)
    pub available_listen_addresses: Vec<String>,
    /// Available outbound listen addresses (from outbound-type listeners)
    pub available_outbound_listen_addresses: Vec<String>,
    /// Channel path prefixes with names (for UI dropdown)
    pub channel_path_prefix: Vec<ChannelPrefixInfo>,
    /// Pipe path prefixes with names (for LLM pipes UI dropdown)
    pub pipe_path_prefix: Vec<ChannelPrefixInfo>,
    /// OAuth callback route prefix (e.g. "/oauth/callback")
    pub oauth_callback_route: String,
}

/// Get channel routing configuration
pub async fn get_surface_routing_config(
    State(state): State<IdentityApiState>
) -> Result<Json<ChannelRoutingConfigResponse>, AppError> {
    //info!("Channel routing configuration requested");

    // Load network configuration
    let network_config = state
        .bootstrap_config
        .load_network_config()
        .map_err(|e| AppError::InternalError(format!("Failed to load network configuration: {}", e)))?;

    // Load pipe paths from the network configuration (agent-stream.json)
    let pipe_paths = network_config
        .pipe_paths
        .iter()
        .map(|c| ChannelPrefixInfo {
            id: c.id.clone(),
            name: c.name.clone(),
            prefix: c.prefix.clone(),
        })
        .collect();

    let config = ChannelRoutingConfigResponse {
        available_listen_addresses: network_config.get_all_external_urls(),
        available_outbound_listen_addresses: network_config.get_outbound_external_urls(),
        channel_path_prefix: network_config
            .get_channel_prefix_configs()
            .iter()
            .map(|c| ChannelPrefixInfo {
                id: c.id.clone(),
                name: c.name.clone(),
                prefix: c.prefix.clone(),
            })
            .collect(),
        pipe_path_prefix: pipe_paths,
        oauth_callback_route: network_config
            .oauth_callback_route
            .clone(),
    };

    Ok(Json(config))
}

/// Networking / inbound-mTLS configuration (startup-only).
///
/// Reflects the current `tls.client_auth` settings loaded from the bootstrap
/// configuration. This is a startup-only setting (per `AGENTS.md` rule 7);
/// changes require editing the bootstrap config and restarting the gateway,
/// so this endpoint does not expose a paired `PUT`.
#[derive(Debug, Serialize)]
pub struct NetworkingConfigResponse {
    pub client_auth: crate::config::types::ClientAuthConfig,
}

/// Returns the gateway's effective inbound client-auth (mTLS) configuration.
pub async fn get_networking_config(
    State(state): State<IdentityApiState>
) -> Result<Json<NetworkingConfigResponse>, AppError> {
    Ok(Json(NetworkingConfigResponse {
        client_auth: state
            .config
            .tls
            .client_auth
            .clone(),
    }))
}
