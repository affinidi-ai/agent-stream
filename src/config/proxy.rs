//! Proxy configuration implementation

use super::network::NetworkConfig;
use super::types::*;
use std::path::PathBuf;
use tracing::{info, warn};

#[allow(dead_code)]
impl BootstrapConfig {
    /// Load network configuration from the configured path
    pub fn load_network_config(&self) -> anyhow::Result<NetworkConfig> {
        let network_path = &self.config_files.agent_stream;
        info!("Loading network configuration from: {}", network_path);
        let network_config = NetworkConfig::load_from_file(network_path)?;
        Ok(network_config)
    }

    /// Absolute path to the editable LLM provider catalog file (`llm.json`)
    /// inside the configured `llm_configuration` storage directory.
    pub fn llm_catalog_path(&self) -> PathBuf {
        PathBuf::from(
            &self
                .storage_paths
                .llm_configuration,
        )
        .join("llm.json")
    }

    /// Path to the shipped LLM catalog used to seed the storage copy on first
    /// run (the same file referenced by `config_files.llm`).
    pub fn llm_catalog_seed_path(&self) -> &str {
        &self.config_files.llm
    }

    /// Absolute path to the **custom** LLM provider catalog file
    /// (`custom_llm.json`) inside the configured `llm_configuration` storage
    /// directory. This user-editable file is merged over the built-in `llm.json`
    /// at read time; a missing or invalid file is ignored so the appliance never
    /// breaks on bad custom input.
    pub fn custom_llm_catalog_path(&self) -> PathBuf {
        PathBuf::from(
            &self
                .storage_paths
                .llm_configuration,
        )
        .join("custom_llm.json")
    }
}

#[allow(dead_code)]
impl GatewayConfig {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: GatewayConfig = toml::from_str(&contents)?;
        config
            .a2a
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid [a2a] config in {}: {}", path.display(), e))?;
        Ok(config)
    }

    /// Create a default configuration
    pub fn default_config() -> Self {
        use crate::config::agent_surface::{AccessPoint, AgentSurface, SurfaceProtocol, SurfaceStatus, Target};
        Self {
            surfaces: vec![AgentSurface {
                surface_id: String::new(),
                name: "default-agent".to_string(),
                description: "Default agent channel".to_string(),
                status: SurfaceStatus::Enabled,
                agent_did: None,
                tenant_id: None,
                tags: Vec::new(),
                access_point: AccessPoint {
                    listen_address: "0.0.0.0:8443".to_string(),
                    route: "/".to_string(),
                    protocol: SurfaceProtocol::A2a,
                    ..Default::default()
                },
                target: Target {
                    endpoint: "https://agent.example.com/a2a/v1".to_string(),
                    ..Default::default()
                },
                canvas: None,
                variants: Vec::new(),
                default_variant_id: None,
                outbound_credentials: Vec::new(),
                identity_slots: Default::default(),
            }],
            tls: TlsConfig {
                cert_path: PathBuf::from("cert.pem"),
                key_path: PathBuf::from("key.pem"),
                verify_upstream: true,
                client_auth: Default::default(),
            },
            a2a: A2aConfig::default(),
            mcp: McpConfig::default(),
            logging: LoggingConfig::default(),
            extension_inspection: ExtensionInspectionConfig::default(),
            integration: IntegrationConfig::default_config(),
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        // Validate channels
        if self.surfaces.is_empty() {
            warn!("At least one channel must be configured");
        }

        // Validate each channel
        for (idx, surface) in self
            .surfaces
            .iter()
            .enumerate()
        {
            let channel_id = surface
                .config_id()
                .map(|id| format!(" ({}.json)", id))
                .unwrap_or_default();

            if surface.name.is_empty() {
                anyhow::bail!("Channel {}{} has empty name", idx, channel_id);
            }
            if surface
                .listen_address()
                .is_empty()
            {
                anyhow::bail!("Channel '{}'{} has empty listen_address", surface.name, channel_id);
            }
            if surface
                .target_endpoint()
                .is_empty()
            {
                anyhow::bail!("Channel '{}'{} has empty target_endpoint", surface.name, channel_id);
            }

            // Validate authentication configuration
            validate_source_auth_surface(surface)?;
        }

        // Check for duplicate route+port combinations
        // Multiple channels can share the same port if they have different routes
        let mut seen_route_port_combos = std::collections::HashSet::new();
        for surface in self.surfaces.iter() {
            let channel_id = surface
                .config_id()
                .map(|id| format!(" ({}.json)", id))
                .unwrap_or_default();

            let listen_address = surface.listen_address();
            let route = surface.route();

            // Extract port from listen_address
            let port = listen_address
                .split(':')
                .next_back()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "Invalid listen_address format for channel '{}'{}: {}",
                        surface.name,
                        channel_id,
                        listen_address
                    )
                })?;

            // Normalize route (ensure it starts with /)
            let normalized_route = if route.starts_with('/') {
                route.to_string()
            } else {
                format!("/{}", route)
            };

            let combo = format!("{}:{}", port, normalized_route);
            if !seen_route_port_combos.insert(combo.clone()) {
                anyhow::bail!(
                    "Duplicate route+port combination '{}' for channel '{}'{}. Each route on a port must be unique.",
                    combo,
                    surface.name,
                    channel_id
                );
            }
        }

        // Note: Channel names are human-readable labels and do NOT need to be unique
        // Only config_id must be unique (enforced by filesystem/database)

        // Validate TLS certificate paths
        if !self.tls.cert_path.exists() {
            anyhow::bail!("TLS certificate file not found: {:?}", self.tls.cert_path);
        }

        if !self.tls.key_path.exists() {
            anyhow::bail!("TLS key file not found: {:?}", self.tls.key_path);
        }

        Ok(())
    }
}

fn validate_source_auth_surface(surface: &crate::config::agent_surface::AgentSurface) -> anyhow::Result<()> {
    use crate::source_auth::models::{MtlsTrust, SourceAuthConfig};

    let Some(src) = surface.source_auth() else {
        return Ok(());
    };

    match src {
        SourceAuthConfig::Mtls(cfg) => match &cfg.trust {
            MtlsTrust::Pinned { certificate_ids } => {
                if certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS pinned trust requires at least one certificate_id", surface.name);
                }
            }
            MtlsTrust::Ca {
                ca_certificate_ids,
                check_crl,
                require_ocsp,
                ..
            } => {
                if ca_certificate_ids.is_empty() {
                    anyhow::bail!("Channel '{}': mTLS CA trust requires at least one ca_certificate_id", surface.name);
                }
                if *check_crl {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has check_crl=true but CRL checking is not yet implemented; set check_crl=false",
                        surface.name
                    );
                }
                if *require_ocsp {
                    anyhow::bail!(
                        "Channel '{}': mTLS CA trust has require_ocsp=true but OCSP stapling is not yet implemented; set require_ocsp=false",
                        surface.name
                    );
                }
            }
        },
        SourceAuthConfig::JwtBearer(_) | SourceAuthConfig::ApiKey(_) | SourceAuthConfig::ApiKeyProvider(_) => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config_with_tls() -> (GatewayConfig, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let cert = dir.path().join("cert.pem");
        let key = dir.path().join("key.pem");
        std::fs::write(&cert, "cert").unwrap();
        std::fs::write(&key, "key").unwrap();

        let mut config = GatewayConfig::default_config();
        config.tls.cert_path = cert;
        config.tls.key_path = key;
        (config, dir)
    }

    #[test]
    fn gateway_config_rejects_duplicate_route_on_same_port() {
        let (mut config, _dir) = valid_config_with_tls();
        let mut duplicate = config.surfaces[0].clone();
        duplicate.name = "duplicate".to_string();
        config
            .surfaces
            .push(duplicate);

        let err = config
            .validate()
            .unwrap_err()
            .to_string();
        assert!(err.contains("Duplicate route+port combination"), "got: {err}");
    }

    #[test]
    fn gateway_config_allows_same_route_on_different_ports() {
        let (mut config, _dir) = valid_config_with_tls();
        let mut other = config.surfaces[0].clone();
        other.name = "other".to_string();
        other
            .access_point
            .listen_address = "0.0.0.0:9443".to_string();
        config.surfaces.push(other);

        config.validate().unwrap();
    }

    #[test]
    fn gateway_config_allows_different_routes_on_same_port() {
        let (mut config, _dir) = valid_config_with_tls();
        let mut other = config.surfaces[0].clone();
        other.name = "other".to_string();
        other.access_point.route = "/other".to_string();
        config.surfaces.push(other);

        config.validate().unwrap();
    }
}
