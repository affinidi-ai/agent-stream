#![recursion_limit = "256"]
#![allow(clippy::too_many_arguments)]

#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

use std::io;
use std::path::Path;
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use tracing::{Level, error, info, warn};
use tracing_appender::non_blocking::WorkerGuard;
use tracing_subscriber::fmt::format::FmtSpan;
use tracing_subscriber::fmt::writer::MakeWriterExt;
use tracing_subscriber::layer::{Layer, SubscriberExt};
use tracing_subscriber::util::SubscriberInitExt;

mod config;
mod entity_status; // Shared soft-delete lifecycle (enabled|disabled|deleted) for registry entities
mod metrics;

// Refactored modular structure
mod access_tokens; // Management access tokens (service-account PATs) for the management API
mod api_keys; // API Key Provider for A2A authentication
mod auth;
pub mod auth_manager;
mod backup_restore; // Backup and restore logic for _storage
mod certificates; // Certificate management (TLS/SSL certificates)
mod comm; // Shared DIDComm connection health status and diagnostics
mod credential_providers; // OAuth credential provider CRUD management
mod delegation_vault; // Delegation vault — encrypted OAuth tokens + consent flow
mod embedded_marketplace; // Embedded marketplace handler (model catalog + purchase)
mod encryption; // Encryption at rest for local storage
mod env_compat; // Deprecated AGENT_STREAM_* environment variable names
mod export; // Storage export with PII redaction and public-key encryption
mod fabric_marketplace; // Fabric forwarding utility for marketplace DIDComm

mod drift; // LLM drift detection: per-surface behavioural drift dimensions over time
mod gateways;
mod governance; // Signed, tamper-evident governance records for LLM surfaces
mod http_client;
mod identity;
mod integrations;
mod jwt_bearer; // JWT Bearer token authentication
mod llm_catalog; // Editable LLM provider catalog (storage-backed CRUD)
mod marketplace_models; // Marketplace model storage (purchased models)
mod mediators;
mod members; // Members: registry of appliance clients (LLM consumers), distinct from admin users
mod messages;
mod oauth_identifiers; // Public OAuth sign-in identifier profiles (referenced by IDE/upstream/sandbox sign-in)
mod observability;
mod outbound_fetch;
mod pipe_templates; // Reusable, portable pipe configuration snapshots (builtin + user)
mod pipes; // Pipe management for external services (LLMs, APIs, etc.)
mod policies;
mod prompts; // Versioned, reusable prompt templates rendered at the gateway
mod protocols; // Protocol-agnostic utilities (multi-protocol support)
mod proxy;
mod rbac;
mod rejection_taxonomy; // Canonical rejection-reason taxonomy + classifier (config-file driven)
mod secrets;
mod server;
mod source_auth; // Unified source authentication (JWT Bearer, API Key, mTLS)
mod storage;
mod surface_context; // Shared context types for OPA policy evaluation
mod surfaces; // Agent Surface configuration CRUD (replaces channels)
mod teams; // Teams: group callers by email, aggregate/cap cross-surface usage
mod telemetry; // Multi-resolution usage time-series (surfaces, stages, members, teams)
pub mod tenancy;
mod terms;
mod timeseries; // Backend-neutral time-series port + embedded RRD adapter (swappable for external TSDB)
mod uploads; // Generic storage-backed image uploads (avatars, logos)
mod url_validation; // SSRF protection for user-supplied URLs
mod vault_identity; // Vault identity generation for API keys and certificates

#[cfg(test)]
mod component_tests;

use config::{BootstrapConfig, GatewayConfig};
use storage::{ConfigCache, ConfigurationStore, DynamoDbConfigStore};

/// A2A Protocol Intercepting Proxy
///
/// An HTTPS proxy server for the Agent2Agent (A2A) protocol that intercepts
/// and forwards requests between clients and A2A agents.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to bootstrap configuration file (TOML format)
    /// This file specifies the DynamoDB table or other config source
    #[arg(short, long, value_name = "FILE", default_value = "config.toml")]
    config: PathBuf,

    /// Path to TLS certificate file (overrides config file)
    #[arg(long, env = "AS_CERT")]
    cert: Option<PathBuf>,

    /// Path to TLS private key file (overrides config file)
    #[arg(long, env = "AS_KEY")]
    key: Option<PathBuf>,

    /// Generate a default bootstrap configuration file
    #[arg(long)]
    generate_bootstrap: bool,

    // Base folder
    #[arg(long, default_value = "")]
    base_folder: String,

    // Use cors origins
    #[arg(long, default_value = "")]
    cors_origins: String,

    /// Export storage with PII redaction, encrypted with recipient's Ed25519 public key
    #[arg(long, value_name = "OUTPUT_FILE")]
    export_storage: Option<PathBuf>,

    /// Decrypt a previously exported storage archive
    #[arg(long, value_name = "INPUT_FILE")]
    decrypt_export: Option<PathBuf>,

    /// Output path (used with --decrypt-export, defaults to export.zip)
    #[arg(long, value_name = "OUTPUT_FILE", default_value = "export.zip")]
    output: PathBuf,
}

fn main() -> Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let result = runtime.block_on(async_main());
    // Background tasks are still running after a shutdown signal; don't let a blocking one hold up exit.
    runtime.shutdown_timeout(std::time::Duration::from_secs(5));
    result
}

async fn async_main() -> Result<()> {
    // Note: Can't log here yet - logging not initialized

    // Initialize rustls crypto provider (ring backend)
    // This must be done before any TLS operations
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("Failed to install rustls crypto provider"))?;

    // Initialize dashboard start time
    observability::init_start_time();

    crate::server::mode::install_signal_handlers();

    let args = Args::parse();

    // Generate default bootstrap config if requested
    if args.generate_bootstrap {
        generate_default_bootstrap(&args.base_folder, &args.cors_origins)?;
        return Ok(());
    }

    // Decrypt a previously exported storage archive (no config needed)
    if let Some(input_path) = &args.decrypt_export {
        export::decrypt_export(input_path, &args.output)?;
        return Ok(());
    }

    // Load bootstrap configuration
    let config_path = std::env::current_dir()?.join(&args.config);
    let bootstrap_config = BootstrapConfig::from_file(&config_path)
        .with_context(|| format!("Failed to load bootstrap config from {:?}", config_path))?;

    crate::server::mode::set_server_mode(bootstrap_config.server_mode);
    crate::storage::filesystem::set_cache_refresh_interval_secs(bootstrap_config.cache_refresh_interval_secs);
    crate::server::mode::spawn_signal_handlers();

    println!("DEBUG: Loaded bootstrap config from {:?}", config_path);
    println!(
        "DEBUG:   config_cache_path: {}",
        bootstrap_config
            .storage_paths
            .config_cache
    );
    println!(
        "DEBUG:   settings_storage_path: {}",
        bootstrap_config
            .storage_paths
            .settings
    );
    println!(
        "DEBUG:   metrics_config_path: {}",
        bootstrap_config
            .config_files
            .metrics
    );

    // Export storage with PII redaction (needs config for storage paths)
    if let Some(output_path) = &args.export_storage {
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        export::export_storage(&storage_root, output_path)?;
        return Ok(());
    }

    // Refuse to start without an explicit encryption-at-rest choice before a
    // staged backup restore can write anything to storage.
    bootstrap_config
        .encryption
        .validate()
        .map_err(anyhow::Error::msg)
        .context("Bootstrap configuration validation failed")?;

    // Backup-restore directory (reused below to observe the post-restore
    // re-encryption marker once encryption is initialised).
    let backup_restore_dir = if bootstrap_config
        .storage_paths
        .backup_restore
        .starts_with('/')
        || args.base_folder.is_empty()
    {
        std::path::PathBuf::from(
            &bootstrap_config
                .storage_paths
                .backup_restore,
        )
    } else {
        std::path::PathBuf::from(&args.base_folder).join(
            &bootstrap_config
                .storage_paths
                .backup_restore,
        )
    };

    // Check for backup.asbak and perform restore if present. The restore path
    // validates key configuration first so staged-restore failures are audited.
    {
        let restore_domain = bootstrap_config
            .load_network_config()
            .context("Failed to load did.domain for backup restore")?
            .did
            .domain;
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        if backup_restore::check_and_restore_backup(
            &storage_root,
            &backup_restore_dir,
            bootstrap_config
                .backup_encryption_key
                .as_deref(),
            bootstrap_config
                .legacy_backup_encryption_keys
                .as_deref(),
            &restore_domain,
        ) {
            // Restore was performed — exit so Docker/supervisor restarts us
            std::process::exit(1);
        }
    }

    // Key configuration remains mandatory even when no restore is staged.
    backup_restore::encryption::resolve_backup_key_checked(
        bootstrap_config
            .backup_encryption_key
            .as_deref(),
    )
    .context("Backup encryption key configuration is invalid")?;
    backup_restore::encryption::resolve_legacy_backup_keys(
        bootstrap_config
            .legacy_backup_encryption_keys
            .as_deref(),
    )
    .context("Legacy backup encryption key configuration is invalid")?;

    bootstrap_config
        .validate()
        .context("Bootstrap configuration validation failed")?;

    // Initialize prompt guard pattern definitions from config file
    if let Err(e) = crate::pipes::prompt_guard::init_definitions(
        &bootstrap_config
            .config_files
            .prompt_guard,
    ) {
        warn!("Prompt guard definitions not loaded: {} — built-in patterns will be unavailable", e);
    }

    let config = load_configuration(&bootstrap_config)
        .await
        .context("Failed to load configuration")?;

    // Resolve the optional OTLP exporter auth header from the secrets store.
    let otlp_auth_header = resolve_startup_otlp_auth(&bootstrap_config)
        .await
        .context("Failed to resolve OTLP exporter authentication")?;

    // Initialize logging
    // before this point consider using println
    let _guard: Option<WorkerGuard> = init_logging(&config, &bootstrap_config, otlp_auth_header.clone())?;

    for warning in &bootstrap_config.load_warnings {
        warn!("{}", warning);
    }

    // Load resource-limit configuration into the process-global. Placed after
    // logging init so a missing/misconfigured path is visible. A missing or
    // malformed file leaves every dimension unconstrained (limit 1_000_000).
    crate::config::init_global_limits(crate::config::load_limits_config(
        &bootstrap_config
            .config_files
            .limits,
    ));

    // Initialize encryption at rest
    let encryption = bootstrap_config
        .encryption
        .clone();
    info!("Setting up encryption configuration...");

    // Initialize global encryption for serde (constructs EncryptionService internally)
    encryption::serde_encrypted::init_global_encryption(encryption.clone())
        .context("Failed to initialize serde encryption")?;

    // Initialize global encryption config for all storage operations
    storage::filesystem::init_global_encryption(encryption.clone())
        .context("Failed to initialize storage encryption")?;

    // If a portable backup was just restored, records are on disk as plaintext.
    // The storage layer re-encrypts them under this node's key as it loads each
    // store on this boot; observe and clear the marker.
    backup_restore::reencrypt::maybe_run_post_restore_reencrypt(&backup_restore_dir, &encryption);

    if encryption.enabled {
        // Fail closed if the storage root holds envelope-encrypted values written under a
        // different backend than the one now configured (e.g. local-MEK data with aws_kms active).
        let storage_root = export::resolve_storage_root(
            &bootstrap_config
                .storage_paths
                .agent_surfaces,
            &args.base_folder,
        );
        let active_version = encryption::preflight::active_envelope_version(encryption.key_source);
        encryption::preflight::check_envelope_versions(&storage_root, active_version)
            .context("Encryption backend preflight failed — refusing to start")?;

        info!("✓ Encryption at rest is ENABLED - sensitive data will be encrypted");
    } else {
        warn!("⚠ Encryption at rest is DISABLED - sensitive data will be stored in plain text");
    }

    // Initialize variable patterns from config for runtime use
    crate::storage::integration_trigger_handlers::set_variable_pattern(
        config
            .integration
            .variable_pattern
            .clone(),
    )
    .map_err(|e| anyhow::anyhow!("Invalid integration trigger variable pattern configuration: {e}"))?;
    crate::integrations::runtime_variables::set_variable_patterns(
        config
            .integration
            .variable_pattern
            .clone(),
        config
            .integration
            .custom_variable_prefix
            .clone(),
    )
    .map_err(|e| anyhow::anyhow!("Invalid integration variable pattern configuration: {e}"))?;

    info!("Initialized variable patterns from config");

    // Override TLS paths with command line arguments if provided
    // Priority: command line args > bootstrap config
    let mut config = config;
    let legacy_env_path = |name| {
        env_compat::var(name)
            .ok()
            .map(PathBuf::from)
    };
    if let Some(cert) = args
        .cert
        .or_else(|| legacy_env_path("AS_CERT"))
    {
        info!("Using TLS certificate from command line: {:?}", cert);
        config.tls.cert_path = cert;
    }

    if let Some(key) = args
        .key
        .or_else(|| legacy_env_path("AS_KEY"))
    {
        info!("Using TLS key from command line: {:?}", key);
        config.tls.key_path = key;
    }

    // NOW load surfaces (after logging is initialized so errors are logged)
    // Only for "local" configuration source
    if bootstrap_config.channel_config_source == "local" {
        info!("Loading surfaces from local storage (after logging initialized)");
        match load_surfaces(&bootstrap_config).await {
            Ok(channels) => {
                info!("Successfully loaded {} surface(s)", channels.len());
                config.surfaces = channels;
            }
            Err(e) => {
                error!("Failed to load surfaces: {}", e);
                return Err(e.context("Failed to load surfaces from local storage"));
            }
        }
    }

    // Print ASCII art banner (always to terminal and logs)
    println!();
    println!("     _                    _      ____  _");
    println!("    / \\   __ _  ___ _ __ | |_   / ___|| |_ _ __ ___  __ _ _ __ ___");
    println!("   / _ \\ / _` |/ _ \\ '_ \\| __|  \\___ \\| __| '__/ _ \\/ _` | '_ ` _ \\");
    println!("  / ___ \\ (_| |  __/ | | | |_    ___) | |_| | |  __/ (_| | | | | | |");
    println!(" /_/   \\_\\__, |\\___|_| |_|\\__|  |____/ \\__|_|  \\___|\\__,_|_| |_| |_|");
    println!("         |___/");
    println!();

    println!("Starting Agent Stream");
    println!("Configuration: {}", config_path.display());

    info!("");
    info!("     _                    _      ____  _");
    info!("    / \\   __ _  ___ _ __ | |_   / ___|| |_ _ __ ___  __ _ _ __ ___");
    info!("   / _ \\ / _` |/ _ \\ '_ \\| __|  \\___ \\| __| '__/ _ \\/ _` | '_ ` _ \\");
    info!("  / ___ \\ (_| |  __/ | | | |_    ___) | |_| | |  __/ (_| | | | | | |");
    info!(" /_/   \\_\\__, |\\___|_| |_|\\__|  |____/ \\__|_|  \\___|\\__,_|_| |_| |_|");
    info!("         |___/");
    info!("");

    info!("Starting Agent Stream");
    info!("Configuration: {}", config_path.display());

    let active_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Enabled)
        .count();
    let disabled_count = config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Disabled)
        .count();
    info!("Configured {} channel(s) ({} active, {} disabled)", config.surfaces.len(), active_count, disabled_count);
    for surface in config
        .surfaces
        .iter()
        .filter(|s| s.status == crate::config::agent_surface::SurfaceStatus::Enabled)
    {
        info!("  Channel '{}': {} -> {}", surface.name, surface.listen_address(), surface.target_endpoint());
    }

    // Validate configuration
    config
        .validate()
        .context("Configuration validation failed")?;

    // Run the Axum-based server (identity API is initialized inside if enabled)
    let result = tokio::select! {
        result = server::run_axum_proxy(config.clone(), bootstrap_config.clone(), otlp_auth_header) => result,
        signal = shutdown_signal() => {
            info!("Received {}, shutting down", signal);
            Ok(())
        }
    };

    if tokio::time::timeout(SHUTDOWN_STEP_TIMEOUT, flush_stores())
        .await
        .is_err()
    {
        warn!("Timed out flushing stores during shutdown");
    }

    // Shutdown OpenTelemetry gracefully (check metrics.json config)
    // We reload to check if it was actually enabled
    if let Ok(metrics_cfg) = config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) && metrics_cfg
        .opentelemetry
        .enabled
    {
        info!("Shutting down OpenTelemetry");
        if tokio::time::timeout(SHUTDOWN_STEP_TIMEOUT, tokio::task::spawn_blocking(observability::shutdown_otel))
            .await
            .is_err()
        {
            warn!("Timed out shutting down OpenTelemetry");
        }
    }

    result
}

/// Upper bound for each shutdown step, so a stalled volume or exporter can't outlast the container stop timeout.
const SHUTDOWN_STEP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Writes every store that keeps a periodic in-memory tail, so a restart doesn't lose it.
async fn flush_stores() {
    if let Some(store) = observability::global_system_metrics_store() {
        store.flush().await;
    }
    // Usage telemetry is graph-fidelity only: enforcement uses the separate monthly TeamUsageTracker.
    if let Some(store) = crate::telemetry::global_telemetry_store() {
        store.flush().await;
    }
    if let Some(store) = crate::metrics::ops_telemetry::global_ops_store() {
        store.flush().await;
    }
    if let Some(store) = crate::drift::store::global_drift_store() {
        store.flush().await;
    }
}

/// Resolves with the name of the first termination signal received: SIGTERM or Ctrl-C.
async fn shutdown_signal() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => tokio::select! {
                _ = sigterm.recv() => "SIGTERM",
                _ = ctrl_c() => "SIGINT",
            },
            Err(e) => {
                warn!("Failed to install SIGTERM handler: {}", e);
                ctrl_c().await;
                "SIGINT"
            }
        }
    }
    #[cfg(not(unix))]
    {
        ctrl_c().await;
        "Ctrl-C"
    }
}

/// Waits for Ctrl-C; never resolves if the handler can't be installed, so that failure can't stop the server.
async fn ctrl_c() {
    if let Err(e) = tokio::signal::ctrl_c().await {
        warn!("Failed to install Ctrl-C handler: {}", e);
        std::future::pending::<()>().await;
    }
}

/// Load configuration from the specified source with fallback to last-known-good config
/// Channels are loaded from DynamoDB, while TLS, A2A, and logging configs come from bootstrap
async fn load_configuration(bootstrap: &BootstrapConfig) -> Result<GatewayConfig> {
    eprintln!("🔍 [CONFIG-LOAD] load_configuration called");
    eprintln!("🔍 [CONFIG-LOAD] channel_config_source = '{}'", bootstrap.channel_config_source);
    eprintln!(
        "🔍 [CONFIG-LOAD] agent surface storage path = '{}'",
        bootstrap
            .storage_paths
            .agent_surfaces
    );

    // Initialize config cache
    let config_cache = ConfigCache::new(
        &bootstrap
            .storage_paths
            .config_cache,
    );

    match bootstrap
        .channel_config_source
        .as_str()
    {
        "dynamodb" => {
            let table_name = bootstrap
                .dynamodb_table
                .as_ref()
                .context("DynamoDB table name not specified")?;

            info!("Loading channels from DynamoDB table: {}", table_name);

            // Try to load from DynamoDB first
            let dynamodb_result = async {
                let store = DynamoDbConfigStore::new(
                    table_name.clone(),
                    bootstrap.aws_region.clone(),
                    bootstrap.aws_profile.clone(),
                )
                .await?;

                // Load only channels from DynamoDB
                let mut config = store.load_config().await?;

                // Use TLS, A2A, logging, and extension inspection configs from bootstrap
                config.tls = bootstrap.tls.clone();
                config.a2a = bootstrap.a2a.clone();
                // Logging base (level, json, log_directory) comes from config.toml;
                // redaction rules come from gateway.json and are merged in below.
                let gw_redaction = config
                    .logging
                    .redaction
                    .clone();
                config.logging = bootstrap.logging.clone();
                config.logging.redaction = gw_redaction;
                config.extension_inspection = bootstrap
                    .extension_inspection
                    .clone();
                Ok::<GatewayConfig, anyhow::Error>(config)
            }
            .await;

            match dynamodb_result {
                Ok(config) => {
                    info!("Successfully loaded configuration from DynamoDB");

                    // Save successful configuration to cache
                    if let Err(cache_error) = config_cache
                        .save(&config, "dynamodb")
                        .await
                    {
                        error!("Failed to cache configuration: {}", cache_error);
                        // Don't fail startup just because caching failed
                    }

                    Ok(config)
                }
                Err(dynamodb_error) => {
                    error!("Failed to load configuration from DynamoDB: {}", dynamodb_error);

                    // Try to load from cache as fallback
                    if config_cache.exists().await {
                        info!("Attempting to load last-known-good configuration from cache");

                        match config_cache.load().await {
                            Ok(cached) => {
                                warn!(
                                    "Using cached configuration from {} (cached at {})",
                                    cached.source, cached.cached_at
                                );

                                // Update bootstrap-specific configs even for cached config
                                let mut config = cached.config;
                                config.tls = bootstrap.tls.clone();
                                config.a2a = bootstrap.a2a.clone();
                                let gw_redaction = config
                                    .logging
                                    .redaction
                                    .clone();
                                config.logging = bootstrap.logging.clone();
                                config.logging.redaction = gw_redaction;
                                config.extension_inspection = bootstrap
                                    .extension_inspection
                                    .clone();

                                Ok(config)
                            }
                            Err(cache_error) => {
                                error!("Failed to load cached configuration: {}", cache_error);
                                Err(dynamodb_error.context("DynamoDB load failed and no valid cache available"))
                            }
                        }
                    } else {
                        error!("No cached configuration available for fallback");
                        Err(dynamodb_error.context("DynamoDB load failed and no cache exists"))
                    }
                }
            }
        }
        "local" => {
            eprintln!("🔍 [CONFIG-LOAD] Taking LOCAL branch");
            eprintln!("[V8]");
            eprintln!("🔍 [CONFIG-LOAD] Deferring channel loading until after logging is initialized");

            // Load network config to get integration configuration
            let network_config_path = &bootstrap
                .config_files
                .agent_stream;
            let network_config = config::NetworkConfig::load_from_file(network_config_path)
                .context("Failed to load network config for integration configuration")?;

            // Create configuration with EMPTY channels (will be loaded after logging is initialized)
            // Logging base (level, json, log_directory) comes from config.toml;
            // redaction rules come from gateway.json.
            let mut logging = bootstrap.logging.clone();
            if let Some(gw_logging) = &network_config.logging {
                logging.redaction = gw_logging.redaction.clone();
            }

            let config = GatewayConfig {
                surfaces: Vec::new(), // Empty for now
                tls: bootstrap.tls.clone(),
                a2a: bootstrap.a2a.clone(),
                mcp: bootstrap.mcp.clone(),
                logging,
                extension_inspection: bootstrap
                    .extension_inspection
                    .clone(),
                integration: network_config.integration,
            };

            info!("Local configuration loaded successfully");
            Ok(config)
        }
        other => {
            anyhow::bail!("Unsupported configuration source: {}", other)
        }
    }
}

/// Load surfaces from storage (called AFTER logging is initialized)
async fn load_surfaces(bootstrap: &BootstrapConfig) -> Result<Vec<crate::config::agent_surface::AgentSurface>> {
    let path = PathBuf::from(
        &bootstrap
            .storage_paths
            .agent_surfaces,
    );

    // Don't create the directory just to discover there are no surfaces.
    // When surfaces exist the store is constructed on demand (here and by
    // the G2G/settlement paths); an absent directory means zero surfaces.
    if !path.exists() {
        return Ok(Vec::new());
    }

    info!("🔍 [SURFACE-LOAD] Loading surfaces from: {}", path.display());

    let store = surfaces::FileSystemAgentSurfaceStore::new(path).await?;

    let channels = surfaces::AgentSurfaceStore::list_all(&store)
        .await
        .context("Failed to load surfaces from storage")?;

    info!("✅ Loaded {} surface(s) from local storage", channels.len());

    Ok(channels)
}

/// Resolve the optional OTLP exporter auth header from the secrets store.
///
/// Returns `Ok(None)` when OpenTelemetry is disabled, the metrics config cannot
/// be loaded, or no auth is configured. Returns an error (fail-fast) when auth
/// is configured but the referenced secret cannot be read, so the gateway does
/// not silently export telemetry unauthenticated.
async fn resolve_startup_otlp_auth(bootstrap_config: &config::BootstrapConfig) -> Result<Option<(String, String)>> {
    let metrics_config = match config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) {
        Ok(cfg) => cfg,
        Err(_) => return Ok(None),
    };

    if !metrics_config
        .opentelemetry
        .enabled
    {
        return Ok(None);
    }

    let Some(auth) = metrics_config
        .opentelemetry
        .auth
        .as_ref()
    else {
        return Ok(None);
    };

    let store = secrets::create_secrets_store(Some(
        bootstrap_config
            .storage_paths
            .secrets
            .clone(),
    ))
    .await
    .context("Failed to initialize secrets store for OTLP auth resolution")?;

    let header = config::metrics_config::resolve_otel_auth_header(auth, &store).await?;
    Ok(Some(header))
}

/// Initialize the logging subsystem
fn init_logging(
    config: &GatewayConfig,
    bootstrap_config: &config::BootstrapConfig,
    otlp_auth_header: Option<(String, String)>,
) -> Result<Option<WorkerGuard>> {
    let mut guard = None;

    let max_level = match Level::from_str(config.logging.level.as_str()) {
        Ok(level) => level,
        Err(e) => anyhow::bail!("Cannot parse log level: {}", e),
    };

    // Build the log redactor from gateway.json config (compiled once, shared via Arc)
    let redactor = observability::LogRedactor::from_config(&config.logging.redaction);
    // Capture the redactor for hot-reload up front, even if OpenTelemetry starts
    // disabled, so a later enable-via-reload applies the configured span
    // redaction instead of the default (which would leak matched values).
    observability::set_reload_redactor(redactor.clone());
    if !redactor.is_empty() {
        eprintln!(
            "✅ Log redaction enabled with {} rule(s)",
            config
                .logging
                .redaction
                .rules
                .len()
        );
    }

    // Load metrics configuration from metrics.json
    let metrics_config = match config::load_metrics_config(
        &bootstrap_config
            .config_files
            .metrics,
    ) {
        Ok(cfg) => {
            //println!("✅ Loaded metrics configuration from: {}", bootstrap_config.config_files.metrics);
            cfg
        }
        Err(e) => {
            eprintln!(
                "⚠️  Failed to load metrics config from {}: {}",
                bootstrap_config
                    .config_files
                    .metrics,
                e
            );
            eprintln!("⚠️  Continuing with OpenTelemetry disabled");
            // Create default config with everything disabled
            config::MetricsConfig {
                opentelemetry: config::OpenTelemetryConfig {
                    enabled: false,
                    endpoint: "http://localhost:4317".to_string(),
                    protocol: config::metrics_config::OtlpProtocol::default(),
                    auth: None,
                    service_name: env!("CARGO_PKG_NAME").to_string(),
                    environment: "development".to_string(),
                    instance_id: None,
                    traces: config::metrics_config::TracesConfig {
                        enabled: false,
                        sample_rate: 1.0,
                        target_crates: vec!["agent-stream".to_string()],
                    },
                    metrics: config::MetricsExportConfig {
                        enabled: false,
                        export_interval_seconds: 60,
                        batch_max_queue_size: None,
                        batch_scheduled_delay_ms: None,
                        batch_max_export_size: None,
                    },
                    logs: config::metrics_config::LogsConfig {
                        enabled: false,
                        ..Default::default()
                    },
                },
                cloudwatch: config::metrics_config::CloudWatchMetricConfig {
                    enabled: false,
                    region: Some("us-east-1".to_string()),
                    ..Default::default()
                },
                retention: config::RetentionConfig::default(),
                advanced: config::AdvancedConfig::default(),
            }
        }
    };

    // Initialize OpenTelemetry providers if enabled. The trace + log layers are
    // installed as reloadable layers below, so a config save can swap them in
    // place without restarting the process (see observability::reload_otel).
    let otel_trace_provider = if metrics_config
        .opentelemetry
        .enabled
    {
        let mut otel_config = observability::OtelConfig::from(&metrics_config.opentelemetry);
        otel_config.auth_header = otlp_auth_header;

        let tracer_provider = match observability::init_tracer(&otel_config, redactor.clone()) {
            Ok(provider) => Some(provider),
            Err(e) => {
                eprintln!("⚠️  Failed to initialize OpenTelemetry tracer: {}", e);
                None
            }
        };

        if let Err(e) = observability::init_metrics(&otel_config) {
            eprintln!("⚠️  Failed to initialize OpenTelemetry metrics: {}", e);
        }

        if metrics_config
            .opentelemetry
            .logs
            .enabled
            && let Err(e) = observability::init_logs(&otel_config)
        {
            eprintln!("⚠️  Failed to initialize OpenTelemetry logs: {}", e);
        }

        tracer_provider
    } else {
        None
    };

    // Build the initial reloadable OTEL layers (real when enabled, else no-op)
    // and install them first in the subscriber so they can be hot-swapped by a
    // later config save via `observability::reload_otel`.
    let initial_trace_layer = match &otel_trace_provider {
        Some(provider) => observability::build_trace_layer_boxed(
            provider,
            &metrics_config
                .opentelemetry
                .service_name,
        ),
        None => observability::noop_layer_boxed(),
    };
    let initial_log_layer = match observability::get_logger_provider() {
        Some(provider) => observability::build_log_layer_boxed(provider),
        None => observability::noop_layer_boxed(),
    };

    // Assemble the subscriber from a single vec of boxed layers so every logging
    // mode shares one code path and the OTEL layers stay swappable.
    let mut layers: Vec<observability::BoxedLayer> = vec![
        observability::install_trace_reload(
            initial_trace_layer,
            metrics_config
                .opentelemetry
                .traces
                .effective_target_crates(),
        ),
        observability::install_log_reload(initial_log_layer),
        observability::WebSocketLogLayer::new().boxed(),
        observability::StageStreamLayer::new().boxed(),
    ];

    if config.logging.json {
        if let Some(log_dir) = &config.logging.log_directory {
            let (none_blocking, worker_guard) = tracing_appender::non_blocking(tracing_appender::rolling::never(
                Path::new(log_dir),
                "agent-stream.log",
            ));
            guard = Some(worker_guard);

            layers.push(
                tracing_subscriber::fmt::Layer::new()
                    .json()
                    .flatten_event(false)
                    .with_writer(
                        observability::RedactingMakeWriter::new(none_blocking, redactor.clone())
                            .with_max_level(max_level),
                    )
                    .with_ansi(false)
                    .with_target(false)
                    .with_span_events(FmtSpan::NONE)
                    .with_span_list(false)
                    .boxed(),
            );
        }

        layers.push(
            tracing_subscriber::fmt::Layer::new()
                .json()
                .flatten_event(false)
                .with_writer(
                    observability::RedactingMakeWriter::new(io::stderr, redactor.clone()).with_max_level(max_level),
                )
                .with_ansi(true)
                .with_target(false)
                .with_span_events(FmtSpan::NONE)
                .with_span_list(false)
                .boxed(),
        );
    } else {
        if let Some(log_dir) = &config.logging.log_directory {
            let (none_blocking, worker_guard) = tracing_appender::non_blocking(tracing_appender::rolling::never(
                Path::new(log_dir),
                "agent-stream.log",
            ));
            guard = Some(worker_guard);

            layers.push(
                tracing_subscriber::fmt::Layer::new()
                    .event_format(observability::SimpleFormat)
                    .with_writer(
                        observability::RedactingMakeWriter::new(none_blocking, redactor.clone())
                            .with_max_level(max_level),
                    )
                    .with_ansi(false)
                    .boxed(),
            );
        }

        layers.push(
            tracing_subscriber::fmt::Layer::new()
                .event_format(observability::SimpleFormat)
                .with_writer(
                    observability::RedactingMakeWriter::new(io::stderr, redactor.clone()).with_max_level(max_level),
                )
                .with_ansi(true)
                .boxed(),
        );
    }

    tracing_subscriber::registry()
        .with(layers)
        .init();

    if metrics_config
        .opentelemetry
        .traces
        .uses_legacy_target_crate()
    {
        warn!("traces.target_crates entry trust_gateway is deprecated and read as agent-stream; update metrics.json");
    }

    Ok(guard)
}

/// Generate a default bootstrap configuration file
fn generate_default_bootstrap(
    base_folder: &str,
    cors_origins: &str,
) -> Result<()> {
    let config = build_default_bootstrap(base_folder, cors_origins)?;
    let toml_str = toml::to_string_pretty(&config)?;

    println!("# agent-stream bootstrap configuration file\n");
    println!("# This file contains local configuration (TLS, logging, storage paths)");
    println!("# and specifies where to load surfaces from (local filesystem)\n");
    println!("{}", toml_str);

    println!("\n# Save this to config.toml and run:");
    println!("# agent-stream --config config.toml");

    Ok(())
}

/// Build the bootstrap configuration `--generate-bootstrap` prints. Config file
/// and storage paths come from the built-in defaults, with the storage paths'
/// leading `../` replaced by `base_folder`.
fn build_default_bootstrap(
    base_folder: &str,
    cors_origins: &str,
) -> Result<BootstrapConfig> {
    let base_folder_prefix = if base_folder.is_empty() {
        "".to_string()
    } else if base_folder.ends_with('/') {
        base_folder.to_string()
    } else {
        format!("{}/", base_folder)
    };
    let logging = config::LoggingConfig {
        log_directory: Some(format!("{}_storage/logs", base_folder_prefix)),
        ..config::LoggingConfig::default()
    };
    let mut did_cache = config::types::DIDCacheBootstrapConfig::default();
    if let Some(rest) = did_cache
        .storage_path
        .strip_prefix("../")
    {
        did_cache.storage_path = format!("{}{}", base_folder_prefix, rest);
    }
    // CORS origins are now configured in network_config.cors (handled separately)
    let _ = cors_origins; // Suppress unused variable warning

    let mut storage_paths = config::StoragePaths::default();
    for path in storage_paths.paths_mut() {
        if let Some(rest) = path.strip_prefix("../") {
            *path = format!("{}{}", base_folder_prefix, rest);
        }
    }

    let config = BootstrapConfig {
        channel_config_source: "local".to_string(),
        dynamodb_table: None,
        aws_region: None,
        aws_profile: None,
        encryption: config::EncryptionConfig {
            enabled: true,
            key_env_var: "AS_MASTER_KEY".to_string(),
            ..config::EncryptionConfig::default()
        },
        tls: config::TlsConfig {
            cert_path: PathBuf::from(format!("{}certs/cert.pem", base_folder_prefix)),
            key_path: PathBuf::from(format!("{}certs/key.pem", base_folder_prefix)),
            verify_upstream: true,
            client_auth: Default::default(),
        },
        a2a: config::A2aConfig::default(),
        mcp: config::McpConfig::default(),
        oob_connection: config::OobConnectionConfig::default(),
        reconnect_policy: config::ReconnectPolicyConfig::default(),
        logging,
        extension_inspection: config::ExtensionInspectionConfig::default(),
        // Keep config file paths relative to config.toml's directory.
        config_files: config::types::ConfigFilePaths::default(),
        storage_paths,
        secrets_backend: "filesystem".to_string(),
        rbac: crate::rbac::RbacConfig::default(),
        did_cache,
        metrics_cache_ttl_seconds: 1,
        websocket_require_auth: true,
        session_timeout_minutes: 20,
        websocket_broadcast_buffer: 500,
        metrics_retention_minutes: 360,
        metrics_cache_ttl_seconds_legacy: 1,
        auth_mode: crate::auth::AuthMode::default(),
        marketplace_cache_ttl: 300,
        backup_encryption_key: Some("env://AS_BACKUP_ENCRYPTION_KEY".to_string()),
        legacy_backup_encryption_keys: None,
        drift: config::types::DriftBootstrapConfig::default(),
        surface_defaults: Default::default(),
        tenancy: crate::tenancy::TenancyConfig::default(),
        config_dir: None,
        server_mode: crate::server::mode::ServerMode::default(),
        cache_refresh_interval_secs: 0,
        load_warnings: Vec::new(),
    };

    Ok(config)
}

#[cfg(test)]
mod bootstrap_generation_tests {
    use super::*;

    #[test]
    fn generated_bootstrap_defaults_to_active_without_cache_polling() {
        let config = build_default_bootstrap("", "").expect("default bootstrap should be generated");

        assert_eq!(config.server_mode, crate::server::mode::ServerMode::Active);
        assert_eq!(config.cache_refresh_interval_secs, 0);
    }

    #[test]
    fn generated_bootstrap_round_trips_through_toml() {
        let config = build_default_bootstrap("", "").expect("default bootstrap should be generated");
        let parsed: BootstrapConfig =
            toml::from_str(&toml::to_string_pretty(&config).unwrap()).expect("generated TOML must load back");

        assert_eq!(parsed.server_mode, config.server_mode);
        assert_eq!(parsed.cache_refresh_interval_secs, config.cache_refresh_interval_secs);
    }

    #[test]
    fn generated_bootstrap_encrypts_at_rest_with_the_environment_key() {
        let config = build_default_bootstrap("", "").expect("default bootstrap should be generated");
        let parsed: BootstrapConfig =
            toml::from_str(&toml::to_string_pretty(&config).unwrap()).expect("generated TOML must load back");

        assert!(parsed.encryption.enabled);
        assert!(
            !parsed
                .encryption
                .allow_unencrypted
        );
        assert_eq!(parsed.encryption.key_source, config::KeySourceConfig::Environment);
        assert_eq!(parsed.encryption.key_env_var, "AS_MASTER_KEY");
        assert_eq!(parsed.encryption.validate(), Ok(()));
    }

    fn as_json<T: serde::Serialize>(value: &T) -> serde_json::Value {
        serde_json::to_value(value).unwrap()
    }

    #[test]
    fn generated_paths_match_the_defaults_for_the_parent_base_folder() {
        let config = build_default_bootstrap("..", "").expect("bootstrap configuration must be generated");

        assert_eq!(as_json(&config.storage_paths), as_json(&config::StoragePaths::default()));
        assert_eq!(as_json(&config.config_files), as_json(&config::types::ConfigFilePaths::default()));
        assert_eq!(as_json(&config.did_cache), as_json(&config::types::DIDCacheBootstrapConfig::default()));
    }

    #[test]
    fn generated_storage_paths_sit_under_the_base_folder() {
        let mut config = build_default_bootstrap("/data", "").expect("bootstrap configuration must be generated");

        assert_eq!(
            config
                .storage_paths
                .governance,
            "/data/_storage/governance"
        );
        assert_eq!(
            config
                .storage_paths
                .default_members,
            "defaults/default_members"
        );
        for path in config
            .storage_paths
            .paths_mut()
        {
            assert!(!path.starts_with("../"), "{path} kept the default prefix");
        }
    }
}
