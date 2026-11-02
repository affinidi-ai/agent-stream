//! Bootstrap configuration implementation

use super::types::*;
use std::path::{Path, PathBuf};

fn resolve_storage_path_from(
    config_dir: &Path,
    path: &str,
) -> String {
    let path = PathBuf::from(path);
    if !path.is_relative() {
        return path
            .to_string_lossy()
            .into_owned();
    }
    let joined = config_dir.join(path);
    joined
        .canonicalize()
        .unwrap_or_else(|_| {
            let mut resolved = PathBuf::new();
            for component in joined.components() {
                match component {
                    std::path::Component::ParentDir => {
                        resolved.pop();
                    }
                    _ => resolved.push(component),
                }
            }
            resolved
        })
        .to_string_lossy()
        .into_owned()
}

/// Keeps reading data from where earlier versions put it, so an upgrade does
/// not silently start a store empty or lose a config file. Each fallback
/// applies only when the new location does not exist and the old one does, and
/// returns a notice telling the operator how to pin the location. `from_file`
/// runs before logging is initialised, so the caller prints the notices.
///
/// * The team usage, telemetry, ops telemetry and drift defaults moved from
///   `_volatile/` to `_storage/`; with the key omitted, the old default is kept
///   (otherwise team usage would reset quota counters partway through the
///   period).
/// * Governance, global policies, prompts, member provisioning and the drift
///   stores used to reach their store unresolved, so a relative path resolved
///   from the working directory rather than the config directory.
/// * The config file defaults moved from `config/<file>` to `<file>`.
fn keep_legacy_locations(
    config_dir: &Path,
    working_dir: Option<&Path>,
    contents: &str,
    unresolved_storage: &StoragePaths,
    config: &mut BootstrapConfig,
) -> Vec<String> {
    let mut notices = Vec::new();
    let Ok(raw) = toml::from_str::<toml::Value>(contents) else {
        return notices;
    };
    let configured = |table: &str, key: &str| {
        raw.get(table)
            .and_then(toml::Value::as_table)
            .is_some_and(|table| table.contains_key(key))
    };
    let from_working_dir = |path: &str| {
        working_dir
            .filter(|working_dir| *working_dir != config_dir)
            .map(|working_dir| resolve_storage_path_from(working_dir, path))
    };
    let mut fall_back = |table: &str, key: &str, current: &mut String, candidates: Vec<String>| {
        if Path::new(current.as_str()).exists() {
            return;
        }
        if let Some(legacy) = candidates
            .into_iter()
            .find(|candidate| candidate != current && Path::new(candidate).exists())
        {
            notices.push(format!(
                "{table}.{key} resolves to {current}, which does not exist; using the existing legacy location \
                 {legacy} instead. Set {table}.{key} in config.toml to choose the location explicitly."
            ));
            *current = legacy;
        }
    };

    let storage = &mut config.storage_paths;
    // (key, old default, field, whether the old default reached its store unresolved)
    let moved_defaults = [
        ("team_usage", "../_volatile/usage/team_usage", &mut storage.team_usage, false),
        ("telemetry", "../_volatile/telemetry", &mut storage.telemetry, false),
        ("ops_telemetry", "../_volatile/timeseries/ops_telemetry", &mut storage.ops_telemetry, false),
        ("drift", "../_volatile/timeseries/drift", &mut storage.drift, true),
    ];
    for (key, old_default, current, was_unresolved) in moved_defaults {
        if configured("storage_paths", key) {
            continue;
        }
        let mut candidates = vec![resolve_storage_path_from(config_dir, old_default)];
        if was_unresolved {
            candidates.extend(from_working_dir(old_default));
        }
        fall_back("storage_paths", key, current, candidates);
    }

    let previously_unresolved = [
        ("governance", &unresolved_storage.governance, &mut storage.governance),
        ("global_policies", &unresolved_storage.global_policies, &mut storage.global_policies),
        ("prompts", &unresolved_storage.prompts, &mut storage.prompts),
        ("member_provisioning", &unresolved_storage.member_provisioning, &mut storage.member_provisioning),
        ("drift", &unresolved_storage.drift, &mut storage.drift),
        ("drift_baselines", &unresolved_storage.drift_baselines, &mut storage.drift_baselines),
        ("drift_runs", &unresolved_storage.drift_runs, &mut storage.drift_runs),
        ("drift_sessions", &unresolved_storage.drift_sessions, &mut storage.drift_sessions),
        ("drift_eval_state", &unresolved_storage.drift_eval_state, &mut storage.drift_eval_state),
    ];
    for (key, unresolved, current) in previously_unresolved {
        if Path::new(unresolved.as_str()).is_absolute() {
            continue;
        }
        fall_back(
            "storage_paths",
            key,
            current,
            from_working_dir(unresolved)
                .into_iter()
                .collect(),
        );
    }

    let files = &mut config.config_files;
    let moved_config_files = [
        ("agent_stream", &mut files.agent_stream),
        ("metrics", &mut files.metrics),
        ("rbac", &mut files.rbac),
        ("limits", &mut files.limits),
        ("llm", &mut files.llm),
        ("saml", &mut files.saml),
    ];
    for (key, current) in moved_config_files {
        if configured("config_files", key) {
            continue;
        }
        let Some(file_name) = Path::new(current.as_str()).file_name() else {
            continue;
        };
        let legacy = config_dir
            .join("config")
            .join(file_name)
            .to_string_lossy()
            .into_owned();
        fall_back("config_files", key, current, vec![legacy]);
    }

    notices
}

/// Checks `config.toml` for the removed built-in leader election. An enabled
/// `[failover]` block is refused: ignoring it would start every instance of the
/// pair Active (`server_mode` defaults to `active`) with listeners running and
/// cache refresh off. A disabled block, or a leftover `storage_paths.failover`,
/// only produces a warning.
fn removed_failover_warnings(raw: &toml::Value) -> anyhow::Result<Vec<String>> {
    let mut warnings = Vec::new();

    if let Some(failover) = raw.get("failover") {
        let enabled = failover
            .get("enabled")
            .and_then(toml::Value::as_bool)
            .unwrap_or(false);
        if enabled {
            anyhow::bail!(
                "[failover] enabled = true is no longer supported: Agent Stream does not elect a leader \
                 itself any more. Remove the [failover] block, set server_mode (\"active\" or \"standby\") \
                 and cache_refresh_interval_secs (for example 5), and have an external controller promote \
                 an instance with SIGUSR1 and demote it with SIGUSR2. See docs/CONFIGURATION_RELOAD.md#server-mode."
            );
        }
        warnings.push(
            "The [failover] block in config.toml is no longer read and is ignored; remove it. \
             See docs/CONFIGURATION_RELOAD.md#server-mode for server_mode and signal-driven Active/Standby."
                .to_string(),
        );
    }

    if raw
        .get("storage_paths")
        .and_then(|paths| paths.get("failover"))
        .is_some()
    {
        warnings.push("storage_paths.failover in config.toml is no longer read and is ignored; remove it.".to_string());
    }

    Ok(warnings)
}

/// Refuses any `secrets_backend` other than `filesystem`, so a config naming
/// another backend fails at startup instead of keeping secrets on local disk.
fn ensure_supported_secrets_backend(backend: &str) -> anyhow::Result<()> {
    if backend != SUPPORTED_SECRETS_BACKEND {
        anyhow::bail!(
            "secrets_backend = \"{backend}\" is not supported; set it to \"{SUPPORTED_SECRETS_BACKEND}\" or remove it"
        );
    }
    Ok(())
}

impl BootstrapConfig {
    /// Load bootstrap configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let mut config: BootstrapConfig = toml::from_str(&contents)?;
        config.load_warnings = removed_failover_warnings(&toml::from_str(&contents)?)?;
        ensure_supported_secrets_backend(&config.secrets_backend)?;

        // Resolve config file paths relative to the config file directory
        if let Some(config_dir) = path.parent() {
            // Resolve all config file paths
            if PathBuf::from(
                &config
                    .config_files
                    .agent_stream,
            )
            .is_relative()
            {
                config
                    .config_files
                    .agent_stream = config_dir
                    .join(
                        &config
                            .config_files
                            .agent_stream,
                    )
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.metrics).is_relative() {
                let resolved = config_dir.join(&config.config_files.metrics);

                config.config_files.metrics = resolved
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.rbac).is_relative() {
                config.config_files.rbac = config_dir
                    .join(&config.config_files.rbac)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.limits).is_relative() {
                config.config_files.limits = config_dir
                    .join(&config.config_files.limits)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.llm).is_relative() {
                config.config_files.llm = config_dir
                    .join(&config.config_files.llm)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(&config.config_files.saml).is_relative() {
                config.config_files.saml = config_dir
                    .join(&config.config_files.saml)
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(
                &config
                    .config_files
                    .prompt_guard,
            )
            .is_relative()
            {
                config
                    .config_files
                    .prompt_guard = config_dir
                    .join(
                        &config
                            .config_files
                            .prompt_guard,
                    )
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(
                &config
                    .config_files
                    .marketplace_models,
            )
            .is_relative()
            {
                config
                    .config_files
                    .marketplace_models = config_dir
                    .join(
                        &config
                            .config_files
                            .marketplace_models,
                    )
                    .to_string_lossy()
                    .to_string();
            }
            if PathBuf::from(
                &config
                    .config_files
                    .audio_streams,
            )
            .is_relative()
            {
                config
                    .config_files
                    .audio_streams = config_dir
                    .join(
                        &config
                            .config_files
                            .audio_streams,
                    )
                    .to_string_lossy()
                    .to_string();
            }

            // Resolve TLS certificate paths
            if config
                .tls
                .cert_path
                .is_relative()
            {
                config.tls.cert_path = config_dir.join(&config.tls.cert_path);
            }
            if config
                .tls
                .key_path
                .is_relative()
            {
                config.tls.key_path = config_dir.join(&config.tls.key_path);
            }

            // Resolve all storage paths relative to config directory
            let resolve_storage_path = |path: &str| resolve_storage_path_from(config_dir, path);

            let unresolved_storage = config.storage_paths.clone();
            for storage_path in config
                .storage_paths
                .paths_mut()
            {
                *storage_path = resolve_storage_path(storage_path);
            }
            let working_dir = std::env::current_dir().ok();
            for notice in
                keep_legacy_locations(config_dir, working_dir.as_deref(), &contents, &unresolved_storage, &mut config)
            {
                eprintln!("WARN: {notice}");
            }

            // Resolve DID cache storage path using the same resolve_storage_path function
            config.did_cache.storage_path = resolve_storage_path(&config.did_cache.storage_path);

            // Resolve log directory if present using the same resolve_storage_path function
            if let Some(ref log_dir) = config.logging.log_directory {
                config.logging.log_directory = Some(resolve_storage_path(log_dir));
            }

            // Remember the directory the config was loaded from so
            // downstream services can resolve sibling resource folders
            // (e.g. the LLM surface template seeder).
            config.config_dir = Some(config_dir.to_path_buf());
        }

        Ok(config)
    }

    /// Validate the bootstrap configuration
    pub fn validate(&self) -> anyhow::Result<()> {
        match self
            .channel_config_source
            .as_str()
        {
            "dynamodb" => {
                if self.dynamodb_table.is_none() {
                    anyhow::bail!("dynamodb_table must be specified when channel_config_source is 'dynamodb'");
                }
            }
            "file" => {
                // File-based config doesn't need additional validation here
            }
            "local" => {
                // Local config doesn't need additional validation here
            }
            other => {
                anyhow::bail!("Invalid channel_config_source '{}'. Must be 'dynamodb', 'file', or 'local'", other);
            }
        }

        self.encryption
            .validate()
            .map_err(anyhow::Error::msg)?;

        // Validate A2A config (expires vs timeout, inflight limits, etc.)
        self.a2a
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid [a2a] config: {e}"))?;

        self.reconnect_policy
            .validate()
            .map_err(|e| anyhow::anyhow!("Invalid [reconnect_policy] config: {e}"))?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn terms_storage_path_resolves_relative_to_the_config_directory() {
        let config_dir = Path::new("/opt/affinidi/config");

        assert_eq!(resolve_storage_path_from(config_dir, "../_storage/terms"), "/opt/affinidi/_storage/terms");
    }

    const MINIMAL_CONFIG: &str = "[tls]\ncert_path = \"certs/cert.pem\"\nkey_path = \"certs/key.pem\"\n";

    /// A temporary root, canonicalized so it compares equal to resolved paths
    /// (the macOS temp dir sits behind a symlink).
    fn temp_root() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let root = dir
            .path()
            .canonicalize()
            .unwrap();
        (dir, root)
    }

    /// Writes `config.toml` into `<root>/config` and loads it.
    fn load(
        root: &Path,
        contents: &str,
    ) -> BootstrapConfig {
        let config_dir = root.join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let path = config_dir.join("config.toml");
        std::fs::write(&path, contents).unwrap();
        BootstrapConfig::from_file(&path).expect("config.toml must load")
    }

    #[test]
    fn a_config_without_an_encryption_table_is_refused() {
        let (_dir, root) = temp_root();
        let config = load(root.as_path(), MINIMAL_CONFIG);

        let message = format!(
            "{:#}",
            config
                .validate()
                .expect_err("no encryption choice must refuse to start")
        );
        for expected in ["Encryption at rest is not configured", "enabled = true", "allow_unencrypted = true"] {
            assert!(message.contains(expected), "expected {expected:?} in: {message}");
        }
    }

    #[test]
    fn every_storage_path_resolves_relative_to_the_config_directory() {
        let (_dir, root) = temp_root();
        let mut config = load(root.as_path(), MINIMAL_CONFIG);

        for path in config
            .storage_paths
            .paths_mut()
        {
            assert!(Path::new(path.as_str()).is_absolute(), "{path} was not resolved");
            assert!(path.starts_with(&*root.to_string_lossy()), "{path} is outside the config root");
        }
        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .governance
            ),
            root.as_path()
                .join("_storage/governance")
        );
    }

    #[test]
    fn absolute_storage_paths_are_kept() {
        let (_dir, root) = temp_root();
        let config =
            load(root.as_path(), &format!("{MINIMAL_CONFIG}[storage_paths]\ngovernance = \"/srv/governance\"\n"));

        assert_eq!(
            config
                .storage_paths
                .governance,
            "/srv/governance"
        );
    }

    #[test]
    fn an_omitted_key_keeps_an_existing_legacy_volatile_store() {
        let (_dir, root) = temp_root();
        std::fs::create_dir_all(
            root.as_path()
                .join("_volatile/usage/team_usage"),
        )
        .unwrap();

        let config = load(root.as_path(), MINIMAL_CONFIG);

        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .team_usage
            ),
            root.as_path()
                .join("_volatile/usage/team_usage")
        );
        assert_eq!(
            Path::new(&config.storage_paths.telemetry),
            root.as_path()
                .join("_storage/telemetry"),
            "a store with no legacy directory uses the new default"
        );
    }

    #[test]
    fn an_explicit_key_ignores_the_legacy_volatile_store() {
        let (_dir, root) = temp_root();
        std::fs::create_dir_all(
            root.as_path()
                .join("_volatile/usage/team_usage"),
        )
        .unwrap();

        let config = load(
            root.as_path(),
            &format!("{MINIMAL_CONFIG}[storage_paths]\nteam_usage = \"../_storage/team_usage\"\n"),
        );

        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .team_usage
            ),
            root.as_path()
                .join("_storage/team_usage")
        );
    }

    #[test]
    fn an_existing_new_store_wins_over_the_legacy_volatile_store() {
        let (_dir, root) = temp_root();
        for dir in ["_volatile/usage/team_usage", "_storage/team_usage"] {
            std::fs::create_dir_all(root.as_path().join(dir)).unwrap();
        }

        let config = load(root.as_path(), MINIMAL_CONFIG);

        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .team_usage
            ),
            root.as_path()
                .join("_storage/team_usage")
        );
    }

    #[test]
    fn every_omitted_key_keeps_its_existing_legacy_volatile_store() {
        let (_dir, root) = temp_root();
        let legacy_dirs = [
            "_volatile/usage/team_usage",
            "_volatile/telemetry",
            "_volatile/timeseries/ops_telemetry",
            "_volatile/timeseries/drift",
        ];
        for dir in legacy_dirs {
            std::fs::create_dir_all(root.as_path().join(dir)).unwrap();
        }

        let config = load(root.as_path(), MINIMAL_CONFIG);
        let storage = &config.storage_paths;

        for (path, dir) in [&storage.team_usage, &storage.telemetry, &storage.ops_telemetry, &storage.drift]
            .into_iter()
            .zip(legacy_dirs)
        {
            assert_eq!(Path::new(path), root.as_path().join(dir));
        }
    }

    /// Parses `contents` as `<root>/config/config.toml`, resolves its storage
    /// paths and applies the legacy fallbacks with `working_dir`, as `from_file`
    /// does with the process working directory.
    fn resolve_with_working_dir(
        root: &Path,
        working_dir: &Path,
        contents: &str,
    ) -> (BootstrapConfig, Vec<String>) {
        let config_dir = root.join("config");
        let mut config: BootstrapConfig = toml::from_str(contents).unwrap();
        for path in [&mut config.config_files.limits, &mut config.config_files.rbac] {
            *path = config_dir
                .join(path.as_str())
                .to_string_lossy()
                .into_owned();
        }
        let unresolved = config.storage_paths.clone();
        for path in config
            .storage_paths
            .paths_mut()
        {
            *path = resolve_storage_path_from(&config_dir, path);
        }
        let notices = keep_legacy_locations(&config_dir, Some(working_dir), contents, &unresolved, &mut config);
        (config, notices)
    }

    #[test]
    fn omitted_drift_finds_its_old_default_from_the_working_directory() {
        let (_dir, root) = temp_root();
        let working_dir = root.join("run/bin");
        std::fs::create_dir_all(&working_dir).unwrap();
        std::fs::create_dir_all(root.join("run/_volatile/timeseries/drift")).unwrap();

        let (config, notices) = resolve_with_working_dir(&root, &working_dir, MINIMAL_CONFIG);

        assert_eq!(Path::new(&config.storage_paths.drift), root.join("run/_volatile/timeseries/drift"));
        assert_eq!(notices.len(), 1, "got: {notices:?}");
        assert!(notices[0].contains("storage_paths.drift"), "got: {notices:?}");
    }

    #[test]
    fn previously_unresolved_store_keeps_its_working_directory_location() {
        let (_dir, root) = temp_root();
        let working_dir = root.join("run/bin");
        std::fs::create_dir_all(&working_dir).unwrap();
        std::fs::create_dir_all(root.join("run/_storage/governance")).unwrap();

        let (config, notices) = resolve_with_working_dir(&root, &working_dir, MINIMAL_CONFIG);

        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .governance
            ),
            root.join("run/_storage/governance")
        );
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("storage_paths.governance")),
            "got: {notices:?}"
        );
        assert_eq!(
            Path::new(&config.storage_paths.prompts),
            root.join("_storage/prompts"),
            "a store with nothing at its old location uses the config directory"
        );
    }

    #[test]
    fn existing_config_directory_store_wins_over_the_working_directory() {
        let (_dir, root) = temp_root();
        let working_dir = root.join("run/bin");
        for dir in ["run/bin", "run/_storage/governance", "_storage/governance"] {
            std::fs::create_dir_all(root.join(dir)).unwrap();
        }

        let (config, notices) = resolve_with_working_dir(&root, &working_dir, MINIMAL_CONFIG);

        assert_eq!(
            Path::new(
                &config
                    .storage_paths
                    .governance
            ),
            root.join("_storage/governance")
        );
        assert!(notices.is_empty(), "got: {notices:?}");
    }

    #[test]
    fn omitted_config_file_keeps_its_old_config_subfolder_location() {
        let (_dir, root) = temp_root();
        std::fs::create_dir_all(root.join("config/config")).unwrap();
        std::fs::write(root.join("config/config/limits.json"), "{}").unwrap();

        let (config, notices) = resolve_with_working_dir(&root, &root, MINIMAL_CONFIG);

        assert_eq!(Path::new(&config.config_files.limits), root.join("config/config/limits.json"));
        assert!(
            notices
                .iter()
                .any(|notice| notice.contains("config_files.limits")),
            "got: {notices:?}"
        );
        assert_eq!(
            Path::new(&config.config_files.rbac),
            root.join("config/rbac.json"),
            "a file with nothing at its old location keeps the new default"
        );
    }

    #[test]
    fn explicit_config_file_ignores_the_old_config_subfolder() {
        let (_dir, root) = temp_root();
        std::fs::create_dir_all(root.join("config/config")).unwrap();
        std::fs::write(root.join("config/config/limits.json"), "{}").unwrap();

        let (config, notices) = resolve_with_working_dir(
            &root,
            &root,
            &format!("{MINIMAL_CONFIG}[config_files]\nlimits = \"limits.json\"\n"),
        );

        assert_eq!(Path::new(&config.config_files.limits), root.join("config/limits.json"));
        assert!(notices.is_empty(), "got: {notices:?}");
    }

    /// Loads `contents` as `config.toml`, returning the error instead of
    /// panicking so refused configurations can be checked.
    #[test]
    fn filesystem_secrets_backend_loads() {
        let config = try_load(&format!("secrets_backend = \"filesystem\"\n{MINIMAL_CONFIG}"))
            .expect("the filesystem backend must load");
        assert_eq!(config.secrets_backend, "filesystem");
    }

    #[test]
    fn default_secrets_backend_is_filesystem() {
        let config = try_load(MINIMAL_CONFIG).expect("a config without secrets_backend must load");
        assert_eq!(config.secrets_backend, "filesystem");
    }

    #[test]
    fn unsupported_secrets_backend_is_refused() {
        let err = try_load(&format!("secrets_backend = \"aws\"\n{MINIMAL_CONFIG}"))
            .expect_err("an unsupported secrets backend must not load");
        assert!(
            err.to_string()
                .contains("secrets_backend = \"aws\" is not supported")
        );
    }

    fn try_load(contents: &str) -> anyhow::Result<BootstrapConfig> {
        let (_dir, root) = temp_root();
        let config_dir = root.join("config");
        std::fs::create_dir_all(&config_dir).unwrap();
        let path = config_dir.join("config.toml");
        std::fs::write(&path, contents).unwrap();
        BootstrapConfig::from_file(&path)
    }

    #[test]
    fn enabled_legacy_failover_refuses_to_load() {
        let error = try_load(&format!(
            "{MINIMAL_CONFIG}[failover]\nenabled = true\nleader_storage = \"dynamodb\"\nddb_name = \"leases\"\n"
        ))
        .expect_err("an enabled [failover] block must not be silently ignored");

        let message = format!("{error:#}");
        assert!(message.contains("server_mode"), "got: {message}");
        assert!(message.contains("SIGUSR1"), "got: {message}");
    }

    #[test]
    fn disabled_legacy_failover_loads_with_a_warning() {
        let config =
            try_load(&format!("{MINIMAL_CONFIG}[failover]\nenabled = false\n")).expect("a disabled block must load");

        assert_eq!(config.load_warnings.len(), 1);
        assert!(config.load_warnings[0].contains("[failover]"));
        assert_eq!(config.server_mode, crate::server::mode::ServerMode::Active);
    }

    #[test]
    fn legacy_failover_storage_path_loads_with_a_warning() {
        let config = try_load(&format!("{MINIMAL_CONFIG}[storage_paths]\nfailover = \"../_storage/failover\"\n"))
            .expect("a leftover storage path must load");

        assert_eq!(
            config.load_warnings,
            vec!["storage_paths.failover in config.toml is no longer read and is ignored; remove it.".to_string()]
        );
    }

    #[test]
    fn removed_plaintext_retention_options_still_load() {
        let config = try_load(&format!(
            "{MINIMAL_CONFIG}[encryption]\nenabled = false\nstore_raw_files = true\nprefer_raw_if_modified = true\n"
        ))
        .expect("a config that still sets the removed encryption options must load");

        assert!(
            config
                .load_warnings
                .is_empty()
        );
    }

    #[test]
    fn config_without_legacy_failover_has_no_warnings() {
        let config = try_load(MINIMAL_CONFIG).expect("a minimal config must load");

        assert!(
            config
                .load_warnings
                .is_empty()
        );
    }
}
