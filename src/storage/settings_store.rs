#![allow(dead_code)]

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use tokio::fs;
use tokio::sync::Mutex as AsyncMutex;
use tracing::{info, warn};

/// Process-global settings store, registered once at boot by the orchestrator.
/// Lets subsystems that don't hold an `Arc<SettingsStore>` (e.g. the policy
/// audit gate) read the current settings.
static GLOBAL_SETTINGS: OnceLock<Arc<SettingsStore>> = OnceLock::new();

/// Register the global settings store (called once from the orchestrator).
pub fn set_global_settings_store(store: Arc<SettingsStore>) {
    let _ = GLOBAL_SETTINGS.set(store);
}

/// Read the current system-level settings from the global store. Returns `None`
/// only before [`set_global_settings_store`] has been called (e.g. in unit
/// tests). Each call clones a fresh snapshot, so a settings update made through
/// the same store is immediately visible here — no explicit refresh step.
pub fn global_settings() -> Option<DashboardSettings> {
    GLOBAL_SETTINGS
        .get()
        .map(|s| s.get())
}

/// Whether the given audit category is enabled in the global settings store,
/// read without cloning the settings struct. Returns `false` before the global
/// store is registered. Use this on hot paths (e.g. the policy-decision audit
/// gate) instead of [`global_settings`], which clones the whole struct.
pub fn global_audit_category_enabled(category: &str) -> bool {
    GLOBAL_SETTINGS
        .get()
        .map(|s| s.audit_category_enabled(category))
        .unwrap_or(false)
}

/// Which event categories write to the audit log. All default to `false`, so an
/// older `settings.json` missing these keys deserializes with auditing off.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct AuditCategories {
    /// OPA allow/deny policy decisions (pipe, IDE-member, gateway, surface).
    #[serde(default)]
    pub policies: bool,
    /// TRQP trust-check query outcomes (reserved; not yet recorded in Agent Stream).
    #[serde(default)]
    pub trust_checks: bool,
    /// Managed identity VP injections (reserved; not yet recorded in Agent Stream).
    #[serde(default)]
    pub identity: bool,
}

/// Dashboard and system settings that can be configured by users
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DashboardSettings {
    /// Badge time threshold in minutes for showing "new" or "active" badges
    #[serde(default = "default_badge_threshold_minutes")]
    pub badge_threshold_minutes: u64,

    /// Metrics retention period in hours (how long to keep connection and rule validation metrics)
    #[serde(default = "default_metrics_retention_minutes")]
    pub metrics_retention_minutes: u64,

    /// Task activity scope in seconds (for throughput calculation window)
    #[serde(default = "default_task_activity_window_seconds")]
    pub task_activity_window_seconds: u64,

    /// Total connections window in minutes (sliding window for connection counts)
    #[serde(default = "default_connections_window_minutes")]
    pub connections_window_minutes: u64,

    /// Average latency window in minutes (sliding window for latency calculations)
    #[serde(default = "default_latency_window_minutes")]
    pub latency_window_minutes: u64,

    /// Temporary onboarding channel time-to-live in seconds
    #[serde(default = "default_onboarding_channel_ttl_seconds")]
    pub onboarding_channel_ttl_seconds: u64,

    /// Dashboard auto-refresh interval in seconds
    #[serde(default = "default_refresh_interval_seconds")]
    pub refresh_interval_seconds: u64,

    /// Log timestamp display format (utc, local, relative, compact)
    #[serde(default = "default_log_timestamp_format")]
    pub log_timestamp_format: String,

    /// Time series bucket interval in seconds for aggregated connections graph
    #[serde(default = "default_bucket_seconds")]
    pub bucket_seconds: u64,

    /// Minimum number of payment items to display in the Payments page
    #[serde(default = "default_payments_min_display")]
    pub payments_min_display: u64,

    /// Feature flags for experimental features
    #[serde(default)]
    pub feature_flags: HashMap<String, bool>,

    /// Whether Prometheus metrics endpoint authentication is enabled
    #[serde(default)]
    pub prometheus_auth_enabled: bool,

    /// Username for Prometheus basic auth
    #[serde(default)]
    pub prometheus_auth_username: String,

    /// Bcrypt hash of the Prometheus basic auth password.
    /// Never returned in API responses — only used for verification.
    #[serde(default)]
    pub prometheus_auth_password_hash: String,

    /// Master switch for durable audit-log recording. Off by default — audits
    /// must be explicitly enabled.
    #[serde(default)]
    pub audit_enabled: bool,

    /// Which event categories are written to the audit log when `audit_enabled`.
    #[serde(default)]
    pub audit_categories: AuditCategories,

    /// Operator-set id that fills `${APPLIANCE_ID}` in integration templates,
    /// e.g. the appliance's id in Agent Watch. Empty leaves the variable unfilled.
    #[serde(default)]
    pub appliance_id: String,
}

/// Longest accepted `appliance_id`.
pub const APPLIANCE_ID_MAX_LEN: usize = 256;

/// Whether `id` may be used as an `appliance_id`: printable ASCII without
/// quotes, backslashes, braces or whitespace, so it substitutes safely into
/// JSON and text templates. DIDs, UUIDs and slugs all qualify.
pub fn is_valid_appliance_id(id: &str) -> bool {
    id.len() <= APPLIANCE_ID_MAX_LEN
        && id
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'"' | b'\\' | b'{' | b'}' | b'$'))
}

/// The operator-set appliance id from the global settings store, read under
/// the lock without cloning the settings. `None` when unset or before the
/// store is registered.
pub fn global_appliance_id_override() -> Option<String> {
    GLOBAL_SETTINGS
        .get()
        .and_then(|s| s.appliance_id_override())
}

impl DashboardSettings {
    /// Whether the given audit category is enabled. Returns `false` unless the
    /// master `audit_enabled` switch is on AND the category is enabled.
    pub fn audit_category_enabled(
        &self,
        category: &str,
    ) -> bool {
        if !self.audit_enabled {
            return false;
        }
        match category {
            "policies" => self.audit_categories.policies,
            "trust_checks" => {
                self.audit_categories
                    .trust_checks
            }
            "identity" => self.audit_categories.identity,
            _ => false,
        }
    }
}

/// Settings as every settings response returns them. The Prometheus password
/// hash is only for verification, so this response can only be built with it removed.
#[derive(Debug, Serialize)]
#[serde(transparent)]
pub struct SettingsResponse(DashboardSettings);

impl From<DashboardSettings> for SettingsResponse {
    fn from(mut settings: DashboardSettings) -> Self {
        settings
            .prometheus_auth_password_hash
            .clear();
        Self(settings)
    }
}

fn default_badge_threshold_minutes() -> u64 {
    5
}

fn default_metrics_retention_minutes() -> u64 {
    6 * 60 // 6 hours in minutes (360 minutes)
}

fn default_task_activity_window_seconds() -> u64 {
    60
}

fn default_connections_window_minutes() -> u64 {
    60
}

fn default_latency_window_minutes() -> u64 {
    60
}

fn default_onboarding_channel_ttl_seconds() -> u64 {
    30
}

fn default_refresh_interval_seconds() -> u64 {
    5
}

fn default_log_timestamp_format() -> String {
    "local".to_string()
}

fn default_bucket_seconds() -> u64 {
    30
}

fn default_payments_min_display() -> u64 {
    10
}

impl Default for DashboardSettings {
    fn default() -> Self {
        Self {
            badge_threshold_minutes: default_badge_threshold_minutes(),
            metrics_retention_minutes: default_metrics_retention_minutes(),
            task_activity_window_seconds: default_task_activity_window_seconds(),
            connections_window_minutes: default_connections_window_minutes(),
            latency_window_minutes: default_latency_window_minutes(),
            onboarding_channel_ttl_seconds: default_onboarding_channel_ttl_seconds(),
            refresh_interval_seconds: default_refresh_interval_seconds(),
            log_timestamp_format: default_log_timestamp_format(),
            bucket_seconds: default_bucket_seconds(),
            payments_min_display: default_payments_min_display(),
            feature_flags: HashMap::new(),
            prometheus_auth_enabled: false,
            prometheus_auth_username: String::new(),
            prometheus_auth_password_hash: String::new(),
            audit_enabled: false,
            audit_categories: AuditCategories::default(),
            appliance_id: String::new(),
        }
    }
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for SettingsStore {
    /// Re-read the settings the previous Active saved, so a later partial
    /// update does not write this instance's startup copy back. Unlike
    /// [`SettingsStore::load`], it never writes: a missing or unparsable file
    /// keeps the current settings.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        let _persist = self.persist_lock.lock().await;
        let content = match fs::read(&self.storage_path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(e),
        };
        match serde_json::from_slice::<DashboardSettings>(&content) {
            Ok(settings) => {
                *self
                    .settings
                    .write()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = settings;
            }
            Err(e) => warn!("Failed to parse settings file on promotion, keeping current settings: {}", e),
        }
        Ok(())
    }
}

/// Settings store that manages persistent dashboard settings
#[derive(Clone)]
pub struct SettingsStore {
    settings: Arc<RwLock<DashboardSettings>>,
    storage_path: PathBuf,
    persist_lock: Arc<AsyncMutex<()>>,
}

impl SettingsStore {
    /// Create a new settings store with the specified storage directory
    pub fn new<P: AsRef<Path>>(storage_dir: P) -> Self {
        let storage_path = storage_dir
            .as_ref()
            .join("settings.json");

        Self {
            settings: Arc::new(RwLock::new(DashboardSettings::default())),
            storage_path,
            persist_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Load settings from disk (async version)
    pub async fn load(&self) -> Result<()> {
        // Create settings directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create settings directory: {:?}", parent))?;
        }

        // Try to load existing settings file
        if self.storage_path.exists() {
            match fs::read_to_string(&self.storage_path).await {
                Ok(content) => {
                    match serde_json::from_str::<DashboardSettings>(&content) {
                        Ok(settings) => {
                            info!("Loaded settings from {:?}", self.storage_path);
                            info!("  Badge threshold: {} minutes", settings.badge_threshold_minutes);
                            info!("  Metrics retention: {} minutes", settings.metrics_retention_minutes);
                            info!("  Onboarding channel TTL: {} seconds", settings.onboarding_channel_ttl_seconds);

                            let mut current = self.settings.write().unwrap();
                            *current = settings;
                        }
                        Err(e) => {
                            warn!("Failed to parse settings file, using defaults: {}", e);
                            // Save default settings
                            self.save().await?;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read settings file, using defaults: {}", e);
                    // Save default settings
                    self.save().await?;
                }
            }
        } else {
            info!("Settings file not found, creating with defaults: {:?}", self.storage_path);
            // Save default settings
            self.save().await?;
        }

        Ok(())
    }

    /// Load settings from disk (synchronous version)
    pub fn load_sync(&self) -> Result<()> {
        // Create settings directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create settings directory: {:?}", parent))?;
        }

        // Try to load existing settings file
        if self.storage_path.exists() {
            match std::fs::read_to_string(&self.storage_path) {
                Ok(content) => {
                    match serde_json::from_str::<DashboardSettings>(&content) {
                        Ok(settings) => {
                            info!("Loaded settings from {:?}", self.storage_path);
                            info!("  Badge threshold: {} minutes", settings.badge_threshold_minutes);
                            info!("  Metrics retention: {} minutes", settings.metrics_retention_minutes);
                            info!("  Onboarding channel TTL: {} seconds", settings.onboarding_channel_ttl_seconds);

                            let mut current = self.settings.write().unwrap();
                            *current = settings;
                        }
                        Err(e) => {
                            warn!("Failed to parse settings file, using defaults: {}", e);
                            // Save default settings
                            self.save_sync()?;
                        }
                    }
                }
                Err(e) => {
                    warn!("Failed to read settings file, using defaults: {}", e);
                    // Save default settings
                    self.save_sync()?;
                }
            }
        } else {
            info!("Settings file not found, creating with defaults: {:?}", self.storage_path);
            // Save default settings
            self.save_sync()?;
        }

        Ok(())
    }

    /// Save current settings to disk (async version)
    pub async fn save(&self) -> Result<()> {
        let settings = self
            .settings
            .read()
            .unwrap()
            .clone();

        // Create settings directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create settings directory: {:?}", parent))?;
        }

        // Serialize settings to JSON
        let json = serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;

        // Write to file
        fs::write(&self.storage_path, json)
            .await
            .with_context(|| format!("Failed to write settings to {:?}", self.storage_path))?;

        info!("Saved settings to {:?}", self.storage_path);

        Ok(())
    }

    /// Save current settings to disk (synchronous version)
    pub fn save_sync(&self) -> Result<()> {
        let settings = self
            .settings
            .read()
            .unwrap()
            .clone();

        // Create settings directory if it doesn't exist
        if let Some(parent) = self.storage_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create settings directory: {:?}", parent))?;
        }

        // Serialize settings to JSON
        let json = serde_json::to_string_pretty(&settings).context("Failed to serialize settings")?;

        // Write to file
        std::fs::write(&self.storage_path, json)
            .with_context(|| format!("Failed to write settings to {:?}", self.storage_path))?;

        info!("Saved settings to {:?}", self.storage_path);

        Ok(())
    }

    /// Get current settings
    pub fn get(&self) -> DashboardSettings {
        self.settings
            .read()
            .unwrap()
            .clone()
    }

    /// Whether the given audit category is enabled, read under the lock without
    /// cloning the whole settings struct. This is on the request hot path (the
    /// policy-decision audit gate runs on every allow/deny at every enforcement
    /// point), so it must not allocate.
    pub fn audit_category_enabled(
        &self,
        category: &str,
    ) -> bool {
        self.settings
            .read()
            .unwrap()
            .audit_category_enabled(category)
    }

    /// The operator-set appliance id, or `None` when it is empty.
    pub fn appliance_id_override(&self) -> Option<String> {
        let settings = self.settings.read().unwrap();
        let id = settings.appliance_id.trim();
        (!id.is_empty()).then(|| id.to_string())
    }

    pub fn validate(new_settings: &DashboardSettings) -> Result<()> {
        if new_settings.badge_threshold_minutes < 1 {
            anyhow::bail!("Badge threshold must be at least 1 minute");
        }

        if !is_valid_appliance_id(&new_settings.appliance_id) {
            anyhow::bail!(
                "Appliance ID must be at most {APPLIANCE_ID_MAX_LEN} printable characters without spaces, quotes, backslashes, braces or $"
            );
        }

        if new_settings.metrics_retention_minutes < 1 || new_settings.metrics_retention_minutes > 10080 {
            anyhow::bail!("Metrics retention must be between 1 and 10,080 minutes (7 days)");
        }

        Ok(())
    }

    /// Persist a complete settings snapshot before publishing it to runtime readers.
    pub async fn persist(
        &self,
        new_settings: DashboardSettings,
    ) -> Result<()> {
        Self::validate(&new_settings)?;
        let _guard = self.persist_lock.lock().await;

        if let Some(parent) = self.storage_path.parent() {
            fs::create_dir_all(parent)
                .await
                .with_context(|| format!("Failed to create settings directory: {:?}", parent))?;
        }

        let json = serde_json::to_string_pretty(&new_settings).context("Failed to serialize settings")?;
        let temp_path = self
            .storage_path
            .with_extension(format!("json.{}.tmp", uuid::Uuid::new_v4()));
        fs::write(&temp_path, json)
            .await
            .with_context(|| format!("Failed to write settings to {:?}", temp_path))?;
        if let Err(error) = fs::rename(&temp_path, &self.storage_path).await {
            let _ = fs::remove_file(&temp_path).await;
            return Err(error).with_context(|| format!("Failed to replace settings at {:?}", self.storage_path));
        }

        let mut current = self.settings.write().unwrap();
        *current = new_settings;
        info!("Saved settings to {:?}", self.storage_path);
        Ok(())
    }

    /// Update settings
    pub fn update(
        &self,
        new_settings: DashboardSettings,
    ) -> Result<()> {
        Self::validate(&new_settings)?;

        let mut current = self.settings.write().unwrap();
        *current = new_settings;

        Ok(())
    }

    /// Get metrics retention minutes
    pub fn get_metrics_retention_minutes(&self) -> u64 {
        self.settings
            .read()
            .unwrap()
            .metrics_retention_minutes
    }

    /// Get badge threshold minutes
    pub fn get_badge_threshold_minutes(&self) -> u64 {
        self.settings
            .read()
            .unwrap()
            .badge_threshold_minutes
    }

    /// Get temporary channel TTL in seconds
    pub fn get_onboarding_channel_ttl_seconds(&self) -> u64 {
        self.settings
            .read()
            .unwrap()
            .onboarding_channel_ttl_seconds
    }

    /// Get the storage directory path (for constructing user settings paths)
    pub fn storage_dir(&self) -> &Path {
        self.storage_path
            .parent()
            .unwrap_or(Path::new("."))
    }
}

/// Per-user settings that override system defaults for display preferences.
/// All fields are optional — when set, they override the corresponding system setting.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UserSettings {
    /// Dashboard auto-refresh interval in seconds (overrides system default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_interval_seconds: Option<u64>,

    /// Log timestamp display format (overrides system default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_timestamp_format: Option<String>,

    /// Time series bucket interval in seconds (overrides system default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bucket_seconds: Option<u64>,

    /// Badge time threshold in minutes (overrides system default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub badge_threshold_minutes: Option<u64>,

    /// Minimum payment items to display (overrides system default)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub payments_min_display: Option<u64>,

    /// Feature flags overrides (overrides system default per flag)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub feature_flags: Option<HashMap<String, bool>>,
}

/// Per-user settings store that manages user-specific dashboard preferences.
/// Stores settings in `{storage_dir}/users/{user_id}.json`.
pub struct UserSettingsStore {
    storage_dir: PathBuf,
}

impl UserSettingsStore {
    /// Create a new user settings store under the given settings storage directory
    pub fn new<P: AsRef<Path>>(settings_dir: P) -> Self {
        Self {
            storage_dir: settings_dir
                .as_ref()
                .join("users"),
        }
    }

    /// Get user settings for a specific user
    pub async fn get(
        &self,
        user_id: &str,
    ) -> Result<UserSettings> {
        let path = self.user_path(user_id);
        if path.exists() {
            let content = fs::read_to_string(&path)
                .await
                .with_context(|| format!("Failed to read user settings: {:?}", path))?;
            serde_json::from_str(&content).with_context(|| format!("Failed to parse user settings: {:?}", path))
        } else {
            Ok(UserSettings::default())
        }
    }

    /// Update user settings
    pub async fn update(
        &self,
        user_id: &str,
        settings: UserSettings,
    ) -> Result<()> {
        // Validate
        if let Some(refresh) = settings.refresh_interval_seconds
            && (!(1..=300).contains(&refresh))
        {
            anyhow::bail!("Refresh interval must be between 1 and 300 seconds");
        }
        if let Some(badge) = settings.badge_threshold_minutes
            && badge < 1
        {
            anyhow::bail!("Badge threshold must be at least 1 minute");
        }
        if let Some(ref format) = settings.log_timestamp_format
            && !["utc", "local", "relative", "compact"].contains(&format.as_str())
        {
            anyhow::bail!("Invalid log timestamp format: {}", format);
        }

        // Ensure directory exists
        fs::create_dir_all(&self.storage_dir)
            .await
            .with_context(|| format!("Failed to create user settings directory: {:?}", self.storage_dir))?;

        let path = self.user_path(user_id);
        let json = serde_json::to_string_pretty(&settings).context("Failed to serialize user settings")?;
        fs::write(&path, json)
            .await
            .with_context(|| format!("Failed to write user settings: {:?}", path))?;

        info!("Saved user settings for user {}", user_id);
        Ok(())
    }

    /// Delete user settings (reset to system defaults)
    pub async fn delete(
        &self,
        user_id: &str,
    ) -> Result<()> {
        let path = self.user_path(user_id);
        if path.exists() {
            fs::remove_file(&path)
                .await
                .with_context(|| format!("Failed to delete user settings: {:?}", path))?;
            info!("Deleted user settings for user {}", user_id);
        }
        Ok(())
    }

    /// Get effective settings for a user (user overrides merged with system defaults)
    pub fn merge_with_system(
        &self,
        user_settings: &UserSettings,
        system: &DashboardSettings,
    ) -> DashboardSettings {
        DashboardSettings {
            refresh_interval_seconds: user_settings
                .refresh_interval_seconds
                .unwrap_or(system.refresh_interval_seconds),
            log_timestamp_format: user_settings
                .log_timestamp_format
                .clone()
                .unwrap_or_else(|| {
                    system
                        .log_timestamp_format
                        .clone()
                }),
            bucket_seconds: user_settings
                .bucket_seconds
                .unwrap_or(system.bucket_seconds),
            badge_threshold_minutes: user_settings
                .badge_threshold_minutes
                .unwrap_or(system.badge_threshold_minutes),
            payments_min_display: user_settings
                .payments_min_display
                .unwrap_or(system.payments_min_display),
            // System-level fields always come from system settings
            metrics_retention_minutes: system.metrics_retention_minutes,
            task_activity_window_seconds: system.task_activity_window_seconds,
            connections_window_minutes: system.connections_window_minutes,
            latency_window_minutes: system.latency_window_minutes,
            onboarding_channel_ttl_seconds: system.onboarding_channel_ttl_seconds,
            feature_flags: {
                let mut flags = system.feature_flags.clone();
                if let Some(ref user_flags) = user_settings.feature_flags {
                    flags.extend(
                        user_flags
                            .iter()
                            .map(|(k, v)| (k.clone(), *v)),
                    );
                }
                flags
            },
            // System-level: prometheus auth always comes from system settings
            prometheus_auth_enabled: system.prometheus_auth_enabled,
            prometheus_auth_username: system
                .prometheus_auth_username
                .clone(),
            // Only the system settings verify the password, so the merge never carries its hash.
            prometheus_auth_password_hash: String::new(),
            // System-level: audit config always comes from system settings.
            audit_enabled: system.audit_enabled,
            audit_categories: system
                .audit_categories
                .clone(),
            appliance_id: system.appliance_id.clone(),
        }
    }

    fn user_path(
        &self,
        user_id: &str,
    ) -> PathBuf {
        // Sanitize user_id to prevent path traversal
        let safe_id: String = user_id
            .chars()
            .map(|c| {
                if c == '/' || c == '\\' || c == '.' || c == '\0' {
                    '_'
                } else {
                    c
                }
            })
            .collect();
        self.storage_dir
            .join(format!("{}.json", safe_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[tokio::test]
    async fn reload_picks_up_settings_another_instance_saved() {
        use crate::server::mode::ReloadOnPromotion;

        let temp_dir = TempDir::new().unwrap();
        let standby = SettingsStore::new(temp_dir.path());
        standby.load().await.unwrap();
        let active = SettingsStore::new(temp_dir.path());
        active
            .persist(DashboardSettings {
                badge_threshold_minutes: 42,
                ..DashboardSettings::default()
            })
            .await
            .unwrap();

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert_eq!(
            standby
                .get()
                .badge_threshold_minutes,
            42
        );
    }

    #[tokio::test]
    async fn reload_keeps_settings_and_file_when_the_file_is_unusable() {
        use crate::server::mode::ReloadOnPromotion;

        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());
        store
            .persist(DashboardSettings {
                badge_threshold_minutes: 7,
                ..DashboardSettings::default()
            })
            .await
            .unwrap();
        let path = temp_dir
            .path()
            .join("settings.json");
        tokio::fs::write(&path, "not json")
            .await
            .unwrap();

        store
            .reload_from_storage()
            .await
            .unwrap();
        tokio::fs::remove_file(&path)
            .await
            .unwrap();
        store
            .reload_from_storage()
            .await
            .unwrap();

        assert_eq!(
            store
                .get()
                .badge_threshold_minutes,
            7
        );
        assert!(!path.exists(), "a reload never writes defaults");
    }

    #[tokio::test]
    async fn reload_treats_a_file_that_is_not_utf8_as_unparseable() {
        use crate::server::mode::ReloadOnPromotion;

        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());
        store
            .persist(DashboardSettings {
                badge_threshold_minutes: 7,
                ..DashboardSettings::default()
            })
            .await
            .unwrap();
        tokio::fs::write(
            temp_dir
                .path()
                .join("settings.json"),
            [0xff, 0xfe, 0xfd],
        )
        .await
        .unwrap();

        store
            .reload_from_storage()
            .await
            .expect("an unparseable file does not hold readiness back");

        assert_eq!(
            store
                .get()
                .badge_threshold_minutes,
            7
        );
    }

    #[test]
    fn test_default_settings() {
        let settings = DashboardSettings::default();
        assert_eq!(settings.badge_threshold_minutes, 5);
        assert_eq!(settings.metrics_retention_minutes, 360);
        assert!(
            settings
                .appliance_id
                .is_empty()
        );
    }

    #[test]
    fn appliance_id_accepts_dids_uuids_and_slugs() {
        for id in ["", "did:web:as.example.com%3A8443", "7f3c2a1e-9b4d-4c8e-a1f2-3b4c5d6e7f80", "aw-appliance_42.eu"] {
            let settings = DashboardSettings {
                appliance_id: id.to_string(),
                ..DashboardSettings::default()
            };
            assert!(SettingsStore::validate(&settings).is_ok(), "{id} must be accepted");
        }
    }

    #[test]
    fn appliance_id_rejects_values_that_break_templates() {
        for id in
            ["has space", "quote\"d", "back\\slash", "${OTHER}", "line\nbreak", &"a".repeat(APPLIANCE_ID_MAX_LEN + 1)]
        {
            let settings = DashboardSettings {
                appliance_id: id.to_string(),
                ..DashboardSettings::default()
            };
            assert!(SettingsStore::validate(&settings).is_err(), "{id} must be rejected");
        }
    }

    #[test]
    fn appliance_id_override_is_none_when_empty() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());
        assert_eq!(store.appliance_id_override(), None);

        store
            .update(DashboardSettings {
                appliance_id: "aw-appliance-42".to_string(),
                ..DashboardSettings::default()
            })
            .unwrap();
        assert_eq!(store.appliance_id_override(), Some("aw-appliance-42".to_string()));
    }

    #[test]
    fn test_settings_store_sync() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());

        // Load should create default settings
        store.load_sync().unwrap();

        let settings = store.get();
        assert_eq!(settings.badge_threshold_minutes, 5);
        assert_eq!(settings.metrics_retention_minutes, 360);

        // Update settings
        let new_settings = DashboardSettings {
            badge_threshold_minutes: 10,
            metrics_retention_minutes: 720,
            task_activity_window_seconds: 90,
            connections_window_minutes: 120,
            latency_window_minutes: 90,
            onboarding_channel_ttl_seconds: 30,
            refresh_interval_seconds: 30,
            log_timestamp_format: "utc".to_string(),
            bucket_seconds: 60,
            payments_min_display: 10,
            feature_flags: HashMap::new(),
            ..DashboardSettings::default()
        };
        store
            .update(new_settings)
            .unwrap();
        store.save_sync().unwrap();

        // Create new store and load
        let store2 = SettingsStore::new(temp_dir.path());
        store2.load_sync().unwrap();

        let loaded = store2.get();
        assert_eq!(loaded.badge_threshold_minutes, 10);
        assert_eq!(loaded.metrics_retention_minutes, 720);
    }

    #[tokio::test]
    async fn successful_persistence_publishes_and_reloads_complete_snapshot() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());
        let requested = DashboardSettings {
            audit_enabled: true,
            audit_categories: AuditCategories {
                policies: true,
                ..AuditCategories::default()
            },
            ..DashboardSettings::default()
        };

        store
            .persist(requested.clone())
            .await
            .unwrap();

        assert!(store.get().audit_enabled);
        let reloaded = SettingsStore::new(temp_dir.path());
        reloaded.load().await.unwrap();
        assert!(reloaded.get().audit_enabled);
        assert_eq!(
            reloaded
                .get()
                .audit_categories,
            requested.audit_categories
        );
    }

    #[tokio::test]
    async fn failed_persistence_keeps_runtime_settings_unchanged() {
        let temp_dir = TempDir::new().unwrap();
        let blocked_parent = temp_dir
            .path()
            .join("blocked");
        std::fs::write(&blocked_parent, "not a directory").unwrap();
        let store = SettingsStore::new(&blocked_parent);
        let original = store.get();
        let requested = DashboardSettings {
            audit_enabled: true,
            audit_categories: AuditCategories {
                policies: true,
                ..AuditCategories::default()
            },
            ..original.clone()
        };

        store
            .persist(requested)
            .await
            .expect_err("persistence through a file parent must fail");

        assert_eq!(store.get().audit_enabled, original.audit_enabled);
        assert_eq!(store.get().audit_categories, original.audit_categories);
    }

    #[test]
    fn test_validation() {
        let temp_dir = TempDir::new().unwrap();
        let store = SettingsStore::new(temp_dir.path());

        // Invalid badge threshold
        let invalid = DashboardSettings {
            badge_threshold_minutes: 0,
            ..DashboardSettings::default()
        };
        assert!(store.update(invalid).is_err());

        // Invalid metrics retention (too low)
        let invalid = DashboardSettings {
            metrics_retention_minutes: 0,
            ..DashboardSettings::default()
        };
        assert!(store.update(invalid).is_err());

        // Invalid metrics retention (too high)
        let invalid = DashboardSettings {
            metrics_retention_minutes: 10081,
            ..DashboardSettings::default()
        };
        assert!(store.update(invalid).is_err());
    }

    #[tokio::test]
    async fn test_user_settings_store() {
        let temp_dir = TempDir::new().unwrap();
        let store = UserSettingsStore::new(temp_dir.path());

        // Default: no user settings
        let settings = store
            .get("user-123")
            .await
            .unwrap();
        assert!(
            settings
                .refresh_interval_seconds
                .is_none()
        );
        assert!(
            settings
                .log_timestamp_format
                .is_none()
        );

        // Update user settings
        let user_settings = UserSettings {
            refresh_interval_seconds: Some(10),
            log_timestamp_format: Some("utc".to_string()),
            bucket_seconds: Some(60),
            badge_threshold_minutes: None,
            payments_min_display: None,
            feature_flags: None,
        };
        store
            .update("user-123", user_settings)
            .await
            .unwrap();

        // Load back
        let loaded = store
            .get("user-123")
            .await
            .unwrap();
        assert_eq!(loaded.refresh_interval_seconds, Some(10));
        assert_eq!(
            loaded
                .log_timestamp_format
                .as_deref(),
            Some("utc")
        );
        assert_eq!(loaded.bucket_seconds, Some(60));
        assert!(
            loaded
                .badge_threshold_minutes
                .is_none()
        );

        // Merge with system defaults
        let system = DashboardSettings::default();
        let effective = store.merge_with_system(&loaded, &system);
        assert_eq!(effective.refresh_interval_seconds, 10); // User override
        assert_eq!(effective.log_timestamp_format, "utc"); // User override
        assert_eq!(effective.bucket_seconds, 60); // User override
        assert_eq!(effective.badge_threshold_minutes, 5); // System default
        assert_eq!(effective.metrics_retention_minutes, 360); // System default (always)

        // Delete user settings
        store
            .delete("user-123")
            .await
            .unwrap();
        let deleted = store
            .get("user-123")
            .await
            .unwrap();
        assert!(
            deleted
                .refresh_interval_seconds
                .is_none()
        );
    }

    const PROMETHEUS_HASH: &str = "$2b$12$abcdefghijklmnopqrstuuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ012";

    fn settings_with_prometheus_auth() -> DashboardSettings {
        DashboardSettings {
            prometheus_auth_enabled: true,
            prometheus_auth_username: "scraper".to_string(),
            prometheus_auth_password_hash: PROMETHEUS_HASH.to_string(),
            ..DashboardSettings::default()
        }
    }

    #[test]
    fn merged_user_settings_never_carry_the_prometheus_password_hash() {
        let temp_dir = TempDir::new().unwrap();
        let store = UserSettingsStore::new(temp_dir.path());

        let effective = store.merge_with_system(&UserSettings::default(), &settings_with_prometheus_auth());

        assert_eq!(effective.prometheus_auth_password_hash, "");
        assert!(effective.prometheus_auth_enabled);
        assert_eq!(effective.prometheus_auth_username, "scraper");
    }

    #[test]
    fn the_settings_response_omits_the_prometheus_password_hash() {
        let json = serde_json::to_value(SettingsResponse::from(settings_with_prometheus_auth())).unwrap();

        assert_eq!(json["prometheus_auth_password_hash"], "");
        assert_eq!(json["prometheus_auth_enabled"], true);
        assert_eq!(json["prometheus_auth_username"], "scraper");
        assert!(
            !json
                .to_string()
                .contains(PROMETHEUS_HASH),
            "{json}"
        );
    }

    #[tokio::test]
    async fn test_user_settings_validation() {
        let temp_dir = TempDir::new().unwrap();
        let store = UserSettingsStore::new(temp_dir.path());

        // Invalid refresh interval
        let invalid = UserSettings {
            refresh_interval_seconds: Some(0),
            ..Default::default()
        };
        assert!(
            store
                .update("user-1", invalid)
                .await
                .is_err()
        );

        // Invalid log format
        let invalid = UserSettings {
            log_timestamp_format: Some("invalid".to_string()),
            ..Default::default()
        };
        assert!(
            store
                .update("user-1", invalid)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn test_user_settings_path_sanitization() {
        let temp_dir = TempDir::new().unwrap();
        let store = UserSettingsStore::new(temp_dir.path());

        let sanitized_user_id = "______etc_passwd";
        let malicious_user_id = "../../../etc/passwd";
        let dangerous_path = temp_dir
            .path()
            .join("users")
            .join(format!("{malicious_user_id}.json"));
        let sanitized_path = temp_dir
            .path()
            .join("users")
            .join(format!("{sanitized_user_id}.json"));

        // Verify the dangerous traversal path does not already exist (precondition)
        assert!(!dangerous_path.exists(), "Precondition failed: dangerous path already exists at {:?}", dangerous_path);

        // User ID with path traversal characters should be sanitized
        let settings = UserSettings {
            refresh_interval_seconds: Some(15),
            ..Default::default()
        };
        store
            .update(sanitized_user_id, settings.clone())
            .await
            .unwrap();

        store
            .update(malicious_user_id, settings)
            .await
            .unwrap();

        // The sanitized file must live inside the users/ directory
        assert!(sanitized_path.exists(), "Sanitized settings file should exist at {:?}", sanitized_path);

        // The dangerous traversal path must NOT exist
        assert!(!dangerous_path.exists(), "Path traversal must not create file at {:?}", dangerous_path);

        // Round-trip should still work
        let loaded = store
            .get(malicious_user_id)
            .await
            .unwrap();
        assert_eq!(loaded.refresh_interval_seconds, Some(15));
    }
}
