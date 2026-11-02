//! Generic filesystem storage for JSON-serializable entities
//!
//! Provides both cached and non-cached storage implementations with
//! common CRUD operations for any type that implements `StorableEntity`.
//!
//! # Encryption at Rest
//!
//! All storage implementations support encryption using AES-GCM AEAD, which
//! `[encryption]` enables or explicitly opts out of. When enabled, data is encrypted before writing to disk and decrypted
//! when reading from disk.

use crate::encryption::{EncryptionService, init::init_encryption_service};
use anyhow::{Context, Result};
use async_trait::async_trait;
use dashmap::DashMap;
use serde::{Serialize, de::DeserializeOwned};
use std::borrow::Cow;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::fs;
use tokio::sync::broadcast;
use tokio::time::{Duration, interval};
use tracing::{debug, error, info, warn};

// ============================================================================
// Global Encryption Configuration
// ============================================================================

use once_cell::sync::Lazy;
use std::sync::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Global encryption service for serde operations
/// This is initialized by the application and used throughout serialization
static GLOBAL_STORAGE_CONFIG: Lazy<RwLock<Option<StorageConfig>>> = Lazy::new(|| RwLock::new(None));
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);
static CACHE_REFRESH_INTERVAL_SECS: AtomicU64 = AtomicU64::new(0);
static WARNED_RETIRED_RECORDS: Lazy<std::sync::Mutex<std::collections::HashSet<PathBuf>>> = Lazy::new(Default::default);

/// Error for [`StorableEntity::migrate_raw_json`] to return for a record of a
/// kind that was removed and can never load again. The loader skips the record
/// and leaves its file on disk, like any failed record, but does not count it as
/// a load error and warns about it once per file per process, so a periodic
/// cache refresh does not log it again on every tick. The message must not
/// contain the record's content.
#[derive(Debug)]
pub struct RetiredRecord(pub String);

impl std::fmt::Display for RetiredRecord {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for RetiredRecord {}

/// Returns true the first time it is called for `path` in this process.
fn first_retired_record_warning(path: &Path) -> bool {
    WARNED_RETIRED_RECORDS
        .lock()
        .map(|mut warned| warned.insert(path.to_path_buf()))
        .unwrap_or(true)
}

/// Logs a skipped retired record at WARN the first time per file, then at DEBUG.
fn warn_retired_record<T: StorableEntity>(
    entity_name: &str,
    path: &Path,
    id: &str,
    retired: &RetiredRecord,
) {
    let logged_path = loggable_path::<T>(path, id);
    if first_retired_record_warning(path) {
        warn!("Skipping {} from {}: {}", entity_name, logged_path, retired);
    } else {
        debug!("Skipping {} from {}: {}", entity_name, logged_path, retired);
    }
}

pub fn set_cache_refresh_interval_secs(secs: u64) {
    CACHE_REFRESH_INTERVAL_SECS.store(secs, Ordering::Relaxed);
}

pub fn cache_refresh_interval_secs() -> u64 {
    CACHE_REFRESH_INTERVAL_SECS.load(Ordering::Relaxed)
}

pub fn cache_refresh_enabled() -> bool {
    cache_refresh_interval_secs() > 0
}

/// Initialize the global encryption service
///
/// Constructs the `EncryptionService` internally from the given config
/// via `init_encryption_service`. Must be called before any encrypted
/// structs are serialized/deserialized.
pub fn init_global_encryption(encryption_config: crate::config::EncryptionConfig) -> anyhow::Result<()> {
    let storage_config = storage_config_from_encryption_config(&encryption_config)?;
    let mut global_storage_config = GLOBAL_STORAGE_CONFIG
        .write()
        .unwrap();
    *global_storage_config = Some(storage_config);

    debug!("Global storage config initialized for all storage operations");
    Ok(())
}

/// Get the global storage config, falling back to default if not initialized
fn get_global_storage_config() -> StorageConfig {
    GLOBAL_STORAGE_CONFIG
        .read()
        .unwrap()
        .clone()
        .unwrap_or_default()
}

// ============================================================================
// Core Traits
// ============================================================================

/// Trait for entities that can be stored in filesystem storage
///
/// Types implementing this trait must be serializable to JSON and provide
/// an ID for filesystem naming.
pub trait StorableEntity: Serialize + DeserializeOwned + Clone + Send + Sync + 'static {
    /// Get the unique identifier for this entity
    ///
    /// This ID will be used as the filename (with .json extension)
    fn id(&self) -> &str;

    /// Whether the id is itself a credential, such as a session token, so it is
    /// never logged in full.
    const ID_IS_SECRET: bool = false;

    /// Optional hook called after loading from disk
    ///
    /// Use this for data normalization, migrations, or validation
    /// after deserialization.
    fn on_load(&mut self) {
        // Default: no-op
    }

    /// Pre-deserialization migration hook for raw JSON.
    ///
    /// Called on the raw `serde_json::Value` before deserializing into the typed entity.
    /// Returns `Ok(true)` if the JSON was modified (indicating the file should be re-persisted),
    /// `Ok(false)` if no changes were made, or `Err` if the migration encountered an error.
    ///
    /// Use this for schema migrations that must run before deserialization — e.g. renaming
    /// or transforming fields that no longer exist on the Rust struct.
    fn migrate_raw_json(_value: &mut serde_json::Value) -> Result<bool> {
        Ok(false)
    }
}

/// Type alias for the RwLock-based cache used by `RwLockFilesystemStorage`
///
/// Callers that need direct mutable access to the cache (e.g. session cleanup)
/// should use `raw_cache()` which returns this type.
pub type StorageCache<T> = Arc<tokio::sync::RwLock<std::collections::HashMap<String, T>>>;

/// Type alias for the DashMap-based cache used by `CachedFilesystemStorage`
///
/// DashMap provides lock-free concurrent reads and fine-grained per-shard
/// locking for writes, making it ideal for high-concurrency read-heavy workloads.
pub type DashMapCache<T> = Arc<DashMap<String, T>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageEventSource {
    LocalWrite,
    RemoteWrite,
}

#[derive(Clone)]
pub enum StorageEvent<T: StorableEntity> {
    Upsert {
        #[allow(dead_code)]
        id: String,
        #[allow(dead_code)]
        entity: T,
        source: StorageEventSource,
    },
    Delete {
        #[allow(dead_code)]
        id: String,
        source: StorageEventSource,
    },
}

/// Trait for filesystem storage operations
///
/// Provides a common interface for CRUD operations that can be
/// implemented by different storage backends.
#[async_trait]
pub trait StorageBackend<T: StorableEntity>: Send + Sync {
    /// Create or update an entity
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()>;

    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        self.save(entity).await
    }

    /// Get an entity by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>>;

    /// List all entities
    async fn list_all(&self) -> Result<Vec<T>>;

    /// Delete an entity by ID
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Check if an entity exists
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }

    /// Return a snapshot of all entities as a HashMap.
    ///
    /// Cached backends read from the in-memory cache; the uncached
    /// backend loads from disk.  The RwLock is acquired (and released)
    /// internally so callers never see the lock.
    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        let entities = self.list_all().await?;
        Ok(entities
            .into_iter()
            .map(|e| (e.id().to_string(), e))
            .collect())
    }

    /// Get a direct reference to the underlying RwLock cache.
    ///
    /// Returns `Some` for RwLock-based backends (`RwLockFilesystemStorage`,
    /// `InMemoryStorage`), `None` for DashMap-backed and uncached backends.
    /// Use this only when you need mutable (write) access to the
    /// cache, e.g. during initialisation fixups.  For read-only
    /// snapshots prefer `hash_map()`.
    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        None
    }

    fn subscribe(&self) -> Option<broadcast::Receiver<StorageEvent<T>>> {
        None
    }

    async fn refresh_from_disk(&self) -> Result<()> {
        Ok(())
    }
}

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for filesystem storage
///
/// Controls how data is stored on disk, including whether it is encrypted.
#[derive(Clone, Debug)]
pub struct StorageConfig {
    /// Enable encryption at rest
    pub encryption_service: Option<EncryptionService>,

    /// Return an error when any candidate entity file cannot be loaded.
    /// Existing callers remain fail-open unless they opt in.
    pub strict_loading: bool,
}

impl StorageConfig {
    /// Create a new config without encryption
    pub fn new() -> Self {
        Self {
            encryption_service: None,
            strict_loading: false,
        }
    }

    pub fn with_strict_loading(mut self) -> Self {
        self.strict_loading = true;
        self
    }

    /// Add encryption to the config
    pub fn with_encryption_service(
        mut self,
        service: EncryptionService,
    ) -> Self {
        self.encryption_service = Some(service);
        self
    }
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Helper Functions for EncryptionConfig Integration
// ============================================================================

/// Create StorageConfig from EncryptionConfig
///
/// This bridges the on-disk TOML configuration (EncryptionConfig) to runtime
/// storage configuration (StorageConfig). If encryption is enabled, it loads
/// the key from the configured source and creates an Encryptor.
///
/// # Arguments
/// * `encryption_config` - EncryptionConfig from BootstrapConfig
///
/// # Errors
/// Returns an error if:
/// - Key loading fails
/// - Key has invalid format or encoding
/// - EncryptionService creation fails
pub fn storage_config_from_encryption_config(
    encryption_config: &crate::config::EncryptionConfig
) -> Result<StorageConfig> {
    let mut config = StorageConfig::default();
    if encryption_config.enabled {
        let encryption_service =
            init_encryption_service(encryption_config).context("Failed to initialize encryption service")?;
        config = config.with_encryption_service(encryption_service);
    }

    Ok(config)
}

/// Returns the globally configured file-level encryption service when encryption
/// is enabled, otherwise `None`.
///
/// Stores that persist through a bespoke file path rather than the generic
/// `StorageBackend` helpers use this to encrypt their on-disk representation
/// with the same envelope service as the rest of the appliance.
pub fn global_encryption_service() -> Option<EncryptionService> {
    get_global_storage_config()
        .encryption_service
        .filter(EncryptionService::is_enabled)
}

// ============================================================================
// Convenience Functions for Storage Creation
// ============================================================================

// ============================================================================
// Helper Functions for Raw/Encrypted File Management
// ============================================================================

/// Whether a file name may be built from `id`: one path component, with no
/// separator, parent-directory step or NUL, so it can only name a file inside
/// the storage directory.
fn is_safe_entity_id(id: &str) -> bool {
    !id.is_empty() && id != "." && !id.contains("..") && !id.contains(['/', '\\', '\0'])
}

/// Refuse a write for `id` unless it is a safe entity id whose file sits
/// directly in `storage_dir`.
pub(crate) fn ensure_storable_id(
    storage_dir: &Path,
    entity_name: &str,
    id: &str,
) -> Result<()> {
    if !is_safe_entity_id(id) || get_raw_path(storage_dir, id).parent() != Some(storage_dir) {
        anyhow::bail!("{entity_name} id {id:?} cannot name a stored entity");
    }
    Ok(())
}

/// A deserialization error's kind and position, without the message (which can
/// quote the content that failed to parse).
fn deserialize_error_kind(error: &serde_json::Error) -> String {
    format!("{:?} error at line {} column {}", error.classify(), error.line(), error.column())
}

/// Characters of a secret entity id that are logged: enough to correlate log
/// lines, too few to use the id.
const LOGGED_SECRET_ID_PREFIX_LEN: usize = 8;

/// `id` as it may appear in logs and errors: in full, or only its first
/// characters when [`StorableEntity::ID_IS_SECRET`] is set.
pub(crate) fn loggable_id<T: StorableEntity>(id: &str) -> Cow<'_, str> {
    if !T::ID_IS_SECRET {
        return Cow::Borrowed(id);
    }
    let prefix: String = id
        .chars()
        .take(LOGGED_SECRET_ID_PREFIX_LEN)
        .collect();
    Cow::Owned(format!("{prefix}..."))
}

/// `path`, whose file name is built from `id`, as it may appear in logs and errors.
fn loggable_path<T: StorableEntity>(
    path: &Path,
    id: &str,
) -> String {
    let path = format!("{path:?}");
    if !T::ID_IS_SECRET || id.is_empty() {
        return path;
    }
    path.replace(id, &loggable_id::<T>(id))
}

/// Get the encrypted file path for an entity
fn get_encrypted_path(
    storage_dir: &Path,
    id: &str,
) -> PathBuf {
    storage_dir.join(format!("{}.json.enc", id))
}

/// Get the raw (unencrypted) file path for an entity
fn get_raw_path(
    storage_dir: &Path,
    id: &str,
) -> PathBuf {
    storage_dir.join(format!("{}.json", id))
}

/// Remove a plaintext `id.json` once its encrypted `id.json.enc` sibling is
/// authoritative, so decrypted content does not linger on disk.
///
/// No-op unless encryption is active. Refuses to delete when the ciphertext
/// sibling is missing — the plaintext would be the only readable copy. Failures
/// are logged, not propagated: the record is already durably encrypted and
/// loadable.
async fn remove_plaintext_sibling<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    id: &str,
    config: &StorageConfig,
) {
    if config
        .encryption_service
        .is_none()
    {
        return;
    }

    let raw_path = get_raw_path(storage_dir, id);
    if !raw_path.exists() {
        return;
    }

    if !get_encrypted_path(storage_dir, id).exists() {
        error!(
            "Refusing to delete plaintext {} file {}: its encrypted sibling is missing, so it is the only readable copy",
            entity_name,
            loggable_path::<T>(&raw_path, id)
        );
        return;
    }

    match fs::remove_file(&raw_path).await {
        Ok(()) => {
            info!("Removed plaintext {} file {} after encryption", entity_name, loggable_path::<T>(&raw_path, id))
        }
        Err(e) => {
            error!("Failed to remove plaintext {} file {}: {}", entity_name, loggable_path::<T>(&raw_path, id), e)
        }
    }
}

/// Load a raw (unencrypted) JSON file, deserialize it, and auto-encrypt it
///
/// This helper is used during startup when only raw JSON files exist but
/// encryption is enabled. It loads the JSON, runs the entity's raw-JSON
/// migration, deserializes it, calls on_load(), and encrypts the (migrated)
/// content before saving. A migration error, including a [`RetiredRecord`], is
/// returned before anything is written, so the plaintext file is left as-is.
async fn load_and_encrypt_raw_entity<T: StorableEntity>(
    storage_dir: &Path,
    id: &str,
    raw_path: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
) -> Result<T> {
    let logged_id = loggable_id::<T>(id);
    let logged_path = loggable_path::<T>(raw_path, id);
    let mut content = fs::read(raw_path)
        .await
        .context("Failed to read raw entity file")?;

    // Same two-step parse as the main load path: Value → migrate → deserialize.
    let mut json_value: serde_json::Value = serde_json::from_slice(&content)
        .with_context(|| format!("Failed to parse entity {logged_id} from {logged_path}"))?;
    if T::migrate_raw_json(&mut json_value)? {
        info!("Schema-migrated {} {} during auto-encryption", entity_name, logged_id);
        content = serde_json::to_vec(&json_value).context("Failed to serialize schema-migrated entity")?;
    }

    let mut entity: T = serde_json::from_value(json_value).map_err(|serde_err| {
        error!(
            "Deserialization error for entity {}: {}. File: {}, Content length: {} bytes",
            logged_id,
            serde_err,
            logged_path,
            content.len()
        );
        anyhow::anyhow!("Failed to deserialize entity {} from {}: {}", logged_id, logged_path, serde_err)
    })?;

    entity.on_load(); // Allow post-load processing

    // Encrypt and save the JSON content if encryption is enabled
    if let Some(encryption_service) = config
        .encryption_service
        .as_ref()
    {
        let json_str =
            String::from_utf8(content.clone()).context("Failed to convert JSON content to string for encryption")?;
        let encrypted_content = encryption_service
            .encrypt_string(json_str)
            .context("Failed to encrypt entity for auto-migration")?;
        let encrypted_path = get_encrypted_path(storage_dir, id);
        fs::write(&encrypted_path, encrypted_content)
            .await
            .context("Failed to write encrypted entity during auto-migration")?;
        info!("Auto-migrated entity {} from unencrypted to encrypted storage", logged_id);
        // Encrypt-then-delete: the ciphertext is durably written, so the plaintext
        // original must not linger.
        remove_plaintext_sibling::<T>(storage_dir, entity_name, id, config).await;
    }

    Ok(entity)
}

/// Rename an entity's file on disk when the filename doesn't match `entity.id()`.
///
/// Saves the entity under its canonical id and removes the old mismatched file.
/// Returns `true` on success, `false` if either the save or delete failed.
async fn rename_mismatched_entity_file<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
    old_file_id: &str,
) -> bool {
    let entity_id = loggable_id::<T>(entity.id());
    let old_file_id_logged = loggable_id::<T>(old_file_id);
    warn!(
        "Filename mismatch for {}: file '{}' has id '{}'. Renaming to '{}.json'",
        entity_name, old_file_id_logged, entity_id, entity_id
    );
    if let Err(e) = save_entity_to_disk(storage_dir, entity_name, config, entity).await {
        error!("Failed to save renamed {} {}: {}", entity_name, entity_id, e);
        return false;
    }
    if let Err(e) = delete_entity_from_disk::<T>(storage_dir, entity_name, old_file_id).await {
        error!("Failed to remove old {} file '{}': {}", entity_name, old_file_id_logged, e);
        return false;
    }
    true
}

/// Load all entities from disk, performing decryption and auto-migration as needed.
///
/// Returns a map of entity ID → entity, ready to be used as a cache.
/// This is the shared implementation used by both CachedFilesystemStorage and
/// RwLockFilesystemStorage.
async fn load_all_entities_from_disk<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
) -> Result<std::collections::HashMap<String, T>> {
    let mut entries = fs::read_dir(storage_dir)
        .await
        .context("Failed to read storage directory")?;

    let mut entities = std::collections::HashMap::new();
    let mut error_count = 0;
    let mut processed_ids = std::collections::HashSet::new();

    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        let file_name = path
            .file_name()
            .and_then(|n| n.to_str());

        if let Some(file_name) = file_name {
            let processed = if file_name.ends_with(".json") {
                // Raw file
                let id = file_name
                    .trim_end_matches(".json")
                    .to_string();

                // When encryption is active, a plaintext .json must not linger.
                // Skip it only when an authoritative .json.enc sibling already
                // exists (that entry loads separately in this scan); a
                // plaintext-only record — e.g. a portable restore — falls through
                // to the auto-migration path below, which loads it, encrypts it,
                // and deletes the plaintext.
                if config
                    .encryption_service
                    .is_some()
                    && get_encrypted_path(storage_dir, &id).exists()
                {
                    remove_plaintext_sibling::<T>(storage_dir, entity_name, &id, config).await;
                    continue;
                }

                if processed_ids.contains(&id) {
                    continue;
                }

                Some(id)
            } else if file_name.ends_with(".json.enc") {
                // Encrypted file
                let id = file_name
                    .trim_end_matches(".json.enc")
                    .to_string();

                if processed_ids.contains(&id) {
                    continue;
                }

                Some(id)
            } else {
                None
            };

            if let Some(id) = processed {
                let logged_id = loggable_id::<T>(&id).into_owned();
                // Determine which file to load from
                let file_to_load = if config
                    .encryption_service
                    .is_some()
                {
                    get_encrypted_path(storage_dir, &id)
                } else {
                    get_raw_path(storage_dir, &id)
                };

                // If the primary file doesn't exist and encryption is enabled,
                // check if only the raw file exists and auto-migrate it
                if !file_to_load.exists() {
                    if config
                        .encryption_service
                        .is_some()
                    {
                        let raw_path = get_raw_path(storage_dir, &id);
                        if raw_path.exists() {
                            // Found only the raw file during startup, load and encrypt it
                            match load_and_encrypt_raw_entity::<T>(storage_dir, &id, &raw_path, entity_name, config)
                                .await
                            {
                                Ok(entity) => {
                                    entities.insert(id.clone(), entity);
                                    processed_ids.insert(id);
                                    continue;
                                }
                                Err(e) => {
                                    if let Some(retired) = e.downcast_ref::<RetiredRecord>() {
                                        warn_retired_record::<T>(entity_name, &raw_path, &id, retired);
                                    } else {
                                        error!(
                                            "Failed to auto-migrate raw {} {} from {}: {}",
                                            entity_name,
                                            logged_id,
                                            loggable_path::<T>(&raw_path, &id),
                                            e
                                        );
                                        error_count += 1;
                                    }
                                    continue;
                                }
                            }
                        }
                    }
                    error!(
                        "Could not load {} candidate {}: selected file {} does not exist",
                        entity_name,
                        loggable_path::<T>(&path, &id),
                        loggable_path::<T>(&file_to_load, &id)
                    );
                    error_count += 1;
                    processed_ids.insert(id);
                    continue;
                }

                match fs::read(&file_to_load).await {
                    Ok(content) => {
                        // Track whether we loaded from a raw (unencrypted) file
                        let loaded_from_raw = !file_to_load
                            .as_path()
                            .to_str()
                            .map(|s| s.ends_with(".json.enc"))
                            .unwrap_or(false);

                        // Decrypt if needed
                        let json_content = if file_to_load
                            .as_path()
                            .to_str()
                            .map(|s| s.ends_with(".json.enc"))
                            .unwrap_or(false)
                        {
                            let encryption_service = config
                                .encryption_service
                                .as_ref()
                                .context("File is encrypted but no encryptor available")?;
                            {
                                let encrypted_str = match String::from_utf8(content.clone()) {
                                    Ok(s) => s,
                                    Err(e) => {
                                        error!(
                                            "Failed to convert encrypted {} {} to UTF-8: {}",
                                            entity_name, logged_id, e
                                        );
                                        error_count += 1;
                                        continue;
                                    }
                                };
                                match encryption_service.decrypt_string(encrypted_str) {
                                    Ok(decrypted) => decrypted.into_bytes(),
                                    Err(e) => {
                                        error!(
                                            "Failed to decrypt {} from {}: {}",
                                            entity_name,
                                            loggable_path::<T>(&file_to_load, &id),
                                            e
                                        );
                                        error_count += 1;
                                        continue;
                                    }
                                }
                            }
                        } else {
                            content
                        };

                        // Parse JSON — two-step: Value → migrate → deserialize
                        // Step 1: Parse into raw Value
                        let mut json_value: serde_json::Value = match serde_json::from_slice(&json_content) {
                            Ok(v) => v,
                            Err(e) => {
                                error!(
                                    "Failed to parse {} from {}: {}",
                                    entity_name,
                                    loggable_path::<T>(&file_to_load, &id),
                                    e
                                );
                                error_count += 1;
                                processed_ids.insert(id);
                                continue;
                            }
                        };

                        // Step 2: Run pre-deserialization migration on raw JSON
                        let schema_migrated = match T::migrate_raw_json(&mut json_value) {
                            Ok(migrated) => migrated,
                            Err(e) => {
                                if let Some(retired) = e.downcast_ref::<RetiredRecord>() {
                                    warn_retired_record::<T>(entity_name, &file_to_load, &id, retired);
                                } else {
                                    error!(
                                        "Failed to migrate {} from {}: {}",
                                        entity_name,
                                        loggable_path::<T>(&file_to_load, &id),
                                        e
                                    );
                                    error_count += 1;
                                }
                                processed_ids.insert(id);
                                continue;
                            }
                        };

                        // Step 3: Deserialize from (possibly migrated) Value into typed entity
                        match serde_json::from_value::<T>(json_value) {
                            Ok(mut entity) => {
                                entity.on_load(); // Allow post-load processing

                                // Use entity.id() (config_id) as the canonical cache key,
                                // not the filename-derived id which may be stale/mismatched.
                                let entity_id = entity.id().to_string();
                                let filename_mismatch = entity_id != id;
                                entities.insert(entity_id.clone(), entity.clone());
                                debug!("Loaded {} from {}", entity_name, loggable_path::<T>(&file_to_load, &id));

                                // If the filename doesn't match the entity's canonical id,
                                // re-save under the correct name and remove the old file.
                                if filename_mismatch {
                                    if !rename_mismatched_entity_file(storage_dir, entity_name, config, &entity, &id)
                                        .await
                                    {
                                        error_count += 1;
                                    }
                                    // Mark the new id as processed to avoid double-loading
                                    processed_ids.insert(entity_id);
                                } else {
                                    // If schema migration changed the JSON, persist the migrated version
                                    if schema_migrated {
                                        info!(
                                            "Schema-migrated {} {}, persisting updated config",
                                            entity_name, logged_id
                                        );
                                        if let Err(e) =
                                            save_entity_to_disk(storage_dir, entity_name, config, &entity).await
                                        {
                                            error!(
                                                "Failed to persist schema-migrated {} {}: {}",
                                                entity_name, logged_id, e
                                            );
                                            error_count += 1;
                                        }
                                    }

                                    // If encryption is enabled and we loaded from an unencrypted file,
                                    // encrypt and save it (auto-migration)
                                    if loaded_from_raw
                                        && let Some(encryption_service) = config
                                            .encryption_service
                                            .as_ref()
                                    {
                                        let json_str = match serde_json::to_string_pretty(&entity) {
                                            Ok(s) => s,
                                            Err(e) => {
                                                error!(
                                                    "Failed to convert {} {} content to string for encryption: {}",
                                                    entity_name, logged_id, e
                                                );
                                                error_count += 1;
                                                processed_ids.insert(id);
                                                continue;
                                            }
                                        };
                                        match encryption_service.encrypt_string(json_str) {
                                            Ok(encrypted_content) => {
                                                let encrypted_path = get_encrypted_path(storage_dir, &id);
                                                if let Err(e) = fs::write(&encrypted_path, encrypted_content).await {
                                                    error!(
                                                        "Failed to write encrypted {} {} during auto-migration: {}",
                                                        entity_name, logged_id, e
                                                    );
                                                    error_count += 1;
                                                } else {
                                                    info!(
                                                        "Auto-migrated {} {} from unencrypted to encrypted storage",
                                                        entity_name, logged_id
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    "Failed to encrypt {} {} for auto-migration: {}",
                                                    entity_name, logged_id, e
                                                );
                                                error_count += 1;
                                            }
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    "Failed to parse {} from {}: {}",
                                    entity_name,
                                    loggable_path::<T>(&file_to_load, &id),
                                    e
                                );
                                error_count += 1;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to read {} from {}: {}", entity_name, loggable_path::<T>(&file_to_load, &id), e);
                        error_count += 1;
                    }
                }

                processed_ids.insert(id);
            }
        }
    }

    if error_count > 0 {
        error!("Encountered {} error(s) loading {}(s)", error_count, entity_name);
        if config.strict_loading {
            anyhow::bail!("encountered {error_count} error(s) loading {entity_name}(s)");
        }
    }

    Ok(entities)
}

/// Log encryption status, create storage dir, and load entities from disk.
///
/// Returns the loaded entity map. Used by both DashMap and RwLock init helpers.
async fn load_storage_dir<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
) -> Result<std::collections::HashMap<String, T>> {
    let encryption_status = if config
        .encryption_service
        .is_some()
    {
        "with encryption"
    } else {
        "without encryption"
    };
    info!("Initializing {} storage {} at: {}", entity_name, encryption_status, storage_dir.display());

    // Create storage directory if it doesn't exist
    fs::create_dir_all(storage_dir)
        .await
        .context("Failed to create storage directory")?;

    // Load existing entities from disk
    let entities = load_all_entities_from_disk(storage_dir, entity_name, config).await?;
    info!("Loaded {} {}(s) from {}", entities.len(), entity_name, storage_dir.display());

    Ok(entities)
}

/// Initialize a DashMap-backed cached storage directory.
///
/// Used by `CachedFilesystemStorage::new_with_config`.
async fn init_dashmap_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<(PathBuf, DashMapCache<T>, StorageConfig)> {
    let entities = load_storage_dir(&storage_dir, entity_name, &config).await?;
    let cache: Arc<DashMap<String, T>> = Arc::new(DashMap::from_iter(entities));
    Ok((storage_dir, cache, config))
}

fn spawn_dashmap_refresh_loop<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: DashMapCache<T>,
    event_tx: broadcast::Sender<StorageEvent<T>>,
) {
    let sync_interval_secs = cache_refresh_interval_secs();
    if sync_interval_secs == 0 {
        return;
    }
    info!(
        "spawning cache refresh loop for {} at: {} (interval={}s)",
        entity_name,
        storage_dir.display(),
        sync_interval_secs
    );
    tokio::spawn(async move {
        let mut ticker = interval(Duration::from_secs(sync_interval_secs));
        loop {
            ticker.tick().await;
            if let Err(err) = refresh_dashmap_cache(&storage_dir, entity_name, &config, &cache, &event_tx).await {
                warn!("Failed to refresh {} cache from filesystem: {}", entity_name, err);
            }
        }
    });
}

async fn refresh_dashmap_cache<T: StorableEntity>(
    storage_dir: &PathBuf,
    entity_name: &str,
    config: &StorageConfig,
    cache: &DashMapCache<T>,
    event_tx: &broadcast::Sender<StorageEvent<T>>,
) -> Result<()> {
    let latest = load_all_entities_from_disk(storage_dir, entity_name, config).await?;
    let latest_keys: std::collections::HashSet<String> = latest
        .keys()
        .cloned()
        .collect();

    for (id, entity) in latest {
        let changed = if let Some(existing) = cache.get(&id) {
            serde_json::to_vec(existing.value()).ok() != serde_json::to_vec(&entity).ok()
        } else {
            true
        };

        cache.insert(id.clone(), entity);
        if changed
            && let Some(updated) = cache
                .get(&id)
                .map(|v| v.value().clone())
        {
            let _ = event_tx.send(StorageEvent::Upsert {
                id: id.clone(),
                entity: updated,
                source: StorageEventSource::RemoteWrite,
            });
        }
    }

    let current_keys: Vec<String> = cache
        .iter()
        .map(|entry| entry.key().clone())
        .collect();
    for key in current_keys {
        if !latest_keys.contains(&key) {
            cache.remove(&key);
            let _ = event_tx.send(StorageEvent::Delete {
                id: key,
                source: StorageEventSource::RemoteWrite,
            });
        }
    }

    Ok(())
}

/// Initialize an RwLock-backed cached storage directory.
///
/// Used by `RwLockFilesystemStorage::new_with_config`.
async fn init_rwlock_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<(PathBuf, StorageCache<T>, StorageConfig)> {
    let entities = load_storage_dir(&storage_dir, entity_name, &config).await?;
    let cache = Arc::new(tokio::sync::RwLock::new(entities));
    Ok((storage_dir, cache, config))
}

/// Save an entity to disk, handling serialization and encryption.
///
/// Shared by all three storage backends.
async fn save_entity_to_disk<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
) -> Result<()> {
    let id = entity.id();
    ensure_storable_id(storage_dir, entity_name, id)?;

    // Serialize to JSON
    let json_content = serde_json::to_string_pretty(entity).context("Failed to serialize entity")?;

    // Store based on config
    if let Some(ref encryption_service) = config.encryption_service {
        // Encrypted storage
        let encrypted_path = get_encrypted_path(storage_dir, id);
        let encrypted_content = encryption_service
            .encrypt_string(json_content.clone())
            .context("Failed to encrypt entity")?;
        fs::write(&encrypted_path, encrypted_content)
            .await
            .context("Failed to write encrypted entity to disk")?;
        debug!(
            "Saved encrypted {} {} to {}",
            entity_name,
            loggable_id::<T>(id),
            loggable_path::<T>(&encrypted_path, id)
        );
    } else {
        // Plain storage
        let raw_path = get_raw_path(storage_dir, id);
        fs::write(&raw_path, json_content.as_bytes())
            .await
            .context("Failed to write entity to disk")?;
        debug!("Saved {} {} to {}", entity_name, loggable_id::<T>(id), loggable_path::<T>(&raw_path, id));
    }

    Ok(())
}

async fn save_entity_to_disk_atomic<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    config: &StorageConfig,
    entity: &T,
) -> Result<()> {
    let id = entity.id();
    ensure_storable_id(storage_dir, entity_name, id)?;

    let json_content = serde_json::to_string_pretty(entity).context("Failed to serialize entity")?;

    if let Some(ref encryption_service) = config.encryption_service {
        let encrypted_path = get_encrypted_path(storage_dir, id);
        let encrypted_content = encryption_service
            .encrypt_string(json_content.clone())
            .context("Failed to encrypt entity")?;
        atomic_write_file(&encrypted_path, encrypted_content.as_bytes())
            .await
            .context("Failed to write encrypted entity to disk")?;
        debug!(
            "Atomically saved encrypted {} {} to {}",
            entity_name,
            loggable_id::<T>(id),
            loggable_path::<T>(&encrypted_path, id)
        );
    } else {
        let raw_path = get_raw_path(storage_dir, id);
        atomic_write_file(&raw_path, json_content.as_bytes())
            .await
            .context("Failed to write entity to disk")?;
        debug!("Atomically saved {} {} to {}", entity_name, loggable_id::<T>(id), loggable_path::<T>(&raw_path, id));
    }

    Ok(())
}

async fn atomic_write_file(
    target_path: &Path,
    content: &[u8],
) -> Result<()> {
    let parent = target_path
        .parent()
        .context("Target path has no parent directory")?;
    fs::create_dir_all(parent)
        .await
        .context("Failed to create parent directory for atomic write")?;

    let file_name = target_path
        .file_name()
        .and_then(|name| name.to_str())
        .context("Target path has invalid file name")?;
    let unique = ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp_name = format!(".{file_name}.{unique}.tmp");
    let tmp_path = parent.join(tmp_name);

    fs::write(&tmp_path, content)
        .await
        .with_context(|| format!("Failed to write temporary file {}", tmp_path.display()))?;

    fs::rename(&tmp_path, target_path)
        .await
        .with_context(|| {
            format!("Failed to atomically replace {} with {}", target_path.display(), tmp_path.display())
        })?;

    Ok(())
}

/// Delete an entity's files from disk (encrypted and/or raw).
///
/// Shared by all three storage backends.
async fn delete_entity_from_disk<T: StorableEntity>(
    storage_dir: &Path,
    entity_name: &str,
    id: &str,
) -> Result<()> {
    if !is_safe_entity_id(id) {
        anyhow::bail!("{entity_name} id {id:?} cannot name a stored entity");
    }

    // Delete encrypted file if exists
    let encrypted_path = get_encrypted_path(storage_dir, id);
    if encrypted_path.exists() {
        fs::remove_file(&encrypted_path)
            .await
            .context("Failed to delete encrypted entity file")?;
        debug!("Deleted encrypted {} file {}", entity_name, loggable_path::<T>(&encrypted_path, id));
    }

    // Delete raw file if exists
    let raw_path = get_raw_path(storage_dir, id);
    if raw_path.exists() {
        fs::remove_file(&raw_path)
            .await
            .context("Failed to delete raw entity file")?;
        debug!("Deleted raw {} file {}", entity_name, loggable_path::<T>(&raw_path, id));
    }

    debug!("Deleted {} {}", entity_name, loggable_id::<T>(id));
    Ok(())
}

// ============================================================================
// Cached Implementation (DashMap)
// ============================================================================

/// Filesystem storage with lock-free in-memory cache backed by DashMap
///
/// This implementation maintains a DashMap cache of all entities for fast,
/// concurrent access. Reads are lock-free and writes use fine-grained
/// per-shard locking so they never block unrelated reads.
///
/// # When to use
/// - Frequently accessed data with concurrent readers
/// - Data that fits comfortably in memory
/// - When read performance is critical
/// - When you do **not** need whole-map locked access (use
///   `RwLockFilesystemStorage` for that)
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{CachedFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct MyEntity {
///     id: String,
///     data: String,
/// }
///
/// impl StorableEntity for MyEntity {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = CachedFilesystemStorage::new(
///     "/path/to/storage".into(),
///     "my_entity"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct CachedFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: DashMapCache<T>,
    event_tx: broadcast::Sender<StorageEvent<T>>,
}

impl<T: StorableEntity> Clone for CachedFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            cache: self.cache.clone(),
            event_tx: self.event_tx.clone(),
        }
    }
}

impl<T: StorableEntity> CachedFilesystemStorage<T> {
    /// Create a new cached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging (e.g., "channel", "gateway")
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read or parsed
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new cached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration (encryption, etc.)
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        let (storage_dir, cache, config) = init_dashmap_storage(storage_dir, entity_name, config).await?;
        let (event_tx, _) = broadcast::channel(1024);
        if cache_refresh_interval_secs() > 0 {
            spawn_dashmap_refresh_loop(
                storage_dir.clone(),
                entity_name,
                config.clone(),
                cache.clone(),
                event_tx.clone(),
            );
        }

        Ok(Self {
            storage_dir,
            entity_name,
            config,
            cache,
            event_tx,
        })
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await?;
        self.cache
            .insert(entity.id().to_string(), entity.clone());
        let _ = self
            .event_tx
            .send(StorageEvent::Upsert {
                id: entity.id().to_string(),
                entity: entity.clone(),
                source: StorageEventSource::LocalWrite,
            });
        Ok(())
    }

    /// Create or update an entity, writing to disk atomically (temp file + rename).
    pub async fn atomic_save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk_atomic(&self.storage_dir, self.entity_name, &self.config, entity).await?;
        self.cache
            .insert(entity.id().to_string(), entity.clone());
        let _ = self
            .event_tx
            .send(StorageEvent::Upsert {
                id: entity.id().to_string(),
                entity: entity.clone(),
                source: StorageEventSource::LocalWrite,
            });
        Ok(())
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        if let Some(entity) = self
            .cache
            .get(id)
            .map(|r| r.value().clone())
        {
            return Ok(Some(entity));
        }

        refresh_dashmap_cache(&self.storage_dir, self.entity_name, &self.config, &self.cache, &self.event_tx).await?;

        Ok(self
            .cache
            .get(id)
            .map(|r| r.value().clone()))
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        Ok(self
            .cache
            .iter()
            .map(|r| r.value().clone())
            .collect())
    }

    pub async fn refresh_from_disk(&self) -> Result<()> {
        refresh_dashmap_cache(&self.storage_dir, self.entity_name, &self.config, &self.cache, &self.event_tx).await
    }

    /// Delete an entity by ID
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk::<T>(&self.storage_dir, self.entity_name, id).await?;
        self.cache.remove(id);
        let _ = self
            .event_tx
            .send(StorageEvent::Delete {
                id: id.to_string(),
                source: StorageEventSource::LocalWrite,
            });
        Ok(())
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.cache.contains_key(id))
    }

    /// Create a new cached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for CachedFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        CachedFilesystemStorage::save(self, entity).await
    }
    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        CachedFilesystemStorage::atomic_save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        CachedFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        CachedFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        CachedFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        CachedFilesystemStorage::exists(self, id).await
    }

    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        Ok(self
            .cache
            .iter()
            .map(|r| (r.key().clone(), r.value().clone()))
            .collect())
    }

    fn subscribe(&self) -> Option<broadcast::Receiver<StorageEvent<T>>> {
        Some(self.event_tx.subscribe())
    }

    async fn refresh_from_disk(&self) -> Result<()> {
        CachedFilesystemStorage::refresh_from_disk(self).await
    }
}

// ============================================================================
// Non-Cached Implementation (Always Read from Disk)
// ============================================================================

/// Filesystem storage without caching - always reads from disk
///
/// This implementation does not maintain an in-memory cache and reads
/// from disk on every access. Use this for sensitive data or when
/// memory is constrained.
///
/// # When to use
/// - Sensitive data (secrets, credentials)
/// - Large entities that don't fit well in memory
/// - Infrequently accessed data
/// - When memory is constrained
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{UncachedFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct Secret {
///     id: String,
///     encrypted_value: Vec<u8>,
/// }
///
/// impl StorableEntity for Secret {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = UncachedFilesystemStorage::new(
///     "/path/to/secrets".into(),
///     "secret"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct UncachedFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    _phantom: std::marker::PhantomData<T>,
}

impl<T: StorableEntity> Clone for UncachedFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<T: StorableEntity> UncachedFilesystemStorage<T> {
    /// Create a new uncached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new uncached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        let encryption_status = if config
            .encryption_service
            .is_some()
        {
            "with encryption"
        } else {
            "without encryption"
        };
        info!("Initializing uncached {} storage {} at: {}", entity_name, encryption_status, storage_dir.display());

        // Create storage directory if it doesn't exist
        fs::create_dir_all(&storage_dir)
            .await
            .context("Failed to create storage directory")?;

        // Uncached stores never scan on load, so sweep plaintext copies left
        // beside their ciphertext (e.g. by the removed `store_raw_files`) here.
        // A plaintext-only record is kept for the migrate-on-load path.
        if config
            .encryption_service
            .is_some()
        {
            let mut entries = fs::read_dir(&storage_dir)
                .await
                .context("Failed to read storage directory")?;
            while let Some(entry) = entries
                .next_entry()
                .await
                .context("Failed to read storage directory entry")?
            {
                let file_name = entry.file_name();
                if let Some(id) = file_name
                    .to_str()
                    .and_then(|name| name.strip_suffix(".json"))
                    && get_encrypted_path(&storage_dir, id).exists()
                {
                    remove_plaintext_sibling::<T>(&storage_dir, entity_name, id, &config).await;
                }
            }
        }

        Ok(Self {
            storage_dir,
            entity_name,
            config,
            _phantom: std::marker::PhantomData,
        })
    }

    /// Create a new uncached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store encrypted files
    /// * `entity_name` - Human-readable name for logging
    /// * `encryption_service` - EncryptionService for data at rest
    ///
    /// # Errors
    /// Returns an error if the directory cannot be created
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }

    /// Get the encrypted file path for an entity
    fn get_encrypted_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_encrypted_path(&self.storage_dir, id)
    }

    /// Get the raw file path for an entity
    fn get_raw_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_raw_path(&self.storage_dir, id)
    }

    /// Load an entity from disk
    ///
    /// If encryption is enabled and only a raw (unencrypted) JSON file is found,
    /// it will be automatically encrypted and saved as .json.enc for future loads.
    /// An id that could name a file outside the storage directory names no
    /// entity.
    async fn load_from_disk(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        if !is_safe_entity_id(id) {
            return Ok(None);
        }

        // Determine which file to load from
        let file_to_load = if self
            .config
            .encryption_service
            .is_some()
        {
            self.get_encrypted_path(id)
        } else {
            self.get_raw_path(id)
        };

        // If the primary file doesn't exist and encryption is enabled,
        // check if only the raw file exists and auto-migrate it
        if !file_to_load.exists() {
            if self
                .config
                .encryption_service
                .is_some()
            {
                let raw_path = self.get_raw_path(id);
                if raw_path.exists() {
                    // Found only the raw file, use it for loading instead
                    return self
                        .load_and_encrypt_raw(id, &raw_path)
                        .await;
                }
            }
            return Ok(None);
        }

        let content = fs::read(&file_to_load)
            .await
            .context("Failed to read entity file")?;

        // Track whether we loaded from a raw (unencrypted) file
        let loaded_from_raw = !file_to_load
            .as_path()
            .to_str()
            .map(|s| s.ends_with(".json.enc"))
            .unwrap_or(false);

        // Decrypt if needed
        let json_content = if file_to_load
            .as_path()
            .to_str()
            .map(|s| s.ends_with(".json.enc"))
            .unwrap_or(false)
        {
            let encryption_service = self
                .config
                .encryption_service
                .as_ref()
                .context("File is encrypted but no encryptor available")?;
            {
                // File was encrypted with encrypt_string, so read as UTF-8 string
                let encrypted_str = String::from_utf8(content.clone()).context("Encrypted data is not valid UTF-8")?;
                encryption_service
                    .decrypt_string(encrypted_str)
                    .map_err(|err| {
                        error!(
                            "Decryption error for {} {}: {}. File: {}, Content length: {} bytes",
                            self.entity_name,
                            loggable_id::<T>(id),
                            err,
                            loggable_path::<T>(&file_to_load, id),
                            content.len(),
                        );
                        anyhow::anyhow!(
                            "Failed to decrypt entity {} {} from {}: {}",
                            self.entity_name,
                            loggable_id::<T>(id),
                            loggable_path::<T>(&file_to_load, id),
                            err
                        )
                    })?
                    .into_bytes()
            }
        } else {
            content
        };

        // The content may be decrypted, and a serde message can quote it, so
        // only the error's kind and position are logged or returned.
        let mut entity: T = serde_json::from_slice(&json_content).map_err(|serde_err| {
            let kind = deserialize_error_kind(&serde_err);
            error!("Deserialization error for {} {:?}: {}", self.entity_name, loggable_id::<T>(id), kind);
            anyhow::anyhow!("Failed to deserialize {} {:?}: {}", self.entity_name, loggable_id::<T>(id), kind)
        })?;

        entity.on_load(); // Allow post-load processing

        // If encryption is enabled and we loaded from an unencrypted file, encrypt and save it
        // This provides automatic migration of existing unencrypted files to encrypted storage
        if loaded_from_raw
            && let Some(encryption_service) = self
                .config
                .encryption_service
                .as_ref()
        {
            // Preserve the original JSON content for encryption
            let json_str = String::from_utf8(json_content.clone())
                .context("Failed to convert JSON content to string for encryption")?;
            let encrypted_content = encryption_service
                .encrypt_string(json_str)
                .context("Failed to encrypt entity for auto-migration")?;
            let encrypted_path = self.get_encrypted_path(id);
            fs::write(&encrypted_path, encrypted_content)
                .await
                .context("Failed to write encrypted entity during auto-migration")?;
            info!("Auto-migrated {} {} from unencrypted to encrypted storage", self.entity_name, loggable_id::<T>(id));
            // Encrypt-then-delete: the ciphertext is durably written, so the
            // plaintext original must not linger.
            remove_plaintext_sibling::<T>(&self.storage_dir, self.entity_name, id, &self.config).await;
        }

        Ok(Some(entity))
    }

    /// Load a raw (unencrypted) JSON file and encrypt it
    async fn load_and_encrypt_raw(
        &self,
        id: &str,
        raw_path: &PathBuf,
    ) -> Result<Option<T>> {
        let content = fs::read(raw_path)
            .await
            .context("Failed to read raw entity file")?;

        // Parse JSON
        let mut entity: T = serde_json::from_slice(&content).map_err(|serde_err| {
            error!(
                "Deserialization error for {} {}: {}. File: {}, Content length: {} bytes",
                self.entity_name,
                loggable_id::<T>(id),
                serde_err,
                loggable_path::<T>(raw_path, id),
                content.len()
            );
            anyhow::anyhow!(
                "Failed to deserialize {} {} from {}: {}",
                self.entity_name,
                loggable_id::<T>(id),
                loggable_path::<T>(raw_path, id),
                serde_err
            )
        })?;

        entity.on_load(); // Allow post-load processing

        // Encrypt and save the JSON content if encryption is enabled
        if let Some(encryption_service) = self
            .config
            .encryption_service
            .as_ref()
        {
            let json_str = String::from_utf8(content.clone())
                .context("Failed to convert JSON content to string for encryption")?;
            let encrypted_content = encryption_service
                .encrypt_string(json_str)
                .context("Failed to encrypt entity for auto-migration")?;
            let encrypted_path = self.get_encrypted_path(id);
            fs::write(&encrypted_path, encrypted_content)
                .await
                .context("Failed to write encrypted entity during auto-migration")?;
            info!("Auto-migrated {} {} from unencrypted to encrypted storage", self.entity_name, loggable_id::<T>(id));
            // Encrypt-then-delete: the ciphertext is durably written, so the
            // plaintext original must not linger.
            remove_plaintext_sibling::<T>(&self.storage_dir, self.entity_name, id, &self.config).await;
        }

        Ok(Some(entity))
    }

    /// List all entity IDs from disk
    async fn list_all_ids(&self) -> Result<Vec<String>> {
        let mut ids = Vec::new();
        let mut processed_ids = std::collections::HashSet::new();
        let mut entries = fs::read_dir(&self.storage_dir)
            .await
            .context("Failed to read storage directory")?;

        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            let file_name = path
                .file_name()
                .and_then(|n| n.to_str());

            if let Some(file_name) = file_name
                && let Some(id) = if file_name.ends_with(".json") {
                    Some(
                        file_name
                            .trim_end_matches(".json")
                            .to_string(),
                    )
                } else if file_name.ends_with(".json.enc") {
                    Some(
                        file_name
                            .trim_end_matches(".json.enc")
                            .to_string(),
                    )
                } else {
                    None
                }
                && !processed_ids.contains(&id)
            {
                ids.push(id.clone());
                processed_ids.insert(id);
            }
        }

        Ok(ids)
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await
    }

    pub async fn atomic_save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk_atomic(&self.storage_dir, self.entity_name, &self.config, entity).await
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        self.load_from_disk(id).await
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        let ids = self.list_all_ids().await?;
        let mut entities = Vec::new();

        for id in ids {
            if let Some(entity) = self
                .load_from_disk(&id)
                .await?
            {
                entities.push(entity);
            }
        }

        Ok(entities)
    }

    /// Delete an entity by ID
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk::<T>(&self.storage_dir, self.entity_name, id).await
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for UncachedFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        UncachedFilesystemStorage::save(self, entity).await
    }
    async fn save_atomic(
        &self,
        entity: &T,
    ) -> Result<()> {
        UncachedFilesystemStorage::atomic_save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        UncachedFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        UncachedFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        UncachedFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        UncachedFilesystemStorage::exists(self, id).await
    }
}

// ============================================================================
// RwLock-based Cached Implementation (For Async-Heavy Workloads)
// ============================================================================

/// Filesystem storage with in-memory cache using RwLock
///
/// This implementation maintains an in-memory cache of all entities for fast
/// read access, using tokio's async RwLock for synchronization. All operations
/// are synchronized between disk and cache.
///
/// # When to use
/// - When you need async lock guards (can hold across .await points)
/// - Workloads with long-held read locks during async operations
/// - When DashMap's lock-free nature isn't required
/// - Legacy code that already uses RwLock pattern
///
/// # Performance Considerations
/// - **Lock contention**: Multiple concurrent writes will serialize
/// - **Async overhead**: Slightly higher overhead than DashMap
/// - **Better for**: Long-running read operations with .await
/// - **Worse for**: High-frequency writes
///
/// # Example
/// ```rust,no_run
/// use crate::storage::filesystem::{RwLockFilesystemStorage, StorableEntity};
///
/// #[derive(Clone, serde::Serialize, serde::Deserialize)]
/// struct MyEntity {
///     id: String,
///     data: String,
/// }
///
/// impl StorableEntity for MyEntity {
///     fn id(&self) -> &str {
///         &self.id
///     }
/// }
///
/// # async fn example() -> anyhow::Result<()> {
/// let storage = RwLockFilesystemStorage::new(
///     "/path/to/storage".into(),
///     "my_entity"
/// ).await?;
/// # Ok(())
/// # }
/// ```
pub struct RwLockFilesystemStorage<T: StorableEntity> {
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
    cache: StorageCache<T>,
}

impl<T: StorableEntity> Clone for RwLockFilesystemStorage<T> {
    fn clone(&self) -> Self {
        Self {
            storage_dir: self.storage_dir.clone(),
            entity_name: self.entity_name,
            config: self.config.clone(),
            cache: self.cache.clone(),
        }
    }
}

impl<T: StorableEntity> RwLockFilesystemStorage<T> {
    /// Create a new RwLock-based cached filesystem storage without encryption
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store JSON files
    /// * `entity_name` - Human-readable name for logging (e.g., "pipe", "config")
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read or parsed
    #[allow(dead_code)]
    pub async fn new(
        storage_dir: PathBuf,
        entity_name: &'static str,
    ) -> Result<Self> {
        Self::new_with_config(storage_dir, entity_name, StorageConfig::default()).await
    }

    /// Create a new RwLock-based cached filesystem storage with custom config
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store files
    /// * `entity_name` - Human-readable name for logging
    /// * `config` - Storage configuration
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    pub async fn new_with_config(
        storage_dir: PathBuf,
        entity_name: &'static str,
        config: StorageConfig,
    ) -> Result<Self> {
        let (storage_dir, cache, config) = init_rwlock_storage(storage_dir, entity_name, config).await?;
        Ok(Self {
            storage_dir,
            entity_name,
            config,
            cache,
        })
    }

    /// Create a new RwLock-based cached filesystem storage with encryption
    ///
    /// Convenience method for creating storage with encryption enabled.
    ///
    /// # Arguments
    /// * `storage_dir` - Directory to store encrypted files
    /// * `entity_name` - Human-readable name for logging
    /// * `encryption_service` - EncryptionService for data at rest
    ///
    /// # Errors
    /// Returns an error if:
    /// - The directory cannot be created
    /// - Existing files cannot be read, decrypted, or parsed
    #[allow(dead_code)]
    pub async fn new_with_encryption(
        storage_dir: PathBuf,
        entity_name: &'static str,
        encryption_service: EncryptionService,
    ) -> Result<Self> {
        let config = StorageConfig::default().with_encryption_service(encryption_service);
        Self::new_with_config(storage_dir, entity_name, config).await
    }

    /// Get the encrypted file path for an entity
    #[allow(dead_code)]
    fn get_encrypted_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_encrypted_path(&self.storage_dir, id)
    }

    /// Get the raw file path for an entity
    #[allow(dead_code)]
    fn get_raw_path(
        &self,
        id: &str,
    ) -> PathBuf {
        get_raw_path(&self.storage_dir, id)
    }

    /// Create or update an entity
    pub async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        save_entity_to_disk(&self.storage_dir, self.entity_name, &self.config, entity).await?;

        // Update cache
        let mut cache = self.cache.write().await;
        cache.insert(entity.id().to_string(), entity.clone());

        Ok(())
    }

    /// Get an entity by ID
    pub async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        let cache = self.cache.read().await;
        Ok(cache.get(id).cloned())
    }

    /// List all entities
    pub async fn list_all(&self) -> Result<Vec<T>> {
        let cache = self.cache.read().await;
        Ok(cache
            .values()
            .cloned()
            .collect())
    }

    /// Delete an entity by ID
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        delete_entity_from_disk::<T>(&self.storage_dir, self.entity_name, id).await?;

        // Remove from cache
        let mut cache = self.cache.write().await;
        cache.remove(id);

        Ok(())
    }

    /// Check if an entity exists
    pub async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        Ok(self.get(id).await?.is_some())
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for RwLockFilesystemStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        RwLockFilesystemStorage::save(self, entity).await
    }
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        RwLockFilesystemStorage::get(self, id).await
    }
    async fn list_all(&self) -> Result<Vec<T>> {
        RwLockFilesystemStorage::list_all(self).await
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        RwLockFilesystemStorage::delete(self, id).await
    }
    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        RwLockFilesystemStorage::exists(self, id).await
    }
    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        Ok(self
            .cache
            .read()
            .await
            .clone())
    }
    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        Some(&self.cache)
    }
}

// ============================================================================
// In-Memory Storage (no filesystem)
// ============================================================================

/// Pure in-memory storage backend using `Arc<RwLock<HashMap>>`.
///
/// This provides the same `StorageBackend` interface as the filesystem
/// implementations but stores everything in memory only.  Useful for
/// session-style data that does not need to survive restarts or for
/// testing.
///
/// When `timeout_minutes` is set, entries are lazily evicted on read
/// operations once they exceed the configured age.
pub struct InMemoryStorage<T: StorableEntity> {
    cache: StorageCache<T>,
    /// Per-entry insertion timestamps for timeout-based eviction
    timestamps: Arc<tokio::sync::RwLock<std::collections::HashMap<String, std::time::Instant>>>,
    /// Optional TTL – entries older than this are evicted on access
    timeout: Option<std::time::Duration>,
}

impl<T: StorableEntity> Clone for InMemoryStorage<T> {
    fn clone(&self) -> Self {
        Self {
            cache: self.cache.clone(),
            timestamps: self.timestamps.clone(),
            timeout: self.timeout,
        }
    }
}

impl<T: StorableEntity> InMemoryStorage<T> {
    /// Create a new, empty in-memory storage (no timeout).
    pub fn new() -> Self {
        Self {
            cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timestamps: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timeout: None,
        }
    }

    /// Create a new, empty in-memory storage with a timeout.
    ///
    /// Entries that have not been saved/updated for longer than
    /// `timeout_minutes` will be lazily evicted on the next read.
    pub fn with_timeout(timeout_minutes: u64) -> Self {
        Self {
            cache: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timestamps: Arc::new(tokio::sync::RwLock::new(std::collections::HashMap::new())),
            timeout: Some(std::time::Duration::from_secs(timeout_minutes * 60)),
        }
    }

    /// Evict entries whose insertion timestamp exceeds the configured timeout.
    ///
    /// This is a no-op when no timeout is configured.
    async fn evict_expired(&self) {
        let timeout = match self.timeout {
            Some(t) => t,
            None => return,
        };

        let now = std::time::Instant::now();
        let expired_keys: Vec<String> = {
            let ts = self.timestamps.read().await;
            ts.iter()
                .filter_map(|(k, inserted)| {
                    if now.duration_since(*inserted) > timeout {
                        Some(k.clone())
                    } else {
                        None
                    }
                })
                .collect()
        };

        if expired_keys.is_empty() {
            return;
        }

        let mut cache = self.cache.write().await;
        let mut ts = self.timestamps.write().await;
        for key in &expired_keys {
            cache.remove(key);
            ts.remove(key);
        }
        debug!("InMemoryStorage: evicted {} expired entries (timeout {}s)", expired_keys.len(), timeout.as_secs());
    }
}

impl<T: StorableEntity> Default for InMemoryStorage<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl<T: StorableEntity> StorageBackend<T> for InMemoryStorage<T> {
    async fn save(
        &self,
        entity: &T,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;
        let id = entity.id().to_string();
        cache.insert(id.clone(), entity.clone());
        if self.timeout.is_some() {
            let mut ts = self.timestamps.write().await;
            ts.insert(id, std::time::Instant::now());
        }
        Ok(())
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<T>> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache.get(id).cloned())
    }

    async fn list_all(&self) -> Result<Vec<T>> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache
            .values()
            .cloned()
            .collect())
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        let mut cache = self.cache.write().await;
        cache.remove(id);
        if self.timeout.is_some() {
            let mut ts = self.timestamps.write().await;
            ts.remove(id);
        }
        Ok(())
    }

    async fn exists(
        &self,
        id: &str,
    ) -> Result<bool> {
        self.evict_expired().await;
        let cache = self.cache.read().await;
        Ok(cache.contains_key(id))
    }

    async fn hash_map(&self) -> Result<std::collections::HashMap<String, T>> {
        self.evict_expired().await;
        Ok(self
            .cache
            .read()
            .await
            .clone())
    }

    fn raw_cache(&self) -> Option<&StorageCache<T>> {
        Some(&self.cache)
    }
}

/// Create a pure in-memory storage (no filesystem, no timeout).
///
/// Returns a trait object for generic storage access.
#[allow(dead_code)]
pub fn in_memory_storage<T: StorableEntity>() -> Box<dyn StorageBackend<T>> {
    Box::new(InMemoryStorage::<T>::new())
}

/// Create a pure in-memory storage with a timeout (no filesystem).
///
/// Entries are lazily evicted after `timeout_minutes` minutes.
/// Returns a trait object for generic storage access.
pub fn in_memory_storage_with_timeout<T: StorableEntity>(timeout_minutes: u64) -> Box<dyn StorageBackend<T>> {
    Box::new(InMemoryStorage::<T>::with_timeout(timeout_minutes))
}

// ============================================================================
// Convenience Functions for Storage Creation
// ============================================================================

/// Create a cached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn cached_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(CachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create cached filesystem storage that rejects any unreadable candidate file.
pub async fn cached_storage_strict<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config().with_strict_loading();
    Ok(Box::new(CachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create an uncached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn uncached_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(UncachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create a RwLock-based cached filesystem storage with type inference
///
/// Returns a trait object for generic storage access.
/// If a global encryption config is set, it will be applied to this storage instance.
pub async fn rwlock_storage<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
) -> Result<Box<dyn StorageBackend<T>>> {
    let config = get_global_storage_config();
    Ok(Box::new(RwLockFilesystemStorage::new_with_config(storage_dir, entity_name, config).await?))
}

/// Create a cached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [cached_storage] instead.
///
/// # Arguments
/// * `storage_dir` - Directory to store files
/// * `entity_name` - Name for logging/identification
/// * `config` - StorageConfig for encryption options
///
/// # Example
/// ```no_run
/// # use std::path::PathBuf;
/// # use crate::storage::filesystem::{cached_storage_with_config, StorageConfig};
/// # async fn example() -> anyhow::Result<()> {
/// let config = StorageConfig::default();
///
/// let storage = cached_storage_with_config::<MyEntity>(
///     PathBuf::from("./storage"),
///     "my_entity",
///     config,
/// ).await?;
/// # Ok(())
/// # }
/// ```
#[allow(dead_code)]
pub async fn cached_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<CachedFilesystemStorage<T>> {
    CachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

/// Create an uncached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [uncached_storage] instead.
#[allow(dead_code)]
pub async fn uncached_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<UncachedFilesystemStorage<T>> {
    UncachedFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

/// Create a RwLock-based cached filesystem storage with custom StorageConfig
///
/// Use this when you need to specify encryption or other storage options.
/// For basic usage without configuration, use [rwlock_storage] instead.
#[allow(dead_code)]
pub async fn rwlock_storage_with_config<T: StorableEntity>(
    storage_dir: PathBuf,
    entity_name: &'static str,
    config: StorageConfig,
) -> Result<RwLockFilesystemStorage<T>> {
    RwLockFilesystemStorage::new_with_config(storage_dir, entity_name, config).await
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encryption::{KeyManager, KeySource};
    use base64::Engine;
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    /// Helper to create an EncryptionService from a random key for tests
    fn test_encryption_service() -> (EncryptionService, [u8; 32]) {
        let key_manager = KeyManager::from_raw_key(&rand::random::<[u8; 32]>()).unwrap();
        let key = *key_manager.master_key();
        let service = EncryptionService::new(KeySource::Raw { key }).unwrap();
        (service, key)
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestEntity {
        id: String,
        name: String,
        value: i32,
    }

    impl StorableEntity for TestEntity {
        fn id(&self) -> &str {
            &self.id
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct SecretIdEntity {
        id: String,
    }

    impl StorableEntity for SecretIdEntity {
        const ID_IS_SECRET: bool = true;

        fn id(&self) -> &str {
            &self.id
        }
    }

    #[test]
    fn loggable_id_keeps_a_non_secret_id_in_full() {
        assert_eq!(loggable_id::<TestEntity>("member-0123456789"), "member-0123456789");
    }

    #[test]
    fn loggable_id_keeps_only_the_prefix_of_a_secret_id() {
        let logged = loggable_id::<SecretIdEntity>("aaaaaaaabbbbbbbb");

        assert_eq!(logged, "aaaaaaaa...");
        assert!(!logged.contains('b'));
    }

    #[test]
    fn loggable_path_redacts_a_secret_id_in_the_file_name() {
        let id = "aaaaaaaabbbbbbbb";
        let path = get_raw_path(Path::new("/data/session"), id);

        let logged = loggable_path::<SecretIdEntity>(&path, id);

        assert_eq!(logged, r#""/data/session/aaaaaaaa....json""#);
        assert!(!logged.contains('b'));
    }

    #[test]
    fn loggable_path_keeps_a_non_secret_path_in_full() {
        let path = get_raw_path(Path::new("/data/member"), "member-1");

        assert_eq!(loggable_path::<TestEntity>(&path, "member-1"), r#""/data/member/member-1.json""#);
    }

    #[tokio::test]
    async fn retired_record_warning_logs_only_the_prefix_of_a_secret_id() {
        let id = "aaaaaaaabbbbbbbb";
        let path = get_raw_path(Path::new("/data/retired-secret-id"), id);
        let retired = RetiredRecord("kind was removed".to_string());

        let (logs, ()) = crate::observability::log_capture::capture_logs(async {
            warn_retired_record::<SecretIdEntity>("session", &path, id, &retired)
        })
        .await;

        assert!(logs.contains("aaaaaaaa....json"), "{logs}");
        assert!(!logs.contains(id), "a log holds the secret id: {logs}");
    }

    #[test]
    fn loggable_path_with_empty_secret_id_is_unchanged() {
        let path = Path::new("/data/session/x.json");

        assert_eq!(loggable_path::<SecretIdEntity>(path, ""), r#""/data/session/x.json""#);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct MigrationFailureEntity {
        id: String,
    }

    impl StorableEntity for MigrationFailureEntity {
        fn id(&self) -> &str {
            &self.id
        }

        fn migrate_raw_json(_value: &mut serde_json::Value) -> Result<bool> {
            anyhow::bail!("migration failed")
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RetiredKindEntity {
        id: String,
    }

    impl StorableEntity for RetiredKindEntity {
        fn id(&self) -> &str {
            &self.id
        }

        fn migrate_raw_json(value: &mut serde_json::Value) -> Result<bool> {
            if value.get("retired").is_some() {
                return Err(RetiredRecord("kind was removed".to_string()).into());
            }
            Ok(false)
        }
    }

    #[tokio::test]
    async fn retired_records_are_skipped_without_counting_as_load_errors() {
        let temp_dir = TempDir::new().unwrap();
        let retired_path = temp_dir
            .path()
            .join("old.json");
        fs::write(&retired_path, br#"{"id":"old","retired":true}"#)
            .await
            .unwrap();
        fs::write(
            temp_dir
                .path()
                .join("kept.json"),
            br#"{"id":"kept"}"#,
        )
        .await
        .unwrap();

        // Strict loading treats a retired record as an intentional skip, not a failure.
        let storage = CachedFilesystemStorage::<RetiredKindEntity>::new_with_config(
            temp_dir.path().to_path_buf(),
            "retired_entity",
            StorageConfig::default().with_strict_loading(),
        )
        .await
        .unwrap();

        assert!(
            storage
                .get("kept")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            storage
                .get("old")
                .await
                .unwrap()
                .is_none()
        );
        assert!(retired_path.exists(), "a retired record's file is left on disk");
        assert!(!first_retired_record_warning(&retired_path), "the load above already warned about this file");
    }

    #[tokio::test]
    async fn auto_encryption_leaves_a_retired_plaintext_record_untouched() {
        let temp_dir = TempDir::new().unwrap();
        let raw_path = temp_dir
            .path()
            .join("old.json");
        fs::write(&raw_path, br#"{"id":"old","retired":true}"#)
            .await
            .unwrap();
        let (encryption_service, _) = test_encryption_service();

        let storage = CachedFilesystemStorage::<RetiredKindEntity>::new_with_config(
            temp_dir.path().to_path_buf(),
            "retired_entity",
            StorageConfig::default()
                .with_encryption_service(encryption_service)
                .with_strict_loading(),
        )
        .await
        .unwrap();

        assert!(
            storage
                .get("old")
                .await
                .unwrap()
                .is_none()
        );
        assert!(raw_path.exists(), "the plaintext file is left as-is");
        assert!(
            !temp_dir
                .path()
                .join("old.json.enc")
                .exists(),
            "a retired record is not encrypted"
        );
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct RenamedFieldEntity {
        id: String,
        name: String,
    }

    impl StorableEntity for RenamedFieldEntity {
        fn id(&self) -> &str {
            &self.id
        }

        fn migrate_raw_json(value: &mut serde_json::Value) -> Result<bool> {
            let Some(object) = value.as_object_mut() else {
                return Ok(false);
            };
            let Some(old) = object.remove("old_name") else {
                return Ok(false);
            };
            object.insert("name".to_string(), old);
            Ok(true)
        }
    }

    #[tokio::test]
    async fn auto_encryption_runs_the_raw_json_migration_first() {
        let temp_dir = TempDir::new().unwrap();
        fs::write(
            temp_dir
                .path()
                .join("e1.json"),
            br#"{"id":"e1","old_name":"migrated"}"#,
        )
        .await
        .unwrap();
        let (encryption_service, key) = test_encryption_service();

        let storage = CachedFilesystemStorage::<RenamedFieldEntity>::new_with_config(
            temp_dir.path().to_path_buf(),
            "renamed_entity",
            StorageConfig::default().with_encryption_service(encryption_service),
        )
        .await
        .unwrap();
        assert_eq!(
            storage
                .get("e1")
                .await
                .unwrap()
                .unwrap()
                .name,
            "migrated"
        );

        let encrypted = fs::read_to_string(
            temp_dir
                .path()
                .join("e1.json.enc"),
        )
        .await
        .unwrap();
        let decrypted = EncryptionService::new(KeySource::Raw { key })
            .unwrap()
            .decrypt_string(encrypted)
            .unwrap();
        let stored: serde_json::Value = serde_json::from_str(&decrypted).unwrap();
        assert_eq!(stored["name"], "migrated", "the migrated JSON is what gets encrypted");
        assert!(
            stored
                .get("old_name")
                .is_none()
        );
    }

    #[test]
    fn retired_record_warning_fires_once_per_path() {
        let path = Path::new("/nonexistent/retired-warning-once.json");
        assert!(first_retired_record_warning(path));
        assert!(!first_retired_record_warning(path));
    }

    #[tokio::test]
    async fn strict_loading_rejects_candidate_failures_while_default_loading_skips_them() {
        let malformed = TempDir::new().unwrap();
        fs::write(
            malformed
                .path()
                .join("bad.json"),
            b"not json",
        )
        .await
        .unwrap();
        assert!(
            CachedFilesystemStorage::<TestEntity>::new(malformed.path().to_path_buf(), "test_entity")
                .await
                .is_ok()
        );
        assert!(
            CachedFilesystemStorage::<TestEntity>::new_with_config(
                malformed.path().to_path_buf(),
                "test_entity",
                StorageConfig::default().with_strict_loading(),
            )
            .await
            .is_err()
        );

        let unreadable = TempDir::new().unwrap();
        fs::create_dir(
            unreadable
                .path()
                .join("bad.json"),
        )
        .await
        .unwrap();
        assert!(
            CachedFilesystemStorage::<TestEntity>::new_with_config(
                unreadable
                    .path()
                    .to_path_buf(),
                "test_entity",
                StorageConfig::default().with_strict_loading(),
            )
            .await
            .is_err()
        );

        let migration = TempDir::new().unwrap();
        fs::write(
            migration
                .path()
                .join("bad.json"),
            br#"{"id":"bad"}"#,
        )
        .await
        .unwrap();
        assert!(
            CachedFilesystemStorage::<MigrationFailureEntity>::new_with_config(
                migration.path().to_path_buf(),
                "migration_entity",
                StorageConfig::default().with_strict_loading(),
            )
            .await
            .is_err()
        );

        let encrypted = TempDir::new().unwrap();
        fs::write(
            encrypted
                .path()
                .join("bad.json.enc"),
            b"not ciphertext",
        )
        .await
        .unwrap();
        let (encryption_service, _) = test_encryption_service();
        assert!(
            CachedFilesystemStorage::<TestEntity>::new_with_config(
                encrypted.path().to_path_buf(),
                "test_entity",
                StorageConfig::default()
                    .with_encryption_service(encryption_service)
                    .with_strict_loading(),
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn strict_refresh_keeps_the_last_valid_cache_on_candidate_failure() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new_with_config(
            temp_dir.path().to_path_buf(),
            "test_entity",
            StorageConfig::default().with_strict_loading(),
        )
        .await
        .unwrap();
        let valid = TestEntity {
            id: "valid".to_string(),
            name: "Valid".to_string(),
            value: 1,
        };
        storage
            .save(&valid)
            .await
            .unwrap();
        fs::write(
            temp_dir
                .path()
                .join("bad.json"),
            b"not json",
        )
        .await
        .unwrap();

        assert!(
            storage
                .refresh_from_disk()
                .await
                .is_err()
        );
        assert_eq!(
            storage
                .list_all()
                .await
                .unwrap(),
            vec![valid]
        );
    }

    #[tokio::test]
    async fn test_cached_storage_crud() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Create
        let entity = TestEntity {
            id: "test-1".to_string(),
            name: "Test".to_string(),
            value: 42,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity.clone()));

        // List
        let all = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);
        assert_eq!(all[0], entity);

        // Update
        let entity2 = TestEntity {
            id: "test-1".to_string(),
            name: "Updated".to_string(),
            value: 99,
        };
        storage
            .save(&entity2)
            .await
            .unwrap();
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity2));

        // Delete
        storage
            .delete("test-1")
            .await
            .unwrap();
        let deleted = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn test_cached_storage_atomic_save_updates_cache_and_leaves_no_temp_file() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        let entity = TestEntity {
            id: "atomic-1".to_string(),
            name: "Atomic".to_string(),
            value: 7,
        };

        StorageBackend::save_atomic(&storage, &entity)
            .await
            .unwrap();

        assert_eq!(
            storage
                .get("atomic-1")
                .await
                .unwrap(),
            Some(entity)
        );
        let files = std::fs::read_dir(temp_dir.path())
            .unwrap()
            .collect::<std::io::Result<Vec<_>>>()
            .unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0]
                .path()
                .extension()
                .and_then(|extension| extension.to_str()),
            Some("json")
        );
    }

    #[tokio::test]
    async fn test_cached_storage_save_emits_localwrite_upsert_event() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        let entity = TestEntity {
            id: "evt-1".to_string(),
            name: "Event".to_string(),
            value: 1,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local event")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Upsert { id, entity: observed, source } => {
                assert_eq!(id, "evt-1");
                assert_eq!(observed, entity);
                assert_eq!(source, StorageEventSource::LocalWrite);
            }
            _ => panic!("expected local upsert event"),
        }
    }

    #[tokio::test]
    async fn test_refresh_dashmap_cache_emits_remotewrite_upsert_event_on_external_update() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        let initial = TestEntity {
            id: "evt-2".to_string(),
            name: "Before".to_string(),
            value: 10,
        };
        storage
            .save(&initial)
            .await
            .unwrap();

        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local event")
            .expect("channel closed unexpectedly");

        let external_update = TestEntity {
            id: "evt-2".to_string(),
            name: "After".to_string(),
            value: 99,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &external_update)
            .await
            .unwrap();

        refresh_dashmap_cache(
            &storage.storage_dir,
            storage.entity_name,
            &storage.config,
            &storage.cache,
            &storage.event_tx,
        )
        .await
        .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for remote event")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Upsert { id, entity: observed, source } => {
                assert_eq!(id, "evt-2");
                assert_eq!(observed, external_update);
                assert_eq!(source, StorageEventSource::RemoteWrite);
            }
            _ => panic!("expected remote upsert event"),
        }
    }

    #[tokio::test]
    async fn test_cached_storage_delete_emits_localwrite_delete_event() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let mut rx = <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::subscribe(&storage)
            .expect("cached storage must support subscribe");

        let entity = TestEntity {
            id: "evt-del-1".to_string(),
            name: "Delete".to_string(),
            value: 5,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        let _ = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local upsert event")
            .expect("channel closed unexpectedly");

        storage
            .delete("evt-del-1")
            .await
            .unwrap();

        let event = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("timed out waiting for local delete event")
            .expect("channel closed unexpectedly");

        match event {
            StorageEvent::Delete { id, source } => {
                assert_eq!(id, "evt-del-1");
                assert_eq!(source, StorageEventSource::LocalWrite);
            }
            _ => panic!("expected local delete event"),
        }
    }

    #[tokio::test]
    async fn test_refresh_from_disk_reflects_external_update_and_eviction() {
        let temp_dir = TempDir::new().unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        let a = TestEntity {
            id: "a".to_string(),
            name: "A".to_string(),
            value: 1,
        };
        let b = TestEntity {
            id: "b".to_string(),
            name: "B".to_string(),
            value: 2,
        };
        storage
            .save(&a)
            .await
            .unwrap();
        storage
            .save(&b)
            .await
            .unwrap();

        let a_updated = TestEntity {
            id: "a".to_string(),
            name: "A-updated".to_string(),
            value: 99,
        };
        save_entity_to_disk(&storage.storage_dir, storage.entity_name, &storage.config, &a_updated)
            .await
            .unwrap();
        delete_entity_from_disk::<TestEntity>(&storage.storage_dir, storage.entity_name, "b")
            .await
            .unwrap();

        let mut before = storage
            .list_all()
            .await
            .unwrap();
        before.sort_by(|x, y| x.id.cmp(&y.id));
        assert_eq!(before, vec![a.clone(), b.clone()]);

        <CachedFilesystemStorage<TestEntity> as StorageBackend<TestEntity>>::refresh_from_disk(&storage)
            .await
            .unwrap();

        let after = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(after, vec![a_updated]);
    }

    #[tokio::test]
    async fn an_uncached_lookup_or_delete_never_builds_a_path_outside_its_directory() {
        let root = TempDir::new().unwrap();
        let inside = root.path().join("inside");
        let outside = root.path().join("outside");
        let storage = UncachedFilesystemStorage::<TestEntity>::new(inside.clone(), "test_entity")
            .await
            .unwrap();
        let neighbour = UncachedFilesystemStorage::<TestEntity>::new(outside.clone(), "test_entity")
            .await
            .unwrap();
        let entity = TestEntity {
            id: "victim".to_string(),
            name: "Outside".to_string(),
            value: 7,
        };
        neighbour
            .save(&entity)
            .await
            .unwrap();

        for id in [
            "../outside/victim".to_string(),
            outside
                .join("victim")
                .to_string_lossy()
                .to_string(),
            "..".to_string(),
            "victim\0".to_string(),
        ] {
            assert_eq!(
                storage
                    .get(&id)
                    .await
                    .unwrap(),
                None,
                "{id:?} loaded an entity outside the storage directory"
            );
            assert!(
                storage
                    .delete(&id)
                    .await
                    .is_err(),
                "{id:?} was accepted for delete"
            );
        }
        assert_eq!(
            neighbour
                .get("victim")
                .await
                .unwrap(),
            Some(entity),
            "the entity outside the storage directory must be untouched"
        );
    }

    #[tokio::test]
    async fn a_save_never_writes_a_file_outside_its_directory() {
        let root = TempDir::new().unwrap();
        let inside = root.path().join("inside");
        let outside = root.path().join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        let cached = CachedFilesystemStorage::<TestEntity>::new(inside.clone(), "test_entity")
            .await
            .unwrap();
        let uncached = UncachedFilesystemStorage::<TestEntity>::new(inside.clone(), "test_entity")
            .await
            .unwrap();

        for id in [
            "../outside/victim".to_string(),
            outside
                .join("victim")
                .to_string_lossy()
                .to_string(),
            "..".to_string(),
            ".".to_string(),
            "".to_string(),
            "a\\b".to_string(),
            "victim\0".to_string(),
        ] {
            let entity = TestEntity {
                id: id.clone(),
                name: "Escaped".to_string(),
                value: 1,
            };
            assert!(
                cached
                    .save(&entity)
                    .await
                    .is_err(),
                "{id:?} was accepted for save"
            );
            assert!(
                cached
                    .atomic_save(&entity)
                    .await
                    .is_err(),
                "{id:?} was accepted for atomic save"
            );
            assert!(
                uncached
                    .save(&entity)
                    .await
                    .is_err(),
                "{id:?} was accepted for uncached save"
            );
            assert!(
                uncached
                    .atomic_save(&entity)
                    .await
                    .is_err(),
                "{id:?} was accepted for uncached atomic save"
            );
        }

        assert_eq!(
            std::fs::read_dir(&outside)
                .unwrap()
                .count(),
            0,
            "nothing may be written outside the store"
        );
        assert!(
            cached
                .list_all()
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_deserialization_error_never_quotes_the_stored_content() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();
        std::fs::write(
            temp_dir
                .path()
                .join("wrong-shape.json"),
            r#"{"id":"wrong-shape","name":"SENSITIVE-CONTENT","value":"SENSITIVE-CONTENT"}"#,
        )
        .unwrap();

        let error = storage
            .get("wrong-shape")
            .await
            .expect_err("the stored content does not fit the entity");

        let message = format!("{error:#}");
        assert!(message.contains("wrong-shape"), "the error names the entity, got: {message}");
        assert!(!message.contains("SENSITIVE-CONTENT"), "the error quotes the stored content: {message}");
    }

    #[tokio::test]
    async fn test_uncached_storage_crud() {
        let temp_dir = TempDir::new().unwrap();
        let storage = UncachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
            .await
            .unwrap();

        // Create
        let entity = TestEntity {
            id: "test-1".to_string(),
            name: "Test".to_string(),
            value: 42,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity.clone()));

        // List
        let all = storage
            .list_all()
            .await
            .unwrap();
        assert_eq!(all.len(), 1);

        // Delete
        storage
            .delete("test-1")
            .await
            .unwrap();
        let deleted = storage
            .get("test-1")
            .await
            .unwrap();
        assert_eq!(deleted, None);
    }

    #[tokio::test]
    async fn test_persistence_between_instances() {
        let temp_dir = TempDir::new().unwrap();

        // Create and save with first instance
        {
            let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
                .await
                .unwrap();

            let entity = TestEntity {
                id: "test-persist".to_string(),
                name: "Persistent".to_string(),
                value: 123,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load with second instance
        {
            let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
                .await
                .unwrap();

            let loaded = storage
                .get("test-persist")
                .await
                .unwrap();
            assert!(loaded.is_some());
            assert_eq!(loaded.unwrap().value, 123);
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct NormalizableEntity {
        id: String,
        #[serde(default)]
        normalized: bool,
    }

    impl StorableEntity for NormalizableEntity {
        fn id(&self) -> &str {
            &self.id
        }

        fn on_load(&mut self) {
            self.normalized = true;
        }
    }

    #[tokio::test]
    async fn test_on_load_hook() {
        let temp_dir = TempDir::new().unwrap();

        // Save entity without normalized flag
        {
            let storage =
                CachedFilesystemStorage::<NormalizableEntity>::new(temp_dir.path().to_path_buf(), "normalizable")
                    .await
                    .unwrap();

            let entity = NormalizableEntity {
                id: "test-1".to_string(),
                normalized: false,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load should trigger on_load which sets normalized=true
        {
            let storage =
                CachedFilesystemStorage::<NormalizableEntity>::new(temp_dir.path().to_path_buf(), "normalizable")
                    .await
                    .unwrap();

            let loaded = storage
                .get("test-1")
                .await
                .unwrap()
                .unwrap();
            assert!(loaded.normalized);
        }
    }

    // ============================================================================
    // Encryption Tests
    // ============================================================================

    /// Serializes tests that change the process-wide cache refresh interval.
    static CACHE_REFRESH_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Saves a record through a cached store, rewrites it on disk as another
    /// instance would, and reports the value the store returns after waiting.
    fn value_after_external_write(
        refresh_interval_secs: u64,
        wait: Duration,
    ) -> i32 {
        set_cache_refresh_interval_secs(refresh_interval_secs);
        let temp_dir = TempDir::new().unwrap();
        let value = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let storage = CachedFilesystemStorage::<TestEntity>::new(temp_dir.path().to_path_buf(), "test_entity")
                    .await
                    .unwrap();
                let mut entity = TestEntity {
                    id: "shared".to_string(),
                    name: "record".to_string(),
                    value: 1,
                };
                storage
                    .save(&entity)
                    .await
                    .unwrap();

                entity.value = 2;
                std::fs::write(get_raw_path(temp_dir.path(), "shared"), serde_json::to_string_pretty(&entity).unwrap())
                    .unwrap();

                tokio::time::sleep(wait).await;
                storage
                    .get("shared")
                    .await
                    .unwrap()
                    .unwrap()
                    .value
            });
        set_cache_refresh_interval_secs(0);
        value
    }

    #[test]
    fn zero_cache_refresh_interval_never_picks_up_external_writes() {
        let _guard = CACHE_REFRESH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        assert_eq!(
            value_after_external_write(0, Duration::from_millis(2500)),
            1,
            "with refresh disabled the cache keeps the value it loaded"
        );
    }

    #[test]
    fn cache_refresh_interval_picks_up_external_writes() {
        let _guard = CACHE_REFRESH_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);

        assert_eq!(
            value_after_external_write(1, Duration::from_millis(2500)),
            2,
            "a positive interval refreshes the cache from shared storage"
        );
    }

    #[tokio::test]
    async fn test_uncached_init_removes_stale_plaintext_sibling() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, key) = test_encryption_service();
        let entity = TestEntity {
            id: "stale".to_string(),
            name: "secret".to_string(),
            value: 1,
        };
        UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap()
        .save(&entity)
        .await
        .unwrap();

        let raw_path = temp_dir
            .path()
            .join("stale.json");
        let orphan_path = temp_dir
            .path()
            .join("orphan.json");
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();
        std::fs::write(&orphan_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            EncryptionService::new(KeySource::Raw { key }).unwrap(),
        )
        .await
        .unwrap();

        assert!(!raw_path.exists(), "plaintext beside its ciphertext must be removed at init");
        assert!(orphan_path.exists(), "a plaintext-only record is the only copy and must be kept");
        assert_eq!(
            storage
                .get("stale")
                .await
                .unwrap()
                .map(|loaded| loaded.value),
            Some(1)
        );
    }

    #[tokio::test]
    async fn test_uncached_storage_with_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Create
        let entity = TestEntity {
            id: "encrypted-2".to_string(),
            name: "Confidential".to_string(),
            value: 99,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("encrypted-2")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));

        // Verify encryption (encrypted files use .json.enc extension)
        let file_path = temp_dir
            .path()
            .join("encrypted-2.json.enc");
        let file_content = std::fs::read(&file_path).unwrap();
        let file_str = String::from_utf8_lossy(&file_content);
        assert!(!file_str.contains("Confidential"));
    }

    #[tokio::test]
    async fn test_cached_load_migrates_orphan_plaintext_on_restore() {
        // A portable restore drops a plaintext id.json with no .json.enc sibling.
        // On boot the cached store must load it, encrypt it to .json.enc, and
        // delete the plaintext — never skip it (which left the store empty and the
        // plaintext lingering under KMS encryption).
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, key) = test_encryption_service();

        let entity = TestEntity {
            id: "restored".to_string(),
            name: "sensitive".to_string(),
            value: 7,
        };
        let raw_path = temp_dir
            .path()
            .join("restored.json");
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();

        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Loaded into the cache rather than skipped.
        let loaded = storage
            .get("restored")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity.clone()));

        // Plaintext removed, ciphertext written and non-leaking.
        assert!(!raw_path.exists(), "plaintext must be removed after migration");
        let enc_path = temp_dir
            .path()
            .join("restored.json.enc");
        assert!(enc_path.exists(), "encrypted sibling must exist after migration");
        let enc_bytes = std::fs::read(&enc_path).unwrap();
        assert!(!String::from_utf8_lossy(&enc_bytes).contains("sensitive"));

        // A fresh instance over the same key loads the record from ciphertext only.
        let service2 = EncryptionService::new(KeySource::Raw { key }).unwrap();
        let reopened = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            service2,
        )
        .await
        .unwrap();
        assert_eq!(
            reopened
                .get("restored")
                .await
                .unwrap(),
            Some(entity)
        );
    }

    #[tokio::test]
    async fn test_cached_load_removes_stale_plaintext_sibling() {
        // A plaintext id.json beside its authoritative id.json.enc must be deleted
        // on load (the ciphertext is authoritative), and the record must still load.
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, key) = test_encryption_service();

        let entity = TestEntity {
            id: "stale".to_string(),
            name: "secret".to_string(),
            value: 1,
        };
        {
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service,
            )
            .await
            .unwrap();
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Plant a stale plaintext sibling next to the authoritative ciphertext.
        let raw_path = temp_dir
            .path()
            .join("stale.json");
        std::fs::write(&raw_path, serde_json::to_string_pretty(&entity).unwrap()).unwrap();
        assert!(
            temp_dir
                .path()
                .join("stale.json.enc")
                .exists()
        );

        let service2 = EncryptionService::new(KeySource::Raw { key }).unwrap();
        let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            service2,
        )
        .await
        .unwrap();

        assert!(!raw_path.exists(), "stale plaintext sibling must be removed on load");
        assert_eq!(
            storage
                .get("stale")
                .await
                .unwrap(),
            Some(entity)
        );
    }

    #[tokio::test]
    async fn test_rwlock_storage_with_encryption() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service, _key) = test_encryption_service();

        let storage = RwLockFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service,
        )
        .await
        .unwrap();

        // Create
        let entity = TestEntity {
            id: "encrypted-3".to_string(),
            name: "Sensitive".to_string(),
            value: 123,
        };
        storage
            .save(&entity)
            .await
            .unwrap();

        // Read
        let loaded = storage
            .get("encrypted-3")
            .await
            .unwrap();
        assert_eq!(loaded, Some(entity));
    }

    #[tokio::test]
    async fn test_wrong_key_fails_to_load() {
        let temp_dir = TempDir::new().unwrap();

        // Save with one key
        {
            let (encryption_service1, _key1) = test_encryption_service();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service1,
            )
            .await
            .unwrap();

            let entity = TestEntity {
                id: "test-key".to_string(),
                name: "Secret".to_string(),
                value: 42,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Try to load with different key
        {
            let (encryption_service2, _key2) = test_encryption_service();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service2,
            )
            .await;

            // Should fail to load due to decryption failure
            assert!(
                storage.is_err()
                    || storage
                        .unwrap()
                        .get("test-key")
                        .await
                        .unwrap()
                        .is_none()
            );
        }
    }

    #[tokio::test]
    async fn decryption_error_log_leaves_out_the_encrypted_content() {
        let temp_dir = TempDir::new().unwrap();
        let (encryption_service1, _key1) = test_encryption_service();
        let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
            temp_dir.path().to_path_buf(),
            "test_entity",
            encryption_service1,
        )
        .await
        .unwrap();
        storage
            .save(&TestEntity {
                id: "test-key".to_string(),
                name: "Secret".to_string(),
                value: 42,
            })
            .await
            .unwrap();
        let ciphertext = std::fs::read_to_string(get_encrypted_path(temp_dir.path(), "test-key")).unwrap();

        let (encryption_service2, _key2) = test_encryption_service();
        let (logs, _) = crate::observability::log_capture::capture_logs(async {
            let storage = UncachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service2,
            )
            .await?;
            storage.get("test-key").await
        })
        .await;

        assert!(logs.contains("Decryption error"), "{logs}");
        assert!(!logs.contains(ciphertext.trim()), "a log holds the encrypted content: {logs}");
    }

    #[tokio::test]
    async fn test_encryption_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let key_manager = KeyManager::from_raw_key(&rand::random::<[u8; 32]>()).unwrap();
        let raw_key = *key_manager.master_key();

        // Save with encryption
        {
            let encryption_service = EncryptionService::new(KeySource::Raw { key: raw_key }).unwrap();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service,
            )
            .await
            .unwrap();

            let entity = TestEntity {
                id: "persist".to_string(),
                name: "Persistent Secret".to_string(),
                value: 777,
            };
            storage
                .save(&entity)
                .await
                .unwrap();
        }

        // Load with same key in new instance
        {
            let encryption_service = EncryptionService::new(KeySource::Raw { key: raw_key }).unwrap();
            let storage = CachedFilesystemStorage::<TestEntity>::new_with_encryption(
                temp_dir.path().to_path_buf(),
                "test_entity",
                encryption_service,
            )
            .await
            .unwrap();

            let loaded = storage
                .get("persist")
                .await
                .unwrap()
                .unwrap();
            assert_eq!(loaded.name, "Persistent Secret");
            assert_eq!(loaded.value, 777);
        }
    }

    #[test]
    fn test_storage_config_from_encryption_disabled() {
        // Test that StorageConfig is created without encryption when disabled
        let encryption_config = crate::config::EncryptionConfig {
            enabled: false,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "TEST_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
            allow_unencrypted: false,
        };

        let config = storage_config_from_encryption_config(&encryption_config).unwrap();
        assert!(
            config
                .encryption_service
                .is_none()
        );
    }

    #[test]
    fn test_storage_config_from_missing_env_var() {
        // Test that error is returned when environment variable is missing
        let encryption_config = crate::config::EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "NONEXISTENT_ENCRYPTION_KEY_12345".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
            allow_unencrypted: false,
        };

        // This should fail because the env var doesn't exist
        let result = storage_config_from_encryption_config(&encryption_config);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("Failed to initialize encryption service")
        );
    }

    #[test]
    fn test_storage_config_with_valid_key() {
        // Test creating StorageConfig with a valid encryption key from environment
        use std::env;

        // Generate a valid 32-byte key
        let key: [u8; 32] = rand::random();
        let key_str = base64::engine::general_purpose::STANDARD.encode(key);

        unsafe { env::set_var("TEST_VALID_ENCRYPTION_KEY", &key_str) };

        let encryption_config = crate::config::EncryptionConfig {
            enabled: true,
            key_source: crate::config::KeySourceConfig::Environment,
            key_env_var: "TEST_VALID_ENCRYPTION_KEY".to_string(),
            key_file: None,
            kms_key_id: None,
            kms_max_concurrent_ops: 16,
            field_encryption_enabled: false,
            allow_unencrypted: false,
        };

        let config = storage_config_from_encryption_config(&encryption_config).unwrap();
        assert!(
            config
                .encryption_service
                .is_some()
        );

        unsafe { env::remove_var("TEST_VALID_ENCRYPTION_KEY") };
    }
}
