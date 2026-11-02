//! Storage module for configuration and settings persistence
//!
//! This module provides various storage backends for configuration and settings,
//! including DynamoDB, filesystem, and caching mechanisms.

use std::sync::Arc;
use tokio::sync::OnceCell;

pub mod config_cache;
pub mod config_store;
#[cfg(feature = "didwebvh")]
pub mod did_logs;
#[cfg(feature = "didwebvh")]
#[cfg(feature = "didwebvh")]
pub mod did_logs_file;
pub mod dynamodb_store;
pub mod filesystem;
pub mod integration_credential_migration;
pub mod integration_credentials;
pub mod integration_handlers;
pub mod integration_trigger_handlers;
pub mod integrations;
pub mod settings_store;
pub mod usage_shards;

// Re-export main types for convenience
pub use config_cache::ConfigCache;
pub use config_store::ConfigurationStore;
#[cfg(feature = "didwebvh")]
pub use did_logs::DidLogStorage;
#[cfg(feature = "didwebvh")]
pub use did_logs_file::FileDidLogStorage;
pub use dynamodb_store::DynamoDbConfigStore;
pub use filesystem::StorageBackend;
pub use integrations::{Integration, IntegrationStorage};
pub use settings_store::SettingsStore;
pub use settings_store::UserSettingsStore;

// Global integration storage instance
static INTEGRATION_STORAGE: OnceCell<Arc<IntegrationStorage>> = OnceCell::const_new();

/// Initialize the global integration storage
pub async fn init_integration_storage(storage: Arc<IntegrationStorage>) {
    INTEGRATION_STORAGE
        .set(storage)
        .ok();
}

/// Get the global integration storage instance
pub fn get_integration_storage() -> Option<Arc<IntegrationStorage>> {
    INTEGRATION_STORAGE
        .get()
        .cloned()
}

// Global settings storage path
static SETTINGS_STORAGE_PATH: OnceCell<String> = OnceCell::const_new();

// Global integration triggers storage path
static INTEGRATION_TRIGGERS_STORAGE_PATH: OnceCell<String> = OnceCell::const_new();

/// Initialize the global settings storage path
pub fn init_settings_storage_path(path: String) {
    SETTINGS_STORAGE_PATH
        .set(path)
        .ok();
}

/// Get the global settings storage path
#[allow(dead_code)]
pub fn get_settings_storage_path() -> Option<String> {
    SETTINGS_STORAGE_PATH
        .get()
        .cloned()
}

/// Initialize the global integration triggers storage path
pub fn init_integration_triggers_storage_path(path: String) {
    INTEGRATION_TRIGGERS_STORAGE_PATH
        .set(path)
        .ok();
}

/// Get the global integration triggers storage path
pub fn get_integration_triggers_storage_path() -> Option<String> {
    INTEGRATION_TRIGGERS_STORAGE_PATH
        .get()
        .cloned()
}
