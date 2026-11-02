//! API Key Provider Module
//!
//! Provides API key management for onboarded agents. External clients can obtain
//! agent-scoped API keys for authenticated access through the gateway.
//!
//! # Features
//! - Per-agent API key creation with client_id scoping
//! - Key rotation and revocation
//! - Storage-agnostic design with filesystem backend
//! - Integration with A2A auth validation
//!
//! # Storage Layout (Filesystem)
//! ```text
//! _storage/
//! └── api_keys/
//!     └── {agent_id}/
//!         ├── {key_id_1}.json
//!         └── ...
//! ```

mod errors;
mod fs_store;
mod generator;
pub mod handlers;
mod models;
pub mod parent;
pub mod router;
mod service;
pub mod traits;

// Re-exports for public API
pub use errors::ApiKeyResult;
pub use fs_store::FsApiKeyStore;
pub(crate) use generator::{KEY_ID_PREFIX, LEGACY_KEY_ID_PREFIX};
#[cfg(test)]
pub use models::ApiKeyIssuer;
pub use models::{ApiKeyCreated, ApiKeyMeta, ApiKeyStatus};
pub use traits::ApiKeyValidator;
