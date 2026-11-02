#![allow(dead_code)]

pub mod create;
pub mod handlers;
pub mod identifier;
pub mod identity_manager;
pub mod log;
pub mod resolver;
pub mod scid;
pub mod surface_integration;
pub mod transfer_auth;
pub mod trust_computer;
pub mod types;
pub mod verifier;

// Re-export commonly used types
#[cfg(test)]
pub(crate) use handlers::generate_ed25519_keypair;
pub(crate) use handlers::generate_random_dna;
pub use handlers::{
    DidWebVhApiState, create_identity, delete_identity, generate_parallel_did_web, get_identity, get_identity_history,
    get_policy_config, list_identities, resolve_did, rotate_keys, serve_did_log, transfer_ownership, update_identity,
    update_policy_config, verify_identity,
};
pub use identity_manager::{DidWebVhIdentityStore, FileSystemDidWebVhIdentityStore};
pub use types::LogEntry;
