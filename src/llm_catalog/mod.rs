//! Editable LLM provider catalog.
//!
//! The catalog (`llm.json`) lists the LLM providers the gateway knows about.
//! Each provider carries its endpoints, models, parameters, rate-limiting and
//! capability metadata. It is stored as a single JSON document in the
//! `llm_configuration` storage directory and seeded from the shipped catalog
//! (`config_files.llm`) on first run. The storage copy is authoritative at
//! runtime and is never overwritten by the seed once present.

pub mod handlers;
pub mod router;
pub mod store;

pub use store::{LlmProviderCatalog, retain_enabled_models};

use std::sync::{Arc, OnceLock};

/// Process-wide handle to the catalog, set once at orchestrator boot so runtime
/// executors (main pipe and judge/jury) can resolve request-shaping profiles
/// without threading the store through every call site. Mirrors the static
/// accessor pattern used elsewhere for process-global configuration.
static GLOBAL_CATALOG: OnceLock<Arc<LlmProviderCatalog>> = OnceLock::new();

/// Install the process-wide catalog handle. Subsequent calls are ignored, so the
/// first writer (the orchestrator) wins for the lifetime of the process.
pub fn set_global_catalog(catalog: Arc<LlmProviderCatalog>) {
    let _ = GLOBAL_CATALOG.set(catalog);
}

/// Fetch the process-wide catalog handle, if one has been installed.
pub fn global_catalog() -> Option<Arc<LlmProviderCatalog>> {
    GLOBAL_CATALOG.get().cloned()
}

/// Whether dialling `host` must reach only public addresses because a catalog
/// provider's base URL on that host passed the public-address check at save.
pub fn requires_public_host(host: &str) -> bool {
    global_catalog().is_some_and(|catalog| catalog.requires_public_host(host))
}
