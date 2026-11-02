//! Cache for pipe configurations and executors

use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use super::{PipeConfig, executor::PipeExecutor};

lazy_static::lazy_static! {
    /// Global cache for pipe configurations
    pub static ref PIPE_CONFIG_CACHE: Arc<RwLock<HashMap<String, Arc<PipeConfig>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    /// Global cache for pipe executors
    pub static ref PIPE_EXECUTOR_CACHE: Arc<RwLock<HashMap<String, Arc<PipeExecutor>>>> =
        Arc::new(RwLock::new(HashMap::new()));
}

/// Invalidate cached pipe config and executor
pub async fn invalidate_pipe_cache(pipe_id: &str) {
    {
        let mut config_cache = PIPE_CONFIG_CACHE
            .write()
            .await;
        config_cache.remove(pipe_id);
    }
    {
        // Executors are keyed by pipe, variant, and effective-target digest.
        // Every key remains under the pipe's `$` prefix, so drop them all.
        let variant_prefix = format!("{pipe_id}$");
        let mut exec_cache = PIPE_EXECUTOR_CACHE
            .write()
            .await;
        exec_cache.retain(|key, _| key != pipe_id && !key.starts_with(&variant_prefix));
    }
    // Drop cached responses for this surface across every variant and effective
    // target so a response cached under a changed or removed config is never
    // served after an update or delete.
    if let Some(response_cache) = crate::pipes::response_cache::global_response_cache() {
        response_cache.remove_pipe(pipe_id);
    }
}

/// Drop every cached executor, keeping the pipe configs. An executor holds the
/// upstream secrets it has resolved for as long as it lives, so a secret update
/// or delete drops them all and the next request rebuilds its executor against
/// the stored values.
pub async fn invalidate_executors() {
    let mut exec_cache = PIPE_EXECUTOR_CACHE
        .write()
        .await;
    exec_cache.clear();
}

/// Clear all pipe caches
#[allow(dead_code)]
pub async fn clear_all_pipe_caches() {
    {
        let mut config_cache = PIPE_CONFIG_CACHE
            .write()
            .await;
        config_cache.clear();
    }
    {
        let mut exec_cache = PIPE_EXECUTOR_CACHE
            .write()
            .await;
        exec_cache.clear();
    }
}
