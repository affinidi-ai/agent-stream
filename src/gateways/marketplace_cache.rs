use chrono::{DateTime, Utc};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::RwLock;
use tracing::debug;

/// Cached marketplace catalog data
#[derive(Debug, Clone)]
pub struct CachedMarketplace {
    pub models: Vec<serde_json::Value>,
    pub cached_at: DateTime<Utc>,
}

/// Cache for aggregated marketplace model catalogs from all connected gateways.
///
/// Stores the merged model list with a configurable TTL so that the gateway
/// doesn't query every connected marketplace on every browser request.
pub struct MarketplaceCache {
    cache: Arc<RwLock<Option<CachedMarketplace>>>,
    refresh_in_progress: Arc<AtomicBool>,
}

impl MarketplaceCache {
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(None)),
            refresh_in_progress: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get cached models if the cache is fresh (younger than `ttl_seconds`).
    pub async fn get_if_fresh(
        &self,
        ttl_seconds: u64,
    ) -> Option<Vec<serde_json::Value>> {
        let cache = self.cache.read().await;
        if let Some(ref cached) = *cache {
            let age = (Utc::now() - cached.cached_at).num_seconds();
            if age >= 0 && (age as u64) < ttl_seconds {
                debug!("Marketplace cache hit ({age}s old, TTL {ttl_seconds}s)");
                return Some(cached.models.clone());
            }
        }
        None
    }

    /// Try to acquire the refresh lock. Returns `true` if this caller should refresh.
    pub fn try_lock_refresh(&self) -> bool {
        self.refresh_in_progress
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
    }

    /// Store freshly-fetched models and release the refresh lock.
    pub async fn set(
        &self,
        models: Vec<serde_json::Value>,
    ) {
        {
            let mut cache = self.cache.write().await;
            *cache = Some(CachedMarketplace { models, cached_at: Utc::now() });
        }
        self.refresh_in_progress
            .store(false, Ordering::SeqCst);
    }

    /// Release the refresh lock without updating the cache (on error).
    #[allow(dead_code)]
    pub fn release_lock(&self) {
        self.refresh_in_progress
            .store(false, Ordering::SeqCst);
    }
}

impl Default for MarketplaceCache {
    fn default() -> Self {
        Self::new()
    }
}
