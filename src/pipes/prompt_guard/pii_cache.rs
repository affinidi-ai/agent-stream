//! In-memory cache of model-PII detection results.
//!
//! A whole-prompt cache is nearly useless (every prompt is unique), so the
//! detector caches at the granularity of a single **inspected text unit** —
//! a chat message, or the whole prompt when coreference grouping is on — keyed
//! by a hash of `(detector model, entity types, text)`. Multi-turn chat re-sends
//! the prior history verbatim, so only the newest turn misses the cache.
//!
//! The cache holds detected PII values, so it mirrors the re-hydration map's
//! posture: process-local, size- and TTL-bounded, and never persisted.

use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use sha2::{Digest, Sha256};

use super::filter::DetectedEntity;

/// Entries older than this are treated as misses and pruned.
const TTL_SECS: i64 = 3600;
/// Soft cap on entries; an insert past it prunes expired then oldest entries.
const MAX_ENTRIES: usize = 10_000;

struct Entry {
    entities: Vec<DetectedEntity>,
    stored_at: i64,
    expires_at: i64,
}

/// Compute the cache key for a text unit under a detector model + type set.
/// Sorting the types makes the key order-insensitive.
pub fn key(
    model: &str,
    entity_types: &[String],
    text: &str,
) -> String {
    let mut types: Vec<&str> = entity_types
        .iter()
        .map(String::as_str)
        .collect();
    types.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(model.as_bytes());
    hasher.update(b"\0");
    hasher.update(types.join(",").as_bytes());
    hasher.update(b"\0");
    hasher.update(text.as_bytes());
    format!("{:x}", hasher.finalize())
}

/// In-memory, TTL- and size-bounded store of detection results.
pub struct PiiDetectionCache {
    entries: DashMap<String, Entry>,
    ttl_secs: i64,
    max_entries: usize,
}

impl Default for PiiDetectionCache {
    fn default() -> Self {
        Self::with_limits(TTL_SECS, MAX_ENTRIES)
    }
}

impl PiiDetectionCache {
    fn with_limits(
        ttl_secs: i64,
        max_entries: usize,
    ) -> Self {
        Self {
            entries: DashMap::new(),
            ttl_secs,
            max_entries,
        }
    }

    /// Return the cached entities for `key` when present and unexpired.
    pub fn get(
        &self,
        key: &str,
    ) -> Option<Vec<DetectedEntity>> {
        let now = now_secs();
        self.entries
            .get(key)
            .and_then(|e| (e.expires_at > now).then(|| e.entities.clone()))
    }

    /// Store `entities` for `key`, evicting when over the soft cap.
    pub fn put(
        &self,
        key: String,
        entities: Vec<DetectedEntity>,
    ) {
        let now = now_secs();
        if self.entries.len() >= self.max_entries {
            self.evict(now);
        }
        self.entries.insert(
            key,
            Entry {
                entities,
                stored_at: now,
                expires_at: now + self.ttl_secs,
            },
        );
    }

    /// Drop expired entries, then the oldest ~10% if still at capacity.
    fn evict(
        &self,
        now: i64,
    ) {
        self.entries
            .retain(|_, e| e.expires_at > now);
        if self.entries.len() < self.max_entries {
            return;
        }
        let mut ages: Vec<(String, i64)> = self
            .entries
            .iter()
            .map(|r| (r.key().clone(), r.stored_at))
            .collect();
        ages.sort_by_key(|(_, t)| *t);
        let drop_n = (self.max_entries / 10).max(1);
        for (k, _) in ages.into_iter().take(drop_n) {
            self.entries.remove(&k);
        }
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Process-wide detection cache.
static GLOBAL: LazyLock<PiiDetectionCache> = LazyLock::new(PiiDetectionCache::default);

/// The process-wide detection cache.
pub fn global() -> &'static PiiDetectionCache {
    &GLOBAL
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entity(text: &str) -> DetectedEntity {
        DetectedEntity {
            entity_type: "PERSON".to_string(),
            text: text.to_string(),
            group: None,
        }
    }

    #[test]
    fn round_trips_a_stored_entry() {
        let cache = PiiDetectionCache::default();
        let k = key("m", &["PERSON".to_string()], "Ask Jane Doe");
        assert!(cache.get(&k).is_none());
        cache.put(k.clone(), vec![entity("Jane Doe")]);
        let hit = cache.get(&k).unwrap();
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].text, "Jane Doe");
    }

    #[test]
    fn expired_entries_are_treated_as_misses() {
        let cache = PiiDetectionCache::with_limits(0, 10);
        let k = key("m", &[], "x");
        cache.put(k.clone(), vec![entity("x")]);
        assert!(cache.get(&k).is_none());
    }

    #[test]
    fn eviction_bounds_the_cache_size() {
        let cache = PiiDetectionCache::with_limits(3600, 2);
        for i in 0..5 {
            cache.put(key("m", &[], &format!("msg{i}")), vec![entity("v")]);
        }
        assert!(cache.entries.len() <= 2);
    }

    #[test]
    fn key_varies_with_model_and_types_order_independent() {
        let a = key("m1", &["PERSON".to_string(), "ORG".to_string()], "t");
        let b = key("m2", &["PERSON".to_string(), "ORG".to_string()], "t");
        let c = key("m1", &["ORG".to_string(), "PERSON".to_string()], "t");
        assert_ne!(a, b); // different model
        assert_eq!(a, c); // type order does not matter
    }
}
