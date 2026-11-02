//! Process-wide response cache for LLM surfaces.
//!
//! When a surface enables [`crate::pipes::config::CacheConfig`], an identical
//! (normalized) buffered chat request served within the configured TTL returns
//! the previously cached upstream response without calling the provider. This
//! cuts both cost and latency on repetitive workloads.
//!
//! The cache is **in-memory only**: a cold cache after a restart is acceptable
//! and avoids the write amplification of persisting every completion to disk.
//! It is DashMap-authoritative and registered process-wide via a global
//! `OnceLock`, mirroring the budget tracker and telemetry stores.

use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};

/// Process-wide response cache, registered at startup.
static GLOBAL_RESPONSE_CACHE: OnceLock<Arc<ResponseCache>> = OnceLock::new();

/// Register the process-wide response cache. First write wins.
pub fn set_global_response_cache(cache: Arc<ResponseCache>) {
    let _ = GLOBAL_RESPONSE_CACHE.set(cache);
}

/// Access the process-wide response cache, if one has been registered.
pub fn global_response_cache() -> Option<Arc<ResponseCache>> {
    GLOBAL_RESPONSE_CACHE
        .get()
        .cloned()
}

/// Request fields that must not influence the cache key because they don't
/// change the semantic content of the completion (or are per-caller noise).
const VOLATILE_KEYS: &[&str] = &["stream", "stream_options", "user", "metadata"];

/// A stored upstream response plus the spend/tokens it originally cost.
#[derive(Debug, Clone)]
struct CacheEntry {
    /// Surface/variant scope this entry belongs to (for per-scope eviction).
    scope: String,
    response: Arc<Value>,
    /// Unix epoch seconds when the entry was stored (eviction ordering).
    stored_at: i64,
    /// Unix epoch seconds after which the entry is stale.
    expires_at: i64,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
    /// Request embedding for semantic matching (`None` for exact-only entries).
    embedding: Option<Vec<f32>>,
    provenance: CacheProvenance,
}

/// Immutable identity and display metadata for the target that produced a
/// cached response. The identity is a digest and contains no secret material.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CacheProvenance {
    pub target_identity: String,
    pub provider: String,
    pub model: String,
}

/// A cache hit: the stored response plus the spend, tokens, and target
/// provenance it avoided.
#[derive(Debug, Clone)]
pub struct CacheHit {
    pub response: Value,
    pub saved_cost: f64,
    pub saved_input_tokens: u64,
    pub saved_output_tokens: u64,
    pub provenance: CacheProvenance,
}

/// In-memory, TTL-bounded cache of upstream LLM responses keyed by a hash of
/// the normalized request.
#[derive(Debug, Default)]
pub struct ResponseCache {
    entries: DashMap<String, CacheEntry>,
    /// Live keys per scope, so semantic lookups and per-scope eviction scan
    /// only a scope's own keys instead of the whole cache (O(scope) not
    /// O(total)). Kept in lock-step with `entries` via `put`/`remove_entry`.
    scope_index: DashMap<String, HashSet<String>>,
    hits: AtomicU64,
    misses: AtomicU64,
    /// Cumulative avoided spend in micro-dollars (USD × 1e6), so the running
    /// savings total can be read without floating-point atomics.
    saved_cost_micros: AtomicU64,
}

impl ResponseCache {
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the cache scope prefix for a surface/variant/effective target.
    /// Two requests only share an entry when they resolve to the same immutable
    /// target identity and have identical normalized bodies.
    pub fn scope_key_for_target(
        pipe_id: &str,
        variant_alias: Option<&str>,
        target_identity: &str,
    ) -> String {
        let route_scope = match variant_alias {
            Some(alias) => format!("{pipe_id}${alias}"),
            None => pipe_id.to_string(),
        };
        format!("{route_scope}$target:{target_identity}")
    }

    /// Narrow `scope` to one caller of an identity pass-through surface
    /// (`forward_caller_token`), whose upstream answers as the caller, so two
    /// callers never share an entry. `forwarded_token` is the token sent
    /// upstream, folded in as its SHA-256 digest.
    pub fn caller_scope(
        scope: &str,
        forwarded_token: &str,
    ) -> String {
        let digest = Sha256::digest(forwarded_token.as_bytes());
        format!("{scope}$caller:{digest:x}")
    }

    #[cfg(test)]
    fn scope_key(
        pipe_id: &str,
        variant_alias: Option<&str>,
    ) -> String {
        Self::scope_key_for_target(pipe_id, variant_alias, "test-target")
    }

    /// Compute the full cache key: the scope plus the SHA-256 of the
    /// canonicalized (volatile-key-stripped, key-sorted) request body.
    ///
    /// INVARIANT: the key is derived **only** from the scope and the request
    /// body. Two callers sending an identical body share one entry unless the
    /// scope separates them, so any per-caller content the upstream request
    /// carries MUST be in the scope. Identity pass-through forwards the
    /// caller's token, so its scope is narrowed with [`Self::caller_scope`].
    pub fn build_key(
        scope: &str,
        body: &Value,
    ) -> String {
        let cleaned = strip_volatile(body);
        let canonical = canonical_string(&cleaned);
        let mut hasher = Sha256::new();
        hasher.update(scope.as_bytes());
        hasher.update(b"\0");
        hasher.update(canonical.as_bytes());
        let digest = hasher.finalize();
        format!("{scope}#{digest:x}")
    }

    /// Look up a cached response. Expired entries are pruned and counted as a
    /// miss. A live entry increments the hit and avoided-spend counters.
    pub fn get(
        &self,
        key: &str,
    ) -> Option<CacheHit> {
        let now = chrono::Utc::now().timestamp();

        // Read the entry under a short-lived borrow, then act after releasing
        // it so the later remove() cannot deadlock on the same DashMap shard.
        let (expired, hit) = {
            let entry = self.entries.get(key)?;
            if entry.expires_at <= now {
                (true, None)
            } else {
                (
                    false,
                    Some(CacheHit {
                        response: (*entry.response).clone(),
                        saved_cost: entry.cost,
                        saved_input_tokens: entry.input_tokens,
                        saved_output_tokens: entry.output_tokens,
                        provenance: entry.provenance.clone(),
                    }),
                )
            }
        };

        if expired {
            self.remove_entry(key);
            self.misses
                .fetch_add(1, Ordering::Relaxed);
            return None;
        }

        let hit = hit?;
        self.hits
            .fetch_add(1, Ordering::Relaxed);
        let micros = (hit.saved_cost * 1_000_000.0).max(0.0) as u64;
        self.saved_cost_micros
            .fetch_add(micros, Ordering::Relaxed);
        Some(hit)
    }

    /// Record a cache miss (used when a lookup was performed but not found, so
    /// hit-rate stats stay accurate).
    pub fn record_miss(&self) {
        self.misses
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Store a successful upstream response under `key` with the immutable
    /// target provenance used to build its scope.
    #[allow(clippy::too_many_arguments)]
    pub fn put_with_provenance(
        &self,
        key: String,
        scope: String,
        response: Value,
        ttl_seconds: u64,
        max_entries: usize,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        embedding: Option<Vec<f32>>,
        provenance: CacheProvenance,
    ) {
        let now = chrono::Utc::now().timestamp();
        let entry = CacheEntry {
            scope: scope.clone(),
            response: Arc::new(response),
            stored_at: now,
            expires_at: now + ttl_seconds as i64,
            input_tokens,
            output_tokens,
            cost,
            embedding,
            provenance,
        };
        self.entries
            .insert(key.clone(), entry);
        self.scope_index
            .entry(scope.clone())
            .or_default()
            .insert(key);
        self.enforce_scope_bound(&scope, max_entries);
    }

    #[cfg(test)]
    #[allow(clippy::too_many_arguments)]
    fn put(
        &self,
        key: String,
        scope: String,
        response: Value,
        ttl_seconds: u64,
        max_entries: usize,
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        embedding: Option<Vec<f32>>,
    ) {
        self.put_with_provenance(
            key,
            scope,
            response,
            ttl_seconds,
            max_entries,
            input_tokens,
            output_tokens,
            cost,
            embedding,
            CacheProvenance::default(),
        );
    }

    /// Remove an entry from both `entries` and the `scope_index`, cleaning up an
    /// emptied scope bucket. The single choke-point for every eviction so the
    /// index can never drift from the entry map.
    fn remove_entry(
        &self,
        key: &str,
    ) -> Option<CacheEntry> {
        let removed = self
            .entries
            .remove(key)
            .map(|(_, entry)| entry);
        if let Some(entry) = &removed {
            // Drop the guard from `get_mut` before touching the map again so the
            // later `remove` cannot deadlock on the same shard.
            let now_empty = {
                match self
                    .scope_index
                    .get_mut(&entry.scope)
                {
                    Some(mut set) => {
                        set.remove(key);
                        set.is_empty()
                    }
                    None => false,
                }
            };
            if now_empty {
                self.scope_index
                    .remove(&entry.scope);
            }
        }
        removed
    }

    /// Semantic lookup: return the highest-similarity live entry in `scope`
    /// whose request-embedding cosine similarity to `query` clears `threshold`.
    /// A hit is counted (and its avoided spend accrued) exactly like `get`.
    pub fn get_semantic(
        &self,
        scope: &str,
        query: &[f32],
        threshold: f32,
    ) -> Option<CacheHit> {
        let now = chrono::Utc::now().timestamp();
        // Scan only this scope's keys (via the index), so the cost is O(scope)
        // rather than O(total cache). Collect the keys first so the index guard
        // is released before `entries.get` / the later `get` acquire their own.
        let keys: Vec<String> = self
            .scope_index
            .get(scope)?
            .iter()
            .cloned()
            .collect();
        let mut best: Option<(String, f32)> = None;
        for key in &keys {
            let Some(entry) = self.entries.get(key) else {
                continue;
            };
            if entry.expires_at <= now {
                continue;
            }
            let Some(embedding) = entry.embedding.as_ref() else {
                continue;
            };
            let similarity = cosine_similarity(query, embedding);
            if similarity >= threshold
                && best
                    .as_ref()
                    .map(|(_, best_sim)| similarity > *best_sim)
                    .unwrap_or(true)
            {
                best = Some((key.clone(), similarity));
            }
        }
        let (key, _) = best?;
        self.get(&key)
    }

    /// Remove every cached entry for a surface, including all variant and
    /// effective-target scopes (`{pipe_id}$*`). Called when updated or deleted so a
    /// response cached under a now-changed (or removed) config is never served.
    pub fn remove_pipe(
        &self,
        pipe_id: &str,
    ) {
        let variant_prefix = format!("{pipe_id}$");
        let scopes: Vec<String> = self
            .scope_index
            .iter()
            .map(|e| e.key().clone())
            .filter(|scope| scope == pipe_id || scope.starts_with(&variant_prefix))
            .collect();
        for scope in scopes {
            let keys: Vec<String> = self
                .scope_index
                .get(&scope)
                .map(|set| set.iter().cloned().collect())
                .unwrap_or_default();
            for key in keys {
                self.remove_entry(&key);
            }
        }
    }

    /// Remove every entry whose TTL has elapsed. Run periodically so a scope
    /// that stops receiving traffic doesn't retain stale entries indefinitely.
    /// Returns the number of entries evicted.
    pub fn sweep_expired(&self) -> usize {
        let now = chrono::Utc::now().timestamp();
        let expired: Vec<String> = self
            .entries
            .iter()
            .filter(|e| e.value().expires_at <= now)
            .map(|e| e.key().clone())
            .collect();
        let count = expired.len();
        for key in expired {
            self.remove_entry(&key);
        }
        count
    }

    /// Evict the oldest entries for a scope once it exceeds `max_entries`.
    fn enforce_scope_bound(
        &self,
        scope: &str,
        max_entries: usize,
    ) {
        if max_entries == 0 {
            return;
        }
        // Read the scope's keys from the index (releasing its guard), then look
        // up each entry's age, then evict the oldest surplus via `remove_entry`.
        let keys: Vec<String> = match self.scope_index.get(scope) {
            Some(set) if set.len() > max_entries => set.iter().cloned().collect(),
            _ => return,
        };
        let mut with_age: Vec<(String, i64)> = keys
            .into_iter()
            .filter_map(|key| {
                self.entries
                    .get(&key)
                    .map(|entry| (key.clone(), entry.stored_at))
            })
            .collect();
        if with_age.len() <= max_entries {
            return;
        }
        with_age.sort_by_key(|(_, stored_at)| *stored_at);
        let evict = with_age.len() - max_entries;
        for (key, _) in with_age
            .into_iter()
            .take(evict)
        {
            self.remove_entry(&key);
        }
    }
}

/// Read-only effectiveness statistics for the cache-savings view.
#[derive(Debug, Clone, serde::Serialize)]
pub struct CacheStats {
    /// Total cache hits since startup.
    pub hits: u64,
    /// Total cache misses since startup.
    pub misses: u64,
    /// Hit rate in `[0.0, 1.0]` (`0.0` when no lookups yet).
    pub hit_rate: f64,
    /// Cumulative avoided spend in USD since startup.
    pub saved_cost_usd: f64,
    /// Number of live (non-pruned) entries currently held.
    pub entries: usize,
}

impl ResponseCache {
    /// Snapshot the cache's effectiveness (hits, misses, hit rate, avoided
    /// spend, live entry count) for the savings dashboard.
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits();
        let misses = self.misses();
        let total = hits.saturating_add(misses);
        let hit_rate = if total > 0 {
            hits as f64 / total as f64
        } else {
            0.0
        };
        CacheStats {
            hits,
            misses,
            hit_rate,
            saved_cost_usd: self.saved_cost(),
            entries: self.len(),
        }
    }

    /// Total cache hits observed since startup.
    pub fn hits(&self) -> u64 {
        self.hits
            .load(Ordering::Relaxed)
    }

    /// Total cache misses observed since startup.
    pub fn misses(&self) -> u64 {
        self.misses
            .load(Ordering::Relaxed)
    }

    /// Cumulative avoided spend in USD since startup.
    pub fn saved_cost(&self) -> f64 {
        self.saved_cost_micros
            .load(Ordering::Relaxed) as f64
            / 1_000_000.0
    }

    /// Number of live (non-pruned) entries currently held.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the cache is currently empty. Paired with `len()` (clippy's
    /// `len_without_is_empty`); exercised by the unit tests.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Return a shallow clone of the request object with the volatile keys removed.
/// Non-object bodies are returned unchanged.
fn strip_volatile(body: &Value) -> Value {
    match body {
        Value::Object(map) => {
            let mut cleaned = map.clone();
            for key in VOLATILE_KEYS {
                cleaned.remove(*key);
            }
            Value::Object(cleaned)
        }
        other => other.clone(),
    }
}

/// Cosine similarity of two equal-length vectors, in `[-1.0, 1.0]`. Returns
/// `0.0` when the lengths differ or either vector has zero magnitude (so a
/// degenerate embedding never yields a false "perfect match").
pub fn cosine_similarity(
    a: &[f32],
    b: &[f32],
) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return 0.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a <= 0.0 || norm_b <= 0.0 {
        return 0.0;
    }
    dot / (norm_a.sqrt() * norm_b.sqrt())
}

/// Extract the natural-language text of a request for semantic embedding.
///
/// For a chat body, concatenates every message's textual content (string
/// content or the `text` parts of a content array). For an embeddings body,
/// uses `input` (string or array of strings). Falls back to the canonical
/// serialization when neither shape is present.
pub fn extract_cache_text(body: &Value) -> String {
    if let Some(messages) = body
        .get("messages")
        .and_then(|m| m.as_array())
    {
        let mut out = String::new();
        for message in messages {
            match message.get("content") {
                Some(Value::String(text)) => {
                    out.push_str(text);
                    out.push('\n');
                }
                Some(Value::Array(parts)) => {
                    for part in parts {
                        if let Some(text) = part
                            .get("text")
                            .and_then(|t| t.as_str())
                        {
                            out.push_str(text);
                            out.push('\n');
                        }
                    }
                }
                _ => {}
            }
        }
        if !out.is_empty() {
            return out;
        }
    }

    match body.get("input") {
        Some(Value::String(text)) => return text.clone(),
        Some(Value::Array(items)) => {
            let joined: Vec<&str> = items
                .iter()
                .filter_map(|item| item.as_str())
                .collect();
            if !joined.is_empty() {
                return joined.join("\n");
            }
        }
        _ => {}
    }

    canonical_string(&strip_volatile(body))
}

/// Serialize a JSON value into a deterministic string with object keys sorted
/// recursively, so two semantically-identical requests hash identically
/// regardless of key order.
fn canonical_string(value: &Value) -> String {
    let mut out = String::new();
    write_canonical(value, &mut out);
    out
}

fn write_canonical(
    value: &Value,
    out: &mut String,
) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b {
            "true"
        } else {
            "false"
        }),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            out.push('"');
            out.push_str(s);
            out.push('"');
        }
        Value::Array(arr) => {
            out.push('[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (idx, key) in keys.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push('"');
                out.push_str(key);
                out.push_str("\":");
                write_canonical(&map[*key], out);
            }
            out.push('}');
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_ignores_object_key_order() {
        let scope = ResponseCache::scope_key("pipe-1", None);
        let a = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}], "temperature": 0.2});
        let b = json!({"temperature": 0.2, "messages": [{"role": "user", "content": "hi"}], "model": "gpt-4o"});
        assert_eq!(ResponseCache::build_key(&scope, &a), ResponseCache::build_key(&scope, &b));
    }

    #[test]
    fn key_ignores_volatile_fields() {
        let scope = ResponseCache::scope_key("pipe-1", None);
        let a = json!({"model": "gpt-4o", "messages": [], "stream": true, "user": "alice"});
        let b = json!({"model": "gpt-4o", "messages": []});
        assert_eq!(ResponseCache::build_key(&scope, &a), ResponseCache::build_key(&scope, &b));
    }

    #[test]
    fn key_differs_on_content() {
        let scope = ResponseCache::scope_key("pipe-1", None);
        let a = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]});
        let b = json!({"model": "gpt-4o", "messages": [{"role": "user", "content": "bye"}]});
        assert_ne!(ResponseCache::build_key(&scope, &a), ResponseCache::build_key(&scope, &b));
    }

    #[test]
    fn scope_separates_variants() {
        assert_ne!(ResponseCache::scope_key("pipe-1", None), ResponseCache::scope_key("pipe-1", Some("fast")));
    }

    #[test]
    fn scope_separates_effective_targets() {
        assert_ne!(
            ResponseCache::scope_key_for_target("pipe-1", None, "target-a"),
            ResponseCache::scope_key_for_target("pipe-1", None, "target-b")
        );
    }

    #[test]
    fn exact_and_semantic_lookups_do_not_cross_callers() {
        let cache = ResponseCache::new();
        let surface = ResponseCache::scope_key_for_target("pipe-1", None, "target-a");
        let alice = ResponseCache::caller_scope(&surface, "alice-token");
        let bob = ResponseCache::caller_scope(&surface, "bob-token");
        assert_eq!(alice, ResponseCache::caller_scope(&surface, "alice-token"));
        let body = json!({"messages": [{"role": "user", "content": "what is on my calendar?"}]});
        let alice_key = ResponseCache::build_key(&alice, &body);
        cache.put(alice_key.clone(), alice, json!({"answer": "alice"}), 3600, 100, 0, 0, 0.0, Some(vec![1.0, 0.0]));

        assert!(
            cache
                .get(&ResponseCache::build_key(&bob, &body))
                .is_none()
        );
        assert!(
            cache
                .get_semantic(&bob, &[1.0, 0.0], 0.9)
                .is_none()
        );
        assert!(
            cache
                .get(&ResponseCache::build_key(&surface, &body))
                .is_none()
        );
        assert_eq!(
            cache
                .get(&alice_key)
                .map(|hit| hit.response),
            Some(json!({"answer": "alice"}))
        );

        cache.remove_pipe("pipe-1");
        assert!(cache.is_empty(), "removing the Surface's entries removes every caller's");
    }

    #[test]
    fn exact_and_semantic_lookups_do_not_cross_effective_targets() {
        let cache = ResponseCache::new();
        let scope_a = ResponseCache::scope_key_for_target("pipe-1", None, "target-a");
        let scope_b = ResponseCache::scope_key_for_target("pipe-1", None, "target-b");
        let body = json!({"messages": [{"role": "user", "content": "same prompt"}]});
        let key_a = ResponseCache::build_key(&scope_a, &body);
        let key_b = ResponseCache::build_key(&scope_b, &body);
        cache.put(key_a, scope_a, json!({"provider": "a"}), 3600, 100, 0, 0, 0.0, Some(vec![1.0, 0.0]));

        assert!(cache.get(&key_b).is_none());
        assert!(
            cache
                .get_semantic(&scope_b, &[1.0, 0.0], 0.9)
                .is_none()
        );
    }

    #[test]
    fn cache_hit_retains_target_provenance() {
        let cache = ResponseCache::new();
        let provenance = CacheProvenance {
            target_identity: "target-a".to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
        };
        let scope = ResponseCache::scope_key_for_target("pipe-1", None, &provenance.target_identity);
        let key = ResponseCache::build_key(&scope, &json!({"messages": []}));
        cache.put_with_provenance(
            key.clone(),
            scope,
            json!({"ok": true}),
            3600,
            100,
            0,
            0,
            0.0,
            None,
            provenance.clone(),
        );

        assert_eq!(
            cache
                .get(&key)
                .unwrap()
                .provenance,
            provenance
        );
    }

    #[test]
    fn put_then_get_returns_response_and_savings() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        let body = json!({"model": "gpt-4o", "messages": []});
        let key = ResponseCache::build_key(&scope, &body);
        let response = json!({"choices": [{"message": {"content": "cached"}}]});

        cache.put(key.clone(), scope, response.clone(), 3600, 100, 10, 5, 0.0123, None);

        let hit = cache
            .get(&key)
            .expect("expected a cache hit");
        assert_eq!(hit.response, response);
        assert_eq!(hit.saved_input_tokens, 10);
        assert_eq!(hit.saved_output_tokens, 5);
        assert!((hit.saved_cost - 0.0123).abs() < 1e-9);
        assert_eq!(cache.hits(), 1);
        assert!((cache.saved_cost() - 0.0123).abs() < 1e-6);
    }

    #[test]
    fn expired_entry_is_pruned_and_missed() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        let key = ResponseCache::build_key(&scope, &json!({"model": "gpt-4o"}));
        // TTL of 0 seconds => expires_at == stored_at, immediately stale.
        cache.put(key.clone(), scope, json!({"ok": true}), 0, 100, 0, 0, 0.0, None);
        assert!(cache.get(&key).is_none());
        assert_eq!(cache.misses(), 1);
        assert!(cache.is_empty());
    }

    #[test]
    fn scope_bound_evicts_oldest() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        // Cap of 2: inserting 3 distinct entries evicts the oldest.
        for i in 0..3 {
            let body = json!({"model": "gpt-4o", "n": i});
            let key = ResponseCache::build_key(&scope, &body);
            cache.put(key, scope.clone(), json!({"i": i}), 3600, 2, 0, 0, 0.0, None);
        }
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cosine_similarity_basics() {
        assert!((cosine_similarity(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine_similarity(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
        // Zero magnitude or length mismatch => 0.0 (never a false perfect match).
        assert_eq!(cosine_similarity(&[0.0, 0.0], &[1.0, 1.0]), 0.0);
        assert_eq!(cosine_similarity(&[1.0], &[1.0, 0.0]), 0.0);
    }

    #[test]
    fn semantic_get_matches_above_threshold() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        // Two stored entries with distinct embeddings.
        cache.put("k-a".to_string(), scope.clone(), json!({"r": "a"}), 3600, 100, 3, 0, 0.0, Some(vec![1.0, 0.0, 0.0]));
        cache.put("k-b".to_string(), scope.clone(), json!({"r": "b"}), 3600, 100, 3, 0, 0.0, Some(vec![0.0, 1.0, 0.0]));

        // Query near the first entry clears a high threshold and returns it.
        let hit = cache
            .get_semantic(&scope, &[0.99, 0.01, 0.0], 0.95)
            .expect("expected a semantic hit");
        assert_eq!(hit.response, json!({"r": "a"}));
        assert_eq!(cache.hits(), 1);
    }

    #[test]
    fn semantic_get_misses_below_threshold() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        cache.put("k-a".to_string(), scope.clone(), json!({"r": "a"}), 3600, 100, 0, 0, 0.0, Some(vec![1.0, 0.0]));
        // Orthogonal query => similarity 0.0, below threshold => no hit.
        assert!(
            cache
                .get_semantic(&scope, &[0.0, 1.0], 0.9)
                .is_none()
        );
    }

    #[test]
    fn semantic_get_ignores_other_scopes() {
        let cache = ResponseCache::new();
        let scope_a = ResponseCache::scope_key("pipe-1", None);
        let scope_b = ResponseCache::scope_key("pipe-2", None);
        cache.put("k-a".to_string(), scope_b, json!({"r": "a"}), 3600, 100, 0, 0, 0.0, Some(vec![1.0, 0.0]));
        // Same embedding, different scope => no hit under scope_a.
        assert!(
            cache
                .get_semantic(&scope_a, &[1.0, 0.0], 0.9)
                .is_none()
        );
    }

    #[test]
    fn extract_cache_text_reads_messages_and_input() {
        let chat = json!({"messages": [{"role": "user", "content": "hello"}, {"role": "assistant", "content": "hi"}]});
        assert!(extract_cache_text(&chat).contains("hello"));
        let embed = json!({"model": "e", "input": "embed me"});
        assert_eq!(extract_cache_text(&embed), "embed me");
        let embed_list = json!({"model": "e", "input": ["a", "b"]});
        assert_eq!(extract_cache_text(&embed_list), "a\nb");
    }

    #[test]
    fn eviction_keeps_scope_index_in_sync() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        for i in 0..3 {
            let body = json!({"model": "gpt-4o", "n": i});
            let key = ResponseCache::build_key(&scope, &body);
            cache.put(key, scope.clone(), json!({"i": i}), 3600, 2, 0, 0, 0.0, None);
        }
        // Two live entries; the index bucket must hold exactly those two keys.
        assert_eq!(cache.len(), 2);
        let indexed = cache
            .scope_index
            .get(&scope)
            .map(|s| s.len())
            .unwrap_or(0);
        assert_eq!(indexed, 2, "scope index must match entries after eviction");
    }

    #[test]
    fn remove_pipe_drops_base_and_variant_scopes() {
        let cache = ResponseCache::new();
        let base = ResponseCache::scope_key("pipe-1", None);
        let variant = ResponseCache::scope_key("pipe-1", Some("fast"));
        let other = ResponseCache::scope_key("pipe-2", None);
        cache.put(ResponseCache::build_key(&base, &json!({"a": 1})), base, json!({"r": 1}), 3600, 100, 0, 0, 0.0, None);
        cache.put(
            ResponseCache::build_key(&variant, &json!({"a": 2})),
            variant,
            json!({"r": 2}),
            3600,
            100,
            0,
            0,
            0.0,
            None,
        );
        cache.put(
            ResponseCache::build_key(&other, &json!({"a": 3})),
            other,
            json!({"r": 3}),
            3600,
            100,
            0,
            0,
            0.0,
            None,
        );
        assert_eq!(cache.len(), 3);

        cache.remove_pipe("pipe-1");

        // Only pipe-2's entry survives; pipe-1 base + variant are gone, and the
        // index has no dangling buckets for pipe-1.
        assert_eq!(cache.len(), 1);
        assert!(
            cache
                .scope_index
                .get(&ResponseCache::scope_key("pipe-1", None))
                .is_none()
        );
        assert!(
            cache
                .scope_index
                .get(&ResponseCache::scope_key("pipe-1", Some("fast")))
                .is_none()
        );
    }

    #[test]
    fn sweep_expired_removes_only_stale_entries() {
        let cache = ResponseCache::new();
        let scope = ResponseCache::scope_key("pipe-1", None);
        let live_key = ResponseCache::build_key(&scope, &json!({"live": true}));
        let stale_key = ResponseCache::build_key(&scope, &json!({"stale": true}));
        cache.put(live_key.clone(), scope.clone(), json!({"r": "live"}), 3600, 100, 0, 0, 0.0, None);
        cache.put(stale_key, scope.clone(), json!({"r": "stale"}), 0, 100, 0, 0, 0.0, None);

        let evicted = cache.sweep_expired();
        assert_eq!(evicted, 1);
        assert_eq!(cache.len(), 1);
        // The surviving key is still reachable and the index bucket is intact.
        assert!(cache.get(&live_key).is_some());
        assert_eq!(
            cache
                .scope_index
                .get(&scope)
                .map(|s| s.len())
                .unwrap_or(0),
            1
        );
    }
}
