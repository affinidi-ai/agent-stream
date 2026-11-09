//! Filesystem-backed store for management access tokens, with an in-memory
//! cache and a token-hash index for O(1) validation. Mirrors the api_keys store
//! shape (DashMap cache + one JSON file per record).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use dashmap::DashMap;
use tokio::fs;
use tracing::{debug, error, warn};

use crate::auth_manager::pat::{PatAuthenticator, PatPrincipal};
use crate::auth_manager::resource_scope::{self, CompiledCanonicalResourceScope, RequiredHeader};

use super::{AccessToken, MAX_DELEGATION_DEPTH, generate_secret, has_token_prefix};

/// SHA-256 hex of a token secret, for storage and index lookup. The secret is a
/// 256-bit CSPRNG value, so a fast one-way hash is a sufficient verifier.
pub(crate) fn hash_secret(token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hex::encode(hasher.finalize())
}

/// Timing-safe string comparison, to confirm a hash-index hit without leaking
/// match position through timing.
fn constant_time_eq(
    a: &str,
    b: &str,
) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.as_bytes()
        .ct_eq(b.as_bytes())
        .into()
}

/// Minimum interval between disk persists of a token's `last_used_at`. A single
/// high-traffic service account (e.g. an external control plane fronting many
/// tenants) must not rewrite its record on every request; the in-memory view
/// still authenticates normally and `last_used_at` stays accurate to within this
/// window.
const LAST_USED_PERSIST_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

/// Entity label for skipped token records in `agent_stream_storage_load_errors_total`.
const STORAGE_ENTITY: &str = "access_token";

/// Deterministic fingerprint of the scope-defining fields of a token. Used as
/// part of the `compiled_scopes` cache key (alongside the token id) so a
/// concurrent `authenticate()` can never pair a compiled scope with a token
/// snapshot whose `resource_pattern` / `required_headers` it was not compiled
/// from -- closing the race between `update()` evicting the old entry and a
/// racing `compiled_scope_for()` recompiling and reinserting it.
fn scope_fingerprint(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    pattern.hash(&mut hasher);
    for h in headers {
        h.name.hash(&mut hasher);
        h.pattern.hash(&mut hasher);
    }
    hasher.finish()
}

pub struct FsAccessTokenStore {
    dir: PathBuf,
    /// id -> token record.
    cache: Arc<DashMap<String, AccessToken>>,
    /// token_hash -> id, for constant-work validation lookups.
    hash_index: Arc<DashMap<String, String>>,
    /// Serializes mutations (create / revoke / update / rotate / last-used
    /// bump) and the promotion reload so two cannot interleave — e.g. child
    /// creation racing a parent revocation or two rotations replacing the same
    /// secret (CWE-362). Store-wide rather than per-id: token management is
    /// admin-gated and low-volume, so the simpler lock is worth more than the
    /// lost parallelism. Reads do not take it.
    write_lock: Arc<tokio::sync::Mutex<()>>,
    /// (id, scope_fingerprint) -> compiled resource scope, built lazily on
    /// first authenticate. Avoids recompiling header validators per request.
    compiled_scopes: Arc<DashMap<(String, u64), Arc<CompiledCanonicalResourceScope>>>,
    /// id -> last time `last_used_at` was flushed, to coalesce writes on a hot token.
    last_persist: Arc<DashMap<String, std::time::Instant>>,
}

impl FsAccessTokenStore {
    pub async fn new(dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir).await?;
        let store = Self {
            dir,
            cache: Arc::new(DashMap::new()),
            hash_index: Arc::new(DashMap::new()),
            write_lock: Arc::new(tokio::sync::Mutex::new(())),
            compiled_scopes: Arc::new(DashMap::new()),
            last_persist: Arc::new(DashMap::new()),
        };
        for token in store.read_records().await? {
            store.insert_cached(token);
        }
        Ok(store)
    }

    /// Read every token record in the store directory. A record that cannot be
    /// read or parsed is skipped and counted in the storage load-error metric.
    async fn read_records(&self) -> std::io::Result<Vec<AccessToken>> {
        let mut tokens = Vec::new();
        let mut entries = fs::read_dir(&self.dir).await?;
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path
                .extension()
                .and_then(|e| e.to_str())
                != Some("json")
            {
                continue;
            }
            match fs::read(&path).await {
                Ok(bytes) => match serde_json::from_slice::<AccessToken>(&bytes) {
                    Ok(token) => tokens.push(token),
                    Err(e) => {
                        error!("access_tokens: skipping unreadable record {:?}: {}", path, e);
                        crate::metrics::backends::prometheus::track_storage_load_error(STORAGE_ENTITY, "parse_failed");
                    }
                },
                Err(e) => {
                    error!("access_tokens: failed reading {:?}: {}", path, e);
                    crate::metrics::backends::prometheus::track_storage_load_error(STORAGE_ENTITY, "read_failed");
                }
            }
        }
        Ok(tokens)
    }

    fn insert_cached(
        &self,
        token: AccessToken,
    ) {
        self.hash_index
            .insert(token.token_hash.clone(), token.id.clone());
        self.cache
            .insert(token.id.clone(), token);
    }

    fn path_for(
        &self,
        id: &str,
    ) -> PathBuf {
        self.dir
            .join(format!("{id}.json"))
    }

    async fn persist(
        &self,
        token: &AccessToken,
    ) -> std::io::Result<()> {
        let bytes =
            serde_json::to_vec_pretty(token).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(self.path_for(&token.id), bytes).await
    }

    pub async fn create(
        &self,
        token: AccessToken,
    ) -> std::io::Result<()> {
        let _guard = self.write_lock.lock().await;
        self.validate_new_token(&token, Utc::now())?;
        self.persist(&token).await?;
        self.insert_cached(token);
        Ok(())
    }

    fn validate_new_token(
        &self,
        token: &AccessToken,
        now: chrono::DateTime<Utc>,
    ) -> std::io::Result<()> {
        if token.delegation_depth > MAX_DELEGATION_DEPTH {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "access-token delegation depth exceeds the configured maximum",
            ));
        }
        let Some(parent_id) = token
            .parent_token_id
            .as_deref()
        else {
            return if token.delegation_depth == 0 {
                Ok(())
            } else {
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "root access token must have delegation depth zero",
                ))
            };
        };
        let parent = self
            .get(parent_id)
            .filter(|parent| parent.is_active(now) && self.lineage_is_active(parent, now))
            .ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::PermissionDenied, "parent access token is no longer active")
            })?;
        if parent.is_resource_scoped()
            || token.user_id != parent.user_id
            || token.delegation_depth
                != parent
                    .delegation_depth
                    .saturating_add(1)
            || (!parent.scopes.is_empty()
                && (token.scopes.is_empty()
                    || token
                        .scopes
                        .iter()
                        .any(|scope| !parent.scopes.contains(scope))))
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "access-token delegation exceeds its parent authority",
            ));
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<AccessToken> {
        self.cache
            .iter()
            .map(|e| e.value().clone())
            .collect()
    }

    pub fn get(
        &self,
        id: &str,
    ) -> Option<AccessToken> {
        self.cache
            .get(id)
            .map(|e| e.value().clone())
    }

    /// Mark a token and every transitive descendant revoked. Returns the root
    /// record, or `None` if unknown.
    pub async fn revoke(
        &self,
        id: &str,
    ) -> std::io::Result<Option<AccessToken>> {
        let _guard = self.write_lock.lock().await;
        let Some(root) = self.get(id) else {
            return Ok(None);
        };
        for token_id in self.descendants_including(id) {
            let Some(mut token) = self.get(&token_id) else {
                continue;
            };
            if token.revoked_at.is_some() {
                continue;
            }
            token.revoked_at = Some(Utc::now());
            self.persist(&token).await?;
            self.cache
                .insert(token.id.clone(), token.clone());
            self.hash_index
                .remove(&token.token_hash);
            self.compiled_scopes
                .retain(|(cached_id, _), _| cached_id != &token_id);
            self.last_persist
                .remove(&token_id);
        }
        Ok(self.get(id).or(Some(root)))
    }

    fn descendants_including(
        &self,
        root_id: &str,
    ) -> Vec<String> {
        let mut token_ids = vec![root_id.to_string()];
        let mut index = 0;
        while index < token_ids.len() {
            let parent_id = token_ids[index].clone();
            for entry in self.cache.iter() {
                if entry
                    .parent_token_id
                    .as_deref()
                    == Some(parent_id.as_str())
                    && !token_ids.contains(entry.key())
                {
                    token_ids.push(entry.key().clone());
                }
            }
            index += 1;
        }
        token_ids
    }

    pub fn controls(
        &self,
        controller_id: &str,
        target_id: &str,
    ) -> bool {
        let mut current_id = target_id.to_string();
        let mut visited = std::collections::HashSet::new();
        loop {
            if current_id == controller_id {
                return true;
            }
            if !visited.insert(current_id.clone()) {
                return false;
            }
            let Some(current) = self.get(&current_id) else {
                return false;
            };
            let Some(parent_id) = current.parent_token_id else {
                return false;
            };
            current_id = parent_id;
        }
    }

    /// Update a token's mutable metadata (display name, scope allow-list, and
    /// resource scope). The secret hash, bound user, and timestamps are never
    /// touched. Returns the updated record, or `None` if unknown.
    pub async fn update(
        &self,
        id: &str,
        name: String,
        description: String,
        scopes: Vec<String>,
        resource_pattern: Option<String>,
        required_headers: Vec<RequiredHeader>,
    ) -> std::io::Result<Option<AccessToken>> {
        let _guard = self.write_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return Ok(None);
        };
        let old_fp = scope_fingerprint(
            token
                .resource_pattern
                .as_deref(),
            &token.required_headers,
        );
        token.name = name;
        token.description = description;
        token.scopes = scopes;
        token.resource_pattern = resource_pattern;
        token.required_headers = required_headers;
        self.persist(&token).await?;
        self.cache
            .insert(token.id.clone(), token.clone());
        // Evict the now-stale compiled entry for the previous scope fields. A
        // concurrent authenticate() reading either the old or new token record
        // computes its own matching fingerprint, so there is no window where a
        // stale compiled scope could be paired with mismatched token fields.
        self.compiled_scopes
            .remove(&(id.to_string(), old_fp));
        Ok(Some(token))
    }

    /// Replace a token's secret while retaining its stable record id and lineage.
    /// The new secret is returned exactly once.
    pub async fn rotate(
        &self,
        id: &str,
        actor: &str,
        expected_generation: u32,
    ) -> std::io::Result<Option<(AccessToken, String)>> {
        let _guard = self.write_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return Ok(None);
        };
        if !token.is_active(Utc::now())
            || !self.lineage_is_active(&token, Utc::now())
            || token.rotation_generation != expected_generation
        {
            return Ok(None);
        }
        let now = Utc::now();
        let secret = generate_secret();
        let old_hash = token.token_hash.clone();
        token.token_hash = hash_secret(&secret);
        token.rotation_generation = token
            .rotation_generation
            .saturating_add(1);
        token.rotated_at = Some(now);
        token.rotated_by = Some(actor.to_string());
        token.last_used_at = None;
        self.persist(&token).await?;
        self.hash_index
            .remove(&old_hash);
        self.hash_index
            .insert(token.token_hash.clone(), token.id.clone());
        self.cache
            .insert(token.id.clone(), token.clone());
        self.last_persist.remove(id);
        Ok(Some((token, secret)))
    }

    fn lineage_is_active(
        &self,
        record: &AccessToken,
        now: chrono::DateTime<Utc>,
    ) -> bool {
        if record.delegation_depth > MAX_DELEGATION_DEPTH {
            return false;
        }
        let mut current = record.clone();
        let mut visited = std::collections::HashSet::from([current.id.clone()]);
        loop {
            let Some(parent_id) = current
                .parent_token_id
                .as_deref()
            else {
                return current.delegation_depth == 0;
            };
            if !visited.insert(parent_id.to_string()) {
                return false;
            }
            let Some(parent) = self.get(parent_id) else {
                return false;
            };
            if !parent.is_active(now)
                || parent.is_resource_scoped()
                || current.user_id != parent.user_id
                || current.delegation_depth
                    != parent
                        .delegation_depth
                        .saturating_add(1)
                || (!parent.scopes.is_empty()
                    && (current.scopes.is_empty()
                        || current
                            .scopes
                            .iter()
                            .any(|scope| !parent.scopes.contains(scope))))
            {
                return false;
            }
            current = parent;
        }
    }

    async fn touch_last_used(
        &self,
        id: &str,
    ) {
        // Only the Active writes token records: a Standby or an instance still
        // activating holds its startup copy, and persisting it could overwrite a
        // revocation the Active made. The activation generation is captured so the
        // check can be repeated once the write lock is held.
        let generation = crate::server::mode::current_activation_generation();
        if !crate::server::mode::is_serving_generation(generation) {
            return;
        }
        // Coalesce writes: a hot token must not rewrite its record on every
        // request. Within the window, skip entirely — no clone, no disk I/O, and
        // no need to take the write lock below.
        let now = std::time::Instant::now();
        if let Some(prev) = self.last_persist.get(id)
            && now.duration_since(*prev.value()) < LAST_USED_PERSIST_INTERVAL
        {
            return;
        }
        // Claim the window up front so concurrent requests collapse to one write.
        self.last_persist
            .insert(id.to_string(), now);
        // Take the same write lock as revoke/update/rotate and re-read the record
        // under it. Without this, a `last_used` bump computed from a pre-revocation
        // read could be written back over a record that a concurrent rotate/revoke
        // just marked revoked — resurrecting a dead token (CWE-362). Only a record
        // that is still active gets bumped; a revoked or expired one is left as-is.
        let _guard = self.write_lock.lock().await;
        let Some(mut token) = self.get(id) else {
            return;
        };
        if !token.is_active(Utc::now()) || !crate::server::mode::is_serving_generation(generation) {
            return;
        }
        token.last_used_at = Some(Utc::now());
        if let Err(e) = self.persist(&token).await {
            debug!("access_tokens: failed to persist last_used for {}: {}", id, e);
            return;
        }
        self.cache
            .insert(token.id.clone(), token);
    }

    fn find_by_secret(
        &self,
        token: &str,
    ) -> Option<AccessToken> {
        let presented = hash_secret(token);
        let id = self
            .hash_index
            .get(&presented)
            .map(|e| e.value().clone())?;
        let record = self.get(&id)?;
        if constant_time_eq(&record.token_hash, &presented) {
            Some(record)
        } else {
            None
        }
    }

    /// Resolve (and cache) the compiled resource scope for a record.
    ///
    /// - `Ok(None)` — the token declares neither a pattern nor required headers.
    /// - `Ok(Some(scope))` — a valid compiled scope (cached for reuse).
    /// - `Err(())` — a declared scope failed to compile; the caller must reject
    ///   the token (fail closed) rather than treat it as unscoped.
    fn compiled_scope_for(
        &self,
        record: &AccessToken,
    ) -> Result<Option<Arc<CompiledCanonicalResourceScope>>, ()> {
        if record
            .resource_pattern
            .is_none()
            && record
                .required_headers
                .is_empty()
        {
            return Ok(None);
        }
        let fp = scope_fingerprint(
            record
                .resource_pattern
                .as_deref(),
            &record.required_headers,
        );
        let key = (record.id.clone(), fp);
        if let Some(existing) = self.compiled_scopes.get(&key) {
            return Ok(Some(existing.value().clone()));
        }
        match resource_scope::compile_canonical(
            record
                .resource_pattern
                .as_deref(),
            &record.required_headers,
        ) {
            Ok(compiled) => {
                let arc = Arc::new(compiled);
                self.compiled_scopes
                    .insert(key, arc.clone());
                Ok(Some(arc))
            }
            Err(e) => {
                warn!(token_id = %record.id, error = %e, "access token has an invalid resource scope; rejecting");
                Err(())
            }
        }
    }
}

#[async_trait]
impl PatAuthenticator for FsAccessTokenStore {
    async fn authenticate(
        &self,
        token: &str,
    ) -> Option<PatPrincipal> {
        if !has_token_prefix(token) {
            return None;
        }
        let record = self.find_by_secret(token)?;
        let now = Utc::now();
        if !record.is_active(now) || !self.lineage_is_active(&record, now) {
            return None;
        }
        // A stored scope that no longer compiles makes the token unusable rather
        // than silently unscoped.
        let resource_scope = self
            .compiled_scope_for(&record)
            .ok()?;
        let resource_scoped = resource_scope.is_some();
        self.touch_last_used(&record.id)
            .await;
        Some(PatPrincipal {
            user_id: record.user_id.clone(),
            scopes: if record.scopes.is_empty() {
                None
            } else {
                Some(record.scopes.clone())
            },
            token_id: record.id,
            delegation_depth: record.delegation_depth,
            resource_scoped,
            resource_scope,
        })
    }
}

/// Re-read the tokens the previous Active wrote, so a token it revoked is
/// rejected and one it created or rotated authenticates. Records no longer on
/// disk leave the cache, and compiled scopes and last-used coalescing restart
/// from the reloaded records.
#[async_trait]
impl crate::server::mode::ReloadOnPromotion for FsAccessTokenStore {
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        let _guard = self.write_lock.lock().await;
        let tokens = self.read_records().await?;
        let ids: std::collections::HashSet<String> = tokens
            .iter()
            .map(|token| token.id.clone())
            .collect();
        let hashes: std::collections::HashSet<String> = tokens
            .iter()
            .map(|token| token.token_hash.clone())
            .collect();
        for token in tokens {
            self.insert_cached(token);
        }
        self.cache
            .retain(|id, _| ids.contains(id));
        self.hash_index
            .retain(|hash, _| hashes.contains(hash));
        self.compiled_scopes.clear();
        self.last_persist.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_tokens::{LEGACY_TOKEN_PREFIX, TOKEN_ID_PREFIX, TOKEN_PREFIX, generate_token};
    use chrono::Duration;

    async fn store() -> FsAccessTokenStore {
        let dir = std::env::temp_dir().join(format!("agent-stream-access-tokens-{}", uuid::Uuid::new_v4()));
        FsAccessTokenStore::new(dir)
            .await
            .unwrap()
    }

    fn record(
        hash: &str,
        scopes: Vec<String>,
    ) -> AccessToken {
        AccessToken {
            id: format!("asat_{}", uuid::Uuid::new_v4().as_simple()),
            name: "test".into(),
            description: String::new(),
            token_hash: hash.to_string(),
            user_id: "user-1".into(),
            scopes,
            resource_pattern: None,
            required_headers: Vec::new(),
            created_by: "user-1".into(),
            parent_token_id: None,
            delegation_depth: 0,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[tokio::test]
    async fn authenticates_live_token_and_maps_scopes() {
        let s = store().await;
        let secret = "aspat_secret-value";
        let mut rec = record(&hash_secret(secret), vec!["pipes.edit".into()]);
        rec.user_id = "admin-9".into();
        s.create(rec).await.unwrap();

        let principal = s
            .authenticate(secret)
            .await
            .expect("should authenticate");
        assert_eq!(principal.user_id, "admin-9");
        assert_eq!(principal.scopes, Some(vec!["pipes.edit".to_string()]));
    }

    #[tokio::test]
    async fn empty_scopes_map_to_none() {
        let s = store().await;
        let secret = "aspat_unscoped";
        s.create(record(&hash_secret(secret), vec![]))
            .await
            .unwrap();
        let principal = s
            .authenticate(secret)
            .await
            .unwrap();
        assert_eq!(principal.scopes, None);
    }

    #[test]
    fn new_tokens_use_the_current_prefixes() {
        let (id, secret) = generate_token();

        assert!(id.starts_with(TOKEN_ID_PREFIX));
        assert!(secret.starts_with(TOKEN_PREFIX));
    }

    #[tokio::test]
    async fn authenticates_token_issued_with_legacy_prefix() {
        let s = store().await;
        let secret = format!("{LEGACY_TOKEN_PREFIX}issued-before-rename");
        let mut rec = record(&hash_secret(&secret), vec![]);
        rec.id = format!("atgat_{}", uuid::Uuid::new_v4().as_simple());
        let legacy_id = rec.id.clone();
        s.create(rec).await.unwrap();

        assert!(
            s.authenticate(&secret)
                .await
                .is_some()
        );
        assert!(s.get(&legacy_id).is_some(), "a record created before the id rename is still found");
        assert!(
            s.authenticate(&format!("{TOKEN_PREFIX}issued-before-rename"))
                .await
                .is_none(),
            "a legacy secret is not interchangeable with its renamed form"
        );
    }

    #[tokio::test]
    async fn rejects_unknown_wrong_prefix_and_revoked() {
        let s = store().await;
        let secret = "aspat_live";
        s.create(record(&hash_secret(secret), vec![]))
            .await
            .unwrap();

        assert!(
            s.authenticate("aspat_nope")
                .await
                .is_none(),
            "unknown token"
        );
        assert!(
            s.authenticate("bearer-without-prefix")
                .await
                .is_none(),
            "wrong prefix"
        );

        let id = s.list()[0].id.clone();
        s.revoke(&id).await.unwrap();
        assert!(
            s.authenticate(secret)
                .await
                .is_none(),
            "revoked token"
        );
    }

    #[tokio::test]
    async fn rejects_expired_token() {
        let s = store().await;
        let secret = "aspat_expired";
        let mut rec = record(&hash_secret(secret), vec![]);
        rec.expires_at = Some(Utc::now() - Duration::minutes(1));
        s.create(rec).await.unwrap();
        assert!(
            s.authenticate(secret)
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn accepts_a_bounded_child_and_rejects_invalid_lineage() {
        let s = store().await;
        let mut root = record(&hash_secret("aspat_root"), vec!["pipes.view".into(), "secrets.view".into()]);
        root.user_id = "svc-user".into();
        let root_id = root.id.clone();
        s.create(root).await.unwrap();

        let mut child = record(&hash_secret("aspat_child"), vec!["pipes.view".into()]);
        child.user_id = "svc-user".into();
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        s.create(child)
            .await
            .expect("valid child");
        assert!(
            s.authenticate("aspat_child")
                .await
                .is_some()
        );

        let mut wrong_subject = record(&hash_secret("aspat_wrong-subject"), vec!["pipes.view".into()]);
        wrong_subject.user_id = "another-user".into();
        wrong_subject.parent_token_id = Some(root_id.clone());
        wrong_subject.delegation_depth = 1;
        assert_eq!(
            s.create(wrong_subject)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );

        let mut broader = record(&hash_secret("aspat_broader"), vec!["teams.edit".into()]);
        broader.user_id = "svc-user".into();
        broader.parent_token_id = Some(root_id);
        broader.delegation_depth = 1;
        assert_eq!(
            s.create(broader)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );

        let mut orphan = record(&hash_secret("aspat_orphan"), vec!["pipes.view".into()]);
        orphan.parent_token_id = Some("asat_missing".into());
        orphan.delegation_depth = 1;
        assert_eq!(
            s.create(orphan)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    async fn resource_scoped_parent_cannot_create_a_child() {
        let s = store().await;
        let mut root = record(&hash_secret("aspat_scoped-root"), vec!["access_tokens.edit".into()]);
        root.resource_pattern = Some("TENANT:.*".into());
        let root_id = root.id.clone();
        s.create(root).await.unwrap();

        let mut child = record(&hash_secret("aspat_scoped-child"), vec!["access_tokens.edit".into()]);
        child.parent_token_id = Some(root_id);
        child.delegation_depth = 1;
        assert_eq!(
            s.create(child)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidInput
        );
    }

    #[tokio::test]
    async fn parent_scope_narrowing_invalidates_a_broader_child() {
        let s = store().await;
        let root = record(&hash_secret("aspat_scope-root"), vec!["pipes.view".into(), "secrets.view".into()]);
        let root_id = root.id.clone();
        s.create(root).await.unwrap();

        let mut child = record(&hash_secret("aspat_scope-child"), vec!["pipes.view".into()]);
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        s.create(child).await.unwrap();
        assert!(
            s.authenticate("aspat_scope-child")
                .await
                .is_some()
        );

        s.update(&root_id, "root".into(), String::new(), vec!["secrets.view".into()], None, vec![])
            .await
            .unwrap();
        assert!(
            s.authenticate("aspat_scope-child")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn revoking_a_parent_cascades_to_descendants() {
        let s = store().await;
        let root = record(&hash_secret("aspat_cascade-root"), vec![]);
        let root_id = root.id.clone();
        s.create(root).await.unwrap();

        let mut child = record(&hash_secret("aspat_cascade-child"), vec![]);
        let child_id = child.id.clone();
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        s.create(child).await.unwrap();

        let mut grandchild = record(&hash_secret("aspat_cascade-grandchild"), vec![]);
        let grandchild_id = grandchild.id.clone();
        grandchild.parent_token_id = Some(child_id.clone());
        grandchild.delegation_depth = 2;
        s.create(grandchild)
            .await
            .unwrap();

        assert!(s.controls(&root_id, &root_id));
        assert!(s.controls(&root_id, &child_id));
        assert!(s.controls(&root_id, &grandchild_id));
        assert!(s.controls(&child_id, &grandchild_id));
        assert!(!s.controls(&child_id, &root_id));

        s.revoke(&root_id)
            .await
            .unwrap();
        for token_id in [&root_id, &child_id, &grandchild_id] {
            assert!(
                s.get(token_id)
                    .unwrap()
                    .revoked_at
                    .is_some(),
                "{token_id} must be revoked"
            );
        }
        assert!(
            s.authenticate("aspat_cascade-child")
                .await
                .is_none()
        );
        assert!(
            s.authenticate("aspat_cascade-grandchild")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn update_changes_name_and_scopes_not_the_secret() {
        let s = store().await;
        let secret = "aspat_editable";
        s.create(record(&hash_secret(secret), vec!["pipes.view".into()]))
            .await
            .unwrap();
        let id = s.list()[0].id.clone();

        let updated = s
            .update(
                &id,
                "renamed".into(),
                "new desc".into(),
                vec!["pipes.edit".into(), "secrets.view".into()],
                None,
                vec![],
            )
            .await
            .unwrap()
            .expect("token exists");
        assert_eq!(updated.name, "renamed");
        assert_eq!(updated.description, "new desc");
        assert_eq!(updated.scopes, vec!["pipes.edit".to_string(), "secrets.view".to_string()]);

        // The same secret still authenticates and now carries the new scopes.
        let principal = s
            .authenticate(secret)
            .await
            .expect("still valid");
        assert_eq!(principal.scopes, Some(vec!["pipes.edit".to_string(), "secrets.view".to_string()]));

        // Unknown id ⇒ None.
        assert!(
            s.update("asat_missing", "x".into(), String::new(), vec![], None, vec![])
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotate_replaces_secret_on_the_same_record() {
        let s = store().await;
        let secret = "aspat_rotate-me";
        s.create(record(&hash_secret(secret), vec!["metrics.view".into()]))
            .await
            .unwrap();
        let id = s.list()[0].id.clone();

        let (new_rec, new_secret) = s
            .rotate(&id, "admin-1", 0)
            .await
            .unwrap()
            .expect("rotated");
        assert_eq!(new_rec.id, id, "rotation preserves the record id and lineage");
        assert_eq!(new_rec.user_id, "user-1", "subject is carried over");
        assert_eq!(new_rec.scopes, vec!["metrics.view".to_string()], "scopes carried over");
        assert_eq!(new_rec.created_by, "user-1", "original creator is preserved");
        assert_eq!(new_rec.rotated_by.as_deref(), Some("admin-1"));
        assert_eq!(new_rec.rotation_generation, 1);
        assert!(new_rec.rotated_at.is_some());
        assert!(new_secret.starts_with(TOKEN_PREFIX));

        // The same record remains active; only its replacement secret works.
        assert!(
            s.get(&id)
                .unwrap()
                .revoked_at
                .is_none(),
            "rotation does not revoke the stable token record"
        );
        assert!(
            s.authenticate(&new_secret)
                .await
                .is_some(),
            "new secret is live"
        );
        assert!(
            s.authenticate(secret)
                .await
                .is_none(),
            "old secret is dead"
        );

        // A stale generation cannot rotate the record again.
        assert!(
            s.rotate(&id, "admin-1", 0)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rotating_a_parent_preserves_child_lineage() {
        let s = store().await;
        let root = record(&hash_secret("aspat_rotate-root"), vec![]);
        let root_id = root.id.clone();
        s.create(root).await.unwrap();

        let mut child = record(&hash_secret("aspat_rotate-child"), vec![]);
        child.parent_token_id = Some(root_id.clone());
        child.delegation_depth = 1;
        s.create(child).await.unwrap();

        let (rotated, new_secret) = s
            .rotate(&root_id, "admin-1", 0)
            .await
            .unwrap()
            .expect("root rotates");
        assert_eq!(rotated.id, root_id);
        assert!(
            s.authenticate("aspat_rotate-root")
                .await
                .is_none()
        );
        assert!(
            s.authenticate(&new_secret)
                .await
                .is_some()
        );
        assert!(
            s.authenticate("aspat_rotate-child")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn rotate_unknown_returns_none() {
        let s = store().await;
        assert!(
            s.rotate("asat_missing", "admin-1", 0)
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_rotations_accept_exactly_one_generation() {
        // Two rotations racing on generation zero must not both return secrets.
        // The write lock and generation check make the second caller fail closed.
        let s = std::sync::Arc::new(store().await);
        s.create(record(&hash_secret("aspat_race-me"), vec![]))
            .await
            .unwrap();
        let id = s.list()[0].id.clone();

        let a = {
            let (s, id) = (s.clone(), id.clone());
            tokio::spawn(async move {
                s.rotate(&id, "admin-1", 0)
                    .await
                    .unwrap()
            })
        };
        let b = {
            let (s, id) = (s.clone(), id.clone());
            tokio::spawn(async move {
                s.rotate(&id, "admin-1", 0)
                    .await
                    .unwrap()
            })
        };
        let (ra, rb) = (a.await.unwrap(), b.await.unwrap());

        assert_eq!(
            [ra.is_some(), rb.is_some()]
                .iter()
                .filter(|x| **x)
                .count(),
            1,
            "exactly one rotation advances the generation"
        );
        assert_eq!(s.list().len(), 1, "rotation does not create another record");
        assert_eq!(
            s.get(&id)
                .unwrap()
                .rotation_generation,
            1
        );
    }

    #[test]
    fn concurrent_auth_does_not_restore_a_rotated_secret() {
        let _ready = crate::server::mode::ready_for_test();
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap()
            .block_on(concurrent_auth_vs_rotation());
    }

    async fn concurrent_auth_vs_rotation() {
        // authenticate() bumps last_used via touch_last_used. Sharing the write
        // lock with rotation prevents a stale snapshot from restoring the old hash.
        //
        // Run many interleavings on a multi-thread runtime so the harmful ordering
        // (auth reads old hash -> rotation persists new hash -> auth writes old
        // snapshot) is exercised. The old secret must remain unusable.
        for i in 0..64 {
            let s = std::sync::Arc::new(store().await);
            let old_secret = format!("aspat_touch-race-{i}");
            s.create(record(&hash_secret(&old_secret), vec![]))
                .await
                .unwrap();
            let id = s.list()[0].id.clone();

            let auth = {
                let (s, secret) = (s.clone(), old_secret.clone());
                tokio::spawn(async move { s.authenticate(&secret).await })
            };
            let rot = {
                let (s, id) = (s.clone(), id.clone());
                tokio::spawn(async move {
                    s.rotate(&id, "admin-1", 0)
                        .await
                        .unwrap()
                })
            };
            let _ = auth.await.unwrap();
            rot.await
                .unwrap()
                .expect("rotation replaces the secret");

            let record = s.get(&id).unwrap();
            assert_eq!(record.rotation_generation, 1, "iter {i}: rotation remains recorded");
            assert!(record.revoked_at.is_none(), "iter {i}: stable token remains active");
            assert!(
                s.authenticate(&old_secret)
                    .await
                    .is_none(),
                "iter {i}: old secret does not authenticate after rotation"
            );
            assert_eq!(s.list().len(), 1, "iter {i}: rotation keeps one stable record");
        }
    }

    #[tokio::test]
    async fn survives_reload_from_disk() {
        let dir = std::env::temp_dir().join(format!("agent-stream-access-tokens-{}", uuid::Uuid::new_v4()));
        let secret = "aspat_persisted";
        {
            let s = FsAccessTokenStore::new(&dir)
                .await
                .unwrap();
            s.create(record(&hash_secret(secret), vec!["secrets.edit".into()]))
                .await
                .unwrap();
        }
        let reloaded = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();
        let principal = reloaded
            .authenticate(secret)
            .await
            .expect("reloaded token authenticates");
        assert_eq!(principal.scopes, Some(vec!["secrets.edit".to_string()]));
    }

    async fn active_and_standby() -> (FsAccessTokenStore, FsAccessTokenStore) {
        let dir = std::env::temp_dir().join(format!("agent-stream-access-tokens-{}", uuid::Uuid::new_v4()));
        let active = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();
        let standby = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();
        (active, standby)
    }

    #[tokio::test]
    async fn promotion_reload_rejects_a_token_the_previous_active_revoked() {
        use crate::server::mode::ReloadOnPromotion;
        let secret = "aspat_revoked_elsewhere";
        let token = record(&hash_secret(secret), vec![]);
        let id = token.id.clone();
        let (active, standby) = active_and_standby().await;
        active
            .create(token)
            .await
            .unwrap();
        standby
            .reload_from_storage()
            .await
            .unwrap();
        assert!(standby.get(&id).is_some());
        active
            .revoke(&id)
            .await
            .unwrap()
            .expect("token exists");

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert!(
            standby
                .authenticate(secret)
                .await
                .is_none()
        );
        let on_disk: AccessToken = serde_json::from_slice(
            &fs::read(standby.path_for(&id))
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(on_disk.revoked_at.is_some(), "the revocation stays on disk");
    }

    #[test]
    fn a_ready_active_writes_last_used_at() {
        let _ready = crate::server::mode::ready_for_test();
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let secret = "aspat_used_on_active";
                let token = record(&hash_secret(secret), vec![]);
                let id = token.id.clone();
                let s = store().await;
                s.create(token).await.unwrap();

                s.authenticate(secret)
                    .await
                    .expect("authenticates");

                let on_disk: AccessToken = serde_json::from_slice(
                    &fs::read(s.path_for(&id))
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert!(on_disk.last_used_at.is_some(), "a ready Active records the use");
            });
    }

    #[test]
    fn a_standby_using_a_stale_token_does_not_write_it_back() {
        use crate::server::mode::{self, ServerMode};
        let _guard = mode::MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let secret = "aspat_stale_on_standby";
                let token = record(&hash_secret(secret), vec![]);
                let id = token.id.clone();
                let dir = std::env::temp_dir().join(format!("agent-stream-access-tokens-{}", uuid::Uuid::new_v4()));
                let active = FsAccessTokenStore::new(&dir)
                    .await
                    .unwrap();
                active
                    .create(token)
                    .await
                    .unwrap();
                let standby = FsAccessTokenStore::new(&dir)
                    .await
                    .unwrap();
                active
                    .revoke(&id)
                    .await
                    .unwrap()
                    .expect("token exists");

                mode::set_server_mode(ServerMode::Standby);
                standby
                    .authenticate(secret)
                    .await;
                mode::set_server_mode(ServerMode::Active);
                assert!(mode::mark_activation_ready(mode::current_activation_generation()));

                let on_disk: AccessToken = serde_json::from_slice(
                    &fs::read(standby.path_for(&id))
                        .await
                        .unwrap(),
                )
                .unwrap();
                assert!(on_disk.revoked_at.is_some(), "the revocation stays on disk");
                assert!(on_disk.last_used_at.is_none());
            });
    }

    #[tokio::test]
    async fn an_unreadable_token_record_is_skipped_and_counted() {
        let parse_failures = || {
            crate::metrics::backends::prometheus::STORAGE_LOAD_ERRORS
                .with_label_values(&[STORAGE_ENTITY, "parse_failed"])
                .get()
        };
        let dir = std::env::temp_dir().join(format!("agent-stream-access-tokens-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir)
            .await
            .unwrap();
        fs::write(dir.join("asat_corrupt.json"), [0xff, 0xfe])
            .await
            .unwrap();
        let before = parse_failures();

        let store = FsAccessTokenStore::new(&dir)
            .await
            .unwrap();

        assert!(store.list().is_empty());
        assert!(parse_failures() > before);
    }

    #[tokio::test]
    async fn promotion_reload_picks_up_created_rotated_and_deleted_tokens() {
        use crate::server::mode::ReloadOnPromotion;
        let (active, standby) = active_and_standby().await;
        let rotated = record(&hash_secret("aspat_before_rotation"), vec![]);
        let rotated_id = rotated.id.clone();
        let deleted = record(&hash_secret("aspat_deleted"), vec![]);
        let deleted_id = deleted.id.clone();
        active
            .create(rotated)
            .await
            .unwrap();
        active
            .create(deleted)
            .await
            .unwrap();
        standby
            .reload_from_storage()
            .await
            .unwrap();
        let created_secret = "aspat_created_elsewhere";
        active
            .create(record(&hash_secret(created_secret), vec!["secrets.view".into()]))
            .await
            .unwrap();
        let (_, new_secret) = active
            .rotate(&rotated_id, "user-1", 0)
            .await
            .unwrap()
            .expect("token rotates");
        fs::remove_file(active.path_for(&deleted_id))
            .await
            .unwrap();

        standby
            .reload_from_storage()
            .await
            .unwrap();

        let created = standby
            .authenticate(created_secret)
            .await
            .expect("token created on the previous Active authenticates");
        assert_eq!(created.scopes, Some(vec!["secrets.view".to_string()]));
        assert!(
            standby
                .authenticate("aspat_before_rotation")
                .await
                .is_none()
        );
        assert!(
            standby
                .authenticate(&new_secret)
                .await
                .is_some()
        );
        assert!(
            standby
                .authenticate("aspat_deleted")
                .await
                .is_none()
        );
        assert!(
            standby
                .get(&deleted_id)
                .is_none()
        );
        assert_eq!(standby.list().len(), 2);
    }

    #[tokio::test]
    async fn promotion_reload_that_cannot_list_the_directory_keeps_the_cache() {
        use crate::server::mode::ReloadOnPromotion;
        let (active, standby) = active_and_standby().await;
        let secret = "aspat_kept";
        active
            .create(record(&hash_secret(secret), vec![]))
            .await
            .unwrap();
        standby
            .reload_from_storage()
            .await
            .unwrap();
        fs::remove_dir_all(&active.dir)
            .await
            .unwrap();

        assert!(
            standby
                .reload_from_storage()
                .await
                .is_err()
        );

        assert!(
            standby
                .authenticate(secret)
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn authenticate_carries_compiled_resource_scope() {
        let s = store().await;
        let secret = "aspat_scoped";
        let mut rec = record(&hash_secret(secret), vec![]);
        rec.resource_pattern = Some("TENANT:${acct}:pipes:.*".into());
        rec.required_headers = vec![RequiredHeader {
            name: "acct".into(),
            pattern: "tenant-a".into(),
        }];
        s.create(rec).await.unwrap();
        let principal = s
            .authenticate(secret)
            .await
            .expect("valid token");
        assert!(
            principal
                .resource_scope
                .is_some(),
            "a token with a pattern must carry a compiled scope"
        );
    }

    #[tokio::test]
    async fn authenticate_fails_closed_on_uncompilable_scope() {
        let s = store().await;
        let secret = "aspat_broken";
        let mut rec = record(&hash_secret(secret), vec![]);
        // An unbalanced group cannot compile — the token must be unusable rather
        // than silently unscoped.
        rec.resource_pattern = Some("TENANT:(:.*".into());
        s.create(rec).await.unwrap();
        assert!(
            s.authenticate(secret)
                .await
                .is_none(),
            "an uncompilable stored scope must fail closed"
        );
    }

    /// Regression test for the compiled-scope cache race: after `update()`
    /// narrows a token's pattern, the very next `authenticate()` must enforce
    /// the *new* pattern — never a stale compiled scope left over from before
    /// the update (the (id, fingerprint) cache key makes this true by
    /// construction, since a stale entry can never match the new fields).
    #[tokio::test]
    async fn authenticate_reflects_pattern_immediately_after_update() {
        let s = store().await;
        let secret = "aspat_narrowed";
        let mut rec = record(&hash_secret(secret), vec![]);
        rec.resource_pattern = Some("TENANT:${acct}:pipes:.*".into());
        rec.required_headers = vec![RequiredHeader {
            name: "acct".into(),
            pattern: "tenant-a".into(),
        }];
        s.create(rec).await.unwrap();
        let id = s.list()[0].id.clone();

        // Warm the cache under the original (wide) pattern.
        let before = s
            .authenticate(secret)
            .await
            .expect("valid token");
        let before_scope = before
            .resource_scope
            .expect("pattern present");
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("acct", "tenant-a".parse().unwrap());
        let before = before_scope
            .evaluate(&headers)
            .unwrap();
        assert!(
            before
                .pattern
                .unwrap()
                .is_match("TENANT:tenant-a:pipes:anything")
        );
        assert_eq!(before.tenant_id.as_deref(), Some("tenant-a"));

        // Narrow the pattern.
        s.update(
            &id,
            "narrowed".into(),
            String::new(),
            vec![],
            Some("TENANT:${acct}:pipes:only-this".into()),
            vec![RequiredHeader {
                name: "acct".into(),
                pattern: "tenant-a".into(),
            }],
        )
        .await
        .unwrap();

        let after = s
            .authenticate(secret)
            .await
            .expect("still valid");
        let after_scope = after
            .resource_scope
            .expect("pattern present");
        let re = after_scope
            .evaluate(&headers)
            .unwrap()
            .pattern
            .unwrap();
        assert!(re.is_match("TENANT:tenant-a:pipes:only-this"), "must enforce the new, narrowed pattern");
        assert!(!re.is_match("TENANT:tenant-a:pipes:anything"), "must not enforce the stale, wider pattern");
    }
}
