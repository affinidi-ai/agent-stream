//! Single-document storage for the editable LLM provider catalog.
//!
//! The catalog is one JSON file (`llm.json`) shaped as
//! `{ "providers": [ { ... }, ... ] }`. Each provider is stored verbatim as a
//! `serde_json::Value` so the full nested structure (endpoints, models,
//! parameters, rate limiting, capabilities) round-trips without loss. Providers
//! are keyed by their machine-readable `enum_value`.

use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock, RwLock};
use std::time::SystemTime;

use serde_json::Value;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::pipes::request_shaping::{self, ModelRequestProfile};

/// Default contents written into the editor when no custom catalog file exists.
const DEFAULT_CUSTOM_TEMPLATE: &str = "{\n  \"providers\": []\n}\n";

/// JSON Schema (draft-07) describing an LLM provider catalog. Embedded so the
/// appliance validates both user custom input and any refreshed built-in
/// catalog against the same contract shipped in the repo, without a runtime
/// file dependency.
const CATALOG_SCHEMA: &str = include_str!("../../config/schemas/llm_catalog.schema.json");

/// Lazily compiled validator for {@link CATALOG_SCHEMA}. Returns `None` when the
/// embedded schema cannot be compiled (never expected in a shipped build) so
/// callers fall back to a structural check rather than failing.
fn catalog_schema_validator() -> Option<&'static jsonschema::Validator> {
    static VALIDATOR: OnceLock<Option<jsonschema::Validator>> = OnceLock::new();
    VALIDATOR
        .get_or_init(|| match serde_json::from_str::<Value>(CATALOG_SCHEMA) {
            Ok(schema) => match jsonschema::Validator::options().build(&schema) {
                Ok(v) => Some(v),
                Err(e) => {
                    warn!(error = %e, "failed to compile LLM catalog schema");
                    None
                }
            },
            Err(e) => {
                warn!(error = %e, "embedded LLM catalog schema is not valid JSON");
                None
            }
        })
        .as_ref()
}

/// Errors returned by catalog mutations, mapped to HTTP status codes by the handlers.
#[derive(Debug)]
pub enum CatalogError {
    /// A provider with the same `enum_value` already exists.
    Duplicate(String),
    /// The provider document failed validation.
    Validation(String),
    /// No provider matched the requested `enum_value`.
    NotFound(String),
    /// Reading or writing the catalog file failed.
    Io(String),
}

impl std::fmt::Display for CatalogError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            CatalogError::Duplicate(v) => write!(f, "provider '{}' already exists", v),
            CatalogError::Validation(m) => write!(f, "{}", m),
            CatalogError::NotFound(v) => write!(f, "provider '{}' not found", v),
            CatalogError::Io(m) => write!(f, "{}", m),
        }
    }
}

/// File-backed store for the LLM provider catalog.
///
/// Reads are served fresh from disk so manual edits and `POST /v1/config/reload`
/// take effect without restart. Writes are serialized through a mutex to avoid
/// lost updates from concurrent admin requests.
/// Cached merged providers keyed by the built-in file mtime and the optional
/// custom file mtime (absent when `custom_llm.json` does not exist).
type MergedCache = Option<(SystemTime, Option<SystemTime>, Arc<Vec<Value>>)>;

pub struct LlmProviderCatalog {
    path: PathBuf,
    /// Sibling `custom_llm.json` holding user-defined providers merged over the
    /// built-in catalog at read time. Never seeded; a missing file means "no
    /// custom providers".
    custom_path: PathBuf,
    write_lock: Mutex<()>,
    /// Held by a built-in refresh and a rollback for their whole run, so they
    /// change the catalog and its refresh record one at a time.
    refresh_lock: Mutex<()>,
    /// Hot-path cache of the **merged** providers array (built-in + valid
    /// custom), keyed by both files' mtimes so that manual edits, reloads, and
    /// admin writes to either file invalidate it automatically.
    cache: RwLock<MergedCache>,
}

impl LlmProviderCatalog {
    /// Create the catalog store, seeding the storage file from `seed_path` when
    /// the storage copy is absent. An existing storage copy is never overwritten.
    pub fn new(
        path: PathBuf,
        seed_path: Option<PathBuf>,
    ) -> anyhow::Result<Self> {
        // The custom catalog always sits next to the built-in one in the same
        // storage directory. It is never seeded — absence means "no custom".
        let custom_path = path
            .parent()
            .map(|p| p.join("custom_llm.json"))
            .unwrap_or_else(|| PathBuf::from("custom_llm.json"));
        if !path.exists() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let seeded = match seed_path {
                Some(seed) => match std::fs::read_to_string(&seed) {
                    Ok(contents) => match serde_json::from_str::<Value>(&contents) {
                        Ok(doc) => extract_providers(&doc),
                        Err(e) => {
                            warn!(
                                seed = %seed.display(),
                                error = %e,
                                "LLM catalog seed is not valid JSON — starting with an empty catalog"
                            );
                            Vec::new()
                        }
                    },
                    Err(_) => {
                        warn!(
                            seed = %seed.display(),
                            "LLM catalog seed not found — starting with an empty catalog"
                        );
                        Vec::new()
                    }
                },
                None => Vec::new(),
            };
            let doc = serde_json::json!({ "providers": seeded });
            std::fs::write(&path, serde_json::to_string_pretty(&doc)?)?;
            info!(
                path = %path.display(),
                providers = doc["providers"].as_array().map(|a| a.len()).unwrap_or(0),
                "Seeded LLM provider catalog"
            );
        }

        Ok(Self {
            path,
            custom_path,
            write_lock: Mutex::new(()),
            refresh_lock: Mutex::new(()),
            cache: RwLock::new(None),
        })
    }

    /// Read the providers array fresh from disk.
    pub fn list_providers(&self) -> Result<Vec<Value>, CatalogError> {
        self.read_doc()
    }

    /// Return the **merged** providers array (built-in + valid custom) via the
    /// mtime-gated cache, reading from disk only when either file has changed
    /// since the last read. Returns an empty list when the catalog cannot be
    /// read so callers degrade to built-in defaults. This is the runtime view:
    /// pricing, request-shaping profiles, and model-enabled checks all see
    /// custom providers as if they were part of `llm.json`.
    /// Whether `host` is the `default_base_url` host of a provider whose URL
    /// passed the public-address check at save ([`PUBLIC_BASE_URL_MARKER`]),
    /// so dialling it must still reach only public addresses.
    pub fn requires_public_host(
        &self,
        host: &str,
    ) -> bool {
        self.cached_providers()
            .iter()
            .filter(|provider| is_marked_public(provider))
            .filter_map(|provider| provider_base_url(provider))
            .filter_map(|url| url::Url::parse(url).ok())
            .any(|url| {
                url.host_str()
                    .is_some_and(|marked| marked.eq_ignore_ascii_case(host))
            })
    }

    pub fn cached_providers(&self) -> Arc<Vec<Value>> {
        let builtin_mtime = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .ok();
        let custom_mtime = std::fs::metadata(&self.custom_path)
            .and_then(|m| m.modified())
            .ok();

        if let Some(bmt) = builtin_mtime
            && let Ok(guard) = self.cache.read()
            && let Some((cached_b, cached_c, providers)) = guard.as_ref()
            && *cached_b == bmt
            && *cached_c == custom_mtime
        {
            return Arc::clone(providers);
        }

        let builtin = match self.read_doc() {
            Ok(builtin) => builtin,
            Err(e) => {
                if let Ok(guard) = self.cache.read()
                    && let Some((_, _, providers)) = guard.as_ref()
                {
                    tracing::debug!(error = %e, "LLM catalog cannot be read; serving the last catalog read");
                    return Arc::clone(providers);
                }
                Vec::new()
            }
        };
        let providers = Arc::new(self.merge_custom(builtin));
        if let Some(bmt) = builtin_mtime
            && let Ok(mut guard) = self.cache.write()
        {
            *guard = Some((bmt, custom_mtime, Arc::clone(&providers)));
        }
        providers
    }

    /// Built-in providers (`llm.json`) followed by every valid custom provider.
    /// Invalid custom providers (missing identity, colliding with a built-in
    /// `enum_value`, or duplicated) are silently dropped so a bad custom file
    /// can never break the runtime catalog.
    fn merge_custom(
        &self,
        mut builtin: Vec<Value>,
    ) -> Vec<Value> {
        let builtin_enums: HashSet<String> = builtin
            .iter()
            .filter_map(|p| provider_enum_value(p).map(|e| e.to_ascii_lowercase()))
            .collect();
        builtin.extend(self.valid_custom_providers(&builtin_enums));
        builtin
    }

    /// Parse the custom catalog file, returning its providers array or an empty
    /// list on any error (absent file, invalid JSON). Never fails.
    fn read_custom_doc(&self) -> Vec<Value> {
        let Ok(contents) = std::fs::read_to_string(&self.custom_path) else {
            return Vec::new();
        };
        match serde_json::from_str::<Value>(&contents) {
            Ok(doc) => extract_providers(&doc),
            Err(e) => {
                warn!(
                    path = %self.custom_path.display(),
                    error = %e,
                    "custom LLM catalog is not valid JSON — ignoring custom providers"
                );
                Vec::new()
            }
        }
    }

    /// Filter the custom providers down to the ones safe to merge: each must
    /// carry a valid identity, must not reuse a built-in `enum_value`, and must
    /// be unique within the custom set (first occurrence wins).
    fn valid_custom_providers(
        &self,
        builtin_enums: &HashSet<String>,
    ) -> Vec<Value> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for provider in self.read_custom_doc() {
            let Ok(enum_value) = validate_provider(&provider) else {
                continue;
            };
            let lowered = enum_value.to_ascii_lowercase();
            if builtin_enums.contains(&lowered) || !seen.insert(lowered) {
                continue;
            }
            out.push(provider);
        }
        out
    }

    /// Raw text of the custom catalog file for the JSON editor, or a starter
    /// template when the file does not exist yet.
    pub fn read_custom_raw(&self) -> String {
        std::fs::read_to_string(&self.custom_path).unwrap_or_else(|_| DEFAULT_CUSTOM_TEMPLATE.to_string())
    }

    /// The valid custom providers as they currently merge at runtime, for the
    /// dashboard **Custom** tab. Colliding/invalid entries are excluded (the
    /// same view the runtime uses), so what the tab shows is what actually
    /// merges.
    pub fn custom_providers(&self) -> Vec<Value> {
        let builtin_enums: HashSet<String> = self
            .read_doc()
            .unwrap_or_default()
            .iter()
            .filter_map(|p| provider_enum_value(p).map(|e| e.to_ascii_lowercase()))
            .collect();
        self.valid_custom_providers(&builtin_enums)
    }

    /// Validate and persist the custom catalog document. Validation is
    /// authoritative (the frontend mirrors it for inline feedback): the document
    /// must satisfy the embedded JSON schema, every provider must carry a valid
    /// identity, no custom `enum_value` may reuse a built-in provider id, no
    /// custom `enum_value` may be duplicated, and a new or changed
    /// `default_base_url` must resolve to a public address. On success returns
    /// the stored providers array.
    pub async fn save_custom(
        &self,
        doc: Value,
    ) -> Result<Vec<Value>, CatalogError> {
        validate_against_schema(&doc)?;
        let mut providers = extract_providers(&doc);
        let builtin_enums: HashSet<String> = self
            .read_doc()?
            .iter()
            .filter_map(|p| provider_enum_value(p).map(|e| e.to_ascii_lowercase()))
            .collect();
        let mut seen = HashSet::new();
        for provider in &providers {
            let enum_value = validate_provider(provider)?;
            let lowered = enum_value.to_ascii_lowercase();
            if builtin_enums.contains(&lowered) {
                return Err(CatalogError::Validation(format!(
                    "custom provider '{}' reuses a built-in provider id — choose a unique enum_value",
                    enum_value
                )));
            }
            if !seen.insert(lowered) {
                return Err(CatalogError::Validation(format!(
                    "custom provider '{}' is defined more than once",
                    enum_value
                )));
            }
        }
        let stored = self.custom_providers();
        for provider in &mut providers {
            let stored_provider = stored
                .iter()
                .find(|s| provider_enum_value(s) == provider_enum_value(provider));
            check_base_url(provider, stored_provider).await?;
        }
        let _guard = self.write_lock.lock().await;
        self.write_custom_doc(&providers)?;
        Ok(providers)
    }

    fn write_custom_doc(
        &self,
        providers: &[Value],
    ) -> Result<(), CatalogError> {
        if let Some(parent) = self.custom_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| CatalogError::Io(format!("failed to create custom catalog dir: {}", e)))?;
        }
        let doc = serde_json::json!({ "providers": providers });
        let serialized = serde_json::to_string_pretty(&doc)
            .map_err(|e| CatalogError::Io(format!("failed to serialize custom LLM catalog: {}", e)))?;
        std::fs::write(&self.custom_path, serialized).map_err(|e| {
            CatalogError::Io(format!("failed to write custom LLM catalog {}: {}", self.custom_path.display(), e))
        })?;
        if let Ok(mut guard) = self.cache.write() {
            *guard = None;
        }
        Ok(())
    }

    /// Path the previous built-in `llm.json` is moved aside to during a refresh
    /// (`llm.json.bak`), providing a one-step recovery point.
    fn backup_path(&self) -> PathBuf {
        self.path
            .parent()
            .map(|p| p.join("llm.json.bak"))
            .unwrap_or_else(|| PathBuf::from("llm.json.bak"))
    }

    /// Path of the accepted refresh publication (`llm_catalog_refresh.json`),
    /// kept next to `llm.json`. A rollback leaves it in place, so a restored
    /// catalog never lowers the publication sequence the next refresh accepts.
    pub(crate) fn refresh_state_path(&self) -> PathBuf {
        self.path
            .parent()
            .map(|p| p.join("llm_catalog_refresh.json"))
            .unwrap_or_else(|| PathBuf::from("llm_catalog_refresh.json"))
    }

    /// Whether `llm.json.bak` exists, which means a refresh replaced the
    /// built-in catalog and no rollback restored it since.
    pub(crate) fn has_backup(&self) -> bool {
        self.backup_path().exists()
    }

    /// The built-in `llm.json` as it is on disk now, or `None` when it cannot
    /// be read.
    pub(crate) fn read_builtin_bytes(&self) -> Option<Vec<u8>> {
        std::fs::read(&self.path).ok()
    }

    /// Lock a built-in refresh or rollback holds for its whole run.
    pub(crate) fn refresh_lock(&self) -> &Mutex<()> {
        &self.refresh_lock
    }

    /// Drop the mtime-gated merged-providers cache so the next read reflects the
    /// on-disk state.
    fn invalidate_cache(&self) {
        if let Ok(mut guard) = self.cache.write() {
            *guard = None;
        }
    }

    /// Merge a **validated** refreshed catalog into the built-in `llm.json`,
    /// keeping the previous file as `llm.json.bak` for recovery.
    ///
    /// A provider already stored takes only [`REFRESHED_PROVIDER_FIELDS`] from
    /// the download and keeps everything else, so the file cannot change where
    /// a provider's key is sent or how it is sent. A provider only in the
    /// download is added disabled, after its `default_base_url` passes the
    /// public-address check, with the provider and each of its models
    /// disabled. A provider only in the download whose id matches a custom
    /// provider is skipped, so the download never takes over that id. A
    /// provider only in storage is kept.
    ///
    /// The download and the merged result are validated (schema + non-empty +
    /// unique ids, compared case-insensitively + a `models` array on every
    /// downloaded provider + relative endpoint paths) **before** anything on
    /// disk is touched, so `llm.json` holding two providers whose ids differ
    /// only in case refuses the refresh. The previous file is copied to `llm.json.bak`, and the merged
    /// catalog replaces `llm.json` through a temporary file renamed into
    /// place, so readers and a crash see the old catalog or the new one.
    /// Base URLs of added providers are checked before the write lock is
    /// taken, so their DNS lookups never hold up other catalog writes.
    pub async fn refresh_builtin(
        &self,
        doc: Value,
    ) -> Result<BuiltinRefresh, CatalogError> {
        validate_catalog_document(&doc)?;
        validate_models_present(&doc)?;
        validate_endpoint_paths(&doc)?;
        let checked = self
            .check_added_providers(&doc)
            .await?;

        let _guard = self.write_lock.lock().await;
        let mut providers = self.read_doc()?;
        let builtin_enums = lowered_enum_values(&providers);
        let custom_enums = lowered_enum_values(&self.valid_custom_providers(&builtin_enums));
        let mut added = 0;
        for downloaded in extract_providers(&doc) {
            let id = provider_enum_value(&downloaded).map(str::to_ascii_lowercase);
            match providers
                .iter_mut()
                .find(|stored| provider_enum_value(stored).map(str::to_ascii_lowercase) == id)
            {
                Some(stored) => *stored = merge_refreshed_provider(stored, &downloaded),
                None if id
                    .as_ref()
                    .is_some_and(|id| custom_enums.contains(id)) =>
                {
                    warn!(
                        provider = provider_enum_value(&downloaded).unwrap_or_default(),
                        "Skipped a provider in the refreshed LLM catalog whose id matches a custom provider"
                    );
                }
                None => {
                    let provider = id
                        .and_then(|id| checked.get(&id))
                        .cloned()
                        .ok_or_else(|| {
                            CatalogError::Io(
                                "the built-in LLM catalog changed during the refresh; try again".to_string(),
                            )
                        })?;
                    providers.push(provider);
                    added += 1;
                }
            }
        }
        let merged = serde_json::json!({ "providers": &providers });
        validate_catalog_document(&merged)?;
        let serialized = serde_json::to_vec_pretty(&merged)
            .map_err(|e| CatalogError::Io(format!("failed to serialize refreshed catalog: {}", e)))?;

        let backup = self.backup_path();
        let current = std::fs::read(&self.path)
            .map_err(|e| CatalogError::Io(format!("failed to read LLM catalog {}: {}", self.path.display(), e)))?;
        write_file_atomically(&backup, &current).map_err(|e| {
            CatalogError::Io(format!("failed to back up existing catalog to {}: {}", backup.display(), e))
        })?;
        write_file_atomically(&self.path, &serialized).map_err(|e| {
            CatalogError::Io(format!("failed to write refreshed catalog {}: {}", self.path.display(), e))
        })?;

        self.invalidate_cache();
        info!(
            path = %self.path.display(),
            providers = providers.len(),
            added,
            "Refreshed built-in LLM catalog (previous kept as llm.json.bak)"
        );
        Ok(BuiltinRefresh {
            providers: providers.len(),
            added,
        })
    }

    /// Check the `default_base_url` of every provider the download adds (not
    /// stored, not matching a custom provider) and disable it. Returns the
    /// checked providers keyed by lowercased `enum_value`.
    async fn check_added_providers(
        &self,
        doc: &Value,
    ) -> Result<HashMap<String, Value>, CatalogError> {
        let builtin_enums = lowered_enum_values(&self.read_doc()?);
        let custom_enums = lowered_enum_values(&self.valid_custom_providers(&builtin_enums));
        let mut checked = HashMap::new();
        for mut provider in extract_providers(doc) {
            let Some(id) = provider_enum_value(&provider).map(str::to_ascii_lowercase) else {
                continue;
            };
            if builtin_enums.contains(&id) || custom_enums.contains(&id) {
                continue;
            }
            check_base_url(&mut provider, None).await?;
            disable_added_provider(&mut provider);
            checked.insert(id, provider);
        }
        Ok(checked)
    }

    /// Restore the previous built-in catalog from `llm.json.bak` by renaming
    /// the backup over `llm.json`. This is the recovery path if a refreshed
    /// catalog turns out to be problematic. Returns the restored provider
    /// count.
    pub async fn rollback_builtin(&self) -> Result<usize, CatalogError> {
        let _guard = self.write_lock.lock().await;
        let backup = self.backup_path();
        if !backup.exists() {
            return Err(CatalogError::NotFound("no llm.json.bak backup is available to restore".to_string()));
        }
        std::fs::rename(&backup, &self.path)
            .map_err(|e| CatalogError::Io(format!("failed to restore catalog from {}: {}", backup.display(), e)))?;
        self.invalidate_cache();
        let count = self
            .read_doc()
            .map(|p| p.len())
            .unwrap_or(0);
        info!(path = %self.path.display(), providers = count, "Rolled back built-in LLM catalog from llm.json.bak");
        Ok(count)
    }

    /// Resolve the request-shaping profile for a model from the catalog,
    /// falling back to the supplied schema/JSON-mode hints when no entry exists.
    pub fn resolve_model_profile(
        &self,
        provider_enum: &str,
        model: &str,
        fallback_api_schema: &str,
        fallback_supports_json_mode: Option<bool>,
    ) -> ModelRequestProfile {
        let providers = self.cached_providers();
        request_shaping::resolve_profile_from_providers(
            &providers,
            provider_enum,
            model,
            fallback_api_schema,
            fallback_supports_json_mode,
        )
    }

    /// Resolve token pricing for a model from the catalog, honoring an optional
    /// per-endpoint override, then the model's `pricing` block, then the
    /// built-in pricing table. Returns `None` when no rate is known (callers
    /// then treat the computed cost as `0.0`).
    pub fn resolve_model_pricing(
        &self,
        provider_enum: &str,
        model: &str,
        endpoint_path: Option<&str>,
    ) -> Option<crate::pipes::types::llm::TokenPricing> {
        let providers = self.cached_providers();
        crate::pipes::types::llm::resolve_pricing_from_providers(&providers, provider_enum, model, endpoint_path)
    }

    /// Report whether a catalog model is enabled.
    ///
    /// Returns `Some(true)` when the model exists and is enabled, `Some(false)`
    /// when it exists but is explicitly disabled (`"enabled": false`), and
    /// `None` when the provider or model is not present in the catalog. Callers
    /// treat `None` as "not governed by the catalog" so unlisted custom or
    /// moderation models stay usable. Provider matching is case-insensitive.
    pub fn model_enabled(
        &self,
        provider_enum: &str,
        model: &str,
    ) -> Option<bool> {
        let providers = self.cached_providers();
        providers
            .iter()
            .find_map(|provider| {
                if !provider_enum_value(provider).is_some_and(|e| e.eq_ignore_ascii_case(provider_enum)) {
                    return None;
                }
                provider
                    .get("models")
                    .and_then(Value::as_array)?
                    .iter()
                    .find(|m| {
                        m.get("value")
                            .and_then(Value::as_str)
                            == Some(model)
                    })
                    .map(model_is_enabled)
            })
    }

    /// Read a single provider by `enum_value` from the **merged** catalog
    /// (built-in ∪ valid custom), so the read-only detail page works for both
    /// tabs. Writes remain built-in-only via `update_provider`/`delete_provider`
    /// (custom providers are edited through the whole-array `save_custom` PUT).
    pub fn get_provider(
        &self,
        enum_value: &str,
    ) -> Result<Option<Value>, CatalogError> {
        let providers = self.read_doc()?;
        if let Some(found) = providers
            .into_iter()
            .find(|p| provider_enum_value(p) == Some(enum_value))
        {
            return Ok(Some(found));
        }
        Ok(self
            .custom_providers()
            .into_iter()
            .find(|p| provider_enum_value(p) == Some(enum_value)))
    }

    /// Append a new provider. Fails if a provider with the same `enum_value`,
    /// compared case-insensitively, exists.
    pub async fn create_provider(
        &self,
        mut provider: Value,
    ) -> Result<Value, CatalogError> {
        let enum_value = validate_provider_document(&provider)?;
        check_base_url(&mut provider, None).await?;
        let _guard = self.write_lock.lock().await;
        let mut providers = self.read_doc()?;
        if lowered_enum_values(&providers).contains(&enum_value.to_ascii_lowercase()) {
            return Err(CatalogError::Duplicate(enum_value));
        }
        providers.push(provider.clone());
        self.write_doc(&providers)?;
        Ok(provider)
    }

    /// Replace an existing provider identified by `enum_value`. The body's
    /// `enum_value` must match the path key (rename is not supported in place).
    pub async fn update_provider(
        &self,
        enum_value: &str,
        mut provider: Value,
    ) -> Result<Value, CatalogError> {
        let body_enum = validate_provider_document(&provider)?;
        if body_enum != enum_value {
            return Err(CatalogError::Validation(format!(
                "enum_value '{}' in body does not match '{}' in path",
                body_enum, enum_value
            )));
        }
        let stored = self
            .read_doc()?
            .into_iter()
            .find(|p| provider_enum_value(p) == Some(enum_value));
        check_base_url(&mut provider, stored.as_ref()).await?;
        let _guard = self.write_lock.lock().await;
        let mut providers = self.read_doc()?;
        match providers
            .iter()
            .position(|p| provider_enum_value(p) == Some(enum_value))
        {
            Some(idx) => {
                providers[idx] = provider.clone();
                self.write_doc(&providers)?;
                Ok(provider)
            }
            None => Err(CatalogError::NotFound(enum_value.to_string())),
        }
    }

    /// Remove a provider by `enum_value`. Returns `true` when one was removed.
    pub async fn delete_provider(
        &self,
        enum_value: &str,
    ) -> Result<bool, CatalogError> {
        let _guard = self.write_lock.lock().await;
        let mut providers = self.read_doc()?;
        let before = providers.len();
        providers.retain(|p| provider_enum_value(p) != Some(enum_value));
        if providers.len() == before {
            return Ok(false);
        }
        self.write_doc(&providers)?;
        Ok(true)
    }

    fn read_doc(&self) -> Result<Vec<Value>, CatalogError> {
        let contents = std::fs::read_to_string(&self.path)
            .map_err(|e| CatalogError::Io(format!("failed to read LLM catalog {}: {}", self.path.display(), e)))?;
        let doc: Value = serde_json::from_str(&contents)
            .map_err(|e| CatalogError::Io(format!("failed to parse LLM catalog {}: {}", self.path.display(), e)))?;
        Ok(extract_providers(&doc))
    }

    fn write_doc(
        &self,
        providers: &[Value],
    ) -> Result<(), CatalogError> {
        let doc = serde_json::json!({ "providers": providers });
        let serialized = serde_json::to_vec_pretty(&doc)
            .map_err(|e| CatalogError::Io(format!("failed to serialize LLM catalog: {}", e)))?;
        write_file_atomically(&self.path, &serialized)
            .map_err(|e| CatalogError::Io(format!("failed to write LLM catalog {}: {}", self.path.display(), e)))?;
        if let Ok(mut guard) = self.cache.write() {
            *guard = None;
        }
        Ok(())
    }
}

/// Result of a built-in catalog refresh.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BuiltinRefresh {
    /// Built-in providers after the merge.
    pub providers: usize,
    /// Providers the download added, all disabled.
    pub added: usize,
}

/// The only provider fields a refresh takes from the download for a provider
/// already stored. Identity, connection and key settings (`enum_value`,
/// `name`, `default_base_url`, `api_version_prefix`, `api_schema`, the
/// `api_key_*` fields, `requires_forward_caller_token`) stay as stored.
const REFRESHED_PROVIDER_FIELDS: [&str; 4] = ["models", "endpoints", "endpoint_parameters", "description"];

/// The stored provider with [`REFRESHED_PROVIDER_FIELDS`] replaced by the
/// download's values; a field the download omits is removed. Model `enabled`
/// switches follow [`carry_model_switches`].
fn merge_refreshed_provider(
    stored: &Value,
    downloaded: &Value,
) -> Value {
    let mut merged = stored.clone();
    if let Some(fields) = merged.as_object_mut() {
        for key in REFRESHED_PROVIDER_FIELDS {
            match downloaded.get(key) {
                Some(value) => {
                    fields.insert(key.to_string(), value.clone());
                }
                None => {
                    fields.remove(key);
                }
            }
        }
        if let Some(models) = fields.get_mut("models") {
            carry_model_switches(stored, models);
        }
    }
    merged
}

/// Give each downloaded model the `enabled` switch of the stored model with the
/// same `value`, and disable a model new to a provider stored with
/// `"enabled": false`. A refresh therefore never turns on a model an
/// administrator, or the refresh that added the provider, turned off.
fn carry_model_switches(
    stored: &Value,
    models: &mut Value,
) {
    let provider_enabled = stored
        .get("enabled")
        .and_then(Value::as_bool)
        != Some(false);
    let stored_models = stored
        .get("models")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    let Some(models) = models.as_array_mut() else {
        return;
    };
    for model in models
        .iter_mut()
        .filter_map(Value::as_object_mut)
    {
        let value = model
            .get("value")
            .and_then(Value::as_str)
            .map(str::to_string);
        let stored_model = value
            .as_deref()
            .and_then(|value| {
                stored_models
                    .iter()
                    .find(|stored| {
                        stored
                            .get("value")
                            .and_then(Value::as_str)
                            == Some(value)
                    })
            });
        match stored_model.map(|stored| stored.get("enabled")) {
            Some(Some(enabled)) => {
                model.insert("enabled".to_string(), enabled.clone());
            }
            Some(None) => {
                model.remove("enabled");
            }
            None if !provider_enabled => {
                model.insert("enabled".to_string(), Value::Bool(false));
            }
            None => {}
        }
    }
}

/// Mark a provider the download added as disabled, together with each of its
/// models, so none of them is offered or callable until an admin enables it.
fn disable_added_provider(provider: &mut Value) {
    let Some(fields) = provider.as_object_mut() else {
        return;
    };
    fields.insert("enabled".to_string(), Value::Bool(false));
    if let Some(models) = fields
        .get_mut("models")
        .and_then(Value::as_array_mut)
    {
        for model in models
            .iter_mut()
            .filter_map(Value::as_object_mut)
        {
            model.insert("enabled".to_string(), Value::Bool(false));
        }
    }
}

/// Refuse a downloaded provider without a `models` array. A refreshed field
/// the download omits is removed, so such an entry would strip every model and
/// price from the stored provider.
fn validate_models_present(doc: &Value) -> Result<(), CatalogError> {
    match extract_providers(doc)
        .iter()
        .find(|provider| {
            !provider
                .get("models")
                .is_some_and(Value::is_array)
        }) {
        Some(provider) => Err(CatalogError::Validation(format!(
            "provider '{}' in the refreshed catalog has no models array",
            provider_enum_value(provider).unwrap_or_default()
        ))),
        None => Ok(()),
    }
}

/// Refuse a downloaded endpoint `path` that does not start with exactly one
/// `/`. Anything else is used as a full URL, so the download could choose the
/// host that receives a provider's key.
fn validate_endpoint_paths(doc: &Value) -> Result<(), CatalogError> {
    for provider in extract_providers(doc) {
        let endpoints = provider
            .get("endpoints")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or_default();
        for path in endpoints
            .iter()
            .filter_map(|endpoint| endpoint.get("path"))
        {
            let relative = path
                .as_str()
                .is_some_and(|p| p.starts_with('/') && !p.starts_with("//") && !p.starts_with("/\\"));
            if !relative {
                return Err(CatalogError::Validation(format!(
                    "endpoint path of '{}' must be a path starting with a single '/'",
                    provider_enum_value(&provider).unwrap_or_default()
                )));
            }
        }
    }
    Ok(())
}

/// Extract the providers array from either a bare `{ "providers": [...] }`
/// catalog or a legacy `{ "llm": { "providers": [...] } }` document.
fn extract_providers(doc: &Value) -> Vec<Value> {
    doc.get("providers")
        .or_else(|| {
            doc.get("llm")
                .and_then(|llm| llm.get("providers"))
        })
        .and_then(|p| p.as_array())
        .cloned()
        .unwrap_or_default()
}

/// Read the `enum_value` identity field of a provider document.
fn provider_enum_value(provider: &Value) -> Option<&str> {
    provider
        .get("enum_value")
        .and_then(|v| v.as_str())
}

/// The lowercased `enum_value` of every provider that has one.
fn lowered_enum_values(providers: &[Value]) -> HashSet<String> {
    providers
        .iter()
        .filter_map(|p| provider_enum_value(p).map(str::to_ascii_lowercase))
        .collect()
}

/// Replace `path` with `contents` through `<path>.tmp`, flushed to disk before
/// the rename, so a reader or a crash sees the old file or the new one, never
/// a partial one. The temporary file is removed on failure.
pub(crate) fn write_file_atomically(
    path: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    let mut name = path
        .file_name()
        .map(std::ffi::OsStr::to_os_string)
        .unwrap_or_default();
    name.push(".tmp");
    let temporary = path.with_file_name(name);
    let written = std::fs::File::create(&temporary)
        .and_then(|mut file| {
            file.write_all(contents)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written?;
    if let Some(parent) = path.parent()
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
    Ok(())
}

/// Whether a model document is enabled. A missing or non-boolean `enabled`
/// field counts as enabled, so a model opts out only with `"enabled": false`.
pub fn model_is_enabled(model: &Value) -> bool {
    model
        .get("enabled")
        .and_then(Value::as_bool)
        != Some(false)
}

/// Drop every disabled model from each provider's `models` array in place, so
/// disabled models are never offered to the dashboard for selection.
pub fn retain_enabled_models(providers: &mut [Value]) {
    for provider in providers.iter_mut() {
        if let Some(models) = provider
            .get_mut("models")
            .and_then(Value::as_array_mut)
        {
            models.retain(model_is_enabled);
        }
    }
}

/// Validate a catalog document against the embedded JSON schema.
///
/// When the schema compiled, every violation is collected into a single
/// human-readable message for the editor / refresh flow. When the schema is
/// unavailable (should never happen in a shipped build) a minimal structural
/// check stands in so a malformed document is still rejected.
fn validate_against_schema(doc: &Value) -> Result<(), CatalogError> {
    let Some(validator) = catalog_schema_validator() else {
        let has_providers = doc
            .get("providers")
            .map(Value::is_array)
            .unwrap_or(false);
        if !has_providers {
            return Err(CatalogError::Validation(
                "configuration must be a JSON object with a 'providers' array".to_string(),
            ));
        }
        return Ok(());
    };
    let errors: Vec<String> = validator
        .iter_errors(doc)
        .map(|e| e.to_string())
        .collect();
    if !errors.is_empty() {
        return Err(CatalogError::Validation(format!("schema validation failed: {}", errors.join("; "))));
    }
    Ok(())
}

/// Validate a full catalog document for a built-in refresh: schema-valid, at
/// least one provider, every provider carries a valid identity, and no
/// duplicate `enum_value`.
fn validate_catalog_document(doc: &Value) -> Result<(), CatalogError> {
    validate_against_schema(doc)?;
    let providers = extract_providers(doc);
    if providers.is_empty() {
        return Err(CatalogError::Validation("refreshed catalog contains no providers".to_string()));
    }
    let mut seen = HashSet::new();
    for provider in &providers {
        let enum_value = validate_provider(provider)?;
        if !seen.insert(enum_value.to_ascii_lowercase()) {
            return Err(CatalogError::Validation(format!("provider '{}' is defined more than once", enum_value)));
        }
    }
    Ok(())
}

/// Validate one provider sent on its own: the catalog schema, as the only
/// provider of a catalog document, then its identity and prices.
fn validate_provider_document(provider: &Value) -> Result<String, CatalogError> {
    validate_against_schema(&serde_json::json!({ "providers": [provider] }))?;
    validate_provider(provider)
}

/// Set on a provider whose `default_base_url` passed the public-address check
/// when it was saved. The outbound DNS check then keeps refusing private and
/// link-local addresses for that host at dial time, so a name that resolved
/// publicly at save cannot later be pointed at the internal network.
const PUBLIC_BASE_URL_MARKER: &str = "default_base_url_public";

/// A provider's `default_base_url` is dialled with its provider key attached,
/// so a new or changed one must resolve to a public address. The one already
/// stored for the provider passes, so a built-in local provider (Ollama) or a
/// self-hosted one written to disk keeps working when the provider is edited.
/// The server, never the request body, decides [`PUBLIC_BASE_URL_MARKER`]: set
/// when the check passed, kept from the stored provider for an unchanged URL.
async fn check_base_url(
    provider: &mut Value,
    stored: Option<&Value>,
) -> Result<(), CatalogError> {
    let checked_public = match provider_base_url(provider).map(str::to_string) {
        None => false,
        Some(url) if stored.and_then(provider_base_url) == Some(url.as_str()) => stored.is_some_and(is_marked_public),
        Some(url) => {
            if let Err(reason) = crate::url_validation::validate_resolved_webhook_url(&url).await {
                warn!(
                    url = %crate::url_validation::redact_url_for_logging(&url),
                    reason = %reason,
                    "Refused LLM provider default_base_url"
                );
                return Err(CatalogError::Validation(format!(
                    "default_base_url of '{}' must resolve to a public address; private, loopback, link-local and \
                     cloud metadata targets are refused",
                    provider_enum_value(provider).unwrap_or_default()
                )));
            }
            true
        }
    };
    if let Some(fields) = provider.as_object_mut() {
        if checked_public {
            fields.insert(PUBLIC_BASE_URL_MARKER.to_string(), Value::Bool(true));
        } else {
            fields.remove(PUBLIC_BASE_URL_MARKER);
        }
    }
    Ok(())
}

fn is_marked_public(provider: &Value) -> bool {
    provider
        .get(PUBLIC_BASE_URL_MARKER)
        .and_then(Value::as_bool)
        == Some(true)
}

fn provider_base_url(provider: &Value) -> Option<&str> {
    provider
        .get("default_base_url")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|url| !url.is_empty())
}

/// Validate a provider document, returning its `enum_value` on success.
fn validate_provider(provider: &Value) -> Result<String, CatalogError> {
    if !provider.is_object() {
        return Err(CatalogError::Validation("provider must be a JSON object".to_string()));
    }
    let enum_value = provider_enum_value(provider)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| CatalogError::Validation("enum_value is required".to_string()))?;
    let name_ok = provider
        .get("name")
        .and_then(|v| v.as_str())
        .map(str::trim)
        .is_some_and(|s| !s.is_empty());
    if !name_ok {
        return Err(CatalogError::Validation("name is required".to_string()));
    }
    validate_catalog_prices(provider)?;
    Ok(enum_value.to_string())
}

/// Check every catalog price on a provider: each `cost_per_1k_input` and
/// `cost_per_1k_output` on its models and endpoints must be a number that,
/// per million tokens, passes the same check as a declared price (zero or
/// more, finite, no more than the ceiling).
fn validate_catalog_prices(provider: &Value) -> Result<(), CatalogError> {
    let entries = ["models", "endpoints"]
        .into_iter()
        .filter_map(|key| {
            provider
                .get(key)
                .and_then(Value::as_array)
        })
        .flatten();
    for entry in entries {
        for field in ["cost_per_1k_input", "cost_per_1k_output"] {
            let Some(price) = entry.get(field) else {
                continue;
            };
            let valid = price
                .as_f64()
                .is_some_and(|per_1k| {
                    crate::pipes::types::llm::validate_price_per_million(field, per_1k * 1000.0).is_ok()
                });
            if !valid {
                let entry_name = entry
                    .get("value")
                    .or_else(|| entry.get("path"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                return Err(CatalogError::Validation(format!(
                    "{field} of '{entry_name}' must be a number from 0 to {} USD per 1,000 tokens (got {price})",
                    crate::pipes::types::llm::MAX_PRICE_PER_MILLION_TOKENS / 1000.0
                )));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn temp_path(name: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("llm_catalog_test_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&p);
        p.push("llm.json");
        p
    }

    fn provider(enum_value: &str) -> Value {
        json!({ "enum_value": enum_value, "name": format!("Provider {}", enum_value), "endpoints": [], "models": [] })
    }

    fn provider_with_models(
        enum_value: &str,
        models: Value,
    ) -> Value {
        json!({ "enum_value": enum_value, "name": format!("Provider {}", enum_value), "endpoints": [], "models": models })
    }

    #[test]
    fn model_is_enabled_treats_missing_as_enabled() {
        assert!(model_is_enabled(&json!({ "value": "m" })));
        assert!(model_is_enabled(&json!({ "value": "m", "enabled": true })));
        assert!(!model_is_enabled(&json!({ "value": "m", "enabled": false })));
    }

    #[test]
    fn retain_enabled_models_drops_disabled_only() {
        let mut providers = vec![provider_with_models(
            "openai",
            json!([
                { "value": "keep-default" },
                { "value": "keep-explicit", "enabled": true },
                { "value": "drop", "enabled": false },
            ]),
        )];
        retain_enabled_models(&mut providers);
        let values: Vec<&str> = providers[0]["models"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|m| m["value"].as_str())
            .collect();
        assert_eq!(values, vec!["keep-default", "keep-explicit"]);
    }

    #[test]
    fn model_enabled_reports_catalog_state() {
        let catalog = temp_path("model_enabled");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        std::fs::write(
            &catalog,
            json!({
                "providers": [provider_with_models(
                    "anthropic",
                    json!([
                        { "value": "on-default" },
                        { "value": "on-explicit", "enabled": true },
                        { "value": "off", "enabled": false },
                    ]),
                )]
            })
            .to_string(),
        )
        .unwrap();
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        assert_eq!(store.model_enabled("anthropic", "on-default"), Some(true));
        assert_eq!(store.model_enabled("anthropic", "on-explicit"), Some(true));
        assert_eq!(store.model_enabled("anthropic", "off"), Some(false));
        // Unknown model or provider is not governed by the catalog.
        assert_eq!(store.model_enabled("anthropic", "ghost"), None);
        assert_eq!(store.model_enabled("ghost", "off"), None);
        // Provider match ignores ASCII case.
        assert_eq!(store.model_enabled("Anthropic", "off"), Some(false));
    }

    #[test]
    fn seeds_from_legacy_shaped_seed() {
        let catalog = temp_path("seed_legacy");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let seed = catalog
            .parent()
            .unwrap()
            .join("seed.json");
        std::fs::write(&seed, json!({ "llm": { "providers": [provider("openai")] } }).to_string()).unwrap();

        let store = LlmProviderCatalog::new(catalog.clone(), Some(seed)).unwrap();
        let providers = store
            .list_providers()
            .unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(provider_enum_value(&providers[0]), Some("openai"));
        // Storage copy is normalized to the bare `{ "providers": [...] }` shape.
        let on_disk: Value = serde_json::from_str(&std::fs::read_to_string(&catalog).unwrap()).unwrap();
        assert!(
            on_disk
                .get("providers")
                .is_some()
        );
        assert!(on_disk.get("llm").is_none());
    }

    #[test]
    fn does_not_overwrite_existing_storage_copy() {
        let catalog = temp_path("no_overwrite");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        std::fs::write(&catalog, json!({ "providers": [provider("anthropic")] }).to_string()).unwrap();
        let seed = catalog
            .parent()
            .unwrap()
            .join("seed.json");
        std::fs::write(&seed, json!({ "providers": [provider("openai")] }).to_string()).unwrap();

        let store = LlmProviderCatalog::new(catalog, Some(seed)).unwrap();
        let providers = store
            .list_providers()
            .unwrap();
        assert_eq!(providers.len(), 1);
        assert_eq!(provider_enum_value(&providers[0]), Some("anthropic"));
    }

    #[tokio::test]
    async fn every_catalog_write_refuses_a_price_out_of_range() {
        let catalog = temp_path("prices");
        let store = LlmProviderCatalog::new(catalog, None).unwrap();
        let priced = |field: &str, price: Value| {
            let mut provider = provider_with_models(
                "openai",
                json!([{ "name": "GPT-4o", "value": "gpt-4o", "cost_per_1k_input": 0.0025, "cost_per_1k_output": 0.01 }]),
            );
            provider["models"][0][field] = price;
            provider
        };
        let mut on_endpoint = provider("openai");
        on_endpoint["endpoints"] = json!([{ "name": "Chat", "path": "/chat/completions", "cost_per_1k_input": -1.0 }]);

        for (label, bad) in [
            ("a negative input price", priced("cost_per_1k_input", json!(-0.001))),
            ("an output price above the ceiling", priced("cost_per_1k_output", json!(100.01))),
            ("a price that is not a number", priced("cost_per_1k_input", json!("free"))),
            ("a negative endpoint price", on_endpoint),
        ] {
            assert!(
                matches!(
                    store
                        .create_provider(bad.clone())
                        .await,
                    Err(CatalogError::Validation(_))
                ),
                "create accepted {label}"
            );
            assert!(
                matches!(
                    store
                        .save_custom(json!({ "providers": [{ "enum_value": "mine", "name": "Mine", "models": bad["models"], "endpoints": bad["endpoints"] }] }))
                        .await,
                    Err(CatalogError::Validation(_))
                ),
                "the custom catalog accepted {label}"
            );
        }
        store
            .create_provider(priced("cost_per_1k_output", json!(100.0)))
            .await
            .expect("the ceiling itself is a valid price");
        assert!(
            matches!(
                store
                    .update_provider("openai", priced("cost_per_1k_input", json!(-0.5)))
                    .await,
                Err(CatalogError::Validation(_))
            ),
            "update accepted a negative price"
        );
        store
            .update_provider("openai", priced("cost_per_1k_input", json!(0.0)))
            .await
            .expect("zero is a valid price");
    }

    #[tokio::test]
    async fn create_get_update_delete_round_trip() {
        let catalog = temp_path("crud");
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        // create
        let created = store
            .create_provider(provider("openai"))
            .await
            .unwrap();
        assert_eq!(provider_enum_value(&created), Some("openai"));

        // duplicate rejected, whatever its case
        for duplicate in ["openai", "OpenAI"] {
            let dup = store
                .create_provider(provider(duplicate))
                .await;
            assert!(matches!(dup, Err(CatalogError::Duplicate(ref id)) if id == duplicate), "{dup:?}");
        }

        // get
        let fetched = store
            .get_provider("openai")
            .unwrap();
        assert!(fetched.is_some());

        // update
        let updated = store
            .update_provider("openai", json!({ "enum_value": "openai", "name": "OpenAI Renamed" }))
            .await
            .unwrap();
        assert_eq!(updated["name"], json!("OpenAI Renamed"));

        // update with mismatched enum_value rejected
        let mismatch = store
            .update_provider("openai", provider("other"))
            .await;
        assert!(matches!(mismatch, Err(CatalogError::Validation(_))));

        // delete
        assert!(
            store
                .delete_provider("openai")
                .await
                .unwrap()
        );
        assert!(
            !store
                .delete_provider("openai")
                .await
                .unwrap()
        );
        assert!(
            store
                .get_provider("openai")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn rejects_invalid_provider() {
        let catalog = temp_path("invalid");
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        let no_enum = store
            .create_provider(json!({ "name": "No Enum" }))
            .await;
        assert!(matches!(no_enum, Err(CatalogError::Validation(_))));

        let no_name = store
            .create_provider(json!({ "enum_value": "x" }))
            .await;
        assert!(matches!(no_name, Err(CatalogError::Validation(_))));
    }

    /// Build a store whose built-in catalog holds `openai`, plus a helper to the
    /// sibling custom file path.
    fn store_with_builtin(name: &str) -> (LlmProviderCatalog, PathBuf) {
        let catalog = temp_path(name);
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        std::fs::write(&catalog, json!({ "providers": [provider("openai")] }).to_string()).unwrap();
        let custom = catalog
            .parent()
            .unwrap()
            .join("custom_llm.json");
        let store = LlmProviderCatalog::new(catalog, None).unwrap();
        (store, custom)
    }

    fn with_base_url(
        mut provider: Value,
        url: &str,
    ) -> Value {
        provider["default_base_url"] = json!(url);
        provider
    }

    const INTERNAL_BASE_URLS: [&str; 10] = [
        "http://localhost:11434",
        "http://127.0.0.1:8000",
        "http://[::1]:8000",
        "http://10.0.0.5:8000",
        "http://172.16.0.9:8000",
        "http://192.168.1.10:8000",
        "http://169.254.10.1",
        "http://169.254.169.254/latest/meta-data",
        "http://metadata.google.internal",
        "http://[fd00::1]:8000",
    ];

    #[tokio::test]
    async fn a_provider_sent_on_its_own_must_match_the_catalog_schema() {
        let (store, _custom) = store_with_builtin("provider_schema");

        for malformed in [
            json!({ "enum_value": "acme", "name": "Acme", "models": "gpt-4o" }),
            json!({ "enum_value": "acme", "name": "Acme", "default_base_url": 42 }),
            json!({ "enum_value": "acme", "name": "Acme", "models": [{ "name": "No value" }] }),
            json!({ "enum_value": "acme", "name": "Acme", "endpoints": [{ "name": "No path" }] }),
        ] {
            let created = store
                .create_provider(malformed.clone())
                .await;
            assert!(
                matches!(&created, Err(CatalogError::Validation(message)) if message.contains("schema")),
                "create accepted {malformed}: {created:?}"
            );
            let mut update = malformed.clone();
            update["enum_value"] = json!("openai");
            let updated = store
                .update_provider("openai", update)
                .await;
            assert!(matches!(updated, Err(CatalogError::Validation(_))), "update accepted {malformed}");
        }
        assert_eq!(
            store
                .list_providers()
                .unwrap(),
            vec![provider("openai")]
        );
    }

    #[tokio::test]
    async fn a_new_provider_base_url_must_be_public() {
        let (store, _custom) = store_with_builtin("create_base_url");

        for url in INTERNAL_BASE_URLS {
            let created = store
                .create_provider(with_base_url(provider("acme"), url))
                .await;
            assert!(
                matches!(&created, Err(CatalogError::Validation(message)) if message.contains("public address")),
                "{url} must be refused, got {created:?}"
            );
        }
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            1
        );

        let public = with_base_url(provider("acme"), "https://93.184.216.34");
        let created = store
            .create_provider(public.clone())
            .await
            .unwrap();
        assert_eq!(created["default_base_url"], "https://93.184.216.34");
        assert_eq!(created[PUBLIC_BASE_URL_MARKER], true);
    }

    #[tokio::test]
    async fn only_a_base_url_checked_at_save_is_marked_public() {
        let catalog = temp_path("public_marker");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let ollama = with_base_url(provider("ollama"), "http://localhost:11434");
        std::fs::write(&catalog, json!({ "providers": [ollama.clone()] }).to_string()).unwrap();
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        // A request body cannot mark an unchecked (stored, local) URL public.
        let mut claimed = ollama.clone();
        claimed[PUBLIC_BASE_URL_MARKER] = json!(true);
        let updated = store
            .update_provider("ollama", claimed)
            .await
            .unwrap();
        assert!(
            updated
                .get(PUBLIC_BASE_URL_MARKER)
                .is_none(),
            "{updated}"
        );

        store
            .create_provider(with_base_url(provider("acme"), "https://93.184.216.34:8443/v1"))
            .await
            .unwrap();
        // Saving the checked provider again keeps the mark; dropping the URL clears it.
        let mut renamed = with_base_url(provider("acme"), "https://93.184.216.34:8443/v1");
        renamed["name"] = json!("Acme AI");
        assert_eq!(
            store
                .update_provider("acme", renamed)
                .await
                .unwrap()[PUBLIC_BASE_URL_MARKER],
            true
        );

        assert!(store.requires_public_host("93.184.216.34"));
        assert!(!store.requires_public_host("localhost"));
        assert!(!store.requires_public_host("api.example.com"));

        let without_url = provider("acme");
        let cleared = store
            .update_provider("acme", without_url)
            .await
            .unwrap();
        assert!(
            cleared
                .get(PUBLIC_BASE_URL_MARKER)
                .is_none()
        );
        assert!(!store.requires_public_host("93.184.216.34"));
    }

    #[tokio::test]
    async fn an_update_keeps_a_stored_local_base_url_but_refuses_a_new_internal_one() {
        let catalog = temp_path("update_base_url");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let ollama = with_base_url(provider("ollama"), "http://localhost:11434");
        std::fs::write(&catalog, json!({ "providers": [ollama.clone()] }).to_string()).unwrap();
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        let mut renamed = ollama.clone();
        renamed["name"] = json!("Local Ollama");
        assert_eq!(
            store
                .update_provider("ollama", renamed.clone())
                .await
                .unwrap(),
            renamed
        );

        let moved = with_base_url(renamed.clone(), "http://10.0.0.5:11434");
        assert!(matches!(
            store
                .update_provider("ollama", moved)
                .await,
            Err(CatalogError::Validation(_))
        ));
        assert_eq!(
            store
                .get_provider("ollama")
                .unwrap(),
            Some(renamed)
        );
    }

    #[tokio::test]
    async fn save_custom_refuses_a_new_internal_base_url_and_keeps_a_stored_one() {
        let (store, custom) = store_with_builtin("custom_base_url");
        let vllm = with_base_url(provider("vllm"), "http://10.0.0.5:8000");
        std::fs::write(&custom, json!({ "providers": [vllm.clone()] }).to_string()).unwrap();

        let added = with_base_url(provider("other"), "http://127.0.0.1:9000");
        let refused = store
            .save_custom(json!({ "providers": [vllm.clone(), added] }))
            .await;
        assert!(
            matches!(&refused, Err(CatalogError::Validation(message)) if message.contains("'other'")),
            "{refused:?}"
        );

        let mut described = vllm.clone();
        described["description"] = json!("Self-hosted vLLM");
        assert_eq!(
            store
                .save_custom(json!({ "providers": [described.clone()] }))
                .await
                .unwrap(),
            vec![described]
        );
    }

    #[tokio::test]
    async fn save_custom_merges_into_runtime_catalog() {
        let (store, _custom) = store_with_builtin("custom_merge");
        // Only the built-in provider before saving custom.
        assert_eq!(store.cached_providers().len(), 1);

        let saved = store
            .save_custom(json!({ "providers": [provider_with_models(
                "acme",
                json!([{ "name": "Acme One", "value": "acme-1" }]),
            )] }))
            .await
            .unwrap();
        assert_eq!(saved.len(), 1);

        // Merged runtime view now includes the custom provider…
        let merged = store.cached_providers();
        let enums: Vec<&str> = merged
            .iter()
            .filter_map(|p| provider_enum_value(p))
            .collect();
        assert!(enums.contains(&"openai"));
        assert!(enums.contains(&"acme"));
        // …and its model resolves as if built-in.
        assert_eq!(store.model_enabled("acme", "acme-1"), Some(true));
        // The built-in list is untouched (Built-In tab stays built-in only).
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            1
        );
        // The Custom tab view shows only the custom provider.
        assert_eq!(store.custom_providers().len(), 1);
    }

    #[tokio::test]
    async fn get_provider_falls_back_to_custom() {
        // The read-only detail page fetches `GET /llm-providers/{enum_value}`
        // for both tabs — Custom rows must resolve too.
        let (store, _custom) = store_with_builtin("get_provider_custom");
        store
            .save_custom(json!({ "providers": [provider("acme")] }))
            .await
            .unwrap();

        // Built-in still resolves.
        let openai = store
            .get_provider("openai")
            .unwrap();
        assert!(openai.is_some());
        assert_eq!(provider_enum_value(openai.as_ref().unwrap()), Some("openai"));

        // Custom now resolves too.
        let acme = store
            .get_provider("acme")
            .unwrap();
        assert!(acme.is_some());
        assert_eq!(provider_enum_value(acme.as_ref().unwrap()), Some("acme"));

        // Unknown id still returns None.
        assert!(
            store
                .get_provider("unknown")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn save_custom_rejects_builtin_collision() {
        let (store, _custom) = store_with_builtin("custom_collision");
        let result = store
            .save_custom(json!({ "providers": [provider("openai")] }))
            .await;
        assert!(matches!(result, Err(CatalogError::Validation(_))));
        // Nothing was written.
        assert_eq!(store.custom_providers().len(), 0);
    }

    #[tokio::test]
    async fn save_custom_rejects_duplicate_within_custom() {
        let (store, _custom) = store_with_builtin("custom_dup");
        let result = store
            .save_custom(json!({ "providers": [provider("acme"), provider("acme")] }))
            .await;
        assert!(matches!(result, Err(CatalogError::Validation(_))));
    }

    #[tokio::test]
    async fn save_custom_rejects_schema_violation() {
        let (store, _custom) = store_with_builtin("custom_schema");
        // Provider missing the required `name` field.
        let result = store
            .save_custom(json!({ "providers": [{ "enum_value": "acme" }] }))
            .await;
        assert!(matches!(result, Err(CatalogError::Validation(_))));
    }

    #[test]
    fn invalid_custom_file_is_ignored_at_runtime() {
        let (store, custom) = store_with_builtin("custom_invalid_ignored");
        // Corrupt custom file on disk — the runtime must degrade gracefully.
        std::fs::write(&custom, "{ this is not valid json ]").unwrap();
        let merged = store.cached_providers();
        // Built-in still present; no panic, custom simply ignored.
        assert_eq!(merged.len(), 1);
        assert_eq!(provider_enum_value(&merged[0]), Some("openai"));
        // The Custom tab view is empty for an unparseable file.
        assert_eq!(store.custom_providers().len(), 0);
        // The editor still gets the raw (invalid) text so the user can fix it.
        assert!(
            store
                .read_custom_raw()
                .contains("not valid json")
        );
    }

    #[test]
    fn colliding_custom_entry_dropped_at_runtime() {
        // A custom file that (somehow) reuses a built-in id is skipped on merge,
        // not surfaced — defense-in-depth on top of save-time rejection.
        let (store, custom) = store_with_builtin("custom_collision_runtime");
        std::fs::write(&custom, json!({ "providers": [provider("openai"), provider("acme")] }).to_string()).unwrap();
        let merged = store.cached_providers();
        let enums: Vec<&str> = merged
            .iter()
            .filter_map(|p| provider_enum_value(p))
            .collect();
        // Exactly one `openai` (the built-in) and the non-colliding custom `acme`.
        assert_eq!(
            enums
                .iter()
                .filter(|e| **e == "openai")
                .count(),
            1
        );
        assert!(enums.contains(&"acme"));
    }

    #[test]
    fn read_custom_raw_returns_template_when_absent() {
        let (store, _custom) = store_with_builtin("custom_absent");
        let raw = store.read_custom_raw();
        let parsed: Value = serde_json::from_str(&raw).unwrap();
        assert!(
            parsed["providers"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn embedded_schema_compiles() {
        assert!(catalog_schema_validator().is_some(), "shipped LLM catalog schema must compile");
    }

    #[tokio::test]
    async fn refresh_builtin_replaces_and_backs_up() {
        let (store, _custom) = store_with_builtin("refresh_ok");
        // Baseline: one built-in provider.
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            provider_enum_value(
                &store
                    .list_providers()
                    .unwrap()[0]
            ),
            Some("openai")
        );

        let refreshed = serde_json::json!({
            "providers": [provider("openai"), provider("anthropic"), provider("gemini")]
        });
        let refresh = store
            .refresh_builtin(refreshed)
            .await
            .unwrap();
        assert_eq!(refresh, BuiltinRefresh { providers: 3, added: 2 });

        // New catalog is live…
        let enums: Vec<String> = store
            .list_providers()
            .unwrap()
            .iter()
            .filter_map(|p| provider_enum_value(p).map(str::to_string))
            .collect();
        assert_eq!(enums, vec!["openai", "anthropic", "gemini"]);

        // …and the previous catalog is preserved as llm.json.bak.
        let backup = store.backup_path();
        assert!(backup.exists(), "backup llm.json.bak must exist after refresh");
        let backup_doc: Value = serde_json::from_str(&std::fs::read_to_string(&backup).unwrap()).unwrap();
        let backup_providers = extract_providers(&backup_doc);
        assert_eq!(backup_providers.len(), 1);
        assert_eq!(provider_enum_value(&backup_providers[0]), Some("openai"));
    }

    #[tokio::test]
    async fn refresh_builtin_rejects_invalid_and_keeps_original() {
        let (store, _custom) = store_with_builtin("refresh_invalid");

        // Schema violation: a provider missing `name`.
        let bad = serde_json::json!({ "providers": [{ "enum_value": "acme" }] });
        assert!(matches!(
            store
                .refresh_builtin(bad)
                .await,
            Err(CatalogError::Validation(_))
        ));

        // Empty catalog is rejected too.
        let empty = serde_json::json!({ "providers": [] });
        assert!(matches!(
            store
                .refresh_builtin(empty)
                .await,
            Err(CatalogError::Validation(_))
        ));

        // The original catalog is untouched and no backup was created.
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            1
        );
        assert!(!store.backup_path().exists());
    }

    #[tokio::test]
    async fn refresh_builtin_rejects_duplicate_ids() {
        let (store, _custom) = store_with_builtin("refresh_dup");
        let dup = serde_json::json!({ "providers": [provider("acme"), provider("acme")] });
        assert!(matches!(
            store
                .refresh_builtin(dup)
                .await,
            Err(CatalogError::Validation(_))
        ));
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            1
        );
    }

    fn stored_provider(
        store: &LlmProviderCatalog,
        enum_value: &str,
    ) -> Value {
        store
            .list_providers()
            .unwrap()
            .into_iter()
            .find(|p| provider_enum_value(p) == Some(enum_value))
            .unwrap_or_else(|| panic!("{enum_value} is not stored"))
    }

    #[tokio::test]
    async fn refresh_takes_only_model_data_for_a_stored_provider() {
        let catalog = temp_path("refresh_merge");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let mut stored = json!({
            "enum_value": "openai",
            "name": "OpenAI",
            "default_base_url": "https://api.openai.com/v1",
            "api_version_prefix": "/v1",
            "api_schema": "openai",
            "api_key_secret": "openai-key",
            "api_key_label": "OpenAI API key",
            "api_key_validation": "mandatory",
            "api_key_required": true,
            "requires_forward_caller_token": false,
            "enabled": true,
            "description": "Old description",
            "endpoint_parameters": { "old": true },
            "endpoints": [{ "name": "Chat", "path": "/chat/completions" }],
            "models": [{ "name": "GPT-4o", "value": "gpt-4o", "cost_per_1k_input": 0.0025, "enabled": true }]
        });
        stored[PUBLIC_BASE_URL_MARKER] = json!(true);
        let ollama = with_base_url(provider("ollama"), "http://localhost:11434");
        std::fs::write(&catalog, json!({ "providers": [stored.clone(), ollama.clone()] }).to_string()).unwrap();
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        let downloaded = json!({
            "enum_value": "openai",
            "name": "Renamed",
            "default_base_url": "https://collector.example",
            "api_version_prefix": "/v9",
            "api_schema": "anthropic",
            "api_key_secret": "other-key",
            "api_key_label": "Paste it here",
            "api_key_validation": "none",
            "api_key_required": false,
            "requires_forward_caller_token": true,
            "enabled": false,
            "description": "New description",
            "endpoint_parameters": { "new": true },
            "endpoints": [{ "name": "Responses", "path": "/responses" }],
            "models": [{ "name": "GPT-5", "value": "gpt-5", "cost_per_1k_input": 0.001, "enabled": false }]
        });
        let refresh = store
            .refresh_builtin(json!({ "providers": [downloaded.clone()] }))
            .await
            .unwrap();
        assert_eq!(refresh, BuiltinRefresh { providers: 2, added: 0 });

        let mut expected = stored;
        for key in REFRESHED_PROVIDER_FIELDS {
            expected[key] = downloaded[key].clone();
        }
        assert_eq!(stored_provider(&store, "openai"), expected);
        assert_eq!(stored_provider(&store, "ollama"), ollama, "a provider missing from the download is kept");
        assert!(store.requires_public_host("api.openai.com"));
        assert!(!store.requires_public_host("collector.example"));
    }

    #[tokio::test]
    async fn refresh_drops_a_model_field_the_download_omits() {
        let (store, _custom) = store_with_builtin("refresh_omitted");
        let mut downloaded = provider("openai");
        downloaded
            .as_object_mut()
            .unwrap()
            .remove("endpoints");
        store
            .refresh_builtin(json!({ "providers": [downloaded] }))
            .await
            .unwrap();
        assert!(
            stored_provider(&store, "openai")
                .get("endpoints")
                .is_none()
        );
    }

    #[tokio::test]
    async fn refresh_refuses_a_provider_without_a_models_array() {
        let (store, _custom) = store_with_builtin("refresh_no_models");
        let stored = stored_provider(&store, "openai");
        for models in [None, Some(json!(null)), Some(json!({}))] {
            let mut downloaded = provider("openai");
            match models {
                Some(value) => downloaded["models"] = value,
                None => {
                    downloaded
                        .as_object_mut()
                        .unwrap()
                        .remove("models");
                }
            }
            let refused = store
                .refresh_builtin(json!({ "providers": [downloaded] }))
                .await;
            assert!(matches!(refused, Err(CatalogError::Validation(_))), "{refused:?}");
            assert_eq!(stored_provider(&store, "openai"), stored);
        }
        store
            .refresh_builtin(json!({ "providers": [provider("openai")] }))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn refresh_refuses_stored_ids_that_differ_only_in_case() {
        let catalog = temp_path("refresh_case_duplicates");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let stored = json!({ "providers": [provider("openai"), provider("OpenAI")] }).to_string();
        std::fs::write(&catalog, &stored).unwrap();
        let store = LlmProviderCatalog::new(catalog.clone(), None).unwrap();

        let refused = store
            .refresh_builtin(json!({ "providers": [provider_with_models("openai", json!([{ "name": "GPT-5", "value": "gpt-5" }]))] }))
            .await;
        assert!(
            matches!(refused, Err(CatalogError::Validation(ref message)) if message.contains("more than once")),
            "{refused:?}"
        );
        assert_eq!(std::fs::read_to_string(&catalog).unwrap(), stored);
    }

    #[tokio::test]
    async fn refresh_adds_a_new_provider_disabled_after_the_base_url_check() {
        let (store, _custom) = store_with_builtin("refresh_new_provider");
        let mut acme = with_base_url(
            provider_with_models(
                "acme",
                json!([{ "name": "Default", "value": "acme-default" }, { "name": "On", "value": "acme-on", "enabled": true }]),
            ),
            "https://93.184.216.34/v1",
        );
        acme["enabled"] = json!(true);
        acme[PUBLIC_BASE_URL_MARKER] = json!(false);

        let refresh = store
            .refresh_builtin(json!({ "providers": [provider("openai"), acme] }))
            .await
            .unwrap();
        assert_eq!(refresh, BuiltinRefresh { providers: 2, added: 1 });
        let added = stored_provider(&store, "acme");
        assert_eq!(added["enabled"], false);
        assert_eq!(added[PUBLIC_BASE_URL_MARKER], true);
        assert_eq!(added["default_base_url"], "https://93.184.216.34/v1");

        assert_eq!(store.model_enabled("acme", "acme-default"), Some(false));
        assert_eq!(store.model_enabled("acme", "acme-on"), Some(false));
        let mut offered = store
            .cached_providers()
            .to_vec();
        retain_enabled_models(&mut offered);
        let acme_offered = offered
            .iter()
            .find(|p| provider_enum_value(p) == Some("acme"))
            .unwrap();
        assert_eq!(acme_offered["models"], json!([]));
    }

    #[tokio::test]
    async fn an_added_provider_stays_disabled_across_later_refreshes() {
        let (store, _custom) = store_with_builtin("refresh_added_twice");
        let acme = |models: Value| with_base_url(provider_with_models("acme", models), "https://93.184.216.34/v1");
        store
            .refresh_builtin(
                json!({ "providers": [provider("openai"), acme(json!([{ "name": "One", "value": "acme-1" }]))] }),
            )
            .await
            .unwrap();

        store
            .refresh_builtin(json!({ "providers": [
                provider("openai"),
                acme(json!([
                    { "name": "One", "value": "acme-1", "enabled": true },
                    { "name": "Two", "value": "acme-2" }
                ]))
            ] }))
            .await
            .unwrap();
        assert_eq!(store.model_enabled("acme", "acme-1"), Some(false));
        assert_eq!(store.model_enabled("acme", "acme-2"), Some(false));
    }

    #[tokio::test]
    async fn a_refresh_keeps_each_stored_model_switch() {
        let catalog = temp_path("refresh_model_switches");
        std::fs::create_dir_all(catalog.parent().unwrap()).unwrap();
        let mut openai = provider_with_models(
            "openai",
            json!([
                { "name": "Off", "value": "off", "enabled": false },
                { "name": "On", "value": "on" }
            ]),
        );
        openai["enabled"] = json!(true);
        let mut azure = provider_with_models("azure", json!([{ "name": "Kept", "value": "kept" }]));
        azure["enabled"] = json!(false);
        std::fs::write(&catalog, json!({ "providers": [openai, azure] }).to_string()).unwrap();
        let store = LlmProviderCatalog::new(catalog, None).unwrap();

        store
            .refresh_builtin(json!({ "providers": [
                provider_with_models("openai", json!([
                    { "name": "Off", "value": "off", "enabled": true },
                    { "name": "On", "value": "on", "enabled": false },
                    { "name": "New", "value": "new" }
                ])),
                provider_with_models("azure", json!([
                    { "name": "Kept", "value": "kept" },
                    { "name": "Added", "value": "added" }
                ]))
            ] }))
            .await
            .unwrap();
        assert_eq!(store.model_enabled("openai", "off"), Some(false), "an administrator's switch-off is kept");
        assert_eq!(store.model_enabled("openai", "on"), Some(true), "a stored model with no switch stays on");
        assert_eq!(store.model_enabled("openai", "new"), Some(true), "a new model of an enabled provider is on");
        assert_eq!(
            store.model_enabled("azure", "kept"),
            Some(true),
            "a disabled provider's stored model keeps working"
        );
        assert_eq!(store.model_enabled("azure", "added"), Some(false), "a new model of a disabled provider is off");
    }

    #[tokio::test]
    async fn refresh_skips_a_new_provider_whose_id_matches_a_custom_provider() {
        let (store, custom) = store_with_builtin("refresh_custom_collision");
        let custom_acme = with_base_url(provider("acme"), "https://custom.example/v1");
        std::fs::write(&custom, json!({ "providers": [custom_acme] }).to_string()).unwrap();

        let refresh = store
            .refresh_builtin(json!({
                "providers": [provider("openai"), with_base_url(provider("ACME"), "https://93.184.216.34/v1")]
            }))
            .await
            .unwrap();
        assert_eq!(refresh, BuiltinRefresh { providers: 1, added: 0 });
        assert!(
            store
                .list_providers()
                .unwrap()
                .iter()
                .all(|p| !provider_enum_value(p).is_some_and(|e| e.eq_ignore_ascii_case("acme")))
        );
        assert_eq!(store.custom_providers().len(), 1);
        let resolved: Vec<Value> = store
            .cached_providers()
            .iter()
            .filter(|p| provider_enum_value(p).is_some_and(|e| e.eq_ignore_ascii_case("acme")))
            .cloned()
            .collect();
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0]["default_base_url"], "https://custom.example/v1");
    }

    #[tokio::test]
    async fn refresh_refuses_an_endpoint_path_that_is_not_relative() {
        let (store, _custom) = store_with_builtin("refresh_endpoint_path");
        let before = std::fs::read_to_string(&store.path).unwrap();

        for path in [
            "https://collector.example/v1/chat/completions",
            "collector.example/chat",
            "//collector.example/chat",
            "/\\collector.example/chat",
        ] {
            for id in ["openai", "acme"] {
                let mut downloaded = provider(id);
                downloaded["endpoints"] = json!([{ "name": "Chat", "path": path }]);
                let refused = store
                    .refresh_builtin(json!({ "providers": [downloaded] }))
                    .await;
                assert!(
                    matches!(&refused, Err(CatalogError::Validation(message))
                        if message.contains("endpoint path") && message.contains(id)),
                    "{id} with {path} must be refused, got {refused:?}"
                );
            }
        }
        assert_eq!(std::fs::read_to_string(&store.path).unwrap(), before);
        assert!(!store.backup_path().exists());

        let mut relative = provider("openai");
        relative["endpoints"] = json!([{ "name": "Chat", "path": "/chat/completions" }]);
        store
            .refresh_builtin(json!({ "providers": [relative] }))
            .await
            .unwrap();
        assert_eq!(stored_provider(&store, "openai")["endpoints"][0]["path"], "/chat/completions");
    }

    #[tokio::test]
    async fn refresh_refuses_a_new_provider_with_an_internal_base_url() {
        let (store, _custom) = store_with_builtin("refresh_new_internal");
        let before = std::fs::read_to_string(&store.path).unwrap();

        for url in INTERNAL_BASE_URLS {
            let refused = store
                .refresh_builtin(json!({ "providers": [provider("openai"), with_base_url(provider("acme"), url)] }))
                .await;
            assert!(
                matches!(&refused, Err(CatalogError::Validation(message)) if message.contains("public address")),
                "{url} must be refused, got {refused:?}"
            );
        }
        assert_eq!(std::fs::read_to_string(&store.path).unwrap(), before);
        assert!(!store.backup_path().exists());
    }

    #[tokio::test]
    async fn refresh_matches_a_stored_provider_ignoring_case() {
        let (store, _custom) = store_with_builtin("refresh_case");
        let mut downloaded = with_base_url(provider("OpenAI"), "https://collector.example");
        downloaded["description"] = json!("New");
        let refresh = store
            .refresh_builtin(json!({ "providers": [downloaded] }))
            .await
            .unwrap();
        assert_eq!(refresh, BuiltinRefresh { providers: 1, added: 0 });
        let openai = stored_provider(&store, "openai");
        assert_eq!(openai["description"], "New");
        assert!(
            openai
                .get("default_base_url")
                .is_none()
        );
    }

    #[tokio::test]
    async fn rollback_builtin_restores_previous() {
        let (store, _custom) = store_with_builtin("rollback_ok");
        store
            .refresh_builtin(serde_json::json!({ "providers": [provider("anthropic")] }))
            .await
            .unwrap();
        assert_eq!(
            store
                .list_providers()
                .unwrap()
                .len(),
            2
        );

        let restored = store
            .rollback_builtin()
            .await
            .unwrap();
        assert_eq!(restored, 1);
        assert_eq!(
            provider_enum_value(
                &store
                    .list_providers()
                    .unwrap()[0]
            ),
            Some("openai")
        );
        // The backup is consumed by the restore (renamed back into place).
        assert!(!store.backup_path().exists());
    }

    #[tokio::test]
    async fn rollback_without_backup_errors() {
        let (store, _custom) = store_with_builtin("rollback_none");
        assert!(matches!(store.rollback_builtin().await, Err(CatalogError::NotFound(_))));
    }

    #[tokio::test]
    async fn refresh_leaves_no_temporary_file() {
        let (store, _custom) = store_with_builtin("refresh_no_tmp");
        store
            .refresh_builtin(json!({ "providers": [provider("openai")] }))
            .await
            .unwrap();
        assert!(
            !store
                .path
                .with_file_name("llm.json.tmp")
                .exists()
        );
        assert!(
            !store
                .path
                .with_file_name("llm.json.bak.tmp")
                .exists()
        );
    }

    #[test]
    fn cached_providers_keep_the_last_catalog_when_llm_json_cannot_be_read() {
        let (store, _custom) = store_with_builtin("cache_unreadable");
        let before = store.cached_providers();
        assert_eq!(before.len(), 1);

        std::fs::write(&store.path, "{ not json").unwrap();
        assert_eq!(*store.cached_providers(), *before);

        std::fs::remove_file(&store.path).unwrap();
        assert_eq!(*store.cached_providers(), *before);
    }

    #[test]
    fn write_file_atomically_replaces_the_file_and_cleans_up_on_failure() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("record.json");
        std::fs::write(&path, b"old").unwrap();
        write_file_atomically(&path, b"new").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"new");
        assert!(
            !directory
                .path()
                .join("record.json.tmp")
                .exists()
        );

        let occupied = directory
            .path()
            .join("occupied");
        std::fs::create_dir(&occupied).unwrap();
        std::fs::write(occupied.join("keep"), b"x").unwrap();
        assert!(write_file_atomically(&occupied, b"new").is_err());
        assert!(
            !directory
                .path()
                .join("occupied.tmp")
                .exists()
        );
    }
}
