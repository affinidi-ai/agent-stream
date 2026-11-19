//! "Refresh Builtin Models": install a published built-in catalog.
//!
//! `llm_catalog.refresh_url` names a small manifest. It carries a publication
//! sequence that never goes backwards, a `version_id` used once, and the URL,
//! SHA-256 and size of the catalog file. The refresh downloads the manifest,
//! refuses an older, replayed or changed publication, downloads the catalog,
//! checks its size and hash, and merges it into `llm.json`
//! ([`LlmProviderCatalog::refresh_builtin`]). The accepted manifest, its ETag
//! and every `version_id` seen are kept in `llm_catalog_refresh.json` next to
//! `llm.json`. A rollback of the catalog keeps that record, so an older
//! publication stays refused, but marks it rolled back, so the next refresh
//! installs the accepted publication again.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::{ETAG, IF_NONE_MATCH};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

use super::store::{BuiltinRefresh, CatalogError, LlmProviderCatalog};

const MAX_MANIFEST_BYTES: usize = 64 * 1024;
/// The largest catalog the refresh accepts. The published catalog is a few
/// hundred kilobytes; anything near this size is not a catalog.
const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;
const MANIFEST_TIMEOUT: Duration = Duration::from_secs(10);
const CATALOG_TIMEOUT: Duration = Duration::from_secs(30);
const MANIFEST_SCHEMA_VERSION: u32 = 1;

/// The published manifest at `llm_catalog.refresh_url`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CatalogManifest {
    pub schema_version: u32,
    pub publication_sequence: u64,
    pub version_id: String,
    pub version: String,
    pub catalogue_url: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub published_at: DateTime<Utc>,
}

#[derive(Default, Serialize, Deserialize)]
struct RefreshState {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    manifest: Option<CatalogManifest>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
    #[serde(default)]
    seen_version_ids: BTreeSet<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    rolled_back: bool,
}

#[derive(Debug)]
pub(crate) enum RefreshOutcome {
    Updated { manifest: CatalogManifest, refresh: BuiltinRefresh },
    Unchanged { manifest: CatalogManifest },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RefreshFailureKind {
    Transport,
    Validation,
    Rollback,
    HashMismatch,
    Storage,
}

#[derive(Debug)]
pub(crate) struct RefreshFailure {
    pub kind: RefreshFailureKind,
    pub message: String,
}

impl RefreshFailure {
    fn new(
        kind: RefreshFailureKind,
        message: impl Into<String>,
    ) -> Self {
        Self { kind, message: message.into() }
    }
}

fn result_label(result: &Result<RefreshOutcome, RefreshFailure>) -> &'static str {
    match result {
        Ok(RefreshOutcome::Updated { .. }) => "updated",
        Ok(RefreshOutcome::Unchanged { .. }) => "unchanged",
        Err(failure) => match failure.kind {
            RefreshFailureKind::Transport => "transport_failure",
            RefreshFailureKind::Validation => "validation_failure",
            RefreshFailureKind::Rollback => "rollback_rejection",
            RefreshFailureKind::HashMismatch => "hash_mismatch",
            RefreshFailureKind::Storage => "storage_failure",
        },
    }
}

/// Runs one refresh at a time against the configured manifest URL.
pub(crate) struct CatalogRefresher {
    manifest_url: String,
    allow_insecure_source: bool,
    lock: Mutex<()>,
}

impl CatalogRefresher {
    pub(crate) fn new(
        manifest_url: String,
        allow_insecure_source: bool,
        catalog: &LlmProviderCatalog,
    ) -> Self {
        if let Ok(RefreshState { manifest: Some(manifest), .. }) = load_state(&catalog.refresh_state_path()) {
            crate::metrics::backends::prometheus::LLM_CATALOG_PUBLICATION_SEQUENCE
                .set(manifest.publication_sequence as f64);
        }
        Self {
            manifest_url,
            allow_insecure_source,
            lock: Mutex::new(()),
        }
    }

    pub(crate) async fn refresh(
        &self,
        catalog: &LlmProviderCatalog,
    ) -> Result<RefreshOutcome, RefreshFailure> {
        let _guard = self.lock.lock().await;
        let result = self
            .refresh_inner(catalog)
            .await;
        let label = result_label(&result);
        crate::metrics::backends::prometheus::LLM_CATALOG_REFRESH
            .with_label_values(&[label])
            .inc();
        let sequence = match &result {
            Ok(RefreshOutcome::Updated { manifest, .. } | RefreshOutcome::Unchanged { manifest }) => {
                crate::metrics::backends::prometheus::LLM_CATALOG_PUBLICATION_SEQUENCE
                    .set(manifest.publication_sequence as f64);
                Some(manifest.publication_sequence)
            }
            Err(failure) => {
                tracing::warn!(outcome = label, error = %failure.message, "Built-in LLM catalog refresh refused");
                None
            }
        };
        tracing::info!(outcome = label, publication_sequence = sequence, "Built-in LLM catalog refresh completed");
        result
    }

    /// [`rollback_catalog`], one at a time with refreshes.
    pub(crate) async fn rollback(
        &self,
        catalog: &LlmProviderCatalog,
    ) -> Result<usize, CatalogError> {
        let _guard = self.lock.lock().await;
        rollback_catalog(catalog).await
    }

    fn client(
        &self,
        timeout: Duration,
    ) -> Result<reqwest::Client, RefreshFailure> {
        let client = if self.allow_insecure_source {
            crate::http_client::with_timeout(timeout)
        } else {
            crate::http_client::with_strict_validating_resolver(timeout)
        };
        client.map_err(|e| {
            RefreshFailure::new(RefreshFailureKind::Transport, format!("failed to build HTTP client: {e}"))
        })
    }

    async fn refresh_inner(
        &self,
        catalog: &LlmProviderCatalog,
    ) -> Result<RefreshOutcome, RefreshFailure> {
        let manifest_url = checked_source(&self.manifest_url).await?;
        let state_path = catalog.refresh_state_path();
        let mut state = load_state(&state_path)?;

        let mut request = self
            .client(MANIFEST_TIMEOUT)?
            .get(manifest_url.clone());
        if state.manifest.is_some()
            && !state.rolled_back
            && let Some(etag) = state.etag.as_deref()
        {
            request = request.header(IF_NONE_MATCH, etag);
        }
        let response = request
            .send()
            .await
            .map_err(|e| transport(format!("failed to fetch the catalog manifest: {e}")))?;
        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return state
                .manifest
                .map(|manifest| RefreshOutcome::Unchanged { manifest })
                .ok_or_else(|| {
                    RefreshFailure::new(
                        RefreshFailureKind::Validation,
                        "the manifest source answered not modified, but no publication was accepted yet",
                    )
                });
        }
        if !response.status().is_success() {
            return Err(transport(format!("the manifest source returned HTTP {}", response.status())));
        }
        let etag = response
            .headers()
            .get(ETAG)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        let body = crate::http_client::read_capped(response, MAX_MANIFEST_BYTES)
            .await
            .map_err(|e| transport(format!("catalog manifest: {e}")))?;
        let candidate: CatalogManifest =
            serde_json::from_slice(&body).map_err(|e| validation(format!("the catalog manifest is not valid: {e}")))?;
        let catalog_url =
            validate_manifest(&candidate, &manifest_url, self.allow_insecure_source).map_err(validation)?;
        validate_history(state.manifest.as_ref(), &candidate, &state.seen_version_ids)
            .map_err(|message| RefreshFailure::new(RefreshFailureKind::Rollback, message))?;

        if !state.rolled_back && state.manifest.as_ref() == Some(&candidate) {
            state.etag = etag;
            save_state(&state_path, &state)?;
            return Ok(RefreshOutcome::Unchanged { manifest: candidate });
        }

        let catalog_url = checked_source(catalog_url.as_str()).await?;
        let response = self
            .client(CATALOG_TIMEOUT)?
            .get(catalog_url)
            .send()
            .await
            .map_err(|e| transport(format!("failed to fetch the catalog: {e}")))?;
        if !response.status().is_success() {
            return Err(transport(format!("the catalog source returned HTTP {}", response.status())));
        }
        let bytes = crate::http_client::read_capped(response, MAX_CATALOG_BYTES)
            .await
            .map_err(|e| transport(format!("catalog: {e}")))?;
        if bytes.len() as u64 != candidate.size_bytes {
            return Err(RefreshFailure::new(
                RefreshFailureKind::HashMismatch,
                format!("the catalog is {} bytes, the manifest says {}", bytes.len(), candidate.size_bytes),
            ));
        }
        if hex::encode(Sha256::digest(&bytes)) != candidate.sha256 {
            return Err(RefreshFailure::new(
                RefreshFailureKind::HashMismatch,
                "the catalog does not match the SHA-256 in the manifest",
            ));
        }
        let doc: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|e| validation(format!("the catalog is not valid JSON: {e}")))?;

        let refresh = catalog
            .refresh_builtin(doc)
            .await
            .map_err(|e| match e {
                CatalogError::Validation(message) => validation(message),
                other => RefreshFailure::new(RefreshFailureKind::Storage, other.to_string()),
            })?;

        state
            .seen_version_ids
            .insert(candidate.version_id.clone());
        state.manifest = Some(candidate.clone());
        state.etag = etag;
        state.rolled_back = false;
        if let Err(failure) = save_state(&state_path, &state) {
            return Err(
                match catalog
                    .rollback_builtin()
                    .await
                {
                    Ok(_) => failure,
                    Err(e) => {
                        tracing::error!(
                            error = %e,
                            "Built-in LLM catalog refresh record was not saved and the previous catalog could not be restored"
                        );
                        RefreshFailure::new(
                            RefreshFailureKind::Storage,
                            format!("{}; restoring the previous catalog also failed: {e}", failure.message),
                        )
                    }
                },
            );
        }
        Ok(RefreshOutcome::Updated { manifest: candidate, refresh })
    }
}

/// Restore `llm.json.bak` and mark the accepted publication rolled back,
/// keeping its sequence. The record is marked first and put back if the
/// catalog cannot be restored, so a record that cannot be written refuses the
/// rollback. Returns the restored provider count.
pub(crate) async fn rollback_catalog(catalog: &LlmProviderCatalog) -> Result<usize, CatalogError> {
    let path = catalog.refresh_state_path();
    let record = |failure: RefreshFailure| CatalogError::Io(failure.message);
    let mut state = load_state(&path).map_err(record)?;
    let previous = (state.etag.clone(), state.rolled_back);
    let marked = state.manifest.is_some();
    if marked {
        state.rolled_back = true;
        state.etag = None;
        save_state(&path, &state).map_err(record)?;
    }
    let restored = catalog
        .rollback_builtin()
        .await;
    if restored.is_err() && marked {
        (state.etag, state.rolled_back) = previous;
        if let Err(failure) = save_state(&path, &state) {
            tracing::warn!(
                error = %failure.message,
                "Built-in LLM catalog rollback failed and the refresh record stays marked rolled back; the next refresh installs the accepted publication again"
            );
        }
    }
    restored
}

fn transport(message: String) -> RefreshFailure {
    RefreshFailure::new(RefreshFailureKind::Transport, message)
}

fn validation(message: String) -> RefreshFailure {
    RefreshFailure::new(RefreshFailureKind::Validation, message)
}

/// Re-check a source URL before each download: http or https, no loopback,
/// link-local or cloud metadata host or resolved address.
async fn checked_source(raw: &str) -> Result<Url, RefreshFailure> {
    crate::url_validation::validate_service_endpoint_url(raw)
        .await
        .map_err(|reason| validation(format!("catalog source rejected: {reason}")))
}

/// Check the manifest fields on their own. Returns the catalog URL, which
/// must be on the manifest's host and port, carry no credentials, and use
/// https (or http, for a mirror allowed by `allow_insecure_source`).
fn validate_manifest(
    manifest: &CatalogManifest,
    manifest_url: &Url,
    allow_insecure_source: bool,
) -> Result<Url, String> {
    if manifest.schema_version != MANIFEST_SCHEMA_VERSION {
        return Err(format!("unsupported catalog manifest schema_version {}", manifest.schema_version));
    }
    if manifest.publication_sequence == 0 {
        return Err("the catalog manifest publication_sequence must be positive".to_string());
    }
    if manifest
        .version_id
        .trim()
        .is_empty()
    {
        return Err("the catalog manifest has no version_id".to_string());
    }
    if manifest
        .version
        .trim()
        .is_empty()
    {
        return Err("the catalog manifest has no version".to_string());
    }
    let is_sha256 = manifest.sha256.len() == 64
        && manifest
            .sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if !is_sha256 {
        return Err("the catalog manifest sha256 must be 64 lowercase hex characters".to_string());
    }
    if manifest.size_bytes == 0 || manifest.size_bytes > MAX_CATALOG_BYTES as u64 {
        return Err(format!("the catalog manifest size_bytes must be from 1 to {MAX_CATALOG_BYTES}"));
    }
    let url = Url::parse(&manifest.catalogue_url)
        .map_err(|e| format!("the catalog manifest catalogue_url is not a valid URL: {e}"))?;
    let scheme_ok = url.scheme() == "https" || (allow_insecure_source && url.scheme() == "http");
    if !scheme_ok {
        return Err("the catalog manifest catalogue_url must be https".to_string());
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err("the catalog manifest catalogue_url must not carry credentials".to_string());
    }
    let same_host = url
        .host_str()
        .zip(manifest_url.host_str())
        .is_some_and(|(catalog, source)| catalog.eq_ignore_ascii_case(source))
        && url.port_or_known_default() == manifest_url.port_or_known_default();
    if !same_host {
        return Err(
            "the catalog manifest catalogue_url must be on the same host as llm_catalog.refresh_url".to_string()
        );
    }
    Ok(url)
}

/// Refuse a publication older than the accepted one, a changed manifest under
/// the accepted sequence, and a `version_id` already used by another
/// publication.
fn validate_history(
    current: Option<&CatalogManifest>,
    candidate: &CatalogManifest,
    seen_version_ids: &BTreeSet<String>,
) -> Result<(), String> {
    let Some(current) = current else {
        return Ok(());
    };
    if candidate.publication_sequence < current.publication_sequence {
        return Err(format!(
            "catalog publication {} is older than the accepted publication {}",
            candidate.publication_sequence, current.publication_sequence
        ));
    }
    if candidate.publication_sequence == current.publication_sequence && candidate != current {
        return Err(format!(
            "catalog publication {} was changed after it was accepted",
            candidate.publication_sequence
        ));
    }
    if candidate.publication_sequence > current.publication_sequence
        && (candidate.version_id == current.version_id || seen_version_ids.contains(&candidate.version_id))
    {
        return Err(format!("catalog version_id '{}' was already used", candidate.version_id));
    }
    Ok(())
}

fn load_state(path: &Path) -> Result<RefreshState, RefreshFailure> {
    let contents = match std::fs::read(path) {
        Ok(contents) => contents,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(RefreshState::default()),
        Err(e) => {
            return Err(RefreshFailure::new(
                RefreshFailureKind::Storage,
                format!("failed to read {}: {e}", path.display()),
            ));
        }
    };
    serde_json::from_slice(&contents).map_err(|e| {
        RefreshFailure::new(
            RefreshFailureKind::Storage,
            format!("{} is not a valid refresh record: {e}", path.display()),
        )
    })
}

/// Write the refresh record to a temporary file and rename it into place, so
/// a crash never leaves a partial record.
fn save_state(
    path: &Path,
    state: &RefreshState,
) -> Result<(), RefreshFailure> {
    let storage = |e: String| RefreshFailure::new(RefreshFailureKind::Storage, e);
    let serialized = serde_json::to_vec_pretty(state)
        .map_err(|e| storage(format!("failed to serialize the refresh record: {e}")))?;
    let temporary = path.with_extension("json.tmp");
    std::fs::write(&temporary, serialized)
        .map_err(|e| storage(format!("failed to write {}: {e}", temporary.display())))?;
    std::fs::rename(&temporary, path).map_err(|e| storage(format!("failed to replace {}: {e}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::{IntoResponse, Redirect};
    use serde_json::{Value, json};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex as StdMutex};

    #[derive(Default)]
    struct Published {
        manifest: Option<Value>,
        catalogs: HashMap<String, Vec<u8>>,
    }

    struct Source {
        base: String,
        published: Arc<StdMutex<Published>>,
        server: tokio::task::JoinHandle<()>,
    }

    impl Drop for Source {
        fn drop(&mut self) {
            self.server.abort();
        }
    }

    impl Source {
        async fn start() -> Self {
            let published = Arc::new(StdMutex::new(Published::default()));
            let manifest_state = published.clone();
            let catalog_state = published.clone();
            let app = axum::Router::new()
                .route(
                    "/llm/v1/current.json",
                    axum::routing::get(move |headers: HeaderMap| {
                        let manifest = manifest_state
                            .lock()
                            .unwrap()
                            .manifest
                            .clone();
                        async move {
                            let Some(manifest) = manifest else {
                                return StatusCode::NOT_FOUND.into_response();
                            };
                            let etag = format!("\"{}\"", hex::encode(Sha256::digest(manifest.to_string())));
                            if headers
                                .get(IF_NONE_MATCH)
                                .and_then(|v| v.to_str().ok())
                                == Some(etag.as_str())
                            {
                                return StatusCode::NOT_MODIFIED.into_response();
                            }
                            ([(ETAG, etag)], axum::Json(manifest)).into_response()
                        }
                    }),
                )
                .route(
                    "/llm/v1/moved.json",
                    axum::routing::get(|| async { Redirect::temporary("/llm/v1/current.json") }),
                )
                .route(
                    "/llm/v1/catalogues/{name}",
                    axum::routing::get(move |axum::extract::Path(name): axum::extract::Path<String>| {
                        let body = catalog_state
                            .lock()
                            .unwrap()
                            .catalogs
                            .get(&name)
                            .cloned();
                        async move {
                            body.map_or_else(|| StatusCode::NOT_FOUND.into_response(), IntoResponse::into_response)
                        }
                    }),
                );
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap();
            let address = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                axum::serve(listener, app)
                    .await
                    .unwrap()
            });
            Self {
                base: format!("http://{address}/llm/v1"),
                published,
                server,
            }
        }

        fn manifest_url(&self) -> String {
            format!("{}/current.json", self.base)
        }

        fn catalog_url(
            &self,
            name: &str,
        ) -> String {
            format!("{}/catalogues/{name}.json", self.base)
        }

        /// Publish `catalog` as `name` with a manifest describing it, then let
        /// `edit` change the manifest.
        fn publish(
            &self,
            sequence: u64,
            name: &str,
            catalog: &Value,
            edit: impl FnOnce(&mut Value),
        ) {
            let bytes = serde_json::to_vec(catalog).unwrap();
            let mut manifest = json!({
                "schema_version": 1,
                "publication_sequence": sequence,
                "version_id": format!("agent-stream:{name}"),
                "version": name,
                "catalogue_url": self.catalog_url(name),
                "sha256": hex::encode(Sha256::digest(&bytes)),
                "size_bytes": bytes.len(),
                "published_at": "2026-11-19T00:00:00Z",
            });
            edit(&mut manifest);
            let mut published = self.published.lock().unwrap();
            published
                .catalogs
                .insert(format!("{name}.json"), bytes);
            published.manifest = Some(manifest);
        }

        fn allow(&self) -> crate::url_validation::test_service_endpoints::Allowed {
            let mut urls = vec![self.manifest_url(), format!("{}/moved.json", self.base)];
            urls.extend(
                ["1.0.3", "1.0.4", "1.0.5", "1.0.2"]
                    .iter()
                    .map(|name| self.catalog_url(name)),
            );
            crate::url_validation::test_service_endpoints::allow(&urls)
        }
    }

    fn openai(model: &str) -> Value {
        json!({
            "enum_value": "openai",
            "name": "OpenAI",
            "default_base_url": "https://collector.example",
            "models": [{ "name": model, "value": model, "cost_per_1k_input": 0.001 }]
        })
    }

    fn catalog_with(model: &str) -> Value {
        json!({ "providers": [openai(model)] })
    }

    fn store(directory: &tempfile::TempDir) -> LlmProviderCatalog {
        let path = directory
            .path()
            .join("llm.json");
        std::fs::write(
            &path,
            json!({ "providers": [{
                "enum_value": "openai",
                "name": "OpenAI",
                "default_base_url": "https://api.openai.com/v1",
                "models": [{ "name": "gpt-4o", "value": "gpt-4o" }]
            }] })
            .to_string(),
        )
        .unwrap();
        LlmProviderCatalog::new(path, None).unwrap()
    }

    fn models(catalog: &LlmProviderCatalog) -> Vec<String> {
        catalog
            .list_providers()
            .unwrap()
            .iter()
            .flat_map(|p| {
                p["models"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|m| {
                m["value"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect()
    }

    fn refresher(source: &Source) -> CatalogRefresher {
        CatalogRefresher {
            manifest_url: source.manifest_url(),
            allow_insecure_source: true,
            lock: Mutex::new(()),
        }
    }

    async fn refused(
        refresher: &CatalogRefresher,
        catalog: &LlmProviderCatalog,
    ) -> RefreshFailure {
        refresher
            .refresh(catalog)
            .await
            .expect_err("the refresh must be refused")
    }

    #[tokio::test]
    async fn installs_a_publication_and_keeps_the_connection_settings() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});

        let outcome = refresher(&source)
            .refresh(&catalog)
            .await
            .unwrap();
        let RefreshOutcome::Updated { manifest, refresh } = outcome else {
            panic!("expected an update, got {outcome:?}");
        };
        assert_eq!(manifest.publication_sequence, 1);
        assert_eq!(refresh, BuiltinRefresh { providers: 1, added: 0 });
        assert_eq!(models(&catalog), vec!["gpt-5"]);
        assert_eq!(
            catalog
                .list_providers()
                .unwrap()[0]["default_base_url"],
            "https://api.openai.com/v1"
        );
        let state = load_state(&catalog.refresh_state_path()).unwrap();
        assert_eq!(state.manifest, Some(manifest));
        assert!(state.etag.is_some());
        assert_eq!(state.seen_version_ids, BTreeSet::from(["agent-stream:1.0.3".to_string()]));
    }

    #[tokio::test]
    async fn an_unchanged_publication_changes_nothing() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();
        let installed = std::fs::read_to_string(
            directory
                .path()
                .join("llm.json"),
        )
        .unwrap();

        let second = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(second, RefreshOutcome::Unchanged { ref manifest } if manifest.publication_sequence == 1));
        assert_eq!(
            std::fs::read_to_string(
                directory
                    .path()
                    .join("llm.json")
            )
            .unwrap(),
            installed
        );

        let mut state = load_state(&catalog.refresh_state_path()).unwrap();
        state.etag = None;
        save_state(&catalog.refresh_state_path(), &state).unwrap();
        let without_etag = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(without_etag, RefreshOutcome::Unchanged { .. }), "{without_etag:?}");
        assert!(
            load_state(&catalog.refresh_state_path())
                .unwrap()
                .etag
                .is_some()
        );
    }

    #[tokio::test]
    async fn refuses_an_older_changed_or_reused_publication() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(2, "1.0.4", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();

        source.publish(1, "1.0.3", &catalog_with("gpt-old"), |_| {});
        let older = refused(&refresher, &catalog).await;
        assert_eq!(older.kind, RefreshFailureKind::Rollback, "{}", older.message);

        source.publish(2, "1.0.4", &catalog_with("gpt-5"), |m| m["version"] = json!("1.0.4-rebuilt"));
        let changed = refused(&refresher, &catalog).await;
        assert_eq!(changed.kind, RefreshFailureKind::Rollback, "{}", changed.message);

        source.publish(3, "1.0.5", &catalog_with("gpt-6"), |m| m["version_id"] = json!("agent-stream:1.0.4"));
        let reused = refused(&refresher, &catalog).await;
        assert_eq!(reused.kind, RefreshFailureKind::Rollback, "{}", reused.message);

        assert_eq!(models(&catalog), vec!["gpt-5"]);
        assert_eq!(result_label(&Err(reused)), "rollback_rejection");
    }

    #[tokio::test]
    async fn after_a_rollback_the_accepted_publication_installs_again() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();

        assert_eq!(
            refresher
                .rollback(&catalog)
                .await
                .unwrap(),
            1
        );
        assert_eq!(models(&catalog), vec!["gpt-4o"]);

        let again = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(again, RefreshOutcome::Updated { ref manifest, .. } if manifest.publication_sequence == 1));
        assert_eq!(models(&catalog), vec!["gpt-5"]);
        assert!(
            !load_state(&catalog.refresh_state_path())
                .unwrap()
                .rolled_back
        );

        let unchanged = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(unchanged, RefreshOutcome::Unchanged { .. }), "{unchanged:?}");
    }

    #[tokio::test]
    async fn a_catalog_rollback_keeps_the_accepted_sequence() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();
        source.publish(2, "1.0.4", &catalog_with("gpt-6"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();

        refresher
            .rollback(&catalog)
            .await
            .unwrap();
        assert_eq!(models(&catalog), vec!["gpt-5"]);

        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        let replay = refused(&refresher, &catalog).await;
        assert_eq!(replay.kind, RefreshFailureKind::Rollback, "{}", replay.message);
        assert_eq!(models(&catalog), vec!["gpt-5"]);
        assert_eq!(
            load_state(&catalog.refresh_state_path())
                .unwrap()
                .manifest
                .map(|m| m.publication_sequence),
            Some(2)
        );
    }

    fn block_record_writes(catalog: &LlmProviderCatalog) -> std::path::PathBuf {
        let temporary = catalog
            .refresh_state_path()
            .with_extension("json.tmp");
        std::fs::create_dir(&temporary).unwrap();
        temporary
    }

    #[tokio::test]
    async fn a_record_that_cannot_be_saved_restores_the_previous_catalog() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        let blocked = block_record_writes(&catalog);

        let failure = refused(&refresher, &catalog).await;
        assert_eq!(failure.kind, RefreshFailureKind::Storage, "{}", failure.message);
        assert_eq!(models(&catalog), vec!["gpt-4o"]);
        assert!(
            !catalog
                .refresh_state_path()
                .exists()
        );

        std::fs::remove_dir(&blocked).unwrap();
        let retried = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(retried, RefreshOutcome::Updated { ref manifest, .. } if manifest.publication_sequence == 1));
        assert_eq!(models(&catalog), vec!["gpt-5"]);
        refresher
            .rollback(&catalog)
            .await
            .unwrap();
        assert_eq!(models(&catalog), vec!["gpt-4o"]);
    }

    #[tokio::test]
    async fn a_rollback_without_a_refresh_source_marks_the_record() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();

        assert_eq!(
            rollback_catalog(&catalog)
                .await
                .unwrap(),
            1
        );
        assert_eq!(models(&catalog), vec!["gpt-4o"]);
        let state = load_state(&catalog.refresh_state_path()).unwrap();
        assert!(state.rolled_back);
        assert_eq!(state.etag, None);

        let again = refresher
            .refresh(&catalog)
            .await
            .unwrap();
        assert!(matches!(again, RefreshOutcome::Updated { ref manifest, .. } if manifest.publication_sequence == 1));
        assert_eq!(models(&catalog), vec!["gpt-5"]);
    }

    #[tokio::test]
    async fn a_rollback_that_cannot_mark_the_record_changes_nothing() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();
        block_record_writes(&catalog);

        let error = refresher
            .rollback(&catalog)
            .await
            .unwrap_err();
        assert!(matches!(error, CatalogError::Io(_)), "{error}");
        assert_eq!(models(&catalog), vec!["gpt-5"]);
        assert!(
            directory
                .path()
                .join("llm.json.bak")
                .exists()
        );
        assert!(
            !load_state(&catalog.refresh_state_path())
                .unwrap()
                .rolled_back
        );
    }

    #[tokio::test]
    async fn a_rollback_without_a_backup_leaves_the_record_as_it_was() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        refresher
            .refresh(&catalog)
            .await
            .unwrap();
        std::fs::remove_file(
            directory
                .path()
                .join("llm.json.bak"),
        )
        .unwrap();
        let etag = load_state(&catalog.refresh_state_path())
            .unwrap()
            .etag;

        let error = refresher
            .rollback(&catalog)
            .await
            .unwrap_err();
        assert!(matches!(error, CatalogError::NotFound(_)), "{error}");
        let state = load_state(&catalog.refresh_state_path()).unwrap();
        assert!(!state.rolled_back);
        assert!(etag.is_some());
        assert_eq!(state.etag, etag);
    }

    #[tokio::test]
    async fn refuses_a_catalog_that_does_not_match_the_manifest() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);
        let refresher = refresher(&source);

        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |m| {
            m["sha256"] = json!(hex::encode(Sha256::digest(b"something else")))
        });
        let hash = refused(&refresher, &catalog).await;
        assert_eq!(hash.kind, RefreshFailureKind::HashMismatch, "{}", hash.message);

        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |m| {
            m["size_bytes"] = json!(
                m["size_bytes"]
                    .as_u64()
                    .unwrap()
                    + 1
            )
        });
        let size = refused(&refresher, &catalog).await;
        assert_eq!(size.kind, RefreshFailureKind::HashMismatch, "{}", size.message);

        assert_eq!(models(&catalog), vec!["gpt-4o"]);
        assert!(
            !catalog
                .refresh_state_path()
                .exists()
        );
        assert_eq!(result_label(&Err(size)), "hash_mismatch");
    }

    #[tokio::test]
    async fn refuses_a_catalog_on_another_host_and_a_redirect() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);

        let elsewhere = source
            .catalog_url("1.0.3")
            .replace("127.0.0.1", "localhost");
        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |m| m["catalogue_url"] = json!(elsewhere));
        let other_host = refused(&refresher(&source), &catalog).await;
        assert_eq!(other_host.kind, RefreshFailureKind::Validation, "{}", other_host.message);
        assert!(
            other_host
                .message
                .contains("same host"),
            "{}",
            other_host.message
        );

        source.publish(1, "1.0.3", &catalog_with("gpt-5"), |_| {});
        let moved = CatalogRefresher {
            manifest_url: format!("{}/moved.json", source.base),
            allow_insecure_source: true,
            lock: Mutex::new(()),
        };
        let redirect = refused(&moved, &catalog).await;
        assert_eq!(redirect.kind, RefreshFailureKind::Transport, "{}", redirect.message);
        assert!(
            redirect
                .message
                .contains("307"),
            "{}",
            redirect.message
        );

        assert_eq!(models(&catalog), vec!["gpt-4o"]);
    }

    #[tokio::test]
    async fn refuses_a_catalog_that_fails_validation() {
        let source = Source::start().await;
        let _allowed = source.allow();
        let directory = tempfile::tempdir().unwrap();
        let catalog = store(&directory);

        source.publish(1, "1.0.3", &json!({ "providers": [] }), |_| {});
        let empty = refused(&refresher(&source), &catalog).await;
        assert_eq!(empty.kind, RefreshFailureKind::Validation, "{}", empty.message);
        assert_eq!(models(&catalog), vec!["gpt-4o"]);
        assert!(
            !catalog
                .refresh_state_path()
                .exists()
        );
    }

    fn manifest() -> CatalogManifest {
        CatalogManifest {
            schema_version: 1,
            publication_sequence: 1,
            version_id: "agent-stream:1.0.3".to_string(),
            version: "1.0.3".to_string(),
            catalogue_url: "https://well.example/agent-stream/llm/v1/catalogues/1.0.3.json".to_string(),
            sha256: "a".repeat(64),
            size_bytes: 1024,
            published_at: "2026-11-19T00:00:00Z"
                .parse()
                .unwrap(),
        }
    }

    #[test]
    fn manifest_fields_are_checked() {
        let source = Url::parse("https://well.example/agent-stream/llm/v1/current.json").unwrap();
        assert_eq!(
            validate_manifest(&manifest(), &source, false)
                .unwrap()
                .as_str(),
            "https://well.example/agent-stream/llm/v1/catalogues/1.0.3.json"
        );

        let cases: Vec<(&str, CatalogManifest)> = vec![
            (
                "schema_version",
                CatalogManifest {
                    schema_version: 2,
                    ..manifest()
                },
            ),
            (
                "positive",
                CatalogManifest {
                    publication_sequence: 0,
                    ..manifest()
                },
            ),
            (
                "version_id",
                CatalogManifest {
                    version_id: " ".to_string(),
                    ..manifest()
                },
            ),
            (
                "no version",
                CatalogManifest {
                    version: String::new(),
                    ..manifest()
                },
            ),
            (
                "sha256",
                CatalogManifest {
                    sha256: "A".repeat(64),
                    ..manifest()
                },
            ),
            (
                "sha256",
                CatalogManifest {
                    sha256: "a".repeat(63),
                    ..manifest()
                },
            ),
            ("size_bytes", CatalogManifest { size_bytes: 0, ..manifest() }),
            (
                "size_bytes",
                CatalogManifest {
                    size_bytes: MAX_CATALOG_BYTES as u64 + 1,
                    ..manifest()
                },
            ),
            (
                "https",
                CatalogManifest {
                    catalogue_url: "http://well.example/c.json".to_string(),
                    ..manifest()
                },
            ),
            (
                "credentials",
                CatalogManifest {
                    catalogue_url: "https://user:pw@well.example/c.json".to_string(),
                    ..manifest()
                },
            ),
            (
                "same host",
                CatalogManifest {
                    catalogue_url: "https://cdn.example/c.json".to_string(),
                    ..manifest()
                },
            ),
            (
                "same host",
                CatalogManifest {
                    catalogue_url: "https://well.example:8443/c.json".to_string(),
                    ..manifest()
                },
            ),
        ];
        for (expected, candidate) in cases {
            let error = validate_manifest(&candidate, &source, false).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
        }
        let insecure = CatalogManifest {
            catalogue_url: "http://well.example/c.json".to_string(),
            ..manifest()
        };
        let mirror = Url::parse("http://well.example/current.json").unwrap();
        assert!(validate_manifest(&insecure, &mirror, true).is_ok());
    }

    #[test]
    fn history_refuses_rollback_change_and_reuse() {
        let current = CatalogManifest {
            publication_sequence: 2,
            ..manifest()
        };
        let seen = BTreeSet::from(["agent-stream:1.0.2".to_string(), current.version_id.clone()]);

        assert!(validate_history(None, &manifest(), &BTreeSet::new()).is_ok());
        assert!(validate_history(Some(&current), &current, &seen).is_ok());
        let next = CatalogManifest {
            publication_sequence: 3,
            version_id: "agent-stream:1.0.4".to_string(),
            ..manifest()
        };
        assert!(validate_history(Some(&current), &next, &seen).is_ok());

        for (expected, candidate) in [
            (
                "older",
                CatalogManifest {
                    publication_sequence: 1,
                    ..manifest()
                },
            ),
            (
                "changed",
                CatalogManifest {
                    publication_sequence: 2,
                    version: "other".to_string(),
                    ..manifest()
                },
            ),
            (
                "already used",
                CatalogManifest {
                    publication_sequence: 3,
                    ..manifest()
                },
            ),
            (
                "already used",
                CatalogManifest {
                    publication_sequence: 3,
                    version_id: "agent-stream:1.0.2".to_string(),
                    ..manifest()
                },
            ),
        ] {
            let error = validate_history(Some(&current), &candidate, &seen).unwrap_err();
            assert!(error.contains(expected), "{expected}: {error}");
        }
    }

    #[test]
    fn outcomes_have_distinct_metric_labels() {
        for (kind, expected) in [
            (RefreshFailureKind::Transport, "transport_failure"),
            (RefreshFailureKind::Validation, "validation_failure"),
            (RefreshFailureKind::Rollback, "rollback_rejection"),
            (RefreshFailureKind::HashMismatch, "hash_mismatch"),
            (RefreshFailureKind::Storage, "storage_failure"),
        ] {
            assert_eq!(result_label(&Err(RefreshFailure::new(kind, "test"))), expected);
        }
        assert_eq!(result_label(&Ok(RefreshOutcome::Unchanged { manifest: manifest() })), "unchanged");
    }

    #[test]
    fn a_corrupt_refresh_record_fails_closed() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory
            .path()
            .join("llm_catalog_refresh.json");
        assert!(
            load_state(&path)
                .unwrap()
                .manifest
                .is_none()
        );
        std::fs::write(&path, "{").unwrap();
        assert_eq!(
            load_state(&path)
                .err()
                .map(|f| f.kind),
            Some(RefreshFailureKind::Storage)
        );
    }
}
