//! Embedder client for the semantic response cache.
//!
//! Vectorises a request's natural-language text by calling an OpenAI-compatible
//! `/v1/embeddings` endpoint, so the [`crate::pipes::response_cache`] can match
//! semantically-similar requests. Kept separate from the main executor because
//! it runs *before* the executor (on the request-side of the handler) and has
//! no dependency on the surface's own provider.

use std::sync::OnceLock;

use dashmap::DashMap;
use futures::StreamExt;
use serde_json::{Value, json};

use crate::pipes::config::CacheEmbedder;
use crate::secrets::SurfaceSecrets;

/// Request timeout for a single embed call. Kept short because the embed sits on
/// the request hot path (every semantic-cache request pays it, hit or miss), so
/// a slow embedder must not stall callers for long.
const EMBED_TIMEOUT_SECS: u64 = 5;

/// Hard cap on the embedder response body. A misbehaving or compromised embedder
/// cannot make the gateway buffer an unbounded response.
const MAX_EMBED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

/// Consecutive failures before the per-endpoint breaker opens.
const BREAKER_FAILURE_THRESHOLD: u32 = 3;

/// How long the breaker stays open after tripping, before a probe is allowed.
const BREAKER_COOLDOWN_SECS: i64 = 30;

/// Per-endpoint failure state for the lightweight embedder circuit breaker.
#[derive(Default)]
struct BreakerState {
    consecutive_failures: u32,
    /// Unix seconds until which the breaker is open (`0` = closed).
    open_until: i64,
}

/// Process-wide embedder breakers, keyed by endpoint URL.
static EMBEDDER_BREAKERS: OnceLock<DashMap<String, BreakerState>> = OnceLock::new();

fn breakers() -> &'static DashMap<String, BreakerState> {
    EMBEDDER_BREAKERS.get_or_init(DashMap::new)
}

/// Whether the breaker for `endpoint` is currently open, so the embed should be
/// skipped (degrading to a cache miss) without a network round trip.
fn breaker_open(endpoint: &str) -> bool {
    let now = chrono::Utc::now().timestamp();
    breakers()
        .get(endpoint)
        .map(|s| s.open_until > now)
        .unwrap_or(false)
}

/// Reset the breaker after a healthy round trip.
fn record_success(endpoint: &str) {
    if let Some(mut state) = breakers().get_mut(endpoint) {
        state.consecutive_failures = 0;
        state.open_until = 0;
    }
}

/// Record a transport/HTTP failure; open the breaker once the threshold is hit.
fn record_failure(endpoint: &str) {
    let now = chrono::Utc::now().timestamp();
    let mut state = breakers()
        .entry(endpoint.to_string())
        .or_default();
    state.consecutive_failures = state
        .consecutive_failures
        .saturating_add(1);
    if state.consecutive_failures >= BREAKER_FAILURE_THRESHOLD {
        state.open_until = now + BREAKER_COOLDOWN_SECS;
    }
}

/// Why an embedding was not produced.
#[derive(Debug, Clone, PartialEq)]
pub enum EmbedError {
    /// The embedder sends a platform key and the request's budget is spent
    /// (see [`crate::teams::call_budget`]). No call was made. The caller skips
    /// the work and counts it with [`crate::teams::call_budget::record_skip`].
    BudgetRefused(String),
    /// Any other failure: the caller degrades as on any embedder error.
    Failed(String),
}

impl std::fmt::Display for EmbedError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::BudgetRefused(reason) => write!(f, "budget spent: {reason}"),
            Self::Failed(reason) => f.write_str(reason),
        }
    }
}

impl From<String> for EmbedError {
    fn from(reason: String) -> Self {
        Self::Failed(reason)
    }
}

/// Embed `text` with the configured embedder, returning the embedding vector.
///
/// Resolves the embedder's API key from the secrets store (internal id first,
/// then public `secret_id`), SSRF-guards the endpoint, POSTs
/// `{ model, input: text }`, and parses `data[0].embedding`. Errors are
/// returned as strings so the caller can degrade to a cache miss without
/// failing the request.
///
/// A short timeout, a bounded response read, and a per-endpoint circuit breaker
/// keep a slow, oversized, or failing embedder from stalling the request path:
/// after repeated failures the breaker opens and subsequent calls fail fast
/// (returning `Err`, i.e. a cache miss) until a cooldown elapses.
///
/// An embedder on a platform key is refused before it is called when the
/// request's budget is spent ([`EmbedError::BudgetRefused`]).
pub async fn embed_text(
    embedder: &CacheEmbedder,
    text: &str,
    secrets: &SurfaceSecrets,
) -> Result<Vec<f32>, EmbedError> {
    crate::url_validation::validate_service_endpoint_url(&embedder.endpoint_url).await?;

    if breaker_open(&embedder.endpoint_url) {
        return Err(EmbedError::Failed("embedder circuit breaker open (recent failures)".to_string()));
    }

    let api_key = resolve_api_key(embedder, secrets).await?;

    let body = json!({ "model": embedder.model, "input": text });
    let payload = serde_json::to_vec(&body).map_err(|e| format!("failed to serialize embedder request: {e}"))?;

    let client = crate::http_client::with_service_endpoint_resolver(std::time::Duration::from_secs(EMBED_TIMEOUT_SECS))
        .map_err(|e| format!("failed to build embedder HTTP client: {e}"))?;
    let mut request = client
        .post(&embedder.endpoint_url)
        .header("Content-Type", "application/json")
        .body(payload);
    if let Some(key) = api_key.as_ref() {
        request = request.bearer_auth(key);
    }

    let response = match request.send().await {
        Ok(response) => response,
        Err(e) => {
            record_failure(&embedder.endpoint_url);
            return Err(EmbedError::Failed(format!("embedder request failed: {e}")));
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        record_failure(&embedder.endpoint_url);
        return Err(EmbedError::Failed(format!("embedder returned HTTP {status}")));
    }

    let bytes = match read_bounded(response, MAX_EMBED_RESPONSE_BYTES).await {
        Ok(bytes) => bytes,
        Err(e) => {
            record_failure(&embedder.endpoint_url);
            return Err(EmbedError::Failed(e));
        }
    };

    // A healthy round trip (2xx within size bounds) closes the breaker. A parse
    // failure below is a schema problem, not an endpoint-health problem, so it
    // does not re-open the breaker.
    record_success(&embedder.endpoint_url);

    let value: Value = serde_json::from_slice(&bytes).map_err(|e| format!("failed to parse embedder response: {e}"))?;

    Ok(parse_embedding(&value)?)
}

/// Read a response body into memory, failing if it exceeds `max` bytes.
async fn read_bounded(
    response: reqwest::Response,
    max: usize,
) -> Result<Vec<u8>, String> {
    let mut stream = response.bytes_stream();
    let mut buf: Vec<u8> = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|e| format!("embedder response read failed: {e}"))?;
        if buf.len() + chunk.len() > max {
            return Err(format!("embedder response exceeded {max} bytes"));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// Resolve the embedder's API key from the secrets store, if configured, and
/// refuse the call when its key is a platform key and the request's budget is
/// spent. A keyless embedder is never refused.
async fn resolve_api_key(
    embedder: &CacheEmbedder,
    secrets: &SurfaceSecrets,
) -> Result<Option<String>, EmbedError> {
    // The resolution the save-time tenancy check uses, re-checked against the
    // surface's tenant, so only a secret the surface may use is ever sent. An
    // embedder never sends the caller's key, only its own.
    let key = match embedder
        .api_key_secret
        .as_ref()
    {
        Some(secret_id) => {
            crate::pipes::key_source::resolve_call_key(crate::pipes::key_source::CallerKey::NotOffered, || {
                secrets.resolve_key(secret_id)
            })
            .await
            .map_err(|e| format!("failed to load cache embedder API key: {e}"))?
        }
        None => None,
    };
    let source = crate::pipes::key_source::call_key_source(
        key.as_ref()
            .map(|key| key.source),
        None,
    );
    tracing::debug!(key_source = source.as_str(), "cache embedder key resolved");
    // A keyless embedder tracks no cost and spends no operator credential, so
    // it is never refused for budget.
    if key.is_some()
        && let Some(reason) = crate::teams::call_budget::refusal(source).await
    {
        return Err(EmbedError::BudgetRefused(reason));
    }
    Ok(key.map(|key| key.value))
}

/// Parse `data[0].embedding` from an OpenAI-compatible embeddings response into
/// a `Vec<f32>`.
fn parse_embedding(value: &Value) -> Result<Vec<f32>, String> {
    let array = value
        .get("data")
        .and_then(|d| d.as_array())
        .and_then(|d| d.first())
        .and_then(|entry| entry.get("embedding"))
        .and_then(|embedding| embedding.as_array())
        .ok_or_else(|| "embedder response missing data[0].embedding".to_string())?;

    array
        .iter()
        .map(|component| {
            component
                .as_f64()
                .map(|f| f as f32)
                .ok_or_else(|| "embedding component is not a number".to_string())
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn parses_embedding_vector() {
        let response = json!({
            "object": "list",
            "data": [{ "object": "embedding", "index": 0, "embedding": [0.1, 0.2, 0.3] }],
            "model": "text-embedding-3-small",
            "usage": { "prompt_tokens": 4, "total_tokens": 4 }
        });
        let embedding = parse_embedding(&response).expect("parses");
        assert_eq!(embedding.len(), 3);
        assert!((embedding[1] - 0.2).abs() < 1e-6);
    }

    #[test]
    fn rejects_response_without_embedding() {
        let response = json!({ "data": [] });
        assert!(parse_embedding(&response).is_err());
    }

    #[test]
    fn breaker_opens_after_threshold_failures() {
        let endpoint = "https://embedder.test/breaker-open";
        assert!(!breaker_open(endpoint));
        for _ in 0..BREAKER_FAILURE_THRESHOLD {
            record_failure(endpoint);
        }
        assert!(breaker_open(endpoint), "breaker must open at the failure threshold");
    }

    #[test]
    fn breaker_stays_closed_below_threshold() {
        let endpoint = "https://embedder.test/breaker-below";
        for _ in 0..(BREAKER_FAILURE_THRESHOLD - 1) {
            record_failure(endpoint);
        }
        assert!(!breaker_open(endpoint), "breaker must stay closed below the threshold");
    }

    #[test]
    fn success_resets_breaker() {
        let endpoint = "https://embedder.test/breaker-reset";
        for _ in 0..BREAKER_FAILURE_THRESHOLD {
            record_failure(endpoint);
        }
        assert!(breaker_open(endpoint));
        record_success(endpoint);
        assert!(!breaker_open(endpoint), "a success must close the breaker");
    }
}
