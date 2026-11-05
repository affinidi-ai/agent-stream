//! JWKS fetching and in-memory caching
//!
//! [`JwksClient`] fetches JSON Web Key Sets from a JWT verification strategy's JWKS URI,
//! caches them per strategy, and re-fetches when a token references a `kid` that
//! is not in the current cache.
//!
//! # Cache TTL
//! The TTL is taken from the `Cache-Control: max-age=N` response header.
//! When the header is absent, a default of **86 400 seconds (24 h)** is used.
//!
//! A `kid` missing from fresh keys causes at most one re-fetch per
//! [`UNKNOWN_KID_REFETCH_COOLDOWN`] for each cache entry, so tokens naming
//! made-up `kid` values cannot make every request fetch from the key server.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::jwt_bearer::errors::{JwtBearerError, JwtBearerResult};

async fn validate_jwks_fetch_url(raw: &str) -> Result<(), JwtBearerError> {
    crate::url_validation::validate_resolved_cloud_metadata_url(raw)
        .await
        .map(|_| ())
        .map_err(|e| JwtBearerError::JwksFetchFailed(format!("jwks_uri blocked: {}", e)))
}

/// Default JWKS cache TTL when no `Cache-Control: max-age` header is present.
const DEFAULT_TTL_SECS: u64 = 86_400;

/// The shortest time between two re-fetches caused by a `kid` that fresh keys
/// lack, so a rotated key is picked up within this long of its first use.
pub const UNKNOWN_KID_REFETCH_COOLDOWN: Duration = Duration::from_secs(60);

// ── JSON Web Key types ────────────────────────────────────────────────────────

/// A single JSON Web Key as returned by a JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Jwk {
    /// Key type, e.g. `"RSA"` or `"EC"`.
    pub kty: String,

    /// Key use, e.g. `"sig"`.
    #[serde(rename = "use", skip_serializing_if = "Option::is_none")]
    pub key_use: Option<String>,

    /// Key ID — used to match a token's `kid` header.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    /// Algorithm, e.g. `"RS256"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,

    // RSA parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub e: Option<String>,

    // EC parameters
    #[serde(skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
}

/// Response from a JWKS endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwksResponse {
    pub keys: Vec<Jwk>,
}

// ── Cache entry ───────────────────────────────────────────────────────────────

struct CacheEntry {
    /// Map of `kid` → `Jwk`.  Keys without a `kid` are stored under `""`.
    keys: HashMap<String, Jwk>,
    fetched_at: Instant,
    ttl: Duration,
    /// When this entry was fetched because fresh keys lacked a `kid`.
    unknown_kid_refetch_at: Option<Instant>,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.fetched_at.elapsed() > self.ttl
    }

    fn refetched_for_unknown_kid_recently(&self) -> bool {
        self.unknown_kid_refetch_at
            .is_some_and(|at| at.elapsed() < UNKNOWN_KID_REFETCH_COOLDOWN)
    }
}

// ── JwksClient ────────────────────────────────────────────────────────────────

/// Thread-safe JWKS client with per-strategy caching.
#[derive(Clone)]
pub struct JwksClient {
    http: reqwest::Client,
    /// strategy_id → cache entry
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
}

impl JwksClient {
    /// Create a new client using the supplied `reqwest::Client`.
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Fetch JWKS from `jwks_uri` without caching.
    ///
    /// Used by the `validate_jwks_uri` admin endpoint to probe whether a URI is
    /// reachable and returns a parseable JWKS.
    ///
    /// Returns the parsed [`JwksResponse`] on success, or a [`JwtBearerError::JwksFetchFailed`]
    /// on any HTTP or parse error.
    pub async fn fetch_jwks(
        &self,
        jwks_uri: &str,
    ) -> JwtBearerResult<JwksResponse> {
        validate_jwks_fetch_url(jwks_uri).await?;

        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;

        if !response.status().is_success() {
            return Err(JwtBearerError::JwksFetchFailed(format!("JWKS endpoint returned HTTP {}", response.status())));
        }

        response
            .json::<JwksResponse>()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(format!("Failed to parse JWKS: {}", e)))
    }

    /// Evict the cached JWKS for `strategy_id`.
    /// Should be called when a strategy is updated or deleted.
    /// FIXME: should be used in production code
    #[allow(dead_code)]
    pub async fn evict(
        &self,
        strategy_id: &str,
    ) {
        let mut cache = self.cache.write().await;
        if cache
            .remove(strategy_id)
            .is_some()
        {
            debug!("Evicted JWKS cache for strategy {}", strategy_id);
        }
    }

    /// Retrieve the JWK for the given `kid` from `strategy_id`'s JWKS.
    ///
    /// 1. If the cache is present and fresh, look up `kid` there.
    /// 2. If missing or expired, or if `kid` is not found, re-fetch once. A `kid`
    ///    that fresh keys lack re-fetches only when the entry was not itself
    ///    re-fetched for an unknown `kid` within [`UNKNOWN_KID_REFETCH_COOLDOWN`].
    /// 3. If `kid` is still absent after a re-fetch, return [`JwtBearerError::KeyNotFound`];
    ///    when the cooldown prevents the re-fetch, return
    ///    [`JwtBearerError::KeyNotFoundDuringCooldown`].
    pub async fn get_key(
        &self,
        strategy_id: &str,
        jwks_uri: &str,
        kid: &str,
    ) -> JwtBearerResult<Jwk> {
        // Fast path — read lock only
        let mut unknown_kid = false;
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(strategy_id) {
                if !entry.is_expired() {
                    if let Some(jwk) = entry.keys.get(kid) {
                        debug!("JWKS cache hit for strategy {} kid {}", strategy_id, kid);
                        return Ok(jwk.clone());
                    }
                    if entry.refetched_for_unknown_kid_recently() {
                        debug!("kid '{}' not found for strategy {}; re-fetched recently, not again", kid, strategy_id);
                        return Err(JwtBearerError::KeyNotFoundDuringCooldown(kid.to_string()));
                    }
                    unknown_kid = true;
                } else {
                    debug!("JWKS cache expired for strategy {}, re-fetching", strategy_id);
                }
            }
        }

        // Claim the unknown-kid re-fetch under the write lock before fetching,
        // so concurrent requests make one fetch between them and a failed
        // fetch still starts the cooldown.
        let mut unknown_kid_refetch_at = None;
        if unknown_kid {
            let mut cache = self.cache.write().await;
            if let Some(entry) = cache
                .get_mut(strategy_id)
                .filter(|entry| !entry.is_expired())
            {
                if let Some(jwk) = entry.keys.get(kid) {
                    return Ok(jwk.clone());
                }
                if entry.refetched_for_unknown_kid_recently() {
                    return Err(JwtBearerError::KeyNotFoundDuringCooldown(kid.to_string()));
                }
                debug!("kid '{}' not found in fresh cache for strategy {}, re-fetching", kid, strategy_id);
                let now = Instant::now();
                entry.unknown_kid_refetch_at = Some(now);
                unknown_kid_refetch_at = Some(now);
            }
        }

        // Slow path — re-fetch and write
        info!("Fetching JWKS for strategy {} from {}", strategy_id, jwks_uri);
        let mut entry = self
            .fetch_and_build_entry(jwks_uri)
            .await?;
        entry.unknown_kid_refetch_at = unknown_kid_refetch_at;

        let jwk = entry.keys.get(kid).cloned();

        {
            let mut cache = self.cache.write().await;
            cache.insert(strategy_id.to_string(), entry);
        }

        jwk.ok_or_else(|| JwtBearerError::KeyNotFound(kid.to_string()))
    }

    // ── private ───────────────────────────────────────────────────────────────

    async fn fetch_and_build_entry(
        &self,
        jwks_uri: &str,
    ) -> JwtBearerResult<CacheEntry> {
        validate_jwks_fetch_url(jwks_uri).await?;

        let response = self
            .http
            .get(jwks_uri)
            .send()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(e.to_string()))?;

        // Parse Cache-Control: max-age=N
        let ttl = parse_max_age(response.headers()).unwrap_or(DEFAULT_TTL_SECS);
        let ttl = Duration::from_secs(ttl);

        if !response.status().is_success() {
            return Err(JwtBearerError::JwksFetchFailed(format!("JWKS endpoint returned HTTP {}", response.status())));
        }

        let jwks: JwksResponse = response
            .json()
            .await
            .map_err(|e| JwtBearerError::JwksFetchFailed(format!("Failed to parse JWKS: {}", e)))?;

        let mut keys: HashMap<String, Jwk> = HashMap::new();
        for key in jwks.keys {
            let id = key
                .kid
                .clone()
                .unwrap_or_default();
            keys.insert(id, key);
        }

        debug!("Fetched {} key(s) from JWKS, TTL={:?}", keys.len(), ttl);

        Ok(CacheEntry {
            keys,
            fetched_at: Instant::now(),
            ttl,
            unknown_kid_refetch_at: None,
        })
    }
}

/// Parse `Cache-Control: max-age=N` from response headers.
/// Returns `None` if the header is absent or unparseable.
fn parse_max_age(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers
        .get(reqwest::header::CACHE_CONTROL)?
        .to_str()
        .ok()?;

    for directive in value.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=") {
            return rest
                .trim()
                .parse::<u64>()
                .ok();
        }
    }
    None
}

/// Look up a key by `kid` in a static (inline) JWKS slice.
///
/// Used by the validator when the strategy's `JwksSource` is `Static { jwks }`.
/// No HTTP request is made and no caching is performed — the keys are already
/// present in the strategy configuration.
///
/// # Errors
/// Returns [`JwtBearerError::KeyNotFound`] when no key with a matching `kid` exists.
pub fn get_static_key(
    jwks: &[Jwk],
    kid: &str,
) -> JwtBearerResult<Jwk> {
    jwks.iter()
        .find(|k| k.kid.as_deref() == Some(kid))
        .cloned()
        .ok_or_else(|| JwtBearerError::KeyNotFound(kid.to_string()))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use reqwest::header::{CACHE_CONTROL, HeaderMap, HeaderValue};

    // ── parse_max_age ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_max_age_present() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("public, max-age=3600"));
        assert_eq!(parse_max_age(&headers), Some(3600));
    }

    #[test]
    fn test_parse_max_age_only_value() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("max-age=7200"));
        assert_eq!(parse_max_age(&headers), Some(7200));
    }

    #[test]
    fn test_parse_max_age_absent() {
        let headers = HeaderMap::new();
        assert_eq!(parse_max_age(&headers), None);
    }

    #[test]
    fn test_parse_max_age_no_directive() {
        let mut headers = HeaderMap::new();
        headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store, no-cache"));
        assert_eq!(parse_max_age(&headers), None);
    }

    // ── CacheEntry expiry ─────────────────────────────────────────────────────

    #[test]
    fn test_cache_entry_not_expired_when_fresh() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now(),
            ttl: Duration::from_secs(3600),
            unknown_kid_refetch_at: None,
        };
        assert!(!entry.is_expired());
    }

    #[test]
    fn test_cache_entry_expired_with_zero_ttl() {
        let entry = CacheEntry {
            keys: HashMap::new(),
            fetched_at: Instant::now() - Duration::from_secs(1),
            ttl: Duration::from_secs(0),
            unknown_kid_refetch_at: None,
        };
        assert!(entry.is_expired());
    }

    // ── JwksClient with mock HTTP ─────────────────────────────────────────────
    // These tests use axum to spin up an in-process HTTP server.

    use crate::jwt_bearer::test_utils::{rsa_jwks_body, start_jwks_server};

    // Dummy RSA n/e — only used to exercise caching logic, not signature verification.
    const DUMMY_N: &str = "sIwr7ZNXUF0";
    const DUMMY_E: &str = "AQAB";

    #[tokio::test]
    async fn test_get_key_cache_miss_fetches_from_server() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        let jwk = client
            .get_key("provider-a", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn test_get_key_cache_hit_does_not_change_ttl() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        client
            .get_key("provider-b", &jwks_uri, "key-1")
            .await
            .unwrap();
        let ttl_after_first = {
            let cache = client.cache.read().await;
            cache
                .get("provider-b")
                .map(|e| e.ttl)
        };

        client
            .get_key("provider-b", &jwks_uri, "key-1")
            .await
            .unwrap();
        let ttl_after_second = {
            let cache = client.cache.read().await;
            cache
                .get("provider-b")
                .map(|e| e.ttl)
        };

        assert_eq!(ttl_after_first, ttl_after_second);
    }

    /// Serve `jwks_body` at `/.well-known/jwks.json`, counting the fetches.
    async fn counting_jwks_server(
        jwks_body: std::sync::Arc<std::sync::Mutex<String>>
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>, crate::jwt_bearer::test_utils::TestServer) {
        let fetches = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = fetches.clone();
        let app = axum::Router::new().route(
            "/.well-known/jwks.json",
            axum::routing::get(move || {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let body = jwks_body
                    .lock()
                    .unwrap()
                    .clone();
                async move { ([(axum::http::header::CONTENT_TYPE, "application/json")], body) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        (format!("http://{address}/.well-known/jwks.json"), fetches, crate::jwt_bearer::test_utils::TestServer(server))
    }

    #[tokio::test]
    async fn made_up_kids_refetch_at_most_once_per_cooldown_and_a_rotated_key_is_found() {
        let body = std::sync::Arc::new(std::sync::Mutex::new(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)));
        let (jwks_uri, fetches, _server) = counting_jwks_server(body.clone()).await;
        let client = JwksClient::new(reqwest::Client::new());
        client
            .get_key("provider-k", &jwks_uri, "key-1")
            .await
            .unwrap();

        *body.lock().unwrap() = rsa_jwks_body("key-2", DUMMY_N, DUMMY_E);
        client
            .get_key("provider-k", &jwks_uri, "key-2")
            .await
            .unwrap();
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 2, "the first new kid re-fetches");

        for made_up in ["made-up-1", "made-up-2", "made-up-3"] {
            let result = client
                .get_key("provider-k", &jwks_uri, made_up)
                .await;
            assert!(matches!(result, Err(JwtBearerError::KeyNotFoundDuringCooldown(_))), "{made_up}");
        }
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 2, "no re-fetch within the cooldown");
        client
            .get_key("provider-k", &jwks_uri, "key-2")
            .await
            .unwrap();

        client
            .cache
            .write()
            .await
            .get_mut("provider-k")
            .unwrap()
            .unknown_kid_refetch_at = Some(Instant::now() - UNKNOWN_KID_REFETCH_COOLDOWN);
        let _ = client
            .get_key("provider-k", &jwks_uri, "made-up-4")
            .await;
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 3, "after the cooldown one more re-fetch");
    }

    #[tokio::test]
    async fn concurrent_made_up_kids_make_one_refetch_between_them() {
        let body = std::sync::Arc::new(std::sync::Mutex::new(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)));
        let (jwks_uri, fetches, _server) = counting_jwks_server(body).await;
        let client = JwksClient::new(reqwest::Client::new());
        client
            .get_key("provider-c", &jwks_uri, "key-1")
            .await
            .unwrap();

        let lookups = (0..20).map(|index| {
            let client = client.clone();
            let jwks_uri = jwks_uri.clone();
            tokio::spawn(async move {
                client
                    .get_key("provider-c", &jwks_uri, &format!("made-up-{index}"))
                    .await
            })
        });
        for lookup in futures::future::join_all(lookups).await {
            assert!(matches!(
                lookup.unwrap(),
                Err(JwtBearerError::KeyNotFound(_) | JwtBearerError::KeyNotFoundDuringCooldown(_))
            ));
        }
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn a_failed_unknown_kid_refetch_still_starts_the_cooldown() {
        let body = std::sync::Arc::new(std::sync::Mutex::new(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E)));
        let (jwks_uri, fetches, _server) = counting_jwks_server(body.clone()).await;
        let client = JwksClient::new(reqwest::Client::new());
        client
            .get_key("provider-f", &jwks_uri, "key-1")
            .await
            .unwrap();

        *body.lock().unwrap() = "not a key set".to_string();
        assert!(matches!(
            client
                .get_key("provider-f", &jwks_uri, "made-up-1")
                .await,
            Err(JwtBearerError::JwksFetchFailed(_))
        ));
        assert!(matches!(
            client
                .get_key("provider-f", &jwks_uri, "made-up-2")
                .await,
            Err(JwtBearerError::KeyNotFoundDuringCooldown(_))
        ));
        assert_eq!(fetches.load(std::sync::atomic::Ordering::SeqCst), 2);
        client
            .get_key("provider-f", &jwks_uri, "key-1")
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn test_get_key_unknown_kid_returns_error() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        let result = client
            .get_key("provider-c", &jwks_uri, "missing-kid")
            .await;
        assert!(matches!(result, Err(JwtBearerError::KeyNotFound(_))));
    }

    #[tokio::test]
    async fn test_max_age_header_respected() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(1800)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        client
            .get_key("provider-d", &jwks_uri, "key-1")
            .await
            .unwrap();

        let cache = client.cache.read().await;
        let entry = cache
            .get("provider-d")
            .unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(1800));
    }

    #[tokio::test]
    async fn test_missing_max_age_defaults_to_24h() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), None).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        client
            .get_key("provider-e", &jwks_uri, "key-1")
            .await
            .unwrap();

        let cache = client.cache.read().await;
        let entry = cache
            .get("provider-e")
            .unwrap();
        assert_eq!(entry.ttl, Duration::from_secs(DEFAULT_TTL_SECS));
    }

    #[tokio::test]
    async fn test_expired_cache_triggers_refetch() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        {
            let mut cache = client.cache.write().await;
            cache.insert(
                "provider-f".to_string(),
                CacheEntry {
                    keys: HashMap::new(),
                    fetched_at: Instant::now() - Duration::from_secs(90_000),
                    ttl: Duration::from_secs(3600),
                    unknown_kid_refetch_at: None,
                },
            );
        }

        let jwk = client
            .get_key("provider-f", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert_eq!(jwk.kid.as_deref(), Some("key-1"));
    }

    #[tokio::test]
    async fn test_evict_removes_cache_entry() {
        let (base, _server) = start_jwks_server(rsa_jwks_body("key-1", DUMMY_N, DUMMY_E), Some(3600)).await;
        let jwks_uri = format!("{}/.well-known/jwks.json", base);
        let client = JwksClient::new(reqwest::Client::new());

        client
            .get_key("provider-g", &jwks_uri, "key-1")
            .await
            .unwrap();
        assert!(
            client
                .cache
                .read()
                .await
                .contains_key("provider-g")
        );

        client
            .evict("provider-g")
            .await;
        assert!(
            !client
                .cache
                .read()
                .await
                .contains_key("provider-g")
        );
    }

    // ── get_static_key ────────────────────────────────────────────────────────

    fn make_jwk(kid: &str) -> Jwk {
        Jwk {
            kty: "RSA".to_string(),
            key_use: Some("sig".to_string()),
            kid: Some(kid.to_string()),
            alg: Some("RS256".to_string()),
            n: Some("dummy-n".to_string()),
            e: Some("AQAB".to_string()),
            crv: None,
            x: None,
            y: None,
        }
    }

    #[test]
    fn test_get_static_key_returns_correct_key() {
        let jwks = vec![make_jwk("key-a"), make_jwk("key-b"), make_jwk("key-c")];

        let result = get_static_key(&jwks, "key-b");

        assert!(result.is_ok(), "should find key-b in the static JWKS");
        assert_eq!(result.unwrap().kid.as_deref(), Some("key-b"));
    }

    #[test]
    fn test_get_static_key_missing_kid_returns_key_not_found() {
        let jwks = vec![make_jwk("key-a"), make_jwk("key-b")];

        let result = get_static_key(&jwks, "key-z");

        assert!(
            matches!(result, Err(JwtBearerError::KeyNotFound(ref kid)) if kid == "key-z"),
            "should return KeyNotFound for an unknown kid, got: {:?}",
            result
        );
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_metadata_ip() {
        let client = JwksClient::new(reqwest::Client::new());
        let result = client
            .fetch_jwks("http://169.254.169.254/latest/meta-data/jwks.json")
            .await;
        assert!(matches!(result, Err(JwtBearerError::JwksFetchFailed(_))));
    }

    #[tokio::test]
    async fn fetch_jwks_rejects_embedded_credentials() {
        let client = JwksClient::new(reqwest::Client::new());
        let result = client
            .fetch_jwks("https://user:pass@example.com/jwks.json")
            .await;
        assert!(matches!(result, Err(JwtBearerError::JwksFetchFailed(_))));
    }

    #[tokio::test]
    async fn get_key_rejects_metadata_ip() {
        let client = JwksClient::new(reqwest::Client::new());
        let result = client
            .get_key("metadata", "http://169.254.170.2/v2/credentials/jwks.json", "kid")
            .await;
        assert!(matches!(result, Err(JwtBearerError::JwksFetchFailed(_))));
    }
}
