//! Unified source authentication middleware
//!
//! [`SourceAuthMiddleware`] is the single integration point called by every request
//! handler that needs source authentication. It dispatches to the appropriate
//! authentication backend based on the channel's `SourceAuthConfig`.

use std::sync::Arc;

use axum::http::HeaderMap;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tracing::{debug, error, info};

use crate::api_keys::ApiKeyValidator;
use crate::certificates::CertificateStore;
use crate::jwt_bearer::{
    JwksClient, JwtBearerVerifier, JwtVerificationStrategyStorage, errors::JwtBearerError, models::JwtBearerAuthConfig,
};
use crate::secrets::SecretsStore;
use crate::secrets::{SecretsCache, get_cached_secret};
use crate::source_auth::errors::{SourceAuthError, SourceAuthResult};
use crate::source_auth::models::{AuthenticatedIdentity, CredentialExtraction, PeerCertInfo, SourceAuthConfig};
use crate::source_auth::mtls::{ResolvedTrustMaterial, TrustEntry, verify_peer_cert};

/// Per-cert cache entry: PEM-decoded DER bytes + SHA-256 fingerprint,
/// keyed by the certificate's `updated_at` timestamp so that out-of-band
/// edits self-invalidate without an explicit cache flush.
#[derive(Clone)]
struct CachedTrustEntry {
    updated_at: DateTime<Utc>,
    der: Arc<Vec<u8>>,
    fingerprint: [u8; 32],
}

/// Unified source authentication gate.
///
/// Holds references to all authentication backends and dispatches based on
/// the channel's `SourceAuthConfig`.
#[derive(Clone)]
pub struct SourceAuthMiddleware {
    jwt_strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
    jwt_verifier: Arc<JwtBearerVerifier>,
    secrets_store: Option<Arc<dyn SecretsStore>>,
    secrets_cache: SecretsCache,
    api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
    cert_store: Option<Arc<dyn CertificateStore>>,
    /// Per-cert cache for mTLS trust material; see [`CachedTrustEntry`].
    trust_cache: Arc<DashMap<String, CachedTrustEntry>>,
}

impl SourceAuthMiddleware {
    /// Create a new middleware instance.
    pub fn new(
        jwt_strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
        jwks_client: Arc<JwksClient>,
        secrets_store: Option<Arc<dyn SecretsStore>>,
        secrets_cache: SecretsCache,
        api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        cert_store: Option<Arc<dyn CertificateStore>>,
    ) -> Self {
        let jwt_verifier = Arc::new(JwtBearerVerifier::new(jwks_client));
        Self {
            jwt_strategy_store,
            jwt_verifier,
            secrets_store,
            secrets_cache,
            api_key_validator,
            cert_store,
            trust_cache: Arc::new(DashMap::new()),
        }
    }

    /// Return the underlying JWT strategy store (used by the CRUD router).
    pub fn provider_store(&self) -> Arc<dyn JwtVerificationStrategyStorage> {
        Arc::clone(&self.jwt_strategy_store)
    }

    /// Return the underlying JWKS client (used by the validate-jwks-uri endpoint).
    pub fn jwks_client(&self) -> Arc<JwksClient> {
        Arc::clone(
            &self
                .jwt_verifier
                .jwks_client(),
        )
    }

    /// Authenticate an inbound request against the given source auth configuration.
    ///
    /// Dispatches to the appropriate backend and returns the authenticated identity.
    ///
    /// `owner_tenant_id` is the tenant of the surface being called: an API-key
    /// secret must be one that tenant may reference. `peer_cert` is the
    /// (optional) client certificate captured by the listener layer. Required
    /// for mTLS auth; ignored otherwise.
    pub async fn authenticate(
        &self,
        config: &SourceAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
        owner_tenant_id: Option<&str>,
        peer_cert: Option<&PeerCertInfo>,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        match config {
            SourceAuthConfig::JwtBearer(jwt_config) => {
                self.authenticate_jwt_bearer(jwt_config, headers, channel_name)
                    .await
            }
            SourceAuthConfig::ApiKey(apikey_config) => {
                self.authenticate_apikey(apikey_config, headers, channel_name, owner_tenant_id)
                    .await
            }
            SourceAuthConfig::ApiKeyProvider(provider_config) => {
                self.authenticate_apikey_provider(provider_config, headers, channel_name)
                    .await
            }
            SourceAuthConfig::Mtls(mtls_config) => {
                self.authenticate_mtls(mtls_config, peer_cert, channel_name)
                    .await
            }
        }
    }

    /// Whether `candidate` is a credential this front door accepts: the one the
    /// request presented in the header `config` reads (see
    /// [`SourceAuthConfig::presents_credential`]), or, for API-key auth, any
    /// key of its secret. Such a value is never sent upstream as the caller's
    /// provider key. A secret that cannot be loaded counts as a match, so the
    /// value is withheld.
    pub async fn is_front_door_credential(
        &self,
        config: &SourceAuthConfig,
        headers: &HeaderMap,
        owner_tenant_id: Option<&str>,
        candidate: &str,
    ) -> bool {
        if config.presents_credential(headers, candidate) {
            return true;
        }
        let SourceAuthConfig::ApiKey(apikey_config) = config else {
            return false;
        };
        match get_cached_secret(&apikey_config.secret_id, owner_tenant_id, &self.secrets_store, &self.secrets_cache)
            .await
        {
            Ok(valid_keys) => valid_keys
                .iter()
                .any(|valid| constant_time_compare(candidate, valid)),
            Err(_) => true,
        }
    }

    // ── JWT Bearer ──────────────────────────────────────────────────────────

    async fn authenticate_jwt_bearer(
        &self,
        config: &JwtBearerAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        // 1. Extract bearer token from the configured header / scheme
        let header_value = headers
            .get(config.token_header.as_str())
            .and_then(|v| v.to_str().ok());
        let token = crate::jwt_bearer::validator::extract_bearer_with_scheme(header_value, &config.token_scheme)
            .map_err(SourceAuthError::from)?;

        // 2. Resolve strategy
        let jwt_strategy = self
            .jwt_strategy_store
            .get(&config.jwt_verification_strategy_id)
            .await
            .map_err(|e| JwtBearerError::Storage(e.to_string()))
            .map_err(SourceAuthError::from)?
            .ok_or_else(|| {
                SourceAuthError::from(JwtBearerError::StrategyNotFound(
                    config
                        .jwt_verification_strategy_id
                        .clone(),
                ))
            })?;

        // 3. Verify
        let claims = self
            .jwt_verifier
            .validate_with_audience_policy(token, &jwt_strategy, &config.audiences, config.allow_missing_audience)
            .await
            .map_err(SourceAuthError::from)?;

        let subject = claims
            .get("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("<none>")
            .to_string();

        info!(
            surface = %channel_name,
            subject = %subject,
            "JWT Bearer source authentication succeeded"
        );

        Ok(AuthenticatedIdentity::JwtBearer { subject, claims })
    }

    // ── API Key (SecretsStore) ─────────────────────────────────────────────

    async fn authenticate_apikey(
        &self,
        config: &crate::source_auth::models::ApiKeyAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
        owner_tenant_id: Option<&str>,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        let key_value =
            extract_credential(&config.extraction, headers).ok_or_else(|| SourceAuthError::MissingCredential {
                reason: "API key not found in request".to_string(),
            })?;

        let valid_keys =
            get_cached_secret(&config.secret_id, owner_tenant_id, &self.secrets_store, &self.secrets_cache)
                .await
                .map_err(|e| SourceAuthError::Internal {
                    reason: format!("Failed to load API key secret: {e}"),
                })?;

        for valid in &valid_keys {
            if constant_time_compare(&key_value, valid) {
                info!(
                    surface = %channel_name,
                    secret_id = %config.secret_id,
                    "API Key source authentication succeeded"
                );
                return Ok(AuthenticatedIdentity::ApiKey {
                    key_name: config.secret_id.clone(),
                });
            }
        }

        Err(SourceAuthError::InvalidCredential {
            reason: "API key not found or inactive".to_string(),
        })
    }

    // ── API Key Provider ────────────────────────────────────────────────────

    async fn authenticate_apikey_provider(
        &self,
        config: &crate::source_auth::models::ApiKeyProviderAuthConfig,
        headers: &HeaderMap,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        let key_value =
            extract_credential(&config.extraction, headers).ok_or_else(|| SourceAuthError::MissingCredential {
                reason: "API key not found in request".to_string(),
            })?;

        let store = self
            .api_key_validator
            .as_ref()
            .ok_or_else(|| SourceAuthError::Internal {
                reason: "API Key Provider not configured".to_string(),
            })?;

        match store
            .validate(&config.agent_id, &key_value)
            .await
        {
            Ok(Some(meta)) => {
                info!(
                    surface = %channel_name,
                    agent_id = %config.agent_id,
                    key_id = %meta.key_id,
                    "API Key Provider source authentication succeeded"
                );
                Ok(AuthenticatedIdentity::ApiKey { key_name: meta.key_id })
            }
            Ok(None) => {
                debug!(channel = %channel_name, agent_id = %config.agent_id, "API key not found or revoked");
                Err(SourceAuthError::InvalidCredential {
                    reason: "API key not found or revoked".to_string(),
                })
            }
            Err(e) => {
                error!(channel = %channel_name, agent_id = %config.agent_id, error = %e, "API key validation failed");
                Err(SourceAuthError::Internal {
                    reason: format!("API key validation failed: {e}"),
                })
            }
        }
    }

    // ── mTLS ────────────────────────────────────────────────────────────────

    async fn authenticate_mtls(
        &self,
        config: &crate::source_auth::models::MtlsAuthConfig,
        peer_cert: Option<&PeerCertInfo>,
        channel_name: &str,
    ) -> SourceAuthResult<AuthenticatedIdentity> {
        // The listener layer must have captured a peer certificate (direct
        // TLS handshake or trusted forwarded-cert header). If none is
        // present, surface a credential-missing error rather than an
        // internal error so the caller returns 401.
        let Some(peer) = peer_cert else {
            debug!(channel = %channel_name, "mTLS auth required but no client certificate was presented");
            track_mtls_failure(channel_name, "missing_cert");
            return Err(SourceAuthError::MissingCredential {
                reason: "Client certificate not presented".to_string(),
            });
        };

        let cert_store = self
            .cert_store
            .as_ref()
            .ok_or_else(|| SourceAuthError::Internal {
                reason: "mTLS auth configured but certificate store is unavailable".to_string(),
            })?;

        // Resolve the certificate IDs referenced by the trust config into
        // pre-hashed [`TrustEntry`] values. Hot path is a DashMap lookup;
        // PEM decode + SHA-256 happen at most once per (cert_id, updated_at).
        let (pinned, ca) = match &config.trust {
            crate::source_auth::models::MtlsTrust::Pinned { certificate_ids } => {
                let entries = self
                    .resolve_trust_entries(cert_store.as_ref(), certificate_ids)
                    .await?;
                (entries, Vec::new())
            }
            crate::source_auth::models::MtlsTrust::Ca { ca_certificate_ids, .. } => {
                let entries = self
                    .resolve_trust_entries(cert_store.as_ref(), ca_certificate_ids)
                    .await?;
                (Vec::new(), entries)
            }
        };

        let trust = ResolvedTrustMaterial { pinned: &pinned, ca: &ca };

        match verify_peer_cert(peer, config, trust, std::time::SystemTime::now()) {
            Ok(identity) => {
                if let AuthenticatedIdentity::Mtls {
                    principal, fingerprint, source, ..
                } = &identity
                {
                    info!(
                        surface = %channel_name,
                        principal = %principal,
                        fingerprint = %fingerprint,
                        source = %source,
                        "mTLS source authentication succeeded"
                    );
                    track_mtls_success(channel_name, *source);
                }
                Ok(identity)
            }
            Err(e) => {
                debug!(
                    surface = %channel_name,
                    error = %e,
                    "mTLS source authentication failed"
                );
                track_mtls_failure(channel_name, mtls_failure_reason(&e));
                Err(e)
            }
        }
    }

    /// Resolve a list of certificate IDs against the store, returning
    /// pre-decoded DER + pre-computed SHA-256 fingerprint per cert.
    /// Inactive certs are treated as missing. Uses the internal
    /// [`Self::trust_cache`] keyed by `cert.updated_at` to avoid
    /// re-parsing PEM on every request.
    async fn resolve_trust_entries(
        &self,
        store: &dyn CertificateStore,
        ids: &[String],
    ) -> SourceAuthResult<Vec<TrustEntry>> {
        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            let cert = store
                .get(id)
                .await
                .map_err(|e| SourceAuthError::Internal {
                    reason: format!("Failed to load certificate '{id}': {e}"),
                })?
                .ok_or_else(|| SourceAuthError::ConfigNotFound { id: id.clone() })?;
            if !cert.active {
                return Err(SourceAuthError::ConfigNotFound { id: id.clone() });
            }

            // Cache hit: same updated_at as what we have.
            if let Some(existing) = self.trust_cache.get(id)
                && existing.updated_at == cert.updated_at
            {
                out.push(TrustEntry {
                    id: id.clone(),
                    der: Arc::clone(&existing.der),
                    fingerprint: existing.fingerprint,
                });
                continue;
            }

            // Miss or stale: decode + hash, populate cache.
            let der = decode_pem_certificate(
                cert.certificate_pem
                    .as_bytes(),
            )
            .map_err(|e| SourceAuthError::Internal {
                reason: format!("Failed to decode certificate '{id}': {e}"),
            })?;
            let mut hasher = Sha256::new();
            hasher.update(&der);
            let fingerprint: [u8; 32] = hasher.finalize().into();
            let der_arc = Arc::new(der);
            self.trust_cache.insert(
                id.clone(),
                CachedTrustEntry {
                    updated_at: cert.updated_at,
                    der: Arc::clone(&der_arc),
                    fingerprint,
                },
            );
            out.push(TrustEntry {
                id: id.clone(),
                der: der_arc,
                fingerprint,
            });
        }
        Ok(out)
    }
}

/// Decode the first CERTIFICATE block from PEM bytes into DER.
fn decode_pem_certificate(pem_bytes: &[u8]) -> Result<Vec<u8>, String> {
    let (_, parsed) = x509_parser::pem::parse_x509_pem(pem_bytes).map_err(|e| format!("PEM parse error: {e}"))?;
    if parsed.label != "CERTIFICATE" {
        return Err(format!("Expected PEM tag 'CERTIFICATE', got '{}'", parsed.label));
    }
    Ok(parsed.contents)
}

/// Map a [`SourceAuthError`] returned by mTLS verification to a low-
/// cardinality label suitable for the `reason` metric label.
fn mtls_failure_reason(err: &SourceAuthError) -> &'static str {
    match err {
        SourceAuthError::MissingCredential { .. } => "missing_cert",
        SourceAuthError::InvalidCredential { reason } => {
            if reason.contains("chain verification") {
                "chain_invalid"
            } else if reason.contains("pinned") {
                "pinned_mismatch"
            } else if reason.contains("allowed_subjects") {
                "not_allowed"
            } else if reason.contains("Forwarded") {
                "forwarded_disallowed"
            } else if reason.contains("EKU") {
                "missing_eku"
            } else if reason.contains("identity binding") {
                "binding_failed"
            } else {
                "invalid_cert"
            }
        }
        SourceAuthError::ConfigNotFound { .. } => "trust_misconfigured",
        SourceAuthError::Internal { .. } => "internal_error",
    }
}

fn track_mtls_success(
    channel_name: &str,
    source: crate::source_auth::models::PeerCertSource,
) {
    crate::metrics::backends::prometheus::_track_auth_attempt(channel_name, "mtls", source.as_str());
}

fn track_mtls_failure(
    channel_name: &str,
    reason: &str,
) {
    crate::metrics::backends::prometheus::_track_auth_attempt(channel_name, "mtls", "failure");
    crate::metrics::backends::prometheus::_track_auth_failure(channel_name, "mtls", reason);
}

// ── Credential extraction helper ────────────────────────────────────────────

/// Extract a credential string from the request based on the extraction configuration.
fn extract_credential(
    extraction: &CredentialExtraction,
    headers: &HeaderMap,
) -> Option<String> {
    match extraction {
        CredentialExtraction::HttpHeader { field } => headers
            .get(field.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string()),
        // `McpMeta` and `A2aExtension` require body parsing, which this
        // helper does not perform.
        CredentialExtraction::McpMeta | CredentialExtraction::A2aExtension => None,
    }
}

fn constant_time_compare(
    left: &str,
    right: &str,
) -> bool {
    left.as_bytes()
        .ct_eq(right.as_bytes())
        .into()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_keys::{ApiKeyIssuer, ApiKeyMeta, ApiKeyResult, ApiKeyStatus};
    use crate::jwt_bearer::{
        JwksClient,
        models::{JwksSource, JwtBearerAuthConfig, JwtVerificationStrategy},
        storage::JwtVerificationStrategyStorage,
        test_utils::start_jwks_server,
    };
    use crate::secrets::Secret;
    use crate::source_auth::errors::SourceAuthError;
    use crate::source_auth::models::*;
    use async_trait::async_trait;
    use axum::http::{HeaderMap, HeaderValue};
    use chrono::Utc;
    use dashmap::DashMap;
    use jsonwebtoken::{Algorithm, EncodingKey, Header as JwtHeader, encode};
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::sync::RwLock;

    // ── In-memory Secrets Store ─────────────────────────────────────────────

    struct InMemorySecretsStore {
        secrets: RwLock<HashMap<String, Secret>>,
    }

    impl InMemorySecretsStore {
        fn new() -> Self {
            Self {
                secrets: RwLock::new(HashMap::new()),
            }
        }

        async fn add_secret(
            &self,
            secret_id: &str,
            value: &str,
        ) {
            let secret = Secret {
                id: uuid::Uuid::new_v4().to_string(),
                name: secret_id.to_string(),
                secret_id: secret_id.to_string(),
                description: None,
                value: value.to_string(),
                secret_type: "ApiKey".to_string(),
                tags: vec![],
                tenant_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };
            self.secrets
                .write()
                .await
                .insert(secret_id.to_string(), secret);
        }
    }

    #[async_trait]
    impl SecretsStore for InMemorySecretsStore {
        async fn list_all(&self) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            Ok(self
                .secrets
                .read()
                .await
                .values()
                .cloned()
                .map(Into::into)
                .collect())
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .secrets
                .read()
                .await
                .get(id)
                .cloned())
        }
        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            Ok(self
                .secrets
                .read()
                .await
                .get(secret_id)
                .cloned())
        }
        async fn create(
            &self,
            _request: crate::secrets::CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn update(
            &self,
            _id: &str,
            _request: crate::secrets::UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> anyhow::Result<()> {
            unimplemented!()
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> anyhow::Result<Vec<crate::secrets::SecretListItem>> {
            unimplemented!()
        }
    }

    // ── In-memory API Key Validator ─────────────────────────────────────────

    struct InMemoryApiKeyValidator {
        keys: RwLock<HashMap<(String, String), ApiKeyMeta>>,
    }

    impl InMemoryApiKeyValidator {
        fn new() -> Self {
            Self {
                keys: RwLock::new(HashMap::new()),
            }
        }

        async fn add_key(
            &self,
            agent_id: &str,
            key_value: &str,
            key_id: &str,
        ) {
            let meta = ApiKeyMeta {
                key_id: key_id.to_string(),
                agent_id: agent_id.to_string(),
                client_id: "test-client".to_string(),
                status: ApiKeyStatus::Active,
                created_at: Utc::now(),
                expires_at: None,
                revoked_at: None,
                last_used_at: None,
                labels: HashMap::new(),
                issuer: ApiKeyIssuer {
                    actor: "test".to_string(),
                    method: "api".to_string(),
                },
                rotated_from: None,
                needs_rotation: false,
            };
            self.keys
                .write()
                .await
                .insert((agent_id.to_string(), key_value.to_string()), meta);
        }
    }

    #[async_trait]
    impl ApiKeyValidator for InMemoryApiKeyValidator {
        async fn validate(
            &self,
            agent_id: &str,
            presented_key: &str,
        ) -> ApiKeyResult<Option<ApiKeyMeta>> {
            Ok(self
                .keys
                .read()
                .await
                .get(&(agent_id.to_string(), presented_key.to_string()))
                .cloned())
        }
    }

    // ── In-memory JWT Strategy Store ────────────────────────────────────────

    struct InMemoryStrategyStore {
        strategies: RwLock<HashMap<String, JwtVerificationStrategy>>,
    }

    impl InMemoryStrategyStore {
        fn new() -> Self {
            Self {
                strategies: RwLock::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl JwtVerificationStrategyStorage for InMemoryStrategyStore {
        async fn create(
            &self,
            mut strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            strategy.id = uuid::Uuid::new_v4().to_string();
            self.strategies
                .write()
                .await
                .insert(strategy.id.clone(), strategy.clone());
            Ok(strategy)
        }
        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<JwtVerificationStrategy>> {
            Ok(self
                .strategies
                .read()
                .await
                .get(id)
                .cloned())
        }
        async fn list(&self) -> anyhow::Result<Vec<JwtVerificationStrategy>> {
            Ok(self
                .strategies
                .read()
                .await
                .values()
                .cloned()
                .collect())
        }
        async fn update(
            &self,
            strategy: JwtVerificationStrategy,
        ) -> anyhow::Result<JwtVerificationStrategy> {
            self.strategies
                .write()
                .await
                .insert(strategy.id.clone(), strategy.clone());
            Ok(strategy)
        }
        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.strategies
                .write()
                .await
                .remove(id);
            Ok(())
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn build_middleware(
        secrets_store: Option<Arc<dyn SecretsStore>>,
        api_key_validator: Option<Arc<dyn ApiKeyValidator>>,
        strategy_store: Arc<dyn JwtVerificationStrategyStorage>,
        jwks_client: Arc<JwksClient>,
    ) -> SourceAuthMiddleware {
        let secrets_cache: SecretsCache = Arc::new(DashMap::new());
        SourceAuthMiddleware::new(strategy_store, jwks_client, secrets_store, secrets_cache, api_key_validator, None)
    }

    fn default_jwks_client() -> Arc<JwksClient> {
        Arc::new(JwksClient::new(reqwest::Client::new()))
    }

    fn default_stores() -> (Arc<InMemorySecretsStore>, Arc<InMemoryStrategyStore>) {
        (Arc::new(InMemorySecretsStore::new()), Arc::new(InMemoryStrategyStore::new()))
    }

    // ── API Key (SecretsStore) tests ────────────────────────────────────────

    #[tokio::test]
    async fn valid_apikey_returns_apikey_identity() {
        let (secrets_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "secret-123")
            .await;

        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("secret-123"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string()
            }
        );
    }

    #[tokio::test]
    async fn valid_apikey_comma_separated_returns_apikey_identity() {
        let (secrets_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "key-a,key-b,key-c")
            .await;

        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("key-b"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "my-secret".to_string()
            }
        );
    }

    #[tokio::test]
    async fn a_front_door_credential_is_any_key_of_its_secret_or_the_presented_value() {
        let (secrets_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("project-key", "key-current,key-rotated")
            .await;
        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());
        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader {
                field: "X-Boris-Api-Key".to_string(),
            },
            secret_id: "project-key".to_string(),
        });
        let mut headers = HeaderMap::new();
        headers.insert("X-Boris-Api-Key", HeaderValue::from_static("key-current"));

        assert!(
            mw.is_front_door_credential(&config, &headers, None, "key-current")
                .await,
            "the presented key"
        );
        assert!(
            mw.is_front_door_credential(&config, &headers, None, "key-rotated")
                .await,
            "another key of the secret"
        );
        assert!(
            !mw.is_front_door_credential(&config, &headers, None, "sk-provider-key")
                .await,
            "a provider key"
        );

        let unknown = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader {
                field: "X-Boris-Api-Key".to_string(),
            },
            secret_id: "no-such-secret".to_string(),
        });
        assert!(
            mw.is_front_door_credential(&unknown, &HeaderMap::new(), None, "sk-provider-key")
                .await,
            "a secret that cannot be loaded withholds the key"
        );
    }

    #[tokio::test]
    async fn missing_apikey_header_returns_missing_credential() {
        let (secrets_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let headers = HeaderMap::new();
        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn invalid_apikey_returns_invalid_credential() {
        let (secrets_store, strategy_store) = default_stores();
        secrets_store
            .add_secret("my-secret", "secret-123")
            .await;

        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            secret_id: "my-secret".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("wrong-key"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    // ── API Key Provider tests ──────────────────────────────────────────────

    #[tokio::test]
    async fn valid_apikey_provider_returns_apikey_identity() {
        let (_, strategy_store) = default_stores();
        let validator = Arc::new(InMemoryApiKeyValidator::new());
        validator
            .add_key("agent-1", "provider-key-123", "key-id-1")
            .await;

        let mw = build_middleware(None, Some(validator), strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("provider-key-123"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let identity = result.expect("should succeed");
        assert_eq!(
            identity,
            AuthenticatedIdentity::ApiKey {
                key_name: "key-id-1".to_string()
            }
        );
    }

    #[tokio::test]
    async fn invalid_apikey_provider_returns_invalid_credential() {
        let (_, strategy_store) = default_stores();
        let validator = Arc::new(InMemoryApiKeyValidator::new());

        let mw = build_middleware(None, Some(validator), strategy_store, default_jwks_client());

        let config = SourceAuthConfig::ApiKeyProvider(ApiKeyProviderAuthConfig {
            extraction: CredentialExtraction::HttpHeader { field: "X-API-Key".to_string() },
            agent_id: "agent-1".to_string(),
        });

        let mut headers = HeaderMap::new();
        headers.insert("X-API-Key", HeaderValue::from_static("bad-key"));

        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    // ── mTLS test ───────────────────────────────────────────────────────────

    #[tokio::test]
    async fn mtls_missing_peer_cert_returns_missing_credential() {
        let (secrets_store, strategy_store) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, strategy_store, default_jwks_client());

        let config = SourceAuthConfig::Mtls(crate::source_auth::models::MtlsAuthConfig {
            trust: crate::source_auth::models::MtlsTrust::Pinned {
                certificate_ids: vec!["cert-1".to_string()],
            },
            identity_binding: crate::source_auth::models::MtlsIdentityBinding::Fingerprint,
            allowed_subjects: Vec::new(),
            allow_forwarded: true,
        });

        let headers = HeaderMap::new();
        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    // ── JWT Bearer tests ────────────────────────────────────────────────────

    // Ed25519 test key pair — PKCS#8 format
    // Generated with: openssl genpkey -algorithm ED25519
    const ED25519_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIPiOVQaSEcxl/NogGyUAX88ouBy1bWJFMp4gi0pcCgcY
-----END PRIVATE KEY-----";

    // Base64url-encoded 32-byte Ed25519 public key (the `x` component for JWK)
    const ED25519_JWK_X: &str = "xMjCoPwAtNcNFrwDLMlggNGrTdN0LAd_kxjJGWg8jZU";

    fn ed25519_jwks_body(
        kid: &str,
        x: &str,
    ) -> String {
        format!(
            r#"{{"keys":[{{"kty":"OKP","kid":"{kid}","use":"sig","alg":"EdDSA","crv":"Ed25519","x":"{x}"}}]}}"#,
            kid = kid,
            x = x,
        )
    }

    fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn make_token(
        claims: serde_json::Value,
        kid: &str,
    ) -> String {
        let mut header = JwtHeader::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());
        let key = EncodingKey::from_ed_pem(ED25519_PRIVATE_PEM.as_bytes()).unwrap();
        encode(&header, &claims, &key).unwrap()
    }

    fn bearer(token: &str) -> HeaderMap {
        let mut map = HeaderMap::new();
        map.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", token)).unwrap());
        map
    }

    async fn jwt_test_setup() -> (
        SourceAuthMiddleware,
        String, // strategy_id
        crate::jwt_bearer::test_utils::TestServer,
    ) {
        let kid = "source-auth-test-key";
        let (base, server) = start_jwks_server(ed25519_jwks_body(kid, ED25519_JWK_X), Some(3600)).await;

        let strategy_store = Arc::new(InMemoryStrategyStore::new());
        let strategy = strategy_store
            .create(JwtVerificationStrategy {
                id: String::new(),
                name: "Test EdDSA IdP".to_string(),
                expected_issuer: "https://issuer.example.com".to_string(),
                jwks_source: JwksSource::Remote {
                    jwks_uri: format!("{}/.well-known/jwks.json", base),
                },
                tenant_id: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            })
            .await
            .unwrap();

        let jwks_client = Arc::new(JwksClient::new(reqwest::Client::new()));
        let (secrets_store, _) = default_stores();

        let mw = build_middleware(Some(secrets_store), None, strategy_store, jwks_client);

        (mw, strategy.id, server)
    }

    #[tokio::test]
    async fn valid_jwt_returns_jwt_bearer_identity() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": exp,
                "iat": now_secs(),
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let identity = result.expect("should succeed");
        match identity {
            AuthenticatedIdentity::JwtBearer { subject, claims } => {
                assert_eq!(subject, "user-1");
                assert_eq!(
                    claims
                        .get("iss")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "https://issuer.example.com"
                );
                assert_eq!(
                    claims
                        .get("aud")
                        .unwrap()
                        .as_str()
                        .unwrap(),
                    "my-audience"
                );
            }
            other => panic!("expected JwtBearer identity, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_bearer_header_returns_missing_credential() {
        let (_mw, strategy_id, _server) = jwt_test_setup().await;

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = HeaderMap::new();
        let result = _mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::MissingCredential { .. }), "expected MissingCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn expired_jwt_returns_invalid_credential() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() - 3600, // expired 1 hour ago
                "iat": now_secs() - 7200,
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn unknown_strategy_returns_config_not_found() {
        let kid = "source-auth-test-key";
        let (mw, _strategy_id, _server) = jwt_test_setup().await;

        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-1",
                "aud": "my-audience",
                "exp": now_secs() + 3600,
                "iat": now_secs(),
            }),
            kid,
        );

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "nonexistent-strategy".to_string(),
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let headers = bearer(&token);
        let result = mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::ConfigNotFound { .. }), "expected ConfigNotFound, got: {err:?}");
    }

    #[tokio::test]
    async fn invalid_jwt_returns_invalid_credential() {
        let (_mw, strategy_id, _server) = jwt_test_setup().await;

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        let mut headers = HeaderMap::new();
        headers.insert(axum::http::header::AUTHORIZATION, HeaderValue::from_static("Bearer not.a.valid.jwt"));

        let result = _mw
            .authenticate(&config, &headers, "test-channel", None, None)
            .await;
        let err = result.expect_err("should fail");
        assert!(matches!(err, SourceAuthError::InvalidCredential { .. }), "expected InvalidCredential, got: {err:?}");
    }

    #[tokio::test]
    async fn authorization_header_value_preserved() {
        let kid = "source-auth-test-key";
        let (mw, strategy_id, _server) = jwt_test_setup().await;

        let exp = now_secs() + 3600;
        let token = make_token(
            json!({
                "iss": "https://issuer.example.com",
                "sub": "user-2",
                "aud": "my-audience",
                "exp": exp,
                "iat": now_secs(),
            }),
            kid,
        );
        let raw_header = format!("Bearer {}", token);
        let headers = bearer(&token);

        let config = SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: strategy_id,
            audiences: vec!["my-audience".to_string()],
            ..Default::default()
        });

        mw.authenticate(&config, &headers, "test-channel", None, None)
            .await
            .expect("should succeed");

        let forwarded = headers
            .get(axum::http::header::AUTHORIZATION)
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(forwarded, raw_header);
    }

    // ── Credential extraction unit tests ────────────────────────────────────

    #[test]
    fn extract_http_header_finds_value() {
        let mut headers = HeaderMap::new();
        headers.insert("X-Custom", HeaderValue::from_static("my-value"));

        let extraction = CredentialExtraction::HttpHeader { field: "X-Custom".to_string() };
        let result = extract_credential(&extraction, &headers);
        assert_eq!(result, Some("my-value".to_string()));
    }

    #[test]
    fn extract_http_header_returns_none_when_missing() {
        let headers = HeaderMap::new();

        let extraction = CredentialExtraction::HttpHeader { field: "X-Custom".to_string() };
        let result = extract_credential(&extraction, &headers);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_mcp_meta_returns_none() {
        let headers = HeaderMap::new();
        let result = extract_credential(&CredentialExtraction::McpMeta, &headers);
        assert_eq!(result, None);
    }

    #[test]
    fn extract_a2a_extension_returns_none() {
        let headers = HeaderMap::new();
        let result = extract_credential(&CredentialExtraction::A2aExtension, &headers);
        assert_eq!(result, None);
    }
}
