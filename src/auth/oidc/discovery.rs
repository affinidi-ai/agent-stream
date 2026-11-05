//! The provider's discovery document (`/.well-known/openid-configuration`).
//! It is fetched on first use and cached, so Agent Stream starts and serves
//! traffic while the provider is unreachable; only dashboard sign-in waits.

use std::sync::Arc;
use std::time::{Duration, Instant};

use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{info, warn};
use url::Url;

use super::config::{OidcConfig, transport_problem};

/// How long a fetched document is used before it is fetched again.
const DISCOVERY_TTL: Duration = Duration::from_secs(24 * 60 * 60);
/// The largest discovery document accepted.
const MAX_DISCOVERY_BYTES: usize = 64 * 1024;

/// The parts of the discovery document sign-in uses.
#[derive(Debug, Clone, Deserialize)]
pub struct ProviderMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,
    #[serde(default)]
    pub id_token_signing_alg_values_supported: Option<Vec<String>>,
    #[serde(default)]
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

/// The cached discovery document.
pub struct Discovery {
    http: reqwest::Client,
    cached: RwLock<Option<(Arc<ProviderMetadata>, Instant)>>,
}

impl Discovery {
    pub fn new(http: reqwest::Client) -> Self {
        Self {
            http,
            cached: RwLock::new(None),
        }
    }

    /// The provider's metadata, from the cache while it is fresh, otherwise
    /// fetched and checked against `config`.
    pub async fn metadata(
        &self,
        config: &OidcConfig,
    ) -> Result<Arc<ProviderMetadata>, String> {
        if let Some((metadata, fetched_at)) = self
            .cached
            .read()
            .await
            .as_ref()
            && fetched_at.elapsed() < DISCOVERY_TTL
        {
            return Ok(metadata.clone());
        }
        let metadata = Arc::new(self.fetch(config).await?);
        *self.cached.write().await = Some((metadata.clone(), Instant::now()));
        Ok(metadata)
    }

    /// Drop the cached document, so the next sign-in fetches it again (after a
    /// failure that a moved endpoint could explain).
    pub async fn forget(&self) {
        *self.cached.write().await = None;
    }

    async fn fetch(
        &self,
        config: &OidcConfig,
    ) -> Result<ProviderMetadata, String> {
        let url = config.discovery_url();
        crate::url_validation::validate_service_endpoint_url(&url)
            .await
            .map_err(|e| format!("discovery address refused: {e}"))?;
        let response = self
            .http
            .get(&url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|e| format!("discovery request failed: {e}"))?;
        if !response.status().is_success() {
            return Err(format!("discovery answered HTTP {}", response.status()));
        }
        let body = crate::http_client::read_capped(response, MAX_DISCOVERY_BYTES).await?;
        let metadata: ProviderMetadata =
            serde_json::from_slice(&body).map_err(|e| format!("discovery document is not usable: {e}"))?;
        check(&metadata, config)?;
        for (field, endpoint) in [("token_endpoint", &metadata.token_endpoint), ("jwks_uri", &metadata.jwks_uri)] {
            crate::url_validation::validate_service_endpoint_url(endpoint)
                .await
                .map_err(|e| format!("discovery {field} refused: {e}"))?;
        }
        info!(issuer = %metadata.issuer, "Fetched the OpenID provider's discovery document");
        Ok(metadata)
    }
}

/// Check a discovery document against `oidc.json`: the issuer it names, the
/// transport of every endpoint, and what the provider says it supports.
fn check(
    metadata: &ProviderMetadata,
    config: &OidcConfig,
) -> Result<(), String> {
    if metadata.issuer != config.issuer {
        return Err(format!(
            "discovery names issuer {} but oidc.json has {}; they must be identical",
            metadata.issuer, config.issuer
        ));
    }
    for (field, endpoint) in [
        ("authorization_endpoint", &metadata.authorization_endpoint),
        ("token_endpoint", &metadata.token_endpoint),
        ("jwks_uri", &metadata.jwks_uri),
    ] {
        let url = Url::parse(endpoint).map_err(|_| format!("discovery {field} is not an absolute URL"))?;
        if let Some(problem) = transport_problem(&url) {
            return Err(format!("discovery {field} {problem}"));
        }
    }
    if let Some(methods) = &metadata.code_challenge_methods_supported
        && !methods
            .iter()
            .any(|method| method == "S256")
    {
        return Err("the provider does not support PKCE with S256".to_string());
    }
    let auth_method = config
        .token_endpoint_auth_method
        .as_str();
    if let Some(methods) = &metadata.token_endpoint_auth_methods_supported
        && !methods
            .iter()
            .any(|method| method == auth_method)
    {
        return Err(format!("the provider does not accept token_endpoint_auth_method {auth_method}"));
    }
    if let Some(algorithms) = &metadata.id_token_signing_alg_values_supported
        && !config
            .id_token_signing_algs
            .iter()
            .any(|allowed| {
                algorithms
                    .iter()
                    .any(|offered| offered == &format!("{allowed:?}"))
            })
    {
        warn!(
            offered = ?algorithms,
            allowed = ?config.id_token_signing_algs,
            "The provider signs ID tokens with none of the algorithms in id_token_signing_algs; sign-in will fail"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::oidc::test_support::{config_for, metadata_for};

    #[test]
    fn a_document_naming_another_issuer_is_refused() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        assert!(check(&metadata, &config).is_ok());

        metadata.issuer = "https://idp.example.com/".to_string();
        let refused = check(&metadata, &config).unwrap_err();
        assert!(refused.contains("must be identical"), "{refused}");
    }

    #[test]
    fn every_endpoint_must_be_https() {
        let config = config_for("https://idp.example.com");
        for field in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let mut metadata = metadata_for("https://idp.example.com");
            let plain = "http://idp.example.com/endpoint".to_string();
            match field {
                "authorization_endpoint" => metadata.authorization_endpoint = plain,
                "token_endpoint" => metadata.token_endpoint = plain,
                _ => metadata.jwks_uri = plain,
            }
            let refused = check(&metadata, &config).unwrap_err();
            assert!(refused.contains(field) && refused.contains("https://"), "{refused}");
        }
    }

    #[test]
    fn a_provider_without_s256_pkce_is_refused() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        metadata.code_challenge_methods_supported = Some(vec!["plain".to_string()]);
        assert!(
            check(&metadata, &config)
                .unwrap_err()
                .contains("S256")
        );

        metadata.code_challenge_methods_supported = None;
        assert!(check(&metadata, &config).is_ok(), "a provider that does not say is tried");
    }

    #[test]
    fn the_client_authentication_method_must_be_one_the_provider_accepts() {
        let config = config_for("https://idp.example.com");
        let mut metadata = metadata_for("https://idp.example.com");
        metadata.token_endpoint_auth_methods_supported = Some(vec!["client_secret_post".to_string()]);
        assert!(
            check(&metadata, &config)
                .unwrap_err()
                .contains("client_secret_basic")
        );

        metadata.token_endpoint_auth_methods_supported =
            Some(vec!["client_secret_post".to_string(), "client_secret_basic".to_string()]);
        assert!(check(&metadata, &config).is_ok());
    }
}
