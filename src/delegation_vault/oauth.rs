//! OAuth 2.0 flow handling — authorization URL generation, callback processing, token exchange
//!
//! This module implements the full 3-legged OAuth flow:
//! 1. Generate authorization URL (with a single-use state held on the appliance)
//! 2. Handle callback (exchange code for tokens)
//! 3. Token refresh
//! 4. DelegationCredential VC issuance

use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rand::RngCore;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{info, warn};
use uuid::Uuid;

use super::{ConsentRequired, OAuthState, OAuthTokenResponse};
use crate::credential_providers::CredentialProvider;
use crate::identity::ssi::vc_issuer::VcSigner;
use crate::secrets::SecretsStore;
use std::sync::{Arc, LazyLock};

/// How long an authorization URL's `state` can be redeemed at the callback.
const OAUTH_STATE_TTL: Duration = Duration::minutes(10);

/// Most consent flows waiting for their callback at once.
const MAX_PENDING_OAUTH_STATES: usize = 10_000;

/// Whom a consent flow is for. At most one flow is pending per identity.
type FlowIdentity = (String, String, String);

fn flow_identity(state: &OAuthState) -> FlowIdentity {
    (
        state.agent_did.clone(),
        state
            .user_identity_hash
            .clone(),
        state
            .credential_provider_id
            .clone(),
    )
}

/// Consent flows waiting for their callback, keyed by the `state` value sent to
/// the provider. The flow's context never leaves the appliance, so a callback
/// can only redeem a state this process issued, once, before it expires.
static PENDING_OAUTH_STATES: LazyLock<Mutex<PendingOAuthStates>> =
    LazyLock::new(|| Mutex::new(PendingOAuthStates::new(MAX_PENDING_OAUTH_STATES)));

struct PendingOAuthStates {
    capacity: usize,
    by_nonce: HashMap<String, OAuthState>,
    /// The nonce of each identity's pending flow.
    by_identity: HashMap<FlowIdentity, String>,
}

impl PendingOAuthStates {
    fn new(capacity: usize) -> Self {
        Self {
            capacity,
            by_nonce: HashMap::new(),
            by_identity: HashMap::new(),
        }
    }

    /// Hold `candidate` until its callback and return the flow to send the user
    /// through. When an unexpired flow is already pending for the same agent,
    /// user and credential provider, that flow is returned instead, so repeated
    /// consent prompts (an agent retrying) share one flow and the store grows
    /// with distinct identities, not requests. When full, expired flows are
    /// dropped first, then the flows closest to expiry.
    fn issue(
        &mut self,
        candidate: OAuthState,
        now: DateTime<Utc>,
    ) -> OAuthState {
        let identity = flow_identity(&candidate);
        if let Some(nonce) = self
            .by_identity
            .get(&identity)
            .cloned()
        {
            match self.by_nonce.get(&nonce) {
                Some(pending) if pending.expires_at > now => return pending.clone(),
                _ => {
                    self.remove(&nonce);
                }
            }
        }
        if self.by_nonce.len() >= self.capacity {
            let expired: Vec<String> = self
                .by_nonce
                .iter()
                .filter(|(_, pending)| pending.expires_at <= now)
                .map(|(nonce, _)| nonce.clone())
                .collect();
            for nonce in expired {
                self.remove(&nonce);
            }
        }
        while self.by_nonce.len() >= self.capacity {
            let Some(oldest) = self
                .by_nonce
                .iter()
                .min_by_key(|(_, pending)| pending.expires_at)
                .map(|(nonce, _)| nonce.clone())
            else {
                break;
            };
            self.remove(&oldest);
        }
        self.by_identity
            .insert(identity, candidate.nonce.clone());
        self.by_nonce
            .insert(candidate.nonce.clone(), candidate.clone());
        candidate
    }

    fn remove(
        &mut self,
        nonce: &str,
    ) -> Option<OAuthState> {
        let state = self.by_nonce.remove(nonce)?;
        let identity = flow_identity(&state);
        if self
            .by_identity
            .get(&identity)
            .is_some_and(|pending| pending == nonce)
        {
            self.by_identity
                .remove(&identity);
        }
        Some(state)
    }

    /// Remove and return the flow for `nonce`, refusing one that is unknown,
    /// already redeemed or expired.
    fn take(
        &mut self,
        nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<OAuthState> {
        let state = self
            .remove(nonce)
            .ok_or_else(|| anyhow!("OAuth state is unknown or was already used"))?;
        if now > state.expires_at {
            return Err(anyhow!("OAuth state has expired"));
        }
        Ok(state)
    }
}

/// Build the authorization URL with resolved client_id from secrets store
pub async fn build_authorization_url(
    provider: &CredentialProvider,
    agent_did: &str,
    user_identity_hash: &str,
    channel_id: &str,
    scopes: &[String],
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<String> {
    let auth_endpoint = provider
        .authorization_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no authorization_endpoint", provider.provider_id))?;
    crate::url_validation::validate_service_endpoint_url(auth_endpoint)
        .await
        .map_err(|e| anyhow!("Blocked authorization_endpoint for provider '{}': {}", provider.provider_id, e))?;

    // Resolve client_id from secrets store
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id secret")?;

    // Generate PKCE code_verifier (RFC 7636 §4.1: 43-128 chars, unreserved charset).
    // The flow already pending for this agent, user and provider keeps its own.
    let now = Utc::now();
    let state = PENDING_OAUTH_STATES
        .lock()
        .issue(
            OAuthState {
                agent_did: agent_did.to_string(),
                user_identity_hash: user_identity_hash.to_string(),
                surface_id: channel_id.to_string(),
                credential_provider_id: provider.id.clone(),
                provider_id: provider.provider_id.clone(),
                nonce: random_url_token(),
                expires_at: now + OAUTH_STATE_TTL,
                code_verifier: Some(generate_pkce_verifier()),
            },
            now,
        );
    let state_param = state.nonce;
    let code_challenge = generate_pkce_challenge(
        state
            .code_verifier
            .as_deref()
            .unwrap_or_default(),
    );

    let callback_url = provider
        .callback_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}{}", gateway_base_url, provider.callback_path));

    let effective_scopes = if scopes.is_empty() {
        &provider.default_scopes
    } else {
        scopes
    };
    let scope_string = effective_scopes.join(" ");

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        auth_endpoint,
        urlencoding::encode(&client_id),
        urlencoding::encode(&callback_url),
        urlencoding::encode(&scope_string),
        urlencoding::encode(&state_param),
        urlencoding::encode(&code_challenge),
    );

    for (key, value) in &provider.additional_params {
        url.push_str(&format!("&{}={}", urlencoding::encode(key), urlencoding::encode(value)));
    }

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        agent_did = %agent_did,
        user_hash = %user_identity_hash,
        scopes = ?effective_scopes,
        "Built OAuth authorization URL with resolved client_id"
    );

    Ok(url)
}

/// Client for a provider's token endpoint. The endpoint may sit on a private
/// network, but every resolved address is re-checked at connect time, so a
/// host that passed `validate_service_endpoint_url` cannot rebind to loopback,
/// link-local or metadata before the client secret is sent.
fn token_endpoint_client() -> Result<reqwest::Client> {
    crate::http_client::with_service_endpoint_resolver(std::time::Duration::from_secs(
        crate::http_client::EXTERNAL_TIMEOUT_SECS,
    ))
}

/// Exchange an OAuth authorization code for tokens
pub async fn exchange_code_for_tokens(
    provider: &CredentialProvider,
    code: &str,
    gateway_base_url: &str,
    secrets_store: &Arc<dyn SecretsStore>,
    code_verifier: Option<&str>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret")?;

    let callback_url = provider
        .callback_url
        .as_deref()
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("{}{}", gateway_base_url, provider.callback_path));
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    crate::url_validation::validate_service_endpoint_url(token_endpoint)
        .await
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;
    crate::url_validation::validate_service_endpoint_url(&callback_url)
        .await
        .map_err(|e| anyhow!("Blocked callback_url for provider '{}': {}", provider.provider_id, e))?;

    let http_client = token_endpoint_client()?;

    let mut params = vec![
        ("grant_type", "authorization_code".to_string()),
        ("code", code.to_string()),
        ("redirect_uri", callback_url.clone()),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    if let Some(verifier) = code_verifier {
        params.push(("code_verifier", verifier.to_string()));
    }

    let safe_token_endpoint = crate::url_validation::redact_url_for_logging(token_endpoint);

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %safe_token_endpoint,
        has_pkce = %code_verifier.is_some(),
        "Exchanging authorization code for tokens"
    );

    let response = http_client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .context("Failed to send token exchange request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read token response body")?;

    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            body = %body,
            "Token exchange failed"
        );
        return Err(anyhow!("Token exchange failed (HTTP {}): {}", status, body));
    }

    // Try JSON first; fall back to application/x-www-form-urlencoded (e.g. GitHub without Accept header)
    let token_response: OAuthTokenResponse = serde_json::from_str(&body)
        .or_else(|_| {
            let pairs: std::collections::HashMap<String, String> = serde_urlencoded::from_str(&body)?;
            Ok::<OAuthTokenResponse, serde_urlencoded::de::Error>(OAuthTokenResponse {
                access_token: pairs
                    .get("access_token")
                    .cloned()
                    .unwrap_or_default(),
                refresh_token: pairs
                    .get("refresh_token")
                    .cloned(),
                token_type: pairs
                    .get("token_type")
                    .cloned()
                    .unwrap_or_else(|| "bearer".to_string()),
                expires_in: pairs
                    .get("expires_in")
                    .and_then(|v| v.parse().ok()),
                scope: pairs.get("scope").cloned(),
            })
        })
        .map_err(|e| anyhow!("Failed to parse token response as JSON or form-urlencoded: {e}"))?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_type = %token_response.token_type,
        has_refresh_token = %token_response.refresh_token.is_some(),
        expires_in = ?token_response.expires_in,
        scope = ?token_response.scope,
        "Token exchange successful"
    );

    Ok(token_response)
}

/// Refresh an expired access token using a refresh token
pub async fn refresh_access_token(
    provider: &CredentialProvider,
    refresh_token: &str,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id for refresh")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret for refresh")?;

    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    crate::url_validation::validate_service_endpoint_url(token_endpoint)
        .await
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;

    let http_client = token_endpoint_client()?;

    let params = [
        ("grant_type", "refresh_token"),
        ("refresh_token", refresh_token),
        ("client_id", &client_id),
        ("client_secret", &client_secret),
    ];

    let safe_token_endpoint = crate::url_validation::redact_url_for_logging(token_endpoint);

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %safe_token_endpoint,
        "Refreshing access token"
    );

    let response = http_client
        .post(token_endpoint)
        .header("Accept", "application/json")
        .form(&params)
        .send()
        .await
        .context("Failed to send token refresh request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read refresh response body")?;

    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            "Token refresh failed — user may need to re-consent"
        );
        return Err(anyhow!("Token refresh failed (HTTP {}): {}", status, body));
    }

    let token_response: OAuthTokenResponse = serde_json::from_str(&body)
        .or_else(|_| {
            let pairs: std::collections::HashMap<String, String> = serde_urlencoded::from_str(&body)?;
            Ok::<OAuthTokenResponse, serde_urlencoded::de::Error>(OAuthTokenResponse {
                access_token: pairs
                    .get("access_token")
                    .cloned()
                    .unwrap_or_default(),
                refresh_token: pairs
                    .get("refresh_token")
                    .cloned(),
                token_type: pairs
                    .get("token_type")
                    .cloned()
                    .unwrap_or_else(|| "bearer".to_string()),
                expires_in: pairs
                    .get("expires_in")
                    .and_then(|v| v.parse().ok()),
                scope: pairs.get("scope").cloned(),
            })
        })
        .map_err(|e| anyhow!("Failed to parse refresh response as JSON or form-urlencoded: {e}"))?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        has_new_refresh_token = %token_response.refresh_token.is_some(),
        expires_in = ?token_response.expires_in,
        "Token refresh successful"
    );

    Ok(token_response)
}

/// Build a consent-required payload for protocol-aware signaling
#[allow(dead_code)]
pub fn build_consent_required(
    provider: &CredentialProvider,
    authorization_url: &str,
    scopes: &[String],
) -> ConsentRequired {
    ConsentRequired {
        provider_id: provider.provider_id.clone(),
        provider_name: provider.name.clone(),
        authorization_url: authorization_url.to_string(),
        scopes: scopes.to_vec(),
        message: format!("{} authorization is required to access resources on your behalf.", provider.name),
    }
}

/// Build and sign a DelegationCredential VC using the gateway's Ed25519 key.
///
/// Produces a W3C VC v2 credential with an EdDsaRdfc2022 Data Integrity Proof
/// when a `vc_signer` is provided. Falls back to an unsigned VC if no signer
/// is available (e.g. during tests or degraded mode).
pub async fn build_delegation_vc(
    gateway_did: &str,
    agent_did: &str,
    user_identity_hash: &str,
    provider: &CredentialProvider,
    scopes: &[String],
    vc_signer: Option<&Arc<dyn VcSigner>>,
) -> Result<serde_json::Value> {
    let now = Utc::now();
    let vc_id = format!("urn:uuid:{}", Uuid::new_v4());

    let credential = json!({
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://fabric.affinidi.io/credentials/delegation/v1"
        ],
        "type": ["VerifiableCredential", "DelegationCredential"],
        "id": vc_id,
        "issuer": gateway_did,
        "validFrom": now.to_rfc3339(),
        "credentialSubject": {
            "id": agent_did,
            "delegationType": "oauth2_on_behalf_of",
            "delegatedBy": {
                "identityHash": user_identity_hash,
                "claimSource": "jwt_bearer"
            },
            "resource": {
                "providerId": provider.provider_id,
                "providerName": provider.name,
                "scopes": scopes
            },
            "consentedAt": now.to_rfc3339()
        }
    });

    match vc_signer {
        Some(signer) => signer
            .sign(credential)
            .await
            .context("Failed to sign DelegationCredential VC"),
        None => {
            warn!(
                target: "credential_delegation",
                "No VC signer available — DelegationCredential will be unsigned"
            );
            Ok(credential)
        }
    }
}

/// Fetch a token using the OAuth 2.0 Client Credentials flow (M2M, no user consent)
pub async fn fetch_client_credentials_token(
    provider: &CredentialProvider,
    scopes: &[String],
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<OAuthTokenResponse> {
    let client_id_ref = provider
        .client_id_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_id_secret_ref", provider.provider_id))?;
    let client_secret_ref = provider
        .client_secret_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no client_secret_secret_ref", provider.provider_id))?;
    let token_endpoint = provider
        .token_endpoint
        .as_deref()
        .ok_or_else(|| anyhow!("Provider '{}' has no token_endpoint", provider.provider_id))?;
    let client_id = resolve_secret(secrets_store, client_id_ref)
        .await
        .context("Failed to resolve client_id for client_credentials")?;
    let client_secret = resolve_secret(secrets_store, client_secret_ref)
        .await
        .context("Failed to resolve client_secret for client_credentials")?;

    crate::url_validation::validate_service_endpoint_url(token_endpoint)
        .await
        .map_err(|e| anyhow!("Blocked token_endpoint for provider '{}': {}", provider.provider_id, e))?;

    let scope_string = scopes.join(" ");

    let http_client = token_endpoint_client()?;

    let mut params = vec![
        ("grant_type", "client_credentials".to_string()),
        ("client_id", client_id),
        ("client_secret", client_secret),
    ];

    if !scope_string.is_empty() {
        params.push(("scope", scope_string));
    }

    let safe_token_endpoint = crate::url_validation::redact_url_for_logging(token_endpoint);

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_endpoint = %safe_token_endpoint,
        scopes = ?scopes,
        "Fetching client_credentials token (M2M)"
    );

    let response = http_client
        .post(token_endpoint)
        .form(&params)
        .send()
        .await
        .context("Failed to send client_credentials token request")?;

    let status = response.status();
    let body = response
        .text()
        .await
        .context("Failed to read client_credentials response body")?;

    if !status.is_success() {
        warn!(
            target: "credential_delegation",
            provider_id = %provider.provider_id,
            status = %status,
            body = %body,
            "Client credentials token fetch failed"
        );
        return Err(anyhow!("Client credentials token fetch failed (HTTP {}): {}", status, body));
    }

    let token_response: OAuthTokenResponse =
        serde_json::from_str(&body).context("Failed to parse client_credentials token response")?;

    info!(
        target: "credential_delegation",
        provider_id = %provider.provider_id,
        token_type = %token_response.token_type,
        expires_in = ?token_response.expires_in,
        "Client credentials token fetch successful"
    );

    Ok(token_response)
}

/// Resolve an API key directly from the secrets store (no OAuth flow)
pub async fn resolve_api_key(
    provider: &CredentialProvider,
    secrets_store: &Arc<dyn SecretsStore>,
) -> Result<String> {
    let secret_ref = provider
        .api_key_secret_ref
        .as_deref()
        .ok_or_else(|| anyhow!("API key provider '{}' has no api_key_secret_ref", provider.provider_id))?;
    resolve_secret(secrets_store, secret_ref)
        .await
        .context("Failed to resolve API key secret")
}

/// Generate a PKCE code_verifier (RFC 7636 §4.1): 43 characters of the
/// unreserved set, within the 43-128 the RFC allows.
pub(crate) fn generate_pkce_verifier() -> String {
    random_url_token()
}

/// 32 random bytes, base64url-encoded without padding (43 characters).
pub(crate) fn random_url_token() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64_url_encode_bytes(&bytes)
}

/// Generate a PKCE code_challenge from a code_verifier (RFC 7636 §4.2)
/// code_challenge = BASE64URL(SHA256(code_verifier))
pub(crate) fn generate_pkce_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64_url_encode_bytes(&digest)
}

/// Redeem the `state` a provider returned to the callback. The flow it names
/// is removed, so each state works once, and it is refused when this appliance
/// did not issue it or it has expired.
pub fn take_oauth_state(state_param: &str) -> Result<OAuthState> {
    PENDING_OAUTH_STATES
        .lock()
        .take(state_param, Utc::now())
}

/// Resolve a secret value from the secrets store by secret_id
async fn resolve_secret(
    secrets_store: &Arc<dyn SecretsStore>,
    secret_ref: &str,
) -> Result<String> {
    let secrets = secrets_store
        .list_all()
        .await
        .context("Failed to list secrets")?;
    let secret = secrets
        .iter()
        .find(|s| s.secret_id == secret_ref)
        .ok_or_else(|| anyhow!("Secret with secret_id '{}' not found", secret_ref))?;
    let full_secret = secrets_store
        .get(&secret.id)
        .await
        .context("Failed to get secret by id")?
        .ok_or_else(|| anyhow!("Secret '{}' disappeared during resolution", secret_ref))?;
    Ok(full_secret.value)
}

fn base64_url_encode_bytes(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// A flow for its own user, so fixtures never share an identity.
    fn pending_state(
        nonce: &str,
        expires_in_minutes: i64,
    ) -> OAuthState {
        OAuthState {
            agent_did: "did:web:agent.example.com".to_string(),
            user_identity_hash: format!("sha256:user-{nonce}"),
            surface_id: "ch-test-1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            nonce: nonce.to_string(),
            expires_at: Utc::now() + Duration::minutes(expires_in_minutes),
            code_verifier: Some("test_verifier_value_12345678901234567890".to_string()),
        }
    }

    #[test]
    fn an_issued_state_redeems_its_flow_once() {
        let nonce = random_url_token();
        PENDING_OAUTH_STATES
            .lock()
            .issue(pending_state(&nonce, 10), Utc::now());

        let redeemed = take_oauth_state(&nonce).expect("issued state is redeemed");
        assert_eq!(redeemed.agent_did, "did:web:agent.example.com");
        assert_eq!(redeemed.user_identity_hash, format!("sha256:user-{nonce}"));
        assert_eq!(redeemed.surface_id, "ch-test-1");
        assert_eq!(redeemed.credential_provider_id, "cp-1");
        assert_eq!(redeemed.provider_id, "github");
        assert_eq!(
            redeemed
                .code_verifier
                .as_deref(),
            Some("test_verifier_value_12345678901234567890")
        );

        let replay = take_oauth_state(&nonce).expect_err("a redeemed state is refused");
        assert!(
            replay
                .to_string()
                .contains("already used"),
            "got: {replay}"
        );
    }

    #[test]
    fn a_state_the_appliance_did_not_issue_is_refused() {
        let unknown = take_oauth_state(&random_url_token()).expect_err("unknown nonce is refused");
        assert!(
            unknown
                .to_string()
                .contains("unknown"),
            "got: {unknown}"
        );

        // The plaintext state accepted before: base64url of the flow's JSON.
        use base64::Engine;
        let forged_json = r#"{"agent_did":"did:web:victim","user_identity_hash":"sha256:attacker","surface_id":"ch-1","credential_provider_id":"cp-1","provider_id":"github","nonce":"n","expires_at":"2999-01-01T00:00:00Z"}"#;
        let plaintext_state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(forged_json);
        assert!(take_oauth_state(&plaintext_state).is_err(), "plaintext state is refused");
        assert!(take_oauth_state("ENC[forged]").is_err(), "a state that only looks encrypted is refused");
        assert!(take_oauth_state("").is_err(), "an empty state is refused");
    }

    #[test]
    fn an_expired_state_is_refused_and_cannot_be_retried() {
        let nonce = random_url_token();
        PENDING_OAUTH_STATES
            .lock()
            .issue(pending_state(&nonce, -1), Utc::now() - Duration::minutes(11));

        let expired = take_oauth_state(&nonce).expect_err("expired state is refused");
        assert!(
            expired
                .to_string()
                .contains("expired"),
            "got: {expired}"
        );
        assert!(take_oauth_state(&nonce).is_err(), "an expired state is gone after the first try");
    }

    #[test]
    fn pending_flows_are_bounded_dropping_expired_then_oldest() {
        let now = Utc::now();
        let mut pending = PendingOAuthStates::new(3);
        pending.issue(pending_state("expired", -1), now);
        pending.issue(pending_state("oldest", 5), now);
        pending.issue(pending_state("middle", 7), now);

        pending.issue(pending_state("newer", 9), now);
        assert_eq!(pending.by_nonce.len(), 3);
        assert!(
            !pending
                .by_nonce
                .contains_key("expired"),
            "expired flows are dropped first"
        );
        assert!(
            pending
                .by_nonce
                .contains_key("oldest")
        );

        pending.issue(pending_state("newest", 10), now);
        assert_eq!(pending.by_nonce.len(), 3);
        assert!(
            !pending
                .by_nonce
                .contains_key("oldest"),
            "then the flow closest to expiry"
        );
        for kept in ["middle", "newer", "newest"] {
            assert_eq!(
                pending
                    .take(kept, now)
                    .expect("kept flow is redeemable")
                    .nonce,
                kept
            );
        }
    }

    /// A flow for `user` of one agent and provider, with nonce `nonce`.
    fn flow_for(
        user: &str,
        nonce: &str,
    ) -> OAuthState {
        OAuthState {
            user_identity_hash: format!("sha256:{user}"),
            ..pending_state(nonce, 10)
        }
    }

    #[test]
    fn a_flood_for_one_identity_leaves_other_flows_redeemable() {
        let now = Utc::now();
        let mut pending = PendingOAuthStates::new(2);
        let alice = pending.issue(flow_for("alice", "alice-flow"), now);
        assert_eq!(alice.nonce, "alice-flow");

        for retry in 0..100 {
            let bob = pending.issue(flow_for("bob", &format!("bob-{retry}")), now);
            assert_eq!(bob.nonce, "bob-0", "a retry gets the flow already pending");
            assert_eq!(bob.code_verifier, flow_for("bob", "bob-0").code_verifier);
        }
        assert_eq!(pending.by_nonce.len(), 2, "one flow per identity");

        assert_eq!(
            pending
                .take("alice-flow", now)
                .map(|flow| flow.nonce)
                .ok()
                .as_deref(),
            Some("alice-flow")
        );
        assert_eq!(
            pending
                .take("bob-0", now)
                .map(|flow| flow.user_identity_hash)
                .ok()
                .as_deref(),
            Some("sha256:bob")
        );
        assert!(pending.by_identity.is_empty(), "a redeemed flow frees its identity");
    }

    #[test]
    fn a_new_flow_replaces_an_expired_or_redeemed_one_for_the_same_identity() {
        let now = Utc::now();
        let mut pending = PendingOAuthStates::new(10);
        pending.issue(
            OAuthState {
                expires_at: now - Duration::minutes(1),
                ..flow_for("carol", "carol-old")
            },
            now - Duration::minutes(11),
        );
        let fresh = pending.issue(flow_for("carol", "carol-new"), now);
        assert_eq!(fresh.nonce, "carol-new", "an expired flow is not handed out again");
        assert!(
            pending
                .take("carol-old", now)
                .is_err(),
            "the expired flow is gone"
        );

        assert!(
            pending
                .take("carol-new", now)
                .is_ok()
        );
        assert_eq!(
            pending
                .issue(flow_for("carol", "carol-next"), now)
                .nonce,
            "carol-next"
        );
    }

    #[test]
    fn evicting_a_flow_frees_its_identity() {
        let now = Utc::now();
        let mut pending = PendingOAuthStates::new(1);
        pending.issue(flow_for("dave", "dave-flow"), now);
        pending.issue(flow_for("erin", "erin-flow"), now);
        assert_eq!(pending.by_identity.len(), 1, "the evicted flow's identity is dropped with it");
        assert_eq!(
            pending
                .issue(flow_for("dave", "dave-again"), now)
                .nonce,
            "dave-again"
        );
    }

    #[test]
    fn state_tokens_are_long_and_url_safe() {
        let first = random_url_token();
        assert_eq!(first.len(), 43);
        assert!(
            first
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
        assert_ne!(first, random_url_token());
    }

    #[tokio::test]
    async fn an_authorization_url_carries_only_a_single_use_state() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        let secrets: Arc<dyn SecretsStore> =
            Arc::new(MemorySecretsStore::with(vec![secret("s-1", "GH_ID", "client-123", None)]));
        let provider = CredentialProvider {
            id: "cp-1".to_string(),
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: Some("https://8.8.8.8/login/oauth/authorize".to_string()),
            token_endpoint: Some("https://8.8.8.8/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GH_ID".to_string()),
            client_secret_secret_ref: None,
            default_scopes: vec!["repo".to_string()],
            callback_path: "/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
        };

        let url = build_authorization_url(
            &provider,
            "did:web:agent.example.com",
            "sha256:user-1",
            "ch-1",
            &[],
            "https://gw.example.com",
            &secrets,
        )
        .await
        .expect("authorization URL is built");

        let parsed = url::Url::parse(&url).expect("authorization URL parses");
        let state_param = parsed
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .expect("authorization URL has a state");
        assert_eq!(state_param.len(), 43, "the state is an opaque random token");
        assert!(!url.contains("agent.example.com") && !url.contains("user-1"), "no flow context in the URL");

        let again = build_authorization_url(
            &provider,
            "did:web:agent.example.com",
            "sha256:user-1",
            "ch-1",
            &[],
            "https://gw.example.com",
            &secrets,
        )
        .await
        .expect("authorization URL is built again");
        assert_eq!(again, url, "a repeated consent prompt reuses the pending flow and its PKCE challenge");

        let flow = take_oauth_state(&state_param).expect("the state redeems its flow");
        assert_eq!(flow.agent_did, "did:web:agent.example.com");
        assert_eq!(flow.user_identity_hash, "sha256:user-1");
        assert_eq!(flow.surface_id, "ch-1");
        assert_eq!(flow.credential_provider_id, "cp-1");
        let verifier = flow
            .code_verifier
            .expect("the PKCE verifier stays on the appliance");
        let challenge = parsed
            .query_pairs()
            .find(|(key, _)| key == "code_challenge")
            .map(|(_, value)| value.into_owned());
        assert_eq!(challenge, Some(generate_pkce_challenge(&verifier)));
        assert!(take_oauth_state(&state_param).is_err(), "the state cannot be replayed");
    }

    #[test]
    fn test_build_consent_required_format() {
        let provider = CredentialProvider {
            id: "cp-1".to_string(),
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: Some("https://github.com/login/oauth/authorize".to_string()),
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GITHUB_CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("GITHUB_CLIENT_SECRET".to_string()),
            default_scopes: vec!["repo".to_string()],
            callback_path: "/oauth/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
        };

        let consent =
            build_consent_required(&provider, "https://github.com/authorize?state=xyz", &["repo".to_string()]);
        assert_eq!(consent.provider_id, "github");
        assert_eq!(consent.provider_name, "GitHub");
        assert!(
            consent
                .authorization_url
                .contains("github.com")
        );
        assert_eq!(consent.scopes, vec!["repo"]);
        assert!(
            consent
                .message
                .contains("GitHub")
        );
    }

    #[tokio::test]
    async fn test_build_delegation_vc_structure() {
        let provider = CredentialProvider {
            id: "cp-1".to_string(),
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: None,
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GH_ID".to_string()),
            client_secret_secret_ref: Some("GH_SECRET".to_string()),
            default_scopes: vec![],
            callback_path: "/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
        };

        // Test without signer (unsigned fallback)
        let vc = build_delegation_vc(
            "did:web:gateway.example.com",
            "did:web:agent.example.com",
            "sha256:user123",
            &provider,
            &["repo".to_string(), "read:user".to_string()],
            None,
        )
        .await
        .expect("build_delegation_vc should succeed without signer");

        assert_eq!(vc["issuer"], "did:web:gateway.example.com");
        assert_eq!(vc["credentialSubject"]["id"], "did:web:agent.example.com");
        assert_eq!(vc["credentialSubject"]["delegatedBy"]["identityHash"], "sha256:user123");
        assert_eq!(vc["credentialSubject"]["resource"]["providerId"], "github");

        let types = vc["type"]
            .as_array()
            .expect("type should be array");
        assert!(
            types
                .iter()
                .any(|t| t == "DelegationCredential")
        );

        // VC ID should be a UUID URN
        let id = vc["id"]
            .as_str()
            .expect("id should be string");
        assert!(id.starts_with("urn:uuid:"), "VC id should be URN UUID, got: {}", id);

        // Should use v2 context
        let contexts = vc["@context"]
            .as_array()
            .expect("@context should be array");
        assert!(
            contexts
                .iter()
                .any(|c| c == "https://www.w3.org/ns/credentials/v2"),
            "Should use W3C VC v2 context"
        );

        // Should use validFrom instead of issuanceDate
        assert!(vc.get("validFrom").is_some(), "Should have validFrom field");
        assert!(
            vc.get("issuanceDate")
                .is_none(),
            "Should not have issuanceDate field"
        );
    }

    #[test]
    fn test_pkce_verifier_length_and_charset() {
        let verifier = generate_pkce_verifier();
        // Base64url of 32 bytes = 43 chars (no padding)
        assert_eq!(verifier.len(), 43, "PKCE verifier should be 43 base64url chars");
        // Must only contain base64url chars
        assert!(
            verifier
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
            "PKCE verifier must be base64url: {}",
            verifier
        );
    }

    #[test]
    fn test_pkce_challenge_is_s256_of_verifier() {
        let verifier = generate_pkce_verifier();
        let challenge = generate_pkce_challenge(&verifier);

        // Manually compute expected: SHA256(verifier) → base64url
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let hash = hasher.finalize();
        let expected = base64_url_encode_bytes(&hash);

        assert_eq!(challenge, expected, "Challenge should be base64url(SHA256(verifier))");
    }

    #[test]
    fn test_pkce_verifier_uniqueness() {
        let v1 = generate_pkce_verifier();
        let v2 = generate_pkce_verifier();
        assert_ne!(v1, v2, "Two verifiers should be different");
    }

    #[tokio::test]
    async fn test_build_delegation_vc_signed() {
        use crate::identity::VCIssuerConfig;
        use crate::identity::ssi::vc_issuer::LocalVcSigner;
        use ssi::jwk::JWK;
        use std::sync::Arc;
        use tokio::sync::RwLock;

        let signing_key: JWK = serde_json::from_value(serde_json::json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "B7hiAU-eeRjFFNXtswXSQhmzwmYfBuZF9f1c3wODZJI",
            "d": "prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64"
        }))
        .expect("Failed to parse test JWK");

        let config = Arc::new(RwLock::new(VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:gateway.example.com".to_string(),
            signing_key,
        }));

        let signer: Arc<dyn VcSigner> = Arc::new(LocalVcSigner::new(config));

        let provider = CredentialProvider {
            id: "cp-1".to_string(),
            name: "GitHub".to_string(),
            provider_id: "github".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::default(),
            authorization_endpoint: None,
            token_endpoint: Some("https://github.com/login/oauth/access_token".to_string()),
            client_id_secret_ref: Some("GH_ID".to_string()),
            client_secret_secret_ref: Some("GH_SECRET".to_string()),
            default_scopes: vec![],
            callback_path: "/callback/github".to_string(),
            token_refresh_enabled: true,
            additional_params: std::collections::HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            callback_url: None,
        };

        let vc = build_delegation_vc(
            "did:web:gateway.example.com",
            "did:web:agent.example.com",
            "sha256:user123",
            &provider,
            &["repo".to_string()],
            Some(&signer),
        )
        .await
        .expect("Signed DelegationCredential should succeed");

        // Should have a Data Integrity proof
        let proof = vc
            .get("proof")
            .expect("Signed VC should contain a proof");
        assert_eq!(proof["type"], "DataIntegrityProof", "Proof type should be DataIntegrityProof");
        assert!(
            proof
                .get("proofValue")
                .is_some(),
            "Proof should contain proofValue"
        );

        // Core VC fields should still be present
        assert_eq!(vc["issuer"], "did:web:gateway.example.com");
        assert_eq!(vc["credentialSubject"]["id"], "did:web:agent.example.com");
        assert_eq!(vc["credentialSubject"]["delegationType"], "oauth2_on_behalf_of");
    }

    fn client_credentials_provider(token_endpoint: &str) -> CredentialProvider {
        let now = Utc::now();
        CredentialProvider {
            id: "cp-m2m".to_string(),
            name: "M2M".to_string(),
            provider_id: "m2m".to_string(),
            provider_type: crate::credential_providers::CredentialProviderType::OAuth2ClientCredentials,
            authorization_endpoint: None,
            token_endpoint: Some(token_endpoint.to_string()),
            client_id_secret_ref: Some("M2M_CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("M2M_CLIENT_SECRET".to_string()),
            default_scopes: Vec::new(),
            callback_path: String::new(),
            callback_url: None,
            token_refresh_enabled: false,
            additional_params: HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn client_secrets() -> Arc<dyn SecretsStore> {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        Arc::new(MemorySecretsStore::with(vec![
            secret("s-1", "M2M_CLIENT_ID", "client-id", None),
            secret("s-2", "M2M_CLIENT_SECRET", "client-secret", None),
        ]))
    }

    #[tokio::test]
    async fn the_client_secret_is_not_sent_to_a_token_endpoint_that_rebinds_to_loopback() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("token").await;
        let dns = crate::url_validation::test_dns::rebind_to_loopback("idp.rebind.test");
        let provider = client_credentials_provider(
            &upstream
                .url
                .replace("127.0.0.1", "idp.rebind.test"),
        );

        let result = fetch_client_credentials_token(&provider, &[], &client_secrets()).await;

        assert!(result.is_err(), "a rebound token endpoint must be refused");
        assert_eq!(dns.lookups(), 2, "the address must be checked again at connect time");
        assert_eq!(upstream.requests(), 0);
    }

    #[tokio::test]
    async fn a_client_credentials_token_is_fetched_from_an_allowed_token_endpoint() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::replying(vec![json!({
            "access_token": "m2m-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
        })])
        .await;
        let token_endpoint = upstream
            .url
            .replace("127.0.0.1", "idp.allowed.test");
        let _dns = crate::url_validation::test_dns::answer("idp.allowed.test", &[[127, 0, 0, 1].into()]);
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&token_endpoint));

        let token =
            fetch_client_credentials_token(&client_credentials_provider(&token_endpoint), &[], &client_secrets())
                .await
                .expect("an allowed token endpoint answers");

        assert_eq!(token.access_token, "m2m-access-token");
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(upstream.requests(), 1);
    }
}
