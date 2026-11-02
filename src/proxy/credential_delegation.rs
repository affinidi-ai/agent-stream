//! Credential delegation integration for the proxy pipeline.
//!
//! Intercepts outbound requests on channels with `outbound_credentials` bindings,
//! looks up the delegation vault for cached tokens, refreshes expired tokens, and
//! injects credentials into upstream requests — or signals consent_required to the caller.

use crate::config::types::{CredentialInjection, CredentialRequirement, OutboundCredentialBinding};
use crate::credential_providers::CredentialProviderType;
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::delegation_vault::audit::{self, DelegationAuditAction};
use crate::delegation_vault::{DelegationToken, VaultLookupResult, oauth, storage::DelegationVaultStorage};
use crate::secrets::SecretsStore;
use chrono::Utc;
use std::sync::Arc;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

/// Rich context attached to every audit event emitted during delegation resolution
#[derive(Debug, Clone, Default)]
pub struct DelegationAuditContext {
    /// Human-readable channel name
    pub channel_name: Option<String>,
    /// Target endpoint the channel proxies to
    pub target_endpoint: Option<String>,
    /// Protocol of the channel (a2a, mcp, etc.)
    pub protocol: Option<String>,
    /// MCP tool name (if this is an MCP tool call)
    pub mcp_tool_name: Option<String>,
    /// Actual DID identity of the agent (from identity store lookup)
    pub agent_identity_did: Option<String>,
    /// Identity binding VP (signed proof of user→agent binding)
    pub vp_jwt: Option<String>,
    /// Tenant that owns the surface; absent for an appliance-wide surface
    pub tenant_id: Option<String>,
}

/// Result of a delegation credential lookup for a single binding
pub enum DelegationLookupResult {
    /// Token found — inject these headers into the upstream request
    Inject(Vec<(String, String)>),
    /// User has not yet consented — return consent_required to caller
    ConsentRequired { authorization_url: String, provider_name: String, scopes: Vec<String> },
    /// Binding doesn't apply to this request (e.g. tool filter)
    NotApplicable,
}

/// Enrich an audit event with delegation-specific context
fn enrich_audit_event(
    evt: &mut audit::DelegationAuditEvent,
    ctx: Option<&DelegationAuditContext>,
    binding: &OutboundCredentialBinding,
    provider_name: Option<&str>,
) {
    if let Some(ctx) = ctx {
        evt.channel_name = ctx.channel_name.clone();
        evt.target_endpoint = ctx.target_endpoint.clone();
        evt.protocol = ctx.protocol.clone();
        evt.mcp_tool_name = ctx.mcp_tool_name.clone();
        evt.agent_identity_did = ctx.agent_identity_did.clone();
        evt.tenant_id = ctx.tenant_id.clone();
        if let Some(vp_jwt) = &ctx.vp_jwt {
            evt.set_vp_jwt(vp_jwt.clone());
        }
    }
    if let Some(name) = provider_name {
        evt.provider_name = Some(name.to_string());
    }
    evt.inject_as = Some(format!("{:?}", binding.inject_as).to_lowercase());
}

/// Check all outbound credential bindings for a channel and return injection headers
/// or a consent_required signal.
///
/// # Arguments
/// * `bindings` — the channel's `outbound_credentials` configuration
/// * `user_identity_hash` — peppered hash of the caller's identity claim
/// * `agent_did` — the DID of the agent this channel proxies to
/// * `channel_id` — for logging
/// * `mcp_tool_name` — if this is an MCP tool call, the tool name (for `Tools` requirement filter)
/// * `vault_store` — delegation vault storage
/// * `provider_store` — credential provider storage
/// * `secrets_store` — secrets storage (for refreshing tokens)
/// * `gateway_base_url` — for building OAuth authorization URLs
/// * `via_fabric` — true when this resolution is happening on the GW2 side of a fabric request
pub async fn resolve_delegation_credentials(
    bindings: &[OutboundCredentialBinding],
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    mcp_tool_name: Option<&str>,
    vault_store: &Arc<dyn DelegationVaultStorage>,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
    via_fabric: bool,
    audit_ctx: Option<&DelegationAuditContext>,
) -> Vec<DelegationLookupResult> {
    let mut results: Vec<DelegationLookupResult> = Vec::new();

    for binding in bindings {
        // Check if this binding applies to the current request
        match &binding.required_for {
            CredentialRequirement::All => {}
            CredentialRequirement::Tools(tools) => {
                if let Some(tool) = mcp_tool_name {
                    if !tools
                        .iter()
                        .any(|t| t == tool)
                    {
                        results.push(DelegationLookupResult::NotApplicable);
                        continue;
                    }
                } else {
                    // Not a tool call, and this binding is only for specific tools
                    results.push(DelegationLookupResult::NotApplicable);
                    continue;
                }
            }
        }

        // Load provider to determine type
        let provider = match provider_store
            .get(&binding.credential_provider_id)
            .await
        {
            Ok(Some(p)) => p,
            Ok(None) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = %binding.credential_provider_id,
                    "Credential provider not found — skipping binding"
                );
                results.push(DelegationLookupResult::NotApplicable);
                continue;
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Failed to load credential provider"
                );
                results.push(DelegationLookupResult::NotApplicable);
                continue;
            }
        };

        // Route by provider type
        match &provider.provider_type {
            CredentialProviderType::ApiKey => {
                // Direct secret resolution — no OAuth, no vault
                match oauth::resolve_api_key(&provider, secrets_store).await {
                    Ok(api_key) => {
                        debug!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "API key resolved — injecting into upstream request"
                        );
                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenInjected,
                            Some(agent_did),
                            Some(user_identity_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.via_fabric = via_fabric;
                        evt.detail = Some("api_key".to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);
                        let headers = build_injection_headers(&binding.inject_as, &api_key);
                        results.push(DelegationLookupResult::Inject(headers));
                    }
                    Err(e) => {
                        warn!(
                            target: "credential_delegation",
                            provider_id = %binding.credential_provider_id,
                            error = %e,
                            "Failed to resolve API key"
                        );
                        results.push(DelegationLookupResult::NotApplicable);
                    }
                }
                continue;
            }
            CredentialProviderType::OAuth2ClientCredentials => {
                // M2M flow: check vault first (for caching), then fetch fresh if needed
                let m2m_user_hash = "__client_credentials__";
                let lookup_result = vault_store
                    .lookup(agent_did, m2m_user_hash, &binding.credential_provider_id)
                    .await;

                match lookup_result {
                    Ok(VaultLookupResult::Found(token)) => {
                        debug!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "Client credentials token found in vault — injecting"
                        );
                        if let Err(e) = vault_store
                            .mark_used(&token.id)
                            .await
                        {
                            warn!(
                                target: "credential_delegation",
                                token_id = %token.id,
                                error = %e,
                                "Failed to mark client_credentials token as used"
                            );
                        }
                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenInjected,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.token_id = Some(token.id.clone());
                        evt.via_fabric = via_fabric;
                        evt.detail = Some("client_credentials_cached".to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);
                        let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                        results.push(DelegationLookupResult::Inject(headers));
                        continue;
                    }
                    Ok(VaultLookupResult::ExpiredRefreshable(old_token))
                    | Ok(VaultLookupResult::ExpiredNoRefresh(old_token)) => {
                        if let Err(e) = vault_store
                            .delete(&old_token.id)
                            .await
                        {
                            warn!(
                                target: "credential_delegation",
                                surface_id = %channel_id,
                                provider_id = %binding.credential_provider_id,
                                token_id = %old_token.id,
                                error = %e,
                                "Failed to delete stale client_credentials token from vault"
                            );
                        }
                    }
                    _ => {
                        // Not found or error — proceed to fetch fresh token
                    }
                }

                let effective_scopes = if binding.scopes.is_empty() {
                    &provider.default_scopes
                } else {
                    &binding.scopes
                };

                match oauth::fetch_client_credentials_token(&provider, effective_scopes, secrets_store).await {
                    Ok(token_response) => {
                        info!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            "Client credentials token fetched — caching in vault"
                        );
                        let expires_at = token_response
                            .expires_in
                            .map(|secs| Utc::now() + chrono::Duration::seconds(secs));
                        let now = Utc::now();
                        let delegation_token = DelegationToken {
                            id: Uuid::new_v4().to_string(),
                            agent_did: agent_did.to_string(),
                            user_identity_hash: m2m_user_hash.to_string(),
                            credential_provider_id: binding
                                .credential_provider_id
                                .clone(),
                            provider_id: provider.provider_id.clone(),
                            access_token: token_response
                                .access_token
                                .clone(),
                            refresh_token: token_response.refresh_token,
                            token_type: token_response.token_type,
                            scopes: effective_scopes.to_vec(),
                            expires_at,
                            delegation_vc: None,
                            consent_granted_at: now,
                            last_used_at: Some(now),
                            created_at: now,
                            updated_at: now,
                        };
                        let token_id = delegation_token.id.clone();
                        if let Err(e) = vault_store
                            .store(delegation_token)
                            .await
                        {
                            error!(
                                target: "credential_delegation",
                                surface_id = %channel_id,
                                provider_id = %binding.credential_provider_id,
                                error = %e,
                                "Failed to store fresh client_credentials token in vault"
                            );
                        }

                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenInjected,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.token_id = Some(token_id);
                        evt.via_fabric = via_fabric;
                        evt.detail = Some("client_credentials_fresh".to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);

                        let headers = build_injection_headers(&binding.inject_as, &token_response.access_token);
                        results.push(DelegationLookupResult::Inject(headers));
                    }
                    Err(e) => {
                        warn!(
                            target: "credential_delegation",
                            surface_id = %channel_id,
                            provider_id = %binding.credential_provider_id,
                            error = %e,
                            "Client credentials token fetch failed"
                        );
                        let mut evt = audit::audit_event(
                            DelegationAuditAction::TokenNotFound,
                            Some(agent_did),
                            Some(m2m_user_hash),
                            Some(&binding.credential_provider_id),
                            Some(channel_id),
                        );
                        evt.via_fabric = via_fabric;
                        evt.detail = Some(e.to_string());
                        enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                        audit::audit(evt);
                        results.push(DelegationLookupResult::NotApplicable);
                    }
                }
                continue;
            }
            CredentialProviderType::OAuth2AuthorizationCode => {
                // Existing 3LO flow — vault lookup → inject or consent
            }
        }

        // ── OAuth2 Authorization Code flow (3LO) ────────────────────────

        // Lookup in vault — trait signature: lookup(agent_did, user_identity_hash, provider_id)
        let lookup_result = vault_store
            .lookup(agent_did, user_identity_hash, &binding.credential_provider_id)
            .await;

        match lookup_result {
            Ok(VaultLookupResult::Found(token)) => {
                debug!(
                    target: "credential_delegation",
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "Delegation token found — injecting into upstream request"
                );

                // Mark as used
                if let Err(e) = vault_store
                    .mark_used(&token.id)
                    .await
                {
                    warn!(
                        target: "credential_delegation",
                        token_id = %token.id,
                        error = %e,
                        "Failed to mark delegation token as used"
                    );
                }

                // Audit: token injected
                let mut evt = audit::audit_event(
                    DelegationAuditAction::TokenInjected,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.token_id = Some(token.id.clone());
                evt.via_fabric = via_fabric;
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                audit::audit(evt);

                let headers = build_injection_headers(&binding.inject_as, &token.access_token);
                results.push(DelegationLookupResult::Inject(headers));
            }
            Ok(VaultLookupResult::ExpiredRefreshable(mut token)) => {
                info!(
                    target: "credential_delegation",
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "Delegation token expired — attempting refresh"
                );

                // Load provider to get token endpoint
                match provider_store
                    .get(&binding.credential_provider_id)
                    .await
                {
                    Ok(Some(provider)) => {
                        match oauth::refresh_access_token(
                            &provider,
                            token
                                .refresh_token
                                .as_deref()
                                .unwrap_or_default(),
                            secrets_store,
                        )
                        .await
                        {
                            Ok(refreshed) => {
                                token.access_token = refreshed.access_token.clone();
                                if let Some(rt) = &refreshed.refresh_token {
                                    token.refresh_token = Some(rt.clone());
                                }
                                if let Some(exp) = refreshed.expires_in {
                                    token.expires_at = Some(chrono::Utc::now() + chrono::Duration::seconds(exp));
                                }
                                if let Err(e) = vault_store
                                    .update(token.clone())
                                    .await
                                {
                                    warn!(
                                        target: "credential_delegation",
                                        token_id = %token.id,
                                        error = %e,
                                        "Failed to update refreshed token in vault"
                                    );
                                }
                                if let Err(e) = vault_store
                                    .mark_used(&token.id)
                                    .await
                                {
                                    warn!(
                                        target: "credential_delegation",
                                        token_id = %token.id,
                                        error = %e,
                                        "Failed to mark refreshed token as used"
                                    );
                                }

                                info!(
                                    target: "credential_delegation",
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    "Token refreshed successfully"
                                );

                                // Audit: token refreshed
                                let mut evt = audit::audit_event(
                                    DelegationAuditAction::TokenRefreshed,
                                    Some(agent_did),
                                    Some(user_identity_hash),
                                    Some(&binding.credential_provider_id),
                                    Some(channel_id),
                                );
                                evt.token_id = Some(token.id.clone());
                                evt.via_fabric = via_fabric;
                                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                                audit::audit(evt);

                                let headers = build_injection_headers(&binding.inject_as, &refreshed.access_token);
                                results.push(DelegationLookupResult::Inject(headers));
                            }
                            Err(e) => {
                                warn!(
                                    target: "credential_delegation",
                                    surface_id = %channel_id,
                                    provider_id = %binding.credential_provider_id,
                                    error = %e,
                                    "Token refresh failed — requesting new consent"
                                );
                                // Audit: refresh failed
                                let mut evt = audit::audit_event(
                                    DelegationAuditAction::RefreshFailed,
                                    Some(agent_did),
                                    Some(user_identity_hash),
                                    Some(&binding.credential_provider_id),
                                    Some(channel_id),
                                );
                                evt.via_fabric = via_fabric;
                                evt.detail = Some(e.to_string());
                                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                                audit::audit(evt);
                                // Fall through to consent_required
                                let cr = build_consent_required(
                                    binding,
                                    user_identity_hash,
                                    agent_did,
                                    channel_id,
                                    provider_store,
                                    secrets_store,
                                    gateway_base_url,
                                )
                                .await;
                                results.push(cr);
                            }
                        }
                    }
                    _ => {
                        warn!(
                            target: "credential_delegation",
                            provider_id = %binding.credential_provider_id,
                            "Cannot refresh — credential provider not found"
                        );
                        let cr = build_consent_required(
                            binding,
                            user_identity_hash,
                            agent_did,
                            channel_id,
                            provider_store,
                            secrets_store,
                            gateway_base_url,
                        )
                        .await;
                        results.push(cr);
                    }
                }
            }
            Ok(VaultLookupResult::ExpiredNoRefresh(_)) | Ok(VaultLookupResult::NotFound) => {
                info!(
                    target: "credential_delegation",
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    user_hash = %user_identity_hash,
                    "No valid delegation token — consent required"
                );

                let cr = build_consent_required(
                    binding,
                    user_identity_hash,
                    agent_did,
                    channel_id,
                    provider_store,
                    secrets_store,
                    gateway_base_url,
                )
                .await;
                results.push(cr);
            }
            Err(e) => {
                warn!(
                    target: "credential_delegation",
                    surface_id = %channel_id,
                    provider_id = %binding.credential_provider_id,
                    error = %e,
                    "Vault lookup failed"
                );
                // Audit: token not found (vault error)
                let mut evt = audit::audit_event(
                    DelegationAuditAction::TokenNotFound,
                    Some(agent_did),
                    Some(user_identity_hash),
                    Some(&binding.credential_provider_id),
                    Some(channel_id),
                );
                evt.via_fabric = via_fabric;
                evt.detail = Some(e.to_string());
                enrich_audit_event(&mut evt, audit_ctx, binding, Some(&provider.name));
                audit::audit(evt);
                results.push(DelegationLookupResult::NotApplicable);
            }
        }
    }

    results
}

/// Build HTTP headers for injecting a delegated credential
fn build_injection_headers(
    inject_as: &CredentialInjection,
    access_token: &str,
) -> Vec<(String, String)> {
    match inject_as {
        CredentialInjection::BearerHeader => {
            vec![("Authorization".to_string(), format!("Bearer {}", access_token))]
        }
        CredentialInjection::CustomHeader { name, format } => {
            let value = format.replace("{value}", access_token);
            // Guard against header injection via CRLF in name or value.
            let clean_name: String = name
                .chars()
                .filter(|c| *c != '\r' && *c != '\n')
                .collect();
            let clean_value: String = value
                .chars()
                .filter(|c| *c != '\r' && *c != '\n')
                .collect();
            vec![(clean_name, clean_value)]
        }
        CredentialInjection::Meta { field } => {
            // Meta injection is handled at the JSON-RPC body level, not HTTP headers.
            // Return a special marker that the caller can detect.
            vec![(format!("X-Delegation-Meta-{}", field), access_token.to_string())]
        }
    }
}

/// Build a consent_required response for a binding that has no valid token
async fn build_consent_required(
    binding: &OutboundCredentialBinding,
    user_identity_hash: &str,
    agent_did: &str,
    channel_id: &str,
    provider_store: &Arc<dyn CredentialProviderStorage>,
    secrets_store: &Arc<dyn SecretsStore>,
    gateway_base_url: &str,
) -> DelegationLookupResult {
    match provider_store
        .get(&binding.credential_provider_id)
        .await
    {
        Ok(Some(provider)) => {
            let scopes = if binding.scopes.is_empty() {
                provider
                    .default_scopes
                    .clone()
            } else {
                binding.scopes.clone()
            };

            match oauth::build_authorization_url(
                &provider,
                agent_did,
                user_identity_hash,
                channel_id,
                &scopes,
                gateway_base_url,
                secrets_store,
            )
            .await
            {
                Ok(url) => DelegationLookupResult::ConsentRequired {
                    authorization_url: url,
                    provider_name: provider.name.clone(),
                    scopes,
                },
                Err(e) => {
                    warn!(
                        target: "credential_delegation",
                        provider_id = %binding.credential_provider_id,
                        error = %e,
                        "Failed to build authorization URL"
                    );
                    DelegationLookupResult::NotApplicable
                }
            }
        }
        _ => {
            warn!(
                target: "credential_delegation",
                provider_id = %binding.credential_provider_id,
                "Credential provider not found for consent_required"
            );
            DelegationLookupResult::NotApplicable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::{Duration, Utc};
    use std::collections::HashMap;
    use std::sync::Arc;

    use crate::config::types::{ConsentMode, CredentialInjection, CredentialRequirement, OutboundCredentialBinding};
    use crate::credential_providers::CredentialProvider;
    use crate::delegation_vault::{DelegationToken, VaultLookupResult};
    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

    // ── Mock vault store ──────────────────────────────────────────────────

    struct MockVaultStore {
        result: tokio::sync::Mutex<VaultLookupResult>,
    }

    impl MockVaultStore {
        fn new(result: VaultLookupResult) -> Arc<Self> {
            Arc::new(Self {
                result: tokio::sync::Mutex::new(result),
            })
        }
    }

    #[async_trait]
    impl DelegationVaultStorage for MockVaultStore {
        async fn store(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            Ok(token)
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<DelegationToken>> {
            Ok(None)
        }
        async fn lookup(
            &self,
            _agent_did: &str,
            _user_identity_hash: &str,
            _provider_id: &str,
        ) -> Result<VaultLookupResult> {
            let guard = self.result.lock().await;
            Ok(guard.clone())
        }
        async fn list_all(&self) -> Result<Vec<DelegationToken>> {
            Ok(vec![])
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn delete_by_user(
            &self,
            _user_identity_hash: &str,
        ) -> Result<usize> {
            Ok(0)
        }
        async fn update(
            &self,
            token: DelegationToken,
        ) -> Result<DelegationToken> {
            Ok(token)
        }
        async fn mark_used(
            &self,
            _id: &str,
        ) -> Result<()> {
            Ok(())
        }
    }

    // ── Mock credential provider store ────────────────────────────────────

    struct MockProviderStore {
        providers: HashMap<String, CredentialProvider>,
    }

    impl MockProviderStore {
        fn empty() -> Arc<Self> {
            Arc::new(Self { providers: HashMap::new() })
        }

        fn with_oauth_provider(id: &str) -> Arc<Self> {
            let mut providers = HashMap::new();
            providers
                .insert(id.to_string(), make_credential_provider(id, CredentialProviderType::OAuth2AuthorizationCode));
            Arc::new(Self { providers })
        }
    }

    #[async_trait]
    impl CredentialProviderStorage for MockProviderStore {
        async fn create(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }
        async fn get(
            &self,
            id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(self
                .providers
                .get(id)
                .cloned())
        }
        async fn list(&self) -> Result<Vec<CredentialProvider>> {
            Ok(self
                .providers
                .values()
                .cloned()
                .collect())
        }
        async fn update(
            &self,
            provider: CredentialProvider,
        ) -> Result<CredentialProvider> {
            Ok(provider)
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<bool> {
            Ok(true)
        }
        async fn find_by_provider_id(
            &self,
            _provider_id: &str,
        ) -> Result<Option<CredentialProvider>> {
            Ok(None)
        }
    }

    // ── Mock secrets store ────────────────────────────────────────────────

    struct MockSecretsStore;

    #[async_trait]
    impl crate::secrets::store::SecretsStore for MockSecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            unimplemented!()
        }
        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            Ok(None)
        }
        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            unimplemented!()
        }
        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            Ok(())
        }
        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    fn make_credential_provider(
        id: &str,
        provider_type: CredentialProviderType,
    ) -> CredentialProvider {
        let now = Utc::now();
        CredentialProvider {
            id: id.to_string(),
            name: format!("Test Provider {}", id),
            provider_id: format!("test-{}", id),
            provider_type,
            authorization_endpoint: Some("https://auth.example.com/authorize".to_string()),
            token_endpoint: Some("https://auth.example.com/token".to_string()),
            client_id_secret_ref: Some("CLIENT_ID".to_string()),
            client_secret_secret_ref: Some("CLIENT_SECRET".to_string()),
            default_scopes: vec!["repo".to_string()],
            callback_path: format!("/oauth/callback/test-{}", id),
            token_refresh_enabled: true,
            additional_params: HashMap::new(),
            api_key_secret_ref: None,
            description: None,
            tenant_id: None,
            created_at: now,
            updated_at: now,
            callback_url: None,
        }
    }

    fn make_binding(provider_id: &str) -> OutboundCredentialBinding {
        OutboundCredentialBinding {
            credential_provider_id: provider_id.to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
        }
    }

    #[test]
    fn enriched_audit_events_carry_the_surface_tenant_only_when_known() {
        let binding = make_binding("p1");
        let mut with_tenant =
            audit::audit_event(DelegationAuditAction::TokenInjected, None, None, Some("p1"), Some("s1"));
        let ctx = DelegationAuditContext {
            tenant_id: Some("acme".to_string()),
            ..Default::default()
        };
        enrich_audit_event(&mut with_tenant, Some(&ctx), &binding, None);
        assert_eq!(
            with_tenant
                .tenant_id
                .as_deref(),
            Some("acme")
        );

        let mut appliance_wide =
            audit::audit_event(DelegationAuditAction::TokenInjected, None, None, Some("p1"), Some("s1"));
        enrich_audit_event(&mut appliance_wide, Some(&DelegationAuditContext::default()), &binding, None);
        assert_eq!(appliance_wide.tenant_id, None);
    }

    fn make_tool_binding(
        provider_id: &str,
        tools: Vec<String>,
    ) -> OutboundCredentialBinding {
        OutboundCredentialBinding {
            credential_provider_id: provider_id.to_string(),
            scopes: vec!["repo".to_string()],
            required_for: CredentialRequirement::Tools(tools),
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::BearerHeader,
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
        }
    }

    fn make_token(
        expired: bool,
        has_refresh: bool,
    ) -> DelegationToken {
        let now = Utc::now();
        DelegationToken {
            id: "tok-1".to_string(),
            agent_did: "did:web:agent.example".to_string(),
            user_identity_hash: "sha256:user1".to_string(),
            credential_provider_id: "cp-1".to_string(),
            provider_id: "github".to_string(),
            access_token: "gho_test_access_token_12345".to_string(),
            refresh_token: if has_refresh {
                Some("gho_test_refresh_token".to_string())
            } else {
                None
            },
            token_type: "bearer".to_string(),
            scopes: vec!["repo".to_string()],
            expires_at: if expired {
                Some(now - Duration::seconds(60))
            } else {
                Some(now + Duration::hours(1))
            },
            delegation_vc: None,
            consent_granted_at: now,
            last_used_at: None,
            created_at: now,
            updated_at: now,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn test_found_token_injects_bearer_header() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DelegationLookupResult::Inject(headers) => {
                assert_eq!(headers.len(), 1);
                assert_eq!(headers[0].0, "Authorization");
                assert_eq!(headers[0].1, "Bearer gho_test_access_token_12345");
            }
            _ => panic!("Expected Inject, got {:?}", result_tag(&results[0])),
        }
    }

    #[tokio::test]
    async fn test_not_found_returns_not_applicable_when_no_provider() {
        // When vault has no token AND provider store has no provider,
        // build_consent_required falls back to NotApplicable
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DelegationLookupResult::NotApplicable),
            "Expected NotApplicable when provider not found, got {:?}",
            result_tag(&results[0])
        );
    }

    #[tokio::test]
    async fn test_tool_filter_skips_non_matching_binding() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // Call with a different tool name
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            Some("create_issue"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DelegationLookupResult::NotApplicable),
            "Non-matching tool should produce NotApplicable"
        );
    }

    #[tokio::test]
    async fn test_tool_filter_matches_correct_tool() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            Some("list_repos"),
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(matches!(&results[0], DelegationLookupResult::Inject(_)), "Matching tool should produce Inject");
    }

    #[tokio::test]
    async fn test_tool_binding_skips_when_no_tool_name() {
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_tool_binding("cp-1", vec!["list_repos".to_string()])];

        // No tool name (non-MCP request)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DelegationLookupResult::NotApplicable),
            "Tool binding with no tool name should produce NotApplicable"
        );
    }

    #[tokio::test]
    async fn test_empty_bindings_returns_empty() {
        let vault = MockVaultStore::new(VaultLookupResult::NotFound);
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);

        let results = resolve_delegation_credentials(
            &[],
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert!(results.is_empty(), "Empty bindings should return empty results");
    }

    #[tokio::test]
    async fn test_custom_header_injection() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![OutboundCredentialBinding {
            credential_provider_id: "cp-1".to_string(),
            scopes: vec![],
            required_for: CredentialRequirement::All,
            consent_mode: ConsentMode::OnDemand,
            inject_as: CredentialInjection::CustomHeader {
                name: "X-GitHub-Token".to_string(),
                format: "token {value}".to_string(),
            },
            elicit_timeout_secs: 300,
            elicit_fallback: crate::config::types::ElicitFallback::OnDemand,
        }];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        match &results[0] {
            DelegationLookupResult::Inject(headers) => {
                assert_eq!(headers[0].0, "X-GitHub-Token");
                assert_eq!(headers[0].1, "token gho_test_access_token_12345");
            }
            _ => panic!("Expected Inject with custom header"),
        }
    }

    #[tokio::test]
    async fn test_vault_error_returns_not_applicable() {
        struct ErrorVaultStore;

        #[async_trait]
        impl DelegationVaultStorage for ErrorVaultStore {
            async fn store(
                &self,
                token: DelegationToken,
            ) -> Result<DelegationToken> {
                Ok(token)
            }
            async fn get(
                &self,
                _id: &str,
            ) -> Result<Option<DelegationToken>> {
                Ok(None)
            }
            async fn lookup(
                &self,
                _a: &str,
                _b: &str,
                _c: &str,
            ) -> Result<VaultLookupResult> {
                Err(anyhow::anyhow!("storage unreachable"))
            }
            async fn list_all(&self) -> Result<Vec<DelegationToken>> {
                Ok(vec![])
            }
            async fn delete(
                &self,
                _id: &str,
            ) -> Result<bool> {
                Ok(true)
            }
            async fn delete_by_user(
                &self,
                _: &str,
            ) -> Result<usize> {
                Ok(0)
            }
            async fn update(
                &self,
                token: DelegationToken,
            ) -> Result<DelegationToken> {
                Ok(token)
            }
            async fn mark_used(
                &self,
                _id: &str,
            ) -> Result<()> {
                Ok(())
            }
        }

        let vault: Arc<dyn DelegationVaultStorage> = Arc::new(ErrorVaultStore);
        // Use a real provider so we reach the vault lookup (instead of
        // short-circuiting on provider_not_found).
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &vault,
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        assert!(
            matches!(&results[0], DelegationLookupResult::NotApplicable),
            "Vault error should degrade to NotApplicable"
        );
    }

    #[tokio::test]
    async fn test_expired_no_refresh_triggers_consent_required_path() {
        // Expired with no refresh token → should attempt consent_required
        // Since MockProviderStore is empty, falls back to NotApplicable
        let vault = MockVaultStore::new(VaultLookupResult::ExpiredNoRefresh(make_token(true, false)));
        let providers = MockProviderStore::empty();
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);
        let bindings = vec![make_binding("cp-1")];

        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            true, // via_fabric
            None,
        )
        .await;

        assert_eq!(results.len(), 1);
        // Provider not in mock store — falls through to NotApplicable
        assert!(
            matches!(&results[0], DelegationLookupResult::NotApplicable),
            "ExpiredNoRefresh with no provider should degrade to NotApplicable"
        );
    }

    #[tokio::test]
    async fn test_multiple_bindings_processed_independently() {
        let token = make_token(false, false);
        let vault = MockVaultStore::new(VaultLookupResult::Found(token));
        let providers = MockProviderStore::with_oauth_provider("cp-1");
        let secrets: Arc<dyn SecretsStore> = Arc::new(MockSecretsStore);

        let bindings = vec![make_binding("cp-1"), make_tool_binding("cp-2", vec!["special_tool".to_string()])];

        // No tool name → first binding matches (All), second is filtered (Tools with no tool)
        let results = resolve_delegation_credentials(
            &bindings,
            "sha256:user1",
            "did:web:agent.example",
            "ch-1",
            None,
            &(vault as Arc<dyn DelegationVaultStorage>),
            &(providers as Arc<dyn CredentialProviderStorage>),
            &secrets,
            "https://gw.example.com",
            false,
            None,
        )
        .await;

        assert_eq!(results.len(), 2);
        assert!(matches!(&results[0], DelegationLookupResult::Inject(_)));
        assert!(matches!(&results[1], DelegationLookupResult::NotApplicable));
    }

    fn result_tag(r: &DelegationLookupResult) -> &'static str {
        match r {
            DelegationLookupResult::Inject(_) => "Inject",
            DelegationLookupResult::ConsentRequired { .. } => "ConsentRequired",
            DelegationLookupResult::NotApplicable => "NotApplicable",
        }
    }
}
