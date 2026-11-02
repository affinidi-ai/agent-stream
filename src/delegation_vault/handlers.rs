//! API handlers for delegation vault management and OAuth callback

use super::{
    DelegationToken, DelegationTokenListItem, notifier::SharedVaultPopulationNotifier, oauth,
    storage::DelegationVaultStorage,
};
use crate::credential_providers::storage::CredentialProviderStorage;
use crate::identity::VCIssuer;
use crate::identity::ssi::vc_issuer::VcSigner;
use crate::secrets::SecretsStore;
use crate::surfaces::AgentSurfaceStore;
use axum::{
    Json,
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
};
use chrono::{Duration, Utc};
use serde::Deserialize;
use std::sync::Arc;
use tracing::{error, info, warn};
use uuid::Uuid;

/// Shared state for delegation vault handlers
#[derive(Clone)]
pub struct DelegationVaultState {
    pub vault_store: Arc<dyn DelegationVaultStorage>,
    pub provider_store: Arc<dyn CredentialProviderStorage>,
    pub secrets_store: Arc<dyn SecretsStore>,
    pub gateway_base_url: String,
    pub agent_surface_store: Option<Arc<dyn AgentSurfaceStore>>,
    pub oauth_callback_route: String,
    pub vc_signer: Option<Arc<dyn VcSigner>>,
    /// Channel-agnostic VC issuer used when explicit consent-granted workload-binding
    /// VP audit evidence is enabled. Optional only because tests may construct this
    /// state without identity support.
    pub vc_issuer: Option<Arc<VCIssuer>>,
    pub consent_granted_workload_binding_vp_enabled: bool,
    /// Wakes parked tool-call tasks that are waiting for the OAuth flow to
    /// finish (set by orchestrator at startup; `None` only in test contexts).
    #[allow(dead_code)] // set on OAuth success paths; optional in tests
    pub vault_population_notifier: Option<SharedVaultPopulationNotifier>,
}

fn should_mint_consent_granted_workload_binding_vp(
    enabled: bool,
    has_vc_issuer: bool,
) -> bool {
    enabled && has_vc_issuer
}

/// GET /api/v1/delegation-vault
pub async fn list_tokens(State(state): State<DelegationVaultState>) -> impl IntoResponse {
    match state
        .vault_store
        .list_all()
        .await
    {
        Ok(tokens) => {
            let items: Vec<DelegationTokenListItem> = tokens
                .iter()
                .map(|t| t.into())
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap())).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to list: {}", e)})))
                .into_response()
        }
    }
}

/// GET /api/v1/delegation-vault/{id}
pub async fn get_token(
    State(state): State<DelegationVaultState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state
        .vault_store
        .get(&id)
        .await
    {
        Ok(Some(token)) => {
            // Return metadata only — never expose access_token/refresh_token via API
            let item: DelegationTokenListItem = (&token).into();
            (StatusCode::OK, Json(serde_json::to_value(item).unwrap())).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Delegation token not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to get: {}", e)})))
                .into_response()
        }
    }
}

/// DELETE /api/v1/delegation-vault/{id}
pub async fn revoke_token(
    State(state): State<DelegationVaultState>,
    Path(id): Path<String>,
) -> impl IntoResponse {
    match state
        .vault_store
        .delete(&id)
        .await
    {
        Ok(true) => {
            info!(
                target: "credential_delegation",
                id = %id,
                action = "revoke",
                "Delegation token revoked via API"
            );
            let mut evt =
                super::audit::audit_event(super::audit::DelegationAuditAction::TokenRevoked, None, None, None, None);
            evt.token_id = Some(id.to_string());
            super::audit::audit(evt);
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Delegation token not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to revoke: {}", e)})))
                .into_response()
        }
    }
}

/// DELETE /api/v1/delegation-vault/by-user/{user_hash}
pub async fn revoke_user_tokens(
    State(state): State<DelegationVaultState>,
    Path(user_hash): Path<String>,
) -> impl IntoResponse {
    match state
        .vault_store
        .delete_by_user(&user_hash)
        .await
    {
        Ok(count) => {
            info!(
                target: "credential_delegation",
                user_hash = %user_hash,
                count = %count,
                action = "revoke_all",
                "All delegation tokens revoked for user via API"
            );
            let mut evt = super::audit::audit_event(
                super::audit::DelegationAuditAction::UserTokensRevoked,
                None,
                Some(&user_hash),
                None,
                None,
            );
            evt.detail = Some(format!("{} tokens revoked", count));
            super::audit::audit(evt);
            (StatusCode::OK, Json(serde_json::json!({"revoked": count}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to revoke: {}", e)})))
                .into_response()
        }
    }
}

/// Query parameters for OAuth callback
#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

/// GET /v1/identity/oauth/callback/{provider_id}
///
/// Handles the OAuth provider redirect after user consent.
/// Exchanges the authorization code for tokens and stores them in the vault.
pub async fn oauth_callback(
    State(state): State<DelegationVaultState>,
    Path(provider_id): Path<String>,
    Query(query): Query<OAuthCallbackQuery>,
) -> impl IntoResponse {
    info!(
        target: "credential_delegation",
        provider_id = %provider_id,
        has_code = %query.code.is_some(),
        has_error = %query.error.is_some(),
        action = "oauth_callback",
        "OAuth callback received"
    );

    // Check for OAuth error response
    if let Some(error) = &query.error {
        let desc = query
            .error_description
            .as_deref()
            .unwrap_or("Unknown error");
        warn!(
            target: "credential_delegation",
            provider_id = %provider_id,
            oauth_error = %error,
            description = %desc,
            "OAuth provider returned an error"
        );
        return Html(format!(
            r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>The OAuth provider returned an error: <strong>{}</strong></p>
<p>{}</p>
<p>You may close this window and try again.</p>
</body></html>"#,
            html_escape(error),
            html_escape(desc)
        ))
        .into_response();
    }

    // Validate required parameters
    let code = match &query.code {
        Some(c) => c.clone(),
        None => {
            return Html(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Missing authorization code. Please try again.</p>
</body></html>"#
                    .to_string(),
            )
            .into_response();
        }
    };

    let state_encoded = match &query.state {
        Some(s) => s.clone(),
        None => {
            return Html(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Missing state parameter. This may be a CSRF attack.</p>
</body></html>"#
                    .to_string(),
            )
            .into_response();
        }
    };

    let oauth_state = match oauth::take_oauth_state(&state_encoded) {
        Ok(s) => s,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                provider_id = %provider_id,
                error = %e,
                "OAuth callback state refused"
            );
            return Html(format!(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Invalid or expired state parameter: {}</p>
<p>Please try again from the original application.</p>
</body></html>"#,
                html_escape(&e.to_string())
            ))
            .into_response();
        }
    };

    // Load the credential provider
    let provider = match state
        .provider_store
        .get(&oauth_state.credential_provider_id)
        .await
    {
        Ok(Some(p)) => p,
        Ok(None) => {
            error!(
                target: "credential_delegation",
                provider_id = %provider_id,
                credential_provider_id = %oauth_state.credential_provider_id,
                "Credential provider not found during callback"
            );
            return Html(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Credential provider configuration not found. It may have been deleted.</p>
</body></html>"#
                    .to_string(),
            )
            .into_response();
        }
        Err(e) => {
            error!(
                target: "credential_delegation",
                error = %e,
                "Failed to load credential provider during callback"
            );
            return Html(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Internal error loading provider configuration.</p>
</body></html>"#
                    .to_string(),
            )
            .into_response();
        }
    };

    // Exchange authorization code for tokens (with PKCE code_verifier if present)
    let token_response = match oauth::exchange_code_for_tokens(
        &provider,
        &code,
        &state.gateway_base_url,
        &state.secrets_store,
        oauth_state
            .code_verifier
            .as_deref(),
    )
    .await
    {
        Ok(tr) => tr,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                provider_id = %provider_id,
                error = %e,
                "Token exchange failed during callback"
            );
            return Html(format!(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Failed to exchange authorization code for tokens.</p>
<p>Error: {}</p>
</body></html>"#,
                html_escape(&e.to_string())
            ))
            .into_response();
        }
    };

    // Build the DelegationCredential VC
    let granted_scopes: Vec<String> = token_response
        .scope
        .as_deref()
        .map(|s| {
            s.split_whitespace()
                .map(String::from)
                .collect()
        })
        .unwrap_or_else(|| {
            provider
                .default_scopes
                .clone()
        });

    // Derive gateway DID from base URL: https://example.com → did:web:example.com
    let gateway_did = state
        .gateway_base_url
        .strip_prefix("https://")
        .or_else(|| {
            state
                .gateway_base_url
                .strip_prefix("http://")
        })
        .map(|domain| format!("did:web:{}", domain))
        .unwrap_or_else(|| "did:web:gateway.local".to_string());

    let delegation_vc = oauth::build_delegation_vc(
        &gateway_did,
        &oauth_state.agent_did,
        &oauth_state.user_identity_hash,
        &provider,
        &granted_scopes,
        state.vc_signer.as_ref(),
    )
    .await;

    let delegation_vc_json = match &delegation_vc {
        Ok(vc) => serde_json::to_string(vc).ok(),
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to build signed DelegationCredential VC — storing without VC"
            );
            None
        }
    };

    // Calculate token expiry
    let expires_at = token_response
        .expires_in
        .map(|secs| Utc::now() + Duration::seconds(secs));

    // Store in delegation vault — upsert: if a token already exists for this
    // (agent_did, user_identity_hash, credential_provider_id) composite key,
    // replace it rather than creating a duplicate.
    let now = Utc::now();

    // Check for an existing token to preserve the original ID and created_at
    let (token_id, created_at) = match state
        .vault_store
        .lookup(&oauth_state.agent_did, &oauth_state.user_identity_hash, &oauth_state.credential_provider_id)
        .await
    {
        Ok(super::VaultLookupResult::Found(existing))
        | Ok(super::VaultLookupResult::ExpiredRefreshable(existing))
        | Ok(super::VaultLookupResult::ExpiredNoRefresh(existing)) => {
            info!(
                target: "credential_delegation",
                old_id = %existing.id,
                agent_did = %oauth_state.agent_did,
                user_hash = %oauth_state.user_identity_hash,
                provider_id = %oauth_state.credential_provider_id,
                "Replacing existing delegation token on re-auth"
            );
            let _ = state
                .vault_store
                .delete(&existing.id)
                .await;
            (existing.id, existing.created_at)
        }
        _ => (Uuid::new_v4().to_string(), now),
    };

    let delegation_token_id_for_audit = token_id.clone();
    let delegation_token = DelegationToken {
        id: token_id,
        agent_did: oauth_state.agent_did.clone(),
        user_identity_hash: oauth_state
            .user_identity_hash
            .clone(),
        credential_provider_id: oauth_state
            .credential_provider_id
            .clone(),
        provider_id: oauth_state
            .provider_id
            .clone(),
        access_token: token_response.access_token,
        refresh_token: token_response.refresh_token,
        token_type: token_response.token_type,
        scopes: granted_scopes.clone(),
        expires_at,
        delegation_vc: delegation_vc_json,
        consent_granted_at: now,
        last_used_at: None,
        created_at,
        updated_at: now,
    };

    match state
        .vault_store
        .store(delegation_token)
        .await
    {
        Ok(_) => {
            info!(
                target: "credential_delegation",
                provider_id = %provider_id,
                agent_did = %oauth_state.agent_did,
                user_hash = %oauth_state.user_identity_hash,
                scopes = ?granted_scopes,
                expires_at = ?expires_at,
                action = "oauth_callback_success",
                "OAuth consent complete — tokens stored in vault"
            );

            // Audit: consent granted
            let mut evt = super::audit::audit_event(
                super::audit::DelegationAuditAction::ConsentGranted,
                Some(&oauth_state.agent_did),
                Some(&oauth_state.user_identity_hash),
                Some(&provider_id),
                Some(&oauth_state.surface_id),
            );
            evt.scopes = Some(granted_scopes.clone());
            evt.provider_name = Some(provider.name.clone());
            evt.token_id = Some(delegation_token_id_for_audit.clone());
            evt.agent_identity_did = Some(oauth_state.agent_did.clone());
            // Resolve channel name from store
            if let Some(ref cs) = state.agent_surface_store
                && let Ok(Some(ch)) = cs
                    .get(&oauth_state.surface_id)
                    .await
            {
                evt.channel_name = Some(ch.name.clone());
            }

            if should_mint_consent_granted_workload_binding_vp(
                state.consent_granted_workload_binding_vp_enabled,
                state.vc_issuer.is_some(),
            ) {
                if let Some(ref vc_issuer) = state.vc_issuer {
                    let delegation_action = serde_json::json!({
                        "providerId": provider.provider_id,
                        "providerName": provider.name,
                        "outcome": "consent_granted",
                        "scopes": granted_scopes,
                        "expiresAt": expires_at.map(|t| t.to_rfc3339()),
                        "tokenId": delegation_token_id_for_audit.clone(),
                    });
                    let workload_binding = serde_json::json!({
                        "agentIdentity": { "id": oauth_state.agent_did },
                        "userIdentity": { "userIdentityHash": oauth_state.user_identity_hash },
                        "delegationAction": delegation_action,
                    });
                    match vc_issuer
                        .create_consent_audit_presentation(
                            &oauth_state.agent_did,
                            workload_binding,
                            &delegation_token_id_for_audit,
                        )
                        .await
                    {
                        Ok(jwt) => {
                            evt.set_vp_jwt(jwt);
                        }
                        Err(e) => {
                            warn!(
                                target: "credential_delegation",
                                agent_did = %oauth_state.agent_did,
                                provider_id = %provider_id,
                                error = %e,
                                "Failed to mint consent_granted workload-binding VP for audit log"
                            );
                        }
                    }
                } else {
                    warn!(
                        target: "credential_delegation",
                        "No VC issuer available — consent_granted workload-binding audit event will be unsigned"
                    );
                }
            }

            super::audit::audit(evt);

            // Wake any parked tool-call tasks waiting for this vault key to
            // be populated by the MCP elicitation flow.
            if let Some(notifier) = &state.vault_population_notifier {
                notifier
                    .notify(&oauth_state.agent_did, &oauth_state.user_identity_hash, &provider_id)
                    .await;
            }
        }
        Err(e) => {
            error!(
                target: "credential_delegation",
                error = %e,
                "Failed to store delegation token after successful OAuth"
            );
            return Html(format!(
                r#"<!DOCTYPE html>
<html><head><title>Authorization Failed</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2>Authorization Failed</h2>
<p>Tokens were obtained but could not be stored: {}</p>
</body></html>"#,
                html_escape(&e.to_string())
            ))
            .into_response();
        }
    }

    // Success page
    let nonce = crate::proxy::security_headers::script_nonce();
    (
        [(axum::http::header::CONTENT_SECURITY_POLICY, crate::proxy::security_headers::inline_script_page_csp(&nonce))],
        Html(format!(
            r#"<!DOCTYPE html>
<html><head><title>Authorization Successful</title></head>
<body style="font-family: sans-serif; padding: 40px; text-align: center;">
<h2 style="color: #22c55e;">Authorization Successful</h2>
<p>{} access has been granted for scopes: <code>{}</code></p>
<p>You may close this window and return to your application.</p>
<p style="color: #666; font-size: 0.9em;">The agent can now access {} on your behalf.</p>
<script nonce="{}">
// Attempt to close the window after a short delay
setTimeout(function() {{ window.close(); }}, 3000);
</script>
</body></html>"#,
            html_escape(&provider.name),
            html_escape(&granted_scopes.join(", ")),
            html_escape(&provider.name),
            nonce
        )),
    )
        .into_response()
}

/// Simple HTML escaping for dynamic content in callback pages
fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Query parameters for the audit log endpoint
#[derive(Debug, Deserialize)]
pub struct AuditLogQuery {
    pub page: Option<usize>,
    pub page_size: Option<usize>,
    pub filter: Option<String>,
}

/// GET /api/v1/delegation-audit
pub async fn list_audit_events(Query(query): Query<AuditLogQuery>) -> impl IntoResponse {
    let page = query.page.unwrap_or(1).max(1);
    let page_size = query
        .page_size
        .unwrap_or(25)
        .clamp(1, 100);
    let filter = super::audit::AuditLogFilter {
        text: query.filter.as_deref(),
        // Keep the credential-delegation view clean: policy-decision evidence is
        // surfaced through the dedicated policy-audit endpoint instead.
        exclude_vp_audit: true,
        ..Default::default()
    };

    match super::audit::read_audit_log(page, page_size, filter).await {
        Ok(result) => (StatusCode::OK, Json(serde_json::to_value(result).unwrap())).into_response(),
        Err(e) => {
            warn!(target: "credential_delegation", error = %e, "Failed to read audit log");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to read audit log: {}", e)})),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consent_granted_workload_binding_vp_requires_explicit_enablement_and_issuer() {
        assert!(!should_mint_consent_granted_workload_binding_vp(false, false));
        assert!(!should_mint_consent_granted_workload_binding_vp(false, true));
        assert!(!should_mint_consent_granted_workload_binding_vp(true, false));
        assert!(should_mint_consent_granted_workload_binding_vp(true, true));
    }
}
