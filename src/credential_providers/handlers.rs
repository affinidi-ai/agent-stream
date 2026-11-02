//! API handlers for credential provider CRUD operations

use super::{
    CreateCredentialProviderRequest, CredentialProvider, CredentialProviderListItem, CredentialProviderType,
    UpdateCredentialProviderRequest, storage::CredentialProviderStorage,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use chrono::Utc;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::secrets::SecretsStore;
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource, tenant_for_create,
};

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn provider_allowed(
    provider: &CredentialProvider,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(provider.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::CredentialProviders,
            &provider.id,
        )
}

#[derive(Clone)]
pub struct CredentialProviderState {
    pub store: Arc<dyn CredentialProviderStorage>,
    pub secrets_store: Arc<dyn SecretsStore>,
    pub oauth_callback_route: String,
}

async fn validate_secret_references(
    state: &CredentialProviderState,
    tenant_id: Option<&str>,
    references: impl IntoIterator<Item = Option<&str>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), Response> {
    for secret_id in references
        .into_iter()
        .flatten()
    {
        let secret = state
            .secrets_store
            .get_by_secret_id(secret_id)
            .await
            .map_err(|error| {
                warn!(%error, "Failed to validate credential provider Secret reference");
                (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": "Internal server error" })))
                    .into_response()
            })?
            .ok_or_else(|| {
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "Secret reference is not accessible" })))
                    .into_response()
            })?;
        if !can_reference(tenant_id, secret.tenant_id.as_deref())
            || !scope_allows_resource(
                resource_scope(scope),
                tenant_context(context),
                ResourceKind::Secrets,
                &secret.secret_id,
            )
        {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": "Secret reference is not accessible" })),
            )
                .into_response());
        }
    }
    Ok(())
}

/// Validate a set of named URL fields against the SSRF blocklist.
/// Returns an error response on the first invalid URL, or `None` if all pass.
async fn validate_url_fields(fields: &[(&str, Option<&str>)]) -> Option<Response> {
    for (name, value) in fields {
        let Some(raw) = value else { continue };
        if let Err(e) = crate::url_validation::validate_service_endpoint_url(raw).await {
            return Some(
                (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("{}: {}", name, e)})))
                    .into_response(),
            );
        }
    }
    None
}

/// POST /api/v1/credential-providers
pub async fn create_provider(
    State(state): State<CredentialProviderState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateCredentialProviderRequest>,
) -> impl IntoResponse {
    req.tenant_id = match tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context)) {
        Ok(tenant_id) => tenant_id,
        Err(message) => return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "error": message }))).into_response(),
    };
    // Validate required fields
    if req.name.trim().is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "name is required"}))).into_response();
    }
    if req
        .provider_id
        .trim()
        .is_empty()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "provider_id is required"})))
            .into_response();
    }

    // Type-specific validation
    match &req.provider_type {
        CredentialProviderType::OAuth2AuthorizationCode | CredentialProviderType::OAuth2ClientCredentials => {
            if req
                .token_endpoint
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "token_endpoint is required for OAuth providers"})),
                )
                    .into_response();
            }
            if req
                .client_id_secret_ref
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
                || req
                    .client_secret_secret_ref
                    .as_deref()
                    .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "client_id_secret_ref and client_secret_secret_ref are required for OAuth providers"})),
                )
                    .into_response();
            }
        }
        CredentialProviderType::ApiKey => {
            if req
                .api_key_secret_ref
                .as_deref()
                .is_none_or(|s| s.trim().is_empty())
            {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({"error": "api_key_secret_ref is required for ApiKey providers"})),
                )
                    .into_response();
            }
        }
    }

    // Validate user-supplied URLs before storing them
    if let Some(resp) = validate_url_fields(&[
        ("token_endpoint", req.token_endpoint.as_deref()),
        (
            "authorization_endpoint",
            req.authorization_endpoint
                .as_deref(),
        ),
        ("callback_url", req.callback_url.as_deref()),
    ])
    .await
    {
        return resp;
    }

    if let Err(response) = validate_secret_references(
        &state,
        req.tenant_id.as_deref(),
        [
            req.client_id_secret_ref
                .as_deref(),
            req.client_secret_secret_ref
                .as_deref(),
            req.api_key_secret_ref
                .as_deref(),
        ],
        &context,
        &scope,
    )
    .await
    {
        return response;
    }

    // Check for duplicate provider_id
    match state
        .store
        .find_by_provider_id(&req.provider_id)
        .await
    {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": format!("provider_id '{}' already exists", req.provider_id)
                })),
            )
                .into_response();
        }
        Ok(None) => {}
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to check for duplicate provider_id"
            );
        }
    }

    let provider_id_clean = req
        .provider_id
        .trim()
        .to_lowercase();
    let id = Uuid::new_v4().to_string();
    let now = Utc::now();

    let provider = CredentialProvider {
        id: id.clone(),
        name: req.name.trim().to_string(),
        provider_id: provider_id_clean.clone(),
        provider_type: req.provider_type,
        authorization_endpoint: req.authorization_endpoint,
        token_endpoint: req
            .token_endpoint
            .map(|s| s.trim().to_string()),
        client_id_secret_ref: req
            .client_id_secret_ref
            .map(|s| s.trim().to_string()),
        client_secret_secret_ref: req
            .client_secret_secret_ref
            .map(|s| s.trim().to_string()),
        default_scopes: req.default_scopes,
        callback_path: format!("{}/{}", state.oauth_callback_route, provider_id_clean),
        callback_url: req
            .callback_url
            .map(|s| s.trim().to_string()),
        token_refresh_enabled: req.token_refresh_enabled,
        additional_params: req.additional_params,
        api_key_secret_ref: req
            .api_key_secret_ref
            .map(|s| s.trim().to_string()),
        description: req.description,
        tenant_id: req.tenant_id,
        created_at: now,
        updated_at: now,
    };
    if !provider_allowed(&provider, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }

    if let Err(e) = crate::config::enforce_add("credentials.providers").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": e.message()}))).into_response();
    }

    match state
        .store
        .create(provider.clone())
        .await
    {
        Ok(created) => (StatusCode::CREATED, Json(serde_json::to_value(created).unwrap())).into_response(),
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to create credential provider"
            );
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to create: {}", e)})))
                .into_response()
        }
    }
}

/// GET /api/v1/credential-providers
pub async fn list_providers(
    State(state): State<CredentialProviderState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match state.store.list().await {
        Ok(mut providers) => {
            providers.retain(|provider| provider_allowed(provider, &context, &scope));
            let items: Vec<CredentialProviderListItem> = providers
                .iter()
                .map(|p| p.into())
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(items).unwrap())).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to list: {}", e)})))
                .into_response()
        }
    }
}

/// GET /api/v1/credential-providers/{id}
pub async fn get_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    match state.store.get(&id).await {
        Ok(Some(provider)) if provider_allowed(&provider, &context, &scope) => {
            (StatusCode::OK, Json(serde_json::to_value(provider).unwrap())).into_response()
        }
        Ok(Some(_)) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Ok(None) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to get: {}", e)})))
                .into_response()
        }
    }
}

/// PUT /api/v1/credential-providers/{id}
pub async fn update_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateCredentialProviderRequest>,
) -> impl IntoResponse {
    let existing = match state.store.get(&id).await {
        Ok(Some(p)) => p,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to get: {}", e)})),
            )
                .into_response();
        }
    };
    if !provider_allowed(&existing, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }

    // Validate any user-supplied URLs before applying the update
    if let Some(resp) = validate_url_fields(&[
        ("token_endpoint", req.token_endpoint.as_deref()),
        (
            "authorization_endpoint",
            req.authorization_endpoint
                .as_deref(),
        ),
        ("callback_url", req.callback_url.as_deref()),
    ])
    .await
    {
        return resp;
    }

    let updated = CredentialProvider {
        id: existing.id,
        name: req
            .name
            .unwrap_or(existing.name),
        provider_id: existing.provider_id, // immutable
        provider_type: req
            .provider_type
            .unwrap_or(existing.provider_type),
        authorization_endpoint: req
            .authorization_endpoint
            .or(existing.authorization_endpoint),
        token_endpoint: req
            .token_endpoint
            .or(existing.token_endpoint),
        client_id_secret_ref: req
            .client_id_secret_ref
            .or(existing.client_id_secret_ref),
        client_secret_secret_ref: req
            .client_secret_secret_ref
            .or(existing.client_secret_secret_ref),
        default_scopes: req
            .default_scopes
            .unwrap_or(existing.default_scopes),
        callback_path: existing.callback_path, // auto-generated, immutable
        callback_url: req
            .callback_url
            .or(existing.callback_url),
        token_refresh_enabled: req
            .token_refresh_enabled
            .unwrap_or(existing.token_refresh_enabled),
        additional_params: req
            .additional_params
            .unwrap_or(existing.additional_params),
        api_key_secret_ref: req
            .api_key_secret_ref
            .or(existing.api_key_secret_ref),
        description: req
            .description
            .or(existing.description),
        tenant_id: existing.tenant_id,
        created_at: existing.created_at,
        updated_at: Utc::now(),
    };

    if let Err(response) = validate_secret_references(
        &state,
        updated.tenant_id.as_deref(),
        [
            updated
                .client_id_secret_ref
                .as_deref(),
            updated
                .client_secret_secret_ref
                .as_deref(),
            updated
                .api_key_secret_ref
                .as_deref(),
        ],
        &context,
        &scope,
    )
    .await
    {
        return response;
    }

    match state
        .store
        .update(updated.clone())
        .await
    {
        Ok(u) => (StatusCode::OK, Json(serde_json::to_value(u).unwrap())).into_response(),
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to update: {}", e)})))
                .into_response()
        }
    }
}

/// DELETE /api/v1/credential-providers/{id}
pub async fn delete_provider(
    State(state): State<CredentialProviderState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let existing = match state.store.get(&id).await {
        Ok(Some(provider)) => provider,
        Ok(None) => {
            return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"})))
                .into_response();
        }
        Err(error) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": error.to_string()})))
                .into_response();
        }
    };
    if !provider_allowed(&existing, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "credential provider is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match state.store.delete(&id).await {
        Ok(true) => {
            info!(
                target: "credential_delegation",
                id = %id,
                "Credential provider deleted via API"
            );
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "Credential provider not found"}))).into_response()
        }
        Err(e) => {
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Failed to delete: {}", e)})))
                .into_response()
        }
    }
}

/// POST /api/v1/credential-providers/validate
/// Tests that the token endpoint is reachable
pub async fn validate_provider(Json(req): Json<serde_json::Value>) -> impl IntoResponse {
    let token_endpoint = match req
        .get("token_endpoint")
        .and_then(|v| v.as_str())
    {
        Some(url) => url.to_string(),
        None => {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "token_endpoint is required"})))
                .into_response();
        }
    };

    if let Err(e) = crate::url_validation::validate_service_endpoint_url(&token_endpoint).await {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("token_endpoint: {}", e)})))
            .into_response();
    }

    let client = match crate::http_client::with_service_endpoint_resolver(std::time::Duration::from_secs(
        crate::http_client::SHORT_TIMEOUT_SECS,
    )) {
        Ok(client) => client,
        Err(e) => {
            warn!(
                target: "credential_delegation",
                error = %e,
                "Failed to build token endpoint validation HTTP client"
            );
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to build HTTP client: {}", e)})),
            )
                .into_response();
        }
    };
    let safe_token_endpoint = crate::url_validation::redact_url_for_logging(&token_endpoint);

    match client
        .get(&token_endpoint)
        .send()
        .await
    {
        Ok(resp) => {
            // We just check reachability — OAuth token endpoints typically return 400/405
            // for GET requests, which is fine
            let status = resp.status().as_u16();
            info!(
                target: "credential_delegation",
                token_endpoint = %safe_token_endpoint,
                http_status = %status,
                "Token endpoint validation check"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "reachable": true,
                    "http_status": status,
                    "token_endpoint": token_endpoint,
                })),
            )
                .into_response()
        }
        Err(e) => {
            warn!(
                target: "credential_delegation",
                token_endpoint = %safe_token_endpoint,
                error = %e,
                "Token endpoint validation failed"
            );
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "reachable": false,
                    "error": format!("{}", e),
                    "token_endpoint": token_endpoint,
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::*;

    fn provider(tenant_id: Option<&str>) -> CredentialProvider {
        let now = Utc::now();
        CredentialProvider {
            id: "provider-1".into(),
            name: "Provider".into(),
            provider_id: "provider".into(),
            provider_type: CredentialProviderType::ApiKey,
            authorization_endpoint: None,
            token_endpoint: None,
            client_id_secret_ref: None,
            client_secret_secret_ref: None,
            default_scopes: Vec::new(),
            callback_path: String::new(),
            callback_url: None,
            token_refresh_enabled: true,
            additional_params: HashMap::new(),
            api_key_secret_ref: Some("secret-1".into()),
            description: None,
            tenant_id: tenant_id.map(str::to_string),
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn canonical_provider_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:credential-providers:provider-1\z").unwrap(),
        ))));

        assert!(provider_allowed(&provider(Some("tenant-a")), &context, &scope));
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!provider_allowed(&provider(None), &context, &scope));
        assert!(!provider_allowed(&provider(Some("tenant-b")), &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:secrets:provider-1\z").unwrap(),
        ))));
        assert!(!provider_allowed(&provider(Some("tenant-a")), &context, &wrong_kind));
    }

    async fn validate(token_endpoint: &str) -> serde_json::Value {
        let response = validate_provider(Json(serde_json::json!({ "token_endpoint": token_endpoint })))
            .await
            .into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }

    #[tokio::test]
    async fn the_reachability_check_refuses_a_token_endpoint_that_rebinds_to_loopback() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("token").await;
        let dns = crate::url_validation::test_dns::rebind_to_loopback("idp.rebind.test");

        let result = validate(
            &upstream
                .url
                .replace("127.0.0.1", "idp.rebind.test"),
        )
        .await;

        assert_eq!(result["reachable"], false, "{result}");
        assert_eq!(dns.lookups(), 2, "the address must be checked again at connect time");
        assert_eq!(upstream.requests(), 0);
    }

    #[tokio::test]
    async fn the_reachability_check_reaches_an_allowed_token_endpoint() {
        let upstream = crate::pipes::test_upstreams::CaptureUpstream::answering("token").await;
        let token_endpoint = upstream
            .url
            .replace("127.0.0.1", "idp.allowed.test");
        let _dns = crate::url_validation::test_dns::answer("idp.allowed.test", &[[127, 0, 0, 1].into()]);
        let _allowed = crate::url_validation::test_service_endpoints::allow(std::slice::from_ref(&token_endpoint));

        let result = validate(&token_endpoint).await;

        assert_eq!(result["reachable"], true, "{result}");
        assert_eq!(result["http_status"], 200);
        assert_eq!(upstream.requests(), 1);
    }
}
