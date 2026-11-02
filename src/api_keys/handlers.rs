//! API Key HTTP handlers

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tracing::error;

use super::errors::ApiKeyError;
use super::generator::DefaultKeyGenerator;
use super::models::CreateApiKeyRequest;
use super::parent::ApiKeyParents;
use super::traits::ApiKeyStore;
use crate::auth_manager::pat::PatResourceScope;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

/// Shared state for API key handlers
pub type ApiKeyState = Arc<dyn ApiKeyStore>;

/// Path parameters for agent-scoped operations
#[derive(Debug, Deserialize)]
pub struct AgentPath {
    pub agent_id: String,
}

/// Path parameters for key-specific operations
#[derive(Debug, Deserialize)]
pub struct KeyPath {
    pub agent_id: String,
    pub key_id: String,
}

/// Request body for revoke/rotate operations
#[derive(Debug, Deserialize)]
pub struct ActorRequest {
    #[serde(default = "default_actor")]
    pub actor: String,
}

fn default_actor() -> String {
    "api".to_string()
}

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

fn api_key_allowed(
    key_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::ApiKeys, key_id)
}

fn collection_key_allowed(
    agent_id: &str,
    key_id: &str,
    allowed_agents: &HashSet<String>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    let unrestricted = context.is_none() && scope.is_none();
    (unrestricted || allowed_agents.contains(agent_id)) && api_key_allowed(key_id, context, scope)
}

async fn authorize_agent(
    parents: &ApiKeyParents,
    agent_id: &str,
    context: &Option<Extension<PatTenantContext>>,
    mutation: bool,
) -> Result<(), axum::response::Response> {
    match parents
        .tenants(agent_id)
        .await
    {
        Ok(tenants) if tenants.is_empty() => {
            Err(ApiKeyError::AgentNotFound { agent_id: agent_id.to_string() }.into_response())
        }
        Ok(tenants)
            if tenants
                .iter()
                .all(|tenant_id| can_access(tenant_id.as_deref(), tenant_context(context))) =>
        {
            Ok(())
        }
        Ok(_) => {
            let status = if mutation {
                StatusCode::FORBIDDEN
            } else {
                StatusCode::NOT_FOUND
            };
            Err((status, Json(serde_json::json!({ "error": "Agent not accessible" }))).into_response())
        }
        Err(error) => {
            error!(agent_id = %agent_id, %error, "Failed to resolve API-key parent surface");
            Err((StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response())
        }
    }
}

/// Convert ApiKeyError to HTTP response
impl IntoResponse for ApiKeyError {
    fn into_response(self) -> axum::response::Response {
        let (status, message) = match &self {
            ApiKeyError::KeyNotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            ApiKeyError::AgentNotFound { .. } => (StatusCode::NOT_FOUND, self.to_string()),
            ApiKeyError::AlreadyRevoked { .. } => (StatusCode::CONFLICT, self.to_string()),
            ApiKeyError::InvalidStatusTransition { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiKeyError::Validation { .. } => (StatusCode::BAD_REQUEST, self.to_string()),
            ApiKeyError::Storage(_) | ApiKeyError::Serialization(_) | ApiKeyError::Io(_) => {
                error!("Internal error: {}", self);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string())
            }
        };

        let body = serde_json::json!({
            "error": message
        });

        (status, Json(body)).into_response()
    }
}

/// List all API keys for an agent
///
/// GET /api/v1/api-keys/{agent_id}
pub async fn list_keys(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(AgentPath { agent_id }): Path<AgentPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, false).await {
        return response;
    }
    match store.list(&agent_id).await {
        Ok(mut keys) => {
            keys.retain(|key| api_key_allowed(&key.key_id, &context, &scope));
            (StatusCode::OK, Json(keys)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// List all API keys across all agents
///
/// GET /api/v1/api-keys
pub async fn list_all_keys(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    let allowed_agents = match parents
        .accessible(tenant_context(&context))
        .await
    {
        Ok(allowed_agents) => allowed_agents,
        Err(error) => {
            error!(%error, "Failed to list API-key parent surfaces");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response();
        }
    };
    match store.list_all().await {
        Ok(mut keys) => {
            keys.retain(|key| collection_key_allowed(&key.agent_id, &key.key_id, &allowed_agents, &context, &scope));
            (StatusCode::OK, Json(keys)).into_response()
        }
        Err(e) => e.into_response(),
    }
}

/// Create a new API key
///
/// POST /api/v1/api-keys/{agent_id}
pub async fn create_key(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(AgentPath { agent_id }): Path<AgentPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<CreateApiKeyRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, true).await {
        return response;
    }
    // Enforce the appliance API-key limit (plus the cross-store secrets total).
    if let Err(e) = crate::config::enforce_add("secrets.apikeys").await {
        return (StatusCode::FORBIDDEN, Json(serde_json::json!({ "message": e.message() }))).into_response();
    }

    let labels: Option<HashMap<String, String>> = request.labels;

    // A positive lifetime yields an absolute expiry instant; anything else means
    // the key never expires.
    let expires_at = request
        .expires_in_seconds
        .filter(|secs| *secs > 0)
        .map(|secs| chrono::Utc::now() + chrono::Duration::seconds(secs));

    let (key_id, secret) = DefaultKeyGenerator::generate();
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }

    match store
        .create_with_material_and_expiry(&agent_id, key_id, secret, &request.client_id, labels, "api", expires_at)
        .await
    {
        Ok(created) => (StatusCode::CREATED, Json(created)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Get API key metadata. The secret is disclosed only by create/rotate responses.
///
/// GET /api/v1/api-keys/{agent_id}/{key_id}
pub async fn get_key(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, false).await {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return ApiKeyError::not_found(&key_id).into_response();
    }
    match store
        .get(&agent_id, &key_id)
        .await
    {
        Ok(Some(key)) => (StatusCode::OK, Json(key)).into_response(),
        Ok(None) => ApiKeyError::not_found(&key_id).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Revoke an API key
///
/// POST /api/v1/api-keys/{agent_id}/{key_id}/revoke
pub async fn revoke_key(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ActorRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, true).await {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .revoke(&agent_id, &key_id, &request.actor)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

/// Rotate an API key
///
/// POST /api/v1/api-keys/{agent_id}/{key_id}/rotate
pub async fn rotate_key(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ActorRequest>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, true).await {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    let (new_key_id, new_secret) = DefaultKeyGenerator::generate();
    if !api_key_allowed(&new_key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "Replacement API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .rotate_with_material(&agent_id, &key_id, new_key_id, new_secret, &request.actor)
        .await
    {
        Ok(created) => (StatusCode::OK, Json(created)).into_response(),
        Err(e) => e.into_response(),
    }
}

/// Delete an API key permanently
///
/// DELETE /api/v1/api-keys/{agent_id}/{key_id}
pub async fn delete_key(
    State(store): State<ApiKeyState>,
    Extension(parents): Extension<ApiKeyParents>,
    Path(KeyPath { agent_id, key_id }): Path<KeyPath>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> impl IntoResponse {
    if let Err(response) = authorize_agent(&parents, &agent_id, &context, true).await {
        return response;
    }
    if !api_key_allowed(&key_id, &context, &scope) {
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({ "error": "API key is outside this token's permitted scope" })),
        )
            .into_response();
    }
    match store
        .delete(&agent_id, &key_id)
        .await
    {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => e.into_response(),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use async_trait::async_trait;
    use regex::Regex;

    use super::*;
    use crate::api_keys::parent::tests::{fabric_record, llm_surface, parents_with};
    use crate::api_keys::{ApiKeyCreated, ApiKeyMeta, ApiKeyResult, FsApiKeyStore};

    struct CountingKeyStore {
        creates: AtomicUsize,
        rotations: AtomicUsize,
    }

    #[async_trait]
    impl ApiKeyStore for CountingKeyStore {
        async fn create_with_material_and_expiry(
            &self,
            _agent_id: &str,
            _key_id: String,
            _secret: String,
            _client_id: &str,
            _labels: Option<HashMap<String, String>>,
            _actor: &str,
            _expires_at: Option<chrono::DateTime<chrono::Utc>>,
        ) -> ApiKeyResult<ApiKeyCreated> {
            self.creates
                .fetch_add(1, Ordering::SeqCst);
            unreachable!()
        }

        async fn list(
            &self,
            _agent_id: &str,
        ) -> ApiKeyResult<Vec<ApiKeyMeta>> {
            Ok(Vec::new())
        }

        async fn list_all(&self) -> ApiKeyResult<Vec<ApiKeyMeta>> {
            Ok(Vec::new())
        }

        async fn get(
            &self,
            _agent_id: &str,
            _key_id: &str,
        ) -> ApiKeyResult<Option<ApiKeyMeta>> {
            Ok(None)
        }

        async fn revoke(
            &self,
            _agent_id: &str,
            _key_id: &str,
            _actor: &str,
        ) -> ApiKeyResult<()> {
            unreachable!()
        }

        async fn rotate_with_material(
            &self,
            _agent_id: &str,
            _key_id: &str,
            _new_key_id: String,
            _new_secret: String,
            _actor: &str,
        ) -> ApiKeyResult<ApiKeyCreated> {
            self.rotations
                .fetch_add(1, Ordering::SeqCst);
            unreachable!()
        }

        async fn delete(
            &self,
            _agent_id: &str,
            _key_id: &str,
        ) -> ApiKeyResult<()> {
            unreachable!()
        }

        async fn touch_usage(
            &self,
            _agent_id: &str,
            _key_id: &str,
        ) -> ApiKeyResult<()> {
            unreachable!()
        }
    }

    #[test]
    fn api_key_scope_checks_child_id_separately_from_parent_ownership() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(Arc::new(
            Regex::new(r"\ATENANT:tenant-a:api-keys:askey_allowed\z").unwrap(),
        ))));

        assert!(api_key_allowed("askey_allowed", &context, &scope));
        assert!(!api_key_allowed("askey_denied", &context, &scope));
    }

    #[test]
    fn unrestricted_collection_includes_orphans_but_scoped_collection_does_not() {
        let allowed_agents = HashSet::from(["surface-a".to_string()]);

        assert!(collection_key_allowed("orphaned-surface", "askey_orphan", &allowed_agents, &None, &None,));

        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        assert!(!collection_key_allowed("orphaned-surface", "askey_orphan", &allowed_agents, &context, &None,));
        assert!(collection_key_allowed("surface-a", "askey_owned", &allowed_agents, &context, &None,));
    }

    #[tokio::test]
    async fn generated_ids_are_denied_before_create_or_rotation_mutates_store() {
        let key_store = Arc::new(CountingKeyStore {
            creates: AtomicUsize::new(0),
            rotations: AtomicUsize::new(0),
        });
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(&dir, vec![fabric_record("surface-a", None)], Vec::new()).await;

        let create_response = create_key(
            State(key_store.clone()),
            Extension(parents.clone()),
            Path(AgentPath { agent_id: "surface-a".into() }),
            None,
            Some(Extension(PatResourceScope(Arc::new(Regex::new(r"\Anever-match\z").unwrap())))),
            Json(CreateApiKeyRequest {
                client_id: "client-a".into(),
                labels: None,
                expires_in_seconds: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(create_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            key_store
                .creates
                .load(Ordering::SeqCst),
            0
        );

        let rotate_response = rotate_key(
            State(key_store.clone()),
            Extension(parents),
            Path(KeyPath {
                agent_id: "surface-a".into(),
                key_id: "askey_old".into(),
            }),
            None,
            Some(Extension(PatResourceScope(Arc::new(Regex::new(r"\Aaskey_old\z").unwrap())))),
            Json(ActorRequest { actor: "test".into() }),
        )
        .await
        .into_response();
        assert_eq!(rotate_response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            key_store
                .rotations
                .load(Ordering::SeqCst),
            0
        );
    }

    async fn create_for(
        parents: &ApiKeyParents,
        agent_id: &str,
        context: Option<Extension<PatTenantContext>>,
    ) -> (StatusCode, serde_json::Value) {
        let dir = tempfile::tempdir().unwrap();
        let store: ApiKeyState = Arc::new(
            FsApiKeyStore::new(dir.path().to_str().unwrap())
                .await
                .unwrap(),
        );
        let response = create_key(
            State(store),
            Extension(parents.clone()),
            Path(AgentPath { agent_id: agent_id.into() }),
            context,
            None,
            Json(CreateApiKeyRequest {
                client_id: "client-a".into(),
                labels: None,
                expires_in_seconds: None,
            }),
        )
        .await
        .into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    fn tenant_a() -> Option<Extension<PatTenantContext>> {
        Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }))
    }

    #[tokio::test]
    async fn a_key_is_issued_for_an_llm_surface() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(&dir, Vec::new(), vec![llm_surface("chat-a", Some("tenant-a"))]).await;

        let (status, body) = create_for(&parents, "chat-a", tenant_a()).await;

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(body["agent_id"], "chat-a");
        assert!(
            body["secret"]
                .as_str()
                .is_some_and(|secret| !secret.is_empty())
        );
    }

    #[tokio::test]
    async fn a_key_is_refused_for_an_unknown_or_foreign_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(
            &dir,
            vec![fabric_record("shared", Some("tenant-b"))],
            vec![llm_surface("chat-b", Some("tenant-b")), llm_surface("shared", Some("tenant-a"))],
        )
        .await;

        assert_eq!(
            create_for(&parents, "missing", tenant_a())
                .await
                .0,
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            create_for(&parents, "chat-b", tenant_a())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            create_for(&parents, "shared", tenant_a())
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }

    fn scope(pattern: &str) -> Option<Extension<PatResourceScope>> {
        Some(Extension(PatResourceScope(Arc::new(Regex::new(pattern).unwrap()))))
    }

    async fn rotate_in(
        store: &ApiKeyState,
        parents: &ApiKeyParents,
        key_id: &str,
        scope: Option<Extension<PatResourceScope>>,
    ) -> (StatusCode, serde_json::Value) {
        let response = rotate_key(
            State(store.clone()),
            Extension(parents.clone()),
            Path(KeyPath {
                agent_id: "chat-a".into(),
                key_id: key_id.into(),
            }),
            tenant_a(),
            scope,
            Json(ActorRequest { actor: "test".into() }),
        )
        .await
        .into_response();
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap_or_default())
    }

    #[tokio::test]
    async fn a_scope_written_for_legacy_key_ids_covers_new_keys() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(&dir, Vec::new(), vec![llm_surface("chat-a", Some("tenant-a"))]).await;
        let store_dir = tempfile::tempdir().unwrap();
        let store: ApiKeyState = Arc::new(
            FsApiKeyStore::new(
                store_dir
                    .path()
                    .to_str()
                    .unwrap(),
            )
            .await
            .unwrap(),
        );
        for key_id in ["atgk_old", "atgk_other"] {
            store
                .create_with_material_and_expiry(
                    "chat-a",
                    key_id.into(),
                    "atgs_secret".into(),
                    "client-a",
                    None,
                    "test",
                    None,
                )
                .await
                .unwrap();
        }
        let legacy_scope = r"\ATENANT:tenant-a:api-keys:atgk_.*\z";

        let created = create_key(
            State(store.clone()),
            Extension(parents.clone()),
            Path(AgentPath { agent_id: "chat-a".into() }),
            tenant_a(),
            scope(legacy_scope),
            Json(CreateApiKeyRequest {
                client_id: "client-a".into(),
                labels: None,
                expires_in_seconds: None,
            }),
        )
        .await
        .into_response();
        assert_eq!(created.status(), StatusCode::CREATED);

        let (status, body) = rotate_in(&store, &parents, "atgk_old", scope(legacy_scope)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body["key_id"]
                .as_str()
                .is_some_and(|key_id| key_id.starts_with(crate::api_keys::KEY_ID_PREFIX))
        );

        let (status, _) =
            rotate_in(&store, &parents, "atgk_other", scope(r"\ATENANT:tenant-a:api-keys:atgk_other\z")).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }
}
