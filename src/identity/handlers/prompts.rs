//! API handlers for prompt-template management.
//!
//! Prompts are versioned, reusable chat templates rendered at the gateway.
//! CRUD is admin-gated via the `prompts.*` RBAC features. The id is
//! caller-supplied (validated) so prompts are referenced by a stable slug.

use std::sync::Arc;

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::state::IdentityApiState;
use crate::prompts::FileSystemPromptStore;
use crate::prompts::types::Prompt;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::{
    PatTenantContext, ResourceKind, can_access, can_mutate, scope_allows_resource, tenant_for_create,
};

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Resolve the configured prompt store or fail.
fn store(state: &IdentityApiState) -> ApiResult<Arc<FileSystemPromptStore>> {
    state
        .prompt_store
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Prompt store not configured".to_string()))
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

fn prompt_allowed(
    prompt: &Prompt,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    // A prompt with no tenant is an intentional global/shared prompt (the
    // documented model, see `legacy_prompt_without_tenant_id_is_global`) and is
    // readable by every caller. Tenant-owned prompts (tenant_id set) stay
    // confined by the fail-closed tenancy gate + the token id-namespace.
    if prompt.tenant_id.is_none() {
        return true;
    }
    can_access(prompt.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Prompts, &prompt.id)
}

/// May this caller change or delete the prompt, rather than read it?
///
/// [`prompt_allowed`] lets every caller read an untenanted prompt, but an
/// untenanted prompt is rendered for every tenant, so only the operator may
/// change it; a tenant token may change only what carries its own tenant id.
fn prompt_writable(
    prompt: &Prompt,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> bool {
    can_mutate(prompt.tenant_id.as_deref(), context)
        && scope_allows_resource(scope, context, ResourceKind::Prompts, &prompt.id)
}

/// Validate a caller-supplied prompt id: non-empty, ≤128 chars, and only
/// `[A-Za-z0-9_-]` so it is safe as a storage filename (no path traversal).
fn validate_prompt_id(id: &str) -> ApiResult<()> {
    if !crate::prompts::is_valid_prompt_id(id) {
        return Err((
            StatusCode::BAD_REQUEST,
            "Prompt id must be 1–128 characters of letters, digits, '_' and '-'".to_string(),
        ));
    }
    Ok(())
}

/// `GET /v1/prompts` — list all non-deleted prompts.
pub async fn list_prompts(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Vec<Prompt>>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsView).await?;
    let context_ref = tenant_context(&context);
    let scope_ref = resource_scope(&scope);
    let mut prompts = store(&state)?
        .list_active()
        .await;
    prompts.retain(|prompt| prompt_allowed(prompt, context_ref, scope_ref));
    Ok(Json(prompts))
}

/// `GET /v1/prompts/{id}` — fetch a single prompt.
pub async fn get_prompt(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<Prompt>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsView).await?;
    store(&state)?
        .get(&id)
        .await
        .filter(|prompt| {
            !prompt.status.is_deleted() && prompt_allowed(prompt, tenant_context(&context), resource_scope(&scope))
        })
        .map(Json)
        .ok_or((StatusCode::NOT_FOUND, format!("Prompt not found: {id}")))
}

/// `POST /v1/prompts` — create a prompt. The caller supplies the id.
pub async fn create_prompt(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut prompt): Json<Prompt>,
) -> ApiResult<Json<Prompt>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsEdit).await?;
    let prompt_store = store(&state)?;

    validate_prompt_id(&prompt.id)?;
    prompt.tenant_id = tenant_for_create(prompt.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    if !prompt_allowed(&prompt, tenant_context(&context), resource_scope(&scope)) {
        return Err((
            StatusCode::FORBIDDEN,
            format!("prompt id '{}' is outside this token's permitted namespace", prompt.id),
        ));
    }
    if prompt_store
        .get(&prompt.id)
        .await
        .is_some_and(|p| !p.status.is_deleted())
    {
        return Err((StatusCode::CONFLICT, format!("A prompt with id '{}' already exists", prompt.id)));
    }

    crate::config::enforce_add("prompts")
        .await
        .map_err(|e| (StatusCode::FORBIDDEN, e.message()))?;

    prompt
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid prompt: {e}")))?;

    let now = chrono::Utc::now();
    prompt.created_at = now;
    prompt.updated_at = now;
    prompt_store
        .save(&prompt)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save prompt: {e}")))?;
    Ok(Json(prompt))
}

/// `PUT /v1/prompts/{id}` — replace a prompt's configuration.
pub async fn update_prompt(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(mut prompt): Json<Prompt>,
) -> ApiResult<Json<Prompt>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsEdit).await?;
    let prompt_store = store(&state)?;

    let existing = prompt_store
        .get(&id)
        .await
        .filter(|p| !p.status.is_deleted())
        .ok_or((StatusCode::NOT_FOUND, format!("Prompt not found: {id}")))?;
    if !prompt_writable(&existing, tenant_context(&context), resource_scope(&scope)) {
        return Err((StatusCode::FORBIDDEN, "Prompt is outside this token's permitted scope".into()));
    }

    // The path id is authoritative; carry the creation timestamp forward.
    prompt.id = id;
    prompt.tenant_id = existing.tenant_id;
    prompt.created_at = existing.created_at;
    prompt.updated_at = chrono::Utc::now();
    prompt
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid prompt: {e}")))?;
    prompt_store
        .save(&prompt)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save prompt: {e}")))?;
    Ok(Json(prompt))
}

/// `DELETE /v1/prompts/{id}` — tombstone a prompt (retained on disk).
pub async fn delete_prompt(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<StatusCode> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsDelete).await?;
    let prompt_store = store(&state)?;

    let mut prompt = prompt_store
        .get(&id)
        .await
        .filter(|p| !p.status.is_deleted())
        .ok_or((StatusCode::NOT_FOUND, format!("Prompt not found: {id}")))?;
    if !prompt_writable(&prompt, tenant_context(&context), resource_scope(&scope)) {
        return Err((StatusCode::FORBIDDEN, "Prompt is outside this token's permitted scope".into()));
    }
    prompt.status = crate::entity_status::EntityStatus::Deleted;
    prompt.updated_at = chrono::Utc::now();
    prompt_store
        .save(&prompt)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete prompt: {e}")))?;
    Ok(StatusCode::NO_CONTENT)
}

/// Body for the render (playground) endpoint.
#[derive(Debug, Deserialize, Default)]
pub struct RenderRequest {
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub variables: serde_json::Map<String, Value>,
}

/// `POST /v1/prompts/{id}/render` — render a prompt to an OpenAI `messages`
/// array with the supplied variables (the playground preview).
pub async fn render_prompt(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    pat: Option<Extension<PatContext>>,
    Json(req): Json<RenderRequest>,
) -> ApiResult<Json<Value>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::PromptsView).await?;
    let prompt = store(&state)?
        .get_active(&id)
        .await
        .filter(|prompt| prompt_allowed(prompt, tenant_context(&context), resource_scope(&scope)))
        .ok_or((StatusCode::NOT_FOUND, format!("Prompt not found: {id}")))?;
    // Surface the version's declared `{{variables}}` alongside the render so the
    // playground can show which inputs the template expects.
    let declared = prompt
        .resolve_version(req.version)
        .map(|v| v.variables())
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let messages = prompt
        .render(req.version, &req.variables)
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    Ok(Json(json!({ "messages": messages, "variables": declared })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_status::EntityStatus;

    fn prompt(tenant_id: Option<&str>) -> Prompt {
        Prompt {
            id: "prompt-1".into(),
            name: "Prompt".into(),
            description: None,
            status: EntityStatus::Enabled,
            test_fixture: false,
            tenant_id: tenant_id.map(str::to_string),
            versions: vec![],
            default_version: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn canonical_prompt_access_combines_tenant_kind_and_id() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:prompts:prompt-1\z").unwrap()));
        assert!(prompt_allowed(&prompt(Some("tenant-a")), Some(&context), Some(&scope)));
        assert!(prompt_allowed(&prompt(None), Some(&context), Some(&scope)));
        assert!(!prompt_allowed(&prompt(Some("tenant-b")), Some(&context), Some(&scope)));

        let wrong_kind = PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:pipes:prompt-1\z").unwrap()));
        assert!(!prompt_allowed(&prompt(Some("tenant-a")), Some(&context), Some(&wrong_kind)));
    }

    #[test]
    fn a_tenant_may_read_a_global_prompt_but_not_rewrite_it() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:prompts:.*\z").unwrap()));
        assert!(prompt_allowed(&prompt(None), Some(&context), Some(&scope)));
        assert!(!prompt_writable(&prompt(None), Some(&context), Some(&scope)));
        assert!(prompt_writable(&prompt(Some("tenant-a")), Some(&context), Some(&scope)));
        assert!(!prompt_writable(&prompt(Some("tenant-b")), Some(&context), Some(&scope)));

        let wrong_kind = PatResourceScope(Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:pipes:.*\z").unwrap()));
        assert!(!prompt_writable(&prompt(Some("tenant-a")), Some(&context), Some(&wrong_kind)));

        assert!(prompt_writable(&prompt(None), None, None));
        assert!(prompt_writable(&prompt(Some("tenant-a")), None, None));
        assert!(!prompt_writable(&prompt(None), None, Some(&scope)));
    }
}
