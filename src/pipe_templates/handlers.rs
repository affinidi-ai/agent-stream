//! REST handlers for pipe templates.

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use tracing::{debug, error, warn};

use super::filesystem::PipeTemplateStore;
use super::types::{CreatePipeTemplate, PipeTemplate};
use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::identity::handlers::pipes::{AppError, validate_pipe_id};
use crate::identity::state::IdentityApiState;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

/// Application error type for pipe template handlers.
#[derive(Debug)]
pub enum PipeTemplateApiError {
    BadRequest(String),
    NotFound(String),
    Forbidden(String),
    InternalError(String),
}

impl IntoResponse for PipeTemplateApiError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            Self::BadRequest(m) => {
                warn!("Pipe template API bad request: {}", m);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(m.clone()))
            }
            Self::NotFound(m) => {
                warn!("Pipe template API not found: {}", m);
                (StatusCode::NOT_FOUND, "Not Found", Some(m.clone()))
            }
            Self::Forbidden(m) => {
                warn!("Pipe template API forbidden: {}", m);
                (StatusCode::FORBIDDEN, "Forbidden", Some(m.clone()))
            }
            Self::InternalError(m) => {
                error!("Pipe template API internal error: {}", m);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(m.clone()))
            }
        };
        (
            status,
            Json(ErrorBody {
                error: message.to_string(),
                details,
            }),
        )
            .into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// The initialized template stores. All pipe templates persist in the
/// LLM-surface store; the generic pipe-template store has been retired.
fn all_stores(state: &IdentityApiState) -> Vec<&std::sync::Arc<super::FileSystemPipeTemplateStore>> {
    let mut stores = Vec::new();
    if let Some(s) = state
        .llm_surface_template_store
        .as_ref()
    {
        stores.push(s);
    }
    stores
}

/// Pick the store an incoming template should be persisted to. All
/// templates go to the LLM-surface store.
fn target_store<'a>(
    state: &'a IdentityApiState,
    _tpl: &PipeTemplate,
) -> Result<&'a std::sync::Arc<super::FileSystemPipeTemplateStore>, PipeTemplateApiError> {
    state
        .llm_surface_template_store
        .as_ref()
        .ok_or_else(|| PipeTemplateApiError::InternalError("Pipe template store not initialized".to_string()))
}

/// Locate the store currently holding `id`, returning it with the loaded
/// template. Searches the LLM-surface store first.
async fn locate<'a>(
    state: &'a IdentityApiState,
    id: &str,
) -> Result<Option<(&'a std::sync::Arc<super::FileSystemPipeTemplateStore>, PipeTemplate)>, PipeTemplateApiError> {
    for s in all_stores(state) {
        if let Some(tpl) = s
            .get(id)
            .await
            .map_err(|e| PipeTemplateApiError::InternalError(format!("get: {}", e)))?
        {
            return Ok(Some((s, tpl)));
        }
    }
    Ok(None)
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

fn template_allowed(
    template: &PipeTemplate,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    // Builtin templates are an appliance-wide, read-only shared library every
    // tenant instantiates pipes from — always readable, regardless of tenant
    // context or token id-namespace. Non-builtin untenanted templates are legacy
    // and fall through to the fail-closed tenancy gate below.
    if template.builtin {
        return true;
    }
    can_access(template.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::PipeTemplates,
            &template.id,
        )
}

/// `GET /v1/pipe-templates`
pub async fn list_templates(
    State(state): State<IdentityApiState>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<PipeTemplate>>, PipeTemplateApiError> {
    let mut templates = Vec::new();
    for s in all_stores(&state) {
        let mut part = s
            .list_all()
            .await
            .map_err(|e| PipeTemplateApiError::InternalError(format!("list: {}", e)))?;
        templates.append(&mut part);
    }
    templates.retain(|template| template_allowed(template, &context, &scope));
    // Stable order: builtins first (alphabetical), then user templates.
    templates.sort_by(|a, b| match (a.builtin, b.builtin) {
        (true, false) => std::cmp::Ordering::Less,
        (false, true) => std::cmp::Ordering::Greater,
        _ => a
            .name
            .to_lowercase()
            .cmp(&b.name.to_lowercase()),
    });
    debug!("Listed {} pipe template(s)", templates.len());
    Ok(Json(templates))
}

/// `GET /v1/pipe-templates/{id}`
pub async fn get_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<PipeTemplate>, PipeTemplateApiError> {
    let (_, tpl) = locate(&state, &id)
        .await?
        .ok_or_else(|| PipeTemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&tpl, &context, &scope) {
        return Err(PipeTemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    Ok(Json(tpl))
}

/// `POST /v1/pipe-templates`
pub async fn create_template(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreatePipeTemplate>,
) -> Result<(StatusCode, Json<PipeTemplate>), PipeTemplateApiError> {
    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| PipeTemplateApiError::Forbidden(message.to_string()))?;
    if req.name.trim().is_empty() {
        return Err(PipeTemplateApiError::BadRequest("name must not be empty".to_string()));
    }

    let id = format!("user-{}", uuid::Uuid::new_v4());
    let now = chrono::Utc::now().to_rfc3339();
    let tpl = req.into_template(id, now);
    if !template_allowed(&tpl, &context, &scope) {
        return Err(PipeTemplateApiError::Forbidden("Pipe template is outside this token's permitted scope".into()));
    }

    let s = target_store(&state, &tpl)?;
    s.save(&tpl)
        .await
        .map_err(|e| PipeTemplateApiError::InternalError(format!("save: {}", e)))?;
    Ok((StatusCode::CREATED, Json(tpl)))
}

/// `PUT /v1/pipe-templates/{id}`
pub async fn update_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut tpl): Json<PipeTemplate>,
) -> Result<Json<PipeTemplate>, PipeTemplateApiError> {
    let (s, existing) = locate(&state, &id)
        .await?
        .ok_or_else(|| PipeTemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, &context, &scope) {
        return Err(PipeTemplateApiError::Forbidden("Pipe template is outside this token's permitted scope".into()));
    }
    if existing.builtin {
        return Err(PipeTemplateApiError::Forbidden(format!("builtin template '{}' cannot be modified", id)));
    }
    tpl.id = id;
    tpl.builtin = false;
    tpl.tenant_id = existing.tenant_id;
    tpl.created_at = existing.created_at;
    tpl.updated_at = Some(chrono::Utc::now().to_rfc3339());
    if tpl.name.trim().is_empty() {
        return Err(PipeTemplateApiError::BadRequest("name must not be empty".to_string()));
    }
    s.save(&tpl)
        .await
        .map_err(|e| PipeTemplateApiError::InternalError(format!("save: {}", e)))?;
    Ok(Json(tpl))
}

/// `GET /v1/pipe-templates/{id}/export`
///
/// Returns the raw template JSON with a `Content-Disposition`
/// attachment header so browsers download it as a portable
/// `*.pipe-template.json` file. Server-managed fields are stripped so
/// the exported file is round-trippable across gateways.
pub async fn export_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Response, PipeTemplateApiError> {
    let (_, mut tpl) = locate(&state, &id)
        .await?
        .ok_or_else(|| PipeTemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&tpl, &context, &scope) {
        return Err(PipeTemplateApiError::NotFound(format!("template '{}' not found", id)));
    }
    tpl.tenant_id = None;
    tpl.builtin = false;
    tpl.created_at = None;
    tpl.updated_at = None;
    let body = serde_json::to_vec_pretty(&tpl)
        .map_err(|e| PipeTemplateApiError::InternalError(format!("serialize: {}", e)))?;
    let safe_id = id.replace(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_', "_");
    let filename = format!("{}.pipe-template.json", safe_id);
    let mut response = (StatusCode::OK, body).into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        "application/json"
            .parse()
            .unwrap(),
    );
    response.headers_mut().insert(
        axum::http::header::CONTENT_DISPOSITION,
        format!("attachment; filename=\"{}\"", filename)
            .parse()
            .unwrap(),
    );
    Ok(response)
}

/// `POST /v1/pipe-templates/import`
///
/// Accepts a `PipeTemplate` JSON body (typically the contents of a
/// previously-exported file) and persists it as a fresh user template.
/// If the incoming id is empty or collides with an existing template, the
/// import re-assigns a new id rather than failing. Any other id must follow
/// the pipe id format (`[A-Za-z0-9_-]`, at most 128 characters).
pub async fn import_template(
    State(state): State<IdentityApiState>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut tpl): Json<PipeTemplate>,
) -> Result<(StatusCode, Json<PipeTemplate>), PipeTemplateApiError> {
    tpl.builtin = false;
    tpl.tenant_id = tenant_for_create(tpl.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| PipeTemplateApiError::Forbidden(message.to_string()))?;
    if tpl.name.trim().is_empty() {
        return Err(PipeTemplateApiError::BadRequest("name must not be empty".to_string()));
    }
    validate_import_id(&tpl.id)?;
    let taken = !tpl.id.trim().is_empty()
        && locate(&state, &tpl.id)
            .await?
            .is_some();
    tpl.id = import_id(std::mem::take(&mut tpl.id), taken)?;
    let now = chrono::Utc::now().to_rfc3339();
    tpl.created_at = Some(now.clone());
    tpl.updated_at = Some(now);
    if !template_allowed(&tpl, &context, &scope) {
        return Err(PipeTemplateApiError::Forbidden("Pipe template is outside this token's permitted scope".into()));
    }
    let s = target_store(&state, &tpl)?;
    s.save(&tpl)
        .await
        .map_err(|e| PipeTemplateApiError::InternalError(format!("save: {}", e)))?;
    debug!("Imported pipe template '{}' ({})", tpl.name, tpl.id);
    Ok((StatusCode::CREATED, Json(tpl)))
}

/// Reject a requested import id that is neither empty (and so reassigned) nor
/// in the pipe id format.
fn validate_import_id(requested: &str) -> Result<(), PipeTemplateApiError> {
    if requested.trim().is_empty() {
        return Ok(());
    }
    validate_pipe_id(requested).map_err(|e| {
        PipeTemplateApiError::BadRequest(match e {
            AppError::InvalidInput(message) => message,
            other => format!("{other:?}"),
        })
    })
}

/// The id an imported template is saved under: a fresh `user-<uuid>` when the
/// requested id is empty or `taken`, otherwise the requested id. A requested
/// id outside the pipe id format is rejected even when `taken`.
fn import_id(
    requested: String,
    taken: bool,
) -> Result<String, PipeTemplateApiError> {
    validate_import_id(&requested)?;
    if requested.trim().is_empty() || taken {
        return Ok(format!("user-{}", uuid::Uuid::new_v4()));
    }
    Ok(requested)
}

/// `DELETE /v1/pipe-templates/{id}`
pub async fn delete_template(
    State(state): State<IdentityApiState>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, PipeTemplateApiError> {
    let (s, existing) = locate(&state, &id)
        .await?
        .ok_or_else(|| PipeTemplateApiError::NotFound(format!("template '{}' not found", id)))?;
    if !template_allowed(&existing, &context, &scope) {
        return Err(PipeTemplateApiError::Forbidden("Pipe template is outside this token's permitted scope".into()));
    }
    if existing.builtin {
        return Err(PipeTemplateApiError::Forbidden(format!("builtin template '{}' cannot be deleted", id)));
    }
    s.delete(&id)
        .await
        .map_err(|e| PipeTemplateApiError::InternalError(format!("delete: {}", e)))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn template(tenant_id: Option<&str>) -> PipeTemplate {
        serde_json::from_value(serde_json::json!({
            "id": "template-1",
            "name": "Template",
            "tenant_id": tenant_id,
        }))
        .unwrap()
    }

    #[test]
    fn canonical_template_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:pipe-templates:template-1\z").unwrap(),
        ))));

        assert!(template_allowed(&template(Some("tenant-a")), &context, &scope));
        // Non-builtin untenanted (legacy) template is now DENIED to a tenant PAT
        // (fail closed) — it must be reassigned to a tenant first.
        assert!(!template_allowed(&template(None), &context, &scope));
        assert!(!template_allowed(&template(Some("tenant-b")), &context, &scope));
        // A builtin template is the shared library — readable by any tenant PAT.
        let builtin: PipeTemplate = serde_json::from_value(serde_json::json!({
            "id": "builtin-1", "name": "Builtin", "tenant_id": null, "builtin": true,
        }))
        .unwrap();
        assert!(template_allowed(&builtin, &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:pipes:template-1\z").unwrap(),
        ))));
        assert!(!template_allowed(&template(Some("tenant-a")), &context, &wrong_kind));
    }

    #[test]
    fn import_rejects_an_id_that_could_name_a_path() {
        for id in ["../x", "/tmp/x", "a/b", "a\\b", "a.b", "..", "x\0", &"a".repeat(129)] {
            assert!(
                matches!(validate_import_id(id), Err(PipeTemplateApiError::BadRequest(_))),
                "{id:?} passed the check made before the lookup"
            );
            for taken in [false, true] {
                assert!(
                    matches!(import_id(id.to_string(), taken), Err(PipeTemplateApiError::BadRequest(_))),
                    "{id:?} (taken: {taken}) was accepted for import"
                );
            }
        }
    }

    #[test]
    fn import_keeps_a_valid_unused_id() {
        assert_eq!(import_id("my-template_1".to_string(), false).unwrap(), "my-template_1");
        assert_eq!(import_id("a".repeat(128), false).unwrap(), "a".repeat(128));
    }

    #[test]
    fn import_reassigns_an_empty_or_taken_id() {
        for (id, taken) in [("", false), ("   ", false), ("my-template_1", true)] {
            let assigned = import_id(id.to_string(), taken).unwrap();
            let uuid = assigned
                .strip_prefix("user-")
                .unwrap_or_else(|| panic!("{id:?} was not reassigned: {assigned:?}"));
            assert!(uuid::Uuid::parse_str(uuid).is_ok(), "{assigned:?}");
        }
    }
}
