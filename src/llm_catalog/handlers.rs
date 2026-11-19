//! API handlers for LLM provider catalog CRUD operations.

use std::sync::Arc;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;
use tracing::info;

use super::refresh::{CatalogRefresher, RefreshFailureKind, RefreshOutcome, rollback_catalog};
use super::store::{CatalogError, LlmProviderCatalog};

#[derive(Clone)]
pub struct LlmCatalogState {
    pub catalog: Arc<LlmProviderCatalog>,
    /// Refresh from the manifest at `llm_catalog.refresh_url` for the "Refresh
    /// Builtin Models" flow. `None` disables the refresh action.
    pub(crate) refresher: Option<Arc<CatalogRefresher>>,
}

fn catalog_error_response(err: CatalogError) -> axum::response::Response {
    let status = match err {
        CatalogError::Duplicate(_) => StatusCode::CONFLICT,
        CatalogError::Validation(_) => StatusCode::BAD_REQUEST,
        CatalogError::NotFound(_) => StatusCode::NOT_FOUND,
        CatalogError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({ "error": err.to_string() }))).into_response()
}

/// GET /api/v1/llm-providers
pub async fn list_providers(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    match state.catalog.list_providers() {
        Ok(providers) => (StatusCode::OK, Json(serde_json::json!({ "providers": providers }))).into_response(),
        Err(e) => catalog_error_response(e),
    }
}

/// GET /api/v1/llm-providers/{enum_value}
pub async fn get_provider(
    State(state): State<LlmCatalogState>,
    Path(enum_value): Path<String>,
) -> impl IntoResponse {
    match state
        .catalog
        .get_provider(&enum_value)
    {
        Ok(Some(provider)) => (StatusCode::OK, Json(provider)).into_response(),
        Ok(None) => catalog_error_response(CatalogError::NotFound(enum_value)),
        Err(e) => catalog_error_response(e),
    }
}

/// POST /api/v1/llm-providers
pub async fn create_provider(
    State(state): State<LlmCatalogState>,
    Json(provider): Json<Value>,
) -> impl IntoResponse {
    match state
        .catalog
        .create_provider(provider)
        .await
    {
        Ok(created) => {
            info!(
                enum_value = created
                    .get("enum_value")
                    .and_then(|v| v.as_str())
                    .unwrap_or(""),
                "LLM provider created"
            );
            (StatusCode::CREATED, Json(created)).into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}

/// PUT /api/v1/llm-providers/{enum_value}
pub async fn update_provider(
    State(state): State<LlmCatalogState>,
    Path(enum_value): Path<String>,
    Json(provider): Json<Value>,
) -> impl IntoResponse {
    match state
        .catalog
        .update_provider(&enum_value, provider)
        .await
    {
        Ok(updated) => {
            info!(enum_value = %enum_value, "LLM provider updated");
            (StatusCode::OK, Json(updated)).into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}

/// DELETE /api/v1/llm-providers/{enum_value}
pub async fn delete_provider(
    State(state): State<LlmCatalogState>,
    Path(enum_value): Path<String>,
) -> impl IntoResponse {
    match state
        .catalog
        .delete_provider(&enum_value)
        .await
    {
        Ok(true) => {
            info!(enum_value = %enum_value, "LLM provider deleted");
            (StatusCode::OK, Json(serde_json::json!({ "deleted": enum_value }))).into_response()
        }
        Ok(false) => catalog_error_response(CatalogError::NotFound(enum_value)),
        Err(e) => catalog_error_response(e),
    }
}

/// GET /api/v1/llm-providers/custom
///
/// Returns the raw custom-catalog text for the JSON editor plus the parsed,
/// currently-merging custom providers for the **Custom** tab list.
pub async fn get_custom(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    let raw = state
        .catalog
        .read_custom_raw();
    let providers = state
        .catalog
        .custom_providers();
    (StatusCode::OK, Json(serde_json::json!({ "raw": raw, "providers": providers }))).into_response()
}

/// PUT /api/v1/llm-providers/custom
///
/// Validate the submitted custom-catalog document (JSON schema + no built-in
/// `enum_value` collision + no duplicates) and persist it. On success the
/// merged runtime catalog picks the changes up on the next read (mtime-gated),
/// so custom providers become selectable everywhere built-in ones are.
pub async fn put_custom(
    State(state): State<LlmCatalogState>,
    Json(doc): Json<Value>,
) -> impl IntoResponse {
    match state
        .catalog
        .save_custom(doc)
        .await
    {
        Ok(providers) => {
            info!(count = providers.len(), "Custom LLM catalog saved");
            (StatusCode::OK, Json(serde_json::json!({ "providers": providers }))).into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}

/// GET /api/v1/llm-providers/refresh
///
/// Report whether the "Refresh Builtin Models" action is configured (a non-empty
/// `llm_catalog.refresh_url`), so the dashboard only shows the button when a
/// click can succeed.
pub async fn refresh_status(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({ "available": state.refresher.is_some() }))).into_response()
}

/// POST /api/v1/llm-providers/refresh
///
/// Read the manifest at `llm_catalog.refresh_url`, download the catalog it
/// names, check it against the manifest, and merge its model data into the
/// built-in catalog, keeping the previous file as `llm.json.bak`. A refused
/// publication or a failed download leaves the catalog untouched.
pub async fn refresh_builtin(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    let Some(refresher) = state.refresher.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No refresh source configured. Set `llm_catalog.refresh_url` in agent-stream.json."
            })),
        )
            .into_response();
    };

    match refresher
        .refresh(&state.catalog)
        .await
    {
        Ok(RefreshOutcome::Updated { manifest, refresh }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "outcome": "updated",
                "providers": refresh.providers,
                "added": refresh.added,
                "version": manifest.version,
                "publication_sequence": manifest.publication_sequence,
                "backup": true,
            })),
        )
            .into_response(),
        Ok(RefreshOutcome::Unchanged { manifest }) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "outcome": "unchanged",
                "version": manifest.version,
                "publication_sequence": manifest.publication_sequence,
            })),
        )
            .into_response(),
        Err(failure) => {
            let status = match failure.kind {
                RefreshFailureKind::Transport => StatusCode::BAD_GATEWAY,
                RefreshFailureKind::Storage => StatusCode::INTERNAL_SERVER_ERROR,
                RefreshFailureKind::Validation | RefreshFailureKind::Rollback | RefreshFailureKind::HashMismatch => {
                    StatusCode::BAD_REQUEST
                }
            };
            (status, Json(serde_json::json!({ "error": failure.message }))).into_response()
        }
    }
}

/// POST /api/v1/llm-providers/refresh/rollback
///
/// Restore the previous built-in catalog from `llm.json.bak` (the recovery path
/// if a refreshed catalog is problematic) and reload the in-memory catalog. The
/// next refresh installs the accepted publication again, but no older one.
pub async fn rollback_builtin(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    let restored = match &state.refresher {
        Some(refresher) => {
            refresher
                .rollback(&state.catalog)
                .await
        }
        None => rollback_catalog(&state.catalog).await,
    };
    match restored {
        Ok(count) => {
            info!(providers = count, "Built-in LLM catalog rolled back from llm.json.bak");
            (StatusCode::OK, Json(serde_json::json!({ "providers": count, "restored": true }))).into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}
