//! API handlers for LLM provider catalog CRUD operations.

use std::sync::Arc;
use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde_json::Value;
use tracing::info;

use super::store::{CatalogError, LlmProviderCatalog};

#[derive(Clone)]
pub struct LlmCatalogState {
    pub catalog: Arc<LlmProviderCatalog>,
    /// URL of the published master catalog for the "Refresh Builtin Models"
    /// flow (`llm_catalog.refresh_url` in agent-stream.json). `None` disables
    /// the refresh action.
    pub refresh_url: Option<String>,
    /// `llm_catalog.allow_insecure_source`: the source may be plain http or on
    /// a private network. Off, the download also refuses to connect to any
    /// address that is not public, so a DNS answer cannot steer it inside.
    pub allow_insecure_source: bool,
}

/// The largest catalog the refresh accepts. The published catalog is a few
/// hundred kilobytes; anything near this size is not a catalog.
const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;

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
    (StatusCode::OK, Json(serde_json::json!({ "available": state.refresh_url.is_some() }))).into_response()
}

/// POST /api/v1/llm-providers/refresh
///
/// Download the published master `llm.json` from the configured
/// `llm_catalog.refresh_url`, validate it against the catalog schema, and swap
/// it into storage — keeping the previous file as `llm.json.bak` and forcing a
/// reload of the in-memory catalog. A bad download or invalid catalog leaves
/// the existing catalog untouched.
pub async fn refresh_builtin(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    let Some(url) = state.refresh_url.clone() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": "No refresh source configured. Set `llm_catalog.refresh_url` in agent-stream.json."
            })),
        )
            .into_response();
    };

    // Defense-in-depth even though the URL was validated at startup: reject
    // non-http(s) schemes and cloud-metadata targets.
    if let Err(reason) = crate::url_validation::validate_service_endpoint_url(&url).await {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Refresh URL rejected: {}", reason) })),
        )
            .into_response();
    }

    // By default every resolved address is re-checked at connection time, so a
    // public host name cannot be answered with a private address. An operator
    // who opted into an internal mirror gets the plain client.
    let timeout = Duration::from_secs(30);
    let client = if state.allow_insecure_source {
        crate::http_client::with_timeout(timeout)
    } else {
        crate::http_client::with_strict_validating_resolver(timeout)
    };
    let client = match client {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": format!("failed to build HTTP client: {}", e) })),
            )
                .into_response();
        }
    };

    let safe_url = crate::url_validation::redact_url_for_logging(&url);

    let resp = match client.get(&url).send().await {
        Ok(r) => r,
        Err(e) => {
            return (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({ "error": format!("failed to fetch catalog from {}: {}", safe_url, e) })),
            )
                .into_response();
        }
    };
    if !resp.status().is_success() {
        return (
            StatusCode::BAD_GATEWAY,
            Json(serde_json::json!({ "error": format!("catalog source returned HTTP {}", resp.status()) })),
        )
            .into_response();
    }
    let body = match crate::http_client::read_capped(resp, MAX_CATALOG_BYTES).await {
        Ok(b) => b,
        Err(e) => {
            return (StatusCode::BAD_GATEWAY, Json(serde_json::json!({ "error": e }))).into_response();
        }
    };
    let doc: Value = match serde_json::from_slice(&body) {
        Ok(d) => d,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": format!("downloaded catalog is not valid JSON: {}", e) })),
            )
                .into_response();
        }
    };

    match state
        .catalog
        .refresh_builtin(doc)
        .await
    {
        Ok(count) => {
            info!(providers = count, source = %safe_url, "Built-in LLM catalog refreshed");
            (StatusCode::OK, Json(serde_json::json!({ "providers": count, "source": url, "backup": true })))
                .into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}

/// POST /api/v1/llm-providers/refresh/rollback
///
/// Restore the previous built-in catalog from `llm.json.bak` (the recovery path
/// if a refreshed catalog is problematic) and reload the in-memory catalog.
pub async fn rollback_builtin(State(state): State<LlmCatalogState>) -> impl IntoResponse {
    match state
        .catalog
        .rollback_builtin()
        .await
    {
        Ok(count) => {
            info!(providers = count, "Built-in LLM catalog rolled back from llm.json.bak");
            (StatusCode::OK, Json(serde_json::json!({ "providers": count, "restored": true }))).into_response()
        }
        Err(e) => catalog_error_response(e),
    }
}
