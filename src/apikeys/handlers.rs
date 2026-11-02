//! HTTP handlers for API key management endpoints

use super::{ApiKeyStore, CreateApiKeyRequest, UpdateApiKeyRequest};
use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use std::sync::Arc;
use tracing::{error, info};

/// List all API keys
pub async fn list_keys(State(store): State<Arc<dyn ApiKeyStore>>) -> Response {
    info!("[API Keys] Listing all API keys");
    match store.list_all().await {
        Ok(keys) => {
            info!("[API Keys] Successfully listed {} keys", keys.len());
            Json(keys).into_response()
        }
        Err(e) => {
            error!("[API Keys] Failed to list API keys: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Get a specific API key by ID
pub async fn get_key(
    State(store): State<Arc<dyn ApiKeyStore>>,
    Path(id): Path<String>,
) -> Response {
    info!("[API Keys] Getting API key: {}", id);
    match store.get(&id).await {
        Ok(Some(key)) => {
            info!("[API Keys] Successfully retrieved API key: {}", id);
            Json(key).into_response()
        }
        Ok(None) => {
            info!("[API Keys] API key not found: {}", id);
            (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "API key not found" }))).into_response()
        }
        Err(e) => {
            error!("[API Keys] Failed to get API key: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Create a new API key
pub async fn create_key(
    State(store): State<Arc<dyn ApiKeyStore>>,
    Json(request): Json<CreateApiKeyRequest>,
) -> Response {
    info!("[API Keys] CREATE request received for: {}", request.name);

    match store.create(request).await {
        Ok(key) => {
            info!("[API Keys] Successfully created API key: {} (id={})", key.name, key.id);
            (StatusCode::CREATED, Json(key)).into_response()
        }
        Err(e) => {
            error!("[API Keys] Failed to create API key: {}", e);
            let status = if e
                .to_string()
                .contains("already exists")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Update an existing API key
pub async fn update_key(
    State(store): State<Arc<dyn ApiKeyStore>>,
    Path(id): Path<String>,
    Json(request): Json<UpdateApiKeyRequest>,
) -> Response {
    info!("Updating API key: {}", id);

    match store
        .update(&id, request)
        .await
    {
        Ok(key) => Json(key).into_response(),
        Err(e) => {
            error!("Failed to update API key: {}", e);
            let status = if e
                .to_string()
                .contains("not found")
            {
                StatusCode::NOT_FOUND
            } else if e
                .to_string()
                .contains("already exists")
            {
                StatusCode::CONFLICT
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}

/// Delete an API key
pub async fn delete_key(
    State(store): State<Arc<dyn ApiKeyStore>>,
    Path(id): Path<String>,
) -> Response {
    info!("Deleting API key: {}", id);

    match store.delete(&id).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            error!("Failed to delete API key: {}", e);
            let status = if e
                .to_string()
                .contains("not found")
            {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            (status, Json(serde_json::json!({ "error": e.to_string() }))).into_response()
        }
    }
}
