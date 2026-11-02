use axum::{
    extract::Path,
    http::StatusCode,
    Json, Extension,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

use crate::storage::{Webhook, WebhookStorage};

// These handlers are kept for potential future use but not currently exposed via HTTP routes
#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct CreateWebhookRequest {
    pub name: String,
    pub description: String,
    pub url: String,
    pub secret: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize, Serialize)]
pub struct UpdateWebhookRequest {
    pub name: String,
    pub description: String,
    pub url: String,
    pub secret: Option<String>,
}

/// List all webhooks
#[allow(dead_code)]
pub async fn list_webhooks(
    Extension(storage): Extension<Arc<WebhookStorage>>,
) -> Result<Json<Vec<Webhook>>, (StatusCode, String)> {
    let webhooks = storage.list()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list webhooks: {}", e)))?;
    Ok(Json(webhooks))
}

/// Get a specific webhook by ID
#[allow(dead_code)]
pub async fn get_webhook(
    Extension(storage): Extension<Arc<WebhookStorage>>,
    Path(id): Path<String>,
) -> Result<Json<Webhook>, (StatusCode, String)> {
    let webhook = storage.load(&id)
        .map_err(|_| (StatusCode::NOT_FOUND, "Webhook not found".to_string()))?;
    Ok(Json(webhook))
}

/// Create a new webhook
#[allow(dead_code)]
pub async fn create_webhook(
    Extension(storage): Extension<Arc<WebhookStorage>>,
    Json(req): Json<CreateWebhookRequest>,
) -> Result<(StatusCode, Json<Webhook>), (StatusCode, String)> {
    // Validate webhook URL
    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Err((StatusCode::BAD_REQUEST, "Webhook URL must start with http:// or https://".to_string()));
    }

    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Webhook name is required".to_string()));
    }

    // Create the webhook
    let webhook = Webhook::new(
        req.name,
        req.description,
        req.url,
        req.secret,
    );

    storage.save(&webhook)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to save webhook: {}", e)))?;

    tracing::info!("Created webhook '{}' ({})", webhook.name, webhook.id);
    
    Ok((StatusCode::CREATED, Json(webhook)))
}

/// Update an existing webhook
#[allow(dead_code)]
pub async fn update_webhook(
    Extension(storage): Extension<Arc<WebhookStorage>>,
    Path(id): Path<String>,
    Json(req): Json<UpdateWebhookRequest>,
) -> Result<Json<Webhook>, (StatusCode, String)> {
    // Validate webhook URL
    if !req.url.starts_with("http://") && !req.url.starts_with("https://") {
        return Err((StatusCode::BAD_REQUEST, "Webhook URL must start with http:// or https://".to_string()));
    }

    // Validate name
    if req.name.trim().is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Webhook name is required".to_string()));
    }

    // Load existing webhook to preserve created_at
    let existing = storage.load(&id)
        .map_err(|_| (StatusCode::NOT_FOUND, "Webhook not found".to_string()))?;

    // Create updated webhook
    let updated = Webhook {
        id: existing.id,
        name: req.name,
        description: req.description,
        url: req.url,
        secret: req.secret,
        created_at: existing.created_at,
        updated_at: chrono::Utc::now().to_rfc3339(),
    };

    storage.update(&id, &updated)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update webhook: {}", e)))?;

    tracing::info!("Updated webhook '{}' ({})", updated.name, updated.id);
    
    Ok(Json(updated))
}

/// Delete a webhook
#[allow(dead_code)]
pub async fn delete_webhook(
    Extension(storage): Extension<Arc<WebhookStorage>>,
    Path(id): Path<String>,
) -> Result<StatusCode, (StatusCode, String)> {
    storage.delete(&id)
        .map_err(|_| (StatusCode::NOT_FOUND, "Webhook not found".to_string()))?;

    tracing::info!("Deleted webhook ID: {}", id);
    
    Ok(StatusCode::NO_CONTENT)
}
