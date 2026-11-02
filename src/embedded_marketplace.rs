//! Embedded marketplace handler for GW2
//!
//! When a channel targets `embedded://marketplace`, this module handles the
//! request in-process instead of proxying to an external HTTP service.
//!
//! Supports two operations:
//! - `GET /api/models` — return the model catalog from the configured marketplace models file
//! - `POST /api/purchase/{model_id}` — provision an API key

use serde_json::Value;
use tracing::{info, warn};

/// Marketplace catalog entry as stored in `marketplace-models.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct MarketplaceCatalogEntry {
    pub id: String,
    pub name: String,
    pub provider: String,
    #[serde(default)]
    pub logo: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub rating: f64,
    #[serde(default)]
    pub review_count: u64,
    #[serde(default)]
    pub pricing: String,
    #[serde(default, alias = "contextWindow")]
    pub context_window: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub metadata: Value,
}

/// Result of handling an embedded marketplace request.
pub struct MarketplaceResponse {
    pub status: u16,
    pub body: String,
    pub headers: std::collections::HashMap<String, String>,
}

/// Handle an embedded marketplace request.
///
/// `catalog_path` — path to the marketplace models JSON file
/// `method`       — HTTP method (GET / POST)
/// `path`         — request path, e.g. `/api/models` or `/api/purchase/openai-gpt-4o`
pub async fn handle_embedded_marketplace(
    catalog_path: &str,
    method: &str,
    path: &str,
) -> MarketplaceResponse {
    let method_upper = method.to_uppercase();

    // Route: GET /api/models
    if path == "/api/models" || path == "/api/models/" {
        if method_upper != "GET" {
            return MarketplaceResponse {
                status: 405,
                body: r#"{"error":"Method not allowed"}"#.to_string(),
                headers: json_headers(),
            };
        }
        return handle_get_models(catalog_path).await;
    }

    // Route: POST /api/purchase/{model_id}
    if let Some(model_id) = path
        .strip_prefix("/api/purchase/")
        .map(|s| s.trim_end_matches('/'))
        .filter(|s| !s.is_empty())
    {
        if method_upper != "POST" {
            return MarketplaceResponse {
                status: 405,
                body: r#"{"error":"Method not allowed"}"#.to_string(),
                headers: json_headers(),
            };
        }
        return handle_purchase(catalog_path, model_id).await;
    }

    MarketplaceResponse {
        status: 404,
        body: r#"{"error":"Not found"}"#.to_string(),
        headers: json_headers(),
    }
}

/// Load the model catalog from the configured marketplace models file.
async fn load_catalog(catalog_path: &str) -> Result<Vec<MarketplaceCatalogEntry>, String> {
    let content = tokio::fs::read_to_string(catalog_path)
        .await
        .map_err(|e| format!("Failed to read {}: {}", catalog_path, e))?;
    serde_json::from_str(&content).map_err(|e| format!("Failed to parse {}: {}", catalog_path, e))
}

/// GET /api/models — return the full catalog.
async fn handle_get_models(catalog_path: &str) -> MarketplaceResponse {
    match load_catalog(catalog_path).await {
        Ok(models) => {
            let body = serde_json::to_string(&models).unwrap_or_else(|_| "[]".to_string());
            info!("[marketplace] Serving catalog ({} models) from {}", models.len(), catalog_path);
            MarketplaceResponse {
                status: 200,
                body,
                headers: json_headers(),
            }
        }
        Err(e) => {
            warn!("[marketplace] {}", e);
            MarketplaceResponse {
                status: 500,
                body: serde_json::json!({"error": e}).to_string(),
                headers: json_headers(),
            }
        }
    }
}

/// POST /api/purchase/{model_id} — provision an API key.
///
/// Purchases are not charged; access is governed by the fabric connection and
/// the appliance's Trust Fabric policy.
async fn handle_purchase(
    catalog_path: &str,
    model_id: &str,
) -> MarketplaceResponse {
    // Verify the model exists
    let catalog = match load_catalog(catalog_path).await {
        Ok(c) => c,
        Err(e) => {
            return MarketplaceResponse {
                status: 500,
                body: serde_json::json!({"error": e}).to_string(),
                headers: json_headers(),
            };
        }
    };

    let model = match catalog
        .iter()
        .find(|m| m.id == model_id)
    {
        Some(m) => m,
        None => {
            return MarketplaceResponse {
                status: 404,
                body: serde_json::json!({"error": format!("Model {} not found", model_id)}).to_string(),
                headers: json_headers(),
            };
        }
    };

    // Generate API key
    let suffix = uuid::Uuid::new_v4()
        .simple()
        .to_string();
    let provider_slug = model
        .metadata
        .get("provider")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");
    let api_key = format!("sk-mkt-{}-{}", provider_slug, &suffix[..32]);

    let now = chrono::Utc::now();
    let expires_at = now + chrono::Duration::days(30);

    info!("[marketplace] Provisioned API key for model={} provider={}", model_id, provider_slug);

    let response = serde_json::json!({
        "success": true,
        "api_key": api_key,
        "model_id": model_id,
        "model_name": model.name,
        "provider": model.provider,
        "purchased_at": now.to_rfc3339(),
        "expires_at": expires_at.to_rfc3339(),
        "message": format!("API key provisioned for {}", model.name),
    });

    MarketplaceResponse {
        status: 200,
        body: response.to_string(),
        headers: json_headers(),
    }
}

fn json_headers() -> std::collections::HashMap<String, String> {
    let mut h = std::collections::HashMap::new();
    h.insert("content-type".to_string(), "application/json".to_string());
    h
}
