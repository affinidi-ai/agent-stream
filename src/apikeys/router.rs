//! Router for API key management endpoints

use super::{ApiKeyStore, handlers};
use axum::{Router, routing::get};
use std::sync::Arc;
use tracing::info;

/// Create the API keys router
pub fn create_apikeys_router(store: Arc<dyn ApiKeyStore>) -> Router {
    info!("[API Keys Router] Creating API keys router with routes: /api/v1/apikeys/, /api/v1/apikeys/{{id}}");
    Router::new()
        .route("/api/v1/apikeys", get(handlers::list_keys).post(handlers::create_key))
        .route("/api/v1/apikeys/", get(handlers::list_keys).post(handlers::create_key))
        .route(
            "/api/v1/apikeys/{id}",
            get(handlers::get_key)
                .put(handlers::update_key)
                .delete(handlers::delete_key),
        )
        .with_state(store)
}
