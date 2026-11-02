use axum::{
    Json,
    body::Body,
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tracing::{error, info};

use crate::identity::state::IdentityApiState;

/// Request body for the debug export endpoint.
#[derive(Debug, Deserialize)]
pub struct ExportStorageRequest {
    /// Ed25519 public key in PEM format
    pub public_key_pem: String,
}

/// Export storage with PII redaction, encrypted with the provided Ed25519 public key.
///
/// Returns the encrypted ATGX file as a binary download.
pub async fn export_storage(
    State(state): State<IdentityApiState>,
    Json(req): Json<ExportStorageRequest>,
) -> Response {
    info!("Storage export requested via API");

    if req
        .public_key_pem
        .trim()
        .is_empty()
    {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "public_key_pem is required"})))
            .into_response();
    }

    // Resolve storage root from bootstrap config
    let storage_root = crate::export::resolve_storage_root(
        &state
            .bootstrap_config
            .storage_paths
            .agent_surfaces,
        "",
    );

    // Build encrypted export (blocking I/O — run in spawn_blocking)
    let pubkey_pem = req.public_key_pem.clone();
    let result =
        tokio::task::spawn_blocking(move || crate::export::build_encrypted_export(&storage_root, &pubkey_pem)).await;

    match result {
        Ok(Ok(encrypted_bytes)) => {
            let size = encrypted_bytes.len();
            info!("Storage export complete: {} bytes", size);

            let mut headers = HeaderMap::new();
            headers.insert(header::CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
            headers.insert(
                header::CONTENT_DISPOSITION,
                HeaderValue::from_static("attachment; filename=\"storage-export.asexp\""),
            );

            (StatusCode::OK, headers, Body::from(encrypted_bytes)).into_response()
        }
        Ok(Err(e)) => {
            error!("Storage export failed: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": format!("Export failed: {}", e)})))
                .into_response()
        }
        Err(e) => {
            error!("Storage export task panicked: {:#}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Export task failed"})))
                .into_response()
        }
    }
}
