//! Router for certificate management endpoints

use super::{CertificateStore, handlers};
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;
use axum::{
    Router,
    routing::{delete, get, post, put},
};
use std::sync::Arc;
use tracing::info;

/// Create the certificates router. Every route is gated because certificate
/// inventory and material are privileged vault data.
pub fn create_certificates_router(
    store: Arc<dyn CertificateStore>,
    gate: RbacGuard,
) -> Router {
    info!(
        "[Certificates Router] Creating certificates router with routes: /api/v1/certificates/, /api/v1/certificates/{{id}}"
    );
    Router::new()
        .route("/api/v1/certificates", gate.gate(get(handlers::list_certificates), Feature::CertificatesView))
        .route("/api/v1/certificates", gate.gate(post(handlers::create_certificate), Feature::CertificatesEdit))
        .route("/api/v1/certificates/", gate.gate(get(handlers::list_certificates), Feature::CertificatesView))
        .route("/api/v1/certificates/", gate.gate(post(handlers::create_certificate), Feature::CertificatesEdit))
        .route("/api/v1/certificates/{id}", gate.gate(get(handlers::get_certificate), Feature::CertificatesView))
        .route("/api/v1/certificates/{id}", gate.gate(put(handlers::update_certificate), Feature::CertificatesEdit))
        .route("/api/v1/certificates/{id}", gate.gate(delete(handlers::delete_certificate), Feature::CertificatesEdit))
        .with_state(store)
}
