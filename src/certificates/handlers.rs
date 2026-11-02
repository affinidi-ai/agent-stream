//! HTTP handlers for certificate endpoints

use super::{CertificateResponse, CertificateStore, CreateCertificateRequest, UpdateCertificateRequest};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use std::sync::Arc;
use tracing::info;

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

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

pub async fn list_certificates(
    State(store): State<Arc<dyn CertificateStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("[Certificates] Listing all certificates");
    match store.list_all().await {
        Ok(mut certificates) => {
            let context = tenant_context(&context);
            let scope = resource_scope(&scope);
            certificates.retain(|certificate| {
                can_access(
                    certificate
                        .tenant_id
                        .as_deref(),
                    context,
                ) && scope_allows_resource(scope, context, ResourceKind::Certificates, &certificate.id)
            });
            info!("[Certificates] Found {} certificates", certificates.len());
            Ok(Json(certificates))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn get_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    info!("[Certificates] Getting certificate: {}", id);
    match store.get(&id).await {
        Ok(Some(certificate))
            if can_access(
                certificate
                    .tenant_id
                    .as_deref(),
                tenant_context(&context),
            ) && scope_allows_resource(
                resource_scope(&scope),
                tenant_context(&context),
                ResourceKind::Certificates,
                &certificate.id,
            ) =>
        {
            Ok(Json(CertificateResponse::from(certificate)))
        }
        Ok(Some(_)) => Err((StatusCode::NOT_FOUND, format!("Certificate not found: {}", id))),
        Ok(None) => {
            info!("[Certificates] Certificate not found: {}", id);
            Err((StatusCode::NOT_FOUND, format!("Certificate not found: {}", id)))
        }
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn create_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut request): Json<CreateCertificateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    request.tenant_id = tenant_for_create(request.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let id = uuid::Uuid::new_v4().to_string();
    let certificate_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id) {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    info!("[Certificates] CREATE request received for: {}", request.name);
    if let Err(e) = crate::config::enforce_add("secrets.certificates").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }
    match store
        .create_with_ids(request, id, certificate_id)
        .await
    {
        Ok(certificate) => Ok((StatusCode::CREATED, Json(CertificateResponse::from(certificate)))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn update_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<UpdateCertificateRequest>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let existing = store
        .get(&id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Certificate not found: {id}")))?;
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id)
    {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    info!("[Certificates] UPDATE request received for: {}", id);
    match store
        .update(&id, request)
        .await
    {
        Ok(certificate) => Ok(Json(CertificateResponse::from(certificate))),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub async fn delete_certificate(
    State(store): State<Arc<dyn CertificateStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<impl IntoResponse, (StatusCode, String)> {
    let existing = store
        .get(&id)
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Certificate not found: {id}")))?;
    if !can_access(existing.tenant_id.as_deref(), tenant_context(&context))
        || !scope_allows_resource(resource_scope(&scope), tenant_context(&context), ResourceKind::Certificates, &id)
    {
        return Err((StatusCode::FORBIDDEN, "certificate is outside this token's permitted scope".into()));
    }
    info!("[Certificates] DELETE request received for: {}", id);
    match store.delete(&id).await {
        Ok(()) => Ok(StatusCode::NO_CONTENT),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificates::{CertificateKind, FilesystemCertificateStore};
    use axum::response::IntoResponse;

    fn scope_for(kind: &str) -> Extension<PatResourceScope> {
        let compiled = crate::auth_manager::resource_scope::compile_canonical(
            Some(&format!("TENANT:${{account}}:{kind}:.*")),
            &[crate::auth_manager::resource_scope::RequiredHeader {
                name: "account".into(),
                pattern: r"[a-z0-9-]+".into(),
            }],
        )
        .unwrap();
        let mut headers = axum::http::HeaderMap::new();
        headers.insert("account", "tenant-a".parse().unwrap());
        Extension(PatResourceScope(
            compiled
                .evaluate(&headers)
                .unwrap()
                .pattern
                .unwrap(),
        ))
    }

    fn context() -> Extension<PatTenantContext> {
        Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        })
    }

    fn request() -> CreateCertificateRequest {
        CreateCertificateRequest {
            name: "Certificate".into(),
            description: None,
            tags: None,
            kind: CertificateKind::ClientLeaf,
            tenant_id: None,
            certificate_pem: "pem".into(),
            private_key_pem: None,
            expires_at: None,
            active: Some(true),
            identity_did: None,
        }
    }

    #[tokio::test]
    async fn canonical_create_stamps_tenant_and_rejects_wrong_kind() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemCertificateStore::new(directory.path().to_path_buf())
                .await
                .unwrap(),
        );
        let state: Arc<dyn CertificateStore> = store.clone();
        let response = create_certificate(
            State(state.clone()),
            Some(Extension(PatContext(None))),
            Some(context()),
            Some(scope_for("certificates")),
            Json(request()),
        )
        .await
        .unwrap()
        .into_response();
        assert_eq!(response.status(), StatusCode::CREATED);
        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()[0]
                .tenant_id
                .as_deref(),
            Some("tenant-a")
        );

        let rejected = create_certificate(
            State(state),
            Some(Extension(PatContext(None))),
            Some(context()),
            Some(scope_for("pipes")),
            Json(request()),
        )
        .await;
        assert!(matches!(rejected, Err((StatusCode::FORBIDDEN, _))));
        assert_eq!(
            store
                .list_all()
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn foreign_tenant_read_is_not_found() {
        let directory = tempfile::tempdir().unwrap();
        let store = Arc::new(
            FilesystemCertificateStore::new(directory.path().to_path_buf())
                .await
                .unwrap(),
        );
        let mut foreign = request();
        foreign.tenant_id = Some("tenant-b".into());
        store
            .create_with_ids(foreign, "foreign".into(), "foreign-public".into())
            .await
            .unwrap();
        let state: Arc<dyn CertificateStore> = store;

        let result =
            get_certificate(State(state), Path("foreign".into()), Some(context()), Some(scope_for("certificates")))
                .await;
        assert!(matches!(result, Err((StatusCode::NOT_FOUND, _))));
    }
}
