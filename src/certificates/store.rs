//! Certificate Store Trait

use async_trait::async_trait;

use super::{Certificate, CertificateListItem, CreateCertificateRequest, UpdateCertificateRequest};

/// Trait for certificate storage backend
#[async_trait]
pub trait CertificateStore: Send + Sync {
    async fn list_all(&self) -> Result<Vec<CertificateListItem>, String>;
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Certificate>, String>;
    async fn create_with_ids(
        &self,
        request: CreateCertificateRequest,
        id: String,
        certificate_id: String,
    ) -> Result<Certificate, String>;
    async fn update(
        &self,
        id: &str,
        request: UpdateCertificateRequest,
    ) -> Result<Certificate, String>;
    async fn set_tenant_id(
        &self,
        _id: &str,
        _tenant_id: Option<String>,
    ) -> Result<Certificate, String> {
        Err("Tenant reassignment is not supported by this Certificate store".to_string())
    }
    async fn delete(
        &self,
        id: &str,
    ) -> Result<(), String>;
}
