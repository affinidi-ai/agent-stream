//! Certificate management module

pub mod filesystem;
pub mod handlers;
pub mod router;
pub mod store;

use serde::{Deserialize, Serialize};

/// What this certificate represents in the gateway.
///
/// Determines whether the cert participates in TLS server termination,
/// mTLS pinned-cert trust, or chain validation as a trust anchor.
/// Existing stored certificates without this field deserialize as
/// [`CertificateKind::ServerLeaf`] to preserve historical behaviour.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CertificateKind {
    /// Server certificate + private key bundle used to terminate TLS.
    /// (Historical default.)
    #[default]
    ServerLeaf,
    /// Client leaf certificate used in mTLS [`MtlsTrust::Pinned`] mode.
    ClientLeaf,
    /// Issuer CA certificate used as a trust anchor for mTLS
    /// [`MtlsTrust::Ca`] mode.
    Ca,
}

/// Certificate information returned in list responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateListItem {
    pub id: String,
    pub name: String,
    pub certificate_id: String, // UUID for certificate identifier
    pub description: Option<String>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub kind: CertificateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
}

/// Full certificate data including the PEM content
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Certificate {
    pub id: String,
    pub name: String,
    pub certificate_id: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    #[serde(default)]
    pub kind: CertificateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(rename = "certificate_pem")]
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
    /// Optional DID associated with this certificate for identity
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<String>,
}

/// Certificate data returned on reads: every field of [`Certificate`] EXCEPT
/// `private_key_pem`. The private key is write-only — accepted on create and
/// persisted to disk, but never serialized back to any API caller (a
/// `certificates.view` caller must not receive it). Keep in sync with
/// [`Certificate`].
#[derive(Debug, Clone, Serialize)]
pub struct CertificateResponse {
    pub id: String,
    pub name: String,
    pub certificate_id: String,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub kind: CertificateKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub certificate_pem: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_did: Option<String>,
}

impl From<&Certificate> for CertificateResponse {
    fn from(certificate: &Certificate) -> Self {
        Self {
            id: certificate.id.clone(),
            name: certificate.name.clone(),
            certificate_id: certificate
                .certificate_id
                .clone(),
            description: certificate
                .description
                .clone(),
            tags: certificate.tags.clone(),
            kind: certificate.kind,
            tenant_id: certificate.tenant_id.clone(),
            certificate_pem: certificate
                .certificate_pem
                .clone(),
            expires_at: certificate.expires_at,
            created_at: certificate.created_at,
            updated_at: certificate.updated_at,
            active: certificate.active,
            identity_did: certificate
                .identity_did
                .clone(),
        }
    }
}

impl From<Certificate> for CertificateResponse {
    fn from(certificate: Certificate) -> Self {
        Self::from(&certificate)
    }
}

/// Request to create a new certificate
#[derive(Debug, Deserialize)]
pub struct CreateCertificateRequest {
    pub name: String,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    #[serde(default)]
    pub kind: CertificateKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub certificate_pem: String,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub active: Option<bool>,
    pub identity_did: Option<String>,
}

/// Request to update an existing certificate
#[derive(Debug, Deserialize)]
pub struct UpdateCertificateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub tags: Option<Vec<String>>,
    pub kind: Option<CertificateKind>,
    pub certificate_pem: Option<String>,
    pub private_key_pem: Option<String>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub active: Option<bool>,
    pub identity_did: Option<String>,
}

pub use filesystem::FilesystemCertificateStore;
pub use store::CertificateStore;
