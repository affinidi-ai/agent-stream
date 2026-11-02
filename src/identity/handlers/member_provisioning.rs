//! API handlers for member auto-provisioning configuration.
//!
//! Auto-provisioning mints appliance **members** on first sight of a verified
//! caller identity (a JWT claim, an mTLS subject, or a named API key) and, when
//! configured, assigns them to teams by claim-matching rules. This module
//! exposes the appliance-level config CRUD (admin-gated via the `enrolment.*`
//! RBAC features) plus a write-free preview that shows what a given identity
//! *would* resolve to. First-sight creation itself happens in the data-plane
//! team gate; see [`crate::members::MemberProvisioner`].

use std::sync::Arc;

use axum::{Extension, Json, extract::State, http::StatusCode};
use serde::Deserialize;

use crate::auth::storage::PasskeyStorage;
use crate::auth_manager::pat::PatContext;
use crate::identity::state::IdentityApiState;
use crate::members::provisioning::ProvisionPreview;
use crate::members::{MemberProvisioner, MemberProvisioningConfig};
use crate::rbac::{Feature, RbacConfig};
use crate::source_auth::models::{AuthenticatedIdentity, MtlsSans, PeerCertSource};

use super::authz::require_feature as require;

type ApiResult<T> = Result<T, (StatusCode, String)>;

/// Resolve the configured member provisioner or fail.
fn provisioner(state: &IdentityApiState) -> ApiResult<Arc<MemberProvisioner>> {
    state
        .member_provisioner
        .clone()
        .ok_or((StatusCode::INTERNAL_SERVER_ERROR, "Member provisioner not configured".to_string()))
}

/// `GET /v1/member-provisioning` — read the appliance provisioning config.
pub async fn get_provisioning_config(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
) -> ApiResult<Json<MemberProvisioningConfig>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::EnrolmentView).await?;
    Ok(Json(
        provisioner(&state)?
            .config()
            .await,
    ))
}

/// `PUT /v1/member-provisioning` — replace the appliance provisioning config.
pub async fn update_provisioning_config(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
    Json(config): Json<MemberProvisioningConfig>,
) -> ApiResult<Json<MemberProvisioningConfig>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::EnrolmentEdit).await?;
    let prov = provisioner(&state)?;
    prov.update_config(config)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid provisioning config: {e}")))?;
    Ok(Json(prov.config().await))
}

/// A caller identity described by the admin for a dry-run preview. Mirrors the
/// verified-identity shapes the data plane can present, but is supplied by hand
/// so an operator can validate their rules before a real caller arrives.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PreviewIdentityRequest {
    /// A decoded JWT: `subject` (the `sub` claim) plus the full claim set.
    Jwt {
        #[serde(default)]
        subject: String,
        #[serde(default)]
        claims: serde_json::Value,
    },
    /// A named API key.
    ApiKey { key_name: String },
    /// An mTLS client certificate, described by its subject DN and optional SANs.
    Mtls {
        #[serde(default)]
        subject_dn: String,
        #[serde(default)]
        sans: MtlsSans,
    },
}

impl PreviewIdentityRequest {
    fn into_identity(self) -> AuthenticatedIdentity {
        match self {
            PreviewIdentityRequest::Jwt { subject, claims } => AuthenticatedIdentity::JwtBearer { subject, claims },
            PreviewIdentityRequest::ApiKey { key_name } => AuthenticatedIdentity::ApiKey { key_name },
            PreviewIdentityRequest::Mtls { subject_dn, sans } => AuthenticatedIdentity::Mtls {
                principal: subject_dn.clone(),
                fingerprint: String::new(),
                subject_dn,
                issuer_dn: String::new(),
                sans,
                source: PeerCertSource::DirectTls,
            },
        }
    }
}

/// A preview request: the caller identity (flattened, `type`-tagged) plus an
/// optional `config`. When `config` is present the dry-run reflects that
/// (typically unsaved) editor state; otherwise the stored config is used.
#[derive(Debug, Clone, Deserialize)]
pub struct PreviewRequest {
    #[serde(flatten)]
    identity: PreviewIdentityRequest,
    #[serde(default)]
    config: Option<MemberProvisioningConfig>,
}

/// `POST /v1/member-provisioning/preview` — dry-run the rules against a caller
/// identity supplied in the request body, optionally against a config supplied
/// inline (so the editor can preview unsaved changes). Writes nothing.
pub async fn preview_provisioning(
    State(state): State<IdentityApiState>,
    Extension(caller_id): Extension<String>,
    Extension(storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    pat: Option<Extension<PatContext>>,
    Json(request): Json<PreviewRequest>,
) -> ApiResult<Json<ProvisionPreview>> {
    require(&caller_id, &storage, &rbac, pat.as_deref(), &Feature::EnrolmentView).await?;
    let prov = provisioner(&state)?;
    let identity = request
        .identity
        .into_identity();
    let preview = match request.config {
        Some(config) => {
            prov.preview_with_config(&config, &identity)
                .await
        }
        None => prov.preview(&identity).await,
    };
    Ok(Json(preview))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_request_flattens_identity_and_optional_config() {
        // Identity fields sit at the top level alongside an inline config.
        let with_config: PreviewRequest = serde_json::from_value(serde_json::json!({
            "type": "jwt",
            "subject": "sub-1",
            "claims": { "email": "dev@team.io" },
            "config": { "enabled": true }
        }))
        .expect("deserializes with config");
        assert!(matches!(with_config.identity, PreviewIdentityRequest::Jwt { .. }));
        let config = with_config
            .config
            .expect("config present");
        assert!(config.enabled);

        // Config is optional — a bare identity still deserializes.
        let without_config: PreviewRequest = serde_json::from_value(serde_json::json!({
            "type": "api_key",
            "key_name": "ci-key"
        }))
        .expect("deserializes without config");
        assert!(
            without_config
                .config
                .is_none()
        );
        assert!(matches!(without_config.identity, PreviewIdentityRequest::ApiKey { .. }));
    }
}
