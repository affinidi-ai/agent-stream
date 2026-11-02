use crate::auth::storage::PasskeyStorage;
use crate::auth::types::UserRole;
use crate::rbac::{Feature, RbacConfig};
use axum::{Extension, Json, http::StatusCode};

/// The single source of truth for every RBAC feature the dashboard reads, as
/// `(permission_name, Feature)` pairs. Every permission endpoint derives its
/// response from this one list, so a newly-added `Feature` is exposed
/// everywhere at once — a per-endpoint list that fell out of sync is what
/// previously hid the LLM Drift page from administrators.
fn permission_features() -> Vec<(&'static str, Feature)> {
    vec![
        ("users.view", Feature::UsersView),
        ("users.edit", Feature::UsersEdit),
        ("users.approve", Feature::UsersApprove),
        ("users.delete", Feature::UsersDelete),
        ("teams.view", Feature::TeamsView),
        ("teams.edit", Feature::TeamsEdit),
        ("teams.delete", Feature::TeamsDelete),
        ("members.view", Feature::MembersView),
        ("members.edit", Feature::MembersEdit),
        ("members.delete", Feature::MembersDelete),
        ("enrolment.view", Feature::EnrolmentView),
        ("enrolment.edit", Feature::EnrolmentEdit),
        ("prompts.view", Feature::PromptsView),
        ("prompts.edit", Feature::PromptsEdit),
        ("prompts.delete", Feature::PromptsDelete),
        ("gateways.view", Feature::GatewaysView),
        ("gateways.edit", Feature::GatewaysEdit),
        ("gateways.delete", Feature::GatewaysDelete),
        ("mediators.view", Feature::MediatorsView),
        ("mediators.edit", Feature::MediatorsEdit),
        ("mediators.delete", Feature::MediatorsDelete),
        ("connection_points.view", Feature::ConnectionPointsView),
        ("connection_points.edit", Feature::ConnectionPointsEdit),
        ("connection_points.delete", Feature::ConnectionPointsDelete),
        ("notifications.view", Feature::NotificationsView),
        ("notifications.edit", Feature::NotificationsEdit),
        ("notifications.delete", Feature::NotificationsDelete),
        ("surfaces.view", Feature::SurfacesView),
        ("surfaces.edit", Feature::SurfacesEdit),
        ("surfaces.delete", Feature::SurfacesDelete),
        ("surfaces.capture", Feature::SurfacesCapture),
        ("secrets.view", Feature::SecretsView),
        ("secrets.edit", Feature::SecretsEdit),
        ("secrets.delete", Feature::SecretsDelete),
        ("api_keys.view", Feature::ApiKeysView),
        ("api_keys.edit", Feature::ApiKeysEdit),
        ("api_keys.delete", Feature::ApiKeysDelete),
        ("access_tokens.view", Feature::AccessTokensView),
        ("access_tokens.edit", Feature::AccessTokensEdit),
        ("access_tokens.delete", Feature::AccessTokensDelete),
        ("tenant_ownership.manage", Feature::TenantOwnershipManage),
        ("certificates.view", Feature::CertificatesView),
        ("certificates.edit", Feature::CertificatesEdit),
        ("vault_identities.edit", Feature::VaultIdentitiesEdit),
        ("credential_providers.view", Feature::CredentialProvidersView),
        ("credential_providers.edit", Feature::CredentialProvidersEdit),
        ("credential_providers.delete", Feature::CredentialProvidersDelete),
        ("delegation_vault.view", Feature::DelegationVaultView),
        ("delegation_vault.delete", Feature::DelegationVaultDelete),
        ("storage.admin", Feature::StorageAdmin),
        ("identity.issue", Feature::IdentityIssue),
        ("identities.manage", Feature::IdentitiesManage),
        ("config.reload", Feature::ConfigReload),
        ("policies.view", Feature::PoliciesView),
        ("policies.edit", Feature::PoliciesEdit),
        ("policies.delete", Feature::PoliciesDelete),
        ("policies.publish", Feature::PoliciesPublish),
        ("pipes.view", Feature::PipesView),
        ("pipes.edit", Feature::PipesEdit),
        ("pipes.delete", Feature::PipesDelete),
        ("pipes.execute", Feature::PipesExecute),
        ("pipes.pricing", Feature::PipesPricing),
        ("llm_catalog.edit", Feature::LlmCatalogEdit),
        ("integrations.view", Feature::IntegrationsView),
        ("integrations.edit", Feature::IntegrationsEdit),
        ("integrations.delete", Feature::IntegrationsDelete),
        ("settings.view", Feature::SettingsView),
        ("settings.edit", Feature::SettingsEdit),
        ("terms.view", Feature::TermsView),
        ("terms.edit", Feature::TermsEdit),
        ("metrics.view", Feature::MetricsView),
        ("metrics.view_attributed", Feature::MetricsViewAttributed),
        ("dashboard.view", Feature::DashboardView),
        ("logs.view", Feature::LogsView),
        ("audit.view", Feature::AuditView),
        ("governance.view", Feature::GovernanceView),
        ("drift.view", Feature::DriftView),
        ("drift.manage", Feature::DriftManage),
        ("payments.view", Feature::PaymentsView),
        ("payments.edit", Feature::PaymentsEdit),
        ("payments.delete", Feature::PaymentsDelete),
        ("payments.retry", Feature::PaymentsRetry),
        ("jwt_verification_strategies.view", Feature::JwtVerificationStrategiesView),
        ("jwt_verification_strategies.edit", Feature::JwtVerificationStrategiesEdit),
        ("jwt_verification_strategies.delete", Feature::JwtVerificationStrategiesDelete),
        ("oauth_identifiers.view", Feature::OauthIdentifiersView),
        ("oauth_identifiers.edit", Feature::OauthIdentifiersEdit),
        ("oauth_identifiers.delete", Feature::OauthIdentifiersDelete),
    ]
}

/// Build the `{ feature: bool }` permission map for `role`.
fn permissions_for_role(
    rbac: &RbacConfig,
    role: &UserRole,
) -> serde_json::Map<String, serde_json::Value> {
    permission_features()
        .into_iter()
        .map(|(name, feature)| (name.to_string(), serde_json::Value::Bool(rbac.has_permission(role, &feature))))
        .collect()
}

/// A permission map with every feature denied (unauthenticated / unknown user).
fn denied_permissions() -> serde_json::Map<String, serde_json::Value> {
    permission_features()
        .into_iter()
        .map(|(name, _)| (name.to_string(), serde_json::Value::Bool(false)))
        .collect()
}

/// Get user permissions based on RBAC config (with optional authentication)
/// If user_id extension is present, returns user-specific permissions
/// If not authenticated, returns all permissions as false
pub async fn get_permissions_optional(
    user_id: Option<Extension<String>>,
    storage: Option<Extension<std::sync::Arc<PasskeyStorage>>>,
    rbac_config: Option<Extension<std::sync::Arc<crate::rbac::RbacConfig>>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    // Authenticated + resolvable user → their permissions; any other case
    // (unauthenticated, unknown user, load error) denies everything.
    let permissions = match (user_id, storage, rbac_config) {
        (Some(Extension(uid)), Some(Extension(store)), Some(Extension(rbac))) => {
            match store
                .load_user_by_id(&uid)
                .await
            {
                Ok(Some(user_data)) => permissions_for_role(&rbac, &user_data.role),
                _ => denied_permissions(),
            }
        }
        _ => denied_permissions(),
    };

    Ok(Json(serde_json::Value::Object(permissions)))
}

/// Get user permissions based on RBAC config (authenticated only)
pub async fn get_permissions(
    Extension(user_id): Extension<String>,
    Extension(storage): Extension<std::sync::Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<std::sync::Arc<crate::rbac::RbacConfig>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    let user_data = storage
        .load_user_by_id(&user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load user: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "User not found".to_string()))?;

    Ok(Json(serde_json::Value::Object(permissions_for_role(&rbac_config, &user_data.role))))
}

/// Get public permissions (for unauthenticated users during registration).
/// Returns every feature denied, since no user is logged in.
#[allow(dead_code)]
pub async fn get_public_permissions() -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    Ok(Json(serde_json::Value::Object(denied_permissions())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_list_has_no_duplicate_names() {
        let feats = permission_features();
        let count = feats.len();
        let mut names: Vec<&str> = feats
            .iter()
            .map(|(n, _)| *n)
            .collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate permission name in the feature list");
    }

    #[test]
    fn admin_map_exposes_monitoring_features() {
        // A missing key hides the corresponding Monitoring page in the dashboard,
        // so every gated page's feature must be present AND true for an admin.
        let map = permissions_for_role(&RbacConfig::default(), &UserRole::Administrator);
        for key in ["drift.view", "drift.manage", "governance.view"] {
            assert_eq!(map.get(key), Some(&serde_json::Value::Bool(true)), "admin missing {key}");
        }
    }

    #[test]
    fn plain_user_lacks_admin_only_monitoring_features() {
        let map = permissions_for_role(&RbacConfig::default(), &UserRole::User);
        for key in ["drift.view", "drift.manage", "governance.view"] {
            assert_eq!(map.get(key), Some(&serde_json::Value::Bool(false)), "user should not have {key}");
        }
    }

    #[test]
    fn denied_map_covers_every_feature_as_false() {
        let denied = denied_permissions();
        assert_eq!(denied.len(), permission_features().len());
        assert!(
            denied
                .values()
                .all(|v| v == &serde_json::Value::Bool(false))
        );
    }
}
