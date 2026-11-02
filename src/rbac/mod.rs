//! Role-Based Access Control (RBAC) module

use crate::auth::types::UserRole;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

/// RBAC configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RbacConfig {
    /// Feature permissions map: feature_name -> required_role.
    /// Defaults to the hardened permission set so that a missing or partial
    /// `permissions` key in `rbac.json` never degrades to open access.
    /// When the key is present, the supplied entries are merged on top of
    /// the defaults — unlisted features keep their default role.
    #[serde(default = "default_permissions", deserialize_with = "deserialize_permissions_merged")]
    pub permissions: HashMap<String, String>,
}

fn deserialize_permissions_merged<'de, D>(deserializer: D) -> Result<HashMap<String, String>, D::Error>
where
    D: Deserializer<'de>,
{
    let overrides: HashMap<String, String> = HashMap::deserialize(deserializer)?;
    let mut merged = default_permissions();
    merged.extend(overrides);
    Ok(merged)
}

/// Returns the fully-populated default permissions map.
/// Used by serde when the `permissions` key is absent during deserialization,
/// ensuring security-critical features are never left unrestricted.
fn default_permissions() -> HashMap<String, String> {
    RbacConfig::default().permissions
}

impl Default for RbacConfig {
    fn default() -> Self {
        let mut permissions = HashMap::new();
        // Settings - Admin only
        permissions.insert("settings.view".to_string(), "administrator".to_string());
        permissions.insert("settings.edit".to_string(), "administrator".to_string());
        // User Management - Admin only
        permissions.insert("users.view".to_string(), "administrator".to_string());
        permissions.insert("users.edit".to_string(), "administrator".to_string());
        permissions.insert("users.approve".to_string(), "administrator".to_string());
        permissions.insert("users.delete".to_string(), "administrator".to_string());
        // Team Management - Admin only
        permissions.insert("teams.view".to_string(), "administrator".to_string());
        permissions.insert("teams.edit".to_string(), "administrator".to_string());
        permissions.insert("teams.delete".to_string(), "administrator".to_string());
        // Member Management (appliance clients) - Admin only
        permissions.insert("members.view".to_string(), "administrator".to_string());
        permissions.insert("members.edit".to_string(), "administrator".to_string());
        permissions.insert("members.delete".to_string(), "administrator".to_string());
        // Enrolment auto-provisioning config - Admin only
        permissions.insert("enrolment.view".to_string(), "administrator".to_string());
        permissions.insert("enrolment.edit".to_string(), "administrator".to_string());

        permissions.insert("prompts.view".to_string(), "user".to_string());
        permissions.insert("prompts.edit".to_string(), "administrator".to_string());
        permissions.insert("prompts.delete".to_string(), "administrator".to_string());
        // Gateway Management - Admin only (edit/delete); view = user
        permissions.insert("gateways.edit".to_string(), "administrator".to_string());
        permissions.insert("gateways.delete".to_string(), "administrator".to_string());
        // Mediator Management - PowerUser and above
        permissions.insert("mediators.edit".to_string(), "poweruser".to_string());
        permissions.insert("mediators.delete".to_string(), "poweruser".to_string());
        // Connection Point Management (fabric/G2G) - PowerUser and above
        permissions.insert("connection_points.edit".to_string(), "poweruser".to_string());
        permissions.insert("connection_points.delete".to_string(), "poweruser".to_string());
        // Surface Management - Admin only (edit/delete); capture = PowerUser
        permissions.insert("surfaces.edit".to_string(), "administrator".to_string());
        permissions.insert("surfaces.delete".to_string(), "administrator".to_string());
        permissions.insert("surfaces.capture".to_string(), "poweruser".to_string());
        // OIDC Provider Management - Admin only
        permissions.insert("jwt_verification_strategies.view".to_string(), "administrator".to_string());
        permissions.insert("jwt_verification_strategies.edit".to_string(), "administrator".to_string());
        permissions.insert("jwt_verification_strategies.delete".to_string(), "administrator".to_string());
        // OAuth Identifier profiles (public sign-in identifiers) - Admin only
        permissions.insert("oauth_identifiers.view".to_string(), "administrator".to_string());
        permissions.insert("oauth_identifiers.edit".to_string(), "administrator".to_string());
        permissions.insert("oauth_identifiers.delete".to_string(), "administrator".to_string());
        // Privileged and secret-bearing control-plane APIs - Admin only.
        permissions.insert("secrets.view".to_string(), "administrator".to_string());
        permissions.insert("secrets.edit".to_string(), "administrator".to_string());
        permissions.insert("secrets.delete".to_string(), "administrator".to_string());
        permissions.insert("api_keys.view".to_string(), "administrator".to_string());
        permissions.insert("api_keys.edit".to_string(), "administrator".to_string());
        permissions.insert("api_keys.delete".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.view".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.edit".to_string(), "administrator".to_string());
        permissions.insert("access_tokens.delete".to_string(), "administrator".to_string());
        permissions.insert("tenant_ownership.manage".to_string(), "administrator".to_string());
        permissions.insert("certificates.view".to_string(), "administrator".to_string());
        permissions.insert("certificates.edit".to_string(), "administrator".to_string());
        permissions.insert("vault_identities.edit".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.view".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.edit".to_string(), "administrator".to_string());
        permissions.insert("credential_providers.delete".to_string(), "administrator".to_string());
        permissions.insert("delegation_vault.view".to_string(), "administrator".to_string());
        permissions.insert("delegation_vault.delete".to_string(), "administrator".to_string());
        permissions.insert("storage.admin".to_string(), "administrator".to_string());
        permissions.insert("identity.issue".to_string(), "administrator".to_string());
        permissions.insert("identities.manage".to_string(), "administrator".to_string());
        permissions.insert("config.reload".to_string(), "administrator".to_string());
        permissions.insert("policies.view".to_string(), "administrator".to_string());
        permissions.insert("policies.edit".to_string(), "administrator".to_string());
        permissions.insert("policies.delete".to_string(), "administrator".to_string());
        // Activating a policy appliance-wide (global assignment) — the most
        // privileged policy action — is separated from authoring (edit).
        permissions.insert("policies.publish".to_string(), "administrator".to_string());
        // Integration Management (platform-wide user/identity lifecycle webhooks that
        // observe every user's PII, configured with delivery credentials) - Admin only
        permissions.insert("integrations.view".to_string(), "administrator".to_string());
        permissions.insert("integrations.edit".to_string(), "administrator".to_string());
        permissions.insert("integrations.delete".to_string(), "administrator".to_string());
        permissions.insert("terms.view".to_string(), "administrator".to_string());
        permissions.insert("terms.edit".to_string(), "administrator".to_string());
        // Features accessible to all authenticated users (minimum role = user).
        // Explicitly listed so that default-deny does not lock them out.
        permissions.insert("gateways.view".to_string(), "user".to_string());
        permissions.insert("mediators.view".to_string(), "user".to_string());
        permissions.insert("trust_registries.view".to_string(), "user".to_string());
        permissions.insert("surfaces.view".to_string(), "user".to_string());
        permissions.insert("connection_points.view".to_string(), "user".to_string());
        permissions.insert("notifications.view".to_string(), "user".to_string());
        permissions.insert("notifications.edit".to_string(), "user".to_string());
        permissions.insert("notifications.delete".to_string(), "user".to_string());
        permissions.insert("pipes.view".to_string(), "user".to_string());
        permissions.insert("pipes.edit".to_string(), "user".to_string());
        permissions.insert("pipes.delete".to_string(), "user".to_string());
        permissions.insert("pipes.execute".to_string(), "user".to_string());
        // Setting what a surface bills at (a declared price or the cost
        // override) moves every budget that counts its spend - Admin only.
        permissions.insert("pipes.pricing".to_string(), "administrator".to_string());
        // The model catalog prices every call no surface prices itself, so
        // changing it moves every budget on the appliance - Admin only.
        permissions.insert("llm_catalog.edit".to_string(), "administrator".to_string());
        permissions.insert("metrics.view".to_string(), "user".to_string());
        permissions.insert("metrics.view_attributed".to_string(), "administrator".to_string());
        permissions.insert("dashboard.view".to_string(), "user".to_string());
        // The appliance log covers every surface, user and tenant - Admin only.
        permissions.insert("logs.view".to_string(), "administrator".to_string());
        permissions.insert("audit.view".to_string(), "administrator".to_string());
        permissions.insert("governance.view".to_string(), "administrator".to_string());
        permissions.insert("drift.view".to_string(), "administrator".to_string());
        permissions.insert("drift.manage".to_string(), "administrator".to_string());
        permissions.insert("payments.view".to_string(), "user".to_string());
        permissions.insert("payments.edit".to_string(), "user".to_string());
        permissions.insert("payments.delete".to_string(), "user".to_string());
        permissions.insert("payments.retry".to_string(), "user".to_string());

        Self { permissions }
    }
}

/// Features that can be restricted
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Feature {
    // User Management
    UsersView,
    UsersEdit,
    UsersApprove,
    UsersDelete,

    // Team Management
    TeamsView,
    TeamsEdit,
    TeamsDelete,

    // Member Management (appliance clients)
    MembersView,
    MembersEdit,
    MembersDelete,

    // Enrolment auto-provisioning (appliance-level config)
    EnrolmentView,
    EnrolmentEdit,

    // Prompt Management (versioned prompt templates)
    PromptsView,
    PromptsEdit,
    PromptsDelete,

    // Gateway Management
    GatewaysView,
    GatewaysEdit,
    GatewaysDelete,

    // Mediator Management
    MediatorsView,
    MediatorsEdit,
    MediatorsDelete,

    // Connection Point Management (fabric/G2G)
    ConnectionPointsView,
    ConnectionPointsEdit,
    ConnectionPointsDelete,

    // Vault Management
    SecretsView,
    SecretsEdit,
    SecretsDelete,

    // API Key Management
    ApiKeysView,
    ApiKeysEdit,
    ApiKeysDelete,

    // Management access tokens (service-account PATs for the management API)
    AccessTokensView,
    AccessTokensEdit,
    AccessTokensDelete,

    // Tenant ownership inspection and reassignment
    TenantOwnershipManage,

    // Certificate Management
    CertificatesView,
    CertificatesEdit,

    // Vault Identity Management
    VaultIdentitiesEdit,

    // Credential Provider Management
    CredentialProvidersView,
    CredentialProvidersEdit,
    CredentialProvidersDelete,

    // Delegation Vault Management
    DelegationVaultView,
    DelegationVaultDelete,

    // Full storage export/backup/restore
    StorageAdmin,

    // Identity issuance and configuration reload
    IdentityIssue,
    // DID:webvh identity management (/v1/identities)
    IdentitiesManage,
    ConfigReload,

    // Policy definition Management
    PoliciesView,
    PoliciesEdit,
    PoliciesDelete,
    /// Activate a policy appliance-wide (global assignment) — a separate,
    /// more-privileged action than authoring (`PoliciesEdit`).
    PoliciesPublish,

    // Notification Management
    NotificationsView,
    NotificationsEdit,
    NotificationsDelete,

    // Channel Management
    SurfacesView,
    SurfacesEdit,
    SurfacesDelete,
    SurfacesCapture,

    // Pipe Management
    PipesView,
    PipesEdit,
    PipesDelete,
    PipesExecute,
    /// Add or change a surface's declared prices or its cost override.
    PipesPricing,

    /// Create, change, delete, refresh or roll back the LLM provider catalog.
    LlmCatalogEdit,

    // Integration Management
    IntegrationsView,
    IntegrationsEdit,
    IntegrationsDelete,

    // System Settings
    SettingsView,
    SettingsEdit,

    // Terms Management
    TermsView,
    TermsEdit,

    // Metrics
    MetricsView,
    MetricsViewAttributed,

    DashboardView,
    LogsView,
    AuditView,
    GovernanceView,
    DriftView,
    DriftManage,

    // Payment Management
    PaymentsView,
    PaymentsEdit,
    PaymentsDelete,
    PaymentsRetry,

    // OIDC Provider Management
    JwtVerificationStrategiesView,
    JwtVerificationStrategiesEdit,
    JwtVerificationStrategiesDelete,

    // OAuth Identifier profiles (public sign-in identifiers)
    OauthIdentifiersView,
    OauthIdentifiersEdit,
    OauthIdentifiersDelete,
}

impl Feature {
    pub fn as_str(&self) -> &'static str {
        match self {
            Feature::UsersView => "users.view",
            Feature::UsersEdit => "users.edit",
            Feature::UsersApprove => "users.approve",
            Feature::UsersDelete => "users.delete",
            Feature::TeamsView => "teams.view",
            Feature::TeamsEdit => "teams.edit",
            Feature::TeamsDelete => "teams.delete",
            Feature::MembersView => "members.view",
            Feature::MembersEdit => "members.edit",
            Feature::MembersDelete => "members.delete",
            Feature::EnrolmentView => "enrolment.view",
            Feature::EnrolmentEdit => "enrolment.edit",
            Feature::PromptsView => "prompts.view",
            Feature::PromptsEdit => "prompts.edit",
            Feature::PromptsDelete => "prompts.delete",
            Feature::GatewaysView => "gateways.view",
            Feature::GatewaysEdit => "gateways.edit",
            Feature::GatewaysDelete => "gateways.delete",
            Feature::MediatorsView => "mediators.view",
            Feature::MediatorsEdit => "mediators.edit",
            Feature::MediatorsDelete => "mediators.delete",
            Feature::ConnectionPointsView => "connection_points.view",
            Feature::ConnectionPointsEdit => "connection_points.edit",
            Feature::ConnectionPointsDelete => "connection_points.delete",
            Feature::SecretsView => "secrets.view",
            Feature::SecretsEdit => "secrets.edit",
            Feature::SecretsDelete => "secrets.delete",
            Feature::ApiKeysView => "api_keys.view",
            Feature::ApiKeysEdit => "api_keys.edit",
            Feature::ApiKeysDelete => "api_keys.delete",
            Feature::AccessTokensView => "access_tokens.view",
            Feature::AccessTokensEdit => "access_tokens.edit",
            Feature::AccessTokensDelete => "access_tokens.delete",
            Feature::TenantOwnershipManage => "tenant_ownership.manage",
            Feature::CertificatesView => "certificates.view",
            Feature::CertificatesEdit => "certificates.edit",
            Feature::VaultIdentitiesEdit => "vault_identities.edit",
            Feature::CredentialProvidersView => "credential_providers.view",
            Feature::CredentialProvidersEdit => "credential_providers.edit",
            Feature::CredentialProvidersDelete => "credential_providers.delete",
            Feature::DelegationVaultView => "delegation_vault.view",
            Feature::DelegationVaultDelete => "delegation_vault.delete",
            Feature::StorageAdmin => "storage.admin",
            Feature::IdentityIssue => "identity.issue",
            Feature::IdentitiesManage => "identities.manage",
            Feature::ConfigReload => "config.reload",
            Feature::PoliciesView => "policies.view",
            Feature::PoliciesEdit => "policies.edit",
            Feature::PoliciesDelete => "policies.delete",
            Feature::PoliciesPublish => "policies.publish",
            Feature::NotificationsView => "notifications.view",
            Feature::NotificationsEdit => "notifications.edit",
            Feature::NotificationsDelete => "notifications.delete",
            Feature::SurfacesView => "surfaces.view",
            Feature::SurfacesEdit => "surfaces.edit",
            Feature::SurfacesDelete => "surfaces.delete",
            Feature::SurfacesCapture => "surfaces.capture",
            Feature::PipesView => "pipes.view",
            Feature::PipesEdit => "pipes.edit",
            Feature::PipesDelete => "pipes.delete",
            Feature::PipesExecute => "pipes.execute",
            Feature::PipesPricing => "pipes.pricing",
            Feature::LlmCatalogEdit => "llm_catalog.edit",
            Feature::IntegrationsView => "integrations.view",
            Feature::IntegrationsEdit => "integrations.edit",
            Feature::IntegrationsDelete => "integrations.delete",
            Feature::SettingsView => "settings.view",
            Feature::SettingsEdit => "settings.edit",
            Feature::TermsView => "terms.view",
            Feature::TermsEdit => "terms.edit",
            Feature::MetricsView => "metrics.view",
            Feature::MetricsViewAttributed => "metrics.view_attributed",
            Feature::DashboardView => "dashboard.view",
            Feature::LogsView => "logs.view",
            Feature::AuditView => "audit.view",
            Feature::GovernanceView => "governance.view",
            Feature::DriftView => "drift.view",
            Feature::DriftManage => "drift.manage",
            Feature::PaymentsView => "payments.view",
            Feature::PaymentsEdit => "payments.edit",
            Feature::PaymentsDelete => "payments.delete",
            Feature::PaymentsRetry => "payments.retry",
            Feature::JwtVerificationStrategiesView => "jwt_verification_strategies.view",
            Feature::JwtVerificationStrategiesEdit => "jwt_verification_strategies.edit",
            Feature::JwtVerificationStrategiesDelete => "jwt_verification_strategies.delete",
            Feature::OauthIdentifiersView => "oauth_identifiers.view",
            Feature::OauthIdentifiersEdit => "oauth_identifiers.edit",
            Feature::OauthIdentifiersDelete => "oauth_identifiers.delete",
        }
    }
}

impl RbacConfig {
    /// Check if a user role has permission for a feature
    pub fn has_permission(
        &self,
        user_role: &UserRole,
        feature: &Feature,
    ) -> bool {
        self.has_named_permission(user_role, feature.as_str())
    }

    pub fn has_named_permission(
        &self,
        user_role: &UserRole,
        feature: &str,
    ) -> bool {
        if let Some(required_role_str) = self.permissions.get(feature) {
            let required_role = match required_role_str
                .to_lowercase()
                .as_str()
            {
                "administrator" => UserRole::Administrator,
                "poweruser" => UserRole::PowerUser,
                "user" => UserRole::User,
                _ => return false, // Invalid role specified
            };

            // Check if user's role meets or exceeds required role
            match user_role {
                UserRole::Administrator => true, // Administrator has all permissions
                UserRole::PowerUser => {
                    matches!(required_role, UserRole::PowerUser | UserRole::User)
                }
                UserRole::User => matches!(required_role, UserRole::User),
            }
        } else {
            // Feature not in permissions map — deny by default.
            // All legitimate features must be explicitly listed in the
            // permissions map with their minimum required role.
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unrestricted_feature() {
        let config = RbacConfig::default();
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::DashboardView));
    }

    #[test]
    fn test_admin_only_feature() {
        let mut config = RbacConfig::default();
        config
            .permissions
            .insert("users.edit".to_string(), "administrator".to_string());

        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
    }

    #[test]
    fn test_poweruser_feature() {
        let mut config = RbacConfig::default();
        config
            .permissions
            .insert("surfaces.edit".to_string(), "poweruser".to_string());

        assert!(!config.has_permission(&UserRole::User, &Feature::SurfacesEdit));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::SurfacesEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::SurfacesEdit));
    }

    #[test]
    fn test_unknown_feature_denied_by_default() {
        let mut config = RbacConfig::default();
        config.permissions.clear();
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
    }

    #[test]
    fn test_metrics_view_attributed_defaults_to_administrator_only() {
        // Aggregate/surface usage stays viewable by `user`, but per-member /
        // per-team attributed breakdowns require administrator by default.
        let config = RbacConfig::default();
        assert!(config.has_permission(&UserRole::User, &Feature::MetricsView));
        assert!(!config.has_permission(&UserRole::User, &Feature::MetricsViewAttributed));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::MetricsViewAttributed));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::MetricsViewAttributed));
    }

    #[test]
    fn test_logs_view_defaults_to_administrator_only() {
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::LogsView));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::LogsView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::LogsView));
    }

    #[test]
    fn test_governance_view_defaults_to_administrator_only() {
        // Governance records carry raw prompts/completions, so reading them is
        // administrator-only by default.
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::GovernanceView));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::GovernanceView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::GovernanceView));
    }

    #[test]
    fn test_drift_view_defaults_to_administrator_only() {
        // Drift series can expose the refusal / safety-rate behaviour of a
        // surface, so reading them is administrator-only by default (parity
        // with governance).
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::DriftView));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::DriftView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::DriftView));
    }

    #[test]
    fn test_drift_manage_defaults_to_administrator_only() {
        // Pinning a baseline is a write, so it is administrator-only by default.
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::DriftManage));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::DriftManage));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::DriftManage));
    }

    #[test]
    fn test_deserialized_empty_json_uses_secure_defaults() {
        let config: RbacConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::UsersEdit));
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
    }

    #[test]
    fn test_deserialized_partial_json_retains_overrides() {
        let json = r#"{"permissions": {"users.edit": "poweruser"}}"#;
        let config: RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::UsersEdit));
        assert!(!config.has_permission(&UserRole::User, &Feature::UsersEdit));
    }

    #[test]
    fn test_partial_json_preserves_defaults_for_unlisted_features() {
        let json = r#"{"permissions": {"users.edit": "poweruser"}}"#;
        let config: RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.has_permission(&UserRole::User, &Feature::DashboardView));
        assert!(config.has_permission(&UserRole::User, &Feature::GatewaysView));
        assert!(config.has_permission(&UserRole::User, &Feature::SurfacesView));
        assert!(!config.has_permission(&UserRole::User, &Feature::SettingsView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::SettingsView));
    }

    #[test]
    fn test_hardened_mutating_features_are_admin_only() {
        let config = RbacConfig::default();
        for feature in [
            Feature::GatewaysEdit,
            Feature::GatewaysDelete,
            Feature::SurfacesEdit,
            Feature::SurfacesDelete,
            Feature::SecretsView,
            Feature::SecretsEdit,
            Feature::SecretsDelete,
            Feature::ApiKeysView,
            Feature::ApiKeysEdit,
            Feature::ApiKeysDelete,
            Feature::AccessTokensView,
            Feature::AccessTokensEdit,
            Feature::AccessTokensDelete,
            Feature::TenantOwnershipManage,
            Feature::CertificatesView,
            Feature::CertificatesEdit,
            Feature::VaultIdentitiesEdit,
            Feature::CredentialProvidersView,
            Feature::CredentialProvidersEdit,
            Feature::CredentialProvidersDelete,
            Feature::DelegationVaultView,
            Feature::DelegationVaultDelete,
            Feature::StorageAdmin,
            Feature::IdentityIssue,
            Feature::IdentitiesManage,
            Feature::ConfigReload,
            Feature::PoliciesView,
            Feature::PoliciesEdit,
            Feature::PoliciesDelete,
            Feature::PoliciesPublish,
            Feature::SettingsEdit,
            Feature::AuditView,
        ] {
            assert!(!config.has_permission(&UserRole::User, &feature), "User must NOT have {:?}", feature);
            assert!(!config.has_permission(&UserRole::PowerUser, &feature), "PowerUser must NOT have {:?}", feature);
            assert!(config.has_permission(&UserRole::Administrator, &feature), "Administrator must have {:?}", feature);
        }
    }

    #[test]
    fn test_pipes_remain_user_accessible() {
        let config = RbacConfig::default();
        for feature in [Feature::PipesEdit, Feature::PipesDelete, Feature::PipesExecute] {
            assert!(
                config.has_permission(&UserRole::User, &feature),
                "User must have {:?} (pipes are the pivot)",
                feature
            );
        }
    }

    #[test]
    fn pipes_pricing_defaults_to_administrator_only() {
        let config = RbacConfig::default();
        assert!(config.has_permission(&UserRole::User, &Feature::PipesEdit), "precondition: users edit pipes");
        assert!(!config.has_permission(&UserRole::User, &Feature::PipesPricing));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::PipesPricing));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::PipesPricing));
    }

    #[test]
    fn llm_catalog_edit_defaults_to_administrator_only() {
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::LlmCatalogEdit));
        assert!(!config.has_permission(&UserRole::PowerUser, &Feature::LlmCatalogEdit));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::LlmCatalogEdit));
    }

    #[test]
    fn test_connection_points_edit_delete_require_poweruser() {
        let config = RbacConfig::default();
        assert!(config.has_permission(&UserRole::User, &Feature::ConnectionPointsView));
        for feature in [Feature::ConnectionPointsEdit, Feature::ConnectionPointsDelete] {
            assert!(!config.has_permission(&UserRole::User, &feature), "User must NOT have {:?}", feature);
            assert!(config.has_permission(&UserRole::PowerUser, &feature), "PowerUser must have {:?}", feature);
            assert!(config.has_permission(&UserRole::Administrator, &feature), "Administrator must have {:?}", feature);
        }
    }

    #[test]
    fn test_secret_bearing_and_evidence_view_features_are_admin_only() {
        let config = RbacConfig::default();
        assert!(!config.has_permission(&UserRole::User, &Feature::SecretsView));
        assert!(!config.has_permission(&UserRole::User, &Feature::ApiKeysView));
        assert!(!config.has_permission(&UserRole::User, &Feature::CertificatesView));
        assert!(!config.has_permission(&UserRole::User, &Feature::CredentialProvidersView));
        assert!(!config.has_permission(&UserRole::User, &Feature::DelegationVaultView));
        assert!(!config.has_permission(&UserRole::User, &Feature::AuditView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::SecretsView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::ApiKeysView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::CertificatesView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::CredentialProvidersView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::DelegationVaultView));
        assert!(config.has_permission(&UserRole::Administrator, &Feature::AuditView));
        assert!(config.has_permission(&UserRole::User, &Feature::ConnectionPointsView));
    }

    #[test]
    fn test_unchanged_family_roles_preserved() {
        let config = RbacConfig::default();
        // Mediators stay poweruser for mutation.
        assert!(!config.has_permission(&UserRole::User, &Feature::MediatorsEdit));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::MediatorsEdit));
        assert!(config.has_permission(&UserRole::PowerUser, &Feature::MediatorsDelete));
        // Notifications stay user-accessible.
        assert!(config.has_permission(&UserRole::User, &Feature::NotificationsEdit));
        assert!(config.has_permission(&UserRole::User, &Feature::NotificationsDelete));
    }

    #[test]
    fn test_integrations_require_administrator() {
        let config = RbacConfig::default();
        // Reading integrations (which carry delivery credentials) and
        // installing/removing platform-wide lifecycle webhooks (which deliver every
        // user's PII to an external URL) are administrator-only.
        for feature in [Feature::IntegrationsView, Feature::IntegrationsEdit, Feature::IntegrationsDelete] {
            assert!(!config.has_permission(&UserRole::User, &feature), "User must NOT have {:?}", feature);
            assert!(!config.has_permission(&UserRole::PowerUser, &feature), "PowerUser must NOT have {:?}", feature);
            assert!(config.has_permission(&UserRole::Administrator, &feature), "Administrator must have {:?}", feature);
        }
    }
}
