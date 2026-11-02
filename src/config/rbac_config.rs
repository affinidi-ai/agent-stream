//! RBAC configuration loader for rbac.json
//!
//! This module handles loading RBAC (Role-Based Access Control) configuration
//! from the rbac.json file.

use anyhow::{Context, Result};
use std::path::Path;

/// Load RBAC configuration from file
pub fn load_rbac_config<P: AsRef<Path>>(path: P) -> Result<crate::rbac::RbacConfig> {
    let path = path.as_ref();
    let content =
        std::fs::read_to_string(path).with_context(|| format!("Failed to read RBAC config from {}", path.display()))?;

    let config: crate::rbac::RbacConfig = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse RBAC config from {}", path.display()))?;

    if grants_integrations_view_below_administrator(&config) {
        tracing::warn!(
            "{} grants integrations.view below administrator; integrations name their delivery endpoints, so restrict it to administrator unless that is intended",
            path.display()
        );
    }

    Ok(config)
}

/// Whether `config` lets a role below administrator read integrations, as the
/// example rbac.json did before `integrations.view` became administrator-only.
/// A role that meets `user` also meets `poweruser`, so one check covers both.
fn grants_integrations_view_below_administrator(config: &crate::rbac::RbacConfig) -> bool {
    config.has_permission(&crate::auth::types::UserRole::PowerUser, &crate::rbac::Feature::IntegrationsView)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn loaded(json: &str) -> crate::rbac::RbacConfig {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), json).unwrap();
        load_rbac_config(file.path()).unwrap()
    }

    #[test]
    fn a_stale_user_or_poweruser_grant_of_integrations_view_is_flagged() {
        for role in ["user", "poweruser"] {
            assert!(
                grants_integrations_view_below_administrator(&loaded(&format!(
                    r#"{{ "permissions": {{ "integrations.view": "{role}" }} }}"#
                ))),
                "{role}"
            );
        }
    }

    #[test]
    fn the_default_integrations_view_grant_is_not_flagged() {
        assert!(!grants_integrations_view_below_administrator(&loaded(r#"{ "permissions": {} }"#)));
        assert!(!grants_integrations_view_below_administrator(&loaded(
            r#"{ "permissions": { "integrations.view": "administrator" } }"#
        )));
    }

    #[test]
    fn test_parse_rbac_config() {
        let json = r#"{
            "permissions": {
                "users.view": "administrator",
                "users.edit": "administrator",
                "gateways.edit": "poweruser"
            }
        }"#;

        let config: crate::rbac::RbacConfig = serde_json::from_str(json).unwrap();
        assert!(config.permissions.len() >= 3);
        assert_eq!(
            config
                .permissions
                .get("users.view"),
            Some(&"administrator".to_string())
        );
        assert_eq!(
            config
                .permissions
                .get("gateways.edit"),
            Some(&"poweruser".to_string())
        );
    }
}
