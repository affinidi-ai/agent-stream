use anyhow::{Context, Result};
use std::collections::HashMap;
use tracing::{info, warn};

use crate::auth::auth_config::SamlConfig;
use crate::auth::saml::graph_api::GraphApiClient;
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};

/// The SAML account has a user who is not approved: an administrator disabled
/// or deleted them. Carried in the `anyhow` error so the ACS handler can refuse
/// the sign-in without creating a user.
#[derive(Debug, thiserror::Error)]
#[error("the user is not approved")]
pub struct UserNotApproved;

/// The username the identity provider asserted is already held by another
/// user, so nothing is created or updated.
#[derive(Debug, thiserror::Error)]
#[error("the username is held by another user")]
pub struct UsernameTaken;

/// Provision or update a user from SAML attributes. A user that exists and is
/// not approved is refused with [`UserNotApproved`], and a username another
/// user already holds with [`UsernameTaken`].
pub async fn provision_user_from_saml(
    storage: &PasskeyStorage,
    attributes: &HashMap<String, String>,
    config: &SamlConfig,
    avatars_storage_path: &str,
) -> Result<UserData> {
    // Extract user attributes using configured mappings
    let user_id_attr = attributes
        .get(
            &config
                .attribute_mapping
                .user_id,
        )
        .or_else(|| attributes.get("NameID"))
        .context("User ID not found in SAML attributes")?;

    let username = attributes
        .get(
            &config
                .attribute_mapping
                .username,
        )
        .or_else(|| attributes.get(&config.attribute_mapping.email))
        .context("Username not found in SAML attributes")?;

    let email = attributes
        .get(&config.attribute_mapping.email)
        .map(|s| s.to_string());

    let first_name = attributes
        .get(
            &config
                .attribute_mapping
                .first_name,
        )
        .map(|s| s.to_string());

    let last_name = attributes
        .get(
            &config
                .attribute_mapping
                .last_name,
        )
        .map(|s| s.to_string());

    let department = attributes
        .get(
            &config
                .attribute_mapping
                .department,
        )
        .map(|s| s.to_string());

    let job_title = attributes
        .get(
            &config
                .attribute_mapping
                .job_title,
        )
        .map(|s| s.to_string());

    // Determine role from SAML attributes
    let role = determine_role(attributes, config);

    let user_write_guard = storage
        .user_write_guard()
        .await;

    // Check if user already exists
    let existing_user = storage
        .load_user_by_saml_id(user_id_attr)
        .await?;

    if storage
        .username_held_by_other(
            username.as_str(),
            existing_user
                .as_ref()
                .map(|user| user.user_id.as_str()),
        )
        .await?
    {
        return Err(anyhow::Error::new(UsernameTaken));
    }

    let user = if let Some(mut user) = existing_user {
        if user.status != UserStatus::Approved {
            return Err(anyhow::Error::new(UserNotApproved));
        }
        info!("Updating existing SAML user: {}", username);

        user.username = username.clone();
        user.email = email.clone();
        user.first_name = first_name;
        user.last_name = last_name;
        user.department = department;
        user.job_title = job_title;
        user.role = if user.is_primary {
            UserRole::Administrator
        } else {
            role
        };
        user.updated_at = chrono::Utc::now();
        user.last_logged_in = Some(chrono::Utc::now());

        user
    } else {
        // Create new user (Just-In-Time provisioning)
        info!("Creating new SAML user: {}", username);

        // Check if this is the first user (should be admin)
        let is_first_user = storage
            .list_users()
            .await?
            .is_empty();

        // Enforce the appliance user limit for JIT-provisioned users. The first
        // user always bootstraps admin access regardless of the configured cap.
        if !is_first_user {
            let user_count = storage
                .count_toward_user_limit()
                .await?;
            crate::config::global_limits()
                .check_can_add("users", user_count)
                .map_err(anyhow::Error::new)?;
        }
        let final_role = if is_first_user {
            UserRole::Administrator
        } else {
            role
        };
        let status = UserStatus::Approved; // SAML users auto-approved (including first user)

        let now = chrono::Utc::now();
        let user = UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username: username.clone(),
            passkeys: Vec::new(),     // SAML users don't have passkeys
            role: final_role.clone(), // Clone so we can use it in logging
            status,
            is_primary: is_first_user,
            created_at: now,
            updated_at: now,
            first_name,
            last_name,
            email: email.clone(),
            department,
            job_title,
            avatar_path: None,
            last_logged_in: Some(now),
            saml_id: Some(user_id_attr.clone()),
            oidc: None,
            deleted_at: None,
        };

        info!("SAML user created successfully: {} (role: {:?})", username, final_role);

        user
    };

    // Save user first (don't block login on avatar fetch)
    storage
        .save_user(&user)
        .await?;

    drop(user_write_guard);

    // Spawn background task to fetch avatar asynchronously
    if let Some(graph_config) = &config.graph_api
        && graph_config.fetch_avatar
    {
        if let Some(user_email) = email.clone() {
            let user_id = user.user_id.clone();
            let graph_config = graph_config.clone();
            let avatars_storage_path = avatars_storage_path.to_string();
            if let Some(avatar_filename) =
                fetch_and_save_avatar(&graph_config, &user_email, &user_id, &avatars_storage_path).await
            {
                let relative_avatar_path = format!("avatars/{}", avatar_filename);
                match storage
                    .set_avatar_if_approved(&user_id, relative_avatar_path.clone())
                    .await
                {
                    Ok(true) => {
                        info!("Successfully updated user {} with avatar: {}", user_id, relative_avatar_path)
                    }
                    Ok(false) => {
                        storage
                            .remove_avatar_files(&user_id, Some(&relative_avatar_path))
                            .await
                    }
                    Err(e) => warn!("Failed to update user with avatar path: {}", e),
                }
            }
        } else {
            warn!("Cannot fetch avatar: user has no email address");
        }
    }

    Ok(user)
}

/// The role a value without a `role_mapping` entry was granted by name before
/// only explicit entries granted roles, so an operator upgrading can see which
/// entry to add. Grants nothing itself.
fn name_once_granting_a_role(saml_role: &str) -> Option<&'static str> {
    match saml_role
        .to_lowercase()
        .as_str()
    {
        "administrator" | "admin" => Some("administrator"),
        "poweruser" | "power_user" | "power-user" => Some("poweruser"),
        _ => None,
    }
}

/// Determine user role from SAML attributes and role mapping. Only an explicit
/// `role_mapping` entry grants a role, matched against the identity provider's
/// value exactly: an unmapped value, whatever its name or case, is `User`, so
/// an identity provider cannot grant administrator by naming a role `admin`.
fn determine_role(
    attributes: &HashMap<String, String>,
    config: &SamlConfig,
) -> UserRole {
    let role_attr = &config.attribute_mapping.role;
    info!(
        "determine_role: role attribute key='{}', role_mapping keys={:?}, available SAML attributes={:?}",
        role_attr,
        config
            .role_mapping
            .keys()
            .collect::<Vec<_>>(),
        attributes
            .keys()
            .collect::<Vec<_>>()
    );

    // Get role attribute value
    if let Some(saml_role) = attributes.get(role_attr) {
        info!("determine_role: SAML role value received = '{}'", saml_role);

        // Check role mapping
        if let Some(mapped_role) = config
            .role_mapping
            .get(saml_role)
        {
            let resolved = match mapped_role
                .to_lowercase()
                .as_str()
            {
                "administrator" => UserRole::Administrator,
                "poweruser" => UserRole::PowerUser,
                "user" => UserRole::User,
                _ => {
                    warn!(
                        "determine_role: role_mapping maps '{}' to unknown role '{}'; expected administrator, poweruser or user",
                        saml_role, mapped_role
                    );
                    UserRole::User
                }
            };
            info!(
                "determine_role: matched explicit role_mapping '{}' -> '{}' -> {:?}",
                saml_role, mapped_role, resolved
            );
            return resolved;
        }

        match name_once_granting_a_role(saml_role) {
            Some(role) => warn!(
                "determine_role: no role_mapping entry for '{}', defaulting to User; earlier versions granted {} for this name, so add \"{}\": \"{}\" to role_mapping to keep it",
                saml_role, role, saml_role, role
            ),
            None => info!("determine_role: no role_mapping entry for '{}', defaulting to User", saml_role),
        }
        return UserRole::User;
    }

    info!("determine_role: role attribute '{}' not present in SAML attributes, defaulting to User", role_attr);
    // Default to User role
    UserRole::User
}

/// Fetch avatar from Microsoft Graph API and save to disk
async fn fetch_and_save_avatar(
    graph_config: &crate::auth::auth_config::GraphApiConfig,
    user_email: &str,
    user_id: &str,
    avatars_storage_path: &str,
) -> Option<String> {
    let graph_client = GraphApiClient::new(graph_config.clone());

    match graph_client
        .fetch_user_avatar(user_email)
        .await
    {
        Ok(Some(avatar_bytes)) => {
            // Save avatar to disk using user_id (not email) for filename
            match GraphApiClient::save_avatar(&avatar_bytes, user_id, avatars_storage_path).await {
                Ok(filename) => {
                    info!("Avatar saved for user {}: {}", user_email, filename);
                    Some(filename)
                }
                Err(e) => {
                    warn!("Failed to save avatar for {}: {}", user_email, e);
                    None
                }
            }
        }
        Ok(None) => {
            // User has no avatar in Azure AD
            None
        }
        Err(e) => {
            warn!("Failed to fetch avatar for {}: {}", user_email, e);
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::auth_config::SamlAttributeMapping;

    fn config() -> SamlConfig {
        SamlConfig {
            idp_entity_id: String::new(),
            idp_sso_url: String::new(),
            idp_slo_url: None,
            sp_entity_id: String::new(),
            sp_acs_url: String::new(),
            idp_cert_path: String::new(),
            attribute_mapping: SamlAttributeMapping {
                user_id: "id".to_string(),
                username: "username".to_string(),
                ..Default::default()
            },
            role_mapping: HashMap::new(),
            require_encrypted_assertions: false,
            sign_requests: false,
            sp_key_path: None,
            sp_cert_path: None,
            graph_api: None,
        }
    }

    fn attributes(id: &str) -> HashMap<String, String> {
        HashMap::from([("id".to_string(), id.to_string()), ("username".to_string(), id.to_string())])
    }

    fn attributes_with_role(
        id: &str,
        role: &str,
    ) -> HashMap<String, String> {
        let mut attributes = attributes(id);
        attributes.insert(
            config()
                .attribute_mapping
                .role,
            role.to_string(),
        );
        attributes
    }

    fn config_mapping(mapping: &[(&str, &str)]) -> SamlConfig {
        SamlConfig {
            role_mapping: mapping
                .iter()
                .map(|(from, to)| (from.to_string(), to.to_string()))
                .collect(),
            ..config()
        }
    }

    async fn storage(temp: &tempfile::TempDir) -> PasskeyStorage {
        PasskeyStorage::new(
            temp.path()
                .join("passkeys")
                .to_string_lossy()
                .to_string(),
            temp.path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap()
    }

    #[test]
    fn an_unmapped_role_value_is_user_whatever_its_name() {
        let config = config_mapping(&[]);
        for value in ["admin", "Admin", "administrator", "ADMINISTRATOR", "poweruser", "power_user", "power-user"] {
            assert_eq!(determine_role(&attributes_with_role("alice", value), &config), UserRole::User, "{value}");
        }
    }

    #[test]
    fn an_old_fallback_name_is_recognised_so_the_operator_is_warned() {
        for (value, role) in [
            ("admin", Some("administrator")),
            ("ADMINISTRATOR", Some("administrator")),
            ("PowerUser", Some("poweruser")),
            ("power_user", Some("poweruser")),
            ("power-user", Some("poweruser")),
            ("staff", None),
            ("admins", None),
        ] {
            assert_eq!(name_once_granting_a_role(value), role, "{value}");
        }
    }

    #[test]
    fn a_mapped_role_value_grants_the_mapped_role() {
        let config = config_mapping(&[("admin", "administrator"), ("ops", "poweruser"), ("staff", "user")]);
        for (value, expected) in
            [("admin", UserRole::Administrator), ("ops", UserRole::PowerUser), ("staff", UserRole::User)]
        {
            assert_eq!(determine_role(&attributes_with_role("alice", value), &config), expected, "{value}");
        }
    }

    #[test]
    fn a_role_value_matches_its_mapping_exactly() {
        let config = config_mapping(&[("admin", "administrator")]);
        for value in ["Admin", "ADMIN", " admin", "admin "] {
            assert_eq!(determine_role(&attributes_with_role("alice", value), &config), UserRole::User, "{value:?}");
        }
    }

    #[test]
    fn a_mapping_target_is_read_whatever_its_case() {
        let config = config_mapping(&[("admin", "Administrator"), ("ops", "PowerUser")]);
        assert_eq!(determine_role(&attributes_with_role("alice", "admin"), &config), UserRole::Administrator);
        assert_eq!(determine_role(&attributes_with_role("alice", "ops"), &config), UserRole::PowerUser);
    }

    #[test]
    fn a_mapping_to_an_unknown_role_or_a_missing_role_attribute_is_user() {
        let config = config_mapping(&[("admin", "root")]);
        assert_eq!(determine_role(&attributes_with_role("alice", "admin"), &config), UserRole::User);
        assert_eq!(determine_role(&attributes("alice"), &config), UserRole::User);
    }

    #[tokio::test]
    async fn each_sign_in_sets_a_later_users_role_from_role_mapping_alone() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let mapped = config_mapping(&[("admin", "administrator")]);
        provision_user_from_saml(&storage, &attributes("primary"), &mapped, "")
            .await
            .unwrap();

        let bob = provision_user_from_saml(&storage, &attributes_with_role("bob", "admin"), &mapped, "")
            .await
            .unwrap();
        assert_eq!(bob.role, UserRole::Administrator);

        let unmapped = config_mapping(&[]);
        let bob = provision_user_from_saml(&storage, &attributes_with_role("bob", "admin"), &unmapped, "")
            .await
            .unwrap();
        assert_eq!(bob.role, UserRole::User, "an unmapped `admin` no longer grants administrator");
        assert!(!bob.is_primary);
    }

    async fn two_users(storage: &PasskeyStorage) -> (UserData, UserData) {
        let config = config();
        let first = provision_user_from_saml(storage, &attributes("alice"), &config, "")
            .await
            .unwrap();
        let second = provision_user_from_saml(storage, &attributes("bob"), &config, "")
            .await
            .unwrap();
        (first, second)
    }

    fn attributes_named(
        id: &str,
        username: &str,
    ) -> HashMap<String, String> {
        HashMap::from([("id".to_string(), id.to_string()), ("username".to_string(), username.to_string())])
    }

    #[tokio::test]
    async fn a_new_account_asserting_a_username_another_user_holds_is_refused_and_nothing_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;

        let refused = provision_user_from_saml(&storage, &attributes_named("name-id-2", "bob"), &config(), "")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UsernameTaken>()
                .is_some(),
            "{refused:?}"
        );
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            2
        );
        let holder = storage
            .load_user_by_id(&bob.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(holder.saml_id.as_deref(), Some("bob"), "the holder is untouched");
    }

    #[tokio::test]
    async fn an_existing_account_whose_asserted_username_is_now_held_by_another_user_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (alice, _) = two_users(&storage).await;

        let refused = provision_user_from_saml(&storage, &attributes_named("alice", "bob"), &config(), "")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UsernameTaken>()
                .is_some(),
            "{refused:?}"
        );
        let stored = storage
            .load_user_by_id(&alice.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.username, "alice");
    }

    #[tokio::test]
    async fn an_account_signing_in_again_with_its_own_username_is_not_refused() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;

        let again = provision_user_from_saml(&storage, &attributes("bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!(again.user_id, bob.user_id);
    }

    #[tokio::test]
    async fn a_user_who_is_not_approved_is_refused_and_left_unchanged() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;
        storage
            .update_user(&bob.user_id, None, Some(UserStatus::Disabled), &crate::config::LimitsConfig::default())
            .await
            .unwrap();

        let refused = provision_user_from_saml(&storage, &attributes("bob"), &config(), "")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UserNotApproved>()
                .is_some(),
            "{refused:?}"
        );
        let stored = storage
            .load_user_by_id(&bob.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, UserStatus::Disabled);
        assert_eq!(stored.username, "bob");
    }

    #[tokio::test]
    async fn a_deleted_user_is_refused_at_the_next_sign_in_and_not_created_again() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;
        storage
            .delete_user(&bob.user_id)
            .await
            .unwrap();

        let refused = provision_user_from_saml(&storage, &attributes("bob"), &config(), "")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UserNotApproved>()
                .is_some(),
            "{refused:?}"
        );
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            2,
            "no second user for the SAML account"
        );
    }

    #[tokio::test]
    async fn a_deleted_user_signs_in_as_the_same_user_once_approved_again() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;
        storage
            .delete_user(&bob.user_id)
            .await
            .unwrap();
        storage
            .update_user(&bob.user_id, None, Some(UserStatus::Approved), &crate::config::LimitsConfig::default())
            .await
            .unwrap();

        let again = provision_user_from_saml(&storage, &attributes("bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!(again.user_id, bob.user_id);
        assert_eq!(again.username, "bob");
        assert_eq!(again.status, UserStatus::Approved);
        assert!(again.deleted_at.is_none());
    }

    #[tokio::test]
    async fn sign_in_never_demotes_the_primary_administrator() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let config = config_mapping(&[("staff", "user")]);
        let first = provision_user_from_saml(&storage, &attributes("alice"), &config, "")
            .await
            .unwrap();
        assert!(first.is_primary);
        assert_eq!(first.role, UserRole::Administrator);

        for attributes in
            [attributes_with_role("alice", "staff"), attributes_with_role("alice", "admin"), attributes("alice")]
        {
            let again = provision_user_from_saml(&storage, &attributes, &config, "")
                .await
                .unwrap();
            assert!(again.is_primary);
            assert_eq!(again.role, UserRole::Administrator);
            assert_eq!(
                storage
                    .load_user("alice")
                    .await
                    .unwrap()
                    .unwrap()
                    .role,
                UserRole::Administrator
            );
        }
    }

    #[tokio::test]
    async fn sign_in_restores_a_primary_administrator_stored_with_a_lower_role() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let config = config_mapping(&[("staff", "user")]);
        let mut primary = provision_user_from_saml(&storage, &attributes("alice"), &config, "")
            .await
            .unwrap();
        primary.role = UserRole::User;
        storage
            .save_user(&primary)
            .await
            .unwrap();

        let again = provision_user_from_saml(&storage, &attributes_with_role("alice", "staff"), &config, "")
            .await
            .unwrap();
        assert!(again.is_primary);
        assert_eq!(again.role, UserRole::Administrator);
    }

    #[tokio::test]
    async fn concurrent_jit_provisioning_creates_one_primary_administrator() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let config = config();
        let alice = attributes("alice");
        let bob = attributes("bob");

        let (alice, bob) = tokio::join!(
            provision_user_from_saml(&storage, &alice, &config, ""),
            provision_user_from_saml(&storage, &bob, &config, ""),
        );
        alice.unwrap();
        bob.unwrap();

        let users = [
            storage
                .load_user("alice")
                .await
                .unwrap()
                .unwrap(),
            storage
                .load_user("bob")
                .await
                .unwrap()
                .unwrap(),
        ];
        assert_eq!(
            users
                .iter()
                .filter(|user| user.is_primary)
                .count(),
            1
        );
        assert_eq!(
            users
                .iter()
                .filter(|user| user.role == UserRole::Administrator)
                .count(),
            1
        );
    }
}
