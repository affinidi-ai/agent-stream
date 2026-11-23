use anyhow::{Context, Result};
use tracing::{debug, info, warn};

use crate::auth::auth_config::SamlConfig;
use crate::auth::saml::graph_api::GraphApiClient;
use crate::auth::saml::service::SamlAttributes;
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
/// not approved is refused with [`UserNotApproved`]. When another user holds
/// the asserted username the SAML user ID is used instead, and only when that
/// is held too is the sign-in refused with [`UsernameTaken`].
pub async fn provision_user_from_saml(
    storage: &PasskeyStorage,
    attributes: &SamlAttributes,
    config: &SamlConfig,
    avatars_storage_path: &str,
) -> Result<UserData> {
    let mapping = &config.attribute_mapping;
    let get = |name: &str| {
        attributes
            .identity
            .get(name)
            .map(String::as_str)
    };

    let user_id_attr = get(&mapping.user_id)
        .or_else(|| get("NameID"))
        .context("User ID not found in SAML attributes")?;

    let username = get(&mapping.username)
        .or_else(|| get(&mapping.email))
        .context("Username not found in SAML attributes")?;

    let email = get(&mapping.email).map(str::to_string);
    let first_name = get(&mapping.first_name).map(str::to_string);
    let last_name = get(&mapping.last_name).map(str::to_string);
    let department = get(&mapping.department).map(str::to_string);
    let job_title = get(&mapping.job_title).map(str::to_string);

    // Determine role from SAML attributes
    let role = determine_role(attributes, config);

    let user_write_guard = storage
        .user_write_guard()
        .await;

    // Check if user already exists
    let existing_user = storage
        .load_user_by_saml_id(user_id_attr)
        .await?;

    let user = if let Some(mut user) = existing_user {
        if user.status != UserStatus::Approved {
            return Err(anyhow::Error::new(UserNotApproved));
        }
        let username = if user.username == username {
            username.to_string()
        } else {
            resolve_username(storage, username, user_id_attr, Some(&user.user_id)).await?
        };
        info!("Updating existing SAML user: {}", username);

        user.username = username;
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
        let username = resolve_username(storage, username, user_id_attr, None).await?;
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
            saml_id: Some(user_id_attr.to_string()),
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
                            .remove_uploaded_avatar(&user_id, &relative_avatar_path)
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

/// The username a SAML user gets: the asserted one, or the SAML user ID when
/// another user holds it. A user whose stored username already is the asserted
/// one never reaches this, so users that already share a username keep signing
/// in.
async fn resolve_username(
    storage: &PasskeyStorage,
    asserted: &str,
    saml_user_id: &str,
    own_user_id: Option<&str>,
) -> Result<String> {
    storage
        .free_username(&[asserted, saml_user_id], own_user_id)
        .await?
        .ok_or_else(|| anyhow::Error::new(UsernameTaken))
}

/// The role a value without a `role_mapping` entry was granted by name before
/// only explicit entries granted roles, so an operator upgrading can see which
/// entry to add. Grants nothing itself.
fn name_once_granting_a_role(saml_role: &str) -> Option<UserRole> {
    match saml_role
        .to_lowercase()
        .as_str()
    {
        "administrator" | "admin" => Some(UserRole::Administrator),
        "poweruser" | "power_user" | "power-user" => Some(UserRole::PowerUser),
        _ => None,
    }
}

/// Determine user role from SAML attributes and role mapping: the highest role
/// any value of the role attribute maps to, so the order the identity provider
/// sends the values in does not matter. Only an explicit `role_mapping` entry
/// grants a role, matched against the identity provider's value exactly: an
/// unmapped value, whatever its name or case, is `User`, so an identity
/// provider cannot grant administrator by naming a role `admin`.
fn determine_role(
    attributes: &SamlAttributes,
    config: &SamlConfig,
) -> UserRole {
    let attributes = &attributes.values;
    let role_attr = &config.attribute_mapping.role;
    info!(
        "determine_role: role attribute key='{}', role_mapping entries={}, available SAML attributes={:?}",
        role_attr,
        config.role_mapping.len(),
        attributes
            .keys()
            .collect::<Vec<_>>()
    );
    debug!(
        "determine_role: role_mapping keys={:?}",
        config
            .role_mapping
            .keys()
            .collect::<Vec<_>>()
    );

    let Some(saml_roles) = attributes.get(role_attr) else {
        info!("determine_role: role attribute '{}' not present in SAML attributes, defaulting to User", role_attr);
        return UserRole::User;
    };

    let resolved = saml_roles
        .iter()
        .map(|saml_role| role_for_value(saml_role, config))
        .max_by_key(UserRole::rank)
        .unwrap_or(UserRole::User);
    let unmapped = saml_roles
        .iter()
        .filter(|saml_role| {
            !config
                .role_mapping
                .contains_key(saml_role.as_str())
        })
        .count();
    debug!("determine_role: {} of {} SAML role values have no role_mapping entry", unmapped, saml_roles.len());

    for (saml_role, role) in legacy_role_hints(saml_roles, config, &resolved) {
        warn!(
            "determine_role: no role_mapping entry for '{}'; earlier versions granted {} for this name, so add \"{}\": \"{}\" to role_mapping to keep it",
            saml_role, role, saml_role, role
        );
    }

    info!("determine_role: {} SAML role values resolve to {:?}", saml_roles.len(), resolved);
    resolved
}

/// The unmapped role values whose name earlier versions granted a role higher
/// than `resolved`, at most one per role with the first such value in document
/// order, so the operator can be told which `role_mapping` entry to add.
fn legacy_role_hints<'a>(
    saml_roles: &'a [String],
    config: &SamlConfig,
    resolved: &UserRole,
) -> Vec<(&'a str, UserRole)> {
    let mut seen = std::collections::HashSet::new();
    saml_roles
        .iter()
        .filter(|saml_role| {
            !config
                .role_mapping
                .contains_key(saml_role.as_str())
        })
        .filter_map(|saml_role| {
            name_once_granting_a_role(saml_role)
                .filter(|role| role.rank() > resolved.rank())
                .map(|role| (saml_role.as_str(), role))
        })
        .filter(|(_, role)| seen.insert(role.rank()))
        .collect()
}

/// The role one value of the role attribute maps to, or `User` when
/// `role_mapping` has no entry for it.
fn role_for_value(
    saml_role: &str,
    config: &SamlConfig,
) -> UserRole {
    let Some(mapped_role) = config
        .role_mapping
        .get(saml_role)
    else {
        return UserRole::User;
    };

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
    debug!("determine_role: matched explicit role_mapping {:?} -> '{}' -> {:?}", saml_role, mapped_role, resolved);
    resolved
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
    use std::collections::HashMap;

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

    fn attributes(id: &str) -> SamlAttributes {
        attributes_named(id, id)
    }

    fn attributes_with_role(
        id: &str,
        role: &str,
    ) -> SamlAttributes {
        attributes_with_roles(id, &[role])
    }

    fn attributes_with_roles(
        id: &str,
        roles: &[&str],
    ) -> SamlAttributes {
        let mut attributes = attributes(id);
        attributes.values.insert(
            config()
                .attribute_mapping
                .role,
            roles
                .iter()
                .map(|role| role.to_string())
                .collect(),
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
            ("admin", Some(UserRole::Administrator)),
            ("ADMINISTRATOR", Some(UserRole::Administrator)),
            ("PowerUser", Some(UserRole::PowerUser)),
            ("power_user", Some(UserRole::PowerUser)),
            ("power-user", Some(UserRole::PowerUser)),
            ("staff", None),
            ("admins", None),
        ] {
            assert_eq!(name_once_granting_a_role(value), role, "{value}");
        }
    }

    #[test]
    fn an_old_fallback_name_is_hinted_only_when_it_would_have_granted_more() {
        let roles = |values: &[&str]| -> Vec<String> {
            values
                .iter()
                .map(|value| value.to_string())
                .collect()
        };
        let unmapped = config_mapping(&[]);
        let admin_roles = roles(&["admin"]);
        assert_eq!(
            legacy_role_hints(&admin_roles, &unmapped, &UserRole::User),
            vec![("admin", UserRole::Administrator)]
        );

        let ops_mapped = config_mapping(&[("ops", "poweruser")]);
        let admin_and_ops = roles(&["admin", "ops"]);
        assert_eq!(
            legacy_role_hints(&admin_and_ops, &ops_mapped, &UserRole::PowerUser),
            vec![("admin", UserRole::Administrator)]
        );

        let admins_mapped = config_mapping(&[("admins", "administrator")]);
        let poweruser_and_admins = roles(&["poweruser", "admins"]);
        assert_eq!(
            legacy_role_hints(&poweruser_and_admins, &admins_mapped, &UserRole::Administrator),
            Vec::<(&str, UserRole)>::new()
        );

        let admin_mapped = config_mapping(&[("admin", "administrator")]);
        assert_eq!(
            legacy_role_hints(&admin_roles, &admin_mapped, &UserRole::Administrator),
            Vec::<(&str, UserRole)>::new()
        );

        let admin_and_admins = roles(&["admin", "admins"]);
        assert_eq!(
            legacy_role_hints(&admin_and_admins, &admins_mapped, &UserRole::Administrator),
            Vec::<(&str, UserRole)>::new(),
            "a name granting the role already resolved is not hinted"
        );
        assert_eq!(
            legacy_role_hints(&roles(&["poweruser"]), &unmapped, &UserRole::PowerUser),
            Vec::<(&str, UserRole)>::new()
        );
        assert_eq!(
            legacy_role_hints(&roles(&["admin", "Admin", "ADMIN"]), &unmapped, &UserRole::User),
            vec![("admin", UserRole::Administrator)],
            "every spelling of a role is hinted once, as the first spelling sent"
        );
        assert_eq!(
            legacy_role_hints(&roles(&["Admin", "poweruser"]), &unmapped, &UserRole::User),
            vec![("Admin", UserRole::Administrator), ("poweruser", UserRole::PowerUser)]
        );
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

    #[test]
    fn the_name_id_can_be_the_role_source() {
        let mut config = config_mapping(&[("alice@example.com", "administrator")]);
        let with_name_id = |name_id: &str| {
            let mut attributes = attributes("alice");
            attributes
                .values
                .insert("NameID".to_string(), vec![name_id.to_string()]);
            attributes
        };
        assert_eq!(
            determine_role(&with_name_id("alice@example.com"), &config),
            UserRole::User,
            "the NameID grants nothing unless it is the role attribute"
        );

        config.attribute_mapping.role = "NameID".to_string();
        assert_eq!(determine_role(&with_name_id("alice@example.com"), &config), UserRole::Administrator);
        assert_eq!(determine_role(&with_name_id("bob@example.com"), &config), UserRole::User);
    }

    #[tokio::test]
    async fn a_name_id_role_source_grants_the_role_its_value_maps_to() {
        use crate::auth::saml::service::assertion_attributes;
        use crate::auth::saml::service::tests::{assertion, statement};

        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let mut config = config_mapping(&[("alice@example.com", "administrator")]);
        config.attribute_mapping.role = "NameID".to_string();
        let sign_in = |name_id: &'static str, id: &'static str| {
            let attributes =
                assertion_attributes(&assertion(Some(name_id), vec![statement(&[("id", &[id]), ("username", &[id])])]));
            let storage = &storage;
            let config = &config;
            async move {
                provision_user_from_saml(storage, &attributes, config, "")
                    .await
                    .unwrap()
                    .role
            }
        };

        sign_in("primary@example.com", "primary").await;
        assert_eq!(sign_in("alice@example.com", "alice").await, UserRole::Administrator);
        assert_eq!(sign_in("bob@example.com", "bob").await, UserRole::User);
    }

    #[test]
    fn the_highest_mapped_role_among_several_values_wins_whatever_the_order() {
        let config = config_mapping(&[("admins", "administrator"), ("ops", "poweruser"), ("staff", "user")]);
        for roles in [["staff", "admins"], ["admins", "staff"]] {
            assert_eq!(
                determine_role(&attributes_with_roles("alice", &roles), &config),
                UserRole::Administrator,
                "{roles:?}"
            );
        }
        for roles in [["staff", "ops"], ["ops", "staff"]] {
            assert_eq!(
                determine_role(&attributes_with_roles("alice", &roles), &config),
                UserRole::PowerUser,
                "{roles:?}"
            );
        }
    }

    #[test]
    fn unmapped_values_beside_a_mapped_one_do_not_lower_or_raise_it() {
        let config = config_mapping(&[("ops", "poweruser")]);
        assert_eq!(
            determine_role(&attributes_with_roles("alice", &["admin", "ops", "other"]), &config),
            UserRole::PowerUser
        );
        assert_eq!(determine_role(&attributes_with_roles("alice", &["admin", "other"]), &config), UserRole::User);
        assert_eq!(determine_role(&attributes_with_roles("alice", &[]), &config), UserRole::User);
    }

    #[tokio::test]
    async fn a_returning_user_with_several_role_values_gets_the_highest_whatever_the_order() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let config = config_mapping(&[("admins", "administrator"), ("staff", "user")]);
        provision_user_from_saml(&storage, &attributes("primary"), &config, "")
            .await
            .unwrap();

        for roles in [["staff", "admins"], ["admins", "staff"]] {
            let bob = provision_user_from_saml(&storage, &attributes_with_roles("bob", &roles), &config, "")
                .await
                .unwrap();
            assert_eq!(bob.role, UserRole::Administrator, "{roles:?}");
            assert_eq!(bob.saml_id.as_deref(), Some("bob"));
        }
    }

    #[tokio::test]
    async fn a_missing_user_id_falls_back_to_the_name_id() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let attributes = SamlAttributes {
            identity: HashMap::from([
                ("NameID".to_string(), "name-id-7".to_string()),
                ("username".to_string(), "carol".to_string()),
            ]),
            values: HashMap::new(),
        };

        let first = provision_user_from_saml(&storage, &attributes, &config(), "")
            .await
            .unwrap();
        assert_eq!(first.saml_id.as_deref(), Some("name-id-7"));

        let again = provision_user_from_saml(&storage, &attributes, &config(), "")
            .await
            .unwrap();
        assert_eq!(again.user_id, first.user_id, "the same NameID signs in as the same user");
    }

    #[tokio::test]
    async fn an_assertion_with_neither_a_user_id_nor_a_name_id_is_refused() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let attributes = SamlAttributes {
            identity: HashMap::from([("username".to_string(), "dave".to_string())]),
            values: HashMap::from([("id".to_string(), vec!["later-statement-id".to_string()])]),
        };

        let refused = provision_user_from_saml(&storage, &attributes, &config(), "").await;
        assert_eq!(
            refused
                .unwrap_err()
                .to_string(),
            "User ID not found in SAML attributes"
        );
        assert!(
            storage
                .list_users()
                .await
                .unwrap()
                .is_empty(),
            "no user is created"
        );
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
    ) -> SamlAttributes {
        SamlAttributes {
            identity: HashMap::from([
                ("id".to_string(), id.to_string()),
                ("username".to_string(), username.to_string()),
            ]),
            values: HashMap::new(),
        }
    }

    #[tokio::test]
    async fn a_new_account_asserting_a_username_another_user_holds_gets_its_saml_user_id_as_username() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;

        let second_bob = provision_user_from_saml(&storage, &attributes_named("name-id-2", "bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!(second_bob.username, "name-id-2");
        assert_ne!(second_bob.user_id, bob.user_id);
        let holder = storage
            .load_user_by_id(&bob.user_id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((holder.username.as_str(), holder.saml_id.as_deref()), ("bob", Some("bob")));
    }

    #[tokio::test]
    async fn a_sign_in_whose_asserted_username_and_saml_user_id_are_both_held_is_refused_and_nothing_is_created() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        two_users(&storage).await;
        provision_user_from_saml(&storage, &attributes_named("someone", "name-id-3"), &config(), "")
            .await
            .unwrap();

        let refused = provision_user_from_saml(&storage, &attributes_named("name-id-3", "bob"), &config(), "")
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
            3
        );
    }

    #[tokio::test]
    async fn an_existing_account_whose_asserted_username_is_now_held_by_another_user_gets_its_saml_user_id() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (alice, _) = two_users(&storage).await;

        let signed_in = provision_user_from_saml(&storage, &attributes_named("alice", "bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!(signed_in.user_id, alice.user_id);
        assert_eq!(signed_in.username, "alice");
    }

    #[tokio::test]
    async fn a_user_id_remap_signs_everyone_in_as_a_new_user_and_leaves_the_old_records_alone() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (alice, bob) = two_users(&storage).await;

        let remapped_alice =
            provision_user_from_saml(&storage, &attributes_named("object-id-a", "alice"), &config(), "")
                .await
                .unwrap();
        let remapped_bob = provision_user_from_saml(&storage, &attributes_named("object-id-b", "bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!(remapped_alice.username, "object-id-a");
        assert_eq!(remapped_bob.username, "object-id-b");
        assert_ne!(remapped_alice.user_id, alice.user_id);
        assert_ne!(remapped_bob.user_id, bob.user_id);
    }

    #[tokio::test]
    async fn two_existing_users_that_share_a_username_both_keep_signing_in() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;
        let mut duplicate = provision_user_from_saml(&storage, &attributes_named("dup", "dup"), &config(), "")
            .await
            .unwrap();
        duplicate.username = "bob".to_string();
        storage
            .save_user(&duplicate)
            .await
            .unwrap();

        let first = provision_user_from_saml(&storage, &attributes_named("bob", "bob"), &config(), "")
            .await
            .unwrap();
        let second = provision_user_from_saml(&storage, &attributes_named("dup", "bob"), &config(), "")
            .await
            .unwrap();

        assert_eq!((first.user_id.as_str(), first.username.as_str()), (bob.user_id.as_str(), "bob"));
        assert_eq!((second.user_id.as_str(), second.username.as_str()), (duplicate.user_id.as_str(), "bob"));
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
    async fn a_disabled_user_whose_asserted_username_is_held_is_refused_as_not_approved() {
        let temp = tempfile::tempdir().unwrap();
        let storage = storage(&temp).await;
        let (_, bob) = two_users(&storage).await;
        storage
            .update_user(&bob.user_id, None, Some(UserStatus::Disabled), &crate::config::LimitsConfig::default())
            .await
            .unwrap();

        let refused = provision_user_from_saml(&storage, &attributes_named("bob", "alice"), &config(), "")
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<UserNotApproved>()
                .is_some(),
            "{refused:?}"
        );
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
