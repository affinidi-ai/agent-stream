use std::collections::HashMap;
use tracing::{error, info, warn};

use super::filesystem::FileSystemNotificationStore;
use crate::auth::storage::{DeleteOutcome, UserData};
use crate::auth_manager::types::User;

/// Trigger user integrations for user.created event
pub async fn trigger_user_created(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.created integrations for user: {}", user.username);
    let values = user_event_values("user.created", user, None, Some(user), None);
    trigger_user_integrations(integration_store, &values, "user.created").await;
}

/// Trigger user integrations for user.approved event
pub async fn trigger_user_approved(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.approved integrations for user: {}", user.username);
    let values = user_event_values("user.approved", user, None, Some(user), None);
    trigger_user_integrations(integration_store, &values, "user.approved").await;
}

/// Trigger user integrations for user.updated event
pub async fn trigger_user_updated(
    integration_store: &FileSystemNotificationStore,
    old_user: &UserData,
    new_user: &UserData,
) {
    info!("Triggering user.updated integrations for user: {}", new_user.username);
    let values = user_event_values("user.updated", new_user, Some(old_user), Some(new_user), None);
    trigger_user_integrations(integration_store, &values, "user.updated").await;
}

/// Trigger user integrations for user.deleted event
pub async fn trigger_user_deleted(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
    outcome: DeleteOutcome,
) {
    info!("Triggering user.deleted integrations for user: {}", user.username);
    let values = user_event_values("user.deleted", user, Some(user), None, Some(outcome));
    trigger_user_integrations(integration_store, &values, "user.deleted").await;
}

/// Trigger user integrations for user.login event
pub async fn trigger_user_login(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.login integrations for user: {}", user.username);
    let values = user_event_values("user.login", user, None, Some(user), None);
    trigger_user_integrations(integration_store, &values, "user.login").await;
}

/// Trigger user integrations for user.accessed event
pub async fn trigger_user_accessed(
    integration_store: &FileSystemNotificationStore,
    user: &UserData,
) {
    info!("Triggering user.accessed integrations for user: {}", user.username);
    let values = user_event_values("user.accessed", user, None, Some(user), None);
    trigger_user_integrations(integration_store, &values, "user.accessed").await;
}

/// The values of a user event. `OLD_STATE` and `NEW_STATE` hold the user as
/// the user API returns it, without the provider account (`oidc`, `saml_id`),
/// which the API shows only to readers of users and which configuring an
/// integration does not require; passkeys never reach an integration either. A
/// state the event does not have is empty. `OUTCOME` is `removed` or `kept` on
/// user.deleted and empty on every other event.
fn user_event_values(
    event_type: &str,
    user: &UserData,
    old_state: Option<&UserData>,
    new_state: Option<&UserData>,
    outcome: Option<DeleteOutcome>,
) -> HashMap<String, String> {
    let state = |user: Option<&UserData>| {
        user.and_then(|user| {
            let mut view = User::from(user.clone());
            view.oidc = None;
            view.saml_id = None;
            serde_json::to_string(&view).ok()
        })
        .unwrap_or_default()
    };
    HashMap::from([
        ("OLD_STATE".to_string(), state(old_state)),
        ("NEW_STATE".to_string(), state(new_state)),
        ("EVENT_TYPE".to_string(), event_type.to_string()),
        ("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339()),
        (
            "OUTCOME".to_string(),
            outcome
                .map(DeleteOutcome::as_str)
                .unwrap_or_default()
                .to_string(),
        ),
        ("USER_ID".to_string(), user.user_id.clone()),
        ("USERNAME".to_string(), user.username.clone()),
        (
            "USER_EMAIL".to_string(),
            user.email
                .clone()
                .unwrap_or_default(),
        ),
        ("USER_ROLE".to_string(), user.role.to_string()),
        ("USER_STATUS".to_string(), user.status.to_string()),
    ])
}

/// Internal helper to trigger integrations with the 'user' category
async fn trigger_user_integrations(
    _integration_store: &FileSystemNotificationStore,
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    // Get integration storage to list all integrations
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => storage,
        None => {
            warn!("Integration storage not initialized for {}; skipping integration trigger", event_type);
            return;
        }
    };

    // Get all integrations
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(e) => {
            error!("Failed to list integrations for {}: {}", event_type, e);
            return;
        }
    };

    // Filter to user and general category integrations that are active
    let user_integrations: Vec<_> = integrations
        .into_iter()
        .filter(|n| {
            let matches_category = n.category.as_deref() == Some("user") || n.category.as_deref() == Some("general");
            let is_active = n.status == "active";
            matches_category && is_active
        })
        .collect();

    if user_integrations.is_empty() {
        info!("No active user integrations configured for {}", event_type);
        return;
    }

    info!("Found {} active user integrations to trigger for {}", user_integrations.len(), event_type);

    // Load user integrations configuration to get custom variable values
    // Get integration triggers storage path from global config
    let triggers_path = match crate::storage::get_integration_triggers_storage_path() {
        Some(path) => path,
        None => {
            warn!("Integration triggers storage path not initialized for {}; skipping integration trigger", event_type);
            return;
        }
    };

    let user_integrations_storage =
        match crate::integrations::UserIntegrationsStorage::new(std::path::PathBuf::from(&triggers_path).join("users"))
            .await
        {
            Ok(storage) => storage,
            Err(e) => {
                error!("Failed to create user integrations storage: {}", e);
                return;
            }
        };

    // Load configured integrations from trigger mappings
    let configured_integrations = match user_integrations_storage
        .load()
        .await
    {
        Ok(config) => config.integration_integrations,
        Err(e) => {
            error!("Failed to load user integrations config: {}", e);
            return;
        }
    };

    // Trigger each integration
    for integration in user_integrations {
        // Check if this integration is configured in the trigger mappings
        let Some(integration_config) = configured_integrations
            .iter()
            .find(|c| c.integration_id == integration.id)
        else {
            info!(
                "Skipping integration {} for event {} - not configured in user trigger mappings",
                integration.name, event_type
            );
            continue;
        };

        // Check if this event type should trigger this integration
        // If event_types is empty, the integration is connected but will trigger for all events
        if !integration_config
            .event_types
            .is_empty()
            && !integration_config
                .event_types
                .contains(&event_type.to_string())
        {
            info!(
                "Skipping integration {} for event {} - not in allowed event types: {:?}",
                integration.name, event_type, integration_config.event_types
            );
            continue;
        }

        info!(
            "Triggering user integration: {} (type: {}) for {}",
            integration.name, integration.integration_type, event_type
        );

        // Build subject and message from event
        let subject = format!("User Event: {}", event_type);
        let message = format!("User event '{}' occurred", event_type);

        // Use custom variables from the integration config
        let mut merged_variables = integration_config
            .variables
            .clone();
        merged_variables.extend(runtime_values.clone());

        // Use the integration trigger service with merged variables
        if let Err(e) = crate::integrations::integration_service::trigger_integration_with_variables(
            &integration.id,
            &subject,
            &message,
            &merged_variables,
        )
        .await
        {
            error!("Failed to trigger integration {} for {}: {}", integration.name, event_type, e);
        } else {
            info!("Successfully triggered user integration: {}", integration.name);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::OidcIdentity;
    use crate::auth::types::{UserRole, UserStatus};

    fn user() -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: "u-1".to_string(),
            username: "alice".to_string(),
            passkeys: Vec::new(),
            role: UserRole::User,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: Some("alice@example.com".to_string()),
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc: Some(OidcIdentity {
                issuer: "https://idp.example.com".to_string(),
                subject: "sub-1".to_string(),
            }),
            deleted_at: None,
        }
    }

    fn state(
        values: &HashMap<String, String>,
        name: &str,
    ) -> serde_json::Value {
        serde_json::from_str(&values[name]).unwrap()
    }

    #[test]
    fn a_user_deleted_event_says_whether_the_record_was_removed_or_kept() {
        let removed = user_event_values("user.deleted", &user(), Some(&user()), None, Some(DeleteOutcome::Removed));
        let kept = user_event_values("user.deleted", &user(), Some(&user()), None, Some(DeleteOutcome::Kept));

        assert_eq!(removed["OUTCOME"], "removed");
        assert_eq!(kept["OUTCOME"], "kept");
        assert_eq!(kept["EVENT_TYPE"], "user.deleted");
        assert_eq!(kept["USER_ID"], "u-1");
        assert_eq!(kept["USERNAME"], "alice");
        assert_eq!(kept["USER_EMAIL"], "alice@example.com");
        assert_eq!(kept["USER_ROLE"], "user");
        assert_eq!(kept["USER_STATUS"], "approved");
        assert_eq!(kept["NEW_STATE"], "");
        assert_eq!(state(&kept, "OLD_STATE")["email"], "alice@example.com");
    }

    #[test]
    fn every_other_user_event_has_an_empty_outcome() {
        let values = user_event_values("user.login", &user(), None, Some(&user()), None);

        assert_eq!(values["OUTCOME"], "");
        assert_eq!(values["OLD_STATE"], "");
        assert_eq!(state(&values, "NEW_STATE")["user_id"], "u-1");
    }

    #[test]
    fn a_user_state_leaves_out_passkeys_and_the_provider_account() {
        let values = user_event_values("user.deleted", &user(), Some(&user()), None, Some(DeleteOutcome::Kept));
        let old = state(&values, "OLD_STATE");

        assert!(old.get("passkeys").is_none(), "{old}");
        assert!(old.get("oidc").is_none(), "{old}");
        assert!(old.get("saml_id").is_none(), "{old}");
        assert_eq!(old["sign_in_method"], "oidc");
    }

    #[test]
    fn a_kept_or_approved_again_record_never_sends_its_provider_account() {
        let mut kept = user();
        kept.saml_id = Some("saml-account".to_string());
        kept.deleted_at = Some(chrono::Utc::now());
        let mut approved_again = kept.clone();
        approved_again.deleted_at = None;
        approved_again.username = approved_again.user_id.clone();

        for record in [&kept, &approved_again] {
            let values = user_event_values("user.approved", record, None, Some(record), None);
            let new = state(&values, "NEW_STATE");

            assert!(new.get("oidc").is_none(), "{new}");
            assert!(new.get("saml_id").is_none(), "{new}");
            assert_eq!(new["user_id"], "u-1");
        }
    }
}
