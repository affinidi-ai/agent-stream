use axum::{
    Extension, Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{error, info, warn};

use crate::auth::storage::PasskeyStorage;
use crate::delegation_vault::audit::{AuditConfigurationOperation, AuditConfigurationOutcome, AuditConfigurationState};
use crate::identity::state::IdentityApiState;
use crate::rbac::{Feature, RbacConfig};
use crate::storage::settings_store::{DashboardSettings, SettingsResponse};

/// Application error type for settings handlers
#[derive(Debug)]
pub enum AppError {
    BadRequest(String),
    Forbidden(String),
    InternalError(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message, details) = match &self {
            AppError::BadRequest(msg) => {
                warn!("API Bad Request: {}", msg);
                (StatusCode::BAD_REQUEST, "Bad Request", Some(msg.clone()))
            }
            AppError::Forbidden(msg) => {
                warn!("API Forbidden: {}", msg);
                (StatusCode::FORBIDDEN, "Forbidden", Some(msg.clone()))
            }
            AppError::InternalError(msg) => {
                error!("API Internal Error: {}", msg);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error", Some(msg.clone()))
            }
        };

        let body = Json(ErrorResponse {
            error: message.to_string(),
            details,
        });

        (status, body).into_response()
    }
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<String>,
}

/// Get current settings
pub async fn get_settings(State(state): State<IdentityApiState>) -> Result<Json<SettingsResponse>, AppError> {
    Ok(Json(
        state
            .settings_store
            .get()
            .into(),
    ))
}

/// Helper to check if the calling user has the required RBAC permission.
/// Returns `Ok(())` if the user is authorised, or an `AppError` otherwise.
async fn require_settings_edit(
    user_id: &str,
    storage: &PasskeyStorage,
    rbac_config: &RbacConfig,
) -> Result<(), AppError> {
    let user = storage
        .load_user_by_id(user_id)
        .await
        .map_err(|e| AppError::InternalError(format!("Failed to load user for RBAC check: {}", e)))?
        .ok_or_else(|| AppError::BadRequest("User not found".to_string()))?;

    if !rbac_config.has_permission(&user.role, &Feature::SettingsEdit) {
        warn!(
            user_id = %user_id,
            feature = "settings.edit",
            "System settings modification rejected — insufficient permissions"
        );
        return Err(AppError::Forbidden("Insufficient permissions".to_string()));
    }
    Ok(())
}

fn audit_configuration_state(settings: &DashboardSettings) -> AuditConfigurationState {
    AuditConfigurationState {
        enabled: settings.audit_enabled,
        policies: settings
            .audit_categories
            .policies,
        trust_checks: settings
            .audit_categories
            .trust_checks,
        identity: settings
            .audit_categories
            .identity,
    }
}

fn audit_configuration_changed(
    previous: &DashboardSettings,
    requested: &DashboardSettings,
) -> bool {
    audit_configuration_state(previous) != audit_configuration_state(requested)
}

fn record_audit_configuration_change(
    actor_id: &str,
    operation: AuditConfigurationOperation,
    outcome: AuditConfigurationOutcome,
    previous: &DashboardSettings,
    requested: &DashboardSettings,
) {
    if !audit_configuration_changed(previous, requested) {
        return;
    }
    let previous = audit_configuration_state(previous);
    let requested = audit_configuration_state(requested);

    if let Err(error) = crate::delegation_vault::audit::record_audit_configuration_change(
        actor_id,
        operation,
        outcome,
        previous,
        requested,
        crate::observability::policy_audit::current_span_trace_id(),
    ) {
        error!(
            target: "audit_control",
            actor_id = %actor_id,
            error = %error,
            "Failed to deliver audit configuration control event"
        );
    }
}

/// Update settings request
#[derive(Debug, Deserialize)]
pub struct UpdateSettingsRequest {
    pub badge_threshold_minutes: Option<u64>,
    pub metrics_retention_minutes: Option<u64>,
    pub task_activity_window_seconds: Option<u64>,
    pub connections_window_minutes: Option<u64>,
    pub latency_window_minutes: Option<u64>,
    pub onboarding_channel_ttl_seconds: Option<u64>,
    pub refresh_interval_seconds: Option<u64>,
    pub log_timestamp_format: Option<String>,
    pub bucket_seconds: Option<u64>,
    pub feature_flags: Option<HashMap<String, bool>>,
    pub prometheus_auth_enabled: Option<bool>,
    pub prometheus_auth_username: Option<String>,
    /// Plaintext password — hashed with bcrypt before storing.
    pub prometheus_auth_password: Option<String>,
    /// Master switch for durable audit-log recording.
    pub audit_enabled: Option<bool>,
    /// Which categories are written to the audit log when `audit_enabled`.
    pub audit_categories: Option<crate::storage::settings_store::AuditCategories>,
    /// Id that fills `${APPLIANCE_ID}`; empty leaves the variable unfilled.
    pub appliance_id: Option<String>,
}

/// Update settings
pub async fn update_settings(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
    Json(req): Json<UpdateSettingsRequest>,
) -> Result<Json<SettingsResponse>, AppError> {
    // RBAC: require settings.edit permission
    require_settings_edit(&user_id, &passkey_storage, &rbac_config).await?;

    // Get current settings
    let previous_settings = state.settings_store.get();
    let mut settings = previous_settings.clone();

    // Update provided fields
    if let Some(threshold) = req.badge_threshold_minutes {
        settings.badge_threshold_minutes = threshold;
    }
    if let Some(retention) = req.metrics_retention_minutes {
        settings.metrics_retention_minutes = retention;
    }
    if let Some(window) = req.task_activity_window_seconds {
        settings.task_activity_window_seconds = window;
    }
    if let Some(window) = req.connections_window_minutes {
        settings.connections_window_minutes = window;
    }
    if let Some(window) = req.latency_window_minutes {
        settings.latency_window_minutes = window;
    }
    if let Some(ttl) = req.onboarding_channel_ttl_seconds {
        settings.onboarding_channel_ttl_seconds = ttl;
    }
    if let Some(refresh) = req.refresh_interval_seconds {
        settings.refresh_interval_seconds = refresh;
    }
    if let Some(format) = req.log_timestamp_format {
        settings.log_timestamp_format = format;
    }
    if let Some(bucket) = req.bucket_seconds {
        settings.bucket_seconds = bucket;
    }
    if let Some(flags) = req.feature_flags {
        settings.feature_flags = flags;
    }
    if let Some(enabled) = req.prometheus_auth_enabled {
        if enabled
            && settings
                .prometheus_auth_password_hash
                .is_empty()
            && req
                .prometheus_auth_password
                .is_none()
        {
            return Err(AppError::BadRequest(
                "Password is required when enabling Prometheus authentication for the first time".to_string(),
            ));
        }
        if enabled {
            if let Some(ref username) = req.prometheus_auth_username {
                if username.is_empty() {
                    return Err(AppError::BadRequest("Prometheus auth username cannot be empty".to_string()));
                }
            } else if settings
                .prometheus_auth_username
                .is_empty()
            {
                return Err(AppError::BadRequest(
                    "Username is required when enabling Prometheus authentication for the first time".to_string(),
                ));
            }
        }
        settings.prometheus_auth_enabled = enabled;
    }
    if let Some(username) = req.prometheus_auth_username {
        settings.prometheus_auth_username = username;
    }
    if let Some(password) = req.prometheus_auth_password {
        if password.is_empty() {
            return Err(AppError::BadRequest("Prometheus auth password cannot be empty".to_string()));
        }
        settings.prometheus_auth_password_hash = bcrypt::hash(&password, bcrypt::DEFAULT_COST)
            .map_err(|e| AppError::InternalError(format!("Failed to hash password: {e}")))?;
    }
    if let Some(enabled) = req.audit_enabled {
        settings.audit_enabled = enabled;
    }
    if let Some(categories) = req.audit_categories {
        settings.audit_categories = categories;
    }
    if let Some(appliance_id) = req.appliance_id {
        settings.appliance_id = appliance_id
            .trim()
            .to_string();
    }

    crate::storage::SettingsStore::validate(&settings).map_err(|e| AppError::BadRequest(e.to_string()))?;

    if let Err(save_error) = state
        .settings_store
        .persist(settings.clone())
        .await
    {
        record_audit_configuration_change(
            &user_id,
            AuditConfigurationOperation::Update,
            AuditConfigurationOutcome::PersistenceFailed,
            &previous_settings,
            &settings,
        );
        return Err(AppError::InternalError(format!("Failed to save settings: {save_error}")));
    }

    record_audit_configuration_change(
        &user_id,
        AuditConfigurationOperation::Update,
        AuditConfigurationOutcome::Succeeded,
        &previous_settings,
        &settings,
    );

    info!(
        "Settings updated: badge_threshold={} minutes, metrics_retention={} minutes, task_activity_window={} seconds, connections_window={} minutes, latency_window={} minutes, temp_channel_ttl={} seconds",
        settings.badge_threshold_minutes,
        settings.metrics_retention_minutes,
        settings.task_activity_window_seconds,
        settings.connections_window_minutes,
        settings.latency_window_minutes,
        settings.onboarding_channel_ttl_seconds
    );

    // Broadcast dashboard refresh to update UI with new window settings
    state
        .ws_state
        .broadcast(crate::server::WsUpdate::RefreshDashboard);

    Ok(Json(settings.into()))
}

/// Reset settings to defaults
pub async fn reset_settings(
    Extension(user_id): Extension<String>,
    Extension(passkey_storage): Extension<Arc<PasskeyStorage>>,
    Extension(rbac_config): Extension<Arc<RbacConfig>>,
    State(state): State<IdentityApiState>,
) -> Result<Json<SettingsResponse>, AppError> {
    // RBAC: require settings.edit permission
    require_settings_edit(&user_id, &passkey_storage, &rbac_config).await?;

    // Reset to default settings
    let previous_settings = state.settings_store.get();
    let default_settings = DashboardSettings::default();

    if let Err(save_error) = state
        .settings_store
        .persist(default_settings.clone())
        .await
    {
        record_audit_configuration_change(
            &user_id,
            AuditConfigurationOperation::Reset,
            AuditConfigurationOutcome::PersistenceFailed,
            &previous_settings,
            &default_settings,
        );
        return Err(AppError::InternalError(format!("Failed to save settings: {save_error}")));
    }

    record_audit_configuration_change(
        &user_id,
        AuditConfigurationOperation::Reset,
        AuditConfigurationOutcome::Succeeded,
        &previous_settings,
        &default_settings,
    );

    info!("Settings reset to defaults");

    Ok(Json(default_settings.into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::UserData;
    use crate::auth::types::{UserRole, UserStatus};
    use crate::storage::settings_store::AuditCategories;

    fn settings_user(role: UserRole) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: "settings-actor".to_string(),
            username: "settings-actor".to_string(),
            passkeys: Vec::new(),
            role,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: None,
            oidc: None,
        }
    }

    #[tokio::test]
    async fn settings_edit_allows_administrator_and_denies_lower_default_roles() {
        let temp_dir = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp_dir
                .path()
                .join("users")
                .to_string_lossy()
                .to_string(),
            temp_dir
                .path()
                .join("avatars")
                .to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap();
        let rbac = RbacConfig::default();

        for role in [UserRole::User, UserRole::PowerUser] {
            let user = settings_user(role);
            storage
                .save_user(&user)
                .await
                .unwrap();
            assert!(matches!(require_settings_edit(&user.user_id, &storage, &rbac).await, Err(AppError::Forbidden(_))));
        }

        let administrator = settings_user(UserRole::Administrator);
        storage
            .save_user(&administrator)
            .await
            .unwrap();
        assert!(
            require_settings_edit(&administrator.user_id, &storage, &rbac)
                .await
                .is_ok()
        );
    }

    #[test]
    fn category_removal_is_an_audit_configuration_change() {
        let previous = DashboardSettings {
            audit_enabled: true,
            audit_categories: AuditCategories {
                policies: true,
                trust_checks: true,
                identity: false,
            },
            ..DashboardSettings::default()
        };
        let requested = DashboardSettings {
            audit_categories: AuditCategories {
                policies: true,
                trust_checks: false,
                identity: false,
            },
            ..previous.clone()
        };

        assert!(audit_configuration_changed(&previous, &requested));
    }

    #[test]
    fn unrelated_settings_update_is_not_an_audit_configuration_change() {
        let previous = DashboardSettings::default();
        let requested = DashboardSettings {
            refresh_interval_seconds: previous.refresh_interval_seconds + 1,
            ..previous.clone()
        };

        assert!(!audit_configuration_changed(&previous, &requested));
    }

    #[test]
    fn reset_from_enabled_audit_is_an_audit_configuration_change() {
        let previous = DashboardSettings {
            audit_enabled: true,
            audit_categories: AuditCategories {
                policies: true,
                ..AuditCategories::default()
            },
            ..DashboardSettings::default()
        };

        assert!(audit_configuration_changed(&previous, &DashboardSettings::default()));
    }
}
