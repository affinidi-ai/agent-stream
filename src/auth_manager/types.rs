use crate::auth::storage::{OidcIdentity, UserData};
use crate::auth::types::{UserRole, UserStatus};
use serde::{Deserialize, Serialize};

/// Represents a user in the auth manager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub user_id: String,
    pub role: UserRole,
    pub status: UserStatus,
    #[serde(default)]
    pub is_primary: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub department: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_logged_in: Option<chrono::DateTime<chrono::Utc>>,
    /// The OpenID provider account of a deleted user's kept record, so an
    /// administrator can tell whose sign-in approving it allows. Absent for
    /// every other user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcIdentity>,
    /// The SAML account of a deleted user's kept record. Absent for every
    /// other user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_id: Option<String>,
}

impl From<UserData> for User {
    fn from(user: UserData) -> Self {
        let kept = user.deleted_at.is_some();
        Self {
            username: user.username,
            user_id: user.user_id,
            role: user.role,
            status: user.status,
            is_primary: user.is_primary,
            created_at: user.created_at,
            updated_at: user.updated_at,
            first_name: user.first_name,
            last_name: user.last_name,
            email: user.email,
            department: user.department,
            job_title: user.job_title,
            avatar_path: user.avatar_path,
            last_logged_in: user.last_logged_in,
            oidc: user.oidc.filter(|_| kept),
            saml_id: user.saml_id.filter(|_| kept),
        }
    }
}

/// Request to update a user
#[derive(Debug, Deserialize)]
pub struct UpdateUserRequest {
    pub role: Option<UserRole>,
    pub status: Option<UserStatus>,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub department: Option<String>,
    pub job_title: Option<String>,
}

/// Request to update user profile
#[derive(Debug, Deserialize)]
pub struct UpdateProfileRequest {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub email: Option<String>,
    pub department: Option<String>,
    pub job_title: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user_data() -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: "u-1".to_string(),
            username: "alice".to_string(),
            passkeys: Vec::new(),
            role: UserRole::User,
            status: UserStatus::Approved,
            is_primary: false,
            first_name: Some("Alice".to_string()),
            last_name: None,
            email: Some("alice@example.com".to_string()),
            department: None,
            job_title: None,
            avatar_path: None,
            created_at: now,
            updated_at: now,
            last_logged_in: None,
            saml_id: Some("saml-1".to_string()),
            oidc: Some(OidcIdentity {
                issuer: "https://idp.example.com".to_string(),
                subject: "sub-1".to_string(),
            }),
            deleted_at: None,
        }
    }

    #[test]
    fn a_user_who_was_not_deleted_does_not_expose_their_provider_accounts() {
        let user = User::from(user_data());

        assert_eq!(user.username, "alice");
        assert_eq!(user.email.as_deref(), Some("alice@example.com"));
        assert!(user.oidc.is_none());
        assert!(user.saml_id.is_none());
        let json = serde_json::to_value(&user).unwrap();
        assert!(json.get("oidc").is_none() && json.get("saml_id").is_none(), "{json}");
    }

    #[test]
    fn a_deleted_users_kept_record_exposes_the_provider_account_it_is_bound_to() {
        let mut data = user_data();
        data.deleted_at = Some(chrono::Utc::now());

        let user = User::from(data);

        assert_eq!(
            user.oidc,
            Some(OidcIdentity {
                issuer: "https://idp.example.com".to_string(),
                subject: "sub-1".to_string()
            })
        );
        assert_eq!(user.saml_id.as_deref(), Some("saml-1"));
        let json = serde_json::to_value(&user).unwrap();
        assert_eq!(json["oidc"]["subject"], "sub-1");
        assert_eq!(json["saml_id"], "saml-1");
    }
}
