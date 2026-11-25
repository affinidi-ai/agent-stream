use crate::auth::storage::{DeleteOutcome, OidcIdentity, SignInMethod, UserData};
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
    /// administrator can tell whose sign-in approving it allows. It stays
    /// until the user's next sign-in gives the record a username again.
    /// Absent for every other user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oidc: Option<OidcIdentity>,
    /// The SAML account of a deleted user's kept record, shown for as long as
    /// the OpenID account is. Absent for every other user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saml_id: Option<String>,
    /// How the user signs in, so the dashboard can say what deleting them
    /// does. It names the kind of account only, never the account itself.
    pub sign_in_method: SignInMethod,
    /// When an administrator deleted the user. Set only on a kept record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Response of `DELETE /v1/users/{user_id}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeleteUserResponse {
    pub outcome: DeleteOutcome,
}

impl From<UserData> for User {
    fn from(user: UserData) -> Self {
        let kept = user.deleted_at.is_some() || user.username == user.user_id;
        let sign_in_method = user.sign_in_method();
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
            sign_in_method,
            deleted_at: user.deleted_at,
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
    fn every_user_reports_how_they_sign_in_before_and_after_delete() {
        let mut data = user_data();
        assert_eq!(User::from(data.clone()).sign_in_method, SignInMethod::Oidc);
        data.deleted_at = Some(chrono::Utc::now());
        assert_eq!(User::from(data.clone()).sign_in_method, SignInMethod::Oidc);

        data.oidc = None;
        assert_eq!(User::from(data.clone()).sign_in_method, SignInMethod::Saml);
        data.saml_id = None;
        let json = serde_json::to_value(User::from(data)).unwrap();
        assert_eq!(json["sign_in_method"], "passkey");
    }

    #[test]
    fn only_a_kept_record_reports_when_it_was_deleted() {
        let live = serde_json::to_value(User::from(user_data())).unwrap();
        assert!(
            live.get("deleted_at")
                .is_none(),
            "{live}"
        );

        let deleted_at = chrono::Utc::now();
        let mut data = user_data();
        data.deleted_at = Some(deleted_at);
        let kept = User::from(data);
        assert_eq!(kept.deleted_at, Some(deleted_at));
        assert_eq!(serde_json::to_value(&kept).unwrap()["deleted_at"], serde_json::to_value(deleted_at).unwrap());
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

    #[test]
    fn a_re_approved_record_keeps_exposing_the_account_until_its_next_sign_in() {
        let mut data = user_data();
        data.username = data.user_id.clone();
        data.deleted_at = None;

        let user = User::from(data);

        assert_eq!(
            user.oidc
                .map(|oidc| oidc.subject),
            Some("sub-1".to_string())
        );
        assert_eq!(user.saml_id.as_deref(), Some("saml-1"));
    }
}
