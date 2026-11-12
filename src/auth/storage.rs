use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tokio::sync::{Mutex, MutexGuard};
use webauthn_rs::prelude::*;

use super::types::{UserRole, UserStatus};
use crate::server::mode::ReloadOnPromotion;
use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};

/// Storage for passkey user data, backed by CachedFilesystemStorage
///
/// Uses in-memory cache (DashMap-based) for fast reads with automatic
/// disk persistence. Ideal for user data which is read on every
/// authentication request but written infrequently.
pub struct PasskeyStorage {
    storage: Box<dyn StorageBackend<UserData>>,
    avatars_path: String,
    user_write_lock: Mutex<()>,
}

/// The avatar file every new passkey user shares; never removed with a user.
const DEFAULT_AVATAR_FILE: &str = "default.png";

/// User data stored on disk
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserData {
    pub user_id: String, // UUID for the user
    pub username: String,
    pub passkeys: Vec<Passkey>,
    pub role: UserRole,
    pub status: UserStatus,

    /// Primary user flag - first user registered, cannot be deleted or demoted
    #[serde(default)]
    pub is_primary: bool,

    // Profile information
    #[serde(default)]
    pub first_name: Option<String>,
    #[serde(default)]
    pub last_name: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub department: Option<String>,
    #[serde(default)]
    pub job_title: Option<String>,
    #[serde(default)]
    pub avatar_path: Option<String>,

    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub last_logged_in: Option<chrono::DateTime<chrono::Utc>>,

    /// SAML user ID (for SAML-authenticated users)
    #[serde(default)]
    pub saml_id: Option<String>,

    /// The OpenID provider account this user signs in with (OIDC mode)
    #[serde(default)]
    pub oidc: Option<OidcIdentity>,

    /// When an administrator deleted this user. Set only on a record that is
    /// kept, disabled, so the user's provider account stays refused. Such a
    /// record does not count toward the user limit.
    #[serde(default)]
    pub deleted_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// An account at an OpenID provider: its issuer and the subject (`sub`) it
/// gave the account. Together they identify the person; email never does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OidcIdentity {
    pub issuer: String,
    pub subject: String,
}

/// The single plain file name an `avatars/<name>` path stores, or `None` for
/// any other path.
fn avatar_file_name(avatar_path: Option<&str>) -> Option<std::ffi::OsString> {
    let relative = avatar_path?.strip_prefix("avatars/")?;
    let mut components = Path::new(relative).components();
    match (components.next(), components.next()) {
        (Some(std::path::Component::Normal(file)), None) => Some(file.to_os_string()),
        _ => None,
    }
}

impl StorableEntity for UserData {
    fn id(&self) -> &str {
        &self.user_id
    }
}

impl PasskeyStorage {
    /// Create a new passkey storage instance backed by CachedFilesystemStorage
    pub async fn new(
        storage_path: String,
        avatars_path: String,
    ) -> Result<Self> {
        // Create avatars directory if it doesn't exist
        std::fs::create_dir_all(&avatars_path)
            .with_context(|| format!("Failed to create avatars directory: {}", avatars_path))?;

        // Copy default avatar if it doesn't exist
        let default_avatar_dest = format!("{avatars_path}/{DEFAULT_AVATAR_FILE}");
        if !Path::new(&default_avatar_dest).exists() {
            let default_avatar_src = include_bytes!("../auth_manager/default_avatar.png");
            std::fs::write(&default_avatar_dest, default_avatar_src)
                .with_context(|| format!("Failed to write default avatar: {}", default_avatar_dest))?;
            tracing::info!("Copied default avatar to: {}", default_avatar_dest);
        }

        let storage = cached_storage(PathBuf::from(&storage_path), "passkey_user").await?;

        Ok(Self {
            storage,
            avatars_path,
            user_write_lock: Mutex::new(()),
        })
    }

    pub async fn user_write_guard(&self) -> MutexGuard<'_, ()> {
        self.user_write_lock
            .lock()
            .await
    }

    /// Get the avatars storage path
    pub fn avatars_path(&self) -> &str {
        &self.avatars_path
    }

    /// Load user data by username (scans in-memory cache)
    pub async fn load_user(
        &self,
        username: &str,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.username == username))
    }

    /// Load user by user_id (direct cache lookup)
    pub async fn load_user_by_id(
        &self,
        user_id: &str,
    ) -> Result<Option<UserData>> {
        self.storage
            .get(user_id)
            .await
    }

    /// Save user data to disk and cache
    pub async fn save_user(
        &self,
        user_data: &UserData,
    ) -> Result<()> {
        self.storage
            .save(user_data)
            .await
    }

    /// Prepare a user with their initial passkey for persistence after consent succeeds.
    pub(crate) async fn prepare_user_with_passkey(
        &self,
        username: &str,
        passkey: Passkey,
    ) -> Result<UserData> {
        let users = self.list_users().await?;
        let is_first_user = users.is_empty();

        if self
            .load_user(username)
            .await?
            .is_some()
        {
            anyhow::bail!("User already exists: {}", username);
        }

        if !is_first_user
            && let Err(error) = crate::config::global_limits().check_can_add(
                "users",
                self.count_toward_user_limit()
                    .await?,
            )
        {
            return Err(anyhow::Error::new(error));
        }

        let now = chrono::Utc::now();
        let user_data = UserData {
            user_id: uuid::Uuid::new_v4().to_string(),
            username: username.to_string(),
            passkeys: vec![passkey],
            role: if is_first_user {
                UserRole::Administrator
            } else {
                UserRole::User
            },
            status: if is_first_user {
                UserStatus::Approved
            } else {
                UserStatus::New
            },
            is_primary: is_first_user,
            created_at: now,
            updated_at: now,
            first_name: None,
            last_name: None,
            email: None,
            department: None,
            job_title: None,
            avatar_path: Some(format!("avatars/{DEFAULT_AVATAR_FILE}")),
            last_logged_in: None,
            saml_id: None,
            oidc: None,
            deleted_at: None,
        };
        Ok(user_data)
    }

    /// Update a user's role and status by id. Approving a kept record gives
    /// it a seat back, so the user limit is checked against the count taken
    /// under the same guard that every other creator holds.
    pub async fn update_user(
        &self,
        user_id: &str,
        role: Option<UserRole>,
        status: Option<UserStatus>,
        limits: &crate::config::LimitsConfig,
    ) -> Result<()> {
        let _user_write_guard = self.user_write_guard().await;
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", user_id))?;

        if let Some(new_status) = status {
            if new_status == UserStatus::Approved && user_data.deleted_at.is_some() {
                limits
                    .check_can_add(
                        "users",
                        self.count_toward_user_limit()
                            .await?,
                    )
                    .map_err(anyhow::Error::new)?;
                user_data.deleted_at = None;
            }
            user_data.status = new_status;
        }
        if let Some(new_role) = role {
            user_data.role = new_role;
        }
        user_data.updated_at = chrono::Utc::now();

        self.save_user(&user_data)
            .await
    }

    /// Record a sign-in on the stored record of an approved user. Returns
    /// `None` when the record is gone or no longer approved, so a delete that
    /// lands during the sign-in is not undone by this write.
    pub async fn record_login(
        &self,
        user_id: &str,
    ) -> Result<Option<UserData>> {
        let _user_write_guard = self.user_write_guard().await;
        let Some(mut user_data) = self
            .load_user_by_id(user_id)
            .await?
            .filter(|user| user.status == UserStatus::Approved)
        else {
            return Ok(None);
        };
        user_data.last_logged_in = Some(chrono::Utc::now());
        self.save_user(&user_data)
            .await?;
        Ok(Some(user_data))
    }

    /// Link an uploaded avatar to a user who is still approved. Returns
    /// whether the link was written; when it was not, the caller removes the
    /// file it uploaded.
    pub async fn set_avatar_if_approved(
        &self,
        user_id: &str,
        avatar_path: String,
    ) -> Result<bool> {
        let _user_write_guard = self.user_write_guard().await;
        let Some(mut user_data) = self
            .load_user_by_id(user_id)
            .await?
            .filter(|user| user.status == UserStatus::Approved && user.deleted_at.is_none())
        else {
            return Ok(false);
        };
        user_data.avatar_path = Some(avatar_path);
        user_data.updated_at = chrono::Utc::now();
        self.save_user(&user_data)
            .await?;
        Ok(true)
    }

    /// Whether another user already holds `username`. Call it while holding
    /// [`Self::user_write_guard`], as the creators of users do, so the answer
    /// is still true when the record is written.
    pub async fn username_held_by_other(
        &self,
        username: &str,
        own_user_id: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .storage
            .list_all()
            .await?
            .iter()
            .any(|holder| holder.username == username && Some(holder.user_id.as_str()) != own_user_id))
    }

    /// The first of `candidates` that no other user has as their username. The
    /// admin handlers address users by id, but a username that two users share
    /// still makes the dashboard ambiguous. Call it under the same guard as
    /// [`Self::username_held_by_other`].
    pub async fn free_username(
        &self,
        candidates: &[&str],
        own_user_id: Option<&str>,
    ) -> Result<Option<String>> {
        for candidate in candidates {
            if !self
                .username_held_by_other(candidate, own_user_id)
                .await?
            {
                return Ok(Some((*candidate).to_string()));
            }
        }
        Ok(None)
    }

    /// Update user profile information
    pub async fn update_profile(
        &self,
        user_id: &str,
        first_name: Option<String>,
        last_name: Option<String>,
        email: Option<String>,
        department: Option<String>,
        job_title: Option<String>,
        avatar_path: Option<String>,
    ) -> Result<()> {
        let _user_write_guard = self.user_write_guard().await;
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", user_id))?;

        if let Some(fn_val) = first_name {
            user_data.first_name = Some(fn_val);
        }
        if let Some(ln_val) = last_name {
            user_data.last_name = Some(ln_val);
        }
        if let Some(email_val) = email {
            user_data.email = Some(email_val);
        }
        if let Some(dept_val) = department {
            user_data.department = Some(dept_val);
        }
        if let Some(job_val) = job_title {
            user_data.job_title = Some(job_val);
        }
        if let Some(avatar_val) = avatar_path {
            user_data.avatar_path = Some(avatar_val);
        }
        user_data.updated_at = chrono::Utc::now();

        self.save_user(&user_data)
            .await
    }

    /// Check if user is approved to sign in
    pub async fn is_user_approved(
        &self,
        username: &str,
    ) -> Result<bool> {
        Ok(self
            .load_user(username)
            .await?
            .is_some_and(|user_data| user_data.status == UserStatus::Approved))
    }

    /// Get all passkeys for a user
    pub async fn get_passkeys(
        &self,
        username: &str,
    ) -> Result<Vec<Passkey>> {
        Ok(self
            .load_user(username)
            .await?
            .map(|data| data.passkeys)
            .unwrap_or_default())
    }

    /// List all user_ids from cache
    #[allow(dead_code)]
    pub async fn list_users(&self) -> Result<Vec<String>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .map(|u| u.user_id)
            .collect())
    }

    /// Number of stored users that count toward the appliance user limit: every
    /// user except the kept record of a deleted user.
    pub async fn count_toward_user_limit(&self) -> Result<usize> {
        Ok(self
            .storage
            .list_all()
            .await?
            .iter()
            .filter(|user| user.deleted_at.is_none())
            .count())
    }

    /// Delete a user by id. A user who signs in through an OpenID provider or
    /// SAML is not removed: the record is scrubbed of profile data and kept
    /// `Disabled` under the provider account, so the next sign-in is refused
    /// instead of creating a new approved user. Deleting a kept record again
    /// changes nothing. The uploaded avatar files are removed after the record
    /// changed, and a failure to remove one is logged, never returned.
    pub async fn delete_user(
        &self,
        user_id: &str,
    ) -> Result<()> {
        let _user_write_guard = self.user_write_guard().await;
        let mut user_data = self
            .load_user_by_id(user_id)
            .await?
            .ok_or_else(|| anyhow::anyhow!("User not found: {}", user_id))?;

        if user_data.deleted_at.is_some() {
            return Ok(());
        }

        let avatar_path = user_data.avatar_path.clone();

        if user_data.oidc.is_none() && user_data.saml_id.is_none() {
            self.storage
                .delete(&user_data.user_id)
                .await?;
            tracing::info!(user_id = %user_data.user_id, "Permanently deleted user");
        } else {
            let now = chrono::Utc::now();
            user_data.username = user_data.user_id.clone();
            user_data.status = UserStatus::Disabled;
            user_data.role = UserRole::User;
            user_data.passkeys = Vec::new();
            user_data.first_name = None;
            user_data.last_name = None;
            user_data.email = None;
            user_data.department = None;
            user_data.job_title = None;
            user_data.avatar_path = None;
            user_data.updated_at = now;
            user_data.deleted_at = Some(now);
            self.save_user(&user_data)
                .await?;
            tracing::info!(user_id = %user_data.user_id, "Disabled the record of a deleted federated user");
        }

        self.remove_avatar_files(&user_data.user_id, avatar_path.as_deref())
            .await;
        Ok(())
    }

    /// Remove the uploaded avatar files of a user: the file the stored path
    /// names and any `<user_id>.<extension>` left by an earlier upload. The
    /// directory listing is only compared with those names, so a removed path
    /// never comes from the record. The shared default is never removed, and a
    /// file that cannot be removed is logged, not returned.
    pub async fn remove_avatar_files(
        &self,
        user_id: &str,
        avatar_path: Option<&str>,
    ) {
        self.remove_avatar_matching(user_id, avatar_file_name(avatar_path), Some(user_id))
            .await;
    }

    /// Remove only the file `avatar_path` names, for an upload whose link to
    /// the user was refused. The user's other avatar files stay.
    pub async fn remove_uploaded_avatar(
        &self,
        user_id: &str,
        avatar_path: &str,
    ) {
        self.remove_avatar_matching(user_id, avatar_file_name(Some(avatar_path)), None)
            .await;
    }

    async fn remove_avatar_matching(
        &self,
        user_id: &str,
        stored: Option<std::ffi::OsString>,
        stem: Option<&str>,
    ) {
        let mut entries = match tokio::fs::read_dir(&self.avatars_path).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) => {
                tracing::warn!(user_id = %user_id, %error, "Could not list the avatars directory to remove an avatar");
                return;
            }
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => return,
                Err(error) => {
                    tracing::warn!(user_id = %user_id, %error, "Could not read the avatars directory to remove an avatar");
                    return;
                }
            };
            let name = entry.file_name();
            if name == DEFAULT_AVATAR_FILE {
                continue;
            }
            let is_wanted = stored.as_deref() == Some(name.as_os_str())
                || stem.is_some_and(|stem| Path::new(&name).file_stem() == Some(std::ffi::OsStr::new(stem)));
            if !is_wanted {
                continue;
            }
            match tokio::fs::remove_file(entry.path()).await {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    tracing::warn!(user_id = %user_id, file = ?name, %error, "Could not remove an avatar file of a deleted user");
                }
            }
        }
    }

    /// Load user by SAML ID (scans in-memory cache)
    pub async fn load_user_by_saml_id(
        &self,
        saml_id: &str,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.saml_id.as_deref() == Some(saml_id)))
    }

    /// Load the user signed in with this OpenID provider account (scans in-memory cache)
    pub async fn load_user_by_oidc_identity(
        &self,
        identity: &OidcIdentity,
    ) -> Result<Option<UserData>> {
        let users = self
            .storage
            .list_all()
            .await?;
        Ok(users
            .into_iter()
            .find(|u| u.oidc.as_ref() == Some(identity)))
    }
}

#[async_trait::async_trait]
impl ReloadOnPromotion for PasskeyStorage {
    /// Re-read the dashboard users another instance stored, so they can sign
    /// in on a promoted standby and users removed there are no longer accepted.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)
    }
}

#[cfg(test)]
mod tests {
    use super::{OidcIdentity, PasskeyStorage, UserData, UserRole, UserStatus};
    use crate::config::{LimitDefinition, LimitExceeded, LimitsConfig};
    use crate::server::mode::ReloadOnPromotion;
    use tempfile::tempdir;

    async fn storage_in(dir: &std::path::Path) -> PasskeyStorage {
        PasskeyStorage::new(
            dir.join("users")
                .to_string_lossy()
                .into_owned(),
            dir.join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap()
    }

    fn user(id: &str) -> UserData {
        let now = chrono::Utc::now();
        UserData {
            user_id: id.to_string(),
            username: id.to_string(),
            passkeys: Vec::new(),
            role: UserRole::User,
            status: UserStatus::New,
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
            deleted_at: None,
        }
    }

    fn oidc_user(id: &str) -> UserData {
        let mut data = user(id);
        data.status = UserStatus::Approved;
        data.email = Some("a@example.com".to_string());
        data.first_name = Some("Ada".to_string());
        data.department = Some("Ops".to_string());
        data.oidc = Some(OidcIdentity {
            issuer: "https://idp.example.com".to_string(),
            subject: "sub-1".to_string(),
        });
        data
    }

    #[tokio::test]
    async fn deleting_a_user_without_an_oidc_account_removes_the_record() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&user("plain"))
            .await
            .unwrap();

        storage
            .delete_user("plain")
            .await
            .unwrap();

        assert!(
            storage
                .load_user_by_id("plain")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_an_oidc_user_keeps_a_disabled_record_for_the_provider_account() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let kept = storage
            .load_user_by_oidc_identity(&OidcIdentity {
                issuer: "https://idp.example.com".to_string(),
                subject: "sub-1".to_string(),
            })
            .await
            .unwrap()
            .expect("the provider account keeps a record");
        assert_eq!(kept.user_id, "oidc-1");
        assert_eq!(kept.status, UserStatus::Disabled);
        assert_eq!(kept.username, "oidc-1", "the username is released for other users");
        assert!(kept.email.is_none() && kept.first_name.is_none() && kept.department.is_none());
        assert!(
            storage
                .load_user("a@example.com")
                .await
                .unwrap()
                .is_none()
        );
    }

    fn saml_user(id: &str) -> UserData {
        let mut data = user(id);
        data.status = UserStatus::Approved;
        data.role = UserRole::PowerUser;
        data.email = Some("s@example.com".to_string());
        data.saml_id = Some("saml-1".to_string());
        data
    }

    async fn write_avatar(
        dir: &std::path::Path,
        name: &str,
    ) -> std::path::PathBuf {
        let path = dir.join("avatars").join(name);
        tokio::fs::create_dir_all(path.parent().unwrap())
            .await
            .unwrap();
        tokio::fs::write(&path, b"image")
            .await
            .unwrap();
        path
    }

    #[tokio::test]
    async fn deleting_a_saml_user_keeps_a_disabled_record_for_the_saml_account() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&saml_user("saml-user"))
            .await
            .unwrap();

        storage
            .delete_user("saml-user")
            .await
            .unwrap();

        let kept = storage
            .load_user_by_saml_id("saml-1")
            .await
            .unwrap()
            .expect("the SAML account keeps a record");
        assert_eq!(kept.user_id, "saml-user");
        assert_eq!(kept.status, UserStatus::Disabled);
        assert!(kept.deleted_at.is_some());
        assert!(kept.email.is_none());
    }

    #[tokio::test]
    async fn a_user_is_deleted_by_id_and_a_username_is_not_an_id() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let mut data = user("id-1");
        data.username = "alice".to_string();
        storage
            .save_user(&data)
            .await
            .unwrap();

        assert!(
            storage
                .delete_user("alice")
                .await
                .is_err()
        );
        storage
            .delete_user("id-1")
            .await
            .unwrap();

        assert!(
            storage
                .load_user_by_id("id-1")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn a_kept_record_is_disabled_marked_deleted_and_back_to_the_lowest_role() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let mut data = oidc_user("oidc-1");
        data.role = UserRole::PowerUser;
        data.last_name = Some("Lovelace".to_string());
        data.job_title = Some("Engineer".to_string());
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let kept = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert!(kept.last_name.is_none() && kept.job_title.is_none() && kept.avatar_path.is_none());
        assert!(kept.passkeys.is_empty());
        assert_eq!(kept.role, UserRole::User);
        assert!(kept.deleted_at.is_some());
        assert!(!kept.is_primary);
    }

    #[tokio::test]
    async fn deleting_a_kept_record_again_changes_nothing() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();
        let first = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let second = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.deleted_at, first.deleted_at);
        assert_eq!(second.updated_at, first.updated_at);
    }

    #[tokio::test]
    async fn deleting_a_user_removes_their_uploaded_avatar_file_in_both_branches() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let plain_file = write_avatar(temp_dir.path(), "plain.png").await;
        let oidc_file = write_avatar(temp_dir.path(), "oidc-1.png").await;
        let mut plain = user("plain");
        plain.avatar_path = Some("avatars/plain.png".to_string());
        let mut federated = oidc_user("oidc-1");
        federated.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&plain)
            .await
            .unwrap();
        storage
            .save_user(&federated)
            .await
            .unwrap();

        storage
            .delete_user("plain")
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert!(!plain_file.exists());
        assert!(!oidc_file.exists());
    }

    #[tokio::test]
    async fn deleting_a_user_leaves_the_shared_default_avatar_and_files_outside_the_avatars_directory() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let default_file = write_avatar(temp_dir.path(), "default.png").await;
        let outside = temp_dir
            .path()
            .join("outside.png");
        tokio::fs::write(&outside, b"image")
            .await
            .unwrap();
        let mut first = user("first");
        first.avatar_path = Some("avatars/default.png".to_string());
        let mut second = user("second");
        second.avatar_path = Some("avatars/../outside.png".to_string());
        let mut third = user("third");
        third.avatar_path = Some("elsewhere/default.png".to_string());
        for data in [&first, &second, &third] {
            storage
                .save_user(data)
                .await
                .unwrap();
        }

        for id in ["first", "second", "third"] {
            storage
                .delete_user(id)
                .await
                .unwrap();
        }

        assert!(default_file.exists(), "the default avatar is shared");
        assert!(outside.exists(), "a path that leaves the avatars directory is never followed");
    }

    #[tokio::test]
    async fn deleting_a_user_whose_avatar_file_is_already_gone_succeeds() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let mut data = user("plain");
        data.avatar_path = Some("avatars/missing.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("plain")
            .await
            .unwrap();

        assert!(
            storage
                .load_user_by_id("plain")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_succeeds_when_the_avatars_directory_does_not_exist() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let mut data = oidc_user("oidc-1");
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();
        tokio::fs::remove_dir_all(
            temp_dir
                .path()
                .join("avatars"),
        )
        .await
        .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert!(
            storage
                .load_user_by_id("oidc-1")
                .await
                .unwrap()
                .unwrap()
                .deleted_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn an_update_waits_for_the_user_write_guard_so_it_cannot_overwrite_a_delete() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        let wait = std::time::Duration::from_millis(50);

        let guard = storage
            .user_write_guard()
            .await;
        let role_update = tokio::time::timeout(
            wait,
            storage.update_user("oidc-1", None, Some(UserStatus::Approved), &LimitsConfig::default()),
        )
        .await;
        let profile_update = tokio::time::timeout(
            wait,
            storage.update_profile("oidc-1", Some("X".to_string()), None, None, None, None, None),
        )
        .await;
        drop(guard);

        assert!(role_update.is_err(), "update_user must wait for the guard");
        assert!(profile_update.is_err(), "update_profile must wait for the guard");
        storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &LimitsConfig::default())
            .await
            .unwrap();
        storage
            .update_profile("oidc-1", Some("X".to_string()), None, None, None, None, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn approving_a_kept_record_clears_the_deleted_marker() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &LimitsConfig::default())
            .await
            .unwrap();

        let approved = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(approved.status, UserStatus::Approved);
        assert!(approved.deleted_at.is_none());
    }

    #[tokio::test]
    async fn kept_records_do_not_count_toward_the_user_limit() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        storage
            .save_user(&user("plain"))
            .await
            .unwrap();
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        assert_eq!(
            storage
                .count_toward_user_limit()
                .await
                .unwrap(),
            2
        );

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert_eq!(
            storage
                .count_toward_user_limit()
                .await
                .unwrap(),
            1
        );
        assert_eq!(
            storage
                .list_users()
                .await
                .unwrap()
                .len(),
            2,
            "the record itself is still stored"
        );
    }

    fn users_limit(limit: u64) -> LimitsConfig {
        LimitsConfig {
            limits: std::collections::HashMap::from([(
                "users".to_string(),
                LimitDefinition {
                    name: "Users".to_string(),
                    description: String::new(),
                    limit,
                },
            )]),
        }
    }

    async fn storage_with_a_kept_record_and_one_other_user(dir: &std::path::Path) -> PasskeyStorage {
        let storage = storage_in(dir).await;
        let mut other = user("plain");
        other.status = UserStatus::Approved;
        storage
            .save_user(&other)
            .await
            .unwrap();
        storage
            .save_user(&oidc_user("oidc-1"))
            .await
            .unwrap();
        storage
            .delete_user("oidc-1")
            .await
            .unwrap();
        storage
    }

    #[tokio::test]
    async fn approving_a_kept_record_at_the_user_limit_is_refused_and_changes_nothing() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(temp_dir.path()).await;

        let refused = storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &users_limit(1))
            .await
            .unwrap_err();

        assert!(
            refused
                .downcast_ref::<LimitExceeded>()
                .is_some(),
            "{refused:?}"
        );
        let stored = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, UserStatus::Disabled);
        assert!(stored.deleted_at.is_some());
    }

    #[tokio::test]
    async fn approving_a_kept_record_below_the_user_limit_is_allowed() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(temp_dir.path()).await;

        storage
            .update_user("oidc-1", None, Some(UserStatus::Approved), &users_limit(2))
            .await
            .unwrap();

        let stored = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.status, UserStatus::Approved);
        assert!(stored.deleted_at.is_none());
    }

    #[tokio::test]
    async fn changes_that_do_not_return_a_deleted_user_to_a_seat_ignore_the_user_limit() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(temp_dir.path()).await;

        storage
            .update_user("oidc-1", Some(UserRole::PowerUser), Some(UserStatus::Disabled), &users_limit(1))
            .await
            .unwrap();
        storage
            .update_user("plain", None, Some(UserStatus::Approved), &users_limit(1))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn an_update_by_id_changes_only_that_record_when_two_share_a_username() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        for id in ["first", "second"] {
            let mut data = user(id);
            data.username = "bob".to_string();
            storage
                .save_user(&data)
                .await
                .unwrap();
        }

        storage
            .update_user("second", Some(UserRole::PowerUser), Some(UserStatus::Approved), &LimitsConfig::default())
            .await
            .unwrap();

        let first = storage
            .load_user_by_id("first")
            .await
            .unwrap()
            .unwrap();
        let second = storage
            .load_user_by_id("second")
            .await
            .unwrap()
            .unwrap();
        assert_eq!((first.status, first.role), (UserStatus::New, UserRole::User));
        assert_eq!((second.status, second.role), (UserStatus::Approved, UserRole::PowerUser));
    }

    #[tokio::test]
    async fn a_username_is_held_by_another_user_only() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let mut data = user("first");
        data.username = "bob".to_string();
        storage
            .save_user(&data)
            .await
            .unwrap();

        assert!(
            storage
                .username_held_by_other("bob", None)
                .await
                .unwrap()
        );
        assert!(
            storage
                .username_held_by_other("bob", Some("second"))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .username_held_by_other("bob", Some("first"))
                .await
                .unwrap()
        );
        assert!(
            !storage
                .username_held_by_other("alice", None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn deleting_a_user_removes_avatar_files_left_by_an_earlier_extension() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let current = write_avatar(temp_dir.path(), "oidc-1.png").await;
        let earlier = write_avatar(temp_dir.path(), "oidc-1.jpg").await;
        let someone_else = write_avatar(temp_dir.path(), "oidc-10.png").await;
        let mut data = oidc_user("oidc-1");
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        assert!(!current.exists());
        assert!(!earlier.exists());
        assert!(someone_else.exists(), "another user's file is never matched");
    }

    #[tokio::test]
    async fn a_file_that_cannot_be_removed_does_not_stop_the_delete() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let stuck = temp_dir
            .path()
            .join("avatars")
            .join("oidc-1.png");
        tokio::fs::create_dir_all(&stuck)
            .await
            .unwrap();
        let mut data = oidc_user("oidc-1");
        data.avatar_path = Some("avatars/oidc-1.png".to_string());
        storage
            .save_user(&data)
            .await
            .unwrap();

        storage
            .delete_user("oidc-1")
            .await
            .unwrap();

        let kept = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(kept.status, UserStatus::Disabled);
        assert!(kept.deleted_at.is_some());
    }

    #[tokio::test]
    async fn recording_a_login_updates_an_approved_user_and_refuses_anyone_else() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(temp_dir.path()).await;

        let signed_in = storage
            .record_login("plain")
            .await
            .unwrap()
            .expect("an approved user signs in");
        assert!(
            signed_in
                .last_logged_in
                .is_some()
        );
        assert!(
            storage
                .load_user_by_id("plain")
                .await
                .unwrap()
                .unwrap()
                .last_logged_in
                .is_some()
        );

        assert!(
            storage
                .record_login("oidc-1")
                .await
                .unwrap()
                .is_none(),
            "a kept record is not signed in"
        );
        assert!(
            storage
                .record_login("nobody")
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            storage
                .load_user_by_id("oidc-1")
                .await
                .unwrap()
                .unwrap()
                .last_logged_in
                .is_none(),
            "a refused sign-in writes nothing"
        );
    }

    #[tokio::test]
    async fn removing_an_uploaded_avatar_keeps_the_users_other_avatar_files() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_in(temp_dir.path()).await;
        let current = write_avatar(temp_dir.path(), "plain.jpg").await;
        let uploaded = write_avatar(temp_dir.path(), "plain.png").await;
        let default_file = write_avatar(temp_dir.path(), "default.png").await;

        storage
            .remove_uploaded_avatar("plain", "avatars/plain.png")
            .await;
        storage
            .remove_uploaded_avatar("plain", "avatars/default.png")
            .await;

        assert!(!uploaded.exists());
        assert!(current.exists(), "the avatar the record still points at stays");
        assert!(default_file.exists());
    }

    #[tokio::test]
    async fn an_avatar_is_linked_only_to_a_user_who_is_still_approved() {
        let temp_dir = tempdir().unwrap();
        let storage = storage_with_a_kept_record_and_one_other_user(temp_dir.path()).await;

        assert!(
            storage
                .set_avatar_if_approved("plain", "avatars/plain.png".to_string())
                .await
                .unwrap()
        );
        assert!(
            !storage
                .set_avatar_if_approved("oidc-1", "avatars/oidc-1.png".to_string())
                .await
                .unwrap()
        );
        assert!(
            !storage
                .set_avatar_if_approved("nobody", "avatars/nobody.png".to_string())
                .await
                .unwrap()
        );
        let plain = storage
            .load_user_by_id("plain")
            .await
            .unwrap()
            .unwrap();
        let kept = storage
            .load_user_by_id("oidc-1")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(plain.avatar_path.as_deref(), Some("avatars/plain.png"));
        assert!(kept.avatar_path.is_none());
    }

    #[tokio::test]
    async fn reload_picks_up_users_another_instance_stored() {
        let temp_dir = tempdir().unwrap();
        let standby = storage_in(temp_dir.path()).await;
        standby
            .save_user(&user("removed"))
            .await
            .unwrap();
        let active = storage_in(temp_dir.path()).await;
        active
            .save_user(&user("added"))
            .await
            .unwrap();
        active
            .delete_user("removed")
            .await
            .unwrap();
        assert!(
            standby
                .load_user("added")
                .await
                .unwrap()
                .is_none()
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert!(
            standby
                .load_user("added")
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            standby
                .load_user("removed")
                .await
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_user_stored_before_oidc_sign_in_still_loads() {
        let mut stored = serde_json::to_value(user("u1")).unwrap();
        stored
            .as_object_mut()
            .unwrap()
            .remove("oidc");

        let loaded: UserData = serde_json::from_value(stored).unwrap();

        assert_eq!(loaded.user_id, "u1");
        assert!(loaded.oidc.is_none());
    }

    #[tokio::test]
    async fn missing_user_is_not_approved() {
        let temp_dir = tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp_dir
                .path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            temp_dir
                .path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();

        assert!(
            !storage
                .is_user_approved("missing-user")
                .await
                .unwrap()
        );
    }
}
