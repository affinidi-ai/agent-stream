//! The caller of a surface (pipe) save, as the per-caller save rules need it
//! (ownership, setting prices, choosing where a stored secret is sent).

use std::sync::Arc;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;

use crate::auth::storage::PasskeyStorage;
use crate::auth::types::UserRole;
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatContext;
use crate::identity::handlers::pipes::AppError;
use crate::pipes::PipeConfig;
use crate::rbac::{Feature, RbacConfig};
use crate::tenancy::PatTenantContext;

/// The authenticated user, the user store and RBAC configuration to read
/// their role, and an access token's permission allow-list. All are absent
/// when the appliance runs without authentication.
#[derive(Clone, Default)]
pub(crate) struct PipeCaller {
    user_id: Option<String>,
    storage: Option<Arc<PasskeyStorage>>,
    rbac: Option<Arc<RbacConfig>>,
    token_scopes: Option<Vec<String>>,
}

impl<S> FromRequestParts<S> for PipeCaller
where
    S: Send + Sync,
{
    type Rejection = std::convert::Infallible;

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        Ok(Self {
            user_id: parts
                .extensions
                .get::<AuthGuardOk>()
                .map(|AuthGuardOk(id)| id.clone()),
            storage: parts
                .extensions
                .get::<Arc<PasskeyStorage>>()
                .cloned(),
            rbac: parts
                .extensions
                .get::<Arc<RbacConfig>>()
                .cloned(),
            token_scopes: parts
                .extensions
                .get::<PatContext>()
                .and_then(|PatContext(scopes)| scopes.clone()),
        })
    }
}

impl PipeCaller {
    /// The authenticated user, or `None` when the appliance runs without
    /// authentication.
    pub(super) fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Whether this caller may change or delete `pipe`: its owner, an
    /// administrator, or an access token of the surface's own tenant
    /// (`context`), since tenant isolation is the boundary between tenant
    /// tokens. A surface without an owner is otherwise administrator-only. A
    /// request with no authenticated caller (no RBAC in force) is not
    /// restricted.
    pub(super) async fn may_manage(
        &self,
        pipe: &PipeConfig,
        context: Option<&PatTenantContext>,
    ) -> Result<bool, AppError> {
        let Some(user_id) = self.user_id.as_deref() else {
            return Ok(true);
        };
        if pipe.owner_user_id.as_deref() == Some(user_id) {
            return Ok(true);
        }
        if let (Some(context), Some(tenant_id)) = (context, pipe.tenant_id.as_deref())
            && context.tenant_id == tenant_id
        {
            return Ok(true);
        }
        let Some(storage) = &self.storage else {
            return Ok(false);
        };
        Ok(caller_role(storage, user_id).await? == Some(UserRole::Administrator))
    }

    /// Whether this caller holds `feature`: their role grants it and an
    /// access token's allow-list, when it has one, names it. A request with no
    /// authenticated caller (no RBAC in force) is not restricted.
    pub(super) async fn holds(
        &self,
        feature: &Feature,
    ) -> Result<bool, AppError> {
        let (Some(user_id), Some(storage), Some(rbac)) = (&self.user_id, &self.storage, &self.rbac) else {
            return Ok(true);
        };
        let role_allows = caller_role(storage, user_id)
            .await?
            .is_some_and(|role| rbac.has_permission(&role, feature));
        let token_allows = self
            .token_scopes
            .as_ref()
            .is_none_or(|scopes| {
                scopes
                    .iter()
                    .any(|scope| scope == feature.as_str())
            });
        Ok(role_allows && token_allows)
    }
}

/// The stored role of `user_id`, `None` for an unknown user. A store error is
/// logged and answered generically, so its text never reaches the caller.
async fn caller_role(
    storage: &PasskeyStorage,
    user_id: &str,
) -> Result<Option<UserRole>, AppError> {
    storage
        .load_user_by_id(user_id)
        .await
        .map(|user| user.map(|user| user.role))
        .map_err(|e| {
            tracing::error!("Failed to load caller {user_id}: {e}");
            AppError::InternalError("Failed to load caller".to_string())
        })
}

#[cfg(test)]
impl PipeCaller {
    /// A caller `user_id` holding `role` (and, for a token, the permission
    /// allow-list `scopes`), with the user store that holds them.
    pub(crate) async fn for_test(
        user_id: &str,
        role: UserRole,
        scopes: Option<Vec<&str>>,
    ) -> (Self, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let storage = PasskeyStorage::new(
            temp.path()
                .join("users")
                .to_string_lossy()
                .into_owned(),
            temp.path()
                .join("avatars")
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let now = chrono::Utc::now();
        storage
            .save_user(&crate::auth::storage::UserData {
                user_id: user_id.into(),
                username: user_id.into(),
                passkeys: Vec::new(),
                role,
                status: crate::auth::types::UserStatus::Approved,
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
            })
            .await
            .unwrap();
        let caller = Self {
            user_id: Some(user_id.into()),
            storage: Some(Arc::new(storage)),
            rbac: Some(Arc::new(RbacConfig::default())),
            token_scopes: scopes.map(|scopes| {
                scopes
                    .into_iter()
                    .map(str::to_string)
                    .collect()
            }),
        };
        (caller, temp)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::PipeType;

    fn owned_by(owner: Option<&str>) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::Webhook {
                endpoint: "https://example.com".into(),
            },
        );
        pipe.owner_user_id = owner.map(str::to_owned);
        pipe
    }

    #[tokio::test]
    async fn only_the_owner_or_an_administrator_may_manage_an_owned_surface() {
        let alices = owned_by(Some("alice"));
        for (user_id, role, allowed) in [
            ("alice", UserRole::User, true),
            ("bob", UserRole::User, false),
            ("bob", UserRole::PowerUser, false),
            ("bob", UserRole::Administrator, true),
        ] {
            let (caller, _users) = PipeCaller::for_test(user_id, role.clone(), None).await;
            assert_eq!(
                caller
                    .may_manage(&alices, None)
                    .await
                    .unwrap(),
                allowed,
                "{user_id} as {role:?}"
            );
        }
    }

    #[tokio::test]
    async fn only_an_administrator_may_manage_a_surface_without_an_owner() {
        let ownerless = owned_by(None);
        for (role, allowed) in [(UserRole::User, false), (UserRole::PowerUser, false), (UserRole::Administrator, true)]
        {
            let (caller, _users) = PipeCaller::for_test("bob", role.clone(), None).await;
            assert_eq!(
                caller
                    .may_manage(&ownerless, None)
                    .await
                    .unwrap(),
                allowed,
                "{role:?}"
            );
        }
    }

    #[tokio::test]
    async fn without_authentication_a_surface_without_an_owner_is_not_restricted() {
        assert!(
            PipeCaller::default()
                .may_manage(&owned_by(None), None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn without_authentication_no_caller_is_restricted() {
        assert!(
            PipeCaller::default()
                .may_manage(&owned_by(Some("alice")), None)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_unknown_caller_may_not_manage_another_users_surface() {
        let (mut caller, _users) = PipeCaller::for_test("bob", UserRole::Administrator, None).await;
        caller.user_id = Some("ghost".into());
        assert!(
            !caller
                .may_manage(&owned_by(Some("alice")), None)
                .await
                .unwrap()
        );
        caller.storage = None;
        assert!(
            !caller
                .may_manage(&owned_by(Some("alice")), None)
                .await
                .unwrap()
        );
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: id.into(),
        }
    }

    #[tokio::test]
    async fn a_token_of_the_surfaces_tenant_may_manage_it_whoever_owns_it() {
        let mut alices = owned_by(Some("alice"));
        alices.tenant_id = Some("tenant-a".into());
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;

        assert!(
            bob.may_manage(&alices, Some(&tenant("tenant-a")))
                .await
                .unwrap(),
            "a same-tenant token"
        );
        assert!(
            !bob.may_manage(&alices, Some(&tenant("tenant-b")))
                .await
                .unwrap(),
            "another tenant's token"
        );
        assert!(
            !bob.may_manage(&alices, None)
                .await
                .unwrap(),
            "a session"
        );
    }

    #[tokio::test]
    async fn a_tenant_token_may_not_manage_an_appliance_wide_surface_it_does_not_own() {
        let (bob, _users) = PipeCaller::for_test("bob", UserRole::User, None).await;
        assert!(
            !bob.may_manage(&owned_by(Some("alice")), Some(&tenant("tenant-a")))
                .await
                .unwrap()
        );
        assert!(
            !bob.may_manage(&owned_by(None), Some(&tenant("tenant-a")))
                .await
                .unwrap()
        );
    }
}
