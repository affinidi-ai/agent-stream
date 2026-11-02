//! Admin CRUD for management access tokens. Routes are RBAC-gated; the create
//! endpoint returns the raw secret exactly once and it is never retrievable
//! again.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::info;

use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::AuthGuardOk;
use crate::auth_manager::pat::PatDelegationContext;
use crate::auth_manager::resource_scope::{self, RequiredHeader};
use crate::rbac::RbacConfig;

use super::store::{FsAccessTokenStore, hash_secret};
use super::{AccessToken, AccessTokenMeta, MAX_DELEGATION_DEPTH, generate_token};

const MAX_EXPIRY_DAYS: u32 = 3650;

/// Trim a pattern and treat empty/whitespace as "no pattern".
fn normalize_pattern(pattern: Option<String>) -> Option<String> {
    pattern
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn validate_delegated_scopes(
    parent_scopes: Option<&[String]>,
    requested_scopes: &[String],
) -> Result<(), &'static str> {
    if let Some(parent_scopes) = parent_scopes
        && (requested_scopes.is_empty()
            || requested_scopes
                .iter()
                .any(|scope| !parent_scopes.contains(scope)))
    {
        return Err("a scoped access token may create only a non-empty subset of its own scopes");
    }
    Ok(())
}

fn validate_delegation_authority(parent: Option<&PatDelegationContext>) -> Result<(), &'static str> {
    if parent.is_some_and(|parent| parent.resource_scoped) {
        return Err("a resource-scoped access token cannot delegate or modify access tokens");
    }
    Ok(())
}

fn validate_scope_and_tenant_selector(
    pattern: Option<&str>,
    headers: &[RequiredHeader],
    tenancy: Option<&crate::tenancy::TenancyConfig>,
) -> Result<(), (StatusCode, String)> {
    let compiled =
        resource_scope::compile_canonical(pattern, headers).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    resource_scope::assert_min_strictness(headers).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    if let Some(selector) = compiled.tenant_selector()
        && !crate::tenancy::header_derived_tenant_permitted(
            selector,
            tenancy.and_then(|config| {
                config
                    .trusted_tenant_header
                    .as_ref()
            }),
        )
    {
        return Err((
            StatusCode::BAD_REQUEST,
            format!(
                "tenant selector for header '{}' admits more than one value; use an exact tenant value or configure tenancy.trusted_tenant_header for an authenticated edge that strips this header",
                selector.header_name
            ),
        ));
    }
    Ok(())
}

fn resolve_expiry(
    now: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
) -> Result<Option<DateTime<Utc>>, String> {
    match expires_at {
        Some(expiry) if expiry <= now => Err("expires_at must be in the future".into()),
        Some(expiry) if expiry > now + Duration::days(i64::from(MAX_EXPIRY_DAYS)) => {
            Err(format!("expires_at must be within {MAX_EXPIRY_DAYS} days"))
        }
        Some(expiry) => Ok(Some(expiry)),
        None => Ok(None),
    }
}

fn delegated_lineage(parent: Option<&PatDelegationContext>) -> Result<(Option<String>, u32), &'static str> {
    let Some(parent) = parent else {
        return Ok((None, 0));
    };
    validate_delegation_authority(Some(parent))?;
    let depth = parent
        .delegation_depth
        .checked_add(1)
        .ok_or("access-token delegation depth is invalid")?;
    if depth > MAX_DELEGATION_DEPTH {
        return Err("access-token delegation depth exceeds the configured maximum");
    }
    Ok((Some(parent.token_id.clone()), depth))
}

fn validate_target_authority(
    store: &FsAccessTokenStore,
    caller: Option<&PatDelegationContext>,
    target_id: &str,
) -> Result<(), (StatusCode, String)> {
    let Some(caller) = caller else {
        return Ok(());
    };
    validate_delegation_authority(Some(caller)).map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    store
        .controls(&caller.token_id, target_id)
        .then_some(())
        .ok_or((StatusCode::FORBIDDEN, "an access token may manage only itself or its descendants".into()))
}

fn role_rank(role: &UserRole) -> u8 {
    match role {
        UserRole::User => 0,
        UserRole::PowerUser => 1,
        UserRole::Administrator => 2,
    }
}

fn validate_scope_ceiling(
    rbac: &RbacConfig,
    issuer: &UserData,
    subject: &UserData,
    scopes: &[String],
) -> Result<(), &'static str> {
    if scopes.is_empty() {
        return (role_rank(&subject.role) <= role_rank(&issuer.role))
            .then_some(())
            .ok_or("an unscoped access token cannot exceed the issuer's role");
    }
    scopes
        .iter()
        .all(|scope| rbac.has_named_permission(&issuer.role, scope) && rbac.has_named_permission(&subject.role, scope))
        .then_some(())
        .ok_or("access-token scopes must be permitted for both issuer and subject")
}

async fn load_approved_user(
    storage: &PasskeyStorage,
    user_id: &str,
) -> Result<UserData, (StatusCode, String)> {
    match storage
        .load_user_by_id(user_id)
        .await
    {
        Ok(Some(user)) if user.status == UserStatus::Approved => Ok(user),
        Ok(Some(_)) => Err((StatusCode::FORBIDDEN, "access-token subject is not approved".into())),
        Ok(None) => Err((StatusCode::BAD_REQUEST, "access-token subject does not exist".into())),
        Err(error) => {
            Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to resolve access-token subject: {error}")))
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateAccessTokenRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// RBAC permission names this token may exercise (must be a subset of the
    /// caller's role at request time). Empty = inherit the caller's full role.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Optional anchored regex confining the IDs this token may manage. May embed
    /// `${header-name}` placeholders resolved from `required_headers`.
    #[serde(default)]
    pub resource_pattern: Option<String>,
    /// Headers this token must present (and their validation regexes), referenced
    /// by `resource_pattern` placeholders and enforced on every call.
    #[serde(default)]
    pub required_headers: Vec<RequiredHeader>,
    /// Optional exact expiration timestamp; omit for a non-expiring token.
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
    /// Bind the token to a specified existing user (a dedicated service account)
    /// instead of the caller. Admin-only in effect: this route is gated on
    /// `access_tokens.edit` (administrator), so only an admin can set it. Omit to
    /// bind the token to the caller. The token's effective permissions are the
    /// intersection of the subject's role and `scopes`, and an unknown or disabled
    /// subject yields a token that fails closed (403) at use — so provision the
    /// service account first.
    #[serde(default)]
    pub subject_user_id: Option<String>,
}

#[derive(Serialize)]
pub struct CreateAccessTokenResponse {
    /// The raw token — shown only here, never retrievable again.
    pub token: String,
    #[serde(flatten)]
    pub meta: AccessTokenMeta,
}

pub async fn list_access_tokens(
    State(store): State<Arc<FsAccessTokenStore>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Json<serde_json::Value> {
    let now = Utc::now();
    let mut items: Vec<AccessTokenMeta> = store
        .list()
        .iter()
        .filter(|token| {
            delegation
                .as_ref()
                .is_none_or(|Extension(context)| store.controls(&context.token_id, &token.id))
        })
        .map(|t| AccessTokenMeta::from_token(t, now))
        .collect();
    items.sort_by(|a, b| {
        b.created_at
            .cmp(&a.created_at)
    });
    Json(json!({ "access_tokens": items }))
}

pub async fn create_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Extension(user_storage): Extension<Arc<PasskeyStorage>>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenancy: Option<Extension<Arc<crate::tenancy::TenancyConfig>>>,
    Json(req): Json<CreateAccessTokenRequest>,
) -> Result<(StatusCode, Json<CreateAccessTokenResponse>), (StatusCode, String)> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".to_string()));
    }
    // Reject unknown permission names so a typo can't silently create a token
    // that never works.
    for scope in &req.scopes {
        if !rbac
            .permissions
            .contains_key(scope.as_str())
        {
            return Err((StatusCode::BAD_REQUEST, format!("unknown scope: {scope}")));
        }
    }
    // Reject a malformed resource pattern / required-header spec up front so a
    // token can never be stored with a scope that would fail closed at runtime.
    validate_scope_and_tenant_selector(
        req.resource_pattern
            .as_deref(),
        &req.required_headers,
        tenancy
            .as_ref()
            .map(|Extension(config)| config.as_ref()),
    )?;
    let caller_id = caller
        .map(|Extension(ok)| ok.0)
        .unwrap_or_default();
    if caller_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "no authenticated caller".to_string()));
    }

    let parent = delegation
        .as_ref()
        .map(|Extension(context)| context);
    validate_delegation_authority(parent).map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    validate_delegated_scopes(parent.and_then(|context| context.scopes.as_deref()), &req.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    let (parent_token_id, delegation_depth) =
        delegated_lineage(parent).map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;

    // Bind the token to an explicit subject when an admin provisions it for a
    // dedicated service account; otherwise bind it to the caller. `created_by`
    // always records the real actor, so the audit trail names who minted it.
    let requested_subject = req
        .subject_user_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if parent.is_some()
        && requested_subject
            .as_deref()
            .is_some_and(|subject| subject != caller_id)
    {
        return Err((StatusCode::FORBIDDEN, "a delegated access token must inherit its parent's subject".into()));
    }
    let subject_id = if parent.is_some() {
        caller_id.clone()
    } else {
        requested_subject.unwrap_or_else(|| caller_id.clone())
    };
    let issuer = load_approved_user(&user_storage, &caller_id).await?;
    let subject = if subject_id == caller_id {
        issuer.clone()
    } else {
        load_approved_user(&user_storage, &subject_id).await?
    };
    validate_scope_ceiling(&rbac, &issuer, &subject, &req.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;

    let (id, secret) = generate_token();
    let now = Utc::now();
    let expires_at = resolve_expiry(now, req.expires_at).map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let token = AccessToken {
        id,
        name: name.to_string(),
        description: req.description,
        token_hash: hash_secret(&secret),
        user_id: subject_id,
        scopes: req.scopes,
        resource_pattern: normalize_pattern(req.resource_pattern),
        required_headers: req.required_headers,
        created_by: caller_id,
        parent_token_id,
        delegation_depth,
        rotation_generation: 0,
        rotated_at: None,
        rotated_by: None,
        created_at: now,
        last_used_at: None,
        expires_at,
        revoked_at: None,
    };
    store
        .create(token.clone())
        .await
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::InvalidInput | std::io::ErrorKind::PermissionDenied => {
                (StatusCode::FORBIDDEN, error.to_string())
            }
            _ => (StatusCode::INTERNAL_SERVER_ERROR, format!("failed to store token: {error}")),
        })?;
    info!(token_id = %token.id, subject = %token.user_id, actor = %token.created_by, "Created management access token");

    let meta = AccessTokenMeta::from_token(&token, now);
    Ok((StatusCode::CREATED, Json(CreateAccessTokenResponse { token: secret, meta })))
}

pub async fn get_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Path(id): Path<String>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Result<Json<AccessTokenMeta>, (StatusCode, String)> {
    if delegation
        .as_ref()
        .is_some_and(|Extension(context)| !store.controls(&context.token_id, &id))
    {
        return Err((StatusCode::NOT_FOUND, "access token not found".into()));
    }
    match store.get(&id) {
        Some(t) => Ok(Json(AccessTokenMeta::from_token(&t, Utc::now()))),
        None => Err((StatusCode::NOT_FOUND, "access token not found".to_string())),
    }
}

#[derive(Deserialize)]
pub struct UpdateAccessTokenRequest {
    pub name: String,
    #[serde(default)]
    pub description: String,
    /// Replacement RBAC permission allow-list. Empty = inherit the bound user's
    /// full role.
    #[serde(default)]
    pub scopes: Vec<String>,
    /// Replacement resource pattern (empty/absent clears it).
    #[serde(default)]
    pub resource_pattern: Option<String>,
    /// Replacement required-header set (empty clears it).
    #[serde(default)]
    pub required_headers: Vec<RequiredHeader>,
}

/// Update a token's display name, scope allow-list, and resource scope. The
/// secret itself is immutable (never re-issued); expiry and the bound user are
/// fixed at creation.
pub async fn update_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Extension(rbac): Extension<Arc<RbacConfig>>,
    Extension(user_storage): Extension<Arc<PasskeyStorage>>,
    Path(id): Path<String>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
    tenancy: Option<Extension<Arc<crate::tenancy::TenancyConfig>>>,
    Json(req): Json<UpdateAccessTokenRequest>,
) -> Result<Json<AccessTokenMeta>, (StatusCode, String)> {
    let caller_id = caller
        .map(|Extension(ok)| ok.0)
        .unwrap_or_default();
    let name = req.name.trim();
    if name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "name is required".to_string()));
    }
    for scope in &req.scopes {
        if !rbac
            .permissions
            .contains_key(scope.as_str())
        {
            return Err((StatusCode::BAD_REQUEST, format!("unknown scope: {scope}")));
        }
    }
    let parent = delegation
        .as_ref()
        .map(|Extension(context)| context);
    validate_target_authority(&store, parent, &id)?;
    validate_delegated_scopes(parent.and_then(|context| context.scopes.as_deref()), &req.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    validate_scope_and_tenant_selector(
        req.resource_pattern
            .as_deref(),
        &req.required_headers,
        tenancy
            .as_ref()
            .map(|Extension(config)| config.as_ref()),
    )?;
    let existing = store
        .get(&id)
        .ok_or((StatusCode::NOT_FOUND, "access token not found".to_string()))?;
    if existing.revoked_at.is_some() {
        return Err((StatusCode::CONFLICT, "cannot edit a revoked token".to_string()));
    }
    let issuer = load_approved_user(&user_storage, &caller_id).await?;
    let subject = if existing.user_id == caller_id {
        issuer.clone()
    } else {
        load_approved_user(&user_storage, &existing.user_id).await?
    };
    validate_scope_ceiling(&rbac, &issuer, &subject, &req.scopes)
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    match store
        .update(
            &id,
            name.to_string(),
            req.description,
            req.scopes,
            normalize_pattern(req.resource_pattern),
            req.required_headers,
        )
        .await
    {
        Ok(Some(token)) => {
            info!(actor = %caller_id, token_id = %id, "Updated management access token");
            Ok(Json(AccessTokenMeta::from_token(&token, Utc::now())))
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "access token not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to update: {e}"))),
    }
}

pub async fn revoke_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Path(id): Path<String>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Result<StatusCode, (StatusCode, String)> {
    // Require an attributable caller and audit the revocation — a destructive,
    // non-repudiable action must never run unattributed, even if the route-level
    // RBAC layer is ever bypassed or misconfigured. Fails closed (401).
    let caller_id = caller
        .map(|Extension(ok)| ok.0)
        .unwrap_or_default();
    if caller_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "no authenticated caller".to_string()));
    }
    validate_target_authority(
        &store,
        delegation
            .as_ref()
            .map(|Extension(context)| context),
        &id,
    )?;
    match store.revoke(&id).await {
        Ok(Some(_)) => {
            info!(actor = %caller_id, token_id = %id, "Revoked management access token");
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(None) => Err((StatusCode::NOT_FOUND, "access token not found".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to revoke: {e}"))),
    }
}

/// Rotate a token's secret in place while preserving its id, subject, scopes,
/// expiry, and delegation lineage. The new secret is returned exactly once.
///
/// POST /api/v1/access-tokens/{id}/rotate
pub async fn rotate_access_token(
    State(store): State<Arc<FsAccessTokenStore>>,
    Path(id): Path<String>,
    caller: Option<Extension<AuthGuardOk>>,
    delegation: Option<Extension<PatDelegationContext>>,
) -> Result<(StatusCode, Json<CreateAccessTokenResponse>), (StatusCode, String)> {
    // Require an attributable caller and audit the rotation, mirroring create.
    // Fails closed (401) if the auth marker is absent.
    let caller_id = caller
        .map(|Extension(ok)| ok.0)
        .unwrap_or_default();
    if caller_id.is_empty() {
        return Err((StatusCode::UNAUTHORIZED, "no authenticated caller".to_string()));
    }
    validate_target_authority(
        &store,
        delegation
            .as_ref()
            .map(|Extension(context)| context),
        &id,
    )?;
    let expected_generation = store
        .get(&id)
        .map(|token| token.rotation_generation)
        .ok_or((StatusCode::NOT_FOUND, "access token not found".to_string()))?;
    match store
        .rotate(&id, &caller_id, expected_generation)
        .await
    {
        Ok(Some((token, secret))) => {
            info!(
                actor = %caller_id,
                token_id = %id,
                rotation_generation = token.rotation_generation,
                "Rotated management access token"
            );
            let meta = AccessTokenMeta::from_token(&token, Utc::now());
            Ok((StatusCode::OK, Json(CreateAccessTokenResponse { token: secret, meta })))
        }
        Ok(None) => Err((StatusCode::CONFLICT, "access token is inactive or changed during rotation".to_string())),
        Err(e) => Err((StatusCode::INTERNAL_SERVER_ERROR, format!("failed to rotate: {e}"))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_tokens::TOKEN_PREFIX;
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::PatAuthenticator;
    use crate::rbac::RbacConfig;

    async fn store() -> Arc<FsAccessTokenStore> {
        let dir = std::env::temp_dir().join(format!("agent-stream-pat-handlers-{}", uuid::Uuid::new_v4()));
        Arc::new(
            FsAccessTokenStore::new(dir)
                .await
                .unwrap(),
        )
    }

    fn admin() -> Option<Extension<AuthGuardOk>> {
        Some(Extension(AuthGuardOk("admin-user".to_string())))
    }

    fn user(
        user_id: &str,
        role: UserRole,
        status: UserStatus,
    ) -> UserData {
        let now = Utc::now();
        UserData {
            user_id: user_id.into(),
            username: user_id.into(),
            passkeys: vec![],
            role,
            status,
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
        }
    }

    async fn users(entries: Vec<UserData>) -> Extension<Arc<PasskeyStorage>> {
        let root = std::env::temp_dir().join(format!("agent-stream-pat-users-{}", uuid::Uuid::new_v4()));
        let storage = Arc::new(
            PasskeyStorage::new(
                root.join("passkeys")
                    .to_string_lossy()
                    .into_owned(),
                root.join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        for entry in entries {
            storage
                .save_user(&entry)
                .await
                .unwrap();
        }
        Extension(storage)
    }

    async fn admin_users() -> Extension<Arc<PasskeyStorage>> {
        users(vec![user("admin-user", UserRole::Administrator, UserStatus::Approved)]).await
    }

    /// Seed one live token; returns its (id, raw secret).
    async fn seed(store: &FsAccessTokenStore) -> (String, String) {
        let (id, secret) = generate_token();
        let token = AccessToken {
            id: id.clone(),
            name: "svc".into(),
            description: String::new(),
            token_hash: hash_secret(&secret),
            user_id: "svc-user".into(),
            scopes: vec!["metrics.view".into()],
            resource_pattern: None,
            required_headers: vec![],
            created_by: "admin-user".into(),
            parent_token_id: None,
            delegation_depth: 0,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        };
        store
            .create(token)
            .await
            .unwrap();
        (id, secret)
    }

    fn create_req(required_headers: Vec<RequiredHeader>) -> CreateAccessTokenRequest {
        CreateAccessTokenRequest {
            name: "svc".into(),
            description: String::new(),
            scopes: vec![],
            resource_pattern: Some("TENANT:${acct}:pipes:.*".into()),
            required_headers,
            expires_at: None,
            subject_user_id: None,
        }
    }

    fn pat_delegation(
        token_id: &str,
        depth: u32,
        scopes: Option<Vec<String>>,
        resource_scoped: bool,
    ) -> Option<Extension<PatDelegationContext>> {
        Some(Extension(PatDelegationContext {
            token_id: token_id.into(),
            delegation_depth: depth,
            resource_scoped,
            scopes,
        }))
    }

    #[test]
    fn delegated_scopes_must_be_a_non_empty_subset() {
        let parent = vec!["secrets.view".to_string(), "secrets.edit".to_string()];

        assert!(validate_delegated_scopes(Some(&parent), &["secrets.view".to_string()]).is_ok());
        assert!(validate_delegated_scopes(Some(&parent), &["secrets.delete".to_string()]).is_err());
        assert!(validate_delegated_scopes(Some(&parent), &[]).is_err());
        assert!(validate_delegated_scopes(None, &[]).is_ok());
    }

    #[test]
    fn expiry_is_absent_or_exact_and_bounded() {
        let now = Utc::now();
        let exact = now + Duration::hours(1);
        assert_eq!(resolve_expiry(now, None), Ok(None));
        assert_eq!(resolve_expiry(now, Some(exact)), Ok(Some(exact)));
        assert!(resolve_expiry(now, Some(now)).is_err());
        assert!(resolve_expiry(now, Some(now + Duration::days(i64::from(MAX_EXPIRY_DAYS) + 1))).is_err());
    }

    #[test]
    fn create_request_rejects_removed_relative_expiry_field() {
        let request = serde_json::json!({
            "name": "service",
            "expires_in_days": 30
        });
        assert!(serde_json::from_value::<CreateAccessTokenRequest>(request).is_err());
    }

    #[test]
    fn delegated_lineage_is_bounded_and_rejects_resource_scoped_parents() {
        let parent = pat_delegation("parent", MAX_DELEGATION_DEPTH - 1, None, false).unwrap();
        assert_eq!(delegated_lineage(Some(&parent.0)), Ok((Some("parent".to_string()), MAX_DELEGATION_DEPTH)));

        let deepest = pat_delegation("deepest", MAX_DELEGATION_DEPTH, None, false).unwrap();
        assert!(delegated_lineage(Some(&deepest.0)).is_err());

        let scoped = pat_delegation("scoped", 0, None, true).unwrap();
        assert!(delegated_lineage(Some(&scoped.0)).is_err());
    }

    #[tokio::test]
    async fn delegated_create_inherits_subject_and_records_parent() {
        let store = store().await;
        let (parent_id, _) = seed(&store).await;
        let user_storage = users(vec![user("svc-user", UserRole::User, UserStatus::Approved)]).await;
        let request = CreateAccessTokenRequest {
            name: "child".into(),
            description: String::new(),
            scopes: vec!["metrics.view".into()],
            resource_pattern: None,
            required_headers: vec![],
            expires_at: None,
            subject_user_id: Some("svc-user".into()),
        };

        let (status, Json(created)) = create_access_token(
            State(store),
            Extension(Arc::new(RbacConfig::default())),
            user_storage,
            Some(Extension(AuthGuardOk("svc-user".into()))),
            pat_delegation(&parent_id, 0, Some(vec!["metrics.view".into()]), false),
            None,
            Json(request),
        )
        .await
        .expect("delegated create");

        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(created.meta.user_id, "svc-user");
        assert_eq!(
            created
                .meta
                .parent_token_id
                .as_deref(),
            Some(parent_id.as_str())
        );
        assert_eq!(created.meta.delegation_depth, 1);
    }

    #[tokio::test]
    async fn delegated_create_rejects_subject_switch_and_resource_scoped_parent() {
        let store = store().await;
        let (parent_id, _) = seed(&store).await;
        let rbac = Extension(Arc::new(RbacConfig::default()));
        let user_storage = users(vec![user("svc-user", UserRole::User, UserStatus::Approved)]).await;

        let switched = create_access_token(
            State(store.clone()),
            rbac.clone(),
            user_storage.clone(),
            Some(Extension(AuthGuardOk("svc-user".into()))),
            pat_delegation(&parent_id, 0, Some(vec!["metrics.view".into()]), false),
            None,
            Json(CreateAccessTokenRequest {
                name: "child".into(),
                description: String::new(),
                scopes: vec!["metrics.view".into()],
                resource_pattern: None,
                required_headers: vec![],
                expires_at: None,
                subject_user_id: Some("another-user".into()),
            }),
        )
        .await;
        assert!(matches!(switched, Err((StatusCode::FORBIDDEN, _))));

        let scoped = create_access_token(
            State(store),
            rbac,
            user_storage,
            Some(Extension(AuthGuardOk("svc-user".into()))),
            pat_delegation(&parent_id, 0, Some(vec!["metrics.view".into()]), true),
            None,
            Json(CreateAccessTokenRequest {
                name: "child".into(),
                description: String::new(),
                scopes: vec!["metrics.view".into()],
                resource_pattern: None,
                required_headers: vec![],
                expires_at: None,
                subject_user_id: None,
            }),
        )
        .await;
        assert!(matches!(scoped, Err((StatusCode::FORBIDDEN, _))));
    }

    #[tokio::test]
    async fn delegated_administration_is_limited_to_its_lineage() {
        let store = store().await;
        let (parent_id, _) = seed(&store).await;
        let unrelated = AccessToken {
            id: format!("asat_{}", uuid::Uuid::new_v4().as_simple()),
            name: "unrelated".into(),
            description: String::new(),
            token_hash: hash_secret("aspat_unrelated"),
            user_id: "svc-user".into(),
            scopes: vec!["metrics.view".into()],
            resource_pattern: None,
            required_headers: vec![],
            created_by: "admin-user".into(),
            parent_token_id: None,
            delegation_depth: 0,
            rotation_generation: 0,
            rotated_at: None,
            rotated_by: None,
            created_at: Utc::now(),
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        };
        let unrelated_id = unrelated.id.clone();
        store
            .create(unrelated)
            .await
            .unwrap();
        let context = pat_delegation(&parent_id, 0, Some(vec!["metrics.view".into()]), false).unwrap();

        assert!(validate_target_authority(&store, Some(&context.0), &parent_id).is_ok());
        assert!(validate_target_authority(&store, Some(&context.0), &unrelated_id).is_err());
        assert!(validate_target_authority(&store, None, &unrelated_id).is_ok());
    }

    #[tokio::test]
    async fn rotate_returns_new_secret_on_the_same_record() {
        let s = store().await;
        let (id, old_secret) = seed(&s).await;

        let (status, Json(body)) = rotate_access_token(State(s.clone()), Path(id.clone()), admin(), None)
            .await
            .expect("rotate ok");
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.token
                .starts_with(TOKEN_PREFIX)
        );
        assert_ne!(body.token, old_secret, "a fresh secret is issued");
        assert_eq!(body.meta.id, id, "rotation preserves the token id");
        assert_eq!(body.meta.rotation_generation, 1);
        assert_eq!(
            body.meta
                .rotated_by
                .as_deref(),
            Some("admin-user")
        );

        assert!(
            s.get(&id)
                .unwrap()
                .revoked_at
                .is_none(),
            "stable token record remains active"
        );
        assert!(
            s.authenticate(&body.token)
                .await
                .is_some(),
            "new secret authenticates"
        );
        assert!(
            s.authenticate(&old_secret)
                .await
                .is_none(),
            "old secret no longer authenticates"
        );
    }

    #[tokio::test]
    async fn create_binds_to_explicit_subject_when_provided() {
        let s = store().await;
        let rbac = Extension(Arc::new(RbacConfig::default()));
        let user_storage = users(vec![
            user("admin-user", UserRole::Administrator, UserStatus::Approved),
            user("svc-metrics", UserRole::User, UserStatus::Approved),
        ])
        .await;
        let req = CreateAccessTokenRequest {
            name: "metrics-dashboard".into(),
            description: String::new(),
            scopes: vec!["metrics.view".into()],
            resource_pattern: None,
            required_headers: vec![],
            expires_at: None,
            subject_user_id: Some("svc-metrics".into()),
        };
        let (status, Json(body)) = create_access_token(State(s), rbac, user_storage, admin(), None, None, Json(req))
            .await
            .expect("create ok");
        assert_eq!(status, StatusCode::CREATED);
        // Bound to the named service account, not the admin caller — but the admin
        // is still recorded as the creator for the audit trail.
        assert_eq!(body.meta.user_id, "svc-metrics", "token binds to the explicit subject");
        assert_eq!(body.meta.created_by, "admin-user", "actor is recorded as creator");
    }

    #[tokio::test]
    async fn create_binds_to_caller_without_subject() {
        let s = store().await;
        let rbac = Extension(Arc::new(RbacConfig::default()));
        let user_storage = admin_users().await;
        let req = CreateAccessTokenRequest {
            name: "self".into(),
            description: String::new(),
            scopes: vec![],
            resource_pattern: None,
            required_headers: vec![],
            expires_at: None,
            subject_user_id: None,
        };
        let (_status, Json(body)) = create_access_token(State(s), rbac, user_storage, admin(), None, None, Json(req))
            .await
            .expect("create ok");
        assert_eq!(body.meta.user_id, "admin-user", "absent subject binds to the caller");
    }

    #[tokio::test]
    async fn create_rejects_unknown_or_disabled_subjects() {
        let store = store().await;
        let rbac = Extension(Arc::new(RbacConfig::default()));
        let user_storage = users(vec![
            user("admin-user", UserRole::Administrator, UserStatus::Approved),
            user("disabled-user", UserRole::User, UserStatus::Disabled),
        ])
        .await;

        for (subject, expected) in [("missing-user", StatusCode::BAD_REQUEST), ("disabled-user", StatusCode::FORBIDDEN)]
        {
            let result = create_access_token(
                State(store.clone()),
                rbac.clone(),
                user_storage.clone(),
                admin(),
                None,
                None,
                Json(CreateAccessTokenRequest {
                    name: "service".into(),
                    description: String::new(),
                    scopes: vec!["metrics.view".into()],
                    resource_pattern: None,
                    required_headers: vec![],
                    expires_at: None,
                    subject_user_id: Some(subject.into()),
                }),
            )
            .await;
            assert!(matches!(result, Err((status, _)) if status == expected));
        }
    }

    #[tokio::test]
    async fn create_rejects_scopes_above_the_service_account_role() {
        let result = create_access_token(
            State(store().await),
            Extension(Arc::new(RbacConfig::default())),
            users(vec![
                user("admin-user", UserRole::Administrator, UserStatus::Approved),
                user("svc-user", UserRole::User, UserStatus::Approved),
            ])
            .await,
            admin(),
            None,
            None,
            Json(CreateAccessTokenRequest {
                name: "service".into(),
                description: String::new(),
                scopes: vec!["settings.edit".into()],
                resource_pattern: None,
                required_headers: vec![],
                expires_at: None,
                subject_user_id: Some("svc-user".into()),
            }),
        )
        .await;

        assert!(matches!(result, Err((StatusCode::FORBIDDEN, _))));
    }

    /// The rotate Ok type isn't `Debug`, so unwrap the error arm by hand.
    fn rotate_err(result: Result<(StatusCode, Json<CreateAccessTokenResponse>), (StatusCode, String)>) -> StatusCode {
        match result {
            Ok(_) => panic!("expected an error response"),
            Err((status, _)) => status,
        }
    }

    #[tokio::test]
    async fn rotate_unknown_is_404() {
        let s = store().await;
        let status = rotate_err(rotate_access_token(State(s), Path("asat_missing".into()), admin(), None).await);
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn rotate_fails_closed_without_caller() {
        let s = store().await;
        let (id, _) = seed(&s).await;
        let status = rotate_err(rotate_access_token(State(s), Path(id), None, None).await);
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_fails_closed_without_caller() {
        let s = store().await;
        let (id, _) = seed(&s).await;
        let err = revoke_access_token(State(s), Path(id), None, None)
            .await
            .expect_err("no caller");
        assert_eq!(err.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn revoke_succeeds_and_marks_revoked_with_caller() {
        let s = store().await;
        let (id, _) = seed(&s).await;
        let status = revoke_access_token(State(s.clone()), Path(id.clone()), admin(), None)
            .await
            .expect("revoke ok");
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(
            s.get(&id)
                .unwrap()
                .revoked_at
                .is_some()
        );
    }

    #[tokio::test]
    async fn create_rejects_wildcard_required_header_pattern() {
        let store = store().await;
        let rbac = Arc::new(RbacConfig::default());
        let user_storage = admin_users().await;

        let req = create_req(vec![RequiredHeader {
            name: "acct".into(),
            pattern: ".*".into(),
        }]);
        let result =
            create_access_token(State(store), Extension(rbac), user_storage, admin(), None, None, Json(req)).await;

        assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))), "a '.*' header pattern must be rejected");
    }

    #[tokio::test]
    async fn create_accepts_exact_tenant_selector() {
        let store = store().await;
        let rbac = Arc::new(RbacConfig::default());
        let user_storage = admin_users().await;

        let req = create_req(vec![RequiredHeader {
            name: "acct".into(),
            pattern: "tenant-a".into(),
        }]);
        let result =
            create_access_token(State(store), Extension(rbac), user_storage, admin(), None, None, Json(req)).await;

        assert!(result.is_ok(), "an exact tenant selector must be accepted");
    }

    #[tokio::test]
    async fn broad_tenant_selector_requires_trusted_edge() {
        let request = || {
            create_req(vec![RequiredHeader {
                name: "acct".into(),
                pattern: r"[a-z0-9-]+".into(),
            }])
        };

        let rejected = create_access_token(
            State(store().await),
            Extension(Arc::new(RbacConfig::default())),
            admin_users().await,
            admin(),
            None,
            None,
            Json(request()),
        )
        .await;
        assert!(matches!(rejected, Err((StatusCode::BAD_REQUEST, _))));

        let trusted = Some(Extension(Arc::new(crate::tenancy::TenancyConfig {
            trusted_tenant_header: Some(crate::tenancy::TrustedTenantHeader {
                header: "acct".into(),
                edge_strips_client_values: true,
            }),
        })));
        let accepted = create_access_token(
            State(store().await),
            Extension(Arc::new(RbacConfig::default())),
            admin_users().await,
            admin(),
            None,
            trusted,
            Json(request()),
        )
        .await;
        assert!(accepted.is_ok());
    }

    #[tokio::test]
    async fn create_rejects_noncanonical_resource_pattern() {
        let store = store().await;
        let rbac = Arc::new(RbacConfig::default());
        let user_storage = admin_users().await;
        let mut req = create_req(vec![RequiredHeader {
            name: "acct".into(),
            pattern: r"\d{12}".into(),
        }]);
        req.resource_pattern = Some("TENANT:${acct}:.*".into());

        let result =
            create_access_token(State(store), Extension(rbac), user_storage, admin(), None, None, Json(req)).await;

        assert!(matches!(result, Err((StatusCode::BAD_REQUEST, _))));
    }

    #[tokio::test]
    async fn update_rejects_wildcard_required_header_pattern() {
        let store = store().await;
        let rbac = Arc::new(RbacConfig::default());
        let user_storage = admin_users().await;

        let created = create_access_token(
            State(store.clone()),
            Extension(rbac.clone()),
            user_storage.clone(),
            admin(),
            None,
            None,
            Json(create_req(vec![RequiredHeader {
                name: "acct".into(),
                pattern: "tenant-a".into(),
            }])),
        )
        .await
        .expect("create should succeed");
        let created_id = created.1.0.meta.id;

        let req = UpdateAccessTokenRequest {
            name: "svc".into(),
            description: String::new(),
            scopes: vec![],
            resource_pattern: Some("TENANT:${acct}:pipes:.*".into()),
            required_headers: vec![RequiredHeader {
                name: "acct".into(),
                pattern: ".+".into(),
            }],
        };
        let result = update_access_token(
            State(store),
            Extension(rbac),
            user_storage,
            Path(created_id),
            admin(),
            None,
            None,
            Json(req),
        )
        .await;

        assert!(
            matches!(result, Err((StatusCode::BAD_REQUEST, _))),
            "a '.+' header pattern must be rejected on update"
        );
    }
}
