//! Component tests for management-access-token (PAT) resource-scope
//! enforcement against the real secrets API — the entity family that is
//! **handler-enforced** (its path is a server UUID, so the middleware cannot
//! enforce by path segment; the handler must load the record and match its
//! `secret_id`).
//!
//! Drives the real `create_secrets_router` handlers end to end under
//! `require_session_auth`, wired with a resource-scoped mock PAT, over a
//! minimal in-memory `SecretsStore`. Covers the create/list/get/update/delete
//! matching + non-matching cases, plus a regression test for the fail-closed
//! fix: a lookup error while resolving the target secret must reject a
//! scoped mutation rather than silently letting it through.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, Response, StatusCode};
use axum::middleware::from_fn_with_state;
use chrono::Utc;
use tower::ServiceExt;

use crate::auth::session::SessionManager;
use crate::auth::storage::{PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::auth_manager::middleware::{AuthGuardState, RbacGuard, require_session_auth};
use crate::auth_manager::pat::{PatAuthenticator, PatPrincipal};
use crate::auth_manager::resource_scope::{self, CompiledCanonicalResourceScope, RequiredHeader};
use crate::config::network::SecretsConfig;
use crate::pipes::executor::PipeExecutor;
use crate::pipes::{PipeConfig, PipeType};
use crate::rbac::RbacConfig;
use crate::secrets::router::create_secrets_router;
use crate::secrets::store::SecretsStore;
use crate::secrets::{
    CreateSecretRequest, Secret, SecretListItem, SecretsCache, UpdateSecretRequest, get_cached_secret,
};

/// Sentinel internal id whose `get()` always fails, simulating a store I/O
/// error while resolving the record a scope check needs.
const LOOKUP_ERROR_ID: &str = "err-secret";

struct MockSecretsStore {
    inner: Mutex<HashMap<String, Secret>>,
}

impl MockSecretsStore {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(HashMap::new()),
        })
    }

    /// Insert a secret directly, bypassing the HTTP API (used to seed
    /// out-of-namespace records the scope must never allow through create).
    fn seed(
        &self,
        secret: Secret,
    ) {
        self.inner
            .lock()
            .unwrap()
            .insert(secret.id.clone(), secret);
    }
}

fn list_item(s: &Secret) -> SecretListItem {
    SecretListItem {
        id: s.id.clone(),
        name: s.name.clone(),
        secret_id: s.secret_id.clone(),
        description: s.description.clone(),
        secret_type: s.secret_type.clone(),
        tags: s.tags.clone(),
        tenant_id: s.tenant_id.clone(),
        created_at: s.created_at,
        updated_at: s.updated_at,
    }
}

#[async_trait]
impl SecretsStore for MockSecretsStore {
    async fn create(
        &self,
        request: CreateSecretRequest,
    ) -> Result<Secret> {
        let now = Utc::now();
        let secret = Secret {
            id: uuid::Uuid::new_v4().to_string(),
            name: request.name,
            secret_id: request.secret_id,
            description: request.description,
            value: request.value,
            secret_type: request.secret_type,
            tags: request.tags,
            tenant_id: request.tenant_id,
            created_at: now,
            updated_at: now,
        };
        self.seed(secret.clone());
        Ok(secret)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<Secret>> {
        if id == LOOKUP_ERROR_ID {
            return Err(anyhow::anyhow!("simulated store lookup failure"));
        }
        Ok(self
            .inner
            .lock()
            .unwrap()
            .get(id)
            .cloned())
    }

    async fn list_all(&self) -> Result<Vec<SecretListItem>> {
        Ok(self
            .inner
            .lock()
            .unwrap()
            .values()
            .map(list_item)
            .collect())
    }

    async fn update(
        &self,
        id: &str,
        request: UpdateSecretRequest,
    ) -> Result<Secret> {
        let mut guard = self.inner.lock().unwrap();
        let secret = guard
            .get_mut(id)
            .ok_or_else(|| anyhow::anyhow!("secret not found"))?;
        if let Some(name) = request.name {
            secret.name = name;
        }
        if let Some(description) = request.description {
            secret.description = Some(description);
        }
        if matches!(request.update_value, Some(true))
            && let Some(value) = request.value
        {
            secret.value = value;
        }
        if let Some(secret_type) = request.secret_type {
            secret.secret_type = secret_type;
        }
        if let Some(tags) = request.tags {
            secret.tags = tags;
        }
        secret.updated_at = Utc::now();
        Ok(secret.clone())
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.inner
            .lock()
            .unwrap()
            .remove(id);
        Ok(())
    }

    async fn find_by_tag(
        &self,
        tag: &str,
    ) -> Result<Vec<SecretListItem>> {
        Ok(self
            .list_all()
            .await?
            .into_iter()
            .filter(|s| {
                s.tags
                    .iter()
                    .any(|t| t == tag)
            })
            .collect())
    }
}

/// A `PatAuthenticator` mock that recognises a single bearer value and always
/// carries the same compiled resource scope.
struct ScopedMockPat {
    scope: Arc<CompiledCanonicalResourceScope>,
}

#[async_trait]
impl PatAuthenticator for ScopedMockPat {
    async fn authenticate(
        &self,
        token: &str,
    ) -> Option<PatPrincipal> {
        (token == "aspat_scoped").then(|| PatPrincipal {
            user_id: "admin-pat".into(),
            scopes: None,
            token_id: "tok-scoped".into(),
            delegation_depth: 0,
            resource_scoped: true,
            resource_scope: Some(self.scope.clone()),
        })
    }
}

fn rh(
    name: &str,
    pattern: &str,
) -> RequiredHeader {
    RequiredHeader {
        name: name.into(),
        pattern: pattern.into(),
    }
}

async fn make_admin_storage() -> (Arc<PasskeyStorage>, tempfile::TempDir) {
    make_storage_with_role(UserRole::Administrator).await
}

async fn make_storage_with_role(role: UserRole) -> (Arc<PasskeyStorage>, tempfile::TempDir) {
    let tmp = tempfile::tempdir().expect("tempdir");
    let storage_path = tmp
        .path()
        .join("passkeys")
        .to_string_lossy()
        .to_string();
    let avatars_path = tmp
        .path()
        .join("avatars")
        .to_string_lossy()
        .to_string();
    let storage = PasskeyStorage::new(storage_path, avatars_path)
        .await
        .expect("storage init");
    let now = chrono::Utc::now();
    storage
        .save_user(&UserData {
            user_id: "admin-pat".into(),
            username: "root".into(),
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
            deleted_at: None,
        })
        .await
        .expect("save user");
    (Arc::new(storage), tmp)
}

/// Build the real secrets router behind `require_session_auth`, with a single
/// resource-scoped PAT recognised as bearer `aspat_scoped`.
fn scoped_secrets_app(
    user_storage: Arc<PasskeyStorage>,
    store: Arc<MockSecretsStore>,
    pattern: Option<&str>,
    headers: Vec<RequiredHeader>,
) -> Router {
    let scope = Arc::new(resource_scope::compile_canonical(pattern, &headers).unwrap());
    let authenticator: Arc<dyn PatAuthenticator> = Arc::new(ScopedMockPat { scope });
    let sess_mgr = Arc::new(SessionManager::new());
    let guard = RbacGuard::new(user_storage.clone(), Arc::new(RbacConfig::default()));
    let store: Arc<dyn SecretsStore> = store;

    create_secrets_router(store, None, None, SecretsConfig::default(), guard).layer(from_fn_with_state(
        AuthGuardState::new(sess_mgr, Some(user_storage), std::sync::Arc::new(crate::terms::TermsManager::disabled()))
            .with_pat_authenticator(Some(authenticator)),
        require_session_auth,
    ))
}

async fn call(
    app: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    bearer: Option<&str>,
    body: serde_json::Value,
) -> StatusCode {
    call_response(app, method, path, headers, bearer, body)
        .await
        .status()
}

async fn call_response(
    app: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    bearer: Option<&str>,
    body: serde_json::Value,
) -> Response<Body> {
    let mut builder = Request::builder()
        .method(method.clone())
        .uri(path);
    if let Some(token) = bearer {
        builder = builder.header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"));
    }
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let body = if method == Method::GET || method == Method::DELETE {
        Body::empty()
    } else {
        builder = builder.header(axum::http::header::CONTENT_TYPE, "application/json");
        Body::from(serde_json::to_vec(&body).unwrap())
    };
    app.clone()
        .oneshot(builder.body(body).unwrap())
        .await
        .unwrap()
}

const ACCT: &[(&str, &str)] = &[("x-external-account", "123456789012")];
const ACCT_SELECTOR: &str = "123456789012";
const PATTERN: &str = "TENANT:${x-external-account}:secrets:.*";

#[tokio::test]
async fn canonical_create_stamps_tenant_and_rejects_other_kind() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);
    let response = call_response(
        &app,
        Method::POST,
        "/api/v1/secrets/new",
        ACCT,
        Some("aspat_scoped"),
        serde_json::json!({
            "name": "db password", "secret_id": "db-password", "value": "s3cr3t"
        }),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let secret: Secret = serde_json::from_slice(&body).unwrap();
    assert_eq!(secret.tenant_id.as_deref(), Some("123456789012"));

    let wrong_kind = scoped_secrets_app(
        make_admin_storage().await.0,
        MockSecretsStore::new(),
        Some("TENANT:${x-external-account}:pipes:.*"),
        vec![rh("x-external-account", ACCT_SELECTOR)],
    );
    assert_eq!(
        call(
            &wrong_kind,
            Method::POST,
            "/api/v1/secrets/new",
            ACCT,
            Some("aspat_scoped"),
            serde_json::json!({ "name": "x", "secret_id": "x", "value": "x" }),
        )
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn canonical_list_includes_same_tenant_hides_global_and_foreign() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    for (id, tenant_id) in [("same", Some("123456789012")), ("global", None), ("foreign", Some("999999999999"))] {
        store.seed(Secret {
            id: id.into(),
            name: id.into(),
            secret_id: id.into(),
            description: None,
            value: "v".into(),
            secret_type: "General".into(),
            tags: vec![],
            tenant_id: tenant_id.map(str::to_string),
            created_at: now,
            updated_at: now,
        });
    }
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);
    let response =
        call_response(&app, Method::GET, "/api/v1/secrets", ACCT, Some("aspat_scoped"), serde_json::Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), usize::MAX)
        .await
        .unwrap();
    let secrets: Vec<SecretListItem> = serde_json::from_slice(&body).unwrap();
    let mut ids: Vec<_> = secrets
        .into_iter()
        .map(|secret| secret.id)
        .collect();
    ids.sort();
    // Fail-closed hardening: an untenanted ("global") secret is no longer visible
    // to a tenant-scoped PAT (it was a cross-tenant read of legacy data).
    assert_eq!(ids, vec!["same"]);
}

#[tokio::test]
async fn create_secret_allows_matching_and_denies_other_namespace() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);

    let matching = serde_json::json!({
        "name": "db password", "secret_id": "db-password", "value": "s3cr3t"
    });
    assert_eq!(
        call(&app, Method::POST, "/api/v1/secrets/new", ACCT, Some("aspat_scoped"), matching).await,
        StatusCode::CREATED,
        "creating a secret inside the token's namespace must succeed"
    );

    let other = serde_json::json!({
        "name": "db password", "secret_id": "other-password", "value": "s3cr3t",
        "tenant_id": "999999999999"
    });
    assert_eq!(
        call(&app, Method::POST, "/api/v1/secrets/new", ACCT, Some("aspat_scoped"), other).await,
        StatusCode::FORBIDDEN,
        "creating a secret outside the token's namespace must be denied"
    );
}

#[tokio::test]
async fn create_secret_refuses_a_secret_id_no_reference_can_name() {
    // The mock store accepts any id, so only the handler stands between these
    // ids and a secret no surface could ever use.
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let app = scoped_secrets_app(storage, store.clone(), Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);

    for secret_id in ["acct:key", "my key", "team/key", "key@corp", "key+1"] {
        let body = serde_json::json!({ "name": "key", "secret_id": secret_id, "value": "s3cr3t" });
        assert_eq!(
            call(&app, Method::POST, "/api/v1/secrets/new", ACCT, Some("aspat_scoped"), body).await,
            StatusCode::BAD_REQUEST,
            "{secret_id:?} was accepted"
        );
    }
    assert!(
        store
            .list_all()
            .await
            .unwrap()
            .is_empty(),
        "a refused secret was stored"
    );
    let valid = serde_json::json!({ "name": "key", "secret_id": "acct-key.v1", "value": "s3cr3t" });
    assert_eq!(
        call(&app, Method::POST, "/api/v1/secrets/new", ACCT, Some("aspat_scoped"), valid).await,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn list_secrets_filters_to_the_token_namespace() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    store.seed(Secret {
        id: "s-in".into(),
        name: "in".into(),
        secret_id: "db".into(),
        description: None,
        value: "v".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: Some("123456789012".into()),
        created_at: now,
        updated_at: now,
    });
    store.seed(Secret {
        id: "s-out".into(),
        name: "out".into(),
        secret_id: "db".into(),
        description: None,
        value: "v".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: Some("999999999999".into()),
        created_at: now,
        updated_at: now,
    });
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);

    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/api/v1/secrets")
                .header(axum::http::header::AUTHORIZATION, "Bearer aspat_scoped")
                .header("x-external-account", "123456789012")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let items: Vec<SecretListItem> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1, "list must be filtered to the token's namespace only");
    assert_eq!(items[0].id, "s-in");
}

#[tokio::test]
async fn get_secret_404s_for_other_namespace() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    store.seed(Secret {
        id: "s-out".into(),
        name: "out".into(),
        secret_id: "db".into(),
        description: None,
        value: "v".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: Some("999999999999".into()),
        created_at: now,
        updated_at: now,
    });
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);

    assert_eq!(
        call(&app, Method::GET, "/api/v1/secrets/s-out", ACCT, Some("aspat_scoped"), serde_json::Value::Null).await,
        StatusCode::NOT_FOUND,
        "reading another account's secret must 404, not 403 (no existence disclosure)"
    );
}

#[tokio::test]
async fn update_and_delete_deny_other_namespace_and_allow_matching() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    store.seed(Secret {
        id: "s-out".into(),
        name: "out".into(),
        secret_id: "db-out".into(),
        description: None,
        value: "v".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: Some("999999999999".into()),
        created_at: now,
        updated_at: now,
    });
    store.seed(Secret {
        id: "s-in".into(),
        name: "in".into(),
        secret_id: "db-in".into(),
        description: None,
        value: "v".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: Some("123456789012".into()),
        created_at: now,
        updated_at: now,
    });
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);

    let update_body = serde_json::json!({ "name": "renamed" });
    assert_eq!(
        call(&app, Method::PUT, "/api/v1/secrets/s-out", ACCT, Some("aspat_scoped"), update_body.clone()).await,
        StatusCode::FORBIDDEN,
        "updating another account's secret must be denied"
    );
    assert_eq!(
        call(&app, Method::DELETE, "/api/v1/secrets/s-out", ACCT, Some("aspat_scoped"), serde_json::Value::Null).await,
        StatusCode::FORBIDDEN,
        "deleting another account's secret must be denied"
    );

    assert_eq!(
        call(&app, Method::PUT, "/api/v1/secrets/s-in", ACCT, Some("aspat_scoped"), update_body).await,
        StatusCode::OK,
        "updating a matching-namespace secret must succeed"
    );
    assert_eq!(
        call(&app, Method::DELETE, "/api/v1/secrets/s-in", ACCT, Some("aspat_scoped"), serde_json::Value::Null).await,
        StatusCode::NO_CONTENT,
        "deleting a matching-namespace secret must succeed"
    );
}

/// Regression test for the fail-closed fix: previously, an `Err` from the
/// pre-mutation lookup fell through to `store.update` / `store.delete`
/// unconditionally, so a scoped token could mutate a secret it could not be
/// confirmed to own. It must now be rejected instead.
#[tokio::test]
async fn update_and_delete_fail_closed_on_lookup_error() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    // Seeded directly (bypassing `get()`'s error simulation) so the record
    // exists; only the pre-mutation *lookup* fails.
    store
        .inner
        .lock()
        .unwrap()
        .insert(
            LOOKUP_ERROR_ID.to_string(),
            Secret {
                id: LOOKUP_ERROR_ID.into(),
                name: "boom".into(),
                secret_id: "TENANT:123456789012:db".into(),
                description: None,
                value: "v".into(),
                secret_type: "General".into(),
                tags: vec![],
                tenant_id: None,
                created_at: now,
                updated_at: now,
            },
        );
    let app = scoped_secrets_app(storage, store, Some(PATTERN), vec![rh("x-external-account", ACCT_SELECTOR)]);
    let path = format!("/api/v1/secrets/{LOOKUP_ERROR_ID}");

    assert_eq!(
        call(&app, Method::PUT, &path, ACCT, Some("aspat_scoped"), serde_json::json!({ "name": "x" })).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a scoped update must fail closed when the pre-mutation lookup errors, not silently proceed"
    );
    assert_eq!(
        call(&app, Method::DELETE, &path, ACCT, Some("aspat_scoped"), serde_json::Value::Null).await,
        StatusCode::INTERNAL_SERVER_ERROR,
        "a scoped delete must fail closed when the pre-mutation lookup errors, not silently proceed"
    );
}

/// An unscoped caller (no PAT resource pattern) is unaffected by the
/// fail-closed change: the pre-check is skipped entirely and the mutation is
/// attempted directly, exactly as before this fix.
#[tokio::test]
async fn unscoped_session_is_unaffected_by_lookup_error() {
    let (storage, _tmp) = make_admin_storage().await;
    let store = MockSecretsStore::new();
    let now = Utc::now();
    store
        .inner
        .lock()
        .unwrap()
        .insert(
            LOOKUP_ERROR_ID.to_string(),
            Secret {
                id: LOOKUP_ERROR_ID.into(),
                name: "boom".into(),
                secret_id: "TENANT:123456789012:db".into(),
                description: None,
                value: "v".into(),
                secret_type: "General".into(),
                tags: vec![],
                tenant_id: None,
                created_at: now,
                updated_at: now,
            },
        );
    // No resource pattern and no required headers: an active session on this
    // app authenticates with no PatResourceScope extension at all.
    let sess_mgr = Arc::new(SessionManager::new());
    let token = sess_mgr
        .create_session("root".into(), "admin-pat".into())
        .await;
    let guard = RbacGuard::new(storage.clone(), Arc::new(RbacConfig::default()));
    let store: Arc<dyn SecretsStore> = store;
    let app = create_secrets_router(store, None, None, SecretsConfig::default(), guard).layer(from_fn_with_state(
        AuthGuardState::new(sess_mgr, Some(storage), std::sync::Arc::new(crate::terms::TermsManager::disabled())),
        require_session_auth,
    ));

    let path = format!("/api/v1/secrets/{LOOKUP_ERROR_ID}");
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::PUT)
                .uri(&path)
                .header(axum::http::header::AUTHORIZATION, format!("Bearer {token}"))
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::to_vec(&serde_json::json!({ "name": "x" })).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "an unscoped session must be unaffected by the scoped fail-closed fix");
}

/// Build the real secrets router behind an unscoped administrator session,
/// sharing `cache` with the router the way the orchestrator shares the
/// source-auth secrets cache, with `secrets.reveal_values` set to `reveal`.
/// Returns the app and the session bearer.
async fn session_secrets_app(
    store: Arc<MockSecretsStore>,
    cache: SecretsCache,
    reveal: bool,
) -> (Router, String, tempfile::TempDir) {
    let (storage, tmp) = make_admin_storage().await;
    let sess_mgr = Arc::new(SessionManager::new());
    let token = sess_mgr
        .create_session("root".into(), "admin-pat".into())
        .await;
    let guard = RbacGuard::new(storage.clone(), Arc::new(RbacConfig::default()));
    let store: Arc<dyn SecretsStore> = store;
    let settings = SecretsConfig {
        reveal_values: reveal,
        ..SecretsConfig::default()
    };
    let app = create_secrets_router(store, None, Some(cache), settings, guard).layer(from_fn_with_state(
        AuthGuardState::new(sess_mgr, Some(storage), std::sync::Arc::new(crate::terms::TermsManager::disabled())),
        require_session_auth,
    ));
    (app, token, tmp)
}

/// Build the real secrets router behind a session for a user holding `role`,
/// with `settings` as the `secrets` block of agent-stream.json. Returns the
/// app and the session bearer.
async fn settings_secrets_app(
    role: UserRole,
    settings: SecretsConfig,
) -> (Router, String, tempfile::TempDir) {
    let (storage, tmp) = make_storage_with_role(role).await;
    let sess_mgr = Arc::new(SessionManager::new());
    let token = sess_mgr
        .create_session("root".into(), "admin-pat".into())
        .await;
    let guard = RbacGuard::new(storage.clone(), Arc::new(RbacConfig::default()));
    let store: Arc<dyn SecretsStore> = MockSecretsStore::new();
    let app = create_secrets_router(store, None, None, settings, guard).layer(from_fn_with_state(
        AuthGuardState::new(sess_mgr, Some(storage), std::sync::Arc::new(crate::terms::TermsManager::disabled())),
        require_session_auth,
    ));
    (app, token, tmp)
}

/// The secret editor reads only the `secrets` settings, and only a caller who
/// may create or edit secrets can read them.
#[tokio::test]
async fn secrets_settings_answer_only_the_secrets_block_to_secret_editors() {
    let settings = SecretsConfig {
        secret_types: vec!["General".into(), "ApiKey".into()],
        reveal_values: false,
    };
    let (app, token, _tmp) = settings_secrets_app(UserRole::Administrator, settings).await;

    let response =
        call_response(&app, Method::GET, "/api/v1/secrets/settings", &[], Some(&token), serde_json::Value::Null).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap(),
    )
    .unwrap();
    assert_eq!(body, serde_json::json!({ "secret_types": ["General", "ApiKey"], "reveal_values": false }));
}

#[tokio::test]
async fn secrets_settings_are_refused_without_secrets_edit() {
    let (app, token, _tmp) = settings_secrets_app(UserRole::User, SecretsConfig::default()).await;

    let status = call(&app, Method::GET, "/api/v1/secrets/settings", &[], Some(&token), serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn secrets_settings_are_refused_without_a_session() {
    let (app, _token, _tmp) = settings_secrets_app(UserRole::Administrator, SecretsConfig::default()).await;

    let status = call(&app, Method::GET, "/api/v1/secrets/settings", &[], None, serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

/// With `secrets.reveal_values` on (the default), reading one secret answers
/// with its value; off, the same read answers the record without it, so the
/// dashboard can still edit the secret but nobody can read the value back.
#[tokio::test]
async fn reading_a_secret_withholds_its_value_when_reveal_is_off() {
    for (reveal, expected_value) in [(true, Some("old")), (false, None)] {
        let store = MockSecretsStore::new();
        store.seed(cached_secret());
        let (app, token, _tmp) = session_secrets_app(store, Arc::new(dashmap::DashMap::new()), reveal).await;

        let response = call_response(
            &app,
            Method::GET,
            "/api/v1/secrets/cached-secret",
            &[],
            Some(&token),
            serde_json::Value::Null,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK, "reveal_values={reveal}");
        let body: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body["secret_id"], "inbound-key", "reveal_values={reveal}");
        assert_eq!(
            body.get("value")
                .and_then(|v| v.as_str()),
            expected_value,
            "reveal_values={reveal}"
        );
    }
}

fn cached_secret() -> Secret {
    let now = Utc::now();
    Secret {
        id: "cached-secret".into(),
        name: "inbound key".into(),
        secret_id: "inbound-key".into(),
        description: None,
        value: "old".into(),
        secret_type: "General".into(),
        tags: vec![],
        tenant_id: None,
        created_at: now,
        updated_at: now,
    }
}

/// Park an executor in the process-wide executor cache under `key`, standing in
/// for a live surface that has already resolved its upstream secrets.
async fn seed_cached_executor(key: &str) {
    let config = PipeConfig::new(
        key.to_string(),
        "surface".to_string(),
        PipeType::Webhook {
            endpoint: "https://example.com/hook".to_string(),
        },
    );
    crate::pipes::cache::PIPE_EXECUTOR_CACHE
        .write()
        .await
        .insert(key.to_string(), Arc::new(PipeExecutor::new(&config)));
}

async fn executor_is_cached(key: &str) -> bool {
    crate::pipes::cache::PIPE_EXECUTOR_CACHE
        .read()
        .await
        .contains_key(key)
}

/// Saving a new value through the API drops the cached credentials and every
/// cached executor, so the next request authenticates against the new value
/// and a live surface sends it upstream, rather than waiting for a restart.
#[tokio::test]
async fn updating_a_secret_drops_its_cached_credentials() {
    let store = MockSecretsStore::new();
    store.seed(cached_secret());
    let cache: SecretsCache = Arc::new(dashmap::DashMap::new());
    let (app, token, _tmp) = session_secrets_app(store.clone(), cache.clone(), true).await;
    let store: Arc<dyn SecretsStore> = store;
    let warmed = get_cached_secret("inbound-key", None, &Some(store.clone()), &cache)
        .await
        .unwrap();
    assert_eq!(warmed, vec!["old".to_string()]);
    seed_cached_executor("secret-update-executor").await;

    let status = call(
        &app,
        Method::PUT,
        "/api/v1/secrets/cached-secret",
        &[],
        Some(&token),
        serde_json::json!({ "value": "new", "update_value": true }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    assert!(
        cache
            .get("inbound-key")
            .is_none(),
        "the update must drop the cached entry"
    );
    let refreshed = get_cached_secret("inbound-key", None, &Some(store), &cache)
        .await
        .unwrap();
    assert_eq!(refreshed, vec!["new".to_string()]);
    assert!(!executor_is_cached("secret-update-executor").await, "the update must drop the cached executors");
}

/// Deleting a secret through the API drops its cached credentials, so a
/// removed credential stops authenticating at once.
#[tokio::test]
async fn deleting_a_secret_drops_its_cached_credentials() {
    let store = MockSecretsStore::new();
    store.seed(cached_secret());
    let cache: SecretsCache = Arc::new(dashmap::DashMap::new());
    let (app, token, _tmp) = session_secrets_app(store.clone(), cache.clone(), true).await;
    let store: Arc<dyn SecretsStore> = store;
    get_cached_secret("inbound-key", None, &Some(store.clone()), &cache)
        .await
        .unwrap();
    assert!(
        cache
            .get("inbound-key")
            .is_some()
    );
    seed_cached_executor("secret-delete-executor").await;

    let status =
        call(&app, Method::DELETE, "/api/v1/secrets/cached-secret", &[], Some(&token), serde_json::Value::Null).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(!executor_is_cached("secret-delete-executor").await, "the delete must drop the cached executors");

    assert!(
        cache
            .get("inbound-key")
            .is_none(),
        "the delete must drop the cached entry"
    );
    assert!(
        get_cached_secret("inbound-key", None, &Some(store), &cache)
            .await
            .is_err(),
        "a deleted secret must not resolve from the cache"
    );
}
