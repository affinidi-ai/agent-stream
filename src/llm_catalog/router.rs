//! LLM provider catalog API router.

use std::sync::Arc;

use axum::{
    Router,
    routing::{delete, get, post, put},
};

use super::{handlers, store::LlmProviderCatalog};
use crate::auth_manager::middleware::RbacGuard;
use crate::rbac::Feature;

/// Create the LLM provider catalog API router.
///
/// `refresh_url` is the published master-catalog location for the "Refresh
/// Builtin Models" flow (`llm_catalog.refresh_url` in agent-stream.json); `None`
/// disables that action. `allow_insecure_source` (`llm_catalog.allow_insecure_source`)
/// lets the download reach a plain http or private-network mirror.
///
/// Every route needs `llm_catalog.edit`, reads included: the catalog prices
/// every call no surface prices itself, so it moves every budget on the
/// appliance, and its model switches decide what surfaces may call. Surface
/// editors read the providers they pick from through the pipes config instead.
pub fn create_llm_providers_router(
    catalog: Arc<LlmProviderCatalog>,
    refresh_url: Option<String>,
    allow_insecure_source: bool,
    gate: RbacGuard,
) -> Router {
    // Treat an absent or blank URL identically: the refresh action is
    // unavailable, so the dashboard hides the button rather than letting it fail.
    let refresh_url = refresh_url.filter(|u| !u.trim().is_empty());
    let state = handlers::LlmCatalogState {
        catalog,
        refresh_url,
        allow_insecure_source,
    };
    Router::new()
        .route("/api/v1/llm-providers", get(handlers::list_providers))
        .route("/api/v1/llm-providers", post(handlers::create_provider))
        .route("/api/v1/llm-providers/custom", get(handlers::get_custom))
        .route("/api/v1/llm-providers/custom", put(handlers::put_custom))
        .route("/api/v1/llm-providers/refresh", post(handlers::refresh_builtin).get(handlers::refresh_status))
        .route("/api/v1/llm-providers/refresh/rollback", post(handlers::rollback_builtin))
        .route("/api/v1/llm-providers/{enum_value}", get(handlers::get_provider))
        .route("/api/v1/llm-providers/{enum_value}", put(handlers::update_provider))
        .route("/api/v1/llm-providers/{enum_value}", delete(handlers::delete_provider))
        .layer(crate::auth_manager::middleware::require_feature(
            gate.storage,
            gate.rbac_config,
            Feature::LlmCatalogEdit,
        ))
        .with_state(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::storage::{PasskeyStorage, UserData};
    use crate::auth::types::{UserRole, UserStatus};
    use crate::auth_manager::middleware::AuthGuardOk;
    use crate::auth_manager::pat::PatContext;
    use crate::rbac::RbacConfig;
    use axum::body::Body;
    use axum::http::{Method, Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    fn openai(cost_per_1k: Value) -> Value {
        json!({
            "enum_value": "openai",
            "name": "OpenAI",
            "endpoints": [],
            "models": [{ "name": "GPT-4o", "value": "gpt-4o", "cost_per_1k_input": cost_per_1k, "cost_per_1k_output": cost_per_1k }]
        })
    }

    /// The catalog router over a catalog holding `openai`, called by a signed-in
    /// `role` (narrowed, for a token, to the permission allow-list `scopes`).
    async fn app(
        role: UserRole,
        scopes: Option<Vec<&str>>,
    ) -> (Router, Arc<LlmProviderCatalog>, tempfile::TempDir) {
        let temp = tempfile::tempdir().unwrap();
        let catalog_path = temp
            .path()
            .join("catalog")
            .join("llm.json");
        std::fs::create_dir_all(catalog_path.parent().unwrap()).unwrap();
        std::fs::write(&catalog_path, json!({ "providers": [openai(json!(0.0025))] }).to_string()).unwrap();
        let catalog = Arc::new(LlmProviderCatalog::new(catalog_path, None).unwrap());

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
            .save_user(&UserData {
                user_id: "user-1".into(),
                username: "user".into(),
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
            })
            .await
            .unwrap();
        let gate = RbacGuard::new(Arc::new(storage), Arc::new(RbacConfig::default()));
        let scopes: Option<Vec<String>> = scopes.map(|scopes| {
            scopes
                .into_iter()
                .map(str::to_string)
                .collect()
        });

        let router = create_llm_providers_router(catalog.clone(), None, false, gate).layer(axum::middleware::from_fn(
            move |mut request: axum::extract::Request, next: axum::middleware::Next| {
                let scopes = scopes.clone();
                async move {
                    request
                        .extensions_mut()
                        .insert(AuthGuardOk("user-1".into()));
                    if scopes.is_some() {
                        request
                            .extensions_mut()
                            .insert(PatContext(scopes));
                    }
                    next.run(request).await
                }
            },
        ));
        (router, catalog, temp)
    }

    async fn status(
        app: &Router,
        method: Method,
        path: &str,
        body: Option<Value>,
    ) -> StatusCode {
        let request = Request::builder()
            .method(method)
            .uri(path)
            .header("content-type", "application/json");
        let body = body.map_or_else(Body::empty, |body| Body::from(body.to_string()));
        app.clone()
            .oneshot(request.body(body).unwrap())
            .await
            .unwrap()
            .status()
    }

    fn catalog_price(catalog: &LlmProviderCatalog) -> Option<f64> {
        catalog
            .resolve_model_pricing("openai", "gpt-4o", None)
            .map(|pricing| pricing.input_price_per_million)
    }

    fn every_catalog_route() -> Vec<(Method, &'static str, Option<Value>)> {
        vec![
            (Method::GET, "/api/v1/llm-providers", None),
            (Method::POST, "/api/v1/llm-providers", Some(json!({ "enum_value": "other", "name": "Other" }))),
            (Method::GET, "/api/v1/llm-providers/custom", None),
            (Method::PUT, "/api/v1/llm-providers/custom", Some(json!({ "providers": [] }))),
            (Method::GET, "/api/v1/llm-providers/refresh", None),
            (Method::POST, "/api/v1/llm-providers/refresh", None),
            (Method::POST, "/api/v1/llm-providers/refresh/rollback", None),
            (Method::GET, "/api/v1/llm-providers/openai", None),
            (Method::PUT, "/api/v1/llm-providers/openai", Some(openai(json!(0.0)))),
            (Method::DELETE, "/api/v1/llm-providers/openai", None),
        ]
    }

    #[tokio::test]
    async fn base_and_power_users_are_refused_every_catalog_route() {
        for role in [UserRole::User, UserRole::PowerUser] {
            let (app, catalog, _temp) = app(role.clone(), None).await;

            for (method, path, body) in every_catalog_route() {
                assert_eq!(
                    status(&app, method.clone(), path, body).await,
                    StatusCode::FORBIDDEN,
                    "{role:?} {method} {path}"
                );
            }
            assert_eq!(catalog_price(&catalog), Some(2.5), "a refused write changed the catalog");
        }
    }

    #[tokio::test]
    async fn an_administrator_reads_the_catalog() {
        let (app, _catalog, _temp) = app(UserRole::Administrator, None).await;

        for path in [
            "/api/v1/llm-providers",
            "/api/v1/llm-providers/custom",
            "/api/v1/llm-providers/refresh",
            "/api/v1/llm-providers/openai",
        ] {
            assert_eq!(status(&app, Method::GET, path, None).await, StatusCode::OK, "GET {path}");
        }
    }

    #[tokio::test]
    async fn the_catalog_needs_a_signed_in_caller() {
        let temp = tempfile::tempdir().unwrap();
        let catalog_path = temp.path().join("llm.json");
        std::fs::write(&catalog_path, json!({ "providers": [openai(json!(0.0025))] }).to_string()).unwrap();
        let catalog = Arc::new(LlmProviderCatalog::new(catalog_path, None).unwrap());
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
        let gate = RbacGuard::new(Arc::new(storage), Arc::new(RbacConfig::default()));
        let app = create_llm_providers_router(catalog, None, false, gate);

        for (method, path, body) in every_catalog_route() {
            assert_eq!(status(&app, method.clone(), path, body).await, StatusCode::UNAUTHORIZED, "{method} {path}");
        }
    }

    #[tokio::test]
    async fn an_administrator_may_change_the_catalog_within_the_price_range() {
        let (app, catalog, _temp) = app(UserRole::Administrator, None).await;

        assert_eq!(
            status(&app, Method::PUT, "/api/v1/llm-providers/openai", Some(openai(json!(-0.001)))).await,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(catalog_price(&catalog), Some(2.5), "an out-of-range price was stored");
        assert_eq!(
            status(&app, Method::PUT, "/api/v1/llm-providers/openai", Some(openai(json!(0.0)))).await,
            StatusCode::OK
        );
        assert_eq!(catalog_price(&catalog), Some(0.0));
    }

    #[tokio::test]
    async fn a_token_must_name_the_catalog_permission_in_its_allow_list() {
        let (narrowed, _catalog, _a) = app(UserRole::Administrator, Some(vec!["pipes.edit", "pipes.pricing"])).await;
        let (named, _named_catalog, _b) = app(UserRole::Administrator, Some(vec!["llm_catalog.edit"])).await;
        let free = openai(json!(0.0));

        assert_eq!(
            status(&narrowed, Method::PUT, "/api/v1/llm-providers/openai", Some(free.clone())).await,
            StatusCode::FORBIDDEN
        );
        assert_eq!(status(&named, Method::PUT, "/api/v1/llm-providers/openai", Some(free)).await, StatusCode::OK);
    }
}
