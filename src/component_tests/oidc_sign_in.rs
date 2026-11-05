//! Component tests for OIDC sign-in: the real `/oidc/login` and
//! `/oidc/callback` handlers against a stub OpenID provider on a loopback
//! port, from the redirect to the provider through the code exchange, the ID
//! token check, the role mapping and the session handed to the dashboard.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, Response, StatusCode, header};
use axum::routing::get;
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::auth::oidc::config::TokenEndpointAuthMethod;
use crate::auth::oidc::test_support::{
    CLIENT_ID, CLIENT_SECRET, REDIRECT_URI, StubProvider, config_for, id_token_claims, logout_claims, sign_logout,
};
use crate::auth::oidc::{OidcConfig, OidcState, oidc_backchannel_logout, oidc_callback, oidc_initiate, oidc_login};
use crate::auth::session::SessionManager;
use crate::auth::storage::{OidcIdentity, PasskeyStorage, UserData};
use crate::auth::types::{UserRole, UserStatus};
use crate::url_validation::test_service_endpoints;

struct Flow {
    app: Router,
    oidc: Arc<OidcState>,
    provider: StubProvider,
    _dir: tempfile::TempDir,
    _allowed: test_service_endpoints::Allowed,
    _ready: std::sync::MutexGuard<'static, ()>,
}

/// The sign-in a test started: what the provider was sent, and the binding
/// cookie the browser holds.
struct Started {
    state: String,
    nonce: String,
    authorization: HashMap<String, String>,
    cookie: String,
}

impl Flow {
    async fn new() -> Self {
        Self::with_config(|_| {}).await
    }

    async fn with_config(adjust: impl FnOnce(&mut OidcConfig)) -> Self {
        Self::with_parts(adjust, Arc::new(SessionManager::new())).await
    }

    async fn with_parts(
        adjust: impl FnOnce(&mut OidcConfig),
        sessions: Arc<SessionManager>,
    ) -> Self {
        let provider = StubProvider::start().await;
        let allowed =
            test_service_endpoints::allow(&[provider.discovery_url(), provider.token_endpoint(), provider.jwks_uri()]);
        let dir = tempfile::tempdir().unwrap();
        let storage = Arc::new(
            PasskeyStorage::new(
                dir.path()
                    .join("users")
                    .to_string_lossy()
                    .into_owned(),
                dir.path()
                    .join("avatars")
                    .to_string_lossy()
                    .into_owned(),
            )
            .await
            .unwrap(),
        );
        let mut config = config_for(&provider.issuer);
        adjust(&mut config);
        let oidc = Arc::new(
            OidcState::new(config, storage, sessions, Arc::new(crate::terms::TermsManager::disabled())).unwrap(),
        );
        let app = Router::new()
            .route("/oidc/login", get(oidc_login))
            .route("/oidc/callback", get(oidc_callback))
            .route("/oidc/initiate", get(oidc_initiate).post(oidc_initiate))
            .route("/oidc/backchannel-logout", axum::routing::post(oidc_backchannel_logout))
            .with_state(oidc.clone());
        Self {
            app,
            oidc,
            provider,
            _dir: dir,
            _allowed: allowed,
            _ready: crate::server::mode::ready_for_test(),
        }
    }

    async fn get(
        &self,
        uri: &str,
        cookie: Option<&str>,
    ) -> Response<Body> {
        let mut request = Request::builder().uri(uri);
        if let Some(cookie) = cookie {
            request = request.header(header::COOKIE, cookie);
        }
        self.app
            .clone()
            .oneshot(
                request
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    async fn start(&self) -> Started {
        let response = self
            .get("/oidc/login", None)
            .await;
        self.started(&response)
    }

    async fn post_form(
        &self,
        uri: &str,
        form: &str,
    ) -> Response<Body> {
        self.app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                    .body(Body::from(form.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap()
    }

    /// The query string that names this provider as `iss`, with `rest` after it.
    fn initiate_query(
        &self,
        rest: &str,
    ) -> String {
        let issuer = url::form_urlencoded::byte_serialize(
            self.provider
                .issuer
                .as_bytes(),
        )
        .collect::<String>();
        format!("iss={issuer}{rest}")
    }

    /// The sign-in a response from `/oidc/login` or `/oidc/initiate` started.
    fn started(
        &self,
        response: &Response<Body>,
    ) -> Started {
        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        let location = url::Url::parse(header_value(response, header::LOCATION)).unwrap();
        assert!(
            location
                .as_str()
                .starts_with(&format!("{}/authorize?", self.provider.issuer)),
            "{location}"
        );
        let authorization: HashMap<String, String> = location
            .query_pairs()
            .into_owned()
            .collect();
        let set_cookie = header_value(response, header::SET_COOKIE);
        let cookie = set_cookie
            .split(';')
            .next()
            .unwrap()
            .to_string();
        Started {
            state: authorization["state"].clone(),
            nonce: authorization["nonce"].clone(),
            cookie,
            authorization,
        }
    }

    /// The provider issues an ID token with `claims` for the next code exchange.
    fn issue(
        &self,
        claims: Value,
    ) {
        self.provider
            .answer_token_requests(
                StatusCode::OK,
                json!({ "id_token": self.provider.id_token(claims), "token_type": "Bearer" }),
            );
    }

    /// Start a sign-in, have the provider issue `adjust`ed claims for it, and
    /// return the callback's response.
    async fn sign_in(
        &self,
        adjust: impl FnOnce(&mut Value),
    ) -> Response<Body> {
        let started = self.start().await;
        let mut claims = id_token_claims(&self.provider.issuer, &started.nonce);
        adjust(&mut claims);
        self.issue(claims);
        self.callback(&started).await
    }

    async fn callback(
        &self,
        started: &Started,
    ) -> Response<Body> {
        self.get(&format!("/oidc/callback?code=the-code&state={}", started.state), Some(&started.cookie))
            .await
    }

    async fn user(&self) -> Option<UserData> {
        self.oidc
            .storage
            .load_user_by_oidc_identity(&OidcIdentity {
                issuer: self.provider.issuer.clone(),
                subject: "user-1".to_string(),
            })
            .await
            .unwrap()
    }

    async fn other_session(
        &self,
        user: &UserData,
    ) -> String {
        self.oidc
            .session_manager
            .create_session(user.username.clone(), user.user_id.clone())
            .await
    }

    async fn session_is_live(
        &self,
        token: &str,
    ) -> bool {
        self.oidc
            .session_manager
            .validate_session(token)
            .await
            .is_some()
    }
}

fn header_value(
    response: &Response<Body>,
    name: header::HeaderName,
) -> &str {
    response
        .headers()
        .get(name)
        .unwrap()
        .to_str()
        .unwrap()
}

fn set_cookies(response: &Response<Body>) -> Vec<String> {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| {
            value
                .to_str()
                .unwrap()
                .to_string()
        })
        .collect()
}

async fn body(response: Response<Body>) -> String {
    String::from_utf8(
        axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

/// The session token the hand-off page stores for the dashboard.
fn handed_off_token(page: &str) -> String {
    page.split("sessionStorage.setItem('session_token', \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn a_new_account_signs_in_and_becomes_a_user_with_its_mapped_role() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    assert_eq!(started.authorization["response_type"], "code");
    assert_eq!(started.authorization["client_id"], CLIENT_ID);
    assert_eq!(started.authorization["redirect_uri"], REDIRECT_URI);
    assert_eq!(started.authorization["scope"], "openid profile");
    assert_eq!(started.authorization["code_challenge_method"], "S256");
    assert!(
        started
            .cookie
            .starts_with(&format!("__Host-oidc_state={}", started.state)),
        "{}",
        started.cookie
    );

    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::OK, "the callback answers with the hand-off page, not a redirect");
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(header_value(&response, header::REFERRER_POLICY), "no-referrer");
    assert!(header_value(&response, header::CONTENT_SECURITY_POLICY).contains("script-src 'nonce-"));
    let cookies = set_cookies(&response);
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("session_token=")),
        "{cookies:?}"
    );
    assert!(
        cookies
            .iter()
            .any(|c| c.starts_with("__Host-oidc_state=;")),
        "the binding cookie is cleared: {cookies:?}"
    );
    let token = handed_off_token(&body(response).await);
    assert!(
        flow.session_is_live(&token)
            .await
    );

    let user = flow.user().await.unwrap();
    assert_eq!(user.username, "alice");
    assert_eq!(user.role, UserRole::Administrator);
    assert_eq!(user.status, UserStatus::Approved);
    assert!(!user.is_primary);

    let requests = flow.provider.token_requests();
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.form["grant_type"], "authorization_code");
    assert_eq!(request.form["code"], "the-code");
    assert_eq!(request.form["redirect_uri"], REDIRECT_URI);
    assert_eq!(
        crate::delegation_vault::oauth::generate_pkce_challenge(&request.form["code_verifier"]),
        started.authorization["code_challenge"],
        "the verifier matches the challenge sent to the provider"
    );
    assert_eq!(
        request
            .authorization
            .as_deref(),
        Some(
            format!(
                "Basic {}",
                base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    format!("{CLIENT_ID}:{CLIENT_SECRET}")
                )
            )
            .as_str()
        )
    );
    assert!(
        !request
            .form
            .contains_key("client_secret"),
        "basic authentication keeps the secret out of the form"
    );
}

#[tokio::test]
async fn client_secret_post_sends_the_credentials_in_the_form() {
    let flow =
        Flow::with_config(|config| config.token_endpoint_auth_method = TokenEndpointAuthMethod::ClientSecretPost).await;

    let response = flow.sign_in(|_| {}).await;

    assert_eq!(response.status(), StatusCode::OK);
    let request = &flow.provider.token_requests()[0];
    assert_eq!(request.authorization, None);
    assert_eq!(request.form["client_id"], CLIENT_ID);
    assert_eq!(request.form["client_secret"], CLIENT_SECRET);
}

#[tokio::test]
async fn a_state_works_once() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    assert_eq!(
        flow.callback(&started)
            .await
            .status(),
        StatusCode::OK
    );

    let replayed = flow.callback(&started).await;

    assert_eq!(replayed.status(), StatusCode::BAD_REQUEST, "an unknown state does not count toward the lockout");
    assert!(
        body(replayed)
            .await
            .contains("Start again from the sign-in page")
    );
}

#[tokio::test]
async fn a_callback_without_this_browsers_binding_cookie_is_refused() {
    let flow = Flow::new().await;
    let other = flow.start().await;

    for cookie in [None, Some(other.cookie.as_str()), Some("__Host-oidc_state=forged")] {
        let restarted = flow.start().await;
        let response = flow
            .get(&format!("/oidc/callback?code=the-code&state={}", restarted.state), cookie)
            .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{cookie:?}");
    }
    assert!(
        flow.provider
            .token_requests()
            .is_empty(),
        "no code is exchanged for an unbound callback"
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn an_unbound_callback_leaves_the_sign_in_waiting() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let foreign = flow
        .get(&format!("/oidc/callback?code=the-code&state={}", started.state), None)
        .await;
    assert_eq!(foreign.status(), StatusCode::BAD_REQUEST);

    flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));
    assert_eq!(
        flow.callback(&started)
            .await
            .status(),
        StatusCode::OK,
        "the browser that started the sign-in can still finish it"
    );
}

#[tokio::test]
async fn in_one_browser_the_most_recently_started_sign_in_finishes() {
    let flow = Flow::new().await;
    let earlier = flow.start().await;
    let later = flow.start().await;

    let stale = flow
        .get(&format!("/oidc/callback?code=the-code&state={}", earlier.state), Some(&later.cookie))
        .await;
    assert_eq!(stale.status(), StatusCode::BAD_REQUEST);
    assert!(
        set_cookies(&stale)
            .iter()
            .all(|cookie| !cookie.starts_with("__Host-oidc_state=")),
        "the newer sign-in's cookie is left in place"
    );

    flow.issue(id_token_claims(&flow.provider.issuer, &later.nonce));
    assert_eq!(
        flow.callback(&later)
            .await
            .status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_provider_refusing_the_sign_in_is_shown_as_such() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let response = flow
        .get(&format!("/oidc/callback?error=access_denied&state={}", started.state), Some(&started.cookie))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        body(response)
            .await
            .contains("did not complete the sign-in")
    );
}

#[tokio::test]
async fn a_failed_code_exchange_is_refused() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.provider
        .answer_token_requests(StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" }));

    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(flow.user().await.is_none());
    flow.start().await;
    assert_eq!(
        flow.provider
            .discovery_fetches(),
        1,
        "an OAuth error keeps the discovery document"
    );
}

#[tokio::test]
async fn a_token_endpoint_that_is_gone_has_the_discovery_document_fetched_again() {
    for status in [StatusCode::NOT_FOUND, StatusCode::BAD_GATEWAY] {
        let flow = Flow::new().await;
        let started = flow.start().await;
        flow.provider
            .answer_token_requests(status, json!({}));

        let response = flow.callback(&started).await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "{status}");
        flow.start().await;
        assert_eq!(
            flow.provider
                .discovery_fetches(),
            2,
            "{status}"
        );
    }
}

#[tokio::test]
async fn an_id_token_for_another_sign_in_is_refused() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["nonce"] = json!("another-sign-ins-nonce"))
        .await;

    assert_eq!(
        response.status(),
        StatusCode::BAD_GATEWAY,
        "the provider's token did not verify, which the caller cannot cause"
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn a_token_endpoint_refusing_this_client_is_a_server_fault() {
    let flow = Flow::new().await;
    let started = flow.start().await;
    flow.provider
        .answer_token_requests(StatusCode::UNAUTHORIZED, json!({ "error": "invalid_client" }));

    let response = flow.callback(&started).await;

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
}

#[tokio::test]
async fn a_callback_without_a_code_is_a_bad_request() {
    let flow = Flow::new().await;
    let started = flow.start().await;

    let response = flow
        .get(&format!("/oidc/callback?state={}", started.state), Some(&started.cookie))
        .await;

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(
        flow.provider
            .token_requests()
            .is_empty()
    );
}

#[tokio::test]
async fn an_account_of_another_tenant_is_refused_before_any_user_is_created() {
    let flow = Flow::new().await;

    let response = flow
        .sign_in(|claims| claims["org_id"] = json!("org_999"))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        body(response)
            .await
            .contains("not allowed to use this dashboard")
    );
    assert!(flow.user().await.is_none());
}

#[tokio::test]
async fn an_account_whose_role_was_removed_upstream_is_refused_and_signed_out_everywhere() {
    let flow = Flow::new().await;
    assert_eq!(
        flow.sign_in(|_| {})
            .await
            .status(),
        StatusCode::OK
    );
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    let response = flow
        .sign_in(|claims| claims["roles"] = json!(["guest"]))
        .await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "the user's other sessions ended"
    );
    assert_eq!(
        flow.user()
            .await
            .unwrap()
            .status,
        UserStatus::Approved,
        "the record is kept"
    );
}

#[tokio::test]
async fn a_changed_role_takes_effect_and_ends_other_sessions_while_an_unchanged_one_keeps_them() {
    let flow = Flow::new().await;
    flow.sign_in(|_| {}).await;
    let user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;

    flow.sign_in(|_| {}).await;
    assert!(
        flow.session_is_live(&elsewhere)
            .await,
        "same role: other sessions continue"
    );

    let response = flow
        .sign_in(|claims| claims["roles"] = json!("member"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        flow.user()
            .await
            .unwrap()
            .role,
        UserRole::User
    );
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "a demotion ends the user's other sessions"
    );
}

#[tokio::test]
async fn a_disabled_user_is_refused_even_with_a_valid_token_and_signed_out_everywhere() {
    let flow = Flow::new().await;
    flow.sign_in(|_| {}).await;
    let mut user = flow.user().await.unwrap();
    let elsewhere = flow
        .other_session(&user)
        .await;
    user.status = UserStatus::Disabled;
    flow.oidc
        .storage
        .save_user(&user)
        .await
        .unwrap();

    let response = flow.sign_in(|_| {}).await;

    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert!(
        !flow
            .session_is_live(&elsewhere)
            .await,
        "the user's other sessions ended"
    );
}

#[tokio::test]
async fn an_unreachable_provider_shows_a_readable_page() {
    let flow = Flow::with_config(|config| config.issuer = "http://127.0.0.1:9".to_string()).await;

    let response = flow
        .get("/oidc/login", None)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body(response)
            .await
            .contains("identity provider could not be reached")
    );
}

/// Where the dashboard opens after the hand-off page: the path the page leaves
/// for the dashboard to restore, or `/`. The page itself only ever loads `/`.
fn handed_off_path(page: &str) -> String {
    assert!(page.contains("window.location.href = '/';"), "{page}");
    page.split("sessionStorage.setItem('post_login_path', \"")
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .map_or_else(|| "/".to_string(), |path| path.replace("\\u0026", "&"))
}

#[tokio::test]
async fn the_providers_link_starts_a_sign_in_by_get_or_post_with_its_login_hint() {
    let flow = Flow::new().await;

    let by_get = flow
        .get(&format!("/oidc/initiate?{}", flow.initiate_query("&login_hint=alice%40example.com")), None)
        .await;
    let started = flow.started(&by_get);
    assert_eq!(started.authorization["login_hint"], "alice@example.com");

    let by_post = flow
        .post_form("/oidc/initiate", &flow.initiate_query("&login_hint=bob%40example.com"))
        .await;
    let started = flow.started(&by_post);
    assert_eq!(started.authorization["login_hint"], "bob@example.com");
    assert!(
        started
            .cookie
            .starts_with("__Host-oidc_state=")
    );

    let plain = flow
        .get(&format!("/oidc/initiate?{}", flow.initiate_query("&login_hint=a%0Ab")), None)
        .await;
    assert!(
        !flow
            .started(&plain)
            .authorization
            .contains_key("login_hint"),
        "a hint with a control character is dropped"
    );
}

#[tokio::test]
async fn a_link_for_another_provider_or_without_one_is_refused() {
    let flow = Flow::new().await;

    for uri in ["/oidc/initiate?iss=https%3A%2F%2Fother.example", "/oidc/initiate", "/oidc/initiate?iss="] {
        let response = flow.get(uri, None).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{uri}");
        assert!(
            body(response)
                .await
                .contains("not for this dashboard"),
            "{uri}"
        );
    }
    let response = flow
        .post_form("/oidc/initiate", "iss=https%3A%2F%2Fother.example")
        .await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn the_dashboard_opens_at_a_target_on_its_own_origin_and_nowhere_else() {
    let flow = Flow::new().await;
    for (target, expected) in [
        ("https%3A%2F%2Fstream.example.com%2Fsurfaces%3Ftab%3Dlogs%26x%3D1", "/surfaces?tab=logs&x=1"),
        ("https%3A%2F%2Fevil.example%2Fsurfaces", "/"),
        ("https%3A%2F%2Fstream.example.com%2F%2Fevil.example", "/"),
        ("%2Fsurfaces", "/"),
    ] {
        let response = flow
            .get(&format!("/oidc/initiate?{}", flow.initiate_query(&format!("&target_link_uri={target}"))), None)
            .await;
        let started = flow.started(&response);
        flow.issue(id_token_claims(&flow.provider.issuer, &started.nonce));

        let page = flow.callback(&started).await;

        assert_eq!(page.status(), StatusCode::OK, "{target}");
        assert_eq!(handed_off_path(&body(page).await), expected, "{target}");
    }
}

#[tokio::test]
async fn a_sign_in_started_at_the_login_page_opens_the_dashboard_home() {
    let flow = Flow::new().await;

    let page = flow.sign_in(|_| {}).await;

    assert_eq!(handed_off_path(&body(page).await), "/");
}

impl Flow {
    /// Sign in with the provider session `sid`, and return the dashboard's
    /// session token.
    async fn signed_in_with_sid(
        &self,
        sid: &str,
    ) -> String {
        let page = self
            .sign_in(|claims| claims["sid"] = json!(sid))
            .await;
        assert_eq!(page.status(), StatusCode::OK);
        handed_off_token(&body(page).await)
    }

    async fn backchannel_logout(
        &self,
        token: &str,
    ) -> Response<Body> {
        self.post_form("/oidc/backchannel-logout", &format!("logout_token={token}"))
            .await
    }

    async fn logout_by(
        &self,
        change: impl FnOnce(&mut Value),
    ) -> Response<Body> {
        let mut claims = logout_claims(&self.provider.issuer, "unused");
        change(&mut claims);
        self.backchannel_logout(&sign_logout(&claims))
            .await
    }
}

#[tokio::test]
async fn a_session_records_the_provider_sign_in_it_came_from() {
    let flow = Flow::new().await;

    let token = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let binding = flow
        .oidc
        .session_manager
        .validate_session_record(&token)
        .await
        .unwrap()
        .oidc
        .unwrap();
    assert_eq!(binding.issuer, flow.provider.issuer);
    assert_eq!(binding.subject, "user-1");
    assert_eq!(binding.sid.as_deref(), Some("op-session-1"));
}

#[tokio::test]
async fn a_logout_naming_a_provider_session_ends_only_that_session() {
    let flow = Flow::new().await;
    let first = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let second = flow
        .signed_in_with_sid("op-session-2")
        .await;

    let response = flow
        .logout_by(|claims| {
            claims["sid"] = json!("op-session-1");
            claims
                .as_object_mut()
                .unwrap()
                .remove("sub");
        })
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert!(
        !flow
            .session_is_live(&first)
            .await
    );
    assert!(
        flow.session_is_live(&second)
            .await,
        "the other provider session continues"
    );
}

#[tokio::test]
async fn a_logout_naming_only_the_account_ends_all_its_sessions() {
    let flow = Flow::new().await;
    let first = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let second = flow
        .signed_in_with_sid("op-session-2")
        .await;

    let response = flow
        .logout_by(|claims| {
            claims
                .as_object_mut()
                .unwrap()
                .remove("sid");
        })
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&first)
            .await
    );
    assert!(
        !flow
            .session_is_live(&second)
            .await
    );
}

#[tokio::test]
async fn a_logout_for_an_unknown_session_still_answers_ok() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let response = flow
        .logout_by(|claims| claims["sid"] = json!("never-seen"))
        .await;

    assert_eq!(response.status(), StatusCode::OK, "a logout is idempotent");
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_token_that_does_not_verify_ends_nothing() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;

    let replayed = sign_logout(&logout_claims(&flow.provider.issuer, "never-seen"));
    assert_eq!(
        flow.backchannel_logout(&replayed)
            .await
            .status(),
        StatusCode::OK
    );
    let mut refused = vec![
        flow.backchannel_logout(&replayed)
            .await,
    ];
    refused.push(
        flow.logout_by(|claims| {
            claims["sid"] = json!("op-session-1");
            claims["nonce"] = json!("n");
        })
        .await,
    );
    refused.push(
        flow.logout_by(|claims| {
            claims["sid"] = json!("op-session-1");
            claims["iss"] = json!("https://other.example");
        })
        .await,
    );
    refused.push(
        flow.backchannel_logout("not-a-token")
            .await,
    );
    refused.push(
        flow.post_form("/oidc/backchannel-logout", "other=1")
            .await,
    );

    for response in refused {
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
        assert_eq!(body(response).await, r#"{"error":"invalid_request"}"#);
    }
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_that_cannot_end_a_session_fails_and_the_provider_can_send_it_again() {
    let failing = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let flow = Flow::with_parts(|_| {}, Arc::new(SessionManager::with_failing_deletes(failing.clone()))).await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let token = sign_logout(&logout_claims(&flow.provider.issuer, "op-session-1"));

    let failed = flow
        .backchannel_logout(&token)
        .await;
    assert_eq!(failed.status(), StatusCode::BAD_REQUEST);
    assert_eq!(header_value(&failed, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(failed).await, r#"{"error":"logout_failed"}"#);
    assert!(
        flow.session_is_live(&session)
            .await
    );

    failing.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        flow.backchannel_logout(&token)
            .await
            .status(),
        StatusCode::OK
    );
    assert!(
        !flow
            .session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_request_that_is_not_a_form_is_refused_like_any_invalid_request() {
    let flow = Flow::new().await;

    let response = flow
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/oidc/backchannel-logout")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(r#"{"logout_token":"x"}"#))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert_eq!(body(response).await, r#"{"error":"invalid_request"}"#);
}

#[tokio::test]
async fn a_logout_whose_keys_cannot_be_fetched_answers_unavailable() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    flow.provider
        .set_jwks(json!("not a key set"));
    let signed_with_a_new_key = crate::auth::oidc::test_support::sign(
        crate::auth::oidc::test_support::KEY_B_PEM,
        Some(crate::auth::oidc::test_support::KEY_B_KID),
        &logout_claims(&flow.provider.issuer, "op-session-1"),
    );

    let response = flow
        .backchannel_logout(&signed_with_a_new_key)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_with_sid_and_sub_ends_that_accounts_sessions_whose_id_token_had_no_sid() {
    let flow = Flow::new().await;
    let page = flow.sign_in(|_| {}).await;
    let without_sid = handed_off_token(&body(page).await);

    let response = flow
        .logout_by(|claims| claims["sid"] = json!("op-session-1"))
        .await;

    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&without_sid)
            .await
    );
}

#[tokio::test]
async fn a_logout_naming_the_account_ends_its_sessions_from_before_sessions_recorded_the_provider_sign_in() {
    let flow = Flow::new().await;
    let bound = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let user = flow.user().await.unwrap();
    let unbound = flow
        .other_session(&user)
        .await;

    let by_sid_only = flow
        .logout_by(|claims| {
            claims["sid"] = json!("op-session-2");
            claims
                .as_object_mut()
                .unwrap()
                .remove("sub");
        })
        .await;
    assert_eq!(by_sid_only.status(), StatusCode::OK);
    assert!(
        flow.session_is_live(&unbound)
            .await,
        "a sid alone cannot name a session without a binding"
    );

    let by_sub = flow
        .logout_by(|claims| {
            claims
                .as_object_mut()
                .unwrap()
                .remove("sid");
        })
        .await;
    assert_eq!(by_sub.status(), StatusCode::OK);
    assert!(
        !flow
            .session_is_live(&unbound)
            .await
    );
    assert!(
        !flow
            .session_is_live(&bound)
            .await
    );
}

#[tokio::test]
async fn a_logout_signed_with_a_key_published_during_the_unknown_key_cooldown_answers_unavailable() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;
    let made_up_kid = crate::auth::oidc::test_support::sign(
        crate::auth::oidc::test_support::KEY_A_PEM,
        Some("made-up"),
        &logout_claims(&flow.provider.issuer, "op-session-1"),
    );
    assert_eq!(
        flow.backchannel_logout(&made_up_kid)
            .await
            .status(),
        StatusCode::BAD_REQUEST,
        "a key the provider does not publish, just fetched again"
    );

    flow.provider
        .rotate_to_key_b();
    let signed_with_the_new_key = crate::auth::oidc::test_support::sign(
        crate::auth::oidc::test_support::KEY_B_PEM,
        Some(crate::auth::oidc::test_support::KEY_B_KID),
        &logout_claims(&flow.provider.issuer, "op-session-1"),
    );
    let response = flow
        .backchannel_logout(&signed_with_the_new_key)
        .await;

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE, "the provider retries after the cooldown");
    assert!(
        flow.session_is_live(&session)
            .await
    );
}

#[tokio::test]
async fn a_logout_posted_to_a_standby_answers_unavailable_and_ends_nothing() {
    let flow = Flow::new().await;
    let session = flow
        .signed_in_with_sid("op-session-1")
        .await;

    crate::server::mode::set_server_mode(crate::server::mode::ServerMode::Standby);
    let response = flow
        .logout_by(|claims| claims["sid"] = json!("op-session-1"))
        .await;
    crate::server::mode::set_server_mode(crate::server::mode::ServerMode::Active);
    assert!(crate::server::mode::mark_activation_ready(crate::server::mode::current_activation_generation()));

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(header_value(&response, header::CACHE_CONTROL), "no-store");
    assert!(
        flow.session_is_live(&session)
            .await
    );
}
