//! A stub OpenID provider for the OIDC tests: discovery, a JWKS with P-256
//! keys, and a token endpoint, served on a loopback port.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use axum::{
    Form, Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use url::Url;

use super::config::{
    ClaimNames, ClientSecret, LogoutSettings, OidcConfig, RoleMapping, TokenEndpointAuthMethod, ValueMatcher,
};
use super::discovery::ProviderMetadata;
use crate::auth::types::UserRole;
use crate::jwt_bearer::JwksClient;
use crate::jwt_bearer::test_utils::TestServer;

pub const CLIENT_ID: &str = "agent-stream";
pub const CLIENT_SECRET: &str = "s3cret";
pub const REDIRECT_URI: &str = "https://stream.example.com/api/oidc/callback";

pub const KEY_A_KID: &str = "key-a";
pub const KEY_A_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgnUDp7RqR0YCACjhJ
CtFwK21yzRUZ2KJrJRsIUPYB96uhRANCAARHEHBxApKlkjyRY+iPcVEe5JqTSg1Q
VDW9tFa4HzliG8/rJ69dHpIcsLgcCwKGofE4X3tVKDgzkWvXYrZ23hoc
-----END PRIVATE KEY-----";
const KEY_A_X: &str = "RxBwcQKSpZI8kWPoj3FRHuSak0oNUFQ1vbRWuB85Yhs";
const KEY_A_Y: &str = "z-snr10ekhywuBwLAoah8Thfe1UoODORa9ditnbeGhw";

pub const KEY_B_KID: &str = "key-b";
pub const KEY_B_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHcmtEx5shvEnipLX
FHBe5mfm3yxzDWzxQwfJWxjgKC2hRANCAATvVbALMgTJyQO2T7XJm5eNqJ82CUDT
0PaX6lHEw7Pzqh/Xzu/qR7Vzq7+60FVzyygBcGHFlr+OBvAu0wLIeAMV
-----END PRIVATE KEY-----";
const KEY_B_X: &str = "71WwCzIEyckDtk-1yZuXjaifNglA09D2l-pRxMOz86o";
const KEY_B_Y: &str = "H9fO7-pHtXOrv7rQVXPLKAFwYcWWv44G8C7TAsh4AxU";

fn jwk(
    kid: &str,
    x: &str,
    y: &str,
) -> Value {
    json!({ "kty": "EC", "crv": "P-256", "use": "sig", "kid": kid, "x": x, "y": y })
}

/// An ES256 JWT over `claims`, signed with the PKCS#8 key `pem`.
pub fn sign(
    pem: &str,
    kid: Option<&str>,
    claims: &Value,
) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = kid.map(str::to_string);
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_pem(pem.as_bytes()).unwrap()).unwrap()
}

/// An ES256 logout token over `claims`, typed `logout+jwt` and signed with
/// the provider's key.
pub fn sign_logout(claims: &Value) -> String {
    let mut header = Header::new(Algorithm::ES256);
    header.typ = Some("logout+jwt".to_string());
    header.kid = Some(KEY_A_KID.to_string());
    jsonwebtoken::encode(&header, claims, &EncodingKey::from_ec_pem(KEY_A_PEM.as_bytes()).unwrap()).unwrap()
}

/// The claims of a valid logout token from `issuer`, for the account
/// `user-1` and the provider session `sid`.
pub fn logout_claims(
    issuer: &str,
    sid: &str,
) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 120,
        "jti": uuid::Uuid::new_v4().to_string(),
        "sub": "user-1",
        "sid": sid,
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
    })
}

/// The claims of a valid ID token for `issuer` and the sign-in with `nonce`:
/// an administrator of `org_123`.
pub fn id_token_claims(
    issuer: &str,
    nonce: &str,
) -> Value {
    let now = chrono::Utc::now().timestamp();
    json!({
        "iss": issuer,
        "aud": CLIENT_ID,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
        "nonce": nonce,
        "preferred_username": "alice",
        "email": "alice@example.com",
        "given_name": "Alice",
        "family_name": "Smith",
        "org_id": "org_123",
        "roles": ["admin"],
    })
}

/// A checked configuration for `issuer`, as `oidc.json` would give it: the
/// `org_id` binding and a `roles` mapping that refuses unmapped accounts.
pub fn config_for(issuer: &str) -> OidcConfig {
    OidcConfig {
        label: "Example IdP".to_string(),
        issuer: issuer.to_string(),
        client_id: CLIENT_ID.to_string(),
        client_secret: ClientSecret(CLIENT_SECRET.to_string()),
        token_endpoint_auth_method: TokenEndpointAuthMethod::ClientSecretBasic,
        redirect_uri: Url::parse(REDIRECT_URI).unwrap(),
        scopes: vec!["openid".to_string(), "profile".to_string()],
        id_token_signing_algs: vec![Algorithm::ES256],
        claims: ClaimNames::default(),
        required_claims: BTreeMap::from([("org_id".to_string(), vec![ValueMatcher::Exact("org_123".to_string())])]),
        role_mapping: RoleMapping {
            claim: "roles".to_string(),
            values: vec![
                (ValueMatcher::Exact("admin".to_string()), UserRole::Administrator),
                (ValueMatcher::Exact("member".to_string()), UserRole::User),
            ],
            unmapped: None,
        },
        logout: LogoutSettings::default(),
    }
}

pub fn metadata_for(issuer: &str) -> ProviderMetadata {
    ProviderMetadata {
        issuer: issuer.to_string(),
        authorization_endpoint: format!("{issuer}/authorize"),
        token_endpoint: format!("{issuer}/token"),
        jwks_uri: format!("{issuer}/jwks"),
        token_endpoint_auth_methods_supported: None,
        id_token_signing_alg_values_supported: None,
        code_challenge_methods_supported: Some(vec!["S256".to_string()]),
        backchannel_logout_supported: Some(true),
        end_session_endpoint: Some(format!("{issuer}/logout")),
    }
}

/// A token request as the stub received it.
#[derive(Debug, Clone)]
pub struct TokenRequest {
    pub authorization: Option<String>,
    pub form: BTreeMap<String, String>,
}

struct StubState {
    issuer: String,
    end_session: bool,
    jwks: Value,
    jwks_fetches: usize,
    discovery_fetches: usize,
    discovery_down: bool,
    token_answer: (StatusCode, Value),
    token_requests: Vec<TokenRequest>,
}

/// The stub provider. It stops when dropped.
pub struct StubProvider {
    pub issuer: String,
    state: Arc<Mutex<StubState>>,
    _server: TestServer,
}

impl StubProvider {
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let state = Arc::new(Mutex::new(StubState {
            issuer: issuer.clone(),
            end_session: true,
            jwks: json!({ "keys": [jwk(KEY_A_KID, KEY_A_X, KEY_A_Y)] }),
            jwks_fetches: 0,
            discovery_fetches: 0,
            discovery_down: false,
            token_answer: (StatusCode::BAD_REQUEST, json!({ "error": "invalid_grant" })),
            token_requests: Vec::new(),
        }));
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(discovery))
            .route("/jwks", get(jwks))
            .route("/token", post(token))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .unwrap();
        });
        Self {
            issuer,
            state,
            _server: TestServer(server),
        }
    }

    pub fn jwks_uri(&self) -> String {
        format!("{}/jwks", self.issuer)
    }

    pub fn token_endpoint(&self) -> String {
        format!("{}/token", self.issuer)
    }

    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.issuer)
    }

    pub fn jwks_client(&self) -> JwksClient {
        JwksClient::new(reqwest::Client::new())
    }

    /// An ID token signed with the provider's current key.
    pub fn id_token(
        &self,
        claims: Value,
    ) -> String {
        sign(KEY_A_PEM, Some(KEY_A_KID), &claims)
    }

    pub fn set_jwks(
        &self,
        jwks: Value,
    ) {
        self.state
            .lock()
            .unwrap()
            .jwks = jwks;
    }

    /// Key A as published with an explicit `alg`.
    pub fn jwk_a_with_alg(
        &self,
        alg: &str,
    ) -> Value {
        let mut key = jwk(KEY_A_KID, KEY_A_X, KEY_A_Y);
        key["alg"] = json!(alg);
        key
    }

    /// Publish key B in place of key A.
    pub fn rotate_to_key_b(&self) {
        self.set_jwks(json!({ "keys": [jwk(KEY_B_KID, KEY_B_X, KEY_B_Y)] }));
    }

    pub fn jwks_fetches(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .jwks_fetches
    }

    pub fn discovery_fetches(&self) -> usize {
        self.state
            .lock()
            .unwrap()
            .discovery_fetches
    }

    /// Answer discovery requests with `503` while `down` is true.
    pub fn set_discovery_down(
        &self,
        down: bool,
    ) {
        self.state
            .lock()
            .unwrap()
            .discovery_down = down;
    }

    /// Answer the next token requests with `status` and `body`.
    pub fn answer_token_requests(
        &self,
        status: StatusCode,
        body: Value,
    ) {
        self.state
            .lock()
            .unwrap()
            .token_answer = (status, body);
    }

    /// Publish no `end_session_endpoint` in discovery.
    pub fn without_end_session(&self) {
        self.state
            .lock()
            .unwrap()
            .end_session = false;
    }

    pub fn token_requests(&self) -> Vec<TokenRequest> {
        self.state
            .lock()
            .unwrap()
            .token_requests
            .clone()
    }
}

async fn discovery(State(state): State<Arc<Mutex<StubState>>>) -> (StatusCode, Json<Value>) {
    let (issuer, end_session) = {
        let mut state = state.lock().unwrap();
        state.discovery_fetches += 1;
        if state.discovery_down {
            return (StatusCode::SERVICE_UNAVAILABLE, Json(json!({})));
        }
        (state.issuer.clone(), state.end_session)
    };
    let mut document = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "id_token_signing_alg_values_supported": ["ES256"],
        "backchannel_logout_supported": true,
    });
    if end_session {
        document["end_session_endpoint"] = json!(format!("{issuer}/logout"));
    }
    (StatusCode::OK, Json(document))
}

async fn jwks(State(state): State<Arc<Mutex<StubState>>>) -> Json<Value> {
    let mut state = state.lock().unwrap();
    state.jwks_fetches += 1;
    Json(state.jwks.clone())
}

async fn token(
    State(state): State<Arc<Mutex<StubState>>>,
    headers: HeaderMap,
    Form(form): Form<BTreeMap<String, String>>,
) -> (StatusCode, Json<Value>) {
    let mut state = state.lock().unwrap();
    state
        .token_requests
        .push(TokenRequest {
            authorization: headers
                .get(axum::http::header::AUTHORIZATION)
                .and_then(|value| value.to_str().ok())
                .map(str::to_string),
            form,
        });
    let (status, body) = state.token_answer.clone();
    (status, Json(body))
}
