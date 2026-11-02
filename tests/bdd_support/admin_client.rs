use std::collections::HashMap;

use serde_json::Value;

#[derive(Debug, Clone)]
pub struct RecordedResponse {
    pub status: u16,
    pub body: Value,
    pub text: String,
    pub headers: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub struct AdminClient {
    base_url: String,
    admin_prefix: String,
    token: Option<String>,
    client: reqwest::Client,
}

impl AdminClient {
    pub async fn login(
        base_url: &str,
        test_token: &str,
        username: &str,
    ) -> Self {
        let (client, response) = Self::login_with_role(base_url, test_token, username, "administrator").await;
        assert!(response.status < 400, "test-auth login failed with {}: {}", response.status, response.text);
        client
    }

    pub async fn login_with_role(
        base_url: &str,
        test_token: &str,
        username: &str,
        role: &str,
    ) -> (Self, RecordedResponse) {
        let client = reqwest::Client::new();
        let admin_prefix = resolve_admin_prefix(&client, base_url).await;
        let url = format!("{base_url}{admin_prefix}/internal/test-support/auth/login");
        let response = client
            .post(url)
            .header("X-Test-Token", test_token)
            .json(&serde_json::json!({ "username": username, "role": role }))
            .send()
            .await
            .expect("test-auth login request should complete");
        let recorded = recorded_response(response).await;
        let token = recorded
            .body
            .get("session_token")
            .and_then(Value::as_str)
            .map(str::to_string);

        (
            Self {
                base_url: base_url.to_string(),
                admin_prefix,
                token,
                client,
            },
            recorded,
        )
    }

    /// The same client authenticating with `token` (such as a management
    /// access token) instead of its session.
    pub fn with_bearer(
        &self,
        token: &str,
    ) -> Self {
        Self {
            token: Some(token.to_string()),
            ..self.clone()
        }
    }

    pub async fn create_pipe(
        &self,
        pipe: Value,
    ) -> RecordedResponse {
        self.request("POST", "/v1/pipes", Some(pipe))
            .await
    }

    pub async fn get_pipe(
        &self,
        pipe_id: &str,
    ) -> RecordedResponse {
        self.request("GET", &format!("/v1/pipes/{pipe_id}"), None)
            .await
    }

    pub async fn update_pipe(
        &self,
        pipe_id: &str,
        pipe: Value,
    ) -> RecordedResponse {
        self.request("PUT", &format!("/v1/pipes/{pipe_id}"), Some(pipe))
            .await
    }

    pub async fn delete_pipe(
        &self,
        pipe_id: &str,
    ) -> RecordedResponse {
        self.request("DELETE", &format!("/v1/pipes/{pipe_id}"), None)
            .await
    }

    pub async fn create_policy_definition(
        &self,
        policy: Value,
    ) -> RecordedResponse {
        self.request("POST", "/v1/policy-definitions", Some(policy))
            .await
    }

    pub async fn create_jwt_verification_strategy(
        &self,
        strategy: Value,
    ) -> RecordedResponse {
        self.request("POST", "/v1/jwt-verification-strategies", Some(strategy))
            .await
    }

    pub async fn create_member(
        &self,
        member: Value,
    ) -> RecordedResponse {
        self.request("POST", "/v1/members", Some(member))
            .await
    }

    pub async fn create_team(
        &self,
        team: Value,
    ) -> RecordedResponse {
        self.request("POST", "/v1/teams", Some(team))
            .await
    }

    pub async fn get_admin_json(
        &self,
        path: &str,
    ) -> RecordedResponse {
        self.request("GET", path, None)
            .await
    }

    pub async fn post_admin_json(
        &self,
        path: &str,
        body: Value,
    ) -> RecordedResponse {
        self.request("POST", path, Some(body))
            .await
    }

    pub async fn delete_admin_json(
        &self,
        path: &str,
    ) -> RecordedResponse {
        self.request("DELETE", path, None)
            .await
    }

    pub async fn put_admin_json(
        &self,
        path: &str,
        body: Value,
    ) -> RecordedResponse {
        self.request("PUT", path, Some(body))
            .await
    }

    pub async fn accept_current_terms(&self) -> RecordedResponse {
        let status = self
            .get_admin_json("/v1/terms/status")
            .await;
        assert_eq!(status.status, 200, "Terms status should succeed: {}", status.text);
        let accepted_terms = status
            .body
            .get("required_terms")
            .and_then(Value::as_array)
            .expect("Terms status should include required_terms")
            .iter()
            .map(|term| {
                serde_json::json!({
                    "terms_type": term["terms_type"],
                    "version_id": term["version_id"],
                    "accepted": true,
                })
            })
            .collect::<Vec<_>>();
        self.post_admin_json("/v1/terms/acceptances", serde_json::json!({ "accepted_terms": accepted_terms }))
            .await
    }

    pub async fn get_admin_json_with_bearer(
        &self,
        path: &str,
        token: &str,
    ) -> RecordedResponse {
        let url = format!("{}{}{}", self.base_url, self.admin_prefix, path);
        let response = self
            .client
            .get(url)
            .bearer_auth(token)
            .send()
            .await
            .expect("management access-token request should complete");
        recorded_response(response).await
    }

    pub async fn create_secret(
        &self,
        name: &str,
        secret_id: &str,
        value: &str,
    ) -> RecordedResponse {
        let body = serde_json::json!({
            "name": name,
            "secret_id": secret_id,
            "value": value,
            "secret_type": "API Key",
            "tags": ["bdd"]
        });
        self.request_at_base("POST", "/api/v1/secrets/new", Some(body))
            .await
    }

    pub async fn list_secrets(&self) -> RecordedResponse {
        self.request_at_base("GET", "/api/v1/secrets", None)
            .await
    }

    /// `id` is the secret's internal id, not its public `secret_id`.
    pub async fn delete_secret(
        &self,
        id: &str,
    ) -> RecordedResponse {
        self.request_at_base("DELETE", &format!("/api/v1/secrets/{id}"), None)
            .await
    }

    pub async fn get_caller_json(
        &self,
        path: &str,
    ) -> RecordedResponse {
        self.request_at_base("GET", path, None)
            .await
    }

    pub async fn get_caller_json_with_api_key(
        &self,
        path: &str,
        api_key: &str,
    ) -> RecordedResponse {
        self.get_caller_json_with_header(path, "X-API-Key", api_key)
            .await
    }

    pub async fn get_caller_json_with_access_tier(
        &self,
        path: &str,
        access_tier: &str,
    ) -> RecordedResponse {
        self.get_caller_json_with_header(path, "X-Access-Tier", access_tier)
            .await
    }

    pub async fn get_caller_json_with_header(
        &self,
        path: &str,
        name: &str,
        value: &str,
    ) -> RecordedResponse {
        let response = self
            .client
            .get(format!("{}{}", self.base_url, path))
            .header(name, value)
            .send()
            .await
            .expect("caller request should complete");
        recorded_response(response).await
    }

    pub async fn post_caller_json(
        &self,
        path: &str,
        body: Value,
    ) -> RecordedResponse {
        self.post_caller_json_with_headers(path, body, [])
            .await
    }

    pub async fn post_caller_json_with_api_key(
        &self,
        path: &str,
        body: Value,
        api_key: &str,
    ) -> RecordedResponse {
        self.post_caller_json_with_headers(path, body, [("X-API-Key", api_key)])
            .await
    }

    pub async fn post_caller_json_with_bearer_token(
        &self,
        path: &str,
        body: Value,
        token: &str,
    ) -> RecordedResponse {
        let authorization = format!("Bearer {token}");
        self.post_caller_json_with_headers(path, body, [("Authorization", authorization.as_str())])
            .await
    }

    pub async fn post_caller_json_with_access_tier(
        &self,
        path: &str,
        body: Value,
        access_tier: &str,
    ) -> RecordedResponse {
        self.post_caller_json_with_headers(path, body, [("X-Access-Tier", access_tier)])
            .await
    }

    pub async fn post_caller_json_with_header(
        &self,
        path: &str,
        body: Value,
        name: &str,
        value: &str,
    ) -> RecordedResponse {
        self.post_caller_json_with_headers(path, body, [(name, value)])
            .await
    }

    pub async fn post_caller_multipart(
        &self,
        path: &str,
        form: reqwest::multipart::Form,
        header: Option<(&str, &str)>,
    ) -> RecordedResponse {
        let mut request = self
            .client
            .post(format!("{}{}", self.base_url, path))
            .multipart(form);
        if let Some((name, value)) = header {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .expect("caller request should complete");
        recorded_response(response).await
    }

    pub async fn create_tenant_secret(
        &self,
        secret_id: &str,
        value: &str,
        tenant_id: &str,
    ) -> RecordedResponse {
        let body = serde_json::json!({
            "name": secret_id,
            "secret_id": secret_id,
            "value": value,
            "secret_type": "API Key",
            "tags": ["bdd"],
            "tenant_id": tenant_id
        });
        self.request_at_base("POST", "/api/v1/secrets/new", Some(body))
            .await
    }

    pub async fn post_caller_json_with_headers<'a, const N: usize>(
        &self,
        path: &str,
        body: Value,
        headers: [(&'a str, &'a str); N],
    ) -> RecordedResponse {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self
            .client
            .post(url)
            .json(&body);
        for (name, value) in headers {
            request = request.header(name, value);
        }
        let response = request
            .send()
            .await
            .expect("caller request should complete");
        recorded_response(response).await
    }

    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> RecordedResponse {
        self.request_to_url(method, &format!("{}{}{}", self.base_url, self.admin_prefix, path), body)
            .await
    }

    async fn request_at_base(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> RecordedResponse {
        self.request_to_url(method, &format!("{}{}", self.base_url, path), body)
            .await
    }

    async fn request_to_url(
        &self,
        method: &str,
        url: &str,
        body: Option<Value>,
    ) -> RecordedResponse {
        let mut request = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PUT" => self.client.put(url),
            "DELETE" => self.client.delete(url),
            other => panic!("unsupported admin method {other}"),
        };
        if let Some(token) = &self.token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.json(&body);
        }
        let response = request
            .send()
            .await
            .expect("admin request should complete");
        recorded_response(response).await
    }
}

async fn resolve_admin_prefix(
    client: &reqwest::Client,
    base_url: &str,
) -> String {
    for prefix in ["", "/api"] {
        let url = format!("{base_url}{prefix}/v1/auth/mode");
        if let Ok(response) = client.get(url).send().await
            && response.status().is_success()
        {
            return prefix.to_string();
        }
    }
    String::new()
}

async fn recorded_response(response: reqwest::Response) -> RecordedResponse {
    let status = response.status().as_u16();
    let headers = response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            Some((
                name.to_string(),
                value
                    .to_str()
                    .ok()?
                    .to_string(),
            ))
        })
        .collect();
    let text = response
        .text()
        .await
        .expect("response body should be readable");
    let body = serde_json::from_str(&text).unwrap_or(Value::Null);
    RecordedResponse { status, body, text, headers }
}
