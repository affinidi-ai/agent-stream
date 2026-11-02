use crate::world::SurfaceWorld;

pub(crate) const DEFAULT_CALLER_PROMPT: &str = "Say hello through Agent Stream";
use serde_json::json;

pub(crate) async fn invoke_surface_and_require_success(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    let route = route_for_surface(world, surface_name);
    send_chat_prompt(world, &route, "Consume governed usage").await;
    assert_caller_success(world, "initial governed request");
}

pub(crate) async fn invoke_surface_as_member_and_require_success(
    world: &mut SurfaceWorld,
    member_name: &str,
    surface_name: &str,
) {
    send_member_chat_completion(world, member_name, surface_name).await;
    assert_caller_success(world, "initial member request");
}

pub(crate) fn assert_caller_success(
    world: &SurfaceWorld,
    request_name: &str,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 200, "expected {request_name} to succeed, got {}: {}", response.status, response.text);
}

pub(crate) async fn send_chat_completion_to_variant_with_header(
    world: &mut SurfaceWorld,
    surface_name: &str,
    alias: &str,
    header: Option<(&str, &str)>,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}${alias}/v1/chat/completions", route.trim_end_matches('/'));
    let body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    let response = match header {
        Some((name, value)) => {
            world
                .admin_client()
                .post_caller_json_with_header(&path, body, name, value)
                .await
        }
        None => {
            world
                .admin_client()
                .post_caller_json(&path, body)
                .await
        }
    };
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

pub(crate) async fn send_chat_completion_to_surface(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    let route = route_for_surface(world, surface_name);
    send_chat_prompt(world, &route, DEFAULT_CALLER_PROMPT).await;
}

pub(crate) async fn send_chat_completion_with_jwt(
    world: &mut SurfaceWorld,
    surface_name: &str,
    valid: bool,
) {
    const ISSUER: &str = "https://issuer.example.test";
    const AUDIENCE: &str = "agent-stream";
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let token = if valid {
        crate::bdd_support::jwt::signed_token(ISSUER, AUDIENCE)
    } else {
        crate::bdd_support::jwt::invalid_token(ISSUER, AUDIENCE)
    };
    world.caller_response = Some(
        world
            .admin_client()
            .post_caller_json_with_bearer_token(&path, chat_completion_body(DEFAULT_CALLER_PROMPT), &token)
            .await,
    );
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
}

pub(crate) async fn invoke_ide_model(
    world: &mut SurfaceWorld,
    surface_name: &str,
    model: &str,
    header: Option<(&str, &str)>,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let body = json!({
        "model": model,
        "messages": [{ "role": "user", "content": DEFAULT_CALLER_PROMPT }]
    });
    world.caller_response = Some(match header {
        Some((name, value)) => {
            world
                .admin_client()
                .post_caller_json_with_header(&path, body, name, value)
                .await
        }
        None => {
            world
                .admin_client()
                .post_caller_json(&path, body)
                .await
        }
    });
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
}

pub(crate) async fn send_chat_completion_to_surface_with_api_key(
    world: &mut SurfaceWorld,
    surface_name: &str,
    api_key: &str,
) {
    let route = route_for_surface(world, surface_name);
    send_chat_prompt_with_api_key(world, &route, DEFAULT_CALLER_PROMPT, api_key).await;
}

pub(crate) fn route_for_surface(
    world: &SurfaceWorld,
    surface_name: &str,
) -> String {
    world
        .surface_routes
        .get(surface_name)
        .unwrap_or_else(|| panic!("Surface {surface_name:?} should have a route"))
        .clone()
}

pub(crate) async fn send_streaming_chat_prompt(
    world: &mut SurfaceWorld,
    route: &str,
    prompt: &str,
) {
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let mut body = chat_completion_body(prompt);
    body["stream"] = json!(true);
    let response = world
        .admin_client()
        .post_caller_json(&path, body)
        .await;
    world.last_caller_prompt = Some(prompt.to_string());
    world.caller_response = Some(response);
}

pub(crate) async fn send_member_chat_completion(
    world: &mut SurfaceWorld,
    member_name: &str,
    surface_name: &str,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, member_name);
    let response = world
        .admin_client()
        .post_caller_json_with_header(&path, chat_completion_body(DEFAULT_CALLER_PROMPT), &header, &value)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

/// The provider key a caller brings to a Surface that accepts one.
pub(crate) const CALLER_PROVIDER_KEY: &str = "sk-bdd-caller-own-key";

/// The header a caller sends its own provider key in when the Surface's front
/// door reads `Authorization`. It is also the dual-token channel for a
/// caller's upstream identity.
pub(crate) const UPSTREAM_AUTHORIZATION: &str = "X-Agent-Stream-Upstream-Authorization";

/// A caller's upstream identity token (as a Graph token for a Microsoft 365
/// Copilot member), sent in [`UPSTREAM_AUTHORIZATION`].
pub(crate) const UPSTREAM_IDENTITY_TOKEN: &str = "Bearer bdd-upstream-identity-token";

/// The operator's provider key a Surface stores.
pub(crate) const OPERATOR_PROVIDER_KEY: &str = "sk-bdd-operator-key";

/// Send a chat completion to `surface_name` as an unidentified caller, with
/// `headers`.
pub(crate) async fn send_chat_completion_with_headers<const N: usize>(
    world: &mut SurfaceWorld,
    surface_name: &str,
    headers: [(&str, &str); N],
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json_with_headers(&path, chat_completion_body(DEFAULT_CALLER_PROMPT), headers)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

/// Send a chat completion as `member_name`, carrying the caller's own provider
/// key as `Authorization: Bearer`.
pub(crate) async fn send_member_chat_completion_with_provider_key(
    world: &mut SurfaceWorld,
    member_name: &str,
    surface_name: &str,
    provider_key: &str,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, member_name);
    let authorization = format!("Bearer {provider_key}");
    let response = world
        .admin_client()
        .post_caller_json_with_headers(
            &path,
            chat_completion_body(DEFAULT_CALLER_PROMPT),
            [(header.as_str(), value.as_str()), ("Authorization", authorization.as_str())],
        )
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

pub(crate) fn member_identity_header(
    world: &SurfaceWorld,
    member_name: &str,
) -> (String, String) {
    world
        .member_headers
        .get(member_name)
        .unwrap_or_else(|| panic!("member {member_name:?} should have an identity header"))
        .clone()
}

pub(crate) async fn send_chat_prompt(
    world: &mut SurfaceWorld,
    route: &str,
    prompt: &str,
) {
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let body = chat_completion_body(prompt);

    let response = world
        .admin_client()
        .post_caller_json(&path, body)
        .await;
    world.last_caller_prompt = Some(prompt.to_string());
    world.caller_response = Some(response);
}

pub(crate) async fn send_chat_prompt_with_api_key(
    world: &mut SurfaceWorld,
    route: &str,
    prompt: &str,
    api_key: &str,
) {
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let body = chat_completion_body(prompt);

    let response = world
        .admin_client()
        .post_caller_json_with_api_key(&path, body, api_key)
        .await;
    world.last_caller_prompt = Some(prompt.to_string());
    world.caller_response = Some(response);
}

/// Send a chat completion body to the Surface's discovery path
/// (`{route}/discovery`) instead of a chat endpoint, with an optional header.
pub(crate) async fn send_chat_completion_to_discovery_path(
    world: &mut SurfaceWorld,
    surface_name: &str,
    header: Option<(&str, &str)>,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/discovery", route.trim_end_matches('/'));
    let body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    let response = match header {
        Some((name, value)) => {
            world
                .admin_client()
                .post_caller_json_with_header(&path, body, name, value)
                .await
        }
        None => {
            world
                .admin_client()
                .post_caller_json(&path, body)
                .await
        }
    };
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

/// A provider request an LLM Surface forwards for a caller, by the name
/// scenarios use for it.
pub(crate) struct ProviderOperation {
    pub method: &'static str,
    pub path: &'static str,
    pub body: OperationBody,
}

pub(crate) enum OperationBody {
    None,
    Multipart,
    Json(serde_json::Value),
}

impl ProviderOperation {
    /// Whether the provider records this request as a chat completion rather
    /// than by method and path.
    pub(crate) fn is_chat_completion(&self) -> bool {
        self.path == "/v1/chat/completions"
    }
}

pub(crate) fn provider_operation(name: &str) -> ProviderOperation {
    let (method, path, body) = match name {
        "model list" => ("GET", "/v1/models", OperationBody::None),
        "file list" => ("GET", "/v1/files", OperationBody::None),
        "batch list" => ("GET", "/v1/batches", OperationBody::None),
        "file upload" => ("POST", "/v1/files", OperationBody::Multipart),
        "audio transcription" => ("POST", "/v1/audio/transcriptions", OperationBody::Multipart),
        "audio translation" => ("POST", "/v1/audio/translations", OperationBody::Multipart),
        "vector store creation" => (
            "POST",
            "/v1/vector_stores",
            OperationBody::Json(json!({ "name": "notes", "file_ids": ["file-of-another-tenant"] })),
        ),
        "chat completion naming a stored file" => (
            "POST",
            "/v1/chat/completions",
            OperationBody::Json(json!({
                "model": "mock-small",
                "messages": [{ "role": "user", "content": [
                    { "type": "text", "text": DEFAULT_CALLER_PROMPT },
                    { "type": "file", "file": { "file_id": "file-of-another-tenant" } }
                ] }]
            })),
        ),
        other => panic!("unknown provider operation {other:?}"),
    };
    ProviderOperation { method, path, body }
}

/// Send `operation_name` to the LLM Surface, with `header` when given.
pub(crate) async fn send_provider_operation(
    world: &mut SurfaceWorld,
    operation_name: &str,
    surface_name: &str,
    header: Option<(&str, &str)>,
) {
    let operation = provider_operation(operation_name);
    let route = route_for_surface(world, surface_name);
    let path = format!("{}{}", route.trim_end_matches('/'), operation.path);
    let client = world.admin_client();
    let response = match (operation.body, header) {
        (OperationBody::Multipart, header) => {
            let form = reqwest::multipart::Form::new()
                .text("model", "mock-small")
                .text("purpose", "batch")
                .part("file", reqwest::multipart::Part::bytes(b"RIFF".to_vec()).file_name("clip.wav"));
            client
                .post_caller_multipart(&path, form, header)
                .await
        }
        (OperationBody::Json(body), Some((name, value))) => {
            client
                .post_caller_json_with_header(&path, body, name, value)
                .await
        }
        (OperationBody::Json(body), None) => {
            client
                .post_caller_json(&path, body)
                .await
        }
        (OperationBody::None, Some((name, value))) => {
            client
                .get_caller_json_with_header(&path, name, value)
                .await
        }
        (OperationBody::None, None) => {
            client
                .get_caller_json_with_header(&path, "Accept", "application/json")
                .await
        }
    };
    world.caller_response = Some(response);
}

/// Ask the Surface for a VP challenge (`POST {route}/v1/vp-challenge`) without caller credentials.
pub(crate) async fn request_vp_challenge(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    let route = route_for_surface(world, surface_name);
    let path = format!("{}/v1/vp-challenge", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json(&path, json!({}))
        .await;
    world.caller_response = Some(response);
}

pub(crate) fn chat_completion_body(prompt: &str) -> serde_json::Value {
    json!({
        "model": "mock-small",
        "messages": [
            { "role": "user", "content": prompt }
        ]
    })
}
