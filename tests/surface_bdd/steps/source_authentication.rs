use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "secret {string} contains caller API key {string}")]
async fn secret_contains_caller_api_key(
    world: &mut SurfaceWorld,
    secret_id: String,
    api_key: String,
) {
    world.ensure_operator().await;
    let response = world
        .admin_client()
        .create_secret(&secret_id, &secret_id, &api_key)
        .await;
    assert_eq!(
        response.status, 201,
        "expected caller API key secret creation to succeed, got {}: {}",
        response.status, response.text
    );
}

#[given(expr = "LLM Surface {string} requires {string} source authentication using secret {string}")]
async fn llm_surface_requires_source_auth_using_secret(
    world: &mut SurfaceWorld,
    surface_name: String,
    source_auth_type: String,
    secret_id: String,
) {
    configure_api_key_source_auth(world, &surface_name, &source_auth_type, &secret_id).await;
}

#[given(expr = "IDE Surface {string} requires {string} source authentication using secret {string}")]
async fn ide_surface_requires_source_auth_using_secret(
    world: &mut SurfaceWorld,
    surface_name: String,
    source_auth_type: String,
    secret_id: String,
) {
    configure_api_key_source_auth(world, &surface_name, &source_auth_type, &secret_id).await;
}

#[given(expr = "LLM Surface {string} requires JWT source authentication for issuer {string} and audience {string}")]
async fn llm_surface_requires_jwt_source_auth(
    world: &mut SurfaceWorld,
    surface_name: String,
    issuer: String,
    audience: String,
) {
    world.ensure_operator().await;
    let response = world
        .admin_client()
        .create_jwt_verification_strategy(json!({
            "name": format!("{surface_name} BDD issuer"),
            "expected_issuer": issuer,
            "jwks_source": crate::bdd_support::jwt::static_jwks_source()
        }))
        .await;
    assert_eq!(
        response.status, 201,
        "expected JWT strategy creation to succeed, got {}: {}",
        response.status, response.text
    );
    let strategy_id = response.body["id"]
        .as_str()
        .expect("JWT strategy response should include id")
        .to_string();
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["source_auth"] = json!({
                "type": "jwt_bearer",
                "jwt_verification_strategy_id": strategy_id,
                "audiences": [audience],
                "token_header": "Authorization",
                "token_scheme": "Bearer"
            });
        },
        "JWT source authentication",
    )
    .await;
}

async fn configure_api_key_source_auth(
    world: &mut SurfaceWorld,
    surface_name: &str,
    source_auth_type: &str,
    secret_id: &str,
) {
    world.ensure_operator().await;
    assert_eq!(source_auth_type, "API Key", "only API Key source authentication is supported by this BDD step");
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["source_auth"] = json!({
                "type": "api_key",
                "extraction": {
                    "source": "http_header",
                    "field": "X-API-Key"
                },
                "secret_id": secret_id
            });
        },
        "source authentication",
    )
    .await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} without caller credentials")]
async fn caller_sends_chat_completion_without_caller_credentials(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_to_surface(world, &surface_name).await;
}

#[when(
    expr = "the caller sends a chat completion request to the discovery path of LLM Surface {string} without caller credentials"
)]
async fn caller_sends_chat_completion_to_discovery_path_without_caller_credentials(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_to_discovery_path(world, &surface_name, None).await;
}

#[when(
    expr = "the caller sends a chat completion request to LLM Surface {string} with a valid JWT and their own provider key"
)]
async fn caller_sends_chat_completion_with_jwt_and_own_provider_key(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let authorization =
        format!("Bearer {}", crate::bdd_support::jwt::signed_token("https://issuer.example.test", "agent-stream"));
    let provider_key = format!("Bearer {CALLER_PROVIDER_KEY}");
    send_chat_completion_with_headers(
        world,
        &surface_name,
        [("Authorization", authorization.as_str()), (UPSTREAM_AUTHORIZATION, provider_key.as_str())],
    )
    .await;
}

#[when(
    expr = "the caller sends a chat completion request to LLM Surface {string} with their own provider key and a provider identity token"
)]
async fn caller_sends_chat_completion_with_own_provider_key_and_upstream_identity(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let provider_key = format!("Bearer {CALLER_PROVIDER_KEY}");
    send_chat_completion_with_headers(
        world,
        &surface_name,
        [("Authorization", provider_key.as_str()), (UPSTREAM_AUTHORIZATION, UPSTREAM_IDENTITY_TOKEN)],
    )
    .await;
}

#[when(
    expr = "the caller sends a chat completion request to LLM Surface {string} with caller API key {string} repeated as its bearer token"
)]
async fn caller_sends_chat_completion_with_caller_api_key_repeated_as_bearer(
    world: &mut SurfaceWorld,
    surface_name: String,
    api_key: String,
) {
    let authorization = format!("Bearer {api_key}");
    send_chat_completion_with_headers(
        world,
        &surface_name,
        [("X-API-Key", api_key.as_str()), ("Authorization", authorization.as_str())],
    )
    .await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} with caller API key {string}")]
async fn caller_sends_chat_completion_with_caller_api_key(
    world: &mut SurfaceWorld,
    surface_name: String,
    api_key: String,
) {
    send_chat_completion_to_surface_with_api_key(world, &surface_name, &api_key).await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} with a valid JWT")]
async fn caller_sends_chat_completion_with_valid_jwt(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_with_jwt(world, &surface_name, true).await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} with an invalid JWT")]
async fn caller_sends_chat_completion_with_invalid_jwt(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_with_jwt(world, &surface_name, false).await;
}

#[when(expr = "the caller sends chat prompt {string} to LLM Surface {string} with caller API key {string}")]
async fn caller_sends_chat_prompt_to_llm_surface_with_caller_api_key(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
    api_key: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt_with_api_key(world, &route, &prompt, &api_key).await;
}

#[then(expr = "the caller is rejected by source authentication")]
async fn caller_is_rejected_by_source_authentication(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 401,
        "expected source authentication rejection, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "authentication_error",
        "expected source authentication error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "source_authentication_failed",
        "expected source authentication error code, got {}",
        response.text
    );
}
