use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{then, when};
use serde_json::json;

#[when(expr = "management access token {string} runs LLM Surface {string}")]
async fn management_token_runs_llm_surface(
    world: &mut SurfaceWorld,
    token_name: String,
    surface_name: String,
) {
    let token = world
        .management_tokens
        .get(&token_name)
        .expect("management access token should exist")
        .clone();
    let response = world
        .admin_client()
        .with_bearer(&token)
        .post_admin_json(
            &format!("/v1/pipes/{}/execute", surface_id(&surface_name)),
            json!({ "request": chat_completion_body(DEFAULT_CALLER_PROMPT) }),
        )
        .await;
    world.admin_response = Some(response);
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
}

#[then("the Surface run is forbidden")]
fn surface_run_is_forbidden(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface run response should exist");
    assert_eq!(
        response.status, 403,
        "expected the Surface run to be forbidden, got {}: {}",
        response.status, response.text
    );
}

#[then("the Surface run returns a chat completion")]
fn surface_run_returns_a_chat_completion(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface run response should exist");
    assert_eq!(response.status, 200, "expected the Surface run to succeed, got {}: {}", response.status, response.text);
    assert!(
        response.body["response"]["choices"]
            .as_array()
            .is_some_and(|choices| !choices.is_empty()),
        "expected a chat completion in the Surface run response, got: {}",
        response.text
    );
}
