use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};

#[given(expr = "no LLM Surface is configured for route {string}")]
async fn no_llm_surface_is_configured_for_route(
    world: &mut SurfaceWorld,
    route: String,
) {
    world.ensure_operator().await;
    assert!(
        !world
            .surface_routes
            .values()
            .any(|configured_route| configured_route == &route),
        "expected no LLM Surface route {route:?} to be configured"
    );
}

#[when(expr = "the caller sends a chat completion request to route {string}")]
async fn caller_sends_chat_completion_to_route(
    world: &mut SurfaceWorld,
    route: String,
) {
    send_chat_prompt(world, &route, DEFAULT_CALLER_PROMPT).await;
}

#[when(expr = "the caller sends chat prompt {string} to LLM Surface {string}")]
async fn caller_sends_chat_prompt_to_llm_surface(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, &prompt).await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string}")]
async fn caller_sends_chat_completion(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    send_chat_completion_to_surface(world, &surface_name).await;
}

#[when(expr = "the caller sends a {string} request to LLM Surface {string}")]
async fn caller_sends_provider_operation(
    world: &mut SurfaceWorld,
    operation: String,
    surface_name: String,
) {
    send_provider_operation(world, &operation, &surface_name, None).await;
}

#[then(expr = "the caller receives a not found response")]
async fn caller_receives_not_found_response(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 404, "expected not found response, got {}: {}", response.status, response.text);
}

#[then(expr = "the caller receives a provider error response")]
async fn caller_receives_provider_error_response(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 502, "expected provider error response, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["code"], "provider_error",
        "expected stable provider error code, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected stable upstream provider status, got {}",
        response.text
    );
}
