use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "the operator has published IDE Surface {string} for route {string}")]
async fn operator_has_published_ide_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
) {
    world.ensure_operator().await;
    publish_ide_surface(world, None, surface_name, route).await;
}

#[given(expr = "IDE Surface {string} publishes LLM Surface {string} as model {string}")]
async fn ide_surface_publishes_llm_surface_as_model(
    world: &mut SurfaceWorld,
    ide_surface_name: String,
    llm_surface_name: String,
    model: String,
) {
    update_surface(
        world,
        &ide_surface_name,
        |pipe| {
            pipe["pipe_type"]["config"]["members"]
                .as_array_mut()
                .expect("IDE Surface members should be an array")
                .push(json!({
                    "pipe_id": surface_id(&llm_surface_name),
                    "mnemonic": model,
                    "expose": true
                }));
        },
        "member",
    )
    .await;
}

#[when(expr = "member {string} discovers models from IDE Surface {string}")]
async fn member_discovers_models_from_ide_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/models", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, &member_name);
    world.caller_response = Some(
        world
            .admin_client()
            .get_caller_json_with_header(&path, &header, &value)
            .await,
    );
}

#[when(expr = "the caller asks IDE Surface {string} for a VP challenge")]
async fn caller_asks_ide_surface_for_vp_challenge(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    request_vp_challenge(world, &surface_name).await;
}

#[when(expr = "the caller discovers models from IDE Surface {string}")]
async fn caller_discovers_models_from_ide_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/models", route.trim_end_matches('/'));
    world.caller_response = Some(
        world
            .admin_client()
            .get_caller_json(&path)
            .await,
    );
}

#[when(expr = "the caller discovers models from IDE Surface {string} with caller API key {string}")]
async fn caller_discovers_ide_models_with_api_key(
    world: &mut SurfaceWorld,
    surface_name: String,
    api_key: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/models", route.trim_end_matches('/'));
    world.caller_response = Some(
        world
            .admin_client()
            .get_caller_json_with_api_key(&path, &api_key)
            .await,
    );
}

#[when(expr = "the caller discovers models from IDE Surface {string} with access tier {string}")]
async fn caller_discovers_ide_models_with_access_tier(
    world: &mut SurfaceWorld,
    surface_name: String,
    access_tier: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/models", route.trim_end_matches('/'));
    world.caller_response = Some(
        world
            .admin_client()
            .get_caller_json_with_access_tier(&path, &access_tier)
            .await,
    );
}

#[when(expr = "the caller invokes model {string} through IDE Surface {string}")]
async fn caller_invokes_model_through_ide_surface(
    world: &mut SurfaceWorld,
    model: String,
    surface_name: String,
) {
    invoke_ide_model(world, &surface_name, &model, None).await;
}

#[when(expr = "the caller invokes model {string} through IDE Surface {string} with access tier {string}")]
async fn caller_invokes_model_through_ide_surface_with_access_tier(
    world: &mut SurfaceWorld,
    model: String,
    surface_name: String,
    access_tier: String,
) {
    invoke_ide_model(world, &surface_name, &model, Some(("X-Access-Tier", access_tier.as_str()))).await;
}

#[when(expr = "member {string} invokes model {string} through IDE Surface {string}")]
async fn member_invokes_model_through_ide_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    model: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, &member_name);
    let response = world
        .admin_client()
        .post_caller_json_with_header(
            &path,
            json!({
                "model": model,
                "messages": [
                    { "role": "user", "content": DEFAULT_CALLER_PROMPT }
                ]
            }),
            &header,
            &value,
        )
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(expr = "the caller sends a chat completion request for model {string} to IDE Surface {string}")]
async fn caller_sends_chat_completion_for_model_to_ide_surface(
    world: &mut SurfaceWorld,
    model: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json(
            &path,
            json!({
                "model": model,
                "messages": [
                    { "role": "user", "content": DEFAULT_CALLER_PROMPT }
                ]
            }),
        )
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(
    expr = "the caller sends a chat completion request for model {string} to IDE Surface {string} with a provider identity token"
)]
async fn caller_sends_chat_completion_for_model_to_ide_surface_with_upstream_identity(
    world: &mut SurfaceWorld,
    model: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json_with_headers(
            &path,
            json!({
                "model": model,
                "messages": [
                    { "role": "user", "content": DEFAULT_CALLER_PROMPT }
                ]
            }),
            [(UPSTREAM_AUTHORIZATION, UPSTREAM_IDENTITY_TOKEN)],
        )
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[then(expr = "model {string} is available to the caller")]
async fn model_is_available_to_caller(
    world: &mut SurfaceWorld,
    model: String,
) {
    assert_model_discovery_response(world);
    assert!(model_is_listed(world, &model), "expected model {model:?} to be available");
}

#[then(expr = "model {string} is not available to the caller")]
async fn model_is_not_available_to_caller(
    world: &mut SurfaceWorld,
    model: String,
) {
    assert_model_discovery_response(world);
    assert!(
        !model_is_listed(world, &model),
        "expected model {model:?} not to be available, got {}",
        caller_response(world).text
    );
}

#[then(expr = "the caller is told the IDE model was not found")]
async fn caller_is_told_ide_model_was_not_found(world: &mut SurfaceWorld) {
    assert_ide_model_error(world, "model_not_found");
}

#[then(expr = "the caller is told the IDE model is unavailable")]
async fn caller_is_told_ide_model_is_unavailable(world: &mut SurfaceWorld) {
    assert_ide_model_error(world, "model_not_available");
}

fn assert_model_discovery_response(world: &SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 200, "expected successful model discovery, got {}: {}", response.status, response.text);
    assert!(response.body["data"].is_array(), "expected model discovery data array, got {}", response.text);
}

fn model_is_listed(
    world: &SurfaceWorld,
    expected_model: &str,
) -> bool {
    world
        .caller_response
        .as_ref()
        .and_then(|response| response.body["data"].as_array())
        .is_some_and(|models| {
            models
                .iter()
                .any(|model| model["id"] == expected_model)
        })
}

fn assert_ide_model_error(
    world: &SurfaceWorld,
    expected_code: &str,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 404, "expected IDE model rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "invalid_request_error",
        "expected IDE model error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], expected_code,
        "expected IDE model error code {expected_code:?}, got {}",
        response.text
    );
}
