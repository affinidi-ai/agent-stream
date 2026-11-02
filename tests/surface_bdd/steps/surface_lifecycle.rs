use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "the operator can use the Admin API")]
async fn operator_can_use_admin_api(world: &mut SurfaceWorld) {
    world.ensure_operator().await;
}

#[given(expr = "the operator has published LLM Surface {string} for route {string} targeting provider {string}")]
async fn operator_has_published_llm_surface_targeting_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: String,
) {
    publish_llm_surface(world, surface_name, route, &provider_name).await;
}

#[given(
    expr = "the operator has published LLM Surface {string} for route {string} targeting provider {string} as a Custom OpenAI-compatible endpoint"
)]
async fn operator_has_published_llm_surface_at_custom_endpoint(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: String,
) {
    publish_llm_surface_at_custom_endpoint(world, surface_name, route, &provider_name).await;
}

#[given(expr = "the operator has published LLM Surface {string} for route {string}")]
async fn operator_has_published_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
) {
    publish_llm_surface(world, surface_name, route, "bravo").await;
}

#[given(
    expr = "the operator has changed LLM Surface {string} for route {string} from provider {string} to provider {string}"
)]
async fn operator_has_changed_llm_surface_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    previous_provider: String,
    new_provider: String,
) {
    publish_llm_surface(world, surface_name.clone(), route, &previous_provider).await;
    change_llm_surface_provider(world, &surface_name, &new_provider).await;
}

#[given(expr = "the operator has disabled LLM Surface {string} for route {string}")]
async fn operator_has_disabled_llm_surface_for_route(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
) {
    publish_llm_surface(world, surface_name.clone(), route, "bravo").await;
    disable_llm_surface(world, &surface_name).await;
}

#[given(expr = "the operator has updated LLM Surface {string} to target provider {string}")]
async fn operator_has_updated_llm_surface_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    change_llm_surface_provider(world, &surface_name, &provider_name).await;
}

#[given(expr = "the operator has disabled LLM Surface {string}")]
async fn operator_has_disabled_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    disable_llm_surface(world, &surface_name).await;
}

#[when(expr = "the operator publishes LLM Surface {string} for route {string} targeting provider {string}")]
async fn operator_publishes_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: String,
) {
    publish_llm_surface(world, surface_name, route, &provider_name).await;
}

#[when(expr = "the operator changes LLM Surface {string} to use provider {string}")]
async fn operator_changes_llm_surface_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    change_llm_surface_provider(world, &surface_name, &provider_name).await;
}

#[when(expr = "the operator changes LLM Surface {string} to route {string}")]
async fn operator_changes_llm_surface_route(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
) {
    let pipe_id = surface_id(&surface_name);
    let get_response = world
        .admin_client()
        .get_pipe(&pipe_id)
        .await;
    assert_eq!(
        get_response.status, 200,
        "expected LLM Surface lookup to succeed, got {}: {}",
        get_response.status, get_response.text
    );

    let mut pipe = get_response.body;
    pipe["route"] = json!(route);
    world.admin_response = Some(
        world
            .admin_client()
            .update_pipe(&pipe_id, pipe)
            .await,
    );
}

#[then(expr = "publication is persisted for LLM Surface {string} at route {string} using provider {string}")]
async fn publication_is_persisted_for_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: String,
) {
    assert_admin_success(world);
    assert_surface_configuration(world, &surface_name, &route, &provider_name).await;
}

#[then(expr = "the provider change is persisted for LLM Surface {string} using provider {string}")]
async fn provider_change_is_persisted_for_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    assert_admin_success(world);
    let route = world
        .surface_routes
        .get(&surface_name)
        .expect("LLM Surface should have a recorded route")
        .clone();
    assert_surface_configuration(world, &surface_name, &route, &provider_name).await;
}

#[then(expr = "the LLM Surface update is rejected because the route is already published")]
async fn llm_surface_update_is_rejected_for_published_route(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("admin response should be recorded");
    assert_eq!(response.status, 400, "expected route update rejection, got {}: {}", response.status, response.text);
    assert!(
        response
            .text
            .contains("already in use"),
        "expected route collision error, got {}",
        response.text
    );
}

#[then(expr = "LLM Surface {string} retains route {string} and provider {string}")]
async fn llm_surface_retains_route_and_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    route: String,
    provider_name: String,
) {
    assert_surface_configuration(world, &surface_name, &route, &provider_name).await;
}

#[when(expr = "human user {string} points LLM Surface {string} at provider {string}")]
async fn human_user_points_surface_at_provider(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    provider_name: String,
) {
    let base_url = world
        .provider(&provider_name)
        .server
        .base_url()
        .to_string();
    let client = latest_client(world, &username);
    let response = submit_surface_update_as(&client, &surface_name, |pipe| {
        pipe["pipe_type"]["provider"]["base_url"] = json!(base_url)
    })
    .await;
    world.caller_response = Some(response);
}

#[when(
    expr = "human user {string} points variant {string} of LLM Surface {string} at provider {string} with provider key {string}"
)]
async fn human_user_points_variant_at_provider(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
    provider_name: String,
    secret_id: String,
) {
    let base_url = world
        .provider(&provider_name)
        .server
        .base_url()
        .to_string();
    let overrides = json!({
        "pipe_type": {
            "type": "llm",
            "provider": {
                "provider_type": "openai",
                "model": "mock-small",
                "base_url": base_url,
                "api_key_secret": secret_id
            }
        }
    });
    let response = latest_client(world, &username)
        .put_admin_json(
            &format!("/v1/pipes/{}/variants/bdd-variant-{alias}", surface_id(&surface_name)),
            json!({ "overrides": overrides }),
        )
        .await;
    world.caller_response = Some(response);
}

#[then("the variant change is saved")]
fn variant_change_is_saved(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("variant update response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected the variant change to be saved, got {}: {}",
        response.status, response.text
    );
}

#[when(expr = "human user {string} renames LLM Surface {string} to {string}")]
async fn human_user_renames_surface(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    new_name: String,
) {
    let client = latest_client(world, &username);
    let response = submit_surface_update_as(&client, &surface_name, |pipe| pipe["name"] = json!(new_name)).await;
    world.caller_response = Some(response);
}

#[then("the surface change is refused because it needs access to secrets")]
fn surface_change_is_refused_for_secret_access(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("surface update response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected the surface change to be refused, got {}: {}",
        response.status, response.text
    );
    assert!(
        response
            .text
            .contains("secrets.view"),
        "expected the refusal to name the secrets.view permission, got: {}",
        response.text
    );
}

#[then(expr = "the surface change is saved and LLM Surface {string} is named {string}")]
async fn surface_change_is_saved_with_name(
    world: &mut SurfaceWorld,
    surface_name: String,
    name: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("surface update response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected the surface change to be saved, got {}: {}",
        response.status, response.text
    );
    let saved = world
        .admin_client()
        .get_pipe(&surface_id(&surface_name))
        .await;
    assert_eq!(saved.body["name"], name, "expected the saved surface name, got: {}", saved.text);
}

#[then(expr = "the surface change is saved and LLM Surface {string} calls provider {string}")]
async fn surface_change_is_saved_with_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("surface update response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected the surface change to be saved, got {}: {}",
        response.status, response.text
    );
    assert_surface_provider(world, &surface_name, &provider_name).await;
}

#[then(expr = "LLM Surface {string} is still saved with provider {string}")]
async fn surface_is_still_saved_with_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    assert_surface_provider(world, &surface_name, &provider_name).await;
}

async fn assert_surface_provider(
    world: &SurfaceWorld,
    surface_name: &str,
    provider_name: &str,
) {
    let saved = world
        .admin_client()
        .get_pipe(&surface_id(surface_name))
        .await;
    assert_eq!(
        saved.body["pipe_type"]["provider"]["base_url"],
        world
            .provider(provider_name)
            .server
            .base_url(),
        "expected LLM Surface {surface_name:?} to call provider {provider_name:?}, got: {}",
        saved.text
    );
}

fn assert_admin_success(world: &SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("admin response should be recorded");
    assert_eq!(response.status, 200, "expected successful admin response, got {}: {}", response.status, response.text);
}

async fn assert_surface_configuration(
    world: &SurfaceWorld,
    surface_name: &str,
    route: &str,
    provider_name: &str,
) {
    let response = world
        .admin_client()
        .get_pipe(&surface_id(surface_name))
        .await;
    assert_eq!(
        response.status, 200,
        "expected LLM Surface lookup to succeed, got {}: {}",
        response.status, response.text
    );
    assert_eq!(response.body["status"], "enabled", "expected LLM Surface to remain enabled");
    assert_eq!(response.body["route"], route, "expected persisted LLM Surface route");
    assert_eq!(
        response.body["pipe_type"]["provider"]["base_url"],
        world
            .provider(provider_name)
            .server
            .base_url(),
        "expected persisted LLM Surface provider"
    );
}

#[when(expr = "human user {string} tests the provider connection of LLM Surface {string}")]
async fn human_user_tests_provider_connection(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    let response = latest_client(world, &username)
        .post_admin_json(&format!("/v1/pipes/{}/test", surface_id(&surface_name)), json!({}))
        .await;
    world.caller_response = Some(response);
}

#[then("the connection test is refused")]
fn connection_test_is_refused(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("connection test response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected the connection test to be refused, got {}: {}",
        response.status, response.text
    );
}

#[then("the connection test is refused because the surface has no usable provider key")]
fn connection_test_is_refused_without_provider_key(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("connection test response should be recorded");
    assert_eq!(
        response.status, 400,
        "expected the connection test to be refused for a missing provider key, got {}: {}",
        response.status, response.text
    );
}

#[then("the connection test succeeds")]
fn connection_test_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("connection test response should be recorded");
    assert_eq!(response.status, 200, "expected the connection test to run, got {}: {}", response.status, response.text);
    assert_eq!(response.body["status"], "success", "expected the connection test to succeed, got: {}", response.text);
}
