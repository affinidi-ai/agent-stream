use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

const TOKEN_ISSUER: &str = "ada";

#[given(expr = "management access token {string} for base user {string} is limited to {string}")]
async fn management_token_for_base_user_limited_to(
    world: &mut SurfaceWorld,
    token_name: String,
    username: String,
    permission: String,
) {
    let subject_user_id = user_id_of(world, &username).await;
    let issuer = login_human_user(world, TOKEN_ISSUER, ADMINISTRATOR_ROLE).await;
    let response = issuer
        .post_admin_json(
            "/api/v1/access-tokens",
            json!({
                "name": token_name,
                "subject_user_id": subject_user_id,
                "scopes": [permission],
            }),
        )
        .await;
    assert_eq!(response.status, 201, "management access token should be created: {}", response.text);
    let token = response.body["token"]
        .as_str()
        .expect("management access-token response should contain the raw token")
        .to_string();
    world
        .management_tokens
        .insert(token_name, token);
}

#[when(expr = "management access token {string} reads LLM Surface {string}")]
async fn management_token_reads_llm_surface(
    world: &mut SurfaceWorld,
    token_name: String,
    surface_name: String,
) {
    let token = world
        .management_tokens
        .get(&token_name)
        .expect("management access token should exist")
        .clone();
    let client = login_human_user(world, TOKEN_ISSUER, ADMINISTRATOR_ROLE).await;
    let response = client
        .get_admin_json_with_bearer(&format!("/v1/pipes/{}", surface_id(&surface_name)), &token)
        .await;
    world.admin_response = Some(response);
}

#[then("the Surface read is forbidden")]
fn surface_read_is_forbidden(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface read response should exist");
    assert_eq!(
        response.status, 403,
        "expected the Surface read to be forbidden, got {}: {}",
        response.status, response.text
    );
}

#[then(expr = "the Surface read returns LLM Surface {string}")]
fn surface_read_returns_llm_surface(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface read response should exist");
    assert_eq!(
        response.status, 200,
        "expected the Surface read to succeed, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["id"].as_str(),
        Some(surface_id(&surface_name).as_str()),
        "expected LLM Surface {surface_name:?}, got: {}",
        response.text
    );
}
