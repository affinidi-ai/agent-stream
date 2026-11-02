use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::{Value, json};

#[given(expr = "base user {string} has published LLM Surface {string} for route {string}")]
async fn base_user_has_published_llm_surface(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    route: String,
) {
    let publisher = login_human_user(world, &username, BASE_USER_ROLE).await;
    publish_llm_surface_as(world, publisher, surface_name, route, "bravo").await;
}

#[given(expr = "base user {string} has published LLM Surface {string} for route {string} naming {string} as its owner")]
async fn base_user_has_published_llm_surface_naming_owner(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    route: String,
    named_owner: String,
) {
    let named_user_id = user_id_of(world, &named_owner).await;
    let publisher = login_human_user(world, &username, BASE_USER_ROLE).await;
    publish_llm_surface_as_with(
        world,
        publisher,
        surface_name,
        route,
        "bravo",
        json!({ "owner_user_id": named_user_id }),
    )
    .await;
}

#[given(expr = "base user {string} has added variant {string} to LLM Surface {string}")]
async fn base_user_has_added_variant(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
) {
    add_variant_as(world, &username, &alias, &surface_name).await;
    let response = world
        .admin_response
        .as_ref()
        .expect("variant creation response should exist");
    assert_eq!(response.status, 201, "expected the variant to be added, got {}: {}", response.status, response.text);
}

#[when(expr = "base user {string} adds variant {string} to LLM Surface {string}")]
async fn base_user_adds_variant(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
) {
    add_variant_as(world, &username, &alias, &surface_name).await;
}

#[when(expr = "base user {string} makes variant {string} the default of LLM Surface {string}")]
async fn base_user_promotes_variant(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
) {
    let variant_id = variant_id(world, &surface_name, &alias).await;
    let client = login_human_user(world, &username, BASE_USER_ROLE).await;
    let response = client
        .post_admin_json(
            &format!("/v1/pipes/{}/variants/{variant_id}/promote-to-default", surface_id(&surface_name)),
            json!({}),
        )
        .await;
    world.admin_response = Some(response);
}

#[when(expr = "base user {string} removes source authentication from LLM Surface {string}")]
async fn base_user_removes_source_auth(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    remove_source_auth_as(world, &username, BASE_USER_ROLE, &surface_name).await;
}

#[when(expr = "administrator {string} removes source authentication from LLM Surface {string}")]
async fn administrator_removes_source_auth(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    remove_source_auth_as(world, &username, ADMINISTRATOR_ROLE, &surface_name).await;
}

#[when(expr = "base user {string} deletes LLM Surface {string}")]
async fn base_user_deletes_llm_surface(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    delete_surface_as(world, &username, BASE_USER_ROLE, &surface_name).await;
}

#[when(expr = "administrator {string} deletes LLM Surface {string}")]
async fn administrator_deletes_llm_surface(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    delete_surface_as(world, &username, ADMINISTRATOR_ROLE, &surface_name).await;
}

#[then("the Surface change is forbidden")]
fn surface_change_is_forbidden(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface change response should exist");
    assert_eq!(
        response.status, 403,
        "expected the Surface change to be forbidden, got {}: {}",
        response.status, response.text
    );
}

#[then("the Surface change succeeds")]
fn surface_change_succeeds(world: &mut SurfaceWorld) {
    let response = world
        .admin_response
        .as_ref()
        .expect("Surface change response should exist");
    assert!(
        (200..300).contains(&response.status),
        "expected the Surface change to succeed, got {}: {}",
        response.status,
        response.text
    );
}

#[then(expr = "LLM Surface {string} still requires source authentication")]
async fn llm_surface_still_requires_source_auth(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert!(
        !surface["source_auth"].is_null(),
        "expected LLM Surface {surface_name:?} to keep its source authentication, got {surface}"
    );
}

#[then(expr = "LLM Surface {string} no longer requires source authentication")]
async fn llm_surface_no_longer_requires_source_auth(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert!(
        surface["source_auth"].is_null(),
        "expected LLM Surface {surface_name:?} to have no source authentication, got {}",
        surface["source_auth"]
    );
}

#[then(expr = "LLM Surface {string} is still published")]
async fn llm_surface_is_still_published(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert_eq!(surface["status"], "enabled", "expected LLM Surface {surface_name:?} to stay published");
}

#[then(expr = "LLM Surface {string} is no longer published")]
async fn llm_surface_is_no_longer_published(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert_eq!(surface["status"], "deleted", "expected LLM Surface {surface_name:?} to be deleted");
}

#[when(expr = "base user {string} renames variant {string} of LLM Surface {string} to {string}")]
async fn base_user_renames_variant(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
    new_name: String,
) {
    let variant_id = variant_id(world, &surface_name, &alias).await;
    let client = login_human_user(world, &username, BASE_USER_ROLE).await;
    let response = client
        .put_admin_json(
            &format!("/v1/pipes/{}/variants/{variant_id}", surface_id(&surface_name)),
            json!({ "name": new_name }),
        )
        .await;
    world.admin_response = Some(response);
}

#[when(expr = "base user {string} deletes variant {string} of LLM Surface {string}")]
async fn base_user_deletes_variant(
    world: &mut SurfaceWorld,
    username: String,
    alias: String,
    surface_name: String,
) {
    let variant_id = variant_id(world, &surface_name, &alias).await;
    let client = login_human_user(world, &username, BASE_USER_ROLE).await;
    let response = client
        .delete_admin_json(&format!("/v1/pipes/{}/variants/{variant_id}", surface_id(&surface_name)))
        .await;
    world.admin_response = Some(response);
}

#[then(expr = "variant {string} of LLM Surface {string} is still named {string}")]
async fn variant_is_still_named(
    world: &mut SurfaceWorld,
    alias: String,
    surface_name: String,
    name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    let stored_name = surface["variants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|variant| variant["alias"] == alias.as_str())
        .map(|variant| variant["name"].clone());
    assert_eq!(
        stored_name,
        Some(json!(name)),
        "expected variant {alias:?} of LLM Surface {surface_name:?} to keep its name, got: {surface}"
    );
}

#[then(expr = "LLM Surface {string} is owned by base user {string}")]
async fn llm_surface_is_owned_by(
    world: &mut SurfaceWorld,
    surface_name: String,
    username: String,
) {
    let user_id = user_id_of(world, &username).await;
    let surface = stored_surface(world, &surface_name).await;
    assert_eq!(
        surface["owner_user_id"],
        json!(user_id),
        "expected LLM Surface {surface_name:?} to be owned by {username:?}, got: {}",
        surface["owner_user_id"]
    );
}

#[then(expr = "LLM Surface {string} has no variants")]
async fn llm_surface_has_no_variants(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert!(
        surface["variants"]
            .as_array()
            .is_none_or(Vec::is_empty),
        "expected LLM Surface {surface_name:?} to have no variants, got: {surface}"
    );
}

#[then(expr = "LLM Surface {string} has variant {string}")]
async fn llm_surface_has_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    alias: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert!(
        surface["variants"]
            .as_array()
            .is_some_and(|variants| variants
                .iter()
                .any(|variant| variant["alias"] == alias.as_str())),
        "expected LLM Surface {surface_name:?} to have variant {alias:?}, got: {surface}"
    );
}

#[then(expr = "LLM Surface {string} still uses its base configuration by default")]
async fn llm_surface_still_uses_base_by_default(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let surface = stored_surface(world, &surface_name).await;
    assert!(
        surface["default_variant_id"].is_null(),
        "expected LLM Surface {surface_name:?} to keep no default variant, got: {}",
        surface["default_variant_id"]
    );
}

#[given(expr = "base user {string} has published IDE Surface {string} for route {string}")]
async fn base_user_has_published_ide_surface(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    route: String,
) {
    let publisher = login_human_user(world, &username, BASE_USER_ROLE).await;
    publish_ide_surface(world, Some(publisher), surface_name, route).await;
}

#[when(expr = "base user {string} publishes LLM Surface {string} in IDE Surface {string} as model {string}")]
async fn base_user_publishes_llm_surface_in_ide_surface(
    world: &mut SurfaceWorld,
    username: String,
    llm_surface_name: String,
    ide_surface_name: String,
    model: String,
) {
    let client = login_human_user(world, &username, BASE_USER_ROLE).await;
    let response = submit_surface_update_as(&client, &ide_surface_name, |pipe| {
        pipe["pipe_type"]["config"]["members"] = json!([{
            "pipe_id": surface_id(&llm_surface_name),
            "mnemonic": model,
            "expose": true
        }]);
    })
    .await;
    world.admin_response = Some(response);
}

#[then(expr = "IDE Surface {string} publishes no models")]
async fn ide_surface_publishes_no_models(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let members = stored_surface(world, &surface_name).await["pipe_type"]["config"]["members"].clone();
    assert_eq!(members, json!([]), "expected IDE Surface {surface_name:?} to publish no models, got: {members}");
}

#[then(expr = "IDE Surface {string} publishes LLM Surface {string} as model {string}")]
async fn ide_surface_publishes_llm_surface_as_model(
    world: &mut SurfaceWorld,
    surface_name: String,
    llm_surface_name: String,
    model: String,
) {
    let members = stored_surface(world, &surface_name).await["pipe_type"]["config"]["members"].clone();
    assert!(
        members
            .as_array()
            .is_some_and(|members| members
                .iter()
                .any(|member| member["pipe_id"] == surface_id(&llm_surface_name).as_str()
                    && member["mnemonic"] == model.as_str())),
        "expected IDE Surface {surface_name:?} to publish {llm_surface_name:?} as {model:?}, got: {members}"
    );
}

/// The id of `surface_name`'s variant `alias`, empty when it has none.
async fn variant_id(
    world: &SurfaceWorld,
    surface_name: &str,
    alias: &str,
) -> String {
    stored_surface(world, surface_name).await["variants"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|variant| variant["alias"] == alias)
        .and_then(|variant| variant["id"].as_str())
        .unwrap_or_default()
        .to_string()
}

async fn add_variant_as(
    world: &mut SurfaceWorld,
    username: &str,
    alias: &str,
    surface_name: &str,
) {
    let client = login_human_user(world, username, BASE_USER_ROLE).await;
    let response = client
        .post_admin_json(
            &format!("/v1/pipes/{}/variants", surface_id(surface_name)),
            json!({ "alias": alias, "name": alias }),
        )
        .await;
    world.admin_response = Some(response);
}

async fn remove_source_auth_as(
    world: &mut SurfaceWorld,
    username: &str,
    role: &str,
    surface_name: &str,
) {
    let client = login_human_user(world, username, role).await;
    let response = submit_surface_update_as(&client, surface_name, |pipe| pipe["source_auth"] = Value::Null).await;
    world.admin_response = Some(response);
}

async fn delete_surface_as(
    world: &mut SurfaceWorld,
    username: &str,
    role: &str,
    surface_name: &str,
) {
    let client = login_human_user(world, username, role).await;
    let response = client
        .delete_pipe(&surface_id(surface_name))
        .await;
    world.admin_response = Some(response);
}

async fn stored_surface(
    world: &SurfaceWorld,
    surface_name: &str,
) -> Value {
    let response = world
        .admin_client()
        .get_pipe(&surface_id(surface_name))
        .await;
    assert_eq!(response.status, 200, "expected Surface lookup to succeed, got {}: {}", response.status, response.text);
    response.body
}
