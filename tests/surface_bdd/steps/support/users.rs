use crate::bdd_support::admin_client::AdminClient;
use crate::world::SurfaceWorld;

pub(crate) const BASE_USER_ROLE: &str = "user";
pub(crate) const ADMINISTRATOR_ROLE: &str = "administrator";

/// Sign in `username` with `role` through the test-only authentication
/// route, keeping the session client for later steps.
pub(crate) async fn login_human_user(
    world: &mut SurfaceWorld,
    username: &str,
    role: &str,
) -> AdminClient {
    world.ensure_operator().await;
    let appliance = &world
        .infra
        .as_ref()
        .expect("scenario infrastructure should exist")
        ._appliance;
    let (client, response) =
        AdminClient::login_with_role(appliance.base_url(), appliance.test_token(), username, role).await;
    world.caller_response = Some(response);
    world
        .human_clients
        .entry(username.to_string())
        .or_default()
        .push(client.clone());
    client
}

/// `username`'s user id, read from their own profile.
pub(crate) async fn user_id_of(
    world: &mut SurfaceWorld,
    username: &str,
) -> String {
    let client = login_human_user(world, username, BASE_USER_ROLE).await;
    let profile = client
        .get_admin_json("/v1/profile")
        .await;
    profile.body["user_id"]
        .as_str()
        .unwrap_or_else(|| panic!("profile of {username:?} should name its user id: {}", profile.text))
        .to_string()
}
