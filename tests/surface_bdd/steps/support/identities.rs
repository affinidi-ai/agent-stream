use super::login_human_user;
use crate::bdd_support::admin_client::AdminClient;
use crate::world::SurfaceWorld;
use serde_json::json;

/// Sign in human user `username` as an administrator, then make their latest
/// client use a management access token limited to `scopes`.
pub(crate) async fn login_with_access_token(
    world: &mut SurfaceWorld,
    username: &str,
    scopes: &[&str],
) {
    let session = login_human_user(world, username, "administrator").await;
    let token = create_access_token(&session, &format!("{username} scoped token"), scopes).await;
    world
        .human_clients
        .entry(username.to_string())
        .or_default()
        .push(session.with_bearer(&token));
}

/// Create a management access token named `name`, limited to `scopes`, as
/// `client`'s user, and return its raw value.
pub(crate) async fn create_access_token(
    client: &AdminClient,
    name: &str,
    scopes: &[&str],
) -> String {
    let response = client
        .post_admin_json("/api/v1/access-tokens", json!({ "name": name, "scopes": scopes }))
        .await;
    assert_eq!(response.status, 201, "management access token should be created: {}", response.text);
    response.body["token"]
        .as_str()
        .expect("management access-token response should contain the raw token")
        .to_string()
}

pub(crate) fn latest_client(
    world: &SurfaceWorld,
    username: &str,
) -> AdminClient {
    world
        .human_clients
        .get(username)
        .and_then(|clients| clients.last())
        .unwrap_or_else(|| panic!("human user {username:?} should have an authenticated client"))
        .clone()
}

pub(crate) async fn create_member(
    world: &mut SurfaceWorld,
    member_name: &str,
    header: &str,
    identifier: &str,
    requests_per_minute: Option<u32>,
    monthly_token_cap: Option<u64>,
    monthly_budget_usd: Option<f64>,
) {
    let response = world
        .admin_client()
        .create_member(json!({
            "id": "server-assigned",
            "name": member_name,
            "status": "enabled",
            "test_fixture": true,
            "identifiers": [{ "kind": "email", "email": identifier }],
            "monthly_token_cap": monthly_token_cap,
            "monthly_budget_usd": monthly_budget_usd,
            "requests_per_minute": requests_per_minute
        }))
        .await;
    assert_eq!(response.status, 200, "expected member creation to succeed, got {}: {}", response.status, response.text);
    let member_id = response.body["id"]
        .as_str()
        .expect("created member should have an id")
        .to_string();
    world
        .member_ids
        .insert(member_name.to_string(), member_id);
    world
        .member_headers
        .insert(member_name.to_string(), (header.to_string(), identifier.to_string()));

    let personal_team_name = format!("{member_name} personal team");
    create_team_without_cap(world, &personal_team_name, [member_name]).await;
}

pub(crate) async fn create_team_without_cap<const N: usize>(
    world: &mut SurfaceWorld,
    team_name: &str,
    member_names: [&str; N],
) {
    create_team_with_optional_cap(world, team_name, member_names, None).await;
}

pub(crate) async fn create_team<const N: usize>(
    world: &mut SurfaceWorld,
    team_name: &str,
    member_names: [&str; N],
    monthly_token_cap: u64,
) {
    create_team_with_optional_cap(world, team_name, member_names, Some(monthly_token_cap)).await;
}

pub(crate) async fn create_team_with_optional_cap<const N: usize>(
    world: &mut SurfaceWorld,
    team_name: &str,
    member_names: [&str; N],
    monthly_token_cap: Option<u64>,
) {
    let members = member_names
        .into_iter()
        .map(|name| {
            world
                .member_ids
                .get(name)
                .unwrap_or_else(|| panic!("member {name:?} should exist"))
                .clone()
        })
        .collect::<Vec<_>>();
    let response = world
        .admin_client()
        .create_team(json!({
            "id": "server-assigned",
            "name": team_name,
            "status": "enabled",
            "test_fixture": true,
            "monthly_token_cap": monthly_token_cap,
            "members": members
        }))
        .await;
    assert_eq!(response.status, 200, "expected team creation to succeed, got {}: {}", response.status, response.text);
    let team_id = response.body["id"]
        .as_str()
        .expect("created team should have an id")
        .to_string();
    world
        .team_ids
        .insert(team_name.to_string(), team_id);
}
