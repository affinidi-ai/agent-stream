use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::given;

#[given(expr = "human user {string} edits surfaces without access to secrets")]
async fn human_user_edits_surfaces_without_secret_access(
    world: &mut SurfaceWorld,
    username: String,
) {
    login_human_user(world, &username, "user").await;
}

#[given(expr = "human user {string} may view secrets")]
async fn human_user_may_view_secrets(
    world: &mut SurfaceWorld,
    username: String,
) {
    login_human_user(world, &username, "administrator").await;
}

#[given(expr = "human user {string} is an administrator using an access token limited to {string}")]
async fn human_user_uses_scoped_access_token(
    world: &mut SurfaceWorld,
    username: String,
    scopes: String,
) {
    let scopes: Vec<&str> = scopes
        .split(',')
        .map(str::trim)
        .collect();
    login_with_access_token(world, &username, &scopes).await;
}
