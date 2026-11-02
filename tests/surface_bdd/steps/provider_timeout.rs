use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "LLM Surface {string} has a provider timeout of {int} second")]
async fn llm_surface_has_provider_timeout(
    world: &mut SurfaceWorld,
    surface_name: String,
    timeout_seconds: u64,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| pipe["request_timeout_seconds"] = json!(timeout_seconds),
        "provider timeout",
    )
    .await;
}

#[then(expr = "the caller is told the Provider timed out")]
async fn caller_is_told_provider_timed_out(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 504, "expected Provider timeout, got {}: {}", response.status, response.text);
    assert_eq!(response.body["error"]["type"], "timeout_error", "expected timeout error type, got {}", response.text);
    assert_eq!(
        response.body["error"]["code"], "provider_timeout",
        "expected Provider timeout code, got {}",
        response.text
    );
    assert!(
        response
            .text
            .contains("timed out"),
        "expected timeout explanation, got {}",
        response.text
    );
}
