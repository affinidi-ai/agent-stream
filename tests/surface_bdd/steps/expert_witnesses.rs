use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "Expert Witness provider {string} allows inspected content")]
async fn expert_witness_provider_allows_inspected_content(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .allow_guardrail_inspections()
        .await;
}

#[given(expr = "Expert Witness provider {string} flags inspected content")]
async fn expert_witness_provider_flags_inspected_content(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .flag_guardrail_inspections()
        .await;
}

#[given(expr = "Expert Witness provider {string} is unavailable")]
async fn expert_witness_provider_is_unavailable(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .make_guardrail_unavailable()
        .await;
}

#[given(expr = "LLM Surface {string} uses Expert Witness {string} on requests")]
async fn llm_surface_uses_expert_witness_on_requests(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    configure_llm_surface_expert_witness(world, &surface_name, &provider_name, true, false).await;
}

#[given(expr = "LLM Surface {string} uses Expert Witness {string} on responses")]
async fn llm_surface_uses_expert_witness_on_responses(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    configure_llm_surface_expert_witness(world, &surface_name, &provider_name, false, true).await;
}

async fn configure_llm_surface_expert_witness(
    world: &mut SurfaceWorld,
    surface_name: &str,
    provider_name: &str,
    check_request: bool,
    check_response: bool,
) {
    let endpoint = format!(
        "{}/guardrail",
        world
            .provider(provider_name)
            .server
            .base_url()
    );
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["expert_witnesses"] = json!([{
                "id": provider_name,
                "name": provider_name,
                "enabled": true,
                "provider": "generic",
                "endpoint_url": endpoint,
                "timeout_secs": 5,
                "fail_open": false,
                "check_request": check_request,
                "check_response": check_response
            }]);
        },
        "Expert Witness",
    )
    .await;
}

#[then(expr = "Expert Witness provider {string} inspected content {string}")]
async fn expert_witness_provider_inspected_content(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected_content: String,
) {
    let inspections = world
        .provider(&provider_name)
        .server
        .received_guardrail_inspections()
        .await;
    assert_eq!(inspections.len(), 1, "expected Expert Witness provider {provider_name:?} to receive one inspection");
    assert_eq!(
        inspections[0].body["input"], expected_content,
        "Expert Witness provider should inspect exact content, got {}",
        inspections[0].body
    );
}

#[then(expr = "the caller is rejected by an Expert Witness")]
async fn caller_is_rejected_by_expert_witness(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected Expert Witness rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "prompt_guard_violation",
        "expected Expert Witness rejection type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "content_policy_violation",
        "expected Expert Witness rejection code, got {}",
        response.text
    );
}

#[then(expr = "the caller is told the Expert Witness provider is unavailable")]
async fn caller_is_told_expert_witness_provider_is_unavailable(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 502,
        "expected Expert Witness provider failure, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "guardrail_unavailable",
        "expected unavailable Expert Witness type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "guardrail_provider_error",
        "expected unavailable Expert Witness code, got {}",
        response.text
    );
}
