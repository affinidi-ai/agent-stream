use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "LLM Surface {string} uses Prompt Guard to reject prompts matching {string}")]
async fn llm_surface_uses_prompt_guard_to_reject_prompts_matching(
    world: &mut SurfaceWorld,
    surface_name: String,
    pattern: String,
) {
    configure_prompt_guard(world, &surface_name, "request", "reject", pattern, "disallowed prompt").await;
}

#[given(expr = "LLM Surface {string} uses Prompt Guard to mask prompts matching {string} as {string}")]
async fn llm_surface_uses_prompt_guard_to_mask_prompts_matching(
    world: &mut SurfaceWorld,
    surface_name: String,
    pattern: String,
    label: String,
) {
    configure_prompt_guard(world, &surface_name, "request", "mask", pattern, &label).await;
}

#[given(expr = "LLM Surface {string} uses Prompt Guard to reject responses matching {string}")]
async fn llm_surface_uses_prompt_guard_to_reject_responses_matching(
    world: &mut SurfaceWorld,
    surface_name: String,
    pattern: String,
) {
    configure_prompt_guard(world, &surface_name, "response", "reject", pattern, "disallowed response").await;
}

#[given(expr = "LLM Surface {string} uses Prompt Guard to mask responses matching {string} as {string}")]
async fn llm_surface_uses_prompt_guard_to_mask_responses_matching(
    world: &mut SurfaceWorld,
    surface_name: String,
    pattern: String,
    label: String,
) {
    configure_prompt_guard(world, &surface_name, "response", "mask", pattern, &label).await;
}

async fn configure_prompt_guard(
    world: &mut SurfaceWorld,
    surface_name: &str,
    seam: &str,
    action: &str,
    pattern: String,
    label: &str,
) {
    world.ensure_operator().await;
    let guard = json!({
        "regex": {
            "action": action,
            "rules": [
                { "pattern": pattern, "label": label }
            ]
        }
    });
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["prompt_guard"] = json!({
                "enabled": true,
                "request": if seam == "request" { vec![guard.clone()] } else { Vec::new() },
                "response": if seam == "response" { vec![guard] } else { Vec::new() }
            });
        },
        "Prompt Guard",
    )
    .await;
}

#[then(expr = "the request is rejected by the Prompt Guard")]
async fn request_is_rejected_by_prompt_guard(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected Prompt Guard rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "prompt_guard_violation",
        "expected Prompt Guard error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "content_policy_violation",
        "expected Prompt Guard error code, got {}",
        response.text
    );
}

#[given(expr = "LLM Surface {string} uses a PII detector on provider {string} with provider key {string}")]
async fn llm_surface_uses_pii_detector(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
    secret_id: String,
) {
    world.ensure_operator().await;
    let detector = pii_detector_config(world, &provider_name, &secret_id);
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["prompt_guard"] = json!({ "enabled": true, "llm_pii": [detector] });
        },
        "PII detector",
    )
    .await;
}

#[when(expr = "human user {string} tests the PII detector of LLM Surface {string}")]
async fn human_user_tests_saved_pii_detector(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
) {
    let saved = world
        .admin_client()
        .get_pipe(&surface_id(&surface_name))
        .await;
    let detector = saved.body["prompt_guard"]["llm_pii"][0].clone();
    test_pii_detector(world, &username, Some(&surface_name), detector).await;
}

#[when(
    expr = "human user {string} tests a PII detector of LLM Surface {string} on provider {string} with provider key {string}"
)]
async fn human_user_tests_pii_detector(
    world: &mut SurfaceWorld,
    username: String,
    surface_name: String,
    provider_name: String,
    secret_id: String,
) {
    let detector = pii_detector_config(world, &provider_name, &secret_id);
    test_pii_detector(world, &username, Some(&surface_name), detector).await;
}

#[when(expr = "human user {string} tests a PII detector on provider {string} without a provider key")]
async fn human_user_tests_keyless_pii_detector(
    world: &mut SurfaceWorld,
    username: String,
    provider_name: String,
) {
    let mut detector = pii_detector_config(world, &provider_name, "");
    detector["api_key_secret"] = serde_json::Value::Null;
    test_pii_detector(world, &username, None, detector).await;
}

#[when(expr = "human user {string} tests a PII detector at {string} without a provider key")]
async fn human_user_tests_pii_detector_at_endpoint(
    world: &mut SurfaceWorld,
    username: String,
    endpoint_url: String,
) {
    let detector = json!({
        "provider_type": "",
        "endpoint_url": endpoint_url,
        "model": "bdd-detector",
    });
    test_pii_detector(world, &username, None, detector).await;
}

#[then("the detector test is refused because its endpoint is not allowed")]
fn detector_test_is_refused_for_endpoint(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("detector test response should be recorded");
    assert_eq!(
        response.status, 400,
        "expected the detector test to refuse the endpoint, got {}: {}",
        response.status, response.text
    );
    assert!(
        response
            .text
            .contains("Detection endpoint rejected"),
        "expected the refusal to name the endpoint, got: {}",
        response.text
    );
}

fn pii_detector_config(
    world: &SurfaceWorld,
    provider_name: &str,
    secret_id: &str,
) -> serde_json::Value {
    let endpoint_url = format!(
        "{}/v1/chat/completions",
        world
            .provider(provider_name)
            .server
            .base_url()
            .trim_end_matches('/')
    );
    json!({
        "provider_type": "",
        "endpoint_url": endpoint_url,
        "model": "bdd-detector",
        "api_key_secret": secret_id,
    })
}

/// Send `detector` to the detector test as `username`, naming the saved
/// LLM Surface when given.
async fn test_pii_detector(
    world: &mut SurfaceWorld,
    username: &str,
    surface_name: Option<&str>,
    detector: serde_json::Value,
) {
    let mut body = json!({ "config": detector, "text": "Alice Example lives at 1 Example Street" });
    if let Some(surface_name) = surface_name {
        body["surface_id"] = json!(surface_id(surface_name));
    }
    let response = latest_client(world, username)
        .post_admin_json("/v1/prompt-guard/detector-test", body)
        .await;
    world.caller_response = Some(response);
}

#[then("the detector test is refused because the provider key is not saved on the surface")]
fn detector_test_is_refused_for_unsaved_provider_key(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("detector test response should be recorded");
    assert_eq!(
        response.status, 409,
        "expected the detector test to be refused for a key the surface does not use, got {}: {}",
        response.status, response.text
    );
}

#[then("the detector test is refused")]
fn detector_test_is_refused(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("detector test response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected the detector test to be refused, got {}: {}",
        response.status, response.text
    );
}

#[given(expr = "provider {string} detects person {string}")]
async fn provider_detects_person(
    world: &mut SurfaceWorld,
    provider_name: String,
    person: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    let reply = json!({ "entities": [{ "type": "PERSON", "text": person }] });
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_content(reply.to_string())
        .await;
}

#[then(expr = "the detector test finds person {string}")]
fn detector_test_finds_person(
    world: &mut SurfaceWorld,
    person: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("detector test response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected the detector test to complete, got {}: {}",
        response.status, response.text
    );
    assert_eq!(response.body["ok"], true, "expected the detector to answer, got: {}", response.text);
    let found = response.body["entities"]
        .as_array()
        .is_some_and(|entities| {
            entities
                .iter()
                .any(|entity| entity["entity_type"] == "PERSON" && entity["text"] == person.as_str())
        });
    assert!(found, "expected the detector test to find person {person:?}, got: {}", response.text);
}
