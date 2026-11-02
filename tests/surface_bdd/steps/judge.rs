use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "Judge provider {string} classifies prompts as {string}")]
async fn judge_provider_classifies_prompts_as(
    world: &mut SurfaceWorld,
    provider_name: String,
    classification: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_content(json!({ "classification": classification }).to_string())
        .await;
}

#[given(expr = "Judge provider {string} is unavailable")]
async fn judge_provider_is_unavailable(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .make_chat_completions_unavailable()
        .await;
}

#[given(expr = "LLM Surface {string} uses Judge provider {string} to reject classification {string}")]
async fn llm_surface_uses_judge_provider_to_reject_classification(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
    rejected_classification: String,
) {
    let endpoint_url = format!(
        "{}/v1/chat/completions",
        world
            .provider(&provider_name)
            .server
            .base_url()
    );
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["judge"] = json!({
                "enabled": true,
                "mode": "llm",
                "llm": {
                    "provider_type": "openai",
                    "model": "judge-small",
                    "endpoint_url": endpoint_url,
                    "timeout_secs": 5,
                    "api_schema": "openai"
                },
                "system_prompt": "Classify the caller prompt as safe or unsafe and return JSON.",
                "disable_thinking": true,
                "rules": [{
                    "name": "unsafe_content",
                    "condition": {
                        "type": "json_field_equals",
                        "field": "classification",
                        "value": rejected_classification
                    },
                    "status_code": 403,
                    "body": "{\"error\":{\"message\":\"Request rejected by Judge evaluation\",\"type\":\"judge_jury_violation\",\"code\":\"content_policy_violation\"}}",
                    "content_type": "application/json"
                }]
            });
        },
        "Judge",
    )
    .await;
}

#[then(expr = "Judge provider {string} evaluated prompt {string}")]
async fn judge_provider_evaluated_prompt(
    world: &mut SurfaceWorld,
    provider_name: String,
    prompt: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected Judge provider {provider_name:?} to receive one request");
    let messages = requests[0].body["messages"]
        .as_array()
        .expect("Judge request should include messages");
    assert!(
        messages
            .iter()
            .any(|message| message["role"] == "user" && message["content"] == prompt),
        "Judge request should include the exact caller prompt, got {}",
        requests[0].body
    );
}

#[then(expr = "the request is rejected by the Judge")]
async fn request_is_rejected_by_judge(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected Judge rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "judge_jury_violation",
        "expected Judge rejection type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "content_policy_violation",
        "expected Judge rejection code, got {}",
        response.text
    );
}

#[then(expr = "the caller is told the Judge could not evaluate the request")]
async fn caller_is_told_judge_could_not_evaluate_request(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 502, "expected Judge evaluation failure, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "provider_error",
        "expected Judge provider error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "provider_error",
        "expected Judge provider error code, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected unavailable Judge upstream status, got {}",
        response.text
    );
    assert!(
        response
            .text
            .contains("Judge"),
        "expected failure to identify Judge evaluation, got {}",
        response.text
    );
}

#[then(expr = "the caller is told the Judge could not reach a verdict")]
async fn caller_is_told_judge_could_not_reach_verdict(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 502,
        "expected Judge indeterminate failure, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "guardrail_unavailable",
        "expected guardrail unavailable type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "judge_indeterminate",
        "expected Judge indeterminate code, got {}",
        response.text
    );
}
