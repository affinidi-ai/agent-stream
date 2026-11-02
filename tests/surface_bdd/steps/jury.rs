use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "Jury provider {string} rejects responses containing {string}")]
async fn jury_provider_rejects_responses_containing(
    world: &mut SurfaceWorld,
    provider_name: String,
    pattern: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .reject_reviewed_responses_containing(pattern)
        .await;
}

#[given(expr = "Jury provider {string} is unavailable")]
async fn jury_provider_is_unavailable(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    make_chat_completions_unavailable(world, &provider_name).await;
}

#[given(expr = "LLM Surface {string} uses Jury provider {string} with no redrives")]
async fn llm_surface_uses_jury_provider_with_no_redrives(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    configure_llm_surface_jury(world, &surface_name, &provider_name, 0).await;
}

#[given(expr = "LLM Surface {string} uses Jury provider {string} with {int} redrive")]
async fn llm_surface_uses_jury_provider_with_redrives(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
    redrives: u32,
) {
    configure_llm_surface_jury(world, &surface_name, &provider_name, redrives).await;
}

#[given(expr = "LLM Surface {string} uses Jury provider {string} with {int} redrives")]
async fn llm_surface_uses_jury_provider_with_multiple_redrives(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
    redrives: u32,
) {
    configure_llm_surface_jury(world, &surface_name, &provider_name, redrives).await;
}

async fn configure_llm_surface_jury(
    world: &mut SurfaceWorld,
    surface_name: &str,
    provider_name: &str,
    redrives: u32,
) {
    let endpoint_url = format!(
        "{}/v1/chat/completions",
        world
            .provider(provider_name)
            .server
            .base_url()
    );
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["jury"] = json!({
        "enabled": true,
        "mode": "parallel",
        "max_retries": redrives,
        "jurors": [
            {
                "enabled": true,
                "name": provider_name,
                "llm": {
                    "provider_type": "openai",
                    "model": "jury-small",
                    "endpoint_url": endpoint_url,
                    "timeout_secs": 5,
                    "api_schema": "openai"
                },
                "system_prompt": "Approve production-ready responses and reject drafts.",
                "decision": {
                    "mode": "regex",
                    "approve_pattern": "APPROVED",
                    "reject_pattern": "REJECTED"
                },
                "disable_thinking": true
            }
        ],
        "rejection": {
            "status_code": 403,
            "body": "{\"error\":{\"message\":\"Response rejected by Jury evaluation\",\"type\":\"judge_jury_violation\",\"code\":\"content_policy_violation\"}}",
            "content_type": "application/json"
        }
            });
        },
        "Jury",
    )
    .await;
}

#[then(expr = "Jury provider {string} reviewed response {string}")]
async fn jury_provider_reviewed_response(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected_response: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert!(
        requests
            .iter()
            .any(|request| {
                request.body["messages"]
                    .as_array()
                    .is_some_and(|messages| {
                        messages
                            .iter()
                            .any(|message| {
                                message["role"] == "user"
                                    && message["content"]
                                        .as_str()
                                        .is_some_and(|content| content.contains(&expected_response))
                            })
                    })
            }),
        "expected Jury provider {provider_name:?} to review response {expected_response:?}, got {:?}",
        requests
            .iter()
            .map(|request| &request.body)
            .collect::<Vec<_>>()
    );
}

#[then(expr = "the caller receives chat completion {string}")]
async fn caller_receives_chat_completion(
    world: &mut SurfaceWorld,
    expected_content: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 200, "expected successful chat completion, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["choices"][0]["message"]["content"], expected_content,
        "expected exact provider completion to reach the caller"
    );
}

#[then(expr = "the request is rejected by the Jury")]
async fn request_is_rejected_by_jury(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected Jury rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "judge_jury_violation",
        "expected Jury rejection type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "content_policy_violation",
        "expected Jury rejection code, got {}",
        response.text
    );
}

#[then(expr = "the caller is told the Jury could not evaluate the response")]
async fn caller_is_told_jury_could_not_evaluate_response(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 502, "expected Jury evaluation failure, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "provider_error",
        "expected Jury provider error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "provider_error",
        "expected Jury provider error code, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected unavailable Jury upstream status, got {}",
        response.text
    );
    assert!(response.text.contains("Jury"), "expected failure to identify Jury evaluation, got {}", response.text);
}
