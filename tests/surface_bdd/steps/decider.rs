use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "Decider provider {string} selects candidate {string}")]
async fn decider_provider_selects_candidate(
    world: &mut SurfaceWorld,
    provider_name: String,
    candidate: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_content(json!({ "candidate": candidate, "reasoning": "BDD selection" }).to_string())
        .await;
}

#[given(expr = "Decider provider {string} is unavailable")]
async fn decider_provider_is_unavailable(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    make_chat_completions_unavailable(world, &provider_name).await;
}

#[given(
    expr = "LLM Surface {string} uses Decider provider {string} with candidate {string} targeting provider {string} and candidate {string} targeting provider {string}"
)]
async fn llm_surface_uses_decider_provider_with_candidates(
    world: &mut SurfaceWorld,
    surface_name: String,
    decider_provider_name: String,
    first_candidate: String,
    first_provider_name: String,
    second_candidate: String,
    second_provider_name: String,
) {
    configure_llm_surface_decider(
        world,
        &surface_name,
        &decider_provider_name,
        [(&first_candidate, &first_provider_name), (&second_candidate, &second_provider_name)],
    )
    .await;
}

#[given(expr = "LLM Surface {string} uses Decider candidate {string} by default")]
async fn llm_surface_uses_decider_candidate_by_default(
    world: &mut SurfaceWorld,
    surface_name: String,
    candidate: String,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| pipe["decider"]["default_candidate_id"] = json!(candidate),
        "Decider default",
    )
    .await;
}

async fn configure_llm_surface_decider(
    world: &mut SurfaceWorld,
    surface_name: &str,
    decider_provider_name: &str,
    candidates: [(&str, &str); 2],
) {
    let decider_endpoint = format!(
        "{}/v1/chat/completions",
        world
            .provider(decider_provider_name)
            .server
            .base_url()
    );
    let candidate_configs = candidates
        .into_iter()
        .map(|(candidate, provider_name)| {
            json!({
                "id": candidate,
                "name": candidate,
                "description": format!("Requests suited to {candidate}"),
                "llm": {
                    "provider_type": "openai",
                    "model": format!("{candidate}-small"),
                    "endpoint_url": format!("{}/v1/chat/completions", world.provider(provider_name).server.base_url()),
                    "timeout_secs": 5,
                    "api_schema": "openai"
                }
            })
        })
        .collect::<Vec<_>>();
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["decider"] = json!({
                "enabled": true,
                "llm": {
                    "provider_type": "openai",
                    "model": "router-small",
                    "endpoint_url": decider_endpoint,
                    "timeout_secs": 5,
                    "api_schema": "openai"
                },
                "system_prompt": "Select the candidate best suited to the caller prompt.",
                "candidates": candidate_configs,
                "disable_thinking": true
            });
        },
        "Decider",
    )
    .await;
}

#[then(expr = "Decider provider {string} evaluated prompt {string}")]
async fn decider_provider_evaluated_prompt(
    world: &mut SurfaceWorld,
    provider_name: String,
    prompt: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected Decider provider {provider_name:?} to receive one request");
    let messages = requests[0].body["messages"]
        .as_array()
        .expect("Decider request should include messages");
    assert!(
        messages
            .iter()
            .any(|message| message["role"] == "user" && message["content"] == prompt),
        "Decider request should include exact caller prompt {prompt:?}, got {}",
        requests[0].body
    );
}

#[then(expr = "the caller is told the Decider could not route the request")]
async fn caller_is_told_decider_could_not_route_request(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 502, "expected Decider routing failure, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "provider_error",
        "expected Decider provider error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "provider_error",
        "expected Decider provider error code, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected unavailable Decider upstream status, got {}",
        response.text
    );
    assert!(
        response
            .text
            .contains("Decider"),
        "expected failure to identify Decider routing, got {}",
        response.text
    );
}
