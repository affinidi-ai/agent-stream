use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "LLM Surface {string} allows {int} request per minute")]
async fn llm_surface_allows_requests_per_minute(
    world: &mut SurfaceWorld,
    surface_name: String,
    requests_per_minute: u32,
) {
    configure_surface_rate_limit(world, &surface_name, requests_per_minute).await;
}

#[given(expr = "the caller has used the available request for LLM Surface {string}")]
async fn caller_has_used_available_surface_request(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    invoke_surface_and_require_success(world, &surface_name).await;
}

#[given(expr = "LLM Surface {string} prices input and output tokens at {int} dollar per 1000 tokens")]
async fn llm_surface_prices_input_and_output_tokens(
    world: &mut SurfaceWorld,
    surface_name: String,
    price_per_thousand: u64,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["cost_tracking"] = json!({
                "enabled": true,
                "input_price_per_1k": price_per_thousand,
                "output_price_per_1k": price_per_thousand
            });
        },
        "token pricing",
    )
    .await;
}

#[given(expr = "LLM Surface {string} declares a price of {int} dollar per 1000 tokens")]
async fn llm_surface_declares_price(
    world: &mut SurfaceWorld,
    surface_name: String,
    price_per_thousand: u64,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["upstream_pricing"] = json!({
                "input_per_million": price_per_thousand * 1000,
                "output_per_million": price_per_thousand * 1000
            });
        },
        "declared price",
    )
    .await;
}

#[given(expr = "member {string} has streamed a chat completion from LLM Surface {string}")]
async fn member_has_streamed_chat_completion(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, &member_name);
    let mut body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    body["stream"] = json!(true);
    let response = world
        .admin_client()
        .post_caller_json_with_header(&path, body, &header, &value)
        .await;
    assert_eq!(response.status, 200, "expected the stream to be served, got {}: {}", response.status, response.text);
    // A stream's usage is recorded once it ends, off the response path: wait
    // for the member's usage to move (it never does when nothing is billed).
    let member_id = world
        .member_ids
        .get(&member_name)
        .unwrap_or_else(|| panic!("member {member_name:?} should exist"))
        .clone();
    for _ in 0..30 {
        let usage = world
            .admin_client()
            .get_admin_json(&format!("/v1/members/{member_id}/usage"))
            .await;
        if usage.body["total_tokens"]
            .as_u64()
            .is_some_and(|tokens| tokens > 0)
        {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
}

#[given(expr = "LLM Surface {string} has a monthly token cap of {int}")]
async fn llm_surface_has_monthly_token_cap(
    world: &mut SurfaceWorld,
    surface_name: String,
    token_cap: u64,
) {
    configure_surface_token_cap(world, &surface_name, token_cap).await;
}

#[given(expr = "the caller has consumed {int} tokens through LLM Surface {string}")]
async fn caller_has_consumed_tokens_through_surface(
    world: &mut SurfaceWorld,
    tokens: u64,
    surface_name: String,
) {
    assert_eq!(tokens, 10, "BDD mock completions currently report 10 tokens");
    invoke_surface_and_require_success(world, &surface_name).await;
}

#[given(
    expr = "member {string} is identified by header {string} value {string} with a limit of {int} request per minute"
)]
async fn member_is_identified_with_request_limit(
    world: &mut SurfaceWorld,
    member_name: String,
    header: String,
    value: String,
    requests_per_minute: u32,
) {
    create_member(world, &member_name, &header, &value, Some(requests_per_minute), None, None).await;
}

#[given(expr = "member {string} is identified by header {string} value {string} with a monthly token cap of {int}")]
async fn member_is_identified_with_monthly_token_cap(
    world: &mut SurfaceWorld,
    member_name: String,
    header: String,
    value: String,
    token_cap: u64,
) {
    create_member(world, &member_name, &header, &value, None, Some(token_cap), None).await;
}

#[given(
    expr = "member {string} is identified by header {string} value {string} with a monthly budget of {float} dollars"
)]
async fn member_is_identified_with_monthly_budget(
    world: &mut SurfaceWorld,
    member_name: String,
    header: String,
    value: String,
    budget_usd: f64,
) {
    create_member(world, &member_name, &header, &value, None, None, Some(budget_usd)).await;
}

#[given(expr = "LLM Surface {string} accepts the caller's own provider key")]
async fn llm_surface_accepts_callers_own_provider_key(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["override_policy"] = json!({ "api_key": "inject_if_missing" });
        },
        "caller's own provider key",
    )
    .await;
}

#[given(expr = "LLM Surface {string} sends the operator's provider key from secret {string}")]
async fn llm_surface_sends_operators_provider_key(
    world: &mut SurfaceWorld,
    surface_name: String,
    secret_id: String,
) {
    world.ensure_operator().await;
    let response = world
        .admin_client()
        .create_secret(&secret_id, &secret_id, OPERATOR_PROVIDER_KEY)
        .await;
    assert_eq!(
        response.status, 201,
        "expected the operator's provider key secret creation to succeed, got {}: {}",
        response.status, response.text
    );
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["pipe_type"]["provider"]["api_key_secret"] = json!(secret_id);
        },
        "operator's provider key",
    )
    .await;
}

#[given(expr = "member {string} is identified by header {string} value {string}")]
async fn member_is_identified(
    world: &mut SurfaceWorld,
    member_name: String,
    header: String,
    value: String,
) {
    create_member(world, &member_name, &header, &value, None, None, None).await;
}

#[given(expr = "both governed LLM Surfaces enforce member and team usage")]
async fn both_governed_surfaces_enforce_usage(world: &mut SurfaceWorld) {
    for surface_name in ["governed-chat", "governed-chat-two"] {
        configure_surface_team_attribution(world, surface_name).await;
    }
}

#[given(expr = "LLM Surface {string} enforces member and team usage")]
async fn llm_surface_enforces_member_and_team_usage(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    configure_surface_team_attribution(world, &surface_name).await;
}

#[given(expr = "member {string} has invoked LLM Surface {string}")]
async fn member_has_invoked_llm_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    invoke_surface_as_member_and_require_success(world, &member_name, &surface_name).await;
}

#[given(expr = "member {string} has consumed {int} tokens through LLM Surface {string}")]
async fn member_has_consumed_tokens_through_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    tokens: u64,
    surface_name: String,
) {
    assert_eq!(tokens, 10, "BDD mock completions currently report 10 tokens");
    invoke_surface_as_member_and_require_success(world, &member_name, &surface_name).await;
}

#[given(expr = "team {string} contains member {string} without a usage cap")]
async fn team_contains_member_without_usage_cap(
    world: &mut SurfaceWorld,
    team_name: String,
    member_name: String,
) {
    create_team_without_cap(world, &team_name, [&member_name]).await;
}

#[given(expr = "team {string} contains member {string} with a monthly token cap of {int}")]
async fn team_contains_member_with_monthly_token_cap(
    world: &mut SurfaceWorld,
    team_name: String,
    member_name: String,
    token_cap: u64,
) {
    create_team(world, &team_name, [&member_name], token_cap).await;
}

#[given(expr = "LLM Surface {string} is available only to team {string}")]
async fn llm_surface_is_available_only_to_team(
    world: &mut SurfaceWorld,
    surface_name: String,
    team_name: String,
) {
    let team_id = world
        .team_ids
        .get(&team_name)
        .unwrap_or_else(|| panic!("team {team_name:?} should have an id"))
        .clone();
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["team_attribution"] = json!({
                "enabled": true,
                "caller_identity_sources": [{
                    "type": "header",
                    "name": "X-Caller-Email"
                }],
                "enforce": true,
                "allow_individual_overage": false,
                "allowed_teams": [team_id]
            });
        },
        "team entitlement",
    )
    .await;
}

#[given(expr = "team {string} contains members {string} and {string} without a usage cap")]
async fn team_contains_members_without_usage_cap(
    world: &mut SurfaceWorld,
    team_name: String,
    first_member: String,
    second_member: String,
) {
    create_team_without_cap(world, &team_name, [&first_member, &second_member]).await;
}

#[given(expr = "team {string} contains members {string} and {string} with a monthly token cap of {int}")]
async fn team_contains_members_with_monthly_token_cap(
    world: &mut SurfaceWorld,
    team_name: String,
    first_member: String,
    second_member: String,
    token_cap: u64,
) {
    create_team(world, &team_name, [&first_member, &second_member], token_cap).await;
}

async fn configure_surface_rate_limit(
    world: &mut SurfaceWorld,
    surface_name: &str,
    requests_per_minute: u32,
) {
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["rate_limit"] = json!({
                "enabled": true,
                "requests_per_minute": requests_per_minute
            });
        },
        "request limit",
    )
    .await;
}

async fn configure_surface_token_cap(
    world: &mut SurfaceWorld,
    surface_name: &str,
    token_cap: u64,
) {
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["usage_limits"] = json!([{
                "id": "bdd-cumulative-token-cap",
                "enabled": true,
                "scope": "cumulative",
                "monthly_token_cap": token_cap
            }]);
        },
        "token cap",
    )
    .await;
}

async fn configure_surface_team_attribution(
    world: &mut SurfaceWorld,
    surface_name: &str,
) {
    update_surface(
        world,
        surface_name,
        |pipe| {
            pipe["team_attribution"] = json!({
                "enabled": true,
                "caller_identity_sources": [{
                    "type": "header",
                    "name": "X-Caller-Email"
                }],
                "enforce": true,
                "allow_individual_overage": false,
                "allowed_teams": []
            });
        },
        "member and team usage enforcement",
    )
    .await;
}

#[when(expr = "member {string} invokes LLM Surface {string}")]
async fn member_invokes_llm_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    send_member_chat_completion(world, &member_name, &surface_name).await;
}

#[when(expr = "member {string} invokes LLM Surface {string} with their own provider key")]
async fn member_invokes_llm_surface_with_own_provider_key(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    send_member_chat_completion_with_provider_key(world, &member_name, &surface_name, CALLER_PROVIDER_KEY).await;
}

#[when(expr = "the caller sends a chat completion request to LLM Surface {string} with their own provider key")]
async fn caller_sends_chat_completion_with_own_provider_key(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let authorization = format!("Bearer {CALLER_PROVIDER_KEY}");
    send_chat_completion_with_headers(world, &surface_name, [("Authorization", authorization.as_str())]).await;
}

#[when(expr = "member {string} creates a batch through LLM Surface {string}")]
async fn member_creates_batch_through_llm_surface(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/batches", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, &member_name);
    let response = world
        .admin_client()
        .post_caller_json_with_header(
            &path,
            json!({
                "input_file_id": "file-bdd-batch",
                "endpoint": "/v1/chat/completions",
                "completion_window": "24h"
            }),
            &header,
            &value,
        )
        .await;
    world.caller_response = Some(response);
}

#[when(expr = "member {string} asks LLM Surface {string} to search the web")]
async fn member_asks_llm_surface_to_search_the_web(
    world: &mut SurfaceWorld,
    member_name: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let (header, value) = member_identity_header(world, &member_name);
    let mut body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    body["tools"] = json!([{ "type": "web_search" }]);
    let response = world
        .admin_client()
        .post_caller_json_with_header(&path, body, &header, &value)
        .await;
    world.caller_response = Some(response);
}

#[then(expr = "member {string} is refused because a hosted tool on the operator's provider key is not metered")]
async fn member_is_refused_because_hosted_tool_is_not_metered(
    world: &mut SurfaceWorld,
    member_name: String,
) {
    let _ = member_name;
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected a refusal SDKs do not retry, got {}: {}",
        response.status, response.text
    );
    assert_eq!(response.body["error"]["type"], "permission_error", "got {}", response.text);
    assert_eq!(response.body["error"]["code"], "tool_not_metered", "got {}", response.text);
}

#[then(expr = "member {string} is refused because a batch on the operator's provider key is not metered")]
async fn member_is_refused_because_batch_is_not_metered(
    world: &mut SurfaceWorld,
    member_name: String,
) {
    let _ = member_name;
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected a refusal SDKs do not retry, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "permission_error",
        "expected a permission error, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "batch_not_metered",
        "expected the batch refusal's own code, not the team gate's, got {}",
        response.text
    );
}

#[then(expr = "member {string} is rejected because the member budget is spent")]
async fn member_is_rejected_because_member_budget_is_spent(
    world: &mut SurfaceWorld,
    member_name: String,
) {
    assert_rate_limit_response(world, "team_quota_exceeded", Some(&format!("member '{member_name}' monthly budget")));
}

#[then(expr = "provider {string} received the caller's own provider key only on the last request")]
async fn provider_received_callers_own_key_only_on_last_request(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    let (last, earlier) = requests
        .split_last()
        .expect("expected the provider to receive a request");
    let caller_key = format!("Bearer {CALLER_PROVIDER_KEY}");
    assert_eq!(
        last.headers
            .get("authorization")
            .map(String::as_str),
        Some(caller_key.as_str()),
        "expected the last request to carry the caller's own provider key"
    );
    assert!(
        earlier
            .iter()
            .all(|request| request
                .headers
                .get("authorization")
                != Some(&caller_key)),
        "expected earlier requests to go out without the caller's key"
    );
}

#[then(expr = "the caller is rejected by the Surface request limit")]
async fn caller_is_rejected_by_surface_request_limit(world: &mut SurfaceWorld) {
    assert_rate_limit_response(world, "rate_limit_exceeded", None);
}

#[then(expr = "the caller is rejected because the Surface token cap is exhausted")]
async fn caller_is_rejected_because_surface_token_cap_is_exhausted(world: &mut SurfaceWorld) {
    assert_rate_limit_response(world, "rate_limit_exceeded", None);
}

#[then(expr = "member {string} is rejected by the member request limit")]
async fn member_is_rejected_by_member_request_limit(
    world: &mut SurfaceWorld,
    member_name: String,
) {
    let _ = member_name;
    assert_rate_limit_response(world, "member_rate_limit_exceeded", None);
}

#[then(expr = "member {string} is rejected because the model requires a different team")]
async fn member_is_rejected_because_model_requires_different_team(
    world: &mut SurfaceWorld,
    _member_name: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 403, "expected team entitlement rejection, got {}: {}", response.status, response.text);
    assert_eq!(response.body["error"]["type"], "permission_error", "expected permission error, got {}", response.text);
    assert_eq!(
        response.body["error"]["code"], "team_not_permitted",
        "expected team entitlement code, got {}",
        response.text
    );
}

#[then(expr = "member {string} is rejected because the member token cap is exhausted")]
async fn member_is_rejected_because_member_token_cap_is_exhausted(
    world: &mut SurfaceWorld,
    member_name: String,
) {
    assert_rate_limit_response(world, "team_quota_exceeded", Some(&format!("member '{member_name}'")));
}

#[then(expr = "member {string} is rejected because team {string} token cap is exhausted")]
async fn member_is_rejected_because_team_token_cap_is_exhausted(
    world: &mut SurfaceWorld,
    _member_name: String,
    team_name: String,
) {
    assert_rate_limit_response(world, "team_quota_exceeded", Some(&format!("team '{team_name}'")));
}

fn assert_rate_limit_response(
    world: &SurfaceWorld,
    expected_code: &str,
    expected_message_fragment: Option<&str>,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 429, "expected usage limit rejection, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["type"], "rate_limit_error",
        "expected rate limit error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], expected_code,
        "expected rate limit code {expected_code:?}, got {}",
        response.text
    );
    if let Some(fragment) = expected_message_fragment {
        assert!(
            response.body["error"]["message"]
                .as_str()
                .is_some_and(|message| message.contains(fragment)),
            "expected rate limit message containing {fragment:?}, got {}",
            response.text
        );
    }
}
