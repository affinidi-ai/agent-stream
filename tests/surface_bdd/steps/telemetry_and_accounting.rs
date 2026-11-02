use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::then;

#[then(expr = "the response reports {int} input tokens, {int} output tokens, and {int} total tokens")]
async fn response_reports_token_usage(
    world: &mut SurfaceWorld,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
) {
    let response = caller_response(world);
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-input-tokens")
            .map(String::as_str),
        Some(
            input_tokens
                .to_string()
                .as_str()
        )
    );
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-output-tokens")
            .map(String::as_str),
        Some(
            output_tokens
                .to_string()
                .as_str()
        )
    );
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-total-tokens")
            .map(String::as_str),
        Some(
            total_tokens
                .to_string()
                .as_str()
        )
    );
}

#[then(expr = "the response reports a cost of {float} dollars")]
async fn response_reports_cost(
    world: &mut SurfaceWorld,
    expected_cost: f64,
) {
    let response = caller_response(world);
    let actual = response
        .headers
        .get("x-agent-stream-cost-usd")
        .expect("response should report cost")
        .parse::<f64>()
        .expect("reported cost should be numeric");
    assert!((actual - expected_cost).abs() < 1e-9, "expected cost {expected_cost}, got {actual}");
}

#[then(expr = "LLM Surface {string} telemetry attributes {int} tokens to the {word} stage")]
async fn telemetry_attributes_tokens_to_stage(
    world: &mut SurfaceWorld,
    surface_name: String,
    expected_tokens: u64,
    stage: String,
) {
    let stats = pipe_stats(world, &surface_name, expected_tokens).await;
    let stage_key = stage.to_ascii_lowercase();
    let stage_stats = &stats["stage_usage"][stage_key];
    let actual = stage_stats["total_input_tokens"]
        .as_u64()
        .unwrap_or(0)
        + stage_stats["total_output_tokens"]
            .as_u64()
            .unwrap_or(0);
    assert_eq!(actual, expected_tokens, "expected {stage} stage token attribution, got {stats}");
}

#[then(expr = "LLM Surface {string} telemetry reports {int} total tokens")]
async fn telemetry_reports_total_tokens(
    world: &mut SurfaceWorld,
    surface_name: String,
    expected_tokens: u64,
) {
    let stats = pipe_stats(world, &surface_name, expected_tokens).await;
    let actual = stats["total_input_tokens"]
        .as_u64()
        .unwrap_or(0)
        + stats["total_output_tokens"]
            .as_u64()
            .unwrap_or(0);
    assert_eq!(actual, expected_tokens, "expected total token accounting, got {stats}");
}

#[then(expr = "team {string} accounting reports {int} total tokens")]
async fn team_accounting_reports_total_tokens(
    world: &mut SurfaceWorld,
    team_name: String,
    expected_tokens: u64,
) {
    let report = team_usage_report(world, &team_name).await;
    assert_eq!(report["total_tokens"], expected_tokens, "expected team token accounting, got {report}");
}

#[then(expr = "member {string} accounting reports {int} total tokens for team {string}")]
async fn member_accounting_reports_total_tokens(
    world: &mut SurfaceWorld,
    member_name: String,
    expected_tokens: u64,
    team_name: String,
) {
    let report = team_usage_report(world, &team_name).await;
    let member_id = world
        .member_ids
        .get(&member_name)
        .expect("member should have an id");
    let member = report["members"]
        .as_array()
        .and_then(|members| {
            members
                .iter()
                .find(|member| member["member_id"] == *member_id)
        })
        .unwrap_or_else(|| panic!("member {member_name:?} should appear in team usage report: {report}"));
    assert_eq!(member["total_tokens"], expected_tokens, "expected member token accounting, got {member}");
}

#[then(expr = "cache accounting reports {int} hit, {int} saved tokens, and {float} saved dollars")]
async fn cache_accounting_reports_savings(
    world: &mut SurfaceWorld,
    expected_hits: u64,
    expected_saved_tokens: u64,
    expected_saved_cost: f64,
) {
    let response = caller_response(world);
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-total-tokens")
            .and_then(|value| value.parse::<u64>().ok()),
        Some(expected_saved_tokens),
        "expected cache hit to expose avoided token usage"
    );
    let stats = world
        .admin_client()
        .get_admin_json("/v1/cache/stats")
        .await;
    assert_eq!(stats.status, 200, "expected cache accounting lookup to succeed: {}", stats.text);
    assert_eq!(stats.body["hits"], expected_hits, "expected cache hit accounting, got {}", stats.text);
    let actual_saved_cost = stats.body["saved_cost_usd"]
        .as_f64()
        .unwrap_or_default();
    assert!(
        (actual_saved_cost - expected_saved_cost).abs() < 1e-9,
        "expected {expected_saved_cost} saved dollars, got {actual_saved_cost}"
    );
}

async fn pipe_stats(
    world: &SurfaceWorld,
    surface_name: &str,
    minimum_tokens: u64,
) -> serde_json::Value {
    let pipe_id = surface_id(surface_name);
    for _ in 0..30 {
        let response = world
            .admin_client()
            .get_admin_json(&format!("/v1/dashboard/delta?pipe_id={pipe_id}"))
            .await;
        assert_eq!(response.status, 200, "expected telemetry lookup to succeed: {}", response.text);
        if let Some(stats) = response.body["changes"]["metrics"]["pipe_stats"]
            .as_array()
            .and_then(|stats| stats.first())
        {
            let tokens = stats["total_input_tokens"]
                .as_u64()
                .unwrap_or(0)
                + stats["total_output_tokens"]
                    .as_u64()
                    .unwrap_or(0);
            if tokens >= minimum_tokens || minimum_tokens == 0 {
                return stats.clone();
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    panic!("telemetry for LLM Surface {surface_name:?} did not become available");
}

async fn team_usage_report(
    world: &SurfaceWorld,
    team_name: &str,
) -> serde_json::Value {
    let team_id = world
        .team_ids
        .get(team_name)
        .unwrap_or_else(|| panic!("team {team_name:?} should have an id"));
    let response = world
        .admin_client()
        .get_admin_json(&format!("/v1/teams/{team_id}/usage"))
        .await;
    assert_eq!(response.status, 200, "expected team usage lookup to succeed: {}", response.text);
    response.body
}
