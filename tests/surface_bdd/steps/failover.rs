use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then};
use serde_json::json;

#[given(expr = "LLM Surface {string} fails over to provider {string}")]
async fn llm_surface_fails_over_to_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    provider_name: String,
) {
    configure_llm_surface_failover(world, &surface_name, [&provider_name]).await;
}

#[given(expr = "LLM Surface {string} fails over in order to provider {string} then provider {string}")]
async fn llm_surface_fails_over_in_order_to_providers(
    world: &mut SurfaceWorld,
    surface_name: String,
    first_provider_name: String,
    second_provider_name: String,
) {
    configure_llm_surface_failover(world, &surface_name, [&first_provider_name, &second_provider_name]).await;
}

#[given(expr = "LLM Surface {string} opens its circuit breaker after {int} provider failure")]
async fn llm_surface_opens_circuit_breaker_after_failures(
    world: &mut SurfaceWorld,
    surface_name: String,
    failure_threshold: u32,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["circuit_breaker"] = json!({
                "failure_threshold": failure_threshold,
                "timeout_seconds": 60,
                "reset_timeout_seconds": 30
            });
        },
        "circuit breaker",
    )
    .await;
}

#[given(expr = "the caller has already sent a chat completion request to LLM Surface {string}")]
async fn caller_has_already_sent_chat_completion(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    invoke_surface_and_require_success(world, &surface_name).await;
}

#[given(expr = "the caller has already had prompt {string} rejected by LLM Surface {string}")]
async fn caller_has_already_had_prompt_rejected(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, &prompt).await;
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 403,
        "expected the seeded prompt to be rejected by the guard, got {}: {}",
        response.status, response.text
    );
}

async fn configure_llm_surface_failover<const N: usize>(
    world: &mut SurfaceWorld,
    surface_name: &str,
    provider_names: [&str; N],
) {
    let targets = provider_names
        .into_iter()
        .map(|provider_name| {
            json!({
                "llm": {
                    "provider_type": "openai",
                    "model": "mock-small",
                    "endpoint_url": world.provider(provider_name).server.base_url(),
                    "timeout_secs": 5,
                    "api_schema": "openai"
                }
            })
        })
        .collect::<Vec<_>>();
    update_surface(
        world,
        surface_name,
        |pipe| pipe["failover"] = json!({ "enabled": true, "targets": targets }),
        "failover",
    )
    .await;
}

#[then(expr = "providers {string} then {string} were invoked in order")]
async fn two_providers_were_invoked_in_order(
    world: &mut SurfaceWorld,
    first: String,
    second: String,
) {
    let first_requests = world
        .provider(&first)
        .server
        .received_chat_completions()
        .await;
    let second_requests = world
        .provider(&second)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(first_requests.len(), 1, "expected provider {first:?} to receive one request");
    assert_eq!(second_requests.len(), 1, "expected provider {second:?} to receive one request");
    assert!(
        first_requests[0].received_at < second_requests[0].received_at,
        "expected provider invocation order {first:?}, {second:?}"
    );
}

#[then(expr = "providers {string}, {string}, and {string} were invoked in order")]
async fn providers_were_invoked_in_order(
    world: &mut SurfaceWorld,
    first: String,
    second: String,
    third: String,
) {
    let first_requests = world
        .provider(&first)
        .server
        .received_chat_completions()
        .await;
    let second_requests = world
        .provider(&second)
        .server
        .received_chat_completions()
        .await;
    let third_requests = world
        .provider(&third)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(first_requests.len(), 1, "expected provider {first:?} to receive one request");
    assert_eq!(second_requests.len(), 1, "expected provider {second:?} to receive one request");
    assert_eq!(third_requests.len(), 1, "expected provider {third:?} to receive one request");
    assert!(
        first_requests[0].received_at < second_requests[0].received_at
            && second_requests[0].received_at < third_requests[0].received_at,
        "expected provider invocation order {first:?}, {second:?}, {third:?}"
    );
}

#[then(expr = "the failover metrics record a successful failover to the first backup")]
async fn failover_metrics_record_backup_success(world: &mut SurfaceWorld) {
    let text = scrape_prometheus_metrics(world).await;
    assert_eq!(
        metric_value(&text, "agent_stream_llm_failover_total", &[("event", "backup_success"), ("reason", "none")]),
        1.0,
        "expected one backup_success failover event\n{text}"
    );
    assert_eq!(
        metric_value(
            &text,
            "agent_stream_llm_failover_backup_attempts_total",
            &[("target_index", "1"), ("result", "success")],
        ),
        1.0,
        "expected one successful backup attempt on target 1\n{text}"
    );
    assert!(
        metric_value(&text, "agent_stream_llm_failover_total", &[("event", "primary_failure")]) >= 1.0,
        "expected at least one primary_failure failover event\n{text}"
    );
}

#[then(expr = "the failover metrics record all backups exhausted")]
async fn failover_metrics_record_exhaustion(world: &mut SurfaceWorld) {
    let text = scrape_prometheus_metrics(world).await;
    assert_eq!(
        metric_value(&text, "agent_stream_llm_failover_total", &[("event", "exhausted")]),
        1.0,
        "expected one exhausted failover event\n{text}"
    );
    assert_eq!(
        metric_value(&text, "agent_stream_llm_failover_total", &[("event", "backup_success")]),
        0.0,
        "expected no backup_success when every backup fails\n{text}"
    );
    for index in ["1", "2"] {
        assert_eq!(
            metric_value(
                &text,
                "agent_stream_llm_failover_backup_attempts_total",
                &[("target_index", index), ("result", "failure")],
            ),
            1.0,
            "expected a failed backup attempt on target {index}\n{text}"
        );
    }
}

/// Scrape the appliance's Prometheus text endpoint. Each scenario runs its own
/// appliance process, so the returned counters start at zero and reflect only
/// this scenario's traffic.
async fn scrape_prometheus_metrics(world: &SurfaceWorld) -> String {
    let base_url = world
        .infra
        .as_ref()
        .expect("appliance should be running")
        ._appliance
        .base_url();
    reqwest::Client::new()
        .get(format!("{base_url}/v1/metrics/prometheus"))
        .send()
        .await
        .expect("metrics endpoint should respond")
        .text()
        .await
        .expect("metrics body should decode")
}

/// Read a single Prometheus counter value from scraped text, matching a metric
/// name and a subset of its labels. Returns 0.0 when the series is absent (an
/// untouched labeled counter emits no line).
fn metric_value(
    text: &str,
    metric: &str,
    labels: &[(&str, &str)],
) -> f64 {
    text.lines()
        .filter(|line| line.starts_with(metric))
        .find(|line| {
            labels
                .iter()
                .all(|(key, value)| line.contains(&format!("{key}=\"{value}\"")))
        })
        .and_then(|line| line.split_whitespace().last())
        .and_then(|value| value.parse().ok())
        .unwrap_or(0.0)
}

#[then(expr = "the caller is told all failover providers are unavailable")]
async fn caller_is_told_all_failover_providers_are_unavailable(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 502,
        "expected exhausted failover response, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["error"]["type"], "provider_error",
        "expected exhausted failover provider error type, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["code"], "provider_error",
        "expected exhausted failover provider error code, got {}",
        response.text
    );
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected final unavailable upstream status, got {}",
        response.text
    );
    assert!(
        response
            .text
            .contains("delta"),
        "expected final provider error to identify delta, got {}",
        response.text
    );
}
