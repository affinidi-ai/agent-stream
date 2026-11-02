use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::given;
use serde_json::json;

#[given(expr = "LLM Surface {string} balances traffic with primary weight {int} and provider {string} weight {int}")]
async fn llm_surface_balances_weighted_traffic(
    world: &mut SurfaceWorld,
    surface_name: String,
    primary_weight: u32,
    provider_name: String,
    provider_weight: u32,
) {
    let endpoint = world
        .provider(&provider_name)
        .server
        .base_url()
        .to_string();
    update_surface(
        world,
        &surface_name,
        |pipe| {
            pipe["load_balancing"] = json!({
                "enabled": true,
                "strategy": "weighted",
                "primary_weight": primary_weight,
                "targets": [{
                    "llm": {
                        "provider_type": "openai",
                        "model": "mock-small",
                        "endpoint_url": endpoint,
                        "timeout_secs": 5,
                        "api_schema": "openai"
                    },
                    "weight": provider_weight
                }]
            });
        },
        "load balancing",
    )
    .await;
}

#[given(expr = "the caller has received one chat completion from provider {string} through LLM Surface {string}")]
async fn caller_has_received_one_completion_from_provider(
    world: &mut SurfaceWorld,
    provider_name: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_chat_prompt(world, &route, "Say hello through Agent Stream").await;
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected initial load-balanced request to succeed, got {}: {}",
        response.status, response.text
    );
    assert!(
        response
            .text
            .contains(&format!("hello from {provider_name}")),
        "expected initial completion from provider {provider_name:?}, got {}",
        response.text
    );
}
