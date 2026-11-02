use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "LLM Surface {string} has variant {string} targeting provider {string}")]
async fn llm_surface_has_variant_targeting_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    alias: String,
    provider_name: String,
) {
    add_llm_surface_variant(world, &surface_name, &alias, &provider_name, true).await;
}

#[given(expr = "LLM Surface {string} has disabled variant {string} targeting provider {string}")]
async fn llm_surface_has_disabled_variant_targeting_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    alias: String,
    provider_name: String,
) {
    add_llm_surface_variant(world, &surface_name, &alias, &provider_name, false).await;
}

#[given(expr = "LLM Surface {string} routes header {string} value {string} to variant {string}")]
async fn llm_surface_routes_header_value_to_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    header: String,
    value: String,
    alias: String,
) {
    configure_routing_rule(
        world,
        &surface_name,
        json!({ "kind": "header", "name": header, "equals": value }),
        json!({ "variant": alias }),
    )
    .await;
}

#[given(expr = "LLM Surface {string} routes body field {string} value {string} to provider {string}")]
async fn llm_surface_routes_body_field_value_to_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    field: String,
    value: String,
    provider_name: String,
) {
    let endpoint = world
        .provider(&provider_name)
        .server
        .base_url()
        .to_string();
    configure_routing_rule(
        world,
        &surface_name,
        json!({ "kind": "body_field", "field": field, "equals": value }),
        json!({
            "llm": {
                "provider_type": "openai",
                "model": "mock-small",
                "endpoint_url": endpoint,
                "timeout_secs": 5,
                "api_schema": "openai"
            }
        }),
    )
    .await;
}

#[given(expr = "LLM Surface {string} sends 100 percent of eligible traffic to variant {string}")]
async fn llm_surface_sends_all_eligible_traffic_to_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    alias: String,
) {
    update_surface(
        world,
        &surface_name,
        |pipe| pipe["canary"] = json!({ "enabled": true, "splits": [{ "variant": alias, "weight": 100 }] }),
        "canary routing",
    )
    .await;
}

async fn add_llm_surface_variant(
    world: &mut SurfaceWorld,
    surface_name: &str,
    alias: &str,
    provider_name: &str,
    enabled: bool,
) {
    let base_url = world
        .provider(provider_name)
        .server
        .base_url()
        .to_string();
    let variant = json!({
        "id": format!("bdd-variant-{alias}"),
        "alias": alias,
        "name": alias,
        "enabled": enabled,
        "overrides": {
            "pipe_type": {
                "type": "llm",
                "provider": {
                    "provider_type": "openai",
                    "model": "mock-small",
                    "base_url": base_url
                }
            }
        }
    });
    update_surface(
        world,
        surface_name,
        |pipe| {
            if !pipe["variants"].is_array() {
                pipe["variants"] = json!([]);
            }
            pipe["variants"]
                .as_array_mut()
                .expect("LLM Surface variants should be an array")
                .push(variant);
        },
        "variant",
    )
    .await;
}

async fn configure_routing_rule(
    world: &mut SurfaceWorld,
    surface_name: &str,
    match_on: serde_json::Value,
    target: serde_json::Value,
) {
    update_surface(
        world,
        surface_name,
        |pipe| pipe["routing_rules"] = json!([{ "match": match_on, "target": target }]),
        "routing rule",
    )
    .await;
}

#[given(expr = "LLM Surface {string} routes modality {string} to variant {string}")]
async fn llm_surface_routes_modality_to_variant(
    world: &mut SurfaceWorld,
    surface_name: String,
    modality: String,
    alias: String,
) {
    configure_routing_rule(
        world,
        &surface_name,
        json!({ "kind": "modality", "has": modality }),
        json!({ "variant": alias }),
    )
    .await;
}

#[given(expr = "LLM Surface {string} has vision variant {string} targeting provider {string}")]
async fn llm_surface_has_vision_variant_targeting_provider(
    world: &mut SurfaceWorld,
    surface_name: String,
    alias: String,
    provider_name: String,
) {
    let base_url = world
        .provider(&provider_name)
        .server
        .base_url()
        .to_string();
    let variant = json!({
        "id": format!("bdd-variant-{alias}"),
        "alias": alias,
        "name": alias,
        "enabled": true,
        "overrides": {
            "pipe_type": {
                "type": "llm",
                "provider": { "provider_type": "openai", "model": "mock-small", "base_url": base_url }
            },
            "image_input": { "enabled": true, "allowed_formats": ["png", "jpeg", "gif", "webp"] }
        }
    });
    update_surface(
        world,
        &surface_name,
        |pipe| {
            if !pipe["variants"].is_array() {
                pipe["variants"] = json!([]);
            }
            pipe["variants"]
                .as_array_mut()
                .expect("LLM Surface variants should be an array")
                .push(variant);
        },
        "vision variant",
    )
    .await;
}

#[when(expr = "the caller sends a chat completion request with an image to LLM Surface {string}")]
async fn caller_sends_chat_completion_with_image(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let body = json!({
        "model": "mock-small",
        "messages": [{
            "role": "user",
            "content": [
                { "type": "text", "text": DEFAULT_CALLER_PROMPT },
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0KGgo=" } }
            ]
        }]
    });
    let response = world
        .admin_client()
        .post_caller_json(&path, body)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(expr = "the caller sends chat prompt {string} to variant {string} of LLM Surface {string}")]
async fn caller_sends_chat_prompt_to_variant(
    world: &mut SurfaceWorld,
    prompt: String,
    alias: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}${}/v1/chat/completions", route.trim_end_matches('/'), alias);
    let response = world
        .admin_client()
        .post_caller_json(&path, chat_completion_body(&prompt))
        .await;
    world.last_caller_prompt = Some(prompt);
    world.caller_response = Some(response);
}

#[when(expr = "the caller sends a chat completion request to variant {string} of LLM Surface {string}")]
async fn caller_sends_chat_completion_to_variant(
    world: &mut SurfaceWorld,
    alias: String,
    surface_name: String,
) {
    send_chat_completion_to_variant_with_header(world, &surface_name, &alias, None).await;
}

#[when(expr = "the caller sends a chat completion request with header {string} value {string} to LLM Surface {string}")]
async fn caller_sends_chat_completion_with_header(
    world: &mut SurfaceWorld,
    header: String,
    value: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let response = world
        .admin_client()
        .post_caller_json_with_header(&path, chat_completion_body(DEFAULT_CALLER_PROMPT), &header, &value)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(
    expr = "the caller sends a chat completion request with body field {string} value {string} to LLM Surface {string} with their own provider key"
)]
async fn caller_sends_chat_completion_with_body_field_and_own_provider_key(
    world: &mut SurfaceWorld,
    field: String,
    value: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let mut body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    body[field] = json!(value);
    let authorization = format!("Bearer {CALLER_PROVIDER_KEY}");
    let response = world
        .admin_client()
        .post_caller_json_with_headers(&path, body, [("Authorization", authorization.as_str())])
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(
    expr = "the caller sends a chat completion request with body field {string} value {string} to LLM Surface {string}"
)]
async fn caller_sends_chat_completion_with_body_field(
    world: &mut SurfaceWorld,
    field: String,
    value: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let mut body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    body[field] = json!(value);
    let response = world
        .admin_client()
        .post_caller_json(&path, body)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(
    expr = "the caller sends a chat completion request with header {string} value {string} to variant {string} of LLM Surface {string}"
)]
async fn caller_sends_chat_completion_with_header_to_variant(
    world: &mut SurfaceWorld,
    header: String,
    value: String,
    alias: String,
    surface_name: String,
) {
    send_chat_completion_to_variant_with_header(world, &surface_name, &alias, Some((&header, &value))).await;
}

#[then(expr = "the caller is told variant {string} is disabled")]
async fn caller_is_told_variant_is_disabled(
    world: &mut SurfaceWorld,
    alias: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 503, "expected disabled variant response, got {}: {}", response.status, response.text);
    assert_eq!(
        response.body["error"]["code"], "variant_disabled",
        "expected disabled variant code for {alias:?}, got {}",
        response.text
    );
    assert!(
        response.text.contains(&alias),
        "expected disabled variant response to identify {alias:?}, got {}",
        response.text
    );
}
