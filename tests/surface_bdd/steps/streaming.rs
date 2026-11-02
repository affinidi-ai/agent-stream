use super::support::*;
use crate::world::SurfaceWorld;
use cucumber::{given, then, when};
use serde_json::json;

#[given(expr = "provider {string} can stream chat completion {string} without reporting usage")]
async fn provider_can_stream_chat_completion_without_usage(
    world: &mut SurfaceWorld,
    provider_name: String,
    content: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    let server = &world
        .provider(&provider_name)
        .server;
    server
        .set_chat_completion_content(content)
        .await;
    server
        .stream_without_usage()
        .await;
}

#[given(expr = "provider {string} can stream chat completion {string}")]
async fn provider_can_stream_chat_completion(
    world: &mut SurfaceWorld,
    provider_name: String,
    content: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_content(content)
        .await;
}

#[given(expr = "provider {string} is unavailable for streaming chat completions")]
async fn provider_is_unavailable_for_streaming_chat_completions(
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

#[given(expr = "the operator has disabled streaming for LLM Surface {string}")]
async fn operator_has_disabled_streaming(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    update_surface(world, &surface_name, |pipe| pipe["streaming"] = json!({ "enabled": false }), "streaming").await;
}

#[given(expr = "the caller has already streamed a chat completion through LLM Surface {string}")]
async fn caller_has_already_streamed_chat_completion(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_streaming_chat_prompt(world, &route, "Say hello through Agent Stream").await;
    let response = world
        .caller_response
        .as_ref()
        .expect("streaming response should be recorded");
    assert_eq!(response.status, 200, "expected initial stream to succeed, got {}: {}", response.status, response.text);
}

#[when(expr = "the caller requests a streamed chat completion from LLM Surface {string}")]
async fn caller_requests_streamed_chat_completion(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_streaming_chat_prompt(world, &route, DEFAULT_CALLER_PROMPT).await;
}

#[when(expr = "the caller requests a streamed chat completion with usage switched off from LLM Surface {string}")]
async fn caller_requests_streamed_chat_completion_without_usage(
    world: &mut SurfaceWorld,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    let path = format!("{}/v1/chat/completions", route.trim_end_matches('/'));
    let mut body = chat_completion_body(DEFAULT_CALLER_PROMPT);
    body["stream"] = serde_json::json!(true);
    body["stream_options"] = serde_json::json!({ "include_usage": false });
    let response = world
        .admin_client()
        .post_caller_json(&path, body)
        .await;
    world.last_caller_prompt = Some(DEFAULT_CALLER_PROMPT.to_string());
    world.caller_response = Some(response);
}

#[when(expr = "the caller requests streamed chat prompt {string} from LLM Surface {string}")]
async fn caller_requests_streamed_chat_prompt(
    world: &mut SurfaceWorld,
    prompt: String,
    surface_name: String,
) {
    let route = route_for_surface(world, &surface_name);
    send_streaming_chat_prompt(world, &route, &prompt).await;
}

#[then(expr = "the caller receives an OpenAI-compatible event stream containing {string}")]
async fn caller_receives_openai_event_stream_containing(
    world: &mut SurfaceWorld,
    content: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("streaming response should be recorded");
    assert_eq!(response.status, 200, "expected successful event stream, got {}: {}", response.status, response.text);
    assert_eq!(
        response
            .headers
            .get("content-type")
            .map(String::as_str),
        Some("text/event-stream"),
        "expected SSE content type, got {:?}",
        response.headers
    );
    assert!(
        response
            .text
            .contains("chat.completion.chunk"),
        "expected OpenAI-compatible chunks, got {}",
        response.text
    );
    assert!(
        response
            .text
            .contains(&content),
        "expected streamed content {content:?}, got {}",
        response.text
    );
}

#[then(expr = "the event stream ends with {string}")]
async fn event_stream_ends_with(
    world: &mut SurfaceWorld,
    terminal: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("streaming response should be recorded");
    assert!(
        response
            .text
            .trim_end()
            .ends_with(&format!("data: {terminal}")),
        "expected terminal event {terminal:?}, got {}",
        response.text
    );
}

#[then(expr = "the streaming response identifies provider {string}")]
async fn streaming_response_identifies_provider(
    world: &mut SurfaceWorld,
    provider: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("streaming response should be recorded");
    assert_eq!(
        response
            .headers
            .get("x-agent-stream-provider"),
        Some(&provider),
        "expected streaming provider header, got {:?}",
        response.headers
    );
}

#[then(expr = "provider {string} received a streaming chat completion request with usage enabled")]
async fn provider_received_streaming_request_with_usage(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected provider {provider_name:?} to receive one streaming request");
    assert_eq!(requests[0].body["stream"], true, "expected streaming provider request");
    assert_eq!(requests[0].body["stream_options"]["include_usage"], true, "expected streaming usage to be enabled");
}

#[then(expr = "the caller is told the streaming provider is unavailable")]
async fn caller_is_told_streaming_provider_is_unavailable(world: &mut SurfaceWorld) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 502,
        "expected unavailable streaming provider response, got {}: {}",
        response.status, response.text
    );
    assert_eq!(response.body["error"]["type"], "provider_error", "expected provider error type, got {}", response.text);
    assert_eq!(response.body["error"]["code"], "provider_error", "expected provider error code, got {}", response.text);
    assert_eq!(
        response.body["error"]["upstream_status"], 503,
        "expected unavailable upstream status, got {}",
        response.text
    );
}

#[then(expr = "the caller receives buffered chat completion {string}")]
async fn caller_receives_buffered_chat_completion(
    world: &mut SurfaceWorld,
    content: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected successful buffered response, got {}: {}",
        response.status, response.text
    );
    assert_ne!(
        response
            .headers
            .get("content-type")
            .map(String::as_str),
        Some("text/event-stream"),
        "expected buffered response"
    );
    assert_eq!(
        response.body["choices"][0]["message"]["content"], content,
        "expected buffered completion content, got {}",
        response.text
    );
}

#[then(expr = "provider {string} received a buffered chat completion request")]
async fn provider_received_buffered_chat_completion_request(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected provider {provider_name:?} to receive one buffered request");
    assert_eq!(
        requests[0]
            .body
            .get("stream")
            .and_then(serde_json::Value::as_bool),
        Some(false),
        "expected gateway to request a buffered provider response, got {}",
        requests[0].body
    );
}
