use crate::world::SurfaceWorld;

use super::support::*;
use cucumber::{given, then};

#[given(expr = "provider {string} can return chat completions")]
async fn provider_can_return_chat_completions(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
}

#[given(expr = "provider {string} takes {int} seconds to return chat completions")]
async fn provider_takes_seconds_to_return_chat_completions(
    world: &mut SurfaceWorld,
    provider_name: String,
    delay_seconds: u64,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_delay(std::time::Duration::from_secs(delay_seconds))
        .await;
}

#[given(expr = "provider {string} is unavailable for chat completions")]
async fn provider_is_unavailable_for_chat_completions(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    make_chat_completions_unavailable(world, &provider_name).await;
}

#[given(expr = "provider {string} is unauthorized for chat completions")]
async fn provider_is_unauthorized_for_chat_completions(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .make_chat_completions_unauthorized()
        .await;
}

#[given(expr = "provider {string} returns chat completion {string}")]
async fn provider_returns_chat_completion(
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

#[given(expr = "provider {string} returns chat completions {string} then {string}")]
async fn provider_returns_chat_completions(
    world: &mut SurfaceWorld,
    provider_name: String,
    first_content: String,
    second_content: String,
) {
    world
        .ensure_provider(&provider_name)
        .await;
    world
        .provider(&provider_name)
        .server
        .set_chat_completion_contents(vec![first_content, second_content])
        .await;
}

#[given(expr = "provider {string} always returns chat completion {string}")]
async fn provider_always_returns_chat_completion(
    world: &mut SurfaceWorld,
    provider_name: String,
    content: String,
) {
    provider_returns_chat_completion(world, provider_name, content).await;
}

#[then(expr = "provider {string} received {int} chat completion requests")]
async fn provider_received_chat_completion_requests(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected_count: usize,
) {
    assert_provider_chat_completion_count(world, &provider_name, expected_count).await;
}

#[then(expr = "provider {string} received {int} chat completion request")]
async fn provider_received_one_chat_completion_request(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected_count: usize,
) {
    assert_provider_chat_completion_count(world, &provider_name, expected_count).await;
}

async fn assert_provider_chat_completion_count(
    world: &SurfaceWorld,
    provider_name: &str,
    expected_count: usize,
) {
    let requests = world
        .provider(provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(
        requests.len(),
        expected_count,
        "expected provider {provider_name:?} to receive {expected_count} chat completion requests"
    );
}

#[then(expr = "provider {string} received no chat completion requests")]
async fn provider_received_no_chat_completion_requests(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let provider = world.provider(&provider_name);
    let requests = provider
        .server
        .received_chat_completions()
        .await;
    assert!(
        requests.is_empty(),
        "expected provider {provider_name:?} to receive no chat completion requests, got {}",
        requests.len()
    );
}

#[then(expr = "provider {string} received no {string} requests")]
async fn provider_received_no_operation_requests(
    world: &mut SurfaceWorld,
    provider_name: String,
    operation_name: String,
) {
    let received = received_operation_requests(world, &provider_name, &operation_name).await;
    assert_eq!(received, 0, "expected provider {provider_name:?} to receive no {operation_name:?} requests");
}

#[then(expr = "provider {string} received the {string} request")]
async fn provider_received_operation_request(
    world: &mut SurfaceWorld,
    provider_name: String,
    operation_name: String,
) {
    let received = received_operation_requests(world, &provider_name, &operation_name).await;
    assert_eq!(received, 1, "expected provider {provider_name:?} to receive one {operation_name:?} request");
}

/// How many `operation_name` requests the provider received: chat completions
/// from its chat recorder, every other request by method and path.
async fn received_operation_requests(
    world: &SurfaceWorld,
    provider_name: &str,
    operation_name: &str,
) -> usize {
    let operation = provider_operation(operation_name);
    let server = &world
        .provider(provider_name)
        .server;
    if operation.is_chat_completion() {
        server
            .received_chat_completions()
            .await
            .len()
    } else {
        server
            .received_api_requests(operation.method, operation.path)
            .await
            .len()
    }
}

#[then(expr = "the caller receives the {string} response from provider {string}")]
async fn caller_receives_operation_response_from_provider(
    world: &mut SurfaceWorld,
    operation_name: String,
    provider_name: String,
) {
    let operation = provider_operation(&operation_name);
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(
        response.status, 200,
        "expected a successful {operation_name:?} response, got {}: {}",
        response.status, response.text
    );
    assert_eq!(
        response.body["provider"], provider_name,
        "expected the {operation_name:?} response from provider {provider_name:?}, got {}",
        response.text
    );
    assert_eq!(
        response.body["path"], operation.path,
        "expected the provider to answer {}, got {}",
        operation.path, response.text
    );
}

#[then(expr = "provider {string} did not receive header {string}")]
async fn provider_did_not_receive_header(
    world: &mut SurfaceWorld,
    provider_name: String,
    header_name: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected one Provider request before checking headers");
    assert!(
        !requests[0]
            .headers
            .contains_key(&header_name.to_ascii_lowercase()),
        "expected source credential header {header_name:?} to be stripped, got {:?}",
        requests[0].headers
    );
}

#[then(expr = "the caller receives a successful chat completion from provider {string}")]
async fn caller_receives_successful_chat_completion_from_provider(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let response = world
        .caller_response
        .as_ref()
        .expect("caller response should be recorded");
    assert_eq!(response.status, 200, "expected successful chat completion, got {}: {}", response.status, response.text);
    let content = response.body["choices"][0]["message"]["content"]
        .as_str()
        .unwrap_or_default();
    assert_eq!(content, format!("hello from {provider_name}"), "expected provider completion to be preserved");
}

#[then(expr = "provider {string} received chat prompt {string}")]
async fn provider_received_chat_prompt(
    world: &mut SurfaceWorld,
    provider_name: String,
    expected_prompt: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected provider {provider_name:?} to receive one chat completion request");
    let messages = requests[0].body["messages"]
        .as_array()
        .expect("provider request should include messages");
    assert!(
        messages
            .iter()
            .any(|message| message["role"] == "user" && message["content"] == expected_prompt),
        "provider request should include exact prompt {expected_prompt:?}, got {}",
        requests[0].body
    );
}

#[then(expr = "provider {string} received the chat completion request")]
async fn provider_received_chat_completion_request(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let provider = world.provider(&provider_name);
    let requests = provider
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected provider {provider_name:?} to receive one chat completion request");
    let expected_prompt = world
        .last_caller_prompt
        .as_deref()
        .expect("caller prompt should be recorded");
    let messages = requests[0].body["messages"]
        .as_array()
        .expect("provider request should include messages");
    assert!(
        messages
            .iter()
            .any(|message| message["content"] == expected_prompt),
        "provider request should include caller prompt, got {}",
        requests[0].body
    );
}

#[then(expr = "provider {string} received a chat completion request with an image")]
async fn provider_received_chat_completion_request_with_image(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let provider = world.provider(&provider_name);
    let requests = provider
        .server
        .received_chat_completions()
        .await;
    assert_eq!(requests.len(), 1, "expected provider {provider_name:?} to receive one chat completion request");
    let messages = requests[0].body["messages"]
        .as_array()
        .expect("provider request should include messages");
    let has_image = messages
        .iter()
        .any(|message| {
            message["content"]
                .as_array()
                .map(|parts| {
                    parts
                        .iter()
                        .any(|part| part["type"] == "image_url")
                })
                .unwrap_or(false)
        });
    assert!(
        has_image,
        "expected provider {provider_name:?} to receive an image_url content part, got {}",
        requests[0].body
    );
}

#[then(expr = "provider {string} received provider key {string}")]
async fn provider_received_provider_key(
    world: &mut SurfaceWorld,
    provider_name: String,
    secret_id: String,
) {
    let expected = format!("Bearer {}", provider_key_value(&secret_id));
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    let received = requests
        .iter()
        .map(|request| {
            request
                .headers
                .get("authorization")
                .cloned()
        })
        .collect::<Vec<_>>();
    assert!(
        received
            .iter()
            .any(|authorization| authorization.as_deref() == Some(expected.as_str())),
        "expected provider {provider_name:?} to receive provider key {secret_id:?}, got authorization headers {received:?}"
    );
}

#[then(expr = "provider {string} received no provider key")]
async fn provider_received_no_provider_key(
    world: &mut SurfaceWorld,
    provider_name: String,
) {
    let requests = world
        .provider(&provider_name)
        .server
        .received_chat_completions()
        .await;
    assert!(!requests.is_empty(), "expected provider {provider_name:?} to receive a request");
    let authorizations = requests
        .iter()
        .filter_map(|request| {
            request
                .headers
                .get("authorization")
                .cloned()
        })
        .collect::<Vec<_>>();
    assert!(
        authorizations.is_empty(),
        "expected provider {provider_name:?} to receive no provider key, got authorization headers {authorizations:?}"
    );
}
