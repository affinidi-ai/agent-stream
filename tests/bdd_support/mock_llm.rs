use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    Json, Router,
    http::{Method, StatusCode, Uri},
    response::IntoResponse,
    routing::{get, post},
};
use serde_json::Value;
use tokio::sync::{Mutex, oneshot};

#[derive(Debug, Clone)]
pub struct ReceivedChatCompletion {
    pub body: Value,
    pub headers: HashMap<String, String>,
    pub received_at: Instant,
}

/// A request to one of the provider's non-chat endpoints (models, files, batches,
/// speech-to-text), recorded by method and path.
#[derive(Debug, Clone)]
pub struct ReceivedApiRequest {
    pub method: String,
    pub path: String,
}

#[derive(Debug, Clone)]
pub struct ReceivedGuardrailInspection {
    pub body: Value,
}

#[derive(Debug, Clone, Copy)]
enum GuardrailVerdict {
    Allow,
    Flag,
    Unavailable,
}

#[derive(Debug)]
struct State {
    name: String,
    unavailable_for_chat_completions: Mutex<bool>,
    unauthorized_for_chat_completions: Mutex<bool>,
    chat_completion_delay: Mutex<Duration>,
    chat_completion_contents: Mutex<VecDeque<String>>,
    rejected_response_pattern: Mutex<Option<String>>,
    /// Streams end without a usage chunk, whatever the request asked for.
    streams_without_usage: Mutex<bool>,
    guardrail_verdict: Mutex<GuardrailVerdict>,
    requests: Mutex<Vec<ReceivedChatCompletion>>,
    api_requests: Mutex<Vec<ReceivedApiRequest>>,
    guardrail_inspections: Mutex<Vec<ReceivedGuardrailInspection>>,
}

#[derive(Debug)]
pub struct MockLlmProvider {
    base_url: String,
    state: Arc<State>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl MockLlmProvider {
    pub async fn start(name: &str) -> Self {
        let state = Arc::new(State {
            name: name.to_string(),
            unavailable_for_chat_completions: Mutex::new(false),
            unauthorized_for_chat_completions: Mutex::new(false),
            chat_completion_delay: Mutex::new(Duration::ZERO),
            chat_completion_contents: Mutex::new(VecDeque::new()),
            rejected_response_pattern: Mutex::new(None),
            streams_without_usage: Mutex::new(false),
            guardrail_verdict: Mutex::new(GuardrailVerdict::Allow),
            requests: Mutex::new(Vec::new()),
            api_requests: Mutex::new(Vec::new()),
            guardrail_inspections: Mutex::new(Vec::new()),
        });
        let app = Router::new()
            .route("/v1/chat/completions", post(chat_completion))
            .route("/v1/embeddings", post(embedding))
            .route("/v1/models", get(api_request))
            .route("/v1/files", get(api_request).post(api_request))
            .route("/v1/batches", get(api_request))
            .route("/v1/vector_stores", post(api_request))
            .route("/v1/audio/transcriptions", post(api_request))
            .route("/v1/audio/translations", post(api_request))
            .route("/guardrail", post(guardrail_inspection))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("mock LLM provider should bind");
        let addr = listener
            .local_addr()
            .expect("mock LLM address should be readable");
        let (shutdown_tx, shutdown_rx) = oneshot::channel();

        tokio::spawn(async move {
            let result = axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = shutdown_rx.await;
                })
                .await;
            if let Err(error) = result {
                eprintln!("mock LLM provider stopped with error: {error}");
            }
        });

        Self {
            base_url: format!("http://{}", addr),
            state,
            shutdown: Some(shutdown_tx),
        }
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn make_chat_completions_unavailable(&self) {
        *self
            .state
            .unavailable_for_chat_completions
            .lock()
            .await = true;
    }

    /// Reject chat completions with HTTP 401 (invalid credentials). The request
    /// is still recorded, so "received the request" assertions hold — this
    /// simulates a provider auth failure, which is failover-eligible.
    pub async fn make_chat_completions_unauthorized(&self) {
        *self
            .state
            .unauthorized_for_chat_completions
            .lock()
            .await = true;
    }

    pub async fn set_chat_completion_delay(
        &self,
        delay: Duration,
    ) {
        *self
            .state
            .chat_completion_delay
            .lock()
            .await = delay;
    }

    pub async fn set_chat_completion_content(
        &self,
        content: String,
    ) {
        self.set_chat_completion_contents(vec![content])
            .await;
    }

    pub async fn set_chat_completion_contents(
        &self,
        contents: Vec<String>,
    ) {
        assert!(!contents.is_empty(), "mock LLM provider requires at least one completion");
        *self
            .state
            .chat_completion_contents
            .lock()
            .await = contents.into();
    }

    /// End every stream without a usage chunk, as a provider that ignores
    /// `stream_options.include_usage` does.
    pub async fn stream_without_usage(&self) {
        *self
            .state
            .streams_without_usage
            .lock()
            .await = true;
    }

    pub async fn reject_reviewed_responses_containing(
        &self,
        pattern: String,
    ) {
        *self
            .state
            .rejected_response_pattern
            .lock()
            .await = Some(pattern.to_lowercase());
    }

    pub async fn received_chat_completions(&self) -> Vec<ReceivedChatCompletion> {
        self.state
            .requests
            .lock()
            .await
            .clone()
    }

    pub async fn received_api_requests(
        &self,
        method: &str,
        path: &str,
    ) -> Vec<ReceivedApiRequest> {
        self.state
            .api_requests
            .lock()
            .await
            .iter()
            .filter(|request| request.method == method && request.path == path)
            .cloned()
            .collect()
    }

    pub async fn allow_guardrail_inspections(&self) {
        *self
            .state
            .guardrail_verdict
            .lock()
            .await = GuardrailVerdict::Allow;
    }

    pub async fn flag_guardrail_inspections(&self) {
        *self
            .state
            .guardrail_verdict
            .lock()
            .await = GuardrailVerdict::Flag;
    }

    pub async fn make_guardrail_unavailable(&self) {
        *self
            .state
            .guardrail_verdict
            .lock()
            .await = GuardrailVerdict::Unavailable;
    }

    pub async fn received_guardrail_inspections(&self) -> Vec<ReceivedGuardrailInspection> {
        self.state
            .guardrail_inspections
            .lock()
            .await
            .clone()
    }
}

impl Drop for MockLlmProvider {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
    }
}

async fn embedding(Json(_body): Json<Value>) -> Json<Value> {
    Json(serde_json::json!({
        "data": [{ "embedding": [1.0, 0.0, 0.0], "index": 0 }],
        "model": "mock-embedding",
        "usage": { "prompt_tokens": 1, "total_tokens": 1 }
    }))
}

async fn api_request(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    method: Method,
    uri: Uri,
) -> Json<Value> {
    let path = uri.path().to_string();
    state
        .api_requests
        .lock()
        .await
        .push(ReceivedApiRequest {
            method: method.to_string(),
            path: path.clone(),
        });
    Json(serde_json::json!({ "provider": state.name, "path": path }))
}

async fn guardrail_inspection(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    Json(body): Json<Value>,
) -> axum::response::Response {
    state
        .guardrail_inspections
        .lock()
        .await
        .push(ReceivedGuardrailInspection { body });

    match *state
        .guardrail_verdict
        .lock()
        .await
    {
        GuardrailVerdict::Allow => Json(serde_json::json!({ "flagged": false })).into_response(),
        GuardrailVerdict::Flag => Json(serde_json::json!({
            "flagged": true,
            "categories": ["bdd_policy"]
        }))
        .into_response(),
        GuardrailVerdict::Unavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "message": format!("Expert Witness provider {} is unavailable", state.name),
                    "type": "provider_error",
                    "code": "provider_unavailable"
                }
            })),
        )
            .into_response(),
    }
}

async fn chat_completion(
    axum::extract::State(state): axum::extract::State<Arc<State>>,
    headers: axum::http::HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    state
        .requests
        .lock()
        .await
        .push(ReceivedChatCompletion {
            body: body.clone(),
            headers: headers
                .iter()
                .filter_map(|(name, value)| {
                    Some((
                        name.to_string(),
                        value
                            .to_str()
                            .ok()?
                            .to_string(),
                    ))
                })
                .collect(),
            received_at: Instant::now(),
        });

    let delay = *state
        .chat_completion_delay
        .lock()
        .await;
    tokio::time::sleep(delay).await;

    if *state
        .unavailable_for_chat_completions
        .lock()
        .await
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({
                "error": {
                    "message": format!("provider {} is unavailable", state.name),
                    "type": "provider_error",
                    "code": "provider_unavailable"
                }
            })),
        )
            .into_response();
    }

    if *state
        .unauthorized_for_chat_completions
        .lock()
        .await
    {
        return (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({
                "error": {
                    "message": format!("provider {} rejected the credentials", state.name),
                    "type": "authentication_error",
                    "code": "invalid_api_key"
                }
            })),
        )
            .into_response();
    }

    let rejected_response_pattern = state
        .rejected_response_pattern
        .lock()
        .await
        .clone();
    let content = if let Some(pattern) = rejected_response_pattern {
        let rejects_response = body["messages"]
            .as_array()
            .is_some_and(|messages| {
                messages
                    .iter()
                    .any(|message| {
                        message["role"] == "user"
                            && message["content"]
                                .as_str()
                                .is_some_and(|content| {
                                    content
                                        .to_lowercase()
                                        .contains(&pattern)
                                })
                    })
            });
        if rejects_response {
            "REJECTED".to_string()
        } else {
            "APPROVED".to_string()
        }
    } else {
        let mut contents = state
            .chat_completion_contents
            .lock()
            .await;
        if contents.len() > 1 {
            contents
                .pop_front()
                .expect("mock LLM completion queue should not be empty")
        } else {
            contents
                .front()
                .cloned()
                .unwrap_or_else(|| format!("hello from {}", state.name))
        }
    };
    if body
        .get("stream")
        .and_then(Value::as_bool)
        == Some(true)
    {
        let model = body
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("mock-small");
        let content_chunk = serde_json::json!({
            "id": "chatcmpl-bdd-stream",
            "object": "chat.completion.chunk",
            "created": 1710000000,
            "model": model,
            "choices": [{ "index": 0, "delta": { "content": content }, "finish_reason": Value::Null }]
        });
        let usage_chunk = serde_json::json!({
            "id": "chatcmpl-bdd-stream",
            "object": "chat.completion.chunk",
            "created": 1710000000,
            "model": model,
            "choices": [],
            "usage": { "prompt_tokens": 7, "completion_tokens": 3, "total_tokens": 10 }
        });
        let stream = if *state
            .streams_without_usage
            .lock()
            .await
        {
            format!("data: {content_chunk}\n\ndata: [DONE]\n\n")
        } else {
            format!("data: {content_chunk}\n\ndata: {usage_chunk}\n\ndata: [DONE]\n\n")
        };
        return (
            [(axum::http::header::CONTENT_TYPE, "text/event-stream"), (axum::http::header::CACHE_CONTROL, "no-cache")],
            stream,
        )
            .into_response();
    }

    Json(serde_json::json!({
        "id": "chatcmpl-bdd-alpha",
        "object": "chat.completion",
        "created": 1710000000,
        "model": body.get("model").and_then(Value::as_str).unwrap_or("mock-small"),
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": content
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": 7,
            "completion_tokens": 3,
            "total_tokens": 10
        }
    }))
    .into_response()
}
