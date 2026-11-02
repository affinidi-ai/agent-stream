//! Loopback capture upstreams for tests that assert which headers and
//! request bodies each upstream a surface calls actually received.

use std::sync::{Arc, Mutex};

use axum::http::{HeaderMap, StatusCode, header::LOCATION};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};

/// How a capture upstream answers every request.
#[derive(Clone)]
enum Answer {
    Completion(String),
    Status(StatusCode),
    StatusWith(StatusCode, Value),
    Redirect(String),
    Replies(Vec<Value>),
    Stall,
}

/// A loopback server that records the headers and body of every request it
/// receives and answers it as its constructor says.
pub(crate) struct CaptureUpstream {
    /// The OpenAI-compatible chat completions URL to configure as an endpoint.
    pub url: String,
    seen: Arc<Mutex<Vec<(HeaderMap, Value)>>>,
    server: tokio::task::JoinHandle<()>,
}

impl CaptureUpstream {
    /// Answers 200 with an OpenAI chat completion whose content is `content`,
    /// reporting 1,000 input and 1,000 output tokens.
    pub(crate) async fn answering(content: &str) -> Self {
        Self::start(Answer::Completion(content.to_string())).await
    }

    /// Answers every request with `status` and an error body.
    pub(crate) async fn failing(status: StatusCode) -> Self {
        Self::start(Answer::Status(status)).await
    }

    /// Answers every request with `status` and `body`.
    pub(crate) async fn failing_with(
        status: StatusCode,
        body: Value,
    ) -> Self {
        Self::start(Answer::StatusWith(status, body)).await
    }

    /// Answers every request with a 302 to `location`.
    pub(crate) async fn redirecting_to(location: &str) -> Self {
        Self::start(Answer::Redirect(location.to_string())).await
    }

    /// Answers the n-th request with the n-th of `replies` as a 200 JSON
    /// body, and every later request with the last.
    pub(crate) async fn replying(replies: Vec<Value>) -> Self {
        assert!(!replies.is_empty(), "a replying upstream needs at least one reply");
        Self::start(Answer::Replies(replies)).await
    }

    /// Records every request and never answers it.
    pub(crate) async fn stalling() -> Self {
        Self::start(Answer::Stall).await
    }

    async fn start(answer: Answer) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind a loopback port");
        let address = listener
            .local_addr()
            .expect("local address");
        let seen: Arc<Mutex<Vec<(HeaderMap, Value)>>> = Arc::default();
        let recorded = seen.clone();
        let app = axum::Router::new().fallback(move |headers: HeaderMap, body: axum::body::Bytes| {
            let recorded = recorded.clone();
            let answer = answer.clone();
            async move {
                let body = serde_json::from_slice(&body).unwrap_or(Value::Null);
                let turn = {
                    let mut recorded = recorded
                        .lock()
                        .expect("capture lock");
                    recorded.push((headers, body));
                    recorded.len() - 1
                };
                if matches!(answer, Answer::Stall) {
                    std::future::pending::<()>().await;
                }
                respond(&answer, turn)
            }
        });
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("capture upstream serves");
        });
        Self {
            url: format!("http://{address}/v1/chat/completions"),
            seen,
            server,
        }
    }

    /// How many requests reached this upstream.
    pub(crate) fn requests(&self) -> usize {
        self.seen
            .lock()
            .expect("capture lock")
            .len()
    }

    /// Every value of header `name` across every request received, in order.
    pub(crate) fn header_values(
        &self,
        name: &str,
    ) -> Vec<String> {
        self.seen
            .lock()
            .expect("capture lock")
            .iter()
            .flat_map(|(headers, _)| {
                headers
                    .get_all(name)
                    .iter()
                    .map(|value| {
                        value
                            .to_str()
                            .unwrap_or_default()
                            .to_string()
                    })
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    /// Every request body received, in order, parsed as JSON (`Null` when
    /// empty or not JSON).
    pub(crate) fn bodies(&self) -> Vec<Value> {
        self.seen
            .lock()
            .expect("capture lock")
            .iter()
            .map(|(_, body)| body.clone())
            .collect()
    }

    /// How many requests carried the top-level body field `field`.
    pub(crate) fn bodies_naming(
        &self,
        field: &str,
    ) -> usize {
        self.seen
            .lock()
            .expect("capture lock")
            .iter()
            .filter(|(_, body)| body.get(field).is_some())
            .count()
    }

    /// How many request bodies contain `needle` anywhere in their JSON.
    pub(crate) fn bodies_containing(
        &self,
        needle: &str,
    ) -> usize {
        self.seen
            .lock()
            .expect("capture lock")
            .iter()
            .filter(|(_, body)| {
                body.to_string()
                    .contains(needle)
            })
            .count()
    }

    /// The `model` each request named, in order (empty when it named none).
    pub(crate) fn models(&self) -> Vec<String> {
        self.seen
            .lock()
            .expect("capture lock")
            .iter()
            .map(|(_, body)| {
                body.get("model")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string()
            })
            .collect()
    }
}

impl Drop for CaptureUpstream {
    fn drop(&mut self) {
        self.server.abort();
    }
}

fn respond(
    answer: &Answer,
    turn: usize,
) -> Response {
    match answer {
        Answer::Completion(content) => axum::Json(completion(content)).into_response(),
        Answer::Status(status) => {
            (*status, axum::Json(json!({ "error": { "message": "capture upstream failure" } }))).into_response()
        }
        Answer::StatusWith(status, body) => (*status, axum::Json(body.clone())).into_response(),
        Answer::Redirect(location) => (StatusCode::FOUND, [(LOCATION, location.clone())]).into_response(),
        Answer::Replies(replies) => axum::Json(replies[turn.min(replies.len() - 1)].clone()).into_response(),
        Answer::Stall => unreachable!("a stalling upstream never answers"),
    }
}

/// An OpenAI chat completion whose content is `content`, reporting 1,000
/// input and 1,000 output tokens.
pub(crate) fn completion(content: &str) -> Value {
    json!({
        "id": "chatcmpl-capture",
        "object": "chat.completion",
        "model": "capture",
        "choices": [{
            "index": 0,
            "message": { "role": "assistant", "content": content },
            "finish_reason": "stop"
        }],
        "usage": { "prompt_tokens": 1000, "completion_tokens": 1000, "total_tokens": 2000 }
    })
}
