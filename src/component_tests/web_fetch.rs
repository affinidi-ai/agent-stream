//! Component test for a denied Web Fetch inside the governed server-tools
//! loop: the model asks to fetch a private address, the executor refuses it,
//! records a flagged `web_fetch` stage, and sends the generic denial back to
//! the model on the next turn.

use serde_json::{Value, json};

use crate::pipes::executor::{PipeExecutor, StageDecision};
use crate::pipes::server_tools::{ServerToolsConfig, WebFetchConfig};
use crate::pipes::test_upstreams::{CaptureUpstream, completion};
use crate::pipes::types::llm::LLMProvider;
use crate::pipes::{PipeConfig, PipeType};
use crate::url_validation::test_service_endpoints;

const DENIAL: &str = "Tool call denied: URL blocked by SSRF guard";

fn web_fetch_call(url: &str) -> Value {
    json!({
        "id": "chatcmpl-fetch",
        "object": "chat.completion",
        "model": "capture",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": null,
                "tool_calls": [{
                    "id": "call-fetch",
                    "type": "function",
                    "function": { "name": "web_fetch", "arguments": json!({ "url": url }).to_string() }
                }]
            },
            "finish_reason": "tool_calls"
        }],
        "usage": { "prompt_tokens": 10, "completion_tokens": 10, "total_tokens": 20 }
    })
}

fn web_fetch_surface(upstream_url: &str) -> PipeConfig {
    let mut config = PipeConfig::new(
        "p-web-fetch".to_string(),
        "Web Fetch".to_string(),
        PipeType::LLM {
            provider: Box::new(LLMProvider::OpenAI {
                provider_type: "openai".to_string(),
                model: "gpt-4o".to_string(),
                api_key_secret: None,
                organization_id: None,
                base_url: Some(upstream_url.to_string()),
                temperature: None,
                max_tokens: None,
                top_p: None,
                frequency_penalty: None,
                presence_penalty: None,
            }),
            endpoint_path: None,
        },
    );
    config.server_tools = Some(ServerToolsConfig {
        enabled: true,
        max_iterations: 3,
        web_search: None,
        web_fetch: Some(WebFetchConfig {
            enabled: true,
            ..Default::default()
        }),
    });
    config
}

fn tool_message(body: &Value) -> Option<&Value> {
    body["messages"]
        .as_array()?
        .iter()
        .find(|message| message["role"] == "tool")
}

#[tokio::test]
async fn a_web_fetch_of_a_private_address_is_denied_and_the_model_is_told() {
    let upstream =
        CaptureUpstream::replying(vec![web_fetch_call("http://10.0.0.5/"), completion("cannot fetch")]).await;
    let _allowed = test_service_endpoints::allow(std::slice::from_ref(&upstream.url));
    let config = web_fetch_surface(&upstream.url);

    let (response, metrics) = PipeExecutor::new(&config)
        .execute(
            json!({ "messages": [{ "role": "user", "content": "read http://10.0.0.5/" }] }),
            None,
            None,
            None,
            None,
        )
        .await
        .expect("the loop answers after the denied fetch");

    assert_eq!(response["choices"][0]["message"]["content"], "cannot fetch");
    let bodies = upstream.bodies();
    assert_eq!(bodies.len(), 2, "one turn for the tool call and one for the answer");
    assert!(tool_message(&bodies[0]).is_none());
    let denial = tool_message(&bodies[1]).expect("the next turn carries the tool result");
    assert_eq!(denial["tool_call_id"], "call-fetch");
    assert_eq!(denial["content"], DENIAL);
    assert!(
        !bodies[1]
            .to_string()
            .contains("is blocked"),
        "the model sees only the generic reason"
    );

    let stage = metrics
        .stages
        .iter()
        .find(|stage| stage.stage == "web_fetch")
        .expect("the denied fetch is recorded");
    assert_eq!(stage.decision, StageDecision::Flag);
    assert_eq!(stage.input.as_deref(), Some("http://10.0.0.5/"));
    assert!(
        stage
            .detail
            .as_deref()
            .is_some_and(|detail| detail.starts_with("URL blocked by SSRF guard: ")),
        "{:?}",
        stage.detail
    );
}
