//! Streaming egress skins: re-encode the gateway's canonical OpenAI SSE stream
//! into the client's requested dialect (Anthropic Messages or OpenAI Responses).
//!
//! The buffered pipeline is OpenAI-canonical; so is the streaming pipeline
//! (`streaming::spawn_metered_stream` always emits OpenAI `chat.completion.chunk`
//! SSE, translating Anthropic/Copilot upstreams first). This module takes that
//! canonical OpenAI SSE byte stream and, when the ingress skin is not OpenAI
//! Chat, rewrites each event into the target dialect's event sequence. The
//! encoders are pure state machines driven by parsed OpenAI chunks, so they are
//! unit-tested in isolation. See `docs/CLIENT_API_DIALECTS.md`.

use std::collections::HashMap;

use axum::body::{Body, Bytes};
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::pipes::ingress::IngressSchema;

/// The client-facing egress dialect plus the resolved model id (needed for the
/// `message`/`response` skeletons the dialects require).
#[derive(Debug, Clone)]
pub struct EgressSkin {
    pub skin: IngressSchema,
    pub model: String,
}

impl EgressSkin {
    pub fn new(
        skin: IngressSchema,
        model: String,
    ) -> Self {
        Self { skin, model }
    }
}

/// Re-encode an OpenAI-canonical SSE [`Body`] into the egress dialect. Returns
/// the body unchanged for OpenAI Chat egress (zero cost, no task spawned).
pub fn reencode_sse_body(
    body: Body,
    egress: EgressSkin,
) -> Body {
    let Some(mut encoder) = EgressEncoder::new(&egress) else {
        return body;
    };

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);
    tokio::spawn(async move {
        let mut stream = body.into_data_stream();
        let mut pending = String::new();

        while let Some(item) = stream.next().await {
            let Ok(bytes) = item else { break };
            let Ok(text) = std::str::from_utf8(&bytes) else {
                continue;
            };
            pending.push_str(text);

            while let Some(line_end) = pending.find('\n') {
                let line = pending[..line_end]
                    .trim_end_matches('\r')
                    .to_string();
                pending.drain(..=line_end);

                let Some(payload) = line.strip_prefix("data:") else {
                    continue;
                };
                let payload = payload.trim();
                if payload.is_empty() || payload == "[DONE]" {
                    continue;
                }
                let Ok(chunk) = serde_json::from_str::<Value>(payload) else {
                    continue;
                };
                for event in encoder.push_chunk(&chunk) {
                    if tx
                        .send(Ok(Bytes::from(event)))
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            }
        }

        for event in encoder.finish() {
            if tx
                .send(Ok(Bytes::from(event)))
                .await
                .is_err()
            {
                return;
            }
        }
    });

    Body::from_stream(ReceiverStream::new(rx))
}

/// One tool-call delta extracted from an OpenAI streaming chunk.
#[derive(Debug, Default)]
struct ToolCallDelta {
    index: u64,
    id: Option<String>,
    name: Option<String>,
    arguments: Option<String>,
}

/// The salient parts of one OpenAI `chat.completion.chunk`.
#[derive(Debug, Default)]
struct ChunkView {
    content: Option<String>,
    reasoning: Option<String>,
    tool_calls: Vec<ToolCallDelta>,
    finish_reason: Option<String>,
    usage: Option<(u64, u64)>,
}

/// Parse an OpenAI streaming chunk into its deltas.
fn parse_chunk(chunk: &Value) -> ChunkView {
    let mut view = ChunkView::default();

    if let Some(usage) = chunk
        .get("usage")
        .filter(|u| !u.is_null())
    {
        let input = usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let output = usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        view.usage = Some((input, output));
    }

    let Some(choice) = chunk
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first())
    else {
        return view;
    };

    view.finish_reason = choice
        .get("finish_reason")
        .and_then(|f| f.as_str())
        .map(|s| s.to_string());

    let Some(delta) = choice.get("delta") else {
        return view;
    };

    if let Some(content) = delta
        .get("content")
        .and_then(|c| c.as_str())
        && !content.is_empty()
    {
        view.content = Some(content.to_string());
    }

    // Reasoning deltas: canonical `reasoning`, or DeepSeek `reasoning_content`.
    if let Some(reasoning) = delta
        .get("reasoning")
        .or_else(|| delta.get("reasoning_content"))
        .and_then(|c| c.as_str())
        && !reasoning.is_empty()
    {
        view.reasoning = Some(reasoning.to_string());
    }

    if let Some(tool_calls) = delta
        .get("tool_calls")
        .and_then(|t| t.as_array())
    {
        for (i, tc) in tool_calls.iter().enumerate() {
            let index = tc
                .get("index")
                .and_then(|v| v.as_u64())
                .unwrap_or(i as u64);
            let function = tc.get("function");
            view.tool_calls
                .push(ToolCallDelta {
                    index,
                    id: tc
                        .get("id")
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    name: function
                        .and_then(|f| f.get("name"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                    arguments: function
                        .and_then(|f| f.get("arguments"))
                        .and_then(|v| v.as_str())
                        .map(|s| s.to_string()),
                });
        }
    }

    view
}

/// Format a named SSE event (`event:`/`data:` pair) as Anthropic and Responses
/// streams both use.
fn sse_event(
    event: &str,
    data: &Value,
) -> String {
    format!("event: {event}\ndata: {data}\n\n")
}

/// Egress encoder for a non-OpenAI dialect.
enum EgressEncoder {
    Anthropic(AnthropicSse),
    Responses(ResponsesSse),
}

impl EgressEncoder {
    fn new(egress: &EgressSkin) -> Option<Self> {
        match egress.skin {
            IngressSchema::OpenAiChat => None,
            IngressSchema::AnthropicMessages => Some(EgressEncoder::Anthropic(AnthropicSse::new(egress.model.clone()))),
            IngressSchema::OpenAiResponses => Some(EgressEncoder::Responses(ResponsesSse::new(egress.model.clone()))),
        }
    }

    fn push_chunk(
        &mut self,
        chunk: &Value,
    ) -> Vec<String> {
        let view = parse_chunk(chunk);
        match self {
            EgressEncoder::Anthropic(a) => a.push(view),
            EgressEncoder::Responses(r) => r.push(view),
        }
    }

    fn finish(&mut self) -> Vec<String> {
        match self {
            EgressEncoder::Anthropic(a) => a.finish(),
            EgressEncoder::Responses(r) => r.finish(),
        }
    }
}

/// Which content block is currently open in the Anthropic stream.
#[derive(Clone, Copy, PartialEq)]
enum OpenBlock {
    Thinking(usize),
    Text(usize),
    Tool(usize),
}

/// Map an OpenAI `finish_reason` to an Anthropic `stop_reason`.
fn stop_reason_for(
    finish: Option<&str>,
    had_tool: bool,
) -> &'static str {
    match finish {
        Some("length") => "max_tokens",
        Some("tool_calls") => "tool_use",
        Some("content_filter") => "end_turn",
        Some("stop") => "end_turn",
        _ if had_tool => "tool_use",
        _ => "end_turn",
    }
}

/// Anthropic Messages SSE state machine.
struct AnthropicSse {
    model: String,
    message_id: String,
    started: bool,
    finished: bool,
    input_tokens: u64,
    output_tokens: u64,
    finish_reason: Option<String>,
    had_tool: bool,
    next_block: usize,
    open: Option<OpenBlock>,
    /// OpenAI tool_call index → Anthropic content-block index.
    tool_blocks: HashMap<u64, usize>,
}

impl AnthropicSse {
    fn new(model: String) -> Self {
        Self {
            model,
            message_id: format!("msg_{}", uuid::Uuid::new_v4()),
            started: false,
            finished: false,
            input_tokens: 0,
            output_tokens: 0,
            finish_reason: None,
            had_tool: false,
            next_block: 0,
            open: None,
            tool_blocks: HashMap::new(),
        }
    }

    fn ensure_started(
        &mut self,
        out: &mut Vec<String>,
    ) {
        if self.started {
            return;
        }
        self.started = true;
        let message = serde_json::json!({
            "type": "message",
            "id": self.message_id,
            "role": "assistant",
            "model": self.model,
            "content": [],
            "stop_reason": Value::Null,
            "stop_sequence": Value::Null,
            "usage": { "input_tokens": self.input_tokens, "output_tokens": 0 }
        });
        out.push(sse_event("message_start", &serde_json::json!({ "type": "message_start", "message": message })));
        out.push(sse_event("ping", &serde_json::json!({ "type": "ping" })));
    }

    fn close_open(
        &mut self,
        out: &mut Vec<String>,
    ) {
        if let Some(block) = self.open.take() {
            let index = match block {
                OpenBlock::Thinking(i) => i,
                OpenBlock::Text(i) => i,
                OpenBlock::Tool(i) => i,
            };
            out.push(sse_event(
                "content_block_stop",
                &serde_json::json!({ "type": "content_block_stop", "index": index }),
            ));
        }
    }

    fn push(
        &mut self,
        view: ChunkView,
    ) -> Vec<String> {
        let mut out = Vec::new();

        if let Some((input, output)) = view.usage {
            if input > 0 {
                self.input_tokens = input;
            }
            if output > 0 {
                self.output_tokens = output;
            }
        }
        if let Some(reason) = view.finish_reason {
            self.finish_reason = Some(reason);
        }

        self.ensure_started(&mut out);

        // Reasoning (thinking) blocks stream first, before any text/tool blocks.
        if let Some(reasoning) = view.reasoning {
            let thinking_index = match self.open {
                Some(OpenBlock::Thinking(i)) => i,
                _ => {
                    self.close_open(&mut out);
                    let index = self.next_block;
                    self.next_block += 1;
                    self.open = Some(OpenBlock::Thinking(index));
                    out.push(sse_event(
                        "content_block_start",
                        &serde_json::json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": { "type": "thinking", "thinking": "" }
                        }),
                    ));
                    index
                }
            };
            out.push(sse_event(
                "content_block_delta",
                &serde_json::json!({
                    "type": "content_block_delta",
                    "index": thinking_index,
                    "delta": { "type": "thinking_delta", "thinking": reasoning }
                }),
            ));
        }

        if let Some(text) = view.content {
            // Open (or reopen) a text block if one is not the active block.
            let text_index = match self.open {
                Some(OpenBlock::Text(i)) => i,
                _ => {
                    self.close_open(&mut out);
                    let index = self.next_block;
                    self.next_block += 1;
                    self.open = Some(OpenBlock::Text(index));
                    out.push(sse_event(
                        "content_block_start",
                        &serde_json::json!({
                            "type": "content_block_start",
                            "index": index,
                            "content_block": { "type": "text", "text": "" }
                        }),
                    ));
                    index
                }
            };
            out.push(sse_event(
                "content_block_delta",
                &serde_json::json!({
                    "type": "content_block_delta",
                    "index": text_index,
                    "delta": { "type": "text_delta", "text": text }
                }),
            ));
        }

        for tc in view.tool_calls {
            self.had_tool = true;
            let block_index = if let Some(&existing) = self
                .tool_blocks
                .get(&tc.index)
            {
                // Ensure the existing tool block is the active one.
                if self.open != Some(OpenBlock::Tool(existing)) {
                    self.close_open(&mut out);
                    self.open = Some(OpenBlock::Tool(existing));
                }
                existing
            } else {
                self.close_open(&mut out);
                let index = self.next_block;
                self.next_block += 1;
                self.tool_blocks
                    .insert(tc.index, index);
                self.open = Some(OpenBlock::Tool(index));
                out.push(sse_event(
                    "content_block_start",
                    &serde_json::json!({
                        "type": "content_block_start",
                        "index": index,
                        "content_block": {
                            "type": "tool_use",
                            "id": tc.id.clone().unwrap_or_default(),
                            "name": tc.name.clone().unwrap_or_default(),
                            "input": {}
                        }
                    }),
                ));
                index
            };
            if let Some(args) = tc
                .arguments
                .filter(|a| !a.is_empty())
            {
                out.push(sse_event(
                    "content_block_delta",
                    &serde_json::json!({
                        "type": "content_block_delta",
                        "index": block_index,
                        "delta": { "type": "input_json_delta", "partial_json": args }
                    }),
                ));
            }
        }

        out
    }

    fn finish(&mut self) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut out = Vec::new();
        self.ensure_started(&mut out);

        // Guarantee at least one content block for an otherwise-empty message.
        if self.open.is_none() && self.next_block == 0 {
            out.push(sse_event(
                "content_block_start",
                &serde_json::json!({
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": { "type": "text", "text": "" }
                }),
            ));
            self.open = Some(OpenBlock::Text(0));
            self.next_block = 1;
        }

        self.close_open(&mut out);

        let stop_reason = stop_reason_for(self.finish_reason.as_deref(), self.had_tool);
        out.push(sse_event(
            "message_delta",
            &serde_json::json!({
                "type": "message_delta",
                "delta": { "stop_reason": stop_reason, "stop_sequence": Value::Null },
                "usage": { "output_tokens": self.output_tokens }
            }),
        ));
        out.push(sse_event("message_stop", &serde_json::json!({ "type": "message_stop" })));
        out
    }
}

/// One in-flight Responses output item (message text or a function call).
struct ResponsesItem {
    output_index: usize,
    item_id: String,
    kind: ResponsesItemKind,
}

enum ResponsesItemKind {
    Reasoning { summary: String },
    Message { text: String },
    FunctionCall { call_id: String, name: String, arguments: String },
}

/// OpenAI Responses SSE state machine.
struct ResponsesSse {
    model: String,
    response_id: String,
    started: bool,
    finished: bool,
    input_tokens: u64,
    output_tokens: u64,
    finish_reason: Option<String>,
    next_output_index: usize,
    message_item: Option<usize>,
    reasoning_item: Option<usize>,
    tool_items: HashMap<u64, usize>,
    items: Vec<ResponsesItem>,
}

impl ResponsesSse {
    fn new(model: String) -> Self {
        Self {
            model,
            response_id: format!("resp_{}", uuid::Uuid::new_v4()),
            started: false,
            finished: false,
            input_tokens: 0,
            output_tokens: 0,
            finish_reason: None,
            next_output_index: 0,
            message_item: None,
            reasoning_item: None,
            tool_items: HashMap::new(),
            items: Vec::new(),
        }
    }

    fn response_skeleton(
        &self,
        status: &str,
    ) -> Value {
        serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "status": status,
            "model": self.model,
            "output": [],
        })
    }

    fn ensure_started(
        &mut self,
        out: &mut Vec<String>,
    ) {
        if self.started {
            return;
        }
        self.started = true;
        let response = self.response_skeleton("in_progress");
        out.push(sse_event(
            "response.created",
            &serde_json::json!({ "type": "response.created", "response": response }),
        ));
        out.push(sse_event(
            "response.in_progress",
            &serde_json::json!({ "type": "response.in_progress", "response": self.response_skeleton("in_progress") }),
        ));
    }

    fn push(
        &mut self,
        view: ChunkView,
    ) -> Vec<String> {
        let mut out = Vec::new();

        if let Some((input, output)) = view.usage {
            if input > 0 {
                self.input_tokens = input;
            }
            if output > 0 {
                self.output_tokens = output;
            }
        }
        if let Some(reason) = view.finish_reason {
            self.finish_reason = Some(reason);
        }

        self.ensure_started(&mut out);

        // A reasoning item and its summary deltas precede the message item.
        if let Some(reasoning) = view.reasoning {
            let (output_index, item_id) = match self.reasoning_item {
                Some(idx) => (
                    self.items[idx].output_index,
                    self.items[idx]
                        .item_id
                        .clone(),
                ),
                None => {
                    let output_index = self.next_output_index;
                    self.next_output_index += 1;
                    let item_id = format!("rs_{}", uuid::Uuid::new_v4());
                    let idx = self.items.len();
                    self.items
                        .push(ResponsesItem {
                            output_index,
                            item_id: item_id.clone(),
                            kind: ResponsesItemKind::Reasoning { summary: String::new() },
                        });
                    self.reasoning_item = Some(idx);
                    out.push(sse_event(
                        "response.output_item.added",
                        &serde_json::json!({
                            "type": "response.output_item.added",
                            "output_index": output_index,
                            "item": { "id": item_id, "type": "reasoning", "status": "in_progress", "summary": [] }
                        }),
                    ));
                    out.push(sse_event(
                        "response.reasoning_summary_part.added",
                        &serde_json::json!({
                            "type": "response.reasoning_summary_part.added",
                            "item_id": item_id,
                            "output_index": output_index,
                            "summary_index": 0,
                            "part": { "type": "summary_text", "text": "" }
                        }),
                    ));
                    (output_index, item_id)
                }
            };
            if let Some(idx) = self.reasoning_item
                && let ResponsesItemKind::Reasoning { summary } = &mut self.items[idx].kind
            {
                summary.push_str(&reasoning);
            }
            out.push(sse_event(
                "response.reasoning_summary_text.delta",
                &serde_json::json!({
                    "type": "response.reasoning_summary_text.delta",
                    "item_id": item_id,
                    "output_index": output_index,
                    "summary_index": 0,
                    "delta": reasoning
                }),
            ));
        }

        if let Some(text) = view.content {
            let (output_index, item_id) = match self.message_item {
                Some(idx) => {
                    let item = &self.items[idx];
                    (item.output_index, item.item_id.clone())
                }
                None => {
                    let output_index = self.next_output_index;
                    self.next_output_index += 1;
                    let item_id = format!("msg_{}", uuid::Uuid::new_v4());
                    let idx = self.items.len();
                    self.items
                        .push(ResponsesItem {
                            output_index,
                            item_id: item_id.clone(),
                            kind: ResponsesItemKind::Message { text: String::new() },
                        });
                    self.message_item = Some(idx);
                    out.push(sse_event(
                        "response.output_item.added",
                        &serde_json::json!({
                            "type": "response.output_item.added",
                            "output_index": output_index,
                            "item": {
                                "id": item_id,
                                "type": "message",
                                "status": "in_progress",
                                "role": "assistant",
                                "content": []
                            }
                        }),
                    ));
                    out.push(sse_event(
                        "response.content_part.added",
                        &serde_json::json!({
                            "type": "response.content_part.added",
                            "item_id": item_id,
                            "output_index": output_index,
                            "content_index": 0,
                            "part": { "type": "output_text", "text": "", "annotations": [] }
                        }),
                    ));
                    (output_index, item_id)
                }
            };
            if let Some(idx) = self.message_item
                && let ResponsesItemKind::Message { text: acc } = &mut self.items[idx].kind
            {
                acc.push_str(&text);
            }
            out.push(sse_event(
                "response.output_text.delta",
                &serde_json::json!({
                    "type": "response.output_text.delta",
                    "item_id": item_id,
                    "output_index": output_index,
                    "content_index": 0,
                    "delta": text
                }),
            ));
        }

        for tc in view.tool_calls {
            let items_idx = if let Some(&items_idx) = self.tool_items.get(&tc.index) {
                items_idx
            } else {
                let output_index = self.next_output_index;
                self.next_output_index += 1;
                let item_id = format!("fc_{}", uuid::Uuid::new_v4());
                let items_idx = self.items.len();
                self.items
                    .push(ResponsesItem {
                        output_index,
                        item_id: item_id.clone(),
                        kind: ResponsesItemKind::FunctionCall {
                            call_id: tc
                                .id
                                .clone()
                                .unwrap_or_default(),
                            name: tc
                                .name
                                .clone()
                                .unwrap_or_default(),
                            arguments: String::new(),
                        },
                    });
                self.tool_items
                    .insert(tc.index, items_idx);
                out.push(sse_event(
                    "response.output_item.added",
                    &serde_json::json!({
                        "type": "response.output_item.added",
                        "output_index": output_index,
                        "item": {
                            "id": item_id,
                            "type": "function_call",
                            "status": "in_progress",
                            "call_id": tc.id.clone().unwrap_or_default(),
                            "name": tc.name.clone().unwrap_or_default(),
                            "arguments": ""
                        }
                    }),
                ));
                items_idx
            };
            if let ResponsesItemKind::FunctionCall { arguments, .. } = &mut self.items[items_idx].kind
                && let Some(fragment) = tc
                    .arguments
                    .filter(|a| !a.is_empty())
            {
                arguments.push_str(&fragment);
                let (output_index, item_id) = (
                    self.items[items_idx].output_index,
                    self.items[items_idx]
                        .item_id
                        .clone(),
                );
                out.push(sse_event(
                    "response.function_call_arguments.delta",
                    &serde_json::json!({
                        "type": "response.function_call_arguments.delta",
                        "item_id": item_id,
                        "output_index": output_index,
                        "delta": fragment
                    }),
                ));
            }
        }

        out
    }

    fn finish(&mut self) -> Vec<String> {
        if self.finished {
            return Vec::new();
        }
        self.finished = true;
        let mut out = Vec::new();
        self.ensure_started(&mut out);

        let mut output_items: Vec<Value> = Vec::new();
        for item in &self.items {
            match &item.kind {
                ResponsesItemKind::Reasoning { summary } => {
                    out.push(sse_event(
                        "response.reasoning_summary_text.done",
                        &serde_json::json!({
                            "type": "response.reasoning_summary_text.done",
                            "item_id": item.item_id,
                            "output_index": item.output_index,
                            "summary_index": 0,
                            "text": summary
                        }),
                    ));
                    let done_item = serde_json::json!({
                        "id": item.item_id,
                        "type": "reasoning",
                        "status": "completed",
                        "summary": [ { "type": "summary_text", "text": summary } ]
                    });
                    out.push(sse_event(
                        "response.output_item.done",
                        &serde_json::json!({
                            "type": "response.output_item.done",
                            "output_index": item.output_index,
                            "item": done_item.clone()
                        }),
                    ));
                    output_items.push(done_item);
                }
                ResponsesItemKind::Message { text } => {
                    out.push(sse_event(
                        "response.output_text.done",
                        &serde_json::json!({
                            "type": "response.output_text.done",
                            "item_id": item.item_id,
                            "output_index": item.output_index,
                            "content_index": 0,
                            "text": text
                        }),
                    ));
                    out.push(sse_event(
                        "response.content_part.done",
                        &serde_json::json!({
                            "type": "response.content_part.done",
                            "item_id": item.item_id,
                            "output_index": item.output_index,
                            "content_index": 0,
                            "part": { "type": "output_text", "text": text, "annotations": [] }
                        }),
                    ));
                    let done_item = serde_json::json!({
                        "id": item.item_id,
                        "type": "message",
                        "status": "completed",
                        "role": "assistant",
                        "content": [ { "type": "output_text", "text": text, "annotations": [] } ]
                    });
                    out.push(sse_event(
                        "response.output_item.done",
                        &serde_json::json!({
                            "type": "response.output_item.done",
                            "output_index": item.output_index,
                            "item": done_item.clone()
                        }),
                    ));
                    output_items.push(done_item);
                }
                ResponsesItemKind::FunctionCall { call_id, name, arguments } => {
                    out.push(sse_event(
                        "response.function_call_arguments.done",
                        &serde_json::json!({
                            "type": "response.function_call_arguments.done",
                            "item_id": item.item_id,
                            "output_index": item.output_index,
                            "arguments": arguments
                        }),
                    ));
                    let done_item = serde_json::json!({
                        "id": item.item_id,
                        "type": "function_call",
                        "status": "completed",
                        "call_id": call_id,
                        "name": name,
                        "arguments": arguments
                    });
                    out.push(sse_event(
                        "response.output_item.done",
                        &serde_json::json!({
                            "type": "response.output_item.done",
                            "output_index": item.output_index,
                            "item": done_item.clone()
                        }),
                    ));
                    output_items.push(done_item);
                }
            }
        }

        let status = match self.finish_reason.as_deref() {
            Some("length") | Some("content_filter") => "incomplete",
            _ => "completed",
        };
        let response = serde_json::json!({
            "id": self.response_id,
            "object": "response",
            "status": status,
            "model": self.model,
            "output": output_items,
            "usage": {
                "input_tokens": self.input_tokens,
                "output_tokens": self.output_tokens,
                "total_tokens": self.input_tokens + self.output_tokens
            }
        });
        out.push(sse_event(
            "response.completed",
            &serde_json::json!({ "type": "response.completed", "response": response }),
        ));
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text_chunk(content: &str) -> Value {
        json!({ "choices": [ { "index": 0, "delta": { "content": content }, "finish_reason": Value::Null } ] })
    }
    fn finish_chunk(reason: &str) -> Value {
        json!({ "choices": [ { "index": 0, "delta": {}, "finish_reason": reason } ] })
    }

    fn events(
        encoder: &mut EgressEncoder,
        chunks: &[Value],
    ) -> Vec<String> {
        let mut all = Vec::new();
        for c in chunks {
            all.extend(encoder.push_chunk(c));
        }
        all.extend(encoder.finish());
        all
    }

    fn event_types(events: &[String]) -> Vec<String> {
        events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("event: "))
                    .map(|s| s.to_string())
            })
            .collect()
    }

    #[test]
    fn anthropic_text_sequence() {
        let mut enc =
            EgressEncoder::new(&EgressSkin::new(IngressSchema::AnthropicMessages, "claude-x".into())).unwrap();
        let events = events(&mut enc, &[text_chunk("Hel"), text_chunk("lo"), finish_chunk("stop")]);
        let types = event_types(&events);
        assert_eq!(
            types,
            vec![
                "message_start",
                "ping",
                "content_block_start",
                "content_block_delta",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        // The concatenated text deltas reconstruct the answer.
        let joined: String = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .filter(|v| v["type"] == "content_block_delta")
            .filter_map(|v| {
                v["delta"]["text"]
                    .as_str()
                    .map(|s| s.to_string())
            })
            .collect();
        assert_eq!(joined, "Hello");
    }

    #[test]
    fn anthropic_tool_use_sequence() {
        let mut enc = EgressEncoder::new(&EgressSkin::new(IngressSchema::AnthropicMessages, "m".into())).unwrap();
        let start = json!({ "choices": [ { "delta": { "tool_calls": [
            { "index": 0, "id": "call_1", "type": "function", "function": { "name": "f", "arguments": "" } }
        ]}, "finish_reason": Value::Null } ] });
        let args = json!({ "choices": [ { "delta": { "tool_calls": [
            { "index": 0, "function": { "arguments": "{\"a\":1}" } }
        ]}, "finish_reason": Value::Null } ] });
        let events = events(&mut enc, &[start, args, finish_chunk("tool_calls")]);
        let types = event_types(&events);
        assert_eq!(
            types,
            vec![
                "message_start",
                "ping",
                "content_block_start",
                "content_block_delta",
                "content_block_stop",
                "message_delta",
                "message_stop",
            ]
        );
        // stop_reason must be tool_use.
        let md = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .find(|v| v["type"] == "message_delta")
            .unwrap();
        assert_eq!(md["delta"]["stop_reason"], json!("tool_use"));
    }

    #[test]
    fn anthropic_empty_message_still_valid() {
        let mut enc = EgressEncoder::new(&EgressSkin::new(IngressSchema::AnthropicMessages, "m".into())).unwrap();
        let events = events(&mut enc, &[finish_chunk("stop")]);
        let types = event_types(&events);
        assert_eq!(
            types,
            vec!["message_start", "ping", "content_block_start", "content_block_stop", "message_delta", "message_stop"]
        );
    }

    #[test]
    fn responses_text_sequence() {
        let mut enc = EgressEncoder::new(&EgressSkin::new(IngressSchema::OpenAiResponses, "gpt-x".into())).unwrap();
        let usage = json!({ "choices": [], "usage": { "prompt_tokens": 3, "completion_tokens": 2 } });
        let events = events(&mut enc, &[text_chunk("Hi"), finish_chunk("stop"), usage]);
        let types = event_types(&events);
        assert_eq!(
            types,
            vec![
                "response.created",
                "response.in_progress",
                "response.output_item.added",
                "response.content_part.added",
                "response.output_text.delta",
                "response.output_text.done",
                "response.content_part.done",
                "response.output_item.done",
                "response.completed",
            ]
        );
        let completed = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .find(|v| v["type"] == "response.completed")
            .unwrap();
        assert_eq!(completed["response"]["status"], json!("completed"));
        assert_eq!(completed["response"]["output"][0]["content"][0]["text"], json!("Hi"));
    }

    #[test]
    fn responses_tool_call_incomplete_status() {
        let mut enc = EgressEncoder::new(&EgressSkin::new(IngressSchema::OpenAiResponses, "m".into())).unwrap();
        let start = json!({ "choices": [ { "delta": { "tool_calls": [
            { "index": 0, "id": "call_9", "type": "function", "function": { "name": "lookup", "arguments": "{}" } }
        ]}, "finish_reason": Value::Null } ] });
        let events = events(&mut enc, &[start, finish_chunk("length")]);
        let completed = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .find(|v| v["type"] == "response.completed")
            .unwrap();
        assert_eq!(completed["response"]["status"], json!("incomplete"));
        let fc = &completed["response"]["output"][0];
        assert_eq!(fc["type"], json!("function_call"));
        assert_eq!(fc["call_id"], json!("call_9"));
        assert_eq!(fc["name"], json!("lookup"));
    }

    #[test]
    fn openai_chat_egress_needs_no_reencode() {
        assert!(EgressEncoder::new(&EgressSkin::new(IngressSchema::OpenAiChat, "m".into())).is_none());
    }

    fn reasoning_chunk(text: &str) -> Value {
        json!({ "choices": [ { "index": 0, "delta": { "reasoning": text }, "finish_reason": Value::Null } ] })
    }

    #[test]
    fn anthropic_reasoning_streams_thinking_block_first() {
        let mut enc =
            EgressEncoder::new(&EgressSkin::new(IngressSchema::AnthropicMessages, "claude-x".into())).unwrap();
        let events =
            events(&mut enc, &[reasoning_chunk("mus"), reasoning_chunk("ing"), text_chunk("Hi"), finish_chunk("stop")]);
        let parsed: Vec<Value> = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .collect();
        // First content block is a thinking block.
        let first_start = parsed
            .iter()
            .find(|v| v["type"] == "content_block_start")
            .unwrap();
        assert_eq!(first_start["content_block"]["type"], json!("thinking"));
        // Thinking deltas reconstruct the reasoning text.
        let thinking: String = parsed
            .iter()
            .filter(|v| v["delta"]["type"] == "thinking_delta")
            .filter_map(|v| {
                v["delta"]["thinking"]
                    .as_str()
                    .map(str::to_string)
            })
            .collect();
        assert_eq!(thinking, "musing");
        // The thinking block is closed before the text block opens.
        let types = event_types(&events);
        let first_stop = types
            .iter()
            .position(|t| t == "content_block_stop")
            .unwrap();
        let text_starts: Vec<usize> = types
            .iter()
            .enumerate()
            .filter(|(_, t)| *t == "content_block_start")
            .map(|(i, _)| i)
            .collect();
        assert!(text_starts[1] > first_stop, "text block starts after thinking closes");
    }

    #[test]
    fn responses_reasoning_streams_summary_item() {
        let mut enc = EgressEncoder::new(&EgressSkin::new(IngressSchema::OpenAiResponses, "m".into())).unwrap();
        let events = events(&mut enc, &[reasoning_chunk("think"), text_chunk("Hi"), finish_chunk("stop")]);
        let parsed: Vec<Value> = events
            .iter()
            .filter_map(|e| {
                e.lines()
                    .find_map(|l| l.strip_prefix("data:"))
            })
            .filter_map(|d| serde_json::from_str::<Value>(d.trim()).ok())
            .collect();
        // A reasoning item is added at output index 0.
        let added = parsed
            .iter()
            .find(|v| v["type"] == "response.output_item.added" && v["item"]["type"] == "reasoning")
            .unwrap();
        assert_eq!(added["output_index"], json!(0));
        // Its summary delta carries the reasoning text.
        let delta = parsed
            .iter()
            .find(|v| v["type"] == "response.reasoning_summary_text.delta")
            .unwrap();
        assert_eq!(delta["delta"], json!("think"));
        // The completed response carries the reasoning item before the message.
        let completed = parsed
            .iter()
            .find(|v| v["type"] == "response.completed")
            .unwrap();
        assert_eq!(completed["response"]["output"][0]["type"], json!("reasoning"));
        assert_eq!(completed["response"]["output"][1]["type"], json!("message"));
    }
}
