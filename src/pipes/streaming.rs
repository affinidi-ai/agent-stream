//! SSE streaming passthrough for LLM surfaces.
//!
//! When a client requests `"stream": true` and the surface is eligible, the
//! upstream provider's Server-Sent Events response is proxied straight back to
//! the client instead of being buffered. Streaming bypasses every response-side
//! stage (Jury, response prompt guards, external response guardrail), so it is
//! only eligible when none of those is configured and the base provider speaks
//! OpenAI's wire/SSE format.
//!
//! Usage attribution is preserved: the gateway asks for
//! `stream_options.include_usage` (always on a key that bills, else when the
//! client did not set it) and reads the usage out of the proxied stream
//! ([`StreamMeter`]) so spend/tokens are still recorded for streamed calls. A
//! stream on a key that bills that still ends without usage is billed an
//! estimate ([`StreamOutcome::billed_tokens`]), recorded as estimated.

use axum::body::Body;
use bytes::Bytes;
use futures::StreamExt;
use serde_json::Value;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use crate::pipes::PipeConfig;

/// Hard cap on one SSE line the meter holds until it can read it, guarding
/// against an upstream that never emits a newline. A final Responses event
/// echoes the whole response (instructions, tools, the full output), so a line
/// far longer than a network chunk must still be read for its usage; a line
/// past the cap is counted as output and skipped.
const MAX_PENDING_BYTES: usize = 8 * 1024 * 1024;

/// The upstream SSE response plus the metadata needed to record metrics once
/// the stream completes. Returned by `PipeExecutor::execute_streaming`.
pub struct StreamingUpstream {
    /// Live upstream response whose body is proxied to the client.
    pub response: reqwest::Response,
    /// Provider type string (for metrics/telemetry attribution).
    pub provider: String,
    /// The model the upstream ran (the request's own `model` where the
    /// provider runs the model a request names), billed and attributed.
    pub model: String,
    /// Price declared on the upstream that served the stream (the routed
    /// candidate's, else the surface's own); used ahead of the catalog.
    pub pricing: Option<crate::pipes::types::llm::TargetPricing>,
    /// Whether `pricing` may be billed as is: not when the stream spent a
    /// credential the surface's tenant does not own.
    pub own_price_honoured: bool,
    /// The source of the key the stream's call sent: the streamed tokens bill
    /// nothing on an owned key (see [`crate::pipes::key_source`]).
    pub key_source: crate::pipes::key_source::KeySource,
    /// Serialized request size in bytes.
    pub request_bytes: u64,
    /// Wire schema of the upstream stream (`"openai"` proxied verbatim,
    /// `"anthropic"` translated to OpenAI SSE chunks on the fly, `"copilot"`
    /// Microsoft 365 Copilot `chatOverStream` snapshots translated to deltas).
    pub schema: String,
    /// The Microsoft 365 Copilot conversation id this turn ran against (created
    /// fresh, or reused from the caller). `None` for non-Copilot schemas. The
    /// data plane returns it to the caller so a follow-up can reuse the same
    /// stateful conversation and keep native multi-turn memory.
    pub conversation_id: Option<String>,
    /// Token → original-value map built when a request guard opted into
    /// `restore_in_response`. Drives token-safe re-hydration of the streamed
    /// completion; empty (the common case) means verbatim passthrough.
    pub rehydration_map: crate::pipes::prompt_guard::RehydrationMap,
    /// Governance stage for the model-backed PII detector, attached to the
    /// streamed interaction's record when the detector ran. `None` when the
    /// detector was not configured.
    pub model_pii_stage: Option<crate::governance::StageEntry>,
    /// Request-side Judge usage (tokens + cost), folded into the streamed
    /// interaction's metering so a Judge-only surface bills its Judge like the
    /// buffered path. Zero when no Judge ran.
    pub judge_usage: crate::pipes::config::StageUsage,
    /// Route-decider usage (tokens + cost) for the router LLM call, folded into
    /// the streamed metering. Zero when no Route decider ran.
    pub decider_usage: crate::pipes::config::StageUsage,
    /// What the stream is billed at if it reports no final usage, fixed from
    /// the request as sent (see [`StreamOutcome::billed_tokens`]).
    pub estimate: StreamEstimate,
}

/// Token usage and transfer totals observed while proxying a stream.
pub struct StreamOutcome {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub response_bytes: u64,
    /// `true` when the upstream stream ended cleanly (no transport error and the
    /// client did not disconnect mid-stream). A `false` value marks a partial /
    /// aborted stream — the caller still records whatever was delivered so the
    /// dashboard does not lose the in-flight throughput/token metadata.
    pub completed: bool,
    /// Response bytes already handed to the ops store by progress heartbeats, so
    /// the completion recorder can subtract them and avoid double counting.
    pub flushed_response_bytes: u64,
    /// Input tokens already flushed by progress heartbeats.
    pub flushed_input_tokens: u64,
    /// Output tokens already flushed by progress heartbeats.
    pub flushed_output_tokens: u64,
    /// Whether the upstream answer arrived whole (a `finish_reason` or `[DONE]`
    /// went past), regardless of whether the client stayed to receive it.
    ///
    /// Use this, not `completed`, to decide whether the answer may be stored:
    /// a client that disconnects the moment it reads `[DONE]` already has the
    /// entire answer, and gating on `completed` there makes storing a coin
    /// toss against that disconnect.
    pub answer_complete: bool,
    /// Reassembled assistant completion text, when the caller requested
    /// completion capture (governance recording). `None` when not captured.
    pub completion: Option<String>,
    /// Whether the upstream reported its final usage: an OpenAI usage chunk
    /// (one with no choices), a Responses `response.completed`, `.incomplete`
    /// or `.failed`, Anthropic's `message_delta`, a Gemini chunk with a finish
    /// reason, or usage that a provider repeats on every chat chunk on a
    /// stream that ended. Usage seen before that (Anthropic's `message_start`,
    /// a cut-off cumulative count) is partial: `input_tokens` and
    /// `output_tokens` hold it, and a stream that bills is billed at least an
    /// estimate (see [`Self::billed_tokens`]).
    pub usage_reported: bool,
    /// The streamed output's tokens, estimated from its text (answer,
    /// reasoning and tool-call arguments, see [`estimate_text_tokens`]).
    pub output_estimate: u64,
    /// Anthropic prompt-cache tokens the upstream reported, which its input
    /// count leaves out (see [`crate::pipes::types::llm::CacheTokens`]).
    pub cache: crate::pipes::types::llm::CacheTokens,
    /// The client went and the stream did not read on to its end: a drain
    /// bound cut it, or the concurrent-drain caps refused it (see
    /// [`DrainOptions`]). The model may still have been running, so its
    /// estimate takes the cut floor (see [`StreamEstimate::output_tokens`]).
    pub drain_cut: bool,
}

/// Characters per token for an estimate of ASCII text: the char/4 rule of
/// [`crate::pipes::context_transform::estimate_message_tokens`].
pub const ESTIMATE_CHARS_PER_TOKEN: u64 = 4;

/// UTF-8 bytes per token for an estimate of non-ASCII text. A CJK character
/// (3 bytes) is estimated at 1.5 tokens and an emoji (4 bytes) at 2, never
/// more than about twice under what a tokenizer counts.
pub const ESTIMATE_NON_ASCII_BYTES_PER_TOKEN: u64 = 2;

/// Tokens an inline image or other binary payload is estimated at (a base64
/// `data:` URL, or a long base64 string): about what a high-detail image costs
/// at OpenAI and Anthropic.
pub const INLINE_MEDIA_TOKENS: u64 = 1_600;

/// Hidden reasoning tokens added to the output estimate of a reasoning-capable
/// model's stream that set no output cap (OpenAI's reasoning models stream no
/// reasoning text, and a high effort runs to tens of thousands of tokens).
pub const REASONING_ALLOWANCE_TOKENS: u64 = 16_384;

/// How long a stream on a key that bills keeps reading its upstream after the
/// client has gone, for the provider's final usage: long enough for a long
/// reasoning or `max_tokens` answer to finish.
pub const DRAIN_MAX_SECS: u64 = 600;

/// How many bytes a stream on a key that bills reads from its upstream after
/// the client has gone, at most: several times the SSE of the longest answer
/// a model streams.
pub const DRAIN_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// The bounds of reading on after the client of a stream on a key that bills
/// has gone (see [`DRAIN_MAX_SECS`], [`DRAIN_MAX_BYTES`]). Past either, the
/// stream is billed an estimate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DrainBounds {
    pub max_time: std::time::Duration,
    pub max_bytes: u64,
}

impl Default for DrainBounds {
    fn default() -> Self {
        Self {
            max_time: std::time::Duration::from_secs(DRAIN_MAX_SECS),
            max_bytes: DRAIN_MAX_BYTES,
        }
    }
}

/// How many streams one member's calls may read on at once after their
/// clients have gone, across every surface. Each holds an upstream stream for
/// up to [`DRAIN_MAX_SECS`]; past the cap a stream whose client goes stops at
/// once and is billed its estimate with the cut floor.
pub const DRAIN_MAX_PER_MEMBER: usize = 16;

/// How many streams one surface may read on at once after their clients have
/// gone. A surface's streams share its upstream connections, so this bounds
/// how many of them drains may hold; past the cap a stream whose client goes
/// stops at once and is billed its estimate with the cut floor.
pub const DRAIN_MAX_PER_SURFACE: usize = 256;

/// How a stream on a key that bills reads on after its client has gone: its
/// bounds (see [`DrainBounds`]) and the concurrent-drain caps it counts
/// against, for its member and its surface (see [`DRAIN_MAX_PER_MEMBER`],
/// [`DRAIN_MAX_PER_SURFACE`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DrainOptions {
    pub bounds: DrainBounds,
    /// The member the stream bills, when known.
    pub member: Option<String>,
    /// The surface the stream runs on, when known.
    pub surface: Option<String>,
    pub max_per_member: usize,
    pub max_per_surface: usize,
}

impl DrainOptions {
    /// The default bounds and caps, counted against `member` and `surface`.
    pub fn new(
        member: Option<String>,
        surface: Option<String>,
    ) -> Self {
        Self {
            bounds: DrainBounds::default(),
            member,
            surface,
            max_per_member: DRAIN_MAX_PER_MEMBER,
            max_per_surface: DRAIN_MAX_PER_SURFACE,
        }
    }
}

impl From<DrainBounds> for DrainOptions {
    fn from(bounds: DrainBounds) -> Self {
        Self {
            bounds,
            ..Self::new(None, None)
        }
    }
}

/// The drains running now, per member and per surface.
#[derive(Default)]
struct DrainCounts {
    members: std::collections::HashMap<String, usize>,
    surfaces: std::collections::HashMap<String, usize>,
}

static DRAINS: std::sync::LazyLock<std::sync::Mutex<DrainCounts>> = std::sync::LazyLock::new(Default::default);

fn drain_counts() -> std::sync::MutexGuard<'static, DrainCounts> {
    DRAINS
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// One running drain, counted against its member's and its surface's caps
/// until it is dropped.
struct DrainPermit {
    member: Option<String>,
    surface: Option<String>,
}

impl DrainPermit {
    /// A permit for a drain under `options`, unless its member or its surface
    /// already holds its cap of drains.
    fn acquire(options: &DrainOptions) -> Option<Self> {
        let mut counts = drain_counts();
        let full = |held: &std::collections::HashMap<String, usize>, key: &Option<String>, max: usize| {
            key.as_ref()
                .is_some_and(|key| {
                    held.get(key)
                        .copied()
                        .unwrap_or(0)
                        >= max
                })
        };
        if full(&counts.members, &options.member, options.max_per_member)
            || full(&counts.surfaces, &options.surface, options.max_per_surface)
        {
            return None;
        }
        let DrainCounts { members, surfaces } = &mut *counts;
        for (held, key) in [(members, &options.member), (surfaces, &options.surface)] {
            if let Some(key) = key {
                *held
                    .entry(key.clone())
                    .or_default() += 1;
            }
        }
        Some(Self {
            member: options.member.clone(),
            surface: options.surface.clone(),
        })
    }
}

impl Drop for DrainPermit {
    fn drop(&mut self) {
        let mut counts = drain_counts();
        let DrainCounts { members, surfaces } = &mut *counts;
        for (held, key) in [(members, &self.member), (surfaces, &self.surface)] {
            if let Some(key) = key
                && let Some(count) = held.get_mut(key)
            {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    held.remove(key);
                }
            }
        }
    }
}

/// The tokens a text is estimated at: ASCII characters at
/// [`ESTIMATE_CHARS_PER_TOKEN`] a token, other characters at
/// [`ESTIMATE_NON_ASCII_BYTES_PER_TOKEN`] UTF-8 bytes a token.
pub fn estimate_text_tokens(text: &str) -> u64 {
    let counts = text_counts(text);
    counts.tokens()
}

/// What a text is estimated from.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct TextCounts {
    /// ASCII digits: one token each, since tokenizers such as Gemini's split
    /// numbers into single digits.
    digits: u64,
    /// Other ASCII characters.
    ascii: u64,
    /// UTF-8 bytes of non-ASCII characters.
    non_ascii_bytes: u64,
}

impl TextCounts {
    fn add(
        &mut self,
        other: TextCounts,
    ) {
        self.digits += other.digits;
        self.ascii += other.ascii;
        self.non_ascii_bytes += other.non_ascii_bytes;
    }

    /// The estimated tokens: digits one each, other ASCII at
    /// [`ESTIMATE_CHARS_PER_TOKEN`], other scripts at
    /// [`ESTIMATE_NON_ASCII_BYTES_PER_TOKEN`].
    fn tokens(&self) -> u64 {
        self.digits
            + self
                .ascii
                .div_ceil(ESTIMATE_CHARS_PER_TOKEN)
            + self
                .non_ascii_bytes
                .div_ceil(ESTIMATE_NON_ASCII_BYTES_PER_TOKEN)
    }
}

/// The counts a text is estimated from.
fn text_counts(text: &str) -> TextCounts {
    let (digits, ascii) = text
        .bytes()
        .filter(u8::is_ascii)
        .fold((0, 0), |(digits, ascii), b| {
            if b.is_ascii_digit() {
                (digits + 1, ascii)
            } else {
                (digits, ascii + 1)
            }
        });
    TextCounts {
        digits,
        ascii,
        non_ascii_bytes: text.len() as u64 - digits - ascii,
    }
}

/// The input tokens a request is estimated at when its stream reports no
/// final usage, and for the long-context check: the whole body as sent
/// (messages or Responses `input`, the system prompt and `instructions`,
/// `tools` definitions, `response_format` schemas, every key), each text by
/// [`estimate_text_tokens`], and each image at [`INLINE_MEDIA_TOKENS`] (an
/// `image_url` / `image` / `input_image` part, a `data:` URL, or a base64
/// `data` beside a `media_type` / `mime_type`). What a Responses
/// `previous_response_id` or `conversation` refers to is held by the provider
/// and cannot be counted here.
pub fn estimate_request_tokens(body: &Value) -> u64 {
    match body {
        Value::String(text) if text.starts_with("data:") && text.len() > 256 => INLINE_MEDIA_TOKENS,
        Value::String(text) => estimate_text_tokens(text),
        Value::Array(items) => items
            .iter()
            .map(estimate_request_tokens)
            .sum(),
        Value::Object(fields) if is_media_part(fields) => INLINE_MEDIA_TOKENS,
        Value::Object(fields) => fields
            .iter()
            .map(|(key, value)| estimate_text_tokens(key) + estimate_request_tokens(value))
            .sum(),
        Value::Number(number) => estimate_text_tokens(&number.to_string()).max(1),
        Value::Bool(_) | Value::Null => 1,
    }
}

/// Whether an object is an image part: an OpenAI `image_url` or Responses
/// `input_image` part, an Anthropic `image` block, or base64 `data` with its
/// media type (Anthropic's `source`, Gemini's `inline_data`).
fn is_media_part(fields: &serde_json::Map<String, Value>) -> bool {
    let typed_image = fields
        .get("type")
        .and_then(Value::as_str)
        .is_some_and(|kind| matches!(kind, "image_url" | "image" | "input_image"));
    let base64_media = fields
        .get("data")
        .is_some_and(Value::is_string)
        && ["media_type", "mime_type", "mimeType"]
            .iter()
            .any(|key| fields.contains_key(*key));
    typed_image || base64_media
}

/// What a stream's output is estimated at beyond its streamed text, for a
/// model whose reasoning is billed but not streamed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ReasoningEstimate {
    /// Not a reasoning-capable model: the streamed text is the output.
    #[default]
    None,
    /// A reasoning-capable model with no output cap: the streamed text plus
    /// [`REASONING_ALLOWANCE_TOKENS`].
    Allowance(u64),
    /// A reasoning-capable model whose request capped its output
    /// (`max_tokens`, `max_completion_tokens`, `max_output_tokens`): at least
    /// the cap, the most it could have run.
    Cap(u64),
}

/// What a stream is estimated at when it reports no final usage (see
/// [`StreamOutcome::billed_tokens`]), fixed from the request before it is
/// sent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct StreamEstimate {
    /// The request's input (see [`estimate_request_tokens`]).
    pub input_tokens: u64,
    pub reasoning: ReasoningEstimate,
    /// The output cap the request set (`max_tokens`, `max_completion_tokens`,
    /// `max_output_tokens`), whatever the model: the floor of a stream a
    /// drain cut (see [`Self::output_tokens`]).
    pub output_cap: Option<u64>,
}

impl StreamEstimate {
    /// The estimate for `body` as sent, on a model that is reasoning-capable
    /// (`reasoning_model`) or not.
    pub fn of_request(
        body: &Value,
        reasoning_model: bool,
    ) -> Self {
        let output_cap = crate::pipes::context_transform::requested_output_tokens(body);
        let reasoning = if reasoning_model {
            Self::floor(output_cap)
        } else {
            ReasoningEstimate::None
        };
        Self {
            input_tokens: estimate_request_tokens(body),
            reasoning,
            output_cap,
        }
    }

    /// At least the output cap when the request set one, else the streamed
    /// text plus [`REASONING_ALLOWANCE_TOKENS`].
    fn floor(output_cap: Option<u64>) -> ReasoningEstimate {
        match output_cap {
            Some(cap) => ReasoningEstimate::Cap(cap),
            None => ReasoningEstimate::Allowance(REASONING_ALLOWANCE_TOKENS),
        }
    }

    /// The output tokens estimated for `streamed` tokens of streamed text, on
    /// a stream a drain cut (`drain_cut`) or not. A cut stream's model may
    /// still have been running, reasoning unseen, whatever the catalog or the
    /// id says of it, so it takes the reasoning floor (see [`Self::floor`]).
    pub fn output_tokens(
        &self,
        streamed: u64,
        drain_cut: bool,
    ) -> u64 {
        let reasoning = if drain_cut {
            Self::floor(self.output_cap)
        } else {
            self.reasoning
        };
        match reasoning {
            ReasoningEstimate::None => streamed,
            ReasoningEstimate::Allowance(allowance) => streamed + allowance,
            ReasoningEstimate::Cap(cap) => streamed.max(cap),
        }
    }
}

impl StreamOutcome {
    /// The `(input, output)` tokens a stream is billed at, and whether they are
    /// an estimate: the upstream's final usage when it reported it; else, on a
    /// key that bills (`source` not owned), at least `estimate` (see
    /// [`StreamEstimate`]) over the partial usage seen, so a platform-key
    /// stream that ends, or is cut off, without its final usage never bills
    /// less than it could have run. A stream on an owned key bills nothing,
    /// so it is never estimated.
    pub fn billed_tokens(
        &self,
        source: crate::pipes::key_source::KeySource,
        estimate: &StreamEstimate,
    ) -> (u64, u64, bool) {
        if self.usage_reported || source.owned() {
            return (self.input_tokens, self.output_tokens, false);
        }
        (
            self.input_tokens
                .max(estimate.input_tokens),
            self.output_tokens
                .max(estimate.output_tokens(self.output_estimate, self.drain_cut)),
            true,
        )
    }
}

/// Reads a stream's usage and counts its output text, from the upstream's
/// SSE events whatever their shape: OpenAI chat chunks (a top-level `usage`
/// with `prompt_tokens` / `completion_tokens`, `choices[].delta`), OpenAI
/// Responses events (`response.completed`'s `response.usage`, `*.delta`
/// text), Anthropic Messages events (`message_start`'s `message.usage`,
/// `message_delta`'s `usage`, `content_block_delta` text, with the prompt-cache
/// counts) and Gemini chunks (`usageMetadata`, `candidates[].content.parts`).
/// A caller can reach the latter shapes on an OpenAI-compatible upstream
/// through an encoded path, so every shape is read on every stream. Only a
/// final usage event makes the usage reported (see
/// [`StreamOutcome::usage_reported`]).
#[derive(Debug, Default)]
pub(crate) struct StreamMeter {
    input: Option<u64>,
    output: Option<u64>,
    cache: crate::pipes::types::llm::CacheTokens,
    /// A final usage event went past.
    final_usage: bool,
    /// Chat usage repeated on chunks that carry choices (a provider that
    /// reports a running count): final once the stream ends.
    running_usage: bool,
    /// The `[DONE]` sentinel went past.
    done: bool,
    output_text: TextCounts,
    /// The bytes of the line being received.
    pending: Vec<u8>,
    /// Skipping the rest of a line longer than [`MAX_PENDING_BYTES`].
    skipping: bool,
}

impl StreamMeter {
    /// Feed raw SSE bytes; each complete `data:` line is read. Bytes are split
    /// on newlines before they are decoded, so a character split across two
    /// network chunks is read whole.
    pub(crate) fn feed(
        &mut self,
        bytes: &[u8],
    ) {
        for line in self.lines(bytes) {
            self.line(&line);
        }
    }

    /// The complete lines in `bytes`, after what an earlier call left
    /// pending. A line longer than [`MAX_PENDING_BYTES`] is counted as output
    /// (so an estimate never undercounts it) and skipped.
    pub(crate) fn lines(
        &mut self,
        bytes: &[u8],
    ) -> Vec<Vec<u8>> {
        let mut lines = Vec::new();
        let mut rest = bytes;
        while let Some(idx) = rest
            .iter()
            .position(|b| *b == b'\n')
        {
            let (line, tail) = rest.split_at(idx);
            rest = &tail[1..];
            if std::mem::take(&mut self.skipping) {
                self.output_text
                    .non_ascii_bytes += line.len() as u64;
                continue;
            }
            self.pending
                .extend_from_slice(line);
            lines.push(std::mem::take(&mut self.pending));
        }
        if self.skipping {
            self.output_text
                .non_ascii_bytes += rest.len() as u64;
            return lines;
        }
        self.pending
            .extend_from_slice(rest);
        if self.pending.len() > MAX_PENDING_BYTES {
            self.output_text
                .non_ascii_bytes += self.pending.len() as u64;
            self.pending.clear();
            self.skipping = true;
        }
        lines
    }

    /// Read one SSE line (`data: {...}`), returning the event it carried.
    pub(crate) fn line(
        &mut self,
        line: &[u8],
    ) -> Option<Value> {
        let line = String::from_utf8_lossy(line);
        let payload = line
            .trim()
            .strip_prefix("data:")?
            .trim();
        if payload == "[DONE]" {
            self.done = true;
            return None;
        }
        let event = serde_json::from_str::<Value>(payload).ok()?;
        self.observe(&event);
        Some(event)
    }

    fn count_text(
        &mut self,
        value: Option<&Value>,
    ) {
        if let Some(text) = value.and_then(Value::as_str) {
            self.output_text
                .add(text_counts(text));
        }
    }

    /// Read one parsed event.
    pub(crate) fn observe(
        &mut self,
        event: &Value,
    ) {
        let kind = event
            .get("type")
            .and_then(Value::as_str);
        if let Some(usage) = event
            .get("usage")
            .filter(|usage| usage.is_object())
        {
            let count = |field: &str| {
                usage
                    .get(field)
                    .and_then(Value::as_u64)
            };
            match (count("prompt_tokens"), count("completion_tokens")) {
                (Some(input), Some(output)) => {
                    self.input = Some(input);
                    self.output = Some(output);
                    // OpenAI's usage chunk carries no choices; a running count
                    // rides on chunks that do.
                    let choices = event
                        .get("choices")
                        .and_then(Value::as_array);
                    if choices.is_none_or(Vec::is_empty) {
                        self.final_usage = true;
                    } else {
                        self.running_usage = true;
                    }
                }
                // Anthropic's `message_delta`: the final output count.
                _ => {
                    self.anthropic_usage(usage);
                    if kind == Some("message_delta")
                        && usage
                            .get("output_tokens")
                            .is_some()
                    {
                        self.final_usage = true;
                    }
                }
            }
        }
        if let Some(usage) = event
            .get("usageMetadata")
            .filter(|usage| usage.is_object())
        {
            let count = |field: &str| {
                usage
                    .get(field)
                    .and_then(Value::as_u64)
                    .unwrap_or(0)
            };
            self.input = Some(count("promptTokenCount"));
            self.output = Some(count("candidatesTokenCount") + count("thoughtsTokenCount"));
            if event
                .pointer("/candidates/0/finishReason")
                .is_some_and(|reason| !reason.is_null())
            {
                self.final_usage = true;
            }
        }
        match kind {
            Some("message_start") => {
                if let Some(usage) = event.pointer("/message/usage") {
                    self.anthropic_usage(usage);
                }
            }
            Some("response.completed" | "response.incomplete" | "response.failed") => {
                if let Some(usage) = event.pointer("/response/usage") {
                    let count = |field: &str| {
                        usage
                            .get(field)
                            .and_then(Value::as_u64)
                    };
                    if let (Some(input), Some(output)) = (count("input_tokens"), count("output_tokens")) {
                        self.input = Some(input);
                        self.output = Some(output);
                        self.final_usage = true;
                    }
                }
            }
            Some("content_block_delta") => {
                let delta = event.get("delta");
                for field in ["text", "thinking", "partial_json"] {
                    self.count_text(delta.and_then(|d| d.get(field)));
                }
            }
            Some(kind) if kind.starts_with("response.") && kind.ends_with(".delta") => {
                self.count_text(event.get("delta"));
            }
            _ => {}
        }
        for choice in event
            .get("choices")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let Some(delta) = choice.get("delta") else {
                continue;
            };
            for field in ["content", "reasoning_content", "reasoning", "refusal"] {
                self.count_text(delta.get(field));
            }
            for call in delta
                .get("tool_calls")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
            {
                self.count_text(call.pointer("/function/arguments"));
            }
        }
        for part in event
            .pointer("/candidates/0/content/parts")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            self.count_text(part.get("text"));
        }
    }

    /// Anthropic usage: input and output counts that only grow, and the
    /// prompt-cache counts.
    fn anthropic_usage(
        &mut self,
        usage: &Value,
    ) {
        let count = |field: &str| {
            usage
                .get(field)
                .and_then(Value::as_u64)
        };
        if let Some(input) = count("input_tokens") {
            self.input = Some(
                self.input
                    .unwrap_or(0)
                    .max(input),
            );
        }
        if let Some(output) = count("output_tokens") {
            self.output = Some(
                self.output
                    .unwrap_or(0)
                    .max(output),
            );
        }
        self.cache
            .max(crate::pipes::types::llm::CacheTokens::of_usage(usage));
    }

    /// Whether a final usage event went past (see
    /// [`StreamOutcome::usage_reported`]).
    pub(crate) fn final_seen(&self) -> bool {
        self.final_usage
    }

    /// Whether the usage counts as reported: a final usage event, or a running
    /// chat count on a stream that ended (`ended`: the upstream closed
    /// cleanly, or sent `[DONE]`).
    pub(crate) fn reported(
        &self,
        ended: bool,
    ) -> bool {
        self.final_usage || (self.running_usage && (ended || self.done))
    }

    /// The `(input, output)` tokens seen, final or not.
    pub(crate) fn usage(&self) -> (u64, u64) {
        (self.input.unwrap_or(0), self.output.unwrap_or(0))
    }

    /// The streamed output's tokens, estimated from its text.
    pub(crate) fn output_estimate(&self) -> u64 {
        self.output_text.tokens()
    }
}

/// Accumulates the assistant completion text from the OpenAI-shaped SSE lines a
/// stream forwards to the client, so a streamed interaction can be recorded with
/// the same fidelity as a buffered one. Off (zero-cost) unless `enabled`. Handles
/// partial lines split across network chunks via an internal line buffer, and
/// skips role/finish/`[DONE]` chunks that carry no `content`.
#[derive(Default)]
struct CompletionAccumulator {
    enabled: bool,
    pending: String,
    text: String,
    /// Whether the upstream's terminal frame went past — a `finish_reason` or
    /// the `[DONE]` sentinel.
    ///
    /// Distinct from the stream having been *delivered*: a client that hangs up
    /// the instant it reads `[DONE]` has the whole answer, and marks the stream
    /// aborted all the same. Anything deciding whether the answer is complete
    /// (caching, for one) needs this rather than the delivery outcome, or it
    /// races the client's disconnect and succeeds only sometimes.
    finished: bool,
}

impl CompletionAccumulator {
    fn new(enabled: bool) -> Self {
        Self { enabled, ..Default::default() }
    }

    /// Feed a slice of outgoing SSE text (one or more `data:` lines, possibly
    /// ending mid-line). Appends any `choices[0].delta.content` to the buffer.
    fn feed(
        &mut self,
        chunk: &str,
    ) {
        if !self.enabled {
            return;
        }
        self.pending.push_str(chunk);
        while let Some(idx) = self.pending.find('\n') {
            let line = self.pending[..idx]
                .trim_end_matches('\r')
                .to_string();
            self.pending.drain(..=idx);
            let Some(payload) = line.strip_prefix("data:") else {
                continue;
            };
            let payload = payload.trim();
            if payload.is_empty() {
                continue;
            }
            if payload == "[DONE]" {
                self.finished = true;
                continue;
            }
            let Ok(value) = serde_json::from_str::<Value>(payload) else {
                continue;
            };
            let choice = value
                .get("choices")
                .and_then(Value::as_array)
                .and_then(|a| a.first());
            if choice
                .and_then(|c| c.get("finish_reason"))
                .is_some_and(|r| !r.is_null())
            {
                self.finished = true;
            }
            if let Some(content) = choice
                .and_then(|c| c.get("delta"))
                .and_then(|d| d.get("content"))
                .and_then(Value::as_str)
            {
                self.text.push_str(content);
            }
        }
    }

    /// Did the upstream's answer arrive in full? See [`Self::finished`].
    fn saw_finish(&self) -> bool {
        self.finished
    }

    /// Consume the accumulator, yielding the completion text when enabled.
    fn finish(self) -> Option<String> {
        self.enabled
            .then_some(self.text)
    }
}

/// Forward one upstream SSE payload to the client, restoring NER ID tokens when
/// a rehydrator is active. Feeds the accumulator with the *rehydrated* text so a
/// governance recording matches what the client received (as the buffered path
/// does). Returns `true` when the client has disconnected and the stream should
/// abort.
async fn forward_sse(
    tx: &mpsc::Sender<Result<Bytes, std::io::Error>>,
    rehydrator: &mut Option<crate::pipes::prompt_guard::StreamRehydrator>,
    completion: &mut CompletionAccumulator,
    capture: bool,
    raw: Bytes,
) -> bool {
    match rehydrator.as_mut() {
        Some(rh) => {
            let out = rh.feed(&raw);
            if capture && let Ok(text) = std::str::from_utf8(&out) {
                completion.feed(text);
            }
            if out.is_empty() {
                return false;
            }
            tx.send(Ok(Bytes::from(out)))
                .await
                .is_err()
        }
        None => {
            if capture && let Ok(text) = std::str::from_utf8(&raw) {
                completion.feed(text);
            }
            tx.send(Ok(raw))
                .await
                .is_err()
        }
    }
}

/// Flush any content still held by the rehydrator when the upstream ends,
/// returning the number of bytes emitted (0 when inactive or nothing pending).
async fn flush_sse(
    tx: &mpsc::Sender<Result<Bytes, std::io::Error>>,
    rehydrator: &mut Option<crate::pipes::prompt_guard::StreamRehydrator>,
    completion: &mut CompletionAccumulator,
    capture: bool,
) -> u64 {
    let Some(rh) = rehydrator.as_mut() else {
        return 0;
    };
    let tail = rh.finish();
    if tail.is_empty() {
        return 0;
    }
    if capture && let Ok(text) = std::str::from_utf8(&tail) {
        completion.feed(text);
    }
    let bytes = tail.len() as u64;
    let _ = tx
        .send(Ok(Bytes::from(tail)))
        .await;
    bytes
}

/// An incremental progress heartbeat emitted while a stream is in flight: the
/// response bytes and tokens that have accrued **since the previous heartbeat**.
/// The handler records these against the operational time-series so the
/// dashboard's throughput / token charts advance live during a long stream.
pub struct StreamProgress {
    pub response_bytes: u64,
    pub input_tokens: u64,
    pub output_tokens: u64,
}

/// How often an in-flight stream flushes a progress heartbeat. Aligned with the
/// dashboard's live-refresh cadence so charts advance smoothly.
const PROGRESS_INTERVAL_SECS: u64 = 2;

/// Whether the client asked for a streamed response (`"stream": true`).
pub fn client_requested_stream(body: &Value) -> bool {
    body.get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

/// Whether a request path targets an endpoint whose response is **binary**
/// (opaque bytes, not JSON) and must be proxied verbatim — currently
/// text-to-speech (`/audio/speech`). Image generation and speech-to-text return
/// JSON and ride the normal buffered path, so they are intentionally excluded.
pub fn is_binary_endpoint(path_suffix: Option<&str>) -> bool {
    match path_suffix {
        Some(suffix) => suffix.ends_with("/audio/speech"),
        None => false,
    }
}

/// Whether a **GET** request path targets an LLM API family that must be proxied
/// to the provider (batch/file polling & retrieval) instead of being served as
/// the dashboard SPA shell. These paths never collide with SPA routes. A path
/// that could resolve somewhere else on the way upstream is never proxied: one
/// with a `.` or `..` segment, or with `%`, `;`, `\` or a control character
/// anywhere, since a URL parser drops tab, CR and LF before resolving dot
/// segments (file and
/// batch ids are letters, digits, `_` and `-`, so a real read needs none of
/// them, while a decoding proxy or a servlet container can turn them into a
/// traversal).
pub fn is_proxyable_get_path(path_suffix: &str) -> bool {
    let path = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix);
    (path.contains("/v1/batches") || path.contains("/v1/files"))
        && !path.contains(['%', ';', '\\'])
        && !path
            .chars()
            .any(|c| c.is_ascii_control())
        && !path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
}

/// Whether a **POST** request path targets the file-upload endpoint
/// (`POST /v1/files`), whose body is `multipart/form-data` rather than JSON and
/// must be forwarded to the provider verbatim. `/v1/files/{id}` retrieval is a
/// GET (see [`is_proxyable_get_path`]); only the bare create path uploads.
pub fn is_upload_path(path_suffix: &str) -> bool {
    let trimmed = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    trimmed.ends_with("/v1/files")
}

/// Whether a **POST** request path targets a speech-to-text endpoint
/// (`/v1/audio/transcriptions` or `/v1/audio/translations`), whose body is
/// `multipart/form-data` carrying the audio file. Like [`is_upload_path`], these
/// are forwarded to the provider verbatim; the response is JSON (the transcript /
/// translation). Text-to-speech (`/v1/audio/speech`) is a *binary* response and
/// is handled separately (see [`is_binary_endpoint`]).
pub fn is_audio_multipart_path(path_suffix: &str) -> bool {
    let trimmed = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    trimmed.ends_with("/v1/audio/transcriptions") || trimmed.ends_with("/v1/audio/translations")
}

/// Whether a **GET** request path targets the OpenAI-compatible model-listing
/// endpoint (`GET /v1/models`). The gateway answers this itself with the
/// surface's exposed model(s) rather than proxying, so a client can discover
/// what a route serves (mirroring hosted gateways).
pub fn is_models_path(path_suffix: &str) -> bool {
    let trimmed = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    trimmed.ends_with("/v1/models")
}

/// Whether a **POST** request path asks for a VP challenge
/// (`POST {route}/v1/vp-challenge`), which the gateway issues itself.
pub fn is_vp_challenge_path(path_suffix: &str) -> bool {
    path_suffix.trim_end_matches('/') == "/v1/vp-challenge"
}

/// Whether a request path targets the realtime voice endpoint
/// (`/v1/realtime`, Mode C). The client arrives as a `GET` with an
/// `Upgrade: websocket` header; the gateway upgrades the connection and relays a
/// governed bidirectional realtime session to the surface's upstream provider.
pub fn is_realtime_path(path_suffix: &str) -> bool {
    let trimmed = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    trimmed.ends_with("/v1/realtime")
}

/// Whether a **GET** request path targets the IDE Surface bootstrap document
/// (`GET /.well-known/agent-stream`, optionally with a `.json` suffix). The
/// gateway answers this **unauthenticated** with the public sign-in identifiers
/// and discovery paths, so an IDE client can configure itself from the Access
/// Point URL alone (OIDC-style discovery).
pub fn is_wellknown_ide_path(path_suffix: &str) -> bool {
    let trimmed = path_suffix
        .split(['?', '#'])
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    trimmed.ends_with("/.well-known/agent-stream") || trimmed.ends_with("/.well-known/agent-stream.json")
}

/// Whether a surface may proxy the upstream SSE stream back to the client.
/// Streaming bypasses every response-side stage, so it is only eligible when
/// none is configured: no Jury, no response-side prompt guards, and no external
/// response guardrail. Two request-side stages are compatible and run pre-stream
/// in `execute_streaming`: a **Judge** (gates the prompt, can block) and a
/// **Route decider** (picks one candidate upstream to stream from) — a **Mirror**
/// decider (fan-out + merge) is not. It is further limited to a base provider,
/// and every Route candidate, whose SSE format can be delivered as OpenAI chunks — OpenAI (proxied
/// verbatim), Anthropic (translated on the fly), or Microsoft 365 Copilot
/// (`chatOverStream` snapshots translated to deltas) — and is disabled when
/// `streaming.enabled == false` (the admin buffered-vs-streamed switch).
pub fn passthrough_eligible(config: &PipeConfig) -> bool {
    // Explicit opt-out.
    if let Some(streaming) = &config.streaming
        && !streaming.enabled
    {
        return false;
    }

    // Base provider must speak a wire/SSE format we can stream to the client:
    // OpenAI (verbatim), Anthropic (translated), or Microsoft 365 Copilot
    // (`chatOverStream` snapshots translated to OpenAI deltas) — all handled in
    // `spawn_metered_stream`.
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    let streamable = |schema: &str| matches!(schema, "openai" | "anthropic" | "copilot");
    let streamable_schema = match &config.pipe_type {
        crate::pipes::PipeType::LLM { provider, .. } => streamable(provider.api_schema()),
        _ => false,
    };
    if !streamable_schema {
        return false;
    }

    // Governed server tools run a bounded agentic loop (multiple model turns
    // with tool execution between them), which is incompatible with a single
    // SSE passthrough — force the buffered path.
    if config
        .server_tools
        .as_ref()
        .is_some_and(|st| st.is_active())
    {
        return false;
    }

    // Any routing or response-side processing requires the buffered path.
    if config
        .jury
        .as_ref()
        .is_some_and(|j| j.enabled)
    {
        return false;
    }
    // A Route decider picks one candidate upstream to stream from (run pre-stream
    // in `execute_streaming`), so every candidate must speak a streamable format;
    // a Mirror decider fans out + merges, which cannot stream.
    if config
        .decider
        .as_ref()
        .is_some_and(|d| {
            d.enabled
                && (d.strategy != crate::pipes::judge_jury::DeciderStrategy::Route
                    || d.candidates.is_empty()
                    || d.candidates
                        .iter()
                        .any(|c| !streamable(crate::pipes::judge_jury::target_to_provider(&c.llm).api_schema())))
        })
    {
        return false;
    }
    if let Some(guard) = &config.prompt_guard
        && guard.enabled
    {
        if !guard.response.is_empty() {
            return false;
        }
        if guard
            .external
            .as_ref()
            .is_some_and(|e| e.enabled && e.check_response)
        {
            return false;
        }
    }

    // Any expert witness on the response seam requires the buffered path so its
    // verdict can block delivery. (A legacy `prompt_guard.external` is also
    // checked above, defensively, in case the config has not been migrated.)
    if config
        .expert_witnesses
        .iter()
        .any(|w| w.guardrail.enabled && w.guardrail.check_response)
    {
        return false;
    }

    true
}

/// Compute the USD cost for streamed token usage: the upstream's declared
/// price when set (zero included, and never below the catalog unless
/// `own_price_honoured`), else the model catalog, falling back to the
/// built-in pricing table. Returns `0.0` when no rate is known (matching the
/// buffered path's behaviour for unpriced models).
pub fn cost_for_tokens(
    declared: Option<&crate::pipes::types::llm::TargetPricing>,
    own_price_honoured: bool,
    provider_enum: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
) -> f64 {
    let declared = declared.map(|pricing| pricing.token_pricing());
    let catalog = || crate::pipes::types::llm::catalog_price_for_input(provider_enum, model, None, input_tokens);
    crate::pipes::types::llm::priced_cost(declared.as_slice(), own_price_honoured, catalog, input_tokens, output_tokens)
}

/// The USD cost of a stream's prompt-cache tokens: at the catalog's cache
/// prices unless the stream bills at its declared price, else at Anthropic's
/// published ratios to the input price it bills at (see [`cost_for_tokens`]
/// and [`crate::pipes::types::llm::cache_cost`]).
pub fn cache_cost_for_tokens(
    declared: Option<&crate::pipes::types::llm::TargetPricing>,
    own_price_honoured: bool,
    provider_enum: &str,
    model: &str,
    cache: crate::pipes::types::llm::CacheTokens,
) -> f64 {
    if cache.is_empty() {
        return 0.0;
    }
    let input_per_million = cost_for_tokens(declared, own_price_honoured, provider_enum, model, 1_000_000, 0);
    let catalog = if own_price_honoured && declared.is_some() {
        crate::pipes::types::llm::CachePrices::default()
    } else {
        crate::pipes::types::llm::catalog_cache_prices(provider_enum, model, None)
    };
    crate::pipes::types::llm::cache_cost(cache, input_per_million, catalog)
}

/// Proxy an upstream SSE response to the client while parsing the terminal
/// usage chunk. Always produces the OpenAI-canonical wire format internally
/// (translating Anthropic/Copilot upstreams), then re-encodes the client-facing
/// stream into `egress`'s dialect (Anthropic Messages / OpenAI Responses) when
/// it is not OpenAI Chat. Metrics, usage, rehydration, and `on_complete` run on
/// the canonical stream and are unaffected by the egress skin.
///
/// `drain` is set for a stream on a key that bills: when the client goes, the
/// upstream is read on (nothing more is forwarded) within its bounds, until
/// the provider's final usage event, so the stream bills what the provider
/// ran rather than an estimate. Past its concurrent-drain caps the stream
/// stops when the client goes and is billed its estimate with the cut floor.
#[allow(clippy::too_many_arguments)]
pub fn spawn_metered_stream<F, P>(
    upstream: reqwest::Response,
    schema: String,
    capture_completion: bool,
    rehydration_map: crate::pipes::prompt_guard::RehydrationMap,
    on_progress: P,
    on_complete: F,
    egress: crate::pipes::streaming_skin::EgressSkin,
    drain: Option<DrainOptions>,
) -> Body
where
    F: FnOnce(StreamOutcome) + Send + 'static,
    P: Fn(StreamProgress) + Send + 'static,
{
    let body =
        spawn_openai_sse_body(upstream, schema, capture_completion, rehydration_map, on_progress, on_complete, drain);
    crate::pipes::streaming_skin::reencode_sse_body(body, egress)
}

/// Reading on after a stream's client has gone (see [`DrainOptions`]).
struct Drain {
    bounds: Option<DrainBounds>,
    options: Option<DrainOptions>,
    /// Held while draining, against the concurrent-drain caps.
    permit: Option<DrainPermit>,
    /// When the client went, once it has.
    since: Option<tokio::time::Instant>,
    /// Bytes read since then.
    bytes: u64,
    /// A bound stopped the reading before the stream ended, or the caps
    /// refused it.
    cut: bool,
}

impl Drain {
    fn new(options: Option<DrainOptions>) -> Self {
        Self {
            bounds: options
                .as_ref()
                .map(|options| options.bounds),
            options,
            permit: None,
            since: None,
            bytes: 0,
            cut: false,
        }
    }

    /// The client has gone: start reading on, when the stream drains and its
    /// caps admit one more drain, and say whether it does. A drain the caps
    /// refuse is cut at once.
    fn start(&mut self) -> bool {
        let Some(options) = &self.options else {
            return false;
        };
        match DrainPermit::acquire(options) {
            Some(permit) => {
                self.permit = Some(permit);
                self.since = Some(tokio::time::Instant::now());
            }
            None => {
                self.cut = true;
                tracing::info!("stream not read on after its client left: too many drains running");
            }
        }
        self.since.is_some()
    }

    fn draining(&self) -> bool {
        self.since.is_some()
    }

    /// Count `bytes` read while draining; whether the byte bound is now past.
    fn read(
        &mut self,
        bytes: u64,
    ) -> bool {
        self.bytes += bytes;
        if self
            .bounds
            .is_some_and(|bounds| self.bytes > bounds.max_bytes)
        {
            self.cut = true;
        }
        self.cut
    }

    /// When the time bound passes, while draining.
    fn deadline(&self) -> Option<tokio::time::Instant> {
        Some(self.since? + self.bounds?.max_time)
    }

    fn log(
        &self,
        meter: &StreamMeter,
    ) {
        if self.draining() {
            tracing::info!(
                final_usage = meter.final_seen(),
                cut = self.cut,
                drained_bytes = self.bytes,
                "stream read on after its client left"
            );
        }
    }
}

/// Sleep until `deadline`, or forever without one.
async fn sleep_until_or_never(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline).await,
        None => std::future::pending().await,
    }
}

/// Produce the OpenAI-canonical SSE body for a surface's streamed response.
/// When `schema == "anthropic"` each upstream Anthropic SSE event is translated
/// into an OpenAI-shaped chunk (`data: {choices:[{delta:{...}}]}`) and when
/// `schema == "copilot"` each Microsoft 365 Copilot conversation snapshot is
/// diffed into OpenAI `content` deltas, so the client only ever sees the OpenAI
/// wire format; otherwise bytes are forwarded verbatim. When the stream ends,
/// `on_complete` is invoked with the observed token/byte totals so the caller
/// can record metrics and usage off the response path.
fn spawn_openai_sse_body<F, P>(
    upstream: reqwest::Response,
    schema: String,
    capture_completion: bool,
    rehydration_map: crate::pipes::prompt_guard::RehydrationMap,
    on_progress: P,
    on_complete: F,
    drain: Option<DrainOptions>,
) -> Body
where
    F: FnOnce(StreamOutcome) + Send + 'static,
    P: Fn(StreamProgress) + Send + 'static,
{
    if schema == "anthropic" {
        return spawn_anthropic_translated_stream(
            upstream,
            capture_completion,
            rehydration_map,
            on_progress,
            on_complete,
            drain,
        );
    }
    if schema == "copilot" {
        return spawn_copilot_translated_stream(
            upstream,
            capture_completion,
            rehydration_map,
            on_progress,
            on_complete,
        );
    }

    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        let mut meter = StreamMeter::default();
        let mut drain = Drain::new(drain);
        let mut response_bytes: u64 = 0;
        let mut errored = false;
        let mut aborted = false;
        let mut ended = false;
        let mut completion = CompletionAccumulator::new(capture_completion);
        let mut rehydrator = crate::pipes::prompt_guard::StreamRehydrator::new(rehydration_map);
        // OpenAI only reports tokens in the terminal usage chunk, so heartbeats
        // flush response bytes only; tokens land whole in the completion record.
        let mut flushed_response_bytes: u64 = 0;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(PROGRESS_INTERVAL_SECS));
        ticker.tick().await; // discard the immediate first tick

        loop {
            let deadline = drain.deadline();
            tokio::select! {
                biased;
                item = byte_stream.next() => {
                    let Some(item) = item else {
                        ended = true;
                        break;
                    };
                    match item {
                        Ok(bytes) => {
                            // Read the usage and count the output from the raw
                            // upstream events, line by line.
                            meter.feed(&bytes);
                            if drain.draining() {
                                // The client has gone: read on, forwarding
                                // nothing, until the final usage or a bound.
                                if meter.final_seen() || drain.read(bytes.len() as u64) {
                                    break;
                                }
                                continue;
                            }
                            response_bytes += bytes.len() as u64;

                            if forward_sse(&tx, &mut rehydrator, &mut completion, capture_completion, bytes).await {
                                // Client disconnected: record what was delivered
                                // as a partial stream, reading on for the final
                                // usage when the stream bills.
                                aborted = true;
                                if meter.final_seen() || !drain.start() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            errored = true;
                            if !drain.draining() {
                                let _ = tx
                                    .send(Err(std::io::Error::other(e.to_string())))
                                    .await;
                            }
                            break;
                        }
                    }
                }
                _ = sleep_until_or_never(deadline) => {
                    drain.cut = true;
                    break;
                }
                _ = ticker.tick() => {
                    let delta = response_bytes - flushed_response_bytes;
                    if delta > 0 {
                        flushed_response_bytes = response_bytes;
                        on_progress(StreamProgress { response_bytes: delta, input_tokens: 0, output_tokens: 0 });
                    }
                }
            }
        }

        if !aborted {
            response_bytes += flush_sse(&tx, &mut rehydrator, &mut completion, capture_completion).await;
        }

        drain.log(&meter);
        let (input_tokens, output_tokens) = meter.usage();
        on_complete(StreamOutcome {
            input_tokens,
            output_tokens,
            response_bytes,
            completed: !errored && !aborted,
            answer_complete: completion.saw_finish(),
            flushed_response_bytes,
            flushed_input_tokens: 0,
            flushed_output_tokens: 0,
            completion: completion.finish(),
            usage_reported: meter.reported(ended && !errored),
            output_estimate: meter.output_estimate(),
            cache: meter.cache,
            drain_cut: drain.cut,
        });
    });

    Body::from_stream(ReceiverStream::new(rx))
}

/// Translate an Anthropic Messages SSE stream into OpenAI-shaped chunks.
///
/// Anthropic emits `event:`/`data:` line pairs; we parse each `data:` JSON
/// object and, depending on its `type`, emit the matching OpenAI streaming
/// chunk. Usage is read from `message_start` (`message.usage.input_tokens`) and
/// `message_delta` (`usage.output_tokens`, the final count). Bytes are split
/// on newlines before they are decoded, so a character split across network
/// chunks (and any usage in its chunk) is kept. With `drain`, the upstream is
/// read on after the client goes, as for an OpenAI stream.
fn spawn_anthropic_translated_stream<F, P>(
    upstream: reqwest::Response,
    capture_completion: bool,
    rehydration_map: crate::pipes::prompt_guard::RehydrationMap,
    on_progress: P,
    on_complete: F,
    drain: Option<DrainOptions>,
) -> Body
where
    F: FnOnce(StreamOutcome) + Send + 'static,
    P: Fn(StreamProgress) + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        let mut input_tokens: u64 = 0;
        let mut output_tokens: u64 = 0;
        let mut response_bytes: u64 = 0;
        let mut errored = false;
        let mut aborted = false;
        let mut ended = false;
        let mut state = StreamState::default();
        let mut meter = StreamMeter::default();
        let mut drain = Drain::new(drain);
        let mut completion = CompletionAccumulator::new(capture_completion);
        let mut rehydrator = crate::pipes::prompt_guard::StreamRehydrator::new(rehydration_map);
        // Anthropic reports input tokens at `message_start` and grows output
        // tokens via `message_delta`, so heartbeats can flush live token deltas.
        let mut flushed_response_bytes: u64 = 0;
        let mut flushed_input_tokens: u64 = 0;
        let mut flushed_output_tokens: u64 = 0;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(PROGRESS_INTERVAL_SECS));
        ticker.tick().await; // discard the immediate first tick

        'outer: loop {
            let deadline = drain.deadline();
            tokio::select! {
                biased;
                item = byte_stream.next() => {
                    let Some(item) = item else {
                        ended = true;
                        break;
                    };
                    match item {
                        Ok(bytes) => {
                            if drain.draining() && drain.read(bytes.len() as u64) {
                                break;
                            }
                            // Consume every complete line, leaving a trailing
                            // partial (bytes, so a split character survives).
                            for line in meter.lines(&bytes) {
                                let Some(event) = meter.line(&line) else {
                                    continue;
                                };
                                if let Some(n) = anthropic_input_tokens(&event) {
                                    input_tokens = n;
                                }
                                if let Some(n) = anthropic_output_tokens(&event) {
                                    output_tokens = n;
                                }
                                if drain.draining() {
                                    continue;
                                }
                                for chunk in anthropic_event_to_openai_chunks(&event, &mut state) {
                                    let line = format!("data: {chunk}\n\n");
                                    response_bytes += line.len() as u64;
                                    if forward_sse(&tx, &mut rehydrator, &mut completion, capture_completion, Bytes::from(line)).await {
                                        // Client disconnected: read on for the
                                        // final usage when the stream bills.
                                        aborted = true;
                                        if meter.final_seen() || !drain.start() {
                                            break 'outer;
                                        }
                                        break;
                                    }
                                }
                            }
                            if drain.draining() && meter.final_seen() {
                                break;
                            }
                        }
                        Err(e) => {
                            errored = true;
                            if !drain.draining() {
                                let _ = tx
                                    .send(Err(std::io::Error::other(e.to_string())))
                                    .await;
                            }
                            break;
                        }
                    }
                }
                _ = sleep_until_or_never(deadline) => {
                    drain.cut = true;
                    break;
                }
                _ = ticker.tick() => {
                    let d_bytes = response_bytes - flushed_response_bytes;
                    let d_in = input_tokens - flushed_input_tokens;
                    let d_out = output_tokens - flushed_output_tokens;
                    if d_bytes > 0 || d_in > 0 || d_out > 0 {
                        flushed_response_bytes = response_bytes;
                        flushed_input_tokens = input_tokens;
                        flushed_output_tokens = output_tokens;
                        on_progress(StreamProgress { response_bytes: d_bytes, input_tokens: d_in, output_tokens: d_out });
                    }
                }
            }
        }

        if !errored && !aborted {
            response_bytes += flush_sse(&tx, &mut rehydrator, &mut completion, capture_completion).await;
            let done = "data: [DONE]\n\n";
            response_bytes += done.len() as u64;
            let _ = tx
                .send(Ok(Bytes::from_static(done.as_bytes())))
                .await;
        }

        drain.log(&meter);
        on_complete(StreamOutcome {
            input_tokens,
            output_tokens,
            response_bytes,
            completed: !errored && !aborted,
            answer_complete: completion.saw_finish(),
            flushed_response_bytes,
            flushed_input_tokens,
            flushed_output_tokens,
            completion: completion.finish(),
            usage_reported: meter.reported(ended && !errored),
            output_estimate: meter.output_estimate(),
            cache: meter.cache,
            drain_cut: drain.cut,
        });
    });

    Body::from_stream(ReceiverStream::new(rx))
}

/// Translate a Microsoft 365 Copilot `chatOverStream` SSE stream into
/// OpenAI-shaped chunks.
///
/// Copilot does **not** stream token deltas: each SSE event carries a **full
/// `copilotConversation` snapshot** whose last message holds the assistant's
/// answer *so far* (cumulative text). We therefore diff each snapshot against
/// what we have already forwarded and emit only the newly appended suffix as an
/// OpenAI `content` delta, so the client sees progressive output. Copilot
/// reports no token usage, so the totals are zero (matching the buffered path,
/// which meters Copilot at zero cost — billing is per user license).
///
/// The parser is tolerant of how Copilot serialises each event: compact
/// single-line `data: {...}`, spec-compliant multi-line `data:`-prefixed JSON,
/// or pretty-printed JSON where only the first line carries the `data:` prefix
/// (see [`parse_copilot_sse_block`]).
fn spawn_copilot_translated_stream<F, P>(
    upstream: reqwest::Response,
    capture_completion: bool,
    rehydration_map: crate::pipes::prompt_guard::RehydrationMap,
    on_progress: P,
    on_complete: F,
) -> Body
where
    F: FnOnce(StreamOutcome) + Send + 'static,
    P: Fn(StreamProgress) + Send + 'static,
{
    let (tx, rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(16);

    tokio::spawn(async move {
        let mut byte_stream = upstream.bytes_stream();
        let mut pending = String::new();
        let mut emitted = String::new();
        let mut response_bytes: u64 = 0;
        let mut errored = false;
        let mut aborted = false;
        let mut sent_role = false;
        let mut completion = CompletionAccumulator::new(capture_completion);
        let mut rehydrator = crate::pipes::prompt_guard::StreamRehydrator::new(rehydration_map);
        // Copilot reports no token usage, so heartbeats flush response bytes only.
        let mut flushed_response_bytes: u64 = 0;
        let mut ticker = tokio::time::interval(std::time::Duration::from_secs(PROGRESS_INTERVAL_SECS));
        ticker.tick().await; // discard the immediate first tick

        let start = std::time::Instant::now();
        let mut upstream_reads: u64 = 0;
        let mut emit_count: u64 = 0;
        let mut first_byte_ms: Option<u128> = None;
        let mut first_emit_ms: Option<u128> = None;
        let mut last_emit_ms: u128 = 0;

        'outer: loop {
            tokio::select! {
                biased;
                item = byte_stream.next() => {
                    let Some(item) = item else { break };
                    match item {
                        Ok(bytes) => {
                            let Ok(text) = std::str::from_utf8(&bytes) else {
                                continue;
                            };
                            upstream_reads += 1;
                            if first_byte_ms.is_none() {
                                let ms = start.elapsed().as_millis();
                                first_byte_ms = Some(ms);
                                tracing::info!("[copilot-stream] first upstream bytes at {}ms ({} bytes)", ms, bytes.len());
                            }
                            pending.push_str(text);

                            // Consume every complete SSE event block (terminated by a
                            // blank line), leaving a trailing partial in `pending`.
                            // Microsoft Graph uses CRLF, so tolerate both `\n\n` and
                            // `\r\n\r\n` event boundaries.
                            while let Some((block_end, drain_to)) = next_event_boundary(&pending) {
                                let block = pending[..block_end].to_string();
                                pending.drain(..drain_to);

                                for chunk in copilot_block_to_openai_chunks(&block, &mut emitted, &mut sent_role) {
                                    let line = format!("data: {chunk}\n\n");
                                    response_bytes += line.len() as u64;
                                    emit_count += 1;
                                    let ms = start.elapsed().as_millis();
                                    if first_emit_ms.is_none() {
                                        first_emit_ms = Some(ms);
                                    }
                                    last_emit_ms = ms;
                                    if forward_sse(&tx, &mut rehydrator, &mut completion, capture_completion, Bytes::from(line)).await {
                                        aborted = true;
                                        break 'outer;
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            errored = true;
                            let _ = tx
                                .send(Err(std::io::Error::other(e.to_string())))
                                .await;
                            break;
                        }
                    }
                }
                _ = ticker.tick() => {
                    let delta = response_bytes - flushed_response_bytes;
                    if delta > 0 {
                        flushed_response_bytes = response_bytes;
                        on_progress(StreamProgress { response_bytes: delta, input_tokens: 0, output_tokens: 0 });
                    }
                }
            }
        }

        // Flush a trailing block that arrived without a terminating blank line.
        if !errored && !aborted && !pending.trim().is_empty() {
            for chunk in copilot_block_to_openai_chunks(&pending, &mut emitted, &mut sent_role) {
                let line = format!("data: {chunk}\n\n");
                response_bytes += line.len() as u64;
                emit_count += 1;
                last_emit_ms = start.elapsed().as_millis();
                let _ = forward_sse(&tx, &mut rehydrator, &mut completion, capture_completion, Bytes::from(line)).await;
            }
        }

        tracing::info!(
            "[copilot-stream] upstream_reads={} emitted={} first_byte_ms={:?} first_emit_ms={:?} last_emit_ms={} spread_ms={}",
            upstream_reads,
            emit_count,
            first_byte_ms,
            first_emit_ms,
            last_emit_ms,
            last_emit_ms.saturating_sub(first_emit_ms.unwrap_or(last_emit_ms)),
        );

        if !errored && !aborted {
            // Any content still held by the rehydrator, then the terminal
            // finish-reason chunk and the OpenAI stream sentinel.
            response_bytes += flush_sse(&tx, &mut rehydrator, &mut completion, capture_completion).await;
            let finish = format!("data: {}\n\n", openai_chunk_finish("stop"));
            response_bytes += finish.len() as u64;
            let _ = tx
                .send(Ok(Bytes::from(finish)))
                .await;
            let done = "data: [DONE]\n\n";
            response_bytes += done.len() as u64;
            let _ = tx
                .send(Ok(Bytes::from_static(done.as_bytes())))
                .await;
        }

        // Copilot reports no token usage; meter zero (billing is per license).
        on_complete(StreamOutcome {
            input_tokens: 0,
            output_tokens: 0,
            response_bytes,
            completed: !errored && !aborted,
            answer_complete: completion.saw_finish(),
            flushed_response_bytes,
            flushed_input_tokens: 0,
            flushed_output_tokens: 0,
            completion: completion.finish(),
            usage_reported: false,
            output_estimate: estimate_text_tokens(&emitted),
            cache: crate::pipes::types::llm::CacheTokens::default(),
            drain_cut: false,
        });
    });

    Body::from_stream(ReceiverStream::new(rx))
}

/// Find the next SSE event boundary (a blank line), tolerating both LF (`\n\n`)
/// and CRLF (`\r\n\r\n`) line endings — Microsoft Graph uses CRLF. Returns
/// `(block_end, drain_to)` where `s[..block_end]` is the event block and
/// `s.drain(..drain_to)` consumes the block plus its terminating blank line.
fn next_event_boundary(s: &str) -> Option<(usize, usize)> {
    let lf = s
        .find("\n\n")
        .map(|i| (i, i + 2));
    let crlf = s
        .find("\r\n\r\n")
        .map(|i| (i, i + 4));
    match (lf, crlf) {
        (Some(a), Some(b)) => Some(if a.0 <= b.0 { a } else { b }),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    }
}

/// Turn one Copilot SSE event block into the OpenAI chunk(s) it produces,
/// advancing the cumulative-text and role-primed state. Emits a one-off
/// role-priming chunk before the first content, then a `content` delta chunk
/// for the newly appended text. Returns an empty vec for heartbeat/echo events
/// that add no new assistant text.
fn copilot_block_to_openai_chunks(
    block: &str,
    emitted: &mut String,
    sent_role: &mut bool,
) -> Vec<String> {
    let mut out = Vec::new();
    let Some(event) = parse_copilot_sse_block(block) else {
        return out;
    };
    let Some(cumulative) = copilot_stream_text(&event) else {
        return out;
    };
    let Some(delta) = copilot_delta(emitted, &cumulative) else {
        return out;
    };
    if !*sent_role {
        out.push(openai_chunk_role());
        *sent_role = true;
    }
    *emitted = cumulative;
    out.push(openai_chunk_content(&delta));
    out
}

/// Reconstruct the JSON payload of one Copilot SSE event block.
///
/// Tolerates three serialisations: compact single-line `data: {...}`,
/// spec-compliant multi-line `data:`-prefixed JSON, and pretty-printed JSON
/// where only the first line is `data:`-prefixed and continuation lines are
/// raw. SSE metadata fields (`id:`, `event:`, `retry:`, comments) are dropped;
/// a `data:` prefix (with one optional space) is stripped; everything else is
/// concatenated and parsed as JSON.
fn parse_copilot_sse_block(block: &str) -> Option<Value> {
    let mut json_buf = String::new();
    for line in block.lines() {
        let line = line.trim_end_matches('\r');
        // SSE metadata lines start at column 0 (JSON continuation lines are
        // indented, so they never match these prefixes).
        if line.starts_with("id:") || line.starts_with("event:") || line.starts_with("retry:") || line.starts_with(':')
        {
            continue;
        }
        let content = line
            .strip_prefix("data:")
            .map(|s| {
                s.strip_prefix(' ')
                    .unwrap_or(s)
            })
            .unwrap_or(line);
        json_buf.push_str(content);
    }
    serde_json::from_str(&json_buf).ok()
}

/// Extract the cumulative assistant text from a Copilot conversation snapshot:
/// the `text` of the last message in `messages`. Returns `None` for heartbeat
/// events with no messages (or an empty answer).
fn copilot_stream_text(event: &Value) -> Option<String> {
    event
        .get("messages")
        .and_then(Value::as_array)
        .and_then(|msgs| msgs.last())
        .and_then(|m| m.get("text"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Compute the newly appended suffix between the text already forwarded and the
/// latest cumulative snapshot. Returns `None` when the snapshot is not a strict
/// forward extension (equal length, shorter, or a non-prefix rewrite such as an
/// echoed user prompt), so heartbeats and the request echo never emit content.
fn copilot_delta(
    emitted: &str,
    cumulative: &str,
) -> Option<String> {
    if cumulative.len() > emitted.len() && cumulative.starts_with(emitted) {
        Some(cumulative[emitted.len()..].to_string())
    } else {
        None
    }
}

/// Per-stream translator state carried across every Anthropic SSE event.
///
/// * `sent_role` — whether the OpenAI role-priming chunk (`delta.role`) has
///   been emitted; sent exactly once, before the first text or tool-call chunk.
/// * `next_tool_index` — monotonic OpenAI `tool_calls[].index` counter.
/// * `block_to_tool` — maps Anthropic `content_block` index (which counts
///   mixed text + tool_use blocks) to the OpenAI tool-call index assigned when
///   the `content_block_start` was seen, so subsequent `input_json_delta`s
///   route to the correct tool call.
#[derive(Default)]
struct StreamState {
    sent_role: bool,
    next_tool_index: u64,
    block_to_tool: std::collections::HashMap<u64, u64>,
}

/// Convert one Anthropic SSE event into zero or more OpenAI chunk JSON strings.
///
/// On the first content-bearing event a role-priming chunk (`delta.role`) is
/// emitted so OpenAI clients see the assistant role before any text or tool
/// call. `content_block_start` events with `type: "tool_use"` emit a tool-call
/// announcement chunk (`{ id, type: "function", function: { name, arguments: "" } }`);
/// subsequent `content_block_delta`s with `type: "input_json_delta"` emit
/// arguments-fragment chunks keyed to the same tool-call index. Text blocks
/// still emit content chunks as before.
fn anthropic_event_to_openai_chunks(
    event: &Value,
    state: &mut StreamState,
) -> Vec<String> {
    let event_type = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("");
    let mut out = Vec::new();

    match event_type {
        "content_block_start" => {
            let block = event.get("content_block");
            let block_type = block
                .and_then(|b| b.get("type"))
                .and_then(Value::as_str);
            if block_type == Some("tool_use") {
                let cb_index = event
                    .get("index")
                    .and_then(Value::as_u64)
                    .unwrap_or(0);
                let tool_index = state.next_tool_index;
                state.next_tool_index += 1;
                state
                    .block_to_tool
                    .insert(cb_index, tool_index);

                let tool_id = block
                    .and_then(|b| b.get("id"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let tool_name = block
                    .and_then(|b| b.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or("");

                if !state.sent_role {
                    out.push(openai_chunk_role());
                    state.sent_role = true;
                }
                out.push(openai_chunk_tool_start(tool_index, tool_id, tool_name));
            }
        }
        "content_block_delta" => {
            let delta = event.get("delta");
            let delta_type = delta
                .and_then(|d| d.get("type"))
                .and_then(Value::as_str);
            match delta_type {
                Some("text_delta") => {
                    let text = delta
                        .and_then(|d| d.get("text"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !text.is_empty() {
                        if !state.sent_role {
                            out.push(openai_chunk_role());
                            state.sent_role = true;
                        }
                        out.push(openai_chunk_content(text));
                    }
                }
                Some("thinking_delta") => {
                    let text = delta
                        .and_then(|d| d.get("thinking"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !text.is_empty() {
                        if !state.sent_role {
                            out.push(openai_chunk_role());
                            state.sent_role = true;
                        }
                        out.push(openai_chunk_reasoning(text));
                    }
                }
                Some("input_json_delta") => {
                    let cb_index = event
                        .get("index")
                        .and_then(Value::as_u64)
                        .unwrap_or(0);
                    let Some(&tool_index) = state
                        .block_to_tool
                        .get(&cb_index)
                    else {
                        // Orphan delta (no matching content_block_start); drop.
                        return out;
                    };
                    let fragment = delta
                        .and_then(|d| d.get("partial_json"))
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    if !fragment.is_empty() {
                        out.push(openai_chunk_tool_args(tool_index, fragment));
                    }
                }
                _ => {}
            }
        }
        "message_delta" => {
            let reason = event
                .get("delta")
                .and_then(|d| d.get("stop_reason"))
                .and_then(Value::as_str);
            if let Some(reason) = reason {
                out.push(openai_chunk_finish(map_anthropic_stop_reason(reason)));
            }
        }
        _ => {}
    }

    out
}

/// Replay a stored (complete) completion as an OpenAI SSE stream.
///
/// A cache hit is a whole response, but the caller asked for
/// `text/event-stream` and a well-behaved OpenAI client is parsing SSE frames.
/// Handing it a bare JSON object because we happened to answer from memory
/// makes the cache a breaking change for the client, which is why caching was
/// simply skipped for streaming requests before this existed.
///
/// So the response is re-framed rather than re-shaped: the same chunks a live
/// stream would emit, delivered at once. The client sees the contract it asked
/// for and cannot tell the difference except in the timing — which is the point.
///
/// `include_usage` mirrors the caller's `stream_options.include_usage`: the
/// final usage frame is only sent when they asked for one, since a client that
/// did not ask may not tolerate a chunk carrying no choices.
pub fn replay_completion_as_sse(
    completion: &Value,
    include_usage: bool,
) -> Body {
    let mut out = String::new();
    let mut push = |chunk: String| {
        out.push_str("data: ");
        out.push_str(&chunk);
        out.push_str("\n\n");
    };

    push(openai_chunk_role());

    let choice = completion
        .get("choices")
        .and_then(|c| c.get(0));
    let message = choice.and_then(|c| c.get("message"));

    if let Some(text) = message
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
        && !text.is_empty()
    {
        push(openai_chunk_content(text));
    }

    // Tool calls are replayed too. Dropping them would turn a cached
    // tool-calling turn into a silent empty answer — the one failure mode worse
    // than not caching at all.
    if let Some(calls) = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(Value::as_array)
    {
        for (index, call) in calls.iter().enumerate() {
            let id = call
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let function = call.get("function");
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            let arguments = function
                .and_then(|f| f.get("arguments"))
                .and_then(Value::as_str)
                .unwrap_or_default();
            push(openai_chunk_tool_start(index as u64, id, name));
            if !arguments.is_empty() {
                push(openai_chunk_tool_args(index as u64, arguments));
            }
        }
    }

    let finish_reason = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(Value::as_str)
        .unwrap_or("stop");
    push(openai_chunk_finish(finish_reason));

    if include_usage && let Some(usage) = completion.get("usage") {
        push(
            serde_json::json!({
                "object": "chat.completion.chunk",
                "choices": [],
                "usage": usage,
            })
            .to_string(),
        );
    }

    out.push_str("data: [DONE]\n\n");
    Body::from(out)
}

fn openai_chunk_role() -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{ "index": 0, "delta": { "role": "assistant" }, "finish_reason": null }],
    })
    .to_string()
}

fn openai_chunk_content(text: &str) -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{ "index": 0, "delta": { "content": text }, "finish_reason": null }],
    })
    .to_string()
}

fn openai_chunk_reasoning(text: &str) -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{ "index": 0, "delta": { "reasoning": text }, "finish_reason": null }],
    })
    .to_string()
}

fn openai_chunk_tool_start(
    index: u64,
    id: &str,
    name: &str,
) -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "index": index,
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": "" }
                }]
            },
            "finish_reason": null
        }],
    })
    .to_string()
}

fn openai_chunk_tool_args(
    index: u64,
    fragment: &str,
) -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{
            "index": 0,
            "delta": {
                "tool_calls": [{
                    "index": index,
                    "function": { "arguments": fragment }
                }]
            },
            "finish_reason": null
        }],
    })
    .to_string()
}

fn openai_chunk_finish(finish_reason: &str) -> String {
    serde_json::json!({
        "object": "chat.completion.chunk",
        "choices": [{ "index": 0, "delta": {}, "finish_reason": finish_reason }],
    })
    .to_string()
}

fn map_anthropic_stop_reason(reason: &str) -> &'static str {
    match reason {
        "tool_use" => "tool_calls",
        "max_tokens" => "length",
        _ => "stop",
    }
}

fn anthropic_input_tokens(event: &Value) -> Option<u64> {
    if event
        .get("type")
        .and_then(Value::as_str)
        == Some("message_start")
    {
        event
            .get("message")
            .and_then(|m| m.get("usage"))
            .and_then(|u| u.get("input_tokens"))
            .and_then(Value::as_u64)
    } else {
        None
    }
}

fn anthropic_output_tokens(event: &Value) -> Option<u64> {
    event
        .get("usage")
        .and_then(|u| u.get("output_tokens"))
        .and_then(Value::as_u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn file_and_batch_reads_are_proxied() {
        for suffix in [
            "/v1/files",
            "/v1/files?purpose=batch",
            "/v1/files/file-abc",
            "/v1/files/file-abc/content",
            "/v1/batches",
            "/v1/batches/batch_abc",
        ] {
            assert!(is_proxyable_get_path(suffix), "{suffix}");
        }
        assert!(!is_proxyable_get_path("/v1/models"));
        assert!(!is_proxyable_get_path("/health?next=/v1/files"), "a query is not the path");
    }

    #[test]
    fn a_read_that_would_resolve_off_the_file_and_batch_endpoints_is_not_proxied() {
        for suffix in [
            "/v1/files/../../v1/organization/api_keys",
            "/v1/files/%2e%2e/%2E%2E/v1/organization/api_keys",
            "/v1/files/.%2e/admin",
            "/v1/batches/./x",
            "/v1/files\\..\\..\\admin",
            "/x/../v1/files",
            "/v1/files/..;/..;/v1/chat/completions",
            "/v1/files/file-abc;jsessionid=x",
            "/v1/files%2f..%2f..%2fv1%2fresponses",
            "/v1/files/%5c..%5cadmin",
            "/v1/files/%252e%252e/admin",
            "/v1/files/file%2Dabc",
            "/v1/files/.\t./.\t./v1/organization/api_keys",
            "/v1/files/.\n./admin",
            "/v1/batches/.\r./x",
        ] {
            assert!(!is_proxyable_get_path(suffix), "{suffix}");
        }
    }

    #[test]
    fn only_the_bare_vp_challenge_path_asks_for_a_challenge() {
        assert!(is_vp_challenge_path("/v1/vp-challenge"));
        assert!(is_vp_challenge_path("/v1/vp-challenge/"));
        for suffix in ["/v1/vp-challenge/x", "/x/v1/vp-challenge", "/v1/chat/completions", ""] {
            assert!(!is_vp_challenge_path(suffix), "{suffix}");
        }
    }

    fn content_of(chunk: &str) -> Option<String> {
        let v: Value = serde_json::from_str(chunk).ok()?;
        v["choices"][0]["delta"]["content"]
            .as_str()
            .map(str::to_string)
    }

    /// Collect a replayed body back into the `data:` frames a client would parse.
    async fn frames(body: Body) -> Vec<String> {
        let bytes = axum::body::to_bytes(body, usize::MAX)
            .await
            .expect("body");
        String::from_utf8_lossy(&bytes)
            .split("\n\n")
            .filter(|f| !f.trim().is_empty())
            .map(|f| {
                f.trim_start_matches("data: ")
                    .to_string()
            })
            .collect()
    }

    fn completion(content: &str) -> Value {
        json!({
            "choices": [{ "message": { "role": "assistant", "content": content }, "finish_reason": "stop" }],
            "usage": { "prompt_tokens": 11, "completion_tokens": 22, "total_tokens": 33 },
        })
    }

    /// The SSE text of `events` (one `data:` line each), ending in `[DONE]`.
    fn sse_of(events: &[Value]) -> String {
        let mut sse = String::new();
        for event in events {
            sse.push_str(&format!("data: {event}\n\n"));
        }
        sse.push_str("data: [DONE]\n\n");
        sse
    }

    /// An upstream response streaming `sse` in `chunk`-byte pieces, then
    /// hanging forever when `hang` (an upstream that never ends).
    fn upstream_of(
        sse: &str,
        chunk: usize,
        hang: bool,
    ) -> reqwest::Response {
        let pieces: Vec<Result<Bytes, std::io::Error>> = sse
            .as_bytes()
            .chunks(chunk)
            .map(|piece| Ok(Bytes::copy_from_slice(piece)))
            .collect();
        let stream = futures::stream::iter(pieces);
        let body = if hang {
            reqwest::Body::wrap_stream(stream.chain(futures::stream::pending()))
        } else {
            reqwest::Body::wrap_stream(stream)
        };
        reqwest::Response::from(axum::http::Response::new(body))
    }

    /// Run the `schema` reader over `upstream`, with `drain` bounds; the
    /// client reads the whole stream, or (`client_leaves`) drops it before
    /// the first byte. Returns the outcome and what the client received.
    async fn run_stream(
        upstream: reqwest::Response,
        schema: &str,
        drain: Option<DrainOptions>,
        client_leaves: bool,
    ) -> (StreamOutcome, String) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let body = spawn_openai_sse_body(
            upstream,
            schema.to_string(),
            false,
            Default::default(),
            |_| {},
            move |outcome| {
                let _ = tx.send(outcome);
            },
            drain,
        );
        let received = if client_leaves {
            drop(body);
            String::new()
        } else {
            let bytes = axum::body::to_bytes(body, usize::MAX)
                .await
                .expect("body");
            String::from_utf8_lossy(&bytes).into_owned()
        };
        let outcome = tokio::time::timeout(std::time::Duration::from_secs(10), rx)
            .await
            .expect("the stream completes within its bounds")
            .expect("the stream reports its outcome");
        (outcome, received)
    }

    /// Proxy `events` as an OpenAI-schema upstream in `chunk`-byte pieces to a
    /// client that reads it all.
    async fn proxied(
        events: &[Value],
        chunk: usize,
    ) -> StreamOutcome {
        run_stream(upstream_of(&sse_of(events), chunk, false), "openai", None, false)
            .await
            .0
    }

    fn anthropic_events(text: &str) -> Vec<Value> {
        vec![
            json!({ "type": "message_start", "message": { "id": "msg_1", "model": "claude", "usage": {
                "input_tokens": 30, "output_tokens": 1,
                "cache_creation_input_tokens": 1000, "cache_read_input_tokens": 400,
                "cache_creation": { "ephemeral_5m_input_tokens": 400, "ephemeral_1h_input_tokens": 600 }
            } } }),
            json!({ "type": "content_block_start", "index": 0, "content_block": { "type": "text", "text": "" } }),
            json!({ "type": "content_block_delta", "index": 0, "delta": { "type": "text_delta", "text": text } }),
            json!({ "type": "content_block_stop", "index": 0 }),
            json!({ "type": "message_delta", "delta": { "stop_reason": "end_turn" }, "usage": { "output_tokens": 120 } }),
            json!({ "type": "message_stop" }),
        ]
    }

    #[tokio::test]
    async fn a_stream_reads_its_usage_from_chat_responses_and_anthropic_events() {
        // Every shape, split one byte at a time so no event arrives whole.
        let chat = proxied(
            &[
                json!({ "choices": [{ "delta": { "content": "Hello" } }] }),
                json!({ "choices": [], "usage": { "prompt_tokens": 12, "completion_tokens": 3 } }),
            ],
            1,
        )
        .await;
        assert!(chat.usage_reported);
        assert_eq!((chat.input_tokens, chat.output_tokens), (12, 3));

        let responses = proxied(
            &[
                json!({ "type": "response.output_text.delta", "delta": "Hello" }),
                json!({ "type": "response.completed", "response": { "usage": { "input_tokens": 20, "output_tokens": 5 } } }),
            ],
            7,
        )
        .await;
        assert!(responses.usage_reported, "a streamed Responses call reports its usage in response.completed");
        assert_eq!((responses.input_tokens, responses.output_tokens), (20, 5));
        assert_eq!(responses.output_estimate, 2, "five ASCII characters");

        let anthropic = proxied(&anthropic_events("Hi there"), 5).await;
        assert!(anthropic.usage_reported, "Anthropic events through an OpenAI-compatible upstream");
        assert_eq!((anthropic.input_tokens, anthropic.output_tokens), (30, 120));
        assert_eq!(
            anthropic.cache,
            crate::pipes::types::llm::CacheTokens {
                write: 1000,
                write_1h: 600,
                read: 400
            }
        );
        assert_eq!(anthropic.output_estimate, 2);

        let gemini = proxied(
            &[
                json!({ "candidates": [{ "content": { "parts": [{ "text": "Hi" }] } }], "usageMetadata": { "promptTokenCount": 9 } }),
                json!({ "candidates": [{ "content": { "parts": [{ "text": "!" }] }, "finishReason": "STOP" }],
                        "usageMetadata": { "promptTokenCount": 9, "candidatesTokenCount": 4, "thoughtsTokenCount": 30 } }),
            ],
            4,
        )
        .await;
        assert!(gemini.usage_reported, "a Gemini chunk with a finish reason carries the final usage");
        assert_eq!((gemini.input_tokens, gemini.output_tokens), (9, 34));
    }

    #[tokio::test]
    async fn only_a_final_event_reports_usage() {
        // Anthropic's `message_start` alone is partial.
        let mut events = anthropic_events("Hi");
        events.truncate(3);
        let partial = proxied(&events, 64).await;
        assert!(!partial.usage_reported, "message_start's output count is not the final one");
        assert_eq!((partial.input_tokens, partial.output_tokens), (30, 1));

        // A provider that repeats a running count on every chunk: final once
        // the stream ends.
        let running = proxied(
            &[
                json!({ "choices": [{ "delta": { "content": "a" } }], "usage": { "prompt_tokens": 5, "completion_tokens": 1 } }),
                json!({ "choices": [{ "delta": { "content": "b" } }], "usage": { "prompt_tokens": 5, "completion_tokens": 2 } }),
            ],
            64,
        )
        .await;
        assert!(running.usage_reported);
        assert_eq!(running.output_tokens, 2);
    }

    #[tokio::test]
    async fn a_dropped_anthropic_stream_bills_its_final_usage() {
        let sse = sse_of(&anthropic_events(&"x".repeat(400)));
        // Read on after the client leaves: the provider's final count.
        let (drained, _) =
            run_stream(upstream_of(&sse, 16, false), "anthropic", Some(DrainBounds::default().into()), true).await;
        assert!(!drained.completed, "the client left");
        assert!(drained.usage_reported, "message_delta was read after the client left");
        assert_eq!((drained.input_tokens, drained.output_tokens), (30, 120));
        assert_eq!(drained.cache.write_1h, 600);

        // Without reading on (an owned key), only the partial usage is seen.
        let (stopped, _) = run_stream(upstream_of(&sse, 16, false), "anthropic", None, true).await;
        assert!(!stopped.usage_reported);
    }

    #[tokio::test]
    async fn a_dropped_openai_stream_bills_its_final_usage_chunk() {
        let mut events: Vec<Value> = (0..50)
            .map(|_| json!({ "choices": [{ "delta": { "content": "token " } }] }))
            .collect();
        events.push(json!({ "choices": [], "usage": { "prompt_tokens": 50, "completion_tokens": 80 } }));
        let sse = sse_of(&events);
        let (drained, received) =
            run_stream(upstream_of(&sse, 32, false), "openai", Some(DrainBounds::default().into()), true).await;
        assert!(received.is_empty() && !drained.completed, "precondition: the client left at once");
        assert!(drained.usage_reported);
        assert_eq!((drained.input_tokens, drained.output_tokens), (50, 80));

        let (stopped, _) = run_stream(upstream_of(&sse, 32, false), "openai", None, true).await;
        assert!(!stopped.usage_reported, "without reading on, the usage chunk is never seen");
    }

    #[tokio::test]
    async fn reading_on_stops_at_its_time_and_byte_bounds() {
        let content = sse_of(&[json!({ "choices": [{ "delta": { "content": "partial answer" } }] })]);
        let content = content.trim_end_matches("data: [DONE]\n\n");
        // An upstream that never ends: the time bound stops the read.
        let short = DrainBounds {
            max_time: std::time::Duration::from_millis(50),
            max_bytes: DRAIN_MAX_BYTES,
        };
        let (timed_out, _) = run_stream(upstream_of(content, 8, true), "openai", Some(short.into()), true).await;
        assert!(!timed_out.usage_reported);
        assert!(timed_out.output_estimate > 0, "what was read still counts toward the estimate");

        // A long upstream with no usage: the byte bound stops the read early.
        let long: Vec<Value> = (0..400)
            .map(|_| json!({ "choices": [{ "delta": { "content": "y".repeat(100) } }] }))
            .collect();
        let few = DrainBounds {
            max_time: std::time::Duration::from_secs(DRAIN_MAX_SECS),
            max_bytes: 4 * 1024,
        };
        let (cut, _) = run_stream(upstream_of(&sse_of(&long), 512, true), "openai", Some(few.into()), true).await;
        assert!(!cut.usage_reported);
        assert!(cut.output_estimate < 400 * 25, "the read stopped at the byte bound: {}", cut.output_estimate);
    }

    #[tokio::test]
    async fn an_anthropic_stream_keeps_a_character_split_across_chunks() {
        let text = "日本語のテキスト 🎉";
        let (outcome, received) =
            run_stream(upstream_of(&sse_of(&anthropic_events(text)), 1, false), "anthropic", None, false).await;
        assert!(outcome.usage_reported, "message_delta survives chunks that split characters");
        assert_eq!(outcome.output_tokens, 120);
        let streamed: String = received
            .lines()
            .filter_map(|line| line.strip_prefix("data: "))
            .filter_map(content_of)
            .collect();
        assert_eq!(streamed, text);
    }

    #[tokio::test]
    async fn a_platform_stream_without_final_usage_is_billed_an_estimate() {
        use crate::pipes::key_source::KeySource;
        let silent = proxied(
            &[
                json!({ "choices": [{ "delta": { "content": "x".repeat(40) } }] }),
                json!({ "choices": [{ "delta": { "tool_calls": [{ "function": { "arguments": "{\"a\":1}" } }] } }] }),
            ],
            3,
        )
        .await;
        assert!(!silent.usage_reported, "precondition: no usage chunk");
        assert_eq!(silent.output_estimate, 13, "46 ASCII characters and a digit");
        let plain = StreamEstimate {
            input_tokens: 100,
            reasoning: ReasoningEstimate::None,
            output_cap: None,
        };
        assert_eq!(silent.billed_tokens(KeySource::Platform, &plain), (100, 13, true));
        assert_eq!(silent.billed_tokens(KeySource::Customer, &plain), (0, 0, false), "an owned key bills nothing");
        assert_eq!(silent.billed_tokens(KeySource::Client, &plain), (0, 0, false));
        let reasoning = StreamEstimate {
            input_tokens: 100,
            reasoning: ReasoningEstimate::Cap(5_000),
            output_cap: Some(5_000),
        };
        assert_eq!(silent.billed_tokens(KeySource::Platform, &reasoning), (100, 5_000, true));

        // Partial usage over a smaller estimate: the larger of each.
        let mut events = anthropic_events("Hi");
        events.truncate(3);
        let partial = proxied(&events, 64).await;
        assert_eq!(partial.billed_tokens(KeySource::Platform, &plain), (100, 1, true));
        let small = StreamEstimate {
            input_tokens: 10,
            reasoning: ReasoningEstimate::None,
            output_cap: None,
        };
        assert_eq!(partial.billed_tokens(KeySource::Platform, &small), (30, 1, true));

        let reported =
            proxied(&[json!({ "choices": [], "usage": { "prompt_tokens": 7, "completion_tokens": 2 } })], 64).await;
        assert_eq!(reported.billed_tokens(KeySource::Platform, &plain), (7, 2, false));
    }

    #[test]
    fn a_streams_cache_tokens_are_priced_beside_its_input() {
        let price = crate::pipes::types::llm::TargetPricing {
            input_per_million: 3.0,
            output_per_million: 15.0,
        };
        let cache = crate::pipes::types::llm::CacheTokens {
            write: 1_000_000,
            write_1h: 0,
            read: 1_000_000,
        };
        assert!((cache_cost_for_tokens(Some(&price), true, "anthropic", "house-model", cache) - 4.05).abs() < 1e-9);
        assert_eq!(cache_cost_for_tokens(Some(&price), true, "anthropic", "house-model", Default::default()), 0.0);
    }

    #[test]
    fn the_estimate_counts_the_whole_request_and_never_undercounts_other_scripts_more_than_twice() {
        // ASCII at four characters a token; other scripts at two UTF-8 bytes.
        assert_eq!(estimate_text_tokens(&"x".repeat(40)), 10);
        assert_eq!(estimate_text_tokens("日本語"), 5, "nine bytes");
        assert_eq!(estimate_text_tokens("🎉"), 2);

        // Tools, response formats and Responses instructions count.
        let chat = json!({ "messages": [{ "role": "user", "content": "x".repeat(40) }] });
        let base = estimate_request_tokens(&chat);
        assert!(base >= 14, "at least the old per-message estimate: {base}");
        let mut with_tools = chat.clone();
        with_tools["tools"] = json!([{ "type": "function", "function": {
            "name": "lookup", "description": "d".repeat(400), "parameters": { "type": "object" }
        } }]);
        with_tools["response_format"] =
            json!({ "type": "json_schema", "json_schema": { "schema": { "description": "s".repeat(200) } } });
        assert!(estimate_request_tokens(&with_tools) >= base + 150);
        let responses = json!({ "instructions": "i".repeat(400), "input": "hello" });
        assert!(estimate_request_tokens(&responses) >= 100);

        // An image counts as an image, not as its base64 text.
        let image = format!("data:image/png;base64,{}", "A".repeat(100_000));
        assert_eq!(estimate_request_tokens(&json!(image)), INLINE_MEDIA_TOKENS);
        let anthropic_image = json!({ "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "A".repeat(100_000) } });
        assert_eq!(estimate_request_tokens(&anthropic_image), INLINE_MEDIA_TOKENS);
        let gemini_image = json!({ "inline_data": { "mime_type": "image/png", "data": "A".repeat(100_000) } });
        assert!(estimate_request_tokens(&gemini_image) < 2 * INLINE_MEDIA_TOKENS);
        // A long run of letters is text, however base64-like it looks.
        assert_eq!(estimate_request_tokens(&json!("x".repeat(400_000))), 100_000);
    }

    #[test]
    fn a_reasoning_models_estimate_adds_its_reasoning() {
        let capped = json!({ "messages": [], "max_completion_tokens": 5_000 });
        let open = json!({ "messages": [] });
        assert_eq!(StreamEstimate::of_request(&capped, true).reasoning, ReasoningEstimate::Cap(5_000));
        assert_eq!(
            StreamEstimate::of_request(&open, true).reasoning,
            ReasoningEstimate::Allowance(REASONING_ALLOWANCE_TOKENS)
        );
        assert_eq!(StreamEstimate::of_request(&capped, false).reasoning, ReasoningEstimate::None);
        let estimate = StreamEstimate::of_request(&open, true);
        assert_eq!(estimate.output_tokens(100, false), 100 + REASONING_ALLOWANCE_TOKENS);
        assert_eq!(StreamEstimate::of_request(&capped, true).output_tokens(100, false), 5_000);
        assert_eq!(StreamEstimate::of_request(&capped, true).output_tokens(9_000, false), 9_000);
    }

    #[test]
    fn a_stream_a_drain_cut_takes_the_reasoning_floor_whatever_the_model() {
        let capped = json!({ "messages": [], "max_tokens": 5_000 });
        let open = json!({ "messages": [] });
        // A model the catalog and the id test call plain.
        let plain_open = StreamEstimate::of_request(&open, false);
        let plain_capped = StreamEstimate::of_request(&capped, false);
        assert_eq!(plain_open.output_tokens(100, false), 100, "precondition: no floor when not cut");
        assert_eq!(plain_open.output_tokens(100, true), 100 + REASONING_ALLOWANCE_TOKENS);
        assert_eq!(plain_capped.output_tokens(100, true), 5_000);
        assert_eq!(plain_capped.output_tokens(9_000, true), 9_000);
    }

    #[tokio::test]
    async fn a_drain_cut_by_its_bound_is_billed_the_floor() {
        use crate::pipes::key_source::KeySource;
        let content = sse_of(&[json!({ "choices": [{ "delta": { "content": "partial answer" } }] })]);
        let content = content.trim_end_matches("data: [DONE]\n\n");
        let short = DrainBounds {
            max_time: std::time::Duration::from_millis(50),
            max_bytes: DRAIN_MAX_BYTES,
        };
        let (cut, _) = run_stream(upstream_of(content, 8, true), "openai", Some(short.into()), true).await;
        assert!(cut.drain_cut && !cut.usage_reported, "precondition: the time bound cut the drain");
        let estimate = StreamEstimate::of_request(&json!({ "model": "grok-4", "messages": [] }), false);
        let (_, output, estimated) = cut.billed_tokens(KeySource::Platform, &estimate);
        assert!(estimated);
        assert_eq!(output, cut.output_estimate + REASONING_ALLOWANCE_TOKENS);

        // A drain that read the final usage was not cut.
        let mut events: Vec<Value> = vec![json!({ "choices": [{ "delta": { "content": "token" } }] })];
        events.push(json!({ "choices": [], "usage": { "prompt_tokens": 5, "completion_tokens": 8 } }));
        let (drained, _) =
            run_stream(upstream_of(&sse_of(&events), 16, false), "openai", Some(DrainBounds::default().into()), true)
                .await;
        assert!(drained.usage_reported && !drained.drain_cut);
    }

    #[test]
    fn drains_are_capped_per_member_and_per_surface() {
        let member = format!("member-{}", uuid::Uuid::new_v4());
        let surface = format!("surface-{}", uuid::Uuid::new_v4());
        let options = |member: &str| DrainOptions {
            max_per_member: 2,
            max_per_surface: 3,
            ..DrainOptions::new(Some(member.to_string()), Some(surface.clone()))
        };
        let first = DrainPermit::acquire(&options(&member)).expect("a first drain");
        let _second = DrainPermit::acquire(&options(&member)).expect("a second drain");
        assert!(DrainPermit::acquire(&options(&member)).is_none(), "the member's cap is full");
        let other = format!("member-{}", uuid::Uuid::new_v4());
        let _third = DrainPermit::acquire(&options(&other)).expect("another member on the surface");
        assert!(DrainPermit::acquire(&options(&other)).is_none(), "the surface's cap is full");
        drop(first);
        assert!(DrainPermit::acquire(&options(&member)).is_some(), "a finished drain frees its place");
        assert_eq!((DRAIN_MAX_PER_MEMBER, DRAIN_MAX_PER_SURFACE), (16, 256));
    }

    #[tokio::test]
    async fn a_drain_past_its_cap_stops_at_once_and_is_billed_the_floor() {
        use crate::pipes::key_source::KeySource;
        let member = format!("member-{}", uuid::Uuid::new_v4());
        let options = DrainOptions {
            max_per_member: 1,
            ..DrainOptions::new(Some(member), None)
        };
        let mut events: Vec<Value> = (0..20)
            .map(|_| json!({ "choices": [{ "delta": { "content": "token " } }] }))
            .collect();
        events.push(json!({ "choices": [], "usage": { "prompt_tokens": 50, "completion_tokens": 80 } }));
        let sse = sse_of(&events);

        let held = DrainPermit::acquire(&options).expect("a drain already running");
        let (refused, _) = run_stream(upstream_of(&sse, 32, false), "openai", Some(options.clone()), true).await;
        assert!(!refused.usage_reported, "the stream stopped when its client left");
        assert!(refused.drain_cut);
        let estimate = StreamEstimate::of_request(&json!({ "messages": [] }), false);
        let (_, output, _) = refused.billed_tokens(KeySource::Platform, &estimate);
        assert!(output >= REASONING_ALLOWANCE_TOKENS, "billed the floor: {output}");

        drop(held);
        let (drained, _) = run_stream(upstream_of(&sse, 32, false), "openai", Some(options), true).await;
        assert!(drained.usage_reported, "with a place free the stream reads on to its usage");
        assert_eq!((drained.input_tokens, drained.output_tokens), (50, 80));
    }

    #[tokio::test]
    async fn a_final_responses_event_longer_than_a_network_chunk_reports_its_usage() {
        // `response.completed` echoes the whole response: here 200 KB of
        // instructions, arriving in 16 KiB pieces.
        let completed = json!({ "type": "response.completed", "response": {
            "instructions": "i".repeat(200_000),
            "usage": { "input_tokens": 50_000, "output_tokens": 300 }
        } });
        let outcome =
            proxied(&[json!({ "type": "response.output_text.delta", "delta": "hi" }), completed], 16 * 1024).await;
        assert!(outcome.usage_reported, "the final event was read whole");
        assert_eq!((outcome.input_tokens, outcome.output_tokens), (50_000, 300));
    }

    #[test]
    fn digits_are_counted_one_token_each() {
        assert_eq!(estimate_text_tokens(&"7".repeat(400)), 400);
        assert_eq!(estimate_text_tokens("ab12"), 3, "two digits, then two letters as one token");
        assert_eq!(estimate_request_tokens(&json!([1234567, 7.5])), 7 + 3);
        let csv = (0..1_000)
            .map(|n| format!("{},{}\n", n * 1_000, n))
            .collect::<String>();
        assert!(
            estimate_request_tokens(&json!(csv)) > csv.len() as u64 / 2,
            "numeric text is not estimated at chars/4"
        );
    }

    #[test]
    fn a_line_too_long_to_hold_counts_as_output() {
        let mut meter = StreamMeter::default();
        meter.feed(&vec![b'a'; MAX_PENDING_BYTES + 10]);
        meter.feed(b"bbbb\ndata: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n");
        assert_eq!(meter.output_estimate(), ((MAX_PENDING_BYTES + 14) as u64).div_ceil(2) + 1);
        assert_eq!(meter.usage(), (0, 0));
        assert!(!meter.reported(true));
    }

    /// A replayed hit is a well-formed OpenAI stream, terminator included.
    ///
    /// The client asked for SSE and is parsing frames; a cache hit must be
    /// indistinguishable from a live stream except in timing. A missing
    /// `[DONE]` in particular leaves well-behaved clients waiting forever.
    #[tokio::test]
    async fn a_replayed_hit_is_a_well_formed_stream() {
        let out = frames(replay_completion_as_sse(&completion("hello there"), false)).await;
        assert_eq!(out.last().map(String::as_str), Some("[DONE]"), "got {out:?}");

        let parsed: Vec<Value> = out[..out.len() - 1]
            .iter()
            .map(|f| serde_json::from_str(f).expect("each frame is JSON"))
            .collect();
        assert!(
            parsed
                .iter()
                .all(|c| c["object"] == "chat.completion.chunk"),
            "got {parsed:?}"
        );
        // The content survives the round trip intact.
        let text: String = parsed
            .iter()
            .filter_map(|c| c["choices"][0]["delta"]["content"].as_str())
            .collect();
        assert_eq!(text, "hello there");
        // And it finishes, or a client keeps the turn open.
        assert!(
            parsed
                .iter()
                .any(|c| c["choices"][0]["finish_reason"] == "stop"),
            "got {parsed:?}"
        );
    }

    /// Usage is sent only when the caller asked for it.
    ///
    /// A usage frame carries no choices, and a client that never requested one
    /// is within its rights to choke on it.
    #[tokio::test]
    async fn usage_is_replayed_only_when_requested() {
        let without = frames(replay_completion_as_sse(&completion("x"), false)).await;
        assert!(
            !without
                .iter()
                .any(|f| f.contains("total_tokens")),
            "got {without:?}"
        );

        let with = frames(replay_completion_as_sse(&completion("x"), true)).await;
        let usage = with
            .iter()
            .find(|f| f.contains("total_tokens"))
            .expect("a usage frame");
        let parsed: Value = serde_json::from_str(usage).expect("json");
        assert_eq!(parsed["usage"]["total_tokens"], 33);
    }

    /// A cached tool-calling turn replays its tool calls.
    ///
    /// Replaying only the content would turn it into an empty answer — the
    /// caller would see a turn that finished having asked for nothing, which is
    /// worse than not caching at all because it looks like the model's reply.
    #[tokio::test]
    async fn a_cached_tool_call_is_not_silently_dropped() {
        let stored = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "get_weather", "arguments": "{\"city\":\"Oslo\"}" }
                    }]
                },
                "finish_reason": "tool_calls"
            }]
        });
        let out = frames(replay_completion_as_sse(&stored, false)).await;
        let joined = out.join(" ");
        assert!(joined.contains("get_weather"), "got {out:?}");
        assert!(joined.contains("Oslo"), "arguments must survive: {out:?}");
        assert!(joined.contains("tool_calls"), "and the finish reason: {out:?}");
    }

    /// An empty or odd completion still terminates the stream.
    #[tokio::test]
    async fn a_degenerate_completion_still_terminates() {
        let out = frames(replay_completion_as_sse(&json!({}), true)).await;
        assert_eq!(out.last().map(String::as_str), Some("[DONE]"), "got {out:?}");
    }

    /// "The answer arrived whole" is not "the client stayed to hear it".
    ///
    /// This is the distinction that made caching intermittent: a client that
    /// disconnects the instant it reads `[DONE]` has everything, but marks the
    /// stream aborted, and a store gated on delivery then fires only when it
    /// wins the race. The accumulator records completeness from the frames
    /// themselves, which no disconnect can affect.
    #[test]
    fn the_accumulator_knows_the_answer_was_whole() {
        let mut acc = CompletionAccumulator::new(true);
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hel\"}}]}\n\n");
        assert!(!acc.saw_finish(), "mid-stream, nothing has finished yet");
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"lo\"}}]}\n\n");
        assert!(!acc.saw_finish());

        acc.feed("data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n");
        assert!(acc.saw_finish(), "a finish_reason ends the answer");
        assert_eq!(acc.finish().as_deref(), Some("hello"));
    }

    /// The `[DONE]` sentinel counts too — some upstreams end on it alone.
    #[test]
    fn the_done_sentinel_also_marks_the_answer_whole() {
        let mut acc = CompletionAccumulator::new(true);
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"hi\"}}]}\n\n");
        assert!(!acc.saw_finish());
        acc.feed("data: [DONE]\n\n");
        assert!(acc.saw_finish());
    }

    /// A stream cut off mid-answer must not read as complete, or a truncated
    /// reply gets cached and served to everyone for the whole TTL.
    #[test]
    fn a_truncated_stream_is_not_complete() {
        let mut acc = CompletionAccumulator::new(true);
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"the answer is\"}}]}\n\n");
        // Upstream died here: no finish_reason, no [DONE].
        assert!(!acc.saw_finish());
        assert_eq!(acc.finish().as_deref(), Some("the answer is"));
    }

    /// A null `finish_reason` on every intermediate chunk must not count.
    #[test]
    fn a_null_finish_reason_is_not_a_finish() {
        let mut acc = CompletionAccumulator::new(true);
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"x\"},\"finish_reason\":null}]}\n\n");
        assert!(!acc.saw_finish(), "null means not finished");
    }

    #[test]
    fn client_requested_stream_reads_flag() {
        assert!(client_requested_stream(&json!({ "stream": true })));
        assert!(!client_requested_stream(&json!({ "stream": false })));
        assert!(!client_requested_stream(&json!({})));
    }

    fn minimal_openai_llm() -> PipeConfig {
        PipeConfig::new(
            "p".to_string(),
            "p".to_string(),
            crate::pipes::config::PipeType::LLM {
                provider: Box::new(crate::pipes::types::llm::LLMProvider::OpenAI {
                    provider_type: "openai".to_string(),
                    model: "gpt-4o-mini".to_string(),
                    api_key_secret: Some("sk".to_string()),
                    organization_id: None,
                    base_url: None,
                    temperature: None,
                    max_tokens: None,
                    top_p: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                }),
                endpoint_path: None,
            },
        )
    }

    #[test]
    fn passthrough_eligible_for_plain_openai_surface() {
        assert!(passthrough_eligible(&minimal_openai_llm()));
    }

    #[test]
    fn passthrough_disabled_when_server_tools_active() {
        let mut config = minimal_openai_llm();
        config.server_tools = Some(crate::pipes::server_tools::ServerToolsConfig {
            enabled: true,
            max_iterations: 3,
            web_search: None,
            web_fetch: Some(crate::pipes::server_tools::WebFetchConfig {
                enabled: true,
                ..Default::default()
            }),
        });
        assert!(!passthrough_eligible(&config), "an active server-tools surface must take the buffered agentic path");
    }

    #[test]
    fn passthrough_still_eligible_when_server_tools_present_but_inactive() {
        let mut config = minimal_openai_llm();
        config.server_tools = Some(crate::pipes::server_tools::ServerToolsConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(passthrough_eligible(&config));
    }

    #[test]
    fn passthrough_still_eligible_with_a_request_side_judge() {
        let mut config = minimal_openai_llm();
        config.judge = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "llm": {
                    "provider_type": "openai",
                    "model": "gpt-4o-mini",
                    "endpoint_url": "https://api.openai.com/v1/chat/completions"
                }
            }))
            .expect("judge config"),
        );
        assert!(
            passthrough_eligible(&config),
            "a Judge gates the prompt pre-stream (in execute_streaming) and must not force buffering"
        );
    }

    #[test]
    fn passthrough_disabled_with_a_response_side_jury() {
        let mut config = minimal_openai_llm();
        config.jury = Some(serde_json::from_value(serde_json::json!({ "enabled": true })).expect("jury config"));
        assert!(!passthrough_eligible(&config), "a Jury reviews the response and must force the buffered path");
    }

    #[test]
    fn passthrough_still_eligible_with_a_route_decider() {
        let mut config = minimal_openai_llm();
        config.decider = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "strategy": "route",
                "llm": {
                    "provider_type": "openai",
                    "model": "gpt-4o-mini",
                    "endpoint_url": "https://api.openai.com/v1/chat/completions"
                },
                "candidates": [{
                    "id": "c1",
                    "name": "Fast",
                    "llm": {
                        "provider_type": "openai",
                        "model": "gpt-4o",
                        "endpoint_url": "https://api.openai.com/v1/chat/completions"
                    }
                }]
            }))
            .expect("route decider config"),
        );
        assert!(
            passthrough_eligible(&config),
            "a Route decider picks one candidate pre-stream and must not force buffering"
        );
    }

    fn with_route_candidate(
        provider_type: &str,
        model: &str,
    ) -> PipeConfig {
        let mut config = minimal_openai_llm();
        config.decider = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "strategy": "route",
                "llm": {
                    "provider_type": "openai",
                    "model": "gpt-4o-mini",
                    "endpoint_url": "https://api.openai.com/v1/chat/completions"
                },
                "candidates": [
                    {
                        "id": "fast",
                        "name": "Fast",
                        "llm": {
                            "provider_type": "openai",
                            "model": "gpt-4o",
                            "endpoint_url": "https://api.openai.com/v1/chat/completions"
                        }
                    },
                    {
                        "id": "other",
                        "name": "Other",
                        "llm": { "provider_type": provider_type, "model": model, "endpoint_url": "" }
                    }
                ]
            }))
            .expect("route decider config"),
        );
        config
    }

    #[test]
    fn passthrough_eligible_when_every_route_candidate_streams() {
        assert!(passthrough_eligible(&with_route_candidate("anthropic", "claude-haiku-4-5")));
    }

    #[test]
    fn passthrough_disabled_when_a_route_candidate_cannot_stream() {
        for (provider_type, model) in
            [("bedrock", "anthropic.claude-3-5-haiku-20241022-v1:0"), ("gemini", "gemini-2.5-flash")]
        {
            assert!(
                !passthrough_eligible(&with_route_candidate(provider_type, model)),
                "a {provider_type} candidate has no streamed wire the gateway translates, so routing must buffer"
            );
        }
    }

    #[test]
    fn passthrough_disabled_with_a_mirror_decider() {
        let mut config = minimal_openai_llm();
        config.decider = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "strategy": "mirror",
                "candidates": [{
                    "id": "c1",
                    "name": "A",
                    "llm": {
                        "provider_type": "openai",
                        "model": "gpt-4o",
                        "endpoint_url": "https://api.openai.com/v1/chat/completions"
                    }
                }],
                "mirror": { "mode": "merge" }
            }))
            .expect("mirror decider config"),
        );
        assert!(!passthrough_eligible(&config), "a Mirror decider fans out + merges and must force the buffered path");
    }

    #[test]
    fn completion_accumulator_reassembles_split_deltas() {
        let mut acc = CompletionAccumulator::new(true);
        // Role chunk (no content) then a content delta split across two feeds,
        // a second delta, and the [DONE] sentinel — all forwarded SSE lines.
        acc.feed("data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\n");
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"Hel");
        acc.feed("lo\"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\" world\"}}]}\n\n");
        acc.feed("data: [DONE]\n\n");
        assert_eq!(acc.finish(), Some("Hello world".to_string()));
    }

    #[test]
    fn completion_accumulator_disabled_is_noop() {
        let mut acc = CompletionAccumulator::new(false);
        acc.feed("data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\n\n");
        assert_eq!(acc.finish(), None);
    }

    #[test]
    fn audio_multipart_paths_recognized() {
        assert!(is_audio_multipart_path("/s/v1/audio/transcriptions"));
        assert!(is_audio_multipart_path("/s/v1/audio/translations"));
        assert!(is_audio_multipart_path("/s/v1/audio/transcriptions?x=1"));
        assert!(is_audio_multipart_path("/s/v1/audio/transcriptions/"));
        // Text-to-speech is a binary response, not a multipart upload.
        assert!(!is_audio_multipart_path("/s/v1/audio/speech"));
        assert!(!is_audio_multipart_path("/s/v1/chat/completions"));
        assert!(!is_audio_multipart_path("/s/v1/files"));
        // The speech endpoint stays a binary endpoint; transcription does not.
        assert!(is_binary_endpoint(Some("/s/v1/audio/speech")));
        assert!(!is_binary_endpoint(Some("/s/v1/audio/transcriptions")));
    }

    #[test]
    fn realtime_paths_recognized() {
        assert!(is_realtime_path("/s/v1/realtime"));
        assert!(is_realtime_path("/s/v1/realtime/"));
        assert!(is_realtime_path("/s/v1/realtime?model=gpt-realtime"));
        assert!(!is_realtime_path("/s/v1/chat/completions"));
        assert!(!is_realtime_path("/s/v1/audio/transcriptions"));
    }

    #[test]
    fn text_delta_emits_role_then_content() {
        let mut state = StreamState::default();
        let event = json!({
            "type": "content_block_delta",
            "delta": { "type": "text_delta", "text": "Hello" },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert_eq!(chunks.len(), 2);
        assert!(state.sent_role);

        let role: Value = serde_json::from_str(&chunks[0]).unwrap();
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(content_of(&chunks[1]).as_deref(), Some("Hello"));
    }

    #[test]
    fn thinking_delta_emits_reasoning_chunk() {
        let mut state = StreamState::default();
        let event = json!({
            "type": "content_block_delta",
            "delta": { "type": "thinking_delta", "thinking": "pondering" },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert_eq!(chunks.len(), 2, "role chunk then reasoning chunk");
        let reasoning: Value = serde_json::from_str(&chunks[1]).unwrap();
        assert_eq!(reasoning["choices"][0]["delta"]["reasoning"], "pondering");
    }

    #[test]
    fn second_text_delta_omits_role() {
        let mut state = StreamState {
            sent_role: true,
            ..Default::default()
        };
        let event = json!({
            "type": "content_block_delta",
            "delta": { "type": "text_delta", "text": " world" },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert_eq!(chunks.len(), 1);
        assert_eq!(content_of(&chunks[0]).as_deref(), Some(" world"));
    }

    #[test]
    fn orphan_input_json_delta_emits_nothing() {
        let mut state = StreamState::default();
        let event = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "input_json_delta", "partial_json": "{}" },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert!(chunks.is_empty());
        assert!(!state.sent_role);
    }

    #[test]
    fn message_delta_emits_finish_reason() {
        let mut state = StreamState {
            sent_role: true,
            ..Default::default()
        };
        let event = json!({
            "type": "message_delta",
            "delta": { "stop_reason": "end_turn" },
            "usage": { "output_tokens": 42 },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert_eq!(chunks.len(), 1);
        let v: Value = serde_json::from_str(&chunks[0]).unwrap();
        assert_eq!(v["choices"][0]["finish_reason"], "stop");
    }

    #[test]
    fn tool_use_start_emits_role_then_tool_announcement() {
        let mut state = StreamState::default();
        let event = json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": {
                "type": "tool_use",
                "id": "toolu_01ABC",
                "name": "get_weather",
                "input": {}
            },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        assert_eq!(chunks.len(), 2, "role chunk + tool-start chunk");
        assert!(state.sent_role);
        assert_eq!(state.next_tool_index, 1);
        assert_eq!(state.block_to_tool.get(&0), Some(&0));

        let role: Value = serde_json::from_str(&chunks[0]).unwrap();
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");

        let tool: Value = serde_json::from_str(&chunks[1]).unwrap();
        let tc = &tool["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["id"], "toolu_01ABC");
        assert_eq!(tc["type"], "function");
        assert_eq!(tc["function"]["name"], "get_weather");
        assert_eq!(tc["function"]["arguments"], "");
    }

    #[test]
    fn input_json_delta_after_start_emits_arguments_fragment() {
        let mut state = StreamState::default();
        let start = json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": { "type": "tool_use", "id": "toolu_x", "name": "run" },
        });
        anthropic_event_to_openai_chunks(&start, &mut state);

        let delta = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": { "type": "input_json_delta", "partial_json": "{\"cmd\":" },
        });
        let chunks = anthropic_event_to_openai_chunks(&delta, &mut state);
        assert_eq!(chunks.len(), 1);
        let v: Value = serde_json::from_str(&chunks[0]).unwrap();
        let tc = &v["choices"][0]["delta"]["tool_calls"][0];
        assert_eq!(tc["index"], 0);
        assert_eq!(tc["function"]["arguments"], "{\"cmd\":");
        // Arguments-only chunk must not repeat id/name.
        assert!(tc.get("id").is_none());
        assert!(tc.get("type").is_none());
        assert!(
            tc["function"]
                .get("name")
                .is_none()
        );
    }

    #[test]
    fn multiple_tool_use_blocks_get_sequential_indices() {
        let mut state = StreamState::default();
        // Text block occupies content_block index 0.
        let text_start = json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": { "type": "text", "text": "" },
        });
        anthropic_event_to_openai_chunks(&text_start, &mut state);
        assert_eq!(state.next_tool_index, 0);

        // First tool_use at content_block index 1 → tool_calls[].index = 0.
        let tool1 = json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": { "type": "tool_use", "id": "t1", "name": "a" },
        });
        let chunks1 = anthropic_event_to_openai_chunks(&tool1, &mut state);
        let announce1: Value = serde_json::from_str(chunks1.last().unwrap()).unwrap();
        assert_eq!(announce1["choices"][0]["delta"]["tool_calls"][0]["index"], 0);

        // Second tool_use at content_block index 2 → tool_calls[].index = 1.
        let tool2 = json!({
            "type": "content_block_start",
            "index": 2,
            "content_block": { "type": "tool_use", "id": "t2", "name": "b" },
        });
        let chunks2 = anthropic_event_to_openai_chunks(&tool2, &mut state);
        let announce2: Value = serde_json::from_str(chunks2.last().unwrap()).unwrap();
        assert_eq!(announce2["choices"][0]["delta"]["tool_calls"][0]["index"], 1);

        assert_eq!(state.block_to_tool.get(&1), Some(&0));
        assert_eq!(state.block_to_tool.get(&2), Some(&1));

        // Arguments delta on block 2 routes to tool_calls[].index = 1.
        let arg = json!({
            "type": "content_block_delta",
            "index": 2,
            "delta": { "type": "input_json_delta", "partial_json": "{}" },
        });
        let chunks3 = anthropic_event_to_openai_chunks(&arg, &mut state);
        let v: Value = serde_json::from_str(&chunks3[0]).unwrap();
        assert_eq!(v["choices"][0]["delta"]["tool_calls"][0]["index"], 1);
    }

    #[test]
    fn tool_use_stop_reason_maps_to_tool_calls_finish() {
        let mut state = StreamState {
            sent_role: true,
            ..Default::default()
        };
        let event = json!({
            "type": "message_delta",
            "delta": { "stop_reason": "tool_use" },
            "usage": { "output_tokens": 5 },
        });
        let chunks = anthropic_event_to_openai_chunks(&event, &mut state);
        let v: Value = serde_json::from_str(&chunks[0]).unwrap();
        assert_eq!(v["choices"][0]["finish_reason"], "tool_calls");
    }

    #[test]
    fn stop_reason_mapping() {
        assert_eq!(map_anthropic_stop_reason("tool_use"), "tool_calls");
        assert_eq!(map_anthropic_stop_reason("max_tokens"), "length");
        assert_eq!(map_anthropic_stop_reason("end_turn"), "stop");
        assert_eq!(map_anthropic_stop_reason("stop_sequence"), "stop");
    }

    #[test]
    fn input_tokens_only_from_message_start() {
        let start = json!({
            "type": "message_start",
            "message": { "usage": { "input_tokens": 17 } },
        });
        assert_eq!(anthropic_input_tokens(&start), Some(17));

        let other = json!({ "type": "message_delta", "usage": { "input_tokens": 5 } });
        assert_eq!(anthropic_input_tokens(&other), None);
    }

    #[test]
    fn output_tokens_from_usage_block() {
        let event = json!({
            "type": "message_delta",
            "usage": { "output_tokens": 99 },
        });
        assert_eq!(anthropic_output_tokens(&event), Some(99));

        let no_usage = json!({ "type": "content_block_stop" });
        assert_eq!(anthropic_output_tokens(&no_usage), None);
    }

    // ── Microsoft 365 Copilot streaming translation ──

    #[test]
    fn copilot_delta_emits_only_new_suffix() {
        assert_eq!(copilot_delta("", "Hello").as_deref(), Some("Hello"));
        assert_eq!(copilot_delta("Hello", "Hello world").as_deref(), Some(" world"));
        // No growth → no delta (heartbeat / repeated snapshot).
        assert_eq!(copilot_delta("Hello", "Hello"), None);
        // Non-prefix rewrite (e.g. an echoed user prompt) → no delta.
        assert_eq!(copilot_delta("Hello world", "What is my meeting?"), None);
    }

    #[test]
    fn copilot_stream_text_reads_last_message() {
        // Final snapshot: [user echo, assistant answer] → assistant is last.
        let event = json!({
            "messages": [
                { "text": "Summarize my doc" },
                { "text": "Here is the summary." }
            ]
        });
        assert_eq!(copilot_stream_text(&event).as_deref(), Some("Here is the summary."));

        // Heartbeat with no messages → None.
        assert_eq!(copilot_stream_text(&json!({ "messages": [] })), None);
        assert_eq!(copilot_stream_text(&json!({})), None);
    }

    #[test]
    fn copilot_parses_pretty_printed_data_block() {
        // Only the first line carries `data:`; continuation lines are raw JSON;
        // an `id:` SSE metadata line must be ignored.
        let block = "data: {\n  \"state\": \"active\",\n  \"messages\": [\n    { \"text\": \"Partial answer\" }\n  ]\n}\nid:137";
        let event = parse_copilot_sse_block(block).expect("parses pretty block");
        assert_eq!(event["state"], "active");
        assert_eq!(copilot_stream_text(&event).as_deref(), Some("Partial answer"));
    }

    #[test]
    fn copilot_parses_compact_single_line_block() {
        let block = "data: {\"messages\":[{\"text\":\"Compact\"}]}";
        let event = parse_copilot_sse_block(block).expect("parses compact block");
        assert_eq!(copilot_stream_text(&event).as_deref(), Some("Compact"));
    }

    #[test]
    fn copilot_block_translation_progressively_streams_deltas() {
        let mut emitted = String::new();
        let mut sent_role = false;

        // First content snapshot emits a role chunk then the full text so far.
        let block1 = "data: {\"messages\":[{\"text\":\"Hello\"}]}";
        let chunks1 = copilot_block_to_openai_chunks(block1, &mut emitted, &mut sent_role);
        assert_eq!(chunks1.len(), 2);
        let role: Value = serde_json::from_str(&chunks1[0]).unwrap();
        assert_eq!(role["choices"][0]["delta"]["role"], "assistant");
        assert_eq!(content_of(&chunks1[1]).as_deref(), Some("Hello"));
        assert!(sent_role);
        assert_eq!(emitted, "Hello");

        // Next snapshot grows the text → only the new suffix, no repeated role.
        let block2 = "data: {\"messages\":[{\"text\":\"Hello world\"}]}";
        let chunks2 = copilot_block_to_openai_chunks(block2, &mut emitted, &mut sent_role);
        assert_eq!(chunks2.len(), 1);
        assert_eq!(content_of(&chunks2[0]).as_deref(), Some(" world"));
        assert_eq!(emitted, "Hello world");

        // A heartbeat with no new text emits nothing.
        let heartbeat = "data: {\"messages\":[]}\nid:9";
        let chunks3 = copilot_block_to_openai_chunks(heartbeat, &mut emitted, &mut sent_role);
        assert!(chunks3.is_empty());
        assert_eq!(emitted, "Hello world");
    }

    #[test]
    fn next_event_boundary_handles_lf_and_crlf() {
        // LF boundary.
        let lf = "data: a\n\ndata: b";
        assert_eq!(next_event_boundary(lf), Some((7, 9)));
        assert_eq!(&lf[..7], "data: a");

        // CRLF boundary (Microsoft Graph) — must not be missed.
        let crlf = "data: a\r\n\r\ndata: b";
        let (end, drain) = next_event_boundary(crlf).expect("crlf boundary found");
        assert_eq!(&crlf[..end], "data: a");
        assert_eq!(&crlf[drain..], "data: b");

        // No complete boundary yet.
        assert_eq!(next_event_boundary("data: partial"), None);
    }

    #[test]
    fn copilot_crlf_stream_extracts_content() {
        // A CRLF-delimited Copilot snapshot (as Microsoft Graph sends) must
        // still yield content — regression guard for the empty-response bug.
        let mut pending = String::from("data: {\"messages\":[{\"text\":\"Answer so far\"}]}\r\n\r\n");
        let mut emitted = String::new();
        let mut sent_role = false;
        let mut got = String::new();

        while let Some((end, drain)) = next_event_boundary(&pending) {
            let block = pending[..end].to_string();
            pending.drain(..drain);
            for chunk in copilot_block_to_openai_chunks(&block, &mut emitted, &mut sent_role) {
                if let Some(c) = content_of(&chunk) {
                    got.push_str(&c);
                }
            }
        }
        assert_eq!(got, "Answer so far");
        assert!(sent_role);
    }
}
