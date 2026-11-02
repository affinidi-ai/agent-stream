//! Per-request live stage stream.
//!
//! The executor already emits every pipeline stage as a `[PIPE:id] [STAGE:name]
//! {json}` log event. This layer captures those events for a *single* in-flight
//! request — identified by a `stream_key` field on the request's span — and
//! forwards the parsed `{ stage, payload }` to a receiver the chat handler drains
//! into an SSE. The correlation is the caller's own request span, so a stream
//! only ever sees its own request's stages (no cross-request/tenant surface),
//! and it is authorised by the surface's own inbound credential on that request.

use std::sync::OnceLock;

use dashmap::DashMap;
use serde_json::{Value, json};
use tokio::sync::mpsc::{Receiver, Sender, channel};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Bounded so a stalled/slow SSE consumer can't grow the channel without limit;
/// a full channel drops the stage event rather than blocking the tracing layer.
const STAGE_STREAM_CAPACITY: usize = 256;

fn registry() -> &'static DashMap<String, Sender<Value>> {
    static REGISTRY: OnceLock<DashMap<String, Sender<Value>>> = OnceLock::new();
    REGISTRY.get_or_init(DashMap::new)
}

/// RAII handle for a registered stream: dropping it (including during a panic
/// unwind) removes the registry entry, so a request task that panics before
/// reaching its normal cleanup point can never leak the entry or its channel.
pub struct StageStreamGuard(String);

impl Drop for StageStreamGuard {
    fn drop(&mut self) {
        registry().remove(&self.0);
    }
}

/// Register a live stage stream for `stream_key`. Returns the receiver of parsed
/// `{ stage, payload }` events emitted within the matching request span, and a
/// guard that unregisters the stream on drop.
pub fn register(stream_key: &str) -> (Receiver<Value>, StageStreamGuard) {
    let (tx, rx) = channel(STAGE_STREAM_CAPACITY);
    registry().insert(stream_key.to_string(), tx);
    (rx, StageStreamGuard(stream_key.to_string()))
}

fn emit(
    stream_key: &str,
    value: Value,
) {
    if let Some(tx) = registry().get(stream_key) {
        let _ = tx.try_send(value);
    }
}

/// Span extension carrying the request's stream key.
struct StreamKey(String);

struct KeyVisitor(Option<String>);
impl Visit for KeyVisitor {
    fn record_str(
        &mut self,
        field: &Field,
        value: &str,
    ) {
        if field.name() == "stream_key" {
            self.0 = Some(value.to_string());
        }
    }
    fn record_debug(
        &mut self,
        field: &Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "stream_key" && self.0.is_none() {
            self.0 = Some(
                format!("{value:?}")
                    .trim_matches('"')
                    .to_string(),
            );
        }
    }
}

struct MessageVisitor(Option<String>);
impl Visit for MessageVisitor {
    fn record_str(
        &mut self,
        field: &Field,
        value: &str,
    ) {
        if field.name() == "message" {
            self.0 = Some(value.to_string());
        }
    }
    fn record_debug(
        &mut self,
        field: &Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" && self.0.is_none() {
            self.0 = Some(format!("{value:?}"));
        }
    }
}

/// Parse a `[PIPE:x] [STAGE:name] {json}` log message into `{ stage, payload }`.
pub fn parse_stage(message: &str) -> Option<Value> {
    let idx = message.find("[STAGE:")?;
    let rest = &message[idx + "[STAGE:".len()..];
    let end = rest.find(']')?;
    let stage = &rest[..end];
    let after = rest[end + 1..].trim();
    let payload: Value = serde_json::from_str(after).ok()?;
    Some(json!({ "stage": stage, "payload": payload }))
}

/// A tracing layer that forwards `[STAGE:…]` events to the live stream registered
/// for the request span they occur in.
pub struct StageStreamLayer;

impl StageStreamLayer {
    pub fn new() -> Self {
        Self
    }
}

impl Default for StageStreamLayer {
    fn default() -> Self {
        Self::new()
    }
}

impl<S> Layer<S> for StageStreamLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut visitor = KeyVisitor(None);
        attrs.record(&mut visitor);
        if let Some(key) = visitor.0
            && let Some(span) = ctx.span(id)
        {
            span.extensions_mut()
                .insert(StreamKey(key));
        }
    }

    fn on_event(
        &self,
        event: &Event<'_>,
        ctx: Context<'_, S>,
    ) {
        // Fast path: nothing is streaming.
        if registry().is_empty() {
            return;
        }
        // The stream key lives on the request span (an ancestor of this event).
        let mut key: Option<String> = None;
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope {
                if let Some(sk) = span
                    .extensions()
                    .get::<StreamKey>()
                {
                    key = Some(sk.0.clone());
                    break;
                }
            }
        }
        let Some(key) = key else {
            return;
        };
        let mut visitor = MessageVisitor(None);
        event.record(&mut visitor);
        if let Some(message) = visitor.0
            && let Some(stage) = parse_stage(&message)
        {
            emit(&key, stage);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_stage_log_line() {
        let msg = "[PIPE:my-pipe] [STAGE:judge] {\"outcome\":\"rejected\",\"reason\":\"no medical advice\"}";
        let v = parse_stage(msg).expect("parsed");
        assert_eq!(v["stage"], "judge");
        assert_eq!(v["payload"]["outcome"], "rejected");
        assert_eq!(v["payload"]["reason"], "no medical advice");
    }

    #[test]
    fn ignores_non_stage_lines() {
        assert!(parse_stage("[PIPE:x] some other log").is_none());
        assert!(parse_stage("[STAGE:judge] not json").is_none());
    }

    #[test]
    fn register_and_emit_delivers_only_to_that_key() {
        let (mut rx, guard1) = register("k1");
        let (_rx2, guard2) = register("k2");
        emit("k1", json!({ "stage": "judge", "payload": {} }));
        drop(guard1);
        drop(guard2);
        let got = rx.try_recv().expect("event");
        assert_eq!(got["stage"], "judge");
    }

    #[test]
    fn guard_drop_unregisters_even_on_panic_unwind() {
        let key = "k-panic";
        let result = std::panic::catch_unwind(|| {
            let (_rx, _guard) = register(key);
            panic!("simulated task panic after registration");
        });
        assert!(result.is_err());
        assert!(registry().get(key).is_none());
    }
}
