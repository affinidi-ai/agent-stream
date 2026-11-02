//! Context-window guard and `middle-out` message compression (P6).
//!
//! Before the upstream call, estimate the prompt token count against the
//! surface's configured context window. When over budget, apply the requested
//! `transforms` — today just `middle-out`, which drops messages from the middle
//! of the conversation (preserving the system prompt and the most recent turns)
//! until the prompt fits, matching OpenRouter's semantics. The transform is a
//! pure structural operation on the OpenAI-canonical body, so it is dialect- and
//! provider-agnostic. Off by default; opt in per request (`transforms`) or per
//! surface (`context_management.enabled`).
//!
//! See `docs/INFERENCE_CONTROLS.md`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const MIDDLE_OUT: &str = "middle-out";

fn default_keep_recent() -> usize {
    4
}
fn default_reserve_output() -> u64 {
    1024
}

/// Per-surface context-management configuration (off by default).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextManagementConfig {
    /// Auto-apply `middle-out` when a request would exceed the window, even if
    /// the caller did not ask for it. A request's explicit `transforms` field
    /// always overrides this (`[]` disables for that request).
    #[serde(default)]
    pub enabled: bool,
    /// The upstream model's context window in tokens. Operator-provided (the
    /// gateway has no universal per-model catalog); the compression budget is
    /// this minus the reserved output headroom. Without it, compression is a
    /// no-op even when requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_window_tokens: Option<u64>,
    /// Always preserve the last N messages (the most recent turns).
    #[serde(default = "default_keep_recent")]
    pub keep_recent_messages: usize,
    /// Tokens reserved for the completion when the request does not name a
    /// `max_tokens` (so the prompt budget leaves room for the reply).
    #[serde(default = "default_reserve_output")]
    pub reserve_output_tokens: u64,
}

impl Default for ContextManagementConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            context_window_tokens: None,
            keep_recent_messages: default_keep_recent(),
            reserve_output_tokens: default_reserve_output(),
        }
    }
}

/// The result of a context transform, for the response header and governance.
#[derive(Debug, Clone, PartialEq)]
pub struct ContextTransformOutcome {
    pub strategy: &'static str,
    pub messages_elided: usize,
    pub tokens_before: u64,
    pub tokens_after: u64,
}

impl ContextTransformOutcome {
    pub fn applied(&self) -> bool {
        self.messages_elided > 0
    }
    /// `x-agent-stream-context-transform` header value.
    pub fn header_value(&self) -> String {
        format!(
            "{}; before={}; after={}; elided={}",
            self.strategy, self.tokens_before, self.tokens_after, self.messages_elided
        )
    }
    /// Human-readable governance-stage detail.
    pub fn governance_detail(&self) -> String {
        format!(
            "{} · elided {} message(s) · {}→{} tok",
            self.strategy, self.messages_elided, self.tokens_before, self.tokens_after
        )
    }
}

/// Parse the request `transforms` extension field into a list of strategy
/// names. `Some([])` (explicit empty) disables the surface default; `None`
/// (absent) defers to the surface config.
pub fn parse_transforms(body: &Value) -> Option<Vec<String>> {
    let arr = body
        .get("transforms")?
        .as_array()?;
    Some(
        arr.iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect(),
    )
}

/// Remove the `transforms` extension field so it never reaches the upstream.
pub fn strip_transforms_field(body: &mut Value) {
    if let Some(obj) = body.as_object_mut() {
        obj.remove("transforms");
    }
}

/// The caller's requested completion budget (`max_tokens` /
/// `max_completion_tokens` / `max_output_tokens`), when present.
pub fn requested_output_tokens(body: &Value) -> Option<u64> {
    for key in ["max_tokens", "max_completion_tokens", "max_output_tokens"] {
        if let Some(n) = body
            .get(key)
            .and_then(|v| v.as_u64())
        {
            return Some(n);
        }
    }
    None
}

/// Approximate the token count of one chat message (role overhead + content).
/// A deliberately simple char/4 heuristic — no tokenizer dependency; used only
/// to decide what to drop, not for billing.
pub fn estimate_message_tokens(message: &Value) -> u64 {
    const PER_MESSAGE_OVERHEAD: u64 = 4;
    let content_chars = match message.get("content") {
        Some(Value::String(s)) => s.chars().count(),
        Some(Value::Array(parts)) => parts
            .iter()
            .map(|p| {
                p.get("text")
                    .and_then(|t| t.as_str())
                    .map(|s| s.chars().count())
                    .unwrap_or(0)
            })
            .sum(),
        _ => 0,
    };
    // Tool call arguments also cost tokens.
    let tool_chars = message
        .get("tool_calls")
        .and_then(|t| t.as_array())
        .map(|calls| {
            calls
                .iter()
                .map(|c| {
                    c.pointer("/function/arguments")
                        .and_then(|a| a.as_str())
                        .map(|s| s.chars().count())
                        .unwrap_or(0)
                })
                .sum::<usize>()
        })
        .unwrap_or(0);
    PER_MESSAGE_OVERHEAD + ((content_chars + tool_chars) as u64).div_ceil(4)
}

/// Approximate the prompt token count of a message list.
pub fn estimate_prompt_tokens(messages: &[Value]) -> u64 {
    messages
        .iter()
        .map(estimate_message_tokens)
        .sum()
}

fn is_system(message: &Value) -> bool {
    matches!(
        message
            .get("role")
            .and_then(|r| r.as_str()),
        Some("system") | Some("developer")
    )
}

/// Drop messages from the middle of the conversation until the prompt fits
/// `budget`, preserving every system/developer message and the last
/// `keep_recent` messages. Messages closest to the centre are removed first
/// (expanding outward) — OpenRouter's `middle-out`.
pub fn middle_out(
    messages: &[Value],
    budget: u64,
    keep_recent: usize,
) -> (Vec<Value>, ContextTransformOutcome) {
    let before = estimate_prompt_tokens(messages);
    let mut outcome = ContextTransformOutcome {
        strategy: MIDDLE_OUT,
        messages_elided: 0,
        tokens_before: before,
        tokens_after: before,
    };
    if before <= budget {
        return (messages.to_vec(), outcome);
    }

    let n = messages.len();
    let tail_start = n.saturating_sub(keep_recent.max(1));
    let protected = |i: usize| is_system(&messages[i]) || i >= tail_start;

    let center = (n as f64 - 1.0) / 2.0;
    let mut droppable: Vec<usize> = (0..n)
        .filter(|&i| !protected(i))
        .collect();
    droppable.sort_by(|&a, &b| {
        let da = (a as f64 - center).abs();
        let db = (b as f64 - center).abs();
        da.partial_cmp(&db)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    let mut removed = vec![false; n];
    let mut after = before;
    for i in droppable {
        if after <= budget {
            break;
        }
        after = after.saturating_sub(estimate_message_tokens(&messages[i]));
        removed[i] = true;
        outcome.messages_elided += 1;
    }
    outcome.tokens_after = after;

    let kept: Vec<Value> = (0..n)
        .filter(|&i| !removed[i])
        .map(|i| messages[i].clone())
        .collect();
    (kept, outcome)
}

/// Apply context management to a request body: decide whether to run (request
/// `transforms` overrides the surface default), strip the `transforms` field,
/// and — when over the configured window — compress the messages in place.
/// Returns the outcome only when messages were actually elided.
pub fn apply(
    config: Option<&ContextManagementConfig>,
    body: &mut Value,
) -> Option<ContextTransformOutcome> {
    let requested = parse_transforms(body);
    let should = match &requested {
        Some(list) => list
            .iter()
            .any(|t| t == MIDDLE_OUT),
        None => config.is_some_and(|c| c.enabled),
    };
    strip_transforms_field(body);
    if !should {
        return None;
    }
    let cfg = config?;
    let window = cfg.context_window_tokens?;
    let reserve = requested_output_tokens(body).unwrap_or(cfg.reserve_output_tokens);
    let budget = window
        .saturating_sub(reserve)
        .max(1);
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())?;
    let (kept, outcome) = middle_out(messages, budget, cfg.keep_recent_messages);
    if !outcome.applied() {
        return None;
    }
    if let Some(obj) = body.as_object_mut() {
        obj.insert("messages".to_string(), Value::Array(kept));
    }
    Some(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(
        role: &str,
        content: &str,
    ) -> Value {
        json!({ "role": role, "content": content })
    }

    #[test]
    fn parse_transforms_reads_list_and_empty() {
        assert_eq!(parse_transforms(&json!({ "transforms": ["middle-out"] })), Some(vec!["middle-out".to_string()]));
        assert_eq!(parse_transforms(&json!({ "transforms": [] })), Some(vec![]));
        assert_eq!(parse_transforms(&json!({})), None);
    }

    #[test]
    fn strip_removes_field() {
        let mut body = json!({ "transforms": ["middle-out"], "messages": [] });
        strip_transforms_field(&mut body);
        assert!(
            body.get("transforms")
                .is_none()
        );
    }

    #[test]
    fn requested_output_tokens_prefers_known_keys() {
        assert_eq!(requested_output_tokens(&json!({ "max_tokens": 100 })), Some(100));
        assert_eq!(requested_output_tokens(&json!({ "max_completion_tokens": 200 })), Some(200));
        assert_eq!(requested_output_tokens(&json!({ "max_output_tokens": 300 })), Some(300));
        assert_eq!(requested_output_tokens(&json!({})), None);
    }

    #[test]
    fn estimate_counts_content_and_overhead() {
        // 8 chars / 4 = 2, + 4 overhead = 6
        assert_eq!(estimate_message_tokens(&msg("user", "abcdefgh")), 6);
        // content parts
        let parts = json!({ "role": "user", "content": [{ "type": "text", "text": "abcd" }] });
        assert_eq!(estimate_message_tokens(&parts), 4 + 1);
    }

    #[test]
    fn middle_out_noop_when_under_budget() {
        let messages = vec![msg("system", "sys"), msg("user", "hi")];
        let (kept, outcome) = middle_out(&messages, 1000, 4);
        assert!(!outcome.applied());
        assert_eq!(kept.len(), 2);
    }

    #[test]
    fn middle_out_drops_middle_preserving_system_and_recent() {
        // system + 8 turns, each ~large. Budget forces dropping the middle.
        let mut messages = vec![msg("system", &"s".repeat(400))];
        for i in 0..8 {
            messages.push(msg(
                if i % 2 == 0 {
                    "user"
                } else {
                    "assistant"
                },
                &format!("turn {}", i).repeat(50),
            ));
        }
        let before = estimate_prompt_tokens(&messages);
        let (kept, outcome) = middle_out(&messages, before / 2, 2);
        assert!(outcome.applied());
        // system is preserved
        assert!(
            kept.iter()
                .any(|m| m["role"] == "system")
        );
        // the last two messages are preserved
        let last = &messages[messages.len() - 1];
        assert!(kept.iter().any(|m| m == last));
        // fewer messages than before
        assert!(kept.len() < messages.len());
        assert!(outcome.tokens_after <= before);
    }

    #[test]
    fn middle_out_never_drops_system_even_when_tiny_budget() {
        let messages = vec![
            msg("system", &"s".repeat(4000)),
            msg("user", &"u".repeat(4000)),
            msg("assistant", &"a".repeat(4000)),
            msg("user", &"q".repeat(4000)),
        ];
        let (kept, _o) = middle_out(&messages, 10, 1);
        assert!(
            kept.iter()
                .any(|m| m["role"] == "system")
        );
        // the most recent (last) message is always kept
        assert!(
            kept.iter()
                .any(|m| m == &messages[3])
        );
    }

    #[test]
    fn apply_noop_without_opt_in() {
        let cfg = ContextManagementConfig {
            enabled: false,
            context_window_tokens: Some(100),
            ..Default::default()
        };
        let mut body = json!({ "messages": [msg("user", &"x".repeat(4000))] });
        assert!(apply(Some(&cfg), &mut body).is_none());
    }

    #[test]
    fn apply_request_opt_in_compresses_over_window() {
        let cfg = ContextManagementConfig {
            enabled: false,
            context_window_tokens: Some(50),
            keep_recent_messages: 1,
            reserve_output_tokens: 8,
        };
        let mut body = json!({
            "transforms": ["middle-out"],
            "max_tokens": 8,
            "messages": [
                msg("system", "keep me"),
                msg("user", &"a".repeat(400)),
                msg("assistant", &"b".repeat(400)),
                msg("user", "recent question"),
            ],
        });
        let outcome = apply(Some(&cfg), &mut body).expect("should compress");
        assert!(outcome.applied());
        assert!(
            body.get("transforms")
                .is_none(),
            "transforms field stripped"
        );
        let msgs = body["messages"]
            .as_array()
            .unwrap();
        assert!(
            msgs.iter()
                .any(|m| m["role"] == "system")
        );
        assert!(
            msgs.iter()
                .any(|m| m["content"] == "recent question")
        );
        assert!(msgs.len() < 4);
    }

    #[test]
    fn apply_empty_transforms_disables_surface_default() {
        let cfg = ContextManagementConfig {
            enabled: true,
            context_window_tokens: Some(10),
            keep_recent_messages: 1,
            reserve_output_tokens: 1,
        };
        let mut body = json!({ "transforms": [], "messages": [msg("user", &"x".repeat(4000))] });
        assert!(apply(Some(&cfg), &mut body).is_none(), "explicit empty transforms opts out");
    }

    #[test]
    fn apply_surface_auto_compresses() {
        let cfg = ContextManagementConfig {
            enabled: true,
            context_window_tokens: Some(50),
            keep_recent_messages: 1,
            reserve_output_tokens: 8,
        };
        let mut body = json!({
            "messages": [
                msg("system", "sys"),
                msg("user", &"a".repeat(400)),
                msg("assistant", &"b".repeat(400)),
                msg("user", "recent"),
            ],
        });
        let outcome = apply(Some(&cfg), &mut body).expect("auto compresses");
        assert!(outcome.applied());
    }

    #[test]
    fn apply_noop_without_configured_window() {
        let cfg = ContextManagementConfig {
            enabled: true,
            context_window_tokens: None,
            ..Default::default()
        };
        let mut body = json!({ "transforms": ["middle-out"], "messages": [msg("user", &"x".repeat(4000))] });
        assert!(apply(Some(&cfg), &mut body).is_none());
        assert!(
            body.get("transforms")
                .is_none(),
            "field still stripped"
        );
    }

    #[test]
    fn header_value_shape() {
        let o = ContextTransformOutcome {
            strategy: MIDDLE_OUT,
            messages_elided: 3,
            tokens_before: 12000,
            tokens_after: 7800,
        };
        assert_eq!(o.header_value(), "middle-out; before=12000; after=7800; elided=3");
    }
}
