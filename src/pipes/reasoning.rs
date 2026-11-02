//! Unified reasoning / thinking normalization.
//!
//! Reasoning is expressed differently by every dialect and every provider:
//! OpenAI Chat uses a `reasoning_effort` scalar, the OpenAI Responses API and
//! OpenRouter use a `reasoning` object, Anthropic uses a `thinking` block with a
//! token budget, and Gemini uses `thinkingConfig`. This module defines the one
//! **canonical** representation the pipeline carries — an OpenAI-style
//! `reasoning` object (superset) plus the legacy `reasoning_effort` scalar — and
//! the mappings that normalise every inbound dialect **into** it and shape it
//! **out** to each upstream wire format.
//!
//! See `docs/INFERENCE_CONTROLS.md`.

use serde_json::{Map, Value};

/// Thinking-token budgets mapped from an OpenAI-style effort level, used when a
/// caller asks for reasoning by effort but the upstream wants an explicit token
/// budget (Anthropic `thinking.budget_tokens`, Gemini `thinkingBudget`).
pub const BUDGET_MINIMAL: u64 = 512;
pub const BUDGET_LOW: u64 = 1024;
pub const BUDGET_MEDIUM: u64 = 4096;
pub const BUDGET_HIGH: u64 = 16384;

/// Anthropic requires an extended-thinking budget of at least 1024 tokens.
pub const ANTHROPIC_MIN_BUDGET: u64 = 1024;

/// Map an effort level to a thinking-token budget.
pub fn effort_to_budget(effort: &str) -> u64 {
    match effort {
        "minimal" => BUDGET_MINIMAL,
        "low" => BUDGET_LOW,
        "high" => BUDGET_HIGH,
        _ => BUDGET_MEDIUM,
    }
}

/// Map a thinking-token budget back to the nearest effort level.
pub fn budget_to_effort(budget: u64) -> &'static str {
    if budget <= BUDGET_MINIMAL {
        "minimal"
    } else if budget <= BUDGET_LOW {
        "low"
    } else if budget <= BUDGET_MEDIUM {
        "medium"
    } else {
        "high"
    }
}

/// The reasoning controls resolved from a canonical body, independent of which
/// dialect or provider expressed them.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedReasoning {
    /// OpenAI-style effort level, when the caller expressed one.
    pub effort: Option<String>,
    /// Explicit thinking-token budget, when the caller expressed one.
    pub max_tokens: Option<u64>,
    /// Omit reasoning content from the response (still metered).
    pub exclude: bool,
    /// Whether reasoning is requested at all (Anthropic `thinking.type`).
    pub enabled: bool,
}

impl ResolvedReasoning {
    /// The effort level to send, defaulting through the budget or `"medium"`.
    pub fn effort_or_default(&self) -> String {
        if let Some(effort) = &self.effort {
            return effort.clone();
        }
        if let Some(budget) = self.max_tokens {
            return budget_to_effort(budget).to_string();
        }
        "medium".to_string()
    }

    /// The thinking-token budget to send. Resolved from an explicit budget, else
    /// derived from effort. When `ceiling` is given the budget is clamped
    /// strictly below it (Anthropic requires `budget_tokens < max_tokens`).
    pub fn budget(
        &self,
        ceiling: Option<u64>,
    ) -> u64 {
        let raw = self
            .max_tokens
            .unwrap_or_else(|| effort_to_budget(&self.effort_or_default()));
        match ceiling {
            Some(limit) if limit > 1 && raw >= limit => limit - 1,
            _ => raw,
        }
    }
}

/// Resolve the canonical `reasoning` object (and the legacy `reasoning_effort`
/// scalar) into a single [`ResolvedReasoning`], or `None` when the caller did
/// not request reasoning at all.
pub fn resolve(body: &Value) -> Option<ResolvedReasoning> {
    let reasoning_obj = body
        .get("reasoning")
        .and_then(|r| r.as_object());
    let scalar = body
        .get("reasoning_effort")
        .and_then(|e| e.as_str());

    if reasoning_obj.is_none() && scalar.is_none() {
        return None;
    }

    let enabled = reasoning_obj
        .and_then(|o| o.get("enabled"))
        .and_then(|v| v.as_bool())
        .unwrap_or(true);
    let exclude = reasoning_obj
        .and_then(|o| o.get("exclude"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let effort = reasoning_obj
        .and_then(|o| o.get("effort"))
        .and_then(|v| v.as_str())
        .or(scalar)
        .map(str::to_string);
    let max_tokens = reasoning_obj
        .and_then(|o| o.get("max_tokens"))
        .and_then(|v| v.as_u64());

    Some(ResolvedReasoning {
        effort,
        max_tokens,
        exclude,
        enabled,
    })
}

/// Build a canonical `reasoning` object from an Anthropic `thinking` block.
///
/// `{ type: "enabled", budget_tokens }` → `{ enabled: true, max_tokens }`;
/// `{ type: "disabled" }` → `{ enabled: false }`.
pub fn reasoning_from_anthropic_thinking(thinking: &Value) -> Option<Value> {
    let obj = thinking.as_object()?;
    let kind = obj
        .get("type")
        .and_then(|t| t.as_str())
        .unwrap_or("enabled");
    let mut out = Map::new();
    if kind == "disabled" {
        out.insert("enabled".to_string(), Value::Bool(false));
        return Some(Value::Object(out));
    }
    out.insert("enabled".to_string(), Value::Bool(true));
    if let Some(budget) = obj
        .get("budget_tokens")
        .and_then(|v| v.as_u64())
    {
        out.insert("max_tokens".to_string(), Value::from(budget));
    }
    Some(Value::Object(out))
}

/// Normalise an OpenAI Responses `reasoning` object (`effort` + display-only
/// `summary`) into the canonical `reasoning` object. `summary` is dropped.
pub fn reasoning_from_responses(reasoning: &Value) -> Option<Value> {
    let obj = reasoning.as_object()?;
    let mut out = Map::new();
    if let Some(effort) = obj
        .get("effort")
        .and_then(|v| v.as_str())
    {
        out.insert("effort".to_string(), Value::String(effort.to_string()));
    }
    if let Some(max) = obj
        .get("max_tokens")
        .and_then(|v| v.as_u64())
    {
        out.insert("max_tokens".to_string(), Value::from(max));
    }
    if out.is_empty() {
        return None;
    }
    Some(Value::Object(out))
}

/// Shape canonical reasoning for an **OpenAI Chat Completions** upstream, in
/// place.
///
/// Chat Completions accepts only the `reasoning_effort` scalar, and only on
/// reasoning-capable models. Translate the canonical `reasoning` object into the
/// scalar (never overwriting an explicit one), then remove the object. On a
/// non-reasoning model, strip reasoning entirely so the upstream does not 400.
pub fn shape_openai_body(
    body: &mut Value,
    reasoning_model: bool,
) {
    let resolved = resolve(body);
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    obj.remove("reasoning");
    if !reasoning_model {
        obj.remove("reasoning_effort");
        return;
    }
    let Some(resolved) = resolved else {
        return;
    };
    if !resolved.enabled {
        obj.remove("reasoning_effort");
        return;
    }
    obj.entry("reasoning_effort".to_string())
        .or_insert_with(|| Value::String(resolved.effort_or_default()));
}

/// Shape canonical reasoning for an **Anthropic Messages** upstream, in place.
///
/// Sets `thinking: { type: "enabled", budget_tokens }`, guarantees `max_tokens`
/// leaves headroom above the budget (Anthropic counts thinking against
/// `max_tokens`), drops the sampling params Anthropic rejects while thinking is
/// on, and removes the canonical reasoning fields. No-op when reasoning is
/// absent or explicitly disabled.
pub fn shape_anthropic_body(body: &mut Value) {
    let resolved = resolve(body);
    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let had_reasoning = obj
        .remove("reasoning")
        .is_some();
    let had_scalar = obj
        .remove("reasoning_effort")
        .is_some();
    if !had_reasoning && !had_scalar {
        return;
    }
    let Some(resolved) = resolved else {
        return;
    };
    if !resolved.enabled {
        return;
    }

    let ceiling = obj
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .or_else(|| {
            obj.get("max_completion_tokens")
                .and_then(|v| v.as_u64())
        });
    let mut budget = resolved.budget(ceiling);
    if budget < ANTHROPIC_MIN_BUDGET {
        budget = ANTHROPIC_MIN_BUDGET;
    }

    let current_max = obj
        .get("max_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    if current_max <= budget {
        obj.insert("max_tokens".to_string(), Value::from(budget + ANTHROPIC_MIN_BUDGET));
    }

    // With thinking on, Anthropic requires the default temperature and rejects
    // `top_p`, so drop both rather than send a rejected combination.
    obj.remove("temperature");
    obj.remove("top_p");
    obj.insert("thinking".to_string(), serde_json::json!({ "type": "enabled", "budget_tokens": budget }));
}

/// Build a Gemini `thinkingConfig` from canonical reasoning, or `None` when
/// reasoning is absent. A disabled request pins the budget to zero.
pub fn gemini_thinking_config(body: &Value) -> Option<Value> {
    let resolved = resolve(body)?;
    if !resolved.enabled {
        return Some(serde_json::json!({ "thinkingBudget": 0 }));
    }
    Some(serde_json::json!({
        "thinkingBudget": resolved.budget(None),
        "includeThoughts": !resolved.exclude,
    }))
}

/// Ordinal rank of an effort level, for bounding (`minimal < low < medium < high`).
fn effort_rank(effort: &str) -> u8 {
    match effort {
        "minimal" => 0,
        "low" => 1,
        "high" => 3,
        _ => 2,
    }
}

/// Clamp the requested reasoning budget to a per-surface ceiling (governor).
///
/// Sets `reasoning.max_tokens` to at most `cap` and lowers `reasoning.effort`
/// (and the legacy scalar) to the capped level, so budget-based upstreams
/// (Anthropic, Gemini) and effort-based upstreams (OpenAI) are both bounded. A
/// `cap` of `0` disables the governor. No-op when reasoning is absent, disabled,
/// or already within the ceiling.
pub fn apply_cap(
    body: &mut Value,
    cap: u64,
) {
    if cap == 0 {
        return;
    }
    let Some(resolved) = resolve(body) else {
        return;
    };
    if !resolved.enabled {
        return;
    }
    let requested = resolved
        .max_tokens
        .unwrap_or_else(|| effort_to_budget(&resolved.effort_or_default()));
    if requested <= cap {
        return;
    }

    let capped_effort = budget_to_effort(cap).to_string();
    let effort = match &resolved.effort {
        Some(e) if effort_rank(e) <= effort_rank(&capped_effort) => e.clone(),
        _ => capped_effort,
    };

    let Some(obj) = body.as_object_mut() else {
        return;
    };
    let had_scalar = obj.contains_key("reasoning_effort");
    let reasoning = obj
        .entry("reasoning".to_string())
        .or_insert_with(|| serde_json::json!({}));
    if let Some(r) = reasoning.as_object_mut() {
        r.insert("max_tokens".to_string(), Value::from(cap));
        r.insert("effort".to_string(), Value::String(effort.clone()));
    }
    if had_scalar {
        obj.insert("reasoning_effort".to_string(), Value::String(effort));
    }
}

/// Extract canonical `reasoning_details` from an Anthropic content array.
///
/// `thinking` blocks become `{ type: "reasoning.text", text, signature? }` and
/// `redacted_thinking` blocks become `{ type: "reasoning.encrypted", data }`.
/// The signature is preserved so a later Anthropic round-trip can re-attach it.
pub fn anthropic_thinking_to_details(content_array: &[Value]) -> Vec<Value> {
    content_array
        .iter()
        .filter_map(|block| {
            match block
                .get("type")
                .and_then(|t| t.as_str())
            {
                Some("thinking") => {
                    let text = block
                        .get("thinking")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let mut detail = serde_json::json!({ "type": "reasoning.text", "text": text });
                    if let Some(sig) = block
                        .get("signature")
                        .and_then(|s| s.as_str())
                    {
                        detail["signature"] = Value::String(sig.to_string());
                    }
                    Some(detail)
                }
                Some("redacted_thinking") => {
                    let data = block
                        .get("data")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    Some(serde_json::json!({ "type": "reasoning.encrypted", "data": data }))
                }
                _ => None,
            }
        })
        .collect()
}

/// Concatenate the visible reasoning text from canonical `reasoning_details`.
pub fn reasoning_text_from_details(details: &[Value]) -> String {
    details
        .iter()
        .filter(|d| {
            d.get("type")
                .and_then(|t| t.as_str())
                == Some("reasoning.text")
        })
        .filter_map(|d| {
            d.get("text")
                .and_then(|t| t.as_str())
        })
        .collect::<Vec<_>>()
        .join("")
}

/// Rebuild Anthropic content thinking blocks from canonical `reasoning_details`.
///
/// The inverse of [`anthropic_thinking_to_details`]: `reasoning.text` →
/// `{ type: "thinking", thinking, signature? }`, `reasoning.encrypted` →
/// `{ type: "redacted_thinking", data }`.
pub fn details_to_anthropic_thinking_blocks(details: &[Value]) -> Vec<Value> {
    details
        .iter()
        .filter_map(|detail| {
            match detail
                .get("type")
                .and_then(|t| t.as_str())
            {
                Some("reasoning.text") => {
                    let text = detail
                        .get("text")
                        .and_then(|t| t.as_str())
                        .unwrap_or("");
                    let mut block = serde_json::json!({ "type": "thinking", "thinking": text });
                    if let Some(sig) = detail
                        .get("signature")
                        .and_then(|s| s.as_str())
                    {
                        block["signature"] = Value::String(sig.to_string());
                    }
                    Some(block)
                }
                Some("reasoning.encrypted") => {
                    let data = detail
                        .get("data")
                        .and_then(|d| d.as_str())
                        .unwrap_or("");
                    Some(serde_json::json!({ "type": "redacted_thinking", "data": data }))
                }
                _ => None,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn resolve_none_when_absent() {
        assert!(resolve(&json!({ "messages": [] })).is_none());
    }

    #[test]
    fn resolve_from_scalar() {
        let r = resolve(&json!({ "reasoning_effort": "high" })).unwrap();
        assert_eq!(r.effort.as_deref(), Some("high"));
        assert!(r.enabled);
        assert!(!r.exclude);
    }

    #[test]
    fn resolve_object_wins_over_scalar() {
        let r = resolve(&json!({
            "reasoning_effort": "low",
            "reasoning": { "effort": "high", "exclude": true }
        }))
        .unwrap();
        assert_eq!(r.effort.as_deref(), Some("high"));
        assert!(r.exclude);
    }

    #[test]
    fn resolve_disabled() {
        let r = resolve(&json!({ "reasoning": { "enabled": false } })).unwrap();
        assert!(!r.enabled);
    }

    #[test]
    fn budget_from_effort_and_clamp() {
        let r = resolve(&json!({ "reasoning": { "effort": "high" } })).unwrap();
        assert_eq!(r.budget(None), BUDGET_HIGH);
        // Clamp strictly below the max_tokens ceiling.
        assert_eq!(r.budget(Some(1000)), 999);
    }

    #[test]
    fn budget_explicit_wins() {
        let r = resolve(&json!({ "reasoning": { "max_tokens": 8000 } })).unwrap();
        assert_eq!(r.budget(None), 8000);
        assert_eq!(r.effort_or_default(), "high");
    }

    #[test]
    fn effort_default_medium() {
        let r = resolve(&json!({ "reasoning": { "enabled": true } })).unwrap();
        assert_eq!(r.effort_or_default(), "medium");
    }

    #[test]
    fn from_anthropic_thinking_enabled() {
        let out = reasoning_from_anthropic_thinking(&json!({ "type": "enabled", "budget_tokens": 2048 })).unwrap();
        assert_eq!(out["enabled"], json!(true));
        assert_eq!(out["max_tokens"], json!(2048));
    }

    #[test]
    fn from_anthropic_thinking_disabled() {
        let out = reasoning_from_anthropic_thinking(&json!({ "type": "disabled" })).unwrap();
        assert_eq!(out["enabled"], json!(false));
        assert!(
            out.get("max_tokens")
                .is_none()
        );
    }

    #[test]
    fn from_responses_reasoning_effort() {
        let out = reasoning_from_responses(&json!({ "effort": "low", "summary": "auto" })).unwrap();
        assert_eq!(out["effort"], json!("low"));
        assert!(out.get("summary").is_none());
    }

    #[test]
    fn from_responses_reasoning_empty_is_none() {
        assert!(reasoning_from_responses(&json!({ "summary": "auto" })).is_none());
    }

    #[test]
    fn budget_to_effort_boundaries() {
        assert_eq!(budget_to_effort(512), "minimal");
        assert_eq!(budget_to_effort(1024), "low");
        assert_eq!(budget_to_effort(4096), "medium");
        assert_eq!(budget_to_effort(4097), "high");
    }

    #[test]
    fn shape_openai_reasoning_model_sets_effort_and_strips_object() {
        let mut body = json!({ "reasoning": { "effort": "high" }, "messages": [] });
        shape_openai_body(&mut body, true);
        assert_eq!(body["reasoning_effort"], json!("high"));
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }

    #[test]
    fn shape_openai_respects_explicit_scalar() {
        let mut body = json!({ "reasoning_effort": "low", "reasoning": { "effort": "high" }, "messages": [] });
        shape_openai_body(&mut body, true);
        assert_eq!(body["reasoning_effort"], json!("low"));
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }

    #[test]
    fn shape_openai_non_reasoning_strips_everything() {
        let mut body = json!({ "reasoning_effort": "high", "reasoning": { "effort": "high" }, "messages": [] });
        shape_openai_body(&mut body, false);
        assert!(
            body.get("reasoning_effort")
                .is_none()
        );
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }

    #[test]
    fn shape_openai_disabled_strips_effort() {
        let mut body = json!({ "reasoning": { "enabled": false }, "messages": [] });
        shape_openai_body(&mut body, true);
        assert!(
            body.get("reasoning_effort")
                .is_none()
        );
    }

    #[test]
    fn shape_anthropic_sets_thinking_and_headroom() {
        let mut body =
            json!({ "reasoning": { "effort": "high" }, "max_tokens": 32000, "temperature": 0.5, "messages": [] });
        shape_anthropic_body(&mut body);
        assert_eq!(body["thinking"]["type"], json!("enabled"));
        let budget = body["thinking"]["budget_tokens"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, BUDGET_HIGH);
        assert!(
            body["max_tokens"]
                .as_u64()
                .unwrap()
                > budget
        );
        assert!(
            body.get("temperature")
                .is_none()
        );
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }

    #[test]
    fn shape_anthropic_grows_max_tokens_below_min_budget() {
        // Ceiling below the 1024 minimum: budget floors at the minimum and
        // max_tokens grows above it so `budget_tokens < max_tokens` holds.
        let mut body = json!({ "reasoning": { "effort": "high" }, "max_tokens": 1000, "messages": [] });
        shape_anthropic_body(&mut body);
        let budget = body["thinking"]["budget_tokens"]
            .as_u64()
            .unwrap();
        assert_eq!(budget, ANTHROPIC_MIN_BUDGET);
        assert!(
            body["max_tokens"]
                .as_u64()
                .unwrap()
                > budget
        );
    }

    #[test]
    fn shape_anthropic_min_budget_when_low() {
        let mut body = json!({ "reasoning": { "max_tokens": 100 }, "max_tokens": 8000, "messages": [] });
        shape_anthropic_body(&mut body);
        assert_eq!(body["thinking"]["budget_tokens"], json!(ANTHROPIC_MIN_BUDGET));
    }

    #[test]
    fn shape_anthropic_noop_without_reasoning() {
        let mut body = json!({ "max_tokens": 8000, "temperature": 0.5, "messages": [] });
        shape_anthropic_body(&mut body);
        assert!(body.get("thinking").is_none());
        assert_eq!(body["temperature"], json!(0.5));
    }

    #[test]
    fn shape_anthropic_disabled_adds_nothing() {
        let mut body = json!({ "reasoning": { "enabled": false }, "max_tokens": 8000, "messages": [] });
        shape_anthropic_body(&mut body);
        assert!(body.get("thinking").is_none());
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }

    #[test]
    fn gemini_thinking_config_from_effort() {
        let cfg = gemini_thinking_config(&json!({ "reasoning": { "effort": "low" } })).unwrap();
        assert_eq!(cfg["thinkingBudget"], json!(BUDGET_LOW));
        assert_eq!(cfg["includeThoughts"], json!(true));
    }

    #[test]
    fn gemini_thinking_config_exclude() {
        let cfg = gemini_thinking_config(&json!({ "reasoning": { "effort": "high", "exclude": true } })).unwrap();
        assert_eq!(cfg["includeThoughts"], json!(false));
    }

    #[test]
    fn gemini_thinking_config_disabled_zero_budget() {
        let cfg = gemini_thinking_config(&json!({ "reasoning": { "enabled": false } })).unwrap();
        assert_eq!(cfg["thinkingBudget"], json!(0));
    }

    #[test]
    fn gemini_thinking_config_none_without_reasoning() {
        assert!(gemini_thinking_config(&json!({ "messages": [] })).is_none());
    }

    #[test]
    fn anthropic_details_round_trip() {
        let content = vec![
            json!({ "type": "thinking", "thinking": "step one", "signature": "sig123" }),
            json!({ "type": "text", "text": "the answer" }),
            json!({ "type": "redacted_thinking", "data": "ENC" }),
        ];
        let details = anthropic_thinking_to_details(&content);
        assert_eq!(details.len(), 2);
        assert_eq!(details[0]["type"], json!("reasoning.text"));
        assert_eq!(details[0]["text"], json!("step one"));
        assert_eq!(details[0]["signature"], json!("sig123"));
        assert_eq!(details[1]["type"], json!("reasoning.encrypted"));
        assert_eq!(details[1]["data"], json!("ENC"));

        assert_eq!(reasoning_text_from_details(&details), "step one");

        let blocks = details_to_anthropic_thinking_blocks(&details);
        assert_eq!(blocks.len(), 2);
        assert_eq!(blocks[0]["type"], json!("thinking"));
        assert_eq!(blocks[0]["thinking"], json!("step one"));
        assert_eq!(blocks[0]["signature"], json!("sig123"));
        assert_eq!(blocks[1]["type"], json!("redacted_thinking"));
        assert_eq!(blocks[1]["data"], json!("ENC"));
    }

    #[test]
    fn anthropic_details_empty_when_no_thinking() {
        let content = vec![json!({ "type": "text", "text": "hi" })];
        assert!(anthropic_thinking_to_details(&content).is_empty());
        assert_eq!(reasoning_text_from_details(&[]), "");
    }

    #[test]
    fn apply_cap_clamps_budget_and_effort() {
        let mut body = json!({ "reasoning": { "effort": "high" }, "messages": [] });
        apply_cap(&mut body, 4096);
        assert_eq!(body["reasoning"]["max_tokens"], json!(4096));
        assert_eq!(body["reasoning"]["effort"], json!("medium"));
    }

    #[test]
    fn apply_cap_noop_within_ceiling() {
        let mut body = json!({ "reasoning": { "effort": "low" }, "messages": [] });
        apply_cap(&mut body, 8000);
        // low (1024) is within the ceiling, so nothing changes.
        assert!(
            body["reasoning"]
                .get("max_tokens")
                .is_none()
        );
        assert_eq!(body["reasoning"]["effort"], json!("low"));
    }

    #[test]
    fn apply_cap_from_scalar_creates_object_and_bounds_scalar() {
        let mut body = json!({ "reasoning_effort": "high", "messages": [] });
        apply_cap(&mut body, 1024);
        assert_eq!(body["reasoning"]["max_tokens"], json!(1024));
        assert_eq!(body["reasoning"]["effort"], json!("low"));
        assert_eq!(body["reasoning_effort"], json!("low"));
    }

    #[test]
    fn apply_cap_zero_disables() {
        let mut body = json!({ "reasoning": { "effort": "high" }, "messages": [] });
        apply_cap(&mut body, 0);
        assert!(
            body["reasoning"]
                .get("max_tokens")
                .is_none()
        );
    }

    #[test]
    fn apply_cap_noop_without_reasoning() {
        let mut body = json!({ "messages": [] });
        apply_cap(&mut body, 1024);
        assert!(
            body.get("reasoning")
                .is_none()
        );
    }
}
