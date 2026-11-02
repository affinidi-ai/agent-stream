//! Inbound audio-modality gate.
//!
//! Recognize inline audio a caller attaches to a chat message
//! (`{ "type": "input_audio", "input_audio": { "data", "format" } }` in the
//! OpenAI-canonical body) and gate it before the upstream call:
//!
//! - **Capability gate.** Audio is only allowed through to a model that accepts
//!   audio input (`ModelRequestProfile::supports_audio_input`, resolved from the
//!   catalog). A model that cannot understand audio would otherwise either 400
//!   at the provider or — for a schema with no audio wire form (Anthropic) —
//!   silently drop it; failing fast with a clear message is better.
//! - **Size guard.** The total decoded audio in a request is capped, so a caller
//!   cannot push an unbounded upload through the JSON path.
//!
//! The stage is a structural operation on the OpenAI-canonical body, so it is
//! dialect- and provider-agnostic (a Responses `input_audio` part is normalized
//! to this canonical part upstream). The wire transforms carry the part to the
//! upstream: OpenAI passes it through verbatim; Gemini re-emits it as an
//! `inline_data` part. The detected formats are exposed to Rego as
//! `input.resource.audio_formats` so a policy can gate audio centrally.
//!
//! Governance records never store the raw base64 — `build_record` keeps only a
//! digest of the request plus the text-extracted prompt — so the byte cap here
//! is the only bloat guard the modality needs.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum total decoded audio bytes accepted in a single request. 25 MiB
/// mirrors the audio-input ceiling of the major providers and bounds the JSON
/// path against an oversized upload.
const MAX_TOTAL_AUDIO_BYTES: usize = 25 * 1024 * 1024;

fn default_audio_formats() -> Vec<String> {
    crate::pipes::modality::AUDIO_FORMATS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_max_audio_bytes() -> usize {
    MAX_TOTAL_AUDIO_BYTES
}

/// Per-surface audio-input policy — **off by default (strict opt-in)**. When the
/// block is absent or disabled the surface rejects inline audio. When enabled,
/// audio is accepted for an audio-capable model, restricted to `allowed_formats`
/// (from the backend-published set), and bounded by `max_bytes`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct AudioInputConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_audio_formats")]
    pub allowed_formats: Vec<String>,
    #[serde(default = "default_max_audio_bytes")]
    pub max_bytes: usize,
}

impl Default for AudioInputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_formats: default_audio_formats(),
            max_bytes: default_max_audio_bytes(),
        }
    }
}

impl AudioInputConfig {
    fn allows_format(
        &self,
        fmt: &str,
    ) -> bool {
        self.allowed_formats
            .iter()
            .any(|a| a.eq_ignore_ascii_case(fmt))
    }
}

/// The `input_audio` object of a `{ type: "input_audio" }` content part.
fn input_audio_object(part: &Value) -> Option<&Value> {
    if part
        .get("type")
        .and_then(|t| t.as_str())
        != Some("input_audio")
    {
        return None;
    }
    part.get("input_audio")
}

/// The declared format of an audio part (`wav`, `mp3`, …), lowercased.
fn part_audio_format(part: &Value) -> Option<String> {
    input_audio_object(part)?
        .get("format")
        .and_then(|f| f.as_str())
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
}

/// Estimate the decoded byte length of an audio part's base64 `data` without
/// allocating a decode buffer. A `data:` URL prefix is stripped first; base64
/// decodes to ~3/4 of its text length.
fn estimated_audio_bytes(part: &Value) -> usize {
    let Some(data) = input_audio_object(part)
        .and_then(|a| a.get("data"))
        .and_then(|d| d.as_str())
    else {
        return 0;
    };
    let payload = match data.split_once(',') {
        Some((meta, rest)) if meta.starts_with("data:") => rest,
        _ => data,
    };
    payload.trim().len() / 4 * 3
}

/// The distinct audio formats present in the request, for the policy input
/// (`input.resource.audio_formats`). Cheap: reads the `format` field only, never
/// decodes the payload. `None` when the request carries no audio.
pub fn audio_formats_present(body: &Value) -> Option<Vec<String>> {
    let messages = body
        .get("messages")
        .and_then(|m| m.as_array())?;
    let mut formats: Vec<String> = Vec::new();
    for message in messages {
        if let Some(parts) = message
            .get("content")
            .and_then(|c| c.as_array())
        {
            for part in parts {
                if input_audio_object(part).is_some() {
                    let fmt = part_audio_format(part).unwrap_or_else(|| "unknown".to_string());
                    if !formats.contains(&fmt) {
                        formats.push(fmt);
                    }
                }
            }
        }
    }
    if formats.is_empty() {
        None
    } else {
        formats.sort();
        Some(formats)
    }
}

/// The outcome of the audio gate, for the response header and governance stage.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct AudioGateOutcome {
    pub parts: usize,
    pub bytes: usize,
    pub formats: Vec<String>,
}

impl AudioGateOutcome {
    pub fn applied(&self) -> bool {
        self.parts > 0
    }

    /// `x-agent-stream-audio` header value.
    pub fn header_value(&self) -> String {
        format!("parts={}; bytes={}; formats={}", self.parts, self.bytes, self.formats.join(","))
    }

    /// Human-readable governance-stage detail.
    pub fn governance_detail(&self) -> String {
        format!(
            "{} audio part(s) · {} byte(s) · formats: {}",
            self.parts,
            self.bytes,
            if self.formats.is_empty() {
                "none".to_string()
            } else {
                self.formats.join(",")
            }
        )
    }
}

/// Enforce the audio-modality gate on an OpenAI-canonical request body.
///
/// **Strict opt-in.** A body with no audio is a no-op. When audio is present the
/// surface must explicitly accept it (`config` present and `enabled`), the target
/// model must be audio-capable (`supports_audio`), every declared format must be
/// in the surface allow-list, and the total decoded audio must fit the surface
/// cap. Any failure is a caller-facing message (mapped to `400` at the front
/// door). The body is never mutated — audio flows upstream via the wire transform.
pub fn apply(
    body: &Value,
    config: Option<&AudioInputConfig>,
    supports_audio: bool,
) -> Result<AudioGateOutcome, String> {
    let messages = match body
        .get("messages")
        .and_then(|m| m.as_array())
    {
        Some(m) => m,
        None => return Ok(AudioGateOutcome::default()),
    };

    let mut outcome = AudioGateOutcome::default();
    for message in messages {
        if let Some(parts) = message
            .get("content")
            .and_then(|c| c.as_array())
        {
            for part in parts {
                if input_audio_object(part).is_some() {
                    outcome.parts += 1;
                    outcome.bytes += estimated_audio_bytes(part);
                    let fmt = part_audio_format(part).unwrap_or_else(|| "unknown".to_string());
                    if !outcome.formats.contains(&fmt) {
                        outcome.formats.push(fmt);
                    }
                }
            }
        }
    }

    if outcome.parts == 0 {
        return Ok(outcome);
    }

    // Strict opt-in: the surface must explicitly accept audio input.
    let cfg = match config {
        Some(c) if c.enabled => c,
        _ => return Err("this surface does not accept audio input".to_string()),
    };

    if !supports_audio {
        return Err("the target model does not accept audio input; route audio to an audio-capable model \
             or transcribe it first"
            .to_string());
    }

    for fmt in &outcome.formats {
        if fmt != "unknown" && !cfg.allows_format(fmt) {
            return Err(format!("audio format '{fmt}' is not accepted by this surface"));
        }
    }

    if outcome.bytes > cfg.max_bytes {
        return Err(format!(
            "attached audio is too large ({} bytes decoded; limit {} bytes)",
            outcome.bytes, cfg.max_bytes
        ));
    }

    outcome.formats.sort();
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn audio_part(
        format: &str,
        data: &str,
    ) -> Value {
        json!({ "type": "input_audio", "input_audio": { "data": data, "format": format } })
    }

    fn body_with(parts: Value) -> Value {
        json!({ "model": "m", "messages": [ { "role": "user", "content": parts } ] })
    }

    fn enabled_cfg() -> AudioInputConfig {
        AudioInputConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn no_audio_is_noop_even_without_optin() {
        let body = body_with(json!([{ "type": "text", "text": "hi" }]));
        let outcome = apply(&body, None, false).expect("text-only is always allowed");
        assert!(!outcome.applied());
        assert_eq!(outcome.parts, 0);
        assert_eq!(audio_formats_present(&body), None);
    }

    #[test]
    fn string_content_is_noop() {
        let body = json!({ "messages": [ { "role": "user", "content": "plain" } ] });
        assert!(
            apply(&body, None, false)
                .unwrap()
                .parts
                == 0
        );
    }

    #[test]
    fn audio_without_optin_is_rejected() {
        let body = body_with(json!([audio_part("wav", "QUJDRA==")]));
        // No config, and a config that is present-but-disabled, both fail closed.
        let err = apply(&body, None, true).expect_err("audio needs surface opt-in");
        assert!(err.contains("surface does not accept audio"));
        let disabled = AudioInputConfig::default();
        assert!(apply(&body, Some(&disabled), true).is_err());
    }

    #[test]
    fn audio_to_unsupported_model_is_rejected() {
        let body = body_with(json!([
            { "type": "text", "text": "what is said?" },
            audio_part("wav", "QUJDRA==")
        ]));
        let err = apply(&body, Some(&enabled_cfg()), false).expect_err("audio to a text-only model must fail");
        assert!(err.contains("model does not accept audio"));
    }

    #[test]
    fn audio_to_supported_optedin_model_passes() {
        let body = body_with(json!([audio_part("mp3", "QUJDRA==")]));
        let outcome = apply(&body, Some(&enabled_cfg()), true).expect("audio to an audio model is allowed");
        assert!(outcome.applied());
        assert_eq!(outcome.parts, 1);
        assert_eq!(outcome.formats, vec!["mp3".to_string()]);
    }

    #[test]
    fn disallowed_format_is_rejected() {
        let cfg = AudioInputConfig {
            enabled: true,
            allowed_formats: vec!["wav".to_string()],
            ..Default::default()
        };
        let body = body_with(json!([audio_part("mp3", "QUJD")]));
        let err = apply(&body, Some(&cfg), true).expect_err("mp3 not in allow-list");
        assert!(err.contains("format 'mp3' is not accepted"));
    }

    #[test]
    fn oversize_audio_is_rejected_even_when_supported() {
        // A base64 string whose decoded length exceeds the cap.
        let big = "A".repeat((MAX_TOTAL_AUDIO_BYTES / 3 * 4) + 8);
        let body = body_with(json!([audio_part("wav", &big)]));
        let err = apply(&body, Some(&enabled_cfg()), true).expect_err("oversize audio must fail");
        assert!(err.contains("too large"));
    }

    #[test]
    fn formats_are_deduped_and_sorted() {
        let body = body_with(json!([audio_part("wav", "QUJD"), audio_part("mp3", "QUJD"), audio_part("wav", "QUJD")]));
        assert_eq!(audio_formats_present(&body), Some(vec!["mp3".to_string(), "wav".to_string()]));
        let outcome = apply(&body, Some(&enabled_cfg()), true).unwrap();
        assert_eq!(outcome.parts, 3);
        assert_eq!(outcome.formats, vec!["mp3".to_string(), "wav".to_string()]);
    }

    #[test]
    fn data_url_prefix_is_stripped_for_size_estimate() {
        let part = audio_part("wav", "data:audio/wav;base64,QUJDRA==");
        assert_eq!(estimated_audio_bytes(&part), "QUJDRA==".len() / 4 * 3);
    }

    #[test]
    fn missing_format_reports_unknown() {
        let body = body_with(json!([{ "type": "input_audio", "input_audio": { "data": "QUJD" } }]));
        assert_eq!(audio_formats_present(&body), Some(vec!["unknown".to_string()]));
    }
}
