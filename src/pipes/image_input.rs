//! Inbound image-modality gate — **off by default (strict opt-in)**.
//!
//! Recognize inline images a caller attaches to a chat message (an
//! `{ "type": "image_url", "image_url": { "url" } }` part, whether a `data:` URL
//! or a remote URL) and gate them before the upstream call: a surface must
//! explicitly accept image input, and — for inline `data:` images the gateway
//! can inspect — the format must be in the surface allow-list and the total
//! decoded size must fit the cap. Remote image URLs cannot be inspected without
//! fetching, so when image input is enabled they are accepted (format/size
//! checks apply only to inline data). The detected formats are exposed to Rego
//! as `input.resource.image_formats`.
//!
//! The gate never changes the body; images flow to the upstream through the
//! existing wire transform (OpenAI verbatim, Gemini `inline_data`). The one
//! exception is [`drop_tool_images`], which leaves a tool's images out on a
//! surface that does not accept image input. This gate is the image
//! counterpart of [`crate::pipes::audio`].

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Maximum total decoded inline-image bytes accepted in a single request.
const MAX_TOTAL_IMAGE_BYTES: usize = 20 * 1024 * 1024;

fn default_image_formats() -> Vec<String> {
    crate::pipes::modality::IMAGE_FORMATS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_max_image_bytes() -> usize {
    MAX_TOTAL_IMAGE_BYTES
}

/// Per-surface image-input policy — off by default (strict opt-in). Absent or
/// disabled ⇒ the surface rejects inline images. Enabled ⇒ images are accepted,
/// inline `data:` images are restricted to `allowed_formats` and bounded by
/// `max_bytes`; remote image URLs are forwarded as-is.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ImageInputConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_image_formats")]
    pub allowed_formats: Vec<String>,
    #[serde(default = "default_max_image_bytes")]
    pub max_bytes: usize,
}

impl Default for ImageInputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            allowed_formats: default_image_formats(),
            max_bytes: default_max_image_bytes(),
        }
    }
}

impl ImageInputConfig {
    fn allows_format(
        &self,
        fmt: &str,
    ) -> bool {
        self.allowed_formats
            .iter()
            .any(|a| a.eq_ignore_ascii_case(fmt))
    }
}

/// The image a part carries: the `image_url` string of an `{ type: "image_url" }`
/// part, or the `data:image/…` URL of a `{ type: "file" }` part, which an
/// Anthropic upstream receives as an image too.
fn image_url(part: &Value) -> Option<&str> {
    match part
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("image_url") => part
            .get("image_url")
            .and_then(|i| i.get("url"))
            .and_then(|u| u.as_str()),
        Some("file") => part
            .get("file")
            .and_then(|f| f.get("file_data"))
            .and_then(|d| d.as_str())
            .filter(|d| {
                d.get(..11)
                    .is_some_and(|prefix| prefix.eq_ignore_ascii_case("data:image/"))
            }),
        _ => None,
    }
}

/// The normalized format of an image part (`png`, `jpeg`, …) from a `data:` URL
/// MIME, or `None` for a remote URL the gateway cannot inspect.
fn part_image_format(url: &str) -> Option<String> {
    let meta = url
        .strip_prefix("data:")?
        .split_once(',')?
        .0;
    let mime = meta
        .split(';')
        .next()?
        .to_ascii_lowercase();
    let sub = mime
        .strip_prefix("image/")
        .unwrap_or(&mime);
    let normalized = match sub {
        "jpg" => "jpeg",
        other => other,
    };
    (!normalized.is_empty()).then(|| normalized.to_string())
}

/// Estimate the decoded byte length of a `data:` URL's base64 payload.
fn estimated_image_bytes(url: &str) -> usize {
    let Some(rest) = url.strip_prefix("data:") else {
        return 0;
    };
    match rest.split_once(',') {
        Some((_, payload)) => payload.trim().len() / 4 * 3,
        None => 0,
    }
}

/// The distinct inline-image formats present in the request, for the policy
/// input (`input.resource.image_formats`). Remote-URL images contribute
/// `remote`. `None` when the request carries no images.
pub fn image_formats_present(body: &Value) -> Option<Vec<String>> {
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
                if let Some(url) = image_url(part) {
                    let fmt = part_image_format(url).unwrap_or_else(|| "remote".to_string());
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

/// The outcome of the image gate, for the response header and governance stage.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct ImageGateOutcome {
    pub parts: usize,
    pub bytes: usize,
    pub formats: Vec<String>,
}

impl ImageGateOutcome {
    pub fn applied(&self) -> bool {
        self.parts > 0
    }

    /// `x-agent-stream-images` header value.
    pub fn header_value(&self) -> String {
        format!("parts={}; bytes={}; formats={}", self.parts, self.bytes, self.formats.join(","))
    }

    /// Human-readable governance-stage detail.
    pub fn governance_detail(&self) -> String {
        format!(
            "{} image part(s) · {} inline byte(s) · formats: {}",
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

/// Drop the images a tool returned (`image_url` parts in a `tool` message) when
/// the surface does not accept image input, so a tool's screenshot is left out
/// of the request rather than refusing the conversation it belongs to. Images
/// the caller attaches are untouched and still gated by [`apply`]. Returns how
/// many were dropped.
pub fn drop_tool_images(
    body: &mut Value,
    config: Option<&ImageInputConfig>,
) -> usize {
    if config.is_some_and(|c| c.enabled) {
        return 0;
    }
    let Some(messages) = body
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
    else {
        return 0;
    };
    let mut dropped = 0;
    for message in messages {
        if message
            .get("role")
            .and_then(|r| r.as_str())
            != Some("tool")
        {
            continue;
        }
        if let Some(parts) = message
            .get_mut("content")
            .and_then(|c| c.as_array_mut())
        {
            let before = parts.len();
            parts.retain(|part| image_url(part).is_none());
            dropped += before - parts.len();
        }
    }
    dropped
}

/// Enforce the image-modality gate on an OpenAI-canonical request body.
///
/// **Strict opt-in.** No images ⇒ no-op. Images present ⇒ the surface must
/// accept them (`config` present and `enabled`); every inline `data:` image's
/// format must be in the allow-list and the total inline size must fit the cap.
/// Remote image URLs are forwarded when enabled. Any failure is a caller-facing
/// message (mapped to `400`). The body is never mutated.
pub fn apply(
    body: &Value,
    config: Option<&ImageInputConfig>,
) -> Result<ImageGateOutcome, String> {
    let messages = match body
        .get("messages")
        .and_then(|m| m.as_array())
    {
        Some(m) => m,
        None => return Ok(ImageGateOutcome::default()),
    };

    let mut outcome = ImageGateOutcome::default();
    for message in messages {
        if let Some(parts) = message
            .get("content")
            .and_then(|c| c.as_array())
        {
            for part in parts {
                if let Some(url) = image_url(part) {
                    outcome.parts += 1;
                    outcome.bytes += estimated_image_bytes(url);
                    let fmt = part_image_format(url).unwrap_or_else(|| "remote".to_string());
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

    let cfg = match config {
        Some(c) if c.enabled => c,
        _ => return Err("this surface does not accept image input".to_string()),
    };

    for fmt in &outcome.formats {
        // `remote` = a URL the gateway cannot inspect; forwarded, not format-checked.
        if fmt != "remote" && !cfg.allows_format(fmt) {
            return Err(format!("image format '{fmt}' is not accepted by this surface"));
        }
    }

    if outcome.bytes > cfg.max_bytes {
        return Err(format!(
            "attached images are too large ({} inline bytes decoded; limit {} bytes)",
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

    fn data_image(
        mime: &str,
        data: &str,
    ) -> Value {
        json!({ "type": "image_url", "image_url": { "url": format!("data:{mime};base64,{data}") } })
    }

    fn remote_image(url: &str) -> Value {
        json!({ "type": "image_url", "image_url": { "url": url } })
    }

    fn body_with(parts: Value) -> Value {
        json!({ "model": "m", "messages": [ { "role": "user", "content": parts } ] })
    }

    fn enabled_cfg() -> ImageInputConfig {
        ImageInputConfig {
            enabled: true,
            ..Default::default()
        }
    }

    #[test]
    fn no_image_is_noop() {
        let body = body_with(json!([{ "type": "text", "text": "hi" }]));
        assert!(
            !apply(&body, None)
                .unwrap()
                .applied()
        );
        assert_eq!(image_formats_present(&body), None);
    }

    fn tool_screenshot_conversation() -> Value {
        json!({ "model": "m", "messages": [
            { "role": "user", "content": "What is on screen?" },
            { "role": "tool", "tool_call_id": "t1", "content": [
                { "type": "text", "text": "Captured." },
                data_image("image/png", "QUJD")
            ] }
        ] })
    }

    #[test]
    fn tool_images_are_dropped_on_a_surface_without_image_input() {
        for config in [None, Some(ImageInputConfig::default())] {
            let mut body = tool_screenshot_conversation();
            assert_eq!(drop_tool_images(&mut body, config.as_ref()), 1);
            assert_eq!(body["messages"][1]["content"], json!([{ "type": "text", "text": "Captured." }]));
            assert!(
                !apply(&body, config.as_ref())
                    .expect("served")
                    .applied()
            );
        }
    }

    #[test]
    fn tool_images_are_kept_and_gated_on_a_surface_with_image_input() {
        let mut body = tool_screenshot_conversation();
        assert_eq!(drop_tool_images(&mut body, Some(&enabled_cfg())), 0);
        assert_eq!(body, tool_screenshot_conversation());
        assert_eq!(
            apply(&body, Some(&enabled_cfg()))
                .expect("accepted")
                .parts,
            1
        );
    }

    fn image_file(mime: &str) -> Value {
        json!({ "type": "file", "file": { "filename": "shot", "file_data": format!("data:{mime};base64,QUJD") } })
    }

    #[test]
    fn an_image_sent_as_a_file_part_is_gated_like_any_image() {
        let body = body_with(json!([{ "type": "text", "text": "what is this?" }, image_file("image/png")]));
        assert_eq!(apply(&body, None), Err("this surface does not accept image input".to_string()));
        assert_eq!(image_formats_present(&body), Some(vec!["png".to_string()]));
        let accepted = apply(&body, Some(&enabled_cfg())).expect("accepted when image input is on");
        assert_eq!((accepted.parts, accepted.formats), (1, vec!["png".to_string()]));

        let restricted = ImageInputConfig {
            enabled: true,
            allowed_formats: vec!["jpeg".to_string()],
            ..Default::default()
        };
        assert!(apply(&body, Some(&restricted)).is_err(), "the format allow-list applies");
    }

    #[test]
    fn a_non_image_file_part_is_not_an_image() {
        for mime in ["application/pdf", "text/plain"] {
            let body = body_with(json!([image_file(mime)]));
            assert_eq!(image_formats_present(&body), None, "{mime}");
            assert!(
                !apply(&body, None)
                    .expect("not gated as an image")
                    .applied()
            );
        }
    }

    #[test]
    fn caller_images_are_not_dropped_and_still_refused() {
        let mut body = body_with(json!([data_image("image/png", "QUJD")]));
        assert_eq!(drop_tool_images(&mut body, None), 0);
        assert!(apply(&body, None).is_err());
    }

    #[test]
    fn image_without_optin_is_rejected() {
        let body = body_with(json!([data_image("image/png", "QUJD")]));
        assert!(apply(&body, None).is_err());
        assert!(apply(&body, Some(&ImageInputConfig::default())).is_err());
    }

    #[test]
    fn opted_in_inline_image_passes_and_normalizes_jpg() {
        let body = body_with(json!([data_image("image/jpg", "QUJD")]));
        let outcome = apply(&body, Some(&enabled_cfg())).expect("png/jpeg allowed by default");
        assert!(outcome.applied());
        assert_eq!(outcome.formats, vec!["jpeg".to_string()]);
    }

    #[test]
    fn disallowed_inline_format_is_rejected() {
        let cfg = ImageInputConfig {
            enabled: true,
            allowed_formats: vec!["png".to_string()],
            ..Default::default()
        };
        let body = body_with(json!([data_image("image/webp", "QUJD")]));
        let err = apply(&body, Some(&cfg)).expect_err("webp not allowed");
        assert!(err.contains("format 'webp' is not accepted"));
    }

    #[test]
    fn remote_image_is_forwarded_when_enabled() {
        let body = body_with(json!([remote_image("https://example.com/x.png")]));
        let outcome = apply(&body, Some(&enabled_cfg())).expect("remote images forwarded when enabled");
        assert_eq!(outcome.formats, vec!["remote".to_string()]);
        assert_eq!(image_formats_present(&body), Some(vec!["remote".to_string()]));
    }

    #[test]
    fn oversize_inline_image_is_rejected() {
        let big = "A".repeat((MAX_TOTAL_IMAGE_BYTES / 3 * 4) + 8);
        let body = body_with(json!([data_image("image/png", &big)]));
        let err = apply(&body, Some(&enabled_cfg())).expect_err("oversize inline image must fail");
        assert!(err.contains("too large"));
    }
}
