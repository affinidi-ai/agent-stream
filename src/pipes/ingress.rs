//! Inbound API "skin" negotiation for LLM surfaces.
//!
//! A surface presents an OpenAI-canonical pipeline internally, but a client may
//! speak either the **OpenAI Chat Completions** dialect (`/v1/chat/completions`)
//! or the **Anthropic Messages** dialect (`/v1/messages`). The inbound format is
//! a per-request *skin*, negotiated by the request path and normalized to the
//! OpenAI-canonical body at the front door; the response is re-skinned at the
//! edge. See `docs/CLIENT_API_DIALECTS.md`.

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A client-facing API dialect a surface can answer. Extensible: future skins
/// (Gemini `generateContent`) are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IngressSchema {
    /// OpenAI Chat Completions (`/v1/chat/completions`). The canonical internal
    /// wire format; requires no transform.
    #[serde(rename = "openai_chat")]
    OpenAiChat,
    /// Anthropic Messages (`/v1/messages`). Normalized to OpenAI at the front
    /// door and re-skinned to Anthropic on the way out.
    #[serde(rename = "anthropic_messages")]
    AnthropicMessages,
    /// OpenAI Responses (`/v1/responses`). Normalized to OpenAI Chat at the
    /// front door and re-skinned to the Responses shape on the way out.
    #[serde(rename = "openai_responses")]
    OpenAiResponses,
}

impl IngressSchema {
    /// Stable identifier used in governance records, logs, and headers.
    pub fn as_str(self) -> &'static str {
        match self {
            IngressSchema::OpenAiChat => "openai_chat",
            IngressSchema::AnthropicMessages => "anthropic_messages",
            IngressSchema::OpenAiResponses => "openai_responses",
        }
    }
}

/// Default set of accepted client formats for a surface: **all** dialects, so
/// any client can reach any surface regardless of upstream model.
pub fn default_accepted_ingress_schemas() -> Vec<IngressSchema> {
    vec![IngressSchema::OpenAiChat, IngressSchema::AnthropicMessages, IngressSchema::OpenAiResponses]
}

/// Resolve the ingress skin from a request path suffix.
///
/// `/v1/messages` (final segment `messages`) is the Anthropic Messages dialect;
/// `/v1/responses` (final segment `responses`) is the OpenAI Responses dialect;
/// everything else — including `/v1/chat/completions` — is the OpenAI Chat
/// dialect. Query strings and trailing slashes are ignored.
pub fn detect_ingress_schema(path_suffix: &str) -> IngressSchema {
    let path = path_suffix
        .split('?')
        .next()
        .unwrap_or(path_suffix)
        .trim_end_matches('/');
    if path == "messages" || path.ends_with("/messages") {
        IngressSchema::AnthropicMessages
    } else if path == "responses" || path.ends_with("/responses") {
        IngressSchema::OpenAiResponses
    } else {
        IngressSchema::OpenAiChat
    }
}

/// Whether `schema` is in the surface's accepted set.
pub fn is_ingress_accepted(
    accepted: &[IngressSchema],
    schema: IngressSchema,
) -> bool {
    accepted.contains(&schema)
}

/// Map an HTTP status code to the Anthropic error `type` string.
pub fn anthropic_error_type_for_status(status: u16) -> &'static str {
    match status {
        400 => "invalid_request_error",
        401 => "authentication_error",
        403 => "permission_error",
        404 => "not_found_error",
        413 => "request_too_large",
        429 => "rate_limit_error",
        500 => "api_error",
        529 => "overloaded_error",
        s if (500..600).contains(&s) => "api_error",
        _ => "api_error",
    }
}

/// Build an Anthropic-shaped error envelope:
/// `{ "type": "error", "error": { "type": "...", "message": "..." } }`.
pub fn anthropic_error_body(
    status: u16,
    message: &str,
) -> Value {
    serde_json::json!({
        "type": "error",
        "error": {
            "type": anthropic_error_type_for_status(status),
            "message": message,
        }
    })
}

/// Re-skin an OpenAI-shaped error body (`{ "error": { "message", "type", ... } }`)
/// into the Anthropic envelope, preserving the human-readable message. Falls
/// back to the status-derived type/message when the body is not the expected
/// shape.
pub fn openai_error_to_anthropic(
    status: u16,
    openai_error: &Value,
) -> Value {
    let message = openai_error
        .get("error")
        .and_then(|e| e.get("message"))
        .and_then(|m| m.as_str())
        .or_else(|| {
            openai_error
                .get("message")
                .and_then(|m| m.as_str())
        })
        .unwrap_or("request failed");
    anthropic_error_body(status, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_anthropic_messages_path() {
        assert_eq!(detect_ingress_schema("/v1/messages"), IngressSchema::AnthropicMessages);
        assert_eq!(detect_ingress_schema("v1/messages"), IngressSchema::AnthropicMessages);
        assert_eq!(detect_ingress_schema("/messages"), IngressSchema::AnthropicMessages);
        assert_eq!(detect_ingress_schema("messages"), IngressSchema::AnthropicMessages);
        assert_eq!(detect_ingress_schema("/v1/messages/"), IngressSchema::AnthropicMessages);
        assert_eq!(detect_ingress_schema("/v1/messages?beta=true"), IngressSchema::AnthropicMessages);
    }

    #[test]
    fn detects_openai_for_everything_else() {
        assert_eq!(detect_ingress_schema("/v1/chat/completions"), IngressSchema::OpenAiChat);
        assert_eq!(detect_ingress_schema("/chat/completions"), IngressSchema::OpenAiChat);
        // count_tokens is a distinct endpoint and not (yet) the Messages skin.
        assert_eq!(detect_ingress_schema("/v1/messages/count_tokens"), IngressSchema::OpenAiChat);
        assert_eq!(detect_ingress_schema("/v1/embeddings"), IngressSchema::OpenAiChat);
    }

    #[test]
    fn detects_openai_responses_path() {
        assert_eq!(detect_ingress_schema("/v1/responses"), IngressSchema::OpenAiResponses);
        assert_eq!(detect_ingress_schema("responses"), IngressSchema::OpenAiResponses);
        assert_eq!(detect_ingress_schema("/v1/responses/"), IngressSchema::OpenAiResponses);
        assert_eq!(detect_ingress_schema("/v1/responses?stream=true"), IngressSchema::OpenAiResponses);
    }

    #[test]
    fn default_accepts_all() {
        let d = default_accepted_ingress_schemas();
        assert!(is_ingress_accepted(&d, IngressSchema::OpenAiChat));
        assert!(is_ingress_accepted(&d, IngressSchema::AnthropicMessages));
        assert!(is_ingress_accepted(&d, IngressSchema::OpenAiResponses));
    }

    #[test]
    fn schema_serde_roundtrip() {
        assert_eq!(serde_json::to_string(&IngressSchema::OpenAiChat).unwrap(), "\"openai_chat\"");
        assert_eq!(serde_json::to_string(&IngressSchema::AnthropicMessages).unwrap(), "\"anthropic_messages\"");
        assert_eq!(serde_json::to_string(&IngressSchema::OpenAiResponses).unwrap(), "\"openai_responses\"");
        let back: IngressSchema = serde_json::from_str("\"anthropic_messages\"").unwrap();
        assert_eq!(back, IngressSchema::AnthropicMessages);
    }

    #[test]
    fn error_type_mapping() {
        assert_eq!(anthropic_error_type_for_status(400), "invalid_request_error");
        assert_eq!(anthropic_error_type_for_status(401), "authentication_error");
        assert_eq!(anthropic_error_type_for_status(429), "rate_limit_error");
        assert_eq!(anthropic_error_type_for_status(502), "api_error");
    }

    #[test]
    fn reskins_openai_error() {
        let openai = serde_json::json!({ "error": { "message": "bad key", "type": "invalid_request_error" } });
        let out = openai_error_to_anthropic(401, &openai);
        assert_eq!(out["type"], "error");
        assert_eq!(out["error"]["type"], "authentication_error");
        assert_eq!(out["error"]["message"], "bad key");
    }
}
