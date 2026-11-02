//! Protocol-agnostic utilities for handling multiple protocols (A2A, MCP, UCP, ACP, etc.)
//!
//! This module contains functions that work across different messaging protocols,
//! including extension inspection, metadata injection, and utility functions.

pub mod extensions;

pub use extensions::{
    AnsweredRequest, MAX_REDACTION_BODY_BYTES, MetaStripOutcome, inject_custom_metadata_extension,
    inject_vp_into_response, resolve_secret_references, strip_raw_identity_from_meta,
};

use crate::config::ChannelProtocol;

/// Detect the wire "protocol family" of a JSON-RPC request body from its
/// `method` prefix. Returns `Some("a2a")` or `Some("mcp")` only when the body
/// is positively identifiable; `None` for non-JSON bodies, bodies without a
/// string `method` (e.g. JSON-RPC responses, MCP `initialize`), or unrecognised
/// methods — so ambiguous payloads are never misclassified (and therefore never
/// rejected by the boundary guard).
///
/// Agent Stream does not own A2A/MCP runtime behaviour; this detector exists only for the
/// safe boundary check that rejects a request whose JSON-RPC shape contradicts
/// the surface's declared protocol before it is forwarded to a Gateway target.
pub fn detect_request_protocol_family(body: &[u8]) -> Option<&'static str> {
    let json = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let method = json
        .get("method")
        .and_then(|m| m.as_str())?;
    if method.starts_with("message/") || method.starts_with("tasks/") {
        Some("a2a")
    } else if method.starts_with("tools/") || method.starts_with("prompts/") || method.starts_with("resources/") {
        Some("mcp")
    } else {
        None
    }
}

/// The protocol family a configured [`ChannelProtocol`] expects on the wire, or
/// `None` when the protocol has no JSON-RPC method-based detector (`didcomm`,
/// `marketplace`) and therefore cannot be shape-validated.
pub fn channel_protocol_family(protocol: &ChannelProtocol) -> Option<&'static str> {
    match protocol {
        ChannelProtocol::A2a => Some("a2a"),
        ChannelProtocol::Mcp => Some("mcp"),
        ChannelProtocol::DIDComm | ChannelProtocol::Marketplace => None,
    }
}

#[cfg(test)]
mod family_tests {
    use super::*;

    #[test]
    fn detects_a2a_from_message_method() {
        let body = br#"{"jsonrpc":"2.0","method":"message/send","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_a2a_from_tasks_method() {
        let body = br#"{"jsonrpc":"2.0","method":"tasks/get","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("a2a"));
    }

    #[test]
    fn detects_mcp_from_tools_method() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), Some("mcp"));
    }

    #[test]
    fn returns_none_for_mcp_initialize() {
        // `initialize` is a real MCP method but shares no prefix with the
        // detectable families; it must not be misclassified or rejected.
        let body = br#"{"jsonrpc":"2.0","method":"initialize","params":{}}"#;
        assert_eq!(detect_request_protocol_family(body), None);
    }

    #[test]
    fn returns_none_for_jsonrpc_response() {
        // JSON-RPC responses (id + result, no method) carry no protocol marker.
        let body = br#"{"jsonrpc":"2.0","id":1,"result":{}}"#;
        assert_eq!(detect_request_protocol_family(body), None);
    }

    #[test]
    fn returns_none_for_non_json() {
        assert_eq!(detect_request_protocol_family(b"not json"), None);
    }

    #[test]
    fn channel_family_for_a2a() {
        assert_eq!(channel_protocol_family(&ChannelProtocol::A2a), Some("a2a"));
        assert_eq!(channel_protocol_family(&ChannelProtocol::Mcp), Some("mcp"));
        assert_eq!(channel_protocol_family(&ChannelProtocol::DIDComm), None);
        assert_eq!(channel_protocol_family(&ChannelProtocol::Marketplace), None);
    }
}
