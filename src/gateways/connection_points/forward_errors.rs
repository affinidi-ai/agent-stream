//! Safe error responses for the fabric forward path.
//!
//! Agent Stream forwards Gateway-interop traffic to backend targets over the DIDComm
//! fabric. When a forward request is rejected at the boundary (unsupported
//! protocol, disabled target, bad method/scheme) or fails upstream, the response
//! sent back to the calling Gateway must NOT leak internal routing details —
//! target host/port, the resolved URL, or `reqwest` error chains. Detailed
//! diagnostics stay in the server logs only.
//!
//! The `response_body` envelope (`{ status, headers, body }`) matches the
//! success and OPA-deny contract already consumed by GW1; `body` is the
//! client-facing JSON string.

use serde_json::{Value, json};

/// A boundary rejection: the HTTP-style status and generic, leak-free message to
/// return when a forward request must not be dispatched to its target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundaryRejection {
    pub status: u16,
    pub message: &'static str,
}

/// Evaluate the fabric-forward safe boundary for a request. Returns
/// `Some(rejection)` when the request must NOT be forwarded to its target:
///
/// - (a) its JSON-RPC shape contradicts the surface's declared protocol family
///   (negative-detection only, so ambiguous / non-JSON-RPC bodies pass through);
/// - (b) the target endpoint uses a scheme this HTTP forwarder cannot dial
///   (only `http(s)://` and the `embedded://marketplace` sentinel are allowed —
///   a stray `fabric://` must never be sent to the HTTP client verbatim);
/// - (c) the HTTP method is not one Agent Stream forwards (never silently coerced to GET).
///
/// Pure and side-effect free so the security boundary can be unit-tested
/// directly, independent of the large `process_forward_request` pipeline.
pub fn evaluate_forward_boundary(
    surface_family: Option<&str>,
    body: &[u8],
    target_endpoint: &str,
    http_method: &str,
) -> Option<BoundaryRejection> {
    // (a) Protocol-family mismatch — only when BOTH sides are positively known.
    if let (Some(expected), Some(detected)) = (surface_family, crate::protocols::detect_request_protocol_family(body))
        && expected != detected
    {
        return Some(BoundaryRejection {
            status: 422,
            message: "Request protocol does not match the target protocol",
        });
    }

    // (b) Unsupported target scheme.
    let scheme_ok = target_endpoint.starts_with("https://")
        || target_endpoint.starts_with("http://")
        || target_endpoint == "embedded://marketplace";
    if !scheme_ok {
        return Some(BoundaryRejection {
            status: 502,
            message: "Target endpoint is not reachable over this path",
        });
    }

    // (c) Unknown HTTP method.
    let method_ok = matches!(
        http_method
            .to_uppercase()
            .as_str(),
        "GET" | "POST" | "PUT" | "DELETE" | "PATCH" | "HEAD" | "OPTIONS"
    );
    if !method_ok {
        return Some(BoundaryRejection {
            status: 405,
            message: "HTTP method is not supported",
        });
    }

    None
}

/// Refuse a forward whose `target_url`, built from the caller's `path`, leaves
/// `target_endpoint`: another scheme, host, port or user info, or a path outside
/// the endpoint's own path. A `..` step the target may still decode is refused
/// too (see `path_climbs`). A URL that does not parse is refused.
pub fn evaluate_forward_target(
    target_endpoint: &str,
    target_url: &str,
) -> Option<BoundaryRejection> {
    const NOT_ALLOWED: BoundaryRejection = BoundaryRejection {
        status: 400,
        message: "Request path is not allowed",
    };
    let (Ok(base), Ok(target)) = (url::Url::parse(target_endpoint), url::Url::parse(target_url)) else {
        return Some(NOT_ALLOWED);
    };
    let same_origin = target.scheme() == base.scheme()
        && target.host() == base.host()
        && target.port_or_known_default() == base.port_or_known_default()
        && target.username() == base.username()
        && target.password() == base.password();
    let base_path = base
        .path()
        .trim_end_matches('/');
    let under_base = target
        .path()
        .strip_prefix(base_path)
        .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'));
    if same_origin && under_base && !path_climbs(target.path()) {
        None
    } else {
        Some(NOT_ALLOWED)
    }
}

/// Percent-decoding rounds a forward path is checked through.
const PATH_DECODE_ROUNDS: usize = 3;

/// Whether `path` holds a `..` step as a target may read it: percent-decoded,
/// repeatedly so a double-encoded step counts, with `\` as a separator, and
/// with a segment's `;` parameters dropped, since servlet containers read
/// `..;/` as `../`. A path that is not UTF-8 once decoded, or still decodes
/// after the last round, counts as climbing.
fn path_climbs(path: &str) -> bool {
    let mut current = path.to_string();
    for _ in 0..PATH_DECODE_ROUNDS {
        if current
            .split(['/', '\\'])
            .any(|segment| segment.split(';').next() == Some(".."))
        {
            return true;
        }
        let Ok(decoded) = urlencoding::decode(&current) else {
            return true;
        };
        if decoded == current {
            return false;
        }
        current = decoded.into_owned();
    }
    true
}

/// Map an HTTP status onto a JSON-RPC error code for A2A/MCP-shaped
/// rejections. Deliberately coarse — the code conveys the class of failure
/// without exposing internal specifics.
fn jsonrpc_code_for_status(status: u16) -> i64 {
    match status {
        400 | 422 => -32600, // Invalid Request
        404 | 405 => -32601, // Method not found / not available
        _ => -32603,         // Internal error (403 / 502 / 503 / 504 / …)
    }
}

/// Extract the JSON-RPC `id` from a request body so it can be echoed back in an
/// error envelope (per JSON-RPC, the response id must match the request). Returns
/// `None` for non-JSON bodies or requests without an `id`.
pub fn extract_json_rpc_id(body: &[u8]) -> Option<Value> {
    serde_json::from_slice::<Value>(body)
        .ok()
        .and_then(|v| v.get("id").cloned())
}

/// Build the client-facing error body. Returns a JSON-RPC error envelope when the
/// request/surface speaks a JSON-RPC family (A2A/MCP), otherwise a generic
/// `{ "error": … }` object. Never contains target, url, method, port, or raw
/// error chains.
pub fn safe_error_client_body(
    status: u16,
    message: &str,
    json_rpc: bool,
    request_id: Option<Value>,
) -> String {
    let body = if json_rpc {
        json!({
            "jsonrpc": "2.0",
            "id": request_id.unwrap_or(Value::Null),
            "error": {
                "code": jsonrpc_code_for_status(status),
                "message": message,
            },
        })
    } else {
        json!({ "error": message })
    };
    body.to_string()
}

/// Build the full `ForwardResponse` `response_body` envelope for a safe
/// rejection/failure, mirroring the `{ status, headers, body }` shape GW1
/// already handles for successful and policy-denied responses.
pub fn safe_forward_error(
    status: u16,
    message: &str,
    json_rpc: bool,
    request_id: Option<Value>,
) -> Value {
    json!({
        "status": status,
        "headers": { "content-type": "application/json" },
        "body": safe_error_client_body(status, message, json_rpc, request_id),
        // Retained generic summary for GW-side logging; contains no routing detail.
        "error": message,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rpc_body_echoes_id_and_hides_internals() {
        let body = safe_error_client_body(502, "Failed to forward request to the target", true, Some(json!("req-1")));
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["jsonrpc"], "2.0");
        assert_eq!(v["id"], "req-1");
        assert_eq!(v["error"]["code"], -32603);
        // The generic message carries no routing internals: no resolved URL,
        // host:port, or reqwest error-chain field.
        assert!(!body.contains("://"));
        assert!(!body.contains("error_details"));
        // The envelope exposes only jsonrpc/id/error keys — never target/url.
        assert!(v.get("target").is_none());
        assert!(v.get("url").is_none());
    }

    #[test]
    fn generic_body_for_non_json_rpc() {
        let body = safe_error_client_body(503, "Channel is not active", false, None);
        let v: Value = serde_json::from_str(&body).unwrap();
        assert_eq!(v["error"], "Channel is not active");
        assert!(v.get("jsonrpc").is_none());
    }

    #[test]
    fn envelope_has_status_and_string_body() {
        let env = safe_forward_error(422, "Protocol mismatch", true, None);
        assert_eq!(env["status"], 422);
        assert!(env["body"].is_string());
        // id defaults to null when the request carried none.
        let inner: Value = serde_json::from_str(env["body"].as_str().unwrap()).unwrap();
        assert_eq!(inner["id"], Value::Null);
    }

    #[test]
    fn boundary_rejects_protocol_mismatch() {
        // MCP surface, but an A2A-shaped request body.
        let body = br#"{"jsonrpc":"2.0","method":"message/send","params":{}}"#;
        let rej = evaluate_forward_boundary(Some("mcp"), body, "https://target.example", "POST");
        assert_eq!(rej.unwrap().status, 422);
    }

    #[test]
    fn boundary_allows_matching_family() {
        let body = br#"{"jsonrpc":"2.0","method":"tools/call","params":{}}"#;
        assert_eq!(evaluate_forward_boundary(Some("mcp"), body, "https://target.example", "POST"), None);
    }

    #[test]
    fn boundary_ignores_ambiguous_body() {
        // Non-JSON-RPC body (e.g. agent-card GET) is never misclassified/rejected.
        assert_eq!(evaluate_forward_boundary(Some("a2a"), b"", "https://target.example", "GET"), None);
        assert_eq!(evaluate_forward_boundary(Some("a2a"), b"plain text", "https://target.example", "GET"), None);
    }

    #[test]
    fn boundary_rejects_unsupported_scheme() {
        let rej = evaluate_forward_boundary(None, b"", "fabric://gw/surface", "GET");
        assert_eq!(rej.unwrap().status, 502);
        // Embedded marketplace sentinel and http(s) are allowed.
        assert_eq!(evaluate_forward_boundary(None, b"", "embedded://marketplace", "POST"), None);
        assert_eq!(evaluate_forward_boundary(None, b"", "http://localhost:8080", "GET"), None);
    }

    #[test]
    fn boundary_rejects_unknown_method() {
        let rej = evaluate_forward_boundary(None, b"", "https://target.example", "CONNECT");
        assert_eq!(rej.unwrap().status, 405);
        // Case-insensitive accept of known verbs.
        assert_eq!(evaluate_forward_boundary(None, b"", "https://target.example", "post"), None);
    }

    #[test]
    fn missing_id_defaults_null() {
        assert_eq!(extract_json_rpc_id(b"not json"), None);
        assert_eq!(extract_json_rpc_id(br#"{"jsonrpc":"2.0","method":"tools/call"}"#), None);
        assert_eq!(extract_json_rpc_id(br#"{"jsonrpc":"2.0","id":7,"method":"tools/call"}"#), Some(json!(7)));
    }

    #[test]
    fn a_forward_path_stays_under_the_target_endpoint() {
        let target = |endpoint: &str, path: &str| {
            let url = crate::proxy::handler::join_endpoint_path(endpoint, path);
            evaluate_forward_target(endpoint, &url)
        };
        for (endpoint, path) in [
            ("https://upstream.example:9000", "/a2a"),
            ("https://upstream.example:9000", "/"),
            ("https://upstream.example:9000/api", "/v1/messages?stream=true"),
            ("https://upstream.example:9000/api/", "/"),
            ("https://upstream.example:9000/api", "/v1/files/report..final.pdf"),
            ("https://upstream.example:9000/api", "/v1/files/100%25done"),
            ("https://upstream.example:9000/api", "/v1/items;version=2/a%2Fb"),
            ("https://upstream.example:9000", "@evil.example/collect"),
            ("http://10.0.0.5:8080/base", "/x"),
        ] {
            assert_eq!(target(endpoint, path), None, "{endpoint} + {path} is allowed");
        }
    }

    #[test]
    fn a_forward_path_cannot_leave_the_target_endpoint() {
        let rejected = Some(BoundaryRejection {
            status: 400,
            message: "Request path is not allowed",
        });
        let target = |endpoint: &str, path: &str| {
            let url = crate::proxy::handler::join_endpoint_path(endpoint, path);
            evaluate_forward_target(endpoint, &url)
        };
        for path in [
            "/../admin",
            "/../../admin",
            "/v1/../../admin",
            "/%2e%2e/admin",
            "/%2E%2E/admin",
            "/v1/..%2fadmin",
            "/v1/%2e%2e%2f%2e%2e%2fadmin",
            "/v1/..%5cadmin",
            "/v1\\..\\..\\admin",
            "/v1/%ff",
            "/v1/..;/admin",
            "/v1/..;jsessionid=abc/admin",
            "/v1/%2e%2e;/admin",
            "/v1/%252e%252e%252fadmin",
            "/v1/%25252e%25252e%25252fadmin",
        ] {
            assert_eq!(target("https://upstream.example:9000/api", path), rejected, "{path} is refused");
        }
        assert_eq!(
            target("https://upstream.example:9000", "/../../etc/passwd"),
            None,
            "under a root endpoint `..` only reaches a path the peer could send directly"
        );
        assert_eq!(
            target("https://upstream.example:9000", "/a/%2e%2e%2f%2e%2e%2fb"),
            rejected,
            "an encoded climb is refused"
        );

        // A URL that is not the endpoint's own host, port, scheme or user info.
        for url in [
            "https://evil.example/collect",
            "https://upstream.example:9001/a2a",
            "http://upstream.example:9000/a2a",
            "https://user@upstream.example:9000/a2a",
            "not a url",
        ] {
            assert_eq!(evaluate_forward_target("https://upstream.example:9000", url), rejected, "{url} is refused");
        }
    }
}
