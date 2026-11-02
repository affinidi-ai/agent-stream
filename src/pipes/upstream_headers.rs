//! Extra request headers an LLM surface sends to its own upstream.
//!
//! An upstream can sit behind something that authenticates the gateway
//! separately from the model's own credential — a reverse proxy, a mesh
//! ingress, or a tunnel whose ingress requires its own key. Before this, the
//! only provider type that could send such a header was `custom`, and it had
//! exactly one header slot, which the model's own API key already occupied. The
//! operator's only way out was to leave the upstream unauthenticated.
//!
//! `upstream_headers` closes that: any LLM provider may carry extra headers
//! alongside its own auth, each value read from the secrets store at request
//! time (never stored in the surface config).
//!
//! These headers belong to the upstream they were configured for, so they are
//! sent **only** to the surface's own configured provider — never to a Decider
//! candidate, a failover/load-balancing target, or a variant that swaps the
//! upstream without declaring its own.

use serde::{Deserialize, Serialize};

/// One extra header sent to the surface's own upstream, its value resolved
/// from the secrets store at request time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpstreamHeader {
    /// Header name, e.g. `x-asp-api-key`.
    pub name: String,
    /// Secret reference (internal id or public secret id) holding the value.
    pub secret_id: String,
}

/// Header names an operator may not claim: the provider auth headers every
/// `build_headers` implementation writes, the hop-by-hop and entity headers the
/// HTTP client owns, and the gateway's own request plumbing.
const RESERVED_HEADER_NAMES: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "anthropic-version",
    "content-type",
    "content-length",
    "host",
    "connection",
    "transfer-encoding",
    "te",
    "trailer",
    "upgrade",
];

/// Gateway-owned header prefix; an upstream header may not shadow it.
const RESERVED_HEADER_PREFIX: &str = "x-agent-stream-";

/// Upper bound on configured extra headers, so a surface config cannot turn
/// into an unbounded per-request secret-store fan-out.
const MAX_UPSTREAM_HEADERS: usize = 16;

fn is_valid_header_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// Validate a surface's `upstream_headers` at save time: well-formed names, no
/// provider/gateway header hijacking, no duplicates, and a secret reference on
/// every entry.
pub fn validate(headers: &[UpstreamHeader]) -> Result<(), String> {
    if headers.len() > MAX_UPSTREAM_HEADERS {
        return Err(format!(
            "at most {} upstream headers may be configured ({} given)",
            MAX_UPSTREAM_HEADERS,
            headers.len()
        ));
    }

    let mut seen: Vec<String> = Vec::with_capacity(headers.len());
    for header in headers {
        // Validated exactly as sent (`append_target_headers` pushes the name
        // untouched), so surrounding whitespace fails here, not at send time.
        let name = header.name.as_str();
        if !is_valid_header_name(name) {
            return Err(format!("upstream header name '{}' is not a valid HTTP header name", name));
        }
        let lower = name.to_ascii_lowercase();
        if RESERVED_HEADER_NAMES.contains(&lower.as_str()) {
            return Err(format!(
                "upstream header '{}' is reserved — it carries the provider's own credential or is set by the \
                 gateway; use the provider's API key secret instead",
                name
            ));
        }
        if lower.starts_with(RESERVED_HEADER_PREFIX) {
            return Err(format!("upstream header '{}' is reserved for the gateway's own headers", name));
        }
        if seen.contains(&lower) {
            return Err(format!("upstream header '{}' is configured more than once", name));
        }
        if header
            .secret_id
            .trim()
            .is_empty()
        {
            return Err(format!("upstream header '{}' needs a secret reference for its value", name));
        }
        seen.push(lower);
    }
    Ok(())
}

/// Whether `request_url` is on the origin (scheme, host and port) of
/// `configured_for`, the endpoint a set of headers was configured for. The
/// headers are that endpoint's credential, so they are sent to no other
/// origin. Anything that does not parse as an absolute URL never matches.
pub fn same_origin(
    configured_for: &str,
    request_url: &str,
) -> bool {
    match (url::Url::parse(configured_for), url::Url::parse(request_url)) {
        (Ok(configured), Ok(request)) => {
            let origin = configured.origin();
            origin.is_tuple() && origin == request.origin()
        }
        _ => false,
    }
}

/// Refuse to send `headers` (configured for `configured_for`) with a request to
/// `request_url` on any other origin.
pub fn ensure_same_origin(
    pipe_id: &str,
    headers: &[UpstreamHeader],
    configured_for: &str,
    request_url: &str,
) -> Result<(), crate::pipes::executor::PipeError> {
    if headers.is_empty() || same_origin(configured_for, request_url) {
        return Ok(());
    }
    tracing::warn!(
        pipe = ?pipe_id,
        configured_for = ?crate::url_validation::redact_url_for_logging(configured_for),
        request_url = ?crate::url_validation::redact_url_for_logging(request_url),
        "upstream headers refused: the request is not to the endpoint they were configured for"
    );
    Err(crate::pipes::executor::PipeError::RequestFailed(HEADERS_OFF_ORIGIN.to_string()))
}

/// What the caller of a surface is told when an upstream's headers would go to
/// an origin other than the endpoint they were configured for.
pub const HEADERS_OFF_ORIGIN: &str =
    "The upstream headers of this call belong to another endpoint, so the call was not sent";

/// What the caller of a surface, and its governance record, are told when a
/// credential an upstream needs (its key or a header's secret) cannot be
/// used. The secret reference names the operator's secrets, so it goes to the
/// log line only.
pub const CREDENTIAL_UNAVAILABLE: &str = "An upstream credential this surface needs is unavailable";

/// Log why `credential` (`reference`) cannot be used and return the generic
/// [`CREDENTIAL_UNAVAILABLE`] error the caller sees.
pub fn credential_unavailable(
    pipe_id: &str,
    credential: &str,
    reference: &str,
    cause: &str,
) -> crate::pipes::executor::PipeError {
    tracing::warn!(
        pipe = ?pipe_id,
        credential = ?credential,
        reference = ?reference,
        cause = ?cause,
        "upstream credential unavailable"
    );
    crate::pipes::executor::PipeError::RequestFailed(CREDENTIAL_UNAVAILABLE.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(
        name: &str,
        secret: &str,
    ) -> UpstreamHeader {
        UpstreamHeader {
            name: name.to_string(),
            secret_id: secret.to_string(),
        }
    }

    #[test]
    fn empty_and_well_formed_lists_validate() {
        assert_eq!(validate(&[]), Ok(()));
        assert_eq!(validate(&[header("x-asp-api-key", "secret-1"), header("x-tenant", "secret-2")]), Ok(()));
    }

    #[test]
    fn provider_credential_headers_are_rejected() {
        for name in ["Authorization", "x-api-key", "API-Key", "x-goog-api-key", "anthropic-version"] {
            let err = validate(&[header(name, "secret-1")]).expect_err("reserved name must be refused");
            assert!(err.contains("reserved"), "unexpected error for {name}: {err}");
        }
    }

    #[test]
    fn gateway_prefixed_and_malformed_names_are_rejected() {
        assert!(
            validate(&[header("x-agent-stream-upstream-authorization", "s")])
                .unwrap_err()
                .contains("reserved for the gateway")
        );
        assert!(
            validate(&[header("bad header", "s")])
                .unwrap_err()
                .contains("not a valid HTTP header name")
        );
        assert!(
            validate(&[header("", "s")])
                .unwrap_err()
                .contains("not a valid HTTP header name")
        );
    }

    #[test]
    fn surrounding_whitespace_is_rejected_rather_than_trimmed() {
        for name in [" x-asp-api-key", "x-asp-api-key ", "\tx-asp-api-key"] {
            let err = validate(&[header(name, "s")]).expect_err("untrimmed name must be refused");
            assert!(err.contains("not a valid HTTP header name"), "unexpected error for {name:?}: {err}");
        }
    }

    #[test]
    fn duplicates_and_missing_secrets_are_rejected() {
        assert!(
            validate(&[header("x-asp-api-key", "a"), header("X-ASP-API-KEY", "b")])
                .unwrap_err()
                .contains("more than once")
        );
        assert!(
            validate(&[header("x-asp-api-key", "  ")])
                .unwrap_err()
                .contains("needs a secret reference")
        );
    }

    #[test]
    fn the_list_is_bounded() {
        let many: Vec<UpstreamHeader> = (0..=MAX_UPSTREAM_HEADERS)
            .map(|i| header(&format!("x-h-{i}"), "s"))
            .collect();
        assert!(
            validate(&many)
                .unwrap_err()
                .contains("at most")
        );
    }

    #[test]
    fn round_trips_through_json() {
        let parsed: Vec<UpstreamHeader> =
            serde_json::from_str(r#"[{"name":"x-asp-api-key","secret_id":"sec-1"}]"#).expect("parse");
        assert_eq!(parsed, vec![header("x-asp-api-key", "sec-1")]);
        assert_eq!(
            serde_json::to_string(&parsed).expect("serialize"),
            r#"[{"name":"x-asp-api-key","secret_id":"sec-1"}]"#
        );
    }
}
