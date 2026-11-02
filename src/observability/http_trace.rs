//! Custom HTTP tracing middleware that uses agent-stream as the target
//!
//! This ensures HTTP request spans pass through our OpenTelemetry filter

use axum::{extract::Request, middleware::Next, response::Response};
use opentelemetry::global;
use opentelemetry::trace::TraceContextExt;
use tracing::{Instrument, Level, debug, info};
use tracing_opentelemetry::OpenTelemetrySpanExt;

/// Returns true for paths that serve dashboard/UX static assets — these are
/// noisy (one request per JS/CSS/map/image) and only useful when actively
/// debugging the management UI, so we drop them to DEBUG.
fn is_static_asset_path(path: &str) -> bool {
    if path.starts_with("/static/") {
        return true;
    }
    // Catch hashed top-level bundles, source maps, and common dashboard
    // asset types served from `/` or other UI prefixes.
    matches!(
        std::path::Path::new(path)
            .extension()
            .and_then(|e| e.to_str()),
        Some(
            "js" | "css"
                | "map"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "ico"
                | "webp"
                | "woff"
                | "woff2"
                | "ttf"
                | "eot"
        )
    )
}

/// Returns true for the dashboard's management API — high-volume polling
/// (surfaces, channels, metrics, health) that adds no signal to normal logs.
fn is_management_api_path(path: &str) -> bool {
    path.starts_with("/api/")
}

/// Returns true for DID:web document resolution endpoints served by the
/// gateway (e.g. `/connection-points/{id}/did.json`, `/.well-known/did.json`).
/// These are polled frequently by remote DID resolvers and add no signal.
fn is_did_resolution_path(path: &str) -> bool {
    path.ends_with("/did.json")
}

fn is_noisy_path(path: &str) -> bool {
    is_static_asset_path(path) || is_management_api_path(path) || is_did_resolution_path(path)
}

/// Returns true for dashboard SPA page loads — the React app is served as
/// `index.html` for any non-API/non-asset path, and a browser navigation or
/// refresh shows up as a GET with `Accept: text/html`. These are user UI
/// navigations, not backend traffic worth INFO-level visibility.
fn is_spa_html_navigation(
    method: &axum::http::Method,
    accept: &str,
) -> bool {
    method == axum::http::Method::GET && accept.contains("text/html")
}

/// Query string with every parameter value replaced, so the access log keeps the
/// parameter names without credentials such as an OAuth `code` or a `token`.
fn redact_query_values(query: &str) -> String {
    query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((name, _)) => format!("{name}=<redacted>"),
            None => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Path and query of `uri` as they may appear in logs and trace spans, with every
/// query parameter value redacted.
fn loggable_uri(uri: &axum::http::Uri) -> String {
    match uri.query() {
        Some(query) => format!("{}?{}", uri.path(), redact_query_values(query)),
        None => uri.path().to_string(),
    }
}

/// Unconditional access log: logs every inbound HTTP request with method, path,
/// query parameter names, forwarded-for address, and a small set of headers useful for debugging external
/// integrations (Accept, Host, User-Agent, Origin, MCP session id).
///
/// Logged at INFO so it surfaces in normal logs without enabling debug. Useful
/// for diagnosing situations where a client (e.g. Microsoft Copilot Studio)
/// reaches the gateway but doesn't trigger any channel handler — for instance
/// when it sends a probe GET, OPTIONS preflight, or hits an unmapped route.
///
/// Dashboard/UX static asset requests (JS/CSS/maps/images under `/static/` or
/// with a known asset extension) are logged at DEBUG instead — they're high
/// volume and add no signal for backend troubleshooting.
pub async fn access_log(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();
    let logged_uri = loggable_uri(&uri);
    let headers = request.headers();
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let accept = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let origin = headers
        .get("origin")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let mcp_session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xfwd_for = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let xfwd_proto = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let is_asset = is_noisy_path(&path) || is_spa_html_navigation(&method, &accept);

    if is_asset {
        debug!(
            target: "agent-stream::access",
            "➡️  HTTP {} {} host=\"{}\" accept=\"{}\" ua=\"{}\" origin=\"{}\" mcp_sid=\"{}\" xff=\"{}\" xfp=\"{}\"",
            method,
            logged_uri,
            host,
            accept,
            user_agent,
            origin,
            mcp_session_id,
            xfwd_for,
            xfwd_proto,
        );
    } else {
        info!(
            target: "agent-stream::access",
            "➡️  HTTP {} {} host=\"{}\" accept=\"{}\" ua=\"{}\" origin=\"{}\" mcp_sid=\"{}\" xff=\"{}\" xfp=\"{}\"",
            method,
            logged_uri,
            host,
            accept,
            user_agent,
            origin,
            mcp_session_id,
            xfwd_for,
            xfwd_proto,
        );
    }

    let started = std::time::Instant::now();
    let response = next.run(request).await;
    let status = response.status();
    let elapsed_ms = started.elapsed().as_millis();
    let resp_ct = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if is_asset {
        debug!(
            target: "agent-stream::access",
            "⬅️  HTTP {} {} → {} ({}ms) content-type=\"{}\"",
            method, path, status.as_u16(), elapsed_ms, resp_ct
        );
    } else {
        info!(
            target: "agent-stream::access",
            "⬅️  HTTP {} {} → {} ({}ms) content-type=\"{}\"",
            method, path, status.as_u16(), elapsed_ms, resp_ct
        );
    }
    response
}

/// Check if a request path should be traced
/// Returns true ONLY for agent-to-agent communication, NOT dashboard/API calls
///
/// This dynamically checks against registered channel and pipe prefixes.
/// Prefixes are registered when channels/pipes are created.
///
/// This traces ONLY:
/// - A2A/MCP protocol traffic (agents using channels) - based on registered channel prefixes
/// - LLM pipe traffic (agents using pipes) - based on registered pipe prefixes
/// - Background tasks are traced separately via spawn_traced_task
///
/// This does NOT trace:
/// - Identity API endpoints (dashboard/UX)
/// - Metrics, logs, monitoring endpoints
/// - Static files
#[allow(dead_code)]
fn should_trace_request(path: &str) -> bool {
    // Use the dynamic trace registry to check if this path should be traced
    super::should_trace_path(path)
}

/// Middleware that creates a root span for each HTTP request
///
/// This extracts trace context from HTTP headers if present (W3C traceparent),
/// otherwise creates a new root span.
///
/// Only business logic endpoints are traced (opt-in approach).
pub async fn trace_http_request(
    request: Request,
    next: Next,
) -> Response {
    let method = request.method().clone();
    let uri = request.uri().clone();
    let path = uri.path().to_string();

    // Check if this path should be traced and get its human-readable name
    let trace_info = super::get_trace_info(&path);
    if trace_info.is_none() {
        return next.run(request).await;
    }

    let (entity_name, _entity_type) = trace_info.unwrap();

    // Create a human-readable span name using the entity name
    // entity_name already includes the [TYPE] prefix (e.g., "[CHANNEL] GW1 A2A Direct")
    // So the final span name will be like "POST [CHANNEL] GW1 A2A Direct"
    let span_name = format!("{} {}", method, entity_name);

    // Extract trace context from HTTP headers if present
    let parent_context = global::get_text_map_propagator(|propagator| {
        use opentelemetry::propagation::Extractor;

        struct HeaderExtractor<'a>(&'a axum::http::HeaderMap);

        impl<'a> Extractor for HeaderExtractor<'a> {
            fn get(
                &self,
                key: &str,
            ) -> Option<&str> {
                self.0
                    .get(key)
                    .and_then(|v| v.to_str().ok())
            }

            fn keys(&self) -> Vec<&str> {
                self.0
                    .keys()
                    .map(|k| k.as_str())
                    .collect()
            }
        }

        propagator.extract(&HeaderExtractor(request.headers()))
    });

    // Check if we got a valid parent context
    let has_parent = parent_context
        .span()
        .span_context()
        .is_valid();

    // Create a span with agent-stream as the target
    // If there's a valid parent context, use it; otherwise create a root span
    let span = if has_parent {
        tracing::span!(
            target: "agent-stream",
            Level::INFO,
            "http.request",
            otel.name = %span_name,
            http.method = %method,
            http.uri = %loggable_uri(&uri),
            http.path = %path,
            http.status_code = tracing::field::Empty,
        )
    } else {
        tracing::span!(
            target: "agent-stream",
            parent: None,
            Level::INFO,
            "http.request",
            otel.name = %span_name,
            http.method = %method,
            http.uri = %loggable_uri(&uri),
            http.path = %path,
            http.status_code = tracing::field::Empty,
        )
    };

    // Set the parent context if we extracted one
    if has_parent {
        let _ = span.set_parent(parent_context);
    }

    // Use .instrument() to properly scope the async operation within the span
    async move {
        let response = next.run(request).await;
        let status = response.status();

        // Record status while span is active
        tracing::Span::current().record("http.status_code", status.as_u16());

        response
    }
    .instrument(span)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redact_query_values_keeps_names_and_hides_values() {
        assert_eq!(redact_query_values("code=abc123&state=xyz"), "code=<redacted>&state=<redacted>");
    }

    #[test]
    fn redact_query_values_hides_values_containing_equals_signs() {
        assert_eq!(redact_query_values("token=a=b=c"), "token=<redacted>");
    }

    #[test]
    fn redact_query_values_keeps_valueless_flags() {
        assert_eq!(redact_query_values("stream&key=secret"), "stream&key=<redacted>");
    }

    #[test]
    fn redact_query_values_of_empty_query_is_empty() {
        assert_eq!(redact_query_values(""), "");
    }

    #[test]
    fn loggable_uri_redacts_query_values() {
        let uri: axum::http::Uri = "/v1/chat?code=abc123&token=xyz"
            .parse()
            .unwrap();
        let logged = loggable_uri(&uri);
        assert_eq!(logged, "/v1/chat?code=<redacted>&token=<redacted>");
        assert!(!logged.contains("abc123"));
        assert!(!logged.contains("xyz"));
    }

    #[test]
    fn loggable_uri_without_query_is_the_path() {
        let uri: axum::http::Uri = "/v1/chat".parse().unwrap();
        assert_eq!(loggable_uri(&uri), "/v1/chat");
    }

    #[tokio::test]
    async fn access_log_redacts_query_values() {
        use tower::ServiceExt;

        let app = axum::Router::new()
            .route("/v1/callback", axum::routing::get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(access_log));
        let request = Request::builder()
            .uri("/v1/callback?code=secret-code&state=s1")
            .body(axum::body::Body::empty())
            .unwrap();

        let (logs, response) = crate::observability::log_capture::capture_logs(app.oneshot(request)).await;

        assert_eq!(response.unwrap().status(), axum::http::StatusCode::OK);
        assert!(logs.contains("/v1/callback?code=<redacted>&state=<redacted>"), "{logs}");
        assert!(!logs.contains("secret-code"), "a log holds a query value: {logs}");
    }
}
