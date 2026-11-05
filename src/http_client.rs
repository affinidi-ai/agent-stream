//! Shared reqwest client factory.
//!
//! New outbound reqwest clients should come from one of these builders so that
//! security-relevant defaults (redirect policy, timeout, DNS validation, proxy
//! use) are applied consistently. Some outbound paths build their own client or
//! socket and are not covered here: the pipe executor's upstream clients, the
//! realtime WebSocket dial (`pipes::realtime`), and `outbound_fetch`.
//!
//! ## Builders
//!
//! | Function | Timeout | Redirect | DNS check at connect | `HTTP(S)_PROXY` | Typical use |
//! |---|---|---|---|---|---|
//! | [`external`] | 30 s | `none` | none | honoured | Fixed-vendor calls (Graph API) |
//! | [`external_with_redirect`] | 30 s | follows | none | honoured | OAuth flows that require redirect following |
//! | [`with_short_timeout`] | 10 s | `none` | none | honoured | JWKS fetch, low-latency probes |
//! | [`with_timeout`] | caller-supplied | `none` | none | honoured | Fixed-vendor calls with a runtime timeout |
//! | [`with_strict_validating_resolver`] | caller-supplied | `none` | strict: no loopback, private, link-local or metadata | ignored | User-supplied endpoints (LLM connection test, Langfuse, Slack and webhook integrations, marketplace purchase) |
//! | [`with_service_endpoint_resolver`] | caller-supplied | `none` | no loopback, link-local or metadata; private allowed | ignored | Operator-configured services (Judge/Jury, response-cache embedder, OAuth token endpoints) |
//! | [`proxy_with_timeout`] | caller-supplied | `none` | hostnames only: no metadata | ignored | Shared appliance client with connection pooling |
//!
//! A builder with a DNS check ignores `HTTP(S)_PROXY`, because a proxy would
//! resolve the host itself and bypass the check. reqwest does not call the
//! resolver for an IP-literal URL, so the DNS check covers hostnames only;
//! callers must validate IP literals themselves.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};

pub const EXTERNAL_TIMEOUT_SECS: u64 = 30;
pub const SHORT_TIMEOUT_SECS: u64 = 10;

/// Client for fixed-vendor endpoints. It does not re-check resolved addresses,
/// so a send to a user- or operator-supplied URL must use
/// [`with_strict_validating_resolver`] or [`with_service_endpoint_resolver`].
///
/// - 30-second request timeout
/// - Redirects disabled (SSRF guard — a redirect to an internal address would
///   bypass the URL validation performed before the first request)
pub fn external() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(EXTERNAL_TIMEOUT_SECS))
}

/// External client that follows redirects.
///
/// - 30-second request timeout
/// - Follows redirects (default policy)
///
/// Use only when the target is a verified external endpoint that requires
/// redirect following (e.g. OAuth authorization flows). Do not use for
/// user-supplied URLs — redirects can bypass SSRF guards.
#[allow(dead_code)]
pub fn external_with_redirect() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(EXTERNAL_TIMEOUT_SECS))
        .build()
        .context("Failed to build external HTTP client with redirect")
}

/// Short-timeout client for fast probes (JWKS fetch, low-latency calls).
///
/// - 10-second request timeout
/// - Redirects disabled
pub fn with_short_timeout() -> Result<reqwest::Client> {
    with_timeout(Duration::from_secs(SHORT_TIMEOUT_SECS))
}

/// Client with a caller-supplied timeout, redirects disabled.
///
/// - Caller-supplied request timeout
/// - Redirects disabled
/// - Honours `HTTP_PROXY` / `HTTPS_PROXY` / `NO_PROXY`. It has no DNS resolver
///   for a proxy to bypass, and fixed-vendor calls (JWKS, Graph API) must keep
///   working behind a mandatory egress proxy.
///
/// Use when the timeout is determined at runtime (e.g. per-pipe target config).
pub fn with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .context("Failed to build HTTP client")
}

/// Client with a caller-supplied timeout, redirects disabled, proxy disabled,
/// and the strict webhook DNS resolver wired in.
///
/// The resolver re-validates every resolved IP at connection time against the
/// strict SSRF policy (`is_blocked_resolved_webhook_ip`), so a user-supplied endpoint that
/// passed a pre-request URL check cannot rebind to an internal address between
/// validation and the request (DNS-rebinding TOCTOU). `no_proxy()` prevents an
/// ambient proxy from resolving DNS out-of-band and bypassing the resolver.
///
/// Use for user-supplied endpoints that must never reach internal networks
/// (e.g. the pipe LLM connection-test path).
pub fn with_strict_validating_resolver(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(crate::url_validation::WebhookDnsResolver))
        .build()
        .context("Failed to build strict validating HTTP client")
}

/// Client for operator-configured service endpoints that may legitimately be
/// private, such as same-VPC providers. DNS is still revalidated at connect
/// time so a hostname cannot rebind to loopback, unspecified, link-local or
/// metadata addresses after configuration validation.
pub fn with_service_endpoint_resolver(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(crate::url_validation::ServiceEndpointDnsResolver))
        .build()
        .context("Failed to build service endpoint HTTP client")
}

/// Connection-pooled client shared across the appliance (gateway and fabric
/// calls, among others).
///
/// - Caller-supplied request timeout
/// - Redirects disabled (target auth travels in custom headers that reqwest
///   would not strip on a cross-origin redirect)
/// - Forwarding DNS validation at connection time for hostnames: one that
///   resolves to a cloud metadata address is refused, loopback and private
///   targets are allowed. An IP-literal URL (e.g. `http://169.254.169.254/`) is
///   not resolved, so it is not checked here.
/// - Connection pool tuned for sustained agent-to-agent traffic
pub fn proxy_with_timeout(timeout: Duration) -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .dns_resolver(Arc::new(crate::url_validation::ForwardingDnsResolver))
        .pool_max_idle_per_host(10)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_keepalive(Duration::from_secs(60))
        .user_agent("Affinidi-Fabric-Agent-Stream/1.0")
        .build()
        .context("Failed to build proxy HTTP client")
}

/// Read at most `limit` bytes of a response body, refusing a longer one
/// (declared or streamed) rather than buffering it.
pub(crate) async fn read_capped(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, String> {
    if response
        .content_length()
        .is_some_and(|declared| declared > limit as u64)
    {
        return Err(format!("response exceeds the {limit} byte limit"));
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| format!("failed to read response body: {e}"))?
    {
        if body.len() + chunk.len() > limit {
            return Err(format!("response exceeds the {limit} byte limit"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn proxy_client_reaches_localhost_named_target() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener
            .local_addr()
            .unwrap()
            .port();
        tokio::spawn(async move {
            let (mut socket, _) = listener
                .accept()
                .await
                .unwrap();
            let mut request = [0u8; 1024];
            let _ = socket
                .read(&mut request)
                .await;
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
                .await
                .unwrap();
        });

        let response = proxy_with_timeout(Duration::from_secs(5))
            .unwrap()
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .expect("localhost-named forwarding target must be reachable");
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(response.text().await.unwrap(), "ok");
    }

    /// The proxy client injects target auth as custom headers, which reqwest
    /// does not strip on a cross-origin redirect, and a redirect to an IP
    /// literal would skip the DNS resolver, so it must never follow one.
    #[tokio::test]
    async fn proxy_client_does_not_follow_redirects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap();
        let port = listener
            .local_addr()
            .unwrap()
            .port();
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = served.clone();
        tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let mut request = [0u8; 1024];
                let _ = socket
                    .read(&mut request)
                    .await;
                let response = format!(
                    "HTTP/1.1 302 Found\r\nlocation: http://localhost:{port}/x\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = socket
                    .write_all(response.as_bytes())
                    .await;
            }
        });

        let response = proxy_with_timeout(Duration::from_secs(5))
            .unwrap()
            .get(format!("http://localhost:{port}/"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::FOUND);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1, "the redirect must not be followed");
    }

    fn response(body: &'static str) -> reqwest::Response {
        reqwest::Response::from(axum::http::Response::new(body))
    }

    #[tokio::test]
    async fn read_capped_keeps_a_body_within_the_limit() {
        let body = read_capped(response(r#"{"providers":[]}"#), 64)
            .await
            .unwrap();
        assert_eq!(body, br#"{"providers":[]}"#);
    }

    #[tokio::test]
    async fn read_capped_refuses_a_body_past_the_limit() {
        let error = read_capped(response("0123456789"), 4)
            .await
            .unwrap_err();
        assert!(error.contains("4 byte limit"), "{error}");
    }
}
