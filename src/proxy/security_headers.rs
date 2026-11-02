//! Browser security headers on every listener response.
//!
//! Each header is set only when the handler has not set it, so a response
//! with stricter needs (an upload, a page with its own script nonce) keeps
//! its own value.

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{
    CONTENT_SECURITY_POLICY, CONTENT_TYPE, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, X_CONTENT_TYPE_OPTIONS,
    X_FRAME_OPTIONS,
};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine as _;
use rand::RngCore;

/// The dashboard's policy: scripts only from the appliance and the Bootstrap
/// CDN, styles and fonts from the appliance and the CDNs `index.html` loads,
/// and no framing. `connect-src` admits any `https`/`wss` origin because the
/// dashboard's sandboxes call operator-configured identity providers and
/// Surface Access Points on other hosts.
pub const DASHBOARD_CSP: &str = "default-src 'self'; \
     script-src 'self' https://cdn.jsdelivr.net; \
     style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net; \
     font-src 'self' data: https://cdnjs.cloudflare.com https://fonts.gstatic.com https://cdn.jsdelivr.net; \
     img-src 'self' data: blob: https:; \
     connect-src 'self' https: wss:; \
     media-src 'self' blob:; \
     object-src 'none'; \
     base-uri 'self'; \
     form-action 'self'; \
     frame-ancestors 'none'";

/// Every response that is not a page: nothing in it may load or be framed.
pub const NON_HTML_CSP: &str = "default-src 'none'; frame-ancestors 'none'";

/// One year, without `includeSubDomains`: the appliance may share a parent
/// domain with hosts it does not control.
const HSTS: &str = "max-age=31536000";

/// Add the security headers a response lacks. `tls` is whether the listener
/// serves HTTPS; only then is `Strict-Transport-Security` sent.
pub async fn set_security_headers(
    State(tls): State<bool>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let is_html = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value
                .trim_start()
                .to_ascii_lowercase()
                .starts_with("text/html")
        });
    let headers = response.headers_mut();
    let csp = if is_html {
        DASHBOARD_CSP
    } else {
        NON_HTML_CSP
    };
    for (name, value) in [
        (CONTENT_SECURITY_POLICY, csp),
        (X_CONTENT_TYPE_OPTIONS, "nosniff"),
        (X_FRAME_OPTIONS, "DENY"),
        (REFERRER_POLICY, "strict-origin-when-cross-origin"),
    ] {
        if !headers.contains_key(&name) {
            headers.insert(name, HeaderValue::from_static(value));
        }
    }
    if tls && !headers.contains_key(STRICT_TRANSPORT_SECURITY) {
        headers.insert(STRICT_TRANSPORT_SECURITY, HeaderValue::from_static(HSTS));
    }
    response
}

/// A fresh nonce for one page's inline script: 16 random bytes,
/// base64-encoded.
pub fn script_nonce() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

/// The policy for a self-contained server page whose only script carries
/// `nonce`: that script runs, inline styles apply, nothing else loads, and the
/// page cannot be framed.
pub fn inline_script_page_csp(nonce: &str) -> HeaderValue {
    HeaderValue::from_str(&format!(
        "default-src 'none'; script-src 'nonce-{nonce}'; style-src 'unsafe-inline'; \
         base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    ))
    .expect("a base64 nonce is a valid header value")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Router;
    use axum::body::Body;
    use axum::response::{Html, IntoResponse, Json};
    use axum::routing::get;
    use tower::ServiceExt;

    fn app(tls: bool) -> Router {
        Router::new()
            .route("/page", get(|| async { Html("<p>dashboard</p>") }))
            .route("/api", get(|| async { Json(serde_json::json!({ "ok": true })) }))
            .route(
                "/own-policy",
                get(|| async {
                    let mut response = Html("<script nonce=\"n\"></script>").into_response();
                    response
                        .headers_mut()
                        .insert(CONTENT_SECURITY_POLICY, inline_script_page_csp("n"));
                    response
                }),
            )
            .layer(axum::middleware::from_fn_with_state(tls, set_security_headers))
    }

    async fn headers(
        app: Router,
        path: &str,
    ) -> axum::http::HeaderMap {
        app.oneshot(
            Request::get(path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
        .headers()
        .clone()
    }

    #[tokio::test]
    async fn a_page_gets_the_dashboard_policy_and_every_response_the_common_headers() {
        let page = headers(app(true), "/page").await;
        assert_eq!(page[CONTENT_SECURITY_POLICY], DASHBOARD_CSP);
        let api = headers(app(true), "/api").await;
        assert_eq!(api[CONTENT_SECURITY_POLICY], NON_HTML_CSP);
        for headers in [page, api] {
            assert_eq!(headers[X_CONTENT_TYPE_OPTIONS], "nosniff");
            assert_eq!(headers[X_FRAME_OPTIONS], "DENY");
            assert_eq!(headers[REFERRER_POLICY], "strict-origin-when-cross-origin");
            assert_eq!(headers[STRICT_TRANSPORT_SECURITY], HSTS);
        }
    }

    #[tokio::test]
    async fn plain_http_sends_no_hsts() {
        assert!(
            !headers(app(false), "/page")
                .await
                .contains_key(STRICT_TRANSPORT_SECURITY)
        );
    }

    #[tokio::test]
    async fn a_handlers_own_policy_is_kept() {
        let headers = headers(app(true), "/own-policy").await;
        assert_eq!(headers[CONTENT_SECURITY_POLICY], inline_script_page_csp("n"));
        assert_eq!(headers[X_FRAME_OPTIONS], "DENY");
    }

    #[test]
    fn the_dashboard_policy_allows_no_inline_or_evaluated_script() {
        let script_src = DASHBOARD_CSP
            .split(';')
            .map(str::trim)
            .find(|directive| directive.starts_with("script-src"))
            .unwrap();
        assert!(!script_src.contains("'unsafe-inline'"), "{script_src}");
        assert!(!script_src.contains("'unsafe-eval'"), "{script_src}");
        assert!(DASHBOARD_CSP.contains("frame-ancestors 'none'"));
        assert!(DASHBOARD_CSP.contains("object-src 'none'"));
    }

    #[test]
    fn nonces_are_fresh() {
        assert_ne!(script_nonce(), script_nonce());
        assert_eq!(script_nonce().len(), 24);
    }
}
