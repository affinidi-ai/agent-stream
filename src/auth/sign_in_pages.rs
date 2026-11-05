//! The HTML pages an SSO sign-in ends on, shown in the browser straight from
//! the identity provider: the page that hands the new session to the
//! dashboard, and the page that explains a refusal.

/// Encode a string as a JavaScript string literal safe to embed inside an
/// inline `<script>` element: serde_json covers the JS string context
/// (quotes/escapes `"` and `\`), and escaping `<`, `>`, `&` to `\uXXXX` stops a
/// value containing `</script>` from closing the element (HTML-context XSS).
fn js_string_literal(s: &str) -> String {
    serde_json::to_string(s)
        .unwrap_or_else(|_| "\"\"".to_string())
        .replace('<', "\\u003c")
        .replace('>', "\\u003e")
        .replace('&', "\\u0026")
}

/// The page that hands a new session to the dashboard and redirects to it, with the policy that lets only its own script run. The token is emitted
/// as a JS string literal safe for an inline `<script>` (see
/// [`js_string_literal`]).
/// Escape text for HTML content or a double-quoted attribute value.
fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// `return_path` is where the dashboard opens: `/`, or a path on this origin
/// that the caller has already checked (see `auth::oidc::initiate`).
pub(crate) fn login_success_page(
    session_token: &str,
    return_path: &str,
) -> (axum::http::HeaderValue, String) {
    let nonce = crate::proxy::security_headers::script_nonce();
    let html = format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Login Successful</title>
    <meta http-equiv="refresh" content="0;url={}">
    <script nonce="{}">
        sessionStorage.setItem('session_token', {});
        window.location.href = {};
    </script>
</head>
<body>
    <p>Login successful. Redirecting...</p>
</body>
</html>"#,
        html_escape(return_path),
        nonce,
        js_string_literal(session_token),
        js_string_literal(return_path)
    );
    (crate::proxy::security_headers::inline_script_page_csp(&nonce), html)
}

/// Render a minimal, self-contained HTML page shown when an SSO sign-in is
/// refused (e.g. the appliance user limit is reached). The message is HTML-escaped.
pub(crate) fn sign_in_error_page(message: &str) -> String {
    let escaped = html_escape(message);
    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <title>Sign-in unavailable</title>
    <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family: system-ui, sans-serif; max-width: 32rem; margin: 4rem auto; padding: 0 1rem; color: #1f2937;">
    <h1 style="font-size: 1.25rem;">Sign-in unavailable</h1>
    <p>{escaped}</p>
    <p style="color: #6b7280;">Please contact your administrator, then <a href="/">try again</a>.</p>
</body>
</html>"#
    )
}

#[cfg(test)]
mod tests {
    use super::{js_string_literal, login_success_page, sign_in_error_page};

    #[test]
    fn the_login_page_script_carries_the_nonce_its_policy_allows() {
        let (csp, html) = login_success_page("tok\"</script><script>alert(1)</script>", "/");
        let csp = csp.to_str().unwrap();
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|rest| rest.split('\'').next())
            .unwrap();

        assert!(html.contains(&format!("<script nonce=\"{nonce}\">")), "{html}");
        assert_eq!(
            html.matches("<script")
                .count(),
            1,
            "only the page's own script: {html}"
        );
        assert!(csp.contains(&format!("script-src 'nonce-{nonce}';")), "only the nonce may run script: {csp}");
        assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
        assert_ne!(login_success_page("tok", "/").0, login_success_page("tok", "/").0, "a fresh nonce per page");
    }

    #[test]
    fn js_string_literal_escapes_script_close_and_quotes() {
        // A benign id round-trips as a quoted literal.
        assert_eq!(js_string_literal("abc-123"), "\"abc-123\"");
        // A value trying to break out of the <script> element is neutralised:
        // no literal "</script>" and no unescaped quote survive.
        let out = js_string_literal("a\"</script><script>alert(1)</script>");
        assert!(!out.contains("</script>"), "must not contain a literal </script>: {out}");
        assert!(!out.contains('<'), "all < escaped: {out}");
        assert!(out.contains("\\u003c"));
        assert!(out.contains("\\\""), "inner quote escaped: {out}");
    }

    #[test]
    fn the_login_page_opens_the_return_path_without_letting_it_escape() {
        let (_, html) = login_success_page("tok", "/surfaces?tab=a&b=\"</script>'");

        assert!(html.contains(r#"content="0;url=/surfaces?tab=a&amp;b=&quot;&lt;/script&gt;&#39;""#), "{html}");
        assert!(html.contains(r#"window.location.href = "/surfaces?tab=a\u0026b=\"\u003c/script\u003e'";"#), "{html}");
        assert_eq!(
            html.matches("</script>")
                .count(),
            1,
            "only the page's own script closes: {html}"
        );
    }

    #[test]
    fn the_error_page_escapes_its_message() {
        let html = sign_in_error_page("a <b> & \"c\"");

        assert!(html.contains("<p>a &lt;b&gt; &amp; &quot;c&quot;</p>"), "{html}");
    }
}
