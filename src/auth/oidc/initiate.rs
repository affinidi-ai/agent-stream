//! Third-party-initiated login (OpenID Connect Core 1.0 section 4): the
//! provider, or a page it controls, sends the browser here to start a sign-in
//! at that provider, optionally naming the account and where the dashboard
//! should open. Every request starts a fresh sign-in; nothing here reads or
//! changes a session.

use std::sync::Arc;

use axum::{
    Form,
    extract::State,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use url::{Position, Url};

use super::handlers::{OidcState, Refusal, refused, start_sign_in};

/// The longest `login_hint` passed on to the provider.
const MAX_LOGIN_HINT_CHARS: usize = 256;
/// The longest path and query a `target_link_uri` may give.
const MAX_RETURN_PATH_LEN: usize = 1024;

/// The parameters of a third-party-initiated login, in the query (`GET`) or a
/// form body (`POST`).
#[derive(Debug, Deserialize)]
pub struct InitiateParams {
    iss: Option<String>,
    login_hint: Option<String>,
    target_link_uri: Option<String>,
}

/// GET or POST /oidc/initiate. `Form` reads the query string of a `GET` and
/// the body of a `POST`, a form the provider's page submits cross-site, so the
/// route is never behind a same-origin or CSRF check.
pub async fn oidc_initiate(
    State(oidc): State<Arc<OidcState>>,
    Form(params): Form<InitiateParams>,
) -> Response {
    if params.iss.as_deref() != Some(oidc.config.issuer.as_str()) {
        return refused(Refusal::IssuerMismatch, None, "iss is missing or names another provider").into_response();
    }
    let login_hint = params
        .login_hint
        .as_deref()
        .filter(|hint| usable_login_hint(hint));
    let return_path = params
        .target_link_uri
        .as_deref()
        .and_then(|target| return_path(target, &oidc.config.redirect_uri))
        .unwrap_or_else(|| "/".to_string());
    start_sign_in(&oidc, login_hint, return_path).await
}

/// A `login_hint` is passed on only when it is short and plain text.
fn usable_login_hint(hint: &str) -> bool {
    !hint.is_empty()
        && hint.chars().count() <= MAX_LOGIN_HINT_CHARS
        && !hint
            .chars()
            .any(char::is_control)
}

/// The path and query of `target` when it is a safe place to open the
/// dashboard: an absolute URL on the dashboard's own origin (that of
/// `redirect_uri`), without user info, whose path and query still resolve on
/// that origin, with no encoded slash or backslash in the path, and at most
/// 1,024 characters long. Parsing has already turned backslashes in the path
/// into slashes, collapsed dot segments and encoded control characters.
/// Anything else gives `None`, and the dashboard opens at `/`.
fn return_path(
    target: &str,
    redirect_uri: &Url,
) -> Option<String> {
    let url = Url::parse(target).ok()?;
    let path = &url[Position::BeforePath..Position::AfterQuery];
    let encoded_separator = {
        let lower = url
            .path()
            .to_ascii_lowercase();
        lower.contains("%2f") || lower.contains("%5c")
    };
    let stays_on_origin = url.origin() == redirect_uri.origin()
        && url.username().is_empty()
        && url.password().is_none()
        && redirect_uri
            .join(path)
            .is_ok_and(|resolved| resolved.origin() == redirect_uri.origin());
    (stays_on_origin && !encoded_separator && path.len() <= MAX_RETURN_PATH_LEN).then(|| path.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dashboard() -> Url {
        Url::parse("https://stream.example.com/api/oidc/callback").unwrap()
    }

    #[test]
    fn a_target_on_the_dashboards_origin_opens_its_path_and_query() {
        assert_eq!(return_path("https://stream.example.com/surfaces", &dashboard()).as_deref(), Some("/surfaces"));
        assert_eq!(
            return_path("https://stream.example.com/surfaces/a?tab=logs&x=1#top", &dashboard()).as_deref(),
            Some("/surfaces/a?tab=logs&x=1"),
            "the fragment is dropped"
        );
        assert_eq!(
            return_path("https://STREAM.example.com:443/", &dashboard()).as_deref(),
            Some("/"),
            "the same origin written differently"
        );
        assert_eq!(
            return_path("https://stream.example.com/access-tokens/new?resource_pattern=surfaces%2F*", &dashboard())
                .as_deref(),
            Some("/access-tokens/new?resource_pattern=surfaces%2F*"),
            "an encoded slash in the query cannot change the host"
        );
    }

    #[test]
    fn a_target_anywhere_else_is_ignored() {
        for target in [
            "https://evil.example/surfaces",
            "http://stream.example.com/surfaces",
            "https://stream.example.com:8443/surfaces",
            "https://stream.example.com.evil.example/",
            "https://user:pw@stream.example.com/surfaces",
            "//evil.example/surfaces",
            "/surfaces",
            "javascript:alert(1)",
            "data:text/html,hi",
            "not a url",
        ] {
            assert_eq!(return_path(target, &dashboard()), None, "{target}");
        }
    }

    #[test]
    fn a_path_the_browser_could_read_as_another_host_is_ignored() {
        for target in [
            "https://stream.example.com//evil.example/",
            "https://stream.example.com/\\evil.example/",
            "https://stream.example.com/.//evil.example/",
            "https://stream.example.com/%2e//evil.example/",
            "https://stream.example.com/%2fevil.example/",
            "https://stream.example.com/%5Cevil.example/",
            "https://stream.example.com/a%2Fb",
        ] {
            assert_eq!(return_path(target, &dashboard()), None, "{target}");
        }
        let long = format!("https://stream.example.com/{}", "a".repeat(MAX_RETURN_PATH_LEN));
        assert_eq!(return_path(&long, &dashboard()), None, "too long");
    }

    #[test]
    fn only_a_short_plain_login_hint_is_passed_on() {
        assert!(usable_login_hint("alice@example.com"));
        assert!(usable_login_hint(&"é".repeat(MAX_LOGIN_HINT_CHARS)));
        assert!(!usable_login_hint(""));
        assert!(!usable_login_hint(&"a".repeat(MAX_LOGIN_HINT_CHARS + 1)));
        assert!(!usable_login_hint("alice\r\nX-Injected: 1"));
    }
}
