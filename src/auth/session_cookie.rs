use cookie::time::Duration;
use cookie::{Cookie, SameSite};

pub(crate) const SESSION_COOKIE_NAME: &str = "session_token";

pub(crate) fn build_session_cookie(
    session_token: &str,
    max_age: u64,
) -> String {
    Cookie::build((SESSION_COOKIE_NAME, session_token))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

pub(crate) fn clear_session_cookie() -> String {
    let mut cookie = Cookie::build((SESSION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Strict)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

/// Name of the SAML correlation cookie. The `__Host-` prefix is what makes the
/// browser binding trustworthy: browsers accept such a cookie only with
/// `Secure`, no `Domain` attribute and `Path=/`, so it is locked to the exact
/// host that set it and no sibling subdomain can shadow it.
pub(crate) const SAML_CORRELATION_COOKIE_NAME: &str = "__Host-saml_authn_id";

/// Cookie binding a browser to the SP-initiated AuthnRequest it started, so the
/// response can be verified to complete in the same browser that began the
/// login (defence against login CSRF / cross-browser response injection).
///
/// `SameSite=None` + `Secure` are required because the IdP returns the response
/// as a cross-site top-level POST to the ACS, on which a Lax/Strict cookie would
/// not be sent. `Path=/` is mandated by the `__Host-` prefix, and is also the
/// only path that works everywhere: the identity router is mounted under a
/// configurable prefix (`/api` by default), so the browser-visible ACS path is
/// not necessarily `/saml/acs`. Nothing is lost by widening it — RFC 6265 §8.5
/// is explicit that `Path` is not a security boundary.
pub(crate) fn build_saml_correlation_cookie(
    request_id: &str,
    max_age: u64,
) -> String {
    Cookie::build((SAML_CORRELATION_COOKIE_NAME, request_id))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

/// Expire the single-use correlation cookie. The attributes must match the ones
/// it was set with, or the browser keeps the original cookie.
pub(crate) fn clear_saml_correlation_cookie() -> String {
    let mut cookie = Cookie::build((SAML_CORRELATION_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::None)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

/// Name of the OIDC binding cookie, holding the `state` of the sign-in this
/// browser started. Like the SAML correlation cookie, the `__Host-` prefix
/// stops a sibling subdomain from planting one.
pub(crate) const OIDC_STATE_COOKIE_NAME: &str = "__Host-oidc_state";

/// Cookie binding a browser to the OIDC sign-in it started, so a callback URL
/// captured from one browser cannot complete a sign-in in another (login
/// CSRF). The provider sends the browser back with a cross-site top-level
/// `GET`, on which a `Lax` cookie is sent and a `Strict` one is not.
pub(crate) fn build_oidc_state_cookie(
    state: &str,
    max_age: u64,
) -> String {
    Cookie::build((OIDC_STATE_COOKIE_NAME, state))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(max_age.min(i64::MAX as u64) as i64))
        .build()
        .encoded()
        .to_string()
}

/// Expire the OIDC binding cookie, with the attributes it was set with.
pub(crate) fn clear_oidc_state_cookie() -> String {
    let mut cookie = Cookie::build((OIDC_STATE_COOKIE_NAME, ""))
        .path("/")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    cookie.make_removal();
    cookie.encoded().to_string()
}

/// The value of the cookie `name` on a request, read verbatim (the values
/// these helpers set are URL-safe, so cookie encoding leaves them unchanged).
pub(crate) fn request_cookie(
    headers: &axum::http::HeaderMap,
    name: &str,
) -> Option<String> {
    headers
        .get_all(axum::http::header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .find_map(|pair| {
            let (cookie_name, value) = pair.split_once('=')?;
            (cookie_name.trim() == name).then(|| value.trim().to_string())
        })
}

#[cfg(test)]
mod tests {
    use super::{
        OIDC_STATE_COOKIE_NAME, SAML_CORRELATION_COOKIE_NAME, SESSION_COOKIE_NAME, build_oidc_state_cookie,
        build_saml_correlation_cookie, build_session_cookie, clear_oidc_state_cookie, clear_saml_correlation_cookie,
        clear_session_cookie, request_cookie,
    };
    use cookie::time::{Duration, OffsetDateTime};
    use cookie::{Cookie, SameSite};

    #[test]
    fn test_build_session_cookie_encodes_value_and_sets_attributes() {
        let cookie = build_session_cookie("abc 123?;", 1200);

        assert!(cookie.contains("abc%20123%3F%3B"));

        let parsed = Cookie::parse_encoded(cookie).expect("session cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), "abc 123?;");
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.same_site(), Some(SameSite::Strict));
        assert_eq!(parsed.max_age(), Some(Duration::seconds(1200)));
    }

    #[test]
    fn test_clear_session_cookie_expires_immediately() {
        let cookie = clear_session_cookie();

        let parsed = Cookie::parse(cookie).expect("clear cookie should parse");

        assert_eq!(parsed.name(), SESSION_COOKIE_NAME);
        assert_eq!(parsed.value(), "");
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.http_only(), Some(true));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.same_site(), Some(cookie::SameSite::Strict));
        assert_eq!(parsed.max_age(), Some(Duration::ZERO));
        assert!(
            parsed
                .expires_datetime()
                .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
        );
    }

    #[test]
    fn test_saml_correlation_cookie_satisfies_host_prefix_rules() {
        let cookie = build_saml_correlation_cookie("_abc-123", 300);

        // The __Host- name must survive percent-encoding, or the ACS will not
        // find it in the Cookie header.
        assert!(cookie.starts_with("__Host-saml_authn_id="), "name must not be encoded: {cookie}");

        let parsed = Cookie::parse_encoded(cookie).expect("correlation cookie should parse");

        assert_eq!(parsed.name(), SAML_CORRELATION_COOKIE_NAME);
        assert_eq!(parsed.value(), "_abc-123");
        // Browsers reject a __Host- cookie unless all three hold.
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.domain(), None);
        assert_eq!(parsed.http_only(), Some(true));
        // SameSite=None is what lets the cookie survive the IdP's cross-site POST.
        assert_eq!(parsed.same_site(), Some(SameSite::None));
        assert_eq!(parsed.max_age(), Some(Duration::seconds(300)));
    }

    #[test]
    fn test_clear_saml_correlation_cookie_matches_set_attributes() {
        let parsed = Cookie::parse_encoded(clear_saml_correlation_cookie()).expect("clear cookie should parse");

        assert_eq!(parsed.name(), SAML_CORRELATION_COOKIE_NAME);
        assert_eq!(parsed.value(), "");
        // Mismatched attributes would leave the single-use cookie in the browser.
        assert_eq!(parsed.path(), Some("/"));
        assert_eq!(parsed.secure(), Some(true));
        assert_eq!(parsed.domain(), None);
        assert_eq!(parsed.same_site(), Some(SameSite::None));
        assert_eq!(parsed.max_age(), Some(Duration::ZERO));
        assert!(
            parsed
                .expires_datetime()
                .is_some_and(|expires| expires <= OffsetDateTime::now_utc())
        );
    }

    #[test]
    fn the_oidc_state_cookie_satisfies_host_prefix_rules_and_survives_the_return_trip() {
        let cookie = Cookie::parse(build_oidc_state_cookie("state-123", 600)).unwrap();

        assert_eq!(cookie.name(), OIDC_STATE_COOKIE_NAME);
        assert_eq!(cookie.value(), "state-123");
        assert_eq!(cookie.path(), Some("/"));
        assert_eq!(cookie.domain(), None);
        assert_eq!(cookie.secure(), Some(true));
        assert_eq!(cookie.http_only(), Some(true));
        assert_eq!(cookie.same_site(), Some(SameSite::Lax), "sent on the provider's cross-site redirect back");
        assert_eq!(cookie.max_age(), Some(Duration::seconds(600)));

        let cleared = Cookie::parse(clear_oidc_state_cookie()).unwrap();
        assert_eq!(cleared.name(), OIDC_STATE_COOKIE_NAME);
        assert_eq!(cleared.value(), "");
        assert_eq!(cleared.path(), Some("/"));
        assert_eq!(cleared.secure(), Some(true));
        assert_eq!(cleared.same_site(), Some(SameSite::Lax));
        assert_eq!(cleared.max_age(), Some(Duration::ZERO));
    }

    #[test]
    fn request_cookie_finds_one_cookie_among_several_headers() {
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            axum::http::header::COOKIE,
            "a=1; session_token=s"
                .parse()
                .unwrap(),
        );
        headers.append(
            axum::http::header::COOKIE,
            "__Host-oidc_state=st ; b=2"
                .parse()
                .unwrap(),
        );

        assert_eq!(request_cookie(&headers, OIDC_STATE_COOKIE_NAME).as_deref(), Some("st"));
        assert_eq!(request_cookie(&headers, "b").as_deref(), Some("2"));
        assert_eq!(request_cookie(&headers, "oidc_state"), None, "names match exactly");
        assert_eq!(request_cookie(&axum::http::HeaderMap::new(), "a"), None);
    }
}
