//! Shared path utilities for the proxy module.
//!
//! Defines which requests are public discovery reads, which skip some of the
//! request gates regardless of channel configuration.

/// Whether `path` names a discovery document: its path, with any query or
/// fragment and one trailing `/` removed, ends with one of the documented
/// discovery endpoints. A path that only *contains* one of them is not a
/// discovery document. A path holding `%`, `;`, `\`, a control character or a
/// `.` or `..` segment is never one, since no discovery document needs them and
/// a decoding or normalising proxy in front of a target can turn
/// `/admin/export%3F/agent.json` into a read of `/admin/export`; a URL parser
/// also drops tab, CR and LF, so `.\t.` becomes a `..` segment on the way out.
fn is_public_path(path: &str) -> bool {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path);
    if path.contains(['%', ';', '\\'])
        || path
            .chars()
            .any(|c| c.is_ascii_control())
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return false;
    }
    let path = path
        .strip_suffix('/')
        .unwrap_or(path);

    DISCOVERY_DOCUMENTS
        .iter()
        .any(|document| path.ends_with(document))
}

/// The documented discovery endpoints.
const DISCOVERY_DOCUMENTS: &[&str] = &[
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
    "/agent-card.json",
    "/agent.json",
    "/.well-known/ucp",
    "/.well-known/agent-card",
];

/// Whether `path`, with any query or fragment and one trailing `/` removed, is
/// exactly a discovery endpoint at the root, not a longer path that only ends
/// like one.
pub fn is_root_discovery_document(path: &str) -> bool {
    let path = path
        .split(['?', '#'])
        .next()
        .unwrap_or(path);
    let path = path
        .strip_suffix('/')
        .unwrap_or(path)
        .trim_start_matches('/');
    DISCOVERY_DOCUMENTS
        .iter()
        .any(|document| document.trim_start_matches('/') == path)
}

/// Whether a request is a public discovery read that skips source
/// authentication and the per-gateway and surface policies: a `GET` or `HEAD`
/// for a discovery document. A request with any other method, such as a `POST`
/// of a chat body to `{route}/agent.json`, still runs source authentication
/// and every policy layer.
///
/// Every gate that exempts discovery reads asks this one predicate, with the
/// request's method, so they stay in sync.
pub fn is_public_request(
    method: &str,
    path: &str,
) -> bool {
    (method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD")) && is_public_path(path)
}

/// Top-level paths owned by the dashboard SPA (www/default).
/// A channel prefix that shadows any of these would silently break the
/// dashboard, since channel routes take precedence over the SPA fallback
/// `ServeDir`. Keep in sync with the routes declared in
/// `www/default/src/pages/AuthenticatedApp.tsx`.
const SPA_RESERVED_TOP_LEVEL: &[&str] = &[
    "audit",
    "certificates",
    "connections",
    "connection-points",
    "credential-providers",
    "credentials",
    "dashboard",
    "delegation-vault",
    "gateways",
    "identities",
    "integrations",
    "logs",
    "marketplace",
    "mediators",
    "metrics",
    "notifications",
    "oidc-providers",
    "onboard",
    "pipes",
    "policies",
    "profile",
    "proxies",
    "secrets",
    "settings",
    "surfaces",
    "system-metrics",
    "tasks",
    "trust-registries",
    "users",
];

/// Returns the first path segment of `prefix`, lowercased, or `None` if the
/// prefix is empty / root. E.g. `"/marketplace"` -> `Some("marketplace")`,
/// `"/svc/payments"` -> `Some("svc")`.
fn first_segment(prefix: &str) -> Option<String> {
    prefix
        .trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_ascii_lowercase())
}

/// Validate that no channel / proxy / pipe prefix collides with a top-level
/// SPA route. Channel routes are merged into the same router as the SPA's
/// fallback `ServeDir`, and explicit channel routes win — a collision
/// silently breaks the dashboard page with a proxy 404.
///
/// Returns the list of conflicting `(prefix, spa_path)` pairs. Empty on success.
pub fn check_spa_route_collisions<'a, I>(prefixes: I) -> Vec<(String, String)>
where
    I: IntoIterator<Item = &'a str>,
{
    let mut collisions = Vec::new();
    for prefix in prefixes {
        if let Some(seg) = first_segment(prefix)
            && SPA_RESERVED_TOP_LEVEL.contains(&seg.as_str())
        {
            collisions.push((prefix.to_string(), format!("/{}", seg)));
        }
    }
    collisions
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_get_or_head_for_a_discovery_document_is_a_public_request() {
        for method in ["GET", "HEAD", "get", "head"] {
            assert!(is_public_request(method, "/surface/agent.json"), "{method}");
            assert!(is_public_request(method, "/surface/.well-known/ucp"), "{method}");
        }
        for method in ["POST", "PUT", "PATCH", "DELETE", "OPTIONS", ""] {
            for path in ["/surface/agent.json", "/surface/.well-known/ucp", "/surface/.well-known/agent-card.json"] {
                assert!(
                    !is_public_request(method, path),
                    "a {method:?} to {path} only ends like a discovery document and must still be gated"
                );
            }
        }
        assert!(!is_public_request("GET", "/llm/route/v1/chat/completions"));
    }

    #[test]
    fn public_path_matches_the_documented_discovery_endpoints() {
        for path in [
            "/surface/agent.json/",
            "/surface/agent.json?format=json",
            "/surface/.well-known/agent-card.json#card",
            "/surface/.well-known/agent-card.json",
            "/surface/.well-known/agent.json",
            "/surface/agent-card.json",
            "/surface/agent.json",
            "/.well-known/ucp",
            "/surface/.well-known/ucp",
            "/surface/.well-known/agent-card",
        ] {
            assert!(is_public_path(path), "{path} is a discovery endpoint and must stay public");
        }
    }

    #[test]
    fn a_root_discovery_document_is_only_the_documented_path_itself() {
        for path in [
            "/agent.json",
            "agent.json",
            "/agent.json/",
            "/agent.json?format=json",
            "/.well-known/agent-card.json#card",
            "/.well-known/agent.json",
            "/agent-card.json",
            "/.well-known/ucp",
            "/.well-known/agent-card",
        ] {
            assert!(is_root_discovery_document(path), "{path}");
        }
        for path in [
            "/files/agent.json",
            "/some/route/agent.json?x=1",
            "/surface/.well-known/agent-card.json",
            "/agent.json.bak",
            "/",
            "",
        ] {
            assert!(!is_root_discovery_document(path), "{path}");
        }
    }

    /// The predicate used to be a substring match, so any caller could switch
    /// off source authentication and every policy layer by putting `/discovery`
    /// anywhere in the request path.
    #[test]
    fn public_path_rejects_paths_that_merely_contain_a_discovery_segment() {
        for path in [
            "/payments/garlic/station/not-really/discovery/x",
            "/llm/route/discovery/v1/chat/completions",
            "/llm/route/discovery/../v1/chat/completions",
            "/discovery/../../admin",
            "/api/v1/secrets?x=/discovery",
            "/discovery-api/orders",
            "/v1/discoveryx",
            "/.well-known/ucp/../admin",
            "/.well-known/ucp/checkout",
            "/agent.json/../../v1/secrets",
            "/surface/.well-known/agent-card/evil",
            "/admin/export%3F/agent.json",
            "/admin/export%23/agent.json",
            "/surface%2F.well-known/agent-card.json",
            "/admin;/agent.json",
            "/surface/agent.json;v=1",
            "/admin\\x/discovery",
        ] {
            assert!(!is_public_path(path), "{path} is not a discovery endpoint and must not bypass inbound controls");
        }
    }

    /// No route serves a `/discovery` document, so a path ending in one is
    /// gated like any other.
    #[test]
    fn a_path_ending_in_discovery_is_not_public() {
        for path in [
            "/discovery",
            "/discovery/",
            "/llm/route/discovery",
            "/llm/route/discovery?format=json",
            "/agents/copilot-worker/discovery",
        ] {
            assert!(!is_public_path(path), "{path} must not bypass inbound controls");
            assert!(!is_public_request("GET", path), "GET {path} must not bypass inbound controls");
        }
    }

    #[test]
    fn a_path_with_a_dot_segment_is_not_public() {
        for path in [
            "/v1/secrets/../agent.json",
            "/./agent.json",
            "/surface/./.well-known/ucp",
            "/surface/../.well-known/agent-card.json/",
            "/../agent-card.json?x=1",
            "/x/.\t./agent.json",
            "/x/.\n./.well-known/ucp",
            "/x/.\r./agent-card.json",
            "/a/b/.\n./.\r./agent.json",
        ] {
            assert!(!is_public_path(path), "{path} must not bypass inbound controls");
        }
        assert!(is_public_path("/surface.v2/agent.json"), "a dot inside a segment is not a dot segment");
    }

    #[test]
    fn collision_detects_exact_match() {
        let hits = check_spa_route_collisions(["/marketplace"]);
        assert_eq!(hits, vec![("/marketplace".to_string(), "/marketplace".to_string())]);
    }

    #[test]
    fn collision_detects_nested_under_reserved() {
        let hits = check_spa_route_collisions(["/marketplace/sub"]);
        assert_eq!(hits, vec![("/marketplace/sub".to_string(), "/marketplace".to_string())]);
    }

    #[test]
    fn collision_ignores_non_reserved_prefix() {
        assert!(check_spa_route_collisions(["/payments", "/cats", "/foo"]).is_empty());
    }

    #[test]
    fn collision_ignores_root_and_empty() {
        assert!(check_spa_route_collisions(["/", ""]).is_empty());
    }

    #[test]
    fn collision_is_case_insensitive() {
        let hits = check_spa_route_collisions(["/MarketPlace"]);
        assert_eq!(hits.len(), 1);
    }
}
