//! Management access-token (PAT) authentication seam.
//!
//! A management **access token** is a long-lived bearer credential a service
//! account (e.g. an external control plane) presents to the management API in
//! place of an interactive session. `require_session_auth` validates a session
//! first, then falls back to a [`PatAuthenticator`]. This module defines only
//! the seam so the auth middleware never depends on the concrete token store
//! (which lives in `crate::access_tokens`).

use std::sync::Arc;

use async_trait::async_trait;
use regex::Regex;

use super::resource_scope::CompiledCanonicalResourceScope;
use crate::tenancy::ResourceKind;

/// The principal a validated access token acts as.
pub struct PatPrincipal {
    /// The user the token is bound to; its role is the token's permission ceiling.
    pub user_id: String,
    /// Permission-name allow-list narrowing the bound user's role. `None`
    /// inherits the full role (no narrowing).
    pub scopes: Option<Vec<String>>,
    /// The token record id, for audit attribution.
    pub token_id: String,
    /// Number of delegation hops from the root token.
    pub delegation_depth: u32,
    /// Whether the token has a resource pattern or required-header gate.
    pub resource_scoped: bool,
    /// The token's compiled resource scope (ID pattern + required-header gate),
    /// or `None` when the token declares neither. Shared and reused across
    /// requests; evaluated per request against the presented headers.
    pub resource_scope: Option<Arc<CompiledCanonicalResourceScope>>,
}

/// Validates a presented bearer token as a management access token.
#[async_trait]
pub trait PatAuthenticator: Send + Sync {
    /// Return the principal when `token` is a live (unrevoked, unexpired)
    /// access token, else `None`.
    async fn authenticate(
        &self,
        token: &str,
    ) -> Option<PatPrincipal>;
}

/// Request extension inserted by `require_session_auth` for a request that
/// authenticated with an access token. Carries the token's scope allow-list
/// (`None` = full role). Absent for session-authenticated requests. Read by the
/// per-route RBAC guard to narrow the token's effective permissions.
#[derive(Clone)]
pub struct PatContext(pub Option<Vec<String>>);

/// Trusted lineage metadata for a request authenticated with a PAT. Absent for
/// interactive sessions.
#[derive(Clone)]
pub struct PatDelegationContext {
    pub token_id: String,
    pub delegation_depth: u32,
    pub resource_scoped: bool,
    pub scopes: Option<Vec<String>>,
}

/// Request extension carrying the effective canonical resource pattern after
/// header interpolation. Entity handlers match it against
/// `TENANT:<tenant>:<resource-kind>:<resource-id>` targets.
#[derive(Clone)]
pub struct PatResourceScope(pub Arc<Regex>);

impl PatResourceScope {
    /// Whether `id` is inside the token's permitted namespace.
    pub fn allows(
        &self,
        id: &str,
    ) -> bool {
        self.0.is_match(id)
    }
}

/// Returns true when `id` is permitted under the (optional) resource scope. An
/// absent scope (session, unscoped token) permits everything — the scope, when
/// present, only ever narrows.
pub fn scope_allows(
    scope: Option<&PatResourceScope>,
    id: &str,
) -> bool {
    scope.is_none_or(|s| s.allows(id))
}

#[derive(Debug, PartialEq, Eq)]
pub enum CanonicalPathScope {
    EnforceId { kind: ResourceKind, id: String },
    HandlerEnforced,
    DenyScoped,
    Unscoped,
}

fn decoded_id(raw: &str) -> String {
    urlencoding::decode(raw)
        .map(|value| value.into_owned())
        .unwrap_or_else(|_| raw.to_string())
}

fn canonical_handler_enforced_family(
    kind: ResourceKind,
    rest: &[&str],
) -> Option<CanonicalPathScope> {
    let known = match kind {
        ResourceKind::Secrets => matches!(rest, [] | ["new"] | [_] | ["tag", _]),
        ResourceKind::Certificates => matches!(rest, [] | [_]),
        ResourceKind::ApiKeys => {
            matches!(rest, [] | [_] | [_, _] | [_, _, "revoke" | "rotate"])
        }
        ResourceKind::ConnectionPoints => matches!(
            rest,
            [] | [_]
                | [_, "use" | "exposed-surfaces" | "metrics" | "reconnect"]
                | [_, "messages"]
                | [_, "messages", _]
                | [_, "messages", _, "read"]
        ),
        _ => return None,
    };
    Some(if known {
        CanonicalPathScope::HandlerEnforced
    } else {
        CanonicalPathScope::DenyScoped
    })
}

fn canonical_collection_action(
    kind: ResourceKind,
    rest: &[&str],
) -> Option<CanonicalPathScope> {
    match (kind, rest) {
        (ResourceKind::Gateways, ["connect-via-oob" | "refresh-surfaces"])
        | (ResourceKind::Mediators, ["compatible" | "check-auth"])
        | (ResourceKind::PipeTemplates, ["import"])
        | (ResourceKind::CredentialProviders, ["validate"]) => Some(CanonicalPathScope::HandlerEnforced),
        (ResourceKind::Integrations, ["config" | "runtime-variables"]) => Some(CanonicalPathScope::Unscoped),
        (ResourceKind::Integrations, ["test" | "trigger-multiple"])
        | (ResourceKind::JwtVerificationStrategies, ["validate-jwks-uri"])
        | (ResourceKind::Pipes, ["test-llm-connection"] | ["test-surfaces", "delete"])
        | (ResourceKind::Surfaces, ["validate-policy"]) => Some(CanonicalPathScope::DenyScoped),
        _ => None,
    }
}

fn canonical_nested_action(
    kind: ResourceKind,
    tail: &[&str],
) -> bool {
    matches!(
        (kind, tail),
        (ResourceKind::Pipes, ["variants"])
            | (ResourceKind::Pipes, ["variants", _])
            | (ResourceKind::Pipes, ["variants", _, "promote-to-default" | "resolved"])
            | (ResourceKind::Pipes, ["ide-catalog", "preview" | "bootstrap"])
            | (ResourceKind::Pipes, ["test" | "execute" | "budget"])
            | (ResourceKind::Pipes, ["execute", "stream"])
            | (ResourceKind::Surfaces, ["variants"])
            | (ResourceKind::Surfaces, ["variants", _])
            | (ResourceKind::Surfaces, ["variants", _, "promote-to-default" | "resolved"])
            | (ResourceKind::Gateways, ["integrations" | "policy" | "ping" | "surfaces" | "marketplace"])
            | (ResourceKind::Gateways, ["exposed-surfaces" | "approve" | "connection-points"])
            | (ResourceKind::Mediators, ["trust-ping"])
            | (ResourceKind::Integrations, ["trigger"])
            | (ResourceKind::PolicyDefinitions, ["simulate" | "impact" | "versions"])
            | (ResourceKind::PipeTemplates, ["export"])
            | (ResourceKind::Prompts, ["render"])
            | (ResourceKind::Teams, ["members" | "usage"])
            | (ResourceKind::Teams, ["members", _])
    )
}

/// Path families that own no resource of their own, but read and write one that
/// *is* namespaced — and whose handlers authorize against it.
///
/// `drift` is the whole of it today. Every drift route is a view over a
/// **surface**: a verdict, a baseline, a replay run. There is no "drift
/// resource" to namespace, so `ResourceKind::from_path_family` has nothing to
/// answer with, and the classifier's fallback used to call the family
/// `Unscoped`.
///
/// That fallback fails closed on writes — every non-GET from a resource-scoped
/// token is refused before scopes or the pattern are even consulted — which
/// meant **no** tenant-scoped token could ever pin a baseline or start a
/// replay, whatever it had been granted. Reads passed, so the failure was
/// invisible until somebody pressed a button.
///
/// The surface behind each route is already checked: every one of these calls
/// `authorize_surface_scope`, which resolves the surface to its pipe and applies
/// both the caller's tenant and the caller's resource pattern to it. So the
/// honest classification is `HandlerEnforced`, which is what this returns.
///
/// **An unlisted drift path is `DenyScoped`, not `HandlerEnforced`.** A route
/// added later is refused to scoped callers until it is listed here — which is
/// the moment somebody has to look at whether its handler authorizes anything.
fn canonical_surface_view_family(
    family: &str,
    rest: &[&str],
) -> Option<CanonicalPathScope> {
    if family != "drift" {
        return None;
    }
    let known = matches!(
        rest,
        // Appliance-wide metadata: dimension labels and units, no tenant data.
        ["dimensions"]
            // Keyed or query-scoped by surface; each authorizes it.
            | ["series"]
            | ["verdict"]
            | ["baseline"]
            | ["sessions"]
            | ["runs"]
            // One run, authorized against the surface it belongs to.
            | ["runs", _]
            | ["eval", "run" | "cancel"]
    );
    Some(if known {
        CanonicalPathScope::HandlerEnforced
    } else {
        CanonicalPathScope::DenyScoped
    })
}

pub fn classify_canonical_resource_path(path: &str) -> CanonicalPathScope {
    let segments: Vec<&str> = path
        .split('/')
        .filter(|segment| !segment.is_empty())
        .collect();
    let family = (0..segments.len().min(2)).find_map(|index| {
        (segments[index] == "v1" && index + 1 < segments.len())
            .then(|| ResourceKind::from_path_family(segments[index + 1]).map(|kind| (kind, index + 2)))
            .flatten()
    });
    let Some((kind, rest_start)) = family else {
        // Not a namespaced resource family — but it may still be a view over
        // one, which its handler authorizes for itself.
        let view = (0..segments.len().min(2)).find_map(|index| {
            (segments[index] == "v1" && index + 1 < segments.len())
                .then(|| canonical_surface_view_family(segments[index + 1], &segments[index + 2..]))
                .flatten()
        });
        return view.unwrap_or(CanonicalPathScope::Unscoped);
    };
    let rest = &segments[rest_start..];
    if let Some(classification) = canonical_handler_enforced_family(kind, rest) {
        return classification;
    }
    if let Some(classification) = canonical_collection_action(kind, rest) {
        return classification;
    }
    match rest {
        [] => CanonicalPathScope::HandlerEnforced,
        [raw] => CanonicalPathScope::EnforceId { kind, id: decoded_id(raw) },
        [raw, tail @ ..] if canonical_nested_action(kind, tail) => {
            CanonicalPathScope::EnforceId { kind, id: decoded_id(raw) }
        }
        _ => CanonicalPathScope::DenyScoped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_allows_is_permissive_when_unscoped() {
        assert!(scope_allows(None, "anything"));
    }

    /// Every drift route in the router, and the reason this change exists.
    ///
    /// `drift` names no resource of its own, so the classifier's fallback used
    /// to call it `Unscoped` — which fails closed on every non-GET, so no
    /// resource-scoped token could pin a baseline or start a replay however it
    /// was scoped. Each of these must now be handler-enforced, and each of the
    /// handlers behind them authorizes the surface it is given.
    #[test]
    fn every_drift_route_is_handler_enforced() {
        for path in [
            "/api/v1/drift/dimensions",
            "/api/v1/drift/series",
            "/api/v1/drift/verdict",
            "/api/v1/drift/baseline",
            "/api/v1/drift/sessions",
            "/api/v1/drift/runs",
            "/api/v1/drift/runs/0d1a4f6b-9a3e-2b8c-4d5e-6f707f2c1e60",
            "/api/v1/drift/eval/run",
            "/api/v1/drift/eval/cancel",
        ] {
            assert_eq!(
                classify_canonical_resource_path(path),
                CanonicalPathScope::HandlerEnforced,
                "{path} must be reachable by a resource-scoped token, writes included"
            );
        }
    }

    /// Both mount points. The identity router declares `/v1/…` and is nested
    /// under the deployment's route prefix, so the same route arrives as
    /// `/api/v1/…` — and a classifier that only knew one of them would silently
    /// treat the other as `Unscoped`.
    #[test]
    fn drift_classifies_the_same_with_or_without_the_route_prefix() {
        for tail in ["verdict", "baseline", "eval/run"] {
            assert_eq!(
                classify_canonical_resource_path(&format!("/v1/drift/{tail}")),
                classify_canonical_resource_path(&format!("/api/v1/drift/{tail}")),
                "/v1/drift/{tail} and /api/v1/drift/{tail} are the same route"
            );
        }
    }

    /// A drift route added later is refused to scoped callers until somebody
    /// lists it here — which is the moment they have to look at whether its
    /// handler authorizes anything. Failing closed is the whole point.
    #[test]
    fn an_unlisted_drift_route_is_denied_rather_than_waved_through() {
        for path in
            ["/api/v1/drift/purge", "/api/v1/drift/eval/replay-everything", "/api/v1/drift/runs/some-id/transcript"]
        {
            assert_eq!(
                classify_canonical_resource_path(path),
                CanonicalPathScope::DenyScoped,
                "{path} is not a known drift route and must fail closed"
            );
        }
    }

    /// The new branch must not change anything else. A family that is genuinely
    /// unscoped stays unscoped, and one that is a real resource keeps its id
    /// enforcement.
    #[test]
    fn non_drift_families_are_untouched() {
        assert_eq!(classify_canonical_resource_path("/api/v1/telemetry/series"), CanonicalPathScope::Unscoped);
        assert_eq!(classify_canonical_resource_path("/api/v1/spend-report"), CanonicalPathScope::Unscoped);
        assert_eq!(classify_canonical_resource_path("/v1/drifting/verdict"), CanonicalPathScope::Unscoped);
        assert_eq!(
            classify_canonical_resource_path("/api/v1/pipes/pipe-1"),
            CanonicalPathScope::EnforceId {
                kind: ResourceKind::Pipes,
                id: "pipe-1".into(),
            }
        );
    }

    #[test]
    fn canonical_classifier_returns_typed_resource_ids() {
        assert_eq!(
            classify_canonical_resource_path("/api/v1/policy-definitions/policy%3Aone/versions"),
            CanonicalPathScope::EnforceId {
                kind: ResourceKind::PolicyDefinitions,
                id: "policy:one".into(),
            }
        );
        assert_eq!(
            classify_canonical_resource_path("/v1/pipes/pipe-1/variants/v2"),
            CanonicalPathScope::EnforceId {
                kind: ResourceKind::Pipes,
                id: "pipe-1".into(),
            }
        );
        assert_eq!(
            classify_canonical_resource_path("/v1/gateways/gateway-1/connection-points"),
            CanonicalPathScope::EnforceId {
                kind: ResourceKind::Gateways,
                id: "gateway-1".into(),
            }
        );
    }

    #[test]
    fn canonical_classifier_delegates_parent_and_logical_id_routes_to_handlers() {
        for path in [
            "/api/v1/secrets/uuid",
            "/api/v1/certificates/uuid",
            "/api/v1/api-keys/surface/key/rotate",
            "/v1/connection-points/cp/messages/message/read",
            "/v1/mediators/compatible",
        ] {
            assert_eq!(classify_canonical_resource_path(path), CanonicalPathScope::HandlerEnforced, "{path}");
        }
    }

    #[test]
    fn canonical_classifier_fails_closed_on_unknown_or_unbound_actions() {
        for path in [
            "/api/v1/secrets/id/future-action",
            "/v1/pipes/test-llm-connection",
            "/v1/gateways/id/future-action",
            "/v1/teams/id/future-action",
            "/v1/integrations/trigger-multiple",
        ] {
            assert_eq!(classify_canonical_resource_path(path), CanonicalPathScope::DenyScoped, "{path}");
        }
        assert_eq!(classify_canonical_resource_path("/v1/settings"), CanonicalPathScope::Unscoped);
        assert_eq!(classify_canonical_resource_path("/v1/integrations/config"), CanonicalPathScope::Unscoped);
    }
}
