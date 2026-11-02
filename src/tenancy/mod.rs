use std::fmt;

use serde::{Deserialize, Serialize};

use crate::auth_manager::pat::{PatResourceScope, scope_allows};
use crate::auth_manager::resource_scope::TenantSelector;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatTenantContext {
    pub token_id: String,
    pub tenant_id: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct TenancyConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trusted_tenant_header: Option<TrustedTenantHeader>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TrustedTenantHeader {
    pub header: String,
    #[serde(default)]
    pub edge_strips_client_values: bool,
}

impl TrustedTenantHeader {
    pub fn covers(
        &self,
        tenant_header_name: &str,
    ) -> bool {
        self.edge_strips_client_values
            && self
                .header
                .eq_ignore_ascii_case(tenant_header_name)
    }
}

pub fn header_derived_tenant_permitted(
    selector: &TenantSelector,
    trusted_edge: Option<&TrustedTenantHeader>,
) -> bool {
    !selector.broad || trusted_edge.is_some_and(|edge| edge.covers(&selector.header_name))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceKind {
    Secrets,
    Certificates,
    ApiKeys,
    Pipes,
    Surfaces,
    Gateways,
    ConnectionPoints,
    Mediators,
    Integrations,
    PolicyDefinitions,
    PipeTemplates,
    CredentialProviders,
    JwtVerificationStrategies,
    OauthIdentifiers,
    Prompts,
    Members,
    Teams,
}

impl ResourceKind {
    pub fn from_path_family(family: &str) -> Option<Self> {
        match family {
            "secrets" => Some(Self::Secrets),
            "certificates" => Some(Self::Certificates),
            "api-keys" => Some(Self::ApiKeys),
            "pipes" => Some(Self::Pipes),
            "surfaces" => Some(Self::Surfaces),
            "gateways" => Some(Self::Gateways),
            "connection-points" => Some(Self::ConnectionPoints),
            "mediators" => Some(Self::Mediators),
            "integrations" => Some(Self::Integrations),
            "policy-definitions" => Some(Self::PolicyDefinitions),
            "pipe-templates" => Some(Self::PipeTemplates),
            "credential-providers" => Some(Self::CredentialProviders),
            "jwt-verification-strategies" => Some(Self::JwtVerificationStrategies),
            "oauth-identifiers" => Some(Self::OauthIdentifiers),
            "prompts" => Some(Self::Prompts),
            "members" => Some(Self::Members),
            "teams" => Some(Self::Teams),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Secrets => "secrets",
            Self::Certificates => "certificates",
            Self::ApiKeys => "api-keys",
            Self::Pipes => "pipes",
            Self::Surfaces => "surfaces",
            Self::Gateways => "gateways",
            Self::ConnectionPoints => "connection-points",
            Self::Mediators => "mediators",
            Self::Integrations => "integrations",
            Self::PolicyDefinitions => "policy-definitions",
            Self::PipeTemplates => "pipe-templates",
            Self::CredentialProviders => "credential-providers",
            Self::JwtVerificationStrategies => "jwt-verification-strategies",
            Self::OauthIdentifiers => "oauth-identifiers",
            Self::Prompts => "prompts",
            Self::Members => "members",
            Self::Teams => "teams",
        }
    }
}

impl fmt::Display for ResourceKind {
    fn fmt(
        &self,
        formatter: &mut fmt::Formatter<'_>,
    ) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

pub fn validate_tenant_id(tenant_id: &str) -> Result<(), &'static str> {
    if tenant_id.is_empty() || tenant_id.len() > 128 {
        return Err("tenant id must contain between 1 and 128 characters");
    }
    if !tenant_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
    {
        return Err("tenant id contains unsupported characters");
    }
    Ok(())
}

pub fn canonical_resource_target(
    tenant_id: &str,
    kind: ResourceKind,
    resource_id: &str,
) -> String {
    format!("TENANT:{tenant_id}:{}:{resource_id}", kind.as_str())
}

/// Every target a resource scope may match for one resource. An API key created
/// after the key-id prefix rename also answers to its legacy-prefixed id, so a
/// scope written against the legacy prefix keeps covering newer keys.
///
/// Only ids with the generated shape are aliased: the `ApiKeys` kind also
/// carries Surface ids for source-auth references, and those must not widen.
pub fn canonical_resource_targets(
    tenant_id: &str,
    kind: ResourceKind,
    resource_id: &str,
) -> Vec<String> {
    use crate::api_keys::{KEY_ID_PREFIX, LEGACY_KEY_ID_PREFIX};

    let mut targets = vec![canonical_resource_target(tenant_id, kind, resource_id)];
    if kind == ResourceKind::ApiKeys
        && let Some(suffix) = resource_id.strip_prefix(KEY_ID_PREFIX)
        && suffix.len() == uuid::fmt::Simple::LENGTH
        && suffix
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        targets.push(canonical_resource_target(tenant_id, kind, &format!("{LEGACY_KEY_ID_PREFIX}{suffix}")));
    }
    targets
}

/// Object-level tenancy gate for reads and writes.
///
/// * **No context** (`None`) — an interactive session or an appliance-wide PAT —
///   sees everything: untenanted (`None`) records and every tenant's records.
/// * **A tenant-scoped context** sees ONLY records whose `tenant_id` equals its
///   own. An untenanted (`None`) resource is DENIED to a tenant-scoped PAT.
///
/// The `None`-resource denial is a deliberate fail-closed control: pre-tenancy
/// records deserialize with `tenant_id == None` (the field is
/// `#[serde(default)]`) and there is no backfill, so treating `None` as globally
/// readable let every tenant-scoped PAT read AND write every legacy secret,
/// certificate, and pipe. Legacy/untenanted data must be explicitly reassigned
/// to a tenant (`reassign_ownership`) before a tenant-scoped PAT can reach it.
/// Resource types that maintain an intentional shared library (pipe-templates
/// via the `builtin` flag, global prompts) exempt those records in their own
/// `*_allowed` helpers; this gate stays fail-closed by default.
pub fn can_access(
    resource_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
) -> bool {
    context.is_none_or(|context| resource_tenant_id == Some(context.tenant_id.as_str()))
}

/// Whether the request's access token is narrowed to one tenant or to listed
/// resources. Such a token must not read appliance-wide data that spans every
/// tenant, such as captured surface traffic.
pub fn is_narrowed_token(
    context: Option<&PatTenantContext>,
    delegation: Option<&crate::auth_manager::pat::PatDelegationContext>,
) -> bool {
    context.is_some() || delegation.is_some_and(|delegation| delegation.resource_scoped)
}

/// May this caller change or delete a resource that is not tenant-owned?
///
/// Only the operator may. A resource with no `tenant_id` is an appliance-wide
/// object — a global policy definition enforced on *every* tenant's surfaces —
/// so letting a tenant token rewrite one hands that tenant the other tenants'
/// guardrail.
///
/// This exists because "readable by every caller" and "writable by every
/// caller" were the same check. Callers that read untenanted objects
/// deliberately bypass [`can_access`]; callers that write them must not, and
/// this is the gate they use instead. Verified reachable on a live appliance on
/// 2026-09-25: a tenant-scoped PAT rewrote an untenanted `default allow := false`
/// policy to `:= true` and got a 200.
pub fn can_mutate(
    resource_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
) -> bool {
    match context {
        None => true,
        Some(context) => resource_tenant_id == Some(context.tenant_id.as_str()),
    }
}

pub fn can_reference(
    owner_tenant_id: Option<&str>,
    referenced_tenant_id: Option<&str>,
) -> bool {
    match owner_tenant_id {
        Some(owner) => referenced_tenant_id.is_none_or(|referenced| referenced == owner),
        None => referenced_tenant_id.is_none(),
    }
}

pub fn scope_allows_resource(
    scope: Option<&PatResourceScope>,
    context: Option<&PatTenantContext>,
    kind: ResourceKind,
    resource_id: &str,
) -> bool {
    match (scope, context) {
        (None, _) => true,
        (Some(scope), Some(context)) => canonical_resource_targets(&context.tenant_id, kind, resource_id)
            .iter()
            .any(|target| scope_allows(Some(scope), target)),
        (Some(_), None) => false,
    }
}

pub fn tenant_for_create(
    requested_tenant_id: Option<String>,
    pat_authenticated: bool,
    context: Option<&PatTenantContext>,
) -> Result<Option<String>, &'static str> {
    if let Some(context) = context {
        if requested_tenant_id
            .as_deref()
            .is_some_and(|requested| requested != context.tenant_id)
        {
            return Err("tenant_id conflicts with the PAT tenant context");
        }
        return Ok(Some(context.tenant_id.clone()));
    }
    if pat_authenticated {
        if requested_tenant_id.is_some() {
            return Err("an appliance-wide PAT cannot assign tenant ownership");
        }
        return Ok(None);
    }
    if let Some(tenant_id) = requested_tenant_id.as_deref() {
        validate_tenant_id(tenant_id)?;
    }
    Ok(requested_tenant_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Seeing the appliance-wide rules that bind you is not permission to
    /// rewrite them.
    ///
    /// `policy_definitions::policy_allowed` short-circuits to `true` for an
    /// untenanted definition so a tenant can read the global policy enforced on
    /// their surfaces. That short-circuit returns before the tenancy gate *and*
    /// before the resource-pattern check, and it was covering writes too — so a
    /// tenant token could rewrite the global policy binding every other tenant
    /// on the appliance. Demonstrated on a live appliance by flipping an
    /// untenanted `default allow := false` to `:= true` (HTTP 200).
    #[test]
    fn a_tenant_may_read_a_global_policy_but_not_rewrite_it() {
        let tenant = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };

        // An appliance-wide definition carries no tenant.
        assert!(!can_mutate(None, Some(&tenant)), "a global policy is not a tenant's to change");

        // Their own remains theirs.
        assert!(can_mutate(Some("tenant-a"), Some(&tenant)));
        // Another tenant's never was.
        assert!(!can_mutate(Some("tenant-b"), Some(&tenant)));
        // The operator — no tenant context — keeps full access, or nobody could
        // maintain the global policy at all.
        assert!(can_mutate(None, None));
        assert!(can_mutate(Some("tenant-a"), None));
    }

    #[test]
    fn maps_only_the_tenant_owned_resource_vocabulary() {
        for (family, expected) in [
            ("pipes", ResourceKind::Pipes),
            ("surfaces", ResourceKind::Surfaces),
            ("secrets", ResourceKind::Secrets),
            ("pipe-templates", ResourceKind::PipeTemplates),
            ("oauth-identifiers", ResourceKind::OauthIdentifiers),
            ("teams", ResourceKind::Teams),
        ] {
            assert_eq!(ResourceKind::from_path_family(family), Some(expected));
            assert_eq!(expected.as_str(), family);
        }
        assert_eq!(ResourceKind::from_path_family("notifications"), None);
        assert_eq!(ResourceKind::from_path_family("settings"), None);
        assert_eq!(ResourceKind::from_path_family("users"), None);
    }

    #[test]
    fn validates_and_formats_tenant_resource_targets() {
        assert!(validate_tenant_id("acct:eu-west_1.prod").is_ok());
        assert!(validate_tenant_id("").is_err());
        assert!(validate_tenant_id("tenant/escape").is_err());
        assert_eq!(
            canonical_resource_target("tenant-a", ResourceKind::Pipes, "pipe-id"),
            "TENANT:tenant-a:pipes:pipe-id"
        );
    }

    #[test]
    fn ownership_rules_preserve_global_compatibility() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        assert!(can_access(Some("tenant-a"), Some(&context)));
        // Fail-closed hardening: a tenant-scoped PAT is denied an untenanted
        // (legacy, pre-tenancy) record — it must be reassigned to a tenant first.
        assert!(!can_access(None, Some(&context)));
        assert!(!can_access(Some("tenant-b"), Some(&context)));
        assert!(can_access(Some("tenant-b"), None));
        // Sessions / appliance-wide PATs (no context) still see untenanted records.
        assert!(can_access(None, None));

        assert!(can_reference(Some("tenant-a"), Some("tenant-a")));
        assert!(can_reference(Some("tenant-a"), None));
        assert!(!can_reference(Some("tenant-a"), Some("tenant-b")));
        assert!(can_reference(None, None));
        assert!(!can_reference(None, Some("tenant-a")));
    }

    #[test]
    fn create_rules_distinguish_sessions_tenant_pats_and_appliance_pats() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        assert_eq!(tenant_for_create(None, true, Some(&context)).unwrap(), Some("tenant-a".into()));
        assert!(tenant_for_create(Some("tenant-b".into()), true, Some(&context)).is_err());
        assert!(tenant_for_create(Some("tenant-a".into()), true, None).is_err());
        assert_eq!(tenant_for_create(Some("tenant-a".into()), false, None).unwrap(), Some("tenant-a".into()));
    }

    #[test]
    fn canonical_scope_requires_tenant_context() {
        let scope =
            PatResourceScope(std::sync::Arc::new(regex::Regex::new(r"\ATENANT:tenant-a:pipes:pipe-1\z").unwrap()));

        assert!(!scope_allows_resource(Some(&scope), None, ResourceKind::Pipes, "pipe-1"));
    }

    const NEW_KEY: &str = "askey_0123456789abcdef0123456789abcdef";
    const LEGACY_KEY: &str = "atgk_0123456789abcdef0123456789abcdef";

    #[test]
    fn api_key_scope_written_for_legacy_prefix_covers_renamed_keys() {
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = |pattern: &str| PatResourceScope(std::sync::Arc::new(regex::Regex::new(pattern).unwrap()));
        let allows = |scope: &PatResourceScope, id: &str| {
            scope_allows_resource(Some(scope), Some(&context), ResourceKind::ApiKeys, id)
        };

        let legacy_wildcard = scope(r"\ATENANT:tenant-a:api-keys:atgk_.*\z");
        assert!(allows(&legacy_wildcard, NEW_KEY), "renamed key matches a legacy wildcard");
        assert!(allows(&legacy_wildcard, LEGACY_KEY), "legacy key still matches");
        assert!(!allows(&legacy_wildcard, "other_0123"));
        assert!(!allows(&legacy_wildcard, "askey_x"), "a Surface id shaped like a key prefix is not aliased");

        let legacy_exact = scope(&format!(r"\ATENANT:tenant-a:api-keys:{LEGACY_KEY}\z"));
        assert!(allows(&legacy_exact, LEGACY_KEY));
        assert!(!allows(&legacy_exact, "askey_fedcba9876543210fedcba9876543210"), "a different key is still denied");

        let other_tenant = scope(r"\ATENANT:tenant-b:api-keys:atgk_.*\z");
        assert!(!allows(&other_tenant, NEW_KEY), "the alias never crosses tenants");
    }

    #[test]
    fn legacy_alias_applies_only_to_renamed_api_key_ids() {
        assert_eq!(
            canonical_resource_targets("t", ResourceKind::ApiKeys, NEW_KEY),
            vec![format!("TENANT:t:api-keys:{NEW_KEY}"), format!("TENANT:t:api-keys:{LEGACY_KEY}")]
        );
        assert_eq!(canonical_resource_targets("t", ResourceKind::ApiKeys, LEGACY_KEY).len(), 1);
        assert_eq!(
            canonical_resource_targets("t", ResourceKind::Pipes, NEW_KEY),
            vec![format!("TENANT:t:pipes:{NEW_KEY}")]
        );
        let uppercase_hex = format!("askey_{}", NEW_KEY["askey_".len()..].to_uppercase());
        for not_generated in ["askey_x", uppercase_hex.as_str(), "askey_0123"] {
            assert_eq!(
                canonical_resource_targets("t", ResourceKind::ApiKeys, not_generated),
                vec![format!("TENANT:t:api-keys:{not_generated}")],
                "{not_generated} is not a generated key id"
            );
        }
    }

    #[test]
    fn broad_tenant_selector_requires_a_covering_trusted_edge() {
        let exact = TenantSelector {
            header_name: "x-tenant".into(),
            broad: false,
        };
        let broad = TenantSelector {
            header_name: "x-tenant".into(),
            broad: true,
        };
        let covering = TrustedTenantHeader {
            header: "X-Tenant".into(),
            edge_strips_client_values: true,
        };
        let wrong_header = TrustedTenantHeader {
            header: "x-other".into(),
            edge_strips_client_values: true,
        };
        let unasserted = TrustedTenantHeader {
            header: "x-tenant".into(),
            edge_strips_client_values: false,
        };

        assert!(header_derived_tenant_permitted(&exact, None));
        assert!(!header_derived_tenant_permitted(&broad, None));
        assert!(!header_derived_tenant_permitted(&broad, Some(&wrong_header)));
        assert!(!header_derived_tenant_permitted(&broad, Some(&unasserted)));
        assert!(header_derived_tenant_permitted(&broad, Some(&covering)));
    }

    #[test]
    fn a_token_bound_to_a_tenant_or_to_resources_is_narrowed() {
        let tenant = PatTenantContext {
            token_id: "pat-1".to_string(),
            tenant_id: "tenant-a".to_string(),
        };
        let delegation = |resource_scoped| crate::auth_manager::pat::PatDelegationContext {
            token_id: "pat-1".to_string(),
            delegation_depth: 0,
            resource_scoped,
            scopes: None,
        };

        assert!(is_narrowed_token(Some(&tenant), None));
        assert!(is_narrowed_token(None, Some(&delegation(true))));
        assert!(!is_narrowed_token(None, Some(&delegation(false))));
        assert!(!is_narrowed_token(None, None));
    }
}
