//! Who a governance record or pipe event is attributed to: the caller's
//! canonical identity, the member and teams the team gate resolved, and the
//! tenant that owns the surface.

use serde::{Deserialize, Serialize};

use crate::members::types::ANONYMOUS_MEMBER_ID;
use crate::source_auth::AuthenticatedIdentity;

/// What a record's caller hash was computed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CallerIdentityKind {
    /// A member resolved from the caller by the surface's team attribution.
    Member,
    /// The subject of a verified JWT.
    Subject,
    /// The name of a validated API key.
    ApiKey,
    /// The principal of a verified mTLS client certificate.
    Mtls,
}

/// A caller's canonical key: the value its record hash is computed over, and
/// what kind of identifier that value is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerKey {
    pub kind: CallerIdentityKind,
    pub value: String,
}

impl CallerKey {
    pub fn member(id: impl Into<String>) -> Self {
        Self {
            kind: CallerIdentityKind::Member,
            value: id.into(),
        }
    }

    pub fn from_identity(identity: &AuthenticatedIdentity) -> Self {
        let (kind, value) = match identity {
            AuthenticatedIdentity::JwtBearer { subject, .. } => (CallerIdentityKind::Subject, subject),
            AuthenticatedIdentity::ApiKey { key_name } => (CallerIdentityKind::ApiKey, key_name),
            AuthenticatedIdentity::Mtls { principal, .. } => (CallerIdentityKind::Mtls, principal),
        };
        Self { kind, value: value.clone() }
    }

    /// The canonical caller: the member the caller resolves to, else the
    /// authenticated principal. The built-in anonymous member never identifies
    /// a caller.
    pub fn resolve(
        member_id: Option<&str>,
        identity: Option<&CallerKey>,
    ) -> Option<Self> {
        member_id
            .filter(|id| !id.is_empty() && *id != ANONYMOUS_MEMBER_ID)
            .map(Self::member)
            .or_else(|| identity.cloned())
    }
}

/// The member, teams and tenant a usage record is attributed to.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsageAttribution {
    /// Member the team gate resolved for the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub member_id: Option<String>,
    /// Ids of the member's teams the request was attributed to.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team_ids: Vec<String>,
    /// Names of those teams, in the same order as `team_ids`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub team_names: Vec<String>,
    /// Tenant that owns the surface; absent for an appliance-wide surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl UsageAttribution {
    /// Attribution for a surface owned by `tenant_id`, before any member is known.
    pub fn for_tenant(tenant_id: Option<&str>) -> Self {
        Self {
            tenant_id: tenant_id.map(str::to_string),
            ..Default::default()
        }
    }

    /// Record the member and teams the team gate resolved.
    pub fn set_team_context(
        &mut self,
        ctx: &crate::teams::gate::TeamUsageContext,
    ) {
        self.member_id = Some(ctx.member_id.clone());
        self.team_ids = ctx
            .teams
            .iter()
            .map(|t| t.id.clone())
            .collect();
        self.team_names = ctx
            .teams
            .iter()
            .map(|t| t.name.clone())
            .collect();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jwt(subject: &str) -> AuthenticatedIdentity {
        AuthenticatedIdentity::JwtBearer {
            subject: subject.to_string(),
            claims: serde_json::json!({}),
        }
    }

    #[test]
    fn identity_kinds_follow_the_authentication_method() {
        assert_eq!(
            CallerKey::from_identity(&jwt("sub-1")),
            CallerKey {
                kind: CallerIdentityKind::Subject,
                value: "sub-1".to_string()
            }
        );
        let api_key = CallerKey::from_identity(&AuthenticatedIdentity::ApiKey { key_name: "bot".to_string() });
        assert_eq!(api_key.kind, CallerIdentityKind::ApiKey);
        assert_eq!(api_key.value, "bot");
    }

    #[test]
    fn a_resolved_member_wins_over_the_authenticated_principal() {
        let subject = CallerKey::from_identity(&jwt("sub-1"));
        assert_eq!(CallerKey::resolve(Some("m-1"), Some(&subject)), Some(CallerKey::member("m-1")));
        assert_eq!(CallerKey::resolve(None, Some(&subject)), Some(subject.clone()));
        assert_eq!(CallerKey::resolve(None, None), None);
    }

    #[test]
    fn the_anonymous_member_never_identifies_a_caller() {
        let subject = CallerKey::from_identity(&jwt("sub-1"));
        assert_eq!(CallerKey::resolve(Some(ANONYMOUS_MEMBER_ID), Some(&subject)), Some(subject));
        assert_eq!(CallerKey::resolve(Some(ANONYMOUS_MEMBER_ID), None), None);
    }

    #[test]
    fn kinds_serialize_snake_case() {
        let kinds = [
            (CallerIdentityKind::Member, "member"),
            (CallerIdentityKind::Subject, "subject"),
            (CallerIdentityKind::ApiKey, "api_key"),
            (CallerIdentityKind::Mtls, "mtls"),
        ];
        for (kind, expected) in kinds {
            assert_eq!(serde_json::to_value(kind).unwrap(), expected);
        }
    }

    #[test]
    fn empty_usage_attribution_serializes_to_nothing() {
        assert_eq!(serde_json::to_value(UsageAttribution::default()).unwrap(), serde_json::json!({}));
        let attribution = UsageAttribution {
            member_id: Some("m-1".to_string()),
            team_ids: vec!["t-1".to_string()],
            team_names: vec!["Payments".to_string()],
            tenant_id: Some("acme".to_string()),
        };
        assert_eq!(
            serde_json::to_value(attribution).unwrap(),
            serde_json::json!({"member_id": "m-1", "team_ids": ["t-1"], "team_names": ["Payments"], "tenant_id": "acme"})
        );
    }
}
