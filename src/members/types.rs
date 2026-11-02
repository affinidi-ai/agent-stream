//! Member entity types.
//!
//! A [`Member`] is a **client** of the appliance — a caller that consumes LLM
//! (or any future surface) capacity. Members are identified by a configurable
//! credential ([`MemberIdentifier`]) read from the inbound request, and are
//! deliberately detached from the administrator users (`crate::auth_manager`)
//! who sign in to operate the appliance: a client never needs sign-in access.
//!
//! The server assigns each member a stable UUID id; [`crate::teams::types::Team`]
//! references members by that id, and per-member spend/token caps live here so a
//! member's ceiling spans every team and surface they touch.

use crate::entity_status::EntityStatus;
use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Serde predicate: skip serialising a `false` boolean (keeps the wire shape of
/// an ordinary member unchanged when the test-fixture flag is unset).
fn is_false(value: &bool) -> bool {
    !*value
}

/// Stable id of the built-in **anonymous** member. The appliance always seeds
/// this member so the attribution gate has a default identity for callers that
/// can't be matched to a real member. Disabling it (status `Disabled`) is how an
/// admin turns on "recognised callers only" without any special-case code path.
pub const ANONYMOUS_MEMBER_ID: &str = "anonymous";

/// Stable id of the built-in **sandbox** member. Sandbox (Test) executions have
/// no resolved caller, so their usage is attributed to this member instead of
/// the anonymous one — keeping test traffic visible in the usage views yet
/// distinguishable from real anonymous/live callers. Seeded like the anonymous
/// member and protected by the [`Member::system`] flag.
pub const SANDBOX_MEMBER_ID: &str = "sandbox";

/// Stable id of the built-in **drift runner** member. Replay-evaluation traffic
/// has no resolved caller, so its usage is attributed to this member — keeping
/// evaluation spend visible in the usage views (it is real provider spend) yet
/// distinguishable from live callers, the same way sandbox traffic is.
pub const DRIFT_MEMBER_ID: &str = "drift-runner";

/// Normalise an identifier value for storage and matching: trimmed and
/// lowercased. Emails, API-key names, and JWT subjects are matched
/// case-insensitively to mirror the caller-extraction path.
pub fn normalize_identifier(value: &str) -> String {
    value.trim().to_lowercase()
}

/// Minimal structural validation for an email address. Deliberately permissive
/// (a single `@` with non-empty local part and a dotted domain) rather than a
/// full RFC 5322 validator.
pub fn is_plausible_email(email: &str) -> bool {
    let parts: Vec<&str> = email.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty() && parts[1].contains('.')
}

/// How a member is recognised in an inbound request. The *source* (which header,
/// JWT claim, mTLS field, or API key to read) is configured per surface via
/// [`crate::teams::caller_identity::CallerIdentitySource`]; this is the concrete
/// value that maps the extracted credential to a specific member.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MemberIdentifier {
    /// An email address (e.g. from a header, JWT `email` claim, or mTLS SAN).
    Email { email: String },
    /// A JWT `sub` or any opaque subject identifier.
    Subject { subject: String },
    /// The validated API key's name.
    ApiKey { key_name: String },
    /// An arbitrary header or claim value, matched verbatim (case-insensitively).
    Custom { value: String },
}

impl MemberIdentifier {
    /// The normalised value used to match an extracted caller credential.
    pub fn match_value(&self) -> String {
        let raw = match self {
            MemberIdentifier::Email { email } => email,
            MemberIdentifier::Subject { subject } => subject,
            MemberIdentifier::ApiKey { key_name } => key_name,
            MemberIdentifier::Custom { value } => value,
        };
        normalize_identifier(raw)
    }

    /// Validate the identifier in isolation.
    pub fn validate(&self) -> Result<(), String> {
        if self.match_value().is_empty() {
            return Err("member identifier value must not be empty".to_string());
        }
        if let MemberIdentifier::Email { email } = self
            && !is_plausible_email(&normalize_identifier(email))
        {
            return Err(format!("member identifier '{email}' is not a valid email"));
        }
        Ok(())
    }
}

/// Deserialize a member's identifier list from either the current array form
/// (`identifiers: [ … ]`) or the **legacy singular** form (`identifier: { … }`).
/// The `#[serde(alias = "identifier")]` on the field routes the old key here, so
/// a single stored object is folded into a one-element vector. New records are
/// always serialized as the array.
fn de_identifiers<'de, D>(deserializer: D) -> Result<Vec<MemberIdentifier>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(MemberIdentifier),
        Many(Vec<MemberIdentifier>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(single) => vec![single],
        OneOrMany::Many(list) => list,
    })
}

/// A client of the appliance whose cross-surface usage is attributed and capped.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Member {
    /// Server-assigned UUID. Doubles as the storage filename and the reference
    /// teams use to link the member.
    pub id: String,
    /// Optional display name; falls back to the identifier value when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Lifecycle status. A `Deleted` member is tombstoned: hidden from listings
    /// and excluded from attribution, but retained on disk so historical usage
    /// stays attributable.
    #[serde(default)]
    pub status: EntityStatus,

    /// Built-in system record flag. `true` for members seeded from the
    /// default-config directory (e.g. the anonymous member). System records can
    /// be disabled but never deleted. Server-controlled — clients cannot set it.
    #[serde(default)]
    pub system: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Marks an ephemeral test-fixture member (e.g. created by the testkit). The
    /// runtime ignores this flag; it only lets the debug-/test-mode-only purge
    /// endpoint (`POST /v1/test-support/purge`) find and **hard-delete** every
    /// fixture member in one call. Mirrors
    /// [`crate::pipes::PipeConfig::test_surface`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub test_fixture: bool,

    /// Marks a member that was **auto-provisioned** on first sight from a
    /// verified caller identity (see [`crate::members::provisioning`]) rather
    /// than created by an administrator. Lets the UI badge such rows and an
    /// admin "adopt" them. Server-controlled; a client cannot set it.
    #[serde(default, skip_serializing_if = "is_false")]
    pub auto_provisioned: bool,

    /// How an inbound request is matched to this member. A member may present
    /// under several credentials (e.g. an Entra `oid`, an `email`, and an
    /// mTLS SAN), so any of these values resolves the caller. Serialized as an
    /// array; a legacy singular `identifier` object is still accepted on read.
    #[serde(default, alias = "identifier", deserialize_with = "de_identifiers")]
    pub identifiers: Vec<MemberIdentifier>,

    /// Member-wide monthly USD ceiling across every team and surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    /// Member-wide monthly token ceiling across every team and surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_token_cap: Option<u64>,
    /// When set, the monthly budget and token cap reset on the monthly
    /// anniversary of this instant instead of on the 1st of the month (UTC).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_period_anchor: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-minute request rate limit for this member (the "virtual key" RPM).
    /// `None` ⇒ no per-minute request cap. Enforced by the team gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requests_per_minute: Option<u32>,
    /// Per-minute token rate limit for this member (the "virtual key" TPM),
    /// counted over a trailing 60s window. `None` ⇒ no per-minute token cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokens_per_minute: Option<u64>,

    /// Model allow-list for this member (the "virtual key" scope). When `Some`
    /// and non-empty, a request whose `model` is not in the list is rejected
    /// (403) by the team gate. `None` or empty ⇒ no model restriction. A
    /// request that omits `model` (surface-controlled model) is never blocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_models: Option<Vec<String>>,

    #[serde(default)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Member {
    /// Whether this is the built-in anonymous member. Used by the attribution
    /// gate to phrase the "recognised callers only" denial; deletion protection
    /// is driven by the [`Member::system`] flag, not this id.
    pub fn is_anonymous(&self) -> bool {
        self.id == ANONYMOUS_MEMBER_ID
    }

    /// The normalised value used to match an extracted caller credential.
    pub fn match_value(&self) -> String {
        self.identifiers
            .first()
            .map(|i| i.match_value())
            .unwrap_or_default()
    }

    /// Every normalised identifier value this member can be matched by.
    pub fn match_values(&self) -> Vec<String> {
        self.identifiers
            .iter()
            .map(|i| i.match_value())
            .filter(|v| !v.is_empty())
            .collect()
    }

    /// Whether the extracted caller credential `value` (already normalised)
    /// matches any of this member's identifiers.
    pub fn matches(
        &self,
        value: &str,
    ) -> bool {
        self.identifiers
            .iter()
            .any(|i| i.match_value() == value)
    }

    /// A human-friendly label: the name when set, otherwise the first identifier
    /// value.
    pub fn display_label(&self) -> String {
        self.name
            .clone()
            .filter(|n| !n.trim().is_empty())
            .unwrap_or_else(|| self.match_value())
    }

    /// Whether this member (virtual key) may invoke `requested_model`.
    ///
    /// Returns `true` when the member has no model allow-list (the common
    /// unrestricted case), when the list is empty, or when the request omits a
    /// model (surface-controlled). Otherwise the requested model must appear in
    /// the allow-list verbatim.
    pub fn model_allowed(
        &self,
        requested_model: Option<&str>,
    ) -> bool {
        match self.allowed_models.as_ref() {
            None => true,
            Some(list) if list.is_empty() => true,
            Some(list) => match requested_model {
                None => true,
                Some(model) => list
                    .iter()
                    .any(|allowed| allowed == model),
            },
        }
    }

    /// The budget window containing `now`.
    pub fn budget_period(
        &self,
        now: chrono::DateTime<chrono::Utc>,
    ) -> crate::members::budget_period::BudgetPeriod {
        crate::members::budget_period::BudgetPeriod::containing(self.budget_period_anchor, now)
    }

    /// Validate the member's invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("member id must not be empty".to_string());
        }
        if self.identifiers.is_empty() {
            return Err("member must have at least one identifier".to_string());
        }
        for identifier in &self.identifiers {
            identifier.validate()?;
        }
        if let Some(b) = self.monthly_budget_usd
            && b < 0.0
        {
            return Err("member monthly budget must not be negative".to_string());
        }
        Ok(())
    }
}

impl StorableEntity for Member {
    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn member(identifier: MemberIdentifier) -> Member {
        Member {
            id: "m1".to_string(),
            name: None,
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![identifier],
            monthly_budget_usd: None,
            monthly_token_cap: None,
            budget_period_anchor: None,
            requests_per_minute: None,
            tokens_per_minute: None,
            allowed_models: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn match_value_normalizes_case_and_whitespace() {
        let m = member(MemberIdentifier::Email {
            email: "  Alice@Example.COM ".to_string(),
        });
        assert_eq!(m.match_value(), "alice@example.com");
    }

    #[test]
    fn api_key_identifier_matches_normalized() {
        let m = member(MemberIdentifier::ApiKey {
            key_name: "Service-Key".to_string(),
        });
        assert_eq!(m.match_value(), "service-key");
    }

    #[test]
    fn display_label_prefers_name_then_identifier() {
        let mut m = member(MemberIdentifier::Subject { subject: "sub-123".to_string() });
        assert_eq!(m.display_label(), "sub-123");
        m.name = Some("Carol".to_string());
        assert_eq!(m.display_label(), "Carol");
    }

    #[test]
    fn validate_rejects_blank_identifier() {
        let m = member(MemberIdentifier::Custom { value: "   ".to_string() });
        assert!(m.validate().is_err());
    }

    #[test]
    fn validate_rejects_bad_email_identifier() {
        let m = member(MemberIdentifier::Email { email: "nope".to_string() });
        assert!(m.validate().is_err());
    }

    #[test]
    fn validate_accepts_plausible_email() {
        let m = member(MemberIdentifier::Email {
            email: "dev@team.io".to_string(),
        });
        assert!(m.validate().is_ok());
    }

    #[test]
    fn validate_rejects_negative_budget() {
        let mut m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        m.monthly_budget_usd = Some(-1.0);
        assert!(m.validate().is_err());
    }

    #[test]
    fn model_allowed_unrestricted_when_no_list() {
        let m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        assert!(m.model_allowed(Some("gpt-4o")));
        assert!(m.model_allowed(None));
    }

    #[test]
    fn model_allowed_empty_list_is_unrestricted() {
        let mut m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        m.allowed_models = Some(vec![]);
        assert!(m.model_allowed(Some("gpt-4o")));
    }

    #[test]
    fn model_allowed_enforces_list() {
        let mut m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        m.allowed_models = Some(vec!["gpt-4o-mini".to_string(), "text-embedding-3-small".to_string()]);
        assert!(m.model_allowed(Some("gpt-4o-mini")));
        assert!(m.model_allowed(Some("text-embedding-3-small")));
        assert!(!m.model_allowed(Some("gpt-4o")));
        // A request that omits the model is surface-controlled ⇒ allowed.
        assert!(m.model_allowed(None));
    }

    #[test]
    fn member_with_anonymous_id_is_flagged() {
        let mut m = member(MemberIdentifier::Custom {
            value: ANONYMOUS_MEMBER_ID.to_string(),
        });
        m.id = ANONYMOUS_MEMBER_ID.to_string();
        assert!(m.is_anonymous());
        assert!(m.validate().is_ok());
    }

    #[test]
    fn non_anonymous_member_is_not_flagged() {
        let m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        assert!(!m.is_anonymous());
    }

    #[test]
    fn matches_any_of_several_identifiers() {
        let mut m = member(MemberIdentifier::Subject { subject: "oid-123".to_string() });
        m.identifiers
            .push(MemberIdentifier::Email {
                email: "Dev@Team.io".to_string(),
            });
        m.identifiers
            .push(MemberIdentifier::ApiKey {
                key_name: "Svc-Key".to_string(),
            });
        assert!(m.matches("oid-123"));
        assert!(m.matches("dev@team.io"));
        assert!(m.matches("svc-key"));
        assert!(!m.matches("unknown"));
        assert_eq!(m.match_values(), vec!["oid-123", "dev@team.io", "svc-key"]);
    }

    #[test]
    fn validate_rejects_member_with_no_identifiers() {
        let mut m = member(MemberIdentifier::Custom { value: "abc".to_string() });
        m.identifiers.clear();
        assert!(m.validate().is_err());
    }

    #[test]
    fn deserializes_legacy_singular_identifier() {
        // A stored record from before multi-identifier support carries a single
        // `identifier` object; it must fold into the one-element list.
        let json = serde_json::json!({
            "id": "m9",
            "status": "enabled",
            "identifier": { "kind": "email", "email": "legacy@team.io" }
        });
        let m: Member = serde_json::from_value(json).unwrap();
        assert_eq!(m.identifiers.len(), 1);
        assert!(m.matches("legacy@team.io"));
    }

    #[test]
    fn deserializes_identifiers_array() {
        let json = serde_json::json!({
            "id": "m10",
            "status": "enabled",
            "identifiers": [
                { "kind": "subject", "subject": "oid-1" },
                { "kind": "email", "email": "user@team.io" }
            ]
        });
        let m: Member = serde_json::from_value(json).unwrap();
        assert_eq!(m.identifiers.len(), 2);
        assert!(m.matches("oid-1"));
        assert!(m.matches("user@team.io"));
    }

    #[test]
    fn serializes_to_identifiers_array() {
        let m = member(MemberIdentifier::Email {
            email: "dev@team.io".to_string(),
        });
        let value = serde_json::to_value(&m).unwrap();
        assert!(
            value
                .get("identifiers")
                .is_some()
        );
        assert!(
            value
                .get("identifier")
                .is_none()
        );
    }

    #[test]
    fn budget_period_anchor_round_trips_and_is_omitted_when_unset() {
        let mut m = member(MemberIdentifier::Email {
            email: "dev@team.io".to_string(),
        });
        let unset = serde_json::to_value(&m).unwrap();
        assert!(
            unset
                .get("budget_period_anchor")
                .is_none()
        );

        let anchor = chrono::DateTime::parse_from_rfc3339("2026-09-27T09:14:22.336488Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        m.budget_period_anchor = Some(anchor);
        let back: Member = serde_json::from_value(serde_json::to_value(&m).unwrap()).unwrap();
        assert_eq!(back.budget_period_anchor, Some(anchor));
        assert_eq!(
            back.budget_period(anchor + chrono::Duration::days(3))
                .start,
            anchor
        );
    }
}
