//! Surface-level opt-in configuration for team attribution.
//!
//! This is attached to a surface ([`crate::pipes::config::PipeConfig`]) and is
//! deliberately surface-type agnostic: it only describes *where the caller
//! email lives* and *whether to enforce*. The actual `(cost, tokens)` a surface
//! contributes comes from that surface's own execution metrics, so LLM, Memory,
//! and any future surface type share this exact config.

use crate::teams::caller_identity::CallerIdentitySource;
use serde::{Deserialize, Serialize};

/// Deserialize the caller-identity source list from either the current array
/// form (`caller_identity_sources: [ … ]`) or the **legacy singular** form
/// (`caller_email_source: { … }`). The `#[serde(alias = "caller_email_source")]`
/// on the field routes the old key here, folding a single object into a
/// one-element vector. New records serialize as the array.
fn de_identity_sources<'de, D>(deserializer: D) -> Result<Vec<CallerIdentitySource>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(CallerIdentitySource),
        Many(Vec<CallerIdentitySource>),
    }
    Ok(match OneOrMany::deserialize(deserializer)? {
        OneOrMany::One(single) => vec![single],
        OneOrMany::Many(list) => list,
    })
}

/// Opt-in for a surface to contribute its usage to team quotas.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TeamAttributionConfig {
    /// Master switch: "Surface use contributes to team quotas".
    #[serde(default)]
    pub enabled: bool,

    /// Ordered list of places to look for the caller's identity. The gate uses
    /// the **first** source that yields a non-empty value, so a surface can try
    /// e.g. `[jwt_claim(oid), jwt_claim(email), api_key]` and use whichever the
    /// caller presents. A legacy singular `caller_email_source` object is still
    /// accepted on read and folded into a one-element list.
    #[serde(default, alias = "caller_email_source", deserialize_with = "de_identity_sources")]
    pub caller_identity_sources: Vec<CallerIdentitySource>,

    /// When set, an unrecognised but **verified** caller (JWT / mTLS / API key)
    /// is auto-provisioned into a member on first sight per the appliance's
    /// [`crate::members::provisioning::MemberProvisioningConfig`], instead of
    /// falling back to the anonymous member. Has no effect for unauthenticated
    /// callers or when no provisioning config is active.
    #[serde(default)]
    pub auto_provision: bool,

    /// When set, enforce the caller's and their teams' caps with HTTP 429: a
    /// reached token cap or per-minute rate blocks the request at the gate, and
    /// a spent budget refuses each call the request makes on a platform key
    /// (a call on the caller's or the customer's own key still runs; see
    /// [`crate::teams::call_budget`]). When clear, usage is recorded for
    /// reporting but never blocks.
    #[serde(default)]
    pub enforce: bool,

    /// Surface-owner override: when set, a caller may exceed their personal
    /// per-member cap (only team-wide caps still block). Has no effect unless
    /// `enforce` is set.
    #[serde(default)]
    pub allow_individual_overage: bool,

    /// Surface→team access mapping. When non-empty, only callers belonging to
    /// at least one of these team ids may use the surface; everyone else
    /// (including the anonymous fallback unless its team id is listed) is
    /// denied with HTTP 403. When empty, every resolved caller is allowed. This
    /// is access control and applies regardless of `enforce` (which governs
    /// quota blocking only).
    #[serde(default)]
    pub allowed_teams: Vec<String>,
}

impl TeamAttributionConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self
            .caller_identity_sources
            .is_empty()
        {
            return Err("team attribution requires at least one caller identity source".to_string());
        }
        for source in &self.caller_identity_sources {
            source.validate()?;
        }
        if self
            .allowed_teams
            .iter()
            .any(|t| t.trim().is_empty())
        {
            return Err("allowed_teams must not contain blank team ids".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> TeamAttributionConfig {
        TeamAttributionConfig {
            enabled: true,
            caller_identity_sources: vec![CallerIdentitySource::Header { name: "x-caller".to_string() }],
            auto_provision: false,
            enforce: false,
            allow_individual_overage: false,
            allowed_teams: vec![],
        }
    }

    #[test]
    fn validate_skips_when_disabled() {
        let mut c = config();
        c.enabled = false;
        c.caller_identity_sources = vec![CallerIdentitySource::Header { name: String::new() }];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_accepts_allowed_teams() {
        let mut c = config();
        c.allowed_teams = vec!["engineering".to_string(), "anonymous".to_string()];
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_blank_allowed_team() {
        let mut c = config();
        c.allowed_teams = vec!["engineering".to_string(), "  ".to_string()];
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_blank_header_name_when_enabled() {
        let mut c = config();
        c.caller_identity_sources = vec![CallerIdentitySource::Header { name: String::new() }];
        assert!(c.validate().is_err());
    }

    #[test]
    fn validate_rejects_empty_sources_when_enabled() {
        let mut c = config();
        c.caller_identity_sources = vec![];
        assert!(c.validate().is_err());
    }

    #[test]
    fn deserializes_legacy_singular_source() {
        let json = serde_json::json!({
            "enabled": true,
            "caller_email_source": { "type": "jwt_claim", "claim": "email" }
        });
        let c: TeamAttributionConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            c.caller_identity_sources
                .len(),
            1
        );
        assert!(c.validate().is_ok());
    }

    #[test]
    fn deserializes_source_array() {
        let json = serde_json::json!({
            "enabled": true,
            "caller_identity_sources": [
                { "type": "jwt_claim", "claim": "oid" },
                { "type": "jwt_claim", "claim": "email" }
            ]
        });
        let c: TeamAttributionConfig = serde_json::from_value(json).unwrap();
        assert_eq!(
            c.caller_identity_sources
                .len(),
            2
        );
    }
}
