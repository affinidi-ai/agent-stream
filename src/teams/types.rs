//! Team entity types.
//!
//! A [`Team`] groups appliance **members** (clients, referenced by their UUID)
//! so their spend and token usage across **any** surface can be aggregated and
//! capped. Attribution is surface-type agnostic: a surface contributes a single
//! per-execution `(cost, tokens)` pair regardless of whether it is an LLM
//! surface, a Memory surface, or any future surface type. Per-member ceilings
//! live on the [`crate::members::Member`] itself; a team owns only its team-wide
//! caps.

use crate::entity_status::EntityStatus;
use crate::storage::filesystem::StorableEntity;
use serde::{Deserialize, Serialize};

/// Serde predicate: skip serialising a `false` boolean (keeps the wire shape of
/// an ordinary team unchanged when the test-fixture flag is unset).
fn is_false(value: &bool) -> bool {
    !*value
}

/// Stable id of the built-in **anonymous** team. The appliance always seeds this
/// team (containing the anonymous member) so any caller that resolves to no
/// real team still lands in a team. Disabling it (status `Disabled`) is how an
/// admin requires explicit team membership, with no special-case code path.
pub const ANONYMOUS_TEAM_ID: &str = "anonymous";

/// Stable id of the built-in **sandbox** team. Sandbox (Test) executions are
/// attributed to this team (containing the sandbox member) so test traffic
/// reconciles against the surface totals while staying separable from real
/// anonymous/live traffic. Seeded like the anonymous team and protected by the
/// [`Team::system`] flag.
pub const SANDBOX_TEAM_ID: &str = "sandbox";

/// A team (group) of members whose usage is aggregated and capped together.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Team {
    /// Server-assigned UUID. Doubles as the storage filename and the identity
    /// that links members to this team.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Lifecycle status. A `Deleted` team is tombstoned: hidden from listings
    /// and ignored for attribution, but retained on disk so historical usage
    /// stays attributable.
    #[serde(default)]
    pub status: EntityStatus,

    /// Built-in system record flag. `true` for teams seeded from the
    /// default-config directory (e.g. the anonymous team). System records can be
    /// disabled but never deleted. Server-controlled — clients cannot set it.
    #[serde(default)]
    pub system: bool,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Marks an ephemeral test-fixture team (e.g. created by the testkit). The
    /// runtime ignores this flag; it only lets the debug-/test-mode-only purge
    /// endpoint (`POST /v1/test-support/purge`) find and **hard-delete** every
    /// fixture team in one call. Mirrors
    /// [`crate::pipes::PipeConfig::test_surface`].
    #[serde(default, skip_serializing_if = "is_false")]
    pub test_fixture: bool,

    /// Team-wide monthly USD ceiling across every member's combined spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    /// Team-wide monthly token ceiling across every member's combined usage.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_token_cap: Option<u64>,

    /// Member UUIDs that belong to this team (see [`crate::members::Member`]).
    #[serde(default)]
    pub members: Vec<String>,

    #[serde(default)]
    pub created_at: chrono::DateTime<chrono::Utc>,
    #[serde(default)]
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl Team {
    /// Whether `member_id` belongs to this team.
    pub fn has_member(
        &self,
        member_id: &str,
    ) -> bool {
        self.members
            .iter()
            .any(|m| m == member_id)
    }

    /// Validate the team's invariants. Member ids are UUID references resolved
    /// against the member registry by the caller.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("team id must not be empty".to_string());
        }
        if self.name.trim().is_empty() {
            return Err("team name must not be empty".to_string());
        }
        if let Some(b) = self.monthly_budget_usd
            && b < 0.0
        {
            return Err("team monthly budget must not be negative".to_string());
        }

        let mut seen = std::collections::HashSet::new();
        for member_id in &self.members {
            if member_id.trim().is_empty() {
                return Err("team member id must not be empty".to_string());
            }
            if !seen.insert(member_id.clone()) {
                return Err(format!("duplicate team member '{member_id}'"));
            }
        }
        Ok(())
    }

    /// Drop blank member ids and de-duplicate while preserving order.
    pub fn normalize(&mut self) {
        let mut seen = std::collections::HashSet::new();
        self.members
            .retain(|m| !m.trim().is_empty() && seen.insert(m.clone()));
    }
}

impl StorableEntity for Team {
    fn id(&self) -> &str {
        &self.id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_team() -> Team {
        Team {
            id: "team-1".to_string(),
            name: "Engineering".to_string(),
            description: None,
            status: EntityStatus::Enabled,
            system: false,
            tenant_id: None,
            test_fixture: false,
            monthly_budget_usd: Some(100.0),
            monthly_token_cap: None,
            members: vec!["m-alice".to_string()],
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        }
    }

    #[test]
    fn has_member_matches_uuid() {
        let team = base_team();
        assert!(team.has_member("m-alice"));
        assert!(!team.has_member("m-eve"));
    }

    #[test]
    fn validate_rejects_blank_name() {
        let mut team = base_team();
        team.name = "  ".to_string();
        assert!(team.validate().is_err());
    }

    #[test]
    fn validate_rejects_duplicate_members() {
        let mut team = base_team();
        team.members
            .push("m-alice".to_string());
        assert!(team.validate().is_err());
    }

    #[test]
    fn validate_rejects_negative_budget() {
        let mut team = base_team();
        team.monthly_budget_usd = Some(-1.0);
        assert!(team.validate().is_err());
    }

    #[test]
    fn normalize_dedups_and_drops_blanks() {
        let mut team = base_team();
        team.members = vec!["m-alice".to_string(), "  ".to_string(), "m-alice".to_string(), "m-bob".to_string()];
        team.normalize();
        assert_eq!(team.members, vec!["m-alice".to_string(), "m-bob".to_string()]);
    }

    #[test]
    fn validate_accepts_well_formed_team() {
        let team = base_team();
        assert!(team.validate().is_ok());
    }
}
