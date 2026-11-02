//! Shared lifecycle status for registry entities.
//!
//! Members, teams, LLM surfaces (pipes), and agent surfaces all share one
//! soft-delete lifecycle: an entity is never physically removed, only marked.
//! `Enabled` participates in routing/attribution, `Disabled` is retained but
//! inert, and `Deleted` is a tombstone hidden from listings yet preserved on
//! disk so historical usage attribution and audit trails stay intact.

use serde::{Deserialize, Serialize};

/// Lifecycle status of a registry entity (member, team, surface).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
#[cfg_attr(test, derive(ts_rs::TS))]
#[cfg_attr(test, ts(export, export_to = "../www/src/generated/", rename_all = "lowercase"))]
pub enum EntityStatus {
    /// Active: participates in routing, attribution, and quotas.
    #[default]
    Enabled,
    /// Retained but inert: not routed, not attributed.
    Disabled,
    /// Tombstone: hidden from listings, preserved on disk for history/audit.
    Deleted,
}

impl EntityStatus {
    /// Whether the entity is live (participates in routing/attribution).
    pub fn is_enabled(&self) -> bool {
        matches!(self, Self::Enabled)
    }

    /// Whether the entity has been soft-deleted (tombstoned).
    pub fn is_deleted(&self) -> bool {
        matches!(self, Self::Deleted)
    }
}

impl std::fmt::Display for EntityStatus {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::Enabled => write!(f, "enabled"),
            Self::Disabled => write!(f, "disabled"),
            Self::Deleted => write!(f, "deleted"),
        }
    }
}
