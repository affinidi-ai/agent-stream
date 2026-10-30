//! Appliance-wide (global) policy assignments: reusable policies enforced on
//! **every** surface of a given type (e.g. every LLM Surface), independent of
//! each surface's own OPA configuration. Evaluated deny-overrides alongside the
//! per-surface policies at the enforcement point.

use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// The fixed document id — there is exactly one global-assignments document.
const GLOBAL_DOC_ID: &str = "global";

/// One globally-enforced policy assignment.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobalAssignment {
    /// Stored policy-definition id enforced globally for the type.
    pub policy_id: String,
    /// When true the policy is evaluated and recorded but **not** enforced (a
    /// would-be deny is logged and the request proceeds) — for safe rollout.
    #[serde(default)]
    pub monitor_only: bool,
}

/// Appliance-wide policy assignments, keyed by policy type (`llm`, `ide`, and
/// any future surface type). Persisted as a single document.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct GlobalPolicyAssignments {
    /// Ordered assignments per type. A missing/empty key means no global policy
    /// is enforced for that type.
    #[serde(default)]
    pub assignments: HashMap<String, Vec<GlobalAssignment>>,
}

impl GlobalPolicyAssignments {
    /// The assignments for a policy type (`llm` / `ide`), or an empty slice.
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn for_type(
        &self,
        policy_type: &str,
    ) -> &[GlobalAssignment] {
        self.assignments
            .get(policy_type)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Whether any assignment (across all types) references `policy_id` — used
    /// to recompile the global set when a referenced policy definition changes.
    pub fn references_policy(
        &self,
        policy_id: &str,
    ) -> bool {
        self.assignments
            .values()
            .flatten()
            .any(|a| a.policy_id == policy_id)
    }

    /// The policy types (`llm` / `ide`) that enforce `policy_id` appliance-wide —
    /// used to report a policy's blast radius.
    pub fn types_enforcing(
        &self,
        policy_id: &str,
    ) -> Vec<String> {
        self.assignments
            .iter()
            .filter(|(_, list)| {
                list.iter()
                    .any(|a| a.policy_id == policy_id)
            })
            .map(|(policy_type, _)| policy_type.clone())
            .collect()
    }
}

/// Row wrapper so the single global-assignments document can be stored via the
/// id-keyed [`StorableEntity`] filesystem backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GlobalPolicyDocument {
    #[serde(default = "global_doc_id")]
    id: String,
    #[serde(flatten)]
    assignments: GlobalPolicyAssignments,
}

fn global_doc_id() -> String {
    GLOBAL_DOC_ID.to_string()
}

impl StorableEntity for GlobalPolicyDocument {
    fn id(&self) -> &str {
        &self.id
    }
}

/// File-based store for the single global policy-assignments document.
pub struct FileSystemGlobalPolicyStore {
    storage: Box<dyn StorageBackend<GlobalPolicyDocument>>,
}

impl FileSystemGlobalPolicyStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "global_policy").await?;
        Ok(Self { storage })
    }

    /// Re-read the assignments from disk.
    pub async fn refresh_from_disk(&self) -> Result<()> {
        self.storage
            .refresh_from_disk()
            .await
    }

    /// Load the current assignments (empty when none have been saved yet).
    pub async fn get(&self) -> GlobalPolicyAssignments {
        self.storage
            .get(GLOBAL_DOC_ID)
            .await
            .ok()
            .flatten()
            .map(|d| d.assignments)
            .unwrap_or_default()
    }

    /// Replace the assignments document.
    pub async fn save(
        &self,
        assignments: GlobalPolicyAssignments,
    ) -> Result<()> {
        self.storage
            .save(&GlobalPolicyDocument {
                id: GLOBAL_DOC_ID.to_string(),
                assignments,
            })
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn for_type_and_references() {
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            "llm".to_string(),
            vec![
                GlobalAssignment {
                    policy_id: "p1".to_string(),
                    monitor_only: false,
                },
                GlobalAssignment {
                    policy_id: "p2".to_string(),
                    monitor_only: true,
                },
            ],
        );
        assert_eq!(a.for_type("llm").len(), 2);
        assert!(a.for_type("ide").is_empty());
        assert!(a.references_policy("p2"));
        assert!(!a.references_policy("nope"));
        assert_eq!(a.types_enforcing("p1"), vec!["llm".to_string()]);
        assert!(
            a.types_enforcing("nope")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn store_round_trips() {
        let dir = tempfile::tempdir().expect("tempdir");
        let store = FileSystemGlobalPolicyStore::new(
            dir.path()
                .to_string_lossy()
                .to_string(),
        )
        .await
        .expect("store");
        // Empty by default.
        assert!(
            store
                .get()
                .await
                .assignments
                .is_empty()
        );
        let mut a = GlobalPolicyAssignments::default();
        a.assignments.insert(
            "llm".to_string(),
            vec![GlobalAssignment {
                policy_id: "p1".to_string(),
                monitor_only: false,
            }],
        );
        store
            .save(a.clone())
            .await
            .expect("save");
        assert_eq!(store.get().await, a);
    }
}
