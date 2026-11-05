//! Member storage backend.
//!
//! File-backed, DashMap-cached storage for [`Member`] records, mirroring
//! [`crate::teams::store::FileSystemTeamStore`]. Stored under `_storage/members`
//! (one `{uuid}.json` per member), authoritative cache in memory, immediate disk
//! writes.

use crate::members::types::{Member, normalize_identifier};
use crate::server::mode::ReloadOnPromotion;
use crate::storage::filesystem::{StorageBackend, rwlock_storage};
use anyhow::{Context, Result};
use dashmap::DashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use tracing::warn;

/// Process-wide member store, registered at startup so the data-plane team gate
/// can resolve a caller's member record without threading the store through
/// every surface handler.
static GLOBAL_MEMBER_STORE: OnceLock<Arc<FileSystemMemberStore>> = OnceLock::new();

/// Register the process-wide member store. First write wins.
pub fn set_global_member_store(store: Arc<FileSystemMemberStore>) {
    let _ = GLOBAL_MEMBER_STORE.set(store);
}

/// Access the process-wide member store, if one has been registered.
pub fn global_member_store() -> Option<Arc<FileSystemMemberStore>> {
    GLOBAL_MEMBER_STORE
        .get()
        .cloned()
}

/// File-based storage for member records.
///
/// `identifier_index` maps each member's normalised identifier value to its id
/// so the hot-path caller lookup ([`FileSystemMemberStore::find_for_gate`]) is
/// O(1) instead of scanning every member on every request. The index is an
/// accelerator: lookups always re-verify against the fetched member and fall
/// back to a linear scan on a miss, so a stale entry never yields a wrong match.
pub struct FileSystemMemberStore {
    storage: Box<dyn StorageBackend<Member>>,
    identifier_index: DashMap<String, String>,
}

impl FileSystemMemberStore {
    pub async fn new(storage_dir: String) -> Result<Self> {
        let storage_path = PathBuf::from(storage_dir);
        let storage = rwlock_storage(storage_path, "member").await?;
        let store = Self {
            storage,
            identifier_index: DashMap::new(),
        };
        store.rebuild_index().await;
        Ok(store)
    }

    /// Rebuild the identifier index from the current member set. Called once at
    /// construction; the index is then maintained incrementally on `save`.
    async fn rebuild_index(&self) {
        self.identifier_index.clear();
        for member in self.list().await {
            if member.status.is_deleted() {
                continue;
            }
            for value in member.match_values() {
                self.identifier_index
                    .insert(value, member.id.clone());
            }
        }
    }

    /// Get a member by id.
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<Member> {
        self.storage
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// List all members.
    pub async fn list(&self) -> Vec<Member> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Create or update a member. Stamps `updated_at` before persisting and
    /// keeps the identifier index in sync.
    pub async fn save(
        &self,
        mut member: Member,
    ) -> Result<()> {
        member.updated_at = chrono::Utc::now();
        // Drop any stale index entries pointing at this member (its identifier
        // set may have changed), then re-add the current values.
        self.identifier_index
            .retain(|_, id| id != &member.id);
        if !member.status.is_deleted() {
            for value in member.match_values() {
                self.identifier_index
                    .insert(value, member.id.clone());
            }
        }
        self.storage
            .save(&member)
            .await
    }

    /// Whether a member with `id` exists.
    pub async fn exists(
        &self,
        id: &str,
    ) -> bool {
        self.storage
            .exists(id)
            .await
            .unwrap_or(false)
    }

    /// Hard-delete a member by id: physically remove the record from the cache
    /// and disk. Distinct from the soft-delete handler (which tombstones with
    /// `status = deleted`); used only by the debug-/test-mode-only purge path.
    pub async fn delete(
        &self,
        id: &str,
    ) -> Result<()> {
        self.identifier_index
            .retain(|_, v| v != id);
        self.storage.delete(id).await
    }

    /// Find the enabled member whose identifier matches the extracted caller
    /// credential `value` (compared after normalisation). Disabled and deleted
    /// members never match. Returns `None` when no enabled member matches.
    pub async fn find_by_identifier(
        &self,
        value: &str,
    ) -> Option<Member> {
        let normalized = normalize_identifier(value);
        if normalized.is_empty() {
            return None;
        }
        if let Some(member) = self
            .resolve_via_index(&normalized)
            .await
            && member.status.is_enabled()
        {
            return Some(member);
        }
        self.list()
            .await
            .into_iter()
            .find(|m| m.status.is_enabled() && m.matches(&normalized))
    }

    /// Find the member whose identifier matches the extracted caller credential
    /// `value`, including **disabled** members (but never deleted ones). The
    /// attribution gate uses this so it can still recognise a disabled member
    /// and block them, rather than silently falling through to anonymous.
    pub async fn find_for_gate(
        &self,
        value: &str,
    ) -> Option<Member> {
        let normalized = normalize_identifier(value);
        if normalized.is_empty() {
            return None;
        }
        if let Some(member) = self
            .resolve_via_index(&normalized)
            .await
            && !member.status.is_deleted()
        {
            return Some(member);
        }
        self.list()
            .await
            .into_iter()
            .find(|m| !m.status.is_deleted() && m.matches(&normalized))
    }

    /// Resolve a normalised identifier through the index, re-verifying that the
    /// fetched member actually still carries that identifier (so a stale entry
    /// never yields a wrong match). Returns `None` on an index miss or a stale
    /// entry; callers then fall back to a linear scan.
    async fn resolve_via_index(
        &self,
        normalized: &str,
    ) -> Option<Member> {
        let id = self
            .identifier_index
            .get(normalized)
            .map(|entry| entry.clone())?;
        let member = self.get(&id).await?;
        if member.matches(normalized) {
            Some(member)
        } else {
            None
        }
    }

    /// Seed member records from the default-config directory, creating each only
    /// when a member with the same id is absent so an admin's status/cap edits
    /// are never overwritten on restart. Every `*.json` file is parsed and
    /// validated; the built-in anonymous member (and any future system member)
    /// is shipped here rather than hardcoded. Returns the number newly created.
    pub async fn seed_defaults(
        &self,
        seed_dir: &Path,
    ) -> Result<usize> {
        if !seed_dir.exists() {
            warn!("Member seed directory {} not found; no default members seeded", seed_dir.display());
            return Ok(0);
        }
        let mut entries = tokio::fs::read_dir(seed_dir)
            .await
            .with_context(|| format!("reading member seed dir {}", seed_dir.display()))?;
        let mut seeded = 0usize;
        while let Some(entry) = entries
            .next_entry()
            .await
            .with_context(|| format!("scanning member seed dir {}", seed_dir.display()))?
        {
            let path = entry.path();
            if !path.is_file()
                || path
                    .extension()
                    .and_then(|e| e.to_str())
                    != Some("json")
            {
                continue;
            }
            let raw = tokio::fs::read_to_string(&path)
                .await
                .with_context(|| format!("reading member seed {}", path.display()))?;
            let member: Member =
                serde_json::from_str(&raw).with_context(|| format!("parsing member seed {}", path.display()))?;
            member
                .validate()
                .map_err(|e| anyhow::anyhow!("invalid member seed {}: {e}", path.display()))?;
            if self.exists(&member.id).await {
                continue;
            }
            self.save(member).await?;
            seeded += 1;
        }
        Ok(seeded)
    }

    /// Whether any member (regardless of enabled state) already uses
    /// `match_value` for any of its identifiers, excluding the member with id
    /// `exclude_id`. Used to keep identifier values unique across the registry.
    pub async fn identifier_in_use(
        &self,
        match_value: &str,
        exclude_id: Option<&str>,
    ) -> bool {
        let normalized = normalize_identifier(match_value);
        self.list()
            .await
            .into_iter()
            .any(|m| {
                Some(m.id.as_str()) != exclude_id
                    && m.match_values()
                        .iter()
                        .any(|v| v == &normalized)
            })
    }
}

#[async_trait::async_trait]
impl ReloadOnPromotion for FileSystemMemberStore {
    /// Re-read the members another instance stored, so a promoted standby
    /// resolves them instead of provisioning duplicates.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)?;
        self.rebuild_index().await;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity_status::EntityStatus;
    use crate::members::types::{ANONYMOUS_MEMBER_ID, MemberIdentifier};

    async fn store() -> FileSystemMemberStore {
        let dir = std::env::temp_dir().join(format!("member_store_{}", uuid::Uuid::new_v4()));
        FileSystemMemberStore::new(
            dir.to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap()
    }

    fn member(
        id: &str,
        email: &str,
        status: EntityStatus,
    ) -> Member {
        Member {
            id: id.to_string(),
            name: None,
            description: None,
            status,
            system: false,
            tenant_id: None,
            test_fixture: false,
            auto_provisioned: false,
            identifiers: vec![MemberIdentifier::Email { email: email.to_string() }],
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

    #[tokio::test]
    async fn find_by_identifier_excludes_disabled() {
        let store = store().await;
        store
            .save(member("m1", "a@x.io", EntityStatus::Disabled))
            .await
            .unwrap();
        assert!(
            store
                .find_by_identifier("a@x.io")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn find_for_gate_includes_disabled_but_not_deleted() {
        let store = store().await;
        store
            .save(member("m1", "a@x.io", EntityStatus::Disabled))
            .await
            .unwrap();
        store
            .save(member("m2", "b@x.io", EntityStatus::Deleted))
            .await
            .unwrap();

        // Disabled member is still recognised so the gate can block them.
        let found = store
            .find_for_gate("a@x.io")
            .await
            .expect("disabled member resolves for the gate");
        assert_eq!(found.id, "m1");
        assert_eq!(found.status, EntityStatus::Disabled);

        // Deleted member is a tombstone and never resolves.
        assert!(
            store
                .find_for_gate("b@x.io")
                .await
                .is_none()
        );
        assert!(
            store
                .find_for_gate("")
                .await
                .is_none()
        );
    }

    async fn seed_dir_with_anonymous() -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("member_seed_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&dir)
            .await
            .unwrap();
        let json = r#"{"id":"anonymous","name":"Anonymous","status":"enabled","system":true,"identifier":{"kind":"custom","value":"anonymous"}}"#;
        tokio::fs::write(dir.join("anonymous.json"), json)
            .await
            .unwrap();
        dir
    }

    #[tokio::test]
    async fn seed_defaults_creates_missing_system_member() {
        let store = store().await;
        let dir = seed_dir_with_anonymous().await;

        let n = store
            .seed_defaults(&dir)
            .await
            .unwrap();
        assert_eq!(n, 1);
        let seeded = store
            .get(ANONYMOUS_MEMBER_ID)
            .await
            .expect("anonymous member seeded");
        assert!(seeded.status.is_enabled());
        assert!(seeded.system);
        assert!(seeded.is_anonymous());
    }

    #[tokio::test]
    async fn seed_defaults_does_not_overwrite_admin_edits() {
        let store = store().await;
        let dir = seed_dir_with_anonymous().await;
        store
            .seed_defaults(&dir)
            .await
            .unwrap();

        // Admin disables the anonymous member.
        let mut disabled = store
            .get(ANONYMOUS_MEMBER_ID)
            .await
            .unwrap();
        disabled.status = EntityStatus::Disabled;
        store
            .save(disabled)
            .await
            .unwrap();

        // A second seed must not overwrite the admin's change.
        let n = store
            .seed_defaults(&dir)
            .await
            .unwrap();
        assert_eq!(n, 0);
        let after = store
            .get(ANONYMOUS_MEMBER_ID)
            .await
            .unwrap();
        assert_eq!(after.status, EntityStatus::Disabled);
    }

    #[tokio::test]
    async fn seed_defaults_skips_missing_dir() {
        let store = store().await;
        let missing = std::env::temp_dir().join(format!("absent_{}", uuid::Uuid::new_v4()));
        let n = store
            .seed_defaults(&missing)
            .await
            .unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn reload_resolves_members_another_instance_stored() {
        let dir = std::env::temp_dir().join(format!("member_shared_{}", uuid::Uuid::new_v4()));
        let path = dir
            .to_string_lossy()
            .to_string();
        let standby = FileSystemMemberStore::new(path.clone())
            .await
            .unwrap();
        standby
            .save(member("gone", "gone@x.io", EntityStatus::Enabled))
            .await
            .unwrap();
        let active = FileSystemMemberStore::new(path)
            .await
            .unwrap();
        active
            .save(member("m1", "new@x.io", EntityStatus::Enabled))
            .await
            .unwrap();
        active
            .delete("gone")
            .await
            .unwrap();
        assert!(
            standby
                .find_for_gate("new@x.io")
                .await
                .is_none()
        );

        standby
            .reload_from_storage()
            .await
            .unwrap();

        assert_eq!(
            standby
                .find_for_gate("new@x.io")
                .await
                .map(|m| m.id),
            Some("m1".to_string())
        );
        assert!(
            standby
                .find_for_gate("gone@x.io")
                .await
                .is_none()
        );
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn reload_fails_when_storage_is_unreadable() {
        let dir = std::env::temp_dir().join(format!("member_missing_{}", uuid::Uuid::new_v4()));
        let store = FileSystemMemberStore::new(
            dir.to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap();
        store
            .save(member("m1", "kept@x.io", EntityStatus::Enabled))
            .await
            .unwrap();
        tokio::fs::remove_dir_all(&dir)
            .await
            .unwrap();

        assert!(
            store
                .reload_from_storage()
                .await
                .is_err()
        );
        assert_eq!(
            store
                .find_for_gate("kept@x.io")
                .await
                .map(|m| m.id),
            Some("m1".to_string())
        );
    }

    #[tokio::test]
    async fn find_for_gate_resolves_any_identifier_via_index() {
        let store = store().await;
        let mut m = member("m1", "primary@x.io", EntityStatus::Enabled);
        m.identifiers
            .push(MemberIdentifier::Subject { subject: "oid-42".to_string() });
        m.identifiers
            .push(MemberIdentifier::ApiKey {
                key_name: "svc-key".to_string(),
            });
        store.save(m).await.unwrap();

        for value in ["primary@x.io", "oid-42", "svc-key"] {
            let found = store
                .find_for_gate(value)
                .await
                .unwrap_or_else(|| panic!("expected to resolve {value}"));
            assert_eq!(found.id, "m1");
        }
        assert!(
            store
                .find_for_gate("unknown@x.io")
                .await
                .is_none()
        );
    }

    #[tokio::test]
    async fn index_updates_when_identifier_removed() {
        let store = store().await;
        let mut m = member("m1", "a@x.io", EntityStatus::Enabled);
        m.identifiers
            .push(MemberIdentifier::Subject { subject: "oid-1".to_string() });
        store.save(m).await.unwrap();
        assert!(
            store
                .find_for_gate("oid-1")
                .await
                .is_some()
        );

        // Re-save with the subject identifier removed; the stale index entry
        // must no longer resolve.
        let reduced = member("m1", "a@x.io", EntityStatus::Enabled);
        store
            .save(reduced)
            .await
            .unwrap();
        assert!(
            store
                .find_for_gate("oid-1")
                .await
                .is_none()
        );
        assert!(
            store
                .find_for_gate("a@x.io")
                .await
                .is_some()
        );
    }

    #[tokio::test]
    async fn identifier_in_use_checks_all_identifiers() {
        let store = store().await;
        let mut m = member("m1", "a@x.io", EntityStatus::Enabled);
        m.identifiers
            .push(MemberIdentifier::Subject { subject: "oid-9".to_string() });
        store.save(m).await.unwrap();

        assert!(
            store
                .identifier_in_use("oid-9", None)
                .await
        );
        assert!(
            store
                .identifier_in_use("a@x.io", None)
                .await
        );
        assert!(
            !store
                .identifier_in_use("oid-9", Some("m1"))
                .await
        );
        assert!(
            !store
                .identifier_in_use("other@x.io", None)
                .await
        );
    }
}
