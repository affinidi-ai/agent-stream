//! One-time migration of legacy email-keyed teams to the member-UUID model.
//!
//! Earlier builds stored each team under a slug id with inline member objects
//! (`{ email, monthly_budget_usd?, monthly_token_cap? }`) and per-team default
//! per-member caps. The current model gives every team a server-assigned UUID
//! id, references members by their UUID, and moves per-member caps onto the
//! [`crate::members::Member`] entity.
//!
//! This migration runs at startup **before** the team store loads, operating on
//! the raw `*.json` files in the teams directory: for each legacy team it mints
//! (or reuses) [`crate::members::Member`] records for every inline member,
//! rewrites the team file in the new format keyed by a fresh UUID, and removes
//! the old file when the id changed. Teams already in the new format are left
//! untouched, so the migration is idempotent.

use crate::members::store::FileSystemMemberStore;
use crate::members::types::{Member, MemberIdentifier, normalize_identifier};
use anyhow::Result;
use std::path::PathBuf;

/// Migrate every legacy team file under `teams_dir` to the member-UUID model,
/// minting members in `member_store`. Returns the number of teams migrated.
pub async fn migrate_legacy_teams(
    teams_dir: &str,
    member_store: &FileSystemMemberStore,
) -> Result<usize> {
    let dir = PathBuf::from(teams_dir);
    if !dir.exists() {
        return Ok(0);
    }

    let mut migrated = 0usize;
    let mut entries = tokio::fs::read_dir(&dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if path
            .extension()
            .and_then(|e| e.to_str())
            != Some("json")
        {
            continue;
        }

        let bytes = tokio::fs::read(&path).await?;
        let Ok(mut value) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
            continue;
        };
        let Some(obj) = value.as_object_mut() else {
            continue;
        };

        // System records (e.g. the built-in anonymous team) are seeded, never
        // legacy. They carry a fixed non-UUID id by design, so the UUID-id check
        // below would otherwise rewrite them under a fresh UUID on every restart.
        let is_system = obj
            .get("system")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if is_system {
            continue;
        }

        let id_is_uuid = obj
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| uuid::Uuid::parse_str(s).is_ok())
            .unwrap_or(false);
        let members_are_objects = obj
            .get("members")
            .and_then(|m| m.as_array())
            .map(|arr| {
                arr.iter()
                    .any(|m| m.is_object())
            })
            .unwrap_or(false);
        let has_per_member =
            obj.contains_key("per_member_monthly_budget_usd") || obj.contains_key("per_member_monthly_token_cap");

        if id_is_uuid && !members_are_objects && !has_per_member {
            continue;
        }

        let mut new_member_ids: Vec<String> = Vec::new();
        if let Some(members) = obj
            .get("members")
            .and_then(|m| m.as_array())
            .cloned()
        {
            for m in members {
                if let Some(existing_id) = m.as_str() {
                    new_member_ids.push(existing_id.to_string());
                    continue;
                }
                let Some(mo) = m.as_object() else {
                    continue;
                };
                let email = mo
                    .get("email")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                if email.trim().is_empty() {
                    continue;
                }
                let normalized = normalize_identifier(&email);
                let member_id = match member_store
                    .find_by_identifier(&normalized)
                    .await
                {
                    Some(existing) => existing.id,
                    None => {
                        let id = uuid::Uuid::new_v4().to_string();
                        let member = Member {
                            id: id.clone(),
                            name: None,
                            description: None,
                            status: crate::entity_status::EntityStatus::Enabled,
                            system: false,
                            tenant_id: None,
                            test_fixture: false,
                            auto_provisioned: false,
                            identifiers: vec![MemberIdentifier::Email { email: normalized }],
                            monthly_budget_usd: mo
                                .get("monthly_budget_usd")
                                .and_then(|v| v.as_f64()),
                            monthly_token_cap: mo
                                .get("monthly_token_cap")
                                .and_then(|v| v.as_u64()),
                            budget_period_anchor: None,
                            requests_per_minute: None,
                            tokens_per_minute: None,
                            allowed_models: None,
                            created_at: chrono::Utc::now(),
                            updated_at: chrono::Utc::now(),
                        };
                        member_store
                            .save(member)
                            .await?;
                        id
                    }
                };
                new_member_ids.push(member_id);
            }
        }

        let new_id = if id_is_uuid {
            obj.get("id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
        } else {
            uuid::Uuid::new_v4().to_string()
        };

        obj.insert("id".to_string(), serde_json::Value::String(new_id.clone()));
        obj.insert("members".to_string(), serde_json::json!(new_member_ids));
        obj.remove("per_member_monthly_budget_usd");
        obj.remove("per_member_monthly_token_cap");

        let new_path = dir.join(format!("{new_id}.json"));
        let serialized = serde_json::to_vec_pretty(&value)?;
        tokio::fs::write(&new_path, serialized).await?;
        if path != new_path {
            let _ = tokio::fs::remove_file(&path).await;
        }
        migrated += 1;
    }

    Ok(migrated)
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn member_store() -> FileSystemMemberStore {
        let dir = std::env::temp_dir().join(format!("member_mig_{}", uuid::Uuid::new_v4()));
        FileSystemMemberStore::new(
            dir.to_string_lossy()
                .to_string(),
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn migrates_legacy_team_to_member_uuids() {
        let teams_dir = std::env::temp_dir().join(format!("teams_mig_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&teams_dir)
            .await
            .unwrap();
        let legacy = serde_json::json!({
            "id": "eng",
            "name": "Engineering",
            "enabled": true,
            "per_member_monthly_budget_usd": 10.0,
            "members": [
                { "email": "Alice@Example.com", "monthly_budget_usd": 5.0 }
            ]
        });
        tokio::fs::write(teams_dir.join("eng.json"), serde_json::to_vec_pretty(&legacy).unwrap())
            .await
            .unwrap();

        let store = member_store().await;
        let migrated = migrate_legacy_teams(&teams_dir.to_string_lossy(), &store)
            .await
            .unwrap();
        assert_eq!(migrated, 1);

        // Old slug file removed, a UUID-named file written instead.
        assert!(
            !teams_dir
                .join("eng.json")
                .exists()
        );

        let member = store
            .find_by_identifier("alice@example.com")
            .await
            .expect("member minted");
        assert_eq!(member.monthly_budget_usd, Some(5.0));

        // The rewritten team references the member by UUID and drops the
        // per-member default field.
        let mut files = tokio::fs::read_dir(&teams_dir)
            .await
            .unwrap();
        let entry = files
            .next_entry()
            .await
            .unwrap()
            .unwrap();
        let bytes = tokio::fs::read(entry.path())
            .await
            .unwrap();
        let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(uuid::Uuid::parse_str(value["id"].as_str().unwrap()).is_ok());
        assert_eq!(
            value["members"][0]
                .as_str()
                .unwrap(),
            member.id
        );
        assert!(
            value
                .get("per_member_monthly_budget_usd")
                .is_none()
        );

        // Idempotent: a second run migrates nothing.
        let again = migrate_legacy_teams(&teams_dir.to_string_lossy(), &store)
            .await
            .unwrap();
        assert_eq!(again, 0);
    }

    #[tokio::test]
    async fn leaves_system_team_with_fixed_id_untouched() {
        let teams_dir = std::env::temp_dir().join(format!("teams_mig_{}", uuid::Uuid::new_v4()));
        tokio::fs::create_dir_all(&teams_dir)
            .await
            .unwrap();
        // The built-in anonymous team: a system record with a fixed, non-UUID id
        // and members already in the modern string-UUID form.
        let anonymous = serde_json::json!({
            "id": "anonymous",
            "name": "Anonymous",
            "status": "enabled",
            "system": true,
            "members": ["anonymous"]
        });
        let anon_path = teams_dir.join("anonymous.json");
        tokio::fs::write(&anon_path, serde_json::to_vec_pretty(&anonymous).unwrap())
            .await
            .unwrap();

        let store = member_store().await;
        let migrated = migrate_legacy_teams(&teams_dir.to_string_lossy(), &store)
            .await
            .unwrap();
        // The system team is skipped, so nothing is migrated and the original
        // file (id "anonymous") is preserved rather than rewritten to a UUID.
        assert_eq!(migrated, 0);
        assert!(anon_path.exists());
        let mut files = tokio::fs::read_dir(&teams_dir)
            .await
            .unwrap();
        let mut count = 0usize;
        while let Some(entry) = files
            .next_entry()
            .await
            .unwrap()
        {
            count += 1;
            let bytes = tokio::fs::read(entry.path())
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["id"].as_str().unwrap(), "anonymous");
        }
        assert_eq!(count, 1, "no extra UUID-named team should be created");
    }
}
