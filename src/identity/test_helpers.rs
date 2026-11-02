#![cfg(test)]

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;

use super::filesystem::AgentIdentityRecord;
use super::store::IdentityStore;
use super::vc_issuer::VCIssuer;
use super::vp_challenge_store::VpChallengeStore;

/// Creates a ready-to-use `VCIssuer` backed by in-memory mock stores.
///
/// Handles `init_shared_resolver()` automatically (idempotent).
/// Uses a `tempfile::tempdir()` for filesystem state — caller must hold
/// the returned `TempDir` to keep the directory alive.
pub async fn test_vc_issuer() -> (VCIssuer, tempfile::TempDir) {
    crate::gateways::did_cache::init_shared_resolver()
        .await
        .expect("init_shared_resolver failed");
    let temp_dir = tempfile::tempdir().unwrap();
    let identity_store = Arc::new(MockIdentityStore::new()) as Arc<dyn IdentityStore>;
    let vp_challenge_store = Arc::new(VpChallengeStore::default());
    let issuer = VCIssuer::new(temp_dir.path(), "example.com", identity_store, vp_challenge_store, None, None)
        .await
        .expect("VCIssuer::new failed");
    (issuer, temp_dir)
}

pub struct MockIdentityStore {
    records: Arc<RwLock<HashMap<String, AgentIdentityRecord>>>,
}

impl MockIdentityStore {
    pub fn new() -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait]
impl IdentityStore for MockIdentityStore {
    async fn create(
        &self,
        record: AgentIdentityRecord,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        records.insert(record.identity_hash.clone(), record);
        Ok(())
    }

    async fn find_by_hash(
        &self,
        identity_hash: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .get(identity_hash)
            .cloned())
    }

    async fn find_by_did(
        &self,
        did: &str,
    ) -> Result<Option<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .find(|r| r.did == did)
            .cloned())
    }

    async fn list_all(&self) -> Result<Vec<AgentIdentityRecord>> {
        let records = self.records.read().await;
        Ok(records
            .values()
            .cloned()
            .collect())
    }

    async fn update_usage(
        &self,
        identity_hash: &str,
        channel_config_id: Option<String>,
    ) -> Result<()> {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(identity_hash) {
            record.usage_count += 1;
            record.last_used_at = Some(chrono::Utc::now());
            if let Some(cid) = channel_config_id {
                record.channel_config_id = Some(cid);
            }
        }
        Ok(())
    }

    async fn store_external_did(
        &self,
        did: &str,
        identity_fields: HashMap<String, serde_json::Value>,
        channel_config_id: Option<String>,
        verified: bool,
    ) -> Result<()> {
        let identity_hash = crate::identity::filesystem::calculate_identity_hash(
            &serde_json::to_value(&identity_fields).unwrap_or_default(),
        );

        let record = AgentIdentityRecord {
            did: did.to_string(),
            identity_hash: identity_hash.clone(),
            created_at: chrono::Utc::now(),
            identity_fields,
            usage_count: 0,
            last_used_at: None,
            channel_usage: vec![],
            private_key: None,
            channel_config_id,
            is_local: false,
            verified,
            tr_registered: None,
        };

        let mut records = self.records.write().await;
        records.insert(identity_hash, record);
        Ok(())
    }
}
