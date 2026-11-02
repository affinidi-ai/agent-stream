//! The record a managed API key hangs off. The `agent_id` of a key, and of an
//! `api_key_provider` source authentication, names an LLM or IDE Surface or an
//! internal Fabric surface record. The two id spaces are separate, so an id
//! that names both is reachable only when every record it names is.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::api_keys::traits::ApiKeyStore;
use crate::entity_status::EntityStatus;
use crate::pipes::FileSystemPipeStore;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, can_access};

#[derive(Clone, Default)]
pub struct ApiKeyParents {
    agent_surfaces: Option<Arc<dyn AgentSurfaceStore>>,
    pipes: Option<Arc<FileSystemPipeStore>>,
}

impl ApiKeyParents {
    pub fn new(
        agent_surfaces: Option<Arc<dyn AgentSurfaceStore>>,
        pipes: Option<Arc<FileSystemPipeStore>>,
    ) -> Self {
        Self { agent_surfaces, pipes }
    }

    /// The tenant of every record `agent_id` names. Empty when it names none.
    /// A deleted Surface is not a parent.
    pub async fn tenants(
        &self,
        agent_id: &str,
    ) -> anyhow::Result<Vec<Option<String>>> {
        let mut tenants = Vec::new();
        if let Some(store) = &self.agent_surfaces
            && let Some(surface) = store.get(agent_id).await?
        {
            tenants.push(surface.tenant_id);
        }
        if let Some(store) = &self.pipes
            && let Some(pipe) = store
                .get(agent_id)
                .await
                .filter(|pipe| pipe.status != EntityStatus::Deleted)
        {
            tenants.push(pipe.tenant_id);
        }
        Ok(tenants)
    }

    /// Every parent id whose records the caller can all reach.
    pub async fn accessible(
        &self,
        context: Option<&PatTenantContext>,
    ) -> anyhow::Result<HashSet<String>> {
        let mut reachable: HashMap<String, bool> = HashMap::new();
        let mut record = |id: String, tenant_id: Option<&str>| {
            let allowed = can_access(tenant_id, context);
            reachable
                .entry(id)
                .and_modify(|all| *all &= allowed)
                .or_insert(allowed);
        };
        if let Some(store) = &self.agent_surfaces {
            for surface in store.list_all().await? {
                record(surface.surface_id, surface.tenant_id.as_deref());
            }
        }
        if let Some(store) = &self.pipes {
            for pipe in store.list().await {
                if pipe.status != EntityStatus::Deleted {
                    record(pipe.id, pipe.tenant_id.as_deref());
                }
            }
        }
        Ok(reachable
            .into_iter()
            .filter_map(|(id, allowed)| allowed.then_some(id))
            .collect())
    }

    /// Delete every managed key of `agent_id` once it names no parent. A key
    /// whose parent is gone can no longer be managed, yet a Surface whose
    /// `api_key_provider` names that id would still admit it.
    pub async fn delete_orphaned_keys(
        &self,
        keys: &dyn ApiKeyStore,
        agent_id: &str,
    ) -> anyhow::Result<usize> {
        if !self
            .tenants(agent_id)
            .await?
            .is_empty()
        {
            return Ok(0);
        }
        let orphaned = keys.list(agent_id).await?;
        for key in &orphaned {
            keys.delete(agent_id, &key.key_id)
                .await?;
        }
        Ok(orphaned.len())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use async_trait::async_trait;

    use super::*;
    use crate::config::agent_surface::AgentSurface;
    use crate::pipes::types::llm::LLMProvider;
    use crate::pipes::{PipeConfig, PipeType};

    pub(crate) struct FabricRecords(pub Vec<AgentSurface>);

    #[async_trait]
    impl AgentSurfaceStore for FabricRecords {
        async fn save(
            &self,
            _surface: &AgentSurface,
        ) -> anyhow::Result<()> {
            unreachable!()
        }

        async fn get(
            &self,
            surface_id: &str,
        ) -> anyhow::Result<Option<AgentSurface>> {
            Ok(self
                .0
                .iter()
                .find(|surface| surface.surface_id == surface_id)
                .cloned())
        }

        async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>> {
            Ok(self.0.clone())
        }

        async fn delete(
            &self,
            _surface_id: &str,
        ) -> anyhow::Result<()> {
            unreachable!()
        }
    }

    pub(crate) fn fabric_record(
        id: &str,
        tenant_id: Option<&str>,
    ) -> AgentSurface {
        AgentSurface {
            surface_id: id.into(),
            tenant_id: tenant_id.map(Into::into),
            ..Default::default()
        }
    }

    pub(crate) fn llm_surface(
        id: &str,
        tenant_id: Option<&str>,
    ) -> PipeConfig {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".into(),
            model: "gpt-4o".into(),
            api_key_secret: None,
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        let mut pipe = PipeConfig::new(
            id.into(),
            id.into(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        );
        pipe.tenant_id = tenant_id.map(Into::into);
        pipe
    }

    pub(crate) async fn parents_with(
        dir: &tempfile::TempDir,
        records: Vec<AgentSurface>,
        surfaces: Vec<PipeConfig>,
    ) -> ApiKeyParents {
        let pipes = FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        for surface in surfaces {
            pipes
                .save(surface)
                .await
                .unwrap();
        }
        ApiKeyParents::new(Some(Arc::new(FabricRecords(records))), Some(Arc::new(pipes)))
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: id.into(),
        }
    }

    #[tokio::test]
    async fn an_llm_surface_is_a_parent() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(&dir, Vec::new(), vec![llm_surface("chat", Some("tenant-a"))]).await;

        assert_eq!(
            parents
                .tenants("chat")
                .await
                .unwrap(),
            vec![Some("tenant-a".to_string())]
        );
        assert!(
            parents
                .tenants("unknown")
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_deleted_surface_is_not_a_parent() {
        let dir = tempfile::tempdir().unwrap();
        let mut deleted = llm_surface("chat", None);
        deleted.status = EntityStatus::Deleted;
        let parents = parents_with(&dir, Vec::new(), vec![deleted]).await;

        assert!(
            parents
                .tenants("chat")
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            parents
                .accessible(None)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_id_naming_both_records_reports_both_tenants() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(
            &dir,
            vec![fabric_record("shared", Some("tenant-a"))],
            vec![llm_surface("shared", Some("tenant-b"))],
        )
        .await;

        assert_eq!(
            parents
                .tenants("shared")
                .await
                .unwrap(),
            vec![Some("tenant-a".to_string()), Some("tenant-b".to_string())]
        );
    }

    #[tokio::test]
    async fn accessible_parents_exclude_an_id_another_tenant_also_holds() {
        let dir = tempfile::tempdir().unwrap();
        let parents = parents_with(
            &dir,
            vec![fabric_record("fabric-a", Some("tenant-a")), fabric_record("shared", Some("tenant-a"))],
            vec![
                llm_surface("chat-a", Some("tenant-a")),
                llm_surface("chat-b", Some("tenant-b")),
                llm_surface("shared", Some("tenant-b")),
            ],
        )
        .await;

        let tenant_a = tenant("tenant-a");
        assert_eq!(
            parents
                .accessible(Some(&tenant_a))
                .await
                .unwrap(),
            HashSet::from(["fabric-a".to_string(), "chat-a".to_string()])
        );
        assert_eq!(
            parents
                .accessible(None)
                .await
                .unwrap()
                .len(),
            4
        );
    }

    async fn key_store(dir: &tempfile::TempDir) -> crate::api_keys::fs_store::FsApiKeyStore {
        crate::api_keys::fs_store::FsApiKeyStore::new(dir.path().to_str().unwrap())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn the_keys_of_a_deleted_surface_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap();
        let mut deleted = llm_surface("chat", None);
        deleted.status = EntityStatus::Deleted;
        let parents = parents_with(&dir, Vec::new(), vec![deleted]).await;
        let keys = key_store(&keys_dir).await;
        keys.create("chat", "client-a", None, "test")
            .await
            .unwrap();
        keys.create("chat", "client-b", None, "test")
            .await
            .unwrap();
        keys.create("other", "client-c", None, "test")
            .await
            .unwrap();

        assert_eq!(
            parents
                .delete_orphaned_keys(&keys, "chat")
                .await
                .unwrap(),
            2
        );
        assert!(
            keys.list("chat")
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            keys.list("other")
                .await
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn the_keys_of_a_live_parent_are_kept() {
        let dir = tempfile::tempdir().unwrap();
        let keys_dir = tempfile::tempdir().unwrap();
        let mut deleted = llm_surface("shared", None);
        deleted.status = EntityStatus::Deleted;
        let parents =
            parents_with(&dir, vec![fabric_record("shared", None)], vec![llm_surface("chat", None), deleted]).await;
        let keys = key_store(&keys_dir).await;
        for agent_id in ["chat", "shared"] {
            keys.create(agent_id, "client", None, "test")
                .await
                .unwrap();
        }

        for agent_id in ["chat", "shared"] {
            assert_eq!(
                parents
                    .delete_orphaned_keys(&keys, agent_id)
                    .await
                    .unwrap(),
                0
            );
            assert_eq!(
                keys.list(agent_id)
                    .await
                    .unwrap()
                    .len(),
                1
            );
        }
    }
}
