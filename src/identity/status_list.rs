//! Revocation status list for the credentials this appliance issues.
//!
//! Each local agent identity is given one random index in a Bitstring Status
//! List the first time a credential is issued for it, and every credential
//! issued for that agent points at that index. Revoking the agent sets the bit,
//! which revokes all of its credentials. The list is persisted next to the
//! appliance DID, signed by the appliance DID whenever it changes, and served
//! publicly at [`STATUS_LIST_PATH`].

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use ssi::status::bitstring_status_list::{SizedBitString, StatusSize};
use tokio::sync::Mutex;

use crate::identity::ssi::vc_issuer::VcSigner;
use crate::identity::ssi::verifier::{HttpStatusListSource, StatusListSource};

/// Where the appliance serves its revocation status list, outside the `/api` prefix.
pub const STATUS_LIST_PATH: &str = "/credentials/status/revocation";

/// The minimum Bitstring Status List length, which keeps a holder's index
/// from identifying them among the appliance's agents.
const STATUS_LIST_BITS: usize = 131_072;

const STATE_FILE: &str = "status_list.json";

/// The indexes and the signed list share one lock, so a revocation and a
/// read of the list can neither deadlock nor cache a list signed before it.
#[derive(Debug, Default, Serialize, Deserialize)]
struct StatusListState {
    indexes: HashMap<String, usize>,
    revoked: BTreeSet<usize>,
    #[serde(skip)]
    signed: Option<Arc<Vec<u8>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Revocation {
    Revoked,
    AlreadyRevoked,
}

pub struct StatusListRegistry {
    path: PathBuf,
    url: String,
    issuer_did: String,
    signer: Arc<dyn VcSigner>,
    state: Mutex<StatusListState>,
}

impl StatusListRegistry {
    /// Load the list kept in `storage_dir`, served at `https://{domain}` + [`STATUS_LIST_PATH`]
    /// and signed by `signer` as `issuer_did`.
    pub async fn load(
        storage_dir: impl Into<PathBuf>,
        domain: &str,
        issuer_did: String,
        signer: Arc<dyn VcSigner>,
    ) -> Result<Self> {
        let path = storage_dir
            .into()
            .join(STATE_FILE);
        let state = read_state(&path).await?;
        Ok(Self {
            path,
            url: format!("https://{domain}{STATUS_LIST_PATH}"),
            issuer_did,
            signer,
            state: Mutex::new(state),
        })
    }

    /// Replace the indexes and revocations with the stored list, so an
    /// instance promoted to Active keeps the revocations the previous Active
    /// made. The signed list is rebuilt on its next read.
    pub async fn reload(&self) -> Result<()> {
        let mut state = self.state.lock().await;
        *state = read_state(&self.path).await?;
        Ok(())
    }

    pub fn url(&self) -> &str {
        &self.url
    }

    /// The `credentialStatus` entry for a credential issued to `agent_did`,
    /// assigning the agent an index on its first credential.
    pub async fn entry_for(
        &self,
        agent_did: &str,
    ) -> Result<Value> {
        let index = {
            let mut state = self.state.lock().await;
            match state.indexes.get(agent_did) {
                Some(index) => *index,
                None => {
                    let index = Self::assign(&mut state, agent_did)?;
                    self.persist(&state).await?;
                    index
                }
            }
        };
        Ok(json!({
            "id": format!("{}#{index}", self.url),
            "type": "BitstringStatusListEntry",
            "statusPurpose": "revocation",
            "statusListIndex": index.to_string(),
            "statusListCredential": self.url,
        }))
    }

    /// Revoke every credential issued to `agent_did`, including any issued later.
    pub async fn revoke(
        &self,
        agent_did: &str,
    ) -> Result<Revocation> {
        let mut state = self.state.lock().await;
        let index = match state.indexes.get(agent_did) {
            Some(index) => *index,
            None => Self::assign(&mut state, agent_did)?,
        };
        if !state.revoked.insert(index) {
            return Ok(Revocation::AlreadyRevoked);
        }
        state.signed = None;
        self.persist(&state).await?;
        Ok(Revocation::Revoked)
    }

    pub async fn is_revoked(
        &self,
        agent_did: &str,
    ) -> bool {
        let state = self.state.lock().await;
        state
            .indexes
            .get(agent_did)
            .is_some_and(|index| state.revoked.contains(index))
    }

    /// The signed `BitstringStatusListCredential`, signed again only after a revocation.
    pub async fn signed_list(&self) -> Result<Arc<Vec<u8>>> {
        let mut state = self.state.lock().await;
        if let Some(list) = state.signed.as_ref() {
            return Ok(Arc::clone(list));
        }
        let mut bits = SizedBitString::new_zeroed(StatusSize::default(), STATUS_LIST_BITS);
        for index in state.revoked.iter() {
            bits.set(*index, 1)
                .map_err(|_| anyhow::anyhow!("status list index {index} is out of range"))?;
        }
        let credential = self
            .signer
            .sign(json!({
                "@context": ["https://www.w3.org/ns/credentials/v2"],
                "id": self.url,
                "type": ["VerifiableCredential", "BitstringStatusListCredential"],
                "issuer": self.issuer_did,
                // Whole seconds in `Z` form: a verifier re-serializes this as an
                // xsd:dateTimeStamp before checking the proof, so any other form fails it.
                "validFrom": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "credentialSubject": {
                    "id": format!("{}#list", self.url),
                    "type": "BitstringStatusList",
                    "statusPurpose": "revocation",
                    "encodedList": bits.encode(),
                },
            }))
            .await
            .context("failed to sign the status list")?;
        let list = Arc::new(serde_json::to_vec(&credential)?);
        state.signed = Some(Arc::clone(&list));
        Ok(list)
    }

    /// Give `agent_did` a random unused index, so an index reveals nothing
    /// about when the agent was first issued a credential.
    fn assign(
        state: &mut StatusListState,
        agent_did: &str,
    ) -> Result<usize> {
        anyhow::ensure!(state.indexes.len() < STATUS_LIST_BITS, "the revocation status list is full");
        let used: BTreeSet<usize> = state
            .indexes
            .values()
            .copied()
            .collect();
        let mut rng = rand::rng();
        let index = loop {
            let candidate = rng.random_range(0..STATUS_LIST_BITS);
            if !used.contains(&candidate) {
                break candidate;
            }
        };
        state
            .indexes
            .insert(agent_did.to_string(), index);
        Ok(index)
    }

    async fn persist(
        &self,
        state: &StatusListState,
    ) -> Result<()> {
        let tmp = self
            .path
            .with_extension("json.tmp");
        tokio::fs::write(&tmp, serde_json::to_vec_pretty(state)?).await?;
        tokio::fs::rename(&tmp, &self.path)
            .await
            .with_context(|| format!("failed to write {}", self.path.display()))
    }
}

async fn read_state(path: &Path) -> Result<StatusListState> {
    match tokio::fs::read(path).await {
        Ok(bytes) => serde_json::from_slice(&bytes).with_context(|| format!("invalid {}", path.display())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(StatusListState::default()),
        Err(error) => Err(error).with_context(|| format!("failed to read {}", path.display())),
    }
}

/// Reads this appliance's own status list from the registry and fetches any
/// other issuer's list over HTTPS, so verifying an own credential needs no
/// network and works on hosts that are not publicly reachable.
pub struct RegistryStatusListSource {
    registry: Arc<StatusListRegistry>,
}

impl RegistryStatusListSource {
    pub fn new(registry: Arc<StatusListRegistry>) -> Self {
        Self { registry }
    }
}

#[async_trait]
impl StatusListSource for RegistryStatusListSource {
    async fn fetch(
        &self,
        url: &str,
    ) -> Result<Vec<u8>> {
        if url == self.registry.url() {
            return Ok(self
                .registry
                .signed_list()
                .await?
                .as_ref()
                .clone());
        }
        HttpStatusListSource
            .fetch(url)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct UnsignedSigner;

    #[async_trait]
    impl VcSigner for UnsignedSigner {
        async fn sign(
            &self,
            payload: Value,
        ) -> Result<Value> {
            Ok(payload)
        }
    }

    async fn registry(dir: &std::path::Path) -> StatusListRegistry {
        StatusListRegistry::load(
            dir,
            "appliance.example",
            "did:web:appliance.example".to_string(),
            Arc::new(UnsignedSigner),
        )
        .await
        .expect("status list registry")
    }

    fn index_of(entry: &Value) -> usize {
        entry["statusListIndex"]
            .as_str()
            .and_then(|index| index.parse().ok())
            .expect("a numeric statusListIndex")
    }

    async fn bit(
        registry: &StatusListRegistry,
        index: usize,
    ) -> u8 {
        let list: ssi::status::bitstring_status_list::BitstringStatusListCredential = serde_json::from_slice(
            &registry
                .signed_list()
                .await
                .unwrap(),
        )
        .unwrap();
        list.decode_status_list()
            .unwrap()
            .get(StatusSize::default(), index)
            .unwrap()
    }

    #[tokio::test]
    async fn an_agent_keeps_one_index_across_credentials_and_restarts() {
        let dir = tempfile::tempdir().unwrap();
        let first = registry(dir.path())
            .await
            .entry_for("did:example:agent")
            .await
            .unwrap();
        let again = registry(dir.path())
            .await
            .entry_for("did:example:agent")
            .await
            .unwrap();

        assert_eq!(first, again);
        assert_eq!(first["type"], "BitstringStatusListEntry");
        assert_eq!(first["statusPurpose"], "revocation");
        assert_eq!(first["statusListCredential"], "https://appliance.example/credentials/status/revocation");
        assert!(index_of(&first) < STATUS_LIST_BITS);
    }

    #[tokio::test]
    async fn reload_keeps_revocations_another_instance_made() {
        let dir = tempfile::tempdir().unwrap();
        let standby = registry(dir.path()).await;
        let entry = standby
            .entry_for("did:example:agent")
            .await
            .unwrap();
        let active = registry(dir.path()).await;
        active
            .revoke("did:example:agent")
            .await
            .unwrap();
        assert_eq!(bit(&standby, index_of(&entry)).await, 0, "stale before the reload");

        standby
            .reload()
            .await
            .unwrap();

        assert!(
            standby
                .is_revoked("did:example:agent")
                .await
        );
        assert_eq!(bit(&standby, index_of(&entry)).await, 1, "the cached signed list is rebuilt");
    }

    #[tokio::test]
    async fn reload_fails_and_keeps_state_when_the_file_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(dir.path()).await;
        registry
            .entry_for("did:example:agent")
            .await
            .unwrap();
        registry
            .revoke("did:example:agent")
            .await
            .unwrap();
        tokio::fs::write(dir.path().join(STATE_FILE), "not json")
            .await
            .unwrap();

        assert!(
            registry
                .reload()
                .await
                .is_err()
        );
        assert!(
            registry
                .is_revoked("did:example:agent")
                .await
        );
    }

    #[tokio::test]
    async fn agents_get_distinct_indexes() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(dir.path()).await;
        let mut indexes = BTreeSet::new();
        for n in 0..50 {
            let entry = registry
                .entry_for(&format!("did:example:agent-{n}"))
                .await
                .unwrap();
            assert!(indexes.insert(index_of(&entry)), "index reused for agent {n}");
        }
    }

    #[tokio::test]
    async fn revoking_sets_only_that_agents_bit_and_survives_a_restart() {
        let dir = tempfile::tempdir().unwrap();
        let registry_one = registry(dir.path()).await;
        let revoked = index_of(
            &registry_one
                .entry_for("did:example:revoked")
                .await
                .unwrap(),
        );
        let kept = index_of(
            &registry_one
                .entry_for("did:example:kept")
                .await
                .unwrap(),
        );
        assert_eq!(bit(&registry_one, revoked).await, 0, "the cached list is unrevoked before revoking");

        assert_eq!(
            registry_one
                .revoke("did:example:revoked")
                .await
                .unwrap(),
            Revocation::Revoked
        );

        assert_eq!(bit(&registry_one, revoked).await, 1, "revoking re-signs the list");
        assert_eq!(bit(&registry_one, kept).await, 0);
        let reloaded = registry(dir.path()).await;
        assert!(
            reloaded
                .is_revoked("did:example:revoked")
                .await
        );
        assert!(
            !reloaded
                .is_revoked("did:example:kept")
                .await
        );
        assert_eq!(bit(&reloaded, revoked).await, 1);
    }

    /// `join!` polls `revoke` first: it holds the registry lock across the file
    /// write while the read waits on the empty cache, so the read must finish
    /// after the revocation and show it.
    #[tokio::test]
    async fn a_revocation_and_a_status_list_read_at_the_same_time_both_finish() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(dir.path()).await;
        let index = index_of(
            &registry
                .entry_for("did:example:agent")
                .await
                .unwrap(),
        );

        let (revoked, list) = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(registry.revoke("did:example:agent"), registry.signed_list())
        })
        .await
        .expect("a revocation and a status list read deadlocked");

        assert_eq!(revoked.unwrap(), Revocation::Revoked);
        list.unwrap();
        assert_eq!(bit(&registry, index).await, 1, "a read after the revocation must show it");
    }

    #[tokio::test]
    async fn revoking_twice_reports_already_revoked() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(dir.path()).await;

        assert_eq!(
            registry
                .revoke("did:example:agent")
                .await
                .unwrap(),
            Revocation::Revoked
        );
        assert_eq!(
            registry
                .revoke("did:example:agent")
                .await
                .unwrap(),
            Revocation::AlreadyRevoked
        );
    }

    #[tokio::test]
    async fn an_agent_revoked_before_its_first_credential_is_issued_revoked_credentials() {
        let dir = tempfile::tempdir().unwrap();
        let registry = registry(dir.path()).await;

        registry
            .revoke("did:example:agent")
            .await
            .unwrap();
        let entry = registry
            .entry_for("did:example:agent")
            .await
            .unwrap();

        assert_eq!(bit(&registry, index_of(&entry)).await, 1);
    }

    #[tokio::test]
    async fn the_list_is_signed_as_the_appliance_issuer() {
        let dir = tempfile::tempdir().unwrap();
        let list: Value = serde_json::from_slice(
            &registry(dir.path())
                .await
                .signed_list()
                .await
                .unwrap(),
        )
        .unwrap();

        assert_eq!(list["issuer"], "did:web:appliance.example");
        assert_eq!(list["id"], "https://appliance.example/credentials/status/revocation");
        assert_eq!(list["type"], json!(["VerifiableCredential", "BitstringStatusListCredential"]));
        assert_eq!(list["credentialSubject"]["statusPurpose"], "revocation");
    }

    #[tokio::test]
    async fn the_own_list_is_read_locally_and_other_lists_must_be_public_https() {
        let dir = tempfile::tempdir().unwrap();
        let registry = Arc::new(registry(dir.path()).await);
        let source = RegistryStatusListSource::new(Arc::clone(&registry));

        let own = source
            .fetch(registry.url())
            .await
            .expect("the own list needs no network");
        assert_eq!(
            own,
            *registry
                .signed_list()
                .await
                .unwrap()
        );
        assert!(
            source
                .fetch("https://127.0.0.1/credentials/status/revocation")
                .await
                .is_err(),
            "another issuer's list on a private host is refused"
        );
    }
}
