use std::collections::HashMap;

use cucumber::World;
use tempfile::TempDir;

use crate::bdd_support::admin_client::{AdminClient, RecordedResponse};
use crate::bdd_support::appliance_process::{ApplianceProcess, LaunchOptions, LaunchOutcome};
use crate::bdd_support::config::EncryptionSettings;
use crate::bdd_support::mock_affinidi_well::MockAffinidiWell;
use crate::bdd_support::mock_llm::MockLlmProvider;

pub struct ProviderActor {
    pub server: MockLlmProvider,
}

pub struct ScenarioInfra {
    pub _appliance: ApplianceProcess,
}

#[derive(World)]
#[world(init = Self::new)]
pub struct SurfaceWorld {
    pub temp_dir: TempDir,
    pub providers: HashMap<String, ProviderActor>,
    pub infra: Option<ScenarioInfra>,
    pub admin_client: Option<AdminClient>,
    pub admin_response: Option<RecordedResponse>,
    pub caller_response: Option<RecordedResponse>,
    pub terms_submission: Option<serde_json::Value>,
    pub last_caller_prompt: Option<String>,
    pub expected_governance_records: usize,
    pub surface_routes: HashMap<String, String>,
    pub member_ids: HashMap<String, String>,
    pub member_headers: HashMap<String, (String, String)>,
    pub team_ids: HashMap<String, String>,
    pub human_clients: HashMap<String, Vec<AdminClient>>,
    pub management_tokens: HashMap<String, String>,
    /// Each named caller's JWT, minted once so a caller keeps one identity.
    pub caller_jwts: HashMap<String, String>,
    pub terms_enabled: bool,
    pub affinidi_cache_seeded: bool,
    pub affinidi_well_available: bool,
    pub affinidi_terms_manifest: serde_json::Value,
    pub affinidi_well: Option<MockAffinidiWell>,
    pub encryption: Option<EncryptionSettings>,
    pub appliance_launch: Option<LaunchOutcome>,
    /// A Standby appliance sharing the serving appliance's storage.
    pub standby: Option<ApplianceProcess>,
}

impl std::fmt::Debug for SurfaceWorld {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.debug_struct("SurfaceWorld")
            .field("temp_dir", &self.temp_dir.path())
            .field(
                "providers",
                &self
                    .providers
                    .keys()
                    .collect::<Vec<_>>(),
            )
            .field("infra", &self.infra.is_some())
            .field("admin_client", &self.admin_client.is_some())
            .field("admin_response", &self.admin_response)
            .field("caller_response", &self.caller_response)
            .field("surface_routes", &self.surface_routes)
            .finish()
    }
}

impl SurfaceWorld {
    pub fn new() -> Self {
        Self {
            temp_dir: temp_dir(),
            providers: HashMap::new(),
            infra: None,
            admin_client: None,
            admin_response: None,
            caller_response: None,
            terms_submission: None,
            last_caller_prompt: None,
            expected_governance_records: 0,
            surface_routes: HashMap::new(),
            member_ids: HashMap::new(),
            member_headers: HashMap::new(),
            team_ids: HashMap::new(),
            human_clients: HashMap::new(),
            management_tokens: HashMap::new(),
            caller_jwts: HashMap::new(),
            terms_enabled: false,
            affinidi_cache_seeded: false,
            affinidi_well_available: true,
            affinidi_terms_manifest: serde_json::json!({
                "schema_version": 1,
                "publication_sequence": 1,
                "document_id": "affinidi-terms",
                "version_id": "affinidi:3.2",
                "version": "3.2",
                "title": "Affinidi Terms and Conditions",
                "url": "https://www.affinidi.com/files/Affinidi_Terms_and_Conditions.pdf",
                "requires_reconsent": true,
                "published_at": "2026-08-31T13:24:23Z"
            }),
            affinidi_well: None,
            encryption: None,
            appliance_launch: None,
            standby: None,
        }
    }

    pub async fn ensure_provider(
        &mut self,
        name: &str,
    ) {
        if !self
            .providers
            .contains_key(name)
        {
            self.providers.insert(
                name.to_string(),
                ProviderActor {
                    server: MockLlmProvider::start(name).await,
                },
            );
        }
    }

    pub async fn ensure_operator(&mut self) {
        self.ensure_provider("bravo")
            .await;
        if self.infra.is_none() {
            if self.terms_enabled && self.affinidi_well.is_none() {
                self.affinidi_well = Some(
                    MockAffinidiWell::start(
                        self.affinidi_terms_manifest
                            .clone(),
                        self.affinidi_well_available,
                    )
                    .await,
                );
            }
            if self.affinidi_cache_seeded {
                let cache_dir = self
                    .temp_dir
                    .path()
                    .join("_storage/terms/affinidi");
                std::fs::create_dir_all(&cache_dir).expect("Affinidi Terms cache directory should be created");
                std::fs::write(
                    cache_dir.join("current.json"),
                    serde_json::to_vec_pretty(&serde_json::json!({
                        "id": "current",
                        "manifest": self.affinidi_terms_manifest.clone(),
                        "last_successful_refresh": "2026-09-02T00:00:00Z"
                    }))
                    .expect("Affinidi Terms cache should serialize"),
                )
                .expect("Affinidi Terms cache should be written");
            }
            let appliance = ApplianceProcess::start_with_terms(
                self.temp_dir.path(),
                &self.provider_base_urls(),
                self.terms_enabled,
                self.affinidi_well
                    .as_ref()
                    .map(MockAffinidiWell::metadata_url),
            )
            .await;
            if !self.terms_enabled || self.affinidi_cache_seeded {
                let admin_client =
                    AdminClient::login(appliance.base_url(), appliance.test_token(), appliance.test_username()).await;
                if self.terms_enabled {
                    let response = admin_client
                        .accept_current_terms()
                        .await;
                    assert_eq!(response.status, 200, "BDD operator should accept current Terms: {}", response.text);
                }
                self.admin_client = Some(admin_client);
            }
            self.infra = Some(ScenarioInfra { _appliance: appliance });
        }
    }

    fn provider_base_urls(&self) -> Vec<String> {
        self.providers
            .values()
            .map(|provider| {
                provider
                    .server
                    .base_url()
                    .to_string()
            })
            .collect()
    }

    /// Start another appliance under `root` with this scenario's providers.
    pub async fn start_appliance(
        &self,
        root: &std::path::Path,
        standby: bool,
    ) -> ApplianceProcess {
        let provider_base_urls = self.provider_base_urls();
        let options = LaunchOptions {
            provider_base_urls: &provider_base_urls,
            standby,
            ..LaunchOptions::default()
        };
        match ApplianceProcess::launch(root, &options).await {
            LaunchOutcome::Serving(appliance) => *appliance,
            LaunchOutcome::Exited { log_tail, .. } => {
                panic!("agent-stream exited before it became ready\n\nagent-stream.log tail:\n{log_tail}")
            }
        }
    }

    /// Send the operator's and callers' requests to `appliance` from now on,
    /// returning the appliance it replaces.
    pub async fn serve_from(
        &mut self,
        appliance: ApplianceProcess,
    ) -> Option<ApplianceProcess> {
        self.admin_client =
            Some(AdminClient::login(appliance.base_url(), appliance.test_token(), appliance.test_username()).await);
        for client in self
            .human_clients
            .values_mut()
            .flatten()
        {
            *client = client.with_base_url(appliance.base_url());
        }
        self.infra
            .replace(ScenarioInfra { _appliance: appliance })
            .map(|infra| infra._appliance)
    }

    pub fn provider(
        &self,
        name: &str,
    ) -> &ProviderActor {
        self.providers
            .get(name)
            .unwrap_or_else(|| panic!("provider {name:?} should exist"))
    }

    pub fn admin_client(&self) -> &AdminClient {
        self.admin_client
            .as_ref()
            .expect("operator should be authenticated before admin API use")
    }
}

fn temp_dir() -> TempDir {
    let mut builder = tempfile::Builder::new();
    let prefix = std::env::var("BDD_TEMP_DIR_PREFIX").unwrap_or_else(|_| "agent-stream-bdd-".to_string());
    builder.prefix(&prefix);
    if let Ok(root) = std::env::var("BDD_TEMP_DIR_ROOT") {
        std::fs::create_dir_all(&root).expect("BDD_TEMP_DIR_ROOT should be created");
        builder
            .tempdir_in(root)
            .expect("scenario temp dir should be created")
    } else {
        builder
            .tempdir()
            .expect("scenario temp dir should be created")
    }
}
