//! Moves the credentials older integrations still store inline into the
//! secrets store, on every switch to Active.
//!
//! Each inline credential becomes a secret in the integration's tenant, tagged
//! so a later run finds it again, and the integration is saved last with a
//! reference in place of the value. A run that stops part way finishes on the
//! next one without duplicate secrets. Logs carry ids, field names and secret
//! ids, never a value.

use std::collections::HashSet;
use std::sync::Arc;

use serde_json::Value as JsonValue;

use crate::secrets::{CreateSecretRequest, SecretListItem, SecretsStore, SurfaceSecrets};
use crate::storage::integration_credentials::{
    InlineCredential, MigratedPin, inline_credentials, pin_migrated_destination, pin_unpinned_destinations,
    referenced_secrets,
};
use crate::storage::{Integration, IntegrationStorage};

const MIGRATED_TAG: &str = "migrated-from-integration";

/// What the migration does with one inline credential. Not `Debug`, so a
/// value it carries cannot reach a log.
enum Action {
    Create {
        secret_id: String,
        value: String,
    },
    Reuse {
        secret_id: String,
    },
    /// A reference to a secret is already stored, and a delivery sends it in
    /// place of the inline value, which is dropped.
    DropInline,
}

impl Action {
    fn label(&self) -> &'static str {
        match self {
            Self::Create { .. } => "create",
            Self::Reuse { .. } => "reuse",
            Self::DropInline => "drop_inline",
        }
    }

    fn secret_id(&self) -> &str {
        match self {
            Self::Create { secret_id, .. } | Self::Reuse { secret_id } => secret_id,
            Self::DropInline => "-",
        }
    }
}

struct Step {
    credential: InlineCredential,
    action: Action,
}

/// What a run decides for one integration: the credentials it moves, and the
/// names of those it cannot store as a secret, which stay inline.
struct Plan {
    steps: Vec<Step>,
    not_strings: Vec<String>,
}

/// Migrates every integration, active or disabled, that stores a credential
/// inline, and stops before the next integration once `still_current` turns
/// false. Returns the ids of the integrations that still store a credential
/// inline, each named in a warning and retried on the next run.
pub(crate) async fn migrate_inline_credentials(
    storage: &IntegrationStorage,
    store: Option<Arc<dyn SecretsStore>>,
    still_current: &(dyn Fn() -> bool + Sync),
) -> Vec<String> {
    let integrations = match storage.list().await {
        Ok(integrations) => integrations,
        Err(error) => {
            tracing::warn!(error = %error, "could not list integrations to migrate their inline credentials");
            return Vec::new();
        }
    };
    let pending: Vec<_> = integrations
        .into_iter()
        .filter(|integration| !inline_credentials(&integration.configuration).is_empty())
        .collect();
    if pending.is_empty() {
        return Vec::new();
    }
    let mut failed = Vec::new();
    let listed = match &store {
        Some(store) => store.list_all().await,
        None => Err(anyhow::anyhow!("the secrets store is not configured")),
    };
    let (Some(store), Ok(listed)) = (store, listed.as_ref()) else {
        let reason = listed
            .err()
            .map_or_else(String::new, |error| error.to_string());
        for integration in &pending {
            fail(&mut failed, integration, &reason);
        }
        warn_unmigrated(&failed);
        return failed;
    };
    let mut claimed: HashSet<String> = listed
        .iter()
        .map(|secret| secret.secret_id.clone())
        .collect();
    for integration in pending {
        if !still_current() {
            tracing::info!("Integration credential migration stopped because the activation was superseded");
            break;
        }
        let Plan { steps, not_strings } = match plan(&store, listed, &mut claimed, &integration).await {
            Ok(plan) => plan,
            Err(error) => {
                fail(&mut failed, &integration, &error.to_string());
                continue;
            }
        };
        let not_strings_reason = (!not_strings.is_empty())
            .then(|| format!("{} cannot be stored as a secret because it is not a string", not_strings.join(", ")));
        if steps.is_empty() {
            fail(
                &mut failed,
                &integration,
                not_strings_reason
                    .as_deref()
                    .unwrap_or_default(),
            );
            continue;
        }
        let mut migrated = integration
            .configuration
            .clone();
        let moved = steps
            .iter()
            .try_for_each(|step| match &step.action {
                Action::DropInline => {
                    step.credential
                        .remove(&mut migrated);
                    Ok(())
                }
                action => step
                    .credential
                    .replace_with_reference(&mut migrated, action.secret_id()),
            });
        if let Err(error) = moved {
            fail(&mut failed, &integration, &error.to_string());
            continue;
        }
        let pin = match pin_migrated_destination(
            &integration.configuration,
            &mut migrated,
            integration
                .tenant_id
                .as_deref(),
            Some(store.clone()),
        )
        .await
        {
            Ok(pin) => pin,
            Err(error) => {
                fail(&mut failed, &integration, &format!("its destination could not be pinned: {error}"));
                continue;
            }
        };
        let created = match write_secrets(store.as_ref(), &integration, &steps).await {
            Ok(created) => created,
            Err(error) => {
                fail(&mut failed, &integration, &error.to_string());
                continue;
            }
        };
        match save(storage, &integration, migrated).await {
            Ok(()) => {}
            Err(SaveFailure::Changed(current)) => {
                delete_created(store.as_ref(), &integration, &created, &current).await;
                fail(&mut failed, &integration, "it was changed while its credentials were being migrated");
                continue;
            }
            Err(SaveFailure::Deleted) => {
                delete_created(store.as_ref(), &integration, &created, &JsonValue::Null).await;
                fail(&mut failed, &integration, "it was deleted while its credentials were being migrated");
                continue;
            }
            Err(SaveFailure::Failed(reason)) => {
                fail(&mut failed, &integration, &reason);
                continue;
            }
        }
        for step in &steps {
            tracing::info!(
                target: "security_audit",
                event = "integration_credential_migrated",
                integration_id = %integration.id,
                tenant_id = integration.tenant_id.as_deref().unwrap_or("-"),
                field = %step.credential.name(),
                action = step.action.label(),
                secret_id = %step.action.secret_id(),
                "Migrated an inline integration credential to the secrets store"
            );
        }
        if pin == MigratedPin::KeptMoved {
            tracing::warn!(
                integration_id = %integration.id,
                "A secret this integration references points somewhere other than its last save pinned; the old pin was kept, so its deliveries stay refused until it is saved again"
            );
        }
        if let Some(reason) = not_strings_reason {
            fail(&mut failed, &integration, &reason);
        }
    }
    warn_unmigrated(&failed);
    failed
}

fn fail(
    failed: &mut Vec<String>,
    integration: &Integration,
    reason: &str,
) {
    tracing::warn!(
        integration_id = %integration.id,
        reason = %reason,
        "could not migrate integration inline credentials"
    );
    failed.push(integration.id.clone());
}

fn warn_unmigrated(failed: &[String]) {
    if !failed.is_empty() {
        tracing::warn!(
            integrations = %failed.join(", "),
            "These integrations still store credentials inline because their migration failed; it is retried on the next switch to Active"
        );
    }
}

/// Decides what to do with each of `integration`'s inline credentials, without
/// writing anything.
async fn plan(
    store: &Arc<dyn SecretsStore>,
    listed: &[SecretListItem],
    claimed: &mut HashSet<String>,
    integration: &Integration,
) -> anyhow::Result<Plan> {
    let mut plan = Plan {
        steps: Vec::new(),
        not_strings: Vec::new(),
    };
    let secrets = SurfaceSecrets::new(Some(store.clone()), integration.tenant_id.clone());
    for credential in inline_credentials(&integration.configuration) {
        let action = if let Some(reference) = credential.reference(&integration.configuration) {
            if !matches!(
                secrets
                    .resolve(reference)
                    .await,
                Ok(Some(_))
            ) {
                anyhow::bail!(
                    "{} is stored inline next to a reference that does not resolve, so its inline value is kept",
                    credential.name()
                );
            }
            Action::DropInline
        } else {
            let Some(value) = credential
                .value(&integration.configuration)
                .and_then(JsonValue::as_str)
            else {
                plan.not_strings
                    .push(credential.name());
                continue;
            };
            action_for(store.as_ref(), listed, claimed, integration, &credential, value).await?
        };
        plan.steps
            .push(Step { credential, action });
    }
    Ok(plan)
}

/// Reuses the secret an earlier run wrote for this credential when it holds
/// the credential's value, and otherwise creates a new one. A secret counts as
/// an earlier run's only when it carries every migration tag, belongs to the
/// integration's tenant and has an id this migration generates, so a secret
/// someone else tagged is never used.
async fn action_for(
    store: &dyn SecretsStore,
    listed: &[SecretListItem],
    claimed: &mut HashSet<String>,
    integration: &Integration,
    credential: &InlineCredential,
    value: &str,
) -> anyhow::Result<Action> {
    let tags = tags(integration, credential);
    let base = base_secret_id(integration, credential);
    let mut earlier: Vec<_> = listed
        .iter()
        .filter(|secret| {
            secret.tenant_id == integration.tenant_id
                && is_generated_id(&secret.secret_id, &base)
                && tags
                    .iter()
                    .all(|tag| secret.tags.contains(tag))
        })
        .collect();
    earlier.sort_by_key(|secret| secret.created_at);
    for listed in earlier {
        if let Some(secret) = store.get(&listed.id).await?
            && secret.value == value
        {
            return Ok(Action::Reuse { secret_id: secret.secret_id });
        }
    }
    Ok(Action::Create {
        secret_id: free_secret_id(claimed, &base),
        value: value.to_string(),
    })
}

fn tags(
    integration: &Integration,
    credential: &InlineCredential,
) -> Vec<String> {
    vec![MIGRATED_TAG.to_string(), format!("integration:{}", integration.id), format!("field:{}", credential.name())]
}

/// `integration-<id>-<key>`, or `integration-<id>-header-<name>`, lowercased
/// with every character a secret id refuses replaced by `_`.
fn base_secret_id(
    integration: &Integration,
    credential: &InlineCredential,
) -> String {
    let field = match credential {
        InlineCredential::Key(key) => id_part(key),
        InlineCredential::Header { name, .. } => format!("header-{}", id_part(name)),
    };
    format!("integration-{}-{field}", id_part(&integration.id))
}

fn id_part(text: &str) -> String {
    text.chars()
        .map(|c| match c.to_ascii_lowercase() {
            c @ ('a'..='z' | '0'..='9' | '-' | '_') => c,
            _ => '_',
        })
        .collect()
}

/// Whether `secret_id` is one [`free_secret_id`] gives for `base`.
fn is_generated_id(
    secret_id: &str,
    base: &str,
) -> bool {
    secret_id
        .strip_prefix(base)
        .is_some_and(|suffix| {
            suffix.is_empty()
                || suffix
                    .strip_prefix('-')
                    .is_some_and(|n| {
                        !n.is_empty()
                            && n.bytes()
                                .all(|b| b.is_ascii_digit())
                    })
        })
}

/// `base`, or `base-1`, `base-2` and so on when it is taken, claimed so no
/// other credential in this run is given it.
fn free_secret_id(
    claimed: &mut HashSet<String>,
    base: &str,
) -> String {
    let secret_id = std::iter::once(base.to_string())
        .chain((1..).map(|n| format!("{base}-{n}")))
        .find(|candidate| !claimed.contains(candidate))
        .expect("an unclaimed secret id");
    claimed.insert(secret_id.clone());
    secret_id
}

/// Creates the secrets `steps` plan and returns them, by internal id and
/// secret id. A secret created before a failed one stays, and the next run
/// reuses it.
async fn write_secrets(
    store: &dyn SecretsStore,
    integration: &Integration,
    steps: &[Step],
) -> anyhow::Result<Vec<(String, String)>> {
    let mut created = Vec::new();
    for step in steps {
        if let Action::Create { secret_id, value } = &step.action {
            let secret = store
                .create(CreateSecretRequest {
                    name: secret_id.clone(),
                    secret_id: secret_id.clone(),
                    description: Some(format!("Moved from the configuration of integration {}", integration.id)),
                    value: value.clone(),
                    secret_type: "General".to_string(),
                    tags: tags(integration, &step.credential),
                    tenant_id: integration.tenant_id.clone(),
                })
                .await
                .map_err(|error| {
                    anyhow::anyhow!("the secret for {} could not be created: {error}", step.credential.name())
                })?;
            created.push((secret.id, secret.secret_id));
        }
    }
    Ok(created)
}

/// Deletes the secrets a run created for an integration that changed or was
/// deleted before it could be saved, so a credential the integration no longer
/// stores inline is not left behind. A secret the changed configuration references is kept, and
/// a secret that cannot be deleted is named in a warning.
async fn delete_created(
    store: &dyn SecretsStore,
    integration: &Integration,
    created: &[(String, String)],
    current: &JsonValue,
) {
    let referenced = referenced_secrets(current);
    for (id, secret_id) in created {
        if referenced.contains(id) || referenced.contains(secret_id) {
            continue;
        }
        if let Err(error) = store.delete(id).await {
            tracing::warn!(
                integration_id = %integration.id,
                secret = %id,
                error = %error,
                "could not delete a secret created for an integration whose migration was not saved"
            );
        }
    }
}

/// Why [`save`] did not save an integration.
enum SaveFailure {
    /// The integration changed since the run read it; holds its configuration
    /// as it is now.
    Changed(JsonValue),
    /// The integration was deleted since the run read it.
    Deleted,
    /// It could not be read again or written; the next run retries it.
    Failed(String),
}

/// Saves `migrated` as `integration`'s configuration unless the integration
/// changed since it was read, in which case the next run migrates it again.
/// Best effort: a save through the API that lands between the re-read and the
/// write is overwritten.
async fn save(
    storage: &IntegrationStorage,
    integration: &Integration,
    migrated: JsonValue,
) -> Result<(), SaveFailure> {
    let current = storage
        .find(&integration.id)
        .await
        .map_err(|error| SaveFailure::Failed(format!("it could not be read again before saving: {error}")))?
        .ok_or(SaveFailure::Deleted)?;
    if current.configuration != integration.configuration || current.tenant_id != integration.tenant_id {
        return Err(SaveFailure::Changed(current.configuration));
    }
    let mut saved = current;
    saved.configuration = migrated;
    saved.updated_at = chrono::Utc::now().to_rfc3339();
    storage
        .update(&saved.id, &saved)
        .await
        .map_err(|error| SaveFailure::Failed(format!("it could not be saved: {error}")))
}

/// Runs on every switch to Active, before the instance reports ready:
/// migrates inline credentials, then pins the destination of each integration
/// whose references decide where it sends but that has no pin yet. Both stop
/// before the next integration once `still_current` turns false, so an
/// activation superseded by a demotion writes no more.
pub(crate) async fn prepare_integrations(
    storage: &IntegrationStorage,
    store: Option<Arc<dyn SecretsStore>>,
    still_current: &(dyn Fn() -> bool + Sync),
) {
    migrate_inline_credentials(storage, store.clone(), still_current).await;
    pin_unpinned_destinations(storage, store, still_current).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability::log_capture::capture_logs;
    use crate::secrets::{FilesystemSecretsStore, Secret, UpdateSecretRequest};
    use crate::storage::integration_credentials::{PINNED_DESTINATION, destination_moved, resolve_secret_references};

    const WEBHOOK_URL: &str = "https://hooks.slack.com/services/T000/B000/XXXX";
    const PASSWORD: &str = "smtp-pass-value";
    const API_KEY: &str = "api-key-value";
    const SIGNING_SECRET: &str = "a-signing-secret-that-is-long-enough-1234";

    struct Fixture {
        _dir: tempfile::TempDir,
        storage: IntegrationStorage,
        secrets: Arc<FilesystemSecretsStore>,
    }

    impl Fixture {
        async fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let storage = IntegrationStorage::new(
                dir.path()
                    .join("integrations"),
            )
            .await
            .unwrap();
            let secrets = Arc::new(
                FilesystemSecretsStore::new_async(
                    dir.path()
                        .join("secrets")
                        .to_str()
                        .unwrap(),
                )
                .await
                .unwrap(),
            );
            Self { _dir: dir, storage, secrets }
        }

        /// A second handle on the same integration storage, as another
        /// process or a concurrent API save would hold.
        async fn second_storage(&self) -> IntegrationStorage {
            IntegrationStorage::new(
                self._dir
                    .path()
                    .join("integrations"),
            )
            .await
            .unwrap()
        }

        fn store(&self) -> Option<Arc<dyn SecretsStore>> {
            Some(self.secrets.clone())
        }

        async fn saved(
            &self,
            configuration: JsonValue,
            tenant_id: Option<&str>,
        ) -> Integration {
            let mut integration = Integration::new(
                "Alerts".to_string(),
                String::new(),
                "webhook".to_string(),
                configuration,
                serde_json::json!({}),
                "active".to_string(),
                None,
            );
            integration.tenant_id = tenant_id.map(str::to_string);
            self.storage
                .save(&integration)
                .await
                .unwrap();
            integration
        }

        async fn migrate(&self) -> Vec<String> {
            migrate_inline_credentials(&self.storage, self.store(), &|| true).await
        }

        async fn configuration(
            &self,
            integration: &Integration,
        ) -> JsonValue {
            self.storage
                .load(&integration.id)
                .await
                .unwrap()
                .configuration
        }

        async fn secrets(&self) -> Vec<Secret> {
            let mut secrets = Vec::new();
            for listed in self
                .secrets
                .list_all()
                .await
                .unwrap()
            {
                secrets.push(
                    self.secrets
                        .get(&listed.id)
                        .await
                        .unwrap()
                        .unwrap(),
                );
            }
            secrets.sort_by(|a, b| a.secret_id.cmp(&b.secret_id));
            secrets
        }

        async fn secret(
            &self,
            secret_id: &str,
        ) -> Secret {
            self.secrets
                .get_by_secret_id(secret_id)
                .await
                .unwrap()
                .unwrap_or_else(|| panic!("no secret {secret_id}"))
        }

        async fn create(
            &self,
            secret_id: &str,
            value: &str,
            tags: Vec<String>,
            tenant_id: Option<&str>,
        ) -> Secret {
            self.secrets
                .create(CreateSecretRequest {
                    name: secret_id.to_string(),
                    secret_id: secret_id.to_string(),
                    description: None,
                    value: value.to_string(),
                    secret_type: "General".to_string(),
                    tags,
                    tenant_id: tenant_id.map(str::to_string),
                })
                .await
                .unwrap()
        }
    }

    fn webhook_configuration() -> JsonValue {
        serde_json::json!({
            "url": WEBHOOK_URL,
            "smtp_password": PASSWORD,
            "signing_secret": SIGNING_SECRET,
            "headers": { "X-Api!Key": API_KEY, "X-Trace": "abc" },
        })
    }

    fn migrated_tags(
        integration: &Integration,
        field: &str,
    ) -> Vec<String> {
        vec![MIGRATED_TAG.to_string(), format!("integration:{}", integration.id), format!("field:{field}")]
    }

    #[tokio::test]
    async fn urls_passwords_and_headers_become_tagged_secrets_in_the_integrations_tenant() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(webhook_configuration(), Some("tenant-a"))
            .await;
        let id = &integration.id;

        let failed = fixture.migrate().await;

        assert!(failed.is_empty(), "{failed:?}");
        let configuration = fixture
            .configuration(&integration)
            .await;
        assert_eq!(
            configuration,
            serde_json::json!({
                "url_secret_id": format!("integration-{id}-url"),
                "smtp_password_secret_id": format!("integration-{id}-smtp_password"),
                "signing_secret": SIGNING_SECRET,
                "headers": { "X-Trace": "abc" },
                "headers_secret_id": { "X-Api!Key": format!("integration-{id}-header-x-api_key") },
                "pinned_destination": { "url": "hooks.slack.com:443" },
            })
        );
        for (secret_id, field, value) in [
            (format!("integration-{id}-url"), "url", WEBHOOK_URL),
            (format!("integration-{id}-smtp_password"), "smtp_password", PASSWORD),
            (format!("integration-{id}-header-x-api_key"), "headers.X-Api!Key", API_KEY),
        ] {
            let secret = fixture
                .secret(&secret_id)
                .await;
            assert_eq!(secret.value, value);
            assert_eq!(secret.name, secret_id);
            assert_eq!(secret.tags, migrated_tags(&integration, field));
            assert_eq!(secret.tenant_id.as_deref(), Some("tenant-a"));
        }
        assert_eq!(fixture.secrets().await.len(), 3, "the signing secret stays inline");

        let mut resolved = configuration.clone();
        resolve_secret_references(&mut resolved, Some("tenant-a"), fixture.store())
            .await
            .unwrap();
        assert_eq!(resolved["url"], WEBHOOK_URL);
        assert_eq!(resolved["smtp_password"], PASSWORD);
        assert_eq!(resolved["headers"]["X-Api!Key"], API_KEY);
        assert_eq!(resolved["signing_secret"], SIGNING_SECRET);
        assert!(!destination_moved(&configuration, &resolved, configuration.get(PINNED_DESTINATION)).unwrap());
    }

    #[tokio::test]
    async fn a_disabled_integration_is_migrated_and_delivers_once_enabled() {
        let fixture = Fixture::new().await;
        let mut integration = fixture
            .saved(serde_json::json!({ "webhook_url": WEBHOOK_URL }), None)
            .await;
        integration.status = "disabled".to_string();
        fixture
            .storage
            .save(&integration)
            .await
            .unwrap();

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        let mut enabled = fixture
            .storage
            .load(&integration.id)
            .await
            .unwrap();
        assert_eq!(enabled.status, "disabled");
        assert_eq!(
            enabled.configuration,
            serde_json::json!({
                "webhook_url_secret_id": format!("integration-{}-webhook_url", integration.id),
                "pinned_destination": { "webhook_url": "hooks.slack.com:443" },
            })
        );

        enabled.status = "active".to_string();
        fixture
            .storage
            .update(&enabled.id, &enabled)
            .await
            .unwrap();
        let configuration = fixture
            .configuration(&integration)
            .await;
        let mut resolved = configuration.clone();
        resolve_secret_references(&mut resolved, None, fixture.store())
            .await
            .unwrap();
        assert_eq!(resolved["webhook_url"], WEBHOOK_URL);
        assert!(!destination_moved(&configuration, &resolved, configuration.get(PINNED_DESTINATION)).unwrap());
    }

    #[tokio::test]
    async fn a_tenantless_integration_gets_tenantless_secrets() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        let secret = fixture
            .secret(&format!("integration-{}-smtp_password", integration.id))
            .await;
        assert_eq!(secret.tenant_id, None);
    }

    #[tokio::test]
    async fn a_url_the_save_check_refuses_is_still_migrated_and_pinned() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "url": "http://10.0.0.5/in" }), None)
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await[PINNED_DESTINATION],
            serde_json::json!({ "url": "10.0.0.5:80" })
        );
    }

    #[tokio::test]
    async fn a_taken_secret_id_gets_the_next_free_suffix() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let base = format!("integration-{}-smtp_password", integration.id);
        fixture
            .create(&base, "someone else's", Vec::new(), Some("tenant-b"))
            .await;
        fixture
            .create(&format!("{base}-1"), "someone else's", Vec::new(), None)
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            format!("{base}-2")
        );
        assert_eq!(
            fixture
                .secret(&format!("{base}-2"))
                .await
                .value,
            PASSWORD
        );
        assert_eq!(
            fixture
                .secret(&base)
                .await
                .value,
            "someone else's"
        );
    }

    #[tokio::test]
    async fn running_again_changes_nothing() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(webhook_configuration(), None)
            .await;
        fixture.migrate().await;
        let configuration = fixture
            .configuration(&integration)
            .await;
        let secrets = fixture.secrets().await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            configuration
        );
        let again = fixture.secrets().await;
        assert_eq!(
            again
                .iter()
                .map(|secret| (&secret.id, &secret.value, secret.updated_at))
                .collect::<Vec<_>>(),
            secrets
                .iter()
                .map(|secret| (&secret.id, &secret.value, secret.updated_at))
                .collect::<Vec<_>>()
        );
    }

    #[tokio::test]
    async fn an_interrupted_run_finishes_with_the_secret_it_already_wrote() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let written = fixture
            .create(
                &format!("integration-{}-smtp_password-7", integration.id),
                PASSWORD,
                migrated_tags(&integration, "smtp_password"),
                None,
            )
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            written.secret_id
        );
        assert_eq!(fixture.secrets().await.len(), 1);
    }

    #[tokio::test]
    async fn an_earlier_secret_holding_another_value_is_left_and_a_new_one_created() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let written = fixture
            .create(
                &format!("integration-{}-smtp_password", integration.id),
                "rotated-value",
                migrated_tags(&integration, "smtp_password"),
                None,
            )
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            format!("{}-1", written.secret_id)
        );
        assert_eq!(
            fixture
                .secret(&written.secret_id)
                .await
                .value,
            "rotated-value"
        );
        assert_eq!(
            fixture
                .secret(&format!("{}-1", written.secret_id))
                .await
                .value,
            PASSWORD
        );
    }

    #[tokio::test]
    async fn a_secret_someone_else_tagged_is_never_reused() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let planted = fixture
            .create("planted", PASSWORD, migrated_tags(&integration, "smtp_password"), None)
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            format!("integration-{}-smtp_password", integration.id)
        );
        assert_eq!(
            fixture
                .secret(&planted.secret_id)
                .await
                .value,
            PASSWORD
        );
    }

    #[test]
    fn only_ids_the_migration_generates_count_as_its_own() {
        let base = "integration-abc-smtp_password";

        for (secret_id, generated) in [
            (base.to_string(), true),
            (format!("{base}-1"), true),
            (format!("{base}-27"), true),
            (format!("{base}-"), false),
            (format!("{base}-copy"), false),
            (format!("{base}-1a"), false),
            (format!("{base}x"), false),
            ("planted".to_string(), false),
        ] {
            assert_eq!(is_generated_id(&secret_id, base), generated, "{secret_id}");
        }
    }

    #[tokio::test]
    async fn several_earlier_secrets_without_the_value_leave_them_and_create_a_new_one() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let base = format!("integration-{}-smtp_password", integration.id);
        for secret_id in [base.clone(), format!("{base}-copy")] {
            fixture
                .create(&secret_id, "other", migrated_tags(&integration, "smtp_password"), None)
                .await;
        }

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            format!("{base}-1")
        );
        let secrets = fixture.secrets().await;
        assert_eq!(
            secrets
                .iter()
                .map(|secret| (secret.secret_id.as_str(), secret.value.as_str()))
                .collect::<Vec<_>>(),
            vec![
                (base.as_str(), "other"),
                (format!("{base}-1").as_str(), PASSWORD),
                (format!("{base}-copy").as_str(), "other"),
            ]
        );
    }

    #[tokio::test]
    async fn a_secret_in_another_tenant_or_without_every_tag_is_not_reused() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), Some("tenant-a"))
            .await;
        let tags = migrated_tags(&integration, "smtp_password");
        fixture
            .create("elsewhere", PASSWORD, tags.clone(), Some("tenant-b"))
            .await;
        fixture
            .create("untagged", PASSWORD, tags[1..].to_vec(), Some("tenant-a"))
            .await;

        fixture.migrate().await;

        assert_eq!(
            fixture
                .configuration(&integration)
                .await["smtp_password_secret_id"],
            format!("integration-{}-smtp_password", integration.id)
        );
    }

    #[tokio::test]
    async fn an_inline_value_with_a_reference_is_dropped_without_a_new_secret() {
        let fixture = Fixture::new().await;
        fixture
            .create("smtp-global", "referenced", Vec::new(), None)
            .await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD, "smtp_password_secret_id": "smtp-global" }), None)
            .await;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            serde_json::json!({ "smtp_password_secret_id": "smtp-global" })
        );
        assert_eq!(fixture.secrets().await.len(), 1);
    }

    #[tokio::test]
    async fn a_credential_that_is_not_a_string_stays_inline_and_the_others_are_migrated() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD, "credentials": { "key": "value" } }), None)
            .await;

        let failed = fixture.migrate().await;

        assert_eq!(failed, vec![integration.id.clone()], "the field left inline is named");
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            serde_json::json!({
                "smtp_password_secret_id": format!("integration-{}-smtp_password", integration.id),
                "credentials": { "key": "value" },
            })
        );
        assert_eq!(fixture.secrets().await.len(), 1);
    }

    #[tokio::test]
    async fn an_integration_with_only_credentials_that_are_not_strings_is_left_unchanged() {
        let fixture = Fixture::new().await;
        let configuration = serde_json::json!({ "credentials": { "key": "value" } });
        let integration = fixture
            .saved(configuration.clone(), None)
            .await;

        assert_eq!(fixture.migrate().await, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            configuration
        );
        assert!(
            fixture
                .secrets()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_empty_or_null_reference_does_not_count_and_the_inline_value_is_migrated() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(
                serde_json::json!({
                    "url": WEBHOOK_URL,
                    "url_secret_id": "",
                    "headers": { "Authorization": "Bearer inline" },
                    "headers_secret_id": { "Authorization": null },
                }),
                None,
            )
            .await;
        let id = &integration.id;

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );

        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            serde_json::json!({
                "url_secret_id": format!("integration-{id}-url"),
                "headers": {},
                "headers_secret_id": { "Authorization": format!("integration-{id}-header-authorization") },
                "pinned_destination": { "url": "hooks.slack.com:443" },
            })
        );
        assert_eq!(
            fixture
                .secret(&format!("integration-{id}-url"))
                .await
                .value,
            WEBHOOK_URL
        );
        assert_eq!(
            fixture
                .secret(&format!("integration-{id}-header-authorization"))
                .await
                .value,
            "Bearer inline"
        );
    }

    #[tokio::test]
    async fn a_pin_its_references_no_longer_match_is_kept_so_deliveries_stay_refused() {
        let fixture = Fixture::new().await;
        let hook = fixture
            .create("hook", "https://a.example.com/in", Vec::new(), None)
            .await;
        let integration = fixture
            .saved(
                serde_json::json!({
                    "url_secret_id": "hook",
                    "pinned_destination": { "url": "a.example.com:443" },
                    "headers": { "Authorization": "Bearer inline" },
                }),
                None,
            )
            .await;
        fixture
            .secrets
            .update(
                &hook.id,
                UpdateSecretRequest {
                    name: None,
                    description: None,
                    value: Some("https://b.example.net/in".to_string()),
                    update_value: Some(true),
                    secret_type: None,
                    tags: None,
                },
            )
            .await
            .unwrap();

        let (logs, failed) = capture_logs(fixture.migrate()).await;

        assert!(failed.is_empty(), "{failed:?}");
        let configuration = fixture
            .configuration(&integration)
            .await;
        assert_eq!(configuration[PINNED_DESTINATION], serde_json::json!({ "url": "a.example.com:443" }));
        assert!(
            configuration["headers"]
                .get("Authorization")
                .is_none()
        );
        let mut resolved = configuration.clone();
        resolve_secret_references(&mut resolved, None, fixture.store())
            .await
            .unwrap();
        assert!(destination_moved(&configuration, &resolved, configuration.get(PINNED_DESTINATION)).unwrap());
        assert!(logs.contains("the old pin was kept"), "{logs}");
    }

    #[tokio::test]
    async fn a_superseded_activation_stops_before_the_next_integration() {
        let fixture = Fixture::new().await;
        let configuration = serde_json::json!({ "smtp_password": PASSWORD });
        let first = fixture
            .saved(configuration.clone(), None)
            .await;
        let second = fixture
            .saved(configuration.clone(), None)
            .await;
        let checks = std::sync::atomic::AtomicUsize::new(0);
        let still_current = || checks.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0;

        migrate_inline_credentials(&fixture.storage, fixture.store(), &still_current).await;

        let unchanged = [
            fixture
                .configuration(&first)
                .await,
            fixture
                .configuration(&second)
                .await,
        ]
        .into_iter()
        .filter(|stored| *stored == configuration)
        .count();
        assert_eq!(unchanged, 1, "only the integration before the demotion is migrated");
        assert_eq!(fixture.secrets().await.len(), 1);

        migrate_inline_credentials(&fixture.storage, fixture.store(), &|| false).await;
        assert_eq!(fixture.secrets().await.len(), 1, "a superseded run writes nothing");
    }

    #[tokio::test]
    async fn an_inline_value_next_to_a_reference_that_does_not_resolve_is_kept() {
        let fixture = Fixture::new().await;
        let configuration = serde_json::json!({ "smtp_password": PASSWORD, "smtp_password_secret_id": "deleted" });
        let integration = fixture
            .saved(configuration.clone(), None)
            .await;

        assert_eq!(fixture.migrate().await, vec![integration.id.clone()]);

        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            configuration
        );
        assert!(
            fixture
                .secrets()
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn an_inline_value_next_to_another_tenants_secret_is_kept() {
        let fixture = Fixture::new().await;
        fixture
            .create("tenant-b-password", "other", Vec::new(), Some("tenant-b"))
            .await;
        let configuration =
            serde_json::json!({ "smtp_password": PASSWORD, "smtp_password_secret_id": "tenant-b-password" });
        let integration = fixture
            .saved(configuration.clone(), Some("tenant-a"))
            .await;

        assert_eq!(fixture.migrate().await, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            configuration
        );
    }

    #[tokio::test]
    async fn secrets_created_for_an_integration_that_was_not_saved_are_deleted() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "url": WEBHOOK_URL, "smtp_password": PASSWORD }), None)
            .await;
        let mut edited = integration.clone();
        edited.configuration = serde_json::json!({ "url": WEBHOOK_URL, "smtp_password_secret_id": "rotated" });
        let editing: Arc<dyn SecretsStore> = Arc::new(RefusingStore {
            inner: fixture.secrets.clone(),
            refused: String::new(),
            on_create: Some(OnCreate::Save(fixture.second_storage().await, Box::new(edited.clone()))),
        });

        let failed = migrate_inline_credentials(&fixture.storage, Some(editing), &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            edited.configuration
        );
        assert!(
            fixture
                .secrets()
                .await
                .is_empty(),
            "the secrets this run created are deleted"
        );
    }

    #[tokio::test]
    async fn a_secret_the_changed_integration_references_is_kept() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let created = format!("integration-{}-smtp_password", integration.id);
        let mut edited = integration.clone();
        edited.configuration = serde_json::json!({ "smtp_password_secret_id": created });
        let editing: Arc<dyn SecretsStore> = Arc::new(RefusingStore {
            inner: fixture.secrets.clone(),
            refused: String::new(),
            on_create: Some(OnCreate::Save(fixture.second_storage().await, Box::new(edited.clone()))),
        });

        let failed = migrate_inline_credentials(&fixture.storage, Some(editing), &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            edited.configuration
        );
        assert_eq!(
            fixture
                .secret(&created)
                .await
                .value,
            PASSWORD,
            "the referenced secret is kept"
        );
    }

    #[tokio::test]
    async fn secrets_created_for_an_integration_deleted_mid_run_are_deleted() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let deleting: Arc<dyn SecretsStore> = Arc::new(RefusingStore {
            inner: fixture.secrets.clone(),
            refused: String::new(),
            on_create: Some(OnCreate::Delete(fixture.second_storage().await, integration.id.clone())),
        });

        let failed = migrate_inline_credentials(&fixture.storage, Some(deleting), &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()]);
        assert!(
            fixture
                .secrets()
                .await
                .is_empty(),
            "no secret is left without an integration"
        );
    }

    #[tokio::test]
    async fn secrets_are_kept_when_the_integration_cannot_be_read_again() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let corrupting: Arc<dyn SecretsStore> = Arc::new(RefusingStore {
            inner: fixture.secrets.clone(),
            refused: String::new(),
            on_create: Some(OnCreate::Corrupt(
                fixture
                    ._dir
                    .path()
                    .join("integrations")
                    .join(format!("{}.json", integration.id)),
            )),
        });

        let failed = migrate_inline_credentials(&fixture.storage, Some(corrupting), &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .secret(&format!("integration-{}-smtp_password", integration.id))
                .await
                .value,
            PASSWORD,
            "the secret is kept for the next run to reuse"
        );
        fixture
            .storage
            .save(&integration)
            .await
            .unwrap();
        assert!(
            fixture
                .migrate()
                .await
                .is_empty(),
            "the next run reuses it"
        );
        assert_eq!(fixture.secrets().await.len(), 1);
    }

    /// What [`RefusingStore`] does to the integration while it creates a secret,
    /// as a concurrent API save or a failing disk would.
    enum OnCreate {
        Save(IntegrationStorage, Box<Integration>),
        Delete(IntegrationStorage, String),
        Corrupt(std::path::PathBuf),
    }

    /// A filesystem store that refuses to create one secret id, and can change
    /// the integration while a secret is created.
    struct RefusingStore {
        inner: Arc<FilesystemSecretsStore>,
        refused: String,
        on_create: Option<OnCreate>,
    }

    #[async_trait::async_trait]
    impl SecretsStore for RefusingStore {
        async fn create(
            &self,
            request: CreateSecretRequest,
        ) -> anyhow::Result<Secret> {
            if request.secret_id == self.refused {
                anyhow::bail!("disk full");
            }
            match &self.on_create {
                Some(OnCreate::Save(storage, edited)) => storage.save(edited).await?,
                Some(OnCreate::Delete(storage, id)) => storage.delete(id).await?,
                Some(OnCreate::Corrupt(file)) => std::fs::write(file, b"not json")?,
                None => {}
            }
            self.inner
                .create(request)
                .await
        }

        async fn get(
            &self,
            id: &str,
        ) -> anyhow::Result<Option<Secret>> {
            self.inner.get(id).await
        }

        async fn list_all(&self) -> anyhow::Result<Vec<SecretListItem>> {
            self.inner.list_all().await
        }

        async fn update(
            &self,
            id: &str,
            request: UpdateSecretRequest,
        ) -> anyhow::Result<Secret> {
            self.inner
                .update(id, request)
                .await
        }

        async fn delete(
            &self,
            id: &str,
        ) -> anyhow::Result<()> {
            self.inner.delete(id).await
        }

        async fn find_by_tag(
            &self,
            tag: &str,
        ) -> anyhow::Result<Vec<SecretListItem>> {
            self.inner
                .find_by_tag(tag)
                .await
        }
    }

    #[tokio::test]
    async fn a_failed_secret_write_leaves_the_integration_unmigrated_until_the_next_run() {
        let fixture = Fixture::new().await;
        let configuration = serde_json::json!({ "url": WEBHOOK_URL, "smtp_password": PASSWORD });
        let integration = fixture
            .saved(configuration.clone(), None)
            .await;
        let refusing: Arc<dyn SecretsStore> = Arc::new(RefusingStore {
            inner: fixture.secrets.clone(),
            refused: format!("integration-{}-url", integration.id),
            on_create: None,
        });

        let failed = migrate_inline_credentials(&fixture.storage, Some(refusing), &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()]);
        assert_eq!(
            fixture
                .configuration(&integration)
                .await,
            configuration
        );

        assert!(
            fixture
                .migrate()
                .await
                .is_empty()
        );
        let migrated = fixture
            .configuration(&integration)
            .await;
        assert!(migrated.get("url").is_none());
        assert!(
            migrated
                .get("smtp_password")
                .is_none()
        );
        assert_eq!(fixture.secrets().await.len(), 2, "the secret written before the failure is reused");
    }

    #[tokio::test]
    async fn without_a_secrets_store_every_integration_is_left_unmigrated() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        fixture
            .saved(serde_json::json!({ "smtp_host": "smtp.example.com" }), None)
            .await;

        let failed = migrate_inline_credentials(&fixture.storage, None, &|| true).await;

        assert_eq!(failed, vec![integration.id.clone()], "an integration with nothing inline is not named");
    }

    #[tokio::test]
    async fn an_integration_changed_since_it_was_read_is_not_saved() {
        let fixture = Fixture::new().await;
        let read = fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD }), None)
            .await;
        let mut edited = read.clone();
        edited.configuration["smtp_host"] = serde_json::json!("smtp.example.com");
        fixture
            .storage
            .save(&edited)
            .await
            .unwrap();

        let saved = save(&fixture.storage, &read, serde_json::json!({ "smtp_password_secret_id": "x" })).await;

        assert!(matches!(saved, Err(SaveFailure::Changed(_))));
        assert_eq!(
            fixture
                .configuration(&read)
                .await,
            edited.configuration
        );
    }

    #[tokio::test]
    async fn logs_name_fields_and_secret_ids_but_never_a_value() {
        let fixture = Fixture::new().await;
        let integration = fixture
            .saved(webhook_configuration(), None)
            .await;
        fixture
            .saved(serde_json::json!({ "smtp_password": PASSWORD, "credentials": { "key": API_KEY } }), None)
            .await;
        fixture
            .create(
                &format!("integration-{}-smtp_password", integration.id),
                "old-value",
                migrated_tags(&integration, "smtp_password"),
                None,
            )
            .await;

        let (applied, _) = capture_logs(fixture.migrate()).await;

        for value in [WEBHOOK_URL, PASSWORD, API_KEY, SIGNING_SECRET, "old-value", "XXXX"] {
            assert!(!applied.contains(value), "a log holds a credential value: {applied}");
        }
        assert_eq!(
            applied
                .matches("integration_credential_migrated")
                .count(),
            4,
            "{applied}"
        );
        assert!(applied.contains("credentials cannot be stored as a secret"), "{applied}");
        assert!(applied.contains("field=headers.X-Api!Key"), "{applied}");
    }
}
