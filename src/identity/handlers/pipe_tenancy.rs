use std::sync::Arc;

use crate::auth_manager::pat::PatResourceScope;
use crate::identity::handlers::pipes::AppError;
use crate::identity::state::IdentityApiState;
use crate::pipes::{PipeConfig, PipeType};
use crate::source_auth::{SourceAuthConfig, models::MtlsTrust};
use crate::tenancy::{PatTenantContext, ResourceKind, can_reference, scope_allows_resource};

#[derive(Clone)]
pub(crate) struct PipeReferenceStores {
    pub(crate) secrets: Option<Arc<dyn crate::secrets::SecretsStore>>,
    pub(crate) certificates: Option<Arc<dyn crate::certificates::CertificateStore>>,
    pub(crate) jwt_strategies: Option<Arc<dyn crate::jwt_bearer::JwtVerificationStrategyStorage>>,
    pub(crate) agent_surfaces: Option<Arc<dyn crate::surfaces::AgentSurfaceStore>>,
    pub(crate) integrations: Option<Arc<crate::storage::IntegrationStorage>>,
    pub(crate) oauth_identifiers: Option<Arc<dyn crate::oauth_identifiers::OAuthIdentifierStorage>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PipeReferenceKey {
    pub kind: ResourceKind,
    pub id: String,
}

pub(crate) fn collect_pipe_reference_keys(pipe: &PipeConfig) -> Result<Vec<PipeReferenceKey>, AppError> {
    Ok(reference_keys(&resolved_views(pipe)?))
}

/// Every reference the surface's base and resolved variants (`views`) make.
fn reference_keys(views: &[PipeConfig]) -> Vec<PipeReferenceKey> {
    let mut references = Vec::new();
    for effective in views {
        collect_effective_references(effective, &mut references);
    }
    references.sort_by(|left, right| {
        left.kind
            .as_str()
            .cmp(right.kind.as_str())
            .then_with(|| left.id.cmp(&right.id))
    });
    references.dedup_by(|left, right| left.kind == right.kind && left.id == right.id);
    references
}

/// Check every reference a surface makes against the caller and the surface's
/// tenant, and every price it declares against the secrets that upstream
/// spends (see [`super::pipe_pricing::validate_declared_price_secrets`]). Every
/// save path runs this: create, update, the variant API and promote.
pub(super) async fn validate_pipe_references(
    state: &IdentityApiState,
    stores: &PipeReferenceStores,
    pipe: &PipeConfig,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), AppError> {
    let authorizer = PipeReferenceAuthorizer {
        state,
        stores,
        pipe_id: &pipe.id,
        owner_tenant_id: pipe.tenant_id.as_deref(),
        context,
        scope,
    };
    let views = resolved_views(pipe)?;
    for reference in reference_keys(&views) {
        authorizer
            .validate(&reference)
            .await?;
    }
    super::pipe_pricing::validate_declared_price_secrets(stores.secrets.as_ref(), pipe, &views).await
}

struct PipeReferenceAuthorizer<'a> {
    state: &'a IdentityApiState,
    stores: &'a PipeReferenceStores,
    pipe_id: &'a str,
    owner_tenant_id: Option<&'a str>,
    context: Option<&'a PatTenantContext>,
    scope: Option<&'a PatResourceScope>,
}

impl PipeReferenceAuthorizer<'_> {
    async fn validate(
        &self,
        reference: &PipeReferenceKey,
    ) -> Result<(), AppError> {
        match reference.kind {
            ResourceKind::PolicyDefinitions => {
                let store = self
                    .state
                    .policy_definition_store
                    .as_ref()
                    .ok_or_else(|| unavailable("Policy definition"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .ok_or_else(|| inaccessible("Policy definition"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "Policy definition")
            }
            ResourceKind::Secrets => {
                let store = self
                    .stores
                    .secrets
                    .as_ref()
                    .ok_or_else(|| unavailable("Secret"))?;
                authorize_secret_reference(
                    store.as_ref(),
                    self.owner_tenant_id,
                    self.context,
                    self.scope,
                    &reference.id,
                )
                .await
            }
            ResourceKind::Certificates => {
                let store = self
                    .stores
                    .certificates
                    .as_ref()
                    .ok_or_else(|| unavailable("Certificate"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .map_err(|_| inaccessible("Certificate"))?
                    .ok_or_else(|| inaccessible("Certificate"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "Certificate")
            }
            ResourceKind::JwtVerificationStrategies => {
                let store = self
                    .stores
                    .jwt_strategies
                    .as_ref()
                    .ok_or_else(|| unavailable("JWT verification strategy"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .map_err(|_| inaccessible("JWT verification strategy"))?
                    .ok_or_else(|| inaccessible("JWT verification strategy"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "JWT verification strategy")
            }
            ResourceKind::ApiKeys => {
                let parents = crate::api_keys::parent::ApiKeyParents::new(
                    self.stores
                        .agent_surfaces
                        .clone(),
                    self.state.pipe_store.clone(),
                );
                let tenants =
                    api_key_parent_tenants(&parents, self.pipe_id, self.owner_tenant_id, &reference.id).await?;
                for tenant_id in &tenants {
                    self.ensure(tenant_id.as_deref(), reference, "API-key parent Surface")?;
                }
                Ok(())
            }
            ResourceKind::Integrations => {
                let store = self
                    .stores
                    .integrations
                    .as_ref()
                    .ok_or_else(|| unavailable("Integration"))?;
                let resource = store
                    .load(&reference.id)
                    .await
                    .map_err(|_| inaccessible("Integration"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "Integration")
            }
            ResourceKind::Teams => {
                let store = self
                    .state
                    .team_store
                    .as_ref()
                    .ok_or_else(|| unavailable("Team"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .ok_or_else(|| inaccessible("Team"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "Team")
            }
            ResourceKind::OauthIdentifiers => {
                let store = self
                    .stores
                    .oauth_identifiers
                    .as_ref()
                    .ok_or_else(|| unavailable("OAuth Identifier"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .map_err(|_| inaccessible("OAuth Identifier"))?
                    .ok_or_else(|| inaccessible("OAuth Identifier"))?;
                self.ensure(
                    resource
                        .owner_tenant_id
                        .as_deref(),
                    reference,
                    "OAuth Identifier",
                )
            }
            ResourceKind::Pipes => {
                let store = self
                    .state
                    .pipe_store
                    .as_ref()
                    .ok_or_else(|| unavailable("Pipe"))?;
                let resource = store
                    .get(&reference.id)
                    .await
                    .ok_or_else(|| inaccessible("Pipe"))?;
                self.ensure(resource.tenant_id.as_deref(), reference, "Pipe")
            }
            _ => Err(AppError::InternalError(format!("Unsupported Pipe reference kind: {}", reference.kind))),
        }
    }

    fn ensure(
        &self,
        resource_tenant_id: Option<&str>,
        reference: &PipeReferenceKey,
        label: &str,
    ) -> Result<(), AppError> {
        if !can_reference(self.owner_tenant_id, resource_tenant_id)
            || !scope_allows_resource(self.scope, self.context, reference.kind, &reference.id)
        {
            return Err(inaccessible(label));
        }
        Ok(())
    }
}

/// Check a surface's secret reference against the secret a request would send
/// with it: the one [`crate::secrets::resolve_reference`] resolves it to, the
/// same function every request-time resolver uses. The caller must be allowed
/// that secret's tenant, and a scoped token must admit both the reference as
/// written and the secret's public `secret_id` (the namespace token scopes are
/// written over), so a reference by internal id cannot reach outside the
/// token's namespace. Anything unresolvable is refused.
pub(crate) async fn authorize_secret_reference(
    store: &dyn crate::secrets::SecretsStore,
    owner_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    reference: &str,
) -> Result<(), AppError> {
    resolve_authorized_secret(store, owner_tenant_id, context, scope, reference)
        .await
        .map(|_| ())
}

/// [`authorize_secret_reference`] for a caller that sends the secret right
/// away: returns the secret the check approved, so the value used is the one
/// that was checked.
pub(crate) async fn resolve_authorized_secret(
    store: &dyn crate::secrets::SecretsStore,
    owner_tenant_id: Option<&str>,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
    reference: &str,
) -> Result<crate::secrets::Secret, AppError> {
    let secret = crate::secrets::resolve_reference(store, reference)
        .await
        .map_err(|_| inaccessible("Secret"))?
        .ok_or_else(|| inaccessible("Secret"))?;
    if !can_reference(owner_tenant_id, secret.tenant_id.as_deref())
        || !scope_allows_resource(scope, context, ResourceKind::Secrets, reference)
        || !scope_allows_resource(scope, context, ResourceKind::Secrets, &secret.secret_id)
    {
        return Err(inaccessible("Secret"));
    }
    Ok(secret)
}

/// The tenant of every record an `api_key_provider` names as its parent. A
/// Surface may name itself, so the tenant it is saved under counts too.
async fn api_key_parent_tenants(
    parents: &crate::api_keys::parent::ApiKeyParents,
    pipe_id: &str,
    owner_tenant_id: Option<&str>,
    agent_id: &str,
) -> Result<Vec<Option<String>>, AppError> {
    let mut tenants = parents
        .tenants(agent_id)
        .await
        .map_err(|_| inaccessible("API-key parent Surface"))?;
    if agent_id == pipe_id {
        tenants.push(owner_tenant_id.map(str::to_owned));
    }
    if tenants.is_empty() {
        return Err(inaccessible("API-key parent Surface"));
    }
    Ok(tenants)
}

fn inaccessible(label: &str) -> AppError {
    AppError::InvalidInput(format!("{} reference is not accessible", label))
}

fn unavailable(label: &str) -> AppError {
    AppError::InternalError(format!("{} store not configured", label))
}

/// The surface itself and every variant resolved over it (disabled ones too).
pub(super) fn resolved_views(pipe: &PipeConfig) -> Result<Vec<PipeConfig>, AppError> {
    let mut views = vec![pipe.clone()];
    for variant in &pipe.variants {
        let mut resolvable = pipe.clone();
        if let Some(candidate) = resolvable
            .variants
            .iter_mut()
            .find(|candidate| candidate.id == variant.id)
        {
            candidate.enabled = true;
        }
        let resolved = resolvable
            .resolve_variant(Some(&variant.alias))
            .map_err(|error| {
                AppError::InvalidInput(format!(
                    "Variant '{}' references could not be resolved: {}",
                    variant.alias, error
                ))
            })?;
        views.push(resolved);
    }
    Ok(views)
}

fn collect_effective_references(
    pipe: &PipeConfig,
    references: &mut Vec<PipeReferenceKey>,
) {
    collect_source_auth_references(pipe, references);
    for binding in super::pipe_secret_bindings::secret_bindings(pipe) {
        push_reference(references, ResourceKind::Secrets, &binding.secret);
    }
    for policy_id in pipe.opa_policy_definition_ids() {
        push_reference(references, ResourceKind::PolicyDefinitions, &policy_id);
    }
    for mapping in &pipe.integrations {
        push_reference(references, ResourceKind::Integrations, &mapping.integration_id);
    }
    for alert in pipe
        .usage_alerts
        .iter()
        .flatten()
    {
        for integration_id in &alert.notification_channels {
            push_reference(references, ResourceKind::Integrations, integration_id);
        }
    }
    if let Some(export) = pipe
        .governance_recording
        .as_ref()
        .and_then(|recording| recording.export.as_ref())
    {
        for integration_id in &export.integrations {
            push_reference(references, ResourceKind::Integrations, integration_id);
        }
    }
    if let Some(integration_ids) = pipe
        .drift
        .as_ref()
        .and_then(|drift| {
            drift
                .alert_integrations
                .as_ref()
        })
    {
        for integration_id in integration_ids {
            push_reference(references, ResourceKind::Integrations, integration_id);
        }
    }
    if let Some(attribution) = &pipe.team_attribution {
        for team_id in &attribution.allowed_teams {
            push_reference(references, ResourceKind::Teams, team_id);
        }
    }
    if let Some(identifier_id) = &pipe.sandbox_oauth_identifier_id {
        push_reference(references, ResourceKind::OauthIdentifiers, identifier_id);
    }
    if let PipeType::IDECatalog { config } = &pipe.pipe_type {
        if let Some(identifier_id) = config
            .client_auth
            .as_ref()
            .and_then(|auth| {
                auth.oauth_identifier_id
                    .as_deref()
            })
        {
            push_reference(references, ResourceKind::OauthIdentifiers, identifier_id);
        }
        for member in &config.members {
            push_reference(references, ResourceKind::Pipes, &member.pipe_id);
            if let Some(identifier_id) = &member.upstream_oauth_identifier_id {
                push_reference(references, ResourceKind::OauthIdentifiers, identifier_id);
            }
            if let Some(policy_id) = &member.opa_policy_id {
                push_reference(references, ResourceKind::PolicyDefinitions, policy_id);
            }
        }
    }
}

fn collect_source_auth_references(
    pipe: &PipeConfig,
    references: &mut Vec<PipeReferenceKey>,
) {
    match pipe.source_auth.as_ref() {
        Some(SourceAuthConfig::JwtBearer(config)) => {
            push_reference(references, ResourceKind::JwtVerificationStrategies, &config.jwt_verification_strategy_id)
        }
        Some(SourceAuthConfig::ApiKey(config)) => push_reference(references, ResourceKind::Secrets, &config.secret_id),
        Some(SourceAuthConfig::ApiKeyProvider(config)) => {
            push_reference(references, ResourceKind::ApiKeys, &config.agent_id)
        }
        Some(SourceAuthConfig::Mtls(config)) => match &config.trust {
            MtlsTrust::Pinned { certificate_ids } => {
                for certificate_id in certificate_ids {
                    push_reference(references, ResourceKind::Certificates, certificate_id);
                }
            }
            MtlsTrust::Ca { ca_certificate_ids, .. } => {
                for certificate_id in ca_certificate_ids {
                    push_reference(references, ResourceKind::Certificates, certificate_id);
                }
            }
        },
        None => {}
    }
}

fn push_reference(
    references: &mut Vec<PipeReferenceKey>,
    kind: ResourceKind,
    id: &str,
) {
    let id = id.trim();
    if !id.is_empty() {
        references.push(PipeReferenceKey { kind, id: id.to_string() });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides};
    use crate::pipes::types::llm::LLMProvider;

    fn api_pipe() -> PipeConfig {
        PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::Webhook {
                endpoint: "https://example.com".into(),
            },
        )
    }

    fn openai(secret_id: &str) -> PipeType {
        PipeType::LLM {
            provider: Box::new(LLMProvider::OpenAI {
                provider_type: "openai".into(),
                model: "gpt-4o".into(),
                api_key_secret: Some(secret_id.into()),
                organization_id: None,
                base_url: None,
                temperature: None,
                max_tokens: None,
                top_p: None,
                frequency_penalty: None,
                presence_penalty: None,
            }),
            endpoint_path: None,
        }
    }

    #[test]
    fn collector_includes_disabled_variant_references_and_deduplicates() {
        let mut pipe = api_pipe();
        pipe.opa_policy = Some(crate::pipes::config::PipeOpaConfig {
            enabled: true,
            policy_definition_id: Some("policy-base".into()),
            policy_definition_ids: vec!["policy-shared".into()],
            log_decisions: false,
        });
        pipe.integrations = vec![crate::pipes::config::PipeIntegrationMapping {
            integration_id: "integration-1".into(),
            event_types: Vec::new(),
            variables: serde_json::json!({}),
        }];
        pipe.governance_recording = Some(crate::governance::GovernanceRecordingConfig {
            export: Some(crate::governance::GovernanceExport {
                otel: false,
                integrations: vec!["integration-1".into()],
            }),
            ..Default::default()
        });
        pipe.variants = vec![PipeVariant {
            id: "variant-1".into(),
            alias: "future".into(),
            name: "Future".into(),
            description: String::new(),
            enabled: false,
            overrides: PipeVariantOverrides {
                pipe_type: Some(openai("secret-variant")),
                opa_policy: Some(crate::pipes::config::PipeOpaConfig {
                    enabled: true,
                    policy_definition_id: Some("policy-variant".into()),
                    policy_definition_ids: vec!["policy-shared".into()],
                    log_decisions: false,
                }),
                ..Default::default()
            },
        }];

        let references = collect_pipe_reference_keys(&pipe).unwrap();

        assert!(references.contains(&PipeReferenceKey {
            kind: ResourceKind::Secrets,
            id: "secret-variant".into(),
        }));
        assert!(references.contains(&PipeReferenceKey {
            kind: ResourceKind::PolicyDefinitions,
            id: "policy-base".into(),
        }));
        assert!(references.contains(&PipeReferenceKey {
            kind: ResourceKind::PolicyDefinitions,
            id: "policy-variant".into(),
        }));
        assert_eq!(
            references
                .iter()
                .filter(|reference| { reference.kind == ResourceKind::Integrations && reference.id == "integration-1" })
                .count(),
            1
        );
    }

    fn upstream_header(secret_id: &str) -> crate::pipes::upstream_headers::UpstreamHeader {
        crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".into(),
            secret_id: secret_id.into(),
        }
    }

    fn has_secret(
        references: &[PipeReferenceKey],
        id: &str,
    ) -> bool {
        references.contains(&PipeReferenceKey {
            kind: ResourceKind::Secrets,
            id: id.into(),
        })
    }

    #[test]
    fn collector_includes_upstream_header_secrets_on_the_base_and_each_variant() {
        let mut pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai("secret-model"));
        pipe.upstream_headers = vec![upstream_header("secret-base-header")];
        pipe.variants = vec![
            PipeVariant {
                id: "variant-1".into(),
                alias: "own-headers".into(),
                name: "Own headers".into(),
                description: String::new(),
                enabled: false,
                overrides: PipeVariantOverrides {
                    upstream_headers: Some(vec![upstream_header("secret-variant-header")]),
                    ..Default::default()
                },
            },
            PipeVariant {
                id: "variant-2".into(),
                alias: "new-upstream".into(),
                name: "New upstream".into(),
                description: String::new(),
                enabled: false,
                overrides: PipeVariantOverrides {
                    pipe_type: Some(openai("secret-swapped-model")),
                    upstream_headers: Some(vec![upstream_header("secret-swapped-header")]),
                    ..Default::default()
                },
            },
        ];

        let references = collect_pipe_reference_keys(&pipe).unwrap();

        for id in [
            "secret-model",
            "secret-base-header",
            "secret-variant-header",
            "secret-swapped-model",
            "secret-swapped-header",
        ] {
            assert!(has_secret(&references, id), "{id} is not checked against the caller's tenant");
        }
    }

    #[test]
    fn collector_names_no_upstream_header_secret_when_there_are_none() {
        let pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai("secret-model"));

        let references = collect_pipe_reference_keys(&pipe).unwrap();

        let secrets: Vec<&str> = references
            .iter()
            .filter(|reference| reference.kind == ResourceKind::Secrets)
            .map(|reference| reference.id.as_str())
            .collect();
        assert_eq!(secrets, vec!["secret-model"]);
    }

    fn target_json(header_secret: Option<&str>) -> serde_json::Value {
        let mut llm = serde_json::json!({
            "provider_type": "openai",
            "model": "own-model",
            "endpoint_url": "https://tunnel.example/v1/chat/completions",
        });
        if let Some(secret_id) = header_secret {
            llm["headers"] = serde_json::json!([{ "name": "x-asp-api-key", "secret_id": secret_id }]);
        }
        llm
    }

    /// The target kinds a surface can name, each carrying `header_secret` in
    /// its own headers and nothing else. Variants can override only the Judge
    /// and the Jury, so those two are also placed on a variant.
    const TARGET_KINDS: &[&str] = &[
        "judge",
        "juror",
        "decider router",
        "decider candidate",
        "mirror merger",
        "failover target",
        "load balancing target",
        "routing rule target",
        "variant judge",
        "variant juror",
    ];

    fn pipe_with_target_header(
        kind: &str,
        header_secret: &str,
    ) -> PipeConfig {
        use serde_json::{from_value, json};
        let llm = target_json(Some(header_secret));
        let plain = target_json(None);
        let mut pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai("secret-model"));
        pipe.tenant_id = Some("tenant-a".into());
        let judge = || from_value(json!({ "enabled": true, "llm": llm })).unwrap();
        let jury = || {
            from_value(json!({ "enabled": true, "jurors": [{ "name": "j", "llm": llm, "system_prompt": "Check." }] }))
                .unwrap()
        };
        match kind {
            "judge" => pipe.judge = Some(judge()),
            "juror" => pipe.jury = Some(jury()),
            "decider router" => {
                pipe.decider = Some(
                    from_value(json!({ "enabled": true, "llm": llm, "candidates": [{ "id": "c", "name": "c", "llm": plain }] }))
                        .unwrap(),
                )
            }
            "decider candidate" => {
                pipe.decider = Some(
                    from_value(json!({ "enabled": true, "llm": plain, "candidates": [{ "id": "c", "name": "c", "llm": llm }] }))
                        .unwrap(),
                )
            }
            "mirror merger" => {
                pipe.decider = Some(
                    from_value(json!({
                        "enabled": true,
                        "strategy": "mirror",
                        "mirror": { "mode": "merge", "merger": llm },
                        "candidates": [{ "id": "c", "name": "c", "llm": plain }]
                    }))
                    .unwrap(),
                )
            }
            "failover target" => {
                pipe.failover = Some(from_value(json!({ "enabled": true, "targets": [{ "llm": llm }] })).unwrap())
            }
            "load balancing target" => {
                pipe.load_balancing = Some(from_value(json!({ "enabled": true, "targets": [{ "llm": llm }] })).unwrap())
            }
            "routing rule target" => {
                pipe.routing_rules = vec![
                    from_value(json!({ "match": { "kind": "header", "name": "x-route", "equals": "own" }, "target": { "llm": llm } }))
                        .unwrap(),
                ]
            }
            "variant judge" | "variant juror" => {
                let mut overrides = PipeVariantOverrides::default();
                if kind == "variant judge" {
                    overrides.judge = Some(judge());
                } else {
                    overrides.jury = Some(jury());
                }
                pipe.variants = vec![PipeVariant {
                    id: "variant-1".into(),
                    alias: "strict".into(),
                    name: "Strict".into(),
                    description: String::new(),
                    enabled: false,
                    overrides,
                }];
            }
            other => panic!("unknown target kind {other}"),
        }
        pipe
    }

    fn tenant_store() -> crate::secrets::store::memory::MemorySecretsStore {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        MemorySecretsStore::with(vec![
            secret("uuid-model", "secret-model", "model-key", Some("tenant-a")),
            secret("uuid-own", "own-tunnel-key", "own-value", Some("tenant-a")),
            secret("uuid-foreign", "foreign-tunnel-key", "foreign-value", Some("tenant-b")),
        ])
    }

    /// The secret half of `validate_pipe_references`: every secret the
    /// surface names, checked for the surface's owner.
    async fn check_secrets(
        pipe: &PipeConfig,
        store: &dyn crate::secrets::SecretsStore,
    ) -> Result<(), AppError> {
        for reference in collect_pipe_reference_keys(pipe)? {
            if reference.kind == ResourceKind::Secrets {
                authorize_secret_reference(store, pipe.tenant_id.as_deref(), None, None, &reference.id).await?;
            }
        }
        Ok(())
    }

    #[test]
    fn collector_includes_every_target_kinds_header_secrets() {
        for kind in TARGET_KINDS {
            let pipe = pipe_with_target_header(kind, "secret-target-header");

            let references = collect_pipe_reference_keys(&pipe).unwrap();

            assert!(
                has_secret(&references, "secret-target-header"),
                "the {kind}'s header secret is not checked against the caller's tenant"
            );
        }
    }

    #[tokio::test]
    async fn a_foreign_secret_in_any_target_header_is_refused_and_an_own_one_accepted() {
        let store = tenant_store();
        for kind in TARGET_KINDS {
            // Precondition: the same surface naming its own secret passes, so
            // the refusal below is the foreign secret's and nothing else's.
            check_secrets(&pipe_with_target_header(kind, "own-tunnel-key"), &store)
                .await
                .unwrap_or_else(|e| panic!("the {kind} naming the tenant's own secret was refused: {e:?}"));

            let refused = check_secrets(&pipe_with_target_header(kind, "foreign-tunnel-key"), &store).await;
            assert!(
                matches!(&refused, Err(AppError::InvalidInput(message)) if message == "Secret reference is not accessible"),
                "the {kind} naming another tenant's secret must be refused, got {refused:?}"
            );
        }
    }

    #[tokio::test]
    async fn the_check_resolves_a_reference_as_a_request_would() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        // Tenant A names its own secret with tenant B's internal id. A request
        // resolves that reference to tenant B's secret (internal id first), so
        // the check must too, and refuse it.
        let store = MemorySecretsStore::with(vec![
            secret("uuid-model", "secret-model", "model-key", Some("tenant-a")),
            secret("uuid-of-b", "b-tunnel-key", "b-value", Some("tenant-b")),
            secret("uuid-of-a", "uuid-of-b", "a-value", Some("tenant-a")),
        ]);
        let mut pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai("secret-model"));
        pipe.tenant_id = Some("tenant-a".into());
        pipe.upstream_headers = vec![upstream_header("uuid-of-b")];

        let refused = check_secrets(&pipe, &store).await;

        assert!(refused.is_err(), "a reference a request would resolve to tenant B's secret was approved");
        let used = crate::secrets::resolve_reference(&store, "uuid-of-b")
            .await
            .unwrap()
            .expect("resolves");
        assert_eq!(used.tenant_id.as_deref(), Some("tenant-b"), "check and use must name the same secret");
    }

    #[tokio::test]
    async fn the_check_accepts_a_reference_by_internal_id_to_an_allowed_secret() {
        let store = tenant_store();
        let mut pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai("secret-model"));
        pipe.tenant_id = Some("tenant-a".into());
        pipe.upstream_headers = vec![upstream_header("uuid-own")];

        check_secrets(&pipe, &store)
            .await
            .expect("a request would send tenant A's own secret, which tenant A may use");

        pipe.upstream_headers = vec![upstream_header("uuid-foreign")];
        assert!(
            check_secrets(&pipe, &store)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_scoped_token_must_admit_the_resolved_secrets_public_id_too() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        // The token may use `acct-*` secrets. `acct-alias` is the internal id
        // of a same-tenant secret whose public id is outside that namespace,
        // so naming it by internal id must not reach it.
        let store = MemorySecretsStore::with(vec![
            secret("acct-alias", "other-key", "other-value", Some("tenant-a")),
            secret("uuid-in-scope", "acct-key", "in-scope-value", Some("tenant-a")),
        ]);
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:secrets:acct-[^:]*\z").unwrap(),
        ));
        let check = |reference: &'static str| {
            authorize_secret_reference(&store, Some("tenant-a"), Some(&context), Some(&scope), reference)
        };

        check("acct-key")
            .await
            .expect("precondition: an in-namespace secret named by public id is allowed");
        assert!(
            check("acct-alias")
                .await
                .is_err(),
            "an in-namespace reference that resolves to an out-of-namespace secret was allowed"
        );
        assert!(
            check("uuid-in-scope")
                .await
                .is_err(),
            "a reference outside the namespace was allowed"
        );
    }

    fn free() -> serde_json::Value {
        serde_json::json!({ "input_per_million": 0.0, "output_per_million": 0.0 })
    }

    /// An OpenAI target at an IP literal (the configuration check's SSRF guard
    /// stays off the network) sending `key` and, if given, `header` as its
    /// tunnel header, at a zero declared price.
    fn priced_target(
        key: Option<&str>,
        header: Option<&str>,
    ) -> serde_json::Value {
        let mut llm = serde_json::json!({
            "provider_type": "openai",
            "model": "gpt-4o",
            "endpoint_url": "https://198.51.100.10/v1/chat/completions",
            "pricing": free(),
        });
        if let Some(key) = key {
            llm["api_key_secret"] = serde_json::json!(key);
        }
        if let Some(header) = header {
            llm["headers"] = serde_json::json!([{ "name": "x-asp-api-key", "secret_id": header }]);
        }
        llm
    }

    /// A tenant-A surface whose own upstream sends `key` (at an IP literal).
    fn tenant_surface(key: &str) -> PipeConfig {
        let mut pipe = PipeConfig::new("pipe-1".into(), "Pipe".into(), openai(key));
        if let PipeType::LLM { provider, .. } = &mut pipe.pipe_type
            && let LLMProvider::OpenAI { base_url, .. } = provider.as_mut()
        {
            *base_url = Some("https://198.51.100.10/v1/chat/completions".into());
        }
        pipe.tenant_id = Some("tenant-a".into());
        pipe
    }

    fn pricing_store() -> crate::secrets::store::memory::MemorySecretsStore {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        MemorySecretsStore::with(vec![
            secret("uuid-op", "openai_api_key", "operator-key", None),
            secret("uuid-model", "acct-model-key", "model-key", Some("tenant-a")),
            secret("uuid-tunnel", "acct-tunnel-key", "tunnel-key", Some("tenant-a")),
            secret("uuid-foreign", "foreign-key", "foreign-value", Some("tenant-b")),
        ])
    }

    /// The price half of `validate_pipe_references`.
    async fn check_prices(
        pipe: &PipeConfig,
        store: crate::secrets::store::memory::MemorySecretsStore,
    ) -> Result<(), AppError> {
        let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(store);
        super::super::pipe_pricing::validate_declared_price_secrets(Some(&store), pipe, &resolved_views(pipe)?).await
    }

    fn is_price_refusal(result: &Result<(), AppError>) -> bool {
        matches!(result, Err(AppError::InvalidInput(message)) if message.contains("declares a price"))
    }

    #[tokio::test]
    async fn a_tenant_token_cannot_price_the_operators_provider_key() {
        // A tenant-scoped token whose scope admits the operator's provider key
        // (it must, to reference it) saves a surface whose base, failover
        // backup and Judge all call OpenAI on that key at a zero price.
        let store = pricing_store();
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let scope = PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:secrets:(?:acct-[^:]*|openai_api_key)\z").unwrap(),
        ));
        let operator_target = priced_target(Some("openai_api_key"), None);
        let mut pipe = tenant_surface("openai_api_key");
        pipe.upstream_pricing = Some(serde_json::from_value(free()).unwrap());
        pipe.judge =
            Some(serde_json::from_value(serde_json::json!({ "enabled": true, "llm": operator_target })).unwrap());
        pipe.failover = Some(
            serde_json::from_value(serde_json::json!({ "enabled": true, "targets": [{ "llm": operator_target }] }))
                .unwrap(),
        );

        crate::pipes::handlers::LLMHandler::validate_config(&pipe).expect("precondition: the configuration is valid");
        let references = collect_pipe_reference_keys(&pipe).unwrap();
        assert!(has_secret(&references, "openai_api_key"), "precondition: the operator's key is checked");
        for reference in references
            .iter()
            .filter(|reference| reference.kind == ResourceKind::Secrets)
        {
            authorize_secret_reference(&store, pipe.tenant_id.as_deref(), Some(&context), Some(&scope), &reference.id)
                .await
                .expect("precondition: the tenant may reference the operator's key");
        }

        assert!(
            is_price_refusal(&check_prices(&pipe, store).await),
            "the zero price on the operator's key was accepted"
        );
    }

    #[tokio::test]
    async fn each_upstream_that_spends_an_operator_secret_may_not_declare_its_price() {
        type Configure = fn(&mut PipeConfig);
        let cases: [(&str, Configure); 5] = [
            ("the surface's own upstream", |pipe| {
                *pipe = tenant_surface("openai_api_key");
                pipe.upstream_pricing = Some(serde_json::from_value(free()).unwrap());
            }),
            ("a failover target", |pipe| {
                pipe.failover = Some(
                    serde_json::from_value(serde_json::json!({
                        "enabled": true,
                        "targets": [{ "llm": priced_target(Some("openai_api_key"), None) }]
                    }))
                    .unwrap(),
                )
            }),
            ("a juror", |pipe| {
                pipe.jury = Some(
                    serde_json::from_value(serde_json::json!({
                        "enabled": true,
                        "jurors": [{ "name": "j", "llm": priced_target(Some("openai_api_key"), None), "system_prompt": "Check." }]
                    }))
                    .unwrap(),
                )
            }),
            ("a target whose header is the operator's", |pipe| {
                pipe.judge = Some(
                    serde_json::from_value(serde_json::json!({
                        "enabled": true,
                        "llm": priced_target(Some("acct-model-key"), Some("openai_api_key"))
                    }))
                    .unwrap(),
                )
            }),
            ("a variant that swaps in the operator's key", |pipe| {
                pipe.variants = vec![PipeVariant {
                    id: "variant-1".into(),
                    alias: "catalog".into(),
                    name: "Catalog".into(),
                    description: String::new(),
                    enabled: false,
                    overrides: PipeVariantOverrides {
                        pipe_type: Some(openai("openai_api_key")),
                        upstream_pricing: Some(serde_json::from_value(free()).unwrap()),
                        ..Default::default()
                    },
                }]
            }),
        ];
        for (label, configure) in cases {
            let mut pipe = tenant_surface("acct-model-key");
            configure(&mut pipe);
            assert!(is_price_refusal(&check_prices(&pipe, pricing_store()).await), "{label} declared its price");
        }

        let mut foreign = tenant_surface("acct-model-key");
        foreign.judge = Some(
            serde_json::from_value(
                serde_json::json!({ "enabled": true, "llm": priced_target(Some("foreign-key"), None) }),
            )
            .unwrap(),
        );
        assert!(
            is_price_refusal(&check_prices(&foreign, pricing_store()).await),
            "another tenant's key declared its price"
        );
    }

    #[tokio::test]
    async fn an_upstream_on_the_tenants_own_secrets_or_none_may_declare_its_price() {
        // A tenant's own model: its model key and tunnel key are both the
        // tenant's, on the base and on every kind of target.
        let own = priced_target(Some("acct-model-key"), Some("acct-tunnel-key"));
        let mut pipe = tenant_surface("acct-model-key");
        pipe.upstream_headers = vec![upstream_header("uuid-tunnel")];
        pipe.upstream_pricing = Some(serde_json::from_value(free()).unwrap());
        pipe.judge = Some(serde_json::from_value(serde_json::json!({ "enabled": true, "llm": own })).unwrap());
        pipe.failover =
            Some(serde_json::from_value(serde_json::json!({ "enabled": true, "targets": [{ "llm": own }] })).unwrap());
        check_prices(&pipe, pricing_store())
            .await
            .expect("a tenant prices its own model");

        let mut keyless = tenant_surface("acct-model-key");
        keyless.judge = Some(
            serde_json::from_value(serde_json::json!({ "enabled": true, "llm": priced_target(None, None) })).unwrap(),
        );
        check_prices(&keyless, pricing_store())
            .await
            .expect("an upstream that spends no secret may carry a price");
    }

    #[tokio::test]
    async fn the_price_rule_leaves_unpriced_operator_upstreams_and_appliance_surfaces_alone() {
        // The catalog prices an operator upstream that declares nothing; the
        // cost override is floored at the catalog at request time instead.
        let mut catalog = tenant_surface("openai_api_key");
        catalog.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
            enabled: true,
            input_price_per_1k: Some(0.0001),
            output_price_per_1k: Some(0.0001),
            monthly_budget_usd: None,
            alert_threshold_percent: None,
        });
        check_prices(&catalog, pricing_store())
            .await
            .expect("an operator upstream priced by the catalog is the operator's as before");

        // An appliance-wide surface is the operator's to price (held by the
        // pricing permission instead).
        let mut appliance = tenant_surface("openai_api_key");
        appliance.tenant_id = None;
        appliance.upstream_pricing = Some(serde_json::from_value(free()).unwrap());
        check_prices(&appliance, pricing_store())
            .await
            .expect("the price rule is the tenant's");
    }

    #[tokio::test]
    async fn source_auth_uses_the_secret_the_tenancy_check_approved() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        // `uuid-of-a` is tenant A's internal id and also the public id of
        // tenant B's secret. The check approves A's secret; source auth must
        // validate callers against that same secret, never B's.
        let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-of-a", "a-inbound-keys", "A-VALUE", Some("tenant-a")),
            secret("uuid-of-b", "uuid-of-a", "B-VALUE", Some("tenant-b")),
        ]));
        let cache: crate::secrets::SecretsCache = Default::default();

        authorize_secret_reference(store.as_ref(), Some("tenant-a"), None, None, "uuid-of-a")
            .await
            .expect("precondition: the check approves tenant A's own secret");
        let used = crate::secrets::get_cached_secret("uuid-of-a", Some("tenant-a"), &Some(store.clone()), &cache)
            .await
            .expect("resolves");

        assert_eq!(used, vec!["A-VALUE".to_string()], "source auth validated callers against another tenant's secret");
    }

    #[tokio::test]
    async fn source_auth_refuses_a_secret_the_surfaces_tenant_may_not_use_cached_or_not() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        let store: Arc<dyn crate::secrets::SecretsStore> = Arc::new(MemorySecretsStore::with(vec![secret(
            "uuid-of-a",
            "a-inbound-keys",
            "A-VALUE",
            Some("tenant-a"),
        )]));
        let cache: crate::secrets::SecretsCache = Default::default();

        assert!(
            crate::secrets::get_cached_secret("a-inbound-keys", Some("tenant-b"), &Some(store.clone()), &cache)
                .await
                .is_err(),
            "tenant B's surface authenticated callers with tenant A's secret"
        );
        crate::secrets::get_cached_secret("a-inbound-keys", Some("tenant-a"), &Some(store.clone()), &cache)
            .await
            .expect("tenant A's surface uses its own secret");
        assert!(
            crate::secrets::get_cached_secret("a-inbound-keys", Some("tenant-b"), &Some(store.clone()), &cache)
                .await
                .is_err(),
            "a cached value skipped the tenancy re-check"
        );
    }

    #[test]
    fn collector_ignores_inline_oauth_authority_identifiers() {
        let mut pipe = api_pipe();
        pipe.sandbox_auth = Some(serde_json::json!({
            "provider": "entra",
            "tenant_id": "authority-tenant",
            "client_id": "public-client"
        }));

        let references = collect_pipe_reference_keys(&pipe).unwrap();

        assert!(
            !references
                .iter()
                .any(|reference| reference.kind == ResourceKind::OauthIdentifiers)
        );
    }

    mod api_key_parent {
        use super::super::api_key_parent_tenants;
        use crate::api_keys::parent::tests::{fabric_record, llm_surface, parents_with};
        use crate::identity::handlers::pipes::AppError;

        fn refused(result: &Result<Vec<Option<String>>, AppError>) -> bool {
            matches!(result, Err(AppError::InvalidInput(message)) if message == "API-key parent Surface reference is not accessible")
        }

        #[tokio::test]
        async fn a_new_surface_may_hold_its_own_keys() {
            let dir = tempfile::tempdir().unwrap();
            let parents = parents_with(&dir, Vec::new(), Vec::new()).await;

            let tenants = api_key_parent_tenants(&parents, "chat", Some("tenant-a"), "chat")
                .await
                .unwrap();

            assert_eq!(tenants, vec![Some("tenant-a".to_string())]);
        }

        #[tokio::test]
        async fn another_llm_surface_or_fabric_record_may_hold_the_keys() {
            let dir = tempfile::tempdir().unwrap();
            let parents = parents_with(
                &dir,
                vec![fabric_record("agent", Some("tenant-b"))],
                vec![llm_surface("holder", Some("tenant-a"))],
            )
            .await;

            assert_eq!(
                api_key_parent_tenants(&parents, "chat", Some("tenant-a"), "holder")
                    .await
                    .unwrap(),
                vec![Some("tenant-a".to_string())]
            );
            assert_eq!(
                api_key_parent_tenants(&parents, "chat", Some("tenant-a"), "agent")
                    .await
                    .unwrap(),
                vec![Some("tenant-b".to_string())]
            );
        }

        #[tokio::test]
        async fn a_parent_that_does_not_exist_is_refused() {
            let dir = tempfile::tempdir().unwrap();
            let parents = parents_with(&dir, Vec::new(), vec![llm_surface("holder", None)]).await;

            assert!(refused(&api_key_parent_tenants(&parents, "chat", None, "testkit-agent").await));
        }

        #[tokio::test]
        async fn naming_itself_still_reports_a_fabric_record_with_the_same_id() {
            let dir = tempfile::tempdir().unwrap();
            let parents = parents_with(&dir, vec![fabric_record("chat", Some("tenant-b"))], Vec::new()).await;

            let tenants = api_key_parent_tenants(&parents, "chat", Some("tenant-a"), "chat")
                .await
                .unwrap();

            assert_eq!(tenants, vec![Some("tenant-b".to_string()), Some("tenant-a".to_string())]);
        }
    }
}
