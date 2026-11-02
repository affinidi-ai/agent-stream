//! Who may decide where a surface sends a stored secret.
//!
//! A surface sends each secret it names (a provider key, an upstream or
//! target header, a guardrail, detector, embedder or search-engine key) to
//! one destination. Whoever chooses that pairing chooses who receives the
//! secret's value, so a save that adds a (secret, destination) pair the stored
//! surface does not already have needs `secrets.view`, the permission that
//! already reveals secret values. With `secrets.reveal_values` false it does
//! not reveal them, yet a holder can still obtain a value by pairing it with
//! their own host: an accepted risk, recorded in
//! `docs/PROVIDERS_AND_CREDENTIALS.md`. A save that keeps or drops pairs needs
//! nothing, so an editor can still change everything else about a surface.
//! A tenant's token is exempt for a secret its own tenant owns.
//!
//! With the pairing held at save time, the connection and detector tests,
//! which only send a saved key to its saved destination, need no more than
//! the permission to run or edit the surface.

use std::collections::BTreeSet;

use super::pipe_caller::PipeCaller;
use crate::identity::handlers::pipes::AppError;
use crate::pipes::judge_jury::LLMTarget;
use crate::pipes::types::llm::LLMProvider;
use crate::pipes::types::llm_provider_ext::LLMProviderExt;
use crate::pipes::{PipeConfig, PipeType};
use crate::rbac::Feature;
use crate::tenancy::PatTenantContext;

/// A secret a surface sends and the destination it is sent to.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct SecretBinding {
    pub(super) secret: String,
    destination: String,
}

/// Every secret `view` (one resolved surface or variant) sends outbound,
/// paired with where it goes. Source-authentication secrets only check
/// inbound callers and are not included.
pub(super) fn secret_bindings(view: &PipeConfig) -> Vec<SecretBinding> {
    let mut bindings = Vec::new();
    if let PipeType::LLM { provider, .. } = &view.pipe_type {
        let endpoint = provider.get_endpoint();
        // These providers build the model, deployment or API version into the
        // URL, which an editor may change without changing who receives the
        // key: only the origin decides that. Elsewhere the editor chooses the
        // path, and a shared gateway host can route by path, so it counts.
        let model_in_url = matches!(
            **provider,
            LLMProvider::Gemini { .. }
                | LLMProvider::Replicate { .. }
                | LLMProvider::HuggingFace { .. }
                | LLMProvider::AzureOpenAI { .. }
        ) || (matches!(**provider, LLMProvider::Bedrock { .. }) && !provider.supports_path_suffix());
        let receiver = if model_in_url {
            origin(&endpoint)
        } else {
            endpoint
        };
        let destination = format!("{} {}", provider.provider_type_str(), receiver);
        if let Some(secret) = provider.get_api_key() {
            push(&mut bindings, secret, &destination);
        }
        for header in &view.upstream_headers {
            push(&mut bindings, &header.secret_id, &destination);
        }
    }
    for target in llm_targets(view) {
        // The configured template, so changing the model does not count as a
        // new destination, plus the resolved origin in case `{model}` sits in
        // the host.
        let destination = format!(
            "{} {} {}",
            target.provider_type,
            origin(&target.resolved_endpoint()),
            crate::pipes::defaults::resolve_endpoint_url(&target.provider_type, &target.endpoint_url)
        );
        if let Some(secret) = &target.api_key_secret {
            push(&mut bindings, secret, &destination);
        }
        for header in &target.headers {
            push(&mut bindings, &header.secret_id, &destination);
        }
    }
    if let Some(prompt_guard) = &view.prompt_guard {
        if let Some(external) = &prompt_guard.external
            && let Some(secret) = &external.api_key_secret
        {
            push(&mut bindings, secret, &external.endpoint_url);
        }
        for detector in &prompt_guard.llm_pii {
            if let Some(secret) = &detector.api_key_secret {
                let destination = format!("{} {}", detector.provider_type, detector.resolved_endpoint_url());
                push(&mut bindings, secret, &destination);
            }
        }
    }
    for witness in &view.expert_witnesses {
        if let Some(secret) = &witness
            .guardrail
            .api_key_secret
        {
            push(&mut bindings, secret, &witness.guardrail.endpoint_url);
        }
    }
    let embedders = [
        view.cache
            .as_ref()
            .and_then(|cache| cache.embedder.as_ref()),
        view.drift
            .as_ref()
            .and_then(|drift| drift.eval.as_ref())
            .and_then(|eval| eval.embeddings.as_ref()),
    ];
    for embedder in embedders
        .into_iter()
        .flatten()
    {
        if let Some(secret) = &embedder.api_key_secret {
            push(&mut bindings, secret, &embedder.endpoint_url);
        }
    }
    if let Some(search) = view
        .server_tools
        .as_ref()
        .and_then(|tools| tools.web_search.as_ref())
        && let Some(secret) = &search.engine_secret
    {
        push(&mut bindings, secret, &format!("web_search {}", search.engine));
    }
    bindings
}

/// The scheme, host and port `url` reaches. A URL without a host-based origin
/// (unparsable, or a non-HTTP scheme, whose origin is opaque and would make
/// every such URL compare equal) is kept whole.
fn origin(url: &str) -> String {
    match url::Url::parse(url.trim()) {
        Ok(parsed) if parsed.origin().is_tuple() => parsed
            .origin()
            .ascii_serialization(),
        _ => url.to_string(),
    }
}

/// Every LLM target `view` calls: the Judge, each juror, the Decider router,
/// candidates and Mirror merger, and every failover, load-balancing and
/// routing-rule target.
fn llm_targets(view: &PipeConfig) -> Vec<&LLMTarget> {
    let mut targets = Vec::new();
    if let Some(judge) = &view.judge {
        targets.push(&judge.llm);
    }
    if let Some(jury) = &view.jury {
        targets.extend(
            jury.jurors
                .iter()
                .map(|juror| &juror.llm),
        );
    }
    if let Some(decider) = &view.decider {
        targets.extend(decider.llm.as_ref());
        targets.extend(
            decider
                .candidates
                .iter()
                .map(|candidate| &candidate.llm),
        );
        targets.extend(decider.mirror.merger.as_ref());
    }
    if let Some(failover) = &view.failover {
        targets.extend(
            failover
                .targets
                .iter()
                .map(|target| &target.llm),
        );
    }
    if let Some(load_balancing) = &view.load_balancing {
        targets.extend(
            load_balancing
                .targets
                .iter()
                .map(|target| &target.llm),
        );
    }
    targets.extend(
        view.routing_rules
            .iter()
            .filter_map(|rule| rule.target.llm.as_ref()),
    );
    targets
}

fn push(
    bindings: &mut Vec<SecretBinding>,
    secret: &str,
    destination: &str,
) {
    let secret = secret.trim();
    if !secret.is_empty() {
        bindings.push(SecretBinding {
            secret: secret.to_string(),
            destination: destination.trim().to_string(),
        });
    }
}

/// The bindings of the surface's base and every variant (disabled ones too).
fn all_bindings(pipe: &PipeConfig) -> Result<BTreeSet<SecretBinding>, AppError> {
    Ok(super::pipe_tenancy::resolved_views(pipe)?
        .iter()
        .flat_map(secret_bindings)
        .collect())
}

/// The bindings a stored surface already has. A stored variant that no longer
/// resolves falls back to the base's, so it neither drops the base from the
/// startup list nor turns every pair into a new one, which would hide the
/// variant's own error behind a `secrets.view` refusal on the save that fixes it.
fn stored_pairs(pipe: &PipeConfig) -> BTreeSet<SecretBinding> {
    all_bindings(pipe).unwrap_or_else(|_| {
        secret_bindings(pipe)
            .into_iter()
            .collect()
    })
}

/// One stored (secret, destination) pair, as logged at startup: the secret's
/// reference, never its value, and the destination without any URL
/// credentials, query or fragment, where a provider may carry a key.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StoredBinding {
    pub(crate) pipe_id: String,
    pub(crate) tenant_id: Option<String>,
    pub(crate) secret_reference: String,
    pub(crate) destination: String,
}

/// Every pair the stored surfaces send, base and variants. Pairings saved
/// before `secrets.view` was required stay approved, so operators get this
/// list to review before they rotate keys.
pub(crate) fn stored_bindings(pipes: &[PipeConfig]) -> Vec<StoredBinding> {
    pipes
        .iter()
        .flat_map(|pipe| {
            stored_pairs(pipe)
                .into_iter()
                .map(|binding| StoredBinding {
                    pipe_id: pipe.id.clone(),
                    tenant_id: pipe.tenant_id.clone(),
                    secret_reference: binding.secret,
                    destination: redact_destination(&binding.destination),
                })
        })
        .collect()
}

/// Log [`stored_bindings`] once, one `security_audit` line per pair.
pub(crate) fn log_stored_bindings(pipes: &[PipeConfig]) {
    for binding in stored_bindings(pipes) {
        tracing::info!(
            target: "security_audit",
            event = "stored_secret_binding",
            pipe_id = %binding.pipe_id,
            tenant_id = binding.tenant_id.as_deref().unwrap_or("-"),
            secret_reference = %binding.secret_reference,
            destination = %binding.destination,
            "Stored secret binding"
        );
    }
}

fn redact_destination(destination: &str) -> String {
    destination
        .split(' ')
        .map(|part| {
            if part.contains("://") {
                crate::url_validation::redact_url_for_logging(part)
            } else {
                part.split(['?', '#'])
                    .next()
                    .unwrap_or_default()
                    .to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Require `secrets.view` when a save pairs a secret with a destination the
/// stored surface (`previous`, `None` on create) does not already send it to.
/// A tenant's token may pair a secret its own tenant owns without it.
pub(super) async fn authorize_secret_binding_change(
    previous: Option<&PipeConfig>,
    pipe: &PipeConfig,
    secrets: Option<&dyn crate::secrets::SecretsStore>,
    context: Option<&PatTenantContext>,
    caller: &PipeCaller,
) -> Result<(), AppError> {
    let stored = match previous {
        Some(previous) => stored_pairs(previous),
        None => BTreeSet::new(),
    };
    let added: Vec<SecretBinding> = all_bindings(pipe)?
        .difference(&stored)
        .cloned()
        .collect();
    if added.is_empty() {
        return Ok(());
    }
    if caller
        .holds(&Feature::SecretsView)
        .await?
    {
        return Ok(());
    }
    if let (Some(context), Some(secrets)) = (context, secrets)
        && all_owned_by(&added, &context.tenant_id, secrets).await
    {
        return Ok(());
    }
    Err(AppError::Forbidden(
        "Choosing where a surface sends a stored secret (adding a secret reference, or changing the endpoint a \
         referenced secret is sent to) needs the secrets.view permission"
            .to_string(),
    ))
}

/// Whether every binding's secret resolves, as a request would, to a secret
/// owned by `tenant_id`.
async fn all_owned_by(
    bindings: &[SecretBinding],
    tenant_id: &str,
    secrets: &dyn crate::secrets::SecretsStore,
) -> bool {
    for binding in bindings {
        let owned = matches!(
            crate::secrets::resolve_reference(secrets, &binding.secret).await,
            Ok(Some(secret)) if secret.tenant_id.as_deref() == Some(tenant_id)
        );
        if !owned {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::UserRole;
    use crate::pipes::pipe_variants::{PipeVariant, PipeVariantOverrides};
    use crate::pipes::types::llm::LLMProvider;
    use crate::secrets::store::memory::{MemorySecretsStore, secret};

    async fn caller(
        role: UserRole,
        scopes: Option<Vec<&str>>,
    ) -> (PipeCaller, tempfile::TempDir) {
        PipeCaller::for_test("user-1", role, scopes).await
    }

    fn surface(
        key: &str,
        base_url: Option<&str>,
    ) -> PipeConfig {
        PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::LLM {
                provider: Box::new(LLMProvider::OpenAI {
                    provider_type: "openai".into(),
                    model: "gpt-4o".into(),
                    api_key_secret: Some(key.into()),
                    organization_id: None,
                    base_url: base_url.map(str::to_string),
                    temperature: None,
                    max_tokens: None,
                    top_p: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                }),
                endpoint_path: None,
            },
        )
    }

    fn with_detector(
        mut pipe: PipeConfig,
        key: &str,
        endpoint_url: &str,
    ) -> PipeConfig {
        pipe.prompt_guard = Some(
            serde_json::from_value(serde_json::json!({
                "llm_pii": [{ "provider_type": "", "endpoint_url": endpoint_url, "model": "detector", "api_key_secret": key }]
            }))
            .unwrap(),
        );
        pipe
    }

    fn store() -> MemorySecretsStore {
        MemorySecretsStore::with(vec![
            secret("uuid-op", "operator-key", "OPERATOR", None),
            secret("uuid-a", "acct-key", "A-VALUE", Some("tenant-a")),
        ])
    }

    fn tenant(id: &str) -> PatTenantContext {
        PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: id.into(),
        }
    }

    fn refused(result: &Result<(), AppError>) -> bool {
        matches!(result, Err(AppError::Forbidden(message)) if message.contains("secrets.view"))
    }

    async fn check(
        previous: Option<&PipeConfig>,
        pipe: &PipeConfig,
        context: Option<&PatTenantContext>,
        caller: &PipeCaller,
    ) -> Result<(), AppError> {
        authorize_secret_binding_change(previous, pipe, Some(&store()), context, caller).await
    }

    #[test]
    fn bindings_pair_each_secret_with_its_destination() {
        let mut pipe = with_detector(
            surface("operator-key", Some("https://llm.example/v1")),
            "detector-key",
            "https://detector.example/v1/chat/completions",
        );
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-tunnel".into(),
            secret_id: "tunnel-key".into(),
        }];
        pipe.judge = Some(
            serde_json::from_value(serde_json::json!({ "enabled": true, "llm": {
                "provider_type": "openai", "model": "judge", "endpoint_url": "https://judge.example/v1/chat/completions",
                "api_key_secret": "judge-key"
            } }))
            .unwrap(),
        );

        let bindings = secret_bindings(&pipe);
        let destination_of = |secret: &str| {
            bindings
                .iter()
                .find(|binding| binding.secret == secret)
                .map(|binding| binding.destination.clone())
                .unwrap_or_else(|| panic!("{secret} is not paired with a destination"))
        };
        assert!(destination_of("operator-key").contains("llm.example"));
        assert_eq!(destination_of("tunnel-key"), destination_of("operator-key"));
        assert!(destination_of("judge-key").contains("judge.example"));
        assert!(destination_of("detector-key").contains("detector.example"));
    }

    #[test]
    fn bindings_leave_out_source_authentication_secrets() {
        let mut pipe = surface("operator-key", None);
        pipe.source_auth = Some(
            serde_json::from_value(serde_json::json!({
                "type": "api_key",
                "extraction": { "source": "http_header", "field": "x-api-key" },
                "secret_id": "inbound-keys"
            }))
            .unwrap(),
        );
        assert!(
            !secret_bindings(&pipe)
                .iter()
                .any(|binding| binding.secret == "inbound-keys")
        );
    }

    const SITE_KEY: &str = "site-key";

    /// One place a surface sends a stored secret: `build` keys only that place
    /// with [`SITE_KEY`] and sends it to the given destination.
    struct SecretSite {
        name: &'static str,
        build: fn(&str) -> PipeConfig,
        here: &'static str,
        elsewhere: &'static str,
    }

    const HERE: &str = "https://here.example/v1/chat/completions";
    const ELSEWHERE: &str = "https://elsewhere.example/v1/chat/completions";

    fn keyless_with(patch: serde_json::Value) -> PipeConfig {
        let provider = serde_json::json!({ "provider_type": "openai", "model": "gpt-4o" });
        let mut pipe = with_provider(serde_json::from_value(provider).unwrap());
        let mut value = serde_json::to_value(&pipe).unwrap();
        for (field, setting) in patch.as_object().unwrap() {
            value[field] = setting.clone();
        }
        pipe = serde_json::from_value(value).unwrap();
        pipe
    }

    fn keyed_target(endpoint_url: &str) -> serde_json::Value {
        serde_json::json!({ "provider_type": "openai", "model": "m", "endpoint_url": endpoint_url, "api_key_secret": SITE_KEY })
    }

    fn plain_target() -> serde_json::Value {
        serde_json::json!({ "provider_type": "openai", "model": "m", "endpoint_url": HERE })
    }

    const SECRET_SITES: &[SecretSite] = &[
        SecretSite {
            name: "provider key",
            build: |url| surface(SITE_KEY, Some(url)),
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "upstream header",
            build: |url| {
                keyless_with(serde_json::json!({
                    "pipe_type": { "type": "llm", "provider": { "provider_type": "openai", "model": "gpt-4o", "base_url": url } },
                    "upstream_headers": [{ "name": "x-tunnel", "secret_id": SITE_KEY }]
                }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "custom provider auth secret",
            build: |url| {
                keyless_with(serde_json::json!({ "pipe_type": { "type": "llm", "provider": {
                    "provider_type": "custom", "name": "m", "endpoint": url, "auth_header": "x-key", "auth_secret": SITE_KEY
                } } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "external prompt guard",
            build: |url| {
                keyless_with(
                    serde_json::json!({ "prompt_guard": { "external": { "endpoint_url": url, "api_key_secret": SITE_KEY } } }),
                )
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "LLM detector",
            build: |url| {
                keyless_with(serde_json::json!({ "prompt_guard": { "llm_pii": [
                    { "provider_type": "", "endpoint_url": url, "model": "detector", "api_key_secret": SITE_KEY }
                ] } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "expert witness",
            build: |url| {
                keyless_with(serde_json::json!({ "expert_witnesses": [
                    { "id": "w", "name": "w", "endpoint_url": url, "api_key_secret": SITE_KEY }
                ] }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "cache embedder",
            build: |url| {
                keyless_with(serde_json::json!({ "cache": { "enabled": true, "mode": "semantic", "embedder": {
                    "endpoint_url": url, "model": "e", "api_key_secret": SITE_KEY
                } } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "drift embedder",
            build: |url| {
                keyless_with(serde_json::json!({ "drift": { "enabled": true, "eval": { "embeddings": {
                    "endpoint_url": url, "model": "e", "api_key_secret": SITE_KEY
                } } } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "web search engine",
            build: |engine| {
                keyless_with(serde_json::json!({ "server_tools": { "web_search": {
                    "enabled": true, "engine": engine, "engine_secret": SITE_KEY
                } } }))
            },
            here: "brave",
            elsewhere: "tavily",
        },
        SecretSite {
            name: "judge",
            build: |url| keyless_with(serde_json::json!({ "judge": { "enabled": true, "llm": keyed_target(url) } })),
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "juror",
            build: |url| {
                keyless_with(serde_json::json!({ "jury": { "enabled": true, "jurors": [
                    { "name": "j", "llm": keyed_target(url), "system_prompt": "Check." }
                ] } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "decider router",
            build: |url| {
                keyless_with(
                    serde_json::json!({ "decider": { "enabled": true, "llm": keyed_target(url), "candidates": [
                    { "id": "c", "name": "c", "llm": plain_target() }
                ] } }),
                )
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "decider candidate",
            build: |url| {
                keyless_with(serde_json::json!({ "decider": { "enabled": true, "llm": plain_target(), "candidates": [
                    { "id": "c", "name": "c", "llm": keyed_target(url) }
                ] } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "mirror merger",
            build: |url| {
                keyless_with(serde_json::json!({ "decider": {
                    "enabled": true,
                    "strategy": "mirror",
                    "mirror": { "mode": "merge", "merger": keyed_target(url) },
                    "candidates": [{ "id": "c", "name": "c", "llm": plain_target() }]
                } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "failover target",
            build: |url| {
                keyless_with(
                    serde_json::json!({ "failover": { "enabled": true, "targets": [{ "llm": keyed_target(url) }] } }),
                )
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "load balancing target",
            build: |url| {
                keyless_with(
                    serde_json::json!({ "load_balancing": { "enabled": true, "targets": [{ "llm": keyed_target(url) }] } }),
                )
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "routing rule target",
            build: |url| {
                keyless_with(serde_json::json!({ "routing_rules": [{
                    "match": { "kind": "header", "name": "x-route", "equals": "own" },
                    "target": { "llm": keyed_target(url) }
                }] }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
        SecretSite {
            name: "target header",
            build: |url| {
                let mut target = plain_target();
                target["endpoint_url"] = url.into();
                target["headers"] = serde_json::json!([{ "name": "x-asp-api-key", "secret_id": SITE_KEY }]);
                keyless_with(serde_json::json!({ "judge": { "enabled": true, "llm": target } }))
            },
            here: HERE,
            elsewhere: ELSEWHERE,
        },
    ];

    #[tokio::test]
    async fn every_secret_site_is_paired_and_held() {
        let (user, _users) = caller(UserRole::User, None).await;
        for site in SECRET_SITES {
            let stored = (site.build)(site.here);
            let paired = secret_bindings(&stored)
                .iter()
                .filter(|binding| binding.secret == SITE_KEY)
                .count();
            assert_eq!(paired, 1, "the {} secret is not paired exactly once", site.name);

            check(Some(&stored), &(site.build)(site.here), None, &user)
                .await
                .unwrap_or_else(|e| panic!("keeping the {} destination was refused: {e:?}", site.name));
            assert!(
                refused(&check(Some(&stored), &(site.build)(site.elsewhere), None, &user).await),
                "moving the {} destination was not held",
                site.name
            );
        }
    }

    #[tokio::test]
    async fn an_editor_may_keep_or_drop_the_stored_pairs() {
        let (user, _users) = caller(UserRole::User, None).await;
        let stored = with_detector(
            surface("operator-key", Some("https://llm.example/v1")),
            "operator-key",
            "https://detector.example/v1/chat/completions",
        );

        let mut renamed = stored.clone();
        renamed.name = "Renamed".into();
        check(Some(&stored), &renamed, None, &user)
            .await
            .expect("a save that keeps every pair needs nothing");

        let mut dropped = stored.clone();
        dropped.prompt_guard = None;
        check(Some(&stored), &dropped, None, &user)
            .await
            .expect("a save that drops a pair needs nothing");
    }

    #[tokio::test]
    async fn an_editor_may_not_send_a_stored_secret_somewhere_new() {
        let (user, _users) = caller(UserRole::User, None).await;
        let stored = with_detector(
            surface("operator-key", Some("https://llm.example/v1")),
            "operator-key",
            "https://detector.example/v1/chat/completions",
        );

        let moved_detector =
            with_detector(stored.clone(), "operator-key", "https://collector.example/v1/chat/completions");
        assert!(refused(&check(Some(&stored), &moved_detector, None, &user).await), "a detector endpoint moved");

        let moved_provider = with_detector(
            surface("operator-key", Some("https://collector.example/v1")),
            "operator-key",
            "https://detector.example/v1/chat/completions",
        );
        assert!(refused(&check(Some(&stored), &moved_provider, None, &user).await), "a provider endpoint moved");

        let new_key = with_detector(
            surface("acct-key", Some("https://llm.example/v1")),
            "operator-key",
            "https://detector.example/v1/chat/completions",
        );
        assert!(refused(&check(Some(&stored), &new_key, None, &user).await), "a new key was referenced");

        assert!(refused(&check(None, &stored, None, &user).await), "a new keyed surface was created");
    }

    fn with_provider(provider: LLMProvider) -> PipeConfig {
        PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        )
    }

    fn gemini(model: &str) -> PipeConfig {
        with_provider(LLMProvider::Gemini {
            provider_type: "gemini".into(),
            model: model.into(),
            api_key_secret: Some("operator-key".into()),
            project_id: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        })
    }

    fn azure(
        endpoint: &str,
        deployment_name: &str,
        api_version: &str,
    ) -> PipeConfig {
        with_provider(LLMProvider::AzureOpenAI {
            provider_type: "azure_openai".into(),
            deployment_name: deployment_name.into(),
            endpoint: endpoint.into(),
            api_key_secret: Some("operator-key".into()),
            api_version: api_version.into(),
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        })
    }

    fn with_judge(
        mut pipe: PipeConfig,
        model: &str,
        endpoint_url: &str,
    ) -> PipeConfig {
        pipe.judge = Some(
            serde_json::from_value(serde_json::json!({ "enabled": true, "llm": {
                "provider_type": "openai", "model": model, "endpoint_url": endpoint_url,
                "api_key_secret": "operator-key"
            } }))
            .unwrap(),
        );
        pipe
    }

    #[tokio::test]
    async fn an_editor_may_change_a_model_that_sits_in_the_providers_url() {
        let (user, _users) = caller(UserRole::User, None).await;

        check(Some(&gemini("gemini-1.5-pro")), &gemini("gemini-2.0-flash"), None, &user)
            .await
            .expect("a Gemini model change keeps the key on the same host");

        let stored = azure("https://acct.openai.azure.com", "gpt-4o", "2024-02-15-preview");
        let changed = azure("https://acct.openai.azure.com", "gpt-4o-mini", "2024-10-21");
        check(Some(&stored), &changed, None, &user)
            .await
            .expect("an Azure deployment or api_version change keeps the key on the same resource");

        let moved = azure("https://collector.example", "gpt-4o", "2024-02-15-preview");
        assert!(refused(&check(Some(&stored), &moved, None, &user).await), "an Azure resource moved");
    }

    #[tokio::test]
    async fn an_editor_may_not_move_a_path_routed_endpoint_on_the_same_host() {
        let (user, _users) = caller(UserRole::User, None).await;
        let stored = surface("operator-key", Some("https://gateway.example/team-a"));
        let moved = surface("operator-key", Some("https://gateway.example/team-b"));
        assert!(refused(&check(Some(&stored), &moved, None, &user).await));
    }

    #[tokio::test]
    async fn a_target_model_change_counts_only_when_it_moves_the_host() {
        let (user, _users) = caller(UserRole::User, None).await;
        let base = surface("acct-key", None);

        let stored = with_judge(base.clone(), "judge-a", "https://judge.example/v1/chat/completions");
        let renamed = with_judge(base.clone(), "judge-b", "https://judge.example/v1/chat/completions");
        check(Some(&stored), &renamed, None, &user)
            .await
            .expect("a target model change keeps the key on the same endpoint");

        let stored = with_judge(base.clone(), "judge", "https://{model}.example/v1/chat/completions");
        let moved = with_judge(base, "collector", "https://{model}.example/v1/chat/completions");
        assert!(refused(&check(Some(&stored), &moved, None, &user).await), "a `{{model}}` in the host moved the key");
    }

    fn variant(
        id: &str,
        alias: &str,
    ) -> PipeVariant {
        PipeVariant {
            id: id.into(),
            alias: alias.into(),
            name: id.into(),
            description: String::new(),
            enabled: false,
            overrides: PipeVariantOverrides::default(),
        }
    }

    #[tokio::test]
    async fn a_stored_variant_that_no_longer_resolves_does_not_turn_every_pair_new() {
        let (user, _users) = caller(UserRole::User, None).await;
        // Two variants sharing an alias: the second can no longer be resolved.
        let mut stored = surface("operator-key", Some("https://llm.example/v1"));
        stored.variants = vec![variant("variant-1", "dup"), variant("variant-2", "dup")];
        assert!(all_bindings(&stored).is_err(), "precondition: a stored variant no longer resolves");

        let mut fixed = stored.clone();
        fixed.variants[1].alias = "fixed".into();
        check(Some(&stored), &fixed, None, &user)
            .await
            .expect("the save that fixes the variant keeps the stored pairs");
    }

    #[tokio::test]
    async fn a_pair_only_a_variant_adds_is_held_too() {
        let (user, _users) = caller(UserRole::User, None).await;
        let stored = surface("operator-key", Some("https://llm.example/v1"));
        let mut pipe = stored.clone();
        pipe.variants = vec![PipeVariant {
            id: "variant-1".into(),
            alias: "elsewhere".into(),
            name: "Elsewhere".into(),
            description: String::new(),
            enabled: false,
            overrides: PipeVariantOverrides {
                pipe_type: Some(
                    surface("operator-key", Some("https://collector.example/v1"))
                        .pipe_type
                        .clone(),
                ),
                ..Default::default()
            },
        }];
        assert!(refused(&check(Some(&stored), &pipe, None, &user).await));
    }

    #[tokio::test]
    async fn secrets_view_may_send_a_secret_anywhere_by_role_and_by_token_scope() {
        let (admin, _admins) = caller(UserRole::Administrator, None).await;
        let moved = surface("operator-key", Some("https://collector.example/v1"));
        check(None, &moved, None, &admin)
            .await
            .expect("an administrator holds secrets.view");

        let (narrowed, _a) = caller(UserRole::Administrator, Some(vec!["pipes.edit"])).await;
        assert!(refused(&check(None, &moved, None, &narrowed).await), "a token narrowed to pipes.edit");

        let (named, _b) = caller(UserRole::Administrator, Some(vec!["pipes.edit", "secrets.view"])).await;
        check(None, &moved, None, &named)
            .await
            .expect("a token naming secrets.view");
    }

    #[tokio::test]
    async fn a_tenant_token_may_pair_only_its_own_tenants_secrets() {
        let (user, _users) = caller(UserRole::User, None).await;
        let context = tenant("tenant-a");

        check(None, &surface("acct-key", Some("https://own.example/v1")), Some(&context), &user)
            .await
            .expect("the tenant's own secret");
        assert!(
            refused(
                &check(None, &surface("operator-key", Some("https://own.example/v1")), Some(&context), &user).await
            ),
            "an appliance-wide secret"
        );
        assert!(
            refused(
                &check(None, &surface("acct-key", Some("https://own.example/v1")), Some(&tenant("tenant-b")), &user)
                    .await
            ),
            "another tenant's secret"
        );
        assert!(
            refused(&check(None, &surface("no-such-key", Some("https://own.example/v1")), Some(&context), &user).await),
            "a secret that does not resolve"
        );
    }

    #[tokio::test]
    async fn a_surface_without_secrets_needs_nothing() {
        let (user, _users) = caller(UserRole::User, None).await;
        let pipe = PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::Webhook {
                endpoint: "https://api.example".into(),
            },
        );
        check(None, &pipe, None, &user)
            .await
            .expect("no secret is sent");
    }

    #[test]
    fn stored_bindings_list_the_base_and_every_variant() {
        let mut pipe = surface("operator-key", Some("https://llm.example/v1"));
        pipe.tenant_id = Some("tenant-a".into());
        pipe.variants = vec![PipeVariant {
            id: "variant-1".into(),
            alias: "elsewhere".into(),
            name: "Elsewhere".into(),
            description: String::new(),
            enabled: false,
            overrides: PipeVariantOverrides {
                pipe_type: Some(
                    surface("operator-key", Some("https://collector.example/v1"))
                        .pipe_type
                        .clone(),
                ),
                ..Default::default()
            },
        }];

        let stored = stored_bindings(&[pipe]);
        assert_eq!(stored.len(), 2, "{stored:?}");
        assert!(
            stored
                .iter()
                .all(|binding| binding.pipe_id == "pipe-1"
                    && binding.tenant_id.as_deref() == Some("tenant-a")
                    && binding.secret_reference == "operator-key")
        );
        assert!(stored.iter().any(|binding| {
            binding
                .destination
                .contains("llm.example")
        }));
        assert!(stored.iter().any(|binding| {
            binding
                .destination
                .contains("collector.example")
        }));
    }

    #[test]
    fn stored_bindings_leave_out_url_credentials_and_queries() {
        let full_url = with_detector(
            surface("operator-key", Some("https://user:pass@llm.example/v1")),
            "detector-key",
            "https://detector.example/v1/chat/completions?key=QUERY-KEY#frag",
        );
        let mut path_only = with_detector(surface("other-key", None), "path-key", "/v1/chat/completions?key=PATH-KEY");
        path_only.id = "pipe-2".into();

        for binding in stored_bindings(&[full_url, path_only]) {
            for leaked in ["pass", "QUERY-KEY", "PATH-KEY", "frag", "key="] {
                assert!(
                    !binding
                        .destination
                        .contains(leaked),
                    "{leaked} leaked into {binding:?}"
                );
            }
        }
    }

    #[test]
    fn stored_bindings_skip_a_surface_without_secrets() {
        let pipe = PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::Webhook {
                endpoint: "https://api.example".into(),
            },
        );
        assert!(stored_bindings(&[pipe]).is_empty());
    }
}
