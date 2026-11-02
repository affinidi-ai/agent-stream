//! Who may set the prices a surface bills at.
//!
//! A surface can price an upstream itself instead of leaving it to the
//! catalog: a declared price (`PipeConfig.upstream_pricing`,
//! `LLMTarget.pricing`) or the `cost_tracking` price override. Every member,
//! team and surface budget counts the cost those prices produce, so whoever
//! sets them decides what a call spends against those budgets. Two save-time
//! rules keep that with the party who pays the upstream:
//!
//! - On a tenant's surface, a declared price is accepted only on an upstream
//!   whose every secret (its key and each header's secret) is the tenant's
//!   own. An upstream that spends an operator (appliance-wide) secret is the
//!   operator's to price. An upstream that sends no secret may carry a price.
//! - On an appliance-wide surface, or for a caller with no tenant context,
//!   adding or changing a price needs the `pipes.pricing` permission. A save
//!   that keeps or drops the stored prices needs nothing.
//!
//! At request time a call that spends a secret the surface's tenant does not
//! own is never billed below the catalog, whatever the surface declares
//! (`crate::pipes::types::llm::priced_cost`).

use std::collections::BTreeSet;
use std::sync::Arc;

use serde_json::{Value, json};

use super::pipe_caller::PipeCaller;
use crate::identity::handlers::pipes::AppError;
use crate::pipes::judge_jury::LLMTarget;
use crate::pipes::types::llm::TokenPricing;
use crate::pipes::types::llm_provider_ext::LLMProviderExt;
use crate::pipes::upstream_headers::UpstreamHeader;
use crate::pipes::{PipeConfig, PipeType};
use crate::rbac::Feature;
use crate::tenancy::PatTenantContext;

/// Where an upstream's own price comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PriceSource {
    /// `upstream_pricing` or a target's `pricing`.
    Declared,
    /// The surface's `cost_tracking` override.
    Override,
}

impl PriceSource {
    fn as_str(self) -> &'static str {
        match self {
            Self::Declared => "declared",
            Self::Override => "override",
        }
    }
}

/// The usage bucket an upstream's spend is counted in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bucket {
    /// The main stage: the surface's own upstream, failover, load-balancing
    /// and routing targets, Decider candidates and the Mirror merger.
    Llm,
    Judge,
    Jury,
    /// The Decider router.
    Decider,
}

impl Bucket {
    fn as_str(self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Judge => "judge",
            Self::Jury => "jury",
            Self::Decider => "decider",
        }
    }
}

/// One upstream a surface prices itself rather than leaving to the catalog.
struct PricedUpstream<'a> {
    /// Names the upstream in an error.
    label: String,
    source: PriceSource,
    bucket: Bucket,
    price: TokenPricing,
    provider_type: String,
    model: String,
    endpoint: String,
    key: Option<&'a str>,
    headers: &'a [UpstreamHeader],
}

impl PricedUpstream<'_> {
    /// Every secret this upstream sends: its key, then each header's.
    fn secret_references(&self) -> impl Iterator<Item = &str> {
        self.key
            .into_iter()
            .chain(
                self.headers
                    .iter()
                    .map(|header| header.secret_id.as_str()),
            )
            .map(str::trim)
            .filter(|reference| !reference.is_empty())
    }

    /// What this price applies to: the upstream (provider, model, endpoint and
    /// the secrets it spends), the bucket its spend is counted in, and the
    /// price with its source. Two saves that price the same upstream the same
    /// way yield the same site; a declared price and an equal override do not,
    /// because a declared price also prices streamed calls.
    fn site(&self) -> String {
        let site: Value = json!({
            "source": self.source.as_str(),
            "bucket": self.bucket.as_str(),
            "price": [self.price.input_price_per_million, self.price.output_price_per_million],
            "provider": self.provider_type,
            "model": self.model,
            "endpoint": self.endpoint,
            "secrets": self.secret_references().collect::<Vec<_>>(),
        });
        site.to_string()
    }
}

/// Every upstream `view` (the base or one resolved variant) prices itself.
///
/// A declared price applies to the upstream that declares it. The override
/// applies to every main-stage upstream that declares nothing (the surface's
/// own, failover, load-balancing and routing targets, Decider candidates and
/// the Mirror merger); the Judge, jurors and the Decider router are priced by
/// their own declared price or the catalog only.
fn priced_upstreams(view: &PipeConfig) -> Vec<PricedUpstream<'_>> {
    let override_price = view
        .cost_tracking
        .as_ref()
        .and_then(|config| {
            crate::pipes::executor::explicit_override_pricing(config.input_price_per_1k, config.output_price_per_1k)
        });
    let own_price = |declared: Option<&crate::pipes::types::llm::TargetPricing>, main_stage: bool| match declared {
        Some(declared) => Some((PriceSource::Declared, declared.token_pricing())),
        None if main_stage => override_price
            .clone()
            .map(|price| (PriceSource::Override, price)),
        None => None,
    };

    let mut priced = Vec::new();
    if let PipeType::LLM { provider, .. } = &view.pipe_type
        && let Some((source, price)) = own_price(view.upstream_pricing.as_ref(), true)
    {
        priced.push(PricedUpstream {
            label: "the surface's own upstream".to_string(),
            source,
            bucket: Bucket::Llm,
            price,
            provider_type: provider
                .provider_type_str()
                .to_string(),
            model: provider
                .get_model()
                .to_string(),
            endpoint: provider.get_endpoint(),
            key: provider.get_api_key(),
            headers: &view.upstream_headers,
        });
    }
    for (label, target, bucket) in targets(view) {
        if let Some((source, price)) = own_price(target.pricing.as_ref(), bucket == Bucket::Llm) {
            priced.push(PricedUpstream {
                label,
                source,
                bucket,
                price,
                provider_type: target.provider_type.clone(),
                model: target.model.clone(),
                endpoint: target.resolved_endpoint(),
                key: target
                    .api_key_secret
                    .as_deref(),
                headers: &target.headers,
            });
        }
    }
    priced
}

/// Every LLM target `view` names, labelled, with the bucket its spend is
/// counted in (a main-stage target falls back to the surface's override).
fn targets(view: &PipeConfig) -> Vec<(String, &LLMTarget, Bucket)> {
    let mut targets = Vec::new();
    if let Some(judge) = &view.judge {
        targets.push(("the Judge".to_string(), &judge.llm, Bucket::Judge));
    }
    for juror in view
        .jury
        .iter()
        .flat_map(|jury| jury.jurors.iter())
    {
        targets.push((format!("juror '{}'", juror.name), &juror.llm, Bucket::Jury));
    }
    if let Some(decider) = &view.decider {
        if let Some(router) = &decider.llm {
            targets.push(("the Decider router".to_string(), router, Bucket::Decider));
        }
        for candidate in &decider.candidates {
            targets.push((format!("Decider candidate '{}'", candidate.id), &candidate.llm, Bucket::Llm));
        }
        if let Some(merger) = &decider.mirror.merger {
            targets.push(("the Mirror merger".to_string(), merger, Bucket::Llm));
        }
    }
    for (idx, target) in view
        .failover
        .iter()
        .flat_map(|failover| failover.targets.iter())
        .enumerate()
    {
        targets.push((format!("failover target {}", idx + 1), &target.llm, Bucket::Llm));
    }
    for (idx, target) in view
        .load_balancing
        .iter()
        .flat_map(|lb| lb.targets.iter())
        .enumerate()
    {
        targets.push((format!("load balancing target {}", idx + 1), &target.llm, Bucket::Llm));
    }
    for (idx, rule) in view
        .routing_rules
        .iter()
        .enumerate()
    {
        if let Some(target) = &rule.target.llm {
            targets.push((format!("routing rule {}", idx + 1), target, Bucket::Llm));
        }
    }
    targets
}

/// Refuse a declared price on a tenant's surface for any upstream that sends a
/// secret the tenant does not own (an operator secret, or anyone else's).
/// `views` are the surface's base and resolved variants. A surface with no
/// tenant is the operator's own and is held by the pricing permission instead.
pub(super) async fn validate_declared_price_secrets(
    store: Option<&Arc<dyn crate::secrets::SecretsStore>>,
    pipe: &PipeConfig,
    views: &[PipeConfig],
) -> Result<(), AppError> {
    let Some(owner) = pipe.tenant_id.as_deref() else {
        return Ok(());
    };
    for view in views {
        for upstream in priced_upstreams(view)
            .iter()
            .filter(|upstream| upstream.source == PriceSource::Declared)
        {
            for reference in upstream.secret_references() {
                let store = store.ok_or_else(|| AppError::InternalError("Secret store not configured".to_string()))?;
                let owned = crate::secrets::resolve_reference(store.as_ref(), reference)
                    .await
                    .ok()
                    .flatten()
                    .is_some_and(|secret| secret.tenant_id.as_deref() == Some(owner));
                if !owned {
                    return Err(AppError::InvalidInput(format!(
                        "{} declares a price but sends a secret this surface's tenant does not own; \
                         only an upstream that spends the tenant's own secrets (or none) may declare its price",
                        upstream.label
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Every price site (see [`PricedUpstream::site`]) across a surface's base and
/// every variant.
fn price_sites(pipe: &PipeConfig) -> Result<BTreeSet<String>, AppError> {
    let mut sites = BTreeSet::new();
    for view in super::pipe_tenancy::resolved_views(pipe)? {
        sites.extend(
            priced_upstreams(&view)
                .iter()
                .map(PricedUpstream::site),
        );
    }
    Ok(sites)
}

/// Require `pipes.pricing` when a save adds or changes a price on an
/// appliance-wide surface, or comes from a caller with no tenant context.
/// `previous` is the stored surface (`None` on create); keeping or dropping
/// its prices needs nothing. A tenant's own token saving its own surface is
/// held by [`validate_declared_price_secrets`] instead.
pub(super) async fn authorize_price_change(
    previous: Option<&PipeConfig>,
    pipe: &PipeConfig,
    context: Option<&PatTenantContext>,
    caller: &PipeCaller,
) -> Result<(), AppError> {
    if pipe.tenant_id.is_some() && context.is_some() {
        return Ok(());
    }
    let stored = match previous {
        Some(previous) => price_sites(previous).unwrap_or_default(),
        None => BTreeSet::new(),
    };
    if price_sites(pipe)?.is_subset(&stored) {
        return Ok(());
    }
    if caller
        .holds(&Feature::PipesPricing)
        .await?
    {
        return Ok(());
    }
    Err(AppError::Forbidden(
        "Setting or changing what a surface bills at (a declared price or the cost override) needs the \
         pipes.pricing permission"
            .to_string(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::types::UserRole;
    use crate::pipes::types::llm::{LLMProvider, TargetPricing};

    fn surface() -> PipeConfig {
        PipeConfig::new(
            "pipe-1".into(),
            "Pipe".into(),
            PipeType::LLM {
                provider: Box::new(LLMProvider::OpenAI {
                    provider_type: "openai".into(),
                    model: "gpt-4o".into(),
                    api_key_secret: Some("openai_api_key".into()),
                    organization_id: None,
                    base_url: None,
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

    fn price(per_million: f64) -> TargetPricing {
        TargetPricing {
            input_per_million: per_million,
            output_per_million: per_million,
        }
    }

    fn backup(key: &str) -> PipeConfig {
        let mut pipe = surface();
        pipe.failover = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "targets": [{ "llm": {
                    "provider_type": "openai",
                    "model": "own-model",
                    "endpoint_url": "https://own.example/v1/chat/completions",
                    "api_key_secret": key,
                    "pricing": { "input_per_million": 0.0, "output_per_million": 0.0 }
                } }]
            }))
            .unwrap(),
        );
        pipe
    }

    async fn caller(
        role: UserRole,
        scopes: Option<Vec<&str>>,
    ) -> (PipeCaller, tempfile::TempDir) {
        PipeCaller::for_test("user-1", role, scopes).await
    }

    fn refused(result: &Result<(), AppError>) -> bool {
        matches!(result, Err(AppError::Forbidden(message)) if message.contains("pipes.pricing"))
    }

    #[tokio::test]
    async fn adding_or_changing_a_price_needs_the_pricing_permission() {
        let (user, _users) = caller(UserRole::User, None).await;
        let (admin, _admins) = caller(UserRole::Administrator, None).await;
        let unpriced = surface();
        let mut priced = surface();
        priced.upstream_pricing = Some(price(0.0));
        let mut repriced = surface();
        repriced.upstream_pricing = Some(price(1.0));
        let mut overridden = surface();
        overridden.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
            enabled: true,
            input_price_per_1k: Some(0.0001),
            output_price_per_1k: Some(0.0001),
            monthly_budget_usd: None,
            alert_threshold_percent: None,
        });

        for (label, previous, next) in [
            ("a new priced surface", None, &priced),
            ("a price added", Some(&unpriced), &priced),
            ("a price changed", Some(&priced), &repriced),
            ("an override added", Some(&unpriced), &overridden),
        ] {
            assert!(
                refused(&authorize_price_change(previous, next, None, &user).await),
                "{label} was accepted from a user"
            );
            authorize_price_change(previous, next, None, &admin)
                .await
                .unwrap_or_else(|e| panic!("{label} was refused from an administrator: {e:?}"));
        }
    }

    #[tokio::test]
    async fn keeping_or_dropping_the_stored_prices_needs_nothing() {
        let (user, _users) = caller(UserRole::User, None).await;
        let mut priced = surface();
        priced.upstream_pricing = Some(price(0.0));
        let mut renamed = priced.clone();
        renamed.name = "Renamed".into();
        renamed.description = Some("A user may still edit a priced surface".into());

        authorize_price_change(Some(&priced), &renamed, None, &user)
            .await
            .expect("an unchanged price needs no permission");
        authorize_price_change(Some(&priced), &surface(), None, &user)
            .await
            .expect("dropping a price needs no permission");
        authorize_price_change(None, &surface(), None, &user)
            .await
            .expect("a surface without prices needs no permission");
    }

    #[tokio::test]
    async fn moving_a_kept_price_onto_another_secret_needs_the_permission() {
        // The price is unchanged, but it now prices a call on another key.
        let (user, _users) = caller(UserRole::User, None).await;
        let own = backup("own-model-key");
        let operator = backup("openai_api_key");

        assert!(refused(&authorize_price_change(Some(&own), &operator, None, &user).await));
    }

    fn overridden(per_1k: f64) -> PipeConfig {
        let mut pipe = surface();
        pipe.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
            enabled: true,
            input_price_per_1k: Some(per_1k),
            output_price_per_1k: Some(per_1k),
            monthly_budget_usd: None,
            alert_threshold_percent: None,
        });
        pipe
    }

    #[tokio::test]
    async fn moving_an_override_into_a_declared_price_needs_the_permission() {
        // An administrator set the override; a user rewrites it as the same
        // price declared on the same upstream. A declared price also prices
        // streamed calls, which the override never did.
        let (user, _users) = caller(UserRole::User, None).await;
        let overridden = overridden(0.0001);
        let mut declared = surface();
        declared.upstream_pricing = Some(price(0.1));

        let streamed_before =
            crate::pipes::streaming::cost_for_tokens(None, true, "openai", "gpt-4o", 1_000_000, 1_000_000);
        let streamed_after = crate::pipes::streaming::cost_for_tokens(
            declared
                .upstream_pricing
                .as_ref(),
            true,
            "openai",
            "gpt-4o",
            1_000_000,
            1_000_000,
        );
        assert!(streamed_after < streamed_before, "precondition: the move lowers what a streamed call bills");

        assert!(
            refused(&authorize_price_change(Some(&overridden), &declared, None, &user).await),
            "a user moved the override into a declared price"
        );
        assert!(
            refused(&authorize_price_change(Some(&declared), &overridden, None, &user).await),
            "a user moved a declared price into the override"
        );
    }

    #[tokio::test]
    async fn moving_a_price_to_another_bucket_needs_the_permission() {
        // The same upstream at the same price, counted against the Jury's
        // budget instead of the Judge's.
        let (user, _users) = caller(UserRole::User, None).await;
        let llm = json!({
            "provider_type": "openai",
            "model": "gpt-4o",
            "endpoint_url": "https://api.openai.com/v1/chat/completions",
            "api_key_secret": "openai_api_key",
            "pricing": { "input_per_million": 0.0, "output_per_million": 0.0 }
        });
        let mut judged = surface();
        judged.judge = Some(serde_json::from_value(json!({ "enabled": true, "llm": llm })).unwrap());
        let mut juried = surface();
        juried.jury = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "jurors": [{ "name": "juror", "llm": llm, "system_prompt": "Review." }]
            }))
            .unwrap(),
        );

        assert!(refused(&authorize_price_change(Some(&judged), &juried, None, &user).await));
        authorize_price_change(Some(&juried), &juried.clone(), None, &user)
            .await
            .expect("precondition: keeping the juror's price needs nothing");
    }

    #[tokio::test]
    async fn a_token_must_name_the_pricing_permission_in_its_allow_list() {
        let (narrowed, _a) = caller(UserRole::Administrator, Some(vec!["pipes.edit"])).await;
        let (named, _b) = caller(UserRole::Administrator, Some(vec!["pipes.edit", "pipes.pricing"])).await;
        let mut priced = surface();
        priced.upstream_pricing = Some(price(0.0));

        assert!(refused(&authorize_price_change(None, &priced, None, &narrowed).await));
        authorize_price_change(None, &priced, None, &named)
            .await
            .expect("a token that names pipes.pricing may set a price");
    }

    #[tokio::test]
    async fn the_permission_applies_to_appliance_surfaces_and_callers_without_a_tenant() {
        let (user, _users) = caller(UserRole::User, None).await;
        let context = PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        };
        let mut tenant_priced = surface();
        tenant_priced.tenant_id = Some("tenant-a".into());
        tenant_priced.upstream_pricing = Some(price(0.0));

        authorize_price_change(None, &tenant_priced, Some(&context), &user)
            .await
            .expect("a tenant's own token on its own surface is held by the secret rule instead");
        assert!(
            refused(&authorize_price_change(None, &tenant_priced, None, &user).await),
            "a session without a tenant set a price on a tenant's surface"
        );
        let mut appliance_priced = surface();
        appliance_priced.upstream_pricing = Some(price(0.0));
        assert!(
            refused(&authorize_price_change(None, &appliance_priced, Some(&context), &user).await),
            "a tenant token set a price on an appliance-wide surface"
        );
    }

    #[tokio::test]
    async fn without_authentication_no_caller_is_restricted() {
        let mut priced = surface();
        priced.upstream_pricing = Some(price(0.0));
        authorize_price_change(None, &priced, None, &PipeCaller::default())
            .await
            .expect("an appliance without RBAC in force has no pricing permission to check");
    }

    #[test]
    fn every_upstream_a_surface_prices_is_a_site() {
        let mut pipe = backup("own-model-key");
        pipe.upstream_pricing = Some(price(2.0));
        pipe.judge = Some(
            serde_json::from_value(json!({ "enabled": true, "llm": {
                "provider_type": "openai",
                "model": "judge-model",
                "endpoint_url": "https://judge.example/v1/chat/completions",
                "pricing": { "input_per_million": 0.0, "output_per_million": 0.0 }
            } }))
            .unwrap(),
        );

        let labels: Vec<String> = priced_upstreams(&pipe)
            .into_iter()
            .map(|upstream| upstream.label)
            .collect();
        assert_eq!(labels, vec!["the surface's own upstream", "the Judge", "failover target 1"]);
    }
}
