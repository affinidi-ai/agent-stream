//! LLM request/response handling

use crate::pipes::parsers::LLMResponseParser;
use crate::pipes::types::llm::LLMMetrics;
use crate::pipes::{PipeConfig, PipeType};
use std::time::Instant;

pub struct LLMHandler;

impl LLMHandler {
    /// Process LLM response and extract metrics
    #[allow(dead_code)]
    pub fn process_response(
        pipe_config: &PipeConfig,
        response_body: &[u8],
        start_time: Instant,
    ) -> Option<LLMMetrics> {
        // Extract provider and model from config
        if let PipeType::LLM { provider, .. } = &pipe_config.pipe_type {
            let provider_type = provider.provider_type();
            let model = provider.model_name();

            // Parse response based on provider
            let metrics = LLMResponseParser::parse_auto(response_body, provider_type, model)?;

            // Add latency information
            let _latency_ms = start_time
                .elapsed()
                .as_millis() as u64;

            // For now, we don't track TTFT in non-streaming mode
            // That would require intercepting streaming responses

            Some(metrics)
        } else {
            None
        }
    }

    /// Validate that the pipe configuration is valid for LLM usage
    pub fn validate_config(pipe_config: &PipeConfig) -> Result<(), String> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        for limit in &pipe_config.usage_limits {
            limit.validate()?;
            if let Some(juror_index) = limit.juror_index {
                let juror_count = pipe_config
                    .jury
                    .as_ref()
                    .map(|j| j.jurors.len())
                    .unwrap_or(0);
                if (juror_index as usize) >= juror_count {
                    return Err(format!(
                        "Usage limit '{}' targets juror index {} but the jury has {} juror(s)",
                        limit.id, juror_index, juror_count
                    ));
                }
            }
        }
        if pipe_config.usage_alerts_enabled
            && let Some(alerts) = &pipe_config.usage_alerts
        {
            for alert in alerts {
                alert.validate()?;
            }
        }
        if let Some(cache) = &pipe_config.cache {
            cache.validate()?;
        }
        if let Some(canary) = &pipe_config.canary {
            let aliases: Vec<String> = pipe_config
                .variants
                .iter()
                .map(|v| v.alias.clone())
                .collect();
            canary.validate(&aliases)?;
        }
        if pipe_config.routing_enabled
            && !pipe_config
                .routing_rules
                .is_empty()
        {
            let aliases: Vec<String> = pipe_config
                .variants
                .iter()
                .map(|v| v.alias.clone())
                .collect();
            for (idx, rule) in pipe_config
                .routing_rules
                .iter()
                .enumerate()
            {
                rule.validate(&aliases)
                    .map_err(|e| format!("routing rule {}: {}", idx + 1, e))?;
            }
        }
        match &pipe_config.pipe_type {
            PipeType::LLM { provider, .. } => {
                // Validate provider configuration (OpenAI only)
                if provider
                    .model_name()
                    .is_empty()
                {
                    return Err("Model name cannot be empty".to_string());
                }
                crate::url_validation::validate_service_endpoint_url_blocking(&provider.get_endpoint())?;

                // Microsoft 365 Copilot is delegated-only: it must forward the
                // caller's Entra token so answers stay within that user's ACLs.
                // Without identity pass-through the surface has no per-user
                // grounding and app-only tokens are unsupported by the Chat API.
                // Keyed on the `copilot` wire schema so a custom catalog provider
                // that uses the Copilot API is held to the same requirement.
                if provider.requires_forward_caller_token() && !pipe_config.forward_caller_token {
                    return Err(
                        "Microsoft 365 Copilot surfaces require identity pass-through (forward_caller_token) so the \
                         caller's Entra token grounds answers on their own files under their ACLs"
                            .to_string(),
                    );
                }
            }
            _ => return Err("Pipe is not configured as LLM type".to_string()),
        }

        if let Some(judge) = &pipe_config.judge {
            judge.validate()?;
        }
        if let Some(jury) = &pipe_config.jury {
            jury.validate()?;
        }
        for variant in &pipe_config.variants {
            if let Some(judge) = &variant.overrides.judge {
                judge
                    .validate()
                    .map_err(|e| format!("variant '{}': {}", variant.alias, e))?;
            }
            if let Some(jury) = &variant.overrides.jury {
                jury.validate()
                    .map_err(|e| format!("variant '{}': {}", variant.alias, e))?;
            }
        }

        // Validate Decider routing configuration: candidate ids must be unique
        // and non-empty, the default must resolve, and every routable endpoint
        // must clear the SSRF guard. The router `llm` only runs in Route
        // strategy; Mirror ignores it and instead routes to a dedicated merger.
        if let Some(decider) = &pipe_config.decider {
            use crate::pipes::judge_jury::{DeciderStrategy, MirrorMode};
            decider.validate()?;
            if decider.enabled {
                if decider.strategy == DeciderStrategy::Route
                    && let Some(llm) = &decider.llm
                {
                    Self::validate_target_endpoint(llm)?;
                }
                for candidate in &decider.candidates {
                    Self::validate_target_endpoint(&candidate.llm)?;
                }
                if decider.strategy == DeciderStrategy::Mirror
                    && decider.mirror.mode == MirrorMode::Merge
                    && let Some(merger) = &decider.mirror.merger
                {
                    Self::validate_target_endpoint(merger)?;
                }
            }
        }

        // Validate the external guardrail endpoint (SSRF + non-empty URL).
        // Legacy `prompt_guard.external` is still accepted (migrated into an
        // expert witness at runtime), so validate it here for robustness.
        if let Some(prompt_guard) = &pipe_config.prompt_guard
            && let Some(external) = &prompt_guard.external
            && external.enabled
        {
            external.validate()?;
        }

        // Validate every model-backed PII detector endpoint (SSRF + non-empty URL).
        if let Some(prompt_guard) = &pipe_config.prompt_guard {
            for llm_pii in &prompt_guard.llm_pii {
                if llm_pii.enabled {
                    llm_pii.validate()?;
                }
            }
        }

        // Validate every expert witness (SSRF + non-empty URL + profile).
        for witness in &pipe_config.expert_witnesses {
            if witness.guardrail.enabled {
                witness.validate()?;
            }
        }

        // Validate cross-provider failover: at least one usable backup target
        // and every backup endpoint must clear the SSRF guard.
        if let Some(failover) = &pipe_config.failover {
            failover.validate()?;
            if failover.enabled {
                for target in &failover.targets {
                    Self::validate_target_endpoint(&target.llm)?;
                }
            }
        }

        // Validate weighted load balancing: a non-empty pool with positive
        // total weight and every target endpoint clearing the SSRF guard.
        if let Some(load_balancing) = &pipe_config.load_balancing {
            load_balancing.validate()?;
            if load_balancing.enabled {
                for target in &load_balancing.targets {
                    Self::validate_target_endpoint(&target.llm)?;
                }
            }
        }

        // Validate extra upstream headers (well-formed names, no provider or
        // gateway header hijacking, a secret reference on every entry) on the
        // base config and on every variant that declares its own.
        crate::pipes::upstream_headers::validate(&pipe_config.upstream_headers)?;
        if let Some(pricing) = &pipe_config.upstream_pricing {
            pricing
                .validate()
                .map_err(|e| format!("upstream {e}"))?;
        }
        for variant in &pipe_config.variants {
            if let Some(headers) = &variant
                .overrides
                .upstream_headers
            {
                crate::pipes::upstream_headers::validate(headers)
                    .map_err(|e| format!("variant '{}': {}", variant.alias, e))?;
            }
            if let Some(pricing) = &variant
                .overrides
                .upstream_pricing
            {
                pricing
                    .validate()
                    .map_err(|e| format!("variant '{}': upstream {}", variant.alias, e))?;
            }
            if let Some(cost_tracking) = &variant
                .overrides
                .cost_tracking
            {
                validate_price_override(cost_tracking).map_err(|e| format!("variant '{}': {}", variant.alias, e))?;
            }
        }
        if let Some(cost_tracking) = &pipe_config.cost_tracking {
            validate_price_override(cost_tracking)?;
        }

        // Every LLM target's own headers (the same rules as `upstream_headers`)
        // and declared price, on the base and on each variant's Judge and Jury.
        for (label, target) in llm_targets(pipe_config) {
            Self::validate_target_extras(&label, target)?;
        }

        Self::validate_caller_key_channel(pipe_config)?;
        for variant in &pipe_config.variants {
            if let Ok(resolved) = pipe_config.resolve_variant(Some(&variant.alias)) {
                Self::validate_caller_key_channel(&resolved)
                    .map_err(|e| format!("variant '{}': {}", variant.alias, e))?;
            }
        }

        // Identity pass-through requires validated `jwt_bearer` source auth so
        // the forwarded token is verified (issuer/JWKS/audience/exp) before it
        // is sent to the upstream. Never forward an unvalidated credential.
        if pipe_config.forward_caller_token
            && !matches!(&pipe_config.source_auth, Some(crate::source_auth::SourceAuthConfig::JwtBearer(_)))
        {
            return Err(
                "forward_caller_token requires jwt_bearer source auth so the forwarded token is validated".to_string()
            );
        }

        // A model disabled in the catalog must never be saved, regardless of what
        // the dashboard offered. Skipped when no catalog is installed (e.g. unit
        // tests that never boot the orchestrator).
        if let Some(catalog) = crate::llm_catalog::global_catalog() {
            Self::reject_disabled_models(pipe_config, &catalog)?;
        }
        Ok(())
    }

    /// Refuse a surface that accepts the caller's own provider key
    /// (`override_policy.api_key` `client_wins` or `inject_if_missing`) while
    /// its front door reads `x-agent-stream-upstream-authorization`. The
    /// caller's key is taken from that header, else from `Authorization`, and
    /// never from a header the front door reads, so a front door on
    /// `Authorization` (`jwt_bearer`) takes the caller's key from the dedicated
    /// header alone; a front door on the dedicated header would make the
    /// caller's provider-key channel its own credential.
    fn validate_caller_key_channel(pipe_config: &PipeConfig) -> Result<(), String> {
        use crate::pipes::types::llm::OverridePolicy;

        let accepts_caller_keys = pipe_config
            .override_policy
            .as_ref()
            .and_then(|policy| policy.api_key.as_ref())
            .is_some_and(|policy| matches!(policy, OverridePolicy::ClientWins | OverridePolicy::InjectIfMissing));
        let front_door_reads_channel = pipe_config
            .source_auth
            .as_ref()
            .is_some_and(|auth| {
                auth.reads_header(crate::pipes::handlers::http_handlers::UPSTREAM_AUTHORIZATION_HEADER)
            });
        if accepts_caller_keys && front_door_reads_channel {
            return Err(format!(
                "source auth cannot read {} while override_policy.api_key accepts the caller's own provider key: \
                 that header carries the caller's key when the front door reads Authorization",
                crate::pipes::handlers::http_handlers::UPSTREAM_AUTHORIZATION_HEADER
            ));
        }
        if accepts_caller_keys && Self::keyless_upstream_declares_a_price(pipe_config) {
            return Err(
                "override_policy.api_key cannot accept the caller's own provider key on an upstream that stores \
                 no key but declares a price (upstream_pricing or a cost_tracking price): such an upstream may not \
                 check the key, so any value a caller sent would make its priced calls free. Store the upstream's \
                 key, or set the price to zero"
                    .to_string(),
            );
        }
        Ok(())
    }

    /// Whether the surface's own upstream sends no credential of its own (no
    /// stored API key, no `upstream_headers`) yet declares a non-zero price:
    /// `upstream_pricing`, or a `cost_tracking` price override. Such a call is
    /// priced and billed to the operator when keyless, and labelled the
    /// caller's (billing nothing) as soon as the caller offers any key, which
    /// an upstream that checks no key would still serve.
    fn keyless_upstream_declares_a_price(pipe_config: &PipeConfig) -> bool {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        let crate::pipes::PipeType::LLM { provider, .. } = &pipe_config.pipe_type else {
            return false;
        };
        let stores_a_key = provider
            .get_api_key()
            .is_some_and(|reference| !reference.trim().is_empty())
            || !pipe_config
                .upstream_headers
                .is_empty();
        let declared = pipe_config
            .upstream_pricing
            .is_some_and(|pricing| pricing.input_per_million > 0.0 || pricing.output_per_million > 0.0);
        let overridden = pipe_config
            .cost_tracking
            .as_ref()
            .is_some_and(|cost| {
                crate::pipes::executor::explicit_override_pricing(cost.input_price_per_1k, cost.output_price_per_1k)
                    .is_some()
            });
        !stores_a_key && (declared || overridden)
    }

    /// Validate one LLM target's own `headers` and declared `pricing`, naming the
    /// target in the error. Headers need a provider type that calls the
    /// target's own `endpoint_url`: one that always calls its vendor's default
    /// host would carry them there when the target serves a routed copy.
    fn validate_target_extras(
        label: &str,
        target: &crate::pipes::judge_jury::LLMTarget,
    ) -> Result<(), String> {
        crate::pipes::upstream_headers::validate(&target.headers).map_err(|e| format!("{label}: {e}"))?;
        if !target.headers.is_empty() && !crate::pipes::judge_jury::provider_calls_target_endpoint(target) {
            return Err(format!(
                "{label}: headers need a provider type that sends to the target's endpoint_url; \
                 provider '{}' always calls its own host, so its headers would go there",
                target.provider_type
            ));
        }
        if let Some(pricing) = &target.pricing {
            pricing
                .validate()
                .map_err(|e| format!("{label}: {e}"))?;
        }
        Ok(())
    }

    /// Validate a judge/jury/decider target endpoint exactly as the runtime uses
    /// it: a relative path (e.g. `/messages`) is first resolved against the
    /// provider's default base URL — mirroring `call_llm_inner`'s
    /// `resolve_endpoint_url` — before the SSRF / absolute-URL check. Without
    /// this, a surface that runs fine (the executor resolves the path) is
    /// rejected on save because the raw `/messages` is a relative URL. The SSRF
    /// guard still runs on the resolved absolute URL, so protection is unchanged.
    fn validate_target_endpoint(llm: &crate::pipes::judge_jury::LLMTarget) -> Result<(), String> {
        let resolved = crate::pipes::defaults::resolve_endpoint_url(&llm.provider_type, &llm.endpoint_url);
        crate::url_validation::validate_service_endpoint_url_blocking(&resolved)?;
        Ok(())
    }

    /// Reject the save when any catalog-governed model the pipe references — the
    /// primary LLM model, the Judge model, or an enabled juror's model — is
    /// explicitly disabled (`"enabled": false`). Models absent from the catalog
    /// (custom endpoints, moderation models) are left untouched.
    fn reject_disabled_models(
        pipe_config: &PipeConfig,
        catalog: &crate::llm_catalog::LlmProviderCatalog,
    ) -> Result<(), String> {
        if let PipeType::LLM { provider, .. } = &pipe_config.pipe_type {
            ensure_model_enabled(catalog, provider.provider_type(), provider.model_name())?;
        }
        if let Some(judge) = &pipe_config.judge
            && judge.enabled
        {
            ensure_model_enabled(catalog, &judge.llm.provider_type, &judge.llm.model)?;
        }
        if let Some(jury) = &pipe_config.jury
            && jury.enabled
        {
            for juror in jury
                .jurors
                .iter()
                .filter(|j| j.enabled)
            {
                ensure_model_enabled(catalog, &juror.llm.provider_type, &juror.llm.model)?;
            }
        }
        if let Some(decider) = &pipe_config.decider
            && decider.enabled
        {
            use crate::pipes::judge_jury::{DeciderStrategy, MirrorMode};
            if decider.strategy == DeciderStrategy::Route
                && let Some(llm) = &decider.llm
            {
                ensure_model_enabled(catalog, &llm.provider_type, &llm.model)?;
            }
            for candidate in &decider.candidates {
                ensure_model_enabled(catalog, &candidate.llm.provider_type, &candidate.llm.model)?;
            }
            if decider.strategy == DeciderStrategy::Mirror
                && decider.mirror.mode == MirrorMode::Merge
                && let Some(merger) = &decider.mirror.merger
            {
                ensure_model_enabled(catalog, &merger.provider_type, &merger.model)?;
            }
        }
        Ok(())
    }
}

/// Check a `cost_tracking` price override: each price per thousand tokens it
/// sets must be finite, zero or more, and within the ceiling a declared price
/// has (see [`crate::pipes::types::llm::validate_price_per_million`]).
fn validate_price_override(cost_tracking: &crate::pipes::config::CostTrackingConfig) -> Result<(), String> {
    for (field, price) in [
        ("input_price_per_1k", cost_tracking.input_price_per_1k),
        ("output_price_per_1k", cost_tracking.output_price_per_1k),
    ] {
        if let Some(price) = price {
            crate::pipes::types::llm::validate_price_per_million(field, price * 1000.0).map_err(|_| {
                format!(
                    "cost_tracking {field} must be between 0 and {} USD per thousand tokens (got {price})",
                    crate::pipes::types::llm::MAX_PRICE_PER_MILLION_TOKENS / 1000.0
                )
            })?;
        }
    }
    Ok(())
}

/// Every LLM target a surface names, labelled for error messages: the Judge,
/// jurors, Decider router, candidates and merger, failover and load-balancing
/// targets, and inline routing targets on the base, then each variant's own
/// Judge and jurors (the only targets a variant can override).
fn llm_targets(pipe: &PipeConfig) -> Vec<(String, &crate::pipes::judge_jury::LLMTarget)> {
    fn judge_and_jury<'a>(
        prefix: &str,
        judge: Option<&'a crate::pipes::judge_jury::JudgeConfig>,
        jury: Option<&'a crate::pipes::judge_jury::JuryConfig>,
        targets: &mut Vec<(String, &'a crate::pipes::judge_jury::LLMTarget)>,
    ) {
        if let Some(judge) = judge {
            targets.push((format!("{prefix}Judge"), &judge.llm));
        }
        for juror in jury
            .iter()
            .flat_map(|jury| jury.jurors.iter())
        {
            targets.push((format!("{prefix}juror '{}'", juror.name), &juror.llm));
        }
    }

    let mut targets = Vec::new();
    judge_and_jury("", pipe.judge.as_ref(), pipe.jury.as_ref(), &mut targets);
    if let Some(decider) = &pipe.decider {
        if let Some(router) = &decider.llm {
            targets.push(("Decider router".to_string(), router));
        }
        for candidate in &decider.candidates {
            targets.push((format!("Decider candidate '{}'", candidate.id), &candidate.llm));
        }
        if let Some(merger) = &decider.mirror.merger {
            targets.push(("Mirror merger".to_string(), merger));
        }
    }
    for (idx, target) in pipe
        .failover
        .iter()
        .flat_map(|failover| failover.targets.iter())
        .enumerate()
    {
        targets.push((format!("failover target {}", idx + 1), &target.llm));
    }
    for (idx, target) in pipe
        .load_balancing
        .iter()
        .flat_map(|lb| lb.targets.iter())
        .enumerate()
    {
        targets.push((format!("load balancing target {}", idx + 1), &target.llm));
    }
    for (idx, rule) in pipe
        .routing_rules
        .iter()
        .enumerate()
    {
        if let Some(target) = &rule.target.llm {
            targets.push((format!("routing rule {}", idx + 1), target));
        }
    }
    for variant in &pipe.variants {
        judge_and_jury(
            &format!("variant '{}': ", variant.alias),
            variant
                .overrides
                .judge
                .as_ref(),
            variant
                .overrides
                .jury
                .as_ref(),
            &mut targets,
        );
    }
    targets
}

/// Return an error when a catalog model is explicitly disabled. Unknown models
/// (not in the catalog) are allowed so custom endpoints keep working.
fn ensure_model_enabled(
    catalog: &crate::llm_catalog::LlmProviderCatalog,
    provider_type: &str,
    model: &str,
) -> Result<(), String> {
    if catalog.model_enabled(provider_type, model) == Some(false) {
        return Err(format!("Model '{}' (provider '{}') is disabled and cannot be used", model, provider_type));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::llm_catalog::LlmProviderCatalog;
    use crate::pipes::types::llm::LLMProvider;
    use serde_json::json;
    use std::path::PathBuf;

    fn temp_catalog(
        name: &str,
        models: serde_json::Value,
    ) -> LlmProviderCatalog {
        let mut dir = std::env::temp_dir();
        dir.push(format!("llm_handler_test_{}_{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path: PathBuf = dir.join("llm.json");
        std::fs::write(
            &path,
            json!({
                "providers": [{
                    "enum_value": "anthropic",
                    "name": "Anthropic",
                    "endpoints": [],
                    "models": models,
                }]
            })
            .to_string(),
        )
        .unwrap();
        LlmProviderCatalog::new(path, None).unwrap()
    }

    fn llm_pipe(model: &str) -> PipeConfig {
        let provider = LLMProvider::OpenAI {
            provider_type: "anthropic".to_string(),
            model: model.to_string(),
            api_key_secret: None,
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        PipeConfig::new(
            "p".to_string(),
            "P".to_string(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        )
    }

    #[test]
    fn rejects_disabled_primary_model() {
        let catalog = temp_catalog("primary_off", json!([{ "value": "off", "enabled": false }]));
        let err = LLMHandler::reject_disabled_models(&llm_pipe("off"), &catalog).unwrap_err();
        assert!(err.contains("off"), "unexpected message: {err}");
        assert!(err.contains("disabled"), "unexpected message: {err}");
    }

    #[test]
    fn rejects_forward_caller_token_without_jwt_bearer() {
        let mut pipe = llm_pipe("gpt-4");
        pipe.forward_caller_token = true;
        // No source_auth configured → the forwarded token would be unvalidated.
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("jwt_bearer"), "unexpected message: {err}");
    }

    #[test]
    fn accepts_forward_caller_token_with_jwt_bearer() {
        use crate::jwt_bearer::models::JwtBearerAuthConfig;
        let mut pipe = llm_pipe("gpt-4");
        pipe.forward_caller_token = true;
        pipe.source_auth = Some(crate::source_auth::SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec!["api://app".to_string()],
            allow_missing_audience: false,
            token_header: "Authorization".to_string(),
            token_scheme: "Bearer".to_string(),
        }));
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    fn accepting_caller_keys(
        pipe: &mut PipeConfig,
        policy: crate::pipes::types::llm::OverridePolicy,
    ) {
        pipe.override_policy = Some(crate::pipes::types::llm::ParameterOverrideConfig {
            api_key: Some(policy),
            ..Default::default()
        });
    }

    fn api_key_front_door(header: &str) -> crate::source_auth::SourceAuthConfig {
        crate::source_auth::SourceAuthConfig::ApiKey(crate::source_auth::models::ApiKeyAuthConfig {
            extraction: crate::source_auth::models::CredentialExtraction::HttpHeader { field: header.to_string() },
            secret_id: "front-door-keys".to_string(),
        })
    }

    #[test]
    fn refuses_caller_keys_whose_channel_is_the_front_doors_credential() {
        use crate::pipes::types::llm::OverridePolicy;
        for policy in [OverridePolicy::ClientWins, OverridePolicy::InjectIfMissing] {
            let mut pipe = llm_pipe("gpt-4");
            accepting_caller_keys(&mut pipe, policy);
            pipe.source_auth = Some(api_key_front_door("X-Agent-Stream-Upstream-Authorization"));
            let err = LLMHandler::validate_config(&pipe).unwrap_err();
            assert!(err.contains("x-agent-stream-upstream-authorization"), "unexpected message: {err}");
        }
    }

    #[test]
    fn accepts_caller_keys_beside_a_front_door_on_authorization_or_another_header() {
        use crate::pipes::types::llm::OverridePolicy;
        for front_door in [
            crate::source_auth::SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig::default()),
            api_key_front_door("Authorization"),
            api_key_front_door("x-boris-api-key"),
        ] {
            let mut pipe = llm_pipe("gpt-4");
            accepting_caller_keys(&mut pipe, OverridePolicy::InjectIfMissing);
            pipe.source_auth = Some(front_door);
            assert!(LLMHandler::validate_config(&pipe).is_ok());
        }
        // The stored key's policy never reads a caller key.
        let mut pipe = llm_pipe("gpt-4");
        accepting_caller_keys(&mut pipe, OverridePolicy::GatewayWins);
        pipe.source_auth = Some(api_key_front_door("x-agent-stream-upstream-authorization"));
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn refuses_caller_keys_on_a_keyless_upstream_that_declares_a_price() {
        use crate::pipes::types::llm::{OverridePolicy, TargetPricing};
        let priced = TargetPricing {
            input_per_million: 1.0,
            output_per_million: 2.0,
        };
        for policy in [OverridePolicy::ClientWins, OverridePolicy::InjectIfMissing] {
            let mut pipe = llm_pipe("house-model");
            accepting_caller_keys(&mut pipe, policy.clone());
            pipe.upstream_pricing = Some(priced);
            let err = LLMHandler::validate_config(&pipe).unwrap_err();
            assert!(err.contains("stores no key but declares a price"), "unexpected message: {err}");

            let mut overridden = llm_pipe("house-model");
            accepting_caller_keys(&mut overridden, policy);
            overridden.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
                enabled: true,
                input_price_per_1k: Some(0.001),
                output_price_per_1k: Some(0.002),
                monthly_budget_usd: None,
                alert_threshold_percent: None,
            });
            assert!(LLMHandler::validate_config(&overridden).is_err(), "a cost_tracking price is declared too");
        }

        // A stored key, a zero price, or a policy that never reads a caller
        // key is accepted.
        let mut keyed = llm_pipe("house-model");
        accepting_caller_keys(&mut keyed, OverridePolicy::InjectIfMissing);
        keyed.upstream_pricing = Some(priced);
        if let PipeType::LLM { provider, .. } = &mut keyed.pipe_type
            && let LLMProvider::OpenAI { api_key_secret, .. } = provider.as_mut()
        {
            *api_key_secret = Some("house-key".to_string());
        }
        assert!(LLMHandler::validate_config(&keyed).is_ok());
        let mut free = llm_pipe("house-model");
        accepting_caller_keys(&mut free, OverridePolicy::ClientWins);
        free.upstream_pricing = Some(TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        });
        assert!(LLMHandler::validate_config(&free).is_ok());
        let mut stored_only = llm_pipe("house-model");
        accepting_caller_keys(&mut stored_only, OverridePolicy::GatewayWins);
        stored_only.upstream_pricing = Some(priced);
        assert!(LLMHandler::validate_config(&stored_only).is_ok());
    }

    #[test]
    fn refuses_a_variant_whose_caller_key_channel_is_its_front_doors_credential() {
        use crate::pipes::types::llm::OverridePolicy;
        let mut pipe = llm_pipe("gpt-4");
        accepting_caller_keys(&mut pipe, OverridePolicy::ClientWins);
        let variant: crate::pipes::pipe_variants::PipeVariant = serde_json::from_value(json!({
            "id": "v-1",
            "alias": "keyed",
            "name": "Keyed",
            "overrides": {
                "source_auth": {
                    "type": "api_key",
                    "extraction": { "source": "http_header", "field": "x-agent-stream-upstream-authorization" },
                    "secret_id": "front-door-keys"
                }
            }
        }))
        .unwrap();
        pipe.variants = vec![variant];
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.starts_with("variant 'keyed'"), "unexpected message: {err}");
    }

    fn judge_with_condition(condition: serde_json::Value) -> serde_json::Value {
        json!({
            "enabled": true,
            "mode": "llm",
            "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                     "endpoint_url": "https://api.openai.com/v1/chat/completions" },
            "rules": [{ "name": "Rule", "condition": condition }]
        })
    }

    #[test]
    fn validate_config_rejects_judge_rule_with_invalid_regex() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.judge = Some(
            serde_json::from_value(judge_with_condition(json!({ "type": "regex_match", "pattern": "(" }))).unwrap(),
        );

        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.starts_with("Judge rule 'Rule': invalid regex pattern"), "unexpected message: {err}");
    }

    #[test]
    fn validate_config_rejects_variant_judge_rule_with_unknown_condition_type() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        let variant: crate::pipes::pipe_variants::PipeVariant = serde_json::from_value(json!({
            "id": "v-1",
            "alias": "strict",
            "name": "Strict",
            "overrides": { "judge": judge_with_condition(json!({ "type": "flagged" })) }
        }))
        .unwrap();
        pipe.variants = vec![variant];

        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert_eq!(err, "variant 'strict': Judge rule 'Rule': condition type 'flagged' is not valid in llm mode");
    }

    #[test]
    fn validate_config_accepts_valid_judge_rules() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.judge = Some(
            serde_json::from_value(judge_with_condition(
                json!({ "type": "json_field_not_equals", "field": "decision", "value": "approve" }),
            ))
            .unwrap(),
        );

        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn accepts_enabled_primary_model() {
        let catalog = temp_catalog("primary_on", json!([{ "value": "on", "enabled": true }]));
        assert!(LLMHandler::reject_disabled_models(&llm_pipe("on"), &catalog).is_ok());
    }

    #[test]
    fn accepts_a_well_formed_upstream_header() {
        let mut pipe = llm_pipe("gpt-4");
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn rejects_an_upstream_header_that_hijacks_the_provider_credential() {
        let mut pipe = llm_pipe("gpt-4");
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "Authorization".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("reserved"), "unexpected message: {err}");
    }

    #[test]
    fn rejects_a_variants_malformed_upstream_header() {
        let mut pipe = llm_pipe("gpt-4");
        pipe.variants = vec![crate::pipes::pipe_variants::PipeVariant {
            id: "v1".to_string(),
            alias: "fast".to_string(),
            name: "Fast".to_string(),
            description: String::new(),
            enabled: true,
            overrides: crate::pipes::pipe_variants::PipeVariantOverrides {
                upstream_headers: Some(vec![crate::pipes::upstream_headers::UpstreamHeader {
                    name: "x-mesh-token".to_string(),
                    secret_id: String::new(),
                }]),
                ..Default::default()
            },
        }];
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("variant 'fast'"), "the error must name the variant, got: {err}");
        assert!(err.contains("secret reference"), "unexpected message: {err}");
    }

    fn target_with(
        headers: serde_json::Value,
        pricing: Option<serde_json::Value>,
    ) -> serde_json::Value {
        let mut llm = json!({
            "provider_type": "openai",
            "model": "own-model",
            "endpoint_url": "https://198.51.100.7/v1/chat/completions",
            "headers": headers,
        });
        if let Some(pricing) = pricing {
            llm["pricing"] = pricing;
        }
        llm
    }

    fn own_key() -> serde_json::Value {
        json!([{ "name": "x-asp-api-key", "secret_id": "tunnel-key" }])
    }

    #[test]
    fn accepts_well_formed_target_headers_and_a_zero_price() {
        let mut pipe = llm_pipe("gpt-4");
        let llm = target_with(own_key(), Some(json!({ "input_per_million": 0.0, "output_per_million": 0.0 })));
        pipe.failover = Some(serde_json::from_value(json!({ "enabled": true, "targets": [{ "llm": llm }] })).unwrap());
        pipe.judge = Some(serde_json::from_value(json!({ "enabled": true, "llm": llm })).unwrap());
        pipe.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        });
        assert_eq!(LLMHandler::validate_config(&pipe), Ok(()));
    }

    #[test]
    fn rejects_a_target_header_that_hijacks_the_provider_credential_naming_the_target() {
        let mut pipe = llm_pipe("gpt-4");
        let llm = target_with(json!([{ "name": "Authorization", "secret_id": "tunnel-key" }]), None);
        pipe.failover = Some(serde_json::from_value(json!({ "enabled": true, "targets": [{ "llm": llm }] })).unwrap());
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("failover target 1"), "the error must name the target, got: {err}");
        assert!(err.contains("reserved"), "unexpected message: {err}");
    }

    type Configure<'a> = Box<dyn Fn(&mut PipeConfig) + 'a>;

    #[test]
    fn rejects_every_target_kinds_malformed_headers() {
        let bad = target_with(json!([{ "name": "x-agent-stream-secret", "secret_id": "tunnel-key" }]), None);
        let plain = target_with(json!([]), None);
        let cases: Vec<(&str, Configure<'_>)> = vec![
            ("Judge", Box::new(|p| p.judge = Some(serde_json::from_value(json!({ "llm": bad })).unwrap()))),
            (
                "juror 'j'",
                Box::new(|p| {
                    p.jury = Some(
                        serde_json::from_value(
                            json!({ "jurors": [{ "name": "j", "llm": bad, "system_prompt": "x" }] }),
                        )
                        .unwrap(),
                    )
                }),
            ),
            (
                "Decider router",
                Box::new(|p| {
                    p.decider = Some(
                        serde_json::from_value(
                            json!({ "llm": bad, "candidates": [{ "id": "c", "name": "c", "llm": plain }] }),
                        )
                        .unwrap(),
                    )
                }),
            ),
            (
                "Decider candidate 'c'",
                Box::new(|p| {
                    p.decider = Some(
                        serde_json::from_value(json!({ "candidates": [{ "id": "c", "name": "c", "llm": bad }] }))
                            .unwrap(),
                    )
                }),
            ),
            (
                "Mirror merger",
                Box::new(|p| {
                    p.decider = Some(
                        serde_json::from_value(
                            json!({ "strategy": "mirror", "mirror": { "merger": bad }, "candidates": [] }),
                        )
                        .unwrap(),
                    )
                }),
            ),
            (
                "load balancing target 1",
                Box::new(|p| {
                    p.load_balancing =
                        Some(serde_json::from_value(json!({ "enabled": false, "targets": [{ "llm": bad }] })).unwrap())
                }),
            ),
            (
                "routing rule 1",
                Box::new(|p| {
                    p.routing_rules = vec![
                        serde_json::from_value(json!({
                            "match": { "kind": "header", "name": "x-route", "equals": "own" },
                            "target": { "llm": bad }
                        }))
                        .unwrap(),
                    ]
                }),
            ),
            (
                "variant 'strict': Judge",
                Box::new(|p| {
                    p.variants = vec![crate::pipes::pipe_variants::PipeVariant {
                        id: "v1".to_string(),
                        alias: "strict".to_string(),
                        name: "Strict".to_string(),
                        description: String::new(),
                        enabled: false,
                        overrides: crate::pipes::pipe_variants::PipeVariantOverrides {
                            judge: Some(serde_json::from_value(json!({ "llm": bad })).unwrap()),
                            ..Default::default()
                        },
                    }]
                }),
            ),
        ];
        for (label, configure) in cases {
            let mut pipe = llm_pipe("gpt-4");
            configure(&mut pipe);
            let err = LLMHandler::validate_config(&pipe).expect_err(label);
            assert!(err.starts_with(label), "the error must name {label}, got: {err}");
            assert!(err.contains("reserved for the gateway"), "unexpected message for {label}: {err}");
        }
    }

    #[test]
    fn rejects_target_headers_on_a_provider_that_ignores_endpoint_url() {
        for provider_type in ["anthropic", "gemini", "cohere", "together_ai", "replicate"] {
            let mut pipe = llm_pipe("gpt-4");
            let mut llm = target_with(own_key(), None);
            llm["provider_type"] = json!(provider_type);
            pipe.failover =
                Some(serde_json::from_value(json!({ "enabled": true, "targets": [{ "llm": llm }] })).unwrap());

            let err = LLMHandler::validate_config(&pipe).expect_err(provider_type);
            assert!(err.starts_with("failover target 1"), "the error must name the target, got: {err}");
            assert!(err.contains("endpoint_url"), "unexpected message for {provider_type}: {err}");

            // The same target without headers calls its vendor as before.
            let mut plain = target_with(json!([]), None);
            plain["provider_type"] = json!(provider_type);
            pipe.failover =
                Some(serde_json::from_value(json!({ "enabled": true, "targets": [{ "llm": plain }] })).unwrap());
            LLMHandler::validate_config(&pipe)
                .unwrap_or_else(|e| panic!("{provider_type} without headers was refused: {e}"));
        }
    }

    #[test]
    fn rejects_a_cost_override_out_of_range_on_the_base_or_a_variant() {
        let override_of = |input: f64, output: f64| crate::pipes::config::CostTrackingConfig {
            enabled: true,
            input_price_per_1k: Some(input),
            output_price_per_1k: Some(output),
            monthly_budget_usd: None,
            alert_threshold_percent: None,
        };
        for (input, output) in [(-0.01, 0.01), (0.01, f64::NAN), (100.01, 0.01), (0.01, f64::INFINITY)] {
            let mut pipe = llm_pipe("gpt-4");
            pipe.cost_tracking = Some(override_of(input, output));
            let err = LLMHandler::validate_config(&pipe).expect_err("an out-of-range override");
            assert!(err.contains("cost_tracking"), "unexpected message: {err}");

            let mut pipe = llm_pipe("gpt-4");
            pipe.variants = vec![crate::pipes::pipe_variants::PipeVariant {
                id: "v1".to_string(),
                alias: "cheap".to_string(),
                name: "Cheap".to_string(),
                description: String::new(),
                enabled: true,
                overrides: crate::pipes::pipe_variants::PipeVariantOverrides {
                    cost_tracking: Some(override_of(input, output)),
                    ..Default::default()
                },
            }];
            let err = LLMHandler::validate_config(&pipe).expect_err("an out-of-range variant override");
            assert!(err.starts_with("variant 'cheap'"), "unexpected message: {err}");
        }
        let mut pipe = llm_pipe("gpt-4");
        pipe.cost_tracking = Some(override_of(0.0, 100.0));
        assert_eq!(LLMHandler::validate_config(&pipe), Ok(()), "zero and the ceiling are both valid");
    }

    #[test]
    fn rejects_a_negative_target_or_upstream_price() {
        // A body carrying a negative price does not even parse.
        let llm = target_with(json!([]), Some(json!({ "input_per_million": -1.0, "output_per_million": 0.0 })));
        let parsed = serde_json::from_value::<crate::pipes::judge_jury::JudgeConfig>(json!({ "llm": llm }));
        assert!(
            parsed
                .as_ref()
                .is_err_and(|e| e
                    .to_string()
                    .contains("input_per_million")),
            "a negative target price must be refused as it is read, got {parsed:?}"
        );

        // One built in code is refused at save, naming the target.
        let mut pipe = llm_pipe("gpt-4");
        let mut judge: crate::pipes::judge_jury::JudgeConfig =
            serde_json::from_value(json!({ "llm": target_with(json!([]), None) })).unwrap();
        judge.llm.pricing = Some(crate::pipes::types::llm::TargetPricing {
            input_per_million: -1.0,
            output_per_million: 0.0,
        });
        pipe.judge = Some(judge);
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.starts_with("Judge"), "unexpected message: {err}");

        let mut pipe = llm_pipe("gpt-4");
        pipe.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
            input_per_million: 0.0,
            output_per_million: -0.5,
        });
        assert!(
            LLMHandler::validate_config(&pipe)
                .unwrap_err()
                .contains("output_per_million")
        );
    }

    fn copilot_pipe() -> PipeConfig {
        let provider = LLMProvider::M365Copilot {
            provider_type: "m365_copilot".to_string(),
            model: "copilot".to_string(),
            api_key_secret: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        PipeConfig::new(
            "copilot".to_string(),
            "Copilot".to_string(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        )
    }

    #[test]
    fn rejects_copilot_without_identity_passthrough() {
        let pipe = copilot_pipe();
        // forward_caller_token defaults to false — no per-user grounding.
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("forward_caller_token"), "unexpected message: {err}");
    }

    #[test]
    fn accepts_copilot_with_identity_passthrough_and_jwt_bearer() {
        use crate::jwt_bearer::models::JwtBearerAuthConfig;
        let mut pipe = copilot_pipe();
        pipe.forward_caller_token = true;
        pipe.source_auth = Some(crate::source_auth::SourceAuthConfig::JwtBearer(JwtBearerAuthConfig {
            jwt_verification_strategy_id: "strat-1".to_string(),
            audiences: vec!["api://app".to_string()],
            allow_missing_audience: false,
            token_header: "Authorization".to_string(),
            token_scheme: "Bearer".to_string(),
        }));
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn accepts_model_absent_from_catalog() {
        let catalog = temp_catalog("primary_absent", json!([{ "value": "off", "enabled": false }]));
        // A custom/unlisted model is not governed by the catalog.
        assert!(LLMHandler::reject_disabled_models(&llm_pipe("custom-model"), &catalog).is_ok());
    }

    #[test]
    fn rejects_disabled_judge_model() {
        let catalog = temp_catalog(
            "judge_off",
            json!([
                { "value": "on", "enabled": true },
                { "value": "off", "enabled": false },
            ]),
        );
        let mut pipe = llm_pipe("on");
        pipe.judge = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "llm": { "provider_type": "anthropic", "model": "off", "endpoint_url": "https://api.example" }
            }))
            .unwrap(),
        );
        let err = LLMHandler::reject_disabled_models(&pipe, &catalog).unwrap_err();
        assert!(err.contains("off"), "unexpected message: {err}");
    }

    #[test]
    fn ignores_disabled_judge_block() {
        let catalog = temp_catalog(
            "judge_block_off",
            json!([
                { "value": "on", "enabled": true },
                { "value": "off", "enabled": false },
            ]),
        );
        let mut pipe = llm_pipe("on");
        // Judge present but disabled — its model is not enforced.
        pipe.judge = Some(
            serde_json::from_value(json!({
                "enabled": false,
                "llm": { "provider_type": "anthropic", "model": "off", "endpoint_url": "https://api.example" }
            }))
            .unwrap(),
        );
        assert!(LLMHandler::reject_disabled_models(&pipe, &catalog).is_ok());
    }

    #[test]
    fn rejects_disabled_enabled_juror_model() {
        let catalog = temp_catalog(
            "juror_off",
            json!([
                { "value": "on", "enabled": true },
                { "value": "off", "enabled": false },
            ]),
        );
        let mut pipe = llm_pipe("on");
        pipe.jury = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "jurors": [
                    { "enabled": true, "name": "J", "system_prompt": "",
                      "llm": { "provider_type": "anthropic", "model": "off", "endpoint_url": "https://api.example" } }
                ]
            }))
            .unwrap(),
        );
        let err = LLMHandler::reject_disabled_models(&pipe, &catalog).unwrap_err();
        assert!(err.contains("off"), "unexpected message: {err}");
    }

    #[test]
    fn skips_disabled_juror_entries() {
        let catalog = temp_catalog(
            "juror_skip",
            json!([
                { "value": "on", "enabled": true },
                { "value": "off", "enabled": false },
            ]),
        );
        let mut pipe = llm_pipe("on");
        pipe.jury = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "jurors": [
                    { "enabled": false, "name": "J", "system_prompt": "",
                      "llm": { "provider_type": "anthropic", "model": "off", "endpoint_url": "https://api.example" } }
                ]
            }))
            .unwrap(),
        );
        // The only juror referencing the disabled model is itself disabled.
        assert!(LLMHandler::reject_disabled_models(&pipe, &catalog).is_ok());
    }

    #[test]
    fn rejects_disabled_decider_candidate_model() {
        let catalog = temp_catalog(
            "decider_off",
            json!([
                { "value": "on", "enabled": true },
                { "value": "off", "enabled": false },
            ]),
        );
        let mut pipe = llm_pipe("on");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "llm": { "provider_type": "anthropic", "model": "on", "endpoint_url": "https://api.example" },
                "candidates": [
                    { "id": "a", "name": "A",
                      "llm": { "provider_type": "anthropic", "model": "off", "endpoint_url": "https://api.example" } }
                ]
            }))
            .unwrap(),
        );
        let err = LLMHandler::reject_disabled_models(&pipe, &catalog).unwrap_err();
        assert!(err.contains("off"), "unexpected message: {err}");
    }

    #[test]
    fn validate_config_rejects_decider_with_duplicate_candidate_ids() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "https://api.openai.com/v1/chat/completions" },
                "candidates": [
                    { "id": "dup", "name": "A",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } },
                    { "id": "dup", "name": "B",
                      "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } }
                ]
            }))
            .unwrap(),
        );
        let err = LLMHandler::validate_config(&pipe).unwrap_err();
        assert!(err.contains("duplicate"), "unexpected message: {err}");
    }

    #[test]
    fn validate_config_rejects_decider_candidate_metadata_endpoint() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "https://api.openai.com/v1/chat/completions" },
                "candidates": [
                    { "id": "ssrf", "name": "SSRF",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "http://169.254.169.254/latest/meta-data/" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_err());
    }

    #[test]
    fn validate_config_accepts_valid_decider() {
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "default_candidate_id": "fast",
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "https://api.openai.com/v1/chat/completions" },
                "candidates": [
                    { "id": "fast", "name": "Fast",
                      "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } },
                    { "id": "smart", "name": "Smart",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn validate_config_accepts_mirror_merge_with_merger() {
        // Mirror + Merge routes the main call to a dedicated merger, which must
        // clear the SSRF guard like any candidate.
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "strategy": "mirror",
                "mirror": {
                    "mode": "merge",
                    "merger": { "provider_type": "openai", "model": "gpt-4o",
                                "endpoint_url": "https://api.openai.com/v1/chat/completions" }
                },
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "https://api.openai.com/v1/chat/completions" },
                "candidates": [
                    { "id": "a", "name": "A",
                      "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } },
                    { "id": "b", "name": "B",
                      "llm": { "provider_type": "anthropic", "model": "claude-opus-4-8",
                               "endpoint_url": "/messages", "api_schema": "anthropic" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn validate_config_mirror_skips_unused_router_endpoint() {
        // Mirror never calls the router `llm`, so an unusable router endpoint
        // (here the cloud metadata IP) must not fail the save — only the
        // candidates and merger are dispatched and thus SSRF-checked.
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "strategy": "mirror",
                "mirror": { "mode": "collect" },
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "http://169.254.169.254/latest/meta-data/" },
                "candidates": [
                    { "id": "a", "name": "A",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn validate_config_rejects_mirror_merge_merger_metadata_endpoint() {
        // The merger is dispatched, so an SSRF-y merger endpoint must be rejected.
        let mut pipe = llm_pipe("gpt-4o-mini");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "strategy": "mirror",
                "mirror": {
                    "mode": "merge",
                    "merger": { "provider_type": "openai", "model": "gpt-4o",
                                "endpoint_url": "http://169.254.169.254/latest/meta-data/" }
                },
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini",
                         "endpoint_url": "https://api.openai.com/v1/chat/completions" },
                "candidates": [
                    { "id": "a", "name": "A",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "https://api.openai.com/v1/chat/completions" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_err());
    }

    #[test]
    fn validate_config_accepts_decider_with_relative_provider_endpoints() {
        // Reproduces a surface whose decider + candidates use relative provider
        // paths (Anthropic `/messages`, OpenAI `/chat/completions`). The runtime
        // resolves these against the provider default, so saving must not reject
        // them as "relative URL without a base".
        let mut pipe = llm_pipe("claude-opus-4-8");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "default_candidate_id": "a",
                "llm": { "provider_type": "anthropic", "model": "claude-opus-4-8",
                         "endpoint_url": "/messages", "api_schema": "anthropic" },
                "candidates": [
                    { "id": "a", "name": "Anthropic",
                      "llm": { "provider_type": "anthropic", "model": "claude-opus-4-8",
                               "endpoint_url": "/messages", "api_schema": "anthropic" } },
                    { "id": "b", "name": "OpenAI",
                      "llm": { "provider_type": "openai", "model": "gpt-4o",
                               "endpoint_url": "/chat/completions", "api_schema": "openai" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_ok());
    }

    #[test]
    fn validate_config_still_rejects_relative_endpoint_for_unknown_provider() {
        // An unknown provider can't be resolved, so a relative path stays
        // relative and is still rejected — the fix only accepts paths the
        // runtime can actually resolve to an absolute URL.
        let mut pipe = llm_pipe("m");
        pipe.decider = Some(
            serde_json::from_value(json!({
                "enabled": true,
                "default_candidate_id": "a",
                "llm": { "provider_type": "mystery", "model": "m",
                         "endpoint_url": "/chat", "api_schema": "openai" },
                "candidates": [
                    { "id": "a", "name": "A",
                      "llm": { "provider_type": "mystery", "model": "m",
                               "endpoint_url": "/chat", "api_schema": "openai" } }
                ]
            }))
            .unwrap(),
        );
        assert!(LLMHandler::validate_config(&pipe).is_err());
    }
}
