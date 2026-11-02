//! Pipe Variants — full-pipe snapshots addressed by `$alias`.
//!
//! A [`PipeVariant`] carries a delta over the base [`PipeConfig`]. Resolving
//! a variant produces a fully materialised `PipeConfig` with the variant's
//! overrides applied. A variant may override the full behavioural config of
//! the pipe — upstream (provider / model / endpoint / api key), guards
//! (prompt guard, judge, jury), resource controls (rate limit, circuit
//! breaker, retry), cost tracking, source auth, and inbound OPA policy —
//! while the pipe's identity (id, name, listener, route) stays fixed so the
//! variant is reachable at the same `IN_HOST/route$alias/...` path. This
//! mirrors how surface variants snapshot the whole surface behind a route
//! alias.

#![allow(dead_code)]

use serde::{Deserialize, Serialize};

use super::config::{
    CacheConfig, CircuitBreakerConfig, CostTrackingConfig, PipeConfig, PipeOpaConfig, PipeType, RateLimit, RetryPolicy,
    UsageAlert,
};

// ─── PipeVariant ────────────────────────────────────────────────────────────

/// A complete, named, switchable snapshot of a [`PipeConfig`], stored as a
/// sparse delta over the base.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipeVariant {
    /// Stable UUID identifier. Survives renames of `alias` and `name`.
    pub id: String,

    /// URL-safe alias used in `IN_HOST/route$alias/...`. Grammar:
    /// `^[a-z0-9-]{1,32}$`.
    pub alias: String,

    /// Human-readable name shown in the dashboard.
    pub name: String,

    /// Free-text description.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,

    /// Whether this variant accepts traffic. Disabled variants are still
    /// resolvable for UI display, but the proxy answers any request that
    /// selects a disabled variant with HTTP 503.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Sparse delta over the base pipe.
    #[serde(default, skip_serializing_if = "PipeVariantOverrides::is_empty")]
    pub overrides: PipeVariantOverrides,
}

impl PipeVariant {
    /// Compiled regex pattern for `alias` validation. Mirrored by the
    /// dashboard so both sides reject the same shapes.
    pub const ALIAS_PATTERN: &'static str = r"^[a-z0-9-]{1,32}$";

    /// Returns `Ok(())` if the alias matches `ALIAS_PATTERN`. The error
    /// message includes the offending alias for echoing back to the user.
    pub fn validate_alias(alias: &str) -> Result<(), String> {
        if alias.is_empty() {
            return Err("variant alias is required".to_string());
        }
        if alias.len() > 32 {
            return Err(format!("variant alias '{alias}' must be 32 characters or fewer"));
        }
        for c in alias.chars() {
            if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-') {
                return Err(format!("variant alias '{alias}' may only contain lowercase letters, digits, and dashes"));
            }
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

// ─── PipeVariantOverrides ───────────────────────────────────────────────────

/// A delta over a [`PipeConfig`].
///
/// Two semantics are supported, selected by the `complete` flag:
///
/// - `complete: false` (default, legacy) — sparse merge. `None` at any
///   `Option<T>` field means "inherit from base"; `Some(v)` means "use
///   `v`". This is the original upstream-only behaviour: a variant that
///   only sets `pipe_type` swaps the upstream and inherits everything else.
/// - `complete: true` — frozen snapshot. Every overridable field is
///   wholesale-replaced from the override, including `Option<T>` fields set
///   to `None` (which clear base's value). Non-optional base fields
///   (`pipe_type`, `request_timeout_seconds`) keep base when the override
///   leaves them unset. Use this when the variant is a fully-snapshotted
///   copy of the pipe and must not silently inherit later base edits.
///
/// The pipe's identity (id, name, listener, route, metrics/log toggles,
/// integrations) is never overridable — those define where the variant is
/// reachable and how it is observed, which must match the base.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PipeVariantOverrides {
    /// Wholesale-replace flag — see struct docs.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub complete: bool,

    /// Upstream the variant routes to — provider, model, endpoint, and api
    /// key all live inside `PipeType`. Replaces the base upstream when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pipe_type: Option<PipeType>,

    /// LLM parameter override policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub override_policy: Option<crate::pipes::types::llm::ParameterOverrideConfig>,

    /// Prompt-guard content filtering for requests/responses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_guard: Option<crate::pipes::prompt_guard::PromptGuardConfig>,

    /// Judge — LLM-based pre-processing validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::pipes::judge_jury::JudgeConfig>,

    /// Jury — LLM-based post-processing validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jury: Option<crate::pipes::judge_jury::JuryConfig>,

    /// Expert witnesses — external safety classifiers consulted at the
    /// request/response seams. `Some` replaces the base list wholesale (an
    /// empty vec clears all witnesses); `None` inherits the base list.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expert_witnesses: Option<Vec<crate::pipes::prompt_guard::ExpertWitnessConfig>>,

    /// Inbound rate limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,

    /// Circuit breaker.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,

    /// Retry policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_policy: Option<RetryPolicy>,

    /// Cost tracking.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost_tracking: Option<CostTrackingConfig>,

    /// Budget/usage alerts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_alerts: Option<Vec<UsageAlert>>,

    /// Response cache.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Source authentication (jwt_bearer / api_key / mtls).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<crate::source_auth::SourceAuthConfig>,

    /// Inbound OPA (Rego) policy enforcement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa_policy: Option<PipeOpaConfig>,

    /// Identity pass-through credential mode. `None` inherits the base;
    /// `Some(true/false)` sets whether the caller's inbound bearer token is
    /// forwarded as the outbound credential for this variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forward_caller_token: Option<bool>,

    /// Extra upstream headers for this variant. `Some` replaces the base list
    /// wholesale (an empty vec sends none). A variant that overrides
    /// `pipe_type` and leaves this unset inherits **nothing**: the base's
    /// headers are credentials for the base upstream, which the variant no
    /// longer calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_headers: Option<Vec<crate::pipes::upstream_headers::UpstreamHeader>>,

    /// Declared price of this variant's upstream. Like `upstream_headers`, a
    /// variant that overrides `pipe_type` and leaves this unset inherits
    /// **no** price: the base's price is the base upstream's.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_pricing: Option<crate::pipes::types::llm::TargetPricing>,

    /// HTTP request timeout in seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timeout_seconds: Option<u64>,

    /// Realtime voice (Mode C) opt-in. Lets a variant front a realtime-capable
    /// model with its own session/safety config while sibling variants stay
    /// chat-only — so one surface can route WebSocket voice to a voice variant
    /// and chat to others.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realtime: Option<crate::pipes::realtime::RealtimeConfig>,

    /// Inbound audio-file (`input_audio`) opt-in, per variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_input: Option<crate::pipes::audio::AudioInputConfig>,

    /// Inbound image (`image_url`) opt-in, per variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_input: Option<crate::pipes::image_input::ImageInputConfig>,

    /// Attached-document ingestion opt-in, per variant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_ingestion: Option<crate::pipes::document_ingestion::DocumentIngestionConfig>,

    /// Per-variant override of the management dashboard's opaque canvas
    /// blob (positions, viewport, canvas-only nodes). When `Some`,
    /// replaces the base pipe's `canvas` wholesale at resolve time. The
    /// runtime never reads this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas: Option<serde_json::Value>,
}

impl PipeVariantOverrides {
    /// `true` when no field is overridden — equivalent to "this variant is
    /// identical to base." The `complete` flag is ignored: a complete
    /// override with no payload fields is still semantically empty.
    pub fn is_empty(&self) -> bool {
        self.pipe_type.is_none()
            && self.override_policy.is_none()
            && self.prompt_guard.is_none()
            && self.judge.is_none()
            && self.jury.is_none()
            && self
                .expert_witnesses
                .is_none()
            && self.rate_limit.is_none()
            && self.circuit_breaker.is_none()
            && self.retry_policy.is_none()
            && self.cost_tracking.is_none()
            && self.usage_alerts.is_none()
            && self.cache.is_none()
            && self.source_auth.is_none()
            && self.opa_policy.is_none()
            && self
                .forward_caller_token
                .is_none()
            && self
                .upstream_headers
                .is_none()
            && self
                .upstream_pricing
                .is_none()
            && self
                .request_timeout_seconds
                .is_none()
            && self.realtime.is_none()
            && self.audio_input.is_none()
            && self.image_input.is_none()
            && self
                .document_ingestion
                .is_none()
            && self.canvas.is_none()
    }
}

// ─── Validation ─────────────────────────────────────────────────────────────

/// Errors returned by [`PipeConfig::validate_variants`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantValidationError {
    /// A variant's `alias` failed grammar validation.
    InvalidAlias { id: String, reason: String },
    /// Two variants on the same pipe share an alias.
    DuplicateAlias(String),
    /// Two variants on the same pipe share an id.
    DuplicateId(String),
    /// `default_variant_id` is set but no variant has that id.
    DefaultMissing(String),
}

impl std::fmt::Display for VariantValidationError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::InvalidAlias { id, reason } => write!(f, "variant '{id}': {reason}"),
            Self::DuplicateAlias(a) => write!(f, "duplicate variant alias '{a}'"),
            Self::DuplicateId(i) => write!(f, "duplicate variant id '{i}'"),
            Self::DefaultMissing(i) => write!(f, "default_variant_id '{i}' does not match any variant"),
        }
    }
}

impl std::error::Error for VariantValidationError {}

// ─── Resolver ───────────────────────────────────────────────────────────────

/// Errors returned by [`PipeConfig::resolve_variant`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VariantResolveError {
    /// A `$alias` was supplied but no variant on the pipe matches.
    UnknownAlias(String),
    /// The matched variant is `enabled: false`.
    DisabledVariant(String),
    /// `default_variant_id` is set but no variant has that id.
    MisconfiguredDefault(String),
}

impl std::fmt::Display for VariantResolveError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::UnknownAlias(a) => write!(f, "no variant with alias '{a}' on this pipe"),
            Self::DisabledVariant(a) => write!(f, "variant '{a}' is disabled"),
            Self::MisconfiguredDefault(id) => {
                write!(f, "default_variant_id '{id}' does not match any variant")
            }
        }
    }
}

impl std::error::Error for VariantResolveError {}

impl PipeConfig {
    /// Resolve a variant by alias and return a fully-materialised
    /// `PipeConfig` with that variant's overrides applied.
    ///
    /// - When `alias` is `Some`, the named variant is selected.
    /// - When `alias` is `None`, the default variant is selected.
    /// - When the pipe has no `variants[]` (or it is empty), the pipe is
    ///   returned as-is regardless of `alias`.
    ///
    /// The returned pipe has its `variants[]` cleared and
    /// `default_variant_id` set to `None` — the runtime never sees the
    /// variant catalog because resolution has already happened.
    pub fn resolve_variant(
        &self,
        alias: Option<&str>,
    ) -> Result<PipeConfig, VariantResolveError> {
        if self.variants.is_empty() {
            let mut clone = self.clone();
            clone.variants.clear();
            clone.default_variant_id = None;
            clone.normalize_guardrails();
            return Ok(clone);
        }

        let target_alias = match alias {
            Some(a) => a.to_string(),
            None => match &self.default_variant_id {
                Some(id) => match self
                    .variants
                    .iter()
                    .find(|v| &v.id == id)
                {
                    Some(v) => v.alias.clone(),
                    None => return Err(VariantResolveError::MisconfiguredDefault(id.clone())),
                },
                None => {
                    let mut clone = self.clone();
                    clone.variants.clear();
                    clone.default_variant_id = None;
                    clone.normalize_guardrails();
                    return Ok(clone);
                }
            },
        };

        let variant = match self
            .variants
            .iter()
            .find(|v| v.alias == target_alias)
        {
            Some(v) => v,
            None => return Err(VariantResolveError::UnknownAlias(target_alias)),
        };

        if !variant.enabled {
            return Err(VariantResolveError::DisabledVariant(target_alias));
        }

        let mut resolved = self.clone();
        resolved.variants.clear();
        resolved.default_variant_id = None;

        let overrides = variant.overrides.clone();
        let swaps_upstream = overrides.pipe_type.is_some();
        if overrides.complete {
            // Frozen snapshot: every overridable field is taken from the
            // variant, including `None` (which clears base's value). The
            // two non-optional base fields keep base when left unset.
            if let Some(pipe_type) = overrides.pipe_type {
                resolved.pipe_type = pipe_type;
            }
            resolved.override_policy = overrides.override_policy;
            resolved.prompt_guard = overrides.prompt_guard;
            resolved.judge = overrides.judge;
            resolved.jury = overrides.jury;
            resolved.expert_witnesses = overrides
                .expert_witnesses
                .unwrap_or_default();
            resolved.rate_limit = overrides.rate_limit;
            resolved.circuit_breaker = overrides.circuit_breaker;
            resolved.retry_policy = overrides.retry_policy;
            resolved.cost_tracking = overrides.cost_tracking;
            resolved.usage_alerts = overrides.usage_alerts;
            resolved.cache = overrides.cache;
            resolved.source_auth = overrides.source_auth;
            resolved.opa_policy = overrides.opa_policy;
            resolved.realtime = overrides.realtime;
            resolved.audio_input = overrides.audio_input;
            resolved.image_input = overrides.image_input;
            resolved.document_ingestion = overrides.document_ingestion;
            resolved.forward_caller_token = overrides
                .forward_caller_token
                .unwrap_or(false);
            resolved.upstream_headers = overrides
                .upstream_headers
                .unwrap_or_default();
            resolved.upstream_pricing = overrides.upstream_pricing;
            if let Some(timeout) = overrides.request_timeout_seconds {
                resolved.request_timeout_seconds = timeout;
            }
            if let Some(canvas) = overrides.canvas {
                resolved.canvas = Some(canvas);
            }
        } else {
            // Sparse merge: apply only the fields the variant sets; `None`
            // inherits from base.
            if let Some(pipe_type) = overrides.pipe_type {
                resolved.pipe_type = pipe_type;
            }
            if overrides
                .override_policy
                .is_some()
            {
                resolved.override_policy = overrides.override_policy;
            }
            if overrides
                .prompt_guard
                .is_some()
            {
                resolved.prompt_guard = overrides.prompt_guard;
            }
            if overrides.judge.is_some() {
                resolved.judge = overrides.judge;
            }
            if overrides.jury.is_some() {
                resolved.jury = overrides.jury;
            }
            if let Some(witnesses) = overrides.expert_witnesses {
                resolved.expert_witnesses = witnesses;
            }
            if overrides.rate_limit.is_some() {
                resolved.rate_limit = overrides.rate_limit;
            }
            if overrides
                .circuit_breaker
                .is_some()
            {
                resolved.circuit_breaker = overrides.circuit_breaker;
            }
            if overrides
                .retry_policy
                .is_some()
            {
                resolved.retry_policy = overrides.retry_policy;
            }
            if overrides
                .cost_tracking
                .is_some()
            {
                resolved.cost_tracking = overrides.cost_tracking;
            }
            if overrides
                .usage_alerts
                .is_some()
            {
                resolved.usage_alerts = overrides.usage_alerts;
            }
            if overrides.cache.is_some() {
                resolved.cache = overrides.cache;
            }
            if overrides
                .source_auth
                .is_some()
            {
                resolved.source_auth = overrides.source_auth;
            }
            if overrides.opa_policy.is_some() {
                resolved.opa_policy = overrides.opa_policy;
            }
            if let Some(forward) = overrides.forward_caller_token {
                resolved.forward_caller_token = forward;
            }
            // Extra upstream headers are credentials for the upstream they
            // were configured against: a variant that swaps the upstream and
            // names none sends none.
            if let Some(headers) = overrides.upstream_headers {
                resolved.upstream_headers = headers;
            } else if swaps_upstream {
                resolved
                    .upstream_headers
                    .clear();
            }
            // A declared price is the upstream's too.
            if overrides
                .upstream_pricing
                .is_some()
                || swaps_upstream
            {
                resolved.upstream_pricing = overrides.upstream_pricing;
            }
            if let Some(timeout) = overrides.request_timeout_seconds {
                resolved.request_timeout_seconds = timeout;
            }
            if overrides.realtime.is_some() {
                resolved.realtime = overrides.realtime;
            }
            if overrides
                .audio_input
                .is_some()
            {
                resolved.audio_input = overrides.audio_input;
            }
            if overrides
                .image_input
                .is_some()
            {
                resolved.image_input = overrides.image_input;
            }
            if overrides
                .document_ingestion
                .is_some()
            {
                resolved.document_ingestion = overrides.document_ingestion;
            }
            if let Some(canvas) = overrides.canvas {
                resolved.canvas = Some(canvas);
            }
        }

        resolved.normalize_guardrails();
        Ok(resolved)
    }

    /// Return the alias of the default variant, if any. Returns `None`
    /// when the pipe has no variants or `default_variant_id` is unset or
    /// doesn't match.
    pub fn default_variant_alias(&self) -> Option<&str> {
        let id = self
            .default_variant_id
            .as_ref()?;
        self.variants
            .iter()
            .find(|v| &v.id == id)
            .map(|v| v.alias.as_str())
    }

    /// Validate the variant catalog on this pipe:
    ///
    /// - Every variant's `alias` matches [`PipeVariant::ALIAS_PATTERN`].
    /// - Aliases are unique within the pipe.
    /// - Ids are unique within the pipe.
    /// - `default_variant_id`, when set, matches an existing variant.
    ///
    /// Empty `variants[]` is considered valid.
    pub fn validate_variants(&self) -> Result<(), VariantValidationError> {
        if self.variants.is_empty() {
            return Ok(());
        }

        let mut seen_aliases: std::collections::HashSet<&str> = std::collections::HashSet::new();
        let mut seen_ids: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for v in &self.variants {
            PipeVariant::validate_alias(&v.alias)
                .map_err(|reason| VariantValidationError::InvalidAlias { id: v.id.clone(), reason })?;
            if !seen_aliases.insert(v.alias.as_str()) {
                return Err(VariantValidationError::DuplicateAlias(v.alias.clone()));
            }
            if !seen_ids.insert(v.id.as_str()) {
                return Err(VariantValidationError::DuplicateId(v.id.clone()));
            }
        }

        match &self.default_variant_id {
            None => Ok(()),
            Some(id) => {
                if self
                    .variants
                    .iter()
                    .any(|v| &v.id == id)
                {
                    Ok(())
                } else {
                    Err(VariantValidationError::DefaultMissing(id.clone()))
                }
            }
        }
    }

    /// Whether `resolved`, a variant of this surface after resolution, calls
    /// the surface's default upstream (its default variant's, else the base's):
    /// the same provider type at the same origin. Only that upstream may be
    /// sent the caller's own key or token; a variant that swaps the provider
    /// or the origin is another upstream, like a failover target.
    pub fn keeps_default_upstream(
        &self,
        resolved: &PipeConfig,
    ) -> bool {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        let default = self
            .default_variant_id
            .as_ref()
            .and_then(|id| {
                self.variants
                    .iter()
                    .find(|v| &v.id == id)
            })
            .and_then(|v| v.overrides.pipe_type.as_ref())
            .unwrap_or(&self.pipe_type);
        match (default, &resolved.pipe_type) {
            (PipeType::LLM { provider: default, .. }, PipeType::LLM { provider: resolved, .. }) => {
                std::mem::discriminant(default.as_ref()) == std::mem::discriminant(resolved.as_ref())
                    && crate::pipes::upstream_headers::same_origin(&default.get_endpoint(), &resolved.get_endpoint())
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::types::llm::LLMProvider;

    fn base_pipe() -> PipeConfig {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key_secret: Some("secret-base".to_string()),
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        let mut pipe = PipeConfig::new(
            "pipe-1".to_string(),
            "Base Pipe".to_string(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        );
        pipe.route = Some("/llm".to_string());
        pipe
    }

    #[test]
    fn only_a_variant_on_the_default_upstreams_provider_and_origin_keeps_it() {
        let mut pipe = base_pipe();
        let same_upstream = variant_with_model("v-model", "model", "gpt-4o-mini", "secret-base");
        let mut other_origin = variant_with_model("v-origin", "origin", "gpt-4o", "secret-base");
        if let Some(PipeType::LLM { provider, .. }) = &mut other_origin
            .overrides
            .pipe_type
            && let LLMProvider::OpenAI { base_url, .. } = provider.as_mut()
        {
            *base_url = Some("https://gateway.example/v1".to_string());
        }
        let mut other_provider = variant_with_model("v-provider", "provider", "claude", "secret-base");
        other_provider
            .overrides
            .pipe_type = Some(PipeType::LLM {
            provider: Box::new(
                serde_json::from_value(serde_json::json!({ "provider_type": "anthropic", "model": "claude" }))
                    .expect("anthropic provider"),
            ),
            endpoint_path: None,
        });
        pipe.variants = vec![same_upstream, other_origin, other_provider];

        let keeps = |pipe: &PipeConfig, alias: &str| {
            pipe.keeps_default_upstream(
                &pipe
                    .resolve_variant(Some(alias))
                    .expect("resolves"),
            )
        };
        assert!(keeps(&pipe, "model"), "a model swap keeps the upstream");
        assert!(!keeps(&pipe, "origin"), "another origin");
        assert!(!keeps(&pipe, "provider"), "another provider");

        // With a default variant, the default upstream is that variant's.
        pipe.default_variant_id = Some("v-origin".to_string());
        assert!(keeps(&pipe, "origin"));
        assert!(!keeps(&pipe, "model"));
    }

    fn variant_with_model(
        id: &str,
        alias: &str,
        model: &str,
        secret: &str,
    ) -> PipeVariant {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: model.to_string(),
            api_key_secret: Some(secret.to_string()),
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        PipeVariant {
            id: id.to_string(),
            alias: alias.to_string(),
            name: format!("Variant {alias}"),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                pipe_type: Some(PipeType::LLM {
                    provider: Box::new(provider),
                    endpoint_path: None,
                }),
                ..Default::default()
            },
        }
    }

    #[test]
    fn validate_alias_accepts_valid() {
        assert!(PipeVariant::validate_alias("prod-eu").is_ok());
        assert!(PipeVariant::validate_alias("v2").is_ok());
        assert!(PipeVariant::validate_alias("a").is_ok());
    }

    #[test]
    fn validate_alias_rejects_invalid() {
        assert!(PipeVariant::validate_alias("").is_err());
        assert!(PipeVariant::validate_alias("Prod").is_err());
        assert!(PipeVariant::validate_alias("has space").is_err());
        assert!(PipeVariant::validate_alias("under_score").is_err());
        assert!(PipeVariant::validate_alias(&"x".repeat(33)).is_err());
    }

    #[test]
    fn alias_grammar_forbids_key_separators() {
        // The `$` (variant) and `#` (IDE member) key separators must be rejected
        // by the alias grammar — this is what guarantees a variant/member key can
        // never be forged to collide with a base pipe key (`pipe_id`), a variant
        // key (`pipe_id$alias`), or a member key (`ide_id#...`).
        assert!(PipeVariant::validate_alias("fast$slow").is_err());
        assert!(PipeVariant::validate_alias("a#b").is_err());
        assert!(PipeVariant::validate_alias("$").is_err());
        assert!(PipeVariant::validate_alias("#").is_err());
    }

    #[test]
    fn no_variants_returns_base_unchanged() {
        let pipe = base_pipe();
        let resolved = pipe
            .resolve_variant(Some("anything"))
            .expect("resolves");
        assert!(resolved.variants.is_empty());
        assert_eq!(resolved.default_variant_id, None);
        match resolved.pipe_type {
            PipeType::LLM { provider, .. } => {
                assert_eq!(provider.model_name(), "gpt-4o");
            }
            _ => panic!("expected LLM pipe type"),
        }
    }

    #[test]
    fn resolve_named_variant_swaps_upstream() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert!(resolved.variants.is_empty());
        match resolved.pipe_type {
            PipeType::LLM { provider, .. } => {
                assert_eq!(provider.model_name(), "gpt-4o-mini");
                match provider.as_ref() {
                    LLMProvider::OpenAI { api_key_secret, .. } => {
                        assert_eq!(api_key_secret.as_deref(), Some("secret-fast"));
                    }
                    _ => panic!("expected OpenAI provider"),
                }
            }
            _ => panic!("expected LLM pipe type"),
        }
    }

    #[test]
    fn a_variant_that_swaps_the_upstream_drops_the_base_upstream_headers() {
        // The base's extra headers authenticate the base upstream; a variant
        // pointing somewhere else must not carry them there.
        let mut pipe = base_pipe();
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");

        assert!(
            resolved
                .upstream_headers
                .is_empty(),
            "an upstream-swapping variant must not inherit the base upstream's headers"
        );
    }

    #[test]
    fn a_variant_keeps_the_base_upstream_headers_when_it_keeps_the_upstream() {
        let mut pipe = base_pipe();
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        pipe.variants = vec![PipeVariant {
            id: "slow".to_string(),
            alias: "slow".to_string(),
            name: "Slow".to_string(),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                request_timeout_seconds: Some(120),
                ..Default::default()
            },
        }];

        let resolved = pipe
            .resolve_variant(Some("slow"))
            .expect("resolves");

        assert_eq!(
            resolved
                .upstream_headers
                .len(),
            1
        );
        assert_eq!(
            resolved.upstream_headers[0]
                .name
                .as_str(),
            "x-asp-api-key"
        );
    }

    #[test]
    fn a_variant_may_declare_its_own_upstream_headers() {
        let mut pipe = base_pipe();
        pipe.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant
            .overrides
            .upstream_headers = Some(vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-mesh-token".to_string(),
            secret_id: "mesh-secret".to_string(),
        }]);
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");

        assert_eq!(
            resolved
                .upstream_headers
                .len(),
            1
        );
        assert_eq!(
            resolved.upstream_headers[0]
                .name
                .as_str(),
            "x-mesh-token"
        );
    }

    fn free() -> crate::pipes::types::llm::TargetPricing {
        crate::pipes::types::llm::TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        }
    }

    #[test]
    fn a_variant_that_swaps_the_upstream_drops_the_base_upstream_price() {
        // A free own model as the base must not make a catalog model that a
        // variant swaps in free too.
        let mut pipe = base_pipe();
        pipe.upstream_pricing = Some(free());
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");

        assert_eq!(resolved.upstream_pricing, None);
    }

    #[test]
    fn a_variant_keeps_or_declares_the_upstream_price() {
        let mut pipe = base_pipe();
        pipe.upstream_pricing = Some(free());
        let mut priced = variant_with_model("var-2", "own", "gpt-4o-mini", "secret-own");
        priced
            .overrides
            .upstream_pricing = Some(free());
        pipe.variants = vec![
            PipeVariant {
                id: "slow".to_string(),
                alias: "slow".to_string(),
                name: "Slow".to_string(),
                description: String::new(),
                enabled: true,
                overrides: PipeVariantOverrides {
                    request_timeout_seconds: Some(120),
                    ..Default::default()
                },
            },
            priced,
        ];

        let kept = pipe
            .resolve_variant(Some("slow"))
            .expect("resolves");
        assert_eq!(kept.upstream_pricing, Some(free()));

        let declared = pipe
            .resolve_variant(Some("own"))
            .expect("resolves");
        assert_eq!(declared.upstream_pricing, Some(free()));
    }

    #[test]
    fn resolve_variant_overrides_realtime_and_modality() {
        let mut pipe = base_pipe();
        pipe.variants = vec![PipeVariant {
            id: "voice".to_string(),
            alias: "voice".to_string(),
            name: "Voice".to_string(),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                realtime: Some(crate::pipes::realtime::RealtimeConfig {
                    enabled: true,
                    max_session_secs: 900,
                    ..Default::default()
                }),
                audio_input: Some(crate::pipes::audio::AudioInputConfig {
                    enabled: true,
                    ..Default::default()
                }),
                ..Default::default()
            },
        }];
        let resolved = pipe
            .resolve_variant(Some("voice"))
            .expect("resolves");
        let rt = resolved
            .realtime
            .expect("variant sets realtime");
        assert!(rt.enabled);
        assert_eq!(rt.max_session_secs, 900);
        assert!(
            resolved
                .audio_input
                .expect("variant sets audio_input")
                .enabled
        );
        // A field the variant leaves unset inherits base (None here) in the
        // default sparse-merge mode.
        assert!(resolved.image_input.is_none());
    }

    #[test]
    fn resolve_default_variant_when_alias_none() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        pipe.default_variant_id = Some("var-1".to_string());
        let resolved = pipe
            .resolve_variant(None)
            .expect("resolves");
        match resolved.pipe_type {
            PipeType::LLM { provider, .. } => assert_eq!(provider.model_name(), "gpt-4o-mini"),
            _ => panic!("expected LLM pipe type"),
        }
    }

    #[test]
    fn variant_overrides_forward_caller_token() {
        let mut pipe = base_pipe();
        pipe.variants = vec![PipeVariant {
            id: "v1".to_string(),
            alias: "passthru".to_string(),
            name: "Passthrough".to_string(),
            description: String::new(),
            enabled: true,
            overrides: PipeVariantOverrides {
                forward_caller_token: Some(true),
                ..Default::default()
            },
        }];
        let resolved = pipe
            .resolve_variant(Some("passthru"))
            .expect("resolves");
        assert!(resolved.forward_caller_token);

        // Base stays false when no variant overrides it.
        let base = base_pipe()
            .resolve_variant(None)
            .expect("resolves");
        assert!(!base.forward_caller_token);
    }

    #[test]
    fn resolve_none_without_default_returns_base() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        let resolved = pipe
            .resolve_variant(None)
            .expect("resolves");
        match resolved.pipe_type {
            PipeType::LLM { provider, .. } => assert_eq!(provider.model_name(), "gpt-4o"),
            _ => panic!("expected LLM pipe type"),
        }
    }

    #[test]
    fn resolve_unknown_alias_errors() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        let err = pipe
            .resolve_variant(Some("missing"))
            .unwrap_err();
        assert_eq!(err, VariantResolveError::UnknownAlias("missing".to_string()));
    }

    #[test]
    fn resolve_disabled_variant_errors() {
        let mut pipe = base_pipe();
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.enabled = false;
        pipe.variants = vec![variant];
        let err = pipe
            .resolve_variant(Some("fast"))
            .unwrap_err();
        assert_eq!(err, VariantResolveError::DisabledVariant("fast".to_string()));
    }

    #[test]
    fn resolve_misconfigured_default_errors() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        pipe.default_variant_id = Some("does-not-exist".to_string());
        let err = pipe
            .resolve_variant(None)
            .unwrap_err();
        assert_eq!(err, VariantResolveError::MisconfiguredDefault("does-not-exist".to_string()));
    }

    #[test]
    fn resolve_applies_canvas_override() {
        let mut pipe = base_pipe();
        pipe.canvas = Some(serde_json::json!({"base": true}));
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.canvas = Some(serde_json::json!({"variant": "fast"}));
        pipe.variants = vec![variant];
        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert_eq!(resolved.canvas, Some(serde_json::json!({"variant": "fast"})));
    }

    #[test]
    fn default_variant_alias_returns_alias() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        pipe.default_variant_id = Some("var-1".to_string());
        assert_eq!(pipe.default_variant_alias(), Some("fast"));
    }

    #[test]
    fn default_variant_alias_none_when_unset() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast")];
        assert_eq!(pipe.default_variant_alias(), None);
    }

    #[test]
    fn validate_variants_accepts_valid_catalog() {
        let mut pipe = base_pipe();
        pipe.variants = vec![
            variant_with_model("var-1", "fast", "gpt-4o-mini", "s1"),
            variant_with_model("var-2", "slow", "gpt-4o", "s2"),
        ];
        pipe.default_variant_id = Some("var-1".to_string());
        assert_eq!(pipe.validate_variants(), Ok(()));
    }

    #[test]
    fn validate_variants_rejects_duplicate_alias() {
        let mut pipe = base_pipe();
        pipe.variants = vec![
            variant_with_model("var-1", "fast", "gpt-4o-mini", "s1"),
            variant_with_model("var-2", "fast", "gpt-4o", "s2"),
        ];
        assert_eq!(pipe.validate_variants(), Err(VariantValidationError::DuplicateAlias("fast".to_string())));
    }

    #[test]
    fn validate_variants_rejects_duplicate_id() {
        let mut pipe = base_pipe();
        pipe.variants = vec![
            variant_with_model("var-1", "fast", "gpt-4o-mini", "s1"),
            variant_with_model("var-1", "slow", "gpt-4o", "s2"),
        ];
        assert_eq!(pipe.validate_variants(), Err(VariantValidationError::DuplicateId("var-1".to_string())));
    }

    #[test]
    fn validate_variants_rejects_invalid_alias() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "Bad Alias", "gpt-4o-mini", "s1")];
        match pipe.validate_variants() {
            Err(VariantValidationError::InvalidAlias { id, .. }) => assert_eq!(id, "var-1"),
            other => panic!("expected InvalidAlias, got {other:?}"),
        }
    }

    #[test]
    fn validate_variants_rejects_missing_default() {
        let mut pipe = base_pipe();
        pipe.variants = vec![variant_with_model("var-1", "fast", "gpt-4o-mini", "s1")];
        pipe.default_variant_id = Some("nope".to_string());
        assert_eq!(pipe.validate_variants(), Err(VariantValidationError::DefaultMissing("nope".to_string())));
    }

    #[test]
    fn overrides_is_empty_detects_empty() {
        assert!(PipeVariantOverrides::default().is_empty());
        let with_canvas = PipeVariantOverrides {
            canvas: Some(serde_json::json!({})),
            ..Default::default()
        };
        assert!(!with_canvas.is_empty());
        // The `complete` flag alone is still semantically empty.
        let complete_empty = PipeVariantOverrides {
            complete: true,
            ..Default::default()
        };
        assert!(complete_empty.is_empty());
    }

    #[test]
    fn variant_roundtrips_through_json() {
        let variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        let json = serde_json::to_string(&variant).expect("serializes");
        let parsed: PipeVariant = serde_json::from_str(&json).expect("deserializes");
        assert_eq!(parsed.id, "var-1");
        assert_eq!(parsed.alias, "fast");
        assert!(
            parsed
                .overrides
                .pipe_type
                .is_some()
        );
    }

    fn rate_limit(rpm: u32) -> RateLimit {
        let json = serde_json::json!({ "requests_per_minute": rpm });
        serde_json::from_value(json).expect("rate limit deserializes")
    }

    #[test]
    fn complete_snapshot_clears_unset_optional_fields() {
        let mut pipe = base_pipe();
        pipe.rate_limit = Some(rate_limit(100));
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = true;
        // Variant leaves rate_limit unset -> complete snapshot clears it.
        variant.overrides.rate_limit = None;
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert!(resolved.rate_limit.is_none(), "complete snapshot must clear base rate_limit");
        match resolved.pipe_type {
            PipeType::LLM { provider, .. } => assert_eq!(provider.model_name(), "gpt-4o-mini"),
            _ => panic!("expected LLM pipe type"),
        }
    }

    #[test]
    fn complete_snapshot_applies_overridden_fields() {
        let mut pipe = base_pipe();
        pipe.rate_limit = Some(rate_limit(100));
        pipe.request_timeout_seconds = 30;
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = true;
        variant.overrides.rate_limit = Some(rate_limit(5));
        variant
            .overrides
            .request_timeout_seconds = Some(90);
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert_eq!(
            resolved
                .rate_limit
                .as_ref()
                .map(|r| serde_json::to_value(r).unwrap()["requests_per_minute"].as_u64()),
            Some(Some(5))
        );
        assert_eq!(resolved.request_timeout_seconds, 90);
    }

    #[test]
    fn sparse_override_inherits_unset_fields() {
        let mut pipe = base_pipe();
        pipe.rate_limit = Some(rate_limit(100));
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        // Sparse (complete = false): rate_limit unset -> inherit base.
        variant.overrides.complete = false;
        variant.overrides.rate_limit = None;
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert!(resolved.rate_limit.is_some(), "sparse override must inherit base rate_limit");
    }

    #[test]
    fn sparse_override_applies_cache() {
        let mut pipe = base_pipe();
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = false;
        variant.overrides.cache = Some(CacheConfig {
            enabled: true,
            ttl_seconds: 120,
            max_entries: 50,
            ..Default::default()
        });
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        let cache = resolved
            .cache
            .as_ref()
            .expect("variant cache applied");
        assert!(cache.enabled);
        assert_eq!(cache.ttl_seconds, 120);
        assert_eq!(cache.max_entries, 50);
    }

    #[test]
    fn complete_snapshot_clears_unset_cache() {
        let mut pipe = base_pipe();
        pipe.cache = Some(CacheConfig {
            enabled: true,
            ttl_seconds: 60,
            max_entries: 10,
            ..Default::default()
        });
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = true;
        // Variant leaves cache unset -> complete snapshot clears base cache.
        variant.overrides.cache = None;
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert!(resolved.cache.is_none(), "complete snapshot must clear base cache");
    }

    fn witness(id: &str) -> crate::pipes::prompt_guard::ExpertWitnessConfig {
        crate::pipes::prompt_guard::ExpertWitnessConfig {
            id: id.to_string(),
            name: id.to_string(),
            guardrail: crate::pipes::prompt_guard::ExternalGuardrailConfig {
                enabled: true,
                provider: crate::pipes::prompt_guard::ExternalGuardrailProvider::Enkryptai,
                endpoint_url: "https://api.enkryptai.com/guardrails/detect".to_string(),
                api_key_secret: Some("sec-1".to_string()),
                timeout_secs: 10,
                fail_open: false,
                check_request: true,
                check_response: true,
                headers: Default::default(),
                model: None,
                detectors: None,
                rejection: None,
                profile: None,
            },
        }
    }

    #[test]
    fn sparse_override_replaces_expert_witnesses() {
        let mut pipe = base_pipe();
        pipe.expert_witnesses = vec![witness("base")];
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = false;
        variant
            .overrides
            .expert_witnesses = Some(vec![witness("variant")]);
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        assert_eq!(
            resolved
                .expert_witnesses
                .len(),
            1
        );
        assert_eq!(resolved.expert_witnesses[0].id, "variant");
    }

    #[test]
    fn sparse_override_inherits_expert_witnesses_when_unset() {
        let mut pipe = base_pipe();
        pipe.expert_witnesses = vec![witness("base")];
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = false;
        variant
            .overrides
            .expert_witnesses = None;
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        // None inherits the base list.
        assert_eq!(
            resolved
                .expert_witnesses
                .len(),
            1
        );
        assert_eq!(resolved.expert_witnesses[0].id, "base");
    }

    #[test]
    fn complete_snapshot_clears_expert_witnesses_when_unset() {
        let mut pipe = base_pipe();
        pipe.expert_witnesses = vec![witness("base")];
        let mut variant = variant_with_model("var-1", "fast", "gpt-4o-mini", "secret-fast");
        variant.overrides.complete = true;
        variant
            .overrides
            .expert_witnesses = None;
        pipe.variants = vec![variant];

        let resolved = pipe
            .resolve_variant(Some("fast"))
            .expect("resolves");
        // Frozen snapshot with no witnesses clears the base list.
        assert!(
            resolved
                .expert_witnesses
                .is_empty()
        );
    }

    #[test]
    fn resolve_variant_migrates_legacy_external_into_witness() {
        // Base carries the legacy `prompt_guard.external` block and no
        // witnesses; resolving (even with no variants) migrates it so the
        // runtime + streaming-eligibility check see an expert witness.
        let mut pipe = base_pipe();
        pipe.prompt_guard = Some(crate::pipes::prompt_guard::PromptGuardConfig {
            enabled: true,
            request: Vec::new(),
            response: Vec::new(),
            external: Some(witness("legacy").guardrail),
            llm_pii: Vec::new(),
        });

        let resolved = pipe
            .resolve_variant(None)
            .expect("resolves");
        assert_eq!(
            resolved
                .expert_witnesses
                .len(),
            1
        );
        assert_eq!(resolved.expert_witnesses[0].id, "migrated-external-guardrail");
        assert!(
            resolved
                .prompt_guard
                .as_ref()
                .unwrap()
                .external
                .is_none()
        );
    }
}
