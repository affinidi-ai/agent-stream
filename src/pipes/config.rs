//! Pipe configuration types

use crate::entity_status::EntityStatus;
use crate::pipes::catalog::IdeCatalogConfig;
use crate::pipes::types::llm::LLMProvider;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Pipe type enumeration
#[derive(Debug, Clone, PartialEq)]
#[allow(clippy::upper_case_acronyms)]
pub enum PipeType {
    /// Large Language Model provider
    LLM {
        provider: Box<LLMProvider>,
        /// API endpoint path including version prefix (e.g., "/v1/chat/completions").
        /// Used by sandbox and internal APIs. If absent, falls back to "/v1/chat/completions".
        #[allow(dead_code)]
        endpoint_path: Option<String>,
    },
    /// Webhook endpoint
    Webhook { endpoint: String },
    /// IDE Surface: a governed, per-caller-filtered model-discovery menu that
    /// aggregates other surfaces and dispatches by model id. Shown to users as
    /// an "IDE" surface.
    IDECatalog { config: IdeCatalogConfig },
}

// Custom serializer for PipeType
impl Serialize for PipeType {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;

        match self {
            PipeType::LLM { provider, endpoint_path } => {
                map.serialize_entry("type", "llm")?;
                map.serialize_entry("provider", provider)?;
                if let Some(ep) = endpoint_path {
                    map.serialize_entry("endpoint_path", ep)?;
                }
            }
            PipeType::Webhook { endpoint } => {
                map.serialize_entry("type", "webhook")?;
                map.serialize_entry("endpoint", endpoint)?;
            }
            PipeType::IDECatalog { config } => {
                map.serialize_entry("type", "ide_catalog")?;
                map.serialize_entry("config", config)?;
            }
        }

        map.end()
    }
}

// Custom deserializer for PipeType to work around serde's internally-tagged enum issues
impl<'de> Deserialize<'de> for PipeType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PipeTypeVisitor;

        impl<'de> Visitor<'de> for PipeTypeVisitor {
            type Value = PipeType;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter,
            ) -> fmt::Result {
                formatter.write_str("a pipe type object with a 'type' field")
            }

            fn visit_map<A>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut pipe_type: Option<String> = None;
                let mut provider: Option<LLMProvider> = None;
                let mut endpoint: Option<String> = None;
                let mut endpoint_path: Option<String> = None;
                let mut catalog_config: Option<IdeCatalogConfig> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "type" => {
                            pipe_type = Some(map.next_value()?);
                        }
                        "provider" => {
                            provider = Some(map.next_value()?);
                        }
                        "endpoint" => {
                            endpoint = Some(map.next_value()?);
                        }
                        "endpoint_path" => {
                            endpoint_path = Some(map.next_value()?);
                        }
                        "config" => {
                            catalog_config = Some(map.next_value()?);
                        }
                        _ => {
                            // Ignore unknown fields
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }

                let pipe_type = pipe_type.ok_or_else(|| de::Error::missing_field("type"))?;

                match pipe_type.as_str() {
                    "llm" => {
                        let provider = provider.ok_or_else(|| de::Error::missing_field("provider"))?;
                        Ok(PipeType::LLM {
                            provider: Box::new(provider),
                            endpoint_path,
                        })
                    }
                    "webhook" => {
                        let endpoint = endpoint.ok_or_else(|| de::Error::missing_field("endpoint"))?;
                        Ok(PipeType::Webhook { endpoint })
                    }
                    "ide_catalog" => {
                        let config = catalog_config.ok_or_else(|| de::Error::missing_field("config"))?;
                        Ok(PipeType::IDECatalog { config })
                    }
                    _ => Err(de::Error::unknown_variant(&pipe_type, &["llm", "webhook", "ide_catalog"])),
                }
            }
        }

        deserializer.deserialize_map(PipeTypeVisitor)
    }
}

/// Rate limiting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimit {
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub requests_per_minute: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tokens_per_minute: Option<u64>, // For LLM pipes
}

/// Circuit breaker configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub timeout_seconds: u64,
    pub reset_timeout_seconds: u64,
}

/// Retry policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub backoff_multiplier: f64,
}

/// Cost tracking configuration. The main LLM stage always counts both spend and
/// tokens; `enabled` retains the legacy monthly-budget alert and price overrides.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CostTrackingConfig {
    pub enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_price_per_1k: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output_price_per_1k: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_threshold_percent: Option<u8>, // Alert when reaching X% of budget
}

/// Budget-tracker key for the pipe-wide cumulative scope.
pub const CUMULATIVE_SCOPE_KEY: &str = "cumulative";

/// A countable pipeline stage that can accrue spend and tokens. Individual
/// jurors meter under their own per-juror scope key (see [`UsageLimit::scope_key`])
/// rather than a dedicated enum variant.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum UsageStage {
    Llm,
    Judge,
    Jury,
    Decider,
}

impl UsageStage {
    /// Stable key used to bucket per-scope usage in the budget tracker.
    pub fn scope_key(&self) -> &'static str {
        match self {
            UsageStage::Llm => "stage:llm",
            UsageStage::Judge => "stage:judge",
            UsageStage::Jury => "stage:jury",
            UsageStage::Decider => "stage:decider",
        }
    }
}

/// Tokens and spend consumed by a single pipeline stage during one execution.
///
/// This is the *display/accounting* view used to fold Judge and Jury usage into
/// the execution's grand totals (activity log summary, dashboard metrics,
/// sandbox response). Every stage always counts both tokens and cost; this view
/// mirrors the per-stage budget-tracker buckets that enforce monthly caps.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct StageUsage {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost: f64,
    /// Wall-clock time spent in this stage's LLM call(s) for one execution.
    /// Accumulated across retries (LLM) and summed across jurors (Jury).
    pub latency_ms: u64,
    /// The part of `cost` billed to the account: zero for a call served on an
    /// owned key (the caller's or the customer's), `cost` for a platform key.
    pub billed_cost: f64,
    /// This stage's model calls, by the source of the key each one sent.
    pub key_sources: crate::pipes::key_source::KeySourceCounts,
}

impl StageUsage {
    /// One model call's usage, billed by the source of the key it sent.
    pub fn call(
        input_tokens: u64,
        output_tokens: u64,
        cost: f64,
        latency_ms: u64,
        source: crate::pipes::key_source::KeySource,
    ) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cost,
            latency_ms,
            billed_cost: source.billed_cost(cost),
            key_sources: crate::pipes::key_source::KeySourceCounts::one(source),
        }
    }

    /// Combined input + output tokens for the stage.
    pub fn total_tokens(&self) -> u64 {
        self.input_tokens + self.output_tokens
    }

    /// Fold another stage's tokens, cost, billed cost, latency and calls into
    /// this accumulator.
    pub fn add(
        &mut self,
        other: StageUsage,
    ) {
        self.input_tokens += other.input_tokens;
        self.output_tokens += other.output_tokens;
        self.cost += other.cost;
        self.latency_ms += other.latency_ms;
        self.billed_cost += other.billed_cost;
        self.key_sources
            .add(other.key_sources);
    }
}

/// Accounting scope a [`UsageLimit`] applies to.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UsageScope {
    /// Pipe-wide total across every tracked stage.
    #[default]
    Cumulative,
    /// A single pipeline stage; requires `stage` to be set.
    Stage,
}

/// A spend/token guardrail attached to a stage edge on the pipe canvas. Once the
/// running monthly total for the configured scope reaches a cap, further calls
/// for that scope are blocked (HTTP 429).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageLimit {
    pub id: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub scope: UsageScope,
    /// Required when `scope` is [`UsageScope::Stage`]; ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<UsageStage>,
    /// Index of the juror this limit caps, within the pipe's full juror list.
    /// Only meaningful when `stage` is [`UsageStage::Jury`]; turns a jury-stage
    /// limit into a per-juror limit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub juror_index: Option<u32>,
    /// Monthly USD spend ceiling for the scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_budget_usd: Option<f64>,
    /// Monthly token ceiling for the scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monthly_token_cap: Option<u64>,
}

impl UsageLimit {
    /// The budget-tracker scope key this limit accounts against. A jury-stage
    /// limit with a `juror_index` caps that single juror under its own key.
    pub fn scope_key(&self) -> String {
        match self.scope {
            UsageScope::Cumulative => CUMULATIVE_SCOPE_KEY.to_string(),
            UsageScope::Stage => match (self.stage, self.juror_index) {
                (Some(UsageStage::Jury), Some(idx)) => format!("stage:juror:{idx}"),
                (Some(s), _) => s.scope_key().to_string(),
                (None, _) => CUMULATIVE_SCOPE_KEY.to_string(),
            },
        }
    }

    /// Validate a single limit. A stage-scoped limit must name its stage, and a
    /// limit must set at least one cap to have any effect. Caps must be
    /// non-negative.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("usage limit id must not be empty".to_string());
        }
        if matches!(self.scope, UsageScope::Stage) && self.stage.is_none() {
            return Err(format!("usage limit '{}' is stage-scoped but names no stage", self.id));
        }
        if self
            .monthly_budget_usd
            .is_none()
            && self
                .monthly_token_cap
                .is_none()
        {
            return Err(format!("usage limit '{}' sets neither a budget nor a token cap", self.id));
        }
        if let Some(budget) = self.monthly_budget_usd
            && budget < 0.0
        {
            return Err(format!("usage limit '{}' has a negative budget", self.id));
        }
        Ok(())
    }
}

/// Usage alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAlert {
    pub alert_type: AlertType,
    pub threshold: f64,
    pub notification_channels: Vec<String>, // Integration IDs to notify
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertType {
    CostThreshold,
    TokenThreshold,
    ErrorRate,
    CostSpike,
}

impl UsageAlert {
    /// Validate a usage alert's threshold. The `threshold` field carries a
    /// per-type meaning: USD for `CostThreshold`, token count for
    /// `TokenThreshold`, a fraction in `(0, 1]` for `ErrorRate`, and a
    /// multiplier `> 1` over the rolling baseline for `CostSpike`.
    pub fn validate(&self) -> Result<(), String> {
        if !(self.threshold.is_finite()) || self.threshold <= 0.0 {
            return Err(format!("usage alert {:?} requires a positive threshold", self.alert_type));
        }
        match self.alert_type {
            AlertType::ErrorRate => {
                if self.threshold > 1.0 {
                    return Err("error-rate alert threshold must be a fraction in (0, 1]".to_string());
                }
            }
            AlertType::CostSpike => {
                if self.threshold <= 1.0 {
                    return Err("cost-spike alert threshold must be a multiplier greater than 1".to_string());
                }
            }
            AlertType::CostThreshold | AlertType::TokenThreshold => {}
        }
        Ok(())
    }
}

/// Inbound OPA (Rego) policy enforcement configuration for a pipe.
///
/// Mirrors the surface-level OPA toggle: `enabled` gates evaluation and
/// `policy_definition_id` references a stored Rego policy in the shared
/// policy-definition store. Both are required for enforcement to occur.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct PipeOpaConfig {
    /// Whether OPA evaluation is active for this pipe.
    #[serde(default)]
    pub enabled: bool,

    /// Id of the stored Rego policy definition to evaluate against.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_definition_id: Option<String>,

    /// Additional policy definitions enforced together with
    /// `policy_definition_id` under deny-overrides (every referenced policy must
    /// allow for the request to proceed). Order-preserved.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub policy_definition_ids: Vec<String>,

    /// Emit a log line for every OPA evaluation containing the full input JSON
    /// handed to Rego and the resulting `allow`/`deny`. Purely a debugging aid
    /// for policy authoring — leave off in production because the input
    /// contains request headers and caller identity.
    #[serde(default, skip_serializing_if = "is_false")]
    pub log_decisions: bool,
}

/// Where an inbound verifiable presentation is carried on the request.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum VpEvidenceSource {
    /// A request header (see [`VpEvidenceConfig::header_name`]).
    #[default]
    Header,
    /// A field in the JSON request body.
    Body,
}

/// Per-surface verifiable-presentation evidence configuration. When enabled, an
/// inbound VP is verified and its holder/issuer/claims are injected as
/// `input.identity_binding` for the surface's OPA policy.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct VpEvidenceConfig {
    /// Whether VP evidence is evaluated for this surface.
    #[serde(default)]
    pub enabled: bool,
    /// Deny the request outright when no VP is presented — a belt-and-braces
    /// gate on top of whatever the policy decides. Off by default.
    #[serde(default)]
    pub require_present: bool,
    /// Where the VP is carried on the inbound request.
    #[serde(default)]
    pub source: VpEvidenceSource,
    /// Header name when `source = header` (default `X-Agent-Stream-Presentation`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header_name: Option<String>,
}

/// Main pipe configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeConfig {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub pipe_type: PipeType,
    /// Lifecycle status. A `Deleted` surface is tombstoned: removed from active
    /// routing and hidden from listings, but retained on disk so historical
    /// usage attribution survives.
    #[serde(default)]
    pub status: EntityStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// The user who created the surface through `POST /v1/pipes`. Only the
    /// owner or an administrator may change or delete it. Surfaces created
    /// without an authenticated user, or before ownership was recorded, have
    /// none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_user_id: Option<String>,

    /// Marks an ephemeral test-fixture surface (e.g. created by the testkit).
    /// The runtime ignores this flag; it only enables the debug-/test-mode-only
    /// bulk cleanup endpoint (`POST /v1/pipes/test-surfaces/delete`) to find and
    /// tombstone every fixture surface in one call.
    #[serde(default, skip_serializing_if = "is_false")]
    pub test_surface: bool,

    // Listener configuration (like channels)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub route: Option<String>,

    // Parameter override policies (for LLM pipes)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub override_policy: Option<crate::pipes::types::llm::ParameterOverrideConfig>,

    // Prompt guard — content filtering for LLM requests/responses
    /// Prompt guard configuration for filtering PII and sensitive content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_guard: Option<crate::pipes::prompt_guard::PromptGuardConfig>,

    /// Judge configuration — LLM-based pre-processing validation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub judge: Option<crate::pipes::judge_jury::JudgeConfig>,

    /// Jury configuration — LLM-based post-processing validation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jury: Option<crate::pipes::judge_jury::JuryConfig>,

    /// Decider configuration — content-based routing across candidate upstreams.
    /// When enabled, a router LLM selects which candidate upstream serves each
    /// request, overriding the base provider for that request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decider: Option<crate::pipes::judge_jury::DeciderConfig>,

    /// Expert witnesses — external, purpose-trained safety classifiers
    /// (EnkryptAI / Lakera / Azure / generic) consulted at the request and/or
    /// response seam. Sibling to the Judge and Jury. Each witness carries its
    /// own provider, endpoint, and `check_request` / `check_response` switches,
    /// so different providers can sit on different seams. A flagged verdict from
    /// any witness blocks the call. A legacy `prompt_guard.external` block is
    /// migrated into this list at runtime by `normalize_guardrails`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expert_witnesses: Vec<crate::pipes::prompt_guard::ExpertWitnessConfig>,

    // Resource management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<RateLimit>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_policy: Option<RetryPolicy>,

    /// Cross-provider failover. When the primary upstream fails with a
    /// transport- or upstream-level error, the same request is retried against
    /// ordered backup providers until one succeeds. Content rejections
    /// (prompt-guard) and the gateway's own rate limit never trigger failover.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub failover: Option<FailoverConfig>,

    /// Weighted load balancing across a pool of providers. When enabled, each
    /// request is distributed across the base provider and weighted backup
    /// targets by weight (weighted round-robin), with failover-style
    /// fallthrough across the pool on transport/upstream errors. Takes
    /// precedence over `failover` when both are configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub load_balancing: Option<LoadBalancingConfig>,

    /// SSE streaming passthrough. When a client requests `"stream": true` and
    /// the surface is eligible (OpenAI-schema base provider with no
    /// response-side processing), the upstream token stream is proxied straight
    /// back to the client. Absent ⇒ streaming allowed; set `enabled = false`
    /// to force every request through the buffered path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub streaming: Option<StreamingConfig>,

    /// Response cache. When enabled, an identical (normalized) request served
    /// within the configured TTL returns the previously cached upstream
    /// response without calling the provider, cutting cost and latency.
    /// Opt-in per surface; variant-overridable. Applies to the buffered
    /// (non-streaming) chat path only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache: Option<CacheConfig>,

    /// Canary / A-B traffic split across surface variants. When enabled and a
    /// request does **not** explicitly address a variant (`/route$alias/...`),
    /// the gateway picks a target by weight. A split with an empty `variant`
    /// routes to the base surface. Lives on the base config only (not
    /// variant-overridable).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canary: Option<CanaryConfig>,

    /// Attribute-based routing rules (match on a request header or body field →
    /// route to a variant alias or an inline provider target). Evaluated in
    /// order before canary; an explicit `$alias` still wins. Base config only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub routing_rules: Vec<RoutingRule>,

    /// Whether attribute-based routing is **enforced**. When `false` the
    /// `routing_rules` are still retained (so the surface round-trips and can be
    /// re-enabled without rework) but are never evaluated at request time —
    /// mirroring [`CanaryConfig::enabled`]. Base config only. Defaults `true` so
    /// existing configs with rules keep enforcing.
    #[serde(default = "default_true")]
    pub routing_enabled: bool,

    // Cost tracking
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cost_tracking: Option<CostTrackingConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_alerts: Option<Vec<UsageAlert>>,

    /// Whether breach/anomaly `usage_alerts` are **enforced**. When `false` the
    /// alerts are retained but never evaluated, mirroring `routing_enabled`.
    /// Defaults `true` so existing configs with alerts keep firing.
    #[serde(default = "default_true")]
    pub usage_alerts_enabled: bool,

    /// Spend/token guardrails attached to stage edges on the canvas. Each limit
    /// blocks (HTTP 429) further calls for its scope once a monthly cap is hit.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usage_limits: Vec<UsageLimit>,

    /// Opt-in for this surface to contribute its per-execution spend and tokens
    /// to team quotas. Surface-type agnostic: the surface supplies the email
    /// location and the `(cost, tokens)` come from its execution metrics, so
    /// LLM, Memory, and future surface types share this exact mechanism.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub team_attribution: Option<crate::teams::TeamAttributionConfig>,

    // Integration configuration
    /// List of integrations (Slack, email, webhooks, etc.) to trigger on pipe events
    #[serde(default)]
    pub integrations: Vec<PipeIntegrationMapping>,

    // Monitoring
    #[serde(default = "default_true")]
    pub enable_metrics: bool, // Set to false to disable all metrics collection for performance testing
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,
    #[serde(default)]
    pub log_requests: bool,
    #[serde(default)]
    pub log_responses: bool,

    // HTTP client configuration
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,

    // Metadata
    pub created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,

    /// Unified source authentication configuration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source_auth: Option<crate::source_auth::SourceAuthConfig>,

    /// Inbound OPA (Rego) policy enforcement for this pipe. When enabled and a
    /// policy definition id is set, requests are evaluated after source auth
    /// and denied (403) when the policy returns `allow = false`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub opa_policy: Option<PipeOpaConfig>,

    /// Signed governance recording. When enabled, each interaction on this
    /// surface produces a cryptographically signed, tamper-evident record (a
    /// W3C VC over the prompt, processing stages, and completion), appended to a
    /// per-surface hash chain and optionally pushed to a remote sink. Off unless
    /// this block is present and enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_recording: Option<crate::governance::GovernanceRecordingConfig>,

    /// LLM drift monitoring. When enabled, a sampled fraction of this surface's
    /// production traffic contributes behavioural drift dimensions (refusal
    /// rate, safety-flag rate, latency, response length, schema validity) to the
    /// dedicated drift store that backs the LLM Drift page. Off unless present
    /// and enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drift: Option<crate::drift::DriftConfig>,

    /// Verifiable-presentation evidence: when enabled, an inbound VP is verified
    /// and its holder / issuer / claims are injected as `input.identity_binding`
    /// for the surface's OPA policy (e.g. "allow only if a VP from a known
    /// issuer is present"). Off unless present and enabled. Surface-level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vp_evidence: Option<VpEvidenceConfig>,

    /// Identity pass-through: forward the caller's **validated** inbound bearer
    /// token as the OUTBOUND `Authorization: Bearer` credential to the upstream
    /// provider, instead of the surface's stored API-key secret. Admin opt-in
    /// (default off); requires `jwt_bearer` source auth so the forwarded token
    /// is validated first. Intended for Bearer-accepting upstreams
    /// (OpenAI-compatible, Azure OpenAI with Microsoft Entra ID auth, or another
    /// gateway that accepts the same token). Variant-overridable.
    #[serde(default, skip_serializing_if = "is_false")]
    pub forward_caller_token: bool,

    /// Extra headers sent to this surface's **own** upstream alongside the
    /// provider's own credential, each value resolved from the secrets store at
    /// request time. Lets any provider reach an upstream that authenticates the
    /// gateway separately from the model — a mesh ingress, a reverse proxy, or
    /// a tunnel with its own ingress key — instead of forcing the operator to
    /// leave that upstream open. Never sent to a Decider candidate, a
    /// failover/load-balancing target, or a variant that swaps the upstream
    /// without declaring its own; each of those sends only its own `headers`.
    /// Variant-overridable.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upstream_headers: Vec<crate::pipes::upstream_headers::UpstreamHeader>,

    /// Declared price of this surface's **own** upstream. When set it is used
    /// as-is, zero included, ahead of `cost_tracking`'s override and the
    /// catalog. Like `upstream_headers` it belongs to the base upstream: a
    /// target prices itself with its own `pricing`, and a variant that swaps
    /// the upstream without declaring its own price inherits none.
    /// Variant-overridable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_pricing: Option<crate::pipes::types::llm::TargetPricing>,

    /// Client API formats this surface will answer. The inbound format is
    /// negotiated per request by path (`/v1/chat/completions` = OpenAI Chat
    /// Completions, `/v1/messages` = Anthropic Messages, `/v1/responses` =
    /// OpenAI Responses) and normalized to the
    /// OpenAI-canonical pipeline; the response is re-skinned to match. Defaults
    /// to accepting all three, so any client dialect can reach any surface
    /// regardless of the upstream model. Restrict to lock a surface to a single
    /// client format. See `docs/CLIENT_API_DIALECTS.md`.
    #[serde(default = "crate::pipes::ingress::default_accepted_ingress_schemas")]
    pub accepted_ingress_schemas: Vec<crate::pipes::ingress::IngressSchema>,

    /// Governor ceiling for provider reasoning ("thinking") tokens per request.
    /// When set, a caller's requested reasoning budget (`reasoning.max_tokens`,
    /// or the budget derived from `reasoning.effort` / `reasoning_effort`) is
    /// clamped to this value and the effort level is lowered to match, bounding
    /// both budget-based upstreams (Anthropic, Gemini) and effort-based ones
    /// (OpenAI). `None` (default) leaves reasoning uncapped. See
    /// `docs/INFERENCE_CONTROLS.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_reasoning_tokens: Option<u64>,

    /// Governed server-side tools (`web_search` / `web_fetch`) the gateway
    /// executes on the surface's behalf inside the request. Off by default.
    /// When active, the enabled tool schemas are injected, the model's tool
    /// calls are run under OPA + per-surface domain policy + SSRF guard +
    /// metering + governance, and the results are fed back for a bounded
    /// agentic loop. See `docs/INFERENCE_CONTROLS.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_tools: Option<crate::pipes::server_tools::ServerToolsConfig>,

    /// Context-window guard + `middle-out` compression. Off by default. When
    /// enabled (or requested per call via `transforms`), an over-window prompt
    /// is compressed by dropping middle messages before the upstream call. See
    /// `docs/INFERENCE_CONTROLS.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_management: Option<crate::pipes::context_transform::ContextManagementConfig>,

    /// Inbound document ingestion. Off by default. When enabled, inline
    /// document parts (`{ type: "file" }`) are recognized, gated by a
    /// per-surface allow-list + size cap, and — per the configured mode —
    /// extracted to prompt text (text/markdown/csv/json/docx) so any model can
    /// read them and the text flows through guardrails. See
    /// `docs/MODALITIES.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub document_ingestion: Option<crate::pipes::document_ingestion::DocumentIngestionConfig>,

    /// Inbound audio input. **Off by default (strict opt-in).** When absent or
    /// disabled the surface rejects inline `input_audio` parts. When enabled,
    /// audio is accepted for an audio-capable model, restricted to a format
    /// allow-list and bounded by a size cap. See `docs/MODALITIES.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_input: Option<crate::pipes::audio::AudioInputConfig>,

    /// Inbound image input. **Off by default (strict opt-in).** When absent or
    /// disabled the surface rejects inline `image_url` parts. When enabled,
    /// images are accepted for a vision-capable model, with inline `data:`
    /// images restricted to a format allow-list and bounded by a size cap. See
    /// `docs/MODALITIES.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_input: Option<crate::pipes::image_input::ImageInputConfig>,

    /// Realtime voice (Mode C). **Off by default (strict opt-in).** When absent
    /// or disabled the surface refuses a `…/v1/realtime` WebSocket upgrade. When
    /// enabled, the gateway relays a bidirectional realtime session to a
    /// realtime-capable model, gated like audio and segmented into governed
    /// turns. See `docs/MODALITIES.md`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realtime: Option<crate::pipes::realtime::RealtimeConfig>,

    /// Optional per-surface sandbox sign-in override (public OAuth identifiers
    /// only — `{ type, provider, tenant_id, client_id, scopes }`). Consumed
    /// only by the dashboard **Sandbox tab** to acquire a delegated caller
    /// token when testing a `forward_caller_token` surface. Resolution is
    /// **reference → surface-inline → provider-default**: the preferred path is
    /// `sandbox_oauth_identifier_id` (an OAuth Identifier profile), then this
    /// inline block, then the provider catalog `sandbox_auth` (legacy). The
    /// runtime never reads this field; it round-trips verbatim as an opaque
    /// value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_auth: Option<serde_json::Value>,

    /// Optional reference to an **OAuth Identifier** profile (Credentials store)
    /// used as this surface's sandbox "Sign in to test" identity. The preferred
    /// way to configure sandbox sign-in — enter the public tenant/client/scopes
    /// once in Credentials and reference the profile here instead of pinning an
    /// inline `sandbox_auth` block (or a provider-level default in the LLM
    /// catalog). Resolved to a PKCE config **in the browser** by the dashboard
    /// Sandbox tab; the runtime never reads it and round-trips it verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_oauth_identifier_id: Option<String>,

    /// Opaque management-dashboard canvas blob (node positions, viewport,
    /// canvas-only nodes). The runtime never reads this field; it
    /// round-trips verbatim for the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub canvas: Option<serde_json::Value>,

    /// Dashboard-only hint: when true, the builder runs Auto Layout the first
    /// time this surface opens (then clears the flag on save), so a
    /// machine-generated surface with no hand-authored `canvas` arranges itself.
    /// The runtime never reads it; it round-trips verbatim for the dashboard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_canvas: Option<bool>,

    /// Full-snapshot variant catalog addressed by `$alias`. Each variant
    /// may override the pipe's behavioural config (upstream, guards,
    /// resource controls, cost tracking, source auth, OPA). Resolved to a
    /// concrete `PipeConfig` before the runtime sees it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub variants: Vec<crate::pipes::pipe_variants::PipeVariant>,

    /// Id of the variant selected when a request carries no `$alias`. When
    /// `None`, alias-less requests resolve to the bare base pipe.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_variant_id: Option<String>,
}

/// Cross-provider failover configuration. On a transport- or upstream-level
/// failure of the primary provider, the same request is retried against each
/// backup target in order until one succeeds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Ordered backup providers, tried after the primary fails.
    #[serde(default)]
    pub targets: Vec<FailoverTarget>,
}

impl FailoverConfig {
    /// Validate that an enabled failover config names at least one usable
    /// backup target. Does not perform SSRF checks — the handler layer does
    /// that with the shared validator.
    pub fn validate(&self) -> Result<(), String> {
        if self.enabled && self.targets.is_empty() {
            return Err("failover is enabled but no backup targets are configured".to_string());
        }
        for (idx, target) in self
            .targets
            .iter()
            .enumerate()
        {
            target
                .validate()
                .map_err(|e| format!("failover target {}: {}", idx + 1, e))?;
        }
        Ok(())
    }
}

/// A single ordered backup provider for cross-provider failover.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailoverTarget {
    /// Backup provider/model to route the request to.
    pub llm: crate::pipes::judge_jury::LLMTarget,
}

impl FailoverTarget {
    pub fn validate(&self) -> Result<(), String> {
        if self
            .llm
            .provider_type
            .trim()
            .is_empty()
        {
            return Err("provider_type is required".to_string());
        }
        if self
            .llm
            .model
            .trim()
            .is_empty()
        {
            return Err("model is required".to_string());
        }
        if self
            .llm
            .endpoint_url
            .trim()
            .is_empty()
        {
            return Err("endpoint_url is required".to_string());
        }
        // A relative endpoint (e.g. `/chat/completions`) is resolved against the
        // provider's default base URL first — mirroring what the runtime does via
        // `resolve_endpoint_url` — so a built-in-provider target that runs fine is
        // not rejected on save. The SSRF guard still runs on the resolved URL.
        let resolved = crate::pipes::defaults::resolve_endpoint_url(&self.llm.provider_type, &self.llm.endpoint_url);
        // A custom/catalog provider has no built-in base, so a relative path
        // cannot be resolved (and would fail at runtime too). Reject it with an
        // actionable message instead of the opaque URL-parser error.
        if resolved.starts_with('/') {
            return Err(format!(
                "endpoint_url must be an absolute URL for provider '{}': relative paths like '{}' are only \
                 resolved for built-in providers — set the full upstream URL (e.g. https://host/v1/chat/completions)",
                self.llm.provider_type.trim(),
                self.llm.endpoint_url.trim(),
            ));
        }
        crate::url_validation::validate_service_endpoint_url_blocking(&resolved)
            .map_err(|e| format!("endpoint_url blocked: {}", e))?;
        Ok(())
    }
}

/// Weighted load-balancing configuration. The base pipe provider and each
/// weighted target form a pool; each request is distributed across the pool by
/// weight (weighted round-robin), and a request that fails with a
/// transport/upstream error falls through to the remaining pool members.
fn default_primary_weight() -> u32 {
    1
}

fn default_target_weight() -> u32 {
    1
}

/// Selection strategy for a load-balancing pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancingStrategy {
    /// Deterministic weighted round-robin (default).
    #[default]
    Weighted,
    /// Route to the pool member with the lowest observed latency (EWMA over
    /// completed requests). Unsampled members are tried first to gather a
    /// baseline; ties resolve to the lowest pool index.
    LowestLatency,
    /// Route to the pool member with the lowest catalog price for its model
    /// (input + output per 1k tokens). Members without catalog pricing are
    /// deprioritised; ties resolve to the lowest pool index.
    LowestCost,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoadBalancingConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Selection strategy across the pool. `weighted` (default) is deterministic
    /// weighted round-robin; `lowest_latency` routes to the pool member with the
    /// lowest observed EWMA latency; `lowest_cost` routes to the member with the
    /// lowest catalog price for its model.
    #[serde(default)]
    pub strategy: LoadBalancingStrategy,
    /// Weight of the base pipe's own provider in the pool. `0` drains the
    /// primary from first-pick selection (it remains a last-resort fallthrough
    /// target).
    #[serde(default = "default_primary_weight")]
    pub primary_weight: u32,
    /// Weighted backup providers in the pool.
    #[serde(default)]
    pub targets: Vec<WeightedTarget>,
}

impl LoadBalancingConfig {
    /// Validate that an enabled pool has at least one backup target, a positive
    /// total weight, and well-formed targets. Does not perform SSRF checks —
    /// the handler layer does that with the shared validator.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.targets.is_empty() {
            return Err("load balancing is enabled but no targets are configured".to_string());
        }
        let total_weight: u64 = self.primary_weight as u64
            + self
                .targets
                .iter()
                .map(|t| t.weight as u64)
                .sum::<u64>();
        if total_weight == 0 {
            return Err("load balancing total weight must be greater than zero".to_string());
        }
        for (idx, target) in self
            .targets
            .iter()
            .enumerate()
        {
            target
                .validate()
                .map_err(|e| format!("load balancing target {}: {}", idx + 1, e))?;
        }
        Ok(())
    }
}

/// A single weighted provider in a load-balancing pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WeightedTarget {
    /// Backup provider/model to route requests to.
    pub llm: crate::pipes::judge_jury::LLMTarget,
    /// Relative weight for selection. `0` excludes this target from first-pick
    /// selection (it remains a fallthrough target).
    #[serde(default = "default_target_weight")]
    pub weight: u32,
}

impl WeightedTarget {
    pub fn validate(&self) -> Result<(), String> {
        FailoverTarget { llm: self.llm.clone() }.validate()
    }
}

/// SSE streaming passthrough toggle for an LLM surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamingConfig {
    /// Whether the surface may stream upstream SSE responses straight back to
    /// the client when one requests `"stream": true`. Defaults to enabled; set
    /// to `false` to force the buffered path even for streaming clients.
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl Default for StreamingConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Response-cache configuration for an LLM surface.
///
/// When enabled, an identical (normalized) request served within `ttl_seconds`
/// returns the previously cached upstream response without calling the
/// provider, cutting cost and latency. Opt-in per surface (defaults off) and
/// variant-overridable. `mode` selects exact-match (default) or semantic
/// (embedding-similarity) matching.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    /// Master switch. Defaults to off so caching is always an explicit opt-in.
    #[serde(default)]
    pub enabled: bool,
    /// Time-to-live for a cached response, in seconds.
    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,
    /// Maximum number of cached responses kept per cache scope (each Variant
    /// and upstream, and on an identity pass-through surface each forwarded
    /// token) before the oldest are evicted.
    #[serde(default = "default_cache_max_entries")]
    pub max_entries: usize,
    /// Matching strategy: exact-hash (default) or semantic (embedding cosine
    /// similarity).
    #[serde(default)]
    pub mode: CacheMode,
    /// Minimum cosine similarity (0.0–1.0) for a semantic cache hit. Only used
    /// when `mode == Semantic`.
    #[serde(default = "default_similarity_threshold")]
    pub similarity_threshold: f32,
    /// Embedder used to vectorise requests for semantic matching. Required when
    /// `mode == Semantic`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedder: Option<CacheEmbedder>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            ttl_seconds: default_cache_ttl(),
            max_entries: default_cache_max_entries(),
            mode: CacheMode::default(),
            similarity_threshold: default_similarity_threshold(),
            embedder: None,
        }
    }
}

impl CacheConfig {
    /// Validate the cache configuration. Bounds are only meaningful when the
    /// cache is enabled; semantic mode additionally requires an embedder.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.ttl_seconds == 0 {
            return Err("cache ttl_seconds must be greater than 0".to_string());
        }
        if self.max_entries == 0 {
            return Err("cache max_entries must be greater than 0".to_string());
        }
        if self.mode == CacheMode::Semantic {
            if !(0.0..=1.0).contains(&self.similarity_threshold) || self.similarity_threshold <= 0.0 {
                return Err("cache similarity_threshold must be in (0.0, 1.0]".to_string());
            }
            match &self.embedder {
                None => return Err("semantic cache requires an embedder".to_string()),
                Some(embedder) => embedder.validate()?,
            }
        }
        Ok(())
    }
}

/// Canary / A-B traffic-split configuration for a surface's variants.
///
/// When enabled and a request does not explicitly address a variant
/// (`/route$alias/...`), the gateway chooses a target by weight. A split with an
/// empty/absent `variant` routes to the base surface; otherwise to the named
/// variant alias.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct CanaryConfig {
    /// Master switch. Defaults off so canary routing is an explicit opt-in.
    #[serde(default)]
    pub enabled: bool,
    /// Weighted routing targets. Weights are relative (normalized against their
    /// sum); a split with an empty `variant` routes to the base surface.
    #[serde(default)]
    pub splits: Vec<CanarySplit>,
}

/// One weighted target in a [`CanaryConfig`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CanarySplit {
    /// Variant alias to route to; empty/absent means the base surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Relative weight; the probability of this target is `weight / Σ weights`.
    pub weight: u32,
}

/// Outcome of a canary routing decision, retaining *why* the base surface was
/// chosen so callers can attribute skips in telemetry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CanaryOutcome {
    /// Canary is not enabled.
    Disabled,
    /// Canary is enabled but the splits carry no positive weight.
    NoWeight,
    /// The weighted pick landed on an empty/absent-variant (base) split.
    BaseSplit,
    /// The weighted pick selected the named variant alias.
    Variant(String),
}

impl CanaryConfig {
    /// Weighted-random routing decision. See [`CanaryOutcome`] for the base-surface
    /// reasons. The random pick is drawn here and delegated to
    /// [`decide_with_pick`](Self::decide_with_pick) for the deterministic walk.
    pub fn decide(&self) -> CanaryOutcome {
        use rand::Rng;
        if !self.enabled {
            return CanaryOutcome::Disabled;
        }
        let total: u64 = self
            .splits
            .iter()
            .map(|s| s.weight as u64)
            .sum();
        if total == 0 {
            return CanaryOutcome::NoWeight;
        }
        let pick = rand::rng().random_range(0..total);
        self.decide_with_pick(pick)
    }

    /// Pure weighted-split walk for a given `pick` in `0..Σ weights`. Split out
    /// from [`decide`](Self::decide) so the selection is deterministically
    /// testable without touching the RNG. Assumes `enabled` and a positive total
    /// weight (guaranteed by `decide`).
    fn decide_with_pick(
        &self,
        pick: u64,
    ) -> CanaryOutcome {
        let mut remaining = pick;
        for split in &self.splits {
            let weight = split.weight as u64;
            if remaining < weight {
                return match split
                    .variant
                    .as_ref()
                    .filter(|alias| !alias.trim().is_empty())
                {
                    Some(alias) => CanaryOutcome::Variant(alias.clone()),
                    None => CanaryOutcome::BaseSplit,
                };
            }
            remaining -= weight;
        }
        CanaryOutcome::BaseSplit
    }

    /// Validate the canary configuration against the surface's known variant
    /// aliases. Only meaningful when enabled.
    pub fn validate(
        &self,
        variant_aliases: &[String],
    ) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.splits.is_empty() {
            return Err("canary requires at least one split when enabled".to_string());
        }
        if self
            .splits
            .iter()
            .all(|s| s.weight == 0)
        {
            return Err("canary splits must have a positive total weight".to_string());
        }
        for split in &self.splits {
            if let Some(alias) = split
                .variant
                .as_ref()
                .filter(|a| !a.trim().is_empty())
                && !variant_aliases
                    .iter()
                    .any(|v| v == alias)
            {
                return Err(format!("canary split references unknown variant '{alias}'"));
            }
        }
        Ok(())
    }
}

/// Matching strategy for the response cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Byte-identical (normalized) request bodies match.
    #[default]
    Exact,
    /// Requests whose embedding cosine similarity clears the threshold match.
    Semantic,
}

/// The modalities a [`RoutingMatch::Modality`] rule may match on. `image` /
/// `audio` / `document` / `text` are detected from the chat body; `realtime` is
/// the `/v1/realtime` WebSocket transport signal. Shared by validation and the
/// front-door matcher so both sides accept the same closed vocabulary.
pub const ROUTING_MODALITIES: [&str; 5] = ["text", "image", "audio", "document", "realtime"];

/// A request-attribute routing rule. When its condition matches, the request is
/// routed to a variant alias or an inline provider target. Rules are evaluated
/// in order (first match wins), only when the client did not address a variant
/// explicitly, and take precedence over a canary split.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    /// The condition to match on.
    #[serde(rename = "match")]
    pub match_on: RoutingMatch,
    /// Where to route when the condition matches.
    pub target: RoutingTarget,
}

/// The condition a [`RoutingRule`] matches on.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoutingMatch {
    /// A request header equals a value (header name matched case-insensitively).
    Header { name: String, equals: String },
    /// A top-level request-body string field equals a value.
    BodyField { field: String, equals: String },
    /// The request carries a given modality. Body modalities (`image`, `audio`,
    /// `document`, `text`) are detected from the payload on the chat path;
    /// `realtime` is a transport signal matched only on the `/v1/realtime`
    /// WebSocket path. Enables deterministic, LLM-free routing to a
    /// modality-capable variant.
    Modality { has: String },
}

/// Where a matched [`RoutingRule`] routes the request. `variant` wins when set;
/// otherwise the inline `llm` target is used. At least one must be present.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingTarget {
    /// Variant alias to route to (empty = base surface). Preferred when set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
    /// Inline provider/model target, used only when `variant` is unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<crate::pipes::judge_jury::LLMTarget>,
}

impl RoutingRule {
    /// Validate a routing rule against the surface's known variant aliases.
    pub fn validate(
        &self,
        variant_aliases: &[String],
    ) -> Result<(), String> {
        match &self.match_on {
            RoutingMatch::Header { name, equals } => {
                if name.trim().is_empty() || equals.trim().is_empty() {
                    return Err("routing header rule requires a name and equals value".to_string());
                }
            }
            RoutingMatch::BodyField { field, equals } => {
                if field.trim().is_empty() || equals.trim().is_empty() {
                    return Err("routing body_field rule requires a field and equals value".to_string());
                }
            }
            RoutingMatch::Modality { has } => {
                if !crate::pipes::config::ROUTING_MODALITIES.contains(&has.as_str()) {
                    return Err(format!(
                        "routing modality rule has unknown modality '{has}' (expected one of {})",
                        crate::pipes::config::ROUTING_MODALITIES.join(", ")
                    ));
                }
            }
        }
        match (
            self.target
                .variant
                .as_ref()
                .filter(|a| !a.trim().is_empty()),
            &self.target.llm,
        ) {
            (Some(alias), _) => {
                if !variant_aliases
                    .iter()
                    .any(|v| v == alias)
                {
                    return Err(format!("routing rule targets unknown variant '{alias}'"));
                }
            }
            (None, Some(llm)) => {
                if llm
                    .provider_type
                    .trim()
                    .is_empty()
                    || llm.model.trim().is_empty()
                    || llm
                        .endpoint_url
                        .trim()
                        .is_empty()
                {
                    return Err("routing inline target requires provider_type, model, and endpoint_url".to_string());
                }
            }
            (None, None) => {
                return Err("routing rule must set either a variant or an inline llm target".to_string());
            }
        }
        Ok(())
    }
}

/// Embedder used by the semantic response cache to vectorise requests. Points
/// at an OpenAI-compatible `/v1/embeddings` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CacheEmbedder {
    /// Full embeddings endpoint URL (e.g. `https://api.openai.com/v1/embeddings`).
    pub endpoint_url: String,
    /// Embedding model name (e.g. `text-embedding-3-small`).
    pub model: String,
    /// Secret id holding the embedder's API key, if the endpoint requires one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
}

impl CacheEmbedder {
    /// Validate the embedder: non-empty endpoint (SSRF-clear) and model.
    pub fn validate(&self) -> Result<(), String> {
        if self
            .endpoint_url
            .trim()
            .is_empty()
        {
            return Err("cache embedder endpoint_url must not be empty".to_string());
        }
        crate::url_validation::validate_service_endpoint_url_blocking(&self.endpoint_url)?;
        if self.model.trim().is_empty() {
            return Err("cache embedder model must not be empty".to_string());
        }
        Ok(())
    }
}

fn default_cache_ttl() -> u64 {
    3600
}

fn default_cache_max_entries() -> usize {
    1000
}

fn default_similarity_threshold() -> f32 {
    0.95
}

/// Integration mapping for pipe events
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeIntegrationMapping {
    /// ID of the integration to use
    pub integration_id: String,

    /// Which pipe events should trigger this integration
    /// Examples: "pipe.executed", "pipe.error", "pipe.budget.threshold_reached"
    pub event_types: Vec<String>,

    /// Template variable values for this integration
    /// Maps variable names (without $ prefix) to their runtime values
    #[serde(default)]
    pub variables: serde_json::Value,
}

/// Serde `skip_serializing_if` helper: true when the boolean is `false`, so a
/// default-`false` flag is omitted from the serialized JSON.
fn is_false(value: &bool) -> bool {
    !*value
}

fn default_true() -> bool {
    true
}

fn default_request_timeout() -> u64 {
    60 // 60 seconds default
}

impl PipeConfig {
    #[allow(dead_code)]
    pub fn new(
        id: String,
        name: String,
        pipe_type: PipeType,
    ) -> Self {
        Self {
            id,
            name,
            description: None,
            pipe_type,
            status: EntityStatus::Enabled,
            tenant_id: None,
            owner_user_id: None,
            test_surface: false,
            listen_address: None,
            route: None,
            prompt_guard: None,
            judge: None,
            jury: None,
            decider: None,
            expert_witnesses: Vec::new(),
            rate_limit: None,
            circuit_breaker: None,
            retry_policy: None,
            failover: None,
            load_balancing: None,
            streaming: None,
            cache: None,
            canary: None,
            routing_rules: Vec::new(),
            routing_enabled: true,
            cost_tracking: None,
            usage_alerts: None,
            usage_alerts_enabled: true,
            usage_limits: Vec::new(),
            team_attribution: None,
            integrations: Vec::new(),
            enable_metrics: true,
            metrics_enabled: true,
            log_requests: false,
            log_responses: false,
            request_timeout_seconds: 60,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: Some(chrono::Utc::now().to_rfc3339()),
            override_policy: None,
            source_auth: None,
            opa_policy: None,
            governance_recording: None,
            drift: None,
            vp_evidence: None,
            forward_caller_token: false,
            upstream_headers: Vec::new(),
            upstream_pricing: None,
            accepted_ingress_schemas: crate::pipes::ingress::default_accepted_ingress_schemas(),
            max_reasoning_tokens: None,
            server_tools: None,
            context_management: None,
            document_ingestion: None,
            audio_input: None,
            image_input: None,
            realtime: None,
            sandbox_auth: None,
            sandbox_oauth_identifier_id: None,
            canvas: None,
            auto_canvas: None,
            variants: Vec::new(),
            default_variant_id: None,
        }
    }

    /// Whether inbound OPA evaluation is active for this pipe.
    pub fn opa_enabled(&self) -> bool {
        self.opa_policy
            .as_ref()
            .map(|o| o.enabled)
            .unwrap_or(false)
    }

    /// The VP-evidence config in force when enabled; `None` when VP evidence is
    /// not evaluated for this surface.
    pub fn vp_evidence(&self) -> Option<&VpEvidenceConfig> {
        self.vp_evidence
            .as_ref()
            .filter(|v| v.enabled)
    }

    /// Migrate legacy guardrail config into the expert-witness model, in place
    /// and idempotently. When no expert witnesses are configured but a legacy
    /// `prompt_guard.external` block is present, that block is moved into a
    /// single witness and `prompt_guard.external` is cleared. A no-op once any
    /// witness exists (so a config authored against the witness model is never
    /// overwritten) and a no-op when there is nothing to migrate.
    pub fn normalize_guardrails(&mut self) {
        if !self
            .expert_witnesses
            .is_empty()
        {
            return;
        }
        let legacy = self
            .prompt_guard
            .as_mut()
            .and_then(|pg| pg.external.take());
        if let Some(external) = legacy {
            self.expert_witnesses
                .push(crate::pipes::prompt_guard::ExpertWitnessConfig::from_legacy_external(external));
        }
    }

    /// Id of the stored Rego policy definition to evaluate against, if any.
    pub fn opa_policy_definition_id(&self) -> Option<&str> {
        self.opa_policy
            .as_ref()
            .and_then(|o| {
                o.policy_definition_id
                    .as_deref()
            })
    }

    /// The ordered, deduped set of policy-definition ids enforced on this pipe's
    /// front door: the legacy single `policy_definition_id` first, then any in
    /// `policy_definition_ids`. Empty when OPA references no policy. Evaluated
    /// under deny-overrides.
    pub fn opa_policy_definition_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = Vec::new();
        if let Some(id) = self
            .opa_policy_definition_id()
            .filter(|id| !id.is_empty())
        {
            ids.push(id.to_string());
        }
        if let Some(opa) = self.opa_policy.as_ref() {
            for id in &opa.policy_definition_ids {
                if !id.is_empty() && !ids.contains(id) {
                    ids.push(id.clone());
                }
            }
        }
        ids
    }

    /// Whether OPA evaluations should be logged (input + allow/deny) for this
    /// pipe. Only meaningful when [`Self::opa_enabled`] is true.
    pub fn opa_log_decisions(&self) -> bool {
        self.opa_policy
            .as_ref()
            .map(|o| o.log_decisions)
            .unwrap_or(false)
    }

    /// Produce a transient copy of this pipe that routes to a single explicit
    /// provider target. `failover`, `load_balancing`, and `decider` are cleared
    /// so a backup/pool attempt neither recurses into further failover or load
    /// balancing nor re-routes through the content-based router — the explicit
    /// target provider is used directly. The base's `upstream_headers` and
    /// `upstream_pricing` belong to the base upstream, so the copy carries the
    /// target's own `headers` and `pricing` in their place, never the base's.
    /// The target's headers ride only when the copy's provider calls the
    /// target's own endpoint; a provider type that ignores `endpoint_url`
    /// gets none, so they never reach a vendor host the target did not name.
    pub fn clone_with_failover_target(
        &self,
        target: &crate::pipes::judge_jury::LLMTarget,
    ) -> Self {
        let mut alt = self.clone();
        alt.pipe_type = PipeType::LLM {
            provider: Box::new(crate::pipes::judge_jury::target_to_provider(target)),
            endpoint_path: None,
        };
        alt.failover = None;
        alt.load_balancing = None;
        alt.decider = None;
        alt.upstream_headers = if crate::pipes::judge_jury::provider_calls_target_endpoint(target) {
            target.headers.clone()
        } else {
            Vec::new()
        };
        alt.upstream_pricing = target.pricing;
        alt
    }
}

use crate::storage::filesystem::{RetiredRecord, StorableEntity};

/// Surface types that were removed and have no replacement to migrate to.
const REMOVED_PIPE_TYPES: [&str; 2] = ["api", "mcp"];

/// How an operator clears a skipped surface. A skipped record never enters the
/// cache, so the API and dashboard cannot see, update, or delete it.
const REMOVED_PIPE_TYPE_REMEDY: &str = "Remove this file, or create a new LLM surface with the same id, which \
                                        replaces it.";

/// The removed type named by a serialized `PipeType`, if it is one.
fn removed_pipe_type(pipe_type: Option<&serde_json::Value>) -> Option<&str> {
    pipe_type
        .and_then(|pipe_type| pipe_type.get("type"))
        .and_then(serde_json::Value::as_str)
        .filter(|pipe_type| REMOVED_PIPE_TYPES.contains(pipe_type))
}

impl StorableEntity for PipeConfig {
    fn id(&self) -> &str {
        &self.id
    }

    /// A stored surface of a removed type, or with a variant that overrides its
    /// type to one, cannot be converted, so the loader is told to skip it with
    /// an actionable message instead of serde's generic unknown-variant error.
    /// Only this record is skipped, its file is left untouched on disk, and the
    /// loader warns once per process rather than on every cache refresh. The
    /// message names the type and variant id only, never the record's content,
    /// which can hold credentials such as an API surface's `auth_header`.
    fn migrate_raw_json(value: &mut serde_json::Value) -> anyhow::Result<bool> {
        if let Some(removed) = removed_pipe_type(value.get("pipe_type")) {
            return Err(RetiredRecord(format!(
                "surface type `{removed}` was removed, so this surface is no longer loaded. {REMOVED_PIPE_TYPE_REMEDY}"
            ))
            .into());
        }
        let variants = value
            .get("variants")
            .and_then(serde_json::Value::as_array);
        for variant in variants.into_iter().flatten() {
            let overridden = variant
                .get("overrides")
                .and_then(|overrides| overrides.get("pipe_type"));
            if let Some(removed) = removed_pipe_type(overridden) {
                let variant_id = variant
                    .get("id")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("");
                return Err(RetiredRecord(format!(
                    "variant {variant_id:?} overrides the surface type to `{removed}`, which was removed, so this \
                     surface is no longer loaded. {REMOVED_PIPE_TYPE_REMEDY}"
                ))
                .into());
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn retired_message(mut value: serde_json::Value) -> String {
        let err = PipeConfig::migrate_raw_json(&mut value).expect_err("record must be retired");
        err.downcast_ref::<RetiredRecord>()
            .expect("a removed type is reported as a retired record")
            .to_string()
    }

    #[test]
    fn migrate_raw_json_retires_a_removed_surface_type_without_leaking_content() {
        let message = retired_message(serde_json::json!({
            "id": "legacy-api",
            "pipe_type": { "type": "api", "auth_header": "Bearer secret-token" },
        }));
        assert!(message.contains("`api`"), "{message}");
        assert!(message.contains("create a new LLM surface with the same id"), "{message}");
        assert!(!message.contains("secret-token"), "{message}");
        assert!(!message.contains("Webhook"), "{message}");
    }

    #[test]
    fn migrate_raw_json_retires_a_surface_with_a_removed_variant_type() {
        let message = retired_message(serde_json::json!({
            "id": "llm-surface",
            "pipe_type": { "type": "llm" },
            "variants": [
                { "id": "fine", "overrides": { "pipe_type": { "type": "llm" } } },
                { "id": "legacy\nvariant", "overrides": { "pipe_type": { "type": "mcp", "url": "https://secret.example" } } },
            ],
        }));
        assert!(message.contains("`mcp`"), "{message}");
        assert!(message.contains(r#""legacy\nvariant""#), "variant id is quoted and escaped: {message}");
        assert!(!message.contains("secret.example"), "{message}");
    }

    #[test]
    fn migrate_raw_json_leaves_supported_surfaces_alone() {
        let mut value = serde_json::json!({
            "id": "llm-surface",
            "pipe_type": { "type": "llm" },
            "variants": [{ "id": "v1", "overrides": { "pipe_type": { "type": "webhook" } } }, { "id": "v2" }],
        });
        assert!(!PipeConfig::migrate_raw_json(&mut value).unwrap());
    }

    #[test]
    fn canary_decide_disabled_returns_disabled() {
        let canary = CanaryConfig {
            enabled: false,
            splits: vec![CanarySplit {
                variant: Some("fast".to_string()),
                weight: 10,
            }],
        };
        assert_eq!(canary.decide(), CanaryOutcome::Disabled);
    }

    #[test]
    fn canary_decide_single_split_is_deterministic() {
        // A single positive-weight split always resolves to that target.
        let to_variant = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit {
                variant: Some("fast".to_string()),
                weight: 5,
            }],
        };
        for _ in 0..50 {
            assert_eq!(to_variant.decide(), CanaryOutcome::Variant("fast".to_string()));
        }
        // An empty variant routes to the base surface.
        let to_base = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit { variant: None, weight: 5 }],
        };
        for _ in 0..50 {
            assert_eq!(to_base.decide(), CanaryOutcome::BaseSplit);
        }
    }

    #[test]
    fn canary_decide_zero_total_weight_returns_no_weight() {
        let canary = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit {
                variant: Some("fast".to_string()),
                weight: 0,
            }],
        };
        assert_eq!(canary.decide(), CanaryOutcome::NoWeight);
    }

    #[test]
    fn canary_decide_reports_skip_reasons() {
        // Disabled → Disabled (not merely "base").
        let disabled = CanaryConfig {
            enabled: false,
            splits: vec![CanarySplit {
                variant: Some("fast".to_string()),
                weight: 10,
            }],
        };
        assert_eq!(disabled.decide(), CanaryOutcome::Disabled);

        // Enabled but zero total weight → NoWeight.
        let no_weight = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit {
                variant: Some("fast".to_string()),
                weight: 0,
            }],
        };
        assert_eq!(no_weight.decide(), CanaryOutcome::NoWeight);

        // Empty-variant split chosen → BaseSplit.
        let base_split = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit { variant: None, weight: 5 }],
        };
        assert_eq!(base_split.decide(), CanaryOutcome::BaseSplit);
    }

    #[test]
    fn canary_decide_with_pick_respects_weight_boundaries() {
        // base weight 1 (picks: 0), "canary" weight 3 (picks: 1,2,3).
        let canary = CanaryConfig {
            enabled: true,
            splits: vec![
                CanarySplit { variant: None, weight: 1 },
                CanarySplit {
                    variant: Some("canary".to_string()),
                    weight: 3,
                },
            ],
        };
        assert_eq!(canary.decide_with_pick(0), CanaryOutcome::BaseSplit);
        for pick in 1..=3 {
            assert_eq!(
                canary.decide_with_pick(pick),
                CanaryOutcome::Variant("canary".to_string()),
                "pick {pick} should land on the canary variant"
            );
        }
    }

    #[test]
    fn canary_validate_rejects_unknown_variant() {
        let canary = CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit {
                variant: Some("ghost".to_string()),
                weight: 1,
            }],
        };
        assert!(
            canary
                .validate(&["fast".to_string()])
                .is_err()
        );
        assert!(
            canary
                .validate(&["ghost".to_string()])
                .is_ok()
        );
    }

    /// A stored surface's JSON with its `pipe_type` replaced, as an earlier
    /// version would have written it.
    fn stored_pipe_json(
        id: &str,
        pipe_type: serde_json::Value,
    ) -> serde_json::Value {
        let mut pipe = minimal_llm_pipe();
        pipe.id = id.to_string();
        let mut json = serde_json::to_value(&pipe).unwrap();
        json["pipe_type"] = pipe_type;
        json
    }

    #[test]
    fn removed_surface_types_are_refused_without_quoting_the_record() {
        for (pipe_type, secret) in [
            (
                serde_json::json!({"type": "api", "endpoint": "https://api.example", "auth_header": "Bearer top-secret"}),
                "top-secret",
            ),
            (serde_json::json!({"type": "mcp", "server_name": "private-server"}), "private-server"),
        ] {
            let mut json = stored_pipe_json("legacy", pipe_type);
            let error = PipeConfig::migrate_raw_json(&mut json).expect_err("a removed surface type must be refused");
            let message = error.to_string();

            assert!(message.contains("was removed"), "got: {message}");
            assert!(!message.contains(secret), "the error must not quote the record: {message}");
        }
    }

    #[test]
    fn live_surface_types_pass_the_load_migration_unchanged() {
        let mut json = stored_pipe_json("live", serde_json::to_value(&minimal_llm_pipe().pipe_type).unwrap());
        let before = json.clone();

        assert!(!PipeConfig::migrate_raw_json(&mut json).unwrap());
        assert_eq!(json, before);
    }

    #[tokio::test]
    async fn a_removed_surface_type_skips_only_that_record_and_keeps_its_file() {
        let dir = tempfile::tempdir().unwrap();
        let live = stored_pipe_json("live", serde_json::to_value(&minimal_llm_pipe().pipe_type).unwrap());
        let legacy = stored_pipe_json(
            "legacy",
            serde_json::json!({"type": "api", "endpoint": "https://api.example", "auth_header": "Bearer top-secret"}),
        );
        let legacy_path = dir.path().join("legacy.json");
        std::fs::write(dir.path().join("live.json"), serde_json::to_vec_pretty(&live).unwrap()).unwrap();
        std::fs::write(&legacy_path, serde_json::to_vec_pretty(&legacy).unwrap()).unwrap();

        let store = crate::pipes::FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .expect("one unloadable surface must not fail the whole store");
        let ids: Vec<String> = store
            .list()
            .await
            .into_iter()
            .map(|pipe| pipe.id)
            .collect();

        assert_eq!(ids, vec!["live".to_string()]);
        assert!(legacy_path.exists(), "the skipped record is left on disk for the operator");
    }

    fn minimal_llm_pipe() -> PipeConfig {
        PipeConfig::new(
            "p".to_string(),
            "p".to_string(),
            PipeType::LLM {
                provider: Box::new(LLMProvider::OpenAI {
                    provider_type: "openai".to_string(),
                    model: "gpt-4o".to_string(),
                    api_key_secret: Some("sk".to_string()),
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

    #[test]
    fn owner_is_optional_and_round_trips() {
        let mut pipe = minimal_llm_pipe();
        let v = serde_json::to_value(&pipe).unwrap();
        assert!(
            v.get("owner_user_id")
                .is_none()
        );
        let parsed: PipeConfig = serde_json::from_value(v).unwrap();
        assert_eq!(parsed.owner_user_id, None);

        pipe.owner_user_id = Some("alice".into());
        let parsed: PipeConfig = serde_json::from_value(serde_json::to_value(&pipe).unwrap()).unwrap();
        assert_eq!(
            parsed
                .owner_user_id
                .as_deref(),
            Some("alice")
        );
    }

    #[test]
    fn routing_and_alert_flags_default_true_when_absent() {
        // A config that predates the flags (fields absent) must keep enforcing —
        // both default to `true` for back-compat.
        let pipe = minimal_llm_pipe();
        let mut v = serde_json::to_value(&pipe).unwrap();
        let obj = v.as_object_mut().unwrap();
        obj.remove("routing_enabled");
        obj.remove("usage_alerts_enabled");
        obj.remove("tenant_id");
        let parsed: PipeConfig = serde_json::from_value(v).unwrap();
        assert!(parsed.routing_enabled);
        assert_eq!(parsed.tenant_id, None);
        assert!(parsed.usage_alerts_enabled);
    }

    #[test]
    fn routing_and_alert_flags_roundtrip_false() {
        // A disabled feature retains its values but persists `false` so it is
        // saved, reloaded, and re-enabled without rework.
        let mut pipe = minimal_llm_pipe();
        pipe.routing_enabled = false;
        pipe.usage_alerts_enabled = false;
        let json = serde_json::to_string(&pipe).unwrap();
        let parsed: PipeConfig = serde_json::from_str(&json).unwrap();
        assert!(!parsed.routing_enabled);
        assert!(!parsed.usage_alerts_enabled);
    }

    #[test]
    fn canary_validate_requires_positive_weight_when_enabled() {
        let canary = CanaryConfig {
            enabled: true,
            splits: vec![
                CanarySplit { variant: None, weight: 0 },
                CanarySplit {
                    variant: Some("fast".to_string()),
                    weight: 0,
                },
            ],
        };
        assert!(
            canary
                .validate(&["fast".to_string()])
                .is_err()
        );
    }

    #[test]
    fn routing_rule_validate_variant_target() {
        let rule = RoutingRule {
            match_on: RoutingMatch::Header {
                name: "X-Route".to_string(),
                equals: "fast".to_string(),
            },
            target: RoutingTarget {
                variant: Some("fast".to_string()),
                llm: None,
            },
        };
        assert!(
            rule.validate(&["fast".to_string()])
                .is_ok()
        );
        assert!(
            rule.validate(&["slow".to_string()])
                .is_err()
        );
    }

    #[test]
    fn routing_rule_validate_inline_target() {
        let rule = RoutingRule {
            match_on: RoutingMatch::BodyField {
                field: "tier".to_string(),
                equals: "pro".to_string(),
            },
            target: RoutingTarget {
                variant: None,
                llm: Some(sample_target("openai")),
            },
        };
        assert!(rule.validate(&[]).is_ok());
    }

    #[test]
    fn routing_rule_validate_requires_a_target() {
        let rule = RoutingRule {
            match_on: RoutingMatch::Header {
                name: "X-Route".to_string(),
                equals: "x".to_string(),
            },
            target: RoutingTarget { variant: None, llm: None },
        };
        assert!(rule.validate(&[]).is_err());
    }

    #[test]
    fn routing_rule_validate_rejects_empty_condition() {
        let rule = RoutingRule {
            match_on: RoutingMatch::Header {
                name: "".to_string(),
                equals: "x".to_string(),
            },
            target: RoutingTarget {
                variant: Some("fast".to_string()),
                llm: None,
            },
        };
        assert!(
            rule.validate(&["fast".to_string()])
                .is_err()
        );
    }

    #[test]
    fn routing_rule_validate_accepts_known_modalities() {
        for has in ROUTING_MODALITIES {
            let rule = RoutingRule {
                match_on: RoutingMatch::Modality { has: has.to_string() },
                target: RoutingTarget {
                    variant: Some("v".to_string()),
                    llm: None,
                },
            };
            assert!(
                rule.validate(&["v".to_string()])
                    .is_ok(),
                "modality '{has}' should validate"
            );
        }
    }

    #[test]
    fn routing_rule_validate_rejects_unknown_modality() {
        let rule = RoutingRule {
            match_on: RoutingMatch::Modality { has: "video".to_string() },
            target: RoutingTarget {
                variant: Some("v".to_string()),
                llm: None,
            },
        };
        assert!(
            rule.validate(&["v".to_string()])
                .is_err()
        );
    }

    #[test]
    fn stage_usage_default_is_zero() {
        let u = StageUsage::default();
        assert_eq!(u.input_tokens, 0);
        assert_eq!(u.output_tokens, 0);
        assert_eq!(u.total_tokens(), 0);
        assert_eq!(u.cost, 0.0);
        assert_eq!(u.latency_ms, 0);
    }

    #[test]
    fn stage_usage_total_tokens_sums_io() {
        let u = StageUsage {
            input_tokens: 120,
            output_tokens: 30,
            cost: 0.5,
            latency_ms: 0,
            ..Default::default()
        };
        assert_eq!(u.total_tokens(), 150);
    }

    #[test]
    fn stage_usage_add_accumulates() {
        let mut grand = StageUsage::default();
        grand.add(StageUsage {
            input_tokens: 100,
            output_tokens: 40,
            cost: 0.20,
            latency_ms: 30,
            ..Default::default()
        });
        grand.add(StageUsage {
            input_tokens: 10,
            output_tokens: 5,
            cost: 0.05,
            latency_ms: 12,
            ..Default::default()
        });
        assert_eq!(grand.input_tokens, 110);
        assert_eq!(grand.output_tokens, 45);
        assert_eq!(grand.total_tokens(), 155);
        assert!((grand.cost - 0.25).abs() < 1e-9);
        assert_eq!(grand.latency_ms, 42);
    }

    #[test]
    fn stage_usage_grand_total_composition_matches_stage_sum() {
        // Mirrors the executor: grand totals = LLM + Judge + Jury, and the
        // LLM-only breakdown that drives enforcement stays separate so Judge/
        // Jury are never double-counted against the LLM budget bucket.
        let llm = StageUsage {
            input_tokens: 200,
            output_tokens: 80,
            cost: 0.30,
            latency_ms: 0,
            ..Default::default()
        };
        let judge = StageUsage {
            input_tokens: 50,
            output_tokens: 10,
            cost: 0.06,
            latency_ms: 0,
            ..Default::default()
        };
        let jury = StageUsage {
            input_tokens: 90,
            output_tokens: 30,
            cost: 0.12,
            latency_ms: 0,
            ..Default::default()
        };

        let mut grand = StageUsage::default();
        grand.add(llm);
        grand.add(judge);
        grand.add(jury);

        assert_eq!(grand.input_tokens, 340);
        assert_eq!(grand.output_tokens, 120);
        assert_eq!(grand.total_tokens(), 460);
        assert!((grand.cost - 0.48).abs() < 1e-9);

        // The enforcement view must remain LLM-only, never the grand total.
        assert_eq!(llm.total_tokens(), 280);
        assert!((llm.cost - 0.30).abs() < 1e-9);
        assert_ne!(llm.total_tokens(), grand.total_tokens());
    }

    #[test]
    fn test_pipe_config_deser_with_model_params() {
        let json = r#"{"id":"134d8c9c-5ae7-4f46-8638-311bffc4468e","name":"OpenAI","description":"Test","enabled":true,"listen_address":"fabric-gateway-1.example.com","route":"/llm/nominal/podium","pipe_type":{"type":"llm","provider":{"provider_type":"openai","model":"gpt-4","max_tokens":2100,"temperature":0.9,"top_p":1,"frequency_penalty":0,"presence_penalty":0,"api_key_secret":"acac3a9b-b52a-4c64-95ee-121a3abf59c1"}},"rate_limit":{"requests_per_minute":65,"tokens_per_minute":10000},"cost_tracking":{"enabled":true,"input_price_per_1k":0.03102,"output_price_per_1k":0.06002},"created_at":"2026-01-17T07:36:46.812Z"}"#;

        let result = serde_json::from_str::<PipeConfig>(json);
        match result {
            Ok(config) => {
                assert_eq!(config.name, "OpenAI");
                println!("✓ Deserialization successful!");
            }
            Err(e) => {
                panic!("Deserialization failed: {} at column {}", e, e.column());
            }
        }
    }

    #[test]
    fn pipe_type_ide_catalog_round_trips() {
        use crate::pipes::catalog::{IdeCatalogConfig, IdeCatalogMember};

        let original = PipeType::IDECatalog {
            config: IdeCatalogConfig {
                members: vec![
                    IdeCatalogMember {
                        pipe_id: "gpt".to_string(),
                        variant_alias: None,
                        mnemonic: None,
                        display_name: Some("GPT".to_string()),
                        group: None,
                        order: 0,
                        default: true,
                        expose: true,
                        metadata: None,
                        upstream_oauth_identifier_id: None,
                        opa_policy_id: None,
                        node_id: None,
                    },
                    IdeCatalogMember {
                        pipe_id: "claude".to_string(),
                        variant_alias: Some("fast".to_string()),
                        mnemonic: None,
                        display_name: None,
                        group: None,
                        order: 1,
                        default: false,
                        expose: true,
                        metadata: None,
                        upstream_oauth_identifier_id: None,
                        opa_policy_id: None,
                        node_id: None,
                    },
                ],
                client_auth: None,
            },
        };

        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("\"type\":\"ide_catalog\""), "json was: {json}");

        let restored: PipeType = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(restored, original);

        match restored {
            PipeType::IDECatalog { config } => {
                assert_eq!(config.members.len(), 2);
                assert_eq!(config.members[1].model_id(), "claude$fast");
            }
            other => panic!("expected IDECatalog, got {other:?}"),
        }
    }

    #[test]
    fn pipe_type_deserialize_rejects_unknown_type() {
        let err = serde_json::from_str::<PipeType>(r#"{"type":"nonsense"}"#).expect_err("unknown type must fail");
        let msg = err.to_string();
        assert!(msg.contains("ide_catalog"), "error should list ide_catalog: {msg}");
    }

    #[test]
    fn pipe_type_deserialize_rejects_api_and_mcp() {
        for json in [r#"{"type":"api","endpoint":"https://example.com"}"#, r#"{"type":"mcp","server_name":"srv"}"#] {
            let err = serde_json::from_str::<PipeType>(json).expect_err("api and mcp surfaces are not supported");
            assert!(
                err.to_string()
                    .contains("unknown variant"),
                "{err}"
            );
        }
    }

    #[test]
    fn pipe_type_webhook_round_trips() {
        let pipe_type: PipeType =
            serde_json::from_str(r#"{"type":"webhook","endpoint":"https://example.com/hook"}"#).unwrap();
        assert_eq!(
            pipe_type,
            PipeType::Webhook {
                endpoint: "https://example.com/hook".to_string()
            }
        );
        let json = serde_json::to_value(&pipe_type).unwrap();
        assert_eq!(json["type"], "webhook");
    }

    fn sample_pipe() -> PipeConfig {
        PipeConfig::new(
            "p1".to_string(),
            "Test".to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        )
    }

    #[test]
    fn opa_accessors_default_to_disabled() {
        let pipe = sample_pipe();
        assert!(!pipe.opa_enabled());
        assert_eq!(pipe.opa_policy_definition_id(), None);
    }

    #[test]
    fn opa_accessors_reflect_config() {
        let mut pipe = sample_pipe();
        pipe.opa_policy = Some(PipeOpaConfig {
            enabled: true,
            policy_definition_id: Some("def-123".to_string()),
            policy_definition_ids: Vec::new(),
            log_decisions: false,
        });
        assert!(pipe.opa_enabled());
        assert_eq!(pipe.opa_policy_definition_id(), Some("def-123"));
        assert!(!pipe.opa_log_decisions());
    }

    #[test]
    fn opa_enabled_without_definition_id() {
        let mut pipe = sample_pipe();
        pipe.opa_policy = Some(PipeOpaConfig {
            enabled: true,
            policy_definition_id: None,
            policy_definition_ids: Vec::new(),
            log_decisions: false,
        });
        assert!(pipe.opa_enabled());
        assert_eq!(pipe.opa_policy_definition_id(), None);
    }

    #[test]
    fn opa_policy_serde_round_trip() {
        let mut pipe = sample_pipe();
        pipe.opa_policy = Some(PipeOpaConfig {
            enabled: true,
            policy_definition_id: Some("abc".to_string()),
            policy_definition_ids: Vec::new(),
            log_decisions: true,
        });
        let json = serde_json::to_string(&pipe).expect("serialize");
        let back: PipeConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.opa_policy, pipe.opa_policy);
        assert!(back.opa_enabled());
        assert_eq!(back.opa_policy_definition_id(), Some("abc"));
        assert!(back.opa_log_decisions());
    }

    #[test]
    fn opa_log_decisions_defaults_false_and_is_omitted() {
        // A false `log_decisions` must not appear in the serialised JSON
        // (backward-compat: stored configs authored before this field don't
        // carry it, and deserialising them still yields log_decisions=false).
        let mut pipe = sample_pipe();
        pipe.opa_policy = Some(PipeOpaConfig {
            enabled: true,
            policy_definition_id: Some("def-1".to_string()),
            policy_definition_ids: Vec::new(),
            log_decisions: false,
        });
        let out = serde_json::to_value(&pipe).expect("serialize");
        let opa = out
            .get("opa_policy")
            .and_then(|v| v.as_object())
            .expect("opa_policy object");
        assert!(!opa.contains_key("log_decisions"));

        let back: PipeConfig = serde_json::from_value(out).expect("deserialize");
        assert!(back.opa_enabled());
        assert!(!back.opa_log_decisions());
    }

    #[test]
    fn test_surface_defaults_false_and_is_omitted_when_false() {
        let pipe = sample_pipe();
        assert!(!pipe.test_surface);

        // A false flag is skipped in the serialized JSON.
        let json = serde_json::to_value(&pipe).expect("serialize");
        assert!(
            json.get("test_surface")
                .is_none(),
            "test_surface should be omitted when false"
        );

        // An absent field deserializes back to false.
        let back: PipeConfig = serde_json::from_value(json).expect("deserialize");
        assert!(!back.test_surface);
    }

    #[test]
    fn test_surface_true_round_trips() {
        let mut pipe = sample_pipe();
        pipe.test_surface = true;

        let json = serde_json::to_value(&pipe).expect("serialize");
        assert_eq!(
            json.get("test_surface")
                .and_then(|v| v.as_bool()),
            Some(true)
        );

        let back: PipeConfig = serde_json::from_value(json).expect("deserialize");
        assert!(back.test_surface);
    }

    #[test]
    fn opa_policy_absent_serializes_without_field() {
        let pipe = sample_pipe();
        let json = serde_json::to_string(&pipe).expect("serialize");
        assert!(!json.contains("opa_policy"));
    }

    #[test]
    fn vp_evidence_accessor_gates_on_enabled() {
        let mut pipe = minimal_llm_pipe();
        // Absent → not evaluated.
        assert!(pipe.vp_evidence().is_none());
        // Present but disabled → not evaluated.
        pipe.vp_evidence = Some(VpEvidenceConfig {
            enabled: false,
            ..Default::default()
        });
        assert!(pipe.vp_evidence().is_none());
        // Enabled → evaluated; default source is header.
        pipe.vp_evidence = Some(VpEvidenceConfig {
            enabled: true,
            ..Default::default()
        });
        let cfg = pipe
            .vp_evidence()
            .expect("enabled vp evidence");
        assert!(cfg.enabled);
        assert_eq!(cfg.source, VpEvidenceSource::Header);
        // Round-trips through JSON.
        let json = serde_json::to_value(&pipe).expect("serialize");
        let back: PipeConfig = serde_json::from_value(json).expect("deserialize");
        assert!(back.vp_evidence().is_some());
    }

    fn sample_target(provider: &str) -> crate::pipes::judge_jury::LLMTarget {
        crate::pipes::judge_jury::LLMTarget {
            provider_type: provider.to_string(),
            model: "backup-model".to_string(),
            endpoint_url: "https://198.51.100.1/v1/chat/completions".to_string(),
            api_key_secret: Some("backup-secret".to_string()),
            parameters: None,
            timeout_secs: 30,
            capabilities: None,
            api_schema: "openai".to_string(),
            headers: Vec::new(),
            pricing: None,
        }
    }

    #[test]
    fn failover_validate_requires_targets_when_enabled() {
        let cfg = FailoverConfig { enabled: true, targets: vec![] };
        assert!(cfg.validate().is_err());

        let disabled = FailoverConfig {
            enabled: false,
            targets: vec![],
        };
        assert_eq!(disabled.validate(), Ok(()));
    }

    #[test]
    fn failover_validate_rejects_blank_target_fields() {
        let mut target = sample_target("openai");
        target.endpoint_url = "  ".to_string();
        let cfg = FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget { llm: target }],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("endpoint_url"), "unexpected message: {err}");
        assert!(err.contains("failover target 1"), "unexpected message: {err}");
    }

    #[test]
    fn failover_validate_accepts_well_formed_target() {
        let cfg = FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget {
                llm: sample_target("anthropic"),
            }],
        };
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn failover_validate_accepts_relative_endpoint_for_known_provider() {
        // A relative endpoint (resolved against the provider default at runtime)
        // must not be rejected on save. Regression for the failover target being
        // rejected with "relative URL without a base".
        let mut target = sample_target("openai");
        target.endpoint_url = "/chat/completions".to_string();
        let cfg = FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget { llm: target }],
        };
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn failover_validate_rejects_relative_endpoint_for_custom_provider_with_actionable_message() {
        // A custom/catalog provider has no built-in base, so a relative endpoint
        // cannot be resolved. The error must name the provider and ask for an
        // absolute URL rather than surfacing the opaque URL-parser message.
        let mut target = sample_target("testkit-mock-llm");
        target.endpoint_url = "/chat/completions".to_string();
        let cfg = FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget { llm: target }],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("failover target 1"), "unexpected message: {err}");
        assert!(err.contains("absolute URL"), "unexpected message: {err}");
        assert!(err.contains("testkit-mock-llm"), "unexpected message: {err}");
    }

    #[test]
    fn clone_with_failover_target_swaps_provider_and_clears_failover() {
        let mut base = sample_pipe();
        base.pipe_type = PipeType::LLM {
            provider: Box::new(LLMProvider::OpenAI {
                provider_type: "openai".to_string(),
                model: "gpt-4o".to_string(),
                api_key_secret: Some("primary".to_string()),
                organization_id: None,
                base_url: None,
                temperature: None,
                max_tokens: None,
                top_p: None,
                frequency_penalty: None,
                presence_penalty: None,
            }),
            endpoint_path: None,
        };
        base.failover = Some(FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget {
                llm: sample_target("anthropic"),
            }],
        });
        base.decider = None;

        let alt = base.clone_with_failover_target(&sample_target("anthropic"));

        // Backup attempt must not recurse into further failover or routing.
        assert!(alt.failover.is_none());
        assert!(alt.decider.is_none());
        // Provider must be swapped to the backup target's provider.
        match alt.pipe_type {
            PipeType::LLM { provider, .. } => match *provider {
                LLMProvider::Anthropic { model, .. } => {
                    assert_eq!(model, "backup-model");
                }
                other => panic!("expected Anthropic provider, got {other:?}"),
            },
            other => panic!("expected LLM pipe type, got {other:?}"),
        }
        // Identity is preserved so the backup is observed under the same id.
        assert_eq!(alt.id, base.id);
    }

    fn header(
        name: &str,
        secret_id: &str,
    ) -> crate::pipes::upstream_headers::UpstreamHeader {
        crate::pipes::upstream_headers::UpstreamHeader {
            name: name.to_string(),
            secret_id: secret_id.to_string(),
        }
    }

    fn free() -> crate::pipes::types::llm::TargetPricing {
        crate::pipes::types::llm::TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        }
    }

    #[test]
    fn clone_with_failover_target_carries_the_targets_own_headers_and_never_the_bases() {
        // Extra upstream headers are the base upstream's credentials; a backup
        // target is a different upstream and gets its own, never the base's.
        let mut base = sample_pipe();
        base.upstream_headers = vec![header("x-asp-api-key", "base-tunnel-secret")];
        let mut target = sample_target("openai");
        target.headers = vec![header("x-asp-api-key", "backup-tunnel-secret")];

        let alt = base.clone_with_failover_target(&target);

        assert_eq!(alt.upstream_headers, vec![header("x-asp-api-key", "backup-tunnel-secret")]);
    }

    #[test]
    fn clone_with_failover_target_sends_no_headers_for_a_target_that_names_none() {
        let mut base = sample_pipe();
        base.upstream_headers = vec![header("x-asp-api-key", "base-tunnel-secret")];

        let alt = base.clone_with_failover_target(&sample_target("anthropic"));

        assert!(
            alt.upstream_headers
                .is_empty(),
            "a failover/load-balancing target must not inherit the base upstream's headers"
        );
    }

    #[test]
    fn clone_with_failover_target_prices_the_target_and_never_inherits_the_base_price() {
        let mut base = sample_pipe();
        base.upstream_pricing = Some(free());

        let unpriced = base.clone_with_failover_target(&sample_target("openai"));
        assert_eq!(unpriced.upstream_pricing, None, "the base's own price must not follow a backup");

        let mut priced_target = sample_target("openai");
        priced_target.pricing = Some(free());
        base.upstream_pricing = None;
        let priced = base.clone_with_failover_target(&priced_target);
        assert_eq!(priced.upstream_pricing, Some(free()));
    }

    #[test]
    fn a_routed_copy_sends_the_targets_headers_only_to_the_targets_own_host() {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let base = sample_pipe();
        let mut carried = Vec::new();
        for provider_type in ["openai", "anthropic", "gemini", "cohere", "together_ai", "replicate"] {
            let mut target = sample_target(provider_type);
            target.endpoint_url = "https://gateway.example/v1/chat/completions".to_string();
            target.headers = vec![header("x-gateway-key", "gateway-secret")];

            let alt = base.clone_with_failover_target(&target);
            let PipeType::LLM { provider, .. } = &alt.pipe_type else {
                panic!("the copy is an LLM surface");
            };
            let sent_to = url::Url::parse(&provider.get_endpoint())
                .ok()
                .and_then(|url| {
                    url.host_str()
                        .map(str::to_string)
                })
                .unwrap_or_default();
            if alt
                .upstream_headers
                .is_empty()
            {
                continue;
            }
            assert_eq!(sent_to, "gateway.example", "{provider_type}: the target's header would be sent to {sent_to}");
            carried.push(provider_type);
        }
        assert_eq!(carried, vec!["openai"], "precondition: a provider that calls endpoint_url keeps its headers");
    }

    #[test]
    fn failover_serde_round_trip_and_absent_field() {
        let pipe = sample_pipe();
        let json = serde_json::to_string(&pipe).expect("serialize");
        assert!(!json.contains("failover"));

        let mut with_failover = sample_pipe();
        with_failover.failover = Some(FailoverConfig {
            enabled: true,
            targets: vec![FailoverTarget { llm: sample_target("gemini") }],
        });
        let json = serde_json::to_string(&with_failover).expect("serialize");
        let back: PipeConfig = serde_json::from_str(&json).expect("deserialize");
        let restored = back
            .failover
            .expect("failover present");
        assert!(restored.enabled);
        assert_eq!(restored.targets.len(), 1);
        assert_eq!(
            restored.targets[0]
                .llm
                .provider_type,
            "gemini"
        );
    }

    #[test]
    fn load_balancing_validate_requires_targets_when_enabled() {
        let cfg = LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 1,
            targets: vec![],
        };
        assert!(cfg.validate().is_err());

        let disabled = LoadBalancingConfig {
            enabled: false,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 0,
            targets: vec![],
        };
        assert_eq!(disabled.validate(), Ok(()));
    }

    #[test]
    fn load_balancing_validate_rejects_zero_total_weight() {
        let cfg = LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 0,
            targets: vec![WeightedTarget {
                llm: sample_target("anthropic"),
                weight: 0,
            }],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("total weight"), "unexpected message: {err}");
    }

    #[test]
    fn load_balancing_validate_accepts_well_formed_pool() {
        let cfg = LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 3,
            targets: vec![WeightedTarget {
                llm: sample_target("anthropic"),
                weight: 1,
            }],
        };
        assert_eq!(cfg.validate(), Ok(()));
    }

    #[test]
    fn load_balancing_validate_rejects_blank_target_fields() {
        let mut target = sample_target("openai");
        target.endpoint_url = "  ".to_string();
        let cfg = LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 1,
            targets: vec![WeightedTarget { llm: target, weight: 1 }],
        };
        let err = cfg.validate().unwrap_err();
        assert!(err.contains("endpoint_url"), "unexpected message: {err}");
        assert!(err.contains("load balancing target 1"), "unexpected message: {err}");
    }

    #[test]
    fn clone_with_failover_target_clears_load_balancing() {
        let mut base = sample_pipe();
        base.load_balancing = Some(LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 1,
            targets: vec![WeightedTarget {
                llm: sample_target("anthropic"),
                weight: 1,
            }],
        });
        let alt = base.clone_with_failover_target(&sample_target("anthropic"));
        // A transient pool-member executor must not recurse into load balancing.
        assert!(alt.load_balancing.is_none());
    }

    #[test]
    fn load_balancing_serde_round_trip_and_absent_field() {
        let pipe = sample_pipe();
        let json = serde_json::to_string(&pipe).expect("serialize");
        assert!(!json.contains("load_balancing"));

        let mut with_lb = sample_pipe();
        with_lb.load_balancing = Some(LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::Weighted,
            primary_weight: 2,
            targets: vec![WeightedTarget {
                llm: sample_target("gemini"),
                weight: 5,
            }],
        });
        let json = serde_json::to_string(&with_lb).expect("serialize");
        let back: PipeConfig = serde_json::from_str(&json).expect("deserialize");
        let restored = back
            .load_balancing
            .expect("load_balancing present");
        assert!(restored.enabled);
        assert_eq!(restored.primary_weight, 2);
        assert_eq!(restored.targets.len(), 1);
        assert_eq!(restored.targets[0].weight, 5);
    }

    #[test]
    fn usage_limit_cumulative_validates_with_budget() {
        let limit = UsageLimit {
            id: "ul-1".to_string(),
            enabled: true,
            scope: UsageScope::Cumulative,
            stage: None,
            juror_index: None,
            monthly_budget_usd: Some(50.0),
            monthly_token_cap: None,
        };
        assert_eq!(limit.validate(), Ok(()));
        assert_eq!(limit.scope_key(), "cumulative");
    }

    #[test]
    fn usage_limit_stage_scope_key_reflects_stage() {
        let limit = UsageLimit {
            id: "ul-jury".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: Some(UsageStage::Jury),
            juror_index: None,
            monthly_budget_usd: None,
            monthly_token_cap: Some(100_000),
        };
        assert_eq!(limit.validate(), Ok(()));
        assert_eq!(limit.scope_key(), "stage:jury");
    }

    #[test]
    fn usage_limit_juror_scope_key_includes_index() {
        let limit = UsageLimit {
            id: "ul-juror".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: Some(UsageStage::Jury),
            juror_index: Some(2),
            monthly_budget_usd: None,
            monthly_token_cap: Some(100_000),
        };
        assert_eq!(limit.validate(), Ok(()));
        assert_eq!(limit.scope_key(), "stage:juror:2");
    }

    #[test]
    fn usage_limit_stage_without_stage_is_rejected() {
        let limit = UsageLimit {
            id: "ul-bad".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: None,
            juror_index: None,
            monthly_budget_usd: Some(10.0),
            monthly_token_cap: None,
        };
        assert!(limit.validate().is_err());
    }

    #[test]
    fn usage_limit_without_any_cap_is_rejected() {
        let limit = UsageLimit {
            id: "ul-empty".to_string(),
            enabled: true,
            scope: UsageScope::Cumulative,
            stage: None,
            juror_index: None,
            monthly_budget_usd: None,
            monthly_token_cap: None,
        };
        assert!(limit.validate().is_err());
    }

    #[test]
    fn usage_limit_negative_budget_is_rejected() {
        let limit = UsageLimit {
            id: "ul-neg".to_string(),
            enabled: true,
            scope: UsageScope::Cumulative,
            stage: None,
            juror_index: None,
            monthly_budget_usd: Some(-1.0),
            monthly_token_cap: None,
        };
        assert!(limit.validate().is_err());
    }

    #[test]
    fn usage_limits_round_trip_on_pipe() {
        let mut pipe = sample_pipe();
        pipe.usage_limits = vec![UsageLimit {
            id: "ul-1".to_string(),
            enabled: true,
            scope: UsageScope::Stage,
            stage: Some(UsageStage::Judge),
            juror_index: None,
            monthly_budget_usd: Some(25.0),
            monthly_token_cap: Some(500_000),
        }];
        let json = serde_json::to_string(&pipe).expect("serialize");
        let back: PipeConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.usage_limits.len(), 1);
        assert_eq!(back.usage_limits[0].scope_key(), "stage:judge");
        assert_eq!(back.usage_limits[0].monthly_token_cap, Some(500_000));
    }

    #[test]
    fn usage_limits_absent_serializes_without_field() {
        let pipe = sample_pipe();
        let json = serde_json::to_string(&pipe).expect("serialize");
        assert!(!json.contains("usage_limits"));
    }

    // ── Wire-shape drift guards ──────────────────────────────────────────────
    // The TanStack/React frontend hand-mirrors these serde shapes (see
    // `www/default/src/pages/EditPipePage/types.ts` and `resilienceModel.ts`).
    // These tests pin the exact JSON field names and enum string values so a
    // backend rename can't silently break the frontend contract.

    #[test]
    fn alert_type_wire_strings_are_snake_case() {
        // Must match the frontend `UsageAlertType` union exactly.
        let pairs = [
            (AlertType::CostThreshold, "cost_threshold"),
            (AlertType::TokenThreshold, "token_threshold"),
            (AlertType::ErrorRate, "error_rate"),
            (AlertType::CostSpike, "cost_spike"),
        ];
        for (variant, expected) in pairs {
            let value = serde_json::to_value(&variant).expect("serialize alert type");
            assert_eq!(value, serde_json::Value::String(expected.to_string()));
            let back: AlertType = serde_json::from_value(serde_json::json!(expected)).expect("deserialize alert type");
            assert_eq!(serde_json::to_value(&back).unwrap(), value);
        }
    }

    #[test]
    fn usage_alert_wire_shape_keys_match_frontend() {
        let alert = UsageAlert {
            alert_type: AlertType::CostSpike,
            threshold: 2.5,
            notification_channels: vec!["int-1".to_string()],
        };
        let value = serde_json::to_value(&alert).expect("serialize");
        let obj = value
            .as_object()
            .expect("object");
        assert_eq!(obj["alert_type"], "cost_spike");
        assert_eq!(obj["threshold"], 2.5);
        assert_eq!(obj["notification_channels"], serde_json::json!(["int-1"]));
        // Exactly the three fields the frontend `UsageAlertForm` carries.
        assert_eq!(obj.len(), 3);

        let back: UsageAlert = serde_json::from_value(value).expect("deserialize");
        assert!(matches!(back.alert_type, AlertType::CostSpike));
        assert_eq!(back.threshold, 2.5);
        assert_eq!(back.notification_channels, vec!["int-1".to_string()]);
    }

    #[test]
    fn streaming_config_wire_shape() {
        let value = serde_json::to_value(StreamingConfig { enabled: false }).expect("serialize");
        assert_eq!(value, serde_json::json!({ "enabled": false }));
        let back: StreamingConfig =
            serde_json::from_value(serde_json::json!({ "enabled": true })).expect("deserialize");
        assert!(back.enabled);
        // Omitted `enabled` defaults to true (the frontend treats absent as on).
        let defaulted: StreamingConfig = serde_json::from_value(serde_json::json!({})).expect("deserialize default");
        assert!(defaulted.enabled);
    }

    #[test]
    fn failover_target_wire_shape_wraps_llm() {
        let target = FailoverTarget { llm: sample_target("openai") };
        let value = serde_json::to_value(&target).expect("serialize");
        // The frontend `FailoverTarget` is `{ llm: DeciderLlm }`.
        let obj = value
            .as_object()
            .expect("object");
        assert_eq!(obj.len(), 1);
        assert!(obj.contains_key("llm"));
    }

    #[test]
    fn weighted_target_wire_shape_has_llm_and_weight() {
        let target = WeightedTarget {
            llm: sample_target("openai"),
            weight: 3,
        };
        let value = serde_json::to_value(&target).expect("serialize");
        let obj = value
            .as_object()
            .expect("object");
        // The frontend `WeightedTarget` is `{ llm: DeciderLlm; weight: number }`.
        assert_eq!(obj["weight"], 3);
        assert!(obj.contains_key("llm"));
    }

    #[test]
    fn llm_target_wire_shape_matches_decider_llm() {
        let value = serde_json::to_value(sample_target("openai")).expect("serialize");
        let obj = value
            .as_object()
            .expect("object");
        // Keys the frontend `DeciderLlm` mirror reads/writes.
        for key in ["provider_type", "model", "endpoint_url", "api_key_secret", "timeout_secs", "api_schema"] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        assert_eq!(obj["provider_type"], "openai");
        assert_eq!(obj["api_schema"], "openai");
    }

    fn sample_external_guardrail() -> crate::pipes::prompt_guard::ExternalGuardrailConfig {
        crate::pipes::prompt_guard::ExternalGuardrailConfig {
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
        }
    }

    fn sample_witness(id: &str) -> crate::pipes::prompt_guard::ExpertWitnessConfig {
        crate::pipes::prompt_guard::ExpertWitnessConfig {
            id: id.to_string(),
            name: id.to_string(),
            guardrail: sample_external_guardrail(),
        }
    }

    #[test]
    fn normalize_guardrails_migrates_legacy_external_into_witness() {
        let mut pipe = sample_pipe();
        pipe.prompt_guard = Some(crate::pipes::prompt_guard::PromptGuardConfig {
            enabled: true,
            request: Vec::new(),
            response: Vec::new(),
            external: Some(sample_external_guardrail()),
            llm_pii: Vec::new(),
        });

        pipe.normalize_guardrails();

        // The legacy block is moved into exactly one witness…
        assert_eq!(pipe.expert_witnesses.len(), 1);
        let witness = &pipe.expert_witnesses[0];
        assert_eq!(witness.id, "migrated-external-guardrail");
        assert_eq!(witness.guardrail.endpoint_url, "https://api.enkryptai.com/guardrails/detect");
        // …and the legacy slot is cleared so it is not consulted twice.
        assert!(
            pipe.prompt_guard
                .as_ref()
                .unwrap()
                .external
                .is_none()
        );
    }

    #[test]
    fn normalize_guardrails_is_idempotent() {
        let mut pipe = sample_pipe();
        pipe.prompt_guard = Some(crate::pipes::prompt_guard::PromptGuardConfig {
            enabled: true,
            request: Vec::new(),
            response: Vec::new(),
            external: Some(sample_external_guardrail()),
            llm_pii: Vec::new(),
        });

        pipe.normalize_guardrails();
        pipe.normalize_guardrails();

        // Migrating twice must not duplicate the witness.
        assert_eq!(pipe.expert_witnesses.len(), 1);
    }

    #[test]
    fn normalize_guardrails_noop_when_witnesses_present() {
        let mut pipe = sample_pipe();
        pipe.expert_witnesses = vec![sample_witness("hand-authored")];
        pipe.prompt_guard = Some(crate::pipes::prompt_guard::PromptGuardConfig {
            enabled: true,
            request: Vec::new(),
            response: Vec::new(),
            external: Some(sample_external_guardrail()),
            llm_pii: Vec::new(),
        });

        pipe.normalize_guardrails();

        // A config authored against the witness model wins: the legacy block is
        // left untouched and the hand-authored witness is preserved.
        assert_eq!(pipe.expert_witnesses.len(), 1);
        assert_eq!(pipe.expert_witnesses[0].id, "hand-authored");
        assert!(
            pipe.prompt_guard
                .as_ref()
                .unwrap()
                .external
                .is_some()
        );
    }

    #[test]
    fn normalize_guardrails_noop_when_nothing_to_migrate() {
        let mut pipe = sample_pipe();
        pipe.normalize_guardrails();
        assert!(
            pipe.expert_witnesses
                .is_empty()
        );
    }

    #[test]
    fn expert_witnesses_serde_round_trip_and_absent_field() {
        let pipe = sample_pipe();
        let json = serde_json::to_string(&pipe).expect("serialize");
        // Empty witness list is skipped on the wire.
        assert!(!json.contains("expert_witnesses"));

        let mut with_witnesses = sample_pipe();
        with_witnesses.expert_witnesses = vec![sample_witness("w1"), sample_witness("w2")];
        let json = serde_json::to_string(&with_witnesses).expect("serialize");
        let back: PipeConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.expert_witnesses.len(), 2);
        assert_eq!(back.expert_witnesses[0].id, "w1");
        assert_eq!(back.expert_witnesses[1].id, "w2");
    }
}
