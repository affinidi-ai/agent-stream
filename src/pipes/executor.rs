//! Pipe execution engine with rate limiting, circuit breaking, and retry logic

use super::{
    config::{CircuitBreakerConfig, PipeConfig, StageUsage},
    key_source::{CallKey, CallerCredentials, CallerKey, KeySource, KeySourceCounts},
    parsers::llm_parser,
};
use crate::secrets::SecretsStore;
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration as StdDuration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{Instrument, debug, info, warn};

// ── HTTP client defaults ──────────────────────────────────────────────────────
const HTTP_POOL_MAX_IDLE_PER_HOST: usize = 10;
const HTTP_POOL_IDLE_TIMEOUT_SECS: u64 = 90;
const HTTP_TCP_KEEPALIVE_SECS: u64 = 60;
/// Connect timeout for the streaming client. Applies only to the TCP/TLS
/// handshake — the body-read is intentionally unbounded for long generations.
const HTTP_STREAMING_CONNECT_TIMEOUT_SECS: u64 = 30;

// ── Circuit-breaker fallback defaults ────────────────────────────────────────
const DEFAULT_CB_FAILURE_THRESHOLD: u32 = 5;
const DEFAULT_CB_TIMEOUT_SECS: u64 = 60;
const DEFAULT_CB_RESET_TIMEOUT_SECS: u64 = 30;

/// A binary upstream response (e.g. text-to-speech audio) proxied verbatim.
/// Returned by [`PipeExecutor::execute_binary`].
pub struct BinaryResponse {
    /// Raw response body bytes.
    pub bytes: Vec<u8>,
    /// Upstream `Content-Type` (e.g. `audio/mpeg`).
    pub content_type: String,
    /// Response body size in bytes.
    pub response_bytes: u64,
    /// The source of the credentials the call sent.
    pub key_source: KeySource,
    /// What the call cost at its upstream's price: a binary passthrough's
    /// input text (see [`PipeExecutor::execute_binary`]); zero for a file
    /// upload or a poll, which bill nothing.
    pub cost: f64,
}

impl BinaryResponse {
    /// The part of [`Self::cost`] billed to the account (see
    /// [`KeySource::billed_cost`]).
    pub fn billed_cost(&self) -> f64 {
        self.key_source
            .billed_cost(self.cost)
    }
}

#[derive(Debug, Clone, Default)]
pub struct ExecutionMetrics {
    /// Grand-total input tokens across the LLM (all attempts) plus Judge and Jury.
    pub input_tokens: u64,
    /// Grand-total output tokens across the LLM (all attempts) plus Judge and Jury.
    pub output_tokens: u64,
    /// Grand-total tokens across every stage.
    pub total_tokens: u64,
    /// Grand-total spend across every stage.
    pub cost: f64,
    /// Main LLM stage usage, summed across every attempt (including jury-retry
    /// attempts). Drives monthly budget enforcement — the grand totals above must
    /// never feed the budget tracker or Judge/Jury spend would be double-counted,
    /// since the Judge/Jury stages record their own budget buckets directly.
    pub llm_usage: StageUsage,
    /// Judge stage usage for this execution (zero when no Judge ran).
    pub judge_usage: StageUsage,
    /// Jury stage usage for this execution, summed across every juror and attempt.
    pub jury_usage: StageUsage,
    /// Decider (router) stage usage for this execution (zero when no Decider ran).
    pub decider_usage: StageUsage,
    pub latency_ms: u64,
    pub provider: String,
    pub model: String,
    // Distributed tracing
    pub trace_id: String,
    pub correlation_id: Option<String>,
    pub agent_identity: Option<String>,
    // Enhanced metrics
    pub request_bytes: u64,
    pub response_bytes: u64,
    /// Request latency: time spent in gateway preparing/processing the request before sending to target
    pub time_to_first_token_ms: Option<u64>,
    pub retry_count: u32,
    /// Judge/Jury rejections that were *recovered* by a redrive within this
    /// (ultimately successful) execution. Recorded into rejection telemetry
    /// under the synthetic `redrive` category by the handler seam; the real
    /// content category is reserved for executions that are finally blocked.
    pub redrive_rejections: Vec<RejectionMeta>,
    /// Provider-side cached prompt tokens reported by the upstream (OpenAI
    /// `cached_tokens`, Anthropic `cache_read_input_tokens`, DeepSeek
    /// `prompt_cache_hit_tokens`). Measures the provider's own prompt cache —
    /// distinct from Agent Stream's response cache — for cost-savings visibility.
    /// `0` when the provider reports none.
    pub cached_tokens: u64,
    /// Provider-side **cache-write** (cache-creation) prompt tokens reported by
    /// the upstream (Anthropic `cache_creation_input_tokens`). Tokens written
    /// into the provider prompt cache this turn, billed at a premium. `0` when
    /// the provider reports none.
    pub cache_write_tokens: u64,
    /// Provider-reported reasoning (thinking) tokens for this execution (OpenAI
    /// `completion_tokens_details.reasoning_tokens`). A sub-count of the output
    /// tokens already billed — surfaced for visibility, not an extra charge.
    /// `0` when the provider does not break them out (Anthropic, Gemini).
    pub reasoning_tokens: u64,
    /// Structured-output conformance: `Some(true)`/`Some(false)` when the request
    /// asked for a `json_schema` response and the completion was validated
    /// against it; `None` when no structured output was requested.
    pub schema_valid: Option<bool>,
    /// The Microsoft 365 Copilot conversation id this execution ran against
    /// (created fresh, or reused from the caller). `None` for non-Copilot
    /// schemas. Returned to the caller so a follow-up can continue the same
    /// stateful conversation for native multi-turn memory.
    pub conversation_id: Option<String>,
    /// Resolved governance-relevant pipeline stages (expert witness, decider,
    /// judge, jury, and recovered redrive rejections) in pipeline order,
    /// retained from a successful execution so a governance record shows what let
    /// the interaction through — not just the final `llm_call`. Empty when none
    /// of those stages ran.
    pub stages: Vec<StageRecord>,
    /// Whether this execution was served from the response cache (no upstream
    /// call). Recorded as successful traffic at `cost = 0`; the avoided spend is
    /// carried on `cache_saved_cost`.
    pub cache_hit: bool,
    /// Provider spend avoided by a cache hit (what the upstream call would have
    /// cost). `0.0` for non-cache executions.
    pub cache_saved_cost: f64,
    /// Grand-total spend billed to the account across every stage: `cost` less
    /// the spend served on owned keys (see [`crate::pipes::key_source`]). The
    /// member budget counts this, never `cost`.
    pub billed_cost: f64,
    /// The source of the key the main call sent. `None` when no single main
    /// call ran: a cache hit, or a Mirror Collect over keys from several sources.
    pub key_source: Option<KeySource>,
}

/// The disposition of a resolved pipeline stage in the execution transcript.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StageDecision {
    /// The stage permitted the interaction to continue.
    Allow,
    /// The stage flagged the content but the interaction still completed (e.g. a
    /// Judge/Jury rejection later recovered by a redrive).
    Flag,
    /// The stage ran informationally with no allow/block disposition (e.g. the
    /// Decider's routing choice).
    Observed,
}

/// One resolved governance-relevant pipeline stage retained from an execution,
/// mapped into a governance record's stage transcript.
#[derive(Debug, Clone)]
pub struct StageRecord {
    /// Stable stage name (`expert_witness_request`, `decider`, `judge`, `jury`,
    /// `expert_witness_response`, or a recovered-rejection seam label).
    pub stage: String,
    /// What the stage decided.
    pub decision: StageDecision,
    /// Human-readable detail (verdict, chosen model, token/cost summary).
    pub detail: Option<String>,
    /// The content this stage evaluated (sent to its model/provider). Body
    /// gating + digesting is applied downstream by the governance capture.
    pub input: Option<String>,
    /// The stage's output (model verdict / provider response).
    pub output: Option<String>,
    /// The source of the key this stage's model or provider call sent, when it
    /// made one (or every one of its calls used keys from the same source).
    pub key_source: Option<KeySource>,
}

/// Map an execution's resolved stage transcript into governance stage entries.
fn stage_records_to_entries(records: &[StageRecord]) -> Vec<crate::governance::StageEntry> {
    records
        .iter()
        .map(|s| {
            let outcome = match s.decision {
                StageDecision::Allow => crate::governance::StageOutcome::Allow,
                StageDecision::Flag => crate::governance::StageOutcome::Flag,
                StageDecision::Observed => crate::governance::StageOutcome::Observed,
            };
            crate::governance::StageEntry::decision(s.stage.clone(), outcome, s.detail.clone())
                .with_io(s.input.clone(), s.output.clone())
                .with_key_source(s.key_source)
        })
        .collect()
}

impl ExecutionMetrics {
    /// Add spend an earlier failed attempt of the same request already
    /// incurred (a retry, or a failover, load-balancing or routed target that
    /// failed before another served), so the request is billed for it.
    pub fn absorb_incurred(
        &mut self,
        incurred: &RejectedExecutionUsage,
    ) {
        if incurred.is_empty() {
            return;
        }
        for stage in [&incurred.llm, &incurred.judge, &incurred.jury, &incurred.decider] {
            self.input_tokens += stage.input_tokens;
            self.output_tokens += stage.output_tokens;
            self.total_tokens += stage.total_tokens();
            self.cost += stage.cost;
            self.billed_cost += stage.billed_cost;
        }
        self.llm_usage
            .add(incurred.llm);
        self.judge_usage
            .add(incurred.judge);
        self.jury_usage
            .add(incurred.jury);
        self.decider_usage
            .add(incurred.decider);
    }

    /// The whole execution's spend, stage by stage, as the spend a later
    /// failure of the same request already incurred.
    pub fn as_incurred(&self) -> RejectedExecutionUsage {
        RejectedExecutionUsage {
            llm: self.llm_usage,
            judge: self.judge_usage,
            jury: self.jury_usage,
            decider: self.decider_usage,
        }
    }

    /// The resolved stage transcript as governance stage entries, in pipeline
    /// order, ready to attach to a record's `extra_stages`.
    pub fn governance_stages(&self) -> Vec<crate::governance::StageEntry> {
        stage_records_to_entries(&self.stages)
    }

    /// Usage of each stage that called a model, each under its own provider and
    /// model (the grand totals book everything to the main call's model).
    pub fn usage_by_stage(
        &self,
        config: &PipeConfig,
    ) -> Vec<crate::governance::StageUsageEntry> {
        stage_usage_entries(
            config,
            &self.provider,
            &self.model,
            &self.llm_usage,
            &self.judge_usage,
            &self.jury_usage,
            &self.decider_usage,
        )
    }

    /// Every metered model call this execution made (main, Judge, Jury and
    /// Decider), by the source of the key each one sent.
    pub fn key_sources(&self) -> KeySourceCounts {
        let mut counts = self.llm_usage.key_sources;
        counts.add(self.judge_usage.key_sources);
        counts.add(self.jury_usage.key_sources);
        counts.add(self.decider_usage.key_sources);
        counts
    }

    /// The governance record's metrics for this execution: grand totals, the
    /// currency and the per-stage split.
    pub fn record_metrics(
        &self,
        config: &PipeConfig,
    ) -> crate::governance::RecordMetrics {
        let key_sources = self.key_sources();
        crate::governance::RecordMetrics {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            total_tokens: self.total_tokens,
            cost: self.cost,
            latency_ms: self.latency_ms,
            provider: (!self.provider.is_empty()).then(|| self.provider.clone()),
            model: (!self.model.is_empty()).then(|| self.model.clone()),
            currency: crate::governance::RecordMetrics::usd(),
            usage_by_stage: self.usage_by_stage(config),
            billed_cost: Some(self.billed_cost),
            key_source: self.key_source,
            key_sources: (!key_sources.is_empty()).then_some(key_sources),
            usage_estimated: None,
        }
    }
}

/// Provider and model a juror pool calls: the shared pair when every enabled
/// juror uses the same one, else `(None, None)`.
fn jury_provider_model(config: &PipeConfig) -> (Option<String>, Option<String>) {
    let Some(jury) = config.jury.as_ref() else {
        return (None, None);
    };
    let mut pairs = jury
        .jurors
        .iter()
        .filter(|j| j.enabled)
        .map(|j| (j.llm.provider_type.as_str(), j.llm.model.as_str()));
    let Some(first) = pairs.next() else {
        return (None, None);
    };
    if pairs.all(|p| p == first) {
        (Some(first.0.to_string()), Some(first.1.to_string()))
    } else {
        (None, None)
    }
}

/// One entry per stage that called a model (any tokens or cost), each with the
/// provider and model that stage is configured to call. The main LLM stage uses
/// the provider and model the execution resolved.
pub fn stage_usage_entries(
    config: &PipeConfig,
    llm_provider: &str,
    llm_model: &str,
    llm: &StageUsage,
    judge: &StageUsage,
    jury: &StageUsage,
    decider: &StageUsage,
) -> Vec<crate::governance::StageUsageEntry> {
    let non_empty = |s: &str| (!s.is_empty()).then(|| s.to_string());
    let (jury_provider, jury_model) = jury_provider_model(config);
    let judge_target = config
        .judge
        .as_ref()
        .map(|j| (j.llm.provider_type.clone(), j.llm.model.clone()));
    let decider_target = config
        .decider
        .as_ref()
        .and_then(|d| d.llm.as_ref())
        .map(|l| (l.provider_type.clone(), l.model.clone()));
    let stages: [(&str, &StageUsage, Option<String>, Option<String>); 4] = [
        ("llm", llm, non_empty(llm_provider), non_empty(llm_model)),
        (
            "judge",
            judge,
            judge_target
                .clone()
                .map(|t| t.0),
            judge_target.map(|t| t.1),
        ),
        ("jury", jury, jury_provider, jury_model),
        (
            "decider",
            decider,
            decider_target
                .clone()
                .map(|t| t.0),
            decider_target.map(|t| t.1),
        ),
    ];
    stages
        .into_iter()
        .filter(|(_, u, _, _)| u.total_tokens() > 0 || u.cost > 0.0)
        .map(|(stage, u, provider, model)| crate::governance::StageUsageEntry {
            stage: stage.to_string(),
            provider,
            model,
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            cost: u.cost,
            billed_cost: Some(u.billed_cost),
            key_sources: (!u.key_sources.is_empty()).then_some(u.key_sources),
        })
        .collect()
}

/// Which pipeline seam produced a content rejection, for rejection telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionStage {
    RegexRequest,
    RegexResponse,
    WitnessRequest,
    WitnessResponse,
    Judge,
    Jury,
}

impl RejectionStage {
    /// Stable label used as the telemetry stage segment for this seam.
    pub fn label(&self) -> &'static str {
        match self {
            RejectionStage::RegexRequest => "regex_request",
            RejectionStage::RegexResponse => "regex_response",
            RejectionStage::WitnessRequest => "witness_request",
            RejectionStage::WitnessResponse => "witness_response",
            RejectionStage::Judge => "judge",
            RejectionStage::Jury => "jury",
        }
    }
}

/// Billable stage usage consumed before an execution was rejected.
#[derive(Debug, Clone, Default)]
pub struct RejectedExecutionUsage {
    pub llm: StageUsage,
    pub judge: StageUsage,
    pub jury: StageUsage,
    pub decider: StageUsage,
}

impl RejectedExecutionUsage {
    /// Whether no stage spent anything.
    pub fn is_empty(&self) -> bool {
        [self.llm, self.judge, self.jury, self.decider]
            .iter()
            .all(|stage| *stage == StageUsage::default())
    }

    /// Add another execution's spend, stage by stage.
    pub fn add(
        &mut self,
        other: &Self,
    ) {
        self.llm.add(other.llm);
        self.judge.add(other.judge);
        self.jury.add(other.jury);
        self.decider
            .add(other.decider);
    }

    /// Every stage's tokens.
    pub fn total_tokens(&self) -> u64 {
        self.llm.total_tokens() + self.judge.total_tokens() + self.jury.total_tokens() + self.decider.total_tokens()
    }

    pub fn total_cost(&self) -> f64 {
        self.llm.cost + self.judge.cost + self.jury.cost + self.decider.cost
    }

    /// The part of [`Self::total_cost`] billed to the account (see
    /// [`StageUsage::billed_cost`]).
    pub fn total_billed_cost(&self) -> f64 {
        self.llm.billed_cost + self.judge.billed_cost + self.jury.billed_cost + self.decider.billed_cost
    }

    /// The source of the key the main call sent, when it ran on keys from one
    /// source.
    pub fn key_source(&self) -> Option<KeySource> {
        self.llm.key_sources.sole()
    }

    /// The incurred usage's metered model calls, by key source.
    pub fn key_sources(&self) -> KeySourceCounts {
        let mut counts = self.llm.key_sources;
        counts.add(self.judge.key_sources);
        counts.add(self.jury.key_sources);
        counts.add(self.decider.key_sources);
        counts
    }

    /// The blocked governance record's metrics: the tokens and cost spent
    /// before the block, per stage. `provider` / `model` are the main call's,
    /// as resolved from the surface's configuration (no response was received).
    pub fn record_metrics(
        &self,
        config: &PipeConfig,
        provider: &str,
        model: &str,
    ) -> crate::governance::RecordMetrics {
        let input_tokens =
            self.llm.input_tokens + self.judge.input_tokens + self.jury.input_tokens + self.decider.input_tokens;
        let output_tokens =
            self.llm.output_tokens + self.judge.output_tokens + self.jury.output_tokens + self.decider.output_tokens;
        let key_sources = self.key_sources();
        crate::governance::RecordMetrics {
            input_tokens,
            output_tokens,
            total_tokens: input_tokens + output_tokens,
            cost: self.total_cost(),
            latency_ms: 0,
            provider: (!provider.is_empty()).then(|| provider.to_string()),
            model: (!model.is_empty()).then(|| model.to_string()),
            currency: crate::governance::RecordMetrics::usd(),
            usage_by_stage: stage_usage_entries(
                config,
                provider,
                model,
                &self.llm,
                &self.judge,
                &self.jury,
                &self.decider,
            ),
            billed_cost: Some(self.total_billed_cost()),
            key_source: self.key_source(),
            key_sources: (!key_sources.is_empty()).then_some(key_sources),
            usage_estimated: None,
        }
    }
}

/// Summary of one model-PII detection pass (possibly several detectors run in
/// parallel), used to build the `prompt_guard_model_pii` governance stage.
struct ModelPiiOutcome {
    detectors: usize,
    masked: usize,
    failed: usize,
    /// The detectors' calls, by the source of the key each one sent.
    key_sources: KeySourceCounts,
}

/// `(is_flag, detail)` for the `prompt_guard_model_pii` governance stage. Both
/// pipeline paths share the wording; each maps `is_flag` onto its own stage enum.
fn model_pii_stage_detail(outcome: &ModelPiiOutcome) -> (bool, String) {
    let plural = |n: usize| if n == 1 { "" } else { "s" };
    if outcome.failed > 0 {
        (
            true,
            format!(
                "{} of {} detector{} unavailable — request continued with regex masking only",
                outcome.failed,
                outcome.detectors,
                plural(outcome.detectors)
            ),
        )
    } else {
        (
            false,
            format!(
                "{} PII value{} masked by {} detector{}",
                outcome.masked,
                plural(outcome.masked),
                outcome.detectors,
                plural(outcome.detectors)
            ),
        )
    }
}

/// Structured detail attached to a content rejection so the raw provider/judge/
/// jury reason tokens survive to the telemetry boundary instead of being
/// flattened into the response body. The handler classifies `raw_reasons`
/// (interpreted in the context of `source`) into canonical categories.
#[derive(Debug, Clone)]
pub struct RejectionMeta {
    pub stage: RejectionStage,
    pub source: String,
    pub raw_reasons: Vec<String>,
    /// The rejecting stage's input (the content it evaluated), attached so a
    /// governance block record can show what triggered the rejection.
    pub input: Option<String>,
    /// The rejecting stage's output (its verdict / provider response).
    pub output: Option<String>,
}

impl RejectionMeta {
    pub fn new(
        stage: RejectionStage,
        source: impl Into<String>,
        raw_reasons: Vec<String>,
    ) -> Self {
        Self {
            stage,
            source: source.into(),
            raw_reasons,
            input: None,
            output: None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),
    #[error("Circuit breaker open: {0}")]
    CircuitBreakerOpen(String),
    #[error("{message}")]
    UpstreamResponse { status: u16, message: String },
    /// The upstream refused the caller's own key (HTTP 401 or 403 on a call
    /// that sent it). Returned to the caller with the upstream's status; never
    /// retried, failed over or answered with a stored key, and not a signal
    /// about the provider's health. The upstream's body is not kept, since it
    /// can echo part of the key.
    #[error("The upstream provider rejected the caller's API key (HTTP {status})")]
    CallerKeyRejected { status: u16 },
    /// A call on a platform key refused before it was sent, because the
    /// member's budget, or a budget of one of the member's teams, is spent
    /// (see [`crate::teams::call_budget`]). Returned to the caller as the team
    /// gate's 429 `team_quota_exceeded`. Never retried and not a signal about
    /// the provider's health. `call` says whether the refused call was an
    /// upstream serving the request, which a failover, load-balancing, routed
    /// or Mirror fan-out may replace with another target, or a safety or
    /// decision stage, which refuses the request.
    #[error("{reason}")]
    BudgetExhausted { reason: String, call: BudgetedCall },
    /// A call on a platform key refused before it was sent, while a budget is
    /// in scope, because Agent Stream would not meter what it spends (see
    /// [`crate::pipes::metering`]). The member may still have credit. Returned
    /// to the caller as HTTP 403 `permission_error` with the kind's own code,
    /// and recorded as a `metering` block, never as the team gate's. Like
    /// [`Self::BudgetExhausted`] it is never retried, is not a signal about the
    /// provider's health, and `call` says whether another target may serve
    /// the request (one on an owned key can).
    #[error("{unmetered}")]
    NotMetered { unmetered: crate::pipes::metering::Unmetered, call: BudgetedCall },
    /// A binary passthrough (text-to-speech) whose path does not reach a
    /// speech endpoint (see [`binary_endpoint`]), refused before anything is
    /// sent on every key, since the call would be a model call the binary
    /// path bills as characters. Returned as 400 `binary_endpoint_unsupported`.
    #[error("{}", BINARY_ENDPOINT_UNSUPPORTED)]
    BinaryEndpointUnsupported,
    /// A request carrying content its upstream cannot read (a file type Claude
    /// does not take, or an image URL or stored file reference sent to Claude on
    /// Bedrock), refused before it is sent rather than answered as if nothing was
    /// attached. Returned as 400 `unsupported_content`; never retried, failed
    /// over or counted against the circuit breaker.
    #[error("{0}")]
    UnsupportedContent(&'static str),
    #[error("Provider request timed out: {0}")]
    RequestTimeout(String),
    #[error("Request failed: {0}")]
    RequestFailed(String),
    #[error("Invalid response: {0}")]
    InvalidResponse(String),
    #[error("Retry exhausted: {0}")]
    RetryExhausted(String),
    /// A call refused before it was sent because it would read or write the
    /// provider store behind a credential the surface's tenant does not own
    /// (see `crate::pipes::shared_credential`). Final: never retried, failed
    /// over or counted against the circuit breaker.
    #[error("{0}")]
    SharedCredentialRefused(crate::pipes::shared_credential::SharedCredentialRefusal),
    #[error("Prompt guard rejected: {body}")]
    PromptGuardRejected {
        status_code: u16,
        body: String,
        content_type: String,
        /// Structured rejection detail for telemetry; `None` for legacy/synthetic
        /// rejections that carry no categorisable reason. Boxed to keep the error
        /// variant small.
        rejection: Option<Box<RejectionMeta>>,
        usage: Option<Box<RejectedExecutionUsage>>,
    },
    /// Wraps another `PipeError` to carry Judge/Decider stage usage that was
    /// already incurred (billable LLM calls that succeeded) before a later
    /// infrastructure failure — SSRF guard, endpoint/header resolution, network
    /// error, non-success upstream status — aborted the request. Without this the
    /// spend is capped by the budget tracker but never attributed to the caller's
    /// surface/team usage, since that attribution only otherwise runs on success.
    #[error("{inner}")]
    WithIncurredUsage { inner: Box<PipeError>, usage: Box<RejectedExecutionUsage> },
}

/// What kind of model call a spent budget refused (see
/// [`PipeError::BudgetExhausted`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetedCall {
    /// An upstream that serves the request: the main call, a stream, a
    /// failover, load-balancing or routed target, a Mirror candidate or merger,
    /// a binary or upload passthrough. Refused, that target is unavailable.
    Upstream,
    /// A safety or decision stage: the Judge, a juror, the Decider router, an
    /// LLM PII detector or an expert witness. Refused, the request is refused,
    /// whatever the stage's own error policy: a check that cannot run never
    /// lets the request through.
    Stage,
}

/// Strip, from a call on a key that bills while a budget is in scope, the
/// parameters that only raise what the call costs the operator and not what it
/// bills: a `service_tier` other than `auto`, `default`, `flex` or
/// `standard_only` (OpenAI's `priority` is billed about twice the standard
/// price the catalog charges). A call on an owned key keeps them.
fn strip_cost_raising_parameters(
    body: &mut Value,
    source: KeySource,
) {
    if source.owned() || crate::teams::call_budget::current().is_none() {
        return;
    }
    let Some(object) = body.as_object_mut() else {
        return;
    };
    let kept = object
        .get("service_tier")
        .is_none_or(|tier| matches!(tier.as_str(), Some("auto" | "default" | "flex" | "standard_only")));
    if !kept {
        object.remove("service_tier");
        debug!("service_tier stripped from a platform-key call: it raises the operator's cost, not the bill");
    }
}

/// Ask an OpenAI-compatible stream to `url` for its terminal usage chunk
/// (`stream_options.include_usage`), on the completions shape only (see
/// [`crate::pipes::metering::is_completions_call`]): Responses and Messages
/// define no such field and report their usage in their own events. A stream
/// on a key that bills (`source` not owned) always asks, whatever
/// `stream_options` the caller sent: merged into the caller's object,
/// replacing anything else, so a caller's `include_usage: false` cannot leave
/// a platform-key stream with no usage to bill. A stream on an owned key bills
/// nothing, so the caller's own choice is kept and the chunk is asked for only
/// when it sent none.
fn request_usage_chunk(
    body: &mut Value,
    source: KeySource,
    url: &str,
) {
    if !crate::pipes::metering::is_completions_call(url) {
        return;
    }
    let Some(object) = body.as_object_mut() else {
        return;
    };
    match object.get_mut("stream_options") {
        Some(Value::Object(options)) if !source.owned() => {
            options.insert("include_usage".to_string(), Value::Bool(true));
        }
        Some(_) if source.owned() => {}
        _ => {
            object.insert("stream_options".to_string(), serde_json::json!({ "include_usage": true }));
        }
    }
}

/// What a caller is told when a binary passthrough cannot reach a speech
/// endpoint.
pub const BINARY_ENDPOINT_UNSUPPORTED: &str = "This surface's provider has no speech endpoint the request's path \
reaches: text-to-speech needs an OpenAI-compatible provider and a path ending in /audio/speech.";

/// The endpoint a binary passthrough (text-to-speech) is sent to: the
/// provider's base with the request's path appended, and only when that path
/// decodes, unambiguously, to `.../audio/speech` (see
/// [`crate::pipes::metering::binary_call`]). `None` for a provider with a
/// fixed endpoint (Anthropic, Gemini, Claude on Bedrock, Azure OpenAI, Custom,
/// Microsoft 365 Copilot), which never appends the path and so would receive
/// the body at its chat endpoint: a model call the binary path would bill as
/// text-to-speech characters, past every response-side stage.
fn binary_endpoint(
    provider: &crate::pipes::types::llm::LLMProvider,
    path_suffix: Option<&str>,
) -> Option<String> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;

    let suffix = path_suffix.filter(|_| provider.supports_path_suffix())?;
    let suffix = if suffix.starts_with('/') {
        suffix.to_string()
    } else {
        format!("/{suffix}")
    };
    let endpoint = format!(
        "{}{}",
        provider
            .get_endpoint()
            .trim_end_matches('/'),
        suffix
    );
    crate::pipes::metering::binary_call(&endpoint)
        .is_ok()
        .then_some(endpoint)
}

/// Why a platform-key call was refused before it was sent: a spent budget
/// ([`PipeError::BudgetExhausted`]) or spend Agent Stream does not meter
/// ([`PipeError::NotMetered`]). Kept by a failover, load-balancing, routed or
/// Mirror fan-out whose every target failed, so it answers with the refusal
/// the caller can act on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PlatformRefusal {
    /// The member's or a team's budget is spent: the gate's reason.
    BudgetSpent(String),
    /// What the call would spend is not metered.
    NotMetered(crate::pipes::metering::Unmetered),
}

impl PlatformRefusal {
    /// The error for this refusal of a call of kind `call`.
    pub fn into_error(
        self,
        call: BudgetedCall,
    ) -> PipeError {
        match self {
            Self::BudgetSpent(reason) => PipeError::BudgetExhausted { reason, call },
            Self::NotMetered(unmetered) => PipeError::NotMetered { unmetered, call },
        }
    }
}

impl std::fmt::Display for PlatformRefusal {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::BudgetSpent(reason) => f.write_str(reason),
            Self::NotMetered(unmetered) => write!(f, "{unmetered}"),
        }
    }
}

/// Refuse a model call whose key came from `source` when the current request's
/// budget is spent (see [`crate::teams::call_budget`]). Every model call asks
/// just before it is sent; `what` names the call in the log.
pub(crate) async fn admit_call(
    source: KeySource,
    call: BudgetedCall,
    what: &str,
) -> Result<(), PipeError> {
    match crate::teams::call_budget::refusal(source).await {
        Some(reason) => {
            warn!(call = ?what, key_source = source.as_str(), reason = ?reason, "platform-key call refused: budget spent");
            Err(PipeError::BudgetExhausted { reason, call })
        }
        None => Ok(()),
    }
}

/// Whether an upstream's non-success answer refuses the credentials the call
/// sent: any 401 or 403, and a provider's own bad-key answer under another
/// status: Google AI Studio answers an invalid key with a 400 whose reason is
/// `API_KEY_INVALID`, some OpenAI-compatible servers a 400 with the code
/// `invalid_api_key`, and xAI a 400 ("An incorrect API key was supplied", its
/// API docs' status table) whose error reads `Incorrect API key provided: ...`.
/// Every other provider documented answers a bad key with 401 or 403.
pub fn refuses_credentials(
    status: reqwest::StatusCode,
    body: &str,
) -> bool {
    match status {
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN => true,
        reqwest::StatusCode::BAD_REQUEST => {
            body.contains("\"API_KEY_INVALID\"")
                || body.contains("\"invalid_api_key\"")
                || body.contains("Incorrect API key provided")
        }
        _ => false,
    }
}

impl PipeError {
    /// The reason a spent budget refused a call, when this error is that
    /// refusal (looking through [`Self::WithIncurredUsage`]).
    pub fn budget_refusal(&self) -> Option<&str> {
        match self {
            Self::BudgetExhausted { reason, .. } => Some(reason),
            Self::WithIncurredUsage { inner, .. } => inner.budget_refusal(),
            _ => None,
        }
    }

    /// Why a platform-key call was refused before it was sent, when this
    /// error is that refusal: a spent budget or unmetered spend (looking
    /// through [`Self::WithIncurredUsage`]).
    pub fn platform_refusal(&self) -> Option<PlatformRefusal> {
        match self {
            Self::BudgetExhausted { reason, .. } => Some(PlatformRefusal::BudgetSpent(reason.clone())),
            Self::NotMetered { unmetered, .. } => Some(PlatformRefusal::NotMetered(*unmetered)),
            Self::WithIncurredUsage { inner, .. } => inner.platform_refusal(),
            _ => None,
        }
    }

    /// The unmetered spend a platform-key call was refused for, when this
    /// error is that refusal (looking through [`Self::WithIncurredUsage`]).
    pub fn not_metered(&self) -> Option<crate::pipes::metering::Unmetered> {
        match self {
            Self::NotMetered { unmetered, .. } => Some(*unmetered),
            Self::WithIncurredUsage { inner, .. } => inner.not_metered(),
            _ => None,
        }
    }

    /// Whether a platform-key refusal (a spent budget or unmetered spend)
    /// refused the upstream that would have served the request, so another
    /// target may serve it instead.
    pub fn upstream_unaffordable(&self) -> bool {
        match self {
            Self::BudgetExhausted { call, .. } | Self::NotMetered { call, .. } => *call == BudgetedCall::Upstream,
            Self::WithIncurredUsage { inner, .. } => inner.upstream_unaffordable(),
            _ => false,
        }
    }

    pub fn upstream_response(
        status: reqwest::StatusCode,
        message: String,
    ) -> Self {
        Self::UpstreamResponse {
            status: status.as_u16(),
            message,
        }
    }

    /// The shared-credential refusal this error carries, under any
    /// incurred-usage wrapper.
    pub fn shared_credential_refusal(&self) -> Option<crate::pipes::shared_credential::SharedCredentialRefusal> {
        match self {
            Self::SharedCredentialRefused(refusal) => Some(*refusal),
            Self::WithIncurredUsage { inner, .. } => inner.shared_credential_refusal(),
            _ => None,
        }
    }

    /// The error for a call the upstream answered with a non-success `status`
    /// and `body` (`what` prefixes the message, empty for a model call).
    ///
    /// When the upstream refused the call's credentials (see
    /// [`refuses_credentials`]) and the call sent a caller credential (the
    /// caller's own key or a forwarded identity token,
    /// `sent_caller_credential`), it is [`Self::CallerKeyRejected`], whatever
    /// the call is billed as. A refused stored key stays
    /// [`Self::UpstreamResponse`] so it still fails over. Either way the body
    /// of a credential refusal is dropped, since a provider can echo part of
    /// the key in it; any other failure keeps its body.
    pub fn upstream_failure(
        status: reqwest::StatusCode,
        sent_caller_credential: bool,
        what: &str,
        body: &str,
    ) -> Self {
        if !refuses_credentials(status, body) {
            return Self::upstream_response(status, format!("{what}HTTP {status}: {body}"));
        }
        if sent_caller_credential {
            Self::CallerKeyRejected { status: status.as_u16() }
        } else {
            Self::upstream_response(status, format!("{what}HTTP {status}: the upstream refused the credentials sent"))
        }
    }

    /// Whether this is the upstream's refusal of the caller's own credential,
    /// looking through [`Self::WithIncurredUsage`].
    pub fn caller_key_rejected(&self) -> bool {
        match self {
            Self::CallerKeyRejected { .. } => true,
            Self::WithIncurredUsage { inner, .. } => inner.caller_key_rejected(),
            _ => false,
        }
    }

    /// Whether the request was refused for content its upstream cannot read,
    /// looking through [`Self::WithIncurredUsage`].
    pub fn unsupported_content(&self) -> bool {
        match self {
            Self::UnsupportedContent(_) => true,
            Self::WithIncurredUsage { inner, .. } => inner.unsupported_content(),
            _ => false,
        }
    }

    pub fn upstream_status(&self) -> Option<u16> {
        match self {
            Self::UpstreamResponse { status, .. } | Self::CallerKeyRejected { status } => Some(*status),
            Self::WithIncurredUsage { inner, .. } => inner.upstream_status(),
            _ => None,
        }
    }

    /// Attach a rejecting stage's input/output to a content rejection, so a
    /// governance block record can show what the stage evaluated and returned.
    /// No-op for non-rejection errors or a rejection without metadata.
    pub fn with_stage_io(
        mut self,
        input: Option<String>,
        output: Option<String>,
    ) -> Self {
        if let PipeError::PromptGuardRejected { rejection: Some(meta), .. } = &mut self {
            meta.input = input;
            meta.output = output;
        }
        self
    }

    /// Build a `PromptGuardRejected` from a regex/witness `GuardRejection`,
    /// attaching the rejection metadata (stage + source + the guard's categories).
    pub fn guard_rejected(
        rej: crate::pipes::prompt_guard::GuardRejection,
        stage: RejectionStage,
        source: impl Into<String>,
    ) -> Self {
        let raw_reasons = if rej.categories.is_empty() {
            rej.reason
                .clone()
                .into_iter()
                .collect()
        } else {
            rej.categories.clone()
        };
        PipeError::PromptGuardRejected {
            status_code: rej.status_code,
            body: rej.body,
            content_type: rej.content_type,
            rejection: Some(Box::new(RejectionMeta::new(stage, source, raw_reasons))),
            usage: None,
        }
    }

    pub fn with_rejected_usage(
        self,
        usage: RejectedExecutionUsage,
    ) -> Self {
        match self {
            Self::PromptGuardRejected {
                status_code,
                body,
                content_type,
                rejection,
                ..
            } => Self::PromptGuardRejected {
                status_code,
                body,
                content_type,
                rejection,
                usage: Some(Box::new(usage)),
            },
            other => other,
        }
    }

    /// Attach Judge/Decider spend already incurred before a later infrastructure
    /// failure, so the caller can still bill/record it instead of silently
    /// dropping already-charged usage. A no-op when nothing was incurred.
    pub fn with_incurred_usage(
        self,
        judge_usage: StageUsage,
        decider_usage: StageUsage,
    ) -> Self {
        if judge_usage == StageUsage::default() && decider_usage == StageUsage::default() {
            return self;
        }
        Self::WithIncurredUsage {
            inner: Box::new(self),
            usage: Box::new(RejectedExecutionUsage {
                llm: StageUsage::default(),
                judge: judge_usage,
                jury: StageUsage::default(),
                decider: decider_usage,
            }),
        }
    }

    /// Attach spend already incurred (see [`Self::WithIncurredUsage`]), added
    /// to any the error already carries; a content rejection carries it as its
    /// own usage (see [`Self::with_rejected_usage`]).
    pub fn with_incurred(
        self,
        incurred: RejectedExecutionUsage,
    ) -> Self {
        if incurred.is_empty() {
            return self;
        }
        match self {
            Self::PromptGuardRejected {
                status_code,
                body,
                content_type,
                rejection,
                usage,
            } => {
                let mut total = usage
                    .map(|usage| *usage)
                    .unwrap_or_default();
                total.add(&incurred);
                Self::PromptGuardRejected {
                    status_code,
                    body,
                    content_type,
                    rejection,
                    usage: Some(Box::new(total)),
                }
            }
            Self::WithIncurredUsage { inner, mut usage } => {
                usage.add(&incurred);
                Self::WithIncurredUsage { inner, usage }
            }
            other => Self::WithIncurredUsage {
                inner: Box::new(other),
                usage: Box::new(incurred),
            },
        }
    }

    /// The error without the spend attached to it, and that spend (see
    /// [`Self::with_incurred`]).
    pub fn take_incurred(self) -> (Self, RejectedExecutionUsage) {
        match self {
            Self::WithIncurredUsage { inner, usage } => (*inner, *usage),
            Self::PromptGuardRejected {
                status_code,
                body,
                content_type,
                rejection,
                usage,
            } => (
                Self::PromptGuardRejected {
                    status_code,
                    body,
                    content_type,
                    rejection,
                    usage: None,
                },
                usage
                    .map(|usage| *usage)
                    .unwrap_or_default(),
            ),
            other => (other, RejectedExecutionUsage::default()),
        }
    }
}

/// State for rate limiting
#[derive(Debug)]
struct RateLimitState {
    tokens_used: u64,
    requests_made: u64,
    window_start: DateTime<Utc>,
}

impl RateLimitState {
    fn new() -> Self {
        Self {
            tokens_used: 0,
            requests_made: 0,
            window_start: Utc::now(),
        }
    }

    fn reset_if_needed(&mut self) {
        let now = Utc::now();
        if (now - self.window_start).num_minutes() >= 1 {
            self.tokens_used = 0;
            self.requests_made = 0;
            self.window_start = now;
        }
    }
}

/// State for circuit breaker
#[derive(Debug, Clone, PartialEq)]
enum CircuitState {
    Closed,
    Open { opened_at: DateTime<Utc> },
    HalfOpen,
}

#[derive(Debug)]
struct CircuitBreakerState {
    state: CircuitState,
    failure_count: u32,
    success_count: u32,
    config: CircuitBreakerConfig,
}

impl CircuitBreakerState {
    fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            config,
        }
    }

    fn record_success(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count = 0;
            }
            CircuitState::HalfOpen => {
                self.success_count += 1;
                // After one success in half-open, close the circuit
                if self.success_count >= 1 {
                    info!("Circuit breaker transitioning to Closed");
                    self.state = CircuitState::Closed;
                    self.failure_count = 0;
                    self.success_count = 0;
                }
            }
            CircuitState::Open { .. } => {
                // Should not happen
            }
        }
    }

    fn record_failure(&mut self) {
        match self.state {
            CircuitState::Closed => {
                self.failure_count += 1;
                if self.failure_count >= self.config.failure_threshold {
                    warn!("Circuit breaker opening due to failures");
                    self.state = CircuitState::Open { opened_at: Utc::now() };
                }
            }
            CircuitState::HalfOpen => {
                warn!("Circuit breaker reopening due to failure in half-open state");
                self.state = CircuitState::Open { opened_at: Utc::now() };
                self.success_count = 0;
            }
            CircuitState::Open { .. } => {
                // Already open
            }
        }
    }

    fn can_request(&mut self) -> Result<(), PipeError> {
        match &self.state {
            CircuitState::Closed => Ok(()),
            CircuitState::HalfOpen => Ok(()),
            CircuitState::Open { opened_at } => {
                let now = Utc::now();
                let elapsed = (now - *opened_at).num_seconds();
                if elapsed >= self.config.timeout_seconds as i64 {
                    info!("Circuit breaker transitioning to HalfOpen");
                    self.state = CircuitState::HalfOpen;
                    Ok(())
                } else {
                    Err(PipeError::CircuitBreakerOpen(format!(
                        "Circuit open for {} more seconds",
                        self.config.timeout_seconds as i64 - elapsed
                    )))
                }
            }
        }
    }
}

/// Pipe executor with rate limiting, circuit breaking, and retry
pub struct PipeExecutor {
    config: PipeConfig,
    client: Client,
    /// Separate client for streaming responses — has a connect timeout but no
    /// body-read timeout, so a slow model generating a long response is never
    /// killed mid-stream by the per-request ceiling that applies to buffered calls.
    streaming_client: Client,
    rate_limit_state: Arc<Mutex<RateLimitState>>,
    circuit_breaker: Arc<Mutex<CircuitBreakerState>>,
    /// The surface's secrets, resolved for the surface's own tenant.
    secrets: crate::secrets::SurfaceSecrets,
    /// Whether this executor calls the surface's own primary upstream, the only
    /// one the caller's key may reach. `false` on the transient executor a
    /// failover, load-balancing or routed target runs on (see
    /// [`Self::for_target`]).
    primary: bool,
    /// Resolved API keys cached per secret id. Keyed by `secret_id` so a
    /// Decider-routed candidate (whose provider may carry a different secret
    /// than the base pipe) resolves its own key instead of reusing the base
    /// pipe's — otherwise the wrong provider's key is sent and the call 401s.
    cached_api_keys: Arc<RwLock<HashMap<String, ResolvedSecret>>>,
    /// Monotonic request counter driving weighted round-robin selection across
    /// the load-balancing pool. Persists for the cached executor's lifetime so
    /// distribution is even across requests.
    lb_counter: AtomicU64,
    /// EWMA latency (milliseconds) per load-balancing pool member, indexed the
    /// same as the pool (`0` = primary, `1..` = targets). `0` means "no sample
    /// yet". Used by the `lowest_latency` strategy; persists for the cached
    /// executor's lifetime.
    lb_latency: Vec<AtomicU64>,
}

impl PipeExecutor {
    #[allow(dead_code)]
    pub fn new(config: &PipeConfig) -> Self {
        Self::new_with_secrets(config, None)
    }

    pub fn new_with_secrets(
        config: &PipeConfig,
        secrets_store: Option<Arc<dyn SecretsStore>>,
    ) -> Self {
        let mut config = config.clone();
        config.normalize_guardrails();

        let client = Client::builder()
            .timeout(StdDuration::from_secs(config.request_timeout_seconds))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(crate::url_validation::ServiceEndpointDnsResolver))
            .pool_max_idle_per_host(HTTP_POOL_MAX_IDLE_PER_HOST)
            .pool_idle_timeout(StdDuration::from_secs(HTTP_POOL_IDLE_TIMEOUT_SECS))
            .tcp_keepalive(Some(StdDuration::from_secs(HTTP_TCP_KEEPALIVE_SECS)))
            .build()
            .expect("secure buffered HTTP client configuration must build");

        // Streaming client: connect timeout only — no overall body-read timeout.
        // The buffered client's ceiling is intentionally not applied here because
        // a streaming response can legitimately take minutes (e.g. a large local
        // model generating a long output). The connect timeout still fails fast
        // when the upstream is unreachable.
        let streaming_client = Client::builder()
            .connect_timeout(StdDuration::from_secs(HTTP_STREAMING_CONNECT_TIMEOUT_SECS))
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .dns_resolver(Arc::new(crate::url_validation::ServiceEndpointDnsResolver))
            .pool_max_idle_per_host(HTTP_POOL_MAX_IDLE_PER_HOST)
            .pool_idle_timeout(StdDuration::from_secs(HTTP_POOL_IDLE_TIMEOUT_SECS))
            .tcp_keepalive(Some(StdDuration::from_secs(HTTP_TCP_KEEPALIVE_SECS)))
            .build()
            .expect("secure streaming HTTP client configuration must build");

        let circuit_config = config
            .circuit_breaker
            .clone()
            .unwrap_or(CircuitBreakerConfig {
                failure_threshold: DEFAULT_CB_FAILURE_THRESHOLD,
                timeout_seconds: DEFAULT_CB_TIMEOUT_SECS,
                reset_timeout_seconds: DEFAULT_CB_RESET_TIMEOUT_SECS,
            });

        // One EWMA latency slot per load-balancing pool member (primary + each
        // target), so `lowest_latency` selection has stable per-member state for
        // the cached executor's lifetime.
        let lb_pool_size = config
            .load_balancing
            .as_ref()
            .map(|lb| lb.targets.len() + 1)
            .unwrap_or(0);
        let lb_latency = (0..lb_pool_size)
            .map(|_| AtomicU64::new(0))
            .collect();

        let secrets = crate::secrets::SurfaceSecrets::new(secrets_store, config.tenant_id.clone());

        Self {
            config,
            client,
            streaming_client,
            rate_limit_state: Arc::new(Mutex::new(RateLimitState::new())),
            circuit_breaker: Arc::new(Mutex::new(CircuitBreakerState::new(circuit_config))),
            secrets,
            primary: true,
            cached_api_keys: Arc::new(RwLock::new(HashMap::new())),
            lb_counter: AtomicU64::new(0),
            lb_latency,
        }
    }

    /// The executor of an upstream other than the surface's own default one:
    /// the transient executor a failover, load-balancing or per-request routed
    /// target runs on (`config` is the surface cloned onto that target, see
    /// [`PipeConfig::clone_with_failover_target`]), and the executor of a
    /// routing rule's inline target or of a variant that swaps the provider or
    /// the origin (see [`PipeConfig::keeps_default_upstream`]). Its calls send
    /// their own stored key and never the caller's key or token.
    pub(crate) fn for_target(
        config: &PipeConfig,
        secrets_store: Option<Arc<dyn SecretsStore>>,
    ) -> Self {
        Self {
            primary: false,
            ..Self::new_with_secrets(config, secrets_store)
        }
    }

    /// The surface's secrets, for out-of-band stages (e.g. a drift embedder)
    /// that resolve their own provider key through the same backend.
    pub(crate) fn surface_secrets(&self) -> &crate::secrets::SurfaceSecrets {
        &self.secrets
    }

    /// Execute a request through the pipe
    #[allow(dead_code)]
    pub async fn execute(
        &self,
        request_body: Value,
        estimated_input_tokens: Option<u64>,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        self.execute_with_path_and_auth(
            request_body,
            None,
            CallerCredentials::default(),
            estimated_input_tokens,
            trace_id,
            correlation_id,
            agent_identity,
            None,
        )
        .await
    }

    /// Execute a request through the pipe with optional path suffix
    #[allow(dead_code)]
    pub async fn execute_with_path(
        &self,
        request_body: Value,
        path_suffix: Option<String>,
        estimated_tokens: Option<u64>,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        self.execute_with_path_and_auth(
            request_body,
            path_suffix,
            CallerCredentials::default(),
            estimated_tokens,
            trace_id,
            correlation_id,
            agent_identity,
            None,
        )
        .await
    }

    /// Execute a request through the pipe with optional path suffix and client
    /// authorization header.
    ///
    /// When the surface has active governed server tools (`web_search` /
    /// `web_fetch`), this runs the bounded agentic loop
    /// ([`Self::execute_with_server_tools`]); otherwise it performs a single
    /// model turn ([`Self::execute_model_turn`]).
    #[allow(clippy::too_many_arguments)]
    pub async fn execute_with_path_and_auth(
        &self,
        request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        estimated_tokens: Option<u64>,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let server_tools = self
            .config
            .server_tools
            .clone()
            .filter(|st| st.is_active())
            .filter(|_| matches!(self.config.pipe_type, super::PipeType::LLM { .. }));
        if let Some(st) = server_tools {
            return self
                .execute_with_server_tools(
                    st,
                    request_body,
                    path_suffix,
                    caller,
                    estimated_tokens,
                    trace_id,
                    correlation_id,
                    agent_identity,
                    conversation_id,
                )
                .await;
        }
        self.execute_model_turn(
            request_body,
            path_suffix,
            caller,
            estimated_tokens,
            trace_id,
            correlation_id,
            agent_identity,
            conversation_id,
        )
        .await
    }

    /// A single model turn through the pipe: circuit breaker, rate limit,
    /// per-request routing / load-balancing / cross-provider failover
    /// selection, guards, and the upstream call. The server-tools agentic loop
    /// invokes this once per iteration.
    #[allow(clippy::too_many_arguments)]
    async fn execute_model_turn(
        &self,
        request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        estimated_tokens: Option<u64>,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        // Create OpenTelemetry span for distributed tracing
        let pipe_type_str = match &self.config.pipe_type {
            crate::pipes::config::PipeType::LLM { .. } => "llm",
            crate::pipes::config::PipeType::Webhook { .. } => "webhook",
            crate::pipes::config::PipeType::IDECatalog { .. } => "ide_catalog",
        };

        let span = tracing::info_span!(
            "pipe.execute",
            otel.kind = "client",
            pipe.id = %self.config.id,
            pipe.name = %self.config.name,
            pipe.type = pipe_type_str,
            trace_id = %trace_id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
            correlation_id = ?correlation_id,
            agent.identity = ?agent_identity,
        );

        async move {
            // Circuit-breaker gate for the primary provider. An open breaker
            // holds the primary out to let it recover — but an open circuit is
            // a failover-eligible condition, so rather than failing the caller
            // outright we route the request to configured backups (below).
            let has_circuit_breaker = self
                .config
                .circuit_breaker
                .is_some();
            let primary_circuit_open = if has_circuit_breaker {
                self.circuit_breaker
                    .lock()
                    .await
                    .can_request()
                    .err()
            } else {
                None
            };

            // Fast path: skip rate limiting if disabled or not configured. The
            // gateway's own rate limit always applies, independent of provider
            // health, so it is enforced before any provider selection.
            if let Some(rate_limit) = &self.config.rate_limit
                && rate_limit.enabled
            {
                let rate_limit_span = tracing::info_span!(
                    "pipe.rate_limit",
                    otel.name = "Rate Limit Check",
                    pipe = %self.config.name
                );
                let result = async {
                    self.check_rate_limits(estimated_tokens)
                        .await
                }
                .instrument(rate_limit_span)
                .await;
                result?;
            }

            self.admit_platform_stages()
                .await?;

            // Per-request routing preferences (`models` / `provider`) filter and
            // reorder the surface's own candidate pool (primary + failover / LB
            // targets). LLM surfaces only, and the caller can narrow or reorder
            // but never widen beyond what the surface offers.
            if matches!(self.config.pipe_type, super::PipeType::LLM { .. })
                && let Some(prefs) = crate::pipes::request_routing::parse(&request_body)
            {
                let mut routed_body = request_body.clone();
                crate::pipes::request_routing::strip_routing_fields(&mut routed_body);
                let pool = self.build_routing_pool();
                let mut candidates = crate::pipes::request_routing::filter_and_order(&prefs, pool);
                candidates = self.apply_price_preferences(&prefs, candidates);
                // An open primary breaker drops the primary candidate.
                if primary_circuit_open.is_some() {
                    candidates.retain(|c| c.target.is_some());
                }
                if !prefs.allow_fallbacks {
                    candidates.truncate(1);
                }
                if candidates.is_empty() {
                    return Err(PipeError::RequestFailed(
                        "no upstream candidate matches the request routing preferences".to_string(),
                    ));
                }
                return self
                    .run_request_routed(
                        candidates,
                        routed_body,
                        path_suffix,
                        caller,
                        trace_id,
                        correlation_id,
                        agent_identity,
                        conversation_id,
                    )
                    .await;
            }

            // Distribution / resilience strategy. Weighted load balancing (when
            // enabled) owns selection across the provider pool and its own
            // fallthrough; otherwise the primary runs with retry and ordered
            // cross-provider failover handles backup providers.
            let lb_active = self
                .config
                .load_balancing
                .as_ref()
                .is_some_and(|lb| lb.enabled && !lb.targets.is_empty());

            if lb_active {
                // Load balancing owns its own pool fallthrough; an open primary
                // breaker short-circuits the pool's base member. Record the
                // pool outcome on the breaker (provider-health failures only).
                let lb_result = if let Some(err) = primary_circuit_open {
                    Err(err)
                } else {
                    self.run_load_balanced(
                        &request_body,
                        &path_suffix,
                        &caller,
                        &trace_id,
                        &correlation_id,
                        &agent_identity,
                    )
                    .await
                };
                self.record_circuit_outcome(&lb_result)
                    .await;
                lb_result
            } else if let Some(err) = primary_circuit_open {
                // Primary circuit is open: skip the primary entirely and route
                // to ordered failover backups. `run_failover_if_needed` returns
                // this circuit error unchanged when no eligible failover is
                // configured, preserving the prior fail-fast outcome. The
                // primary breaker is left untouched (the primary was not
                // called), so it stays open until its own half-open trial.
                self.run_failover_if_needed(
                    Err(err),
                    &request_body,
                    &path_suffix,
                    &trace_id,
                    &correlation_id,
                    &agent_identity,
                )
                .await
            } else {
                // Execute with retry against the primary provider.
                let primary_result = self
                    .execute_with_retry(
                        request_body.clone(),
                        path_suffix.clone(),
                        caller.clone(),
                        trace_id.clone(),
                        correlation_id.clone(),
                        agent_identity.clone(),
                        conversation_id.clone(),
                    )
                    .await;

                // Record the PRIMARY provider's own health on its breaker
                // *before* failover can mask a primary failure with a backup
                // success — otherwise the primary circuit would never open on a
                // failover-configured surface, and the gate above could never
                // engage. Only provider-health failures count (see
                // `record_circuit_outcome`).
                self.record_circuit_outcome(&primary_result)
                    .await;

                // Cross-provider failover: if the primary upstream failed with
                // a failover-eligible error, retry the request against ordered
                // backup providers until one succeeds.
                self.run_failover_if_needed(
                    primary_result,
                    &request_body,
                    &path_suffix,
                    &trace_id,
                    &correlation_id,
                    &agent_identity,
                )
                .await
            }
        }
        .instrument(span)
        .await
    }

    /// The bounded agentic loop for governed server tools. Injects the enabled
    /// tool schemas, runs a model turn, and while the model emits `web_search` /
    /// `web_fetch` calls (up to `max_iterations`) executes them under governance
    /// (domain policy + SSRF guard + a recorded stage), appends the results, and
    /// re-invokes. On the final allowed iteration the tools are withdrawn so the
    /// model must produce an answer. Token/cost metrics are summed across turns;
    /// URL citations from the tools are attached to the returned message.
    #[allow(clippy::too_many_arguments)]
    async fn execute_with_server_tools(
        &self,
        server_tools: crate::pipes::server_tools::ServerToolsConfig,
        request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        estimated_tokens: Option<u64>,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let mut body = request_body;
        crate::pipes::server_tools::inject_tool_defs(&mut body, &server_tools);
        let max_iters = server_tools
            .max_iterations
            .clamp(1, 10);

        let mut acc: Option<ExecutionMetrics> = None;
        let mut citations: Vec<Value> = Vec::new();
        let mut iteration: u32 = 0;

        loop {
            // On the final permitted iteration, withdraw the tools so the model
            // is forced to answer rather than request another tool call.
            let force_answer = iteration >= max_iters;
            if force_answer && let Some(obj) = body.as_object_mut() {
                obj.remove("tools");
                obj.remove("tool_choice");
            }

            let (response, turn_metrics) = self
                .execute_model_turn(
                    body.clone(),
                    path_suffix.clone(),
                    caller.clone(),
                    estimated_tokens,
                    trace_id.clone(),
                    correlation_id.clone(),
                    agent_identity.clone(),
                    conversation_id.clone(),
                )
                .await
                .map_err(|e| match &acc {
                    // The turns already served were spent and are billed with
                    // the failure.
                    Some(served) => e.with_incurred(served.as_incurred()),
                    None => e,
                })?;

            match acc.as_mut() {
                Some(a) => Self::fold_server_tool_metrics(a, turn_metrics),
                None => acc = Some(turn_metrics),
            }

            let message = response
                .pointer("/choices/0/message")
                .cloned();
            let calls = message
                .as_ref()
                .map(crate::pipes::server_tools::extract_server_tool_calls)
                .unwrap_or_default();

            if calls.is_empty() || force_answer {
                let final_response = Self::attach_tool_citations(response, &citations);
                return Ok((final_response, acc.expect("accumulator is set after at least one model turn")));
            }

            // Append the assistant turn (carrying the tool_calls) to the running
            // conversation before the tool results.
            if let Some(msg) = message
                && let Some(msgs) = body
                    .get_mut("messages")
                    .and_then(|m| m.as_array_mut())
            {
                msgs.push(msg);
            }

            // Execute each requested tool (no `acc` borrow held across await).
            let mut tool_outputs = Vec::with_capacity(calls.len());
            for call in calls {
                tool_outputs.push(
                    self.run_server_tool(&server_tools, &call)
                        .await,
                );
            }

            let acc_ref = acc
                .as_mut()
                .expect("accumulator set after first turn");
            for (result_msg, mut cites, stage) in tool_outputs {
                citations.append(&mut cites);
                if let Some(stage) = stage {
                    acc_ref.stages.push(stage);
                }
                if let Some(msgs) = body
                    .get_mut("messages")
                    .and_then(|m| m.as_array_mut())
                {
                    msgs.push(result_msg);
                }
            }

            iteration += 1;
        }
    }

    /// Fold one model turn's metrics into the server-tools loop accumulator.
    /// Token/cost/latency/byte counters sum; identity fields take the latest
    /// turn; stage transcripts concatenate in pipeline order.
    fn fold_server_tool_metrics(
        acc: &mut ExecutionMetrics,
        turn: ExecutionMetrics,
    ) {
        acc.input_tokens += turn.input_tokens;
        acc.output_tokens += turn.output_tokens;
        acc.total_tokens += turn.total_tokens;
        acc.cost += turn.cost;
        acc.billed_cost += turn.billed_cost;
        acc.llm_usage
            .add(turn.llm_usage);
        acc.judge_usage
            .add(turn.judge_usage);
        acc.jury_usage
            .add(turn.jury_usage);
        acc.decider_usage
            .add(turn.decider_usage);
        acc.latency_ms += turn.latency_ms;
        acc.request_bytes += turn.request_bytes;
        acc.response_bytes += turn.response_bytes;
        acc.retry_count += turn.retry_count;
        acc.cached_tokens += turn.cached_tokens;
        acc.cache_write_tokens += turn.cache_write_tokens;
        acc.reasoning_tokens += turn.reasoning_tokens;
        acc.redrive_rejections
            .extend(turn.redrive_rejections);
        acc.stages.extend(turn.stages);
        acc.provider = turn.provider;
        acc.model = turn.model;
        acc.key_source = turn.key_source;
        if turn.schema_valid.is_some() {
            acc.schema_valid = turn.schema_valid;
        }
        if turn.conversation_id.is_some() {
            acc.conversation_id = turn.conversation_id;
        }
        if turn
            .time_to_first_token_ms
            .is_some()
        {
            acc.time_to_first_token_ms = turn.time_to_first_token_ms;
        }
    }

    /// Attach deduplicated URL citations to the final assistant message's
    /// `annotations` array (OpenRouter-compatible shape).
    fn attach_tool_citations(
        mut response: Value,
        citations: &[Value],
    ) -> Value {
        if citations.is_empty() {
            return response;
        }
        if let Some(message) = response
            .pointer_mut("/choices/0/message")
            .and_then(|m| m.as_object_mut())
        {
            let mut all = message
                .get("annotations")
                .and_then(|a| a.as_array())
                .cloned()
                .unwrap_or_default();
            for c in citations {
                let url = c.pointer("/url_citation/url");
                if url.is_some()
                    && !all
                        .iter()
                        .any(|e| e.pointer("/url_citation/url") == url)
                {
                    all.push(c.clone());
                }
            }
            message.insert("annotations".to_string(), Value::Array(all));
        }
        response
    }

    /// Dispatch one governed server-tool call, returning the `tool` result
    /// message, any URL citations, and a governance stage record.
    async fn run_server_tool(
        &self,
        cfg: &crate::pipes::server_tools::ServerToolsConfig,
        call: &crate::pipes::server_tools::ServerToolInvocation,
    ) -> (Value, Vec<Value>, Option<StageRecord>) {
        match call.name.as_str() {
            crate::pipes::server_tools::WEB_SEARCH_TOOL => {
                self.run_web_search(cfg, call)
                    .await
            }
            crate::pipes::server_tools::WEB_FETCH_TOOL => {
                self.run_web_fetch(cfg, call)
                    .await
            }
            other => (
                crate::pipes::server_tools::denied_message(
                    &call.tool_call_id,
                    &format!("unknown server tool '{other}'"),
                ),
                Vec::new(),
                None,
            ),
        }
    }

    /// Execute a governed `web_search` call: resolve the engine key, query the
    /// configured engine, filter results by the surface domain policy, and
    /// return the formatted results plus URL citations.
    async fn run_web_search(
        &self,
        cfg: &crate::pipes::server_tools::ServerToolsConfig,
        call: &crate::pipes::server_tools::ServerToolInvocation,
    ) -> (Value, Vec<Value>, Option<StageRecord>) {
        use crate::pipes::server_tools as st;
        let start = Instant::now();
        let query = call
            .arguments
            .get("query")
            .and_then(|q| q.as_str())
            .unwrap_or("")
            .to_string();
        let deny = |reason: String| {
            (
                st::denied_message(&call.tool_call_id, &reason),
                Vec::new(),
                Some(StageRecord {
                    stage: "web_search".to_string(),
                    decision: StageDecision::Flag,
                    detail: Some(reason),
                    input: Some(query.clone()),
                    output: None,
                    key_source: None,
                }),
            )
        };

        let Some(search) = cfg
            .web_search
            .as_ref()
            .filter(|s| s.enabled)
        else {
            return deny("web_search is not enabled on this surface".to_string());
        };
        if query.trim().is_empty() {
            return deny("empty search query".to_string());
        }
        let key = match search
            .engine_secret
            .as_deref()
        {
            Some(id) => match self
                .resolve_secret_by_id(id)
                .await
            {
                Ok(Some(k)) => k,
                _ => return deny("search engine API key could not be resolved".to_string()),
            },
            None => return deny("no search engine API key configured".to_string()),
        };
        let req = match st::build_engine_request(search, &key, &query) {
            Ok(r) => r,
            Err(e) => return deny(e),
        };

        let mut builder = match req.method {
            st::EngineMethod::Get => self.client.get(&req.url),
            st::EngineMethod::Post => self.client.post(&req.url),
        };
        for (k, v) in &req.headers {
            builder = builder.header(k, v);
        }
        if let Some(b) = &req.body {
            builder = builder.json(b);
        }
        let response = match builder.send().await {
            Ok(r) => r,
            Err(e) => return deny(format!("search request failed: {e}")),
        };
        if !response.status().is_success() {
            return deny(format!("search engine returned HTTP {}", response.status()));
        }
        let json = match response.json::<Value>().await {
            Ok(j) => j,
            Err(e) => return deny(format!("search response was not JSON: {e}")),
        };
        let mut results = st::parse_engine_response(&search.engine, &json, search.max_results);
        results.retain(|r| {
            url::Url::parse(&r.url)
                .ok()
                .and_then(|u| {
                    u.host_str()
                        .map(str::to_string)
                })
                .map(|h| st::domain_allowed(&h, search.domain_policy, &search.domain_exceptions))
                .unwrap_or(false)
        });
        let citations = st::citations_from_results(&results);
        let message = st::search_results_message(&call.tool_call_id, &query, &results);
        let stage = StageRecord {
            stage: "web_search".to_string(),
            decision: StageDecision::Observed,
            detail: Some(format!(
                "{} · \"{}\" · {} result(s) · {} ms",
                search.engine,
                query,
                results.len(),
                start.elapsed().as_millis()
            )),
            input: Some(query),
            output: Some(format!("{} result(s)", results.len())),
            key_source: None,
        };
        (message, citations, Some(stage))
    }

    /// Execute a governed `web_fetch` call: SSRF-guard and domain-check the URL,
    /// fetch it, reduce to bounded readable text, and return the content.
    async fn run_web_fetch(
        &self,
        cfg: &crate::pipes::server_tools::ServerToolsConfig,
        call: &crate::pipes::server_tools::ServerToolInvocation,
    ) -> (Value, Vec<Value>, Option<StageRecord>) {
        use crate::pipes::server_tools as st;
        let start = Instant::now();
        let url_str = call
            .arguments
            .get("url")
            .and_then(|u| u.as_str())
            .unwrap_or("")
            .to_string();
        let deny = |reason: &str, detail: String| {
            (
                st::denied_message(&call.tool_call_id, reason),
                Vec::new(),
                Some(StageRecord {
                    stage: "web_fetch".to_string(),
                    decision: StageDecision::Flag,
                    detail: Some(detail),
                    input: Some(url_str.clone()),
                    output: None,
                    key_source: None,
                }),
            )
        };

        let Some(fetch) = cfg
            .web_fetch
            .as_ref()
            .filter(|f| f.enabled)
        else {
            let reason = "web_fetch is not enabled on this surface";
            return deny(reason, reason.to_string());
        };
        // The model chooses this URL, so it gets the strict rules: no private,
        // loopback, link-local or cloud metadata host. The resolved addresses
        // are checked when the fetch resolves the host.
        let url = match crate::url_validation::validate_webhook_url(&url_str) {
            Ok(u) => u,
            Err(e) => {
                let (reason, detail) = FetchError::Blocked(e).denial();
                return deny(reason, detail);
            }
        };
        let host = url
            .host_str()
            .unwrap_or("")
            .to_string();
        if !st::domain_allowed(&host, fetch.domain_policy, &fetch.domain_exceptions) {
            let reason = format!("domain not permitted by surface policy: {host}");
            return deny(&reason, reason.clone());
        }
        let raw = match self
            .fetch_public_url(&url)
            .await
        {
            Ok(body) => body,
            Err(e) => {
                let (reason, detail) = e.denial();
                return deny(reason, detail);
            }
        };
        let extracted = st::extract_text(&raw, fetch.max_content_bytes);
        let message = st::fetch_result_message(&call.tool_call_id, url.as_str(), &extracted);
        let citation = serde_json::json!({
            "type": "url_citation",
            "url_citation": { "url": url.as_str() }
        });
        let stage = StageRecord {
            stage: "web_fetch".to_string(),
            decision: StageDecision::Observed,
            detail: Some(format!("{} · {} byte(s) · {} ms", host, extracted.len(), start.elapsed().as_millis())),
            input: Some(url_str),
            output: Some(format!("{} byte(s)", extracted.len())),
            key_source: None,
        };
        (message, vec![citation], Some(stage))
    }

    /// Fetch a statically SSRF-validated URL: resolve the host once under the
    /// strict address rules and **pin** the resolved IPs so the connection
    /// cannot be re-pointed at a private target after the check (DNS
    /// rebinding). Redirects and proxies are forbidden, the download is
    /// bounded, and the request times out. Returns the (bounded) body text.
    async fn fetch_public_url(
        &self,
        url: &url::Url,
    ) -> Result<String, FetchError> {
        use futures::StreamExt;
        const MAX_FETCH_BYTES: usize = 2 * 1024 * 1024;
        const CONNECT_TIMEOUT: StdDuration = StdDuration::from_secs(5);
        const TOTAL_TIMEOUT: StdDuration = StdDuration::from_secs(15);

        let (Some(host), Some(host_str), Some(port)) = (url.host(), url.host_str(), url.port_or_known_default()) else {
            return Err(FetchError::Blocked("URL has no host or usable port".to_string()));
        };
        let addrs = crate::url_validation::resolve_public_host(&host.to_owned(), port)
            .await
            .map_err(FetchError::Blocked)?;
        let failed = |e: String| FetchError::Failed(e);
        let client = reqwest::Client::builder()
            .timeout(TOTAL_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .resolve_to_addrs(host_str, &addrs)
            .user_agent("AgentStream-WebFetch/1.0")
            .build()
            .map_err(|e| failed(format!("failed to build fetch client: {e}")))?;
        let response = client
            .get(url.clone())
            .send()
            .await
            .map_err(|e| failed(format!("fetch failed: {e}")))?;
        if !response.status().is_success() {
            return Err(failed(format!("fetch returned HTTP {}", response.status())));
        }
        if response
            .content_length()
            .is_some_and(|l| l > MAX_FETCH_BYTES as u64)
        {
            return Err(failed("page exceeds the fetch size limit".to_string()));
        }
        let mut bytes: Vec<u8> = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| failed(format!("read failed: {e}")))?;
            let remaining = MAX_FETCH_BYTES.saturating_sub(bytes.len());
            if chunk.len() >= remaining {
                bytes.extend_from_slice(&chunk[..remaining]);
                break;
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// Open an SSE streaming connection to the upstream provider and return the
    /// raw response for passthrough. Runs the request-side gates (circuit
    /// breaker, rate limit, request prompt guard, external request guardrail,
    /// the request-side Judge, and a Route decider) and the request preparation,
    /// then sends the request with `stream: true`. The caller is responsible for
    /// proxying the response body back to the client and recording usage from
    /// the terminal SSE chunk (plus the Judge/decider usage returned here).
    ///
    /// Eligibility (no Jury, no Mirror decider, no response guards, OpenAI-family
    /// schema) is decided by `crate::pipes::streaming::passthrough_eligible`
    /// before this is called. A Judge gates the prompt pre-stream (can block); a
    /// Route decider picks the candidate upstream to stream from — both run here
    /// rather than forcing the buffered path.
    pub async fn execute_streaming(
        &self,
        mut request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        conversation_id: Option<String>,
    ) -> Result<crate::pipes::streaming::StreamingUpstream, PipeError> {
        // Per-request routing preferences are not applied on the streaming
        // passthrough path (v1); strip them so they never reach the upstream.
        crate::pipes::request_routing::strip_routing_fields(&mut request_body);

        // ── Circuit breaker ──
        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .can_request()?;
        }

        // ── Rate limit ──
        if let Some(rate_limit) = &self.config.rate_limit
            && rate_limit.enabled
        {
            self.check_rate_limits(None)
                .await?;
        }

        self.admit_platform_stages()
            .await?;

        // ── Prompt guard (request) ──
        // Mirror the buffered path's request masking so the provider only ever
        // sees pseudonyms and the map for response re-hydration is available: a
        // shared allocator runs the regex/NER guards, the model-backed PII
        // detector, and pronoun linking, then the token → value map is captured
        // when a guard (or the detector) opted into `restore_in_response`.
        let mut rehydration_map = crate::pipes::prompt_guard::RehydrationMap::new();
        // Governance visibility of the model-PII control on the streaming path,
        // handed to the completion handler to attach to the record (mirrors the
        // buffered path's `prompt_guard_model_pii` stage).
        let mut model_pii_stage: Option<crate::governance::StageEntry> = None;
        if let Some(prompt_guard) = &self.config.prompt_guard
            && prompt_guard.enabled
            && (!prompt_guard
                .request
                .is_empty()
                || !prompt_guard
                    .llm_pii
                    .is_empty())
        {
            let mut allocator = crate::pipes::prompt_guard::PseudonymAllocator::default();

            if !prompt_guard
                .request
                .is_empty()
                && let crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) =
                    crate::pipes::prompt_guard::apply_request_guards_into(
                        &mut request_body,
                        &prompt_guard.request,
                        &mut allocator,
                    )
            {
                return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexRequest, "regex"));
            }

            // Model-backed PII detection (Phase 2b): one or more detectors run in
            // parallel, sharing the allocator so ids stay consistent with the
            // regex/NER guards. A reject-action detector short-circuits here.
            if let Some(outcome) = self
                .run_model_pii_detectors(&mut request_body, &prompt_guard.llm_pii, &mut allocator)
                .await?
            {
                let (is_flag, detail) = model_pii_stage_detail(&outcome);
                model_pii_stage = Some(
                    crate::governance::StageEntry::decision(
                        "prompt_guard_model_pii",
                        if is_flag {
                            crate::governance::StageOutcome::Flag
                        } else {
                            crate::governance::StageOutcome::Observed
                        },
                        Some(detail),
                    )
                    .with_key_source(outcome.key_sources.sole()),
                );
            }

            if prompt_guard
                .request
                .iter()
                .any(|g| g.regex.link_pronouns)
            {
                crate::pipes::prompt_guard::link_pronouns_in_body(&mut request_body);
            }

            let want_restore = prompt_guard
                .request
                .iter()
                .any(|g| g.regex.restore_in_response)
                || prompt_guard
                    .llm_pii
                    .iter()
                    .any(|l| l.restore_in_response);
            if want_restore {
                rehydration_map = allocator.rehydration_map();
            }
        }

        // ── External guardrail (request) ──
        self.run_request_witnesses(&request_body)
            .await?;

        // ── Judge (request-side) ──
        // The Judge screens the prompt before the model runs. It can block the
        // request — returned as a `PromptGuardRejected` the caller renders as a
        // non-stream block — but never sees the response, so a Judge-only
        // surface still streams. Mirrors the buffered path's pre-LLM Judge; it
        // emits its own `[STAGE:judge]` event, and its usage is metered by the
        // caller alongside the streamed LLM usage.
        let mut judge_usage = StageUsage::default();
        if let Some(judge) = self
            .config
            .judge
            .as_ref()
            .filter(|j| j.enabled)
        {
            let (ju, _io) =
                crate::pipes::judge_jury::execute_judge(&self.config.id, judge, &request_body, &self.secrets).await?;
            judge_usage = ju;
        }

        // ── Decider (route, request-side) ──
        // A Route decider picks one candidate upstream to serve this request; we
        // stream that candidate's tokens. Mirror strategy (fan-out + merge) is
        // never streaming-eligible, so it is not run here. `execute_decider`
        // emits `[STAGE:decider]` and returns the candidate's resolved endpoint.
        let mut decider_usage = StageUsage::default();
        let routed = if let Some(decider) = self
            .config
            .decider
            .as_ref()
            .filter(|d| {
                d.enabled && !d.candidates.is_empty() && d.strategy == crate::pipes::judge_jury::DeciderStrategy::Route
            }) {
            let (candidate, candidate_provider, candidate_endpoint, usage, _io) =
                crate::pipes::judge_jury::execute_decider(&self.config.id, decider, &request_body, &self.secrets)
                    .await
                    .map_err(|e| e.with_incurred_usage(judge_usage, StageUsage::default()))?;
            decider_usage = usage;
            Some((candidate_provider, candidate_endpoint, candidate))
        } else {
            None
        };

        // ── Base provider preparation ──
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let base_provider = match &self.config.pipe_type {
            super::PipeType::LLM { provider, .. } => provider.as_ref(),
            _ => {
                return Err(PipeError::RequestFailed("Only LLM pipes support streaming".to_string())
                    .with_incurred_usage(judge_usage, decider_usage));
            }
        };
        // Stream from the Decider's chosen candidate when routed, else the base.
        let provider = routed
            .as_ref()
            .map(|(p, _, _)| p)
            .unwrap_or(base_provider);
        // A routed candidate sends its own headers and is priced by its own
        // declared price; the base upstream's belong to the base upstream.
        let (target_headers, target_pricing) = match &routed {
            Some((_, _, candidate)) => (TargetHeaders::of_target(candidate), candidate.pricing),
            None => (self.surface_headers_for(provider), self.config.upstream_pricing),
        };
        let profile = resolve_request_profile(provider);

        if let Some(override_policy) = &self.config.override_policy {
            self.apply_parameter_overrides(provider, &mut request_body, override_policy, &profile);
        }
        if routed.is_some() || !self.primary {
            strip_caller_body_key(&mut request_body);
        }

        // Inject the gateway model only when the client omitted one.
        if request_body
            .get("model")
            .is_none()
        {
            let model = provider.get_model();
            if !model.is_empty() {
                request_body["model"] = serde_json::json!(model);
            }
        }

        profile.apply_param_rules(&mut request_body);
        let model = model_run(provider, &request_body).to_string();

        let schema = provider
            .api_schema()
            .to_string();

        // Endpoint: the Decider candidate's fully-resolved URL when routed,
        // else the base provider's endpoint (+ optional path suffix for
        // OpenAI-compatible providers). Copilot instead sends to conversation
        // URLs under the provider's own endpoint.
        let direct_endpoint = match &routed {
            Some((_, candidate_endpoint, _)) => candidate_endpoint.clone(),
            None => {
                let mut endpoint = provider.get_endpoint();
                if provider.supports_path_suffix()
                    && let Some(suffix) = &path_suffix
                {
                    endpoint = endpoint
                        .trim_end_matches('/')
                        .to_string();
                    let suffix = if suffix.starts_with('/') {
                        suffix.clone()
                    } else {
                        format!("/{}", suffix)
                    };
                    endpoint.push_str(&suffix);
                }
                endpoint
            }
        };
        let request_url = if schema == "copilot" {
            provider.get_endpoint()
        } else {
            direct_endpoint.clone()
        };
        // The caller chose the path when its suffix was appended. Both the
        // metering check (inside `resolve_provider_headers`) and the
        // shared-credential check below read this one answer.
        let caller_suffix = path_suffix
            .as_deref()
            .filter(|_| routed.is_none() && provider.supports_path_suffix());
        let caller_path = caller_suffix.is_some() && schema != "copilot";

        // Provider headers are resolved up front — the Copilot branch needs them
        // to create the conversation before the streamed chat call.
        let ProviderHeaders {
            headers: provider_headers,
            own_price_honoured,
            key_source,
            sent_caller_credential,
            ..
        } = self
            .resolve_provider_headers(
                provider,
                target_headers,
                &request_url,
                routed.is_none(),
                &caller,
                UpstreamCall::Model {
                    declared: target_pricing,
                    model: &model,
                    body: &request_body,
                    caller_path,
                },
            )
            .await
            .map_err(|e| e.with_incurred_usage(judge_usage, decider_usage))?;
        // After the budget and metering checks, before anything is sent (see
        // `crate::pipes::shared_credential`).
        crate::pipes::shared_credential::admit_call(own_price_honoured, caller_suffix, &request_body).map_err(
            |refusal| PipeError::SharedCredentialRefused(refusal).with_incurred_usage(judge_usage, decider_usage),
        )?;
        crate::pipes::types::llm::ensure_priced_spend(
            &self.config.id,
            own_price_honoured,
            provider.provider_type_str(),
            &model,
            crate::pipes::types::llm::catalog_price(provider.provider_type_str(), &model, None).as_ref(),
        )
        .map_err(|e| e.with_incurred_usage(judge_usage, decider_usage))?;
        strip_cost_raising_parameters(&mut request_body, key_source);

        // The Copilot conversation id this turn ran against (created or reused);
        // returned to the caller so a follow-up can continue the same thread.
        let mut used_conversation_id: Option<String> = None;
        let endpoint = if schema == "copilot" {
            // ── Microsoft 365 Copilot streamed chat (`chatOverStream`) ──
            // The body is the Copilot conversation shape (no `stream` field — the
            // endpoint is inherently streamed). The Chat API is stateful, so when
            // the caller supplies a conversation id we **reuse** it (true
            // multi-turn memory — Copilot already holds the prior turns, so we
            // send only the new user message); otherwise we open a **fresh**
            // conversation and replay the history as grounding context. The id
            // used is returned to the caller so a follow-up can continue the
            // same conversation.
            let base = provider.get_endpoint();
            crate::url_validation::validate_service_endpoint_url(&base)
                .await
                .map_err(|e| PipeError::RequestFailed(e).with_incurred_usage(judge_usage, decider_usage))?;
            let convo_id = match conversation_id.as_deref() {
                Some(id) if !id.trim().is_empty() => {
                    request_body = crate::pipes::request_shaping::transform_to_copilot_format_with(request_body, false);
                    id.to_string()
                }
                _ => {
                    request_body = crate::pipes::request_shaping::transform_to_copilot_format(request_body);
                    self.create_copilot_conversation(&base, &provider_headers, sent_caller_credential)
                        .await
                        .map_err(|e| e.with_incurred_usage(judge_usage, decider_usage))?
                }
            };
            let ep = format!("{}/beta/copilot/conversations/{}/chatOverStream", base.trim_end_matches('/'), convo_id);
            used_conversation_id = Some(convo_id);
            ep
        } else {
            if schema == "anthropic" {
                if let Some(reason) = crate::pipes::request_shaping::claude_unreadable_file(&request_body) {
                    return Err(PipeError::UnsupportedContent(reason).with_incurred_usage(judge_usage, decider_usage));
                }
                // Wire-transform to the Anthropic Messages shape, then force
                // streaming on. Anthropic reports usage inside its own SSE events,
                // so `stream_options` (an OpenAI-only field) is not injected.
                request_body = crate::pipes::request_shaping::transform_to_anthropic_format(request_body);
                request_body["stream"] = serde_json::json!(true);
            } else {
                // Force streaming on, and ask OpenAI-compatible providers to emit a
                // terminal usage chunk so spend/tokens are still attributable.
                request_body["stream"] = serde_json::json!(true);
                request_usage_chunk(&mut request_body, key_source, &direct_endpoint);
                crate::pipes::request_shaping::move_tool_media_to_user_message(&mut request_body);
            }

            direct_endpoint
        };

        // ── SSRF guard ──
        crate::url_validation::validate_service_endpoint_url(&endpoint)
            .await
            .map_err(|e| PipeError::RequestFailed(e).with_incurred_usage(judge_usage, decider_usage))?;

        let request_json = serde_json::to_vec(&request_body).map_err(|e| {
            PipeError::RequestFailed(format!("Failed to serialize request: {}", e))
                .with_incurred_usage(judge_usage, decider_usage)
        })?;
        let request_bytes = request_json.len() as u64;
        // What the stream is billed at if it reports no final usage.
        let estimate = crate::pipes::streaming::StreamEstimate::of_request(
            &request_body,
            model_profile(provider, &model).reasoning,
        );

        let mut request = self
            .streaming_client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(request_json);
        for (name, value) in &provider_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| PipeError::RequestFailed(e.to_string()).with_incurred_usage(judge_usage, decider_usage))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            let failure = PipeError::upstream_failure(status, sent_caller_credential, "", &body);
            if self
                .config
                .circuit_breaker
                .is_some()
                && !failure.caller_key_rejected()
            {
                self.circuit_breaker
                    .lock()
                    .await
                    .record_failure();
            }
            return Err(failure.with_incurred_usage(judge_usage, decider_usage));
        }

        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .record_success();
        }

        Ok(crate::pipes::streaming::StreamingUpstream {
            response,
            provider: provider
                .provider_type_str()
                .to_string(),
            model,
            pricing: target_pricing,
            own_price_honoured,
            key_source,
            request_bytes,
            schema,
            conversation_id: used_conversation_id,
            rehydration_map,
            model_pii_stage,
            judge_usage,
            decider_usage,
            estimate,
        })
    }

    /// Forward a request whose upstream response is **binary** (e.g. text-to-speech
    /// audio) and return the raw bytes verbatim.
    ///
    /// Runs the request-side gates (circuit breaker, rate limit, request prompt
    /// guard, request witnesses) and the lean base-provider preparation, then
    /// sends and returns the response bytes + content type. Response-side stages
    /// (Jury, response guards, token extraction) do not apply to opaque binary
    /// bodies, so this bypasses them and meters zero tokens. Only reached for
    /// binary endpoints (see `crate::pipes::streaming::is_binary_endpoint`).
    pub async fn execute_binary(
        &self,
        mut request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
    ) -> Result<BinaryResponse, PipeError> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let provider = match &self.config.pipe_type {
            super::PipeType::LLM { provider, .. } => provider.as_ref(),
            _ => return Err(PipeError::RequestFailed("Only LLM pipes support binary passthrough".to_string())),
        };

        // ── Binary endpoint ──
        // Refused before any gate runs or anything is sent, on every key: see
        // [`binary_endpoint`].
        let endpoint = binary_endpoint(provider, path_suffix.as_deref()).ok_or_else(|| {
            warn!(
                pipe = ?self.config.id,
                provider = provider.provider_type_str(),
                "binary passthrough refused: the provider's endpoint is not a speech endpoint the path reaches"
            );
            PipeError::BinaryEndpointUnsupported
        })?;

        // ── Circuit breaker ──
        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .can_request()?;
        }

        // ── Rate limit ──
        if let Some(rate_limit) = &self.config.rate_limit
            && rate_limit.enabled
        {
            self.check_rate_limits(None)
                .await?;
        }

        // ── Prompt guard (request) ──
        if let Some(prompt_guard) = &self.config.prompt_guard
            && prompt_guard.enabled
            && !prompt_guard
                .request
                .is_empty()
            && let crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) =
                crate::pipes::prompt_guard::apply_request_guards(&mut request_body, &prompt_guard.request)
        {
            return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexRequest, "regex"));
        }

        // ── External guardrail (request) ──
        self.run_request_witnesses(&request_body)
            .await?;

        // ── Base provider preparation ──
        let profile = resolve_request_profile(provider);
        if let Some(override_policy) = &self.config.override_policy {
            self.apply_parameter_overrides(provider, &mut request_body, override_policy, &profile);
        }
        if request_body
            .get("model")
            .is_none()
        {
            let model = provider.get_model();
            if !model.is_empty() {
                request_body["model"] = serde_json::json!(model);
            }
        }
        profile.apply_param_rules(&mut request_body);

        // ── SSRF guard ──
        crate::url_validation::validate_service_endpoint_url(&endpoint)
            .await
            .map_err(PipeError::RequestFailed)?;

        let model = model_run(provider, &request_body).to_string();
        let ProviderHeaders {
            headers: provider_headers,
            own_price_honoured,
            key_source,
            sent_caller_credential,
            ..
        } = self
            .resolve_provider_headers(
                provider,
                self.surface_headers_for(provider),
                &endpoint,
                true,
                &caller,
                UpstreamCall::Binary {
                    declared: self.config.upstream_pricing,
                    model: &model,
                },
            )
            .await?;
        // After the budget and metering checks above (see
        // [`Self::resolve_provider_headers`]), and before anything is sent: on
        // a credential the surface's tenant does not own, the body names
        // nothing stored (see [`crate::pipes::shared_credential::admit_call`]).
        let caller_suffix = path_suffix
            .as_deref()
            .filter(|_| provider.supports_path_suffix());
        crate::pipes::shared_credential::admit_call(own_price_honoured, caller_suffix, &request_body)
            .map_err(PipeError::SharedCredentialRefused)?;
        let cost = self
            .calculate_main_llm_cost(
                self.config
                    .upstream_pricing
                    .as_ref(),
                own_price_honoured,
                &endpoint,
                provider.provider_type_str(),
                &model,
                binary_input_units(&request_body),
                0,
            )
            .await;

        let request_json = serde_json::to_vec(&request_body)
            .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize request: {}", e)))?;

        let mut request = self
            .client
            .post(&endpoint)
            .header("Content-Type", "application/json")
            .body(request_json);
        for (name, value) in &provider_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| PipeError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            let failure = PipeError::upstream_failure(status, sent_caller_credential, "", &body);
            if self
                .config
                .circuit_breaker
                .is_some()
                && !failure.caller_key_rejected()
            {
                self.circuit_breaker
                    .lock()
                    .await
                    .record_failure();
            }
            return Err(failure);
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/octet-stream")
            .to_string();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| PipeError::InvalidResponse(e.to_string()))?
            .to_vec();

        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .record_success();
        }

        Ok(BinaryResponse {
            response_bytes: bytes.len() as u64,
            bytes,
            content_type,
            key_source,
            cost,
        })
    }

    /// Forward a raw POST body (e.g. a `multipart/form-data` file upload for
    /// `POST /v1/files`) to the upstream provider verbatim, preserving the
    /// caller's `Content-Type` (including the multipart boundary). Runs the
    /// request-side gates (circuit breaker, rate limit, provider auth, SSRF);
    /// the body is opaque, so content guards, parameter rules, and token
    /// metering do not apply.
    pub async fn execute_upload(
        &self,
        path_suffix: Option<String>,
        content_type: String,
        body: Vec<u8>,
        caller: CallerCredentials,
    ) -> Result<BinaryResponse, PipeError> {
        // ── Circuit breaker ──
        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .can_request()?;
        }

        // ── Rate limit ──
        if let Some(rate_limit) = &self.config.rate_limit
            && rate_limit.enabled
        {
            self.check_rate_limits(None)
                .await?;
        }

        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let provider = match &self.config.pipe_type {
            super::PipeType::LLM { provider, .. } => provider.as_ref(),
            _ => return Err(PipeError::RequestFailed("Only LLM pipes support file upload passthrough".to_string())),
        };

        // Endpoint (+ optional path suffix for OpenAI-compatible providers).
        let mut endpoint = provider.get_endpoint();
        if provider.supports_path_suffix()
            && let Some(suffix) = &path_suffix
        {
            endpoint = endpoint
                .trim_end_matches('/')
                .to_string();
            let suffix = if suffix.starts_with('/') {
                suffix.clone()
            } else {
                format!("/{}", suffix)
            };
            endpoint.push_str(&suffix);
        }

        // ── SSRF guard ──
        crate::url_validation::validate_service_endpoint_url(&endpoint)
            .await
            .map_err(PipeError::RequestFailed)?;

        let ProviderHeaders {
            headers: provider_headers,
            own_price_honoured: credentials_owned,
            key_source,
            sent_caller_credential,
            ..
        } = self
            .resolve_provider_headers(
                provider,
                self.surface_headers_for(provider),
                &endpoint,
                true,
                &caller,
                UpstreamCall::Upload,
            )
            .await?;
        // A file uploaded through a shared credential lands in the store every
        // tenant on that credential shares. Speech to text stores nothing.
        // Where a budget is in scope a platform key never gets here: the
        // metering check above refuses every upload on it first
        // (`endpoint_not_metered`). This refusal is what holds where no budget
        // is in scope, and it covers a forwarded identity token too.
        if !credentials_owned
            && path_suffix
                .as_deref()
                .is_some_and(crate::pipes::streaming::is_upload_path)
        {
            warn!(
                pipe = ?self.config.id,
                "File upload refused: it would write a provider store through an operator credential"
            );
            return Err(PipeError::SharedCredentialRefused(
                crate::pipes::shared_credential::SharedCredentialRefusal::Upload,
            ));
        }

        let mut request = self
            .client
            .post(&endpoint)
            .header("Content-Type", content_type)
            .body(body);
        for (name, value) in &provider_headers {
            // Never let a provider header clobber the multipart Content-Type
            // (its boundary must reach the provider intact).
            if name
                .as_str()
                .eq_ignore_ascii_case("content-type")
            {
                continue;
            }
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| PipeError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            let failure = PipeError::upstream_failure(status, sent_caller_credential, "", &body);
            if self
                .config
                .circuit_breaker
                .is_some()
                && !failure.caller_key_rejected()
            {
                self.circuit_breaker
                    .lock()
                    .await
                    .record_failure();
            }
            return Err(failure);
        }

        let resp_content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| PipeError::InvalidResponse(e.to_string()))?
            .to_vec();

        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .record_success();
        }

        Ok(BinaryResponse {
            response_bytes: bytes.len() as u64,
            bytes,
            content_type: resp_content_type,
            key_source,
            cost: 0.0,
        })
    }

    /// Forward a **GET** request (no body) to the upstream provider and return
    /// the response bytes verbatim. Used for polling/retrieval endpoints such as
    /// `GET /v1/batches/{id}` and `GET /v1/files/{id}` whose responses are JSON
    /// (batch/file objects) or binary (file content). Runs the circuit breaker
    /// and rate limit, then a lean provider forward; there is no request body,
    /// so content guards and token metering do not apply.
    pub async fn execute_get(
        &self,
        path_suffix: Option<String>,
        caller: CallerCredentials,
    ) -> Result<BinaryResponse, PipeError> {
        // ── Circuit breaker ──
        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .can_request()?;
        }

        // ── Rate limit ──
        if let Some(rate_limit) = &self.config.rate_limit
            && rate_limit.enabled
        {
            self.check_rate_limits(None)
                .await?;
        }

        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let provider = match &self.config.pipe_type {
            super::PipeType::LLM { provider, .. } => provider.as_ref(),
            _ => return Err(PipeError::RequestFailed("Only LLM pipes support GET passthrough".to_string())),
        };

        // Endpoint (+ optional path suffix for OpenAI-compatible providers).
        let mut endpoint = provider.get_endpoint();
        if provider.supports_path_suffix()
            && let Some(suffix) = &path_suffix
        {
            endpoint = endpoint
                .trim_end_matches('/')
                .to_string();
            let suffix = if suffix.starts_with('/') {
                suffix.clone()
            } else {
                format!("/{}", suffix)
            };
            endpoint.push_str(&suffix);
        }

        // ── SSRF guard ──
        crate::url_validation::validate_service_endpoint_url(&endpoint)
            .await
            .map_err(PipeError::RequestFailed)?;

        let ProviderHeaders {
            headers: provider_headers,
            own_price_honoured: credentials_owned,
            key_source,
            sent_caller_credential,
            ..
        } = self
            .resolve_provider_headers(
                provider,
                self.surface_headers_for(provider),
                &endpoint,
                true,
                &caller,
                UpstreamCall::Poll,
            )
            .await?;
        // A provider's file and batch store is shared by every surface that
        // spends the same key, so a tenant's surface reads through it only with
        // credentials that tenant owns: on an appliance-wide (operator) key the
        // list and the contents would include every other tenant's files.
        // Where a budget is in scope a platform key never gets here: the
        // metering check above refuses every poll on it first
        // (`endpoint_not_metered`). This refusal is what holds where no budget
        // is in scope, and it covers a forwarded identity token too.
        if !credentials_owned {
            warn!(
                pipe = ?self.config.id,
                "GET passthrough refused: it would read a provider store through an operator credential"
            );
            return Err(PipeError::SharedCredentialRefused(
                crate::pipes::shared_credential::SharedCredentialRefusal::Read,
            ));
        }

        let mut request = self.client.get(&endpoint);
        for (name, value) in &provider_headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| PipeError::RequestFailed(e.to_string()))?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response
                .text()
                .await
                .unwrap_or_default();
            let failure = PipeError::upstream_failure(status, sent_caller_credential, "", &body);
            if self
                .config
                .circuit_breaker
                .is_some()
                && !failure.caller_key_rejected()
            {
                self.circuit_breaker
                    .lock()
                    .await
                    .record_failure();
            }
            return Err(failure);
        }

        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("application/json")
            .to_string();

        let bytes = response
            .bytes()
            .await
            .map_err(|e| PipeError::InvalidResponse(e.to_string()))?
            .to_vec();

        if self
            .config
            .circuit_breaker
            .is_some()
        {
            self.circuit_breaker
                .lock()
                .await
                .record_success();
        }

        Ok(BinaryResponse {
            response_bytes: bytes.len() as u64,
            bytes,
            content_type,
            key_source,
            cost: 0.0,
        })
    }

    /// Build the surface's routing pool: the primary provider plus any failover
    /// and load-balancing targets. Empty for non-LLM surfaces.
    fn build_routing_pool(&self) -> Vec<crate::pipes::request_routing::RoutingCandidate> {
        use crate::pipes::request_routing::RoutingCandidate;
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let mut pool = Vec::new();
        let super::PipeType::LLM { provider, .. } = &self.config.pipe_type else {
            return pool;
        };
        pool.push(RoutingCandidate {
            provider_type: provider
                .provider_type_str()
                .to_string(),
            model: provider
                .get_model()
                .to_string(),
            target: None,
        });
        if let Some(failover) = &self.config.failover {
            for target in &failover.targets {
                pool.push(RoutingCandidate {
                    provider_type: target
                        .llm
                        .provider_type
                        .clone(),
                    model: target.llm.model.clone(),
                    target: Some(target.llm.clone()),
                });
            }
        }
        if let Some(lb) = &self.config.load_balancing {
            for target in &lb.targets {
                pool.push(RoutingCandidate {
                    provider_type: target
                        .llm
                        .provider_type
                        .clone(),
                    model: target.llm.model.clone(),
                    target: Some(target.llm.clone()),
                });
            }
        }
        pool
    }

    /// Resolve pricing (per-million tokens) for a routing candidate: the price
    /// declared on its upstream (the target's own, or the surface's for the
    /// primary) when set, zero included, else the catalog.
    fn resolve_candidate_pricing(
        &self,
        candidate: &crate::pipes::request_routing::RoutingCandidate,
    ) -> Option<crate::pipes::types::llm::TokenPricing> {
        let declared = match &candidate.target {
            Some(target) => target.pricing,
            None => self.config.upstream_pricing,
        };
        if let Some(pricing) = declared {
            return Some(pricing.token_pricing());
        }
        let provider_key = candidate
            .provider_type
            .to_lowercase();
        let model = candidate.model.as_str();
        match crate::llm_catalog::global_catalog() {
            Some(catalog) => catalog.resolve_model_pricing(&provider_key, model, None),
            None => crate::pipes::types::llm::resolve_pricing_from_providers(&[], &provider_key, model, None),
        }
    }

    /// Apply the catalog-driven `max_price` filter and `sort: price` ordering.
    /// `latency` / `throughput` sorts keep the given order (they need
    /// pool-indexed samples the per-request path does not carry).
    fn apply_price_preferences(
        &self,
        prefs: &crate::pipes::request_routing::RoutingPreferences,
        candidates: Vec<crate::pipes::request_routing::RoutingCandidate>,
    ) -> Vec<crate::pipes::request_routing::RoutingCandidate> {
        let mut priced: Vec<_> = candidates
            .into_iter()
            .map(|c| {
                let pricing = self.resolve_candidate_pricing(&c);
                (c, pricing)
            })
            .collect();

        if let Some(max_price) = &prefs.max_price {
            priced.retain(|(_, pricing)| match pricing {
                Some(p) => {
                    max_price
                        .prompt
                        .is_none_or(|max| p.input_price_per_million <= max)
                        && max_price
                            .completion
                            .is_none_or(|max| p.output_price_per_million <= max)
                }
                None => false,
            });
        }

        if prefs.sort.as_deref() == Some("price") {
            priced.sort_by(|(_, a), (_, b)| {
                let cost = |p: &Option<crate::pipes::types::llm::TokenPricing>| {
                    p.as_ref()
                        .map(|p| p.input_price_per_million + p.output_price_per_million)
                        .unwrap_or(f64::MAX)
                };
                cost(a)
                    .partial_cmp(&cost(b))
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }

        priced
            .into_iter()
            .map(|(c, _)| c)
            .collect()
    }

    /// Execute a caller-ordered candidate list from per-request routing
    /// preferences. The primary candidate runs on `self`; targets run via a
    /// failover-cloned executor. Falls through on failover-eligible errors.
    #[allow(clippy::too_many_arguments)]
    async fn run_request_routed(
        &self,
        candidates: Vec<crate::pipes::request_routing::RoutingCandidate>,
        request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let total = candidates.len();
        let mut last_err: Option<PipeError> = None;
        let mut refusal: Option<PlatformRefusal> = None;
        let mut incurred = RejectedExecutionUsage::default();
        for (idx, candidate) in candidates
            .into_iter()
            .enumerate()
        {
            // Pin the request to the selected candidate's model so a routed
            // target does not receive the original request's model id.
            let mut candidate_body = request_body.clone();
            if !candidate.model.is_empty()
                && let Some(obj) = candidate_body.as_object_mut()
            {
                obj.insert("model".to_string(), Value::String(candidate.model.clone()));
            }
            let attempt = match &candidate.target {
                None => {
                    let result = self
                        .execute_with_retry(
                            candidate_body,
                            path_suffix.clone(),
                            caller.clone(),
                            trace_id.clone(),
                            correlation_id.clone(),
                            agent_identity.clone(),
                            conversation_id.clone(),
                        )
                        .await;
                    self.record_circuit_outcome(&result)
                        .await;
                    result
                }
                Some(target) => {
                    let alt_config = self
                        .config
                        .clone_with_failover_target(target);
                    let alt_exec = PipeExecutor::for_target(&alt_config, self.secrets.store().cloned());
                    alt_exec
                        .execute_with_retry(
                            candidate_body,
                            path_suffix.clone(),
                            CallerCredentials::default(),
                            trace_id.clone(),
                            correlation_id.clone(),
                            agent_identity.clone(),
                            None,
                        )
                        .await
                }
            };
            match attempt {
                Ok((body, mut metrics)) => {
                    if idx > 0 {
                        info!(
                            "[PIPE:{}] Request routing selected candidate {}/{}: {} / {}",
                            self.config.id,
                            idx + 1,
                            total,
                            candidate.provider_type,
                            candidate.model
                        );
                    }
                    metrics.absorb_incurred(&incurred);
                    return Ok((body, metrics));
                }
                Err(e) if Self::moves_to_next_target(&e) => {
                    if refusal.is_none() {
                        refusal = e.platform_refusal();
                    }
                    let (e, spent) = e.take_incurred();
                    incurred.add(&spent);
                    last_err = Some(e);
                }
                Err(e) => return Err(e.with_incurred(incurred)),
            }
        }
        Self::pool_exhausted(
            Err(last_err
                .unwrap_or_else(|| PipeError::RequestFailed("all request-routing candidates failed".to_string()))),
            refusal,
        )
        .map_err(|e| e.with_incurred(incurred))
    }

    /// decision or pointlessly retry a self-imposed limit. The caller's own key
    /// refused upstream ([`PipeError::CallerKeyRejected`]) is not eligible
    /// either: the caller gets the refusal, and its key never moves to another
    /// provider.
    fn is_failover_eligible(err: &PipeError) -> bool {
        match err {
            PipeError::WithIncurredUsage { inner, .. } => Self::is_failover_eligible(inner),
            err => matches!(
                err,
                PipeError::UpstreamResponse { .. }
                    | PipeError::RequestTimeout(_)
                    | PipeError::RequestFailed(_)
                    | PipeError::RetryExhausted(_)
                    | PipeError::InvalidResponse(_)
                    | PipeError::CircuitBreakerOpen(_)
            ),
        }
    }

    /// Whether a failed attempt hands the request to the next failover,
    /// load-balancing or routed target: a provider-health failure (see
    /// [`Self::is_failover_eligible`]), or a spent budget refusing this
    /// target's platform key, since the next target may run on an owned key.
    /// A budget refusal is not a provider-health failure, so it never reaches
    /// the circuit breaker, and a refused safety or decision stage is final.
    fn moves_to_next_target(err: &PipeError) -> bool {
        Self::is_failover_eligible(err) || err.upstream_unaffordable()
    }

    /// The error a failover, load-balancing or routed pool returns when no
    /// target served the request: the first platform-key refusal (a spent
    /// budget or unmetered spend) when a target was refused for one (the
    /// caller can act on that), else the last target's error.
    fn pool_exhausted(
        last: Result<(Value, ExecutionMetrics), PipeError>,
        refusal: Option<PlatformRefusal>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        match refusal {
            Some(refusal) if last.is_err() => Err(refusal.into_error(BudgetedCall::Upstream)),
            _ => last,
        }
    }

    /// Update the primary provider's circuit breaker from an execution outcome.
    /// No-op when no breaker is configured. Only provider-health failures —
    /// the failover-eligible upstream/transport errors — count against the
    /// breaker; content denials (request Prompt Guard, response Jury) and the
    /// gateway's own rate limit are not signals about the provider, so they
    /// leave breaker state untouched and can never open a healthy circuit.
    async fn record_circuit_outcome<T>(
        &self,
        result: &Result<T, PipeError>,
    ) {
        if self
            .config
            .circuit_breaker
            .is_none()
        {
            return;
        }
        let mut breaker = self
            .circuit_breaker
            .lock()
            .await;
        match result {
            Ok(_) => breaker.record_success(),
            Err(e) if Self::is_failover_eligible(e) => breaker.record_failure(),
            Err(_) => {}
        }
    }

    /// Map a `PipeError` to a stable, low-cardinality `reason` label for failover
    /// metrics and logs. The vocabulary is closed (one label per error class), so
    /// it never introduces unbounded cardinality.
    fn reason_of(err: &PipeError) -> &'static str {
        match err {
            PipeError::UpstreamResponse { .. } => "upstream_response",
            PipeError::CallerKeyRejected { .. } => "caller_key_rejected",
            PipeError::BudgetExhausted { .. } => "budget_exhausted",
            PipeError::NotMetered { .. } => "not_metered",
            PipeError::BinaryEndpointUnsupported => "binary_endpoint_unsupported",
            PipeError::UnsupportedContent(_) => "unsupported_content",
            PipeError::RequestTimeout(_) => "timeout",
            PipeError::RequestFailed(_) => "request_failed",
            PipeError::RetryExhausted(_) => "retry_exhausted",
            PipeError::InvalidResponse(_) => "invalid_response",
            PipeError::CircuitBreakerOpen(_) => "circuit_open",
            PipeError::RateLimitExceeded(_) => "rate_limit",
            PipeError::PromptGuardRejected { .. } => "prompt_guard",
            PipeError::SharedCredentialRefused(_) => "shared_credential",
            PipeError::WithIncurredUsage { inner, .. } => Self::reason_of(inner),
        }
    }

    /// Retry a failed primary execution against ordered backup providers.
    /// Returns the primary result untouched when failover is not configured,
    /// disabled, has no targets, or the primary error is not failover-eligible.
    /// A backup is another upstream, so it sends its own stored key and never
    /// the caller's.
    async fn run_failover_if_needed(
        &self,
        primary: Result<(Value, ExecutionMetrics), PipeError>,
        request_body: &Value,
        path_suffix: &Option<String>,
        trace_id: &Option<String>,
        correlation_id: &Option<String>,
        agent_identity: &Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let Err(primary_err) = &primary else {
            return primary;
        };
        let Some(failover) = &self.config.failover else {
            return primary;
        };
        if !failover.enabled || failover.targets.is_empty() {
            return primary;
        }
        let primary_reason = Self::reason_of(primary_err);
        if !Self::moves_to_next_target(primary_err) {
            // Failover is configured and enabled, but this error class must not
            // shift load to a backup (rate limit, content rejection). Record the
            // suppression so operators can see failover was deliberately skipped.
            crate::metrics::backends::prometheus::track_llm_failover_suppressed(primary_reason);
            info!(
                pipe.id = %self.config.id,
                failover.reason = primary_reason,
                failover.result = "suppressed",
                "Failover suppressed: primary error class is not failover-eligible"
            );
            return primary;
        }

        crate::metrics::backends::prometheus::track_llm_failover("primary_failure", primary_reason);
        let failover_started = Instant::now();

        let mut refusal = primary_err.platform_refusal();
        // Spend the failed attempts already incurred: billed with the target
        // that serves the request, or with the pool's final failure.
        let mut incurred = RejectedExecutionUsage::default();
        let mut last = primary.map_err(|e| {
            let (e, spent) = e.take_incurred();
            incurred.add(&spent);
            e
        });
        for (idx, target) in failover
            .targets
            .iter()
            .enumerate()
        {
            let target_index = idx + 1;
            let target_index_label = target_index.to_string();
            let alt_config = self
                .config
                .clone_with_failover_target(&target.llm);
            let alt_exec = PipeExecutor::for_target(&alt_config, self.secrets.store().cloned());
            warn!(
                pipe.id = %self.config.id,
                failover.target_index = target_index,
                llm.provider = %target.llm.provider_type,
                llm.model = %target.llm.model,
                failover.reason = primary_reason,
                "Primary upstream failed; failing over to backup target"
            );
            let attempt = alt_exec
                .execute_with_retry(
                    request_body.clone(),
                    path_suffix.clone(),
                    CallerCredentials::default(),
                    trace_id.clone(),
                    correlation_id.clone(),
                    agent_identity.clone(),
                    None,
                )
                .await;
            match attempt {
                Ok((body, mut metrics)) => {
                    crate::metrics::backends::prometheus::track_llm_failover_backup_attempt(
                        &target.llm.provider_type,
                        &target_index_label,
                        "success",
                    );
                    crate::metrics::backends::prometheus::track_llm_failover("backup_success", "none");
                    let latency_ms = failover_started
                        .elapsed()
                        .as_millis() as u64;
                    crate::metrics::backends::prometheus::observe_llm_failover_duration(
                        failover_started
                            .elapsed()
                            .as_secs_f64(),
                    );
                    info!(
                        pipe.id = %self.config.id,
                        failover.target_index = target_index,
                        failover.result = "backup_success",
                        failover.latency_ms = latency_ms,
                        llm.provider = %target.llm.provider_type,
                        llm.model = %target.llm.model,
                        "Failover succeeded: backup target served the request"
                    );
                    metrics.absorb_incurred(&incurred);
                    return Ok((body, metrics));
                }
                Err(e) if Self::moves_to_next_target(&e) => {
                    crate::metrics::backends::prometheus::track_llm_failover_backup_attempt(
                        &target.llm.provider_type,
                        &target_index_label,
                        "failure",
                    );
                    if refusal.is_none() {
                        refusal = e.platform_refusal();
                    }
                    let (e, spent) = e.take_incurred();
                    incurred.add(&spent);
                    last = Err(e);
                }
                // A non-eligible error on a backup (e.g. a guard rejection)
                // is final — surface it rather than masking it with the next
                // target.
                Err(e) => {
                    crate::metrics::backends::prometheus::track_llm_failover_backup_attempt(
                        &target.llm.provider_type,
                        &target_index_label,
                        "failure",
                    );
                    return Err(e.with_incurred(incurred));
                }
            }
        }

        // Every backup was attempted and none succeeded.
        let last_reason = match &last {
            Err(e) => Self::reason_of(e),
            Ok(_) => "none",
        };
        crate::metrics::backends::prometheus::track_llm_failover("exhausted", last_reason);
        let latency_ms = failover_started
            .elapsed()
            .as_millis() as u64;
        crate::metrics::backends::prometheus::observe_llm_failover_duration(
            failover_started
                .elapsed()
                .as_secs_f64(),
        );
        warn!(
            pipe.id = %self.config.id,
            failover.attempts = failover.targets.len(),
            failover.reason = last_reason,
            failover.result = "exhausted",
            failover.latency_ms = latency_ms,
            "Failover exhausted: all backup targets failed"
        );
        Self::pool_exhausted(last, refusal).map_err(|e| e.with_incurred(incurred))
    }

    /// Pick a pool-member index by weighted round-robin. Members with weight
    /// zero are never first-picked. Returns the index into `weights` (0 = the
    /// primary provider, 1.. = load-balancing targets).
    fn weighted_pick(
        &self,
        weights: &[u32],
    ) -> usize {
        let total: u64 = weights
            .iter()
            .map(|w| *w as u64)
            .sum();
        if total == 0 {
            return 0;
        }
        let n = self
            .lb_counter
            .fetch_add(1, Ordering::Relaxed)
            % total;
        let mut acc = 0u64;
        for (idx, weight) in weights.iter().enumerate() {
            acc += *weight as u64;
            if n < acc {
                return idx;
            }
        }
        0
    }

    /// Build the ordered attempt list for a load-balanced request: the
    /// weighted-selected member first, then every remaining member (so a failed
    /// first pick still falls through to the rest of the pool for resilience).
    fn load_balance_order(
        start: usize,
        len: usize,
    ) -> Vec<usize> {
        let mut order = Vec::with_capacity(len);
        order.push(start);
        for idx in 0..len {
            if idx != start {
                order.push(idx);
            }
        }
        order
    }

    /// Distribute a request across the weighted provider pool. Member 0 is the
    /// base pipe provider (executed via `self`); members 1.. are load-balancing
    /// targets executed through transient single-provider executors. On a
    /// failover-eligible error the request falls through to the next pool
    /// member; a non-eligible error (e.g. a guard rejection) is final.
    #[allow(clippy::too_many_arguments)]
    async fn run_load_balanced(
        &self,
        request_body: &Value,
        path_suffix: &Option<String>,
        caller: &CallerCredentials,
        trace_id: &Option<String>,
        correlation_id: &Option<String>,
        agent_identity: &Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let lb = self
            .config
            .load_balancing
            .as_ref()
            .expect("run_load_balanced requires load_balancing config");

        // weights[0] = primary, weights[1..] = each target.
        let mut weights: Vec<u32> = Vec::with_capacity(lb.targets.len() + 1);
        weights.push(lb.primary_weight);
        for target in &lb.targets {
            weights.push(target.weight);
        }

        let start = self.select_start_member(lb, &weights);
        let order = Self::load_balance_order(start, weights.len());
        let track_latency = lb.strategy == crate::pipes::config::LoadBalancingStrategy::LowestLatency;

        let mut last: Result<(Value, ExecutionMetrics), PipeError> =
            Err(PipeError::RequestFailed("load balancing pool produced no result".to_string()));
        let mut refusal: Option<PlatformRefusal> = None;
        let mut incurred = RejectedExecutionUsage::default();

        for member in order {
            let started = track_latency.then(Instant::now);
            let attempt = if member == 0 {
                self.execute_with_retry(
                    request_body.clone(),
                    path_suffix.clone(),
                    caller.clone(),
                    trace_id.clone(),
                    correlation_id.clone(),
                    agent_identity.clone(),
                    None,
                )
                .await
            } else {
                let target = &lb.targets[member - 1];
                let alt_config = self
                    .config
                    .clone_with_failover_target(&target.llm);
                let alt_exec = PipeExecutor::for_target(&alt_config, self.secrets.store().cloned());
                debug!(
                    "[PIPE:{}] Load-balancing to pool member {} ({} / {})",
                    self.config.id, member, target.llm.provider_type, target.llm.model
                );
                alt_exec
                    .execute_with_retry(
                        request_body.clone(),
                        path_suffix.clone(),
                        CallerCredentials::default(),
                        trace_id.clone(),
                        correlation_id.clone(),
                        agent_identity.clone(),
                        None,
                    )
                    .await
            };
            if attempt.is_ok()
                && let Some(started) = started
            {
                self.record_lb_latency(member, started.elapsed().as_millis() as u64);
            }
            match attempt {
                Ok((body, mut metrics)) => {
                    metrics.absorb_incurred(&incurred);
                    return Ok((body, metrics));
                }
                Err(e) if Self::moves_to_next_target(&e) => {
                    if refusal.is_none() {
                        refusal = e.platform_refusal();
                    }
                    let (e, spent) = e.take_incurred();
                    incurred.add(&spent);
                    last = Err(e);
                }
                // A non-eligible error (e.g. a guard rejection) is final.
                Err(e) => return Err(e.with_incurred(incurred)),
            }
        }
        Self::pool_exhausted(last, refusal).map_err(|e| e.with_incurred(incurred))
    }

    /// Choose the first pool member for a load-balanced request according to the
    /// configured strategy. Falls through to the rest of the pool for
    /// resilience regardless of strategy (via [`load_balance_order`]).
    fn select_start_member(
        &self,
        lb: &crate::pipes::config::LoadBalancingConfig,
        weights: &[u32],
    ) -> usize {
        match lb.strategy {
            crate::pipes::config::LoadBalancingStrategy::Weighted => self.weighted_pick(weights),
            crate::pipes::config::LoadBalancingStrategy::LowestLatency => self.lowest_latency_start(weights),
            crate::pipes::config::LoadBalancingStrategy::LowestCost => self.lowest_cost_start(lb, weights),
        }
    }

    /// Pool member with the lowest EWMA latency (an unsampled member — latency
    /// `0` — is tried first to gather a baseline). Skips zero-weight members;
    /// ties resolve to the lowest index.
    fn lowest_latency_start(
        &self,
        weights: &[u32],
    ) -> usize {
        let mut best: Option<(usize, u64)> = None;
        for (idx, weight) in weights.iter().enumerate() {
            if *weight == 0 {
                continue;
            }
            let latency = self
                .lb_latency
                .get(idx)
                .map(|slot| slot.load(Ordering::Relaxed))
                .unwrap_or(0);
            if best.is_none_or(|(_, b)| latency < b) {
                best = Some((idx, latency));
            }
        }
        best.map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    /// Pool member with the lowest catalog price for its model. Members without
    /// catalog pricing are deprioritised (`f64::MAX`); ties resolve to the
    /// lowest index.
    fn lowest_cost_start(
        &self,
        lb: &crate::pipes::config::LoadBalancingConfig,
        weights: &[u32],
    ) -> usize {
        let mut best: Option<(usize, f64)> = None;
        for (idx, weight) in weights.iter().enumerate() {
            if *weight == 0 {
                continue;
            }
            let cost = self.member_unit_cost(lb, idx);
            if best.is_none_or(|(_, b)| cost < b) {
                best = Some((idx, cost));
            }
        }
        best.map(|(idx, _)| idx)
            .unwrap_or(0)
    }

    /// Comparable unit cost (USD for 1k input + 1k output tokens) for a pool
    /// member: its declared price when set (zero included), else the model
    /// catalog. Member `0` is the base pipe's provider; `1..` are the
    /// load-balancing targets. `f64::MAX` when the member is not an LLM or has
    /// no pricing.
    fn member_unit_cost(
        &self,
        lb: &crate::pipes::config::LoadBalancingConfig,
        idx: usize,
    ) -> f64 {
        let declared = if idx == 0 {
            self.config.upstream_pricing
        } else {
            lb.targets[idx - 1]
                .llm
                .pricing
        };
        if let Some(pricing) = declared {
            return pricing
                .token_pricing()
                .calculate_cost(1000, 1000);
        }
        let (provider_key, model) = if idx == 0 {
            match &self.config.pipe_type {
                super::PipeType::LLM { provider, .. } => {
                    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
                    (
                        provider
                            .provider_type_str()
                            .to_lowercase(),
                        provider
                            .model_name()
                            .to_string(),
                    )
                }
                _ => return f64::MAX,
            }
        } else {
            let target = &lb.targets[idx - 1].llm;
            (
                target
                    .provider_type
                    .to_lowercase(),
                target.model.clone(),
            )
        };
        let pricing = match crate::llm_catalog::global_catalog() {
            Some(catalog) => catalog.resolve_model_pricing(&provider_key, &model, None),
            None => crate::pipes::types::llm::resolve_pricing_from_providers(&[], &provider_key, &model, None),
        };
        pricing
            .map(|p| p.calculate_cost(1000, 1000))
            .unwrap_or(f64::MAX)
    }

    /// Fold a completed request's latency into the pool member's EWMA
    /// (alpha = 1/8; the first sample seeds directly).
    fn record_lb_latency(
        &self,
        member: usize,
        sample_ms: u64,
    ) {
        if let Some(slot) = self.lb_latency.get(member) {
            let prev = slot.load(Ordering::Relaxed);
            let next = if prev == 0 {
                sample_ms
            } else {
                (prev * 7 + sample_ms) / 8
            };
            slot.store(next, Ordering::Relaxed);
        }
    }

    async fn check_rate_limits(
        &self,
        estimated_tokens: Option<u64>,
    ) -> Result<(), PipeError> {
        if let Some(rate_limit) = &self.config.rate_limit {
            // Skip rate limiting if disabled
            if !rate_limit.enabled {
                return Ok(());
            }

            let mut state = self
                .rate_limit_state
                .lock()
                .await;
            state.reset_if_needed();

            // Check request limit
            let max_requests = rate_limit.requests_per_minute as u64;
            if state.requests_made >= max_requests {
                return Err(PipeError::RateLimitExceeded(format!("Request limit: {}/min", max_requests)));
            }

            // Check token limit
            if let Some(max_tokens) = rate_limit.tokens_per_minute {
                let tokens = estimated_tokens.unwrap_or(0);
                if state.tokens_used + tokens > max_tokens {
                    return Err(PipeError::RateLimitExceeded(format!("Token limit: {}/min", max_tokens)));
                }
            }

            // Update state
            state.requests_made += 1;
            if let Some(tokens) = estimated_tokens {
                state.tokens_used += tokens;
            }
        }

        Ok(())
    }

    /// Enforce the surface's request-rate limit without running a full
    /// execution. Used by the IDE Surface front door to apply the catalogue's
    /// own aggregate requests-per-minute cap before a request is dispatched to a
    /// member surface (the member re-runs its own limits afterwards). Counts one
    /// request against the window on success; returns `RateLimitExceeded` when
    /// the cap is reached.
    pub async fn enforce_rate_limit(&self) -> Result<(), PipeError> {
        self.check_rate_limits(None)
            .await
    }

    async fn execute_with_retry(
        &self,
        request_body: Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let retry_policy = self
            .config
            .retry_policy
            .as_ref();
        let max_attempts = retry_policy
            .map(|p| p.max_retries + 1) // max_retries is number of retries, so add 1 for initial attempt
            .unwrap_or(1);

        // Only create retry span if retry is actually configured
        if retry_policy.is_some() {
            let retry_span = tracing::info_span!(
                "pipe.retry_logic",
                otel.name = "Retry Logic",
                pipe = %self.config.name,
                max_attempts = max_attempts
            );

            async {
                let mut last_error = None;
                let mut retry_count = 0u32;
                // Spend the failed attempts already incurred: billed with the
                // attempt that serves the request, or with its final failure.
                let mut incurred = RejectedExecutionUsage::default();

                for attempt in 0..max_attempts {
                    if attempt > 0 {
                        retry_count += 1;
                        if let Some(policy) = retry_policy {
                            let delay_ms = (policy.initial_backoff_ms as f64
                                * policy
                                    .backoff_multiplier
                                    .powi((attempt - 1) as i32))
                            .min(policy.max_backoff_ms as f64) as u64;

                            debug!("Retrying after {}ms (attempt {}/{})", delay_ms, attempt + 1, max_attempts);
                            tokio::time::sleep(StdDuration::from_millis(delay_ms)).await;
                        }
                    }

                    match self
                        .execute_once(
                            &request_body,
                            path_suffix.clone(),
                            caller.clone(),
                            trace_id.clone(),
                            correlation_id.clone(),
                            agent_identity.clone(),
                            retry_count,
                            conversation_id.clone(),
                        )
                        .await
                    {
                        Ok((body, mut metrics)) => {
                            metrics.absorb_incurred(&incurred);
                            return Ok((body, metrics));
                        }
                        Err(e) if e.caller_key_rejected() => return Err(e.with_incurred(incurred)),
                        // A platform-key refusal refuses every retry the same way.
                        Err(e) if e.platform_refusal().is_some() => return Err(e.with_incurred(incurred)),
                        // Content the upstream cannot read is refused the same way every time.
                        Err(e) if e.unsupported_content() => return Err(e.with_incurred(incurred)),
                        Err(e) => {
                            warn!("Request failed (attempt {}/{}): {:?}", attempt + 1, max_attempts, e);
                            let (e, spent) = e.take_incurred();
                            incurred.add(&spent);
                            last_error = Some(e);
                        }
                    }
                }

                Err(last_error
                    .unwrap_or(PipeError::RetryExhausted("All retry attempts failed".to_string()))
                    .with_incurred(incurred))
            }
            .instrument(retry_span)
            .await
        } else {
            // No retry configured, execute once
            let retry_count = 0u32;

            match self
                .execute_once(
                    &request_body,
                    path_suffix.clone(),
                    caller.clone(),
                    trace_id.clone(),
                    correlation_id.clone(),
                    agent_identity.clone(),
                    retry_count,
                    conversation_id.clone(),
                )
                .await
            {
                Ok(result) => Ok(result),
                Err(e) => Err(e),
            }
        }
    }

    /// One attempt of a buffered execution. A failure or a content rejection
    /// after a Judge, the Decider router, Mirror candidates, a main call or the
    /// Jury already ran carries their spend (see [`PipeError::with_incurred`]),
    /// so it is billed even though the request fails.
    #[allow(clippy::too_many_arguments)]
    async fn execute_once(
        &self,
        request_body: &Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        retry_count: u32,
        conversation_id: Option<String>,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let mut incurred = RejectedExecutionUsage::default();
        self.execute_once_spending(
            request_body,
            path_suffix,
            caller,
            trace_id,
            correlation_id,
            agent_identity,
            retry_count,
            conversation_id,
            &mut incurred,
        )
        .await
        .map_err(|e| match e {
            // A Judge or Jury rejection already carries the attempt's whole spend.
            rejected @ PipeError::PromptGuardRejected { usage: Some(_), .. } => rejected,
            e => e.with_incurred(incurred),
        })
    }

    /// [`Self::execute_once`], recording in `incurred` each stage's spend as it
    /// is incurred.
    #[allow(clippy::too_many_arguments)]
    async fn execute_once_spending(
        &self,
        request_body: &Value,
        path_suffix: Option<String>,
        caller: CallerCredentials,
        trace_id: Option<String>,
        correlation_id: Option<String>,
        agent_identity: Option<String>,
        retry_count: u32,
        conversation_id: Option<String>,
        incurred: &mut RejectedExecutionUsage,
    ) -> Result<(Value, ExecutionMetrics), PipeError> {
        let start = Instant::now();
        let _request_start = std::time::SystemTime::now();
        let trace_id = trace_id.unwrap_or_else(|| format!("pipe-{}", uuid::Uuid::new_v4()));

        // ── Prompt guard (request) ──
        // Runs before routing and validation so the Decider and Judge both
        // evaluate the masked content, and a blocked request never reaches
        // either stage. Guards operate on OpenAI-format messages.
        let mut working_request = request_body.clone();
        // Carries the NER ID restoration map from the request pseudonymize guard
        // (regex or model-backed) to the response, when re-hydration is opted into.
        let mut rehydration_map = crate::pipes::prompt_guard::RehydrationMap::new();
        // Governance visibility of the model-PII control, surfaced as an
        // `Observed` stage in the record so an auditor can see the detector ran
        // (and how many entities it masked) without exposing the value map.
        let mut model_pii_stage: Option<StageRecord> = None;
        if let Some(prompt_guard) = &self.config.prompt_guard
            && prompt_guard.enabled
            && (!prompt_guard
                .request
                .is_empty()
                || !prompt_guard
                    .llm_pii
                    .is_empty())
        {
            // Shared NER ID allocator so the regex/NER guards and model-backed
            // PII detection use one consistent id scheme (and one rehydration map).
            let mut allocator = crate::pipes::prompt_guard::PseudonymAllocator::default();

            // ── Regex / NER guards ──
            if !prompt_guard
                .request
                .is_empty()
            {
                let guard_timer = Instant::now();
                let guard_span = tracing::info_span!(
                    "pipe.prompt_guard.request",
                    otel.name = "Prompt Guard (Request)",
                    pipe = %self.config.name
                );
                let guard_result = async {
                    crate::pipes::prompt_guard::apply_request_guards_into(
                        &mut working_request,
                        &prompt_guard.request,
                        &mut allocator,
                    )
                }
                .instrument(guard_span)
                .await;

                match guard_result {
                    crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) => {
                        let guard_ms = guard_timer
                            .elapsed()
                            .as_millis();
                        warn!("[PIPE:{}] Request blocked by prompt guard", self.config.id);
                        let detail_json = serde_json::to_string(
                            rejection
                                .reason
                                .as_deref()
                                .unwrap_or("Request blocked"),
                        )
                        .unwrap_or_else(|_| "\"Request blocked\"".to_string());
                        info!(
                            "[PIPE:{}] [STAGE:prompt_guard_request] {{\"outcome\":\"rejected\",\"detail\":{},\"duration_ms\":{}}}",
                            self.config.id, detail_json, guard_ms
                        );
                        return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexRequest, "regex"));
                    }
                    crate::pipes::prompt_guard::GuardOutcome::Masked => {
                        let guard_ms = guard_timer
                            .elapsed()
                            .as_millis();
                        info!("[PIPE:{}] Request content masked by prompt guard", self.config.id);
                        info!(
                            "[PIPE:{}] [STAGE:prompt_guard_request] {{\"outcome\":\"masked\",\"detail\":\"Content masked\",\"duration_ms\":{}}}",
                            self.config.id, guard_ms
                        );
                    }
                    crate::pipes::prompt_guard::GuardOutcome::Allowed => {
                        let guard_ms = guard_timer
                            .elapsed()
                            .as_millis();
                        info!(
                            "[PIPE:{}] [STAGE:prompt_guard_request] {{\"outcome\":\"allowed\",\"detail\":\"Content passed\",\"duration_ms\":{}}}",
                            self.config.id, guard_ms
                        );
                    }
                }
            }

            // ── Model-backed PII detection (Phase 2b) ──
            // One or more detectors run in parallel after the regex/NER guards,
            // on the already-masked text, sharing their allocator so ids stay
            // consistent. A reject-action detector short-circuits with an error.
            if let Some(outcome) = self
                .run_model_pii_detectors(&mut working_request, &prompt_guard.llm_pii, &mut allocator)
                .await?
            {
                let (is_flag, detail) = model_pii_stage_detail(&outcome);
                model_pii_stage = Some(StageRecord {
                    stage: "prompt_guard_model_pii".to_string(),
                    decision: if is_flag {
                        StageDecision::Flag
                    } else {
                        StageDecision::Observed
                    },
                    detail: Some(detail),
                    input: None,
                    output: None,
                    key_source: outcome.key_sources.sole(),
                });
            }

            // ── Pronoun linking (Phase 3b) ──
            // Optional, off by default: link singular gendered pronouns to a
            // lone person's NER ID so mentions of one individual share a
            // pseudonym. Safe no-op unless a single person was pseudonymized.
            if prompt_guard
                .request
                .iter()
                .any(|g| g.regex.link_pronouns)
                && crate::pipes::prompt_guard::link_pronouns_in_body(&mut working_request)
            {
                info!(
                    "[PIPE:{}] [STAGE:prompt_guard_request] {{\"outcome\":\"masked\",\"detail\":\"Pronouns linked\"}}",
                    self.config.id
                );
            }

            // ── Rehydration map ──
            // Built when any regex pseudonymize guard or the model-PII detector
            // opted into restoring the real values in the response.
            let want_restore = prompt_guard
                .request
                .iter()
                .any(|g| g.regex.restore_in_response)
                || prompt_guard
                    .llm_pii
                    .iter()
                    .any(|l| l.restore_in_response);
            if want_restore {
                rehydration_map = allocator.rehydration_map();
            }
        }

        // Governance stage transcript: the resolved expert-witness / decider /
        // judge / jury stages that let this interaction through, recorded in
        // pipeline order for the governance record (attached only on success).
        let mut stage_records: Vec<StageRecord> = Vec::new();

        // Model-backed PII masking (when it ran) leads the transcript in pipeline
        // order, before the request witnesses.
        stage_records.extend(model_pii_stage);

        // ── External guardrail (request) ──
        // Consults the expert witnesses (e.g. EnkryptAI / Lakera / Azure) on
        // the already regex-masked request. A flagged verdict blocks the call
        // before it reaches the Decider, Judge, or LLM.
        stage_records.extend(
            self.run_request_witnesses(&working_request)
                .await?,
        );

        // ── Decider + Judge (parallel) ──
        // Once the prompt guard passes we route (Decider → which LLM) and
        // validate (Judge) concurrently: they are independent LLM calls, so
        // running them together keeps latency at max(decider, judge) rather than
        // their sum. With a Judge we wait for both before we know which LLM to
        // call; without a Judge we only wait for the Decider. The Decider's
        // selected candidate overrides the pipe's base provider for this request,
        // driving endpoint/model/header resolution during preparation below.
        let mut decider_usage = StageUsage::default();
        let mut decider_endpoint: Option<String> = None;
        // The target the Decider sent this request to (a Route candidate or
        // the Mirror merger): its own `headers` and `pricing` replace the base
        // upstream's for the main call.
        let mut decider_target: Option<&crate::pipes::judge_jury::LLMTarget> = None;
        let mut judge_usage = StageUsage::default();
        let mut decider_io = crate::pipes::judge_jury::StageIo::default();
        let mut judge_io = crate::pipes::judge_jury::StageIo::default();
        // Mirror fan-out spend: every candidate call, billed as main-LLM work at
        // each candidate's own price. Folded into `llm_usage` at the tail — zero,
        // and therefore a no-op, for Route / non-mirror executions.
        let mut mirror_billed = StageUsage::default();

        let decider_cfg = self
            .config
            .decider
            .as_ref()
            .filter(|d| d.enabled && !d.candidates.is_empty());
        let judge_cfg = self
            .config
            .judge
            .as_ref()
            .filter(|j| j.enabled);

        let is_mirror = decider_cfg
            .map(|d| d.strategy == crate::pipes::judge_jury::DeciderStrategy::Mirror)
            .unwrap_or(false);

        let decider_provider: Option<crate::pipes::types::llm::LLMProvider> = if is_mirror {
            let decider = decider_cfg.expect("is_mirror is only true when a decider config is present");

            // The Judge still gates the request in Mirror strategy; without a
            // router to run alongside, it simply runs before the fan-out.
            if let Some(judge) = judge_cfg {
                let (ju, jio) =
                    crate::pipes::judge_jury::execute_judge(&self.config.id, judge, &working_request, &self.secrets)
                        .await?;
                judge_usage = ju;
                incurred.judge = ju;
                judge_io = jio;
                stage_records.push(StageRecord {
                    stage: "judge".to_string(),
                    decision: StageDecision::Allow,
                    detail: Some(format!("approved · {} tok · ${:.4}", judge_usage.total_tokens(), judge_usage.cost)),
                    input: judge_io.input.take(),
                    output: judge_io.output.take(),
                    key_source: judge_usage.key_sources.sole(),
                });
            }

            info!(
                "[PIPE:{}] Mirror strategy: fanning out to {} candidate(s) (mode={:?})",
                self.config.id,
                decider.candidates.len(),
                decider.mirror.mode
            );
            stage_records.push(StageRecord {
                stage: "decider".to_string(),
                decision: StageDecision::Observed,
                detail: Some(format!("mirror {:?} · {} candidates", decider.mirror.mode, decider.candidates.len())),
                input: None,
                output: None,
                key_source: None,
            });

            // Fan out to every candidate concurrently. The candidate count is
            // capped at `MAX_MIRROR_CANDIDATES`, so the in-flight fan-out is
            // bounded without an extra concurrency limiter.
            let mut outcomes: Vec<CandidateOutcome> = futures::future::join_all(
                decider
                    .candidates
                    .iter()
                    .map(|candidate| self.run_candidate_upstream(candidate, &working_request, &caller)),
            )
            .await;

            // Every candidate failing is a hard error; otherwise survivors carry
            // on. A candidate refused on its platform key (a spent budget or
            // unmetered spend) is one that failed; when every candidate failed
            // and one was refused so, the request gets that refusal.
            if outcomes
                .iter()
                .all(|o| o.error.is_some())
            {
                if let Some(refusal) = outcomes
                    .iter()
                    .find_map(|o| o.refusal.clone())
                {
                    return Err(refusal.into_error(BudgetedCall::Upstream));
                }
                let reasons = outcomes
                    .iter()
                    .filter_map(|o| o.error.clone())
                    .collect::<Vec<_>>()
                    .join("; ");
                return Err(PipeError::RequestFailed(format!("All mirror candidates failed: {}", reasons)));
            }

            // Bill each candidate at its own rate and record a per-candidate stage.
            for outcome in &outcomes {
                let latency_ms = mirror_billed.latency_ms;
                mirror_billed.add(outcome.usage());
                incurred.llm = mirror_billed;
                // Candidates run concurrently: wall-clock is the slowest, not the sum.
                mirror_billed.latency_ms = latency_ms.max(outcome.latency_ms);
                stage_records.push(StageRecord {
                    stage: "mirror_candidate".to_string(),
                    decision: if outcome.error.is_some() {
                        StageDecision::Flag
                    } else {
                        StageDecision::Observed
                    },
                    detail: Some(match &outcome.error {
                        Some(err) => format!("{} ({}) failed: {}", outcome.name, outcome.model, err),
                        None => format!(
                            "{} ({}) · {} tok · ${:.4}",
                            outcome.name,
                            outcome.model,
                            outcome.input_tokens + outcome.output_tokens,
                            outcome.cost
                        ),
                    }),
                    input: None,
                    output: outcome
                        .error
                        .is_none()
                        .then(|| outcome.content.clone()),
                    key_source: outcome.key_source,
                });
            }

            match decider.mirror.mode {
                crate::pipes::judge_jury::MirrorMode::Collect => {
                    // Apply the response prompt guard + pseudonym rehydration to
                    // each candidate answer so Collect masks/restores identically
                    // to Route/Merge (which run the guard on the shared tail) —
                    // both the concatenated body and the per-candidate `x_mirror`
                    // entries. A response reject rule fails the whole request.
                    let response_guards: &[crate::pipes::prompt_guard::ResponseGuard] = self
                        .config
                        .prompt_guard
                        .as_ref()
                        .filter(|g| g.enabled)
                        .map(|g| g.response.as_slice())
                        .unwrap_or(&[]);
                    mask_collect_candidates(&mut outcomes, response_guards, &rehydration_map)?;

                    // Assemble every (now guarded) answer and let the response
                    // witnesses block on any flagged candidate text.
                    let body = build_mirror_collect_body(&outcomes);
                    stage_records.extend(
                        self.run_response_witnesses(&body)
                            .await?,
                    );

                    let request_bytes: u64 = outcomes
                        .iter()
                        .map(|o| o.request_bytes)
                        .sum();
                    let response_bytes: u64 = outcomes
                        .iter()
                        .map(|o| o.response_bytes)
                        .sum();
                    let request_latency_ms = start.elapsed().as_millis() as u64;
                    let grand_input_tokens = mirror_billed.input_tokens + judge_usage.input_tokens;
                    let grand_output_tokens = mirror_billed.output_tokens + judge_usage.output_tokens;
                    let metrics = ExecutionMetrics {
                        input_tokens: grand_input_tokens,
                        output_tokens: grand_output_tokens,
                        total_tokens: grand_input_tokens + grand_output_tokens,
                        cost: mirror_billed.cost + judge_usage.cost,
                        llm_usage: mirror_billed,
                        judge_usage,
                        jury_usage: StageUsage::default(),
                        decider_usage,
                        latency_ms: start.elapsed().as_millis() as u64,
                        provider: "mirror".to_string(),
                        model: "collect".to_string(),
                        trace_id,
                        correlation_id,
                        agent_identity,
                        request_bytes,
                        response_bytes,
                        time_to_first_token_ms: Some(request_latency_ms),
                        retry_count,
                        redrive_rejections: Vec::new(),
                        cached_tokens: 0,
                        cache_write_tokens: 0,
                        reasoning_tokens: 0,
                        schema_valid: None,
                        conversation_id: None,
                        stages: stage_records,
                        cache_hit: false,
                        cache_saved_cost: 0.0,
                        billed_cost: mirror_billed.billed_cost + judge_usage.billed_cost,
                        key_source: mirror_billed
                            .key_sources
                            .sole(),
                    };
                    info!(
                        "[PIPE:{}] Mirror Collect: returning {} candidate answer(s) ({} tok, ${:.6})",
                        self.config.id,
                        outcomes.len(),
                        metrics.total_tokens,
                        metrics.cost
                    );
                    return Ok((body, metrics));
                }
                crate::pipes::judge_jury::MirrorMode::Merge => {
                    let merger = decider
                        .mirror
                        .merger
                        .as_ref()
                        .ok_or_else(|| {
                            PipeError::RequestFailed("Mirror Merge mode requires a merger LLM".to_string())
                        })?;
                    // Rewrite the request so the merger synthesizes the answers,
                    // then route the main call to the merger through the existing
                    // decider-override plumbing (endpoint/model/headers + tail).
                    augment_request_for_merge(&mut working_request, decider, &outcomes);
                    let raw_endpoint = merger
                        .endpoint_url
                        .replace("{model}", &merger.model);
                    decider_endpoint =
                        Some(crate::pipes::defaults::resolve_endpoint_url(&merger.provider_type, &raw_endpoint));
                    decider_target = Some(merger);
                    Some(crate::pipes::judge_jury::target_to_provider(merger))
                }
            }
        } else {
            match (decider_cfg, judge_cfg) {
                (Some(decider), Some(judge)) => {
                    let decider_fut = crate::pipes::judge_jury::execute_decider(
                        &self.config.id,
                        decider,
                        &working_request,
                        &self.secrets,
                    );
                    let judge_fut = crate::pipes::judge_jury::execute_judge(
                        &self.config.id,
                        judge,
                        &working_request,
                        &self.secrets,
                    );
                    let (decider_res, judge_res) = tokio::join!(decider_fut, judge_fut);
                    if let Ok((_, _, _, usage, _)) = &decider_res {
                        incurred.decider = *usage;
                    }
                    if let Ok((usage, _)) = &judge_res {
                        incurred.judge = *usage;
                    }
                    let (target, provider, endpoint, usage, dio) = decider_res?;
                    decider_usage = usage;
                    decider_io = dio;
                    decider_endpoint = Some(endpoint);
                    decider_target = Some(target);
                    // A Judge rejection carries its own spend, which the
                    // attempt's is not added to (see `execute_once`): add the
                    // Decider router's, which ran beside it.
                    let (ju, jio) = judge_res.map_err(|e| match e {
                        rejected @ PipeError::PromptGuardRejected { usage: Some(_), .. } => {
                            rejected.with_incurred(RejectedExecutionUsage {
                                decider: decider_usage,
                                ..RejectedExecutionUsage::default()
                            })
                        }
                        e => e,
                    })?;
                    judge_usage = ju;
                    judge_io = jio;
                    Some(provider)
                }
                (Some(decider), None) => {
                    let (target, provider, endpoint, usage, dio) = crate::pipes::judge_jury::execute_decider(
                        &self.config.id,
                        decider,
                        &working_request,
                        &self.secrets,
                    )
                    .await?;
                    decider_usage = usage;
                    incurred.decider = usage;
                    decider_io = dio;
                    decider_endpoint = Some(endpoint);
                    decider_target = Some(target);
                    Some(provider)
                }
                (None, Some(judge)) => {
                    let (ju, jio) = crate::pipes::judge_jury::execute_judge(
                        &self.config.id,
                        judge,
                        &working_request,
                        &self.secrets,
                    )
                    .await?;
                    judge_usage = ju;
                    incurred.judge = ju;
                    judge_io = jio;
                    None
                }
                (None, None) => None,
            }
        };

        // Route strategy records its router choice + Judge verdict here; Mirror
        // strategy already pushed its own candidate/judge transcript above.
        if decider_cfg.is_some() && !is_mirror {
            stage_records.push(StageRecord {
                stage: "decider".to_string(),
                decision: StageDecision::Observed,
                detail: decider_provider
                    .as_ref()
                    .map(|p| format!("routed to {}", p.model_name())),
                input: decider_io.input.take(),
                output: decider_io.output.take(),
                key_source: decider_usage
                    .key_sources
                    .sole(),
            });
        }
        if judge_cfg.is_some() && !is_mirror {
            stage_records.push(StageRecord {
                stage: "judge".to_string(),
                decision: StageDecision::Allow,
                detail: Some(format!("approved · {} tok · ${:.4}", judge_usage.total_tokens(), judge_usage.cost)),
                input: judge_io.input.take(),
                output: judge_io.output.take(),
                key_source: judge_usage.key_sources.sole(),
            });
        }

        // Get provider details using trait-based extraction
        let prep_span = tracing::info_span!(
            "pipe.request_preparation",
            otel.name = "Request Preparation",
            pipe = %self.config.name
        );

        let (provider_str, api_schema, model, endpoint, modified_request) = async {
            match &self.config.pipe_type {
                super::PipeType::LLM { provider, .. } => {
                    use crate::pipes::types::llm_provider_ext::LLMProviderExt;

                    // Honour the Decider's selected candidate (if any). Endpoint,
                    // model, schema, and parameter handling all flow from this
                    // effective provider for the rest of preparation.
                    let provider: &crate::pipes::types::llm::LLMProvider = decider_provider
                        .as_ref()
                        .unwrap_or(&**provider);

                    let profile = resolve_request_profile(provider);

                    // Only clone and modify if we have override policy
                    let mut modified_request = if self
                        .config
                        .override_policy
                        .is_some()
                    {
                        let override_span = tracing::info_span!(
                            "pipe.parameter_override",
                            otel.name = "Parameter Override",
                            pipe = %self.config.name
                        );
                        let mut modified = working_request.clone();
                        if let Some(override_policy) = &self.config.override_policy {
                            let provider_ref = provider;
                            let override_policy_ref = override_policy;
                            let _result = async {
                                self.apply_parameter_overrides(
                                    provider_ref,
                                    &mut modified,
                                    override_policy_ref,
                                    &profile,
                                );
                            }
                            .instrument(override_span)
                            .await;
                        }
                        modified
                    } else {
                        working_request.clone()
                    };

                    // Ensure the request body carries the correct model. When the
                    // Decider routed this request, force the candidate's model: the
                    // upstream is now the candidate's provider, so any client-supplied
                    // (or base-pipe) model would be wrong for it — e.g. an Anthropic
                    // model name sent to an OpenAI candidate. Otherwise only inject the
                    // gateway model when the client omitted one.
                    if decider_provider.is_some()
                        || modified_request
                            .get("model")
                            .is_none()
                    {
                        let model = provider.get_model();
                        if !model.is_empty() {
                            modified_request["model"] = serde_json::json!(model);
                        }
                    }
                    if decider_provider.is_some() || !self.primary {
                        strip_caller_body_key(&mut modified_request);
                    }

                    // Normalise generation parameters for this model (alias, strip,
                    // inject) before any wire-format transform. Runs unconditionally
                    // so reasoning models and parameter-restricted models are handled
                    // even when no override policy is configured.
                    profile.apply_param_rules(&mut modified_request);

                    // Get base endpoint and conditionally append path suffix.
                    // When the Decider routed this request, use the candidate's
                    // fully-resolved absolute endpoint directly — the base pipe's
                    // provider and path suffix do not apply to the override.
                    let endpoint = if let Some(ep) = decider_endpoint.as_ref() {
                        ep.clone()
                    } else {
                        let mut endpoint = provider.get_endpoint();

                        // Only append path suffix for OpenAI-compatible providers
                        if provider.supports_path_suffix()
                            && let Some(ref suffix) = path_suffix
                        {
                            // Ensure proper path joining - remove trailing slash from endpoint, ensure suffix starts with /
                            endpoint = endpoint
                                .trim_end_matches('/')
                                .to_string();
                            let suffix = if suffix.starts_with('/') {
                                suffix.clone()
                            } else {
                                format!("/{}", suffix)
                            };
                            endpoint.push_str(&suffix);
                            debug!(
                                "Appended path suffix to endpoint: {}",
                                crate::url_validation::redact_url_for_logging(&endpoint)
                            );
                        }
                        endpoint
                    };

                    // NOTE: Request format transformation is deferred until after
                    // preparation, so the wire transform below operates on the
                    // already-guarded OpenAI-format messages.

                    Ok((
                        provider.provider_type_str(),
                        provider.api_schema(),
                        model_run(provider, &modified_request).to_string(),
                        endpoint,
                        modified_request,
                    ))
                }
                _ => Err(PipeError::RequestFailed("Only LLM pipes are currently supported".to_string())),
            }
        }
        .instrument(prep_span)
        .await?;

        // ── Request format transformation ──
        // The prompt guard, Decider, and Judge all ran on OpenAI-format messages
        // above; transform to the chosen provider's wire format before sending.
        // For Copilot, a caller-supplied conversation id means we reuse a
        // stateful conversation (Copilot already holds the prior turns), so we
        // shape only the new user message and skip the `additionalContext`
        // history replay.
        let copilot_reuse = conversation_id
            .as_deref()
            .is_some_and(|id| !id.trim().is_empty());
        let mut used_conversation_id: Option<String> = None;
        let mut modified_request = match api_schema {
            "anthropic" => {
                if let Some(reason) = crate::pipes::request_shaping::claude_unreadable_file(&modified_request) {
                    return Err(PipeError::UnsupportedContent(reason));
                }
                crate::pipes::request_shaping::transform_to_anthropic_format(modified_request)
            }
            "bedrock-anthropic" => {
                if let Some(reason) = crate::pipes::request_shaping::claude_unreadable_file(&modified_request) {
                    return Err(PipeError::UnsupportedContent(reason));
                }
                let body = crate::pipes::request_shaping::transform_to_bedrock_anthropic_format(modified_request);
                if let Some(reason) = crate::pipes::request_shaping::bedrock_unsupported_source(&body) {
                    return Err(PipeError::UnsupportedContent(reason));
                }
                body
            }
            "gemini" => crate::pipes::request_shaping::transform_to_gemini_format(modified_request),
            "copilot" => {
                crate::pipes::request_shaping::transform_to_copilot_format_with(modified_request, !copilot_reuse)
            }
            _ => {
                let mut body = modified_request;
                crate::pipes::request_shaping::move_tool_media_to_user_message(&mut body);
                body
            }
        };

        // The main call's declared price: the Decider target's own when it
        // routed this request, else the base upstream's.
        let main_pricing = match decider_target {
            Some(target) => target.pricing,
            None => self.config.upstream_pricing,
        };

        // The caller chose the path when its suffix was appended: no Decider
        // endpoint, and a provider that appends the request's path. Both the
        // metering check (inside `resolve_provider_headers`) and the
        // shared-credential check below read this one answer.
        let caller_suffix = match &self.config.pipe_type {
            super::PipeType::LLM { provider, .. } if decider_endpoint.is_none() => {
                use crate::pipes::types::llm_provider_ext::LLMProviderExt;
                let provider: &crate::pipes::types::llm::LLMProvider = decider_provider
                    .as_ref()
                    .unwrap_or(&**provider);
                path_suffix
                    .as_deref()
                    .filter(|_| provider.supports_path_suffix())
            }
            _ => None,
        };

        // ── Resolve API key and build provider headers (done once, reused across retries) ──
        let provider_headers: ProviderHeaders = if let super::PipeType::LLM { provider, .. } = &self.config.pipe_type {
            // Honour the Decider's selected candidate (if any) for key/header
            // resolution: a Decider target sends its own headers, never the
            // base upstream's.
            let provider: &crate::pipes::types::llm::LLMProvider = decider_provider
                .as_ref()
                .unwrap_or(&**provider);
            let target_headers = match decider_target {
                Some(target) => TargetHeaders::of_target(target),
                None => self.surface_headers_for(provider),
            };

            self.resolve_provider_headers(
                provider,
                target_headers,
                &endpoint,
                decider_provider.is_none(),
                &caller,
                UpstreamCall::Model {
                    declared: main_pricing,
                    model: &model,
                    body: &modified_request,
                    caller_path: caller_suffix.is_some(),
                },
            )
            .await?
        } else {
            ProviderHeaders {
                headers: vec![],
                own_price_honoured: true,
                key_source: KeySource::Platform,
                sent_caller_credential: false,
                keyless: true,
                budget_checked: false,
            }
        };
        let ProviderHeaders {
            headers: provider_headers,
            own_price_honoured: main_price_honoured,
            key_source: main_key_source,
            sent_caller_credential: main_sent_caller_credential,
            budget_checked: main_budget_checked,
            ..
        } = provider_headers;
        // After the budget and metering checks, before anything is sent (see
        // `crate::pipes::shared_credential`).
        crate::pipes::shared_credential::admit_call(main_price_honoured, caller_suffix, &modified_request)
            .map_err(PipeError::SharedCredentialRefused)?;
        crate::pipes::types::llm::ensure_priced_spend(
            &self.config.id,
            main_price_honoured,
            provider_str,
            &model,
            crate::pipes::types::llm::catalog_price(provider_str, &model, Some(&endpoint)).as_ref(),
        )?;
        strip_cost_raising_parameters(&mut modified_request, main_key_source);

        // ── Microsoft 365 Copilot: create or reuse a conversation before chatting ──
        // The Chat API is stateful — a conversation must exist before a chat
        // turn can be sent. When the caller supplies a conversation id we reuse
        // it (native multi-turn memory — the body carries only the new message);
        // otherwise we open a fresh conversation per execution. Either way the id
        // used is returned via `ExecutionMetrics.conversation_id` so a follow-up
        // can continue the same thread. Runs once here (not inside the jury loop).
        let endpoint = if api_schema == "copilot" {
            let convo_id = match conversation_id.as_deref() {
                Some(id) if !id.trim().is_empty() => id.to_string(),
                _ => {
                    self.create_copilot_conversation(&endpoint, &provider_headers, main_sent_caller_credential)
                        .await?
                }
            };
            used_conversation_id = Some(convo_id.clone());
            format!("{}/beta/copilot/conversations/{}/chat", endpoint.trim_end_matches('/'), convo_id)
        } else {
            endpoint
        };

        // ── Jury retry loop ──
        // When the Jury rejects an LLM response, the rejection reason is appended to the
        // conversation as feedback and the LLM is called again, up to `max_retries` times.
        let max_jury_retries = self
            .config
            .jury
            .as_ref()
            .and_then(|j| j.max_retries)
            .unwrap_or(0);
        let mut jury_attempt = 0u32;

        // Jury and main-LLM usage accumulated across every attempt. Rejected
        // retry attempts are billed by the provider, so their main-LLM tokens
        // are folded in here even though only the final response_body is returned.
        let mut jury_usage = StageUsage::default();
        let mut jury_io = crate::pipes::judge_jury::StageIo::default();
        let mut llm_retry_input = 0u64;
        // Prompt-cache tokens of those rejected attempts, priced apart.
        let mut llm_retry_cache = crate::pipes::types::llm::CacheTokens::default();
        let mut llm_retry_output = 0u64;
        // Judge/Jury rejections recovered by a redrive within this execution.
        // Recorded into rejection telemetry under the synthetic `redrive`
        // category only when the execution ultimately succeeds.
        let mut redrive_rejections: Vec<RejectionMeta> = Vec::new();
        // Main-LLM call latency accumulated across every attempt (initial +
        // jury-rejected retries), mirroring the token accumulation above.
        let mut llm_latency_ms = 0u64;

        let (mut response_body, request_bytes, response_bytes, request_latency_ms) = loop {
            let attempt_label = if jury_attempt == 0 {
                "initial".to_string()
            } else {
                format!("retry {}/{}", jury_attempt, max_jury_retries)
            };
            // A Jury retry is another call on the main call's key, so it asks
            // the budget too. The request's answer was fixed when the first
            // send was admitted, so a retry is never refused part-way.
            if jury_attempt > 0 && main_budget_checked {
                admit_call(main_key_source, BudgetedCall::Upstream, "upstream (jury retry)").await?;
            }

            // ── Serialize request body ──
            let request_json = serde_json::to_vec(&modified_request.clone())
                .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize request: {}", e)))?;
            let request_bytes = request_json.len() as u64;
            info!("[PIPE:{}] Request serialized ({}): {} bytes", self.config.id, attempt_label, request_bytes);

            // ── SSRF guard: never forward to cloud-provider metadata services ──
            crate::url_validation::validate_service_endpoint_url(&endpoint)
                .await
                .map_err(PipeError::RequestFailed)?;

            // ── Build HTTP request with pre-resolved headers ──
            let mut request = self
                .client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .body(request_json);

            for (header_name, header_value) in &provider_headers {
                request = request.header(header_name.as_str(), header_value.as_str());
            }

            info!(
                "[PIPE:{}] Sending request ({}) - provider: {}, model: {}, endpoint: {}",
                self.config.id, attempt_label, provider_str, model, endpoint
            );
            info!(
                "[PIPE:{}] [STAGE:llm_request] {{\"provider\":\"{}\",\"model\":\"{}\",\"attempt\":\"{}\"}}",
                self.config.id, provider_str, model, attempt_label
            );

            // Capture request latency: time spent in gateway preparing the request
            let request_latency_ms = start.elapsed().as_millis() as u64;

            // Start LLM call timer
            let llm_call_timer = Instant::now();

            // ── Send request to LLM provider ──
            let llm_span = tracing::info_span!(
                "llm.provider.request",
                otel.name = "LLM Provider Request",
                llm.provider = %provider_str,
                llm.model = %model,
                llm.endpoint = %endpoint,
                trace_id = %trace_id,
                jury.attempt = jury_attempt,
            );

            let (response_body, response_bytes) = match async {
                let response = request
                    .send()
                    .await
                    .map_err(|e| {
                        if e.is_timeout() {
                            PipeError::RequestTimeout(format!(
                                "provider exceeded the {} second Surface deadline",
                                self.config
                                    .request_timeout_seconds
                            ))
                        } else {
                            PipeError::RequestFailed(e.to_string())
                        }
                    })?;

                if !response.status().is_success() {
                    let status = response.status();
                    let error_body = response
                        .text()
                        .await
                        .unwrap_or_default();
                    return Err(PipeError::upstream_failure(status, main_sent_caller_credential, "", &error_body));
                }

                let response_text = response
                    .text()
                    .await
                    .map_err(|e| PipeError::InvalidResponse(e.to_string()))?;
                let response_bytes = response_text.len() as u64;
                let response_body: Value =
                    serde_json::from_str(&response_text).map_err(|e| PipeError::InvalidResponse(e.to_string()))?;

                Ok((response_body, response_bytes))
            }
            .instrument(llm_span)
            .await
            {
                Ok(result) => result,
                Err(e) => {
                    // Emit a terminal LLM stage so the activity view renders the
                    // failure as a fault instead of an apparently successful run.
                    let llm_call_ms = llm_call_timer
                        .elapsed()
                        .as_millis();
                    let detail: String = e
                        .to_string()
                        .chars()
                        .take(300)
                        .collect();
                    let detail_json = serde_json::to_string(&detail).unwrap_or_else(|_| "\"\"".to_string());
                    warn!(
                        "[PIPE:{}] [STAGE:llm_response] {{\"outcome\":\"error\",\"attempt\":\"{}\",\"duration_ms\":{},\"error\":{}}}",
                        self.config.id, attempt_label, llm_call_ms, detail_json
                    );
                    return Err(e);
                }
            };

            // ── Parse response ──
            info!("[PIPE:{}] Response parsed successfully ({})", self.config.id, attempt_label);
            let llm_call_ms = llm_call_timer
                .elapsed()
                .as_millis();
            llm_latency_ms += llm_call_ms as u64;
            info!(
                "[PIPE:{}] [STAGE:llm_response] {{\"outcome\":\"success\",\"attempt\":\"{}\",\"duration_ms\":{}}}",
                self.config.id, attempt_label, llm_call_ms
            );

            // ── Response format transformation ──
            // Transform non-OpenAI formats so downstream consumers see consistent
            // `choices[].message.content` structure.
            let response_body = match api_schema {
                "anthropic" | "bedrock-anthropic" => {
                    let transformed = transform_from_anthropic_format(response_body);
                    info!("[PIPE:{}] Transformed Anthropic response to OpenAI format", self.config.id);
                    transformed
                }
                "gemini" => {
                    let transformed = transform_from_gemini_format(response_body);
                    info!("[PIPE:{}] Transformed Gemini response to OpenAI format", self.config.id);
                    transformed
                }
                "copilot" => {
                    let transformed = transform_from_copilot_format(response_body);
                    info!("[PIPE:{}] Transformed Microsoft 365 Copilot response to OpenAI format", self.config.id);
                    transformed
                }
                _ => response_body,
            };
            // Every main call so far has spent, whatever happens next.
            incurred.llm = self
                .main_stage_spend(
                    &response_body,
                    (llm_retry_input, llm_retry_output),
                    llm_retry_cache,
                    jury_attempt + 1,
                    main_pricing.as_ref(),
                    main_price_honoured,
                    &endpoint,
                    provider_str,
                    &model,
                    main_key_source,
                    mirror_billed,
                )
                .await;

            // ── Jury evaluation (LLM-based post-processing validation) ──
            // Jury evaluates the raw LLM response before any masking is applied.
            if let Some(jury) = &self.config.jury
                && jury.enabled
            {
                use crate::pipes::judge_jury::JuryVerdict;
                let (verdict, attempt_jury_usage, attempt_jury_io) =
                    crate::pipes::judge_jury::execute_jury(&self.config.id, jury, &response_body, &self.secrets)
                        .await?;
                jury_usage.add(attempt_jury_usage);
                incurred.jury = jury_usage;
                jury_io = attempt_jury_io;

                match verdict {
                    JuryVerdict::Approved => {
                        if jury_attempt > 0 {
                            info!(
                                "[PIPE:{}] Jury APPROVED on retry {}/{}",
                                self.config.id, jury_attempt, max_jury_retries
                            );
                        }
                        break (response_body, request_bytes, response_bytes, request_latency_ms);
                    }
                    JuryVerdict::Rejected(reason) if jury_attempt < max_jury_retries => {
                        jury_attempt += 1;
                        warn!(
                            "[PIPE:{}] Jury rejected (attempt {}/{}), retrying — reason: {}",
                            self.config.id, jury_attempt, max_jury_retries, reason
                        );

                        // Count this recovered rejection as a redrive event: the
                        // request is being retried, so the real content category
                        // is reserved for a final block. The reason is preserved
                        // for diagnostics but classified as `redrive` downstream.
                        redrive_rejections.push(RejectionMeta::new(RejectionStage::Jury, "jury", vec![reason.clone()]));

                        // This rejected response is discarded but was still billed —
                        // fold its main-LLM tokens into the stage total before retrying.
                        if let Ok((retry_in, retry_out, _)) = llm_parser::parse_auto(&response_body) {
                            llm_retry_input += retry_in;
                            llm_retry_output += retry_out;
                        }
                        llm_retry_cache.add(crate::pipes::types::llm::CacheTokens::of_response(&response_body));

                        // Extract the LLM's rejected response to include as context
                        let assistant_content = response_body
                            .pointer("/choices/0/message/content")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string();

                        // Append the rejected response + jury feedback to the conversation
                        if let Some(messages) = modified_request
                            .get_mut("messages")
                            .and_then(|m| m.as_array_mut())
                        {
                            // Add the LLM's rejected response as assistant message
                            messages.push(serde_json::json!({
                                "role": "assistant",
                                "content": assistant_content
                            }));

                            // Build the retry feedback using the configured template
                            let retry_template = jury
                                .retry_prompt
                                .as_deref()
                                .unwrap_or(
                                    "Your previous response was rejected by quality review: {reason}. \
                                 Please revise your response to address these concerns.",
                                );
                            let retry_message = retry_template.replace("{reason}", &reason);

                            messages.push(serde_json::json!({
                                "role": "user",
                                "content": retry_message
                            }));
                        }

                        continue;
                    }
                    JuryVerdict::Rejected(reason) => {
                        // Max retries exhausted — return the final rejection
                        warn!(
                            "[PIPE:{}] Jury rejected after {} retries, returning rejection: {}",
                            self.config.id, jury_attempt, reason
                        );
                        let rejection = jury
                            .rejection
                            .clone()
                            .unwrap_or_default();
                        return Err(PipeError::PromptGuardRejected {
                            status_code: rejection.status_code,
                            body: rejection.body,
                            content_type: rejection.content_type,
                            rejection: Some(Box::new(RejectionMeta::new(RejectionStage::Jury, "jury", vec![reason]))),
                            usage: Some(Box::new(RejectedExecutionUsage {
                                // Every main call the Jury reviewed, with the
                                // Mirror candidates' spend (see
                                // `main_stage_spend` above).
                                llm: incurred.llm,
                                judge: judge_usage,
                                jury: jury_usage,
                                decider: decider_usage,
                            })),
                        }
                        .with_stage_io(jury_io.input.take(), jury_io.output.take()));
                    }
                }
            } else {
                // No jury configured — accept the response as-is
                break (response_body, request_bytes, response_bytes, request_latency_ms);
            }
        };

        // Recovered Judge/Jury rejections (redriven to an accepted response)
        // become flag stages so the record shows what was caught and retried.
        for meta in &redrive_rejections {
            stage_records.push(StageRecord {
                stage: meta.stage.label().to_string(),
                decision: StageDecision::Flag,
                detail: Some(format!("recovered: {}", meta.raw_reasons.join(", "))),
                input: None,
                output: None,
                key_source: None,
            });
        }
        if self
            .config
            .jury
            .as_ref()
            .map(|j| j.enabled)
            .unwrap_or(false)
        {
            stage_records.push(StageRecord {
                stage: "jury".to_string(),
                decision: StageDecision::Allow,
                detail: Some(format!("approved · {} tok · ${:.4}", jury_usage.total_tokens(), jury_usage.cost)),
                input: jury_io.input.take(),
                output: jury_io.output.take(),
                key_source: jury_usage.key_sources.sole(),
            });
        }

        // Apply response prompt guard (content filtering before returning to client)
        // Masking happens after jury so the jury sees the unmasked response
        if let Some(prompt_guard) = &self.config.prompt_guard
            && prompt_guard.enabled
            && !prompt_guard
                .response
                .is_empty()
        {
            let resp_guard_timer = Instant::now();
            let guard_span = tracing::info_span!(
                "pipe.prompt_guard.response",
                otel.name = "Prompt Guard (Response)",
                pipe = %self.config.name
            );
            let guard_result =
                async { crate::pipes::prompt_guard::apply_response_guards(&mut response_body, &prompt_guard.response) }
                    .instrument(guard_span)
                    .await;

            match guard_result {
                crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) => {
                    let guard_ms = resp_guard_timer
                        .elapsed()
                        .as_millis();
                    warn!("[PIPE:{}] Response blocked by prompt guard", self.config.id);
                    let detail_json = serde_json::to_string(
                        rejection
                            .reason
                            .as_deref()
                            .unwrap_or("Response blocked"),
                    )
                    .unwrap_or_else(|_| "\"Response blocked\"".to_string());
                    info!(
                        "[PIPE:{}] [STAGE:prompt_guard_response] {{\"outcome\":\"rejected\",\"detail\":{},\"duration_ms\":{}}}",
                        self.config.id, detail_json, guard_ms
                    );
                    return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexResponse, "regex"));
                }
                crate::pipes::prompt_guard::GuardOutcome::Masked => {
                    let guard_ms = resp_guard_timer
                        .elapsed()
                        .as_millis();
                    info!("[PIPE:{}] Response content masked by prompt guard", self.config.id);
                    info!(
                        "[PIPE:{}] [STAGE:prompt_guard_response] {{\"outcome\":\"masked\",\"detail\":\"Content masked\",\"duration_ms\":{}}}",
                        self.config.id, guard_ms
                    );
                }
                crate::pipes::prompt_guard::GuardOutcome::Allowed => {
                    let guard_ms = resp_guard_timer
                        .elapsed()
                        .as_millis();
                    info!(
                        "[PIPE:{}] [STAGE:prompt_guard_response] {{\"outcome\":\"allowed\",\"detail\":\"Content passed\",\"duration_ms\":{}}}",
                        self.config.id, guard_ms
                    );
                }
            }
        }

        // ── External guardrail (response) ──
        // Consults the expert witnesses on the response after the jury and
        // local regex guards. A flagged verdict blocks delivery.
        stage_records.extend(
            self.run_response_witnesses(&response_body)
                .await?,
        );

        // ── Restore pseudonymized values (response re-hydration) ──
        // The provider, Decider, Judge/Jury, and witnesses all saw NER IDs; put
        // the real values back before the completion reaches the client. Opted
        // into on the request pseudonymize guard (`restore_in_response`).
        if !rehydration_map.is_empty()
            && crate::pipes::prompt_guard::rehydrate_response(&mut response_body, &rehydration_map)
        {
            info!("[PIPE:{}] Restored pseudonymized values in response", self.config.id);
        }

        // Extract token usage
        let token_span = tracing::info_span!(
            "pipe.token_extraction",
            otel.name = "Token Extraction",
            llm.provider = %provider_str
        );

        let (input_tokens, output_tokens, _final_total_tokens) = async {
            match llm_parser::parse_auto(&response_body) {
                Ok(tokens) => {
                    info!(
                        "[PIPE:{}] Tokens extracted - input: {}, output: {}, total: {}",
                        self.config.id, tokens.0, tokens.1, tokens.2
                    );
                    Ok::<_, PipeError>(tokens)
                }
                Err(e) => {
                    // Non-chat endpoints (moderations, rerank, …) frequently
                    // return no `usage` block; meter them as zero tokens rather
                    // than failing the request. Chat completions must always
                    // carry usage, so a missing block there is still an error.
                    let is_chat = path_suffix
                        .as_deref()
                        .map(|suffix| suffix.ends_with("/chat/completions"))
                        .unwrap_or(true);
                    if is_chat {
                        Err(PipeError::InvalidResponse(e))
                    } else {
                        info!(
                            "[PIPE:{}] No usage in non-chat response ({}); metering as zero tokens",
                            self.config.id, e
                        );
                        Ok((0, 0, 0))
                    }
                }
            }
        }
        .instrument(token_span)
        .await?;

        // Main-LLM stage totals = final attempt + any rejected jury-retry attempts.
        let llm_input_tokens = input_tokens + llm_retry_input;
        let llm_output_tokens = output_tokens + llm_retry_output;
        let llm_total_tokens = llm_input_tokens + llm_output_tokens;

        // Provider-side prompt-cache usage reported by the upstream (if any).
        let cached_tokens = llm_parser::parse_cached_tokens(&response_body);
        let cache_write_tokens = llm_parser::parse_cache_write_tokens(&response_body);
        if cached_tokens > 0 || cache_write_tokens > 0 {
            info!(
                "[PIPE:{}] Provider-side cache: {} read + {} written prompt tokens ({} input)",
                self.config.id, cached_tokens, cache_write_tokens, llm_input_tokens
            );
        }

        // Reasoning (thinking) tokens reported by the upstream, surfaced for
        // visibility. When the caller asked to exclude reasoning, strip the
        // reasoning content from the response but keep metering it.
        let reasoning_tokens = llm_parser::parse_reasoning_tokens(&response_body);
        let reasoning_exclude = crate::pipes::reasoning::resolve(request_body)
            .map(|r| r.exclude)
            .unwrap_or(false);
        if reasoning_exclude
            && let Some(message) = response_body
                .pointer_mut("/choices/0/message")
                .and_then(|m| m.as_object_mut())
        {
            message.remove("reasoning");
            message.remove("reasoning_details");
        }

        // Structured-output conformance: when the request asked for a
        // `json_schema` response, unwrap a markdown-fenced completion so the
        // caller gets parseable JSON, then validate against the schema so the
        // caller gets a conformance signal on every provider.
        crate::pipes::structured_output::unwrap_response_content(request_body, &mut response_body);
        let schema_valid =
            crate::pipes::structured_output::validate_response(request_body, &response_body).map(|result| {
                if let Err(reason) = &result {
                    warn!("[PIPE:{}] Structured output failed schema validation: {}", self.config.id, reason);
                }
                result.is_ok()
            });

        // Calculate cost if enabled
        let cost_span = tracing::info_span!(
            "pipe.cost_calculation",
            otel.name = "Cost Calculation",
            llm.provider = %provider_str,
            llm.model = %model,
            input_tokens = llm_input_tokens,
            output_tokens = llm_output_tokens
        );

        let mut llm_cache = crate::pipes::types::llm::CacheTokens::of_response(&response_body);
        llm_cache.add(llm_retry_cache);
        let cost = async {
            self.calculate_main_llm_cost(
                main_pricing.as_ref(),
                main_price_honoured,
                &endpoint,
                provider_str,
                &model,
                llm_input_tokens,
                llm_output_tokens,
            )
            .await
                + self
                    .calculate_cache_cost(
                        main_pricing.as_ref(),
                        main_price_honoured,
                        &endpoint,
                        provider_str,
                        &model,
                        llm_cache,
                    )
                    .await
        }
        .instrument(cost_span)
        .await;
        info!("[PIPE:{}] Cost calculated: ${:.6}", self.config.id, cost);

        // Total latency: request preparation + target processing
        let latency_ms = start.elapsed().as_millis() as u64;

        // Per-stage usage feeds the activity-log/dashboard breakdown; the
        // top-level fields are grand totals across the LLM (all attempts),
        // Judge and Jury. `llm_usage` is the only stage that drives monthly
        // budget enforcement (see pipes/api.rs) — Judge and Jury record their
        // own budget buckets, so folding them into the grand totals must not
        // reach the budget tracker. In Mirror Merge, the fanned-out candidate
        // spend (`mirror_billed`, priced per candidate) folds into `llm_usage`
        // alongside the merger's own call; it is zero for non-mirror runs.
        let mut llm_usage = main_call_usage(
            llm_input_tokens,
            llm_output_tokens,
            cost,
            llm_latency_ms,
            main_key_source,
            jury_attempt + 1,
        );
        llm_usage.add(mirror_billed);
        let grand_input_tokens = llm_input_tokens
            + mirror_billed.input_tokens
            + judge_usage.input_tokens
            + jury_usage.input_tokens
            + decider_usage.input_tokens;
        let grand_output_tokens = llm_output_tokens
            + mirror_billed.output_tokens
            + judge_usage.output_tokens
            + jury_usage.output_tokens
            + decider_usage.output_tokens;
        let grand_total_tokens = grand_input_tokens + grand_output_tokens;
        let grand_cost = cost + mirror_billed.cost + judge_usage.cost + jury_usage.cost + decider_usage.cost;
        let grand_billed_cost =
            llm_usage.billed_cost + judge_usage.billed_cost + jury_usage.billed_cost + decider_usage.billed_cost;

        let metrics = ExecutionMetrics {
            input_tokens: grand_input_tokens,
            output_tokens: grand_output_tokens,
            total_tokens: grand_total_tokens,
            cost: grand_cost,
            llm_usage,
            judge_usage,
            jury_usage,
            decider_usage,
            latency_ms,
            provider: provider_str.to_string(),
            model: model.clone(),
            trace_id,
            correlation_id,
            agent_identity,
            request_bytes,
            response_bytes,
            time_to_first_token_ms: Some(request_latency_ms), // Gateway request preparation time
            retry_count,
            redrive_rejections,
            cached_tokens,
            cache_write_tokens,
            reasoning_tokens,
            schema_valid,
            conversation_id: used_conversation_id,
            stages: stage_records,
            cache_hit: false,
            cache_saved_cost: 0.0,
            billed_cost: grand_billed_cost,
            key_source: Some(main_key_source),
        };

        info!(
            "[PIPE:{}] Pipe executed: {} tokens (llm {}, judge {}, jury {}), ${:.6}, {}ms",
            self.config.id,
            grand_total_tokens,
            llm_total_tokens,
            judge_usage.total_tokens(),
            jury_usage.total_tokens(),
            grand_cost,
            latency_ms
        );
        // Stage-active flags let the activity log show a per-stage breakdown
        // row for every stage that actually ran — including a Moderation-mode
        // Judge, whose OpenAI Moderations call is free and so reports zero
        // tokens/cost (which a cost-only filter would otherwise hide).
        let judge_active = self
            .config
            .judge
            .as_ref()
            .is_some_and(|j| j.enabled);
        let jury_active = self
            .config
            .jury
            .as_ref()
            .is_some_and(|j| j.enabled);
        let decider_active = self
            .config
            .decider
            .as_ref()
            .is_some_and(|d| d.enabled);
        info!(
            "[PIPE:{}] [STAGE:summary] {{\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"llm_tokens\":{},\"llm_cost\":{:.6},\"judge_tokens\":{},\"judge_cost\":{:.6},\"judge_active\":{},\"jury_tokens\":{},\"jury_cost\":{:.6},\"jury_active\":{},\"decider_tokens\":{},\"decider_cost\":{:.6},\"decider_active\":{},\"latency_ms\":{},\"provider\":\"{}\",\"model\":\"{}\"}}",
            self.config.id,
            grand_total_tokens,
            grand_input_tokens,
            grand_output_tokens,
            grand_cost,
            llm_total_tokens,
            cost,
            judge_usage.total_tokens(),
            judge_usage.cost,
            judge_active,
            jury_usage.total_tokens(),
            jury_usage.cost,
            jury_active,
            decider_usage.total_tokens(),
            decider_usage.cost,
            decider_active,
            latency_ms,
            provider_str,
            model
        );

        Ok((response_body, metrics))
    }

    /// Apply parameter overrides based on policy configuration
    ///
    /// Refactored to use trait-based parameter extraction, reducing code duplication by 85%
    fn apply_parameter_overrides(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
        request: &mut Value,
        override_policy: &crate::pipes::types::llm::ParameterOverrideConfig,
        profile: &crate::pipes::request_shaping::ModelRequestProfile,
    ) {
        use crate::pipes::types::llm::OverridePolicy;
        use crate::pipes::types::llm_provider_ext::{LLMProviderExt, ParameterValue};

        // Apply standard parameters using trait-based extraction
        let params = [
            ("temperature", &override_policy.temperature),
            ("max_tokens", &override_policy.max_tokens),
            ("top_p", &override_policy.top_p),
            ("frequency_penalty", &override_policy.frequency_penalty),
            ("presence_penalty", &override_policy.presence_penalty),
        ];

        for (param_name, policy_opt) in params {
            if let Some(policy) = policy_opt
                && let Some(gateway_value) = provider.get_parameter(param_name)
            {
                let client_value = request.get(param_name);

                match policy {
                    OverridePolicy::GatewayWins => {
                        request[param_name] = gateway_value.as_json();
                    }
                    OverridePolicy::ClientWins => {
                        // Client is authoritative: never inject the gateway
                        // value, even when the client omitted the parameter.
                    }
                    OverridePolicy::InjectIfMissing => {
                        if client_value.is_none() {
                            request[param_name] = gateway_value.as_json();
                        }
                    }
                }
            }
        }

        // Special case: reasoning_effort (only for reasoning models)
        if let Some(policy) = &override_policy.reasoning_effort
            && profile.reasoning
        {
            let client_has_reasoning = request
                .get("reasoning_effort")
                .is_some();

            let effort = override_policy
                .reasoning_effort_value
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .unwrap_or("medium");

            match policy {
                OverridePolicy::GatewayWins => {
                    request["reasoning_effort"] = serde_json::json!(effort);
                }
                OverridePolicy::ClientWins => {
                    // Client authoritative: never inject reasoning_effort.
                }
                OverridePolicy::InjectIfMissing => {
                    if !client_has_reasoning {
                        request["reasoning_effort"] = serde_json::json!(effort);
                    }
                }
            }
        }

        // Special case: model override
        if let Some(policy) = &override_policy.model {
            let gateway_model = provider.get_model();
            let gateway_value = ParameterValue::String(gateway_model.to_string());
            let client_value = request.get("model");

            match policy {
                OverridePolicy::GatewayWins => {
                    request["model"] = gateway_value.as_json();
                }
                OverridePolicy::ClientWins => {
                    // Client authoritative: never inject the gateway model,
                    // even when the client omitted it.
                }
                OverridePolicy::InjectIfMissing => {
                    if client_value.is_none() {
                        request["model"] = gateway_value.as_json();
                    }
                }
            }
        } else if request.get("model").is_none() {
            // No override policy configured — always ensure model is present
            let gateway_model = provider.get_model();
            if !gateway_model.is_empty() {
                request["model"] = serde_json::json!(gateway_model);
            }
        }

        // Special case: api_key override
        // Note: API key is typically in headers, not request body
        // This policy controls whether client can override the gateway's configured API key
        // The actual header injection happens in build_headers_with_key()
        // This is used for scenarios where client might send api_key in request body
        if let Some(policy) = &override_policy.api_key {
            let client_has_api_key = request
                .get("api_key")
                .is_some();

            match policy {
                OverridePolicy::GatewayWins => {
                    // Remove any client-provided API key, gateway's key will be used
                    if client_has_api_key {
                        request
                            .as_object_mut()
                            .unwrap()
                            .remove("api_key");
                    }
                }
                OverridePolicy::ClientWins => {
                    // Client authoritative: the client's body key (if any) is
                    // left untouched and the gateway key is never injected.
                    // The header path resolves to the client key only.
                }
                OverridePolicy::InjectIfMissing => {
                    // Only use gateway's key if client doesn't provide one
                    // Gateway's key is handled by build_headers_with_key()
                }
            }
        }
    }

    /// Resolve the stored API key a provider's calls send, from the secrets
    /// store (cached), labelled with where it comes from.
    async fn resolve_gateway_api_key(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
    ) -> Result<Option<CallKey>, PipeError> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        match provider.get_api_key() {
            Some(secret_id) => {
                self.resolve_stored_key(secret_id, "API key")
                    .await
            }
            None => Ok(None),
        }
    }

    /// Resolve a stored key reference (`credential` names it in the log) to
    /// the key a call sends, labelled with where it comes from.
    async fn resolve_stored_key(
        &self,
        secret_id: &str,
        credential: &str,
    ) -> Result<Option<CallKey>, PipeError> {
        Ok(self
            .resolve_secret(secret_id, credential)
            .await?
            .map(|secret| CallKey {
                source: self
                    .secrets
                    .key_source(secret.tenant_id.as_deref()),
                value: secret.value,
            }))
    }

    /// Resolve the effective API key for a provider and build its request
    /// headers, then append `target_headers`: the extra headers that belong to
    /// the upstream this call goes to (see [`Self::surface_headers_for`] for
    /// the surface's own upstream; a Decider candidate or merger passes its
    /// own), refused unless `request_url` is on the origin they were configured
    /// for. Shared by every send path so key selection and the "secret
    /// configured but unresolved" failure behave identically.
    ///
    /// `main_call` is set only for the call to the surface's own upstream that
    /// serves the request (not a Decider candidate or merger); on a primary
    /// executor that is the one call the caller's key is offered to, through
    /// identity pass-through or the `api_key` override policy (see
    /// [`crate::pipes::key_source::resolve_call_key`]). Every other call sends
    /// its provider's stored key.
    ///
    /// The call is an upstream serving the request, so a spent budget refuses
    /// it here when its key is a platform key (see [`admit_call`]). A call
    /// that sends no credential at all is asked only when it is priced
    /// (`call`): who pays a keyless upstream is not knowable from the absence
    /// of a key, and an unpriced one bills nothing. While a budget is in
    /// scope, a platform-key call is also refused when Agent Stream would not
    /// meter what it spends (see [`Self::metered`]). Each call site then asks
    /// the shared-credential rule (see [`crate::pipes::shared_credential`])
    /// before sending, so where both would refuse, a spent budget answers
    /// first, then metering, then the shared-credential rule.
    async fn resolve_provider_headers(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
        target_headers: TargetHeaders<'_>,
        request_url: &str,
        main_call: bool,
        caller: &CallerCredentials,
        call: UpstreamCall<'_>,
    ) -> Result<ProviderHeaders, PipeError> {
        let mut headers = self
            .build_provider_headers(provider, target_headers, request_url, main_call, caller)
            .await?;
        if !headers.keyless
            || self
                .keyless_call_priced(provider, request_url, call)
                .await
        {
            admit_call(headers.key_source, BudgetedCall::Upstream, "upstream").await?;
            headers.budget_checked = true;
            if !headers.key_source.owned()
                && crate::teams::call_budget::current().is_some()
                && let Err(unmetered) = self
                    .metered(provider, request_url, call, headers.own_price_honoured)
                    .await
            {
                warn!(
                    key_source = headers.key_source.as_str(),
                    code = unmetered.code(),
                    "platform-key call refused: its spend is not metered"
                );
                return Err(PipeError::NotMetered {
                    unmetered,
                    call: BudgetedCall::Upstream,
                });
            }
        }
        Ok(headers)
    }

    /// Whether Agent Stream meters what an upstream call to `request_url`
    /// spends (see [`crate::pipes::metering`]): a model call whose body asks
    /// for no hosted tool, search option or audio or image output, below its
    /// model's long-context threshold unless the catalog prices that tier, and
    /// on a metered endpoint when the caller chose the path; a binary call
    /// only on `audio/speech` and for a model priced by input alone (its own
    /// price only where `own_price_honoured`, else the catalog's); never an
    /// upload or a poll.
    async fn metered(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
        request_url: &str,
        call: UpstreamCall<'_>,
        own_price_honoured: bool,
    ) -> Result<(), crate::pipes::metering::Unmetered> {
        use crate::pipes::metering::{self, Unmetered};
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        match call {
            UpstreamCall::Model { model, body, caller_path, .. } => {
                if caller_path {
                    metering::json_call(request_url, body)?;
                }
                metering::request_body(body, model)?;
                // An image-output model may answer with an image unasked, and
                // its image tokens cost well above its text rate: run it only
                // where the catalog prices its image output.
                if metering::is_image_output_model(model)
                    && crate::pipes::types::llm::catalog_image_output_price(
                        provider.provider_type_str(),
                        model,
                        Some(request_url),
                    )
                    .is_none()
                {
                    return Err(Unmetered::Modality);
                }
                // Above a long-context threshold the price rises; run there
                // only when the catalog prices that tier.
                if let Some(threshold) = metering::long_context_threshold(model)
                    && crate::pipes::streaming::estimate_request_tokens(body) > threshold
                    && crate::pipes::types::llm::catalog_long_context_price(
                        provider.provider_type_str(),
                        model,
                        Some(request_url),
                    )
                    .is_none()
                {
                    return Err(Unmetered::LongContext);
                }
                Ok(())
            }
            UpstreamCall::Binary { declared, model } => {
                metering::binary_call(request_url)?;
                // As for a model call (see
                // `crate::pipes::types::llm::ensure_priced_spend`), a price
                // the surface's tenant set never prices a call on a credential
                // it does not own: only the catalog does. The binary path
                // bills input characters only, so a model priced by its output
                // (audio tokens, as `gpt-4o-mini-tts` is) is not metered.
                let (input_rate, output_rate) = if own_price_honoured {
                    let rate = |input, output| {
                        self.calculate_main_llm_cost(
                            declared.as_ref(),
                            true,
                            request_url,
                            provider.provider_type_str(),
                            model,
                            input,
                            output,
                        )
                    };
                    (rate(1_000_000, 0).await, rate(0, 1_000_000).await)
                } else {
                    crate::pipes::types::llm::catalog_price(provider.provider_type_str(), model, Some(request_url))
                        .map_or((0.0, 0.0), |pricing| {
                            (pricing.input_price_per_million, pricing.output_price_per_million)
                        })
                };
                let priced = input_rate > 0.0 && output_rate == 0.0;
                if priced {
                    Ok(())
                } else {
                    Err(Unmetered::UnpricedModel)
                }
            }
            UpstreamCall::Upload | UpstreamCall::Poll => Err(Unmetered::Endpoint),
        }
    }

    /// Whether a call that sends no credential bills anything: its upstream's
    /// declared price, else the surface's override, else the catalog price of
    /// the model it runs, as such a call is billed (see
    /// [`Self::calculate_main_llm_cost`]; a keyless call's own price is always
    /// honoured). An upload or a poll bills nothing.
    async fn keyless_call_priced(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
        request_url: &str,
        call: UpstreamCall<'_>,
    ) -> bool {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        let (UpstreamCall::Model { declared, model, .. } | UpstreamCall::Binary { declared, model, .. }) = call else {
            return false;
        };
        self.calculate_main_llm_cost(
            declared.as_ref(),
            true,
            request_url,
            provider.provider_type_str(),
            model,
            1_000_000,
            1_000_000,
        )
        .await
            > 0.0
    }

    /// The headers [`Self::resolve_provider_headers`] sends, before the budget
    /// check.
    async fn build_provider_headers(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
        target_headers: TargetHeaders<'_>,
        request_url: &str,
        main_call: bool,
        caller: &CallerCredentials,
    ) -> Result<ProviderHeaders, PipeError> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        crate::pipes::upstream_headers::ensure_same_origin(
            &self.config.id,
            target_headers.headers,
            &target_headers.configured_for,
            request_url,
        )?;
        let caller_key_offered = main_call && self.primary;

        // Identity pass-through: when enabled, forward the caller's validated
        // inbound bearer token as the outbound `Authorization: Bearer`
        // credential, skipping the stored API-key secret. Authoritative over
        // the parameter override policy below. When the caller supplied a
        // distinct upstream token (`X-Agent-Stream-Upstream-Authorization`), it
        // is forwarded in preference to the front-door token. The token is
        // authorized against the operator's upstream (Azure OpenAI with Entra
        // ID, another gateway trusting the same issuer), which bills the
        // operator, so the call is a platform call; only a provider that bills
        // the signed-in user's own licence (Microsoft 365 Copilot) makes it the
        // caller's. Its refusal is final either way.
        if caller_key_offered
            && self
                .config
                .forward_caller_token
        {
            return match build_caller_token_headers(provider, caller) {
                Some(headers) => {
                    let source = if provider.requires_forward_caller_token() {
                        KeySource::Client
                    } else {
                        KeySource::Platform
                    };
                    self.with_target_headers(headers, Some(source), true, &target_headers)
                        .await
                }
                None => Err(PipeError::RequestFailed(format!(
                    "[PIPE:{}] forward_caller_token is enabled but the request carried no bearer token to forward.",
                    self.config.id
                ))),
            };
        }

        let offer = if caller_key_offered {
            CallerKey::Offered {
                key: caller.provider_key.as_deref(),
                policy: self
                    .config
                    .override_policy
                    .as_ref()
                    .and_then(|policy| policy.api_key.as_ref()),
            }
        } else {
            CallerKey::NotOffered
        };
        let api_key =
            crate::pipes::key_source::resolve_call_key(offer, || self.resolve_gateway_api_key(provider)).await?;

        debug!(
            "[PIPE:{}] API key resolved: {}",
            self.config.id,
            api_key
                .as_ref()
                .map(|key| key.source.as_str())
                .unwrap_or("none")
        );

        if let Some(key) = api_key {
            let headers = provider.build_headers_with_key(&key.value);
            let sent_caller_credential = key.source == KeySource::Client;
            self.with_target_headers(headers, Some(key.source), sent_caller_credential, &target_headers)
                .await
        } else if let Some(reference) = provider
            .get_api_key()
            .filter(|reference| !reference.is_empty())
        {
            // A secret reference is configured but could not be resolved.
            // Fail loudly rather than fall back to build_headers(), which
            // would send the raw secret reference as the bearer token.
            Err(crate::pipes::upstream_headers::credential_unavailable(
                &self.config.id,
                "API key",
                reference,
                "no secret answers to the reference",
            ))
        } else {
            self.with_target_headers(provider.build_headers(), None, false, &target_headers)
                .await
        }
    }

    /// Finish a call's request headers: append its target headers and record
    /// whether the call may be billed at the upstream's own price, the source
    /// of its credentials and whether it sends any. `key` is the source of the
    /// key already in `headers` (`None` when the call sends no key), and
    /// `sent_caller_credential` whether that key is the caller's own.
    async fn with_target_headers(
        &self,
        mut headers: Vec<(String, String)>,
        key: Option<KeySource>,
        sent_caller_credential: bool,
        target_headers: &TargetHeaders<'_>,
    ) -> Result<ProviderHeaders, PipeError> {
        let (headers_owned, headers_source) = self
            .append_target_headers(target_headers.headers, &mut headers)
            .await?;
        let key_owned = key.is_none_or(|source| {
            self.secrets
                .honours_own_price(source)
        });
        Ok(ProviderHeaders {
            headers,
            own_price_honoured: key_owned && headers_owned,
            key_source: crate::pipes::key_source::call_key_source(key, headers_source),
            sent_caller_credential,
            keyless: key.is_none() && headers_source.is_none(),
            budget_checked: false,
        })
    }

    /// The surface's own `upstream_headers` when `provider` is the surface's
    /// own configured upstream, and none for any other provider, bound to the
    /// endpoint `provider` calls.
    ///
    /// The headers are the base upstream's credentials. A failover,
    /// load-balancing or routing target runs on a copy of this config whose
    /// base *is* that target (`clone_with_failover_target` puts the target's
    /// own headers there), and a Decider candidate or merger passes its own
    /// headers explicitly, so this identity check is what keeps the base's
    /// headers off any other provider's wire.
    fn surface_headers_for(
        &self,
        provider: &crate::pipes::types::llm::LLMProvider,
    ) -> TargetHeaders<'_> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        let is_base_provider = matches!(
            &self.config.pipe_type,
            super::PipeType::LLM { provider: base, .. } if base.as_ref() == provider
        );
        let headers: &[crate::pipes::upstream_headers::UpstreamHeader] = if is_base_provider {
            &self.config.upstream_headers
        } else {
            if !self
                .config
                .upstream_headers
                .is_empty()
            {
                debug!(
                    "[PIPE:{}] upstream headers skipped: request routed to a provider other than the surface's own upstream",
                    self.config.id
                );
            }
            &[]
        };
        TargetHeaders {
            headers,
            configured_for: provider.get_endpoint(),
        }
    }

    /// Append the extra headers of the upstream a call goes to, each value
    /// resolved from the secrets store, to its request headers. Returns whether
    /// every one of their secrets is the surface's own (see
    /// [`crate::secrets::SurfaceSecrets::owns`]) and their combined key source
    /// (`None` when there are none; see [`KeySource::combine`]).
    ///
    /// An unresolvable secret fails the request: dropping a header the upstream
    /// requires would turn a configuration error into an opaque 401, and
    /// silently sending less than the operator configured is never safe.
    async fn append_target_headers(
        &self,
        target_headers: &[crate::pipes::upstream_headers::UpstreamHeader],
        headers: &mut Vec<(String, String)>,
    ) -> Result<(bool, Option<KeySource>), PipeError> {
        if target_headers.is_empty() {
            return Ok((true, None));
        }

        let mut owned = true;
        let mut source: Option<KeySource> = None;
        for header in target_headers {
            let credential = format!("header {:?}", header.name);
            let secret = self
                .resolve_secret(&header.secret_id, &credential)
                .await?
                .ok_or_else(|| {
                    crate::pipes::upstream_headers::credential_unavailable(
                        &self.config.id,
                        &credential,
                        &header.secret_id,
                        "no secret answers to the reference",
                    )
                })?;
            owned &= self
                .secrets
                .owns(secret.tenant_id.as_deref());
            let header_source = self
                .secrets
                .key_source(secret.tenant_id.as_deref());
            source = Some(source.map_or(header_source, |s| s.combine(header_source)));
            headers.push((header.name.clone(), secret.value));
        }

        debug!(
            "[PIPE:{}] upstream headers applied: {}",
            self.config.id,
            target_headers
                .iter()
                .map(|h| h.name.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        );
        Ok((owned, source))
    }

    /// Create a Microsoft 365 Copilot conversation and return its id.
    ///
    /// The Copilot Chat API is stateful: a conversation must exist before a
    /// chat turn can be sent. `base_url` is the Microsoft Graph base; the
    /// resolved provider headers already carry the caller's forwarded bearer
    /// token (`sent_caller_credential` says whether they do). Fails loudly on
    /// any non-2xx or a response missing `id`.
    async fn create_copilot_conversation(
        &self,
        base_url: &str,
        headers: &[(String, String)],
        sent_caller_credential: bool,
    ) -> Result<String, PipeError> {
        let url = format!("{}/beta/copilot/conversations", base_url.trim_end_matches('/'));
        crate::url_validation::validate_service_endpoint_url(&url)
            .await
            .map_err(PipeError::RequestFailed)?;

        let mut request = self
            .client
            .post(&url)
            .header("Content-Type", "application/json")
            .body("{}");
        for (name, value) in headers {
            request = request.header(name.as_str(), value.as_str());
        }

        let response = request
            .send()
            .await
            .map_err(|e| PipeError::RequestFailed(e.to_string()))?;
        if !response.status().is_success() {
            let status = response.status();
            let error_body: String = response
                .text()
                .await
                .unwrap_or_default()
                .chars()
                .take(500)
                .collect();
            return Err(PipeError::upstream_failure(
                status,
                sent_caller_credential,
                "Microsoft 365 Copilot create-conversation failed: ",
                &error_body,
            ));
        }

        let body: Value = response
            .json()
            .await
            .map_err(|e| PipeError::InvalidResponse(e.to_string()))?;
        body.get("id")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                PipeError::InvalidResponse(
                    "Microsoft 365 Copilot create-conversation response missing 'id'".to_string(),
                )
            })
    }

    /// Resolve a secret reference to its value, caching the result per secret id.
    async fn resolve_secret_by_id(
        &self,
        secret_id: &str,
    ) -> Result<Option<String>, PipeError> {
        Ok(self
            .resolve_secret(secret_id, "secret")
            .await?
            .map(|secret| secret.value))
    }

    /// Resolve a secret reference (`credential` names it in the log), caching
    /// the result per secret id.
    ///
    /// Resolution goes through [`crate::secrets::SurfaceSecrets::resolve`]: the
    /// function the save-time tenancy check uses, then a re-check against the
    /// surface's tenant, so a request only ever sends a secret that was checked
    /// and that the surface may still use. A failure is logged with the
    /// reference and reported to the caller without it.
    async fn resolve_secret(
        &self,
        secret_id: &str,
        credential: &str,
    ) -> Result<Option<ResolvedSecret>, PipeError> {
        // Check cache first (keyed by secret id so each provider/candidate/
        // guardrail resolves its own key).
        {
            let cached = self
                .cached_api_keys
                .read()
                .await;
            if let Some(secret) = cached.get(secret_id) {
                return Ok(Some(secret.clone()));
            }
        } // Release read lock

        let resolved = self
            .secrets
            .resolve(secret_id)
            .await
            .map_err(|e| {
                crate::pipes::upstream_headers::credential_unavailable(
                    &self.config.id,
                    credential,
                    secret_id,
                    &e.to_string(),
                )
            })?
            .map(|secret| ResolvedSecret {
                value: secret.value,
                tenant_id: secret.tenant_id,
            });

        // Cache the result under its secret id
        if let Some(secret) = &resolved {
            self.cached_api_keys
                .write()
                .await
                .insert(secret_id.to_string(), secret.clone());
        }
        Ok(resolved)
    }

    /// Run every enabled model-PII detector for a request-side prompt guard.
    ///
    /// Detectors are called **concurrently** (independent HTTP round-trips), then
    /// their results are applied **sequentially** through the shared `allocator`
    /// so NER IDs stay consistent across detectors. A `reject`-action detector
    /// that finds PII — or a `fail_closed` detector that is unavailable — returns
    /// `Err(guard_rejected)`. Returns `None` when no detector is enabled.
    async fn run_model_pii_detectors(
        &self,
        body: &mut Value,
        detectors: &[crate::pipes::prompt_guard::LlmPiiConfig],
        allocator: &mut crate::pipes::prompt_guard::PseudonymAllocator,
    ) -> Result<Option<ModelPiiOutcome>, PipeError> {
        use crate::pipes::prompt_guard::{self, GuardAction, GuardRejection};
        let active: Vec<&prompt_guard::LlmPiiConfig> = detectors
            .iter()
            .filter(|d| d.enabled)
            .collect();
        if active.is_empty() {
            return Ok(None);
        }
        let timer = Instant::now();

        // Resolve each detector's API key first (sequential, cached), then detect
        // concurrently — all detectors read `body` immutably in parallel.
        let mut keys: Vec<Option<CallKey>> = Vec::with_capacity(active.len());
        let mut key_sources = KeySourceCounts::default();
        for d in &active {
            let key = crate::pipes::key_source::resolve_call_key(CallerKey::NotOffered, || async {
                match &d.api_key_secret {
                    Some(secret_id) => {
                        self.resolve_stored_key(secret_id, "API key")
                            .await
                    }
                    None => Ok(None),
                }
            })
            .await?;
            let source = crate::pipes::key_source::call_key_source(key.as_ref().map(|k| k.source), None);
            // A detector refused for budget refuses the request, even when its
            // own policy fails open on a detection error: the masking it
            // would have applied must not be skipped silently. A keyless
            // detector tracks no cost and spends no operator credential, so it
            // is never refused.
            if key.is_some() {
                admit_call(source, BudgetedCall::Stage, "LLM PII detector").await?;
            }
            key_sources.record(source);
            keys.push(key);
        }
        let pii_span = tracing::info_span!(
            "pipe.prompt_guard.model_pii",
            otel.name = "Prompt Guard (Model PII)",
            pipe = %self.config.name
        );
        let results = {
            let body_ref: &Value = body;
            let mut detect_futs = Vec::with_capacity(active.len());
            for (d, key) in active.iter().zip(keys.iter()) {
                detect_futs.push(prompt_guard::llm_pii::detect(
                    &self.client,
                    d,
                    key.as_ref()
                        .map(|k| k.value.as_str()),
                    body_ref,
                ));
            }
            futures::future::join_all(detect_futs)
                .instrument(pii_span)
                .await
        };

        let mut masked = 0usize;
        let mut failed = 0usize;
        for (d, result) in active.iter().zip(results) {
            match result {
                Ok(entities) => {
                    prompt_guard::detector_stats::global().record_success();
                    let count = entities.len();
                    if count > 0 && d.action == GuardAction::Reject {
                        let mut rejection = d
                            .rejection
                            .as_ref()
                            .map(GuardRejection::from)
                            .unwrap_or_default();
                        if rejection.reason.is_none() {
                            rejection.reason = Some(format!(
                                "{count} PII value{} detected in request",
                                if count == 1 {
                                    ""
                                } else {
                                    "s"
                                }
                            ));
                        }
                        warn!("[PIPE:{}] Request blocked by model PII detection ({} entities)", self.config.id, count);
                        return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexRequest, "model_pii"));
                    }
                    prompt_guard::mask_detected_entities(body, &entities, d.mask_mode, d.link_coreferences, allocator);
                    masked += count;
                }
                Err(e) => {
                    warn!("[PIPE:{}] Model PII detection failed: {}", self.config.id, e);
                    prompt_guard::detector_stats::global().record_error();
                    failed += 1;
                    if d.fail_closed {
                        let rejection = GuardRejection {
                            reason: Some("Model PII detection unavailable".to_string()),
                            ..Default::default()
                        };
                        return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexRequest, "model_pii"));
                    }
                }
            }
        }
        info!(
            "[PIPE:{}] [STAGE:prompt_guard_model_pii] {{\"outcome\":\"{}\",\"detectors\":{},\"entities\":{},\"failed\":{},\"duration_ms\":{}}}",
            self.config.id,
            if failed > 0 {
                "partial"
            } else {
                "masked"
            },
            active.len(),
            masked,
            failed,
            timer.elapsed().as_millis()
        );
        Ok(Some(ModelPiiOutcome {
            detectors: active.len(),
            masked,
            failed,
            key_sources,
        }))
    }

    /// Ask the budget, before the request makes any model call, about every
    /// safety or decision stage the surface runs on a platform key (the Judge,
    /// jurors, the Decider router, LLM PII detectors and expert witnesses) and
    /// about the Mirror merger, so a spent budget refuses the request before
    /// anything is spent, never at a response-side stage (the Jury, a response
    /// witness) or at the merger after the main call or the Mirror candidates
    /// already ran on the customer's own key. Only where a budget is enforced.
    /// A stage the budget would not be asked about (see
    /// [`crate::pipes::judge_jury::target_budget_source`], which counts a
    /// target's header secrets as its key does; a detector or witness with no
    /// stored key, whose own call never asks either: detectors take no headers
    /// and a witness's headers are literal configuration, not secrets) is
    /// skipped, and so is one whose key cannot be resolved, which fails at its
    /// own call under its own error policy.
    async fn admit_platform_stages(&self) -> Result<(), PipeError> {
        if crate::teams::call_budget::current().is_none() {
            return Ok(());
        }
        let config = &self.config;
        let mut targets: Vec<(&crate::pipes::judge_jury::LLMTarget, &str)> = Vec::new();
        if let Some(judge) = config
            .judge
            .as_ref()
            .filter(|j| j.enabled)
        {
            targets.push((&judge.llm, "judge"));
        }
        if let Some(jury) = config
            .jury
            .as_ref()
            .filter(|j| j.enabled)
        {
            targets.extend(
                jury.jurors
                    .iter()
                    .filter(|j| j.enabled)
                    .map(|j| (&j.llm, "juror")),
            );
        }
        if let Some(router) = config
            .decider
            .as_ref()
            .filter(|d| {
                d.enabled && !d.candidates.is_empty() && d.strategy == crate::pipes::judge_jury::DeciderStrategy::Route
            })
            .and_then(|d| d.llm.as_ref())
        {
            targets.push((router, "decider router"));
        }
        let mut sources: Vec<(KeySource, &str)> = Vec::new();
        for (target, what) in targets {
            if let Some(source) =
                crate::pipes::judge_jury::target_budget_source(&config.id, target, &self.secrets).await
            {
                sources.push((source, what));
            }
        }
        let detector_secrets = config
            .prompt_guard
            .as_ref()
            .filter(|g| g.enabled)
            .into_iter()
            .flat_map(|g| g.llm_pii.iter())
            .filter(|d| d.enabled)
            .filter_map(|d| d.api_key_secret.as_deref())
            .map(|secret| (secret, "LLM PII detector"));
        let witness_secrets = config
            .expert_witnesses
            .iter()
            .filter(|w| w.guardrail.enabled)
            .filter_map(|w| {
                w.guardrail
                    .api_key_secret
                    .as_deref()
            })
            .map(|secret| (secret, "expert witness"));
        for (secret, what) in detector_secrets.chain(witness_secrets) {
            if let Ok(Some(key)) = self
                .resolve_stored_key(secret, "API key")
                .await
            {
                sources.push((key.source, what));
            }
        }
        for (source, what) in sources {
            admit_call(source, BudgetedCall::Stage, what).await?;
        }
        // The Mirror merger is an upstream that serves the request, so a
        // refusal leaves the request to a failover target as at its own call;
        // asked here, it comes before the candidates spend.
        let merger = config
            .decider
            .as_ref()
            .filter(|d| {
                d.enabled
                    && !d.candidates.is_empty()
                    && d.strategy == crate::pipes::judge_jury::DeciderStrategy::Mirror
                    && d.mirror.mode == crate::pipes::judge_jury::MirrorMode::Merge
            })
            .and_then(|d| d.mirror.merger.as_ref());
        if let Some(merger) = merger
            && let Some(source) =
                crate::pipes::judge_jury::target_budget_source(&config.id, merger, &self.secrets).await
        {
            admit_call(source, BudgetedCall::Upstream, "Mirror merger").await?;
        }
        Ok(())
    }

    /// Resolve the API key for an external guardrail provider, if one is
    /// configured, and the source of the credentials its call sends.
    async fn resolve_external_guard_key(
        &self,
        external: &crate::pipes::prompt_guard::ExternalGuardrailConfig,
    ) -> Result<(Option<String>, KeySource), PipeError> {
        let key = crate::pipes::key_source::resolve_call_key(CallerKey::NotOffered, || async {
            match &external.api_key_secret {
                Some(secret_id) => {
                    self.resolve_stored_key(secret_id, "API key")
                        .await
                }
                None => Ok(None),
            }
        })
        .await?;
        let source = crate::pipes::key_source::call_key_source(key.as_ref().map(|k| k.source), None);
        // A witness refused for budget refuses the request, even though a
        // witness whose provider errors lets it through: the check must run.
        // A keyless witness tracks no cost and spends no operator credential,
        // so it is never refused.
        if key.is_some() {
            admit_call(source, BudgetedCall::Stage, "expert witness").await?;
        }
        Ok((key.map(|k| k.value), source))
    }

    /// Price a main-stage call. A price declared on the upstream that served
    /// it (`declared`) wins, zero included; then the surface's `cost_tracking`
    /// override (ignored when zero); then the catalog by provider and `model`,
    /// the model the upstream ran (see [`model_run`]).
    /// When the call spent a credential the surface's tenant does not own
    /// (`own_price_honoured` false), neither own price may lower the bill
    /// below the catalog (see [`crate::pipes::types::llm::priced_cost`]).
    #[allow(clippy::too_many_arguments)]
    async fn calculate_main_llm_cost(
        &self,
        declared: Option<&crate::pipes::types::llm::TargetPricing>,
        own_price_honoured: bool,
        endpoint: &str,
        provider: &str,
        model: &str,
        input_tokens: u64,
        output_tokens: u64,
    ) -> f64 {
        let own: Vec<crate::pipes::types::llm::TokenPricing> = declared
            .map(|pricing| pricing.token_pricing())
            .into_iter()
            .chain(
                self.config
                    .cost_tracking
                    .as_ref()
                    .and_then(|config| {
                        explicit_override_pricing(config.input_price_per_1k, config.output_price_per_1k)
                    }),
            )
            .collect();
        // Above a long-context threshold the catalog's tier price applies,
        // when it declares one.
        let catalog =
            || crate::pipes::types::llm::catalog_price_for_input(provider, model, Some(endpoint), input_tokens);
        crate::pipes::types::llm::priced_cost(&own, own_price_honoured, catalog, input_tokens, output_tokens)
    }

    /// Price a main-stage call's prompt-cache tokens (Anthropic's cache writes
    /// and reads, which its input count leaves out): at the catalog's cache
    /// prices, unless the call bills at its own price, else at Anthropic's
    /// published ratios to the input price the call bills at (see
    /// [`Self::calculate_main_llm_cost`] and
    /// [`crate::pipes::types::llm::cache_cost`]).
    #[allow(clippy::too_many_arguments)]
    async fn calculate_cache_cost(
        &self,
        declared: Option<&crate::pipes::types::llm::TargetPricing>,
        own_price_honoured: bool,
        endpoint: &str,
        provider: &str,
        model: &str,
        cache: crate::pipes::types::llm::CacheTokens,
    ) -> f64 {
        if cache.is_empty() {
            return 0.0;
        }
        let input_per_million = self
            .calculate_main_llm_cost(declared, own_price_honoured, endpoint, provider, model, 1_000_000, 0)
            .await;
        let own_price = declared.is_some()
            || self
                .config
                .cost_tracking
                .as_ref()
                .and_then(|config| explicit_override_pricing(config.input_price_per_1k, config.output_price_per_1k))
                .is_some();
        let catalog = if own_price_honoured && own_price {
            crate::pipes::types::llm::CachePrices::default()
        } else {
            crate::pipes::types::llm::catalog_cache_prices(provider, model, Some(endpoint))
        };
        crate::pipes::types::llm::cache_cost(cache, input_per_million, catalog)
    }

    /// The main stage's spend so far, kept for a later failure of the same
    /// attempt: the tokens of earlier Jury-rejected calls (`retry_tokens`)
    /// and of `response`, over `calls` calls, priced as the stage bills them
    /// (see [`Self::calculate_main_llm_cost`]), with the Mirror candidates'
    /// spend.
    #[allow(clippy::too_many_arguments)]
    async fn main_stage_spend(
        &self,
        response: &Value,
        retry_tokens: (u64, u64),
        retry_cache: crate::pipes::types::llm::CacheTokens,
        calls: u32,
        pricing: Option<&crate::pipes::types::llm::TargetPricing>,
        own_price_honoured: bool,
        endpoint: &str,
        provider: &str,
        model: &str,
        source: KeySource,
        mirror: StageUsage,
    ) -> StageUsage {
        let (input, output, _) = llm_parser::parse_auto(response).unwrap_or((0, 0, 0));
        let (input, output) = (input + retry_tokens.0, output + retry_tokens.1);
        let mut cache = crate::pipes::types::llm::CacheTokens::of_response(response);
        cache.add(retry_cache);
        let cost = self
            .calculate_main_llm_cost(pricing, own_price_honoured, endpoint, provider, model, input, output)
            .await
            + self
                .calculate_cache_cost(pricing, own_price_honoured, endpoint, provider, model, cache)
                .await;
        let mut usage = main_call_usage(input, output, cost, 0, source, calls);
        usage.add(mirror);
        usage
    }

    /// Call one Mirror candidate upstream with the (already guarded) request and
    /// return its normalized OpenAI-format answer plus per-candidate usage. This
    /// mirrors the main-path preparation (parameter overrides, model forcing,
    /// wire-format transform, header resolution, Copilot conversation setup) but
    /// runs no Jury/guards — those apply once to the aggregated result. Failures
    /// are captured on [`CandidateOutcome::error`] (best-effort fan-out) rather
    /// than aborting the whole request, so one bad upstream never sinks the rest.
    async fn run_candidate_upstream(
        &self,
        candidate: &crate::pipes::judge_jury::DeciderCandidate,
        working_request: &Value,
        caller: &CallerCredentials,
    ) -> CandidateOutcome {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        let started = Instant::now();
        let provider = crate::pipes::judge_jury::target_to_provider(&candidate.llm);
        let provider_str = provider
            .provider_type_str()
            .to_string();
        let api_schema = provider
            .api_schema()
            .to_string();
        let model = provider
            .get_model()
            .to_string();

        let result: Result<CandidateCall, PipeError> = async {
            let profile = resolve_request_profile(&provider);
            let mut modified = working_request.clone();
            if let Some(override_policy) = &self.config.override_policy {
                self.apply_parameter_overrides(&provider, &mut modified, override_policy, &profile);
            }
            if !model.is_empty() {
                modified["model"] = serde_json::json!(model);
            }
            strip_caller_body_key(&mut modified);
            profile.apply_param_rules(&mut modified);
            let model_ran = model_run(&provider, &modified).to_string();

            // Resolve the candidate's absolute endpoint (relative provider paths
            // like `/messages` expanded), exactly as the Decider does per candidate.
            let raw_endpoint = candidate
                .llm
                .endpoint_url
                .replace("{model}", &model);
            let mut endpoint =
                crate::pipes::defaults::resolve_endpoint_url(&candidate.llm.provider_type, &raw_endpoint);

            let mut request_body = match api_schema.as_str() {
                "anthropic" => {
                    if let Some(reason) = crate::pipes::request_shaping::claude_unreadable_file(&modified) {
                        return Err(PipeError::UnsupportedContent(reason));
                    }
                    crate::pipes::request_shaping::transform_to_anthropic_format(modified)
                }
                "bedrock-anthropic" => {
                    if let Some(reason) = crate::pipes::request_shaping::claude_unreadable_file(&modified) {
                        return Err(PipeError::UnsupportedContent(reason));
                    }
                    let body = crate::pipes::request_shaping::transform_to_bedrock_anthropic_format(modified);
                    if let Some(reason) = crate::pipes::request_shaping::bedrock_unsupported_source(&body) {
                        return Err(PipeError::UnsupportedContent(reason));
                    }
                    body
                }
                "gemini" => crate::pipes::request_shaping::transform_to_gemini_format(modified),
                "copilot" => crate::pipes::request_shaping::transform_to_copilot_format_with(modified, true),
                _ => {
                    let mut body = modified;
                    crate::pipes::request_shaping::move_tool_media_to_user_message(&mut body);
                    body
                }
            };

            // A candidate sends its own headers, never the base upstream's,
            // even when it names the same provider as the base.
            let ProviderHeaders {
                headers: provider_headers,
                own_price_honoured,
                key_source,
                sent_caller_credential,
                ..
            } = self
                .resolve_provider_headers(
                    &provider,
                    TargetHeaders::of_target(&candidate.llm),
                    &endpoint,
                    false,
                    caller,
                    UpstreamCall::Model {
                        declared: candidate.llm.pricing,
                        model: &model_ran,
                        body: &request_body,
                        caller_path: false,
                    },
                )
                .await?;
            crate::pipes::shared_credential::admit_call(own_price_honoured, None, &request_body)
                .map_err(PipeError::SharedCredentialRefused)?;
            crate::pipes::types::llm::ensure_priced_spend(
                &self.config.id,
                own_price_honoured,
                &provider_str,
                &model_ran,
                crate::pipes::types::llm::catalog_price(&provider_str, &model_ran, Some(&endpoint)).as_ref(),
            )?;
            strip_cost_raising_parameters(&mut request_body, key_source);

            if api_schema == "copilot" {
                let convo = self
                    .create_copilot_conversation(&endpoint, &provider_headers, sent_caller_credential)
                    .await?;
                endpoint = format!("{}/beta/copilot/conversations/{}/chat", endpoint.trim_end_matches('/'), convo);
            }

            let request_json = serde_json::to_vec(&request_body)
                .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize candidate request: {}", e)))?;
            let request_bytes = request_json.len() as u64;

            crate::url_validation::validate_service_endpoint_url(&endpoint)
                .await
                .map_err(PipeError::RequestFailed)?;

            let mut req = self
                .client
                .post(&endpoint)
                .header("Content-Type", "application/json")
                .body(request_json);
            for (name, value) in &provider_headers {
                req = req.header(name.as_str(), value.as_str());
            }

            let response = req
                .send()
                .await
                .map_err(|e| {
                    if e.is_timeout() {
                        PipeError::RequestTimeout(format!("candidate '{}' exceeded the request deadline", candidate.id))
                    } else {
                        PipeError::RequestFailed(e.to_string())
                    }
                })?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response
                    .text()
                    .await
                    .unwrap_or_default();
                return Err(PipeError::upstream_failure(status, sent_caller_credential, "", &body));
            }
            let text = response
                .text()
                .await
                .map_err(|e| PipeError::InvalidResponse(e.to_string()))?;
            let response_bytes = text.len() as u64;
            let body: Value = serde_json::from_str(&text).map_err(|e| PipeError::InvalidResponse(e.to_string()))?;
            let body = match api_schema.as_str() {
                "anthropic" | "bedrock-anthropic" => transform_from_anthropic_format(body),
                "gemini" => transform_from_gemini_format(body),
                "copilot" => transform_from_copilot_format(body),
                _ => body,
            };

            let (input_tokens, output_tokens, _) = llm_parser::parse_auto(&body).unwrap_or((0, 0, 0));
            let cost = self
                .calculate_main_llm_cost(
                    candidate.llm.pricing.as_ref(),
                    own_price_honoured,
                    &endpoint,
                    &provider_str,
                    &model_ran,
                    input_tokens,
                    output_tokens,
                )
                .await
                + self
                    .calculate_cache_cost(
                        candidate.llm.pricing.as_ref(),
                        own_price_honoured,
                        &endpoint,
                        &provider_str,
                        &model_ran,
                        crate::pipes::types::llm::CacheTokens::of_response(&body),
                    )
                    .await;
            let content = body
                .pointer("/choices/0/message/content")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            Ok(CandidateCall {
                model: model_ran,
                content,
                input_tokens,
                output_tokens,
                cost,
                key_source,
                request_bytes,
                response_bytes,
            })
        }
        .await;

        let latency_ms = started.elapsed().as_millis() as u64;
        match result {
            Ok(call) => CandidateOutcome {
                id: candidate.id.clone(),
                name: candidate.name.clone(),
                provider: provider_str,
                model: call.model,
                content: call.content,
                input_tokens: call.input_tokens,
                output_tokens: call.output_tokens,
                cost: call.cost,
                key_source: Some(call.key_source),
                latency_ms,
                request_bytes: call.request_bytes,
                response_bytes: call.response_bytes,
                error: None,
                refusal: None,
            },
            Err(e) => {
                warn!("[PIPE:{}] Mirror candidate '{}' failed: {}", self.config.id, candidate.id, e);
                let refusal = e.platform_refusal();
                CandidateOutcome {
                    id: candidate.id.clone(),
                    name: candidate.name.clone(),
                    provider: provider_str,
                    model,
                    content: String::new(),
                    input_tokens: 0,
                    output_tokens: 0,
                    cost: 0.0,
                    key_source: None,
                    latency_ms,
                    request_bytes: 0,
                    response_bytes: 0,
                    error: Some(e.to_string()),
                    refusal,
                }
            }
        }
    }

    /// Consult every enabled expert witness whose `check_request` is set,
    /// against the already regex-masked request body. The first flagged verdict
    /// short-circuits the call with `PromptGuardRejected`; an allowed verdict
    /// (or a fail-open provider error) lets the call proceed. Per-witness
    /// tracing spans and `[STAGE:expert_witness_request]` logging are preserved.
    async fn run_request_witnesses(
        &self,
        request_body: &Value,
    ) -> Result<Vec<StageRecord>, PipeError> {
        let mut records = Vec::new();
        for witness in &self.config.expert_witnesses {
            let guardrail = &witness.guardrail;
            if !guardrail.enabled || !guardrail.check_request {
                continue;
            }
            let ext_timer = Instant::now();
            let (api_key, key_source) = self
                .resolve_external_guard_key(guardrail)
                .await?;
            let guard_span = tracing::info_span!(
                "pipe.expert_witness.request",
                otel.name = "Expert Witness (Request)",
                pipe = %self.config.name,
                witness = %witness.id
            );
            let (outcome, witness_input, witness_output) = crate::pipes::prompt_guard::check_request_external(
                &self.client,
                guardrail,
                api_key.as_deref(),
                request_body,
            )
            .instrument(guard_span)
            .await;

            let witness_json = serde_json::to_string(&witness.id).unwrap_or_else(|_| "\"\"".to_string());
            if let crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) = outcome {
                let guard_ms = ext_timer
                    .elapsed()
                    .as_millis();
                warn!("[PIPE:{}] Request blocked by expert witness '{}'", self.config.id, witness.id);
                let detail_json = serde_json::to_string(
                    rejection
                        .reason
                        .as_deref()
                        .unwrap_or("Request blocked"),
                )
                .unwrap_or_else(|_| "\"Request blocked\"".to_string());
                info!(
                    "[PIPE:{}] [STAGE:expert_witness_request] {{\"witness\":{},\"outcome\":\"rejected\",\"detail\":{},\"duration_ms\":{}}}",
                    self.config.id, witness_json, detail_json, guard_ms
                );
                return Err(PipeError::guard_rejected(
                    rejection,
                    RejectionStage::WitnessRequest,
                    guardrail.provider.as_str(),
                )
                .with_stage_io(witness_input, witness_output));
            }
            let guard_ms = ext_timer
                .elapsed()
                .as_millis();
            info!(
                "[PIPE:{}] [STAGE:expert_witness_request] {{\"witness\":{},\"outcome\":\"allowed\",\"detail\":\"Content passed\",\"duration_ms\":{}}}",
                self.config.id, witness_json, guard_ms
            );
            records.push(StageRecord {
                stage: "expert_witness_request".to_string(),
                decision: StageDecision::Allow,
                detail: Some(format!("{} · passed", witness.id)),
                input: witness_input,
                output: witness_output,
                key_source: Some(key_source),
            });
        }
        Ok(records)
    }

    /// Consult every enabled expert witness whose `check_response` is set,
    /// against the response body after the jury and local regex guards. The
    /// first flagged verdict blocks delivery with `PromptGuardRejected`.
    /// Per-witness tracing spans and `[STAGE:expert_witness_response]` logging
    /// are preserved.
    async fn run_response_witnesses(
        &self,
        response_body: &Value,
    ) -> Result<Vec<StageRecord>, PipeError> {
        let mut records = Vec::new();
        for witness in &self.config.expert_witnesses {
            let guardrail = &witness.guardrail;
            if !guardrail.enabled || !guardrail.check_response {
                continue;
            }
            let ext_timer = Instant::now();
            let (api_key, key_source) = self
                .resolve_external_guard_key(guardrail)
                .await?;
            let guard_span = tracing::info_span!(
                "pipe.expert_witness.response",
                otel.name = "Expert Witness (Response)",
                pipe = %self.config.name,
                witness = %witness.id
            );
            let (outcome, witness_input, witness_output) = crate::pipes::prompt_guard::check_response_external(
                &self.client,
                guardrail,
                api_key.as_deref(),
                response_body,
            )
            .instrument(guard_span)
            .await;

            let witness_json = serde_json::to_string(&witness.id).unwrap_or_else(|_| "\"\"".to_string());
            if let crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) = outcome {
                let guard_ms = ext_timer
                    .elapsed()
                    .as_millis();
                warn!("[PIPE:{}] Response blocked by expert witness '{}'", self.config.id, witness.id);
                let detail_json = serde_json::to_string(
                    rejection
                        .reason
                        .as_deref()
                        .unwrap_or("Response blocked"),
                )
                .unwrap_or_else(|_| "\"Response blocked\"".to_string());
                info!(
                    "[PIPE:{}] [STAGE:expert_witness_response] {{\"witness\":{},\"outcome\":\"rejected\",\"detail\":{},\"duration_ms\":{}}}",
                    self.config.id, witness_json, detail_json, guard_ms
                );
                return Err(PipeError::guard_rejected(
                    rejection,
                    RejectionStage::WitnessResponse,
                    guardrail.provider.as_str(),
                )
                .with_stage_io(witness_input, witness_output));
            }
            let guard_ms = ext_timer
                .elapsed()
                .as_millis();
            info!(
                "[PIPE:{}] [STAGE:expert_witness_response] {{\"witness\":{},\"outcome\":\"allowed\",\"detail\":\"Content passed\",\"duration_ms\":{}}}",
                self.config.id, witness_json, guard_ms
            );
            records.push(StageRecord {
                stage: "expert_witness_response".to_string(),
                decision: StageDecision::Allow,
                detail: Some(format!("{} · passed", witness.id)),
                input: witness_input,
                output: witness_output,
                key_source: Some(key_source),
            });
        }
        Ok(records)
    }
}

/// Transform an OpenAI-format request body into Anthropic Messages API format.
///
/// OpenAI format:
///   { "model": "...", "messages": [{"role": "system", "content": "..."}, {"role": "user", "content": "..."}] }
///
/// Anthropic format:
///   { "model": "...", "system": "...", "messages": [{"role": "user", "content": "..."}], "max_tokens": N }
///
/// This function:
/// 1. Extracts system messages from the messages array → top-level "system" field
/// 2. Removes system messages from the messages array
/// 3. Renames "max_tokens" or "max_completion_tokens" to Anthropic's "max_tokens" if missing
/// 4. Removes "response_format" (unsupported by Anthropic)
/// 5. Passes through all other fields unchanged
///
/// Transform an Anthropic Messages API response into OpenAI-compatible format.
///
/// Anthropic returns:
/// ```json
/// {
///   "id": "msg_...", "type": "message", "role": "assistant",
///   "content": [{"type": "text", "text": "Hello!"}],
///   "model": "claude-...", "stop_reason": "end_turn",
///   "usage": {"input_tokens": 10, "output_tokens": 25}
/// }
/// ```
///
/// This converts to OpenAI format so all downstream consumers (jury, prompt
/// guards, ChatSandbox, clients) see a consistent `choices[].message.content`
/// structure.
fn transform_from_anthropic_format(response: Value) -> Value {
    // Quick check: if it already has "choices", it's already OpenAI format
    if response
        .get("choices")
        .is_some()
    {
        return response;
    }

    // Must have Anthropic's "content" array to transform
    let content_array = match response
        .get("content")
        .and_then(|c| c.as_array())
    {
        Some(arr) => arr,
        None => return response,
    };

    // Extract text content — concatenate all text blocks
    let text_content: String = content_array
        .iter()
        .filter(|block| {
            block
                .get("type")
                .and_then(|t| t.as_str())
                == Some("text")
        })
        .filter_map(|block| {
            block
                .get("text")
                .and_then(|t| t.as_str())
        })
        .collect::<Vec<_>>()
        .join("");

    // Collect tool_use blocks → OpenAI tool_calls
    let tool_calls: Vec<Value> = content_array
        .iter()
        .filter(|block| {
            block
                .get("type")
                .and_then(|t| t.as_str())
                == Some("tool_use")
        })
        .map(|block| {
            let id = block
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let name = block
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let input = block
                .get("input")
                .cloned()
                .unwrap_or_else(|| serde_json::json!({}));
            let arguments = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
            serde_json::json!({
                "id": id,
                "type": "function",
                "function": { "name": name, "arguments": arguments }
            })
        })
        .collect();

    // Map stop_reason to finish_reason
    let finish_reason = match response
        .get("stop_reason")
        .and_then(|s| s.as_str())
    {
        Some("end_turn") => "stop",
        Some("max_tokens") => "length",
        Some("stop_sequence") => "stop",
        Some("tool_use") => "tool_calls",
        Some(other) => other,
        None => {
            if tool_calls.is_empty() {
                "stop"
            } else {
                "tool_calls"
            }
        }
    };

    // Build OpenAI-compatible usage (keep both field name variants for parse_auto)
    let usage = if let Some(anthropic_usage) = response.get("usage") {
        let input = anthropic_usage
            .get("input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let output = anthropic_usage
            .get("output_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        // Preserve Anthropic prompt-cache accounting so the downstream parser
        // surfaces cache read (as OpenAI `prompt_tokens_details.cached_tokens`)
        // and cache write (`cache_creation_input_tokens`).
        let cache_read = anthropic_usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let cache_write = anthropic_usage
            .get("cache_creation_input_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let mut usage = serde_json::json!({
            "prompt_tokens": input,
            "completion_tokens": output,
            "total_tokens": input + output
        });
        // Anthropic's own names stay too: unlike OpenAI's cached tokens, these
        // are not part of `prompt_tokens`, so they are priced apart (see
        // `crate::pipes::types::llm::CacheTokens`).
        if cache_read > 0 {
            usage["prompt_tokens_details"] = serde_json::json!({ "cached_tokens": cache_read });
            usage["cache_read_input_tokens"] = serde_json::json!(cache_read);
        }
        if cache_write > 0 {
            usage["cache_creation_input_tokens"] = serde_json::json!(cache_write);
            // The TTL breakdown, so a 1-hour write is priced as one.
            if let Some(breakdown) = anthropic_usage.get("cache_creation") {
                usage["cache_creation"] = breakdown.clone();
            }
        }
        usage
    } else {
        serde_json::json!({
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        })
    };

    // Build the assistant message. When the model emitted tool calls, surface
    // them as OpenAI `tool_calls` and null the content if there was no text
    // (mirroring OpenAI's tool-call responses).
    let mut message = serde_json::json!({ "role": "assistant" });
    if tool_calls.is_empty() {
        message["content"] = Value::String(text_content);
    } else {
        message["content"] = if text_content.is_empty() {
            Value::Null
        } else {
            Value::String(text_content)
        };
        message["tool_calls"] = Value::Array(tool_calls);
    }

    // Surface Anthropic thinking blocks as canonical reasoning so downstream
    // re-skinning and metering see them uniformly.
    let reasoning_details = crate::pipes::reasoning::anthropic_thinking_to_details(content_array);
    if !reasoning_details.is_empty() {
        let reasoning_text = crate::pipes::reasoning::reasoning_text_from_details(&reasoning_details);
        if !reasoning_text.is_empty() {
            message["reasoning"] = Value::String(reasoning_text);
        }
        message["reasoning_details"] = Value::Array(reasoning_details);
    }

    // Build the OpenAI-compatible response
    serde_json::json!({
        "id": response.get("id").cloned().unwrap_or(Value::String("msg_unknown".to_string())),
        "object": "chat.completion",
        "model": response.get("model").cloned().unwrap_or(Value::String("unknown".to_string())),
        "choices": [{
            "index": 0,
            "message": message,
            "finish_reason": finish_reason
        }],
        "usage": usage
    })
}

/// Resolve an explicit per-pipe price override into [`TokenPricing`].
///
/// Both `input_price_per_1k` and `output_price_per_1k` must be present **and
/// strictly positive** for the override to apply; values are scaled from the
/// per-1,000-token basis the editor uses to the per-1,000,000-token basis
/// [`TokenPricing`] uses. A missing, zero, or negative override returns `None`
/// so the caller falls through to catalog pricing — the dashboard seeds 0.0
/// defaults, which would otherwise force every cost to $0.
pub(crate) fn explicit_override_pricing(
    input_price_per_1k: Option<f64>,
    output_price_per_1k: Option<f64>,
) -> Option<crate::pipes::types::llm::TokenPricing> {
    match (input_price_per_1k, output_price_per_1k) {
        (Some(input_per_1k), Some(output_per_1k)) if input_per_1k > 0.0 && output_per_1k > 0.0 => {
            Some(crate::pipes::types::llm::TokenPricing {
                input_price_per_million: input_per_1k * 1000.0,
                output_price_per_million: output_per_1k * 1000.0,
            })
        }
        _ => None,
    }
}

/// A secret resolved for this surface: its value and the tenant that owns it.
#[derive(Clone)]
struct ResolvedSecret {
    value: String,
    tenant_id: Option<String>,
}

/// The extra headers of the upstream a call goes to, bound to the endpoint
/// they were configured for. They are that endpoint's credential, so they are
/// only ever sent to a request on its origin.
struct TargetHeaders<'a> {
    headers: &'a [crate::pipes::upstream_headers::UpstreamHeader],
    configured_for: String,
}

impl<'a> TargetHeaders<'a> {
    /// A target's own headers, configured for its own endpoint.
    fn of_target(target: &'a crate::pipes::judge_jury::LLMTarget) -> Self {
        Self {
            headers: &target.headers,
            configured_for: target.resolved_endpoint(),
        }
    }
}

/// Why a `web_fetch` download did not complete: the host is or resolves to
/// an address the strict rules refuse, or the fetch itself failed.
enum FetchError {
    Blocked(String),
    Failed(String),
}

impl FetchError {
    /// The generic reason the model is told, and the stage detail that keeps
    /// the full error. The model never sees the error itself: it can name the
    /// internal address a host resolved to.
    fn denial(self) -> (&'static str, String) {
        let (reason, error) = match self {
            Self::Blocked(error) => ("URL blocked by SSRF guard", error),
            Self::Failed(error) => ("URL could not be fetched", error),
        };
        (reason, format!("{reason}: {error}"))
    }
}

/// What an upstream call is, for its budget check (see
/// [`PipeExecutor::resolve_provider_headers`]): what it would be priced at,
/// read for a call that sends no credential and for a binary call, and what
/// it sends, read for the metered-endpoint rule (see
/// [`crate::pipes::metering`]).
#[derive(Clone, Copy)]
enum UpstreamCall<'a> {
    /// A JSON model call, priced by its upstream's declared price and the
    /// model it runs, sending `body`. `caller_path` is set when the caller
    /// chose the call's path (an OpenAI-compatible upstream appends the
    /// request's path), unset for an endpoint configured for the call.
    Model {
        declared: Option<crate::pipes::types::llm::TargetPricing>,
        model: &'a str,
        body: &'a Value,
        caller_path: bool,
    },
    /// A binary passthrough (text-to-speech), priced by its input characters
    /// at the model's input price. Its path is always the caller's (see
    /// [`binary_endpoint`]).
    Binary { declared: Option<crate::pipes::types::llm::TargetPricing>, model: &'a str },
    /// A multipart upload passthrough (a file, or speech-to-text): it bills
    /// nothing, so what it spends is never metered.
    Upload,
    /// A GET passthrough (a poll): it bills nothing.
    Poll,
}

/// The request headers of one call, whether the call may be billed at the
/// upstream's own price (its declared price or the surface's override): not
/// when a tenant's surface sent an operator (untenanted) secret, the source of
/// its credentials (what it bills), and whether it sent a credential of the
/// caller's (the caller's own key or a forwarded identity token), whose
/// refusal is final whatever the call bills.
///
/// `keyless` is set when the call sends no credential at all: who pays such
/// an upstream is not knowable, so its budget check depends on its price (see
/// [`PipeExecutor::resolve_provider_headers`]).
/// `budget_checked` says whether the budget was asked for the call, so a
/// repeat of the same call (a Jury retry) asks exactly when the first did.
struct ProviderHeaders {
    headers: Vec<(String, String)>,
    own_price_honoured: bool,
    key_source: KeySource,
    sent_caller_credential: bool,
    keyless: bool,
    budget_checked: bool,
}

/// One fanned-out Mirror candidate result. Failures are represented with
/// `error = Some(..)` and empty content/usage so best-effort fan-out never
/// aborts the whole request when a single upstream misbehaves.
struct CandidateOutcome {
    id: String,
    name: String,
    provider: String,
    model: String,
    /// Assistant completion text (empty on failure).
    content: String,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
    /// The source of the key the candidate call sent; `None` when it failed.
    key_source: Option<KeySource>,
    latency_ms: u64,
    request_bytes: u64,
    response_bytes: u64,
    error: Option<String>,
    /// Why the candidate's platform key was refused before it was sent (a
    /// spent budget or unmetered spend), when it was.
    refusal: Option<PlatformRefusal>,
}

impl CandidateOutcome {
    /// The candidate call's usage, billed by its key source; empty when it
    /// failed.
    fn usage(&self) -> StageUsage {
        match self.key_source {
            Some(source) => StageUsage::call(self.input_tokens, self.output_tokens, self.cost, self.latency_ms, source),
            None => StageUsage::default(),
        }
    }
}

/// The success payload of a single candidate call, before it is folded into a
/// [`CandidateOutcome`] with common identity/latency fields.
struct CandidateCall {
    /// The model the candidate's upstream ran (see [`model_run`]).
    model: String,
    content: String,
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
    key_source: KeySource,
    request_bytes: u64,
    response_bytes: u64,
}

/// Default synthesis instruction for the Mirror merger when no
/// `merge_system_prompt` is configured.
const DEFAULT_MERGE_PROMPT: &str = "You are given several candidate answers to the user's request, each produced by a \
different model. Synthesize a single best answer that combines the strongest, most accurate parts of each and \
discards any errors or weaker content. Do not mention that multiple answers exist or that a merge occurred — reply \
only with the merged answer.";

/// Rewrite the working request in place so the merger LLM synthesizes the
/// fanned-out candidate answers: a system message carries the merge policy and
/// a trailing user message enumerates each (successful) candidate answer.
fn augment_request_for_merge(
    working_request: &mut Value,
    decider: &crate::pipes::judge_jury::DeciderConfig,
    outcomes: &[CandidateOutcome],
) {
    let policy = if decider
        .mirror
        .merge_system_prompt
        .trim()
        .is_empty()
    {
        DEFAULT_MERGE_PROMPT
    } else {
        decider
            .mirror
            .merge_system_prompt
            .as_str()
    };

    let mut answers = String::from("Here are the candidate answers to merge into a single best answer:\n\n");
    for (i, outcome) in outcomes
        .iter()
        .filter(|o| o.error.is_none())
        .enumerate()
    {
        answers.push_str(&format!("--- Candidate {} ({}) ---\n{}\n\n", i + 1, outcome.name, outcome.content));
    }

    if let Some(messages) = working_request
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
    {
        messages.insert(0, serde_json::json!({"role": "system", "content": policy}));
        messages.push(serde_json::json!({"role": "user", "content": answers}));
    }
}

/// Apply the response prompt guard and pseudonym rehydration to each successful
/// Collect candidate answer, so the returned body and its `x_mirror` entries
/// mask/restore identically to the Route/Merge tail. A response reject rule
/// fails the whole request (fail closed rather than leak flagged content).
fn mask_collect_candidates(
    outcomes: &mut [CandidateOutcome],
    response_guards: &[crate::pipes::prompt_guard::ResponseGuard],
    rehydration_map: &crate::pipes::prompt_guard::RehydrationMap,
) -> Result<(), PipeError> {
    if response_guards.is_empty() && rehydration_map.is_empty() {
        return Ok(());
    }
    for outcome in outcomes
        .iter_mut()
        .filter(|o| o.error.is_none())
    {
        let mut item = serde_json::json!({
            "choices": [{"message": {"role": "assistant", "content": outcome.content}}]
        });
        if !response_guards.is_empty()
            && let crate::pipes::prompt_guard::GuardOutcome::Rejected(rejection) =
                crate::pipes::prompt_guard::apply_response_guards(&mut item, response_guards)
        {
            return Err(PipeError::guard_rejected(rejection, RejectionStage::RegexResponse, "regex"));
        }
        if !rehydration_map.is_empty() {
            crate::pipes::prompt_guard::rehydrate_response(&mut item, rehydration_map);
        }
        if let Some(text) = item
            .pointer("/choices/0/message/content")
            .and_then(|v| v.as_str())
        {
            outcome.content = text.to_string();
        }
    }
    Ok(())
}

/// Assemble the Collect-mode response: a valid OpenAI chat completion whose
/// content concatenates every candidate answer (so unaware clients still render
/// something), plus an `x_mirror` extension carrying the structured per-candidate
/// breakdown for the dashboard / a human to compare and choose.
fn build_mirror_collect_body(outcomes: &[CandidateOutcome]) -> Value {
    let mut combined = String::new();
    for (i, outcome) in outcomes.iter().enumerate() {
        combined.push_str(&format!("### Candidate {}: {} ({})\n", i + 1, outcome.name, outcome.model));
        match &outcome.error {
            Some(err) => combined.push_str(&format!("_error: {}_\n\n", err)),
            None => combined.push_str(&format!("{}\n\n", outcome.content)),
        }
    }

    let candidates: Vec<Value> = outcomes
        .iter()
        .map(|o| {
            serde_json::json!({
                "id": o.id,
                "name": o.name,
                "provider": o.provider,
                "model": o.model,
                "content": o.content,
                "error": o.error,
                "input_tokens": o.input_tokens,
                "output_tokens": o.output_tokens,
                "cost": o.cost,
                "latency_ms": o.latency_ms,
            })
        })
        .collect();

    let input_tokens: u64 = outcomes
        .iter()
        .map(|o| o.input_tokens)
        .sum();
    let output_tokens: u64 = outcomes
        .iter()
        .map(|o| o.output_tokens)
        .sum();

    serde_json::json!({
        "id": format!("mirror-{}", uuid::Uuid::new_v4()),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": "mirror-collect",
        "choices": [{
            "index": 0,
            "message": {"role": "assistant", "content": combined.trim_end()},
            "finish_reason": "stop",
        }],
        "usage": {
            "prompt_tokens": input_tokens,
            "completion_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens,
        },
        "x_mirror": {
            "mode": "collect",
            "candidates": candidates,
        },
    })
}

/// Resolve the request-shaping profile for an LLM pipe's provider, preferring the
/// editable provider catalog and falling back to schema/heuristic defaults when no
/// catalog has been installed.
/// The model `provider` runs for a request whose outbound body is `body`: the
/// `model` the body names (the caller's, unless an override policy or the
/// gateway replaced it) when the provider runs the model a request names,
/// else the configured model its endpoint or deployment fixes. A call is
/// billed, and its catalog price looked up, by this model.
pub(crate) fn model_run<'a>(
    provider: &'a crate::pipes::types::llm::LLMProvider,
    body: &'a Value,
) -> &'a str {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    body.get("model")
        .and_then(Value::as_str)
        .filter(|model| provider.runs_requested_model() && !model.is_empty())
        .unwrap_or_else(|| provider.get_model())
}

/// The request profile of `model` as `provider` runs it (see
/// [`resolve_request_profile`] for the provider's configured model).
fn model_profile(
    provider: &crate::pipes::types::llm::LLMProvider,
    model: &str,
) -> crate::pipes::request_shaping::ModelRequestProfile {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    let api_schema = provider.api_schema();
    match crate::llm_catalog::global_catalog() {
        Some(catalog) => catalog.resolve_model_profile(provider.provider_type_str(), model, api_schema, None),
        None => crate::pipes::request_shaping::builtin_profile(api_schema, model, None),
    }
}

pub(crate) fn resolve_request_profile(
    provider: &crate::pipes::types::llm::LLMProvider
) -> crate::pipes::request_shaping::ModelRequestProfile {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    let provider_enum = provider.provider_type_str();
    let model = provider.get_model();
    let api_schema = provider.api_schema();
    match crate::llm_catalog::global_catalog() {
        Some(catalog) => catalog.resolve_model_profile(provider_enum, model, api_schema, None),
        None => crate::pipes::request_shaping::builtin_profile(api_schema, model, None),
    }
}

/// True for the credential/auth header names a provider might set, so identity
/// pass-through can strip them before injecting the caller's bearer token.
fn is_auth_header_name(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase()
            .as_str(),
        "authorization" | "x-api-key" | "api-key" | "x-goog-api-key"
    )
}

/// Build the outbound headers for identity pass-through: the provider's non-auth
/// headers (e.g. Anthropic's `anthropic-version`) plus `Authorization: Bearer
/// <caller token>`. Any provider auth header is stripped so a stale stored-key
/// reference can never leak. Returns `None` when the inbound request carried no
/// usable bearer token.
/// Build the outbound provider headers for identity pass-through
/// (`forward_caller_token`). Forwards a bearer token as the upstream
/// `Authorization`, stripping any provider auth header so a stale secret can't
/// leak. When a distinct **upstream** token is supplied (the caller sent
/// `X-Agent-Stream-Upstream-Authorization`, e.g. a Graph token for Copilot),
/// it takes precedence over the caller's front-door token so the front door and
/// the upstream can authenticate with different identities. Falls back to the
/// caller's front-door token when no upstream token is present (back-compat).
/// The main stage's usage over `calls` calls to one upstream (the first call
/// plus each Jury-rejected retry) that all sent a key from `source`.
fn main_call_usage(
    input_tokens: u64,
    output_tokens: u64,
    cost: f64,
    latency_ms: u64,
    source: KeySource,
    calls: u32,
) -> StageUsage {
    let mut usage = StageUsage::call(input_tokens, output_tokens, cost, latency_ms, source);
    for _ in 1..calls {
        usage
            .key_sources
            .record(source);
    }
    usage
}

/// Remove a caller-supplied `api_key` from a request body bound for a call the
/// caller's key is not offered to (a Decider candidate or merger, or a
/// failover, load-balancing or routed target), so it never reaches another
/// provider.
fn strip_caller_body_key(body: &mut Value) {
    if let Some(object) = body.as_object_mut() {
        object.remove("api_key");
    }
}

/// What a binary passthrough is priced on: the characters of its `input` text
/// (text-to-speech), priced as input tokens at the upstream's input price, the
/// unit OpenAI prices `tts-1` and `tts-1-hd` in (per 1K characters). Zero for
/// a body with no `input` text.
fn binary_input_units(body: &Value) -> u64 {
    body.get("input")
        .and_then(Value::as_str)
        .map_or(0, |input| input.chars().count() as u64)
}

fn build_caller_token_headers(
    provider: &crate::pipes::types::llm::LLMProvider,
    caller: &CallerCredentials,
) -> Option<Vec<(String, String)>> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    let token = caller.forwarded_token()?;
    let mut headers = provider.build_headers();
    headers.retain(|(name, _)| !is_auth_header_name(name));
    headers.push(("Authorization".to_string(), format!("Bearer {token}")));
    Some(headers)
}

/// Transform a Google Gemini generateContent response to OpenAI chat completion format.
///
/// Gemini: { candidates: [{content: {parts: [{text}], role}, finishReason}], usageMetadata: {promptTokenCount, candidatesTokenCount, totalTokenCount} }
/// OpenAI: { choices: [{message: {role, content}, finish_reason}], usage: {prompt_tokens, completion_tokens, total_tokens} }
fn transform_from_gemini_format(response: Value) -> Value {
    let content = response
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
        .map(|parts| {
            parts
                .iter()
                .filter_map(|p| {
                    p.get("text")
                        .and_then(|t| t.as_str())
                })
                .collect::<Vec<_>>()
                .join("")
        })
        .unwrap_or_default();

    let finish_reason = response
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("finishReason"))
        .and_then(|r| r.as_str())
        .map(|r| match r {
            "STOP" => "stop",
            "MAX_TOKENS" => "length",
            "SAFETY" => "content_filter",
            _ => "stop",
        })
        .unwrap_or("stop");

    let usage = response
        .get("usageMetadata")
        .map(|u| {
            let prompt = u
                .get("promptTokenCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            // Thinking tokens are billed at the output rate and reported apart
            // from the answer's.
            let completion = u
                .get("candidatesTokenCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(0)
                + u.get("thoughtsTokenCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0);
            let total = u
                .get("totalTokenCount")
                .and_then(|v| v.as_u64())
                .unwrap_or(prompt + completion);
            serde_json::json!({
                "prompt_tokens": prompt,
                "completion_tokens": completion,
                "total_tokens": total
            })
        })
        .unwrap_or(serde_json::json!({
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }));

    let model = response
        .get("modelVersion")
        .and_then(|m| m.as_str())
        .unwrap_or("gemini");

    serde_json::json!({
        "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        "object": "chat.completion",
        "model": model,
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": finish_reason
        }],
        "usage": usage
    })
}

/// Transform a Microsoft 365 Copilot Chat API response into OpenAI chat
/// completion format.
///
/// Copilot returns a `copilotConversation` whose `messages` array ends with the
/// assistant's answer (`copilotConversationResponseMessage`). We take the last
/// message's `text` as the assistant content. Copilot reports no token usage, so
/// a zero-token `usage` block is synthesised — this keeps the response a valid
/// OpenAI envelope (so metering succeeds) while resolving to zero cost, which is
/// correct: Copilot is billed per user license, not per token.
fn transform_from_copilot_format(response: Value) -> Value {
    let content = response
        .get("messages")
        .and_then(|m| m.as_array())
        .and_then(|msgs| msgs.last())
        .and_then(|msg| msg.get("text"))
        .and_then(|t| t.as_str())
        .unwrap_or_default()
        .to_string();

    serde_json::json!({
        "id": format!("chatcmpl-{}", uuid::Uuid::new_v4()),
        "object": "chat.completion",
        "model": "m365-copilot",
        "choices": [{
            "index": 0,
            "message": {
                "role": "assistant",
                "content": content
            },
            "finish_reason": "stop"
        }],
        "usage": {
            "prompt_tokens": 0,
            "completion_tokens": 0,
            "total_tokens": 0
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn llm_target(model: &str) -> serde_json::Value {
        serde_json::json!({
            "provider_type": "openai", "model": model, "endpoint_url": "https://example.test/v1"
        })
    }

    fn staged_config() -> PipeConfig {
        let mut config = PipeConfig::new(
            "p1".to_string(),
            "P1".to_string(),
            crate::pipes::PipeType::LLM {
                provider: Box::new(
                    serde_json::from_value(serde_json::json!({
                        "type": "openai", "provider_type": "openai", "model": "gpt-4o"
                    }))
                    .unwrap(),
                ),
                endpoint_path: None,
            },
        );
        config.judge = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true, "llm": llm_target("gpt-4o-mini")
            }))
            .unwrap(),
        );
        config.jury = Some(
            serde_json::from_value(serde_json::json!({
                "enabled": true,
                "jurors": [
                    {"name": "a", "llm": llm_target("m1"), "system_prompt": "x"},
                    {"name": "b", "llm": llm_target("m2"), "system_prompt": "x"}
                ]
            }))
            .unwrap(),
        );
        config
    }

    fn usage(
        input: u64,
        output: u64,
        cost: f64,
    ) -> StageUsage {
        StageUsage {
            input_tokens: input,
            output_tokens: output,
            cost,
            latency_ms: 0,
            ..Default::default()
        }
    }

    #[test]
    fn stage_usage_entries_attribute_each_stage_to_its_own_model() {
        let config = staged_config();
        let entries = stage_usage_entries(
            &config,
            "openai",
            "gpt-4o",
            &usage(100, 50, 0.02),
            &usage(20, 2, 0.001),
            &usage(30, 4, 0.002),
            &usage(0, 0, 0.0),
        );
        // The decider did not run, so it has no entry.
        let stages: Vec<&str> = entries
            .iter()
            .map(|e| e.stage.as_str())
            .collect();
        assert_eq!(stages, ["llm", "judge", "jury"]);
        assert_eq!(entries[0].model.as_deref(), Some("gpt-4o"));
        assert_eq!(entries[0].provider.as_deref(), Some("openai"));
        assert_eq!((entries[0].input_tokens, entries[0].output_tokens), (100, 50));
        assert_eq!(entries[1].model.as_deref(), Some("gpt-4o-mini"));
        assert!((entries[1].cost - 0.001).abs() < 1e-12);
        // Jurors on different models: the jury's model is unknown, not guessed.
        assert_eq!(entries[2].model, None);
        assert_eq!(entries[2].provider, None);
    }

    #[test]
    fn jury_with_one_shared_model_reports_it() {
        let mut config = staged_config();
        let jury = config.jury.as_mut().unwrap();
        jury.jurors[1].llm.model = "m1".to_string();
        assert_eq!(jury_provider_model(&config), (Some("openai".to_string()), Some("m1".to_string())));
    }

    #[test]
    fn rejected_usage_becomes_blocked_record_metrics() {
        let config = staged_config();
        let rejected = RejectedExecutionUsage {
            llm: usage(0, 0, 0.0),
            judge: usage(20, 2, 0.001),
            jury: usage(0, 0, 0.0),
            decider: usage(5, 1, 0.0005),
        };
        let m = rejected.record_metrics(&config, "openai", "gpt-4o");
        assert_eq!((m.input_tokens, m.output_tokens, m.total_tokens), (25, 3, 28));
        assert!((m.cost - 0.0015).abs() < 1e-12);
        assert_eq!(m.currency.as_deref(), Some("USD"));
        let stages: Vec<&str> = m
            .usage_by_stage
            .iter()
            .map(|e| e.stage.as_str())
            .collect();
        assert_eq!(stages, ["judge", "decider"]);
        // A request blocked before any model was called spends nothing.
        let none = RejectedExecutionUsage {
            llm: usage(0, 0, 0.0),
            judge: usage(0, 0, 0.0),
            jury: usage(0, 0, 0.0),
            decider: usage(0, 0, 0.0),
        };
        assert!(
            none.record_metrics(&config, "openai", "gpt-4o")
                .usage_by_stage
                .is_empty()
        );
    }

    fn mirror_outcome(
        id: &str,
        name: &str,
        content: &str,
        input_tokens: u64,
        output_tokens: u64,
        error: Option<&str>,
    ) -> CandidateOutcome {
        CandidateOutcome {
            id: id.to_string(),
            name: name.to_string(),
            provider: "openai".to_string(),
            model: "gpt-4o".to_string(),
            content: content.to_string(),
            input_tokens,
            output_tokens,
            cost: 0.01,
            key_source: error
                .is_none()
                .then_some(KeySource::Platform),
            latency_ms: 100,
            request_bytes: 50,
            response_bytes: 80,
            error: error.map(|e| e.to_string()),
            refusal: None,
        }
    }

    #[test]
    fn build_mirror_collect_body_carries_every_candidate() {
        let outcomes = vec![
            mirror_outcome("a", "Alpha", "answer A", 10, 5, None),
            mirror_outcome("b", "Beta", "answer B", 20, 8, None),
            mirror_outcome("c", "Gamma", "", 0, 0, Some("timeout")),
        ];
        let body = build_mirror_collect_body(&outcomes);

        assert_eq!(body["object"], "chat.completion");
        assert_eq!(body["model"], "mirror-collect");
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("Alpha"));
        assert!(content.contains("answer A"));
        assert!(content.contains("answer B"));
        assert!(content.contains("timeout"));

        assert_eq!(body["x_mirror"]["mode"], "collect");
        assert_eq!(
            body["x_mirror"]["candidates"]
                .as_array()
                .unwrap()
                .len(),
            3
        );
        // Usage sums only the returned candidates.
        assert_eq!(body["usage"]["prompt_tokens"], 30);
        assert_eq!(body["usage"]["completion_tokens"], 13);
        assert_eq!(body["usage"]["total_tokens"], 43);
    }

    #[test]
    fn augment_request_for_merge_frames_candidate_answers() {
        let decider: crate::pipes::judge_jury::DeciderConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "strategy": "mirror",
            "mirror": {
                "mode": "merge",
                "merger": {"provider_type": "openai", "model": "gpt-4o", "endpoint_url": "https://api.openai.com/v1/chat/completions"}
            },
            "llm": {"provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "https://api.openai.com/v1/chat/completions"},
            "candidates": [
                {"id": "a", "name": "Alpha", "llm": {"provider_type": "openai", "model": "gpt-4o", "endpoint_url": "https://api.openai.com/v1/chat/completions"}}
            ]
        }))
        .unwrap();
        let mut request = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
        let outcomes = vec![
            mirror_outcome("a", "Alpha", "answer A", 10, 5, None),
            mirror_outcome("b", "Beta", "answer B", 20, 8, Some("failed")),
        ];

        augment_request_for_merge(&mut request, &decider, &outcomes);

        let messages = request["messages"]
            .as_array()
            .unwrap();
        // System merge instruction leads, original user turn is preserved, and a
        // trailing user message carries the (successful) candidate answers.
        assert_eq!(messages[0]["role"], "system");
        assert_eq!(messages[0]["content"], DEFAULT_MERGE_PROMPT);
        assert_eq!(messages[1]["role"], "user");
        assert_eq!(messages[1]["content"], "hi");
        let merge_turn = messages[2]["content"]
            .as_str()
            .unwrap();
        assert!(merge_turn.contains("answer A"));
        // The failed candidate is excluded from the merge material.
        assert!(!merge_turn.contains("answer B"));
    }

    #[test]
    fn augment_request_for_merge_honors_custom_prompt() {
        let decider: crate::pipes::judge_jury::DeciderConfig = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "strategy": "mirror",
            "mirror": {
                "mode": "merge",
                "merge_system_prompt": "Combine the answers as a haiku.",
                "merger": {"provider_type": "openai", "model": "gpt-4o", "endpoint_url": "https://api.openai.com/v1/chat/completions"}
            },
            "llm": {"provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "https://api.openai.com/v1/chat/completions"},
            "candidates": [
                {"id": "a", "name": "Alpha", "llm": {"provider_type": "openai", "model": "gpt-4o", "endpoint_url": "https://api.openai.com/v1/chat/completions"}}
            ]
        }))
        .unwrap();
        let mut request = serde_json::json!({"messages": [{"role": "user", "content": "hi"}]});
        let outcomes = vec![mirror_outcome("a", "Alpha", "answer A", 10, 5, None)];

        augment_request_for_merge(&mut request, &decider, &outcomes);

        assert_eq!(request["messages"][0]["content"], "Combine the answers as a haiku.");
    }

    #[test]
    fn mask_collect_candidates_masks_and_rejects() {
        use crate::pipes::prompt_guard::{RehydrationMap, ResponseGuard};
        let empty_map = RehydrationMap::new();
        let mask_guard: ResponseGuard = serde_json::from_value(serde_json::json!({
            "regex": { "action": "mask", "rules": [{ "pattern": "secret\\d+" }] }
        }))
        .unwrap();

        // Masking rewrites matched content in every non-error candidate.
        let mut outcomes = vec![
            mirror_outcome("a", "A", "here is secret123 ok", 1, 1, None),
            mirror_outcome("b", "B", "clean text", 1, 1, None),
            mirror_outcome("c", "C", "", 0, 0, Some("boom")),
        ];
        mask_collect_candidates(&mut outcomes, std::slice::from_ref(&mask_guard), &empty_map).unwrap();
        assert!(
            !outcomes[0]
                .content
                .contains("secret123")
        );
        assert_eq!(outcomes[1].content, "clean text");
        assert_eq!(outcomes[2].content, "");

        // A reject rule fails the whole request (fail closed).
        let reject_guard: ResponseGuard = serde_json::from_value(serde_json::json!({
            "regex": { "action": "reject", "rules": [{ "pattern": "secret\\d+" }] }
        }))
        .unwrap();
        let mut rejecting = vec![mirror_outcome("a", "A", "secret123", 1, 1, None)];
        assert!(mask_collect_candidates(&mut rejecting, std::slice::from_ref(&reject_guard), &empty_map).is_err());

        // No guards + empty map is a no-op.
        let mut untouched = vec![mirror_outcome("a", "A", "secret123", 1, 1, None)];
        mask_collect_candidates(&mut untouched, &[], &empty_map).unwrap();
        assert_eq!(untouched[0].content, "secret123");
    }

    #[test]
    fn stage_records_map_to_governance_entries_in_order() {
        let records = vec![
            StageRecord {
                stage: "expert_witness_request".to_string(),
                decision: StageDecision::Allow,
                detail: Some("acme · passed".to_string()),
                input: Some("classify this".to_string()),
                output: Some("{\"flagged\":false}".to_string()),
                key_source: None,
            },
            StageRecord {
                stage: "decider".to_string(),
                decision: StageDecision::Observed,
                detail: Some("routed to gpt-4o".to_string()),
                input: None,
                output: None,
                key_source: None,
            },
            StageRecord {
                stage: "judge".to_string(),
                decision: StageDecision::Allow,
                detail: None,
                input: None,
                output: None,
                key_source: None,
            },
            StageRecord {
                stage: "jury".to_string(),
                decision: StageDecision::Flag,
                detail: Some("recovered: toxicity".to_string()),
                input: None,
                output: None,
                key_source: None,
            },
        ];
        let entries = stage_records_to_entries(&records);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].stage, "expert_witness_request");
        assert_eq!(entries[0].outcome, crate::governance::StageOutcome::Allow);
        assert_eq!(entries[0].reason.as_deref(), Some("acme · passed"));
        // Stage input/output flow through to the governance entry (digest +
        // body-gating is applied later, in the governance capture layer).
        assert_eq!(entries[0].input.as_deref(), Some("classify this"));
        assert_eq!(entries[0].output.as_deref(), Some("{\"flagged\":false}"));
        assert_eq!(entries[1].stage, "decider");
        assert_eq!(entries[1].outcome, crate::governance::StageOutcome::Observed);
        assert_eq!(entries[2].stage, "judge");
        assert_eq!(entries[2].outcome, crate::governance::StageOutcome::Allow);
        assert_eq!(entries[3].outcome, crate::governance::StageOutcome::Flag);
        // The `llm_call` stage is synthesized by the governance builder, not here.
        assert!(
            entries
                .iter()
                .all(|e| e.llm_call.is_none())
        );
    }

    #[test]
    fn copilot_response_maps_last_message_to_assistant_content() {
        // Copilot echoes the user turn then appends its answer; the answer is
        // the last message in `messages`.
        let response = serde_json::json!({
            "@odata.context": "https://graph.microsoft.com/beta/$metadata#microsoft.graph.copilotConversation",
            "id": "conv-1",
            "state": "active",
            "turnCount": 1,
            "messages": [
                { "@odata.type": "#microsoft.graph.copilotConversationResponseMessage", "text": "Summarize my doc" },
                { "@odata.type": "#microsoft.graph.copilotConversationResponseMessage", "text": "Here is the summary." }
            ]
        });
        let openai = transform_from_copilot_format(response);

        assert_eq!(openai["object"], serde_json::json!("chat.completion"));
        assert_eq!(openai["choices"][0]["message"]["role"], serde_json::json!("assistant"));
        assert_eq!(openai["choices"][0]["message"]["content"], serde_json::json!("Here is the summary."));
        assert_eq!(openai["choices"][0]["finish_reason"], serde_json::json!("stop"));
        // Copilot reports no token usage: a zero-token block keeps metering valid.
        assert_eq!(openai["usage"]["prompt_tokens"], serde_json::json!(0));
        assert_eq!(openai["usage"]["completion_tokens"], serde_json::json!(0));
        assert_eq!(openai["usage"]["total_tokens"], serde_json::json!(0));
    }

    #[test]
    fn copilot_response_missing_messages_yields_empty_content() {
        let openai = transform_from_copilot_format(serde_json::json!({ "id": "conv-2" }));
        assert_eq!(openai["choices"][0]["message"]["content"], serde_json::json!(""));
        assert_eq!(openai["usage"]["total_tokens"], serde_json::json!(0));
    }

    #[test]
    fn anthropic_response_text_only_maps_to_choices() {
        let response = serde_json::json!({
            "id": "msg_1",
            "type": "message",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [{ "type": "text", "text": "Hello!" }],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 10, "output_tokens": 5 }
        });
        let openai = transform_from_anthropic_format(response);
        assert_eq!(openai["choices"][0]["message"]["role"], serde_json::json!("assistant"));
        assert_eq!(openai["choices"][0]["message"]["content"], serde_json::json!("Hello!"));
        assert_eq!(openai["choices"][0]["finish_reason"], serde_json::json!("stop"));
        assert!(
            openai["choices"][0]["message"]
                .get("tool_calls")
                .is_none()
        );
        assert_eq!(openai["usage"]["total_tokens"], serde_json::json!(15));
    }

    #[test]
    fn anthropic_response_tool_use_maps_to_tool_calls() {
        let response = serde_json::json!({
            "id": "msg_2",
            "role": "assistant",
            "model": "claude-opus-4-8",
            "content": [
                { "type": "text", "text": "Let me check." },
                { "type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": { "city": "Paris" } }
            ],
            "stop_reason": "tool_use",
            "usage": { "input_tokens": 20, "output_tokens": 8 }
        });
        let openai = transform_from_anthropic_format(response);

        let message = &openai["choices"][0]["message"];
        assert_eq!(message["content"], serde_json::json!("Let me check."));
        let tool_calls = message["tool_calls"]
            .as_array()
            .unwrap();
        assert_eq!(tool_calls.len(), 1);
        assert_eq!(tool_calls[0]["id"], serde_json::json!("toolu_1"));
        assert_eq!(tool_calls[0]["type"], serde_json::json!("function"));
        assert_eq!(tool_calls[0]["function"]["name"], serde_json::json!("get_weather"));
        // arguments is a JSON-encoded string of the input object
        let args = tool_calls[0]["function"]["arguments"]
            .as_str()
            .unwrap();
        let parsed: serde_json::Value = serde_json::from_str(args).unwrap();
        assert_eq!(parsed, serde_json::json!({ "city": "Paris" }));

        assert_eq!(openai["choices"][0]["finish_reason"], serde_json::json!("tool_calls"));
    }

    #[test]
    fn anthropic_response_tool_use_only_nulls_content() {
        let response = serde_json::json!({
            "id": "msg_3",
            "role": "assistant",
            "content": [
                { "type": "tool_use", "id": "toolu_2", "name": "search", "input": {} }
            ],
            "stop_reason": "tool_use"
        });
        let openai = transform_from_anthropic_format(response);
        let message = &openai["choices"][0]["message"];
        assert_eq!(message["content"], serde_json::Value::Null, "content null when only tool calls");
        assert_eq!(
            message["tool_calls"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
        assert_eq!(openai["choices"][0]["finish_reason"], serde_json::json!("tool_calls"));
    }

    #[test]
    fn anthropic_response_captures_thinking_as_reasoning() {
        let response = serde_json::json!({
            "id": "msg_r",
            "role": "assistant",
            "content": [
                { "type": "thinking", "thinking": "let me think", "signature": "sig9" },
                { "type": "text", "text": "the answer" }
            ],
            "stop_reason": "end_turn",
            "usage": { "input_tokens": 5, "output_tokens": 6 }
        });
        let openai = transform_from_anthropic_format(response);
        let message = &openai["choices"][0]["message"];
        assert_eq!(message["content"], serde_json::json!("the answer"));
        assert_eq!(message["reasoning"], serde_json::json!("let me think"));
        let details = message["reasoning_details"]
            .as_array()
            .unwrap();
        assert_eq!(details[0]["type"], serde_json::json!("reasoning.text"));
        assert_eq!(details[0]["signature"], serde_json::json!("sig9"));
    }

    #[test]
    fn anthropic_response_preserves_cache_tokens() {
        let response = serde_json::json!({
            "id": "msg_c",
            "role": "assistant",
            "content": [ { "type": "text", "text": "ok" } ],
            "stop_reason": "end_turn",
            "usage": {
                "input_tokens": 10,
                "output_tokens": 5,
                "cache_read_input_tokens": 40,
                "cache_creation_input_tokens": 512,
                "cache_creation": { "ephemeral_5m_input_tokens": 112, "ephemeral_1h_input_tokens": 400 }
            }
        });
        let openai = transform_from_anthropic_format(response);
        assert_eq!(openai["usage"]["prompt_tokens_details"]["cached_tokens"], serde_json::json!(40));
        assert_eq!(openai["usage"]["cache_creation_input_tokens"], serde_json::json!(512));
        assert_eq!(crate::pipes::parsers::llm_parser::parse_cached_tokens(&openai), 40);
        assert_eq!(crate::pipes::parsers::llm_parser::parse_cache_write_tokens(&openai), 512);
        assert_eq!(openai["usage"]["prompt_tokens"], serde_json::json!(10), "Anthropic's input excludes the cache");
        assert_eq!(
            crate::pipes::types::llm::CacheTokens::of_response(&openai),
            crate::pipes::types::llm::CacheTokens {
                write: 512,
                write_1h: 400,
                read: 40
            },
            "both cache counts survive the transform, to be priced apart"
        );
    }

    #[test]
    fn a_gemini_responses_thinking_tokens_are_billed_as_output() {
        let response = serde_json::json!({
            "candidates": [{ "content": { "parts": [{ "text": "ok" }], "role": "model" }, "finishReason": "STOP" }],
            "usageMetadata": { "promptTokenCount": 10, "candidatesTokenCount": 5, "thoughtsTokenCount": 300, "totalTokenCount": 315 }
        });
        let openai = transform_from_gemini_format(response);
        assert_eq!(openai["usage"]["completion_tokens"], serde_json::json!(305));
        assert_eq!(crate::pipes::parsers::llm_parser::parse_auto(&openai), Ok((10, 305, 315)));
    }

    #[test]
    fn a_stream_on_a_key_that_bills_always_asks_for_its_usage() {
        let ask = |options: Option<Value>, source: KeySource| {
            let mut body = serde_json::json!({ "messages": [], "stream": true });
            if let Some(options) = options {
                body["stream_options"] = options;
            }
            request_usage_chunk(&mut body, source, "https://api.example.com/v1/chat/completions");
            body["stream_options"].clone()
        };
        for options in [
            Some(serde_json::json!({ "include_usage": false })),
            Some(serde_json::json!({})),
            Some(Value::Null),
            Some(serde_json::json!(false)),
            None,
        ] {
            let sent = ask(options.clone(), KeySource::Platform);
            assert_eq!(sent["include_usage"], serde_json::json!(true), "{options:?}");
        }
        assert_eq!(
            ask(Some(serde_json::json!({ "include_usage": false, "other": 1 })), KeySource::Platform),
            serde_json::json!({ "include_usage": true, "other": 1 }),
            "merged into the caller's object"
        );
        // An owned key bills nothing: the caller's choice stands.
        assert_eq!(
            ask(Some(serde_json::json!({ "include_usage": false })), KeySource::Customer),
            serde_json::json!({ "include_usage": false })
        );
        assert_eq!(ask(None, KeySource::Client), serde_json::json!({ "include_usage": true }));

        // Responses and Messages report usage in their own events and define
        // no `stream_options`: nothing is added, on any key.
        for url in ["https://api.example.com/v1/respons%65s", "https://api.example.com/v1/messages"] {
            let mut body = serde_json::json!({ "input": "hi", "stream": true });
            request_usage_chunk(&mut body, KeySource::Platform, url);
            assert!(
                body.get("stream_options")
                    .is_none(),
                "{url}"
            );
        }
    }

    #[test]
    fn anthropic_response_already_openai_is_passthrough() {
        let response = serde_json::json!({
            "choices": [{ "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" }]
        });
        let out = transform_from_anthropic_format(response.clone());
        assert_eq!(out, response, "already-OpenAI responses pass through untouched");
    }

    // ── Failover eligibility classification ──
    //
    // These tests pin the single decision (`is_failover_eligible`) that
    // separates a retriable upstream/transport failure from a denial that must
    // never be masked by trying a backup provider. Each failure class named in
    // the operational spec gets its own named test so a future refactor cannot
    // silently re-classify one: eligible classes fail over, suppressed classes
    // do not.

    fn prompt_guard_rejected_error() -> PipeError {
        PipeError::PromptGuardRejected {
            status_code: 403,
            body: "blocked".into(),
            content_type: "application/json".into(),
            rejection: None,
            usage: None,
        }
    }

    #[test]
    fn upstream_5xx_triggers_failover() {
        let err =
            PipeError::upstream_response(reqwest::StatusCode::SERVICE_UNAVAILABLE, "provider unavailable".to_string());
        assert_eq!(err.upstream_status(), Some(503));
        assert!(PipeExecutor::is_failover_eligible(&err));
    }

    #[test]
    fn transport_timeout_triggers_failover() {
        assert!(PipeExecutor::is_failover_eligible(&PipeError::RequestTimeout("provider timed out".into())));
    }

    #[test]
    fn connection_failure_triggers_failover() {
        // A transport-level connection failure (refused / reset / unreachable)
        // surfaces as RequestFailed and is eligible for a backup.
        assert!(PipeExecutor::is_failover_eligible(&PipeError::RequestFailed("connection refused".into())));
    }

    #[test]
    fn provider_auth_failure_triggers_failover() {
        // A provider auth failure (401/403) maps to UpstreamResponse and is
        // intentionally failover-eligible: a backup provider may hold valid
        // credentials, so trying it is the desired behavior. This is a
        // locked-in product decision — do not re-classify auth failures as
        // suppressed without also updating the operational spec. A refusal of
        // the caller's own key is a different error (see
        // `a_refused_caller_key_never_fails_over`).
        for status in [reqwest::StatusCode::UNAUTHORIZED, reqwest::StatusCode::FORBIDDEN] {
            let err = PipeError::upstream_failure(status, false, "", "Incorrect API key provided: sk-...abcd");
            assert!(
                PipeExecutor::is_failover_eligible(&err),
                "provider auth failure {status} on a stored key must be failover-eligible"
            );
            assert!(
                !err.to_string()
                    .contains("sk-"),
                "a stored key's refusal drops the provider's body, which can echo the key: {err}"
            );
        }
    }

    #[test]
    fn a_refused_caller_key_never_fails_over() {
        for status in [reqwest::StatusCode::UNAUTHORIZED, reqwest::StatusCode::FORBIDDEN] {
            let err = PipeError::upstream_failure(status, true, "", "Incorrect API key sk-...abcd");
            assert!(matches!(err, PipeError::CallerKeyRejected { .. }));
            assert_eq!(err.upstream_status(), Some(status.as_u16()));
            assert!(!PipeExecutor::is_failover_eligible(&err), "{status}: a refused caller key must not fail over");
            assert!(
                !err.to_string()
                    .contains("sk-"),
                "the provider's body, which can echo the key, is not kept"
            );
        }
        // Any other status on the caller's key is an ordinary upstream failure.
        let err = PipeError::upstream_failure(reqwest::StatusCode::SERVICE_UNAVAILABLE, true, "", "down");
        assert!(PipeExecutor::is_failover_eligible(&err));
        assert!(
            err.to_string()
                .contains("down"),
            "an ordinary failure keeps its body"
        );
    }

    #[test]
    fn a_providers_own_bad_key_answer_is_a_refusal_of_the_key() {
        let gemini = r#"{"error":{"code":400,"message":"API key not valid. Please pass a valid API key.","status":"INVALID_ARGUMENT","details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"API_KEY_INVALID","domain":"googleapis.com"}]}}"#;
        let compatible = r#"{"error":{"message":"Incorrect API key provided: sk-...abcd","type":"invalid_request_error","code":"invalid_api_key"}}"#;
        let xai = r#"{"code":"Client specified an invalid argument","error":"Incorrect API key provided: sk***kA. You can obtain an API key from https://console.x.ai."}"#;
        for body in [gemini, compatible, xai] {
            let caller = PipeError::upstream_failure(reqwest::StatusCode::BAD_REQUEST, true, "", body);
            assert!(matches!(caller, PipeError::CallerKeyRejected { status: 400 }), "{caller:?}");
            assert!(!PipeExecutor::is_failover_eligible(&caller), "a refused caller key is never retried elsewhere");

            let stored = PipeError::upstream_failure(reqwest::StatusCode::BAD_REQUEST, false, "", body);
            assert!(PipeExecutor::is_failover_eligible(&stored), "a refused stored key still fails over");
            assert!(
                !stored
                    .to_string()
                    .contains("sk")
                    && !stored
                        .to_string()
                        .contains("API_KEY_INVALID"),
                "the refusal's body is dropped: {stored}"
            );
        }
        // An ordinary bad request is not a refusal of the key, and keeps its body.
        let bad_request = PipeError::upstream_failure(
            reqwest::StatusCode::BAD_REQUEST,
            true,
            "",
            r#"{"error":"max_tokens too large"}"#,
        );
        assert!(matches!(bad_request, PipeError::UpstreamResponse { .. }));
        assert!(
            bad_request
                .to_string()
                .contains("max_tokens")
        );
    }

    #[test]
    fn a_budget_refusal_moves_on_only_from_an_upstream_and_never_trips_the_breaker() {
        let refused = |call| PipeError::BudgetExhausted {
            reason: "member 'm' monthly budget $1.00 reached (spent $1.00)".to_string(),
            call,
        };
        let upstream = refused(BudgetedCall::Upstream);
        let stage = refused(BudgetedCall::Stage);
        for err in [&upstream, &stage] {
            assert!(!PipeExecutor::is_failover_eligible(err), "a spent budget is not a provider-health failure");
            assert_eq!(PipeExecutor::reason_of(err), "budget_exhausted");
            assert!(
                err.budget_refusal()
                    .is_some_and(|r| r.contains("monthly budget"))
            );
        }
        assert!(PipeExecutor::moves_to_next_target(&upstream), "another target may run on an owned key");
        assert!(!PipeExecutor::moves_to_next_target(&stage), "a refused safety stage is final");

        let wrapped =
            upstream.with_incurred_usage(StageUsage::call(1, 1, 0.5, 0, KeySource::Customer), StageUsage::default());
        assert!(matches!(wrapped, PipeError::WithIncurredUsage { .. }), "precondition: wrapped");
        assert!(
            wrapped
                .budget_refusal()
                .is_some()
        );
        assert!(wrapped.upstream_unaffordable());

        // A pool that no target served returns the budget's refusal when one
        // was refused for it, and its last error otherwise.
        let exhausted = PipeExecutor::pool_exhausted(
            Err(PipeError::RequestFailed("down".into())),
            Some(PlatformRefusal::BudgetSpent("spent".into())),
        );
        assert!(matches!(
            exhausted,
            Err(PipeError::BudgetExhausted {
                call: BudgetedCall::Upstream,
                ..
            })
        ));
        let failed = PipeExecutor::pool_exhausted(Err(PipeError::RequestFailed("down".into())), None);
        assert!(matches!(failed, Err(PipeError::RequestFailed(_))));
    }

    #[test]
    fn an_unmetered_refusal_moves_on_like_a_budget_refusal_and_keeps_its_kind() {
        use crate::pipes::metering::Unmetered;
        let upstream = PipeError::NotMetered {
            unmetered: Unmetered::Batch,
            call: BudgetedCall::Upstream,
        };
        let stage = PipeError::NotMetered {
            unmetered: Unmetered::Endpoint,
            call: BudgetedCall::Stage,
        };
        assert!(PipeExecutor::moves_to_next_target(&upstream), "another target may run on an owned key");
        assert!(!PipeExecutor::moves_to_next_target(&stage));
        assert!(!PipeExecutor::is_failover_eligible(&upstream), "not a provider-health failure");
        assert_eq!(PipeExecutor::reason_of(&upstream), "not_metered");
        assert_eq!(upstream.budget_refusal(), None, "not a spent budget");
        assert_eq!(upstream.platform_refusal(), Some(PlatformRefusal::NotMetered(Unmetered::Batch)));

        let exhausted =
            PipeExecutor::pool_exhausted(Err(PipeError::RequestFailed("down".into())), upstream.platform_refusal());
        assert!(
            matches!(&exhausted, Err(e) if e.not_metered() == Some(Unmetered::Batch) && e.upstream_unaffordable()),
            "{:?}",
            exhausted.err()
        );
    }

    #[test]
    fn retry_exhausted_triggers_failover() {
        assert!(PipeExecutor::is_failover_eligible(&PipeError::RetryExhausted("all retry attempts failed".into())));
    }

    #[test]
    fn invalid_response_triggers_failover() {
        assert!(PipeExecutor::is_failover_eligible(&PipeError::InvalidResponse("malformed body".into())));
    }

    #[test]
    fn circuit_breaker_open_triggers_failover() {
        // An open circuit is failover-eligible: in the buffered `execute()`
        // path an open primary breaker routes the request to ordered backup
        // providers instead of failing the caller with a 503, and an open
        // circuit surfaced during a failover attempt is treated as retriable
        // rather than final. This test pins the classification; the
        // state-machine tests below cover the breaker lifecycle.
        assert!(PipeExecutor::is_failover_eligible(&PipeError::CircuitBreakerOpen("circuit open".into())));
    }

    #[test]
    fn rate_limit_rejection_does_not_trigger_failover() {
        // The gateway's own rate limit must not fail over to another provider.
        assert!(!PipeExecutor::is_failover_eligible(&PipeError::RateLimitExceeded("Request limit: 10/min".into())));
    }

    #[test]
    fn prompt_guard_rejection_does_not_trigger_failover() {
        // A content rejection must never be retried against a backup — doing so
        // would bypass the guardrail decision.
        assert!(!PipeExecutor::is_failover_eligible(&prompt_guard_rejected_error()));
    }

    #[test]
    fn reason_of_maps_every_error_class_to_a_stable_label() {
        // The failover `reason` label vocabulary is closed; each PipeError class
        // maps to exactly one stable, low-cardinality string. Pinning the full
        // mapping stops a future variant rename from silently changing a metric
        // label or leaking an unbounded value.
        let cases: [(PipeError, &str); 10] = [
            (
                PipeError::upstream_response(reqwest::StatusCode::SERVICE_UNAVAILABLE, "down".into()),
                "upstream_response",
            ),
            (PipeError::CallerKeyRejected { status: 401 }, "caller_key_rejected"),
            (
                PipeError::BudgetExhausted {
                    reason: "spent".into(),
                    call: BudgetedCall::Upstream,
                },
                "budget_exhausted",
            ),
            (PipeError::RequestTimeout("t".into()), "timeout"),
            (PipeError::RequestFailed("f".into()), "request_failed"),
            (PipeError::RetryExhausted("r".into()), "retry_exhausted"),
            (PipeError::InvalidResponse("i".into()), "invalid_response"),
            (PipeError::CircuitBreakerOpen("c".into()), "circuit_open"),
            (PipeError::RateLimitExceeded("rl".into()), "rate_limit"),
            (
                PipeError::PromptGuardRejected {
                    status_code: 403,
                    body: "blocked".into(),
                    content_type: "application/json".into(),
                    rejection: None,
                    usage: None,
                },
                "prompt_guard",
            ),
        ];
        for (err, expected) in &cases {
            assert_eq!(PipeExecutor::reason_of(err), *expected);
        }
    }

    fn rate_limited_executor(
        enabled: bool,
        rpm: u32,
    ) -> PipeExecutor {
        let mut config = PipeConfig::new(
            "rl-pipe".to_string(),
            "RL".to_string(),
            crate::pipes::config::PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        config.rate_limit = Some(crate::pipes::config::RateLimit {
            enabled,
            requests_per_minute: rpm,
            tokens_per_minute: None,
        });
        PipeExecutor::new(&config)
    }

    #[tokio::test]
    async fn enforce_rate_limit_counts_requests_and_blocks_over_cap() {
        let exec = rate_limited_executor(true, 2);
        // Two requests fit within the per-minute cap.
        assert!(
            exec.enforce_rate_limit()
                .await
                .is_ok(),
            "1st request is within the cap"
        );
        assert!(
            exec.enforce_rate_limit()
                .await
                .is_ok(),
            "2nd request is within the cap"
        );
        // The third request trips the request limit.
        match exec
            .enforce_rate_limit()
            .await
        {
            Err(PipeError::RateLimitExceeded(msg)) => {
                assert!(msg.contains("Request limit"), "message names the request limit, got: {msg}");
            }
            other => panic!("expected RateLimitExceeded, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn enforce_rate_limit_noop_when_disabled_or_absent() {
        // A disabled limit never blocks, even past its numeric cap.
        let disabled = rate_limited_executor(false, 1);
        for _ in 0..5 {
            assert!(
                disabled
                    .enforce_rate_limit()
                    .await
                    .is_ok(),
                "a disabled rate limit must never block"
            );
        }
        // No rate_limit config at all never blocks.
        let config = PipeConfig::new(
            "no-rl".to_string(),
            "NoRL".to_string(),
            crate::pipes::config::PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        let absent = PipeExecutor::new(&config);
        for _ in 0..5 {
            assert!(
                absent
                    .enforce_rate_limit()
                    .await
                    .is_ok(),
                "an absent rate limit must never block"
            );
        }
    }

    fn lb_executor() -> PipeExecutor {
        let config = PipeConfig::new(
            "lb-pipe".to_string(),
            "LB".to_string(),
            crate::pipes::config::PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        PipeExecutor::new(&config)
    }

    #[test]
    fn weighted_pick_distributes_by_weight() {
        let exec = lb_executor();
        // Pool weights: primary=3, target=1. Over one full cycle of 4 picks the
        // primary must be selected 3 times and the target once.
        let mut counts = [0usize; 2];
        for _ in 0..4 {
            counts[exec.weighted_pick(&[3, 1])] += 1;
        }
        assert_eq!(counts, [3, 1]);
    }

    #[test]
    fn weighted_pick_skips_zero_weight_member() {
        let exec = lb_executor();
        // Primary weight 0 must never be first-picked; every selection lands on
        // the only positive-weight member (index 1).
        for _ in 0..5 {
            assert_eq!(exec.weighted_pick(&[0, 2]), 1);
        }
    }

    #[test]
    fn weighted_pick_zero_total_falls_back_to_primary() {
        let exec = lb_executor();
        assert_eq!(exec.weighted_pick(&[0, 0]), 0);
    }

    #[test]
    fn load_balance_order_starts_at_pick_then_covers_pool() {
        assert_eq!(PipeExecutor::load_balance_order(0, 3), vec![0, 1, 2]);
        assert_eq!(PipeExecutor::load_balance_order(2, 3), vec![2, 0, 1]);
        assert_eq!(PipeExecutor::load_balance_order(1, 2), vec![1, 0]);
    }

    fn lb_target(
        provider: &str,
        model: &str,
    ) -> crate::pipes::judge_jury::LLMTarget {
        crate::pipes::judge_jury::LLMTarget {
            provider_type: provider.to_string(),
            model: model.to_string(),
            endpoint_url: "https://example.com".to_string(),
            api_key_secret: None,
            parameters: None,
            timeout_secs: 30,
            capabilities: None,
            api_schema: "openai".to_string(),
            headers: Vec::new(),
            pricing: None,
        }
    }

    fn lb_executor_with_pool() -> PipeExecutor {
        use crate::pipes::config::{LoadBalancingConfig, LoadBalancingStrategy, WeightedTarget};
        let mut config = PipeConfig::new(
            "lb-pool".to_string(),
            "LB".to_string(),
            crate::pipes::config::PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        config.load_balancing = Some(LoadBalancingConfig {
            enabled: true,
            strategy: LoadBalancingStrategy::LowestLatency,
            primary_weight: 1,
            targets: vec![
                WeightedTarget {
                    llm: lb_target("anthropic", "claude"),
                    weight: 1,
                },
                WeightedTarget {
                    llm: lb_target("gemini", "gemini-pro"),
                    weight: 1,
                },
            ],
        });
        PipeExecutor::new(&config)
    }

    #[test]
    fn lowest_latency_prefers_fastest_member() {
        let exec = lb_executor_with_pool();
        exec.record_lb_latency(0, 100);
        exec.record_lb_latency(1, 40);
        exec.record_lb_latency(2, 200);
        assert_eq!(exec.lowest_latency_start(&[1, 1, 1]), 1);
    }

    #[test]
    fn lowest_latency_tries_unsampled_first() {
        let exec = lb_executor_with_pool();
        // No samples → all latency 0 → lowest positive-weight index.
        assert_eq!(exec.lowest_latency_start(&[1, 1, 1]), 0);
        assert_eq!(exec.lowest_latency_start(&[0, 1, 1]), 1);
    }

    #[test]
    fn record_lb_latency_is_ewma() {
        let exec = lb_executor_with_pool();
        exec.record_lb_latency(0, 80); // first sample seeds directly → 80
        exec.record_lb_latency(0, 160); // (80*7 + 160)/8 = 90
        exec.record_lb_latency(1, 100);
        exec.record_lb_latency(2, 500);
        // Member 0's smoothed latency (90) beats members 1 (100) and 2 (500).
        assert_eq!(exec.lowest_latency_start(&[1, 1, 1]), 0);
    }

    #[test]
    fn lowest_cost_skips_zero_weight_member() {
        let exec = lb_executor_with_pool();
        let lb = exec
            .config
            .load_balancing
            .clone()
            .expect("pool");
        // Without catalog pricing in unit tests every member costs the same
        // (f64::MAX), so the lowest positive-weight index wins and the
        // zero-weight primary is skipped.
        assert_eq!(exec.lowest_cost_start(&lb, &[0, 1, 1]), 1);
    }

    #[test]
    fn explicit_override_pricing_uses_positive_override() {
        let pricing =
            explicit_override_pricing(Some(0.01), Some(0.02)).expect("positive override should produce pricing");
        assert_eq!(pricing.input_price_per_million, 10.0);
        assert_eq!(pricing.output_price_per_million, 20.0);
    }

    #[test]
    fn explicit_override_pricing_ignores_zero_override() {
        // The dashboard seeds 0.0 defaults; a zero override must fall through
        // (return None) so the caller resolves catalog pricing instead of $0.
        assert!(explicit_override_pricing(Some(0.0), Some(0.0)).is_none());
        assert!(explicit_override_pricing(Some(0.01), Some(0.0)).is_none());
        assert!(explicit_override_pricing(Some(0.0), Some(0.02)).is_none());
    }

    #[test]
    fn explicit_override_pricing_ignores_missing_or_negative_override() {
        assert!(explicit_override_pricing(None, None).is_none());
        assert!(explicit_override_pricing(Some(0.01), None).is_none());
        assert!(explicit_override_pricing(None, Some(0.02)).is_none());
        assert!(explicit_override_pricing(Some(-0.01), Some(0.02)).is_none());
    }

    // ── Circuit-breaker state machine ──
    //
    // The breaker is what turns a provider's repeated upstream failures into a
    // `CircuitBreakerOpen` error, which is itself failover-eligible (see
    // `circuit_breaker_open_triggers_failover`). These tests pin the full
    // Closed → Open → HalfOpen → {Closed, Open} lifecycle so "primary/backup
    // circuit open behavior" is covered at the state-machine level regardless
    // of which provider slot the breaker guards.

    fn breaker(
        failure_threshold: u32,
        timeout_seconds: u64,
    ) -> CircuitBreakerState {
        CircuitBreakerState::new(CircuitBreakerConfig {
            failure_threshold,
            timeout_seconds,
            reset_timeout_seconds: 30,
        })
    }

    #[test]
    fn circuit_opens_after_threshold_failures() {
        let mut cb = breaker(3, 60);
        // Closed: requests are allowed and failures accumulate.
        assert!(cb.can_request().is_ok());
        cb.record_failure();
        cb.record_failure();
        assert!(cb.can_request().is_ok(), "below threshold the circuit stays closed");
        // The threshold-th failure opens the circuit and blocks requests.
        cb.record_failure();
        assert!(matches!(cb.state, CircuitState::Open { .. }));
        match cb.can_request() {
            Err(PipeError::CircuitBreakerOpen(_)) => {}
            other => panic!("expected CircuitBreakerOpen while open, got {other:?}"),
        }
    }

    #[test]
    fn open_circuit_transitions_to_half_open_after_timeout() {
        // A zero-second open timeout means the very next `can_request` promotes
        // the breaker to HalfOpen (a trial request) without any real waiting.
        let mut cb = breaker(1, 0);
        cb.record_failure();
        assert!(matches!(cb.state, CircuitState::Open { .. }));
        assert!(cb.can_request().is_ok(), "an elapsed open timeout allows a half-open trial");
        assert!(matches!(cb.state, CircuitState::HalfOpen));
    }

    #[test]
    fn half_open_success_closes_circuit() {
        let mut cb = breaker(1, 0);
        cb.record_failure(); // -> Open
        cb.can_request()
            .expect("half-open trial allowed"); // Open -> HalfOpen
        cb.record_success(); // HalfOpen -> Closed
        assert!(matches!(cb.state, CircuitState::Closed));
        assert!(cb.can_request().is_ok());
    }

    #[test]
    fn half_open_failure_reopens_circuit() {
        let mut cb = breaker(1, 60);
        cb.record_failure(); // -> Open
        cb.state = CircuitState::HalfOpen; // simulate an elapsed timeout
        cb.record_failure(); // HalfOpen -> Open
        assert!(matches!(cb.state, CircuitState::Open { .. }));
        assert!(cb.can_request().is_err(), "a failed half-open trial re-opens the circuit");
    }

    // ── Parameter override policy tests ──
    //
    // Policy semantics:
    //   GatewayWins     — gateway value always wins (overrides client, injects if absent).
    //   InjectIfMissing — gateway value injected only when the client omitted it.
    //   ClientWins      — client is authoritative; the gateway never injects,
    //                     even when the client omitted the value (passthrough).
    use crate::pipes::config::{PipeConfig, PipeType};
    use crate::pipes::test_upstreams::CaptureUpstream;
    use crate::pipes::types::llm::{LLMProvider, OverridePolicy, ParameterOverrideConfig};
    use crate::url_validation::test_service_endpoints;
    use serde_json::json;

    fn openai_provider(model: &str) -> LLMProvider {
        LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: model.to_string(),
            api_key_secret: Some("secret-id".to_string()),
            organization_id: None,
            base_url: None,
            temperature: Some(0.7),
            max_tokens: Some(1000),
            top_p: Some(0.9),
            frequency_penalty: Some(0.1),
            presence_penalty: Some(0.2),
        }
    }

    fn test_executor() -> PipeExecutor {
        let config = PipeConfig::new(
            "p-test".to_string(),
            "Test".to_string(),
            PipeType::LLM {
                provider: Box::new(openai_provider("gpt-4")),
                endpoint_path: None,
            },
        );
        PipeExecutor::new(&config)
    }

    fn web_fetch_tools(enabled: bool) -> crate::pipes::server_tools::ServerToolsConfig {
        crate::pipes::server_tools::ServerToolsConfig {
            enabled: true,
            max_iterations: 3,
            web_search: None,
            web_fetch: Some(crate::pipes::server_tools::WebFetchConfig { enabled, ..Default::default() }),
        }
    }

    fn web_fetch_call(url: &str) -> crate::pipes::server_tools::ServerToolInvocation {
        crate::pipes::server_tools::ServerToolInvocation {
            tool_call_id: "call-1".to_string(),
            name: "web_fetch".to_string(),
            arguments: json!({ "url": url }),
        }
    }

    #[tokio::test]
    async fn web_fetch_refuses_private_link_local_and_metadata_targets() {
        let exec = test_executor();
        for url in [
            "http://10.0.0.5/",
            "http://172.16.0.9/",
            "http://192.168.1.10/",
            "http://169.254.170.23/v1/credentials",
            "http://169.254.10.1/",
            "http://[fe80::1]/",
            "http://[fd00:ec2::23]/",
            "http://[::ffff:10.0.0.5]/",
            "http://127.0.0.1/",
        ] {
            let (message, citations, stage) = exec
                .run_web_fetch(&web_fetch_tools(true), &web_fetch_call(url))
                .await;
            let stage = stage.expect("a refused fetch is recorded");
            assert_eq!(stage.decision, StageDecision::Flag, "{url}");
            assert!(
                stage
                    .detail
                    .as_deref()
                    .is_some_and(|detail| detail.starts_with("URL blocked by SSRF guard: ")),
                "{url}: {:?}",
                stage.detail
            );
            assert_eq!(message["content"], "Tool call denied: URL blocked by SSRF guard", "{url}");
            assert!(citations.is_empty(), "{url}");
            assert_eq!(message["tool_call_id"], "call-1", "{url}");
        }
    }

    #[tokio::test]
    async fn fetch_public_url_refuses_blocked_addresses_at_connect_time() {
        let exec = test_executor();
        for raw in ["http://10.0.0.5/", "http://[64:ff9b::a00:5]/", "http://100.64.0.1/", "http://localhost:9/"] {
            let url = url::Url::parse(raw).unwrap();
            assert!(
                matches!(
                    exec.fetch_public_url(&url)
                        .await,
                    Err(FetchError::Blocked(_))
                ),
                "{raw} should be refused before connecting"
            );
        }
    }

    #[tokio::test]
    async fn fetch_public_url_returns_the_body_of_an_allowed_page() {
        let page = CaptureUpstream::answering("fetched page").await;
        let _allowed = test_service_endpoints::allow(std::slice::from_ref(&page.url));

        let body = test_executor()
            .fetch_public_url(&url::Url::parse(&page.url).unwrap())
            .await
            .unwrap_or_else(|_| panic!("an allowlisted page should be fetched"));

        assert!(body.contains("fetched page"), "{body}");
        assert_eq!(page.requests(), 1);
    }

    #[tokio::test]
    async fn fetch_public_url_reports_an_error_status_as_a_failed_fetch() {
        let page = CaptureUpstream::failing(axum::http::StatusCode::INTERNAL_SERVER_ERROR).await;
        let _allowed = test_service_endpoints::allow(std::slice::from_ref(&page.url));

        let result = test_executor()
            .fetch_public_url(&url::Url::parse(&page.url).unwrap())
            .await;

        let Err(FetchError::Failed(error)) = result else {
            panic!("an error status should be a failed fetch");
        };
        assert!(error.contains("500"), "{error}");
        assert_eq!(page.requests(), 1);
    }

    #[test]
    fn a_fetch_denial_tells_the_model_only_a_generic_reason() {
        let error = "fetch failed: connection refused by 10.0.0.5:80".to_string();
        let cases = [
            (FetchError::Blocked(error.clone()), "URL blocked by SSRF guard"),
            (FetchError::Failed(error.clone()), "URL could not be fetched"),
        ];
        for (fetch_error, expected) in cases {
            let (reason, detail) = fetch_error.denial();
            let message = crate::pipes::server_tools::denied_message("call-1", reason);
            assert_eq!(message["content"], format!("Tool call denied: {expected}"));
            assert_eq!(detail, format!("{expected}: {error}"));
        }
    }

    #[tokio::test]
    async fn web_fetch_disabled_is_refused_before_the_url_is_checked() {
        let (_, _, stage) = test_executor()
            .run_web_fetch(&web_fetch_tools(false), &web_fetch_call("https://example.com/"))
            .await;
        assert_eq!(
            stage
                .and_then(|stage| stage.detail)
                .as_deref(),
            Some("web_fetch is not enabled on this surface")
        );
    }

    fn apply(
        provider: &LLMProvider,
        request: &mut Value,
        policy: &ParameterOverrideConfig,
    ) {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let profile = crate::pipes::request_shaping::builtin_profile(provider.api_schema(), provider.get_model(), None);
        test_executor().apply_parameter_overrides(provider, request, policy, &profile);
    }

    // ── Extra upstream headers ──
    //
    // The surface's own upstream gets them (alongside the provider credential);
    // anything else the same config may route to does not.

    async fn upstream_header_executor() -> PipeExecutor {
        let mut config = PipeConfig::new(
            "p-headers".to_string(),
            "Headers".to_string(),
            PipeType::LLM {
                provider: Box::new(openai_provider("gpt-4")),
                endpoint_path: None,
            },
        );
        config.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "tunnel-secret".to_string(),
        }];
        let exec = PipeExecutor::new(&config);
        // Seed the resolver cache so the test needs no secrets backend.
        let mut cache = exec
            .cached_api_keys
            .write()
            .await;
        cache.insert("secret-id".to_string(), cached_secret("model-key"));
        cache.insert("tunnel-secret".to_string(), cached_secret("tunnel-key"));
        drop(cache);
        exec
    }

    fn cached_secret(value: &str) -> ResolvedSecret {
        ResolvedSecret {
            value: value.to_string(),
            tenant_id: None,
        }
    }

    /// Resolve `provider`'s request headers for a call to its own endpoint.
    async fn headers_for(
        exec: &PipeExecutor,
        provider: &LLMProvider,
    ) -> Result<Vec<(String, String)>, PipeError> {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        exec.resolve_provider_headers(
            provider,
            exec.surface_headers_for(provider),
            &provider.get_endpoint(),
            true,
            &CallerCredentials::default(),
            UpstreamCall::Poll,
        )
        .await
        .map(|resolved| resolved.headers)
    }

    fn header_value<'a>(
        headers: &'a [(String, String)],
        name: &str,
    ) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn upstream_headers_ride_beside_the_provider_credential() {
        let exec = upstream_header_executor().await;
        let provider = openai_provider("gpt-4");
        let headers = headers_for(&exec, &provider)
            .await
            .expect("headers resolve");
        assert_eq!(header_value(&headers, "Authorization"), Some("Bearer model-key"));
        assert_eq!(header_value(&headers, "x-asp-api-key"), Some("tunnel-key"));
    }

    #[tokio::test]
    async fn upstream_headers_never_reach_another_provider() {
        // A Decider candidate runs under this same config with its own
        // provider; the base upstream's credential must not follow it.
        let exec = upstream_header_executor().await;
        let other = LLMProvider::Anthropic {
            provider_type: "anthropic".to_string(),
            model: "claude-3-haiku".to_string(),
            api_key_secret: None,
            version: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        let headers = headers_for(&exec, &other)
            .await
            .expect("headers resolve");
        assert_eq!(header_value(&headers, "x-asp-api-key"), None);
    }

    #[tokio::test]
    async fn an_unresolvable_upstream_header_secret_fails_the_request() {
        let mut config = PipeConfig::new(
            "p-missing".to_string(),
            "Missing".to_string(),
            PipeType::LLM {
                provider: Box::new(openai_provider("gpt-4")),
                endpoint_path: None,
            },
        );
        config.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "absent-secret".to_string(),
        }];
        let exec = PipeExecutor::new(&config);
        exec.cached_api_keys
            .write()
            .await
            .insert("secret-id".to_string(), cached_secret("model-key"));

        let provider = openai_provider("gpt-4");
        let err = headers_for(&exec, &provider)
            .await
            .expect_err("an unresolvable upstream header secret must fail the request");
        assert!(
            matches!(&err, PipeError::RequestFailed(message) if message == crate::pipes::upstream_headers::CREDENTIAL_UNAVAILABLE),
            "the caller must get the generic credential error, got: {err:?}"
        );
        assert!(
            !format!("{err:?}").contains("absent-secret"),
            "the caller must not learn the secret reference, got: {err:?}"
        );
    }

    // ── Standard body parameters (temperature) ──

    #[test]
    fn gateway_wins_overrides_client_temperature() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::GatewayWins),
            ..Default::default()
        };
        let mut req = json!({ "temperature": 0.1, "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["temperature"], json!(0.7));
    }

    #[test]
    fn gateway_wins_injects_temperature_when_absent() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::GatewayWins),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["temperature"], json!(0.7));
    }

    #[test]
    fn client_wins_keeps_client_temperature() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "temperature": 0.1, "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["temperature"], json!(0.1));
    }

    #[test]
    fn client_wins_does_not_inject_temperature_when_absent() {
        // The key behaviour: ClientWins never injects, even when the client
        // omitted the value.
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert!(
            req.get("temperature")
                .is_none()
        );
    }

    #[test]
    fn inject_if_missing_injects_temperature_when_absent() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::InjectIfMissing),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["temperature"], json!(0.7));
    }

    #[test]
    fn inject_if_missing_keeps_client_temperature() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            temperature: Some(OverridePolicy::InjectIfMissing),
            ..Default::default()
        };
        let mut req = json!({ "temperature": 0.1, "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["temperature"], json!(0.1));
    }

    // ── Model override ──

    #[test]
    fn gateway_wins_overrides_client_model() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            model: Some(OverridePolicy::GatewayWins),
            ..Default::default()
        };
        let mut req = json!({ "model": "client-model", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["model"], json!("gpt-4"));
    }

    #[test]
    fn client_wins_keeps_client_model() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            model: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "model": "client-model", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["model"], json!("client-model"));
    }

    // ── Identity pass-through (forward_caller_token) ──

    fn anthropic_provider(model: &str) -> LLMProvider {
        LLMProvider::Anthropic {
            provider_type: "anthropic".to_string(),
            model: model.to_string(),
            api_key_secret: Some("stale-secret".to_string()),
            version: Some("2023-06-01".to_string()),
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        }
    }

    /// The credentials of a request whose `Authorization` and distinct
    /// upstream header are `authorization` and `upstream`.
    fn forwarded(
        authorization: Option<&str>,
        upstream: Option<&str>,
    ) -> CallerCredentials {
        CallerCredentials {
            authorization: authorization.map(str::to_string),
            upstream_authorization: upstream.map(str::to_string),
            provider_key: None,
        }
    }

    #[test]
    fn passthrough_forwards_caller_bearer_and_strips_stored_key() {
        // OpenAI's build_headers would emit the stored secret ref as a bearer;
        // pass-through must strip it and forward the caller's token instead.
        let provider = openai_provider("gpt-4");
        let headers = build_caller_token_headers(&provider, &forwarded(Some("Bearer user-jwt-123"), None)).unwrap();
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer user-jwt-123".to_string())]);
    }

    #[test]
    fn passthrough_prefers_upstream_token_over_caller_token() {
        // When the caller supplies a distinct upstream token, it is forwarded
        // in preference to the front-door token so the front door and the
        // upstream can authenticate with different identities.
        let provider = openai_provider("gpt-4");
        let headers =
            build_caller_token_headers(&provider, &forwarded(Some("Bearer front-door"), Some("Bearer upstream-graph")))
                .unwrap();
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer upstream-graph".to_string())]);
    }

    #[test]
    fn passthrough_falls_back_to_caller_when_upstream_blank() {
        // A blank/absent upstream token falls back to the front-door token.
        let provider = openai_provider("gpt-4");
        let headers =
            build_caller_token_headers(&provider, &forwarded(Some("Bearer front-door"), Some("Bearer "))).unwrap();
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer front-door".to_string())]);
    }

    #[test]
    fn passthrough_preserves_non_auth_headers() {
        // Anthropic's `anthropic-version` (non-auth) is kept; `x-api-key` dropped.
        let provider = anthropic_provider("claude-x");
        let headers = build_caller_token_headers(&provider, &forwarded(Some("Bearer tok"), None)).unwrap();
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "anthropic-version" && v == "2023-06-01")
        );
        assert!(
            headers
                .iter()
                .any(|(n, v)| n == "Authorization" && v == "Bearer tok")
        );
        assert!(
            !headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("x-api-key"))
        );
    }

    #[test]
    fn passthrough_returns_none_without_bearer_token() {
        let provider = openai_provider("gpt-4");
        assert!(build_caller_token_headers(&provider, &forwarded(None, None)).is_none());
        assert!(build_caller_token_headers(&provider, &forwarded(Some("Basic abc"), None)).is_none());
        assert!(build_caller_token_headers(&provider, &forwarded(Some("Bearer "), None)).is_none());
    }

    #[test]
    fn auth_header_name_detection() {
        assert!(is_auth_header_name("Authorization"));
        assert!(is_auth_header_name("x-api-key"));
        assert!(is_auth_header_name("API-KEY"));
        assert!(is_auth_header_name("x-goog-api-key"));
        assert!(!is_auth_header_name("anthropic-version"));
        assert!(!is_auth_header_name("content-type"));
    }

    #[test]
    fn client_wins_does_not_inject_model_when_absent() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            model: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert!(req.get("model").is_none());
    }

    #[test]
    fn inject_if_missing_injects_model_when_absent() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            model: Some(OverridePolicy::InjectIfMissing),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["model"], json!("gpt-4"));
    }

    #[test]
    fn no_model_policy_still_injects_gateway_model_when_absent() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig::default();
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["model"], json!("gpt-4"));
    }

    // ── reasoning_effort (reasoning-capable model) ──

    #[test]
    fn gateway_wins_sets_reasoning_effort() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::GatewayWins),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["reasoning_effort"], json!("medium"));
    }

    #[test]
    fn client_wins_does_not_inject_reasoning_effort() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert!(
            req.get("reasoning_effort")
                .is_none()
        );
    }

    #[test]
    fn inject_if_missing_sets_reasoning_effort_when_absent() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::InjectIfMissing),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["reasoning_effort"], json!("medium"));
    }

    #[test]
    fn inject_if_missing_keeps_client_reasoning_effort() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::InjectIfMissing),
            ..Default::default()
        };
        let mut req = json!({ "reasoning_effort": "high", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["reasoning_effort"], json!("high"));
    }

    #[test]
    fn gateway_wins_uses_configured_reasoning_effort_value() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::GatewayWins),
            reasoning_effort_value: Some("high".to_string()),
            ..Default::default()
        };
        let mut req = json!({ "reasoning_effort": "low", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["reasoning_effort"], json!("high"));
    }

    #[test]
    fn blank_reasoning_effort_value_falls_back_to_medium() {
        let provider = openai_provider("gpt-5");
        let policy = ParameterOverrideConfig {
            reasoning_effort: Some(OverridePolicy::GatewayWins),
            reasoning_effort_value: Some("   ".to_string()),
            ..Default::default()
        };
        let mut req = json!({ "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["reasoning_effort"], json!("medium"));
    }

    // ── api_key (request body) ──

    #[test]
    fn gateway_wins_strips_client_body_api_key() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            api_key: Some(OverridePolicy::GatewayWins),
            ..Default::default()
        };
        let mut req = json!({ "api_key": "client-key", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert!(req.get("api_key").is_none());
    }

    #[test]
    fn client_wins_keeps_client_body_api_key() {
        let provider = openai_provider("gpt-4");
        let policy = ParameterOverrideConfig {
            api_key: Some(OverridePolicy::ClientWins),
            ..Default::default()
        };
        let mut req = json!({ "api_key": "client-key", "messages": [] });
        apply(&provider, &mut req, &policy);
        assert_eq!(req["api_key"], json!("client-key"));
    }

    // ── Target headers and prices, end to end ──
    //
    // Each upstream a surface calls is a loopback capture server; every test
    // asserts which `x-asp-api-key` values each one received. The secret
    // values are distinct per upstream so a header that reaches the wrong
    // upstream shows up by value.

    mod targets_end_to_end {
        use super::*;
        use crate::pipes::test_upstreams::CaptureUpstream;
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        use crate::url_validation::test_service_endpoints;
        use axum::http::StatusCode;

        const KEY_HEADER: &str = "x-asp-api-key";

        fn store() -> Arc<dyn SecretsStore> {
            Arc::new(MemorySecretsStore::with(vec![
                secret("uuid-model", "model-key", "MODEL", None),
                secret("uuid-base", "base-tunnel", "BASE", None),
                secret("uuid-backup", "backup-tunnel", "BACKUP", None),
                secret("uuid-pool", "pool-tunnel", "POOL", None),
                secret("uuid-judge", "judge-tunnel", "JUDGE", None),
                secret("uuid-juror", "juror-tunnel", "JUROR", None),
                secret("uuid-router", "router-tunnel", "ROUTER", None),
                secret("uuid-candidate", "candidate-tunnel", "CANDIDATE", None),
                secret("uuid-candidate-2", "candidate-2-tunnel", "CANDIDATE-2", None),
                secret("uuid-merger", "merger-tunnel", "MERGER", None),
            ]))
        }

        fn surface_secrets() -> crate::secrets::SurfaceSecrets {
            crate::secrets::SurfaceSecrets::new(Some(store()), None)
        }

        fn key_header(secret_id: &str) -> Vec<crate::pipes::upstream_headers::UpstreamHeader> {
            vec![crate::pipes::upstream_headers::UpstreamHeader {
                name: KEY_HEADER.to_string(),
                secret_id: secret_id.to_string(),
            }]
        }

        fn free() -> crate::pipes::types::llm::TargetPricing {
            crate::pipes::types::llm::TargetPricing {
                input_per_million: 0.0,
                output_per_million: 0.0,
            }
        }

        /// An OpenAI-compatible target at `url`, named `gpt-4o` so an
        /// undeclared price would come from the catalog.
        fn target(
            url: &str,
            header_secret: Option<&str>,
        ) -> crate::pipes::judge_jury::LLMTarget {
            crate::pipes::judge_jury::LLMTarget {
                provider_type: "openai".to_string(),
                model: "gpt-4o".to_string(),
                endpoint_url: url.to_string(),
                api_key_secret: None,
                parameters: None,
                timeout_secs: 10,
                capabilities: None,
                api_schema: "openai".to_string(),
                headers: header_secret
                    .map(key_header)
                    .unwrap_or_default(),
                pricing: None,
            }
        }

        /// A surface whose own upstream is `url`, sending `base-tunnel`.
        fn surface(url: &str) -> PipeConfig {
            let mut config = PipeConfig::new(
                "p-targets".to_string(),
                "Targets".to_string(),
                PipeType::LLM {
                    provider: Box::new(LLMProvider::OpenAI {
                        provider_type: "openai".to_string(),
                        model: "gpt-4o".to_string(),
                        api_key_secret: Some("model-key".to_string()),
                        organization_id: None,
                        base_url: Some(url.to_string()),
                        temperature: None,
                        max_tokens: None,
                        top_p: None,
                        frequency_penalty: None,
                        presence_penalty: None,
                    }),
                    endpoint_path: None,
                },
            );
            config.upstream_headers = key_header("base-tunnel");
            config
        }

        fn allow(upstreams: &[&CaptureUpstream]) -> test_service_endpoints::Allowed {
            test_service_endpoints::allow(
                &upstreams
                    .iter()
                    .map(|upstream| upstream.url.clone())
                    .collect::<Vec<_>>(),
            )
        }

        fn request() -> Value {
            json!({ "messages": [{ "role": "user", "content": "hello" }] })
        }

        async fn run(config: &PipeConfig) -> Result<(Value, ExecutionMetrics), PipeError> {
            PipeExecutor::new_with_secrets(config, Some(store()))
                .execute(request(), None, None, None, None)
                .await
        }

        fn judge(llm: crate::pipes::judge_jury::LLMTarget) -> crate::pipes::judge_jury::JudgeConfig {
            serde_json::from_value(json!({ "enabled": true, "mode": "llm", "llm": llm, "system_prompt": "Judge." }))
                .expect("judge config")
        }

        fn jury(llm: crate::pipes::judge_jury::LLMTarget) -> crate::pipes::judge_jury::JuryConfig {
            serde_json::from_value(json!({
                "enabled": true,
                "jurors": [{ "name": "juror", "llm": llm, "system_prompt": "Review." }]
            }))
            .expect("jury config")
        }

        fn candidate(
            id: &str,
            llm: crate::pipes::judge_jury::LLMTarget,
        ) -> crate::pipes::judge_jury::DeciderCandidate {
            crate::pipes::judge_jury::DeciderCandidate {
                id: id.to_string(),
                name: id.to_string(),
                description: String::new(),
                llm,
            }
        }

        #[tokio::test]
        async fn a_failover_backup_sends_only_its_own_header_and_the_base_only_its_own() {
            let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let backup = CaptureUpstream::answering("from the backup").await;
            let _allowed = allow(&[&base, &backup]);
            let mut config = surface(&base.url);
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget {
                    llm: target(&backup.url, Some("backup-tunnel")),
                }],
            });

            run(&config)
                .await
                .expect("the backup answers");

            assert_eq!(base.requests(), 1, "precondition: the base was tried first");
            assert_eq!(backup.requests(), 1, "precondition: the backup was called");
            assert_eq!(base.header_values(KEY_HEADER), vec!["BASE"]);
            assert_eq!(backup.header_values(KEY_HEADER), vec!["BACKUP"]);
        }

        #[tokio::test]
        async fn an_anthropic_upstream_receives_the_callers_user_as_metadata_user_id() {
            let base = CaptureUpstream::answering("from claude").await;
            let _allowed = allow(&[&base]);
            let mut config = surface(&base.url);
            config.pipe_type = PipeType::LLM {
                provider: Box::new(LLMProvider::Ollama {
                    provider_type: "ollama".to_string(),
                    model: "claude-sonnet-4".to_string(),
                    api_key_secret: Some("model-key".to_string()),
                    base_url: Some(base.url.clone()),
                    api_schema: Some("anthropic".to_string()),
                    _marketplace_source: None,
                    temperature: None,
                    max_tokens: None,
                    top_p: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                }),
                endpoint_path: None,
            };

            PipeExecutor::new_with_secrets(&config, Some(store()))
                .execute(
                    json!({ "messages": [{ "role": "user", "content": "hello" }], "user": "u-42", "seed": 7 }),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .expect("the upstream answers");

            let bodies = base.bodies();
            assert_eq!(bodies.len(), 1, "precondition: the upstream was called once");
            assert!(
                bodies[0]
                    .get("user")
                    .is_none(),
                "Anthropic rejects a top-level `user`"
            );
            assert!(
                bodies[0]
                    .get("seed")
                    .is_none(),
                "Anthropic rejects `seed`"
            );
            assert_eq!(bodies[0]["metadata"], json!({ "user_id": "u-42" }));
        }

        #[tokio::test]
        async fn every_client_dialect_sends_the_callers_user_id_to_claude_buffered_and_streamed() {
            use crate::pipes::request_shaping::{transform_from_anthropic_request, transform_from_responses_request};
            let messages = || {
                transform_from_anthropic_request(json!({
                    "model": "claude-haiku-4-5",
                    "max_tokens": 64,
                    "metadata": { "user_id": "u-42" },
                    "messages": [{ "role": "user", "content": "hello" }]
                }))
            };
            let chat = || json!({ "messages": [{ "role": "user", "content": "hello" }], "user": "u-42" });
            let responses = || transform_from_responses_request(json!({ "input": "hello", "user": "u-42" }));

            for (dialect, canonical) in
                [("Messages", messages as fn() -> Value), ("Chat Completions", chat), ("Responses", responses)]
            {
                for streamed in [false, true] {
                    let base = CaptureUpstream::answering("from claude").await;
                    let _allowed = allow(&[&base]);
                    let mut config = surface(&base.url);
                    config.pipe_type = PipeType::LLM {
                        provider: Box::new(LLMProvider::Ollama {
                            provider_type: "ollama".to_string(),
                            model: "claude-haiku-4-5".to_string(),
                            api_key_secret: Some("model-key".to_string()),
                            base_url: Some(base.url.clone()),
                            api_schema: Some("anthropic".to_string()),
                            _marketplace_source: None,
                            temperature: None,
                            max_tokens: None,
                            top_p: None,
                            frequency_penalty: None,
                            presence_penalty: None,
                        }),
                        endpoint_path: None,
                    };
                    let executor = PipeExecutor::new_with_secrets(&config, Some(store()));
                    let sent = if streamed {
                        executor
                            .execute_streaming(canonical(), None, CallerCredentials::default(), None)
                            .await
                            .map(|_| ())
                    } else {
                        executor
                            .execute(canonical(), None, None, None, None)
                            .await
                            .map(|_| ())
                    };
                    let case = format!("{dialect}, streamed: {streamed}");
                    sent.unwrap_or_else(|e| panic!("{case}: {e}"));

                    let bodies = base.bodies();
                    assert_eq!(bodies.len(), 1, "{case}: precondition: the upstream was called once");
                    assert!(
                        bodies[0]
                            .get("user")
                            .is_none(),
                        "{case}: Anthropic rejects a top-level `user`"
                    );
                    assert_eq!(bodies[0]["metadata"], json!({ "user_id": "u-42" }), "{case}");
                    assert_eq!(bodies[0]["stream"], json!(streamed.then_some(true)), "{case}");
                }
            }
        }

        #[tokio::test]
        async fn a_failover_backup_that_names_no_header_sends_none() {
            let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let backup = CaptureUpstream::answering("from the backup").await;
            let _allowed = allow(&[&base, &backup]);
            let mut config = surface(&base.url);
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget { llm: target(&backup.url, None) }],
            });

            run(&config)
                .await
                .expect("the backup answers");

            assert_eq!(backup.requests(), 1, "precondition: the backup was called");
            assert!(
                backup
                    .header_values(KEY_HEADER)
                    .is_empty(),
                "the base's header followed the backup"
            );
        }

        #[tokio::test]
        async fn a_load_balancing_pool_member_sends_only_its_own_header() {
            let base = CaptureUpstream::answering("from the base").await;
            let member = CaptureUpstream::failing(StatusCode::BAD_GATEWAY).await;
            let _allowed = allow(&[&base, &member]);
            let mut config = surface(&base.url);
            // The primary has no weight, so the pool member is picked first;
            // it fails and the request falls through to the primary.
            config.load_balancing = Some(
                serde_json::from_value(json!({
                    "enabled": true,
                    "primary_weight": 0,
                    "targets": [{ "llm": target(&member.url, Some("pool-tunnel")), "weight": 1 }]
                }))
                .expect("load balancing config"),
            );

            run(&config)
                .await
                .expect("the primary answers");

            assert_eq!(member.requests(), 1, "precondition: the pool member was tried");
            assert_eq!(base.requests(), 1, "precondition: the primary was called");
            assert_eq!(member.header_values(KEY_HEADER), vec!["POOL"]);
            assert_eq!(base.header_values(KEY_HEADER), vec!["BASE"]);
        }

        #[tokio::test]
        async fn a_per_request_routed_target_sends_only_its_own_header() {
            let base = CaptureUpstream::answering("from the base").await;
            let backup = CaptureUpstream::answering("from the backup").await;
            let _allowed = allow(&[&base, &backup]);
            let mut config = surface(&base.url);
            let mut routed = target(&backup.url, Some("backup-tunnel"));
            routed.model = "own-model".to_string();
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget { llm: routed }],
            });
            let mut body = request();
            body["models"] = json!(["own-model"]);

            PipeExecutor::new_with_secrets(&config, Some(store()))
                .execute(body, None, None, None, None)
                .await
                .expect("the routed target answers");

            assert_eq!(backup.requests(), 1, "precondition: the routed target was called");
            assert_eq!(base.requests(), 0);
            assert_eq!(backup.header_values(KEY_HEADER), vec!["BACKUP"]);
        }

        #[tokio::test]
        async fn the_judge_and_a_juror_each_send_only_their_own_header() {
            let base = CaptureUpstream::answering("an answer").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let juror_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &judge_upstream, &juror_upstream]);
            let mut config = surface(&base.url);
            config.judge = Some(judge(target(&judge_upstream.url, Some("judge-tunnel"))));
            config.jury = Some(jury(target(&juror_upstream.url, Some("juror-tunnel"))));

            run(&config)
                .await
                .expect("the Judge and the Jury approve");

            assert_eq!(judge_upstream.requests(), 1, "precondition: the Judge was called");
            assert_eq!(juror_upstream.requests(), 1, "precondition: the juror was called");
            assert_eq!(judge_upstream.header_values(KEY_HEADER), vec!["JUDGE"]);
            assert_eq!(juror_upstream.header_values(KEY_HEADER), vec!["JUROR"]);
            assert_eq!(base.header_values(KEY_HEADER), vec!["BASE"]);
        }

        #[tokio::test]
        async fn a_judge_in_moderation_mode_sends_its_own_header() {
            let judge_upstream = CaptureUpstream::answering("unused").await;
            let _allowed = allow(&[&judge_upstream]);
            let mut moderation = judge(target(&judge_upstream.url, Some("judge-tunnel")));
            moderation.mode = crate::pipes::judge_jury::JudgeMode::Moderation;

            // The capture answer is not a moderation result, so the verdict is
            // an error; the header is what this test is about.
            let _ =
                crate::pipes::judge_jury::execute_judge("p-targets", &moderation, &request(), &surface_secrets()).await;

            assert_eq!(judge_upstream.requests(), 1, "precondition: the moderation call was made");
            assert_eq!(judge_upstream.header_values(KEY_HEADER), vec!["JUDGE"]);
        }

        #[tokio::test]
        async fn a_routed_decider_sends_the_router_and_the_candidate_only_their_own_headers() {
            let base = CaptureUpstream::answering("from the base").await;
            let router = CaptureUpstream::answering(r#"{"candidate":"own"}"#).await;
            let chosen = CaptureUpstream::answering("from the candidate").await;
            let _allowed = allow(&[&base, &router, &chosen]);
            let mut config = surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(target(&router.url, Some("router-tunnel"))),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("own", target(&chosen.url, Some("candidate-tunnel")))],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });

            run(&config)
                .await
                .expect("the candidate answers");

            assert_eq!(router.requests(), 1, "precondition: the router was called");
            assert_eq!(chosen.requests(), 1, "precondition: the candidate was called");
            assert_eq!(router.header_values(KEY_HEADER), vec!["ROUTER"]);
            assert_eq!(chosen.header_values(KEY_HEADER), vec!["CANDIDATE"]);
            assert_eq!(base.requests(), 0);
        }

        fn bedrock_claude_target(url: &str) -> crate::pipes::judge_jury::LLMTarget {
            let mut llm = target(url, Some("candidate-tunnel"));
            llm.provider_type = "bedrock".to_string();
            llm.model = "us.anthropic.claude-sonnet-4-5-20250929-v1:0".to_string();
            llm.api_schema = "bedrock-anthropic".to_string();
            llm
        }

        fn anthropic_message(text: &str) -> Value {
            json!({
                "id": "msg_1",
                "type": "message",
                "role": "assistant",
                "content": [{ "type": "text", "text": text }],
                "stop_reason": "end_turn",
                "usage": { "input_tokens": 10, "output_tokens": 5 }
            })
        }

        fn assert_bedrock_anthropic_body(body: &Value) {
            assert!(body.get("model").is_none(), "the model travels in the InvokeModel URL");
            assert_eq!(body["anthropic_version"], json!("bedrock-2023-05-31"));
            assert_eq!(body["messages"], json!([{ "role": "user", "content": [{ "type": "text", "text": "hello" }] }]));
            assert_eq!(body["max_tokens"], json!(4096));
            for key in ["user", "metadata", "stream"] {
                assert!(body.get(key).is_none(), "Bedrock rejects `{key}`");
            }
        }

        #[tokio::test]
        async fn a_routed_bedrock_claude_candidate_receives_the_anthropic_messages_body() {
            let base = CaptureUpstream::answering("from the base").await;
            let router = CaptureUpstream::answering(r#"{"candidate":"claude"}"#).await;
            let chosen = CaptureUpstream::failing_with(StatusCode::OK, anthropic_message("from claude")).await;
            let _allowed = allow(&[&base, &router, &chosen]);
            let mut config = surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(target(&router.url, Some("router-tunnel"))),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("claude", bedrock_claude_target(&chosen.url))],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });

            let (response, _) = PipeExecutor::new_with_secrets(&config, Some(store()))
                .execute(
                    json!({ "messages": [{ "role": "user", "content": "hello" }], "user": "u-42" }),
                    None,
                    None,
                    None,
                    None,
                )
                .await
                .expect("the candidate answers");

            let bodies = chosen.bodies();
            assert_eq!(bodies.len(), 1, "precondition: the candidate was called once");
            assert_bedrock_anthropic_body(&bodies[0]);
            assert_eq!(response["choices"][0]["message"]["content"], json!("from claude"));
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_bedrock_claude_candidate_refuses_an_image_url_before_sending() {
            let base = CaptureUpstream::answering("from the base").await;
            let router = CaptureUpstream::answering(r#"{"candidate":"claude"}"#).await;
            let chosen = CaptureUpstream::failing_with(StatusCode::OK, anthropic_message("from claude")).await;
            let _allowed = allow(&[&base, &router, &chosen]);
            let mut config = surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(target(&router.url, Some("router-tunnel"))),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("claude", bedrock_claude_target(&chosen.url))],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });
            let request = json!({ "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "What is this?" },
                { "type": "image_url", "image_url": { "url": "https://example.com/cat.png" } }
            ] }] });

            let err = PipeExecutor::new_with_secrets(&config, Some(store()))
                .execute(request, None, None, None, None)
                .await
                .expect_err("Bedrock cannot read an image URL");

            assert!(err.unsupported_content(), "unexpected error: {err}");
            assert_eq!(err.to_string(), crate::pipes::request_shaping::BEDROCK_URL_SOURCE_UNSUPPORTED);
            assert_eq!(chosen.requests(), 0, "nothing is sent to Bedrock");
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_mirror_bedrock_claude_candidate_receives_the_anthropic_messages_body() {
            let base = CaptureUpstream::answering("from the base").await;
            let claude = CaptureUpstream::failing_with(StatusCode::OK, anthropic_message("from claude")).await;
            let other = CaptureUpstream::answering("other answer").await;
            let _allowed = allow(&[&base, &claude, &other]);
            let mut config = surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![
                    candidate("claude", bedrock_claude_target(&claude.url)),
                    candidate("other", target(&other.url, Some("candidate-2-tunnel"))),
                ],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Collect,
                    ..Default::default()
                },
                disable_thinking: None,
            });

            run(&config)
                .await
                .expect("the mirror answers");

            let bodies = claude.bodies();
            assert_eq!(bodies.len(), 1, "precondition: the Bedrock candidate was called once");
            assert_bedrock_anthropic_body(&bodies[0]);
            assert!(
                other.bodies()[0]
                    .get("anthropic_version")
                    .is_none(),
                "an OpenAI candidate keeps the OpenAI body"
            );
        }

        #[tokio::test]
        async fn a_candidate_on_the_bases_own_upstream_still_sends_only_its_own_headers() {
            // The candidate names exactly the base provider (same URL, model
            // and key) but no headers: a target's headers are its own, so the
            // base's do not ride along.
            let base = CaptureUpstream::answering("from the base").await;
            let router = CaptureUpstream::answering(r#"{"candidate":"same"}"#).await;
            let _allowed = allow(&[&base, &router]);
            let mut config = surface(&base.url);
            let mut same = target(&base.url, None);
            same.api_key_secret = Some("model-key".to_string());
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(target(&router.url, Some("router-tunnel"))),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("same", same)],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });

            run(&config)
                .await
                .expect("the candidate answers");

            assert_eq!(base.requests(), 1, "precondition: the candidate's upstream was called");
            assert!(
                base.header_values(KEY_HEADER)
                    .is_empty(),
                "the base's header rode on a candidate"
            );
            assert_eq!(base.header_values("authorization"), vec!["Bearer MODEL"]);
        }

        #[tokio::test]
        async fn mirror_candidates_and_the_merger_each_send_only_their_own_header() {
            let base = CaptureUpstream::answering("from the base").await;
            let first = CaptureUpstream::answering("first answer").await;
            let second = CaptureUpstream::answering("second answer").await;
            let merger = CaptureUpstream::answering("merged answer").await;
            let _allowed = allow(&[&base, &first, &second, &merger]);
            let mut config = surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![
                    candidate("first", target(&first.url, Some("candidate-tunnel"))),
                    candidate("second", target(&second.url, Some("candidate-2-tunnel"))),
                ],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Merge,
                    merger: Some(target(&merger.url, Some("merger-tunnel"))),
                    merge_system_prompt: String::new(),
                    disable_thinking: None,
                },
                disable_thinking: None,
            });

            run(&config)
                .await
                .expect("the merger answers");

            for (upstream, expected) in [(&first, "CANDIDATE"), (&second, "CANDIDATE-2"), (&merger, "MERGER")] {
                assert_eq!(upstream.requests(), 1, "precondition: every mirror upstream was called");
                assert_eq!(upstream.header_values(KEY_HEADER), vec![expected]);
            }
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_redirect_from_the_upstream_carries_no_header_to_its_destination() {
            let destination = CaptureUpstream::answering("redirected").await;
            let base = CaptureUpstream::redirecting_to(&destination.url).await;
            let _allowed = allow(&[&base, &destination]);
            let config = surface(&base.url);

            let result = run(&config).await;

            assert!(result.is_err(), "a redirect is not followed, so the call fails");
            assert_eq!(base.header_values(KEY_HEADER), vec!["BASE"], "precondition: the upstream was called");
            assert_eq!(destination.requests(), 0, "the redirect was followed");
        }

        #[tokio::test]
        async fn a_redirect_from_a_judge_carries_no_header_to_its_destination() {
            let destination = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let judge_upstream = CaptureUpstream::redirecting_to(&destination.url).await;
            let _allowed = allow(&[&judge_upstream, &destination]);
            let llm_judge = judge(target(&judge_upstream.url, Some("judge-tunnel")));

            let result =
                crate::pipes::judge_jury::execute_judge("p-targets", &llm_judge, &request(), &surface_secrets()).await;

            assert!(result.is_err(), "a redirect is not followed, so the Judge call fails");
            assert_eq!(judge_upstream.header_values(KEY_HEADER), vec!["JUDGE"], "precondition: the Judge was called");
            assert_eq!(destination.requests(), 0, "the redirect was followed");
        }

        #[tokio::test]
        async fn an_unresolvable_target_header_fails_that_call_before_it_is_sent() {
            let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let backup = CaptureUpstream::answering("from the backup").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &backup, &judge_upstream]);
            let mut config = surface(&base.url);
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget {
                    llm: target(&backup.url, Some("missing-tunnel")),
                }],
            });

            let failover = run(&config).await;
            let judged = crate::pipes::judge_jury::execute_judge(
                "p-targets",
                &judge(target(&judge_upstream.url, Some("missing-tunnel"))),
                &request(),
                &surface_secrets(),
            )
            .await;

            assert_eq!(base.requests(), 1, "precondition: the primary was tried");
            assert!(failover.is_err());
            assert_eq!(backup.requests(), 0, "the backup was called without its header");
            assert!(judged.is_err());
            assert_eq!(judge_upstream.requests(), 0, "the Judge was called without its header");
            // The caller learns that a credential is missing, never which.
            for error in [failover.unwrap_err(), judged.unwrap_err()] {
                assert!(
                    matches!(&error, PipeError::RequestFailed(message) if message == crate::pipes::upstream_headers::CREDENTIAL_UNAVAILABLE),
                    "unexpected error: {error:?}"
                );
                assert!(!format!("{error:?}").contains("missing-tunnel"), "the error names the reference: {error:?}");
            }
        }

        // ── Tenancy at request time ──

        /// Tenant A's own model key and tunnel key, the operator's key, and a
        /// public id (`b-tunnel`) that belongs to tenant B.
        fn tenant_store() -> Arc<dyn SecretsStore> {
            Arc::new(MemorySecretsStore::with(vec![
                secret("uuid-operator", "model-key", "OPERATOR", None),
                secret("uuid-own", "own-key", "OWN", Some("tenant-a")),
                secret("uuid-own-tunnel", "own-tunnel", "OWN-TUNNEL", Some("tenant-a")),
                secret("uuid-b", "b-tunnel", "B-VALUE", Some("tenant-b")),
            ]))
        }

        /// A tenant-A surface on `url` sending the operator's key and tenant
        /// A's own tunnel key.
        fn tenant_surface(url: &str) -> PipeConfig {
            let mut config = surface(url);
            config.tenant_id = Some("tenant-a".to_string());
            config.upstream_headers = key_header("own-tunnel");
            config
        }

        fn own_key(config: &mut PipeConfig) {
            if let PipeType::LLM { provider, .. } = &mut config.pipe_type
                && let LLMProvider::OpenAI { api_key_secret, .. } = provider.as_mut()
            {
                *api_key_secret = Some("own-key".to_string());
            }
        }

        async fn run_tenant(config: &PipeConfig) -> Result<(Value, ExecutionMetrics), PipeError> {
            PipeExecutor::new_with_secrets(config, Some(tenant_store()))
                .execute(request(), None, None, None, None)
                .await
        }

        fn tenant_secrets() -> crate::secrets::SurfaceSecrets {
            crate::secrets::SurfaceSecrets::new(Some(tenant_store()), Some("tenant-a".to_string()))
        }

        fn catalog_cost() -> f64 {
            crate::pipes::types::llm::TokenPricing::for_model("openai", "gpt-4o")
                .expect("gpt-4o has a built-in price")
                .calculate_cost(1000, 1000)
        }

        async fn list_files(
            config: &PipeConfig,
            secrets: Arc<dyn SecretsStore>,
        ) -> Result<BinaryResponse, PipeError> {
            PipeExecutor::new_with_secrets(config, Some(secrets))
                .execute_get(Some("/v1/files".to_string()), CallerCredentials::default())
                .await
        }

        #[tokio::test]
        async fn a_tenant_surface_never_reads_provider_files_through_an_operator_key() {
            let base = CaptureUpstream::answering("the provider's files").await;
            let _allowed = test_service_endpoints::allow(&[format!("{}/v1/files", base.url)]);
            let mut config = tenant_surface(&base.url);

            let refused = list_files(&config, tenant_store())
                .await
                .err();
            assert!(
                matches!(
                    &refused,
                    Some(PipeError::SharedCredentialRefused(
                        crate::pipes::shared_credential::SharedCredentialRefusal::Read
                    ))
                ),
                "unexpected outcome: {refused:?}"
            );
            assert_eq!(base.requests(), 0, "the operator's key listed every tenant's files");

            own_key(&mut config);
            list_files(&config, tenant_store())
                .await
                .expect("the tenant's own key reads the tenant's own files");
            assert_eq!(base.requests(), 1, "precondition: the tenant's own key reached the provider");
        }

        fn naming_a_stored_file() -> Value {
            json!({ "model": "gpt-4o", "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "summarise this" },
                { "type": "file", "file": { "file_id": "file-of-another-tenant" } }
            ] }] })
        }

        fn is_refused(
            outcome: Option<&PipeError>,
            refusal: crate::pipes::shared_credential::SharedCredentialRefusal,
        ) -> bool {
            outcome.and_then(PipeError::shared_credential_refusal) == Some(refusal)
        }

        #[tokio::test]
        async fn a_tenant_surface_on_an_operator_key_never_names_a_stored_object() {
            use crate::pipes::shared_credential::SharedCredentialRefusal::Call;
            let base = CaptureUpstream::answering("an answer").await;
            let _allowed = allow(&[&base]);
            let mut config = tenant_surface(&base.url);
            let executor = || PipeExecutor::new_with_secrets(&config, Some(tenant_store()));

            let buffered = executor()
                .execute(naming_a_stored_file(), None, None, None, None)
                .await
                .err();
            assert!(is_refused(buffered.as_ref(), Call), "buffered: {buffered:?}");
            let streamed = executor()
                .execute_streaming(naming_a_stored_file(), None, CallerCredentials::default(), None)
                .await
                .err();
            assert!(is_refused(streamed.as_ref(), Call), "streamed: {streamed:?}");
            assert_eq!(base.requests(), 0, "a stored file was named through the operator's key");

            executor()
                .execute(request(), None, None, None, None)
                .await
                .expect("plain inference still runs on the operator's key");
            assert_eq!(base.requests(), 1);

            own_key(&mut config);
            PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                .execute(naming_a_stored_file(), None, None, None, None)
                .await
                .expect("the tenant's own key may name its own files");
            assert_eq!(base.requests(), 2);
        }

        fn claude_tenant_surface(url: &str) -> PipeConfig {
            let mut config = tenant_surface(url);
            config
                .upstream_headers
                .clear();
            config.pipe_type = PipeType::LLM {
                provider: Box::new(LLMProvider::Anthropic {
                    provider_type: "anthropic".to_string(),
                    model: "claude-sonnet-4".to_string(),
                    api_key_secret: Some("model-key".to_string()),
                    version: None,
                    temperature: None,
                    max_tokens: None,
                    top_p: None,
                    frequency_penalty: None,
                    presence_penalty: None,
                }),
                endpoint_path: None,
            };
            config
        }

        fn docx_request() -> Value {
            json!({ "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "Summarise this." },
                { "type": "file", "file": {
                    "filename": "notes.docx",
                    "file_data": "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,UEsDBA=="
                } }
            ] }] })
        }

        #[tokio::test]
        async fn a_tenant_claude_surface_on_an_operator_key_never_names_a_stored_object() {
            use crate::pipes::shared_credential::SharedCredentialRefusal::Call;
            let base = CaptureUpstream::answering("an answer").await;
            let _allowed = allow(&[&base]);
            let config = claude_tenant_surface(&base.url);
            let executor = || PipeExecutor::new_with_secrets(&config, Some(tenant_store()));

            let buffered = executor()
                .execute(naming_a_stored_file(), None, None, None, None)
                .await
                .err();
            assert!(is_refused(buffered.as_ref(), Call), "buffered: {buffered:?}");
            let streamed = executor()
                .execute_streaming(naming_a_stored_file(), None, CallerCredentials::default(), None)
                .await
                .err();
            assert!(is_refused(streamed.as_ref(), Call), "streamed: {streamed:?}");

            let plain = executor()
                .execute(request(), None, None, None, None)
                .await
                .err();
            assert!(
                plain
                    .as_ref()
                    .and_then(PipeError::shared_credential_refusal)
                    .is_none(),
                "plain inference was refused: {plain:?}"
            );
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_claude_surface_refuses_a_file_claude_cannot_read_before_sending() {
            let base = CaptureUpstream::answering("an answer").await;
            let _allowed = allow(&[&base]);
            let config = claude_tenant_surface(&base.url);
            let executor = || PipeExecutor::new_with_secrets(&config, Some(tenant_store()));

            let buffered = executor()
                .execute(docx_request(), None, None, None, None)
                .await
                .expect_err("Claude cannot read a DOCX");
            assert!(buffered.unsupported_content(), "buffered: {buffered:?}");
            assert_eq!(buffered.to_string(), crate::pipes::request_shaping::CLAUDE_UNREADABLE_FILE);
            let streamed = executor()
                .execute_streaming(docx_request(), None, CallerCredentials::default(), None)
                .await
                .err();
            assert!(
                streamed
                    .as_ref()
                    .is_some_and(PipeError::unsupported_content),
                "streamed: {streamed:?}"
            );
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_file_claude_cannot_read_is_refused_once_under_a_retry_policy() {
            let base = CaptureUpstream::answering("an answer").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &judge_upstream]);
            let mut config = claude_tenant_surface(&base.url);
            config.judge = Some(judge(target(&judge_upstream.url, None)));
            config.retry_policy = Some(crate::pipes::config::RetryPolicy {
                max_retries: 2,
                initial_backoff_ms: 1,
                max_backoff_ms: 1,
                backoff_multiplier: 1.0,
            });

            let refused = PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                .execute(docx_request(), None, None, None, None)
                .await
                .expect_err("Claude cannot read a DOCX");

            assert!(refused.unsupported_content(), "unexpected error: {refused:?}");
            assert_eq!(judge_upstream.requests(), 1, "the request ran once, not once per retry");
            assert_eq!(base.requests(), 0);
        }

        #[tokio::test]
        async fn a_tenant_surface_on_an_operator_key_calls_inference_endpoints_only() {
            use crate::pipes::shared_credential::SharedCredentialRefusal::Call;
            let base = CaptureUpstream::answering("an answer").await;
            let _allowed = test_service_endpoints::allow(&[
                format!("{}/v1/chat/completions", base.url),
                format!("{}/v1/vector_stores", base.url),
            ]);
            let mut config = tenant_surface(&base.url);
            let send = |config: &PipeConfig, suffix: &str| {
                let executor = PipeExecutor::new_with_secrets(config, Some(tenant_store()));
                let suffix = suffix.to_string();
                async move {
                    executor
                        .execute_with_path(request(), Some(suffix), None, None, None, None)
                        .await
                }
            };

            let refused = send(&config, "/v1/vector_stores")
                .await
                .err();
            assert!(is_refused(refused.as_ref(), Call), "unexpected outcome: {refused:?}");
            assert_eq!(base.requests(), 0, "a store endpoint was called through the operator's key");
            send(&config, "/v1/chat/completions")
                .await
                .expect("chat completions is an inference endpoint");
            assert_eq!(base.requests(), 1);

            own_key(&mut config);
            send(&config, "/v1/vector_stores")
                .await
                .expect("the tenant's own key reaches any endpoint");
            assert_eq!(base.requests(), 2);
        }

        #[tokio::test]
        async fn a_mirror_candidate_on_an_operator_key_never_names_a_stored_object() {
            let first = CaptureUpstream::answering("first answer").await;
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&first, &base]);
            let mut operator_target = target(&first.url, None);
            operator_target.api_key_secret = Some("model-key".to_string());
            let mut config = tenant_surface(&base.url);
            own_key(&mut config);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![candidate("first", operator_target)],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Collect,
                    ..Default::default()
                },
                disable_thinking: None,
            });

            let _ = PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                .execute(naming_a_stored_file(), None, None, None, None)
                .await;
            assert_eq!(first.requests(), 0, "the candidate named a stored file through the operator's key");
        }

        #[tokio::test]
        async fn a_tenant_surface_on_an_operator_key_never_uploads_files() {
            use crate::pipes::shared_credential::SharedCredentialRefusal::{Call, Upload};
            let base = CaptureUpstream::answering("an upload").await;
            let _allowed = test_service_endpoints::allow(&[
                format!("{}/v1/files", base.url),
                format!("{}/v1/audio/transcriptions", base.url),
                format!("{}/v1/audio/speech", base.url),
            ]);
            let mut config = tenant_surface(&base.url);
            let upload = |config: &PipeConfig, suffix: &str| {
                let executor = PipeExecutor::new_with_secrets(config, Some(tenant_store()));
                let suffix = suffix.to_string();
                async move {
                    executor
                        .execute_upload(
                            Some(suffix),
                            "multipart/form-data; boundary=x".to_string(),
                            b"--x--".to_vec(),
                            CallerCredentials::default(),
                        )
                        .await
                }
            };

            let refused = upload(&config, "/v1/files")
                .await
                .err();
            assert!(is_refused(refused.as_ref(), Upload), "unexpected outcome: {refused:?}");
            let speech = |body: Value| {
                let executor = PipeExecutor::new_with_secrets(&config, Some(tenant_store()));
                async move {
                    executor
                        .execute_binary(body, Some("/v1/audio/speech".to_string()), CallerCredentials::default())
                        .await
                }
            };
            let named = speech(json!({ "model": "tts-1", "input": "hi", "file_id": "file-of-another-tenant" }))
                .await
                .err();
            assert!(is_refused(named.as_ref(), Call), "a stored object is refused on every path: {named:?}");
            assert_eq!(base.requests(), 0, "a file reached the operator's store");

            speech(json!({ "model": "tts-1", "input": "hi" }))
                .await
                .expect("text to speech reads nothing stored, so it runs on the operator's key");
            upload(&config, "/v1/audio/transcriptions")
                .await
                .expect("speech to text stores nothing, so it runs on the operator's key");
            assert_eq!(base.requests(), 2);

            own_key(&mut config);
            upload(&config, "/v1/files")
                .await
                .expect("the tenant's own key uploads to the tenant's own store");
            assert_eq!(base.requests(), 3);
        }

        #[tokio::test]
        async fn an_appliance_wide_surface_reads_provider_files_through_the_operator_key() {
            let base = CaptureUpstream::answering("the provider's files").await;
            let _allowed = test_service_endpoints::allow(&[format!("{}/v1/files", base.url)]);

            list_files(&surface(&base.url), store())
                .await
                .expect("an appliance-wide surface owns the operator's key");
            assert_eq!(base.requests(), 1);
            assert_eq!(base.header_values("authorization"), vec!["Bearer MODEL".to_string()]);
        }

        #[tokio::test]
        async fn a_secret_another_tenant_now_owns_fails_the_call_before_it_is_sent() {
            // Tenant A's surface names `b-tunnel`, a public id tenant B has
            // since registered: every resolver re-checks it and fails closed.
            let base = CaptureUpstream::answering("an answer").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &judge_upstream]);
            let mut config = tenant_surface(&base.url);
            config.upstream_headers = key_header("b-tunnel");

            let main = run_tenant(&config).await;
            let judged = crate::pipes::judge_jury::execute_judge(
                "p-targets",
                &judge(target(&judge_upstream.url, Some("b-tunnel"))),
                &request(),
                &tenant_secrets(),
            )
            .await;

            assert!(main.is_err(), "the surface sent tenant B's secret");
            assert!(judged.is_err(), "the Judge sent tenant B's secret");
            assert_eq!(base.requests(), 0);
            assert_eq!(judge_upstream.requests(), 0);

            // Precondition: the same surface naming its own tunnel key answers.
            config.upstream_headers = key_header("own-tunnel");
            run_tenant(&config)
                .await
                .expect("a surface sends its tenant's own secret");
            assert_eq!(base.header_values(KEY_HEADER), vec!["OWN-TUNNEL"]);
        }

        #[tokio::test]
        async fn a_declared_price_on_an_operator_key_never_bills_below_the_catalog() {
            let base = CaptureUpstream::answering("from the base").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &judge_upstream]);
            let mut judge_target = target(&judge_upstream.url, None);
            judge_target.api_key_secret = Some("model-key".to_string());
            judge_target.pricing = Some(free());
            let mut config = tenant_surface(&base.url);
            config.upstream_pricing = Some(free());
            config.judge = Some(judge(judge_target));

            let (_, operator) = run_tenant(&config)
                .await
                .expect("answers");
            assert!(catalog_cost() > 0.0, "precondition: gpt-4o has a catalog price");
            assert_eq!(operator.llm_usage.cost, catalog_cost(), "the operator's key was billed at the declared zero");
            assert_eq!(operator.judge_usage.cost, catalog_cost(), "the Judge on the operator's key was billed at zero");

            own_key(&mut config);
            if let Some(judge) = config.judge.as_mut() {
                judge.llm.api_key_secret = Some("own-key".to_string());
            }
            let (_, own) = run_tenant(&config)
                .await
                .expect("answers");
            assert_eq!(own.llm_usage.cost, 0.0, "the tenant's own model is billed at its declared price");
            assert_eq!(own.judge_usage.cost, 0.0);
        }

        #[tokio::test]
        async fn a_failover_backup_and_a_mirror_candidate_on_an_operator_key_bill_the_catalog() {
            let failing = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let backup_upstream = CaptureUpstream::answering("from the backup").await;
            let first = CaptureUpstream::answering("first answer").await;
            let _allowed = allow(&[&failing, &backup_upstream, &first]);
            let operator_target = |url: &str| {
                let mut llm = target(url, None);
                llm.api_key_secret = Some("model-key".to_string());
                llm.pricing = Some(free());
                llm
            };

            let mut config = tenant_surface(&failing.url);
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget {
                    llm: operator_target(&backup_upstream.url),
                }],
            });
            let (_, failed_over) = run_tenant(&config)
                .await
                .expect("the backup answers");
            assert_eq!(backup_upstream.requests(), 1, "precondition: the backup answered");
            assert_eq!(failed_over.llm_usage.cost, catalog_cost());

            let mut config = tenant_surface(&first.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![candidate("first", operator_target(&first.url))],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Collect,
                    ..Default::default()
                },
                disable_thinking: None,
            });
            let (_, mirrored) = run_tenant(&config)
                .await
                .expect("the candidate answers");
            assert_eq!(first.requests(), 1, "precondition: the candidate answered");
            assert_eq!(mirrored.llm_usage.cost, catalog_cost());
        }

        #[tokio::test]
        async fn a_cost_override_below_the_catalog_never_lowers_an_operator_keys_bill() {
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&base]);
            let mut config = tenant_surface(&base.url);
            config.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
                enabled: true,
                input_price_per_1k: Some(0.000001),
                output_price_per_1k: Some(0.000001),
                monthly_budget_usd: None,
                alert_threshold_percent: None,
            });
            let override_cost = crate::pipes::types::llm::TokenPricing {
                input_price_per_million: 0.001,
                output_price_per_million: 0.001,
            }
            .calculate_cost(1000, 1000);

            let (_, operator) = run_tenant(&config)
                .await
                .expect("answers");
            assert_eq!(operator.llm_usage.cost, catalog_cost());

            own_key(&mut config);
            let (_, own) = run_tenant(&config)
                .await
                .expect("answers");
            assert_eq!(own.llm_usage.cost, override_cost, "the tenant's own model is billed at its override");
        }

        #[tokio::test]
        async fn a_stream_on_an_operator_key_is_billed_at_least_the_catalog() {
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&base]);
            let mut config = tenant_surface(&base.url);
            config.upstream_pricing = Some(free());

            let stream = PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                .execute_streaming(request(), None, CallerCredentials::default(), None)
                .await
                .expect("the stream opens");
            assert!(!stream.own_price_honoured, "the operator's key was trusted with the declared price");
            let cost = crate::pipes::streaming::cost_for_tokens(
                stream.pricing.as_ref(),
                stream.own_price_honoured,
                &stream.provider,
                &stream.model,
                1000,
                1000,
            );
            assert_eq!(cost, catalog_cost());

            own_key(&mut config);
            let stream = PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                .execute_streaming(request(), None, CallerCredentials::default(), None)
                .await
                .expect("the stream opens");
            assert!(stream.own_price_honoured, "the tenant's own key must keep its declared price");
        }

        // ── Billed by the model the upstream ran ──

        fn naming(model: &str) -> Value {
            json!({ "model": model, "messages": [{ "role": "user", "content": "hello" }] })
        }

        fn price_of(model: &str) -> f64 {
            crate::pipes::types::llm::TokenPricing::for_model("openai", model)
                .expect("a built-in price")
                .calculate_cost(1000, 1000)
        }

        fn configure_model(
            config: &mut PipeConfig,
            configured: &str,
        ) {
            if let PipeType::LLM { provider, .. } = &mut config.pipe_type
                && let LLMProvider::OpenAI { model, .. } = provider.as_mut()
            {
                *model = configured.to_string();
            }
        }

        /// A tenant-A surface on `url` spending the operator's key, configured
        /// with the cheaper `gpt-3.5-turbo`.
        fn cheap_tenant_surface(url: &str) -> PipeConfig {
            let mut config = tenant_surface(url);
            configure_model(&mut config, "gpt-3.5-turbo");
            config
        }

        async fn run_tenant_naming(
            config: &PipeConfig,
            model: &str,
        ) -> Result<(Value, ExecutionMetrics), PipeError> {
            PipeExecutor::new_with_secrets(config, Some(tenant_store()))
                .execute(naming(model), None, None, None, None)
                .await
        }

        async fn stream_tenant_naming(
            config: &PipeConfig,
            model: &str,
        ) -> Result<crate::pipes::streaming::StreamingUpstream, PipeError> {
            PipeExecutor::new_with_secrets(config, Some(tenant_store()))
                .execute_streaming(naming(model), None, CallerCredentials::default(), None)
                .await
        }

        fn streamed_cost(stream: &crate::pipes::streaming::StreamingUpstream) -> f64 {
            crate::pipes::streaming::cost_for_tokens(
                stream.pricing.as_ref(),
                stream.own_price_honoured,
                &stream.provider,
                &stream.model,
                1000,
                1000,
            )
        }

        #[tokio::test]
        async fn a_caller_chosen_model_is_billed_at_the_model_it_ran() {
            let base = CaptureUpstream::answering("from gpt-4").await;
            let _allowed = allow(&[&base]);

            let (_, metrics) = run_tenant_naming(&cheap_tenant_surface(&base.url), "gpt-4")
                .await
                .expect("answers");

            assert_eq!(base.models(), vec!["gpt-4"], "precondition: the caller's model reached the operator's key");
            assert!(price_of("gpt-4") > price_of("gpt-3.5-turbo"), "precondition: gpt-4 costs more");
            assert_eq!(metrics.llm_usage.cost, price_of("gpt-4"), "billed at the configured model's price");
            assert_eq!(metrics.model, "gpt-4");
        }

        #[tokio::test]
        async fn a_streamed_or_failed_over_call_is_billed_at_the_model_it_ran() {
            let streamed = CaptureUpstream::answering("streamed").await;
            let failing = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let backup = CaptureUpstream::answering("from the backup").await;
            let _allowed = allow(&[&streamed, &failing, &backup]);

            let stream = stream_tenant_naming(&cheap_tenant_surface(&streamed.url), "gpt-4")
                .await
                .expect("the stream opens");
            assert_eq!(streamed.models(), vec!["gpt-4"], "precondition: the caller's model was streamed");
            assert_eq!(stream.model, "gpt-4");
            assert_eq!(streamed_cost(&stream), price_of("gpt-4"));

            let mut config = cheap_tenant_surface(&failing.url);
            let mut backup_target = target(&backup.url, None);
            backup_target.model = "gpt-3.5-turbo".to_string();
            backup_target.api_key_secret = Some("model-key".to_string());
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget { llm: backup_target }],
            });
            let (_, failed_over) = run_tenant_naming(&config, "gpt-4")
                .await
                .expect("the backup answers");
            assert_eq!(backup.models(), vec!["gpt-4"], "precondition: the backup ran the caller's model");
            assert_eq!(failed_over.llm_usage.cost, price_of("gpt-4"));
        }

        #[tokio::test]
        async fn a_routed_stream_is_billed_at_the_model_its_candidate_ran() {
            let router = CaptureUpstream::answering(r#"{"candidate":"cheap"}"#).await;
            let chosen = CaptureUpstream::answering("from the candidate").await;
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&router, &chosen, &base]);
            let mut candidate_target = target(&chosen.url, None);
            candidate_target.model = "gpt-3.5-turbo".to_string();
            candidate_target.api_key_secret = Some("model-key".to_string());
            let mut config = cheap_tenant_surface(&base.url);
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(target(&router.url, None)),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("cheap", candidate_target)],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });

            let stream = stream_tenant_naming(&config, "gpt-4")
                .await
                .expect("the candidate streams");

            assert_eq!(chosen.models(), vec!["gpt-4"], "precondition: the candidate ran the caller's model");
            assert_eq!(base.requests(), 0, "precondition: the base was not called");
            assert_eq!(stream.model, "gpt-4");
            assert_eq!(streamed_cost(&stream), price_of("gpt-4"));
        }

        #[test]
        fn a_provider_that_fixes_its_model_runs_the_configured_one() {
            let body = naming("gpt-4");
            let openai = target("https://api.openai.com/v1/chat/completions", None);
            assert_eq!(model_run(&crate::pipes::judge_jury::target_to_provider(&openai), &body), "gpt-4");
            assert_eq!(
                model_run(&crate::pipes::judge_jury::target_to_provider(&openai), &json!({ "model": 4 })),
                "gpt-4o",
                "a model that is not a name falls back to the configured one"
            );
            assert_eq!(model_run(&crate::pipes::judge_jury::target_to_provider(&openai), &json!({})), "gpt-4o");

            let provider_of = |provider_type: &str, model: &str| {
                let mut llm = target("https://upstream.example/v1/chat/completions", None);
                llm.provider_type = provider_type.to_string();
                llm.model = model.to_string();
                crate::pipes::judge_jury::target_to_provider(&llm)
            };
            for (provider_type, configured) in
                [("azure", "gpt-4o-prod"), ("gemini", "gemini-2.5-pro"), ("bedrock", "anthropic.claude-sonnet-4-5")]
            {
                assert_eq!(
                    model_run(&provider_of(provider_type, configured), &naming("cheap-model")),
                    configured,
                    "{provider_type} ran the body's model"
                );
            }
            assert_eq!(
                model_run(&provider_of("bedrock", "meta.llama3-70b"), &naming("meta.llama3-8b")),
                "meta.llama3-8b",
                "Bedrock's OpenAI-compatible gateway runs the body's model"
            );
        }

        // ── An operator key never serves a model the catalog does not price ──

        /// Whether `error` is the refusal of a model the catalog does not price.
        fn unpriced_refusal(error: Option<&PipeError>) -> bool {
            match error {
                Some(PipeError::RequestFailed(message)) => message == crate::pipes::types::llm::MODEL_NOT_PRICED,
                Some(PipeError::WithIncurredUsage { inner, .. }) => unpriced_refusal(Some(inner.as_ref())),
                _ => false,
            }
        }

        #[tokio::test]
        async fn an_operator_key_never_serves_a_model_the_catalog_does_not_price() {
            let base = CaptureUpstream::answering("an answer").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let first = CaptureUpstream::answering("first answer").await;
            let _allowed = allow(&[&base, &judge_upstream, &first]);
            assert!(
                crate::pipes::types::llm::catalog_price("openai", "house-model", None).is_none(),
                "precondition: the catalog does not price house-model"
            );
            let config = tenant_surface(&base.url);

            let buffered = run_tenant_naming(&config, "house-model").await;
            let streamed = stream_tenant_naming(&config, "house-model").await;
            let mut judge_target = target(&judge_upstream.url, None);
            judge_target.model = "house-model".to_string();
            judge_target.api_key_secret = Some("model-key".to_string());
            let judged = crate::pipes::judge_jury::execute_judge(
                "p-targets",
                &judge(judge_target),
                &request(),
                &tenant_secrets(),
            )
            .await;
            assert!(unpriced_refusal(buffered.as_ref().err()), "the buffered call was not refused");
            assert!(unpriced_refusal(streamed.as_ref().err()), "the streamed call was not refused");
            assert!(unpriced_refusal(judged.as_ref().err()), "the Judge was not refused");
            assert_eq!(base.requests(), 0, "the operator's key served an unpriced model");
            assert_eq!(judge_upstream.requests(), 0, "the Judge spent the operator's key on an unpriced model");

            let mut mirrored = tenant_surface(&base.url);
            let mut mirror_target = target(&first.url, None);
            mirror_target.model = "house-model".to_string();
            mirror_target.api_key_secret = Some("model-key".to_string());
            mirrored.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![candidate("first", mirror_target)],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Collect,
                    ..Default::default()
                },
                disable_thinking: None,
            });
            let _ = run_tenant(&mirrored).await;
            assert_eq!(first.requests(), 0, "a Mirror candidate spent the operator's key on an unpriced model");
        }

        #[tokio::test]
        async fn a_priced_model_or_a_key_the_caller_may_price_still_serves_an_unpriced_model() {
            let base = CaptureUpstream::answering("an answer").await;
            let _allowed = allow(&[&base]);

            let (_, priced) = run_tenant_naming(&tenant_surface(&base.url), "gpt-4")
                .await
                .expect("a priced model on the operator's key is served");
            assert_eq!(priced.llm_usage.cost, price_of("gpt-4"));

            let mut own = tenant_surface(&base.url);
            own_key(&mut own);
            let (_, own_metrics) = run_tenant_naming(&own, "house-model")
                .await
                .expect("the tenant's own key serves any model");
            assert_eq!(own_metrics.llm_usage.cost, 0.0);

            let mut appliance = surface(&base.url);
            appliance.upstream_headers = Vec::new();
            let (_, appliance_metrics) = PipeExecutor::new_with_secrets(&appliance, Some(tenant_store()))
                .execute(naming("house-model"), None, None, None, None)
                .await
                .expect("an appliance-wide surface serves any model");
            assert_eq!(
                appliance_metrics
                    .llm_usage
                    .cost,
                0.0
            );
            assert_eq!(base.models(), vec!["gpt-4", "house-model", "house-model"]);
        }

        // ── Headers only to the origin they were configured for ──

        #[tokio::test]
        async fn target_headers_are_refused_for_a_request_to_another_origin() {
            let exec =
                PipeExecutor::new_with_secrets(&surface("https://198.51.100.1/v1/chat/completions"), Some(store()));
            let gateway = target("https://gateway.example/v1/chat/completions", Some("candidate-tunnel"));
            let provider = crate::pipes::judge_jury::target_to_provider(&gateway);

            let refused = exec
                .resolve_provider_headers(
                    &provider,
                    TargetHeaders::of_target(&gateway),
                    "https://elsewhere.example/v1/chat/completions",
                    false,
                    &CallerCredentials::default(),
                    UpstreamCall::Poll,
                )
                .await;
            let sent = exec
                .resolve_provider_headers(
                    &provider,
                    TargetHeaders::of_target(&gateway),
                    "https://gateway.example/v1/chat/completions",
                    false,
                    &CallerCredentials::default(),
                    UpstreamCall::Poll,
                )
                .await
                .expect("the target's own origin gets its headers");

            assert!(
                matches!(&refused, Err(PipeError::RequestFailed(message)) if message == crate::pipes::upstream_headers::HEADERS_OFF_ORIGIN),
                "headers went to another origin: {:?}",
                refused.map(|resolved| resolved.headers)
            );
            assert!(
                sent.headers
                    .iter()
                    .any(|(name, value)| name == KEY_HEADER && value == "CANDIDATE")
            );
        }

        #[tokio::test]
        async fn a_request_sends_the_secret_the_tenancy_check_resolved() {
            // `uuid-of-b` is tenant B's internal id and also the public id of
            // tenant A's secret. The tenancy check resolves it to B's secret
            // (`pipe_tenancy`'s `the_check_resolves_a_reference_as_a_request_would`);
            // every request-time resolver must send B's, never A's.
            let base = CaptureUpstream::answering("an answer").await;
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let _allowed = allow(&[&base, &judge_upstream]);
            let shadowed: Arc<dyn SecretsStore> = Arc::new(MemorySecretsStore::with(vec![
                secret("uuid-model", "model-key", "MODEL", None),
                secret("uuid-of-b", "b-tunnel-key", "B-VALUE", Some("tenant-b")),
                secret("uuid-of-a", "uuid-of-b", "A-VALUE", Some("tenant-a")),
            ]));
            let mut config = surface(&base.url);
            config.tenant_id = Some("tenant-b".to_string());
            config.upstream_headers = key_header("uuid-of-b");
            config.judge = Some(judge(target(&judge_upstream.url, Some("uuid-of-b"))));

            PipeExecutor::new_with_secrets(&config, Some(shadowed))
                .execute(request(), None, None, None, None)
                .await
                .expect("answers");

            assert_eq!(base.header_values(KEY_HEADER), vec!["B-VALUE"]);
            assert_eq!(judge_upstream.header_values(KEY_HEADER), vec!["B-VALUE"]);
        }

        // ── Declared prices ──

        /// A surface whose every stage is a `gpt-4o` capture upstream: Judge,
        /// juror, a Route decider's router and its candidate.
        async fn every_bucket(priced: bool) -> (ExecutionMetrics, Vec<CaptureUpstream>) {
            let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let juror_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
            let router = CaptureUpstream::answering(r#"{"candidate":"own"}"#).await;
            let chosen = CaptureUpstream::answering("from the candidate").await;
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&judge_upstream, &juror_upstream, &router, &chosen, &base]);
            let price = |mut llm: crate::pipes::judge_jury::LLMTarget| {
                llm.pricing = priced.then(free);
                llm
            };
            let mut config = surface(&base.url);
            config.judge = Some(judge(price(target(&judge_upstream.url, None))));
            config.jury = Some(jury(price(target(&juror_upstream.url, None))));
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                llm: Some(price(target(&router.url, None))),
                system_prompt: "Route.".to_string(),
                candidates: vec![candidate("own", price(target(&chosen.url, None)))],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                disable_thinking: None,
            });

            let (_, metrics) = run(&config)
                .await
                .expect("every stage answers");
            (metrics, vec![judge_upstream, juror_upstream, router, chosen, base])
        }

        #[tokio::test]
        async fn a_zero_price_is_honoured_in_every_bucket() {
            let (metrics, upstreams) = every_bucket(true).await;

            for upstream in &upstreams[..4] {
                assert_eq!(upstream.requests(), 1, "precondition: every stage ran");
            }
            assert!(metrics.llm_usage.input_tokens > 0, "precondition: the main call reported usage");
            assert_eq!(metrics.llm_usage.cost, 0.0);
            assert_eq!(metrics.judge_usage.cost, 0.0);
            assert_eq!(metrics.jury_usage.cost, 0.0);
            assert_eq!(metrics.decider_usage.cost, 0.0);
            assert_eq!(metrics.cost, 0.0);
        }

        #[tokio::test]
        async fn an_unpriced_target_keeps_its_catalog_price_in_every_bucket() {
            let (metrics, _upstreams) = every_bucket(false).await;

            let catalog = crate::pipes::types::llm::TokenPricing::for_model("openai", "gpt-4o")
                .expect("gpt-4o has a built-in price")
                .calculate_cost(1000, 1000);
            assert!(catalog > 0.0);
            assert_eq!(metrics.llm_usage.cost, catalog);
            assert_eq!(metrics.judge_usage.cost, catalog);
            assert_eq!(metrics.jury_usage.cost, catalog);
            assert_eq!(metrics.decider_usage.cost, catalog);
        }

        #[tokio::test]
        async fn a_zero_price_beats_the_surface_override_on_the_base_and_a_failover_backup() {
            let base = CaptureUpstream::answering("from the base").await;
            let _allowed = allow(&[&base]);
            let mut config = surface(&base.url);
            config.cost_tracking = Some(crate::pipes::config::CostTrackingConfig {
                enabled: true,
                input_price_per_1k: Some(0.01),
                output_price_per_1k: Some(0.02),
                monthly_budget_usd: None,
                alert_threshold_percent: None,
            });
            let (_, overridden) = run(&config)
                .await
                .expect("answers");
            assert!(overridden.llm_usage.cost > 0.0, "precondition: the override prices the base");

            config.upstream_pricing = Some(free());
            let (_, declared) = run(&config)
                .await
                .expect("answers");
            assert_eq!(declared.llm_usage.cost, 0.0);

            let failing = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
            let _allowed = allow(&[&failing, &base]);
            let mut config = surface(&failing.url);
            let mut backup = target(&base.url, None);
            backup.pricing = Some(free());
            config.failover = Some(crate::pipes::config::FailoverConfig {
                enabled: true,
                targets: vec![crate::pipes::config::FailoverTarget { llm: backup }],
            });
            let (_, failed_over) = run(&config)
                .await
                .expect("the backup answers");
            assert_eq!(failed_over.llm_usage.cost, 0.0);
            assert!(
                failed_over
                    .llm_usage
                    .input_tokens
                    > 0,
                "precondition: the backup reported usage"
            );
        }

        #[tokio::test]
        async fn mirror_candidates_and_the_merger_are_billed_at_their_declared_price() {
            let base = CaptureUpstream::answering("from the base").await;
            let first = CaptureUpstream::answering("first answer").await;
            let merger = CaptureUpstream::answering("merged answer").await;
            let _allowed = allow(&[&base, &first, &merger]);
            let mut config = surface(&base.url);
            let mut own = target(&first.url, None);
            own.pricing = Some(free());
            let mut own_merger = target(&merger.url, None);
            own_merger.pricing = Some(free());
            config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                enabled: true,
                strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                llm: None,
                system_prompt: String::new(),
                candidates: vec![candidate("first", own)],
                default_candidate_id: None,
                mirror: crate::pipes::judge_jury::MirrorConfig {
                    mode: crate::pipes::judge_jury::MirrorMode::Merge,
                    merger: Some(own_merger),
                    merge_system_prompt: String::new(),
                    disable_thinking: None,
                },
                disable_thinking: None,
            });

            let (_, metrics) = run(&config)
                .await
                .expect("the merger answers");

            assert_eq!(first.requests(), 1, "precondition: the candidate ran");
            assert_eq!(merger.requests(), 1, "precondition: the merger ran");
            assert!(metrics.llm_usage.input_tokens >= 2000, "precondition: both calls reported usage");
            assert_eq!(metrics.llm_usage.cost, 0.0);
        }

        #[test]
        fn a_streamed_upstream_is_billed_at_its_declared_price() {
            let catalog = crate::pipes::streaming::cost_for_tokens(None, true, "openai", "gpt-4o", 1000, 1000);
            assert!(catalog > 0.0, "precondition: gpt-4o has a catalog price");
            assert_eq!(
                crate::pipes::streaming::cost_for_tokens(Some(&free()), true, "openai", "gpt-4o", 1000, 1000),
                0.0
            );
        }

        #[test]
        fn lowest_cost_load_balancing_and_price_routing_use_the_declared_price() {
            let mut config = surface("https://198.51.100.1/v1/chat/completions");
            let mut own = target("https://198.51.100.2/v1/chat/completions", None);
            own.pricing = Some(free());
            config.load_balancing = Some(
                serde_json::from_value(json!({
                    "enabled": true,
                    "strategy": "lowest_cost",
                    "targets": [{ "llm": own, "weight": 1 }]
                }))
                .expect("load balancing config"),
            );
            let exec = PipeExecutor::new(&config);
            let lb = config
                .load_balancing
                .as_ref()
                .expect("configured");

            assert_eq!(exec.member_unit_cost(lb, 1), 0.0);
            assert!(exec.member_unit_cost(lb, 0) > 0.0, "precondition: the unpriced primary has a catalog price");
            assert_eq!(exec.lowest_cost_start(lb, &[1, 1]), 1);

            let prefs = crate::pipes::request_routing::parse(&json!({ "provider": { "sort": "price" } }))
                .expect("routing preferences");
            let ordered = exec.apply_price_preferences(&prefs, exec.build_routing_pool());
            assert!(ordered[0].target.is_some(), "the free target must sort first");
        }

        // ── Key sources and billing ──
        //
        // The caller's key reaches only the surface's primary provider's main
        // call; every other call sends its own stored key. A call on an owned
        // key (the caller's or the tenant's) bills nothing; a platform call
        // bills its cost.

        mod key_sources {
            use super::*;
            use crate::pipes::types::llm::{OverridePolicy, ParameterOverrideConfig};

            const AUTH: &str = "authorization";
            const CALLER_KEY: &str = "sk-caller";

            /// A request carrying the caller's own key in `Authorization`,
            /// on a surface whose front door does not read that header.
            fn caller_header() -> CallerCredentials {
                CallerCredentials {
                    authorization: Some(format!("Bearer {CALLER_KEY}")),
                    upstream_authorization: None,
                    provider_key: Some(CALLER_KEY.to_string()),
                }
            }

            fn bearer(value: &str) -> String {
                format!("Bearer {value}")
            }

            fn api_key_policy(
                config: &mut PipeConfig,
                policy: OverridePolicy,
            ) {
                config.override_policy = Some(ParameterOverrideConfig {
                    api_key: Some(policy),
                    ..Default::default()
                });
            }

            /// The surface on `url` without the operator's ingress header, so
            /// the only credential a call sends is its key.
            fn key_only_surface(url: &str) -> PipeConfig {
                let mut config = surface(url);
                config
                    .upstream_headers
                    .clear();
                config
            }

            /// A target at `url` sending the stored key `secret`.
            fn keyed_target(
                url: &str,
                secret: &str,
            ) -> crate::pipes::judge_jury::LLMTarget {
                let mut llm = target(url, None);
                llm.api_key_secret = Some(secret.to_string());
                llm
            }

            async fn run_with_caller_key(
                config: &PipeConfig,
                store: Arc<dyn SecretsStore>,
                body: Value,
            ) -> Result<(Value, ExecutionMetrics), PipeError> {
                PipeExecutor::new_with_secrets(config, Some(store))
                    .execute_with_path_and_auth(body, None, caller_header(), None, None, None, None, None)
                    .await
            }

            #[tokio::test]
            async fn the_callers_key_serves_the_primary_main_call_and_bills_nothing() {
                let base = CaptureUpstream::answering("from the base").await;
                let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                let _allowed = allow(&[&base, &judge_upstream]);
                let mut config = key_only_surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));

                let (_, metrics) = run_with_caller_key(&config, store(), request())
                    .await
                    .expect("answers");

                assert_eq!(base.header_values(AUTH), vec![bearer(CALLER_KEY)]);
                assert_eq!(judge_upstream.header_values(AUTH), vec![bearer("MODEL")], "the Judge sends its own key");
                assert_eq!(metrics.key_source, Some(KeySource::Client));
                assert_eq!(metrics.llm_usage.key_sources, KeySourceCounts::one(KeySource::Client));
                assert!(metrics.llm_usage.cost > 0.0, "precondition: the main call has a catalog cost");
                assert_eq!(metrics.llm_usage.billed_cost, 0.0, "the caller's own key bills nothing");
                assert_eq!(
                    metrics
                        .judge_usage
                        .key_sources,
                    KeySourceCounts::one(KeySource::Platform)
                );
                assert!(metrics.judge_usage.cost > 0.0, "precondition: the Judge has a catalog cost");
                assert_eq!(
                    metrics
                        .judge_usage
                        .billed_cost,
                    metrics.judge_usage.cost
                );
                assert_eq!(metrics.billed_cost, metrics.judge_usage.cost, "only the Judge's platform call bills");
                assert_eq!(metrics.cost, metrics.llm_usage.cost + metrics.judge_usage.cost);

                let record = metrics.record_metrics(&config);
                assert_eq!(record.key_source, Some(KeySource::Client));
                assert_eq!(record.billed_cost, Some(metrics.billed_cost));
                let counts = record
                    .key_sources
                    .expect("calls are counted");
                assert_eq!((counts.client, counts.customer, counts.platform), (1, 0, 1));
                let llm_entry = record
                    .usage_by_stage
                    .iter()
                    .find(|e| e.stage == "llm")
                    .expect("an llm entry");
                assert_eq!(llm_entry.billed_cost, Some(0.0));
            }

            #[tokio::test]
            async fn a_platform_key_bills_its_whole_cost() {
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = allow(&[&base]);
                let config = surface(&base.url);

                let (_, metrics) = run_with_caller_key(&config, store(), request())
                    .await
                    .expect("answers");

                assert_eq!(base.header_values(AUTH), vec![bearer("MODEL")], "no policy: the stored key is sent");
                assert_eq!(metrics.key_source, Some(KeySource::Platform));
                assert!(metrics.cost > 0.0, "precondition: the call has a catalog cost");
                assert_eq!(metrics.billed_cost, metrics.cost);
            }

            #[tokio::test]
            async fn a_customers_stored_key_bills_nothing() {
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = allow(&[&base]);
                let mut config = tenant_surface(&base.url);
                own_key(&mut config);

                let (_, metrics) = run_tenant(&config)
                    .await
                    .expect("answers");

                assert_eq!(base.header_values(AUTH), vec![bearer("OWN")]);
                assert_eq!(metrics.key_source, Some(KeySource::Customer));
                assert!(metrics.cost > 0.0, "precondition: the cost is still the catalog's");
                assert_eq!(metrics.billed_cost, 0.0);

                // Precondition: the operator's key on the same surface is billed.
                let (_, operator) = run_tenant(&tenant_surface(&base.url))
                    .await
                    .expect("answers");
                assert_eq!(operator.key_source, Some(KeySource::Platform));
                assert_eq!(operator.billed_cost, operator.cost);
            }

            #[tokio::test]
            async fn a_rejected_caller_key_returns_the_refusal_and_never_fails_over_or_retries() {
                let base = CaptureUpstream::failing(StatusCode::UNAUTHORIZED).await;
                let backup = CaptureUpstream::answering("from the backup").await;
                let _allowed = allow(&[&base, &backup]);
                let mut config = surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                config.retry_policy = Some(crate::pipes::config::RetryPolicy {
                    max_retries: 2,
                    initial_backoff_ms: 1,
                    max_backoff_ms: 1,
                    backoff_multiplier: 1.0,
                });
                config.failover = Some(crate::pipes::config::FailoverConfig {
                    enabled: true,
                    targets: vec![crate::pipes::config::FailoverTarget {
                        llm: keyed_target(&backup.url, "model-key"),
                    }],
                });

                let refused = run_with_caller_key(&config, store(), request()).await;

                assert!(
                    matches!(refused, Err(PipeError::CallerKeyRejected { status: 401 })),
                    "the caller gets the provider's 401: {refused:?}"
                );
                assert_eq!(base.requests(), 1, "a refused caller key is not retried");
                assert_eq!(backup.requests(), 0, "a refused caller key never fails over");
                let shown = format!(
                    "{:?} {}",
                    refused.as_ref().err(),
                    refused
                        .as_ref()
                        .err()
                        .map(|e| e.to_string())
                        .unwrap_or_default()
                );
                assert!(!shown.contains(CALLER_KEY), "the error never carries the key");

                // Precondition: the same refusal of the operator's key fails over.
                let (_, served) = run(&config)
                    .await
                    .expect("the backup answers");
                assert_eq!(backup.requests(), 1);
                assert_eq!(served.key_source, Some(KeySource::Platform));
            }

            #[tokio::test]
            async fn a_failover_backup_or_pool_member_never_receives_the_callers_key() {
                for policy in [OverridePolicy::InjectIfMissing, OverridePolicy::ClientWins] {
                    let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let backup = CaptureUpstream::answering("from the backup").await;
                    let _allowed = allow(&[&base, &backup]);
                    let mut config = surface(&base.url);
                    api_key_policy(&mut config, policy.clone());
                    config.failover = Some(crate::pipes::config::FailoverConfig {
                        enabled: true,
                        targets: vec![crate::pipes::config::FailoverTarget {
                            llm: keyed_target(&backup.url, "model-key"),
                        }],
                    });
                    let body = json!({ "messages": [{ "role": "user", "content": "hello" }], "api_key": CALLER_KEY });

                    let (_, metrics) = run_with_caller_key(&config, store(), body)
                        .await
                        .expect("the backup answers");

                    assert_eq!(base.header_values(AUTH), vec![bearer(CALLER_KEY)], "{policy:?}: the primary gets it");
                    assert_eq!(
                        backup.header_values(AUTH),
                        vec![bearer("MODEL")],
                        "{policy:?}: the backup sends its own"
                    );
                    assert_eq!(backup.bodies_naming("api_key"), 0, "{policy:?}: no body key reaches the backup");
                    assert_eq!(metrics.key_source, Some(KeySource::Platform));
                    assert_eq!(metrics.billed_cost, metrics.cost);
                }

                let pool = CaptureUpstream::answering("from the pool").await;
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = allow(&[&base, &pool]);
                let mut config = surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                config.load_balancing = Some(
                    serde_json::from_value(json!({
                        "enabled": true,
                        "primary_weight": 0,
                        "targets": [{ "llm": keyed_target(&pool.url, "model-key"), "weight": 1 }]
                    }))
                    .expect("load balancing config"),
                );
                run_with_caller_key(&config, store(), request())
                    .await
                    .expect("the pool member answers");
                assert_eq!(base.requests(), 0, "precondition: the pool member was picked");
                assert_eq!(pool.header_values(AUTH), vec![bearer("MODEL")]);
            }

            #[tokio::test]
            async fn a_decider_candidate_or_mirror_upstream_never_receives_the_callers_key() {
                let base = CaptureUpstream::answering("from the base").await;
                let router = CaptureUpstream::answering(r#"{"candidate":"own"}"#).await;
                let chosen = CaptureUpstream::answering("from the candidate").await;
                let _allowed = allow(&[&base, &router, &chosen]);
                let mut config = surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::ClientWins);
                config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                    enabled: true,
                    strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                    llm: Some(keyed_target(&router.url, "model-key")),
                    system_prompt: "Route.".to_string(),
                    candidates: vec![candidate("own", keyed_target(&chosen.url, "model-key"))],
                    default_candidate_id: None,
                    mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                    disable_thinking: None,
                });

                let (_, metrics) = run_with_caller_key(&config, store(), request())
                    .await
                    .expect("the candidate answers");

                assert_eq!(router.header_values(AUTH), vec![bearer("MODEL")]);
                assert_eq!(chosen.header_values(AUTH), vec![bearer("MODEL")]);
                assert_eq!(metrics.key_source, Some(KeySource::Platform));
                assert_eq!(
                    metrics
                        .decider_usage
                        .key_sources,
                    KeySourceCounts::one(KeySource::Platform)
                );

                let first = CaptureUpstream::answering("first answer").await;
                let merger = CaptureUpstream::answering("merged answer").await;
                let _allowed = allow(&[&base, &first, &merger]);
                let mut config = surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::ClientWins);
                config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                    enabled: true,
                    strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                    llm: None,
                    system_prompt: String::new(),
                    candidates: vec![candidate("first", keyed_target(&first.url, "model-key"))],
                    default_candidate_id: None,
                    mirror: crate::pipes::judge_jury::MirrorConfig {
                        mode: crate::pipes::judge_jury::MirrorMode::Merge,
                        merger: Some(keyed_target(&merger.url, "model-key")),
                        merge_system_prompt: String::new(),
                        disable_thinking: None,
                    },
                    disable_thinking: None,
                });

                let (_, metrics) = run_with_caller_key(&config, store(), request())
                    .await
                    .expect("the merger answers");

                assert_eq!(first.header_values(AUTH), vec![bearer("MODEL")]);
                assert_eq!(merger.header_values(AUTH), vec![bearer("MODEL")]);
                assert_eq!(
                    metrics.llm_usage.key_sources,
                    KeySourceCounts {
                        platform: 2,
                        ..Default::default()
                    },
                    "the candidate and the merger both bill"
                );
                assert_eq!(metrics.billed_cost, metrics.cost);
            }

            #[tokio::test]
            async fn a_stream_reports_its_key_source_and_a_refused_caller_key() {
                let base = CaptureUpstream::answering("streamed").await;
                let _allowed = allow(&[&base]);
                let mut config = key_only_surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                let exec = PipeExecutor::new_with_secrets(&config, Some(store()));

                let client = exec
                    .execute_streaming(request(), None, caller_header(), None)
                    .await
                    .expect("streams");
                let platform = exec
                    .execute_streaming(request(), None, CallerCredentials::default(), None)
                    .await
                    .expect("streams");
                assert_eq!(client.key_source, KeySource::Client);
                assert_eq!(platform.key_source, KeySource::Platform);
                assert_eq!(base.header_values(AUTH), vec![bearer(CALLER_KEY), bearer("MODEL")]);

                let refusing = CaptureUpstream::failing(StatusCode::FORBIDDEN).await;
                let _allowed = allow(&[&refusing]);
                let mut config = surface(&refusing.url);
                api_key_policy(&mut config, OverridePolicy::ClientWins);
                let refused = PipeExecutor::new_with_secrets(&config, Some(store()))
                    .execute_streaming(request(), None, caller_header(), None)
                    .await;
                assert!(matches!(refused, Err(PipeError::CallerKeyRejected { status: 403 })));
            }

            #[tokio::test]
            async fn a_callers_key_beside_an_operator_header_is_a_platform_call() {
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = allow(&[&base]);
                // The surface's own upstream also takes the operator's ingress key.
                let mut config = surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);

                let (_, metrics) = run_with_caller_key(&config, store(), request())
                    .await
                    .expect("answers");

                assert_eq!(base.header_values(AUTH), vec![bearer(CALLER_KEY)]);
                assert_eq!(base.header_values(KEY_HEADER), vec!["BASE".to_string()]);
                assert_eq!(
                    metrics.key_source,
                    Some(KeySource::Platform),
                    "an operator credential makes it the platform's"
                );
                assert!(metrics.cost > 0.0, "precondition: the call has a catalog cost");
                assert_eq!(metrics.billed_cost, metrics.cost);

                // Its refusal is still the refusal of the caller's key: final.
                let refusing = CaptureUpstream::failing(StatusCode::UNAUTHORIZED).await;
                let backup = CaptureUpstream::answering("from the backup").await;
                let _allowed = allow(&[&refusing, &backup]);
                let mut config = surface(&refusing.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                config.failover = Some(crate::pipes::config::FailoverConfig {
                    enabled: true,
                    targets: vec![crate::pipes::config::FailoverTarget {
                        llm: keyed_target(&backup.url, "model-key"),
                    }],
                });
                let refused = run_with_caller_key(&config, store(), request()).await;
                assert!(matches!(refused, Err(PipeError::CallerKeyRejected { status: 401 })), "{refused:?}");
                assert_eq!(backup.requests(), 0, "a refused caller key never fails over");
            }

            #[tokio::test]
            async fn a_forwarded_identity_token_bills_the_operator_unless_its_provider_bills_the_user() {
                use crate::pipes::types::llm_provider_ext::LLMProviderExt;
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = allow(&[&base]);
                let mut config = key_only_surface(&base.url);
                config.forward_caller_token = true;
                let caller = CallerCredentials {
                    authorization: Some("Bearer user-token".to_string()),
                    upstream_authorization: None,
                    provider_key: None,
                };

                let (_, metrics) = PipeExecutor::new_with_secrets(&config, Some(store()))
                    .execute_with_path_and_auth(request(), None, caller.clone(), None, None, None, None, None)
                    .await
                    .expect("answers");
                assert_eq!(base.header_values(AUTH), vec![bearer("user-token")]);
                assert_eq!(metrics.key_source, Some(KeySource::Platform), "the operator's upstream bills the call");
                assert!(metrics.cost > 0.0, "precondition: the call has a catalog cost");
                assert_eq!(metrics.billed_cost, metrics.cost);

                // Microsoft 365 Copilot bills the signed-in user's own licence.
                let copilot: LLMProvider =
                    serde_json::from_value(json!({ "provider_type": "m365_copilot", "model": "copilot" }))
                        .expect("copilot provider");
                let mut copilot_config = config.clone();
                copilot_config.pipe_type = PipeType::LLM {
                    provider: Box::new(copilot.clone()),
                    endpoint_path: None,
                };
                let exec = PipeExecutor::new_with_secrets(&copilot_config, Some(store()));
                let headers = exec
                    .build_provider_headers(
                        &copilot,
                        exec.surface_headers_for(&copilot),
                        &copilot.get_endpoint(),
                        true,
                        &caller,
                    )
                    .await
                    .expect("headers");
                assert_eq!(headers.key_source, KeySource::Client);
                assert!(headers.sent_caller_credential);

                // A refused forwarded token is final, whatever the call bills.
                let refusing = CaptureUpstream::failing(StatusCode::UNAUTHORIZED).await;
                let backup = CaptureUpstream::answering("from the backup").await;
                let _allowed = allow(&[&refusing, &backup]);
                let mut config = key_only_surface(&refusing.url);
                config.forward_caller_token = true;
                config.failover = Some(crate::pipes::config::FailoverConfig {
                    enabled: true,
                    targets: vec![crate::pipes::config::FailoverTarget {
                        llm: keyed_target(&backup.url, "model-key"),
                    }],
                });
                let refused = PipeExecutor::new_with_secrets(&config, Some(store()))
                    .execute_with_path_and_auth(request(), None, caller, None, None, None, None, None)
                    .await;
                assert!(matches!(refused, Err(PipeError::CallerKeyRejected { status: 401 })), "{refused:?}");
                assert_eq!(backup.requests(), 0);
            }

            #[tokio::test]
            async fn a_providers_bad_key_answer_on_the_callers_key_is_final_and_keeps_no_body() {
                let gemini = json!({ "error": {
                    "code": 400,
                    "message": "API key not valid. Please pass a valid API key.",
                    "status": "INVALID_ARGUMENT",
                    "details": [{ "reason": "API_KEY_INVALID", "domain": "googleapis.com" }]
                }});
                let base = CaptureUpstream::failing_with(StatusCode::BAD_REQUEST, gemini).await;
                let backup = CaptureUpstream::answering("from the backup").await;
                let _allowed = allow(&[&base, &backup]);
                let mut config = key_only_surface(&base.url);
                api_key_policy(&mut config, OverridePolicy::InjectIfMissing);
                config.retry_policy = Some(crate::pipes::config::RetryPolicy {
                    max_retries: 2,
                    initial_backoff_ms: 1,
                    max_backoff_ms: 1,
                    backoff_multiplier: 1.0,
                });
                config.failover = Some(crate::pipes::config::FailoverConfig {
                    enabled: true,
                    targets: vec![crate::pipes::config::FailoverTarget {
                        llm: keyed_target(&backup.url, "model-key"),
                    }],
                });

                let refused = run_with_caller_key(&config, store(), request()).await;
                assert!(matches!(refused, Err(PipeError::CallerKeyRejected { status: 400 })), "{refused:?}");
                assert_eq!(base.requests(), 1, "not retried");
                assert_eq!(backup.requests(), 0, "not failed over to a stored key");
            }

            #[tokio::test]
            async fn a_stored_keys_refusal_returns_no_provider_body() {
                let echo = json!({ "error": { "message": "Incorrect API key provided: sk-...MODL", "code": "invalid_api_key" } });
                let base = CaptureUpstream::failing_with(StatusCode::UNAUTHORIZED, echo).await;
                let _allowed = allow(&[&base]);
                let failed = run(&key_only_surface(&base.url)).await;
                let shown = format!("{:?}", failed.as_ref().err());
                assert!(matches!(failed, Err(PipeError::UpstreamResponse { status: 401, .. })), "{shown}");
                assert!(!shown.contains("sk-"), "the key fragment never reaches the error: {shown}");
            }

            #[tokio::test]
            async fn a_body_api_key_never_reaches_the_judge_or_its_governance_input() {
                let base = CaptureUpstream::answering("from the base").await;
                let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                let _allowed = allow(&[&base, &judge_upstream]);
                let mut config = key_only_surface(&base.url);
                config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));
                // No user message, so the Judge evaluates the whole body.
                let body = json!({ "api_key": "sk-body-key", "input_items": ["evaluate me"] });

                let (_, metrics) = PipeExecutor::new_with_secrets(&config, Some(store()))
                    .execute(body, None, None, None, None)
                    .await
                    .expect("answers");

                assert_eq!(judge_upstream.bodies_containing("evaluate me"), 1, "precondition: the Judge saw the body");
                assert_eq!(judge_upstream.bodies_containing("sk-body-key"), 0, "the body key never reaches the Judge");
                let judge_input = metrics
                    .stages
                    .iter()
                    .find(|stage| stage.stage == "judge")
                    .and_then(|stage| stage.input.clone())
                    .expect("the Judge's governance input");
                assert!(judge_input.contains("evaluate me") && !judge_input.contains("sk-body-key"), "{judge_input}");
            }

            #[tokio::test]
            async fn a_failed_request_keeps_the_spend_its_judge_incurred_on_every_attempt() {
                let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                let _allowed = allow(&[&base, &judge_upstream]);
                let mut config = key_only_surface(&base.url);
                config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));
                config.retry_policy = Some(crate::pipes::config::RetryPolicy {
                    max_retries: 1,
                    initial_backoff_ms: 1,
                    max_backoff_ms: 1,
                    backoff_multiplier: 1.0,
                });

                let failed = run(&config).await;
                let Err(PipeError::WithIncurredUsage { inner, usage }) = failed else {
                    panic!("the failure carries the Judge's spend: {failed:?}");
                };
                assert!(matches!(*inner, PipeError::UpstreamResponse { status: 500, .. }), "{inner:?}");
                assert_eq!(judge_upstream.requests(), 2, "precondition: each attempt ran the Judge");
                assert_eq!(
                    usage.judge.key_sources,
                    KeySourceCounts {
                        platform: 2,
                        ..Default::default()
                    }
                );
                assert!(usage.total_billed_cost() > 0.0, "the operator's Judge calls bill");
            }

            #[tokio::test]
            async fn a_failing_jury_keeps_the_spend_of_the_main_call_it_reviewed() {
                let base = CaptureUpstream::answering("from the base").await;
                let juror = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                let _allowed = allow(&[&base, &juror]);
                let mut config = key_only_surface(&base.url);
                config.jury = Some(jury(keyed_target(&juror.url, "model-key")));

                let failed = run(&config).await;
                let Err(PipeError::WithIncurredUsage { usage, .. }) = failed else {
                    panic!("the failure carries the main call's spend: {failed:?}");
                };
                assert_eq!(base.requests(), 1, "precondition: the main call ran");
                assert_eq!(usage.llm.key_sources, KeySourceCounts::one(KeySource::Platform));
                assert!(usage.llm.cost > 0.0 && usage.llm.billed_cost == usage.llm.cost, "{:?}", usage.llm);
            }

            #[tokio::test]
            async fn a_final_jury_rejection_on_mirror_merge_keeps_the_candidates_spend() {
                let base = CaptureUpstream::answering("from the base").await;
                let first = CaptureUpstream::answering("first answer").await;
                let merger = CaptureUpstream::answering("merged answer").await;
                let juror = CaptureUpstream::answering(r#"{"decision":"reject","reason":"off topic"}"#).await;
                let _allowed = allow(&[&base, &first, &merger, &juror]);
                let mut config = key_only_surface(&base.url);
                config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                    enabled: true,
                    strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                    llm: None,
                    system_prompt: String::new(),
                    candidates: vec![candidate("first", keyed_target(&first.url, "model-key"))],
                    default_candidate_id: None,
                    mirror: crate::pipes::judge_jury::MirrorConfig {
                        mode: crate::pipes::judge_jury::MirrorMode::Merge,
                        merger: Some(keyed_target(&merger.url, "model-key")),
                        merge_system_prompt: String::new(),
                        disable_thinking: None,
                    },
                    disable_thinking: None,
                });
                config.jury = Some(jury(keyed_target(&juror.url, "model-key")));

                let rejected = run(&config).await;
                let Err(PipeError::PromptGuardRejected { usage: Some(usage), .. }) = rejected else {
                    panic!("the Jury's final rejection carries the attempt's spend: {rejected:?}");
                };
                assert_eq!(first.requests(), 1, "precondition: the candidate ran");
                let merger_calls = merger.requests() as u64;
                assert!(merger_calls >= 1, "precondition: the merger ran");
                assert_eq!(
                    usage.llm.key_sources.platform,
                    merger_calls + 1,
                    "every merger call and the candidate's are billed: {:?}",
                    usage.llm
                );
                assert_eq!(usage.llm.input_tokens, 1000 * (merger_calls + 1));
            }

            #[tokio::test]
            async fn a_judge_rejection_beside_the_decider_router_keeps_the_routers_spend() {
                let base = CaptureUpstream::answering("from the base").await;
                let router = CaptureUpstream::answering(r#"{"candidate":"own"}"#).await;
                let chosen = CaptureUpstream::answering("from the candidate").await;
                let judge_upstream = CaptureUpstream::answering("BLOCK").await;
                let _allowed = allow(&[&base, &router, &chosen, &judge_upstream]);
                let mut config = key_only_surface(&base.url);
                config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                    enabled: true,
                    strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                    llm: Some(keyed_target(&router.url, "model-key")),
                    system_prompt: "Route.".to_string(),
                    candidates: vec![candidate("own", keyed_target(&chosen.url, "model-key"))],
                    default_candidate_id: None,
                    mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                    disable_thinking: None,
                });
                config.judge = Some(
                    serde_json::from_value(json!({
                        "enabled": true,
                        "mode": "llm",
                        "llm": keyed_target(&judge_upstream.url, "model-key"),
                        "system_prompt": "Judge.",
                        "rules": [{
                            "name": "block",
                            "condition": { "type": "regex_match", "pattern": "BLOCK" },
                            "body": "blocked"
                        }]
                    }))
                    .expect("judge config"),
                );

                let rejected = run(&config).await;
                let Err(PipeError::PromptGuardRejected { usage: Some(usage), .. }) = rejected else {
                    panic!("the Judge's rejection carries its spend: {rejected:?}");
                };
                assert_eq!(router.requests(), 1, "precondition: the router ran beside the Judge");
                assert_eq!(chosen.requests(), 0);
                assert_eq!(
                    usage
                        .judge
                        .key_sources
                        .platform,
                    judge_upstream.requests() as u64
                );
                assert_eq!(
                    usage.decider.key_sources,
                    KeySourceCounts::one(KeySource::Platform),
                    "the router's call is billed too: {:?}",
                    usage.decider
                );
                assert!(usage.decider.billed_cost > 0.0);
            }

            #[tokio::test]
            async fn a_backup_that_serves_bills_the_spend_the_failed_primary_incurred() {
                let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                let backup = CaptureUpstream::answering("from the backup").await;
                let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                let _allowed = allow(&[&base, &backup, &judge_upstream]);
                let mut config = key_only_surface(&base.url);
                config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));
                config.failover = Some(crate::pipes::config::FailoverConfig {
                    enabled: true,
                    targets: vec![crate::pipes::config::FailoverTarget {
                        llm: keyed_target(&backup.url, "model-key"),
                    }],
                });

                let (_, metrics) = run(&config)
                    .await
                    .expect("the backup serves");
                assert_eq!(judge_upstream.requests(), 2, "precondition: the Judge ran for the primary and the backup");
                assert_eq!(
                    metrics
                        .judge_usage
                        .key_sources
                        .platform,
                    2,
                    "both Judge calls are billed"
                );
                assert_eq!(metrics.billed_cost, metrics.cost, "every call ran on the operator's keys and bills");
                assert!(metrics.cost >= metrics.llm_usage.cost + metrics.judge_usage.cost - 1e-12);
            }

            #[tokio::test]
            async fn a_text_to_speech_call_bills_its_input_text_by_its_key_source() {
                let base = CaptureUpstream::answering("audio").await;
                let _allowed = test_service_endpoints::allow(&[format!("{}/v1/audio/speech", base.url)]);
                let price = crate::pipes::types::llm::TargetPricing {
                    input_per_million: 15.0,
                    output_per_million: 0.0,
                };
                let body = json!({ "model": "tts-1", "input": "hello world", "voice": "alloy" });
                let expected = 11.0 * 15.0 / 1_000_000.0;

                let mut config = key_only_surface(&base.url);
                config.upstream_pricing = Some(price);
                let platform = PipeExecutor::new_with_secrets(&config, Some(store()))
                    .execute_binary(body.clone(), Some("/v1/audio/speech".to_string()), CallerCredentials::default())
                    .await
                    .expect("speaks");
                assert_eq!(platform.key_source, KeySource::Platform);
                assert!((platform.cost - expected).abs() < 1e-12, "{}", platform.cost);
                assert_eq!(platform.billed_cost(), platform.cost);

                let mut owned = tenant_surface(&base.url);
                own_key(&mut owned);
                owned.upstream_pricing = Some(price);
                let customer = PipeExecutor::new_with_secrets(&owned, Some(tenant_store()))
                    .execute_binary(body, Some("/v1/audio/speech".to_string()), CallerCredentials::default())
                    .await
                    .expect("speaks");
                assert_eq!(customer.key_source, KeySource::Customer);
                assert!((customer.cost - expected).abs() < 1e-12);
                assert_eq!(customer.billed_cost(), 0.0);
            }

            #[tokio::test]
            async fn a_calls_prompt_cache_tokens_are_priced_beside_its_input() {
                let base = CaptureUpstream::failing_with(
                    StatusCode::OK,
                    json!({
                        "id": "chatcmpl-cache",
                        "object": "chat.completion",
                        "choices": [{ "index": 0, "message": { "role": "assistant", "content": "ok" }, "finish_reason": "stop" }],
                        "usage": {
                            "prompt_tokens": 1000,
                            "completion_tokens": 1000,
                            "cache_creation_input_tokens": 1_000_000,
                            "cache_read_input_tokens": 1_000_000
                        }
                    }),
                )
                .await;
                let _allowed = allow(&[&base]);
                let mut config = key_only_surface(&base.url);
                config.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
                    input_per_million: 3.0,
                    output_per_million: 15.0,
                });

                let (_, metrics) = run(&config)
                    .await
                    .expect("answers");

                // Writes at 1.25x and reads at 0.1x the $3 input price.
                let expected = 1000.0 * 3.0 / 1e6 + 1000.0 * 15.0 / 1e6 + 3.75 + 0.30;
                assert!((metrics.cost - expected).abs() < 1e-9, "{}", metrics.cost);
                assert_eq!(metrics.billed_cost, metrics.cost, "the operator's key bills it");
                assert!((metrics.llm_usage.cost - expected).abs() < 1e-9);
            }

            #[tokio::test]
            async fn a_binary_call_that_reaches_no_speech_endpoint_is_refused_on_every_key() {
                let base = CaptureUpstream::answering("from the base").await;
                let _allowed = test_service_endpoints::allow(&[
                    format!("{}/v1/audio/speech", base.url),
                    format!("{}/v1/chat/completions%3F/audio/speech", base.url),
                ]);
                let body = json!({ "model": "claude-sonnet-4", "input": "hi", "messages": [{ "role": "user", "content": "hi" }] });
                let speak = |config: PipeConfig, path: Option<&'static str>| {
                    let body = body.clone();
                    async move {
                        PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                            .execute_binary(body, path.map(str::to_string), CallerCredentials::default())
                            .await
                    }
                };
                // A fixed-endpoint provider (Anthropic always posts to its
                // Messages endpoint), on the customer's key and on the
                // operator's.
                for key in ["own-key", "model-key"] {
                    let mut anthropic = tenant_surface(&base.url);
                    anthropic
                        .upstream_headers
                        .clear();
                    anthropic.pipe_type = PipeType::LLM {
                        provider: Box::new(LLMProvider::Anthropic {
                            provider_type: "anthropic".to_string(),
                            model: "claude-sonnet-4".to_string(),
                            api_key_secret: Some(key.to_string()),
                            version: None,
                            temperature: None,
                            max_tokens: None,
                            top_p: None,
                            frequency_penalty: None,
                            presence_penalty: None,
                        }),
                        endpoint_path: None,
                    };
                    let refused = speak(anthropic, Some("/v1/audio/speech")).await;
                    assert!(matches!(refused, Err(PipeError::BinaryEndpointUnsupported)), "{key}: {:?}", refused.err());
                }
                // An OpenAI-compatible provider with no path, or a path that
                // only an edge decoding `%3F` would cut at the chat endpoint.
                for path in [None, Some("/v1/chat/completions%3F/audio/speech")] {
                    let mut owned = tenant_surface(&base.url);
                    own_key(&mut owned);
                    let refused = speak(owned, path).await;
                    assert!(
                        matches!(refused, Err(PipeError::BinaryEndpointUnsupported)),
                        "{path:?}: {:?}",
                        refused.err()
                    );
                }
                assert_eq!(base.requests(), 0, "nothing was sent");

                let mut owned = tenant_surface(&base.url);
                own_key(&mut owned);
                speak(owned, Some("/v1/audio/speech"))
                    .await
                    .expect("a speech path on an OpenAI-compatible provider runs");
                assert_eq!(base.requests(), 1);
            }

            // ── The member budget, per call ──
            //
            // A platform-key call is refused while the member's budget is
            // spent; a call on the caller's or the customer's own key always
            // runs. `own-key` is tenant A's own (customer) key and `model-key`
            // the operator's (platform) key.

            mod budget {
                use super::*;
                use crate::teams::call_budget::{self, CallBudget, test_support};

                /// Run `config` on tenant A's secrets with `budget` as the
                /// request's budget.
                async fn run_with_budget(
                    config: &PipeConfig,
                    budget: Arc<CallBudget>,
                ) -> Result<(Value, ExecutionMetrics), PipeError> {
                    call_budget::scope(Some(budget), run_tenant(config)).await
                }

                /// Tenant A's surface on `url` sending its own key.
                fn owned_surface(url: &str) -> PipeConfig {
                    let mut config = tenant_surface(url);
                    own_key(&mut config);
                    config
                }

                fn failover(targets: Vec<crate::pipes::judge_jury::LLMTarget>) -> crate::pipes::config::FailoverConfig {
                    crate::pipes::config::FailoverConfig {
                        enabled: true,
                        targets: targets
                            .into_iter()
                            .map(|llm| crate::pipes::config::FailoverTarget { llm })
                            .collect(),
                    }
                }

                fn refused_as(
                    result: &Result<(Value, ExecutionMetrics), PipeError>,
                    expected: BudgetedCall,
                ) -> bool {
                    matches!(result, Err(PipeError::BudgetExhausted { call, reason }) if *call == expected && reason.contains("monthly budget"))
                }

                #[tokio::test]
                async fn with_no_credit_a_request_on_the_customers_key_runs_and_bills_nothing() {
                    let base = CaptureUpstream::answering("from the customer's key").await;
                    let _allowed = allow(&[&base]);

                    let (_, metrics) = run_with_budget(&owned_surface(&base.url), test_support::spent().await)
                        .await
                        .expect("an owned key is never refused");

                    assert_eq!(base.header_values(AUTH), vec![bearer("OWN")]);
                    assert_eq!(metrics.key_source, Some(KeySource::Customer));
                    assert!(metrics.cost > 0.0, "precondition: the call has a catalog cost");
                    assert_eq!(metrics.billed_cost, 0.0);
                }

                #[tokio::test]
                async fn with_no_credit_a_request_on_a_platform_key_is_refused_before_it_is_sent() {
                    let base = CaptureUpstream::answering("from the operator's key").await;
                    let _allowed = allow(&[&base]);
                    let mut config = tenant_surface(&base.url);
                    config.retry_policy = Some(crate::pipes::config::RetryPolicy {
                        max_retries: 2,
                        initial_backoff_ms: 1,
                        max_backoff_ms: 1,
                        backoff_multiplier: 1.0,
                    });

                    let refused = run_with_budget(&config, test_support::spent().await).await;

                    assert!(refused_as(&refused, BudgetedCall::Upstream), "{refused:?}");
                    assert_eq!(base.requests(), 0, "nothing is sent, and nothing is retried");
                }

                #[tokio::test]
                async fn with_credit_every_call_runs_and_bills_as_before() {
                    let base = CaptureUpstream::answering("from the operator's key").await;
                    let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                    let _allowed = allow(&[&base, &judge_upstream]);
                    let mut config = tenant_surface(&base.url);
                    config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));

                    let (_, metrics) = run_with_budget(&config, test_support::unspent())
                        .await
                        .expect("credit left");

                    assert_eq!((base.requests(), judge_upstream.requests()), (1, 1));
                    assert_eq!(metrics.key_source, Some(KeySource::Platform));
                    assert!(metrics.billed_cost > 0.0);
                    assert_eq!(metrics.billed_cost, metrics.cost);
                }

                #[tokio::test]
                async fn the_callers_own_key_never_meets_the_budget() {
                    let base = CaptureUpstream::answering("from the caller's key").await;
                    let _allowed = allow(&[&base]);
                    let mut config = key_only_surface(&base.url);
                    api_key_policy(&mut config, OverridePolicy::ClientWins);

                    let (_, metrics) = call_budget::scope(
                        Some(test_support::spent().await),
                        run_with_caller_key(&config, store(), request()),
                    )
                    .await
                    .expect("the caller's key is never refused");

                    assert_eq!(base.header_values(AUTH), vec![bearer(CALLER_KEY)]);
                    assert_eq!(metrics.key_source, Some(KeySource::Client));
                    assert_eq!(metrics.billed_cost, 0.0);
                }

                /// `config` with no stored key: its calls send no credential.
                fn keyless(mut config: PipeConfig) -> PipeConfig {
                    if let PipeType::LLM { provider, .. } = &mut config.pipe_type
                        && let LLMProvider::OpenAI { api_key_secret, .. } = provider.as_mut()
                    {
                        *api_key_secret = None;
                    }
                    config
                }

                #[tokio::test]
                async fn with_no_credit_a_keyless_call_is_refused_only_when_it_is_priced() {
                    let base = CaptureUpstream::answering("from a keyless upstream").await;
                    let _allowed = allow(&[&base]);
                    let mut config = keyless(key_only_surface(&base.url));
                    config.upstream_pricing = Some(free());

                    let (_, metrics) = call_budget::scope(Some(test_support::spent().await), run(&config))
                        .await
                        .expect("an unpriced keyless call bills nothing and runs");
                    assert!(
                        base.header_values(AUTH)
                            .is_empty(),
                        "precondition: the call sent no key"
                    );
                    assert_eq!(metrics.billed_cost, 0.0);

                    // The same keyless call priced from the catalog bills, so it is refused.
                    config.upstream_pricing = None;
                    let refused = call_budget::scope(Some(test_support::spent().await), run(&config)).await;
                    assert!(refused_as(&refused, BudgetedCall::Upstream), "{refused:?}");
                    assert_eq!(base.requests(), 1, "the priced keyless call was not sent");
                }

                #[tokio::test]
                async fn with_no_credit_keyless_guards_and_an_unpriced_keyless_judge_still_run() {
                    let base = CaptureUpstream::answering("from the customer's key").await;
                    let witness = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let detector = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                    let _allowed = allow(&[&base, &witness, &detector, &judge_upstream]);

                    let mut config = owned_surface(&base.url);
                    config.expert_witnesses = vec![
                        serde_json::from_value(json!({
                            "id": "witness",
                            "name": "Witness",
                            "endpoint_url": witness.url,
                            "fail_open": true,
                            "check_response": false
                        }))
                        .expect("witness config"),
                    ];
                    config.prompt_guard = Some(
                        serde_json::from_value(json!({
                            "enabled": true,
                            "llm_pii": [{
                                "endpoint_url": detector.url,
                                "model": "pii",
                                "fail_closed": false,
                                "cache_detection": false
                            }]
                        }))
                        .expect("prompt guard config"),
                    );
                    let mut free_judge = target(&judge_upstream.url, None);
                    free_judge.pricing = Some(free());
                    config.judge = Some(judge(free_judge));

                    run_with_budget(&config, test_support::spent().await)
                        .await
                        .expect("keyless guards and an unpriced keyless Judge are never refused");
                    assert_eq!(witness.requests(), 1, "the keyless witness was called");
                    assert_eq!(detector.requests(), 1, "the keyless detector was called");
                    assert_eq!(judge_upstream.requests(), 1, "the unpriced keyless Judge was called");
                    assert_eq!(base.requests(), 1);
                }

                /// Run `body` against `path` on `config`, tenant A's secrets,
                /// with `budget` in scope (none when `None`).
                async fn run_path(
                    config: &PipeConfig,
                    path: &str,
                    body: Value,
                    budget: Option<Arc<CallBudget>>,
                ) -> Result<(Value, ExecutionMetrics), PipeError> {
                    let exec = PipeExecutor::new_with_secrets(config, Some(tenant_store()));
                    call_budget::scope(
                        budget,
                        exec.execute_with_path(body, Some(path.to_string()), None, None, None, None),
                    )
                    .await
                }

                fn not_metered<T>(
                    result: &Result<T, PipeError>,
                    expected: crate::pipes::metering::Unmetered,
                ) -> bool {
                    matches!(result, Err(e) if e.not_metered() == Some(expected) && e.upstream_unaffordable())
                }

                fn shared_credential_refused<T>(
                    result: &Result<T, PipeError>,
                    expected: crate::pipes::shared_credential::SharedCredentialRefusal,
                ) -> bool {
                    matches!(result, Err(e) if e.shared_credential_refusal() == Some(expected))
                }

                /// An appliance-wide surface on `url` sending the operator's
                /// key: a platform key, so the metering rules apply where a
                /// budget is in scope, but no tenant shares that key with the
                /// surface, so the shared-credential rule never applies.
                fn appliance_surface(url: &str) -> PipeConfig {
                    let mut config = surface(url);
                    config.upstream_headers = Vec::new();
                    config
                }

                #[tokio::test]
                async fn a_batch_on_a_platform_key_is_refused_while_a_budget_is_enforced() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("batch created").await;
                    let paths = ["/v1/batches", "/v1/batche%73"];
                    let _allowed = test_service_endpoints::allow(
                        &paths
                            .iter()
                            .map(|path| format!("{}{path}", base.url))
                            .collect::<Vec<_>>(),
                    );

                    for path in paths {
                        let refused =
                            run_path(&tenant_surface(&base.url), path, request(), Some(test_support::unspent())).await;
                        assert!(
                            not_metered(&refused, Unmetered::Batch),
                            "even with credit left, a batch on the operator's key is refused ({path}): {refused:?}"
                        );
                    }
                    assert_eq!(base.requests(), 0);

                    let refused = run_path(
                        &appliance_surface(&base.url),
                        "/v1/batches",
                        request(),
                        Some(test_support::unspent()),
                    )
                    .await;
                    assert!(
                        not_metered(&refused, Unmetered::Batch),
                        "the metering rule follows the key, so an appliance-wide surface is refused too: {refused:?}"
                    );
                    assert_eq!(base.requests(), 0);

                    run_path(&owned_surface(&base.url), "/v1/batches", request(), Some(test_support::unspent()))
                        .await
                        .expect("a batch on the customer's own key runs");
                    // With no budget enforced the metering rule is silent; a
                    // tenant's surface still never reaches the store behind
                    // the operator's key (the shared-credential rule).
                    let refused = run_path(&tenant_surface(&base.url), "/v1/batches", request(), None).await;
                    assert!(
                        shared_credential_refused(
                            &refused,
                            crate::pipes::shared_credential::SharedCredentialRefusal::Call
                        ),
                        "with no budget enforced, a tenant's batch on the operator's key: {refused:?}"
                    );
                    run_path(&appliance_surface(&base.url), "/v1/batches", request(), None)
                        .await
                        .expect("with no budget enforced, an appliance-wide surface's batch runs as before");
                    assert_eq!(base.requests(), 2);
                }

                #[tokio::test]
                async fn hosted_tools_and_audio_or_image_output_are_refused_on_a_platform_key_under_a_budget() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("an answer").await;
                    let _allowed = allow(&[&base]);
                    let with = |field: &str, value: Value| {
                        let mut body = request();
                        body[field] = value;
                        body
                    };
                    let cases = [
                        (with("tools", json!([{ "type": "web_search" }])), Unmetered::Tool),
                        (with("plugins", json!([{ "id": "web" }])), Unmetered::Tool),
                        (with("web_search_options", json!({})), Unmetered::Tool),
                        (with("search_parameters", json!({ "mode": "on" })), Unmetered::Tool),
                        // A search model named by id searches on every call.
                        (with("model", json!("gpt-4o-search-preview")), Unmetered::Tool),
                        (with("modalities", json!(["text", "audio"])), Unmetered::Modality),
                        (with("modalities", json!(["text", "image"])), Unmetered::Modality),
                        // Stored provider context cannot be counted.
                        (with("previous_response_id", json!("resp_1")), Unmetered::StoredContext),
                        (with("conversation", json!({ "id": "conv_1" })), Unmetered::StoredContext),
                    ];
                    let run = |config: PipeConfig, body: Value, budget: Option<Arc<CallBudget>>| async move {
                        call_budget::scope(
                            budget,
                            PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                                .execute(body, None, None, None, None),
                        )
                        .await
                    };
                    for (body, expected) in cases.clone() {
                        let refused = run(tenant_surface(&base.url), body.clone(), Some(test_support::unspent())).await;
                        assert!(not_metered(&refused, expected), "{body}: {:?}", refused.err());
                    }
                    assert_eq!(base.requests(), 0, "nothing was sent on the operator's key");

                    let mut sent = 0;
                    for (body, expected) in cases.clone() {
                        run(owned_surface(&base.url), body.clone(), Some(test_support::unspent()))
                            .await
                            .unwrap_or_else(|e| panic!("the customer's own key runs {body}: {e:?}"));
                        run(appliance_surface(&base.url), body.clone(), None)
                            .await
                            .unwrap_or_else(|e| panic!("with no budget in scope {body} runs: {e:?}"));
                        sent += 2;
                        // With no budget in scope a tenant's surface on the
                        // operator's key still never names stored provider
                        // context (the shared-credential rule); the rest runs.
                        let tenant = run(tenant_surface(&base.url), body.clone(), None).await;
                        if expected == Unmetered::StoredContext {
                            assert!(
                                shared_credential_refused(
                                    &tenant,
                                    crate::pipes::shared_credential::SharedCredentialRefusal::Call
                                ),
                                "with no budget in scope, a tenant's {body}: {:?}",
                                tenant.err()
                            );
                        } else {
                            tenant.unwrap_or_else(|e| panic!("with no budget in scope a tenant's {body} runs: {e:?}"));
                            sent += 1;
                        }
                    }
                    assert_eq!(base.requests(), sent);

                    // Function tools run on the operator's key.
                    let function = with("tools", json!([{ "type": "function", "function": { "name": "f" } }]));
                    run(tenant_surface(&base.url), function, Some(test_support::unspent()))
                        .await
                        .expect("function tools are metered");
                }

                #[tokio::test]
                async fn a_priority_service_tier_is_stripped_on_a_platform_key_under_a_budget() {
                    let base = CaptureUpstream::answering("an answer").await;
                    let _allowed = allow(&[&base]);
                    let tiered = |tier: &str| {
                        let mut body = request();
                        body["service_tier"] = json!(tier);
                        body
                    };
                    let run = |config: PipeConfig, body: Value, budget: Option<Arc<CallBudget>>| async move {
                        call_budget::scope(
                            budget,
                            PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                                .execute(body, None, None, None, None),
                        )
                        .await
                        .expect("answers");
                    };
                    run(tenant_surface(&base.url), tiered("priority"), Some(test_support::unspent())).await;
                    assert_eq!(base.bodies_naming("service_tier"), 0, "priority stripped on the operator's key");
                    run(tenant_surface(&base.url), tiered("flex"), Some(test_support::unspent())).await;
                    run(owned_surface(&base.url), tiered("priority"), Some(test_support::unspent())).await;
                    run(tenant_surface(&base.url), tiered("priority"), None).await;
                    assert_eq!(
                        base.bodies_naming("service_tier"),
                        3,
                        "flex, the customer's own key and no budget keep the caller's tier"
                    );
                }

                #[tokio::test]
                async fn an_image_output_model_is_refused_on_a_platform_key_unless_its_image_output_is_priced() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("an answer").await;
                    let _allowed = allow(&[&base]);
                    // Priced at a text rate, as BR1's catalog prices
                    // OpenRouter's image models; no image-output price.
                    let mut config = key_only_surface(&base.url);
                    config.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
                        input_per_million: 10.0,
                        output_per_million: 10.0,
                    });
                    let ask = |model: &str| json!({ "model": model, "messages": [{ "role": "user", "content": "a picture" }] });
                    let run = |body: Value, budget: Option<Arc<CallBudget>>| {
                        let config = config.clone();
                        async move {
                            call_budget::scope(
                                budget,
                                PipeExecutor::new_with_secrets(&config, Some(store()))
                                    .execute(body, None, None, None, None),
                            )
                            .await
                        }
                    };
                    run(ask("gpt-5-mini"), Some(test_support::unspent()))
                        .await
                        .expect("precondition: the surface's price meters a text model");
                    for model in ["openai/gpt-5-image-mini", "gemini-2.5-flash-image"] {
                        let refused = run(ask(model), Some(test_support::unspent())).await;
                        assert!(not_metered(&refused, Unmetered::Modality), "{model}: {:?}", refused.err());
                    }
                    assert_eq!(base.requests(), 1);
                    run(ask("openai/gpt-5-image-mini"), None)
                        .await
                        .expect("with no budget in scope an image model runs as before");
                    assert_eq!(base.requests(), 2);
                }

                #[tokio::test]
                async fn a_gemini_pro_request_above_its_long_context_threshold_is_refused_unless_priced() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("an answer").await;
                    let _allowed = allow(&[&base]);
                    let mut config = key_only_surface(&base.url);
                    config.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
                        input_per_million: 1.25,
                        output_per_million: 10.0,
                    });
                    let ask = |chars: usize| json!({ "model": "gemini-2.5-pro", "messages": [{ "role": "user", "content": "x".repeat(chars) }] });
                    let run = |body: Value, budget: Option<Arc<CallBudget>>| {
                        let config = config.clone();
                        async move {
                            call_budget::scope(
                                budget,
                                PipeExecutor::new_with_secrets(&config, Some(store()))
                                    .execute(body, None, None, None, None),
                            )
                            .await
                        }
                    };
                    // About 225,000 tokens of input, past Gemini Pro's 200k tier.
                    let refused = run(ask(900_000), Some(test_support::unspent())).await;
                    assert!(not_metered(&refused, Unmetered::LongContext), "{:?}", refused.err());
                    // Numeric text runs at a token a digit: 250,000 digits are
                    // past the tier, though a quarter of that at chars/4.
                    let digits = json!({ "model": "gemini-2.5-pro", "messages": [{ "role": "user", "content": "7".repeat(250_000) }] });
                    let refused = run(digits, Some(test_support::unspent())).await;
                    assert!(not_metered(&refused, Unmetered::LongContext), "{:?}", refused.err());
                    assert_eq!(base.requests(), 0);

                    run(ask(4_000), Some(test_support::unspent()))
                        .await
                        .expect("below the threshold the standard price applies");
                    run(ask(900_000), None)
                        .await
                        .expect("with no budget in scope a long request runs as before");
                    assert_eq!(base.requests(), 2);
                }

                #[tokio::test]
                async fn a_platform_key_under_a_budget_runs_only_on_endpoints_whose_spend_is_metered() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("an answer").await;
                    let unmetered = [
                        "/v1/fine_tuning/jobs",
                        "/v1/realtime/client_secrets",
                        "/v1/images/generations",
                        "/v1/completions",
                    ];
                    let metered = ["/v1/chat/completions", "/v1/embeddings", "/v1/responses"];
                    let _allowed = test_service_endpoints::allow(
                        &unmetered
                            .iter()
                            .chain(&metered)
                            .map(|path| format!("{}{path}", base.url))
                            .collect::<Vec<_>>(),
                    );
                    let background = || {
                        let mut body = request();
                        body["background"] = json!(true);
                        body
                    };

                    for path in unmetered {
                        let refused =
                            run_path(&tenant_surface(&base.url), path, request(), Some(test_support::unspent())).await;
                        assert!(not_metered(&refused, Unmetered::Endpoint), "{path}: {refused:?}");
                    }
                    let refused = run_path(
                        &tenant_surface(&base.url),
                        "/v1/responses",
                        background(),
                        Some(test_support::unspent()),
                    )
                    .await;
                    assert!(not_metered(&refused, Unmetered::Endpoint), "a background response: {refused:?}");
                    let streamed = call_budget::scope(
                        Some(test_support::unspent()),
                        PipeExecutor::new_with_secrets(&tenant_surface(&base.url), Some(tenant_store()))
                            .execute_streaming(
                                request(),
                                Some("/v1/fine_tuning/jobs".to_string()),
                                CallerCredentials::default(),
                                None,
                            ),
                    )
                    .await;
                    assert!(not_metered(&streamed, Unmetered::Endpoint), "streamed: {:?}", streamed.err());
                    assert_eq!(base.requests(), 0, "nothing unmetered was sent on the operator's key");

                    for path in metered {
                        run_path(&tenant_surface(&base.url), path, request(), Some(test_support::unspent()))
                            .await
                            .unwrap_or_else(|e| panic!("{path} is metered: {e:?}"));
                    }
                    assert_eq!(base.requests(), metered.len());

                    run_path(
                        &owned_surface(&base.url),
                        "/v1/fine_tuning/jobs",
                        request(),
                        Some(test_support::unspent()),
                    )
                    .await
                    .expect("the customer's own key runs any endpoint");
                    run_path(&owned_surface(&base.url), "/v1/responses", background(), Some(test_support::unspent()))
                        .await
                        .expect("the customer's own key runs a background response");
                    // With no budget in scope the metering rule is silent; a
                    // tenant's surface on the operator's key still calls only
                    // stateless endpoints (the shared-credential rule).
                    let refused = run_path(&tenant_surface(&base.url), "/v1/fine_tuning/jobs", request(), None).await;
                    assert!(
                        shared_credential_refused(
                            &refused,
                            crate::pipes::shared_credential::SharedCredentialRefusal::Call
                        ),
                        "with no budget in scope, a tenant's fine-tuning call: {refused:?}"
                    );
                    run_path(&appliance_surface(&base.url), "/v1/fine_tuning/jobs", request(), None)
                        .await
                        .expect("with no budget in scope, an appliance-wide surface runs any endpoint as before");
                    assert_eq!(base.requests(), metered.len() + 3);
                }

                #[tokio::test]
                async fn an_upload_or_a_poll_on_a_platform_key_is_refused_under_a_budget() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("{}").await;
                    let _allowed = test_service_endpoints::allow(&[
                        format!("{}/v1/audio/transcriptions", base.url),
                        format!("{}/v1/files/file-1", base.url),
                    ]);
                    let upload = |config: PipeConfig| async move {
                        PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                            .execute_upload(
                                Some("/v1/audio/transcriptions".to_string()),
                                "multipart/form-data; boundary=x".to_string(),
                                b"--x--".to_vec(),
                                CallerCredentials::default(),
                            )
                            .await
                    };
                    let poll = |config: PipeConfig| async move {
                        PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                            .execute_get(Some("/v1/files/file-1".to_string()), CallerCredentials::default())
                            .await
                    };

                    let refused =
                        call_budget::scope(Some(test_support::unspent()), upload(tenant_surface(&base.url))).await;
                    assert!(not_metered(&refused, Unmetered::Endpoint), "speech-to-text: {:?}", refused.err());
                    let refused =
                        call_budget::scope(Some(test_support::unspent()), poll(tenant_surface(&base.url))).await;
                    assert!(not_metered(&refused, Unmetered::Endpoint), "a poll: {:?}", refused.err());
                    assert_eq!(base.requests(), 0);

                    call_budget::scope(Some(test_support::unspent()), upload(owned_surface(&base.url)))
                        .await
                        .expect("an upload on the customer's own key runs");
                    call_budget::scope(Some(test_support::unspent()), poll(owned_surface(&base.url)))
                        .await
                        .expect("a poll on the customer's own key runs");
                    upload(tenant_surface(&base.url))
                        .await
                        .expect("with no budget in scope, an upload runs as before");
                    assert_eq!(base.requests(), 3);
                }

                /// A tenant's surface on the operator's key, where both the
                /// budget's rules and the shared-credential rule refuse: the
                /// spent budget answers first, then the metering rule, then
                /// the shared-credential rule, and nothing is ever sent. Where
                /// the metering rule allows the call (a chat completion naming
                /// a stored file), the shared-credential rule still refuses
                /// it under a budget.
                #[tokio::test]
                async fn where_both_rules_refuse_the_budget_answers_first_then_metering_then_the_shared_key_rule() {
                    use crate::pipes::metering::Unmetered;
                    use crate::pipes::shared_credential::SharedCredentialRefusal;
                    let base = CaptureUpstream::answering("{}").await;
                    let _allowed = test_service_endpoints::allow(&[
                        format!("{}/v1/files", base.url),
                        format!("{}/v1/audio/speech", base.url),
                        format!("{}/v1/chat/completions", base.url),
                    ]);
                    let executor = || PipeExecutor::new_with_secrets(&tenant_surface(&base.url), Some(tenant_store()));
                    let speech_naming_a_file =
                        || json!({ "model": "tts-1", "input": "hi", "file_id": "file-of-another-tenant" });

                    #[derive(Debug, Clone, Copy)]
                    enum Path {
                        Poll,
                        Upload,
                        Speech,
                        Chat,
                        Stream,
                    }
                    async fn send(
                        executor: PipeExecutor,
                        path: Path,
                        speech: Value,
                        budget: Option<Arc<CallBudget>>,
                    ) -> Option<PipeError> {
                        let call = async {
                            match path {
                                Path::Poll => executor
                                    .execute_get(Some("/v1/files".to_string()), CallerCredentials::default())
                                    .await
                                    .err(),
                                Path::Upload => executor
                                    .execute_upload(
                                        Some("/v1/files".to_string()),
                                        "multipart/form-data; boundary=x".to_string(),
                                        b"--x--".to_vec(),
                                        CallerCredentials::default(),
                                    )
                                    .await
                                    .err(),
                                Path::Speech => executor
                                    .execute_binary(
                                        speech,
                                        Some("/v1/audio/speech".to_string()),
                                        CallerCredentials::default(),
                                    )
                                    .await
                                    .err(),
                                Path::Chat => executor
                                    .execute_with_path(
                                        naming_a_stored_file(),
                                        Some("/v1/chat/completions".to_string()),
                                        None,
                                        None,
                                        None,
                                        None,
                                    )
                                    .await
                                    .err(),
                                Path::Stream => executor
                                    .execute_streaming(
                                        naming_a_stored_file(),
                                        Some("/v1/chat/completions".to_string()),
                                        CallerCredentials::default(),
                                        None,
                                    )
                                    .await
                                    .err(),
                            }
                        };
                        call_budget::scope(budget, Box::pin(call)).await
                    }

                    // (path, the metering answer under credit, the shared-credential answer)
                    let cases = [
                        (Path::Poll, Some(Unmetered::Endpoint), SharedCredentialRefusal::Read),
                        (Path::Upload, Some(Unmetered::Endpoint), SharedCredentialRefusal::Upload),
                        (Path::Speech, Some(Unmetered::UnpricedModel), SharedCredentialRefusal::Call),
                        (Path::Chat, None, SharedCredentialRefusal::Call),
                        (Path::Stream, None, SharedCredentialRefusal::Call),
                    ];
                    for (path, metering, shared) in cases {
                        let spent =
                            send(executor(), path, speech_naming_a_file(), Some(test_support::spent().await)).await;
                        assert!(
                            spent
                                .as_ref()
                                .and_then(PipeError::budget_refusal)
                                .is_some(),
                            "{path:?} with no credit: the spent budget answers first: {spent:?}"
                        );

                        let credit =
                            send(executor(), path, speech_naming_a_file(), Some(test_support::unspent())).await;
                        match metering {
                            Some(unmetered) => assert_eq!(
                                credit
                                    .as_ref()
                                    .and_then(PipeError::not_metered),
                                Some(unmetered),
                                "{path:?} with credit: the metering rule answers next: {credit:?}"
                            ),
                            None => assert_eq!(
                                credit
                                    .as_ref()
                                    .and_then(PipeError::shared_credential_refusal),
                                Some(shared),
                                "{path:?} with credit: metering allows it, the shared-credential rule still refuses: {credit:?}"
                            ),
                        }

                        let unbudgeted = send(executor(), path, speech_naming_a_file(), None).await;
                        assert_eq!(
                            unbudgeted
                                .as_ref()
                                .and_then(PipeError::shared_credential_refusal),
                            Some(shared),
                            "{path:?} with no budget in scope: the shared-credential rule answers: {unbudgeted:?}"
                        );
                    }
                    assert_eq!(base.requests(), 0, "nothing reached the store behind the operator's key");
                }

                /// An identity token forwarded to the operator's upstream is
                /// the operator's credential on a tenant's surface (that
                /// upstream bills the operator), so the shared-key rule holds
                /// it as it holds the operator's stored key.
                #[tokio::test]
                async fn a_forwarded_identity_token_on_a_tenant_surface_is_held_to_the_shared_key_rule() {
                    let base = CaptureUpstream::answering("{}").await;
                    let _allowed = test_service_endpoints::allow(&[format!("{}/v1/files", base.url)]);
                    let mut config = tenant_surface(&base.url);
                    config.forward_caller_token = true;
                    let caller = CallerCredentials {
                        authorization: Some("Bearer user-token".to_string()),
                        upstream_authorization: None,
                        provider_key: None,
                    };

                    let refused = PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                        .execute_get(Some("/v1/files".to_string()), caller)
                        .await;
                    assert!(
                        shared_credential_refused(
                            &refused,
                            crate::pipes::shared_credential::SharedCredentialRefusal::Read
                        ),
                        "a forwarded token read the shared store: {:?}",
                        refused.err()
                    );
                    assert_eq!(base.requests(), 0);
                }

                #[tokio::test]
                async fn text_to_speech_on_an_unpriced_model_is_refused_on_a_platform_key_under_a_budget() {
                    use crate::pipes::metering::Unmetered;
                    let base = CaptureUpstream::answering("audio").await;
                    let _allowed = test_service_endpoints::allow(&[format!("{}/v1/audio/speech", base.url)]);
                    let speak = |config: PipeConfig, model: &'static str| async move {
                        PipeExecutor::new_with_secrets(&config, Some(tenant_store()))
                            .execute_binary(
                                json!({ "model": model, "input": "hello", "voice": "alloy" }),
                                Some("/v1/audio/speech".to_string()),
                                CallerCredentials::default(),
                            )
                            .await
                    };
                    let unpriced = "house-tts";
                    assert!(
                        crate::pipes::types::llm::catalog_price("openai", unpriced, None).is_none(),
                        "precondition: the catalog does not price {unpriced}"
                    );

                    let refused =
                        call_budget::scope(Some(test_support::unspent()), speak(tenant_surface(&base.url), unpriced))
                            .await;
                    assert!(not_metered(&refused, Unmetered::UnpricedModel), "{:?}", refused.err());
                    let mut declared = tenant_surface(&base.url);
                    declared.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
                        input_per_million: 15.0,
                        output_per_million: 0.0,
                    });
                    let refused = call_budget::scope(Some(test_support::unspent()), speak(declared, unpriced)).await;
                    assert!(
                        not_metered(&refused, Unmetered::UnpricedModel),
                        "a tenant's own declared price is not honoured on the operator's key: {:?}",
                        refused.err()
                    );
                    assert_eq!(base.requests(), 0);

                    // A model priced by its audio output (an output rate, as
                    // `gpt-4o-mini-tts` is) is not metered by input characters.
                    let refused = call_budget::scope(
                        Some(test_support::unspent()),
                        speak(tenant_surface(&base.url), "gpt-4o-mini-tts"),
                    )
                    .await;
                    assert!(
                        not_metered(&refused, Unmetered::UnpricedModel),
                        "an output rate means audio pricing: {:?}",
                        refused.err()
                    );
                    assert_eq!(base.requests(), 0);

                    // A model priced by its input alone (as `tts-1`) speaks.
                    let mut operator = key_only_surface(&base.url);
                    operator.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
                        input_per_million: 15.0,
                        output_per_million: 0.0,
                    });
                    let priced = call_budget::scope(Some(test_support::unspent()), speak(operator, unpriced))
                        .await
                        .expect("a model priced by input speaks on the operator's key");
                    assert!(priced.cost > 0.0);
                    call_budget::scope(Some(test_support::unspent()), speak(owned_surface(&base.url), unpriced))
                        .await
                        .expect("an unpriced model speaks on the customer's own key");
                    speak(tenant_surface(&base.url), unpriced)
                        .await
                        .expect("with no budget in scope, an unpriced model speaks as before");
                    assert_eq!(base.requests(), 3);
                }

                #[tokio::test]
                async fn a_platform_failover_target_is_unavailable_and_the_next_owned_target_serves() {
                    let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let platform = CaptureUpstream::answering("from the operator's key").await;
                    let owned = CaptureUpstream::answering("from the customer's key").await;
                    let _allowed = allow(&[&base, &platform, &owned]);
                    let mut config = owned_surface(&base.url);
                    config.failover = Some(failover(vec![
                        keyed_target(&platform.url, "model-key"),
                        keyed_target(&owned.url, "own-key"),
                    ]));

                    let (_, metrics) = run_with_budget(&config, test_support::spent().await)
                        .await
                        .expect("the owned backup serves");

                    assert_eq!(base.requests(), 1, "the customer-key main call ran");
                    assert_eq!(platform.requests(), 0, "the platform backup was refused");
                    assert_eq!(owned.header_values(AUTH), vec![bearer("OWN")]);
                    assert_eq!(metrics.key_source, Some(KeySource::Customer));
                    assert_eq!(metrics.billed_cost, 0.0);

                    // With no owned target left, the request gets the budget's 429.
                    let base = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let _allowed = allow(&[&base, &platform]);
                    let mut config = owned_surface(&base.url);
                    config.failover = Some(failover(vec![keyed_target(&platform.url, "model-key")]));

                    let refused = run_with_budget(&config, test_support::spent().await).await;

                    assert_eq!(base.requests(), 1);
                    assert_eq!(platform.requests(), 0);
                    assert!(refused_as(&refused, BudgetedCall::Upstream), "{refused:?}");
                }

                #[tokio::test]
                async fn a_platform_primary_falls_over_to_an_owned_target_without_tripping_its_breaker() {
                    let base = CaptureUpstream::answering("from the operator's key").await;
                    let owned = CaptureUpstream::answering("from the customer's key").await;
                    let _allowed = allow(&[&base, &owned]);
                    let mut config = tenant_surface(&base.url);
                    config.circuit_breaker = Some(CircuitBreakerConfig {
                        failure_threshold: 1,
                        timeout_seconds: 60,
                        reset_timeout_seconds: 60,
                    });
                    config.failover = Some(failover(vec![keyed_target(&owned.url, "own-key")]));
                    let exec = PipeExecutor::new_with_secrets(&config, Some(tenant_store()));

                    let (_, metrics) = call_budget::scope(
                        Some(test_support::spent().await),
                        exec.execute(request(), None, None, None, None),
                    )
                    .await
                    .expect("the owned backup serves");

                    assert_eq!(base.requests(), 0);
                    assert_eq!(metrics.key_source, Some(KeySource::Customer));
                    assert!(
                        exec.circuit_breaker
                            .lock()
                            .await
                            .can_request()
                            .is_ok(),
                        "a budget refusal says nothing about the provider's health"
                    );
                }

                #[tokio::test]
                async fn a_load_balancing_member_or_mirror_candidate_on_a_platform_key_is_unavailable() {
                    let base = CaptureUpstream::answering("from the operator's key").await;
                    let owned = CaptureUpstream::answering("from the customer's key").await;
                    let _allowed = allow(&[&base, &owned]);
                    let mut config = tenant_surface(&base.url);
                    config.load_balancing = Some(
                        serde_json::from_value(json!({
                            "enabled": true,
                            "primary_weight": 1,
                            "targets": [{ "llm": keyed_target(&owned.url, "own-key"), "weight": 0 }]
                        }))
                        .expect("load balancing config"),
                    );

                    let (_, metrics) = run_with_budget(&config, test_support::spent().await)
                        .await
                        .expect("the owned pool member serves");
                    assert_eq!(base.requests(), 0, "the platform primary was refused");
                    assert_eq!(owned.requests(), 1);
                    assert_eq!(metrics.key_source, Some(KeySource::Customer));

                    let platform = CaptureUpstream::answering("from the operator's key").await;
                    let owned = CaptureUpstream::answering("from the customer's key").await;
                    let _allowed = allow(&[&base, &platform, &owned]);
                    let mirror = |candidates| crate::pipes::judge_jury::DeciderConfig {
                        enabled: true,
                        strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                        llm: None,
                        system_prompt: String::new(),
                        candidates,
                        default_candidate_id: None,
                        mirror: crate::pipes::judge_jury::MirrorConfig {
                            mode: crate::pipes::judge_jury::MirrorMode::Collect,
                            merger: None,
                            merge_system_prompt: String::new(),
                            disable_thinking: None,
                        },
                        disable_thinking: None,
                    };
                    let mut config = owned_surface(&base.url);
                    config.decider = Some(mirror(vec![
                        candidate("platform", keyed_target(&platform.url, "model-key")),
                        candidate("owned", keyed_target(&owned.url, "own-key")),
                    ]));

                    let (_, metrics) = run_with_budget(&config, test_support::spent().await)
                        .await
                        .expect("the owned candidate answers");
                    assert_eq!(platform.requests(), 0);
                    assert_eq!(owned.requests(), 1);
                    assert_eq!(metrics.llm_usage.key_sources, KeySourceCounts::one(KeySource::Customer));
                    assert_eq!(metrics.billed_cost, 0.0);

                    config.decider =
                        Some(mirror(vec![candidate("platform", keyed_target(&platform.url, "model-key"))]));
                    let refused = run_with_budget(&config, test_support::spent().await).await;
                    assert!(refused_as(&refused, BudgetedCall::Upstream), "{refused:?}");
                    assert_eq!(platform.requests(), 0);
                }

                #[tokio::test]
                async fn a_judge_on_a_platform_key_fails_closed_and_never_falls_over() {
                    let base = CaptureUpstream::answering("from the customer's key").await;
                    let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                    let backup = CaptureUpstream::answering("from the backup").await;
                    let _allowed = allow(&[&base, &judge_upstream, &backup]);
                    let mut config = owned_surface(&base.url);
                    config.judge = Some(judge(keyed_target(&judge_upstream.url, "model-key")));
                    config.failover = Some(failover(vec![keyed_target(&backup.url, "own-key")]));

                    let refused = run_with_budget(&config, test_support::spent().await).await;

                    assert!(refused_as(&refused, BudgetedCall::Stage), "{refused:?}");
                    assert_eq!(judge_upstream.requests(), 0, "the Judge was not called");
                    assert_eq!(base.requests(), 0, "the request never reached the model unjudged");
                    assert_eq!(backup.requests(), 0, "a refused safety stage is final");

                    // The streamed path refuses the same way.
                    let streamed = call_budget::scope(
                        Some(test_support::spent().await),
                        PipeExecutor::new_with_secrets(&config, Some(tenant_store())).execute_streaming(
                            request(),
                            None,
                            CallerCredentials::default(),
                            None,
                        ),
                    )
                    .await;
                    assert!(
                        matches!(&streamed, Err(e) if e.budget_refusal().is_some() && !e.upstream_unaffordable()),
                        "{:?}",
                        streamed.err()
                    );
                    assert_eq!(base.requests(), 0);
                }

                #[tokio::test]
                async fn a_juror_or_decider_router_on_a_platform_key_fails_closed() {
                    let base = CaptureUpstream::answering("from the customer's key").await;
                    let juror = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                    let router = CaptureUpstream::answering(r#"{"candidate":"owned"}"#).await;
                    let _allowed = allow(&[&base, &juror, &router]);
                    let mut config = owned_surface(&base.url);
                    config.jury = Some(jury(keyed_target(&juror.url, "model-key")));

                    let refused = run_with_budget(&config, test_support::spent().await).await;
                    assert!(refused_as(&refused, BudgetedCall::Stage), "{refused:?}");
                    assert_eq!(juror.requests(), 0, "the juror was not called");
                    assert_eq!(
                        base.requests(),
                        0,
                        "the response-side juror's platform key is checked before the customer-key main call runs"
                    );

                    let mut config = owned_surface(&base.url);
                    config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                        enabled: true,
                        strategy: crate::pipes::judge_jury::DeciderStrategy::Route,
                        llm: Some(keyed_target(&router.url, "model-key")),
                        system_prompt: "Route.".to_string(),
                        candidates: vec![candidate("owned", keyed_target(&base.url, "own-key"))],
                        default_candidate_id: Some("owned".to_string()),
                        mirror: crate::pipes::judge_jury::MirrorConfig::default(),
                        disable_thinking: None,
                    });
                    let refused = run_with_budget(&config, test_support::spent().await).await;
                    assert!(refused_as(&refused, BudgetedCall::Stage), "{refused:?}");
                    assert_eq!(router.requests(), 0, "the router was not called");
                    assert_eq!(base.requests(), 0, "no candidate was picked without the router");
                }

                #[tokio::test]
                async fn a_platform_mirror_merger_is_refused_before_the_customers_candidates_run() {
                    let base = CaptureUpstream::answering("from the base").await;
                    let first = CaptureUpstream::answering("first answer").await;
                    let merger = CaptureUpstream::answering("merged answer").await;
                    let judge_upstream = CaptureUpstream::answering(r#"{"decision":"approve"}"#).await;
                    let _allowed = allow(&[&base, &first, &merger, &judge_upstream]);
                    let mut config = owned_surface(&base.url);
                    config.decider = Some(crate::pipes::judge_jury::DeciderConfig {
                        enabled: true,
                        strategy: crate::pipes::judge_jury::DeciderStrategy::Mirror,
                        llm: None,
                        system_prompt: String::new(),
                        candidates: vec![candidate("first", keyed_target(&first.url, "own-key"))],
                        default_candidate_id: None,
                        mirror: crate::pipes::judge_jury::MirrorConfig {
                            mode: crate::pipes::judge_jury::MirrorMode::Merge,
                            merger: Some(keyed_target(&merger.url, "model-key")),
                            merge_system_prompt: String::new(),
                            disable_thinking: None,
                        },
                        disable_thinking: None,
                    });

                    let refused = run_with_budget(&config, test_support::spent().await).await;
                    assert!(refused_as(&refused, BudgetedCall::Upstream), "{refused:?}");
                    assert_eq!(first.requests(), 0, "the customer-key candidate did not run for nothing");
                    assert_eq!(merger.requests(), 0);

                    // A stage authenticated only by an operator header secret
                    // is asked up front as one with a key is.
                    let mut config = owned_surface(&base.url);
                    config.judge = Some(judge(target(&judge_upstream.url, Some("model-key"))));
                    let refused = run_with_budget(&config, test_support::spent().await).await;
                    assert!(refused_as(&refused, BudgetedCall::Stage), "{refused:?}");
                    assert_eq!(judge_upstream.requests(), 0);
                    assert_eq!(base.requests(), 0);
                }

                #[tokio::test]
                async fn a_fail_open_witness_or_pii_detector_on_a_platform_key_still_refuses() {
                    let base = CaptureUpstream::answering("from the customer's key").await;
                    let witness = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let detector = CaptureUpstream::failing(StatusCode::INTERNAL_SERVER_ERROR).await;
                    let _allowed = allow(&[&base, &witness, &detector]);

                    let mut with_witness = owned_surface(&base.url);
                    with_witness.expert_witnesses = vec![
                        serde_json::from_value(json!({
                            "id": "witness",
                            "name": "Witness",
                            "endpoint_url": witness.url,
                            "api_key_secret": "model-key",
                            "fail_open": true,
                            "check_response": false
                        }))
                        .expect("witness config"),
                    ];
                    let mut with_detector = owned_surface(&base.url);
                    with_detector.prompt_guard = Some(
                        serde_json::from_value(json!({
                            "enabled": true,
                            "llm_pii": [{
                                "endpoint_url": detector.url,
                                "model": "pii",
                                "api_key_secret": "model-key",
                                "fail_closed": false,
                                "cache_detection": false
                            }]
                        }))
                        .expect("prompt guard config"),
                    );

                    // Precondition: with credit, each one's outage lets the request through.
                    for config in [&with_witness, &with_detector] {
                        run_with_budget(config, test_support::unspent())
                            .await
                            .expect("a failing check that fails open lets the request through");
                    }
                    assert_eq!((witness.requests(), detector.requests(), base.requests()), (1, 1, 2));

                    for config in [&with_witness, &with_detector] {
                        let refused = run_with_budget(config, test_support::spent().await).await;
                        assert!(refused_as(&refused, BudgetedCall::Stage), "{refused:?}");
                    }
                    assert_eq!(
                        (witness.requests(), detector.requests(), base.requests()),
                        (1, 1, 2),
                        "neither check was skipped into a pass: the request was refused unsent"
                    );
                }

                #[tokio::test]
                async fn a_stream_on_a_platform_key_is_refused_and_one_on_an_owned_key_runs() {
                    let base = CaptureUpstream::answering("streamed").await;
                    let _allowed = allow(&[&base]);
                    let stream = |config: PipeConfig| async move {
                        call_budget::scope(
                            Some(test_support::spent().await),
                            PipeExecutor::new_with_secrets(&config, Some(tenant_store())).execute_streaming(
                                request(),
                                None,
                                CallerCredentials::default(),
                                None,
                            ),
                        )
                        .await
                    };

                    let refused = stream(tenant_surface(&base.url)).await;
                    assert!(matches!(&refused, Err(e) if e.upstream_unaffordable()), "{:?}", refused.err());
                    assert_eq!(base.requests(), 0);

                    let owned = stream(owned_surface(&base.url))
                        .await
                        .expect("an owned key streams");
                    assert_eq!(owned.key_source, KeySource::Customer);
                    assert_eq!(base.requests(), 1);
                }

                #[tokio::test]
                async fn a_semantic_cache_embedder_on_a_platform_key_is_skipped() {
                    let embedder_upstream = CaptureUpstream::answering("not an embedding").await;
                    let _allowed = allow(&[&embedder_upstream]);
                    let embedder = |secret: &str| crate::pipes::config::CacheEmbedder {
                        endpoint_url: embedder_upstream.url.clone(),
                        model: "embed".to_string(),
                        api_key_secret: Some(secret.to_string()),
                    };
                    let embed = |embedder: crate::pipes::config::CacheEmbedder| async move {
                        call_budget::scope(
                            Some(test_support::spent().await),
                            crate::pipes::cache_embedder::embed_text(&embedder, "hello", &tenant_secrets()),
                        )
                        .await
                    };

                    let refused = embed(embedder("model-key")).await;
                    assert!(
                        matches!(&refused, Err(crate::pipes::cache_embedder::EmbedError::BudgetRefused(_))),
                        "{refused:?}"
                    );
                    assert_eq!(embedder_upstream.requests(), 0);

                    let owned = embed(embedder("own-key")).await;
                    assert!(
                        matches!(&owned, Err(crate::pipes::cache_embedder::EmbedError::Failed(_))),
                        "precondition: the owned embedder is called (its answer is no embedding): {owned:?}"
                    );
                    assert_eq!(embedder_upstream.requests(), 1);
                }
            }
        }
    }
}
