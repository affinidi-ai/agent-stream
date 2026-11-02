//! Public API for executing requests through pipes

use axum::{
    Extension, Json,
    extract::{Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{debug, error, info, warn};

use super::executor::{ExecutionMetrics, PipeError, PipeExecutor};
use crate::auth_manager::pat::PatResourceScope;
use crate::identity::state::IdentityApiState;
use crate::metrics::ConnectionStatus;
use crate::pipes::config::StageUsage;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource};

async fn authorize_pipe_read(
    state: &IdentityApiState,
    pipe_id: &str,
    context: Option<&PatTenantContext>,
    scope: Option<&PatResourceScope>,
) -> Result<(), (StatusCode, String)> {
    let pipe = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Pipe store not initialized".to_string()))?
        .get(pipe_id)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Pipe not found: {}", pipe_id)))?;
    if !can_access(pipe.tenant_id.as_deref(), context)
        || !scope_allows_resource(scope, context, ResourceKind::Pipes, &pipe.id)
    {
        return Err((StatusCode::NOT_FOUND, format!("Pipe not found: {}", pipe_id)));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
pub struct ExecuteRequest {
    /// The request body to send to the LLM/service
    pub request: Value,
    /// Optional estimated input tokens for rate limiting
    pub estimated_input_tokens: Option<u64>,
    /// Optional trace ID for distributed tracing
    pub trace_id: Option<String>,
    /// Optional correlation ID to link requests
    pub correlation_id: Option<String>,
    /// Optional agent identity that originated this request
    pub agent_identity: Option<String>,
    /// Optional variant alias to execute. When set, the pipe is resolved to
    /// that `$alias` variant (full snapshot) before execution — letting the
    /// sandbox test a variant without going through the `route$alias` URL.
    /// When omitted, the base pipe is executed (no variant overlay).
    pub variant: Option<String>,
    /// Optional caller bearer token to forward to the surface as the inbound
    /// `Authorization`, so the sandbox can exercise surfaces that require a
    /// caller identity (e.g. a `forward_caller_token` Microsoft 365 Copilot
    /// surface) with a real delegated token acquired via the sandbox sign-in.
    /// The value is the raw token; the `Bearer ` scheme is added if absent.
    #[serde(default)]
    pub caller_token: Option<String>,
    /// Optional upstream conversation id to continue a stateful multi-turn
    /// conversation. Currently used by the Microsoft 365 Copilot streaming path:
    /// when set, the surface reuses that Copilot conversation (so follow-ups keep
    /// native memory) instead of opening a fresh one and replaying history. The
    /// id used is returned on the streamed response's
    /// `x-agent-stream-conversation-id` header so the client can send it back.
    #[serde(default)]
    pub conversation_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecuteResponse {
    /// The response from the LLM/service
    pub response: Value,
    /// Execution metrics
    pub metrics: ExecutionMetricsResponse,
}

#[derive(Debug, Serialize)]
pub struct ExecutionMetricsResponse {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    /// Per-stage breakdown of the grand totals above. `llm` is summed across
    /// every main-LLM attempt (including rejected jury retries); `judge` and
    /// `jury` carry their own token/cost spend.
    pub llm_usage: StageUsageResponse,
    pub judge_usage: StageUsageResponse,
    pub jury_usage: StageUsageResponse,
    pub decider_usage: StageUsageResponse,
    pub latency_ms: u64,
    pub provider: String,
    pub model: String,
    pub trace_id: String,
    pub correlation_id: Option<String>,
    pub agent_identity: Option<String>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub retry_count: u32,
    /// Provider-side cached prompt tokens reported by the upstream (`0` when the
    /// provider reports none). Distinct from Agent Stream's own response cache.
    #[serde(default)]
    pub cached_tokens: u64,
    /// Provider-side cache-write (cache-creation) prompt tokens (`0` when none).
    #[serde(default)]
    pub cache_write_tokens: u64,
    /// Provider-reported reasoning (thinking) tokens (`0` when the provider does
    /// not break them out). A sub-count of `output_tokens`, surfaced for
    /// visibility.
    #[serde(default)]
    pub reasoning_tokens: u64,
    /// Whether this turn was served from Agent Stream's response cache (no
    /// upstream call).
    #[serde(default)]
    pub cache_hit: bool,
    /// Provider spend avoided by a response-cache hit (`0.0` otherwise).
    #[serde(default)]
    pub cache_saved_cost: f64,
    /// Structured-output conformance when a `json_schema` response was requested
    /// (`true`/`false`); `null` when no structured output was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schema_valid: Option<bool>,
    /// The stateful Microsoft 365 Copilot conversation id this turn ran against
    /// (created or reused). `None` for non-Copilot. The sandbox sends it back on
    /// the next turn so the buffered path continues the same conversation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub conversation_id: Option<String>,
    /// The part of `cost` billed to the account: zero for calls served on the
    /// caller's or the customer's own key.
    pub billed_cost: f64,
    /// Source of the key the main call sent (`client`, `customer`, `platform`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<crate::pipes::key_source::KeySource>,
}

#[derive(Debug, Serialize)]
pub struct StageUsageResponse {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub billed_cost: f64,
    pub key_sources: crate::pipes::key_source::KeySourceCounts,
}

impl From<StageUsage> for StageUsageResponse {
    fn from(u: StageUsage) -> Self {
        Self {
            input_tokens: u.input_tokens,
            output_tokens: u.output_tokens,
            total_tokens: u.total_tokens(),
            cost: u.cost,
            billed_cost: u.billed_cost,
            key_sources: u.key_sources,
        }
    }
}

impl From<ExecutionMetrics> for ExecutionMetricsResponse {
    fn from(m: ExecutionMetrics) -> Self {
        Self {
            input_tokens: m.input_tokens,
            output_tokens: m.output_tokens,
            total_tokens: m.total_tokens,
            cost: m.cost,
            llm_usage: m.llm_usage.into(),
            judge_usage: m.judge_usage.into(),
            jury_usage: m.jury_usage.into(),
            decider_usage: m.decider_usage.into(),
            latency_ms: m.latency_ms,
            provider: m.provider,
            model: m.model,
            trace_id: m.trace_id,
            correlation_id: m.correlation_id,
            agent_identity: m.agent_identity,
            request_bytes: m.request_bytes,
            response_bytes: m.response_bytes,
            retry_count: m.retry_count,
            cached_tokens: m.cached_tokens,
            cache_write_tokens: m.cache_write_tokens,
            reasoning_tokens: m.reasoning_tokens,
            cache_hit: m.cache_hit,
            cache_saved_cost: m.cache_saved_cost,
            schema_valid: m.schema_valid,
            conversation_id: m.conversation_id,
            billed_cost: m.billed_cost,
            key_source: m.key_source,
        }
    }
}

/// Normalise an optional sandbox caller token into an `Authorization` header
/// value. Returns `None` for absent/blank tokens; adds the `Bearer ` scheme
/// when the token does not already carry it.
fn build_caller_auth_header(caller_token: Option<&str>) -> Option<String> {
    caller_token
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(|t| {
            if t.starts_with("Bearer ") {
                t.to_string()
            } else {
                format!("Bearer {t}")
            }
        })
}

/// The sandbox's caller credentials: its optional caller token stands for the
/// request's `Authorization`, both for identity pass-through and as the
/// caller's own provider key. A sandbox run is not authenticated by the
/// surface's front door, so the token is never a front-door credential.
fn sandbox_caller_credentials(authorization: Option<String>) -> crate::pipes::key_source::CallerCredentials {
    crate::pipes::key_source::CallerCredentials {
        provider_key: crate::pipes::key_source::bearer_token(authorization.as_deref()).map(str::to_string),
        authorization,
        upstream_authorization: None,
    }
}

/// Shared setup for the sandbox execute endpoints (buffered and streaming):
/// load the pipe, verify it is enabled, resolve the requested variant, fetch
/// (or build) the cached executor, derive the default LLM path suffix, and
/// enforce monthly usage-limit caps. Returns the resolved config, its executor,
/// and the default path suffix. Errors map to the HTTP status the caller should
/// return.
/// Resolve a pipe + its cached executor + default path, running the shared
/// pre-execution gates. Reused by the Sandbox and the drift evaluation runner.
pub(crate) async fn prepare_pipe_execution(
    state: &IdentityApiState,
    pipe_id: &str,
    variant: Option<&str>,
) -> Result<
    (std::sync::Arc<crate::pipes::PipeConfig>, std::sync::Arc<PipeExecutor>, Option<String>),
    (StatusCode, String),
> {
    // Load pipe configuration
    let pipe_config = state
        .pipe_store
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Pipe store not initialized".to_string()))?
        .get(pipe_id)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, format!("Pipe not found: {}", pipe_id)))?;

    // Check if pipe is enabled
    if !pipe_config
        .status
        .is_enabled()
    {
        return Err((StatusCode::FORBIDDEN, format!("Pipe is disabled: {}", pipe_id)));
    }

    // Executors are cached per (pipe, variant) upstream, mirroring the live
    // listener route: an aliased request keys on `pipe_id$alias`, the bare
    // pipe id keys the default/base upstream. `invalidate_pipe_cache` clears
    // all variant keys for a pipe.
    let exec_cache_key = match variant {
        Some(alias) => format!("{pipe_id}${alias}"),
        None => pipe_id.to_string(),
    };

    // Resolve the selected variant up front into a fully-materialised config.
    // Variants are full snapshots, so the executor (rate limit, circuit
    // breaker, guards, upstream) reads from the *resolved* config. With no
    // variant this resolves the default/base upstream, exactly as the route.
    let pipe_config: std::sync::Arc<crate::pipes::PipeConfig> = match pipe_config.resolve_variant(variant) {
        Ok(resolved) => std::sync::Arc::new(resolved),
        Err(e) => {
            use crate::pipes::pipe_variants::VariantResolveError;
            let status = match &e {
                VariantResolveError::UnknownAlias(_) => StatusCode::NOT_FOUND,
                VariantResolveError::DisabledVariant(_) => StatusCode::SERVICE_UNAVAILABLE,
                VariantResolveError::MisconfiguredDefault(_) => StatusCode::INTERNAL_SERVER_ERROR,
            };
            return Err((status, e.to_string()));
        }
    };

    // Fetch the executor from the shared global cache so rate-limit and
    // circuit-breaker state persist across sandbox requests (and stay in sync
    // with the live listener route). A fresh executor per call would reset the
    // rate-limit bucket every request and never throttle.
    let executor = {
        let cached = {
            let exec_cache = crate::pipes::cache::PIPE_EXECUTOR_CACHE
                .read()
                .await;
            exec_cache
                .get(&exec_cache_key)
                .cloned()
        };
        match cached {
            Some(exec) => exec,
            None => {
                // Cache miss — build a fresh executor from the resolved config.
                let secrets_store = crate::secrets::FilesystemSecretsStore::new(
                    &state
                        .bootstrap_config
                        .storage_paths
                        .secrets,
                )
                .map_err(|e| {
                    (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to initialize secrets store: {}", e))
                })?;
                let secrets_store: std::sync::Arc<dyn crate::secrets::SecretsStore> =
                    std::sync::Arc::new(secrets_store);
                let executor = std::sync::Arc::new(PipeExecutor::new_with_secrets(&pipe_config, Some(secrets_store)));
                let mut exec_cache = crate::pipes::cache::PIPE_EXECUTOR_CACHE
                    .write()
                    .await;
                exec_cache.insert(exec_cache_key.clone(), executor.clone());
                executor
            }
        }
    };

    // Determine default path suffix for LLM pipes
    // When called via the pipe listener, the HTTP handler extracts the path suffix from the URL
    // (e.g., /v1/chat/completions). For the execute API, we read endpoint_path from the pipe config
    // so the request reaches the correct upstream endpoint. Falls back to /v1/chat/completions
    // for backward compatibility with pipes created before endpoint_path was introduced.
    let default_path = match &pipe_config.pipe_type {
        crate::pipes::config::PipeType::LLM { endpoint_path, .. } => Some(
            endpoint_path
                .clone()
                .unwrap_or_else(|| "/v1/chat/completions".to_string()),
        ),
        _ => None,
    };

    // Enforce every configured stage and cumulative usage limit before execution.
    if let Some(reason) = state
        .budget_tracker
        .pipe_limit_block_reason(pipe_id, &pipe_config)
        .await
    {
        crate::pipes::metrics::spawn_pipe_failure_metric(
            state.metrics_store.clone(),
            &pipe_config,
            pipe_id.to_string(),
            pipe_config.name.clone(),
        );
        return Err((StatusCode::TOO_MANY_REQUESTS, reason));
    }

    Ok((pipe_config, executor, default_path))
}

/// The request context of a Sandbox execution: attributed to the built-in
/// sandbox member and team and to the surface's tenant.
async fn sandbox_request_context(
    state: &IdentityApiState,
    pipe_id: &str,
    trace_id: Option<&str>,
) -> crate::observability::request_context::RequestContext {
    let tenant_id = match state.pipe_store.as_ref() {
        Some(store) => store
            .get(pipe_id)
            .await
            .and_then(|pipe| pipe.tenant_id),
        None => None,
    };
    let team_names = match crate::teams::store::global_team_store() {
        Some(teams) => teams
            .get(crate::teams::types::SANDBOX_TEAM_ID)
            .await
            .map(|team| vec![team.name])
            .unwrap_or_default(),
        None => Vec::new(),
    };
    crate::observability::request_context::RequestContext {
        trace_id: trace_id
            .filter(|id| !id.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        usage: crate::governance::UsageAttribution {
            member_id: Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
            team_ids: vec![crate::teams::types::SANDBOX_TEAM_ID.to_string()],
            team_names,
            tenant_id,
        },
        ..Default::default()
    }
}

/// Record a Sandbox request a surface usage limit refused: a signed governance
/// record (when the surface records governance) and a `pipe.error` with stage
/// `usage_limit`, published off the request path.
async fn record_usage_limit_block(
    state: &IdentityApiState,
    pipe_id: &str,
    request: &Value,
    reason: &str,
) {
    let Some(pipe) = (match state.pipe_store.as_ref() {
        Some(store) => store.get(pipe_id).await,
        None => None,
    }) else {
        return;
    };
    if let Some(gov) = pipe
        .governance_recording
        .as_ref()
        .filter(|g| g.enabled)
    {
        crate::governance::capture_failure(
            true,
            gov.capture_policy(),
            pipe.id.clone(),
            pipe.name.clone(),
            Some(request.clone()),
            Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
            crate::governance::InteractionOutcome::Blocked {
                stage: "usage_limit".to_string(),
                reason: Some(reason.to_string()),
                input: None,
                output: None,
                categories: Vec::new(),
            },
            gov.export.clone(),
        );
    }
    if let Some(store) = state
        .notification_store
        .clone()
    {
        let event = crate::integrations::PipeErrorEvent::new(&pipe, reason)
            .at_stage("usage_limit")
            .with_code("rate_limit_exceeded");
        tokio::spawn(async move {
            crate::integrations::trigger_pipe_error(&store, &pipe.integrations, &event).await;
        });
    }
}

/// Execute a request through a pipe
pub async fn execute_pipe(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    let ctx = sandbox_request_context(&state, &pipe_id, request.trace_id.as_deref()).await;
    crate::observability::request_context::scope(
        ctx,
        execute_pipe_in_context(State(state), Path(pipe_id), context, scope, Json(request)),
    )
    .await
}

async fn execute_pipe_in_context(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<ExecuteResponse>, (StatusCode, String)> {
    info!("[PIPE:{}] Executing pipe: {}", pipe_id, pipe_id);

    authorize_pipe_read(
        &state,
        &pipe_id,
        context
            .as_ref()
            .map(|Extension(context)| context),
        scope
            .as_ref()
            .map(|Extension(scope)| scope),
    )
    .await?;

    let (pipe_config, executor, default_path) =
        match prepare_pipe_execution(&state, &pipe_id, request.variant.as_deref()).await {
            Ok(prepared) => prepared,
            Err((StatusCode::TOO_MANY_REQUESTS, reason)) => {
                record_usage_limit_block(&state, &pipe_id, &request.request, &reason).await;
                return Err((StatusCode::TOO_MANY_REQUESTS, reason));
            }
            Err(e) => return Err(e),
        };

    // Normalise the optional caller token into an `Authorization` header value
    // (`Bearer {token}`) so the sandbox can forward a delegated identity to
    // surfaces that require one (e.g. a `forward_caller_token` Copilot surface).
    let caller_auth_header = build_caller_auth_header(
        request
            .caller_token
            .as_deref(),
    );

    // Signed governance recording for this sandbox execution. Test runs are
    // attributed to the built-in sandbox identity so they stay distinguishable
    // from live traffic in the record chain. Clone the prompt now, before
    // `request.request` is moved into the executor.
    let governance_active = crate::governance::is_ready()
        && pipe_config
            .governance_recording
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false);
    let governance_policy = pipe_config
        .governance_recording
        .as_ref()
        .map(|g| g.capture_policy())
        .unwrap_or_default();
    let governance_sink = pipe_config
        .governance_recording
        .as_ref()
        .and_then(|g| g.export.clone());
    let governance_request = governance_active.then(|| request.request.clone());

    // Execute request
    let (response, metrics) = match executor
        .execute_with_path_and_auth(
            request.request,
            default_path,
            sandbox_caller_credentials(caller_auth_header),
            request.estimated_input_tokens,
            crate::observability::request_context::trace_id(),
            request.correlation_id,
            request.agent_identity,
            request.conversation_id,
        )
        .await
    {
        Ok(result) => result,
        Err(PipeError::RateLimitExceeded(msg)) => {
            // Trigger error integration
            if let Some(integration_store) = &state.notification_store {
                crate::integrations::trigger_pipe_error(
                    integration_store,
                    &pipe_config.integrations,
                    &crate::integrations::PipeErrorEvent::new(&pipe_config, msg.clone()).at_stage("rate_limit"),
                )
                .await;
            }
            crate::pipes::metrics::spawn_pipe_failure_metric(
                state.metrics_store.clone(),
                &pipe_config,
                pipe_id.clone(),
                pipe_config.name.clone(),
            );
            crate::governance::capture_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: "rate_limit".to_string(),
                    reason: Some(msg.clone()),
                    input: None,
                    output: None,
                    categories: Vec::new(),
                },
                governance_sink.clone(),
            );
            return Err((StatusCode::TOO_MANY_REQUESTS, msg));
        }
        Err(PipeError::CircuitBreakerOpen(msg)) => {
            // Trigger error integration
            if let Some(integration_store) = &state.notification_store {
                crate::integrations::trigger_pipe_error(
                    integration_store,
                    &pipe_config.integrations,
                    &crate::integrations::PipeErrorEvent::new(&pipe_config, msg.clone()).at_stage("circuit_breaker"),
                )
                .await;
            }
            crate::pipes::metrics::spawn_pipe_failure_metric(
                state.metrics_store.clone(),
                &pipe_config,
                pipe_id.clone(),
                pipe_config.name.clone(),
            );
            crate::governance::capture_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "circuit_breaker".to_string(),
                    reason: Some(msg.clone()),
                },
                governance_sink.clone(),
            );
            return Err((StatusCode::SERVICE_UNAVAILABLE, msg));
        }
        Err(PipeError::PromptGuardRejected {
            status_code, body, rejection, ..
        }) => {
            let gov_block_stage = rejection
                .as_ref()
                .map(|m| m.stage.label().to_string())
                .unwrap_or_else(|| "prompt_guard".to_string());
            let block_categories = rejection
                .as_deref()
                .map(|m| crate::rejection_taxonomy::classify_global(&m.raw_reasons, &m.source))
                .unwrap_or_default();
            // Trigger error integration
            if let Some(integration_store) = &state.notification_store {
                crate::integrations::trigger_pipe_error(
                    integration_store,
                    &pipe_config.integrations,
                    &crate::integrations::PipeErrorEvent::new(&pipe_config, body.clone())
                        .at_stage(gov_block_stage.clone())
                        .with_categories(&block_categories),
                )
                .await;
            }
            // Signed governance record for the blocked sandbox interaction: the
            // caller prompt and the rejecting stage (with its evaluated content
            // and verdict), no completion.
            let gov_block_input = rejection
                .as_ref()
                .and_then(|m| m.input.clone());
            let gov_block_output = rejection
                .as_ref()
                .and_then(|m| m.output.clone());
            crate::governance::capture_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: gov_block_stage,
                    reason: Some(body.clone()),
                    input: gov_block_input,
                    output: gov_block_output,
                    categories: block_categories.clone(),
                },
                governance_sink.clone(),
            );

            // Record the rejection into the usage time-series, classified into
            // canonical categories. Sandbox calls have no resolved caller, so they
            // attribute to the built-in sandbox member/team (parity with the
            // sandbox usage recording above). Gated by `enable_metrics`.
            if pipe_config.enable_metrics
                && let Some(meta) = rejection
            {
                let categories = block_categories;
                let sandbox_teams = [crate::teams::types::SANDBOX_TEAM_ID.to_string()];
                crate::telemetry::record_rejection(
                    &pipe_id,
                    meta.stage.label(),
                    &categories,
                    Some(crate::members::types::SANDBOX_MEMBER_ID),
                    &sandbox_teams,
                )
                .await;
            }
            let code = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
            return Err((code, body));
        }
        Err(e) => {
            error!("[PIPE:{}] Pipe execution failed: {}", pipe_id, e);
            // Trigger error integration
            if let Some(integration_store) = &state.notification_store {
                crate::integrations::trigger_pipe_error(
                    integration_store,
                    &pipe_config.integrations,
                    &crate::integrations::PipeErrorEvent::new(&pipe_config, e.to_string()).at_stage("execution"),
                )
                .await;
            }
            crate::pipes::metrics::spawn_pipe_failure_metric(
                state.metrics_store.clone(),
                &pipe_config,
                pipe_id.clone(),
                pipe_config.name.clone(),
            );
            crate::governance::capture_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "execution".to_string(),
                    reason: Some(e.to_string()),
                },
                governance_sink.clone(),
            );
            let code = if e.caller_key_rejected() {
                e.upstream_status()
                    .and_then(|status| StatusCode::from_u16(status).ok())
                    .unwrap_or(StatusCode::UNAUTHORIZED)
            } else {
                StatusCode::INTERNAL_SERVER_ERROR
            };
            return Err((code, e.to_string()));
        }
    };

    // Record metrics
    if let Err(e) = record_pipe_metrics(&state, &pipe_id, &pipe_config.name, &metrics, ConnectionStatus::Success).await
    {
        error!("[PIPE:{}] Failed to record pipe metrics: {}", pipe_id, e);
    }

    // Record this sandbox execution into the multi-resolution usage time-series
    // (appliance aggregate, surface grand total, and each pipeline stage that
    // ran) so the dashboard/team/member usage graphs draw from a single source.
    // Sandbox calls have no resolved caller, so they are attributed to the
    // built-in sandbox member/team — keeping test traffic visible and reconciled
    // against the surface totals yet separable from real anonymous/live callers.
    // Gated by `enable_metrics`, matching the live route and the rest of metrics.
    if pipe_config.enable_metrics {
        let sandbox_teams = [crate::teams::types::SANDBOX_TEAM_ID.to_string()];
        crate::telemetry::record_pipe_execution(
            &pipe_id,
            &metrics.llm_usage,
            &metrics.judge_usage,
            &metrics.jury_usage,
            &metrics.decider_usage,
            metrics.key_source,
            Some(crate::members::types::SANDBOX_MEMBER_ID),
            &sandbox_teams,
        )
        .await;

        // Record any Judge/Jury rejections recovered by a redrive within this
        // successful sandbox execution under the synthetic `redrive` category,
        // attributed to the sandbox member/team (the real content category is
        // reserved for finally-blocked executions).
        if !metrics
            .redrive_rejections
            .is_empty()
        {
            let redrive_category = [crate::telemetry::REJECTION_REDRIVE_CATEGORY.to_string()];
            for meta in &metrics.redrive_rejections {
                crate::telemetry::record_rejection(
                    &pipe_id,
                    meta.stage.label(),
                    &redrive_category,
                    Some(crate::members::types::SANDBOX_MEMBER_ID),
                    &sandbox_teams,
                )
                .await;
            }
        }
    }

    // Record budget usage. The legacy cost-tracking budget meters the main-LLM
    // stage only — Judge and Jury spend lands in their own usage-limit buckets
    // (see record_stage_usage), so metrics.cost (the grand total) must not be used
    // here or their cost would be counted against the LLM cost budget.
    if let Some(cost_config) = &pipe_config.cost_tracking
        && cost_config.enabled
        && metrics.llm_usage.cost > 0.0
        && let Err(e) = state
            .budget_tracker
            .record_cost(
                pipe_id.clone(),
                pipe_config.name.clone(),
                metrics.llm_usage.cost,
                cost_config.monthly_budget_usd,
                cost_config.alert_threshold_percent,
            )
            .await
    {
        error!("[PIPE:{}] Failed to record budget usage: {}", pipe_id, e);
    }

    // Accumulate LLM-stage spend/tokens into the usage-limit buckets (stage + cumulative)
    // so cost/token caps can trip on the next call. The main LLM stage always counts both
    // real spend and tokens. Reads metrics.llm_usage only — Judge/Jury record their own
    // buckets — so the grand totals are never double-counted here.
    state
        .budget_tracker
        .record_llm_usage(
            &pipe_id,
            metrics.llm_usage.cost,
            metrics
                .llm_usage
                .total_tokens(),
        )
        .await;

    // Trigger pipe.executed integration
    info!("[PIPE:{}] Checking if should trigger pipe.executed integration", pipe_id);
    if let Some(integration_store) = &state.notification_store {
        info!("[PIPE:{}] notification_store is available", pipe_id);
        info!("[PIPE:{}] pipe integrations count = {}", pipe_id, pipe_config.integrations.len());

        let execution = crate::integrations::pipe_integration_triggers::PipeExecution {
            pipe_id: pipe_id.clone(),
            pipe_name: pipe_config.name.clone(),
            input_tokens: metrics.input_tokens,
            output_tokens: metrics.output_tokens,
            total_tokens: metrics.total_tokens,
            cost: metrics.cost,
            latency_ms: metrics.latency_ms,
            provider: metrics.provider.clone(),
            model: metrics.model.clone(),
            trace_id: metrics.trace_id.clone(),
            success: true,
            error_message: None,
            currency: crate::integrations::pipe_integration_triggers::usd_currency(),
            usage_by_stage: metrics.usage_by_stage(&pipe_config),
            streaming: false,
            record_id: None,
            attribution: crate::observability::request_context::usage_attribution(),
            request_content: None,
            response_content: None,
        };

        info!("[PIPE:{}] Calling trigger_pipe_executed", pipe_id);
        crate::integrations::trigger_pipe_executed(integration_store, &pipe_config.integrations, &execution).await;
        info!("[PIPE:{}] trigger_pipe_executed returned", pipe_id);
    } else {
        info!("[PIPE:{}] notification_store is None - integrations will not fire", pipe_id);
    }

    info!("[PIPE:{}] Pipe executed successfully: {} tokens, ${:.6}", pipe_id, metrics.total_tokens, metrics.cost);

    // Signed governance record for the completed sandbox interaction (prompt,
    // model completion, metrics), attributed to the built-in sandbox identity.
    if governance_active {
        crate::governance::capture(crate::governance::CaptureInput {
            surface_id: pipe_id.clone(),
            surface_name: Some(pipe_config.name.clone()),
            trace_id: (!metrics.trace_id.is_empty()).then(|| metrics.trace_id.clone()),
            caller_identity: Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
            request: governance_request,
            response: Some(response.clone()),
            completion_text: None,
            policy: governance_policy,
            metrics: metrics.record_metrics(&pipe_config),
            outcome: crate::governance::InteractionOutcome::Completed,
            extra_stages: metrics.governance_stages(),
            export: governance_sink,
        });
    }

    Ok(Json(ExecuteResponse {
        response,
        metrics: metrics.into(),
    }))
}

/// Streaming sibling of `execute_pipe`: runs the surface's streaming path and
/// returns the upstream SSE (`text/event-stream`) so the sandbox can render the
/// response live. Requires the surface to be streaming-eligible
/// (`crate::pipes::streaming::passthrough_eligible`); otherwise returns `409`
/// so the client transparently falls back to the buffered `/execute`.
///
/// Streaming bypasses every response-side stage and carries no per-execution
/// activity-log detail, so the returned SSE only streams `delta.content`; the
/// sandbox's rich per-message metrics (tokens/cost) come from the buffered path.
/// On completion the (LLM-only) usage is recorded to telemetry + the metrics
/// store under the built-in sandbox member/team, matching the buffered sandbox.
pub async fn execute_pipe_stream(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ExecuteRequest>,
) -> Response {
    let ctx = sandbox_request_context(&state, &pipe_id, request.trace_id.as_deref()).await;
    crate::observability::request_context::scope(
        ctx,
        execute_pipe_stream_in_context(State(state), Path(pipe_id), context, scope, Json(request)),
    )
    .await
}

async fn execute_pipe_stream_in_context(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(request): Json<ExecuteRequest>,
) -> Response {
    info!("[PIPE:{}] Executing pipe (stream): {}", pipe_id, pipe_id);

    if let Err(error) = authorize_pipe_read(
        &state,
        &pipe_id,
        context
            .as_ref()
            .map(|Extension(context)| context),
        scope
            .as_ref()
            .map(|Extension(scope)| scope),
    )
    .await
    {
        return error.into_response();
    }

    let (pipe_config, executor, default_path) =
        match prepare_pipe_execution(&state, &pipe_id, request.variant.as_deref()).await {
            Ok(prepared) => prepared,
            Err((StatusCode::TOO_MANY_REQUESTS, reason)) => {
                record_usage_limit_block(&state, &pipe_id, &request.request, &reason).await;
                return (StatusCode::TOO_MANY_REQUESTS, reason).into_response();
            }
            Err((code, msg)) => return (code, msg).into_response(),
        };

    // Streaming bypasses response-side stages, so a surface with a Jury /
    // Mirror decider / response prompt guard (or a non-streamable schema) cannot
    // stream. A request-side Judge and a Route decider are fine — they gate /
    // route the prompt pre-stream. Signal ineligibility with 409 so the client
    // falls back to the buffered endpoint.
    if !crate::pipes::streaming::passthrough_eligible(&pipe_config) {
        return (
            StatusCode::CONFLICT,
            "This surface is not streaming-eligible; use the buffered execute endpoint.".to_string(),
        )
            .into_response();
    }

    let caller_auth_header = build_caller_auth_header(
        request
            .caller_token
            .as_deref(),
    );

    // Continue a stateful Copilot conversation across sandbox turns when the
    // client sends back the id from a previous turn (native multi-turn memory).
    let conversation_id_in = request
        .conversation_id
        .clone();

    // Signed governance recording for this streamed sandbox execution. Gated by
    // `include_streaming`; the completion is reassembled server-side (below) so
    // the record carries the full model output. Test runs are attributed to the
    // built-in sandbox identity. Clone the prompt before `request.request` is
    // moved into the streaming request body.
    let governance_stream_active = crate::governance::is_ready()
        && pipe_config
            .governance_recording
            .as_ref()
            .map(|g| g.enabled && g.include_streaming)
            .unwrap_or(false);
    let governance_policy = pipe_config
        .governance_recording
        .as_ref()
        .map(|g| g.capture_policy())
        .unwrap_or_default();
    let governance_sink = pipe_config
        .governance_recording
        .as_ref()
        .and_then(|g| g.export.clone());
    let governance_request = governance_stream_active.then(|| request.request.clone());

    // Force streaming on so the executor takes the SSE path.
    let mut request_body = request.request;
    request_body["stream"] = serde_json::json!(true);
    let upstream = match executor
        .execute_streaming(
            request_body,
            default_path,
            sandbox_caller_credentials(caller_auth_header),
            conversation_id_in,
        )
        .await
    {
        Ok(upstream) => upstream,
        Err(PipeError::PromptGuardRejected {
            status_code,
            body,
            content_type,
            rejection,
            ..
        }) => {
            let gov_block_stage = rejection
                .as_ref()
                .map(|m| m.stage.label().to_string())
                .unwrap_or_else(|| "prompt_guard".to_string());
            let gov_block_input = rejection
                .as_ref()
                .and_then(|m| m.input.clone());
            let gov_block_output = rejection
                .as_ref()
                .and_then(|m| m.output.clone());
            let block_categories = rejection
                .as_deref()
                .map(|m| crate::rejection_taxonomy::classify_global(&m.raw_reasons, &m.source))
                .unwrap_or_default();
            crate::governance::capture_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: gov_block_stage,
                    reason: Some(body.clone()),
                    input: gov_block_input,
                    output: gov_block_output,
                    categories: block_categories,
                },
                governance_sink.clone(),
            );
            let code = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
            if content_type.contains("application/json")
                && let Ok(value) = serde_json::from_str::<Value>(&body)
            {
                return (code, Json(value)).into_response();
            }
            return (code, body).into_response();
        }
        Err(PipeError::RateLimitExceeded(msg)) => {
            crate::governance::capture_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: "rate_limit".to_string(),
                    reason: Some(msg.clone()),
                    input: None,
                    output: None,
                    categories: Vec::new(),
                },
                governance_sink.clone(),
            );
            return (StatusCode::TOO_MANY_REQUESTS, msg).into_response();
        }
        Err(PipeError::CircuitBreakerOpen(msg)) => {
            crate::governance::capture_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "circuit_breaker".to_string(),
                    reason: Some(msg.clone()),
                },
                governance_sink.clone(),
            );
            return (StatusCode::SERVICE_UNAVAILABLE, msg).into_response();
        }
        Err(e) => {
            // Judge/Decider may have already run (billable LLM calls) before this
            // later infrastructure failure — attribute that already-incurred
            // spend to the built-in sandbox member/team before it's otherwise
            // lost, mirroring the buffered sandbox path's per-stage recording.
            let (incurred_usage, e) = match e {
                PipeError::WithIncurredUsage { inner, usage } => (Some(usage), *inner),
                other => (None, other),
            };
            if let Some(usage) = incurred_usage
                && pipe_config.enable_metrics
            {
                let pipe_id_for_usage = pipe_id.clone();
                tokio::spawn(async move {
                    let sandbox_teams = [crate::teams::types::SANDBOX_TEAM_ID.to_string()];
                    crate::telemetry::record_pipe_execution(
                        &pipe_id_for_usage,
                        &usage.llm,
                        &usage.judge,
                        &usage.jury,
                        &usage.decider,
                        usage.key_source(),
                        Some(crate::members::types::SANDBOX_MEMBER_ID),
                        &sandbox_teams,
                    )
                    .await;
                });
            }
            error!("[PIPE:{}] Streaming execution failed: {}", pipe_id, e);
            crate::governance::capture_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.clone(),
                pipe_config.name.clone(),
                governance_request,
                Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "execution".to_string(),
                    reason: Some(e.to_string()),
                },
                governance_sink.clone(),
            );
            return (StatusCode::INTERNAL_SERVER_ERROR, format!("Request failed: {}", e)).into_response();
        }
    };

    // Emit the request stage log so the sandbox activity panel shows a run for
    // the streamed execution (the streaming path otherwise writes no per-stage
    // activity detail). The response + summary stages are emitted on completion.
    info!(
        "[PIPE:{}] [STAGE:llm_request] {{\"provider\":\"{}\",\"model\":\"{}\",\"attempt\":\"initial\"}}",
        pipe_id, upstream.provider, upstream.model
    );

    // Minimal completion telemetry, attributed to the built-in sandbox
    // member/team (parity with the buffered sandbox path) and gated by
    // `enable_metrics`. Streaming carries only LLM-stage usage.
    let enable_metrics = pipe_config.enable_metrics;
    let pipe_id_owned = pipe_id.clone();
    let pipe_name_owned = pipe_config.name.clone();
    let provider = upstream.provider.clone();
    let model = upstream.model.clone();
    let pricing = upstream.pricing;
    let own_price_honoured = upstream.own_price_honoured;
    let request_bytes = upstream.request_bytes;
    let stream_schema = upstream.schema.clone();
    let stream_model_pii_stage = upstream
        .model_pii_stage
        .clone();
    // Returned to the client so a follow-up can continue the same stateful
    // Copilot conversation (native multi-turn memory). `None` for non-Copilot.
    let out_conversation_id = upstream
        .conversation_id
        .clone();
    let metrics_store = state.metrics_store.clone();
    let start = std::time::Instant::now();

    // The request-side Judge/Route-decider run pre-stream on this path; fold
    // their spend into the streamed metering below (parity with the live path).
    let judge_cost = upstream.judge_usage.cost;
    let judge_tokens = upstream
        .judge_usage
        .total_tokens();
    let decider_cost = upstream.decider_usage.cost;
    let decider_tokens = upstream
        .decider_usage
        .total_tokens();
    let stream_judge_usage = upstream.judge_usage;
    let stream_decider_usage = upstream.decider_usage;
    let stream_key_source = upstream.key_source;
    // What the stream is billed at if it reports no final usage, and whether
    // it reads on after its client leaves (a key that bills), counted against
    // the surface's concurrent-drain cap.
    let stream_estimate = upstream.estimate;
    let stream_drain = (!stream_key_source.owned())
        .then(|| crate::pipes::streaming::DrainOptions::new(None, Some(pipe_id.to_string())));

    // Live throughput/token heartbeats (see the live data-plane path). Sandbox
    // traffic feeds the surface + appliance-wide operational series so its
    // Monitoring charts advance during a long streamed test.
    let progress_keys = crate::metrics::ops_telemetry::stream_ops_keys(&pipe_id, None);
    let progress_enabled = enable_metrics;

    // Request bytes are known up-front, so flush them immediately (parity with
    // the live path) rather than only at completion.
    if progress_enabled {
        let keys = progress_keys.clone();
        tokio::spawn(async move {
            crate::metrics::ops_telemetry::record_stream_progress(&keys, request_bytes, 0, 0, 0).await;
        });
    }

    let on_progress = move |p: crate::pipes::streaming::StreamProgress| {
        if !progress_enabled {
            return;
        }
        let keys = progress_keys.clone();
        tokio::spawn(async move {
            crate::metrics::ops_telemetry::record_stream_progress(
                &keys,
                0,
                p.response_bytes,
                p.input_tokens,
                p.output_tokens,
            )
            .await;
        });
    };

    let on_complete = move |outcome: crate::pipes::streaming::StreamOutcome| {
        let status = if outcome.completed {
            ConnectionStatus::Success
        } else {
            ConnectionStatus::Failed
        };
        // The tokens the upstream reported, or, on a key that bills, an
        // estimate when it reported none (recorded as estimated below).
        let (input_tokens, output_tokens, usage_estimated) = outcome.billed_tokens(stream_key_source, &stream_estimate);
        if usage_estimated {
            warn!(
                pipe = ?pipe_id_owned,
                input_tokens,
                output_tokens,
                "platform-key stream ended without usage: billed an estimate"
            );
            crate::metrics::backends::prometheus::track_stream_usage_estimated();
        }
        let llm_cost = crate::pipes::streaming::cost_for_tokens(
            pricing.as_ref(),
            own_price_honoured,
            &provider,
            &model,
            input_tokens,
            output_tokens,
        ) + crate::pipes::streaming::cache_cost_for_tokens(
            pricing.as_ref(),
            own_price_honoured,
            &provider,
            &model,
            outcome.cache,
        );
        let llm_tokens = input_tokens + output_tokens;
        // Grand total folds in the request-side Judge + Route decider spend so a
        // Judge/decider surface bills them like the buffered path (parity with
        // the live streaming path).
        let cost = llm_cost + judge_cost + decider_cost;
        let total_tokens = llm_tokens + judge_tokens + decider_tokens;
        let latency_ms = start.elapsed().as_millis() as u64;
        // The streamed call's own usage, billed by the source of its key; the
        // Judge and Decider bill by theirs.
        let stream_llm_usage = crate::pipes::config::StageUsage::call(
            input_tokens,
            output_tokens,
            llm_cost,
            latency_ms,
            stream_key_source,
        );
        let billed_cost =
            stream_llm_usage.billed_cost + stream_judge_usage.billed_cost + stream_decider_usage.billed_cost;
        let mut stream_key_sources = stream_llm_usage.key_sources;
        stream_key_sources.add(stream_judge_usage.key_sources);
        stream_key_sources.add(stream_decider_usage.key_sources);
        let response_bytes = outcome.response_bytes;
        let flushed_response_bytes = outcome.flushed_response_bytes;
        let flushed_input_tokens = outcome.flushed_input_tokens;
        let flushed_output_tokens = outcome.flushed_output_tokens;
        // Request bytes were flushed up-front on the first heartbeat.
        let flushed_request_bytes = request_bytes;

        if outcome.completed {
            // Response + summary stage logs so the activity panel renders a
            // completed run (with token/cost totals) for the streamed execution.
            // Emitted regardless of `enable_metrics` so the sandbox always shows
            // activity.
            info!(
                "[PIPE:{}] [STAGE:llm_response] {{\"outcome\":\"success\",\"attempt\":\"initial\",\"duration_ms\":{}}}",
                pipe_id_owned, latency_ms
            );
            info!(
                "[PIPE:{}] [STAGE:summary] {{\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"llm_tokens\":{},\"llm_cost\":{:.6},\"latency_ms\":{},\"provider\":\"{}\",\"model\":\"{}\"}}",
                pipe_id_owned,
                total_tokens,
                input_tokens,
                output_tokens,
                cost,
                llm_tokens,
                llm_cost,
                latency_ms,
                provider,
                model
            );
        } else {
            info!(
                "[PIPE:{}] [STAGE:llm_response] {{\"outcome\":\"aborted\",\"attempt\":\"initial\",\"duration_ms\":{},\"bytes\":{},\"tokens\":{}}}",
                pipe_id_owned, latency_ms, response_bytes, total_tokens
            );
        }

        // Signed governance record for the streamed sandbox interaction — full
        // fidelity via the reassembled completion. An aborted stream still
        // records its partial completion, flagged with a `stream` error stage.
        // Independent of `enable_metrics` (recorded even when metrics are off).
        if governance_stream_active {
            let mut extra_stages = Vec::new();
            if let Some(stage) = stream_model_pii_stage.clone() {
                extra_stages.push(stage);
            }
            if !outcome.completed {
                extra_stages.push(crate::governance::StageEntry::decision(
                    "stream",
                    crate::governance::StageOutcome::Error,
                    Some("stream aborted before completion".to_string()),
                ));
            }
            crate::governance::capture(crate::governance::CaptureInput {
                surface_id: pipe_id_owned.clone(),
                surface_name: Some(pipe_name_owned.clone()),
                trace_id: None,
                caller_identity: Some(crate::members::types::SANDBOX_MEMBER_ID.to_string()),
                request: governance_request,
                response: None,
                completion_text: outcome.completion.clone(),
                policy: governance_policy,
                metrics: crate::governance::RecordMetrics {
                    input_tokens,
                    output_tokens,
                    total_tokens,
                    cost,
                    latency_ms,
                    provider: (!provider.is_empty()).then(|| provider.clone()),
                    model: (!model.is_empty()).then(|| model.clone()),
                    currency: crate::governance::RecordMetrics::usd(),
                    billed_cost: Some(billed_cost),
                    key_source: Some(stream_key_source),
                    key_sources: Some(stream_key_sources),
                    usage_estimated: usage_estimated.then_some(true),
                    ..Default::default()
                },
                outcome: crate::governance::InteractionOutcome::Completed,
                extra_stages,
                export: governance_sink,
            });
        }

        if !enable_metrics {
            return;
        }
        tokio::spawn(async move {
            let sandbox_teams = [crate::teams::types::SANDBOX_TEAM_ID.to_string()];
            crate::telemetry::record_pipe_execution(
                &pipe_id_owned,
                &stream_llm_usage,
                &stream_judge_usage,
                &crate::pipes::config::StageUsage::default(),
                &stream_decider_usage,
                Some(stream_key_source),
                Some(crate::members::types::SANDBOX_MEMBER_ID),
                &sandbox_teams,
            )
            .await;
            metrics_store
                .record_pipe_stream_completion(
                    pipe_id_owned.clone(),
                    Some(pipe_name_owned.clone()),
                    provider.clone(),
                    model.clone(),
                    status,
                    latency_ms,
                    input_tokens,
                    output_tokens,
                    cost,
                    request_bytes,
                    response_bytes,
                    Some(crate::metrics::PipeStageUsage {
                        llm: stream_llm_usage.into(),
                        judge: stream_judge_usage.into(),
                        decider: stream_decider_usage.into(),
                        key_source: Some(stream_key_source),
                        ..Default::default()
                    }),
                    flushed_request_bytes,
                    flushed_response_bytes,
                    flushed_input_tokens,
                    flushed_output_tokens,
                )
                .await;
        });
    };

    let request_ctx = crate::observability::request_context::current().unwrap_or_default();
    let body = crate::pipes::streaming::spawn_metered_stream(
        upstream.response,
        stream_schema,
        governance_stream_active,
        upstream.rehydration_map,
        on_progress,
        move |outcome| crate::observability::request_context::sync_scope(request_ctx, || on_complete(outcome)),
        crate::pipes::streaming_skin::EgressSkin::new(crate::pipes::ingress::IngressSchema::OpenAiChat, String::new()),
        stream_drain,
    );
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header(axum::http::header::CONNECTION, "keep-alive")
        .header("x-accel-buffering", "no");
    if let Some(id) = &out_conversation_id {
        builder = builder.header("x-agent-stream-conversation-id", id.as_str());
    }
    builder
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

async fn record_pipe_metrics(
    state: &IdentityApiState,
    pipe_id: &str,
    pipe_name: &str,
    metrics: &ExecutionMetrics,
    status: ConnectionStatus,
) -> Result<(), Box<dyn std::error::Error>> {
    // Calculate pipe latency breakdown
    let pipe_gateway_processing_ms = metrics.time_to_first_token_ms; // Gateway processing time
    let pipe_target_processing_ms = if let Some(gateway_ms) = metrics.time_to_first_token_ms {
        if metrics.latency_ms > gateway_ms {
            Some(metrics.latency_ms - gateway_ms) // Target processing time
        } else {
            None
        }
    } else {
        None
    };

    debug!(
        "Recording pipe metrics: pipe_id={}, total_latency={}ms, gateway_processing={:?}ms, target_processing={:?}ms",
        pipe_id, metrics.latency_ms, pipe_gateway_processing_ms, pipe_target_processing_ms
    );

    // Record using the new pipe-specific method with full LLM metrics
    state
        .metrics_store
        .record_pipe_execution(
            pipe_id.to_string(),
            Some(pipe_name.to_string()),
            metrics.provider.clone(),
            metrics.model.clone(),
            status,
            metrics.latency_ms,
            pipe_gateway_processing_ms,
            pipe_target_processing_ms,
            metrics.input_tokens,
            metrics.output_tokens,
            metrics.cost,
            Some(metrics.trace_id.clone()),
            metrics.correlation_id.clone(),
            metrics.agent_identity.clone(),
            metrics.request_bytes,
            metrics.response_bytes,
            metrics.retry_count,
            Some(crate::metrics::PipeStageUsage {
                llm: metrics.llm_usage.into(),
                judge: metrics.judge_usage.into(),
                jury: metrics.jury_usage.into(),
                decider: metrics.decider_usage.into(),
                key_source: metrics.key_source,
            }),
        )
        .await;

    Ok(())
}

/// Get budget usage for a pipe
pub async fn get_budget_usage(
    State(state): State<IdentityApiState>,
    Path(pipe_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<BudgetUsageResponse>, (StatusCode, String)> {
    authorize_pipe_read(
        &state,
        &pipe_id,
        context
            .as_ref()
            .map(|Extension(context)| context),
        scope
            .as_ref()
            .map(|Extension(scope)| scope),
    )
    .await?;
    let usage = state
        .budget_tracker
        .get_usage(&pipe_id)
        .await;

    Ok(Json(match usage {
        Some(u) => BudgetUsageResponse {
            pipe_id: u.pipe_id.clone(),
            month: u.month.clone(),
            total_spent: u.total_spent,
            budget_limit: u.budget_limit,
            usage_percentage: u.usage_percentage(),
            remaining_budget: u.remaining_budget(),
            alert_threshold_percent: u.alert_threshold_percent,
            budget_exceeded: u.budget_exceeded(),
            last_updated: u.last_updated.to_rfc3339(),
        },
        None => BudgetUsageResponse {
            pipe_id,
            month: String::new(),
            total_spent: 0.0,
            budget_limit: 0.0,
            usage_percentage: 0.0,
            remaining_budget: 0.0,
            alert_threshold_percent: 0,
            budget_exceeded: false,
            last_updated: String::new(),
        },
    }))
}

#[derive(Debug, Serialize)]
pub struct BudgetUsageResponse {
    pub pipe_id: String,
    pub month: String,
    pub total_spent: f64,
    pub budget_limit: f64,
    pub usage_percentage: f64,
    pub remaining_budget: f64,
    pub alert_threshold_percent: u8,
    pub budget_exceeded: bool,
    pub last_updated: String,
}

#[cfg(test)]
mod tests {
    use super::build_caller_auth_header;

    #[test]
    fn caller_auth_header_adds_bearer_scheme() {
        assert_eq!(build_caller_auth_header(Some("abc.def.ghi")), Some("Bearer abc.def.ghi".to_string()));
    }

    #[test]
    fn caller_auth_header_preserves_existing_scheme() {
        assert_eq!(build_caller_auth_header(Some("Bearer tok123")), Some("Bearer tok123".to_string()));
    }

    #[test]
    fn caller_auth_header_trims_whitespace() {
        assert_eq!(build_caller_auth_header(Some("  tok  ")), Some("Bearer tok".to_string()));
    }

    #[test]
    fn caller_auth_header_none_for_absent_or_blank() {
        assert_eq!(build_caller_auth_header(None), None);
        assert_eq!(build_caller_auth_header(Some("")), None);
        assert_eq!(build_caller_auth_header(Some("   ")), None);
    }
}
