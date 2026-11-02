//! HTTP handlers for LLM pipe interception
//!
//! These handlers allow SDK clients (like OpenAI Agents JS SDK) to route requests
//! through the gateway by configuring their baseURL to point to /llm/:pipe_id

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, error, info, warn};

use crate::observability::TaskMonitor;
use crate::pipes::budget_tracker::record_surface_llm_usage;
use crate::pipes::route_manager::{PipeRouteMap, route_key_matches_listener};
use crate::pipes::{FileSystemPipeStore, MetricsStore, PipeConfig, executor::PipeExecutor};
use crate::secrets::SecretsStore;

/// Header carrying an optional **upstream** bearer credential, distinct from the
/// front-door `Authorization` header. When a caller authenticates to the front
/// door with one identity but the dispatched member surface must forward a
/// different token upstream (e.g. a Graph-audience token for Microsoft 365
/// Copilot), the client sends the upstream token here. A `forward_caller_token`
/// surface forwards it in preference to the front-door token; front-door JWT
/// verification and OPA only ever read `Authorization`.
pub const UPSTREAM_AUTHORIZATION_HEADER: &str = "x-agent-stream-upstream-authorization";

/// Shared state for pipe HTTP handlers
#[derive(Clone)]
pub struct PipeHandlerState {
    pub pipe_store: Arc<FileSystemPipeStore>,
    pub task_monitor: Arc<TaskMonitor>,
    pub secrets_store: Arc<dyn SecretsStore>,
    pub metrics_store: Option<Arc<MetricsStore>>,
    /// Global metrics store for dashboard visibility
    pub global_metrics_store: Arc<crate::metrics::MetricsStore>,
    /// Map from listener-scoped route to pipe ID for route-based lookup
    pub route_to_pipe: Arc<RwLock<PipeRouteMap>>,
    /// Normalized listener addresses served by this handler instance.
    pub listener_scopes: Vec<String>,
    /// Cached pipe configs to avoid file system reads
    pub pipe_cache: Arc<RwLock<HashMap<String, Arc<PipeConfig>>>>,
    /// Cached executors to avoid recreating HTTP clients and state
    pub executor_cache: Arc<RwLock<HashMap<String, Arc<PipeExecutor>>>>,
    /// Notification store for triggering integrations
    pub notification_store: Option<Arc<crate::integrations::FileSystemNotificationStore>>,
    /// Unified source authentication middleware.
    pub source_auth_middleware: Option<Arc<crate::source_auth::SourceAuthMiddleware>>,
    /// Inbound OPA policy manager. When a pipe enables OPA, requests are
    /// evaluated here after source auth and denied (403) on policy failure.
    pub pipe_policy_manager: Option<Arc<crate::pipes::PipePolicyManager>>,
    /// Path to the dashboard SPA's `index.html`. The pipe data-plane shares
    /// its ingress prefix (e.g. `/llm`) with the dashboard's pipe-editor
    /// routes, so the GET health handler serves this shell for non-`/health`
    /// requests (a direct browser refresh of `/llm/new`, `/llm/:id`, etc.)
    /// instead of returning a "no pipe configured" error.
    pub spa_index_path: Option<String>,
}

/// Handle chat completions requests from SDK clients
///
/// This is the main entry point for SDK requests routed by custom pipe routes
/// POST {pipe.route}/v1/chat/completions
/// Insert a header if the value is a valid header string (best-effort; a value
/// that can't be a header is silently skipped).
fn insert_header(
    headers: &mut axum::http::HeaderMap,
    name: &'static str,
    value: String,
) {
    if let Ok(v) = axum::http::HeaderValue::from_str(&value) {
        headers.insert(name, v);
    }
}

fn source_auth_failed_response() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({
            "error": {
                "message": "Source authentication failed",
                "type": "authentication_error",
                "code": "source_authentication_failed"
            }
        })),
    )
        .into_response()
}

/// The 503 for a request to a surface that declares source authentication when
/// the source-auth middleware failed to start: no caller can be checked, so
/// none is admitted.
fn source_auth_unavailable_response(pipe_id: &str) -> Response {
    error!(pipe_id = %pipe_id, "Source authentication is configured but its middleware is not running - refusing the request");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({
            "error": {
                "message": "Source authentication is unavailable",
                "type": "authentication_error",
                "code": "source_authentication_unavailable"
            }
        })),
    )
        .into_response()
}

/// Re-skin a JSON error response to match the requested ingress dialect. Only
/// Anthropic Messages needs a different envelope; OpenAI Chat and Responses use
/// the OpenAI error shape. Non-error (2xx) and non-JSON (streaming/binary)
/// responses pass through untouched.
async fn reskin_error_response(
    skin: crate::pipes::ingress::IngressSchema,
    response: Response,
) -> Response {
    use crate::pipes::ingress::IngressSchema;
    if skin != IngressSchema::AnthropicMessages || response.status().is_success() {
        return response;
    }
    let is_json = response
        .headers()
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.contains("application/json"))
        .unwrap_or(false);
    if !is_json {
        return response;
    }
    let status = response.status();
    let (_parts, body) = response.into_parts();
    let bytes = match axum::body::to_bytes(body, 1 << 20).await {
        Ok(b) => b,
        Err(_) => {
            let fallback = crate::pipes::ingress::anthropic_error_body(status.as_u16(), "request failed");
            return (status, Json(fallback)).into_response();
        }
    };
    let openai_error: Value = serde_json::from_slice(&bytes).unwrap_or_else(|_| serde_json::json!({}));
    let anthropic = crate::pipes::ingress::openai_error_to_anthropic(status.as_u16(), &openai_error);
    (status, Json(anthropic)).into_response()
}

/// Skin an OpenAI-canonical success body to the requested ingress dialect for
/// buffered (non-streaming) responses.
fn skin_success_body(
    skin: crate::pipes::ingress::IngressSchema,
    openai: Value,
    model: &str,
) -> Value {
    use crate::pipes::ingress::IngressSchema;
    match skin {
        IngressSchema::OpenAiChat => openai,
        IngressSchema::AnthropicMessages => {
            crate::pipes::request_shaping::transform_to_anthropic_response(&openai, model)
        }
        IngressSchema::OpenAiResponses => {
            crate::pipes::request_shaping::transform_to_responses_response(&openai, model)
        }
    }
}

/// Normalize an inbound request body from its ingress dialect into the
/// OpenAI-canonical form the pipeline expects. OpenAI Chat passes through.
fn normalize_ingress_request(
    skin: crate::pipes::ingress::IngressSchema,
    body: Value,
) -> Value {
    use crate::pipes::ingress::IngressSchema;
    match skin {
        IngressSchema::OpenAiChat => body,
        IngressSchema::AnthropicMessages => crate::pipes::request_shaping::transform_from_anthropic_request(body),
        IngressSchema::OpenAiResponses => crate::pipes::request_shaping::transform_from_responses_request(body),
    }
}

async fn surface_usage_limit_block_reason(
    pipe_id: &str,
    pipe: &PipeConfig,
) -> Option<String> {
    let tracker = crate::pipes::budget_tracker::global_budget_tracker()?;
    tracker
        .pipe_limit_block_reason(pipe_id, pipe)
        .await
}

async fn record_rejected_execution_usage(
    state: &PipeHandlerState,
    pipe_id: &str,
    pipe: &PipeConfig,
    usage: &crate::pipes::executor::RejectedExecutionUsage,
    member_id: Option<&str>,
    team_ids: &[String],
) {
    record_surface_llm_usage(pipe_id, usage.llm.cost, usage.llm.total_tokens()).await;
    // The surface's monthly cost budget meters the main-LLM stage, so a blocked
    // request's LLM spend can still trip a budget alert.
    crate::pipes::budget_tracker::record_surface_budget_cost(pipe, usage.llm.cost).await;
    // Emit the multi-resolution usage time-series for the rejected interaction —
    // the surface grand total, each pipeline stage's cost/tokens (so the surface
    // monitoring per-stage cost cards, which read the `surface:{id}:stage:*`
    // series, reflect a Judge/Jury block), and the attributed member/team. The
    // success path records this; without it a blocked stage's spend showed $0.
    crate::telemetry::record_pipe_execution(
        pipe_id,
        &usage.llm,
        &usage.judge,
        &usage.jury,
        &usage.decider,
        usage.key_source(),
        member_id,
        team_ids,
    )
    .await;
    state
        .global_metrics_store
        .record_pipe_execution(
            pipe_id.to_string(),
            Some(pipe.name.clone()),
            "rejected".to_string(),
            "rejected".to_string(),
            crate::metrics::ConnectionStatus::Failed,
            0,
            None,
            None,
            usage.llm.input_tokens + usage.judge.input_tokens + usage.jury.input_tokens + usage.decider.input_tokens,
            usage.llm.output_tokens
                + usage.judge.output_tokens
                + usage.jury.output_tokens
                + usage.decider.output_tokens,
            usage.total_cost(),
            crate::observability::request_context::trace_id(),
            None,
            None,
            0,
            0,
            0,
            Some(crate::metrics::PipeStageUsage {
                llm: usage.llm.into(),
                judge: usage.judge.into(),
                jury: usage.jury.into(),
                decider: usage.decider.into(),
                key_source: usage.key_source(),
            }),
        )
        .await;
}

/// Build the `x-agent-stream-*` observability response headers exposing the
/// per-request trace id, provider/model, token counts (incl. provider-side
/// cached tokens), cost (`x-agent-stream-cost-usd`, at the priced catalog
/// rate), the part of it billed to the account and the main call's key source,
/// and cache status, so a client can read cost/usage without parsing the
/// response body (mirroring hosted gateways).
#[allow(clippy::too_many_arguments)]
fn build_response_headers(
    trace_id: &str,
    provider: &str,
    model: &str,
    input_tokens: u64,
    output_tokens: u64,
    total_tokens: u64,
    cached_tokens: u64,
    cache_write_tokens: u64,
    reasoning_tokens: u64,
    schema_valid: Option<bool>,
    cost: f64,
    billing: ResponseBilling,
    cache_status: &str,
    context_transform: Option<&str>,
    documents: Option<&str>,
    audio: Option<&str>,
    images: Option<&str>,
) -> axum::http::HeaderMap {
    let mut headers = axum::http::HeaderMap::new();
    insert_header(&mut headers, "x-agent-stream-trace-id", trace_id.to_string());
    insert_header(&mut headers, "x-agent-stream-provider", provider.to_string());
    insert_header(&mut headers, "x-agent-stream-model", model.to_string());
    insert_header(&mut headers, "x-agent-stream-input-tokens", input_tokens.to_string());
    insert_header(&mut headers, "x-agent-stream-output-tokens", output_tokens.to_string());
    insert_header(&mut headers, "x-agent-stream-total-tokens", total_tokens.to_string());
    insert_header(&mut headers, "x-agent-stream-cached-tokens", cached_tokens.to_string());
    insert_header(&mut headers, "x-agent-stream-cache-write-tokens", cache_write_tokens.to_string());
    insert_header(&mut headers, "x-agent-stream-reasoning-tokens", reasoning_tokens.to_string());
    if let Some(valid) = schema_valid {
        insert_header(&mut headers, "x-agent-stream-schema-valid", valid.to_string());
    }
    if let Some(transform) = context_transform {
        insert_header(&mut headers, "x-agent-stream-context-transform", transform.to_string());
    }
    if let Some(documents) = documents {
        insert_header(&mut headers, "x-agent-stream-documents", documents.to_string());
    }
    if let Some(audio) = audio {
        insert_header(&mut headers, "x-agent-stream-audio", audio.to_string());
    }
    if let Some(images) = images {
        insert_header(&mut headers, "x-agent-stream-images", images.to_string());
    }
    insert_header(&mut headers, "x-agent-stream-cost-usd", format!("{cost:.6}"));
    insert_header(&mut headers, "x-agent-stream-billed-cost-usd", format!("{:.6}", billing.billed_cost));
    if let Some(source) = billing.key_source {
        insert_header(&mut headers, "x-agent-stream-key-source", source.as_str().to_string());
    }
    insert_header(&mut headers, "x-agent-stream-cache", cache_status.to_string());
    headers
}

/// The credentials a request carries for its surface's upstream (see
/// [`crate::pipes::key_source::CallerCredentials`]). `front_door` is the source
/// auth that authenticates the request, with its surface's tenant: the IDE
/// Surface's own when the request was dispatched through it (`dispatched`),
/// else the called surface's; `middleware` checks a candidate key against its
/// secret.
///
/// The caller's provider key is the bearer token in `Authorization`, else in
/// `x-agent-stream-upstream-authorization`, from a header the front door does
/// not read: where the front door reads `Authorization` (`jwt_bearer`, an API
/// key read from `Authorization`) the dedicated header is the only source.
/// `Authorization` comes first because the dedicated header is also the
/// dual-token channel that carries a caller's upstream identity (a Graph token
/// for a Microsoft 365 Copilot member, see identity pass-through), which must
/// never reach another provider as a key. For the same reason a request an IDE
/// Surface dispatched offers no provider key at all: its `Authorization` is
/// the IDE front door's, and its dedicated header is the member's identity
/// token. A token equal to a front-door credential is never offered either:
/// an SDK that fills `Authorization` with the key it also sends in the front
/// door's own header, or the Anthropic ingress's copy of a front-door
/// `x-api-key`.
async fn caller_credentials(
    middleware: Option<&crate::source_auth::SourceAuthMiddleware>,
    headers: &axum::http::HeaderMap,
    front_door: Option<(&crate::source_auth::SourceAuthConfig, Option<&str>)>,
    dispatched: bool,
) -> crate::pipes::key_source::CallerCredentials {
    use crate::pipes::key_source::bearer_token;

    let header = |name: &str| {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_string)
    };
    let authorization = header(axum::http::header::AUTHORIZATION.as_str());
    let upstream_authorization = header(UPSTREAM_AUTHORIZATION_HEADER);
    let front_door_reads = |name: &str| front_door.is_some_and(|(auth, _)| auth.reads_header(name));
    let from_upstream_header = bearer_token(upstream_authorization.as_deref())
        .filter(|_| !dispatched && !front_door_reads(UPSTREAM_AUTHORIZATION_HEADER));
    let from_authorization = bearer_token(authorization.as_deref())
        .filter(|_| !dispatched && !front_door_reads(axum::http::header::AUTHORIZATION.as_str()));
    let provider_key = match (from_authorization.or(from_upstream_header), front_door) {
        (Some(key), Some((auth, tenant))) => {
            let front_door_credential = match middleware {
                Some(middleware) => {
                    middleware
                        .is_front_door_credential(auth, headers, tenant, key)
                        .await
                }
                None => auth.presents_credential(headers, key),
            };
            if front_door_credential {
                debug!("caller provider key withheld: it is a front-door credential");
            }
            (!front_door_credential).then(|| key.to_string())
        }
        (key, _) => key.map(str::to_string),
    };
    crate::pipes::key_source::CallerCredentials {
        authorization,
        upstream_authorization,
        provider_key,
    }
}

/// The response-cache scope of a request, or `None` when it must not use the
/// cache. An identity pass-through surface (`forward_caller_token`) answers as
/// the caller, so its scope is narrowed to the token forwarded upstream, and a
/// request with no token to forward is not cached.
fn response_cache_scope(
    pipe: &PipeConfig,
    caller: &crate::pipes::key_source::CallerCredentials,
    pipe_id: &str,
    variant_alias: Option<&str>,
    target_identity: &str,
) -> Option<String> {
    use crate::pipes::response_cache::ResponseCache;
    let scope = ResponseCache::scope_key_for_target(pipe_id, variant_alias, target_identity);
    if !pipe.forward_caller_token {
        return Some(scope);
    }
    caller
        .forwarded_token()
        .map(|token| ResponseCache::caller_scope(&scope, token))
}

/// The error code a caller gets when the upstream refused the caller's own key.
const CALLER_KEY_REJECTED: &str = "caller_key_rejected";

/// The error code a caller gets for a binary passthrough (text-to-speech)
/// whose path reaches no speech endpoint on the surface's provider (see
/// [`crate::pipes::executor::PipeError::BinaryEndpointUnsupported`]).
const BINARY_ENDPOINT_UNSUPPORTED_CODE: &str = "binary_endpoint_unsupported";

/// The status a caller gets when the upstream refused its own key: the
/// upstream's own 401 or 403.
fn caller_key_status(status: u16) -> StatusCode {
    StatusCode::from_u16(status).unwrap_or(StatusCode::UNAUTHORIZED)
}

/// The `(status, type, code)` a caller gets for a failed provider call: the
/// upstream's own 401/403 when it refused the caller's key, 504 on a timeout,
/// else 502.
/// Whether a request offers the model tools: a non-empty `tools` array, or a
/// non-empty legacy `functions` array, which a Claude upstream runs as tools.
fn offers_tools(payload: &Value) -> bool {
    ["tools", "functions"]
        .iter()
        .any(|key| {
            payload
                .get(*key)
                .and_then(Value::as_array)
                .is_some_and(|t| !t.is_empty())
        })
}

fn provider_failure_status(e: &crate::pipes::executor::PipeError) -> (StatusCode, &'static str, &'static str) {
    match e {
        crate::pipes::executor::PipeError::RequestTimeout(_) => {
            (StatusCode::GATEWAY_TIMEOUT, "timeout_error", "provider_timeout")
        }
        crate::pipes::executor::PipeError::CallerKeyRejected { status } => {
            (caller_key_status(*status), "authentication_error", CALLER_KEY_REJECTED)
        }
        e if e.unsupported_content() => (StatusCode::BAD_REQUEST, "invalid_request_error", "unsupported_content"),
        _ => (StatusCode::BAD_GATEWAY, "provider_error", "provider_error"),
    }
}

/// The error `type` of a team-gate refusal: a rate or quota limit (429), the
/// gate unable to run on a surface that enforces usage (503), or an access
/// denial.
fn team_gate_error_type(status: StatusCode) -> &'static str {
    if status == StatusCode::TOO_MANY_REQUESTS {
        "rate_limit_error"
    } else if status.is_server_error() {
        "api_error"
    } else {
        "permission_error"
    }
}

/// The code a caller gets when its member or team budget is spent: the team
/// gate's own.
const TEAM_QUOTA_EXCEEDED: &str = "team_quota_exceeded";

/// The body of the team gate's 429 for a spent budget.
fn team_quota_body(reason: &str) -> Value {
    serde_json::json!({
        "error": {
            "message": reason,
            "type": "rate_limit_error",
            "code": TEAM_QUOTA_EXCEEDED
        }
    })
}

/// The governance stage a request is recorded as blocked at when its
/// platform-key call was refused because Agent Stream would not meter its
/// spend: not the team gate's, so a readout tells "not metered" from "credit
/// used up".
const METERING_STAGE: &str = "metering";

/// The answer to an execution whose platform-key call was refused before it
/// was sent: the response, its body, and the governance stage and machine
/// code the block is recorded under.
struct PlatformRefused {
    response: Response,
    body: Value,
    stage: &'static str,
    code: &'static str,
}

/// The answer to an execution whose platform-key call was refused before it
/// was sent, `None` when `e` is not that refusal:
/// - a spent budget (see [`crate::teams::call_budget`]): the team gate's 429
///   `team_quota_exceeded`, recorded as the gate's block (`team_gate`);
/// - spend Agent Stream does not meter (see [`crate::pipes::metering`]): 403
///   `permission_error` with the kind's own code (`batch_not_metered`,
///   `endpoint_not_metered`, `model_not_metered`), which SDKs do not retry,
///   recorded at stage `metering`.
fn platform_refused(e: &crate::pipes::executor::PipeError) -> Option<PlatformRefused> {
    if let Some(unmetered) = e.not_metered() {
        let body = serde_json::json!({
            "error": {
                "message": unmetered.message(),
                "type": "permission_error",
                "code": unmetered.code()
            }
        });
        return Some(PlatformRefused {
            response: (StatusCode::FORBIDDEN, Json(body.clone())).into_response(),
            body,
            stage: METERING_STAGE,
            code: unmetered.code(),
        });
    }
    let body = team_quota_body(e.budget_refusal()?);
    Some(PlatformRefused {
        response: (StatusCode::TOO_MANY_REQUESTS, Json(body.clone())).into_response(),
        body,
        stage: "team_gate",
        code: TEAM_QUOTA_EXCEEDED,
    })
}

/// What a response's billing headers report: the part of the cost billed to
/// the account and the source of the key the main call sent (`None` when no
/// main call ran, as on a cache hit).
#[derive(Debug, Clone, Copy, Default)]
struct ResponseBilling {
    billed_cost: f64,
    key_source: Option<crate::pipes::key_source::KeySource>,
}

/// Request-body modalities detected once per request (cheap: reads only the
/// `format`/type markers, never decodes payloads). `realtime` is intentionally
/// absent — it is a WebSocket transport signal matched by the realtime handler,
/// never on the chat body.
struct RequestModalities {
    image: bool,
    audio: bool,
    document: bool,
}

impl RequestModalities {
    fn detect(body: &Value) -> Self {
        Self {
            image: crate::pipes::image_input::image_formats_present(body).is_some(),
            audio: crate::pipes::audio::audio_formats_present(body).is_some(),
            document: crate::pipes::document_ingestion::document_types_present(body).is_some(),
        }
    }

    /// Whether the request carries `has`. `text` = a request with no media
    /// attachments; `realtime` never matches here (chat path).
    fn contains(
        &self,
        has: &str,
    ) -> bool {
        match has {
            "image" => self.image,
            "audio" => self.audio,
            "document" => self.document,
            "text" => !self.image && !self.audio && !self.document,
            _ => false,
        }
    }
}

/// Evaluate attribute-based routing rules against the request, returning the
/// first matching rule's target. A header rule matches a request header value
/// (header name matched case-insensitively); a body-field rule matches a
/// top-level string field of the JSON body; a modality rule matches an attached
/// input type detected from the body.
fn select_routing_target<'a>(
    rules: &'a [crate::pipes::config::RoutingRule],
    headers: &axum::http::HeaderMap,
    body: &Value,
) -> Option<&'a crate::pipes::config::RoutingTarget> {
    use crate::pipes::config::RoutingMatch;
    // Detected lazily and at most once, so multiple modality rules never
    // re-walk the payload on the request hot path.
    let mut modalities: Option<RequestModalities> = None;
    for rule in rules {
        let matched = match &rule.match_on {
            RoutingMatch::Header { name, equals } => {
                headers
                    .get(name.as_str())
                    .and_then(|v| v.to_str().ok())
                    == Some(equals.as_str())
            }
            RoutingMatch::BodyField { field, equals } => {
                body.get(field)
                    .and_then(|v| v.as_str())
                    == Some(equals.as_str())
            }
            RoutingMatch::Modality { has } => modalities
                .get_or_insert_with(|| RequestModalities::detect(body))
                .contains(has),
        };
        if matched {
            return Some(&rule.target);
        }
    }
    None
}

/// Telemetry-tagged outcome of the routing precedence decision, before variant
/// materialization. `alias`/`inline_target` drive variant resolution and cache
/// keying; `decision`/`metric_variant` feed the routing-decision counter.
pub(crate) struct RouteDecision {
    /// The variant alias to resolve, or `None` for base/default.
    pub alias: Option<String>,
    /// An inline provider target to swap onto the resolved (base) config.
    pub inline_target: Option<crate::pipes::judge_jury::LLMTarget>,
    /// Closed-vocabulary telemetry token (see [`crate::metrics::backends::prometheus::VARIANT_ROUTING_DECISIONS`]).
    pub decision: &'static str,
    /// Variant label for the counter: the chosen alias or `"base"`.
    pub metric_variant: String,
}

/// Fixed `variant` label for a client-supplied alias that is not a configured
/// variant of the pipe. Keeps the counter's cardinality bounded: an explicit
/// `$alias` is caller-controlled and (for a pipe with no variants) resolves to
/// base regardless, so it must never be used verbatim as a Prometheus label.
const UNCONFIGURED_VARIANT_LABEL: &str = "unconfigured";

/// Cardinality-safe `variant` label for a client-supplied `alias`: the alias
/// itself only when it names a configured variant of the pipe (bounded by the
/// variant catalog and the `^[a-z0-9-]{1,32}$` grammar), otherwise the fixed
/// [`UNCONFIGURED_VARIANT_LABEL`].
fn variant_metric_label(
    pipe: &crate::pipes::config::PipeConfig,
    alias: &str,
) -> String {
    if pipe
        .variants
        .iter()
        .any(|v| v.alias == alias)
    {
        alias.to_string()
    } else {
        UNCONFIGURED_VARIANT_LABEL.to_string()
    }
}

/// Identity of the upstream a resolved config calls, keying the executor cache.
/// The upstream's own headers and declared price are part of it: an inline
/// routing target can name the same provider as the base but carry its own
/// headers, and must never be served by an executor holding the base's.
fn effective_target_identity(resolved_pipe: &crate::pipes::config::PipeConfig) -> String {
    use sha2::{Digest, Sha256};

    let serialized = serde_json::to_vec(&(
        &resolved_pipe.pipe_type,
        &resolved_pipe.upstream_headers,
        &resolved_pipe.upstream_pricing,
    ))
    .expect("pipe type must serialize");
    format!("{:x}", Sha256::digest(serialized))
}

fn execution_cache_key(
    pipe_id: &str,
    variant_alias: Option<&str>,
    target_identity: &str,
    primary_upstream: bool,
) -> String {
    let route_scope = match variant_alias {
        Some(alias) => format!("{pipe_id}${alias}"),
        None => pipe_id.to_string(),
    };
    let role = if primary_upstream {
        ""
    } else {
        "$secondary"
    };
    format!("{route_scope}$target:{target_identity}{role}")
}

async fn get_or_insert_cached<T, F>(
    cache: &RwLock<HashMap<String, Arc<T>>>,
    key: String,
    create: F,
) -> Arc<T>
where
    F: FnOnce() -> T,
{
    let mut cache = cache.write().await;
    if let Some(value) = cache.get(&key) {
        value.clone()
    } else {
        let value = Arc::new(create());
        cache.insert(key, value.clone());
        value
    }
}

/// Resolve which variant/target a request routes to, applying the precedence
/// **explicit `$alias` > routing rule > canary split > base/default**. Pure over
/// its inputs (RNG aside, inside the canary split) so it is unit-testable.
pub(crate) fn resolve_route_decision(
    pipe: &crate::pipes::config::PipeConfig,
    explicit_alias: Option<String>,
    headers: &axum::http::HeaderMap,
    payload: &Value,
) -> RouteDecision {
    use crate::pipes::config::CanaryOutcome;

    // 1. Explicit `$alias` wins outright. The alias is caller-controlled, so the
    //    metric label is bounded to configured variants (see `variant_metric_label`)
    //    while the raw alias still drives resolution/caching.
    if let Some(alias) = explicit_alias {
        return RouteDecision {
            metric_variant: variant_metric_label(pipe, &alias),
            alias: Some(alias),
            inline_target: None,
            decision: "explicit_alias",
        };
    }

    // 2. First matching routing rule (only when routing is enabled).
    if pipe.routing_enabled
        && let Some(target) = select_routing_target(&pipe.routing_rules, headers, payload)
    {
        match target
            .variant
            .as_ref()
            .filter(|a| !a.trim().is_empty())
        {
            Some(alias) => {
                debug!(route_variant = %alias, "Routing rule matched → variant");
                return RouteDecision {
                    metric_variant: alias.clone(),
                    alias: Some(alias.clone()),
                    inline_target: None,
                    decision: "routing_rule",
                };
            }
            None => {
                if let Some(llm) = &target.llm {
                    debug!(route_model = %llm.model, "Routing rule matched → inline target");
                }
                return RouteDecision {
                    alias: None,
                    inline_target: target.llm.clone(),
                    decision: "routing_rule_inline",
                    metric_variant: "base".to_string(),
                };
            }
        }
    }

    // 3. Canary weighted split, retaining the skip reason for telemetry.
    let base = |decision: &'static str| RouteDecision {
        alias: None,
        inline_target: None,
        decision,
        metric_variant: "base".to_string(),
    };
    match pipe
        .canary
        .as_ref()
        .map(|c| c.decide())
    {
        Some(CanaryOutcome::Variant(alias)) => {
            debug!(canary_variant = %alias, "Canary split routed request to variant");
            RouteDecision {
                metric_variant: alias.clone(),
                alias: Some(alias),
                inline_target: None,
                decision: "canary",
            }
        }
        Some(CanaryOutcome::Disabled) => base("canary_skipped_disabled"),
        Some(CanaryOutcome::NoWeight) => base("canary_skipped_no_weight"),
        Some(CanaryOutcome::BaseSplit) => base("canary_skipped_base_split"),
        // 4. No canary configured → base/default.
        None => base("base_default"),
    }
}

/// Map a variant-resolution failure to its HTTP response shape and telemetry
/// token: `(status, error code, routing-decision label)`. A disabled variant is
/// **503 Service Unavailable**, an unknown alias is **404 Not Found**, and a
/// misconfigured default is **500 Internal Server Error**.
pub(crate) fn variant_error_response(
    e: &crate::pipes::pipe_variants::VariantResolveError
) -> (StatusCode, &'static str, &'static str) {
    use crate::pipes::pipe_variants::VariantResolveError;
    match e {
        VariantResolveError::UnknownAlias(_) => (StatusCode::NOT_FOUND, "variant_not_found", "rejected_unknown"),
        VariantResolveError::DisabledVariant(_) => {
            (StatusCode::SERVICE_UNAVAILABLE, "variant_disabled", "rejected_disabled")
        }
        VariantResolveError::MisconfiguredDefault(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "variant_misconfigured", "rejected_misconfigured")
        }
    }
}

/// Extract a stable caller identifier from an authenticated identity for
/// governance attribution (hashed downstream — never stored in the clear).
pub(crate) fn caller_identity_string(id: &crate::source_auth::AuthenticatedIdentity) -> String {
    use crate::source_auth::AuthenticatedIdentity as AI;
    match id {
        AI::JwtBearer { subject, .. } => subject.clone(),
        AI::ApiKey { key_name } => key_name.clone(),
        AI::Mtls { principal, .. } => principal.clone(),
    }
}

/// Canonical rejection-category ids of a content rejection.
fn rejection_categories(rejection: Option<&crate::pipes::executor::RejectionMeta>) -> Vec<String> {
    rejection
        .map(|meta| crate::rejection_taxonomy::classify_global(&meta.raw_reasons, &meta.source))
        .unwrap_or_default()
}

/// Record a request the team gate or a surface usage limit refused: a signed
/// governance record with a `Block` stage (when the surface records governance)
/// and a `pipe.error` carrying the stage and the refusal code, published off the
/// request path. `error_body` is the error returned to the caller.
fn record_front_door_block(
    state: &PipeHandlerState,
    pipe: &PipeConfig,
    resolved_pipe: &PipeConfig,
    request: &Value,
    stage: &str,
    code: &str,
    error_body: &Value,
) {
    let error = error_body.to_string();
    trigger_block_event(state, pipe, stage, code, &error);
    if let Some(gov) = resolved_pipe
        .governance_recording
        .as_ref()
        .filter(|g| g.enabled)
    {
        crate::governance::capture_failure(
            true,
            gov.capture_policy(),
            resolved_pipe.id.clone(),
            resolved_pipe.name.clone(),
            Some(request.clone()),
            None,
            crate::governance::InteractionOutcome::Blocked {
                stage: stage.to_string(),
                reason: Some(error.clone()),
                input: None,
                output: None,
                categories: Vec::new(),
            },
            gov.export.clone(),
        );
    }
}

/// Fire `pipe`'s `pipe.error` integrations for a request refused at `stage`
/// with the machine `code`, off the request path.
fn trigger_block_event(
    state: &PipeHandlerState,
    pipe: &PipeConfig,
    stage: &str,
    code: &str,
    error: &str,
) {
    if let Some(store) = state
        .notification_store
        .clone()
    {
        let integrations = pipe.integrations.clone();
        let event = crate::integrations::pipe_integration_triggers::PipeErrorEvent::new(pipe, error.to_string())
            .at_stage(stage)
            .with_code(code);
        tokio::spawn(async move {
            crate::integrations::trigger_pipe_error(&store, &integrations, &event).await;
        });
    }
}

/// Emit a signed governance record for an OPA policy denial/error at a pipe
/// enforcement point, when the surface has governance recording enabled. The
/// deciding policy's definition id / version / content hash (from `evidence`)
/// are recorded so the block is attestable and reproducible against exact Rego
/// bytes. A no-op when governance recording is off for the surface.
fn capture_pipe_policy_denial(
    resolved_pipe: &crate::pipes::PipeConfig,
    request: &Value,
    caller_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
    evidence: Option<crate::pipes::PolicyEvidence>,
    stage_label: &str,
    reason: Option<String>,
    is_error: bool,
) {
    let Some(gov) = resolved_pipe
        .governance_recording
        .as_ref()
    else {
        return;
    };
    if !gov.enabled || !crate::governance::is_ready() {
        return;
    }
    crate::observability::request_context::update(|ctx| {
        if ctx.identity.is_none() {
            ctx.set_identity(caller_identity);
        }
        if ctx.usage.tenant_id.is_none() {
            ctx.usage.tenant_id = resolved_pipe
                .tenant_id
                .clone();
        }
    });
    let evidence = evidence.unwrap_or_default();
    crate::governance::capture_policy_denial(
        true,
        gov.capture_policy(),
        resolved_pipe.id.clone(),
        resolved_pipe.name.clone(),
        Some(request.clone()),
        caller_identity.map(caller_identity_string),
        stage_label,
        reason,
        is_error,
        evidence.definition_id,
        evidence.name,
        evidence.version,
        evidence.content_hash,
        gov.export.clone(),
    );
}

/// Verify inbound verifiable-presentation evidence for a surface (when enabled)
/// and build the `identity_binding` context for the policy input. Returns
/// `Ok(None)` when VP evidence is not configured or no VP is present and not
/// required; `Ok(Some(binding))` when a VP was presented (`verified` reflects
/// the outcome so the policy can decide); `Err(())` when `require_present` is
/// set but no valid VP was presented (the caller must deny the request).
async fn resolve_vp_evidence(
    resolved_pipe: &crate::pipes::PipeConfig,
    headers: &axum::http::HeaderMap,
    payload: &Value,
    expected: crate::identity::ExpectedChallenge<'_>,
) -> Result<Option<crate::surface_context::IdentityBindingContext>, ()> {
    let Some(cfg) = resolved_pipe.vp_evidence() else {
        return Ok(None);
    };
    let vp_raw: Option<String> = match cfg.source {
        crate::pipes::config::VpEvidenceSource::Header => {
            let name = cfg
                .header_name
                .as_deref()
                .unwrap_or("x-agent-stream-presentation");
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        }
        crate::pipes::config::VpEvidenceSource::Body => payload
            .get("verifiable_presentation")
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| v.to_string())
            }),
    };
    let Some(vp_raw) = vp_raw.filter(|s| !s.trim().is_empty()) else {
        // No VP presented.
        return if cfg.require_present {
            Err(())
        } else {
            Ok(None)
        };
    };
    // An unverified binding recorded when a VP is present but cannot be verified
    // (so a non-`require_present` policy can still see `verified == false`).
    let unverified = || crate::surface_context::IdentityBindingContext {
        verified: false,
        agent_did: String::new(),
        gateway_did: String::new(),
        issuer_did: None,
        identity_fields: std::collections::HashMap::new(),
    };
    let Some(vc_issuer) = crate::gateways::connection_points::message_processor::global_vc_issuer() else {
        warn!("VP evidence enabled but VC issuer unavailable; treating VP as unverified");
        return if cfg.require_present {
            Err(())
        } else {
            Ok(Some(unverified()))
        };
    };
    match vc_issuer
        .verify_presentation_with_issuer(&vp_raw, expected)
        .await
    {
        Ok((holder_did, issuer_did, identity_fields)) => Ok(Some(crate::surface_context::IdentityBindingContext {
            verified: true,
            agent_did: holder_did,
            gateway_did: String::new(),
            issuer_did,
            identity_fields,
        })),
        Err(e) => {
            warn!(error = %e, "Inbound VP evidence failed verification");
            if cfg.require_present {
                Err(())
            } else {
                Ok(Some(unverified()))
            }
        }
    }
}

fn vp_challenge_error(
    status: StatusCode,
    message: &str,
    error_type: &str,
    code: &str,
) -> Response {
    (
        status,
        Json(serde_json::json!({
            "error": { "message": message, "type": error_type, "code": code }
        })),
    )
        .into_response()
}

/// An IDE Surface issues challenges for the members that evaluate VP evidence
/// after dispatch.
async fn evaluates_vp_evidence(
    state: &PipeHandlerState,
    pipe: &PipeConfig,
) -> bool {
    let crate::pipes::PipeType::IDECatalog { config } = &pipe.pipe_type else {
        return pipe.vp_evidence().is_some();
    };
    for member in config
        .members
        .iter()
        .filter(|member| member.expose)
    {
        let Some(member_pipe) = state
            .pipe_store
            .get(&member.pipe_id)
            .await
        else {
            continue;
        };
        let resolved = match member_pipe.resolve_variant(
            member
                .variant_alias
                .as_deref(),
        ) {
            Ok(resolved) => resolved,
            Err(_) => member_pipe,
        };
        if resolved.status.is_enabled()
            && resolved
                .vp_evidence()
                .is_some()
        {
            return true;
        }
    }
    false
}

/// `POST {route}/v1/vp-challenge`. Once the route's surface is loaded, its source
/// authentication runs first, so a caller without credentials cannot tell
/// whether it issues challenges; the inbound policy runs on the request carrying
/// the presentation.
async fn issue_vp_challenge(
    state: &PipeHandlerState,
    headers: &axum::http::HeaderMap,
    peer_cert: Option<&crate::source_auth::models::PeerCertInfo>,
    client: std::net::IpAddr,
    pipe_id: &str,
    variant_alias: Option<&str>,
) -> Response {
    let not_found = || {
        vp_challenge_error(
            StatusCode::NOT_FOUND,
            "This surface does not issue VP challenges",
            "invalid_request_error",
            "not_found",
        )
    };
    let Some(pipe) = state
        .pipe_store
        .get(pipe_id)
        .await
    else {
        return not_found();
    };
    let resolved = match pipe.resolve_variant(variant_alias) {
        Ok(resolved) => resolved,
        Err(_) => pipe,
    };

    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
    let source_auth = crate::source_auth::source_auth_gate(
        resolved.source_auth.as_ref(),
        state
            .source_auth_middleware
            .as_deref(),
    );
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        return source_auth_unavailable_response(pipe_id);
    }
    if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
        match sa_middleware
            .authenticate(auth_config, headers, &resolved.name, resolved.tenant_id.as_deref(), peer_cert)
            .await
        {
            Ok(identity) => caller_identity = Some(identity),
            Err(e) => {
                warn!(pipe_id = %pipe_id, reason = %e, "Source authentication failed on VP challenge request - returning 401");
                return source_auth_failed_response();
            }
        }
    }

    if !resolved.status.is_enabled() || !evaluates_vp_evidence(state, &resolved).await {
        return not_found();
    }

    let caller = match caller_identity.as_ref() {
        Some(identity) => crate::identity::ChallengeCaller::Principal(caller_identity_string(identity)),
        None => crate::identity::ChallengeCaller::Address(client),
    };
    let unavailable = || {
        vp_challenge_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "VP challenges are unavailable",
            "api_error",
            "vp_challenge_unavailable",
        )
    };
    let Some(vc_issuer) = crate::gateways::connection_points::message_processor::global_vc_issuer() else {
        warn!(pipe_id = %pipe_id, "VP challenge requested but VC issuer unavailable");
        return unavailable();
    };
    match vc_issuer
        .create_vp_challenge(pipe_id, &caller)
        .await
    {
        Ok(issued) => {
            ([(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-store"))], Json(issued))
                .into_response()
        }
        Err(e)
            if e.downcast_ref::<crate::identity::IssueRefused>()
                == Some(&crate::identity::IssueRefused::CallerLimit) =>
        {
            warn!(pipe_id = %pipe_id, "Refused VP challenge: the caller holds its limit of unused challenges");
            vp_challenge_error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many unused VP challenges; use or let one expire before asking again",
                "rate_limit_error",
                "rate_limit_exceeded",
            )
        }
        Err(e) => {
            warn!(pipe_id = %pipe_id, error = %e, "Could not issue a VP challenge");
            unavailable()
        }
    }
}

/// The 403 for a call refused before it was sent because it would read or
/// write the provider store behind a credential the surface's tenant does not
/// own (see `crate::pipes::shared_credential`).
fn shared_credential_refused_response(
    pipe_id: &str,
    refusal: crate::pipes::shared_credential::SharedCredentialRefusal,
) -> Response {
    warn!(pipe_id = %pipe_id, code = refusal.code(), "Call refused: it would use a provider key shared with other tenants");
    (
        StatusCode::FORBIDDEN,
        Json(serde_json::json!({
            "error": { "message": refusal.message(), "type": "permission_error", "code": refusal.code() }
        })),
    )
        .into_response()
}

/// Whether the inbound policy gate has anything to evaluate for `pipe`: an
/// appliance-wide policy set for its surface type, its own policy, or VP
/// evidence.
fn inbound_policy_applies(
    policy_mgr: &crate::pipes::PipePolicyManager,
    pipe: &PipeConfig,
) -> bool {
    policy_mgr.has_global(crate::pipes::pipe_policy_type(&pipe.pipe_type))
        || pipe.opa_enabled()
        || pipe.vp_evidence().is_some()
}

/// One request at the inbound policy gate.
struct InboundPolicyRequest<'a> {
    resolved_pipe: &'a PipeConfig,
    pipe_id: &'a str,
    variant_alias: Option<&'a str>,
    method: &'a str,
    /// The raw client path, as `input.http.path`.
    path: &'a str,
    headers: &'a axum::http::HeaderMap,
    /// The JSON body, or `Value::Null` for a request without one.
    payload: &'a Value,
    caller_identity: Option<&'a crate::source_auth::AuthenticatedIdentity>,
    resource: crate::surface_context::ResourceContext,
    /// The IDE Surface a dispatched request came through.
    front_door_id: Option<&'a str>,
}

/// The inbound policy gate every route of a surface that reaches its provider
/// runs after source authentication: the chat pipeline, file upload, speech to
/// text, and the file and batch GET passthrough. VP evidence (when the surface
/// enables it) binds the caller's presentation and denies a required one that
/// is missing. Then two layers apply, both deny-overrides and fail-closed: the
/// appliance-wide (global) policy set for this surface type, enforced
/// regardless of the surface's own config, and the surface's own policy.
/// Either alone gates the request. `Err` carries the 403 to return.
async fn enforce_inbound_policy(
    policy_mgr: &crate::pipes::PipePolicyManager,
    request: InboundPolicyRequest<'_>,
) -> Result<(), Response> {
    let InboundPolicyRequest {
        resolved_pipe,
        pipe_id,
        variant_alias,
        method,
        path,
        headers,
        payload,
        caller_identity,
        resource,
        front_door_id,
    } = request;
    if !inbound_policy_applies(policy_mgr, resolved_pipe) {
        return Ok(());
    }
    let surface_type = crate::pipes::pipe_policy_type(&resolved_pipe.pipe_type);
    let enforce_global = policy_mgr.has_global(surface_type);
    let enforce_surface = resolved_pipe.opa_enabled();

    let mut policy_input = crate::surface_context::PolicyInput::new(
        method,
        path,
        crate::surface_context::filter_sensitive_headers(headers),
        "inbound",
        None,
        None,
        Some(pipe_id.to_string()),
        &resolved_pipe.name,
    );
    policy_input.source_auth = caller_identity.map(crate::surface_context::SourceAuthContext::from);
    policy_input.action = Some("dispatch".to_string());
    policy_input.resource = Some(resource);
    // Inbound VP evidence (opt-in per surface) → inject identity binding
    // for the policy; a required-but-missing/invalid VP denies pre-eval.
    let principal = caller_identity.map(caller_identity_string);
    let expected = crate::identity::ExpectedChallenge::Issued {
        surface_id: pipe_id,
        front_door_id,
        principal: principal.as_deref(),
    };
    match resolve_vp_evidence(resolved_pipe, headers, payload, expected).await {
        Ok(binding) => policy_input.identity_binding = binding,
        Err(()) => {
            warn!(pipe_id = %pipe_id, "Required VP evidence missing or invalid - returning 403");
            capture_pipe_policy_denial(
                resolved_pipe,
                payload,
                caller_identity,
                policy_mgr.policy_evidence(pipe_id, variant_alias),
                "vp_evidence",
                Some("Required verifiable presentation missing or invalid".to_string()),
                false,
            );
            return Err((
                StatusCode::FORBIDDEN,
                Json(serde_json::json!({
                    "error": {
                        "message": "Required verifiable presentation missing or invalid",
                        "type": "permission_error",
                        "code": "vp_required"
                    }
                })),
            )
                .into_response());
        }
    }
    let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

    // Appliance-wide global policy first - every surface of this type.
    if enforce_global {
        let (decision, evidence) = policy_mgr.evaluate_global(surface_type, input_value.clone());
        match decision {
            Ok(true) => {}
            Ok(false) => {
                warn!(pipe_id = %pipe_id, surface_type, "Appliance-wide policy denied request - returning 403");
                capture_pipe_policy_denial(
                    resolved_pipe,
                    payload,
                    caller_identity,
                    evidence,
                    "global_policy",
                    Some("Request denied by appliance-wide policy".to_string()),
                    false,
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": {
                            "message": "Request denied by appliance-wide policy",
                            "type": "permission_error",
                            "code": "policy_denied"
                        }
                    })),
                )
                    .into_response());
            }
            Err(e) => {
                error!(pipe_id = %pipe_id, surface_type, reason = %e, "Appliance-wide policy evaluation errored - denying (fail-closed)");
                capture_pipe_policy_denial(
                    resolved_pipe,
                    payload,
                    caller_identity,
                    evidence,
                    "global_policy",
                    Some(e),
                    true,
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": {
                            "message": "Request denied by appliance-wide policy",
                            "type": "permission_error",
                            "code": "policy_error"
                        }
                    })),
                )
                    .into_response());
            }
        }
    }

    // Per-surface policy.
    if enforce_surface {
        let (decision, evidence) = policy_mgr.evaluate_with_evidence(pipe_id, variant_alias, input_value);
        match decision {
            Ok(true) => {}
            Ok(false) => {
                warn!(pipe_id = %pipe_id, "Pipe OPA policy denied request - returning 403");
                capture_pipe_policy_denial(
                    resolved_pipe,
                    payload,
                    caller_identity,
                    evidence,
                    "policy",
                    Some("Request denied by pipe policy".to_string()),
                    false,
                );
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": {
                            "message": "Request denied by pipe policy",
                            "type": "permission_error",
                            "code": "policy_denied"
                        }
                    })),
                )
                    .into_response());
            }
            Err(e) => {
                error!(pipe_id = %pipe_id, reason = %e, "Pipe OPA evaluation errored - denying (fail-closed)");
                capture_pipe_policy_denial(resolved_pipe, payload, caller_identity, evidence, "policy", Some(e), true);
                return Err((
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": {
                            "message": "Request denied by pipe policy",
                            "type": "permission_error",
                            "code": "policy_error"
                        }
                    })),
                )
                    .into_response());
            }
        }
    }
    Ok(())
}

/// The inbound gates a passthrough route (file upload, speech to text, the file
/// and batch GET passthrough) runs before its provider is reached, exactly as
/// the chat pipeline runs them: the caller is attributed to the request
/// context, then the inbound policy gate decides. There is no JSON body, so
/// policies see `Value::Null` for it and no requested model.
async fn enforce_passthrough_policy(
    state: &PipeHandlerState,
    resolved_pipe: &PipeConfig,
    pipe_id: &str,
    method: &str,
    path: &str,
    headers: &axum::http::HeaderMap,
    caller_identity: Option<&crate::source_auth::AuthenticatedIdentity>,
) -> Result<(), Response> {
    crate::observability::request_context::update(|ctx| {
        ctx.usage.tenant_id = resolved_pipe
            .tenant_id
            .clone();
        ctx.set_identity(caller_identity);
    });
    let Some(policy_mgr) = &state.pipe_policy_manager else {
        return Ok(());
    };
    let resource = crate::surface_context::ResourceContext {
        surface_type: Some(crate::pipes::pipe_policy_type(&resolved_pipe.pipe_type).to_string()),
        ..Default::default()
    };
    enforce_inbound_policy(
        policy_mgr,
        InboundPolicyRequest {
            resolved_pipe,
            pipe_id,
            variant_alias: None,
            method,
            path,
            headers,
            payload: &Value::Null,
            caller_identity,
            resource,
            front_door_id: None,
        },
    )
    .await
}

/// Reject message when a surface's LLM is a **realtime-only** voice model that
/// has no buffered/streaming chat (generateContent) form — OpenAI `*realtime*`,
/// Gemini `*native-audio*` / `*live*`. Returns `None` for any chat/vision model
/// and for non-LLM surfaces. Kept separate from the handler so it is unit
/// testable; the capability is read from the resolved model profile
/// (`supports_realtime`), catalog-authoritative with a name-based default.
fn realtime_only_chat_rejection(pipe_type: &crate::pipes::PipeType) -> Option<String> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    if let crate::pipes::PipeType::LLM { provider, .. } = pipe_type
        && crate::pipes::executor::resolve_request_profile(provider).supports_realtime
    {
        let model = provider.get_model();
        return Some(format!(
            "The model '{model}' is a realtime voice model and can only be used through the realtime endpoint (GET /v1/realtime over WebSocket). It cannot process text or image chat requests. Select a chat- or vision-capable model for this surface, or connect to it using the realtime voice API."
        ));
    }
    None
}

struct PipeRouteMatch {
    pipe_id: String,
    route: String,
    tail: String,
    variant_alias: Option<String>,
}

/// The longest surface route on this listener that `path` falls under.
async fn match_pipe_route(
    state: &PipeHandlerState,
    path: &str,
) -> Option<PipeRouteMatch> {
    let route_map = state
        .route_to_pipe
        .read()
        .await;
    let mut best: Option<PipeRouteMatch> = None;
    for (key, id) in route_map.iter() {
        if !route_key_matches_listener(key, &state.listener_scopes) {
            continue;
        }
        let route = &key.route;
        if let Some(m) = crate::proxy::route_variant::parse_route_with_variant(path, route)
            && best
                .as_ref()
                .is_none_or(|best| route.len() > best.route.len())
        {
            best = Some(PipeRouteMatch {
                pipe_id: id.clone(),
                route: route.clone(),
                tail: m.tail.to_string(),
                variant_alias: m.alias.map(str::to_string),
            });
        }
    }
    best
}

/// POST entry point for a surface's LLM data plane.
///
/// Negotiates the inbound API **skin** from the request path
/// (`/v1/chat/completions` = OpenAI Chat, `/v1/messages` = Anthropic Messages,
/// `/v1/responses` = OpenAI Responses), maps native Anthropic `x-api-key` auth to
/// a Bearer credential, runs the OpenAI-canonical pipeline via
/// [`handle_chat_completions_inner`], and re-skins error envelopes to match the
/// requested dialect. Success bodies and SSE are skinned inside the inner handler
/// (they need the resolved model + canonical body). See `docs/CLIENT_API_DIALECTS.md`.
pub async fn handle_chat_completions(
    State(state): State<PipeHandlerState>,
    mut headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    peer_cert: Option<axum::Extension<crate::source_auth::models::PeerCertInfo>>,
    connect_info: Option<axum::Extension<axum::extract::ConnectInfo<std::net::SocketAddr>>>,
    body: axum::body::Bytes,
) -> Response {
    use crate::pipes::ingress::IngressSchema;

    if uri
        .path()
        .trim_end_matches('/')
        .ends_with("/v1/vp-challenge")
        && let Some(route) = match_pipe_route(&state, uri.path()).await
        && crate::pipes::streaming::is_vp_challenge_path(&route.tail)
    {
        let client = crate::auth::throttle::client_address(
            connect_info.map(|axum::Extension(axum::extract::ConnectInfo(peer))| peer),
            &headers,
        );
        return Box::pin(issue_vp_challenge(
            &state,
            &headers,
            peer_cert
                .as_ref()
                .map(|e| &e.0),
            client,
            &route.pipe_id,
            route.variant_alias.as_deref(),
        ))
        .await;
    }

    let ingress_skin = crate::pipes::ingress::detect_ingress_schema(uri.path());

    // Native Anthropic clients authenticate with `x-api-key`; map it to
    // `Authorization: Bearer` so source auth / OPA (which only read
    // `Authorization`) work unchanged. Never overrides an explicit Authorization.
    if ingress_skin == IngressSchema::AnthropicMessages
        && !headers.contains_key(axum::http::header::AUTHORIZATION)
        && let Some(api_key) = headers
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
        && let Ok(bearer) = axum::http::HeaderValue::from_str(&format!("Bearer {api_key}"))
    {
        headers.insert(axum::http::header::AUTHORIZATION, bearer);
    }

    // A caller can ask to receive live pipeline stage
    // events on its own request's stream, so it can show Prompt Guard / Judge /
    // Jury progress without any admin log access. Correlated by the request span.
    let emit_stages = headers
        .get("x-agent-stream-emit-stages")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("true"));
    if emit_stages {
        return handle_chat_completions_with_stages(State(state), headers, uri, peer_cert, body, ingress_skin).await;
    }

    let response = run_in_request_context(State(state), headers, uri, peer_cert, body, ingress_skin).await;
    let mut response = reskin_error_response(ingress_skin, response).await;
    // Surface the negotiated client dialect for observability (logs, traces,
    // governance sinks that read response headers).
    if let Ok(value) = axum::http::HeaderValue::from_str(ingress_skin.as_str()) {
        response
            .headers_mut()
            .insert("x-agent-stream-ingress-skin", value);
    }
    response
}

/// Run a chat completion but return an SSE that emits live pipeline `stage`
/// events (Prompt Guard / Judge / Jury / …) as they occur, then a final
/// `result` event carrying the completion (or the block/error). The request is
/// forced buffered so every stage runs server-side. Stages are captured from the
/// request's own span, so a stream only ever sees its own request's stages.
#[allow(clippy::too_many_arguments)]
async fn handle_chat_completions_with_stages(
    State(state): State<PipeHandlerState>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    peer_cert: Option<axum::Extension<crate::source_auth::models::PeerCertInfo>>,
    body: axum::body::Bytes,
    ingress_skin: crate::pipes::ingress::IngressSchema,
) -> Response {
    use axum::response::sse::{Event, Sse};
    use futures::StreamExt;
    use tracing::Instrument;

    // Preserve the client's `stream` flag: a surface with no response-side stage
    // (e.g. Judge-only, or a plain LLM) still streams its tokens, and only the
    // live pre-LLM stage events are teed in. `stream_options` is dropped — it is
    // only valid with an upstream stream, and the buffered fallback (Jury /
    // Decider / response guards) would otherwise 400 at the provider.
    let body = match serde_json::from_slice::<Value>(&body) {
        Ok(mut v) => {
            if let Some(obj) = v.as_object_mut() {
                obj.remove("stream_options");
            }
            axum::body::Bytes::from(serde_json::to_vec(&v).unwrap_or_else(|_| body.to_vec()))
        }
        Err(_) => body,
    };

    let stream_key = uuid::Uuid::new_v4().to_string();
    let (stage_rx, stage_guard) = crate::observability::stage_stream::register(&stream_key);
    let span = tracing::info_span!("stage_stream", stream_key = %stream_key);

    let (out_tx, out_rx) = tokio::sync::mpsc::channel::<Result<Event, std::convert::Infallible>>(64);

    // Forward live stage events as they are captured.
    let fwd_tx = out_tx.clone();
    let fwd = tokio::spawn(async move {
        let mut stage_rx = stage_rx;
        while let Some(value) = stage_rx.recv().await {
            let event = Event::default()
                .event("stage")
                .data(value.to_string());
            if fwd_tx
                .send(Ok(event))
                .await
                .is_err()
            {
                break;
            }
        }
    });

    // Run the real request. A streaming surface returns an SSE body whose token
    // frames we forward verbatim (alongside the teed-in stage events); a
    // buffered surface returns one JSON body we emit as a final `result` event.
    // `stage_guard` is moved in here (not just `key`) so a panic inside this task
    // still unregisters the stream via its Drop impl.
    tokio::spawn(async move {
        let stage_guard = stage_guard;
        let response = run_in_request_context(State(state), headers, uri, peer_cert, body, ingress_skin)
            .instrument(span)
            .await;
        let status = response.status().as_u16();
        let is_sse = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .is_some_and(|s| s.contains("text/event-stream"));

        if is_sse {
            let mut data = response
                .into_body()
                .into_data_stream();
            let mut buf = String::new();
            'body: while let Some(chunk) = data.next().await {
                let Ok(bytes) = chunk else { break };
                buf.push_str(&String::from_utf8_lossy(&bytes));
                while let Some(idx) = buf.find("\n\n") {
                    let frame: String = buf.drain(..idx + 2).collect();
                    for line in frame.lines() {
                        if let Some(payload) = line.strip_prefix("data:") {
                            let payload = payload.trim();
                            if !payload.is_empty()
                                && out_tx
                                    .send(Ok(Event::default().data(payload)))
                                    .await
                                    .is_err()
                            {
                                break 'body;
                            }
                        }
                    }
                }
            }
            drop(stage_guard);
            let _ = fwd.await;
        } else {
            let read_result = axum::body::to_bytes(response.into_body(), 8 << 20).await;
            drop(stage_guard);
            let _ = fwd.await;
            let event = match read_result {
                Ok(bytes) => {
                    let body_val: Value = serde_json::from_slice(&bytes)
                        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&bytes).to_string()));
                    Event::default()
                        .event("result")
                        .data(serde_json::json!({ "status": status, "body": body_val }).to_string())
                }
                Err(e) => {
                    // The 8MiB buffered-response cap (or another body-read failure)
                    // means `status`/the response body above no longer reflect what
                    // the upstream actually sent \u2014 report the read failure instead
                    // of a false success with a silently empty body.
                    error!("[PIPE] Failed to read buffered stage-stream response body: {}", e);
                    Event::default()
                        .event("result")
                        .data(
                            serde_json::json!({
                                "status": 502,
                                "body": {
                                    "error": {
                                        "message": format!("Failed to read upstream response body: {e}"),
                                        "type": "response_read_error"
                                    }
                                }
                            })
                            .to_string(),
                        )
                }
            };
            let _ = out_tx.send(Ok(event)).await;
        }
    });

    // Mark the SSE unbuffered so a reverse proxy / tunnel flushes each stage and
    // token frame immediately instead of holding the whole response.
    let mut response = Sse::new(tokio_stream::wrappers::ReceiverStream::new(out_rx)).into_response();
    response
        .headers_mut()
        .insert("x-accel-buffering", axum::http::HeaderValue::from_static("no"));
    response
}

/// Run one chat request inside its request context, so every record it
/// produces carries the same trace id (continuing `X-Gateway-Trace-Id` when
/// Agent Gateway forwarded the request) and the same caller attribution.
async fn run_in_request_context(
    state: State<PipeHandlerState>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    peer_cert: Option<axum::Extension<crate::source_auth::models::PeerCertInfo>>,
    body: axum::body::Bytes,
    ingress_skin: crate::pipes::ingress::IngressSchema,
) -> Response {
    use crate::observability::request_context;
    let ctx = request_context::RequestContext::for_request(&headers);
    // The team gate sets the budget the request's platform-key calls are
    // checked against, once it has resolved the caller. The handler's future is
    // boxed: another layer around it inline overflows a debug build's stack.
    crate::teams::call_budget::scope(
        None,
        Box::pin(request_context::scope(
            ctx,
            handle_chat_completions_inner(state, headers, uri, peer_cert, body, ingress_skin),
        )),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn handle_chat_completions_inner(
    State(state): State<PipeHandlerState>,
    headers: axum::http::HeaderMap,
    uri: axum::http::Uri,
    peer_cert: Option<axum::Extension<crate::source_auth::models::PeerCertInfo>>,
    body: axum::body::Bytes,
    ingress_skin: crate::pipes::ingress::IngressSchema,
) -> Response {
    // Extract full request path
    let path = uri.path();

    // Optional distinct upstream credential. A caller (e.g. an IDE client
    // dispatching through an IDE Surface) may authenticate to the front door
    // with one token (`Authorization`) yet need a *different* token forwarded to
    // a member surface's upstream provider (e.g. a Graph-audience token for
    // Microsoft 365 Copilot). When present, a `forward_caller_token` surface
    // forwards this token upstream in preference to the front-door token; the
    // front-door JWT verification and OPA only ever read `Authorization`. It
    // is also where a caller whose front door reads `Authorization` sends its
    // own provider key (see `caller_credentials`).
    let upstream_auth_header = headers
        .get(UPSTREAM_AUTHORIZATION_HEADER)
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    debug!("Chat completion request to path: {}", path);

    // Look up pipe ID from route - try to find longest matching route.
    // A `$alias` suffix on the matched route selects an upstream variant
    // (`/route$alias/v1/chat/completions`); the alias is stripped from the
    // forwarded path suffix and used to resolve the pipe variant below.
    let Some(PipeRouteMatch {
        pipe_id,
        route: matched_route,
        tail: path_suffix,
        variant_alias,
    }) = match_pipe_route(&state, path).await
    else {
        error!("No pipe configured for path: {}", path);
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": {
                    "message": format!("No pipe configured for path: {}", path),
                    "type": "invalid_request_error"
                }
            })),
        )
            .into_response();
    };

    debug!(
        "Received chat completion request for pipe: {} (route: {}, suffix: {}, variant: {:?})",
        pipe_id, matched_route, path_suffix, variant_alias
    );

    // ── Multipart passthrough (file upload + speech-to-text) ──
    // `POST /v1/files` (file create) and the speech-to-text endpoints
    // (`/v1/audio/transcriptions`, `/v1/audio/translations`) carry a
    // `multipart/form-data` body, not JSON, so they bypass the JSON pipeline
    // entirely and are forwarded to the provider verbatim (with source auth,
    // the inbound policy gate and the team gate, like the GET-proxy). The audio
    // file rides the multipart body; the JSON transcript comes back on the
    // normal response path.
    let request_content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if (crate::pipes::streaming::is_upload_path(&path_suffix)
        || crate::pipes::streaming::is_audio_multipart_path(&path_suffix))
        && request_content_type.starts_with("multipart/form-data")
    {
        return Box::pin(proxy_file_upload(
            &state,
            &headers,
            peer_cert
                .as_ref()
                .map(|e| &e.0),
            pipe_id,
            path,
            path_suffix,
            request_content_type,
            body.to_vec(),
        ))
        .await;
    }

    // Parse the JSON request body for every non-upload path.
    let payload: Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": format!("Invalid JSON body: {}", e), "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
    };

    // Load the base pipe configuration (cached by pipe id). This carries the
    // variant-invariant metadata (name, integrations, source auth, metrics)
    // and is the source the upstream variant is resolved from.
    let _pipe: Arc<PipeConfig> = {
        let cached_pipe = {
            let cache = state.pipe_cache.read().await;
            cache.get(&pipe_id).cloned()
        };
        match cached_pipe {
            Some(pipe) => pipe,
            None => match state
                .pipe_store
                .get(&pipe_id)
                .await
            {
                Some(pipe) => {
                    // Appliance-wide surface defaults (governance recording / export,
                    // `pipe` event integrations) apply to the live copy only.
                    let pipe_arc = Arc::new(pipe.with_global_surface_defaults());
                    let mut cache = state.pipe_cache.write().await;
                    cache.insert(pipe_id.clone(), pipe_arc.clone());
                    pipe_arc
                }
                None => {
                    error!("Pipe not found: {}", pipe_id);
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({
                            "error": {
                                "message": format!("Pipe not found: {}", pipe_id),
                                "type": "invalid_request_error",
                                "code": "pipe_not_found"
                            }
                        })),
                    )
                        .into_response();
                }
            },
        }
    };

    // A disabled or soft-deleted surface must not serve live traffic, even if a
    // stale route still resolves to it (e.g. a runtime disable that left the
    // route registered). Treat it as unavailable rather than leaking its state.
    if !_pipe.status.is_enabled() {
        warn!(pipe_id = %pipe_id, status = %_pipe.status, "Rejecting request to non-enabled pipe");
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": {
                    "message": format!("Pipe not available: {}", pipe_id),
                    "type": "invalid_request_error",
                    "code": "pipe_not_available"
                }
            })),
        )
            .into_response();
    }

    // ── Ingress skin gate + normalization ──
    // Ingress skinning is an LLM-surface concept: only LLM and IDE (which
    // dispatches to an LLM member) surfaces speak the chat dialects.
    // Webhook surfaces proxy arbitrary bodies, so their requests must never be
    // transformed — collapse the skin to OpenAI Chat (identity) for them.
    let ingress_skin =
        if matches!(_pipe.pipe_type, crate::pipes::PipeType::LLM { .. } | crate::pipes::PipeType::IDECatalog { .. }) {
            ingress_skin
        } else {
            crate::pipes::ingress::IngressSchema::OpenAiChat
        };

    // The client's dialect was negotiated from the path. Reject it (as if the
    // route did not exist for that format) unless the surface accepts it, then
    // normalize the body to the OpenAI-canonical form the rest of the pipeline
    // expects. OpenAI Chat is the identity transform.
    if !crate::pipes::ingress::is_ingress_accepted(&_pipe.accepted_ingress_schemas, ingress_skin) {
        warn!(
            pipe_id = %pipe_id,
            skin = ingress_skin.as_str(),
            "Rejecting request in a client API format this surface does not accept"
        );
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": {
                    "message": format!("This surface does not accept the {} API format", ingress_skin.as_str()),
                    "type": "invalid_request_error",
                    "code": "ingress_format_not_accepted"
                }
            })),
        )
            .into_response();
    }
    let mut payload = normalize_ingress_request(ingress_skin, payload);
    // Governor: clamp the caller's requested reasoning budget to the surface
    // ceiling before the request enters the pipeline, so budget- and
    // effort-based upstreams are both bounded.
    if let Some(cap) = _pipe.max_reasoning_tokens {
        crate::pipes::reasoning::apply_cap(&mut payload, cap);
    }
    // A non-OpenAI ingress dialect has been normalized to an OpenAI Chat body,
    // so it must be dispatched to the canonical chat endpoint. Otherwise the
    // upstream receives the client's original path (`/v1/messages`,
    // `/v1/responses`) and 404s (no such OpenAI endpoint) or rejects the
    // normalized `messages` body (the Responses endpoint expects `input`).
    let path_suffix = if ingress_skin == crate::pipes::ingress::IngressSchema::OpenAiChat {
        path_suffix
    } else {
        "/v1/chat/completions".to_string()
    };

    // ── IDE Surface dispatch (front door) ──
    // An IDE Surface has no upstream of its own; it dispatches to one of its
    // member surfaces chosen by the request's `model` id. Authenticate and
    // authorize at the front door (the IDE surface's own source auth + OPA),
    // verify the requested model is an exposed member, then re-point the request
    // at that member surface so the rest of the pipeline — the member's own OPA,
    // team gate, model scope, resource controls, and execution — runs under the
    // same caller identity. The client authenticates once, at the front door;
    // member source auth is skipped for a dispatched request (see the guarded
    // source-auth block below).
    let front_door_dispatch = matches!(_pipe.pipe_type, crate::pipes::PipeType::IDECatalog { .. });
    // Capture the IDE Surface's own id + name before `pipe_id`/`_pipe` are
    // re-pointed to the dispatched member surface below. Once dispatch shadows
    // them, every telemetry/metrics/log site attributes to the member; this
    // lets the recording sites *also* mirror the execution onto the front door
    // so the IDE Surface's own Monitoring tab (logs, charts, cost) shows the
    // call even though execution ran on a member surface.
    let front_door_attribution: Option<(String, String)> = if front_door_dispatch {
        Some((pipe_id.clone(), _pipe.name.clone()))
    } else {
        None
    };
    // The IDE Surface's own source auth and tenant, which authenticate a
    // dispatched request: no credential it reads is ever sent upstream as the
    // caller's provider key.
    let front_door_auth = front_door_dispatch.then(|| (_pipe.source_auth.clone(), _pipe.tenant_id.clone()));
    let (pipe_id, variant_alias, _pipe, front_door_identity): (
        String,
        Option<String>,
        Arc<PipeConfig>,
        Option<crate::source_auth::AuthenticatedIdentity>,
    ) = if let crate::pipes::PipeType::IDECatalog { config } = &_pipe.pipe_type {
        // Front-door source authentication (the IDE surface's own credential).
        let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
        let source_auth = crate::source_auth::source_auth_gate(
            _pipe.source_auth.as_ref(),
            state
                .source_auth_middleware
                .as_deref(),
        );
        if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
            return source_auth_unavailable_response(&pipe_id);
        }
        if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
            match sa_middleware
                .authenticate(
                    auth_config,
                    &headers,
                    &_pipe.name,
                    _pipe.tenant_id.as_deref(),
                    peer_cert
                        .as_ref()
                        .map(|e| &e.0),
                )
                .await
            {
                Ok(identity) => caller_identity = Some(identity),
                Err(e) => {
                    warn!(pipe_id = %pipe_id, reason = %e, "IDE Surface source auth failed — returning 401");
                    return source_auth_failed_response();
                }
            }
        }

        // Front-door policy enforcement: the appliance-wide (global) policy set
        // for this surface type — enforced regardless of the surface's own
        // config — then the IDE surface's own OPA. Both deny-overrides and
        // fail-closed.
        if let Some(policy_mgr) = &state.pipe_policy_manager {
            let surface_type = crate::pipes::pipe_policy_type(&_pipe.pipe_type);
            let enforce_global = policy_mgr.has_global(surface_type);
            let enforce_surface = _pipe.opa_enabled();
            if enforce_global || enforce_surface {
                let mut policy_input = crate::surface_context::PolicyInput::new(
                    "POST",
                    path,
                    crate::surface_context::filter_sensitive_headers(&headers),
                    "inbound",
                    None,
                    None,
                    Some(pipe_id.clone()),
                    &_pipe.name,
                );
                policy_input.source_auth = caller_identity
                    .as_ref()
                    .map(crate::surface_context::SourceAuthContext::from);
                policy_input.request = Some(crate::surface_context::RequestContext {
                    purpose: crate::surface_context::RequestPurpose::Dispatch,
                    forwarded_upstream_auth: upstream_auth_header.is_some(),
                });
                policy_input.action = Some("dispatch".to_string());
                policy_input.resource = Some(crate::surface_context::ResourceContext {
                    surface_type: Some(surface_type.to_string()),
                    model: payload
                        .get("model")
                        .and_then(|m| m.as_str())
                        .map(str::to_string),
                    ..Default::default()
                });
                let input_value = serde_json::to_value(&policy_input).unwrap_or_default();

                // Appliance-wide global policy first — every surface of this type.
                if enforce_global {
                    let (decision, evidence) = policy_mgr.evaluate_global(surface_type, input_value.clone());
                    match decision {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(pipe_id = %pipe_id, surface_type, "Appliance-wide policy denied IDE dispatch — returning 403");
                            capture_pipe_policy_denial(
                                _pipe.as_ref(),
                                &payload,
                                caller_identity.as_ref(),
                                evidence,
                                "global_policy",
                                Some("Request denied by appliance-wide policy".to_string()),
                                false,
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": { "message": "Request denied by appliance-wide policy", "type": "permission_error", "code": "policy_denied" }
                                })),
                            )
                                .into_response();
                        }
                        Err(e) => {
                            error!(pipe_id = %pipe_id, surface_type, reason = %e, "Appliance-wide policy evaluation errored — denying (fail-closed)");
                            capture_pipe_policy_denial(
                                _pipe.as_ref(),
                                &payload,
                                caller_identity.as_ref(),
                                evidence,
                                "global_policy",
                                Some(e),
                                true,
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": { "message": "Request denied by appliance-wide policy", "type": "permission_error", "code": "policy_error" }
                                })),
                            )
                                .into_response();
                        }
                    }
                }

                // The IDE surface's own OPA.
                if enforce_surface {
                    let (decision, evidence) = policy_mgr.evaluate_with_evidence(&pipe_id, None, input_value);
                    match decision {
                        Ok(true) => {}
                        Ok(false) => {
                            warn!(pipe_id = %pipe_id, "IDE Surface OPA denied dispatch — returning 403");
                            capture_pipe_policy_denial(
                                _pipe.as_ref(),
                                &payload,
                                caller_identity.as_ref(),
                                evidence,
                                "ide_policy",
                                Some("Request denied by surface policy".to_string()),
                                false,
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": { "message": "Request denied by surface policy", "type": "permission_error", "code": "policy_denied" }
                                })),
                            )
                                .into_response();
                        }
                        Err(e) => {
                            warn!(pipe_id = %pipe_id, error = %e, "IDE Surface OPA evaluation error on dispatch — returning 403");
                            capture_pipe_policy_denial(
                                _pipe.as_ref(),
                                &payload,
                                caller_identity.as_ref(),
                                evidence,
                                "ide_policy",
                                Some(e),
                                true,
                            );
                            return (
                                StatusCode::FORBIDDEN,
                                Json(serde_json::json!({
                                    "error": { "message": "Surface policy could not be evaluated", "type": "permission_error", "code": "policy_evaluation_error" }
                                })),
                            )
                                .into_response();
                        }
                    }
                }
            }
        }

        // Front-door rate limit — the IDE Surface's own aggregate
        // requests-per-minute cap on the shared catalogue, independent of each
        // member surface's own limits (which still run after dispatch). Enforced
        // through an executor cached under the IDE surface id so the window
        // persists across requests; `invalidate_pipe_cache` drops it on surface
        // update. Built only when a limit is actually enabled.
        if _pipe
            .rate_limit
            .as_ref()
            .is_some_and(|r| r.enabled)
        {
            let ide_executor = {
                let cached = {
                    let exec_cache = state
                        .executor_cache
                        .read()
                        .await;
                    exec_cache
                        .get(&pipe_id)
                        .cloned()
                };
                if let Some(exec) = cached {
                    exec
                } else {
                    let built =
                        Arc::new(PipeExecutor::new_with_secrets(_pipe.as_ref(), Some(state.secrets_store.clone())));
                    let mut exec_cache = state
                        .executor_cache
                        .write()
                        .await;
                    exec_cache
                        .entry(pipe_id.clone())
                        .or_insert(built)
                        .clone()
                }
            };
            if let Err(crate::pipes::executor::PipeError::RateLimitExceeded(msg)) = ide_executor
                .enforce_rate_limit()
                .await
            {
                warn!(ide = %pipe_id, reason = %msg, "IDE Surface front-door rate limit exceeded — returning 429");
                return (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(serde_json::json!({
                        "error": { "message": format!("Rate limit exceeded: {}", msg), "type": "rate_limit_error", "code": "rate_limit_exceeded" }
                    })),
                )
                    .into_response();
            }
        }

        // Resolve the requested model id → an exposed catalog member.
        let requested_model = payload
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        if requested_model.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": "an IDE Surface request must name a model", "type": "invalid_request_error", "code": "model_required" }
                })),
            )
                .into_response();
        }
        let Some(member) = config
            .members
            .iter()
            .find(|m| m.expose && m.model_id() == requested_model)
        else {
            warn!(ide = %pipe_id, model = %requested_model, "IDE Surface model not in catalog — returning 404");
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "message": format!("model '{}' is not available in this catalog", requested_model), "type": "invalid_request_error", "code": "model_not_found" }
                })),
            )
                .into_response();
        };

        // Load the referenced member surface.
        let member_pipe = match state
            .pipe_store
            .get(&member.pipe_id)
            .await
        {
            Some(p) => Arc::new(p),
            None => {
                warn!(ide = %pipe_id, member = %member.pipe_id, "IDE Surface member surface missing — returning 404");
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": { "message": format!("model '{}' is not available", requested_model), "type": "invalid_request_error", "code": "model_not_found" }
                    })),
                )
                    .into_response();
            }
        };
        if !member_pipe
            .status
            .is_enabled()
        {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "message": format!("model '{}' is not available", requested_model), "type": "invalid_request_error", "code": "model_not_available" }
                })),
            )
                .into_response();
        }

        // Per-member Model Policy — an optional IDE-scoped OPA gate on this
        // specific model, evaluated after the front-door gates pass and the
        // member is resolved, under the caller's front-door identity. Lets a
        // catalogue expose a model to only a subset of callers without touching
        // the member LLM Surface's own policy. Fail-closed: a member that
        // declares a policy but has no compiled engine (e.g. the policy was
        // deleted) is denied.
        if member
            .opa_policy_definition_id()
            .is_some()
            && let Some(policy_mgr) = &state.pipe_policy_manager
        {
            let mut policy_input = crate::surface_context::PolicyInput::new(
                "POST",
                path,
                crate::surface_context::filter_sensitive_headers(&headers),
                "inbound",
                None,
                None,
                Some(pipe_id.clone()),
                &_pipe.name,
            );
            policy_input.source_auth = caller_identity
                .as_ref()
                .map(crate::surface_context::SourceAuthContext::from);
            policy_input.request = Some(crate::surface_context::RequestContext {
                purpose: crate::surface_context::RequestPurpose::Dispatch,
                forwarded_upstream_auth: upstream_auth_header.is_some(),
            });
            let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
            let model_id = member.model_id();
            let (decision, evidence) = policy_mgr.evaluate_ide_member_with_evidence(&pipe_id, &model_id, input_value);
            match decision {
                Ok(true) => {}
                Ok(false) => {
                    warn!(ide = %pipe_id, model = %model_id, "IDE Surface per-member policy denied dispatch — returning 403");
                    capture_pipe_policy_denial(
                        member_pipe.as_ref(),
                        &payload,
                        caller_identity.as_ref(),
                        evidence,
                        "ide_member_policy",
                        Some(format!("Access to model '{}' is denied by policy", requested_model)),
                        false,
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": { "message": format!("Access to model '{}' is denied by policy", requested_model), "type": "permission_error", "code": "model_policy_denied" }
                        })),
                    )
                        .into_response();
                }
                Err(e) => {
                    warn!(ide = %pipe_id, model = %model_id, error = %e, "IDE Surface per-member policy evaluation error — returning 403");
                    capture_pipe_policy_denial(
                        member_pipe.as_ref(),
                        &payload,
                        caller_identity.as_ref(),
                        evidence,
                        "ide_member_policy",
                        Some(e),
                        true,
                    );
                    return (
                        StatusCode::FORBIDDEN,
                        Json(serde_json::json!({
                            "error": { "message": "Model policy could not be evaluated", "type": "permission_error", "code": "model_policy_evaluation_error" }
                        })),
                    )
                        .into_response();
                }
            }
        }

        // Strip the catalog id from the body so the member executor injects the
        // member provider's real upstream model — variant-safe, since the
        // finally-resolved provider supplies the model when the body omits it.
        if let Some(obj) = payload.as_object_mut() {
            obj.remove("model");
        }

        debug!(
            ide = %pipe_id,
            member = %member.pipe_id,
            alias = ?member.variant_alias,
            "IDE Surface dispatched request to member surface"
        );
        // Emit a `[PIPE:{ide}]`-prefixed line so the IDE Surface's own Surface
        // Logs viewer (which filters on that literal prefix) shows that the
        // request arrived and was rebound to a member surface.
        info!(
            "[PIPE:{}] IDE Surface received request and dispatched it to member surface '{}' (model '{}')",
            pipe_id, member.pipe_id, requested_model
        );
        (member.pipe_id.clone(), member.variant_alias.clone(), member_pipe, caller_identity)
    } else {
        (pipe_id, variant_alias, _pipe, None)
    };

    // ── Attribute-based routing + canary split ──
    // Precedence: an explicit `$alias` from the route > a matching routing rule
    // (request header / body field) > a canary split. A routing rule may target
    // a variant alias (resolved like any variant) or an inline provider target
    // (swapped into the resolved config after variant resolution). The chosen
    // alias drives variant resolution, executor caching, policy/cache scope, and
    // telemetry attribution uniformly.
    let route_decision = resolve_route_decision(&_pipe, variant_alias, &headers, &payload);
    let inline_route_target = route_decision.inline_target;
    let variant_alias = route_decision.alias;

    // Resolve the selected variant up front into a fully-materialised config.
    // Variants are full snapshots, so source auth, inbound OPA, and the
    // executor all read from the *resolved* config — a variant may override
    // the upstream, guards, resource controls, source auth, and policy, not
    // just the upstream.
    let resolved_pipe: Arc<PipeConfig> = match _pipe.resolve_variant(variant_alias.as_deref()) {
        Ok(resolved) => {
            // Attribute the (successful) routing decision exactly once per request.
            crate::metrics::backends::prometheus::track_variant_routing(
                &route_decision.metric_variant,
                route_decision.decision,
            );
            // An inline routing target swaps only the upstream provider on the
            // resolved config (guards/policy/limits are kept), reusing the same
            // provider-swap path as failover.
            match &inline_route_target {
                Some(target) => Arc::new(resolved.clone_with_failover_target(target)),
                None => Arc::new(resolved),
            }
        }
        Err(e) => {
            let (status, code, decision) = variant_error_response(&e);
            // Rejections are attributed here instead of the success branch, so the
            // counter still sees exactly one increment per request.
            crate::metrics::backends::prometheus::track_variant_routing(&route_decision.metric_variant, decision);
            warn!(
                pipe_id = %pipe_id,
                alias = ?variant_alias,
                reason = %e,
                "Pipe variant resolution failed"
            );
            return (
                status,
                Json(serde_json::json!({
                    "error": {
                        "message": e.to_string(),
                        "type": "invalid_request_error",
                        "code": code
                    }
                })),
            )
                .into_response();
        }
    };

    // The caller's own key or token goes only to the surface's default
    // upstream. A routing rule's inline target, and a variant (a canary split,
    // a routing rule or a `$alias`) that swaps the provider or the origin, run
    // as another upstream on their own stored key, like a failover target.
    let primary_upstream =
        inline_route_target.is_none() && (variant_alias.is_none() || _pipe.keeps_default_upstream(&resolved_pipe));
    let target_identity = effective_target_identity(&resolved_pipe);
    let exec_cache_key = execution_cache_key(&pipe_id, variant_alias.as_deref(), &target_identity, primary_upstream);
    debug!(
        pipe_id = %pipe_id,
        alias = ?variant_alias,
        target_identity = %target_identity,
        "Resolved effective LLM target"
    );

    // Hold the write lock through lookup and insertion. Executors with the same
    // immutable target identity are equivalent, and different targets have
    // distinct keys, so concurrent first requests cannot replace one another.
    let executor = get_or_insert_cached(&state.executor_cache, exec_cache_key, || {
        if primary_upstream {
            PipeExecutor::new_with_secrets(&resolved_pipe, Some(state.secrets_store.clone()))
        } else {
            PipeExecutor::for_target(&resolved_pipe, Some(state.secrets_store.clone()))
        }
    })
    .await;

    // Extract pipe name for metrics (identity-level, invariant across variants)
    let pipe_name = _pipe.name.clone();

    // ── Source authentication / JWT Bearer token verification ────────────────
    // Every POST is authenticated, whatever its path: this handler never serves
    // a public discovery document (those are GET reads), so a chat body sent to
    // `{route}/agent.json` is gated like any other. On
    // success the caller identity is retained so the OPA gate below can expose
    // it as `input.source_auth.*` to pipe policies. A request dispatched through
    // an IDE Surface front door is already authenticated there, so its identity
    // is carried in and member source auth is skipped.
    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = front_door_identity;
    let source_auth = if front_door_dispatch {
        crate::source_auth::SourceAuthGate::Open
    } else {
        crate::source_auth::source_auth_gate(
            resolved_pipe
                .source_auth
                .as_ref(),
            state
                .source_auth_middleware
                .as_deref(),
        )
    };
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        return source_auth_unavailable_response(&pipe_id);
    }
    if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
        match sa_middleware
            .authenticate(
                auth_config,
                &headers,
                &resolved_pipe.name,
                resolved_pipe
                    .tenant_id
                    .as_deref(),
                peer_cert
                    .as_ref()
                    .map(|e| &e.0),
            )
            .await
        {
            Ok(identity) => caller_identity = Some(identity),
            Err(e) => {
                warn!(
                    pipe_id = %pipe_id,
                    reason = %e,
                    "Source authentication failed on pipe — returning 401"
                );
                return source_auth_failed_response();
            }
        }
    }

    let caller = match &front_door_auth {
        Some((auth, tenant)) => {
            caller_credentials(
                state
                    .source_auth_middleware
                    .as_deref(),
                &headers,
                auth.as_ref()
                    .map(|auth| (auth, tenant.as_deref())),
                true,
            )
            .await
        }
        None => {
            caller_credentials(
                state
                    .source_auth_middleware
                    .as_deref(),
                &headers,
                resolved_pipe
                    .source_auth
                    .as_ref()
                    .map(|auth| {
                        (
                            auth,
                            resolved_pipe
                                .tenant_id
                                .as_deref(),
                        )
                    }),
                false,
            )
            .await
        }
    };

    // Attribute every record this request produces from here on: the surface's
    // tenant, the authenticated caller, and the identifier the team gate will
    // match a member by (so a record written before the gate names the member).
    crate::observability::request_context::update(|ctx| {
        ctx.usage.tenant_id = resolved_pipe
            .tenant_id
            .clone();
        ctx.set_identity(caller_identity.as_ref());
        ctx.member_identifier = resolved_pipe
            .team_attribution
            .as_ref()
            .filter(|attr| attr.enabled)
            .and_then(|attr| {
                crate::teams::caller_identity::extract_first_caller_identity(
                    &attr.caller_identity_sources,
                    &headers,
                    caller_identity.as_ref(),
                    &payload,
                )
            });
    });

    // ── Inbound OPA policy enforcement ───────────────────────────────────────
    // Runs on every POST, like authentication (see `enforce_inbound_policy`).
    if let Some(policy_mgr) = &state.pipe_policy_manager
        && inbound_policy_applies(policy_mgr, &resolved_pipe)
    {
        let surface_type = crate::pipes::pipe_policy_type(&resolved_pipe.pipe_type);
        let reasoning_ctx = crate::pipes::reasoning::resolve(&payload).filter(|r| r.enabled);
        let routing_prefs = crate::pipes::request_routing::parse(&payload);
        let resource = crate::surface_context::ResourceContext {
            surface_type: Some(surface_type.to_string()),
            model: payload
                .get("model")
                .and_then(|m| m.as_str())
                .map(str::to_string),
            reasoning_effort: reasoning_ctx
                .as_ref()
                .map(|r| r.effort_or_default()),
            reasoning_max_tokens: reasoning_ctx
                .as_ref()
                .map(|r| r.budget(None)),
            requested_models: routing_prefs
                .as_ref()
                .filter(|p| !p.models.is_empty())
                .map(|p| p.models.clone()),
            requested_providers: routing_prefs
                .as_ref()
                .map(|p| {
                    if p.only.is_empty() {
                        p.order.clone()
                    } else {
                        p.only.clone()
                    }
                })
                .filter(|v| !v.is_empty()),
            server_tools: resolved_pipe
                .server_tools
                .as_ref()
                .filter(|st| st.is_active())
                .map(|st| st.active_tool_names()),
            requested_transforms: crate::pipes::context_transform::parse_transforms(&payload).filter(|t| !t.is_empty()),
            document_types: crate::pipes::document_ingestion::document_types_present(&payload),
            audio_formats: crate::pipes::audio::audio_formats_present(&payload),
            image_formats: crate::pipes::image_input::image_formats_present(&payload),
            ..Default::default()
        };
        if let Err(denied) = Box::pin(enforce_inbound_policy(
            policy_mgr,
            InboundPolicyRequest {
                resolved_pipe: &resolved_pipe,
                pipe_id: &pipe_id,
                variant_alias: variant_alias.as_deref(),
                method: "POST",
                path,
                headers: &headers,
                payload: &payload,
                caller_identity: caller_identity.as_ref(),
                resource,
                front_door_id: front_door_attribution
                    .as_ref()
                    .map(|(id, _)| id.as_str()),
            },
        ))
        .await
        {
            return denied;
        }
    }

    // ── Team quota gate ──────────────────────────────────────────────────────
    // When this surface opts into team attribution, resolve the caller's teams
    // and (when enforcing) reject the request if a team or per-member monthly
    // cap is already exhausted. The decision is surface-type agnostic: it only
    // needs the inbound request and the caller identity. The returned context
    // is used to record this execution's spend against those teams below.
    let team_ctx = match crate::teams::team_pre_check(
        resolved_pipe
            .team_attribution
            .as_ref(),
        &headers,
        caller_identity.as_ref(),
        &payload,
    )
    .await
    {
        crate::teams::TeamGateDecision::Block { status, code, reason } => {
            // Access denials (disabled member / no permitted team) surface as
            // 403; quota exhaustion as 429. The gate chooses the status.
            let error_type = team_gate_error_type(status);
            warn!(pipe_id = %pipe_id, %status, code, reason = %reason, "Team gate blocked request");
            let body = serde_json::json!({
                "error": {
                    "message": reason,
                    "type": error_type,
                    "code": code
                }
            });
            record_front_door_block(&state, &_pipe, &resolved_pipe, &payload, "team_gate", code, &body);
            return (status, Json(body)).into_response();
        }
        crate::teams::TeamGateDecision::Allow(ctx) => Some(ctx),
        crate::teams::TeamGateDecision::Skip => None,
    };
    if let Some(team) = &team_ctx {
        crate::observability::request_context::update(|ctx| {
            ctx.usage
                .set_team_context(team)
        });
        // From here every platform-key model call this request makes is
        // checked against the caller's budgets; owned-key calls always run.
        crate::teams::call_budget::set(team.call_budget.clone());
    }

    if !resolved_pipe
        .usage_limits
        .is_empty()
        && let Some(reason) = surface_usage_limit_block_reason(&pipe_id, &resolved_pipe).await
    {
        warn!(pipe_id = %pipe_id, reason = %reason, "Surface usage limit blocked request");
        let body = serde_json::json!({
            "error": {
                "message": reason,
                "type": "rate_limit_error",
                "code": "rate_limit_exceeded"
            }
        });
        record_front_door_block(&state, &_pipe, &resolved_pipe, &payload, "usage_limit", "rate_limit_exceeded", &body);
        return (StatusCode::TOO_MANY_REQUESTS, Json(body)).into_response();
    }

    // ── Auto-provision notification ──
    // When the team gate minted a new member for this caller on first sight,
    // dispatch a `member.auto_provisioned` event to this surface's integrations
    // (once per caller). Spawned so it never blocks the response path.
    if let Some(provisioned) = team_ctx
        .as_ref()
        .and_then(|ctx| ctx.provisioned.clone())
        && let Some(notification_store) = state
            .notification_store
            .clone()
    {
        let integrations = _pipe.integrations.clone();
        tokio::spawn(async move {
            let event = crate::integrations::MemberProvisionedEvent {
                member_id: provisioned.member_id,
                member_label: provisioned.member_label,
                identifier: provisioned.identifier,
                team_ids: provisioned.team_ids,
                team_names: provisioned.team_names,
            };
            crate::integrations::trigger_member_auto_provisioned(&notification_store, &integrations, &event).await;
        });
    }

    // ── Standalone model scoping ──
    // When the surface has no active team attribution (so the team gate above
    // Skipped) but authenticated the caller, still enforce the caller member's
    // model allow-list ("virtual key" scope) resolved from the source-auth
    // identity. With attribution active, `team_pre_check` already applied it.
    if team_ctx.is_none()
        && !crate::teams::model_scope_allows(
            caller_identity.as_ref(),
            payload
                .get("model")
                .and_then(|m| m.as_str()),
        )
        .await
    {
        let requested = payload
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("");
        warn!(pipe_id = %pipe_id, model = requested, "Model not permitted for caller — 403");
        return (
            StatusCode::FORBIDDEN,
            Json(serde_json::json!({
                "error": {
                    "message": format!("model '{}' is not permitted for this caller", requested),
                    "type": "permission_error",
                    "code": "model_not_allowed"
                }
            })),
        )
            .into_response();
    }

    // ── Prompt reference expansion ──
    // When the request body carries a `prompt` block, resolve the stored prompt
    // and render it into `messages` before the request enters the pipeline (and
    // before the cache key is computed, so identical prompt+variables share a
    // cache entry). The block is stripped so it is never forwarded upstream.
    match crate::prompts::take_prompt_reference(&mut payload) {
        Ok(Some(reference)) => {
            let Some(prompt_store) = crate::prompts::global_prompt_store() else {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(serde_json::json!({
                        "error": { "message": "prompt store not configured", "type": "internal_error" }
                    })),
                )
                    .into_response();
            };
            match prompt_store
                .get_active(&reference.id)
                .await
            {
                Some(prompt) => {
                    // Cross-tenant guard: a prompt owned by another tenant must be
                    // indistinguishable from one that does not exist. Return the exact same
                    // generic "unknown prompt" error as the `None` arm below (no existence
                    // oracle). Mirrors the management render path (`prompt_allowed`).
                    if !crate::tenancy::can_reference(_pipe.tenant_id.as_deref(), prompt.tenant_id.as_deref()) {
                        return (
                            StatusCode::BAD_REQUEST,
                            Json(serde_json::json!({
                                "error": { "message": format!("unknown prompt '{}'", reference.id), "type": "invalid_request_error" }
                            })),
                        )
                            .into_response();
                    }
                    match prompt.render(reference.version, &reference.variables) {
                        Ok(messages) => crate::prompts::inject_messages(&mut payload, messages),
                        Err(e) => {
                            return (
                                StatusCode::BAD_REQUEST,
                                Json(serde_json::json!({
                                    "error": { "message": e.to_string(), "type": "invalid_request_error" }
                                })),
                            )
                                .into_response();
                        }
                    }
                }
                None => {
                    return (
                        StatusCode::BAD_REQUEST,
                        Json(serde_json::json!({
                            "error": { "message": format!("unknown prompt '{}'", reference.id), "type": "invalid_request_error" }
                        })),
                    )
                        .into_response();
                }
            }
        }
        Ok(None) => {}
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "message": e, "type": "invalid_request_error" } })),
            )
                .into_response();
        }
    }

    // ── Document ingestion ──
    // Recognize inline document parts (`{ type: "file" }`), enforce the
    // per-surface allow-list + size cap, and extract parseable documents
    // (text/markdown/csv/json/docx) to prompt text — so any model can read them
    // and the extracted text flows through the guardrails, PII masking, and the
    // context-window guard below. Runs before those stages for exactly that
    // reason. Off unless the surface enables it; a disallowed/oversize/unparseable
    // document fails the request closed (400).
    let document_ingestion = match crate::pipes::document_ingestion::apply(
        resolved_pipe
            .document_ingestion
            .as_ref(),
        &mut payload,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({ "error": { "message": e, "type": "invalid_request_error" } })),
            )
                .into_response();
        }
    };

    // ── Realtime-only model guard ──
    // A realtime voice model (OpenAI `*realtime*`, Gemini `*native-audio*` /
    // `*live*`) only answers the realtime WebSocket endpoint (`GET
    // /v1/realtime`); it has no buffered/streaming chat (generateContent) form.
    // Reject a chat request to such a model at the front door with an actionable
    // message instead of forwarding it and surfacing the provider's opaque 404
    // ("is not found ... or is not supported for generateContent").
    if let Some(message) = realtime_only_chat_rejection(&resolved_pipe.pipe_type) {
        warn!(pipe_id = %pipe_id, "Rejected chat request to realtime-only model");
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": {
                    "message": message,
                    "type": "invalid_request_error",
                    "code": "realtime_only_model"
                }
            })),
        )
            .into_response();
    }

    // ── Audio-modality gate ──
    // Strict opt-in: a surface must explicitly accept audio (`audio_input`
    // enabled) and the target model must be audio-capable; formats + size are
    // then checked against the surface policy. Otherwise inline `input_audio`
    // fails closed before it reaches the upstream. Covers both the streaming and
    // buffered paths (runs before the split).
    let audio_supported = match &resolved_pipe.pipe_type {
        crate::pipes::PipeType::LLM { provider, .. } => {
            crate::pipes::executor::resolve_request_profile(provider).supports_audio_input
        }
        _ => true,
    };
    let audio_gate = match crate::pipes::audio::apply(
        &payload,
        resolved_pipe
            .audio_input
            .as_ref(),
        audio_supported,
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(pipe_id = %pipe_id, reason = %e, "Audio-modality gate rejected request");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": e, "type": "invalid_request_error", "code": "audio_not_supported" }
                })),
            )
                .into_response();
        }
    };

    // ── Image-modality gate ──
    // Strict opt-in mirror of the audio gate: a surface must explicitly accept
    // image input (`image_input` enabled); inline `data:` images are then format-
    // and size-checked, and remote image URLs are forwarded. Otherwise inline
    // `image_url` parts fail closed before the upstream call. Images a tool
    // returned are dropped instead on such a surface, so an agent session
    // carrying a tool screenshot is still served.
    let dropped_tool_images = crate::pipes::image_input::drop_tool_images(
        &mut payload,
        resolved_pipe
            .image_input
            .as_ref(),
    );
    if dropped_tool_images > 0 {
        debug!(pipe_id = %pipe_id, dropped_tool_images, "Tool-result images dropped: the surface does not accept image input");
    }
    let image_gate = match crate::pipes::image_input::apply(
        &payload,
        resolved_pipe
            .image_input
            .as_ref(),
    ) {
        Ok(outcome) => outcome,
        Err(e) => {
            warn!(pipe_id = %pipe_id, reason = %e, "Image-modality gate rejected request");
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": { "message": e, "type": "invalid_request_error", "code": "image_not_supported" }
                })),
            )
                .into_response();
        }
    };

    // ── Context-window guard (middle-out compression) ──
    // Before the upstream call, compress an over-window prompt by dropping the
    // middle of the conversation (preserving system + recent turns). Applies to
    // both the streaming and buffered paths (the trimmed body flows into
    // whichever runs). Off unless the surface enables it or the request opts in
    // via `transforms`; the extension field is stripped either way.
    let context_transform = crate::pipes::context_transform::apply(
        resolved_pipe
            .context_management
            .as_ref(),
        &mut payload,
    );

    // ── SSE streaming passthrough ──
    // When the client requests `"stream": true` and the surface has no
    // response-side processing (Jury/Decider/Judge/response guards) and an
    // OpenAI-schema base provider, proxy the upstream token stream straight
    // back instead of buffering. Request-side gates already ran above and the
    // executor enforces the rest (rate limit, circuit breaker, request guards).
    let cache_provenance = match &resolved_pipe.pipe_type {
        crate::pipes::PipeType::LLM { provider, .. } => {
            use crate::pipes::types::llm_provider_ext::LLMProviderExt;
            crate::pipes::response_cache::CacheProvenance {
                target_identity: target_identity.clone(),
                provider: provider
                    .provider_type_str()
                    .to_string(),
                model: provider
                    .model_name()
                    .to_string(),
            }
        }
        _ => crate::pipes::response_cache::CacheProvenance {
            target_identity: target_identity.clone(),
            ..Default::default()
        },
    };

    // ── Response cache lookup ──
    // When the surface enables caching, an identical (exact mode) or
    // semantically-similar (semantic mode) request served within the TTL
    // returns the cached upstream response without calling the provider.
    //
    // Deliberately ahead of the SSE passthrough below. This used to sit after
    // it and skip streaming requests entirely, which meant the cache never ran
    // for the most common shape of call: a plain chat surface with no
    // response-side processing takes the passthrough and returns before ever
    // reaching here. The feature looked enabled and did nothing.
    //
    // A hit is safe to serve either way because the key ignores `stream` and
    // `stream_options` (see `strip_volatile`) — the response does not depend on
    // how it was framed, so an entry stored by a buffered call answers a
    // streaming one, and vice versa. The framing is restored on the way out by
    // `replay_completion_as_sse`.
    //
    // The scope/key (and, in semantic mode, the request embedding) are computed
    // before `payload` is moved into the executor and reused to store the
    // response on a miss below.
    let cache_lookup = if let Some(cache_cfg) = resolved_pipe
        .cache
        .as_ref()
        .filter(|c| c.enabled)
        && let Some(scope) =
            response_cache_scope(&resolved_pipe, &caller, &pipe_id, variant_alias.as_deref(), &target_identity)
    {
        use crate::pipes::config::CacheMode;
        let key = crate::pipes::response_cache::ResponseCache::build_key(&scope, &payload);
        // Semantic mode: embed the request text up front so both the lookup and
        // (on a miss) the store can reuse the vector. A failed embed degrades to
        // an exact-only entry rather than failing the request.
        let embedding = if cache_cfg.mode == CacheMode::Semantic
            && let Some(embedder) = cache_cfg.embedder.as_ref()
        {
            let text = crate::pipes::response_cache::extract_cache_text(&payload);
            let secrets = crate::secrets::SurfaceSecrets::new(
                Some(state.secrets_store.clone()),
                resolved_pipe
                    .tenant_id
                    .clone(),
            );
            match crate::pipes::cache_embedder::embed_text(embedder, &text, &secrets).await {
                Ok(vector) => Some(vector),
                // The embedder's platform key is past the budget: skip the
                // semantic lookup (no safety role) and serve as on a miss.
                Err(crate::pipes::cache_embedder::EmbedError::BudgetRefused(_)) => {
                    crate::teams::call_budget::record_skip(
                        crate::teams::call_budget::BudgetSkip::CacheEmbedding,
                        &pipe_id,
                    );
                    None
                }
                Err(err) => {
                    warn!("[PIPE:{}] semantic cache embed failed, degrading to miss: {}", pipe_id, err);
                    None
                }
            }
        } else {
            None
        };
        Some((scope, key, embedding, cache_cfg.mode == CacheMode::Semantic, cache_cfg.similarity_threshold))
    } else {
        None
    };

    if let Some((scope, key, embedding, semantic, threshold)) = &cache_lookup
        && let Some(cache) = crate::pipes::response_cache::global_response_cache()
    {
        let hit = if *semantic {
            embedding
                .as_ref()
                .and_then(|vector| cache.get_semantic(scope, vector, *threshold))
        } else {
            cache.get(key)
        };
        if let Some(hit) = hit {
            info!(
                "[PIPE:{}] response cache hit — served from cache, saved ${:.6} ({} in / {} out tokens, no upstream call)",
                pipe_id, hit.saved_cost, hit.saved_input_tokens, hit.saved_output_tokens
            );
            // A cache hit still counts as a request against team quotas, but at
            // zero spend since no provider call was made.
            if let Some(ctx) = &team_ctx {
                crate::teams::record_team_usage(ctx, 0.0, 0).await;
            }

            // A cache hit is still real traffic: record it through the same
            // Monitoring sinks a normal execution uses — surface activity
            // (Tasks), a per-execution record (request logs), and the metrics
            // graphs — at $0 provider spend, tagged as a cache hit carrying the
            // avoided cost so the dashboard can show hits + cumulative savings.
            let hit_provider = hit
                .provenance
                .provider
                .clone();
            let hit_model = hit.provenance.model.clone();
            let hit_trace = uuid::Uuid::new_v4().to_string();
            let cache_req_bytes = serde_json::to_vec(&payload)
                .map(|v| v.len() as u64)
                .unwrap_or(0);
            let cache_resp_bytes = serde_json::to_vec(&hit.response)
                .map(|v| v.len() as u64)
                .unwrap_or(0);

            record_surface_llm_usage(&pipe_id, 0.0, 0).await;
            state
                .task_monitor
                .record_pipe_activity(&format!("pipe-{}", pipe_id), cache_req_bytes, cache_resp_bytes, true)
                .await;

            if _pipe.enable_metrics {
                if let Some(store) = &state.metrics_store {
                    let record = crate::pipes::executor::ExecutionMetrics {
                        provider: hit_provider.clone(),
                        model: hit_model.clone(),
                        trace_id: hit_trace.clone(),
                        request_bytes: cache_req_bytes,
                        response_bytes: cache_resp_bytes,
                        cache_hit: true,
                        cache_saved_cost: hit.saved_cost,
                        ..Default::default()
                    };
                    let _ = store
                        .record_execution(&pipe_id, &record)
                        .await;
                }
                state
                    .global_metrics_store
                    .record_pipe_cache_hit(
                        pipe_id.clone(),
                        Some(pipe_name.clone()),
                        hit_provider.clone(),
                        hit_model.clone(),
                        0,
                        cache_req_bytes,
                        cache_resp_bytes,
                        hit.saved_cost,
                        hit.saved_input_tokens + hit.saved_output_tokens,
                        Some(hit_trace.clone()),
                    )
                    .await;
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let zero = crate::pipes::config::StageUsage::default();
                crate::telemetry::record_pipe_execution(
                    &pipe_id,
                    &zero,
                    &zero,
                    &zero,
                    &zero,
                    None,
                    member_id.as_deref(),
                    &team_ids,
                )
                .await;
            }

            let hit_headers = build_response_headers(
                &hit_trace,
                &hit_provider,
                &hit_model,
                hit.saved_input_tokens,
                hit.saved_output_tokens,
                hit.saved_input_tokens + hit.saved_output_tokens,
                0,
                0,
                0,
                None,
                0.0,
                ResponseBilling::default(),
                "hit",
                None,
                None,
                None,
                None,
            );
            let mut hit_headers = hit_headers;
            insert_header(&mut hit_headers, "x-agent-stream-cache-saved-usd", format!("{:.6}", hit.saved_cost));

            // Answer in the shape the caller asked for. They requested SSE, so
            // they get SSE — the same frames a live stream would have produced,
            // just without the wait. Returning the raw object here instead would
            // be a protocol change the client never opted into.
            if crate::pipes::streaming::client_requested_stream(&payload) {
                let include_usage = payload
                    .get("stream_options")
                    .and_then(|o| o.get("include_usage"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false);
                let body = crate::pipes::streaming::replay_completion_as_sse(&hit.response, include_usage);
                let body = crate::pipes::streaming_skin::reencode_sse_body(
                    body,
                    crate::pipes::streaming_skin::EgressSkin::new(ingress_skin, hit_model.clone()),
                );
                let mut response = axum::response::Response::new(body);
                *response.status_mut() = StatusCode::OK;
                *response.headers_mut() = hit_headers;
                response.headers_mut().insert(
                    axum::http::header::CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("text/event-stream"),
                );
                response
                    .headers_mut()
                    .insert(axum::http::header::CACHE_CONTROL, axum::http::HeaderValue::from_static("no-cache"));
                return response;
            }

            let body = skin_success_body(ingress_skin, hit.response, &hit_model);
            return (StatusCode::OK, hit_headers, Json(body)).into_response();
        }
        cache.record_miss();
    }

    if crate::pipes::streaming::client_requested_stream(&payload)
        && crate::pipes::streaming::passthrough_eligible(&resolved_pipe)
    {
        // A streamed turn is cached only when the answer can be stored whole.
        // The stream accumulator reassembles assistant *text*; it does not
        // reconstruct tool calls. Caching a tool-calling turn would therefore
        // file an answer with its tool calls stripped, and a later hit would
        // replay a turn that asked for nothing — indistinguishable from the
        // model simply not calling the tool. So a request that offers tools is
        // read from the cache but never written to it.
        let cache_write = if offers_tools(&payload) {
            None
        } else {
            cache_lookup
                .as_ref()
                .map(|(scope, key, embedding, _, _)| {
                    (scope.clone(), key.clone(), embedding.clone(), cache_provenance.clone())
                })
        };
        return stream_chat_completion(
            &state,
            &executor,
            &_pipe,
            &resolved_pipe,
            &pipe_id,
            &pipe_name,
            payload,
            path_suffix,
            caller,
            team_ctx,
            front_door_attribution.clone(),
            ingress_skin,
            cache_write,
        )
        .await;
    }
    if crate::pipes::streaming::client_requested_stream(&payload)
        && let Some(body) = payload.as_object_mut()
    {
        body.insert("stream".to_string(), serde_json::Value::Bool(false));
        body.remove("stream_options");
    }

    // ── Binary passthrough (text-to-speech, …) ──
    // Endpoints whose upstream response is opaque binary (not JSON) cannot ride
    // the buffered path (which parses JSON) or be cached; forward the request
    // through the request-side gates and return the raw bytes verbatim.
    if crate::pipes::streaming::is_binary_endpoint(Some(&path_suffix)) {
        match executor
            .execute_binary(payload, Some(path_suffix), caller)
            .await
        {
            Ok(bin) => {
                // A binary call (text-to-speech) is billed by its input text
                // at the upstream's price, by the source of its key, into the
                // member budget and (with metrics on) the usage series the
                // spend report reads.
                if _pipe.enable_metrics {
                    let (member_id, team_ids) = match &team_ctx {
                        Some(ctx) => (
                            Some(ctx.member_id.clone()),
                            ctx.teams
                                .iter()
                                .map(|t| t.id.clone())
                                .collect::<Vec<_>>(),
                        ),
                        None => (None, Vec::new()),
                    };
                    let pipe_id_tlm = pipe_id.clone();
                    let usage = crate::pipes::config::StageUsage::call(0, 0, bin.cost, 0, bin.key_source);
                    let key_source = bin.key_source;
                    tokio::spawn(async move {
                        let none = crate::pipes::config::StageUsage::default();
                        crate::telemetry::record_pipe_execution(
                            &pipe_id_tlm,
                            &usage,
                            &none,
                            &none,
                            &none,
                            Some(key_source),
                            member_id.as_deref(),
                            &team_ids,
                        )
                        .await;
                    });
                }
                if let Some(ctx) = &team_ctx {
                    crate::teams::record_team_usage(ctx, bin.billed_cost(), 0).await;
                }
                let mut response_headers = axum::http::HeaderMap::new();
                if let Ok(value) = axum::http::HeaderValue::from_str(&bin.content_type) {
                    response_headers.insert(axum::http::header::CONTENT_TYPE, value);
                }
                insert_header(&mut response_headers, "x-agent-stream-cost-usd", format!("{:.6}", bin.cost));
                insert_header(
                    &mut response_headers,
                    "x-agent-stream-billed-cost-usd",
                    format!("{:.6}", bin.billed_cost()),
                );
                insert_header(
                    &mut response_headers,
                    "x-agent-stream-key-source",
                    bin.key_source
                        .as_str()
                        .to_string(),
                );
                debug!("[PIPE:{}] binary passthrough ({} bytes, {})", pipe_id, bin.response_bytes, bin.content_type);
                return (StatusCode::OK, response_headers, bin.bytes).into_response();
            }
            Err(crate::pipes::executor::PipeError::BinaryEndpointUnsupported) => {
                // Refused before anything was sent: the request's path reaches
                // no speech endpoint on this provider.
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": {
                            "message": crate::pipes::executor::BINARY_ENDPOINT_UNSUPPORTED,
                            "type": "invalid_request_error",
                            "code": BINARY_ENDPOINT_UNSUPPORTED_CODE
                        }
                    })),
                )
                    .into_response();
            }
            Err(crate::pipes::executor::PipeError::SharedCredentialRefused(refusal)) => {
                return shared_credential_refused_response(&pipe_id, refusal);
            }
            Err(e) => {
                error!("[PIPE:{}] Binary passthrough failed: {:?}", pipe_id, e);
                if let Some(refused) = platform_refused(&e) {
                    record_front_door_block(
                        &state,
                        &_pipe,
                        &resolved_pipe,
                        &Value::Null,
                        refused.stage,
                        refused.code,
                        &refused.body,
                    );
                    return refused.response;
                }
                if _pipe.enable_metrics {
                    crate::pipes::metrics::spawn_pipe_failure_metric(
                        state
                            .global_metrics_store
                            .clone(),
                        &resolved_pipe,
                        pipe_id.clone(),
                        pipe_name.clone(),
                    );
                }
                let (status, code) = match &e {
                    crate::pipes::executor::PipeError::RateLimitExceeded(_) => {
                        (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
                    }
                    crate::pipes::executor::PipeError::CircuitBreakerOpen(_) => {
                        (StatusCode::SERVICE_UNAVAILABLE, "circuit_breaker_open")
                    }
                    crate::pipes::executor::PipeError::PromptGuardRejected { .. } => {
                        (StatusCode::FORBIDDEN, "content_rejected")
                    }
                    crate::pipes::executor::PipeError::CallerKeyRejected { status } => {
                        (caller_key_status(*status), CALLER_KEY_REJECTED)
                    }
                    _ => (StatusCode::BAD_GATEWAY, "provider_error"),
                };
                let message = format!("Provider request failed: {}", e);
                return (
                    status,
                    Json(serde_json::json!({
                        "error": {
                            "message": message,
                            "type": "provider_error",
                            "code": code,
                            "upstream_status": e.upstream_status()
                        }
                    })),
                )
                    .into_response();
            }
        }
    }

    // Execute the request with parameter overrides and path suffix
    // Pass client authorization header for API key policy enforcement
    let task_id = format!("pipe-{}", pipe_id);
    let record_failure = || {
        // Reflect the failed request in the surface's monitored task (activity,
        // last-activity, error count) so the Tasks view mirrors reality
        // regardless of the metrics toggle. Fire-and-forget to keep it off the
        // response path.
        {
            let task_monitor = state.task_monitor.clone();
            let task_id = task_id.clone();
            tokio::spawn(async move {
                task_monitor
                    .record_pipe_activity(&task_id, 0, 0, false)
                    .await;
            });
        }
        if _pipe.enable_metrics {
            crate::pipes::metrics::spawn_pipe_failure_metric(
                state
                    .global_metrics_store
                    .clone(),
                &resolved_pipe,
                pipe_id.clone(),
                pipe_name.clone(),
            );
            // Mirror the failure onto the IDE Surface front door that dispatched
            // this request (when applicable), so its own error-rate / traffic
            // graphs register the failed call even though execution ran on a
            // member surface (parity with the success-path mirror).
            if let Some((ide_id, ide_name)) = &front_door_attribution {
                crate::pipes::metrics::spawn_pipe_failure_metric_labeled(
                    state
                        .global_metrics_store
                        .clone(),
                    ide_id.clone(),
                    ide_name.clone(),
                    "ide_catalog".to_string(),
                    String::new(),
                );
            }
        }
    };
    // Capture the request body for I/O-capturing observability (Langfuse /
    // content webhook) only when the surface opted into `log_requests`. Done
    // before `payload` is moved into the executor.
    let logged_request_content = resolved_pipe
        .log_requests
        .then(|| serde_json::to_string(&payload).unwrap_or_default());

    // Signed governance recording: whether this surface records interactions, and
    // whether it captures full prompt/completion bodies. Clone the request now
    // (before `payload` is moved into the executor) so the record can carry the
    // caller's prompt and a request digest.
    let governance_active = crate::governance::is_ready()
        && resolved_pipe
            .governance_recording
            .as_ref()
            .map(|g| g.enabled)
            .unwrap_or(false);
    let governance_policy = resolved_pipe
        .governance_recording
        .as_ref()
        .map(|g| g.capture_policy())
        .unwrap_or_default();
    let governance_sink = resolved_pipe
        .governance_recording
        .as_ref()
        .and_then(|g| g.export.clone());
    let governance_request = governance_active.then(|| payload.clone());

    // Snapshot the drift-monitoring config now, before `resolved_pipe` and
    // `payload` are consumed by the executor. Production-sampling drift is
    // emitted from the success arm below (buffered path only — a
    // streaming-eligible surface has no Judge/Jury, so its drift signal is thin).
    let drift_config = resolved_pipe.drift.clone();

    // Snapshot the request messages for drift session capture before `payload`
    // is moved into the executor (only when the surface samples drift), so the
    // replay evaluation has the original input to re-run.
    let drift_prompt_messages = drift_config
        .as_ref()
        .filter(|c| c.enabled)
        .and_then(|_| {
            payload
                .get("messages")
                .cloned()
        });

    match executor
        .execute_with_path_and_auth(
            payload,
            Some(path_suffix),
            caller,
            None,
            crate::observability::request_context::trace_id(),
            None,
            None,
            None,
        )
        .await
    {
        Ok((response_value, metrics)) => {
            // Build the `x-agent-stream-*` observability response headers from
            // the execution metrics before `metrics` is moved into the recording
            // task below, so the client can read cost/usage/trace without parsing
            // the body.
            let response_headers = build_response_headers(
                &metrics.trace_id,
                &metrics.provider,
                &metrics.model,
                metrics.input_tokens,
                metrics.output_tokens,
                metrics.total_tokens,
                metrics.cached_tokens,
                metrics.cache_write_tokens,
                metrics.reasoning_tokens,
                metrics.schema_valid,
                metrics.cost,
                ResponseBilling {
                    billed_cost: metrics.billed_cost,
                    key_source: metrics.key_source,
                },
                "miss",
                context_transform
                    .as_ref()
                    .map(|t| t.header_value())
                    .as_deref(),
                document_ingestion
                    .as_ref()
                    .map(|d| d.header_value())
                    .as_deref(),
                audio_gate
                    .applied()
                    .then(|| audio_gate.header_value())
                    .as_deref(),
                image_gate
                    .applied()
                    .then(|| image_gate.header_value())
                    .as_deref(),
            );
            // Snapshot the resolved model before `metrics` is moved into the
            // background metrics task; the response skin needs it at return.
            let response_model = metrics.model.clone();

            // Fold this interaction's behavioural drift dimensions into the
            // drift store (no-op unless the surface enabled drift monitoring and
            // this request is in the sampled fraction). Off the hot path.
            crate::drift::record_interaction(
                drift_config.as_ref(),
                &pipe_id,
                crate::drift::DriftSignals {
                    output_tokens: metrics
                        .llm_usage
                        .output_tokens,
                    cost: metrics.cost,
                    latency_ms: metrics.latency_ms,
                    safety_flagged: !metrics
                        .redrive_rejections
                        .is_empty(),
                    schema_valid: metrics.schema_valid,
                    completion_text: response_value
                        .get("choices")
                        .and_then(|c| c.get(0))
                        .and_then(|c| c.get("message"))
                        .and_then(|m| m.get("content"))
                        .and_then(|c| c.as_str()),
                    prompt_messages: drift_prompt_messages.as_ref(),
                },
            );

            // Snapshot the governance signal from `metrics` now, before it is
            // moved into the background metrics tasks below; the signed record is
            // submitted just before the response returns.
            // Minted up front so `pipe.executed` can name the record; none when
            // the surface does not record completed interactions.
            let governance_record_id = (governance_active
                && governance_policy
                    .outcomes
                    .records(crate::governance::RecordOutcome::Ok))
            .then(crate::governance::new_record_id);
            let governance_payload = governance_active.then(|| {
                let record_metrics = metrics.record_metrics(&resolved_pipe);
                let caller_identity = metrics
                    .agent_identity
                    .clone()
                    .or_else(|| {
                        team_ctx
                            .as_ref()
                            .map(|c| c.member_id.clone())
                    });
                let trace_id = (!metrics.trace_id.is_empty()).then(|| metrics.trace_id.clone());
                let mut extra_stages = metrics.governance_stages();
                if let Some(ct) = &context_transform {
                    extra_stages.push(crate::governance::StageEntry::decision(
                        "context_transform".to_string(),
                        crate::governance::StageOutcome::Observed,
                        Some(ct.governance_detail()),
                    ));
                }
                if let Some(di) = &document_ingestion {
                    extra_stages.push(crate::governance::StageEntry::decision(
                        "document_ingestion".to_string(),
                        crate::governance::StageOutcome::Observed,
                        Some(di.governance_detail()),
                    ));
                }
                if audio_gate.applied() {
                    extra_stages.push(crate::governance::StageEntry::decision(
                        "audio_input".to_string(),
                        crate::governance::StageOutcome::Observed,
                        Some(audio_gate.governance_detail()),
                    ));
                }
                if image_gate.applied() {
                    extra_stages.push(crate::governance::StageEntry::decision(
                        "image_input".to_string(),
                        crate::governance::StageOutcome::Observed,
                        Some(image_gate.governance_detail()),
                    ));
                }
                (record_metrics, caller_identity, trace_id, extra_stages)
            });

            // Attribute this execution's spend and tokens to the caller's teams.
            // Uses the surface's grand totals (whole-surface cost), so any
            // surface type contributes uniformly. Only the billed cost counts:
            // calls served on the caller's or the customer's own key cost the
            // account's quota nothing.
            if let Some(ctx) = &team_ctx {
                crate::teams::record_team_usage(ctx, metrics.billed_cost, metrics.total_tokens).await;
            }
            record_surface_llm_usage(
                &pipe_id,
                metrics.llm_usage.cost,
                metrics
                    .llm_usage
                    .total_tokens(),
            )
            .await;
            // Monthly cost budget: raises `pipe.budget.*` alerts off the request path.
            crate::pipes::budget_tracker::record_surface_budget_cost(&_pipe, metrics.llm_usage.cost).await;

            // Reflect this successful execution in the surface's monitored task
            // so the Tasks view shows real activity, byte counts, and a live
            // "last activity" timestamp. Connection points already update the
            // monitor on every message; the pipe data plane must do the same or
            // the Tasks table shows "Never"/0 bytes while the metrics view (fed
            // by a separate store) shows the surface as active.
            state
                .task_monitor
                .record_pipe_activity(&task_id, metrics.request_bytes, metrics.response_bytes, true)
                .await;

            // Store the successful response in the surface's response cache so
            // an identical (or, in semantic mode, similar) future request is
            // served without a provider call.
            if let Some((scope, key, embedding, _semantic, _threshold)) = &cache_lookup
                && let Some(cache) = crate::pipes::response_cache::global_response_cache()
                && let Some(cfg) = resolved_pipe.cache.as_ref()
            {
                cache.put_with_provenance(
                    key.clone(),
                    scope.clone(),
                    response_value.clone(),
                    cfg.ttl_seconds,
                    cfg.max_entries,
                    metrics.input_tokens,
                    metrics.output_tokens,
                    metrics.cost,
                    embedding.clone(),
                    cache_provenance.clone(),
                );
            }

            // Record this execution into the multi-resolution usage time-series
            // (surface grand total, per-stage, and the attributed member/teams)
            // for the dashboard usage-over-time graphs. Gated by the same
            // `enable_metrics` switch as the rest of metrics; the separate
            // monthly TeamUsageTracker above still records for enforcement.
            if _pipe.enable_metrics {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let pipe_id_tlm = pipe_id.clone();
                let llm = metrics.llm_usage;
                let judge = metrics.judge_usage;
                let jury = metrics.jury_usage;
                let decider = metrics.decider_usage;
                let key_source = metrics.key_source;
                // Fire-and-forget: the time-series write takes a global lock and
                // does ~80 map ops, so keep it off the request's response path
                // (parity with the metrics store below).
                tokio::spawn(async move {
                    crate::telemetry::record_pipe_execution(
                        &pipe_id_tlm,
                        &llm,
                        &judge,
                        &jury,
                        &decider,
                        key_source,
                        member_id.as_deref(),
                        &team_ids,
                    )
                    .await;
                });
            }

            // Record any Judge/Jury rejections that a redrive recovered within
            // this (successful) execution into the rejection time-series under
            // the synthetic `redrive` category — the real content category is
            // reserved for executions that are finally blocked (the Err arm
            // below). Same `enable_metrics` gate; fire-and-forget.
            if _pipe.enable_metrics
                && !metrics
                    .redrive_rejections
                    .is_empty()
            {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let redrive_category = vec![crate::telemetry::REJECTION_REDRIVE_CATEGORY.to_string()];
                let redrives: Vec<&'static str> = metrics
                    .redrive_rejections
                    .iter()
                    .map(|m| m.stage.label())
                    .collect();
                let pipe_id_rd = pipe_id.clone();
                tokio::spawn(async move {
                    for stage_label in redrives {
                        crate::telemetry::record_rejection(
                            &pipe_id_rd,
                            stage_label,
                            &redrive_category,
                            member_id.as_deref(),
                            &team_ids,
                        )
                        .await;
                    }
                });
            }

            // Trigger pipe.executed integration
            info!("[PIPE:{}] Checking if should trigger pipe.executed integration", pipe_id);
            if let Some(notification_store) = &state.notification_store {
                info!("[PIPE:{}] notification_store is available", pipe_id);
                info!("[PIPE:{}] pipe integrations count = {}", pipe_id, _pipe.integrations.len());

                let execution = crate::integrations::pipe_integration_triggers::PipeExecution {
                    pipe_id: pipe_id.clone(),
                    pipe_name: _pipe.name.clone(),
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
                    usage_by_stage: metrics.usage_by_stage(&resolved_pipe),
                    streaming: false,
                    record_id: governance_record_id.clone(),
                    attribution: crate::observability::request_context::usage_attribution(),
                    request_content: logged_request_content.clone(),
                    response_content: resolved_pipe
                        .log_responses
                        .then(|| serde_json::to_string(&response_value).unwrap_or_default()),
                };

                info!("[PIPE:{}] Calling trigger_pipe_executed", pipe_id);
                crate::integrations::trigger_pipe_executed(notification_store, &_pipe.integrations, &execution).await;
                info!("[PIPE:{}] trigger_pipe_executed returned", pipe_id);
            } else {
                info!("[PIPE:{}] notification_store is None - integrations will not fire", pipe_id);
            }

            // Feed the surface's usage_alerts breach/anomaly detector. Read the
            // cost/token signal before the metrics value is moved into the
            // background recording task below.
            if resolved_pipe.usage_alerts_enabled
                && let Some(alerts) = resolved_pipe
                    .usage_alerts
                    .as_ref()
                && !alerts.is_empty()
            {
                crate::pipes::breach_alerts::spawn_breach_checks(
                    state
                        .notification_store
                        .clone(),
                    _pipe.integrations.clone(),
                    pipe_id.clone(),
                    pipe_name.clone(),
                    alerts.clone(),
                    crate::pipes::breach_alerts::ExecutionSignal {
                        cost: metrics.cost,
                        total_tokens: metrics.total_tokens,
                        success: true,
                        at: chrono::Utc::now().timestamp(),
                    },
                );
            }

            // Mirror this successful execution onto the IDE Surface front door
            // that dispatched it (when applicable), so the front door's own
            // Monitoring tab shows the call, its charts, and identical cost —
            // even though execution ran on the member surface. Fire-and-forget,
            // separate task with its own `metrics` clone so the member recording
            // below is untouched; same `enable_metrics` gate.
            if _pipe.enable_metrics
                && let Some(front_door) = front_door_attribution.clone()
            {
                let (member_id_fd, team_ids_fd) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let member_pipe_id_fd = pipe_id.clone();
                let metrics_fd = metrics.clone();
                let metrics_store_fd = state.metrics_store.clone();
                let global_metrics_fd = state
                    .global_metrics_store
                    .clone();
                tokio::spawn(async move {
                    mirror_front_door_execution(
                        front_door,
                        member_pipe_id_fd,
                        metrics_fd,
                        member_id_fd,
                        team_ids_fd,
                        metrics_store_fd,
                        global_metrics_fd,
                    )
                    .await;
                });
            }

            // Record metrics in background only if enabled (fire-and-forget, truly async)
            if _pipe.enable_metrics {
                let pipe_id_clone = pipe_id.clone();
                let pipe_name_clone = pipe_name.clone();
                let metrics_store_clone = state.metrics_store.clone();
                let global_metrics_clone = state
                    .global_metrics_store
                    .clone();

                tokio::spawn(async move {
                    if let Some(ref metrics_store) = metrics_store_clone {
                        let _ = metrics_store
                            .record_execution(&pipe_id_clone, &metrics)
                            .await;
                    }

                    // Calculate pipe latency breakdown
                    let pipe_gateway_processing_ms = metrics.time_to_first_token_ms;
                    let pipe_target_processing_ms = if let Some(gateway_ms) = metrics.time_to_first_token_ms {
                        if metrics.latency_ms > gateway_ms {
                            Some(metrics.latency_ms - gateway_ms)
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    global_metrics_clone
                        .record_pipe_execution(
                            pipe_id_clone,
                            Some(pipe_name_clone),
                            metrics.provider.clone(),
                            metrics.model.clone(),
                            crate::metrics::ConnectionStatus::Success,
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
                });
            }

            // Submit the signed governance record for this interaction (chained,
            // signed as a VC, encrypted at rest, off the response path). Only
            // when the surface opted in; carries the caller's prompt, the model
            // completion, and the interaction metrics.
            if let Some((record_metrics, caller_identity, trace_id, extra_stages)) = governance_payload {
                crate::governance::capture_with_id(
                    crate::governance::CaptureInput {
                        surface_id: pipe_id.clone(),
                        surface_name: Some(pipe_name.clone()),
                        trace_id,
                        caller_identity,
                        request: governance_request,
                        response: Some(response_value.clone()),
                        completion_text: None,
                        policy: governance_policy,
                        metrics: record_metrics,
                        outcome: crate::governance::InteractionOutcome::Completed,
                        extra_stages,
                        export: governance_sink.clone(),
                    },
                    governance_record_id
                        .clone()
                        .unwrap_or_else(crate::governance::new_record_id),
                );
            }

            let body = skin_success_body(ingress_skin, response_value, &response_model);
            (StatusCode::OK, response_headers, Json(body)).into_response()
        }
        Err(crate::pipes::executor::PipeError::PromptGuardRejected {
            status_code,
            body,
            content_type,
            rejection,
            usage,
        }) => {
            warn!("[PIPE:{}] Prompt guard rejected: {}", pipe_id, body);
            if let Some(usage) = usage.as_deref() {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                record_rejected_execution_usage(&state, &pipe_id, &_pipe, usage, member_id.as_deref(), &team_ids).await;
                if let Some(ctx) = &team_ctx {
                    crate::teams::record_team_usage(
                        ctx,
                        usage.total_billed_cost(),
                        usage.llm.total_tokens()
                            + usage.judge.total_tokens()
                            + usage.jury.total_tokens()
                            + usage.decider.total_tokens(),
                    )
                    .await;
                }
            }

            // A prompt-guard rejection is a failed request from the caller's
            // point of view (they get a 4xx and no response), so it must land in
            // the surface's traffic + error-rate charts alongside rate-limit and
            // circuit-breaker failures. Also mirrors onto the IDE Surface front
            // door via the closure's `spawn_pipe_failure_metric_labeled` call
            // (IDE dual-attribution).
            record_failure();

            // Signed governance record for the blocked interaction: the prompt
            // and the rejecting stage (with its evaluated content and verdict),
            // no completion.
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
            let block_categories = rejection_categories(rejection.as_deref());
            capture_governance_failure_with_metrics(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_name.clone(),
                governance_request,
                team_ctx
                    .as_ref()
                    .map(|c| c.member_id.clone()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: gov_block_stage.clone(),
                    reason: Some(body.clone()),
                    input: gov_block_input,
                    output: gov_block_output,
                    categories: block_categories.clone(),
                },
                rejected_record_metrics(usage.as_deref(), &resolved_pipe),
                governance_sink.clone(),
            );

            // Record the rejection into the usage time-series, classified into
            // canonical categories, so the dashboard can break rejections down by
            // category per surface / stage / member / team. Gated by the same
            // `enable_metrics` switch as the rest of telemetry; fire-and-forget to
            // keep the time-series write off the response path.
            if _pipe.enable_metrics
                && let Some(meta) = rejection
            {
                let categories = block_categories.clone();
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let pipe_id_rej = pipe_id.clone();
                let stage_label = meta.stage.label();
                // Mirror the rejection onto the IDE Surface front door that
                // dispatched this request (when applicable), so its own
                // Rejection breakdown/timeline registers the block even though
                // the guard ran on a member surface. Matches the success
                // mirror's dual-attribution.
                let front_door_rej = front_door_attribution
                    .as_ref()
                    .map(|(id, _)| id.clone());
                tokio::spawn(async move {
                    crate::telemetry::record_rejection(
                        &pipe_id_rej,
                        stage_label,
                        &categories,
                        member_id.as_deref(),
                        &team_ids,
                    )
                    .await;
                    if let Some(ide_id) = front_door_rej {
                        crate::telemetry::record_rejection(
                            &ide_id,
                            stage_label,
                            &categories,
                            member_id.as_deref(),
                            &team_ids,
                        )
                        .await;
                    }
                });
            }

            // Trigger error integration, off the request path.
            if let Some(notification_store) = state
                .notification_store
                .clone()
            {
                let integrations = _pipe.integrations.clone();
                let event = crate::integrations::PipeErrorEvent::new(&_pipe, body.clone())
                    .at_stage(gov_block_stage)
                    .with_categories(&block_categories);
                tokio::spawn(async move {
                    crate::integrations::trigger_pipe_error(&notification_store, &integrations, &event).await;
                });
            }

            let code = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);

            // Try to parse body as JSON; if it is, return it as-is with the correct content type
            if content_type.contains("application/json")
                && let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body)
            {
                return (code, Json(json_value)).into_response();
            }
            (code, body).into_response()
        }
        Err(crate::pipes::executor::PipeError::RateLimitExceeded(msg)) => {
            error!("[PIPE:{}] Rate limit exceeded: {}", pipe_id, msg);
            record_failure();
            capture_governance_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_name.clone(),
                governance_request,
                team_ctx
                    .as_ref()
                    .map(|c| c.member_id.clone()),
                crate::governance::InteractionOutcome::Blocked {
                    stage: "rate_limit".to_string(),
                    reason: Some(msg.clone()),
                    input: None,
                    output: None,
                    categories: Vec::new(),
                },
                governance_sink.clone(),
            );
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": {
                        "message": msg,
                        "type": "rate_limit_error",
                        "code": "rate_limit_exceeded"
                    }
                })),
            )
                .into_response()
        }
        Err(crate::pipes::executor::PipeError::CircuitBreakerOpen(msg)) => {
            error!("[PIPE:{}] Circuit breaker open: {}", pipe_id, msg);
            record_failure();
            capture_governance_failure(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_name.clone(),
                governance_request,
                team_ctx
                    .as_ref()
                    .map(|c| c.member_id.clone()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "circuit_breaker".to_string(),
                    reason: Some(msg.clone()),
                },
                governance_sink.clone(),
            );
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": {
                        "message": msg,
                        "type": "circuit_breaker_error",
                        "code": "circuit_breaker_open"
                    }
                })),
            )
                .into_response()
        }
        Err(e) => {
            // A Judge, the Decider router, Mirror candidates or earlier
            // attempts may have spent before this failure: bill that spend to
            // the caller's member and teams and the usage series, as the
            // stream does, before it is lost.
            let (e, incurred) = e.take_incurred();
            let failure_metrics = rejected_record_metrics((!incurred.is_empty()).then_some(&incurred), &resolved_pipe);
            if !incurred.is_empty() {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                record_rejected_execution_usage(&state, &pipe_id, &_pipe, &incurred, member_id.as_deref(), &team_ids)
                    .await;
                if let Some(ctx) = &team_ctx {
                    crate::teams::record_team_usage(ctx, incurred.total_billed_cost(), incurred.total_tokens()).await;
                }
            }
            // A platform-key call was refused before it was sent: a spent
            // budget (the team gate's 429, recorded as the gate's block was)
            // or unmetered spend (403, recorded at `metering`).
            if let Some(refused) = platform_refused(&e) {
                warn!("[PIPE:{}] Platform-key call refused ({}): {}", pipe_id, refused.code, e);
                capture_governance_failure_with_metrics(
                    governance_active,
                    governance_policy,
                    pipe_id.clone(),
                    pipe_name.clone(),
                    governance_request,
                    team_ctx
                        .as_ref()
                        .map(|c| c.member_id.clone()),
                    crate::governance::InteractionOutcome::Blocked {
                        stage: refused.stage.to_string(),
                        reason: Some(refused.body.to_string()),
                        input: None,
                        output: None,
                        categories: Vec::new(),
                    },
                    failure_metrics,
                    governance_sink.clone(),
                );
                trigger_block_event(&state, &_pipe, refused.stage, refused.code, &refused.body.to_string());
                return refused.response;
            }
            let error_details = format!("{:?}", e);
            error!("[PIPE:{}] Execution failed: {:?}", pipe_id, e);
            record_failure();
            capture_governance_failure_with_metrics(
                governance_active,
                governance_policy,
                pipe_id.clone(),
                pipe_name.clone(),
                governance_request,
                team_ctx
                    .as_ref()
                    .map(|c| c.member_id.clone()),
                crate::governance::InteractionOutcome::Failed {
                    stage: "execution".to_string(),
                    reason: Some(error_details.clone()),
                },
                failure_metrics,
                governance_sink.clone(),
            );

            // Feed a failure signal so the surface's error-rate alert can fire.
            if resolved_pipe.usage_alerts_enabled
                && let Some(alerts) = resolved_pipe
                    .usage_alerts
                    .as_ref()
                && !alerts.is_empty()
            {
                crate::pipes::breach_alerts::spawn_breach_checks(
                    state
                        .notification_store
                        .clone(),
                    _pipe.integrations.clone(),
                    pipe_id.clone(),
                    pipe_name.clone(),
                    alerts.clone(),
                    crate::pipes::breach_alerts::ExecutionSignal {
                        cost: 0.0,
                        total_tokens: 0,
                        success: false,
                        at: chrono::Utc::now().timestamp(),
                    },
                );
            }

            if let Some(refusal) = e.shared_credential_refusal() {
                return shared_credential_refused_response(&pipe_id, refusal);
            }
            let (status, error_type, code) = provider_failure_status(&e);
            (
                status,
                Json(serde_json::json!({
                    "error": {
                        "message": format!("Provider request failed: {}", e),
                        "details": error_details,
                        "type": error_type,
                        "code": code,
                        "upstream_status": e.upstream_status()
                    }
                })),
            )
                .into_response()
        }
    }
}

/// Governance metrics for a blocked or failed interaction that had already
/// spent tokens: the spend per stage, from the surface's configuration.
fn rejected_record_metrics(
    usage: Option<&crate::pipes::executor::RejectedExecutionUsage>,
    pipe: &PipeConfig,
) -> crate::governance::RecordMetrics {
    let Some(usage) = usage else {
        return crate::governance::RecordMetrics::default();
    };
    let (model, provider) = llm_model_of(&pipe.pipe_type).unwrap_or_default();
    usage.record_metrics(pipe, &provider, &model)
}

/// [`capture_governance_failure`] carrying the spend incurred before the block.
#[allow(clippy::too_many_arguments)]
fn capture_governance_failure_with_metrics(
    active: bool,
    policy: crate::governance::CapturePolicy,
    surface_id: String,
    surface_name: String,
    request: Option<serde_json::Value>,
    caller_identity: Option<String>,
    outcome: crate::governance::InteractionOutcome,
    metrics: crate::governance::RecordMetrics,
    export: Option<crate::governance::GovernanceExport>,
) {
    crate::governance::capture_failure_with_metrics(
        active,
        policy,
        surface_id,
        surface_name,
        request,
        caller_identity,
        outcome,
        metrics,
        export,
    );
}

/// Submit a signed governance record for a blocked or failed buffered
/// interaction (no completion). No-op when the surface hasn't opted in. Fire-and-
/// forget via the global store, so it never touches the caller's error path.
#[allow(clippy::too_many_arguments)]
fn capture_governance_failure(
    active: bool,
    policy: crate::governance::CapturePolicy,
    surface_id: String,
    surface_name: String,
    request: Option<serde_json::Value>,
    caller_identity: Option<String>,
    outcome: crate::governance::InteractionOutcome,
    export: Option<crate::governance::GovernanceExport>,
) {
    crate::governance::capture_failure(
        active,
        policy,
        surface_id,
        surface_name,
        request,
        caller_identity,
        outcome,
        export,
    );
}

/// Mirror a completed member-surface execution onto the IDE Surface front door
/// that dispatched the request.
///
/// An IDE Surface (`PipeType::IDECatalog`) has no upstream of its own — it
/// rebinds `pipe_id`/`_pipe` to a member LLM surface and every downstream
/// telemetry/metrics/log site attributes to that member. This re-records the
/// same execution under the front door's id + name so the IDE Surface's own
/// Monitoring tab lights up identically: usage time-series (cost + per-stage
/// tokens), operational time-series + dashboard `pipe_metrics` (traffic,
/// latency, throughput), the activity log, and a `[PIPE:{ide}]`-prefixed
/// completion line stating which member surface actually served the request.
/// Cost is the same `metrics.cost` the member records, so it matches exactly.
#[allow(clippy::too_many_arguments)]
async fn mirror_front_door_execution(
    front_door: (String, String),
    member_pipe_id: String,
    metrics: crate::pipes::executor::ExecutionMetrics,
    member_id: Option<String>,
    team_ids: Vec<String>,
    metrics_store: Option<Arc<MetricsStore>>,
    global_metrics: Arc<crate::metrics::MetricsStore>,
) {
    let (ide_id, ide_name) = front_door;

    // Activity-log record under the front door's id (borrows `metrics`, so do it
    // before the per-stage `.into()` moves below).
    if let Some(store) = &metrics_store {
        let _ = store
            .record_execution(&ide_id, &metrics)
            .await;
    }

    // Usage time-series: surface grand total + per-stage buckets, so the front
    // door's cost/token cards and spend charts match the member surface.
    crate::telemetry::record_pipe_execution(
        &ide_id,
        &metrics.llm_usage,
        &metrics.judge_usage,
        &metrics.jury_usage,
        &metrics.decider_usage,
        metrics.key_source,
        member_id.as_deref(),
        &team_ids,
    )
    .await;

    // Operational time-series (`ops:surface:{ide}`) + dashboard pipe_metrics
    // summary: traffic, error rate, throughput, tokens, latency.
    let pipe_gateway_processing_ms = metrics.time_to_first_token_ms;
    let pipe_target_processing_ms = metrics
        .time_to_first_token_ms
        .and_then(|gateway_ms| {
            metrics
                .latency_ms
                .checked_sub(gateway_ms)
        })
        .filter(|delta| *delta > 0);
    let cost = metrics.cost;
    let total_tokens = metrics.total_tokens;
    global_metrics
        .record_pipe_execution(
            ide_id.clone(),
            Some(ide_name),
            metrics.provider.clone(),
            metrics.model.clone(),
            crate::metrics::ConnectionStatus::Success,
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

    info!(
        "[PIPE:{}] Dispatched request completed on member surface '{}' — {} tokens, ${:.6}",
        ide_id, member_pipe_id, total_tokens, cost
    );
}

/// Stream an OpenAI-schema chat completion straight back to the caller.
///
/// Runs the request-side gates and lean base-provider preparation in
/// [`PipeExecutor::execute_streaming`], then proxies the upstream SSE byte
/// stream unbuffered while metering token usage from the terminal usage chunk
/// for cost attribution. Only reached when [`crate::pipes::streaming`] judges
/// the surface eligible (no response-side processing, OpenAI base provider).
#[allow(clippy::too_many_arguments)]
async fn stream_chat_completion(
    state: &PipeHandlerState,
    executor: &Arc<PipeExecutor>,
    pipe: &Arc<PipeConfig>,
    resolved_pipe: &Arc<PipeConfig>,
    pipe_id: &str,
    pipe_name: &str,
    payload: Value,
    path_suffix: String,
    caller: crate::pipes::key_source::CallerCredentials,
    team_ctx: Option<crate::teams::gate::TeamUsageContext>,
    front_door: Option<(String, String)>,
    ingress_skin: crate::pipes::ingress::IngressSchema,
    // Where to file this stream's reassembled answer, when the surface caches:
    // `(scope, key, embedding)`, computed before the request was handed over so
    // the entry lands under the key a later lookup will use. `None` when
    // caching is off, or when the turn must not be cached (see the tool-call
    // guard at the call site).
    cache_write: Option<(String, String, Option<Vec<f32>>, crate::pipes::response_cache::CacheProvenance)>,
) -> Response {
    let stream_task_id = format!("pipe-{}", pipe_id);
    let front_door_fail = front_door.clone();
    let record_failure = || {
        // Feed a failure signal so the surface's error-rate alert can fire.
        if resolved_pipe.usage_alerts_enabled
            && let Some(alerts) = resolved_pipe
                .usage_alerts
                .as_ref()
            && !alerts.is_empty()
        {
            crate::pipes::breach_alerts::spawn_breach_checks(
                state
                    .notification_store
                    .clone(),
                pipe.integrations.clone(),
                pipe_id.to_string(),
                pipe_name.to_string(),
                alerts.clone(),
                crate::pipes::breach_alerts::ExecutionSignal {
                    cost: 0.0,
                    total_tokens: 0,
                    success: false,
                    at: chrono::Utc::now().timestamp(),
                },
            );
        }
        // Reflect the failed streamed request in the surface's monitored task so
        // the Tasks view mirrors reality regardless of the metrics toggle.
        {
            let task_monitor = state.task_monitor.clone();
            let task_id = stream_task_id.clone();
            tokio::spawn(async move {
                task_monitor
                    .record_pipe_activity(&task_id, 0, 0, false)
                    .await;
            });
        }
        if pipe.enable_metrics {
            crate::pipes::metrics::spawn_pipe_failure_metric(
                state
                    .global_metrics_store
                    .clone(),
                resolved_pipe,
                pipe_id.to_string(),
                pipe_name.to_string(),
            );
            // Mirror the failure onto the IDE Surface front door that dispatched
            // this streamed request (when applicable), so its own error-rate /
            // traffic graphs register the failed call even though execution ran
            // on a member surface (parity with the success-path mirror).
            if let Some((ide_id, ide_name)) = &front_door_fail {
                crate::pipes::metrics::spawn_pipe_failure_metric_labeled(
                    state
                        .global_metrics_store
                        .clone(),
                    ide_id.clone(),
                    ide_name.clone(),
                    "ide_catalog".to_string(),
                    String::new(),
                );
            }
        }
    };

    let start = std::time::Instant::now();

    // Signed governance recording for streamed interactions. Capture the request
    // (prompt) before `payload` is moved into the executor; `include_streaming`
    // gates whether streamed calls are recorded and drives SSE completion
    // reassembly for full fidelity.
    let governance_stream_active = crate::governance::is_ready()
        && resolved_pipe
            .governance_recording
            .as_ref()
            .map(|g| g.enabled && g.include_streaming)
            .unwrap_or(false);
    // The SSE accumulator reassembles the assistant's answer as it passes. It
    // was switched on for governance recording only; a cacheable stream needs
    // the same text, for the same reason — there is no complete response object
    // on this path, so the answer has to be rebuilt from the frames or it
    // cannot be stored at all.
    let capture_completion = governance_stream_active || cache_write.is_some();
    // Everything the completion callback needs to file the answer, resolved here
    // where the config is still borrowable and moved into the closure.
    let stream_cache_write = cache_write;
    let stream_cache_cfg = resolved_pipe
        .cache
        .as_ref()
        .filter(|c| c.enabled)
        .map(|c| (c.ttl_seconds, c.max_entries));
    let stream_cache_provenance = stream_cache_write
        .as_ref()
        .map(|(_, _, _, provenance)| provenance.clone())
        .unwrap_or_default();
    let cache_model = stream_cache_provenance
        .model
        .clone();
    let governance_policy = resolved_pipe
        .governance_recording
        .as_ref()
        .map(|g| g.capture_policy())
        .unwrap_or_default();
    let governance_sink = resolved_pipe
        .governance_recording
        .as_ref()
        .and_then(|g| g.export.clone());
    let governance_request = governance_stream_active.then(|| payload.clone());
    let governance_caller = team_ctx
        .as_ref()
        .map(|c| c.member_id.clone());

    // Snapshot the request messages for drift session capture before `payload`
    // is moved into the streaming executor (only when the surface samples
    // drift). A session is captured only if the completion is also reassembled
    // (governance streaming), so this pairs with that path.
    let stream_drift_messages = resolved_pipe
        .drift
        .as_ref()
        .filter(|c| c.enabled)
        .and_then(|_| {
            payload
                .get("messages")
                .cloned()
        });

    let upstream = match executor
        .execute_streaming(payload, Some(path_suffix), caller, None)
        .await
    {
        Ok(upstream) => upstream,
        Err(crate::pipes::executor::PipeError::PromptGuardRejected {
            status_code,
            body,
            content_type,
            rejection,
            usage,
        }) => {
            warn!("[PIPE:{}] Prompt guard rejected (stream): {}", pipe_id, body);
            if let Some(usage) = usage.as_deref() {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                record_rejected_execution_usage(state, pipe_id, pipe, usage, member_id.as_deref(), &team_ids).await;
                // Attribute the consumed stage spend (Judge/Decider/LLM) to the
                // caller's member/team, mirroring the buffered rejection path —
                // a streaming-eligible Judge-only surface reaches this arm, so
                // without this the Judge's cost was never attributed.
                if let Some(ctx) = &team_ctx {
                    crate::teams::record_team_usage(
                        ctx,
                        usage.total_billed_cost(),
                        usage.llm.total_tokens()
                            + usage.judge.total_tokens()
                            + usage.jury.total_tokens()
                            + usage.decider.total_tokens(),
                    )
                    .await;
                }
            }

            // A prompt-guard rejection is a failed request from the caller's
            // point of view (they get a 4xx and no SSE stream), so it must land
            // in the surface's traffic + error-rate charts alongside rate-limit
            // and circuit-breaker failures. Also mirrors onto the IDE Surface
            // front door via the closure's `spawn_pipe_failure_metric_labeled`
            // call (IDE dual-attribution).
            record_failure();

            // Signed governance record for the blocked streamed interaction.
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
            let block_categories = rejection_categories(rejection.as_deref());
            capture_governance_failure_with_metrics(
                governance_stream_active,
                governance_policy,
                pipe_id.to_string(),
                pipe_name.to_string(),
                governance_request,
                governance_caller.clone(),
                crate::governance::InteractionOutcome::Blocked {
                    stage: gov_block_stage.clone(),
                    reason: Some(body.clone()),
                    input: gov_block_input,
                    output: gov_block_output,
                    categories: block_categories.clone(),
                },
                rejected_record_metrics(usage.as_deref(), resolved_pipe),
                governance_sink.clone(),
            );
            if let Some(notification_store) = state
                .notification_store
                .clone()
            {
                let integrations = pipe.integrations.clone();
                let event = crate::integrations::PipeErrorEvent::new(pipe, body.clone())
                    .at_stage(gov_block_stage)
                    .with_categories(&block_categories);
                tokio::spawn(async move {
                    crate::integrations::trigger_pipe_error(&notification_store, &integrations, &event).await;
                });
            }

            // Record the streaming-path rejection into the usage time-series,
            // classified into canonical categories (parity with the buffered path).
            if pipe.enable_metrics
                && let Some(meta) = rejection
            {
                let categories = block_categories;
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                let pipe_id_rej = pipe_id.to_string();
                let stage_label = meta.stage.label();
                // Mirror the rejection onto the IDE Surface front door that
                // dispatched this streamed request (when applicable), so its
                // own Rejection breakdown/timeline registers the block even
                // though the guard ran on a member surface. Matches the
                // success mirror's dual-attribution.
                let front_door_rej = front_door_fail
                    .as_ref()
                    .map(|(id, _)| id.clone());
                tokio::spawn(async move {
                    crate::telemetry::record_rejection(
                        &pipe_id_rej,
                        stage_label,
                        &categories,
                        member_id.as_deref(),
                        &team_ids,
                    )
                    .await;
                    if let Some(ide_id) = front_door_rej {
                        crate::telemetry::record_rejection(
                            &ide_id,
                            stage_label,
                            &categories,
                            member_id.as_deref(),
                            &team_ids,
                        )
                        .await;
                    }
                });
            }

            let code = StatusCode::from_u16(status_code).unwrap_or(StatusCode::FORBIDDEN);
            if content_type.contains("application/json")
                && let Ok(json_value) = serde_json::from_str::<serde_json::Value>(&body)
            {
                return (code, Json(json_value)).into_response();
            }
            return (code, body).into_response();
        }
        Err(crate::pipes::executor::PipeError::RateLimitExceeded(msg)) => {
            error!("[PIPE:{}] Rate limit exceeded (stream): {}", pipe_id, msg);
            record_failure();
            capture_governance_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.to_string(),
                pipe_name.to_string(),
                governance_request,
                governance_caller.clone(),
                crate::governance::InteractionOutcome::Blocked {
                    stage: "rate_limit".to_string(),
                    reason: Some(msg.clone()),
                    input: None,
                    output: None,
                    categories: Vec::new(),
                },
                governance_sink.clone(),
            );
            return (
                StatusCode::TOO_MANY_REQUESTS,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "rate_limit_error", "code": "rate_limit_exceeded" }
                })),
            )
                .into_response();
        }
        Err(crate::pipes::executor::PipeError::CircuitBreakerOpen(msg)) => {
            error!("[PIPE:{}] Circuit breaker open (stream): {}", pipe_id, msg);
            record_failure();
            capture_governance_failure(
                governance_stream_active,
                governance_policy,
                pipe_id.to_string(),
                pipe_name.to_string(),
                governance_request,
                governance_caller.clone(),
                crate::governance::InteractionOutcome::Failed {
                    stage: "circuit_breaker".to_string(),
                    reason: Some(msg.clone()),
                },
                governance_sink.clone(),
            );
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": { "message": msg, "type": "circuit_breaker_error", "code": "circuit_breaker_open" }
                })),
            )
                .into_response();
        }
        Err(e) => {
            // Judge/Decider may have already run (billable LLM calls) before this
            // later infrastructure failure — attribute that already-incurred
            // spend to the caller's member/team before it's otherwise lost,
            // mirroring the PromptGuardRejected arm's usage attribution.
            let (incurred_usage, e) = match e {
                crate::pipes::executor::PipeError::WithIncurredUsage { inner, usage } => (Some(usage), *inner),
                other => (None, other),
            };
            let failure_metrics = rejected_record_metrics(incurred_usage.as_deref(), resolved_pipe);
            if let Some(usage) = incurred_usage {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                record_rejected_execution_usage(state, pipe_id, pipe, &usage, member_id.as_deref(), &team_ids).await;
                if let Some(ctx) = &team_ctx {
                    crate::teams::record_team_usage(
                        ctx,
                        usage.total_billed_cost(),
                        usage.llm.total_tokens()
                            + usage.judge.total_tokens()
                            + usage.jury.total_tokens()
                            + usage.decider.total_tokens(),
                    )
                    .await;
                }
            }
            // A platform-key call was refused before it was sent (a spent
            // budget or unmetered spend, see `platform_refused`), with the
            // spend already incurred recorded above.
            if let Some(refused) = platform_refused(&e) {
                warn!("[PIPE:{}] Platform-key call refused ({}, stream): {}", pipe_id, refused.code, e);
                capture_governance_failure_with_metrics(
                    governance_stream_active,
                    governance_policy,
                    pipe_id.to_string(),
                    pipe_name.to_string(),
                    governance_request,
                    governance_caller.clone(),
                    crate::governance::InteractionOutcome::Blocked {
                        stage: refused.stage.to_string(),
                        reason: Some(refused.body.to_string()),
                        input: None,
                        output: None,
                        categories: Vec::new(),
                    },
                    failure_metrics,
                    governance_sink.clone(),
                );
                trigger_block_event(state, pipe, refused.stage, refused.code, &refused.body.to_string());
                return refused.response;
            }
            error!("[PIPE:{}] Streaming execution failed: {:?}", pipe_id, e);
            record_failure();
            capture_governance_failure_with_metrics(
                governance_stream_active,
                governance_policy,
                pipe_id.to_string(),
                pipe_name.to_string(),
                governance_request,
                governance_caller.clone(),
                crate::governance::InteractionOutcome::Failed {
                    stage: "execution".to_string(),
                    reason: Some(format!("{e:?}")),
                },
                failure_metrics,
                governance_sink.clone(),
            );
            if let Some(refusal) = e.shared_credential_refusal() {
                return shared_credential_refused_response(pipe_id, refusal);
            }
            let (status, error_type, code) = provider_failure_status(&e);
            return (
                status,
                Json(serde_json::json!({
                    "error": {
                        "message": format!("Provider request failed: {}", e),
                        "type": error_type,
                        "code": code,
                        "upstream_status": e.upstream_status()
                    }
                })),
            )
                .into_response();
        }
    };

    let enable_metrics = pipe.enable_metrics;
    let pipe_id_owned = pipe_id.to_string();
    let pipe_name_owned = pipe_name.to_string();
    // Drift monitoring config, captured as an owned value so the fire-and-forget
    // emit can run inside the 'static stream-completion block. The streamed
    // signal is thinner than the buffered one (no schema-validity, and a
    // completion only when governance streaming reassembled it), but latency and
    // response length still track drift.
    let stream_drift_config = resolved_pipe.drift.clone();
    let provider = upstream.provider.clone();
    let model = upstream.model.clone();
    let pricing = upstream.pricing;
    let own_price_honoured = upstream.own_price_honoured;
    let stream_key_source = upstream.key_source;
    // What the stream is billed at if it reports no final usage, and whether
    // it reads on after its client leaves (a key that bills), counted against
    // its member's and its surface's concurrent-drain caps.
    let stream_estimate = upstream.estimate;
    let stream_drain = (!stream_key_source.owned()).then(|| {
        crate::pipes::streaming::DrainOptions::new(
            team_ctx
                .as_ref()
                .map(|ctx| ctx.member_id.clone()),
            Some(pipe_id.to_string()),
        )
    });
    let request_bytes = upstream.request_bytes;
    let stream_schema = upstream.schema.clone();
    let stream_model_pii_stage = upstream
        .model_pii_stage
        .clone();
    // Header values known at request time (token/cost totals aren't known until
    // the stream ends, so streaming responses omit those).
    let stream_trace_id =
        crate::observability::request_context::trace_id().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let header_provider = upstream.provider.clone();
    let header_model = upstream.model.clone();
    let global_metrics = state
        .global_metrics_store
        .clone();
    let task_monitor = state.task_monitor.clone();
    let activity_task_id = stream_task_id.clone();

    // Live throughput/token heartbeats: while the stream is in flight, flush the
    // response bytes and tokens accrued since the last tick into the operational
    // time-series so the dashboard's Throughput / Token charts advance during a
    // long stream instead of jumping only at completion. Fans out to the surface
    // (and the IDE front door when dispatched) plus the appliance-wide aggregate.
    let progress_keys = crate::metrics::ops_telemetry::stream_ops_keys(
        pipe_id,
        front_door
            .as_ref()
            .map(|(id, _)| id.as_str()),
    );
    let progress_enabled = enable_metrics;

    // Request bytes are known up-front, so flush them on the first heartbeat (at
    // stream start) rather than only at completion — otherwise "bytes in" would
    // not appear on the dashboard until the stream ended. The completion record
    // then reports `flushed_request_bytes == request_bytes` so the ops remainder
    // is zero (no double count).
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

    // The request-side Judge runs pre-stream on this path; fold its spend into
    // the streamed metering below (parity with the buffered path).
    let judge_cost = upstream.judge_usage.cost;
    let judge_tokens = upstream
        .judge_usage
        .total_tokens();
    // A Route decider's router-LLM call is metered the same way.
    let decider_cost = upstream.decider_usage.cost;
    let decider_tokens = upstream
        .decider_usage
        .total_tokens();

    // Per-stage usage, config and alert wiring for the stream-completion block,
    // which runs on a 'static task: the Judge/Decider spend by stage, the
    // surface config (stage models, budget) and the usage-alert targets.
    let stream_judge_usage = upstream.judge_usage;
    let stream_decider_usage = upstream.decider_usage;
    let stream_config = resolved_pipe.clone();
    let budget_pipe = pipe.clone();
    let stream_notification_store = state
        .notification_store
        .clone();
    let stream_integrations = pipe.integrations.clone();
    let stream_usage_alerts = resolved_pipe
        .usage_alerts_enabled
        .then(|| {
            resolved_pipe
                .usage_alerts
                .clone()
        })
        .flatten()
        .filter(|a| !a.is_empty());
    let exec_trace_id = stream_trace_id.clone();

    let on_complete = move |outcome: crate::pipes::streaming::StreamOutcome| {
        // Attribute whatever was delivered — a fully completed stream, or the
        // partial output of one that aborted mid-flight (client disconnect or
        // upstream transport error). The provider bills the tokens it streamed
        // either way, so losing the metadata would under-report spend and hide
        // the failure from the dashboard.
        let status = if outcome.completed {
            crate::metrics::ConnectionStatus::Success
        } else {
            crate::metrics::ConnectionStatus::Failed
        };
        // Grand total folds in the request-side Judge + Route decider spend so a
        // Judge/decider surface bills them like the buffered path (their tokens
        // sit in the LLM bucket of the per-stage breakdown, which the buffered
        // path splits).
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
        let stream_llm_cost = crate::pipes::streaming::cost_for_tokens(
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
        let cost = stream_llm_cost + judge_cost + decider_cost;
        let total_tokens = input_tokens + output_tokens + judge_tokens + decider_tokens;
        let latency_ms = start.elapsed().as_millis() as u64;
        // The streamed call's own usage, billed by the source of its key; the
        // Judge and Decider bill by theirs.
        let stream_llm_usage = crate::pipes::config::StageUsage::call(
            input_tokens,
            output_tokens,
            stream_llm_cost,
            latency_ms,
            stream_key_source,
        );
        let billed_cost =
            stream_llm_usage.billed_cost + stream_judge_usage.billed_cost + stream_decider_usage.billed_cost;
        let response_bytes = outcome.response_bytes;
        let flushed_response_bytes = outcome.flushed_response_bytes;
        let flushed_input_tokens = outcome.flushed_input_tokens;
        let flushed_output_tokens = outcome.flushed_output_tokens;
        // Request bytes were flushed up-front on the first heartbeat.
        let flushed_request_bytes = request_bytes;
        if !outcome.completed {
            info!(
                "[PIPE:{}] Stream aborted after {}ms — {} bytes, {} tokens delivered before disconnect/error",
                pipe_id_owned, latency_ms, response_bytes, total_tokens
            );
        }

        // Signed governance record for the streamed interaction — full fidelity
        // via the reassembled completion. An aborted stream still records the
        // partial completion, flagged with an extra `stream` error stage.
        // Usage of each model-calling stage under its own provider and model; the
        // main call's share is the grand cost less the Judge and Decider spend.
        let llm_cost = stream_llm_cost;
        let usage_by_stage = crate::pipes::executor::stage_usage_entries(
            &stream_config,
            &provider,
            &model,
            &stream_llm_usage,
            &stream_judge_usage,
            &crate::pipes::config::StageUsage::default(),
            &stream_decider_usage,
        );
        let mut stream_key_sources = stream_llm_usage.key_sources;
        stream_key_sources.add(stream_judge_usage.key_sources);
        stream_key_sources.add(stream_decider_usage.key_sources);
        let stream_stage_usage = crate::metrics::PipeStageUsage {
            llm: stream_llm_usage.into(),
            judge: stream_judge_usage.into(),
            decider: stream_decider_usage.into(),
            key_source: Some(stream_key_source),
            ..Default::default()
        };
        // Minted up front so `pipe.executed` can name the governance record,
        // and dropped when no record is written under it.
        let mut governance_record_id = governance_stream_active.then(crate::governance::new_record_id);
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
            let recorded = crate::governance::capture_with_id(
                crate::governance::CaptureInput {
                    surface_id: pipe_id_owned.clone(),
                    surface_name: Some(pipe_name_owned.clone()),
                    trace_id: Some(exec_trace_id.clone()),
                    caller_identity: governance_caller,
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
                        usage_by_stage: usage_by_stage.clone(),
                        billed_cost: Some(billed_cost),
                        key_source: Some(stream_key_source),
                        key_sources: Some(stream_key_sources),
                        usage_estimated: usage_estimated.then_some(true),
                    },
                    outcome: crate::governance::InteractionOutcome::Completed,
                    extra_stages,
                    export: governance_sink,
                },
                governance_record_id
                    .clone()
                    .unwrap_or_else(crate::governance::new_record_id),
            );
            if !recorded {
                governance_record_id = None;
            }
        }

        // `pipe.executed` for the finished stream, off the request path: the
        // measured usage, whether the answer arrived whole, and the governance
        // record id (so a consumer of both can drop the duplicate).
        let stream_success = outcome.completed || outcome.answer_complete;
        if let Some(store) = stream_notification_store.clone() {
            let execution = crate::integrations::pipe_integration_triggers::PipeExecution {
                pipe_id: pipe_id_owned.clone(),
                pipe_name: pipe_name_owned.clone(),
                input_tokens,
                output_tokens,
                total_tokens,
                cost,
                latency_ms,
                provider: provider.clone(),
                model: model.clone(),
                trace_id: exec_trace_id.clone(),
                success: stream_success,
                error_message: (!stream_success).then(|| "stream aborted before completion".to_string()),
                currency: crate::integrations::pipe_integration_triggers::usd_currency(),
                usage_by_stage: usage_by_stage.clone(),
                streaming: true,
                record_id: governance_record_id.clone(),
                attribution: crate::observability::request_context::usage_attribution(),
                request_content: None,
                response_content: None,
            };
            let integrations = stream_integrations.clone();
            tokio::spawn(async move {
                crate::integrations::trigger_pipe_executed(&store, &integrations, &execution).await;
            });
        }

        // Usage alerts (cost / token thresholds, error rate, cost spike) on the
        // streamed execution, dispatched off the request path.
        if let Some(alerts) = stream_usage_alerts.clone() {
            crate::pipes::breach_alerts::spawn_breach_checks(
                stream_notification_store.clone(),
                stream_integrations.clone(),
                pipe_id_owned.clone(),
                pipe_name_owned.clone(),
                alerts,
                crate::pipes::breach_alerts::ExecutionSignal {
                    cost,
                    total_tokens,
                    success: stream_success,
                    at: chrono::Utc::now().timestamp(),
                },
            );
        }

        // Fold this streamed interaction's drift dimensions into the drift store
        // (no-op unless the surface enabled drift monitoring and the request is
        // sampled). Off the hot path. Streaming carries no Judge/Jury redrive and
        // no server-side schema validation, so `safety_flagged` is false and
        // `schema_valid` is None; the completion text is present only when
        // governance streaming reassembled it.
        // File the reassembled answer so the next identical request is a hit.
        //
        // Only on a clean finish: a stream aborted by a client disconnect or a
        // transport error has delivered a truncated answer, and caching that
        // would serve the truncation to everyone else for the whole TTL.
        // `answer_complete`, not `completed`: the question is whether the
        // upstream's answer arrived whole, not whether the client stayed to
        // hear the end of it. Boris's sandbox — and any well-written SSE client
        // — stops reading the moment it sees `[DONE]`, which marks the stream
        // aborted even though nothing was lost. Gating on delivery made storing
        // a race against that disconnect, so the same prompt cached about a
        // third of the time.
        if outcome.answer_complete
            && let Some((scope, key, embedding, _)) = &stream_cache_write
            && let Some(text) = outcome.completion.as_deref()
            && !text.is_empty()
            && let Some(cache) = crate::pipes::response_cache::global_response_cache()
            && let Some(cfg) = &stream_cache_cfg
        {
            // Rebuilt in the shape the buffered path stores, so one lookup can
            // serve either and `replay_completion_as_sse` can frame it back.
            let response_value = serde_json::json!({
                "object": "chat.completion",
                "model": cache_model,
                "choices": [{
                    "index": 0,
                    "message": { "role": "assistant", "content": text },
                    "finish_reason": "stop",
                }],
                "usage": {
                    "prompt_tokens": input_tokens,
                    "completion_tokens": output_tokens,
                    "total_tokens": input_tokens + output_tokens,
                },
            });
            cache.put_with_provenance(
                key.clone(),
                scope.clone(),
                response_value,
                cfg.0,
                cfg.1,
                input_tokens,
                output_tokens,
                cost,
                embedding.clone(),
                stream_cache_provenance.clone(),
            );
        }

        crate::drift::record_interaction(
            stream_drift_config.as_ref(),
            &pipe_id_owned,
            crate::drift::DriftSignals {
                output_tokens,
                cost,
                latency_ms,
                safety_flagged: false,
                schema_valid: None,
                completion_text: outcome.completion.as_deref(),
                prompt_messages: stream_drift_messages.as_ref(),
            },
        );

        tokio::spawn(async move {
            // Team quota attribution (enforcement counter), always recorded for
            // whatever the provider actually streamed.
            if let Some(ctx) = &team_ctx {
                crate::teams::record_team_usage(ctx, billed_cost, total_tokens).await;
            }
            record_surface_llm_usage(&pipe_id_owned, cost, total_tokens).await;
            // Monthly cost budget (main-LLM share only): raises `pipe.budget.*`.
            crate::pipes::budget_tracker::record_surface_budget_cost(&budget_pipe, llm_cost).await;
            // Reflect the stream in the surface's monitored task (success flag
            // mirrors whether it finished cleanly).
            task_monitor
                .record_pipe_activity(&activity_task_id, request_bytes, response_bytes, outcome.completed)
                .await;
            if enable_metrics {
                let (member_id, team_ids) = match &team_ctx {
                    Some(ctx) => (
                        Some(ctx.member_id.clone()),
                        ctx.teams
                            .iter()
                            .map(|t| t.id.clone())
                            .collect::<Vec<_>>(),
                    ),
                    None => (None, Vec::new()),
                };
                crate::telemetry::record_pipe_execution(
                    &pipe_id_owned,
                    &stream_llm_usage,
                    &stream_judge_usage,
                    &crate::pipes::config::StageUsage::default(),
                    &stream_decider_usage,
                    Some(stream_key_source),
                    member_id.as_deref(),
                    &team_ids,
                )
                .await;

                global_metrics
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
                        Some(stream_stage_usage.clone()),
                        flushed_request_bytes,
                        flushed_response_bytes,
                        flushed_input_tokens,
                        flushed_output_tokens,
                    )
                    .await;

                // Mirror onto the IDE Surface front door that dispatched this
                // streamed request (when applicable), so its own Monitoring tab
                // shows the call, charts, and identical cost. Streaming carries
                // no response-side stages, so only the LLM bucket is fed (parity
                // with the member recording above); like the member, the
                // streaming path writes no activity-log detail.
                if let Some((ide_id, ide_name)) = &front_door {
                    crate::telemetry::record_pipe_execution(
                        ide_id,
                        &stream_llm_usage,
                        &stream_judge_usage,
                        &crate::pipes::config::StageUsage::default(),
                        &stream_decider_usage,
                        Some(stream_key_source),
                        member_id.as_deref(),
                        &team_ids,
                    )
                    .await;

                    global_metrics
                        .record_pipe_stream_completion(
                            ide_id.clone(),
                            Some(ide_name.clone()),
                            provider.clone(),
                            model.clone(),
                            status,
                            latency_ms,
                            input_tokens,
                            output_tokens,
                            cost,
                            request_bytes,
                            response_bytes,
                            Some(stream_stage_usage.clone()),
                            flushed_request_bytes,
                            flushed_response_bytes,
                            flushed_input_tokens,
                            flushed_output_tokens,
                        )
                        .await;

                    info!(
                        "[PIPE:{}] Dispatched stream completed on member surface '{}' — {} tokens, ${:.6}",
                        ide_id, pipe_id_owned, total_tokens, cost
                    );
                }
            }
        });
    };

    // The stream completes after this handler has returned, so its records
    // re-enter the request's context to keep its trace id and attribution.
    let request_ctx = crate::observability::request_context::current().unwrap_or_default();
    let body = crate::pipes::streaming::spawn_metered_stream(
        upstream.response,
        stream_schema,
        capture_completion,
        upstream.rehydration_map,
        on_progress,
        move |outcome| crate::observability::request_context::sync_scope(request_ctx, || on_complete(outcome)),
        crate::pipes::streaming_skin::EgressSkin::new(ingress_skin, header_model.clone()),
        stream_drain,
    );
    Response::builder()
        .status(StatusCode::OK)
        .header(axum::http::header::CONTENT_TYPE, "text/event-stream")
        .header(axum::http::header::CACHE_CONTROL, "no-cache")
        .header(axum::http::header::CONNECTION, "keep-alive")
        .header("x-accel-buffering", "no")
        .header("x-agent-stream-trace-id", stream_trace_id)
        .header("x-agent-stream-provider", header_provider)
        .header("x-agent-stream-model", header_model)
        .header("x-agent-stream-key-source", stream_key_source.as_str())
        .header("x-agent-stream-cache", "miss")
        .body(body)
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Proxy a GET request (batch/file polling & retrieval) to the surface's
/// upstream provider and return the response verbatim. Runs the surface's
/// source authentication, inbound policy gate and team access gate, then the
/// executor's lean GET forward (circuit breaker, rate limit, provider auth,
/// SSRF, and the refusal to read through a credential the surface's tenant does
/// not own). No request body, so content guards, quota metering, and variant
/// selection do not apply.
async fn proxy_api_get(
    state: &PipeHandlerState,
    headers: &axum::http::HeaderMap,
    peer_cert: Option<&crate::source_auth::models::PeerCertInfo>,
    pipe_id: String,
    path: &str,
    path_suffix: String,
) -> Response {
    let pipe = match state
        .pipe_store
        .get(&pipe_id)
        .await
    {
        Some(pipe) => pipe,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "message": format!("No pipe configured: {}", pipe_id), "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
    };
    let resolved = match pipe.resolve_variant(None) {
        Ok(resolved) => Arc::new(resolved),
        Err(_) => Arc::new(pipe),
    };
    if !resolved.status.is_enabled() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "message": "pipe not available", "type": "invalid_request_error", "code": "pipe_not_available" }
            })),
        )
            .into_response();
    }

    // ── Source authentication ──
    // A GET poll is authenticated exactly like a chat request: if the surface
    // declares source auth, the caller must satisfy it (401 otherwise).
    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
    let source_auth = crate::source_auth::source_auth_gate(
        resolved.source_auth.as_ref(),
        state
            .source_auth_middleware
            .as_deref(),
    );
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        return source_auth_unavailable_response(&pipe_id);
    }
    if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
        match sa_middleware
            .authenticate(auth_config, headers, &resolved.name, resolved.tenant_id.as_deref(), peer_cert)
            .await
        {
            Ok(identity) => caller_identity = Some(identity),
            Err(e) => {
                warn!(pipe_id = %pipe_id, reason = %e, "Source authentication failed on GET poll — returning 401");
                return source_auth_failed_response();
            }
        }
    }

    if let Err(denied) =
        enforce_passthrough_policy(state, &resolved, &pipe_id, "GET", path, headers, caller_identity.as_ref()).await
    {
        return denied;
    }

    // ── Team access gate ──
    // Access control (member enabled, surface→team allow-list) applies to GET
    // polling too; there is no request body, so model checks are inert. A
    // spent budget refuses the poll only when it runs on a platform key.
    let call_budget = match crate::teams::team_pre_check(
        resolved
            .team_attribution
            .as_ref(),
        headers,
        caller_identity.as_ref(),
        &serde_json::Value::Null,
    )
    .await
    {
        crate::teams::TeamGateDecision::Block { status, code, reason } => {
            let error_type = team_gate_error_type(status);
            warn!(pipe_id = %pipe_id, %status, code, reason = %reason, "Team gate blocked GET poll");
            let body = serde_json::json!({
                "error": { "message": reason, "type": error_type, "code": code }
            });
            record_front_door_block(state, &resolved, &resolved, &Value::Null, "team_gate", code, &body);
            return (status, Json(body)).into_response();
        }
        crate::teams::TeamGateDecision::Allow(ctx) => ctx.call_budget,
        crate::teams::TeamGateDecision::Skip => None,
    };

    let caller = caller_credentials(
        state
            .source_auth_middleware
            .as_deref(),
        headers,
        resolved
            .source_auth
            .as_ref()
            .map(|auth| (auth, resolved.tenant_id.as_deref())),
        false,
    )
    .await;
    let executor = crate::pipes::executor::PipeExecutor::new_with_secrets(&resolved, Some(state.secrets_store.clone()));
    match crate::teams::call_budget::scope(call_budget, Box::pin(executor.execute_get(Some(path_suffix), caller))).await
    {
        Ok(bin) => {
            let mut response_headers = axum::http::HeaderMap::new();
            if let Ok(value) = axum::http::HeaderValue::from_str(&bin.content_type) {
                response_headers.insert(axum::http::header::CONTENT_TYPE, value);
            }
            (StatusCode::OK, response_headers, bin.bytes).into_response()
        }
        Err(crate::pipes::executor::PipeError::SharedCredentialRefused(refusal)) => {
            shared_credential_refused_response(&pipe_id, refusal)
        }
        Err(e) => {
            error!("[PIPE:{}] GET passthrough failed: {:?}", pipe_id, e);
            if let Some(refused) = platform_refused(&e) {
                record_front_door_block(
                    state,
                    &resolved,
                    &resolved,
                    &Value::Null,
                    refused.stage,
                    refused.code,
                    &refused.body,
                );
                return refused.response;
            }
            let (status, code) = match &e {
                crate::pipes::executor::PipeError::RateLimitExceeded(_) => {
                    (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
                }
                crate::pipes::executor::PipeError::CircuitBreakerOpen(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "circuit_breaker_open")
                }
                crate::pipes::executor::PipeError::CallerKeyRejected { status } => {
                    (caller_key_status(*status), CALLER_KEY_REJECTED)
                }
                _ => (StatusCode::BAD_GATEWAY, "upstream_error"),
            };
            (
                status,
                Json(serde_json::json!({
                    "error": { "message": format!("GET passthrough failed: {}", e), "type": "internal_error", "code": code }
                })),
            )
                .into_response()
        }
    }
}

/// Proxy a `multipart/form-data` request (file upload `POST /v1/files`, or
/// speech-to-text `POST /v1/audio/transcriptions` / `/v1/audio/translations`) to
/// the upstream provider. Mirrors [`proxy_api_get`]: source authentication, the
/// inbound policy gate and the team gate apply (there is no JSON body, so
/// quota/model checks are inert), then the raw multipart body is forwarded
/// verbatim via `execute_upload`, returning the provider's response (the
/// created file object, or the transcript, as JSON).
#[allow(clippy::too_many_arguments)]
async fn proxy_file_upload(
    state: &PipeHandlerState,
    headers: &axum::http::HeaderMap,
    peer_cert: Option<&crate::source_auth::models::PeerCertInfo>,
    pipe_id: String,
    path: &str,
    path_suffix: String,
    content_type: String,
    body: Vec<u8>,
) -> Response {
    let pipe = match state
        .pipe_store
        .get(&pipe_id)
        .await
    {
        Some(pipe) => pipe,
        None => {
            return (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({
                    "error": { "message": format!("No pipe configured: {}", pipe_id), "type": "invalid_request_error" }
                })),
            )
                .into_response();
        }
    };
    let resolved = match pipe.resolve_variant(None) {
        Ok(resolved) => Arc::new(resolved),
        Err(_) => Arc::new(pipe),
    };
    if !resolved.status.is_enabled() {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": { "message": "pipe not available", "type": "invalid_request_error", "code": "pipe_not_available" }
            })),
        )
            .into_response();
    }

    // ── Source authentication ──
    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
    let source_auth = crate::source_auth::source_auth_gate(
        resolved.source_auth.as_ref(),
        state
            .source_auth_middleware
            .as_deref(),
    );
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        return source_auth_unavailable_response(&pipe_id);
    }
    if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
        match sa_middleware
            .authenticate(auth_config, headers, &resolved.name, resolved.tenant_id.as_deref(), peer_cert)
            .await
        {
            Ok(identity) => caller_identity = Some(identity),
            Err(e) => {
                warn!(pipe_id = %pipe_id, reason = %e, "Source authentication failed on file upload — returning 401");
                return source_auth_failed_response();
            }
        }
    }

    if let Err(denied) =
        enforce_passthrough_policy(state, &resolved, &pipe_id, "POST", path, headers, caller_identity.as_ref()).await
    {
        return denied;
    }

    // ── Team access gate ──
    // A spent budget refuses the upload only when it runs on a platform key.
    let call_budget = match crate::teams::team_pre_check(
        resolved
            .team_attribution
            .as_ref(),
        headers,
        caller_identity.as_ref(),
        &serde_json::Value::Null,
    )
    .await
    {
        crate::teams::TeamGateDecision::Block { status, code, reason } => {
            let error_type = team_gate_error_type(status);
            warn!(pipe_id = %pipe_id, %status, code, reason = %reason, "Team gate blocked file upload");
            let body = serde_json::json!({
                "error": { "message": reason, "type": error_type, "code": code }
            });
            record_front_door_block(state, &resolved, &resolved, &Value::Null, "team_gate", code, &body);
            return (status, Json(body)).into_response();
        }
        crate::teams::TeamGateDecision::Allow(ctx) => ctx.call_budget,
        crate::teams::TeamGateDecision::Skip => None,
    };

    let caller = caller_credentials(
        state
            .source_auth_middleware
            .as_deref(),
        headers,
        resolved
            .source_auth
            .as_ref()
            .map(|auth| (auth, resolved.tenant_id.as_deref())),
        false,
    )
    .await;
    let executor = crate::pipes::executor::PipeExecutor::new_with_secrets(&resolved, Some(state.secrets_store.clone()));
    match crate::teams::call_budget::scope(
        call_budget,
        Box::pin(executor.execute_upload(Some(path_suffix), content_type, body, caller)),
    )
    .await
    {
        Ok(bin) => {
            let mut response_headers = axum::http::HeaderMap::new();
            if let Ok(value) = axum::http::HeaderValue::from_str(&bin.content_type) {
                response_headers.insert(axum::http::header::CONTENT_TYPE, value);
            }
            (StatusCode::OK, response_headers, bin.bytes).into_response()
        }
        Err(crate::pipes::executor::PipeError::SharedCredentialRefused(refusal)) => {
            shared_credential_refused_response(&pipe_id, refusal)
        }
        Err(e) => {
            error!("[PIPE:{}] File upload passthrough failed: {:?}", pipe_id, e);
            if let Some(refused) = platform_refused(&e) {
                record_front_door_block(
                    state,
                    &resolved,
                    &resolved,
                    &Value::Null,
                    refused.stage,
                    refused.code,
                    &refused.body,
                );
                return refused.response;
            }
            let (status, code) = match &e {
                crate::pipes::executor::PipeError::RateLimitExceeded(_) => {
                    (StatusCode::TOO_MANY_REQUESTS, "rate_limit_exceeded")
                }
                crate::pipes::executor::PipeError::CircuitBreakerOpen(_) => {
                    (StatusCode::SERVICE_UNAVAILABLE, "circuit_breaker_open")
                }
                crate::pipes::executor::PipeError::CallerKeyRejected { status } => {
                    (caller_key_status(*status), CALLER_KEY_REJECTED)
                }
                _ => (StatusCode::BAD_GATEWAY, "upstream_error"),
            };
            (
                status,
                Json(serde_json::json!({
                    "error": { "message": format!("File upload passthrough failed: {}", e), "type": "internal_error", "code": code }
                })),
            )
                .into_response()
        }
    }
}

/// GET dispatcher for a pipe route. A realtime WebSocket upgrade to a
/// `…/v1/realtime` path is handed to the realtime relay (Mode C); every other
/// GET (health, model discovery, batch/file GET-proxy, SPA fallback) falls
/// through to [`handle_pipe_health`].
pub async fn handle_pipe_get(
    State(state): State<PipeHandlerState>,
    req: axum::extract::Request,
) -> Response {
    let is_ws_upgrade = req
        .headers()
        .get(axum::http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);
    let path = req.uri().path().to_string();
    if is_ws_upgrade && crate::pipes::streaming::is_realtime_path(&path) {
        return crate::pipes::realtime::handle_realtime_get(state, req).await;
    }
    let (parts, _body) = req.into_parts();
    let peer_cert = parts
        .extensions
        .get::<crate::source_auth::models::PeerCertInfo>()
        .cloned()
        .map(axum::Extension);
    handle_pipe_health(State(state), parts.headers, peer_cert, parts.uri).await
}

/// Health check endpoint for a specific pipe
///
/// GET {pipe.route}/health
pub async fn handle_pipe_health(
    State(state): State<PipeHandlerState>,
    headers: axum::http::HeaderMap,
    peer_cert: Option<axum::Extension<crate::source_auth::models::PeerCertInfo>>,
    uri: axum::http::Uri,
) -> Response {
    // Extract full request path
    let path = uri.path();

    // ── Guarded API GET-proxy (batch/file polling & retrieval) ──
    // Batch and Files endpoints are polled/retrieved with GET, which must reach
    // the provider rather than serve the dashboard SPA. This runs BEFORE the SPA
    // fallback and is gated to known API families (`/v1/batches`, `/v1/files`)
    // so a browser refresh of a dashboard route (`/llm/new`, `/llm/:id`) is
    // never affected.
    let get_match = {
        let route_map = state
            .route_to_pipe
            .read()
            .await;
        let mut best: Option<(String, String, String)> = None;
        for (key, id) in route_map.iter() {
            if !route_key_matches_listener(key, &state.listener_scopes) {
                continue;
            }
            let route = &key.route;
            if path.starts_with(route) {
                let suffix = path
                    .strip_prefix(route)
                    .unwrap_or("");
                if best
                    .as_ref()
                    .map(|(_, r, _)| route.len() > r.len())
                    .unwrap_or(true)
                {
                    best = Some((id.clone(), route.clone(), suffix.to_string()));
                }
            }
        }
        best
    };
    if let Some((pipe_id, _route, path_suffix)) = get_match {
        if crate::pipes::streaming::is_proxyable_get_path(&path_suffix) {
            let request_context = crate::observability::request_context::RequestContext::for_request(&headers);
            return crate::observability::request_context::scope(
                request_context,
                proxy_api_get(
                    &state,
                    &headers,
                    peer_cert
                        .as_ref()
                        .map(|e| &e.0),
                    pipe_id,
                    path,
                    path_suffix,
                ),
            )
            .await;
        }
        // ── Model discovery (`GET {route}/v1/models`) ──
        // A plain LLM surface answers with its exposed model(s) (base + each
        // variant), OpenAI-list shaped, so a client can discover what a route
        // serves without a provider round trip. An IDE Surface instead returns
        // the caller's governed, per-caller-filtered model menu.
        if crate::pipes::streaming::is_models_path(&path_suffix) {
            match state
                .pipe_store
                .get(&pipe_id)
                .await
            {
                Some(pipe) => {
                    if matches!(pipe.pipe_type, crate::pipes::PipeType::IDECatalog { .. }) {
                        return serve_ide_models(
                            &state,
                            &headers,
                            peer_cert
                                .as_ref()
                                .map(|e| &e.0),
                            pipe,
                        )
                        .await;
                    }
                    return serve_models_list(&pipe);
                }
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({
                            "error": { "message": format!("No pipe configured: {}", pipe_id), "type": "invalid_request_error" }
                        })),
                    )
                        .into_response();
                }
            }
        }
        // ── IDE Surface bootstrap (`GET {route}/.well-known/agent-stream`) ──
        // Public, unauthenticated discovery document. An IDE client fetches this
        // from the Access Point URL alone to learn the central sign-in
        // identifiers (tenant/client/scopes) and the model-discovery/dispatch
        // paths, so one surface change reconfigures every client. Only an IDE
        // Surface with configured client sign-in serves it; anything else 404s
        // so the client falls back to its own manual settings.
        if crate::pipes::streaming::is_wellknown_ide_path(&path_suffix) {
            match state
                .pipe_store
                .get(&pipe_id)
                .await
            {
                Some(pipe) => return serve_ide_bootstrap(&pipe).await,
                None => {
                    return (
                        StatusCode::NOT_FOUND,
                        Json(serde_json::json!({
                            "error": { "message": format!("No pipe configured: {}", pipe_id), "type": "invalid_request_error" }
                        })),
                    )
                        .into_response();
                }
            }
        }
    }

    // The pipe data-plane shares its ingress prefix (e.g. `/llm`) with the
    // dashboard SPA's pipe-editor routes (`/llm/new`, `/llm/:id`). This GET
    // handler is registered on the prefix wildcard, so a direct browser
    // refresh of one of those routes lands here. Only a genuine pipe health
    // probe targets `/health`; serve the SPA shell for everything else so
    // client-side routing can resume on reload.
    if !path.ends_with("/health") {
        return serve_spa_shell(&state, path).await;
    }

    // Look up pipe ID from route - try to find longest matching route
    let (pipe_id, matched_route, path_suffix) = {
        let route_map = state
            .route_to_pipe
            .read()
            .await;

        // Find the longest matching route prefix
        let mut best_match: Option<(String, String, String)> = None;
        for (key, id) in route_map.iter() {
            if !route_key_matches_listener(key, &state.listener_scopes) {
                continue;
            }
            let route = &key.route;
            if path.starts_with(route) {
                let suffix = path
                    .strip_prefix(route)
                    .unwrap_or("");
                // Prefer longer matches
                if best_match.is_none()
                    || route.len()
                        > best_match
                            .as_ref()
                            .unwrap()
                            .1
                            .len()
                {
                    best_match = Some((id.clone(), route.clone(), suffix.to_string()));
                }
            }
        }

        match best_match {
            Some((id, route, suffix)) => (id, route, suffix),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": format!("No pipe configured for path: {}", path)
                    })),
                )
                    .into_response();
            }
        }
    };

    debug!("Health check for pipe: {} (route: {}, path: {})", pipe_id, matched_route, path_suffix);

    match state
        .pipe_store
        .get(&pipe_id)
        .await
    {
        Some(pipe) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "healthy",
                "pipe_id": pipe_id,
                "pipe_name": pipe.name,
                "route": matched_route,
                "path": path_suffix,
                "enabled": pipe.status.is_enabled(),
            })),
        )
            .into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "status": "not_found",
                "pipe_id": pipe_id,
            })),
        )
            .into_response(),
    }
}

/// Extract `(model, provider_type)` from an LLM surface's provider, or `None`
/// for a non-LLM surface or an empty model name. Shared by the plain
/// per-surface model list and the IDE Surface discovery filter.
fn llm_model_of(pt: &crate::pipes::PipeType) -> Option<(String, String)> {
    use crate::pipes::types::llm_provider_ext::LLMProviderExt;
    if let crate::pipes::PipeType::LLM { provider, .. } = pt {
        let model = provider
            .model_name()
            .to_string();
        if !model.is_empty() {
            return Some((
                model,
                provider
                    .provider_type_str()
                    .to_string(),
            ));
        }
    }
    None
}

/// Answer `GET {route}/v1/models` with the surface's exposed model(s) in
/// OpenAI-list shape (the base surface model plus each variant's model,
/// deduped), so an OpenAI-style client can discover what a route serves.
fn serve_models_list(pipe: &PipeConfig) -> Response {
    let mut models: Vec<(String, String)> = Vec::new();
    if let Some(m) = llm_model_of(&pipe.pipe_type) {
        models.push(m);
    }
    for variant in &pipe.variants {
        if let Ok(resolved) = pipe.resolve_variant(Some(&variant.alias))
            && let Some(m) = llm_model_of(&resolved.pipe_type)
            && !models
                .iter()
                .any(|(existing, _)| existing == &m.0)
        {
            models.push(m);
        }
    }

    let created = chrono::Utc::now().timestamp();
    let data: Vec<serde_json::Value> = models
        .into_iter()
        .map(|(id, owned_by)| {
            serde_json::json!({ "id": id, "object": "model", "created": created, "owned_by": owned_by })
        })
        .collect();
    (StatusCode::OK, Json(serde_json::json!({ "object": "list", "data": data }))).into_response()
}

/// Answer `GET {route}/.well-known/agent-stream` with the IDE Surface's
/// **public** bootstrap document: the central sign-in identifiers plus the
/// model-discovery/dispatch paths, so an IDE client configures itself from the
/// Access Point URL alone. This is served unauthenticated (the client has no
/// credential yet — chicken-and-egg) and only exposes public OAuth identifiers,
/// never secrets. A surface that is not an IDE Surface, or one with no client
/// sign-in configured, returns 404 so the client falls back to manual settings.
async fn serve_ide_bootstrap(pipe: &PipeConfig) -> Response {
    let (client_auth, upstreams) = match &pipe.pipe_type {
        crate::pipes::PipeType::IDECatalog { config } => (config.client_auth.clone(), config.synthesized_upstreams()),
        _ => (None, Vec::new()),
    };
    match client_auth {
        Some(auth) => {
            // Overlay any referenced OAuth Identifier profiles onto the published
            // (public) sign-in identifiers before serving.
            let auth = crate::pipes::catalog::resolve_client_auth(auth).await;
            let upstreams = crate::pipes::catalog::resolve_upstreams(upstreams).await;
            (
                StatusCode::OK,
                Json(crate::pipes::catalog::IdeBootstrapResponse::for_client_and_upstreams(auth, upstreams)),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": {
                    "message": "This surface publishes no client sign-in bootstrap",
                    "type": "invalid_request_error",
                    "code": "no_bootstrap"
                }
            })),
        )
            .into_response(),
    }
}

/// structural filter shared by live discovery and the admin preview: the
/// member must be exposed, its surface enabled, the requested variant
/// resolvable, and the resolved surface an LLM (a non-LLM member has no model
/// to list). Returns the resolved member config alongside the entry so the live
/// path can apply per-caller access gates before publishing; the preview path
/// publishes every returned entry unfiltered.
pub(crate) async fn ide_member_entry(
    pipe_store: &FileSystemPipeStore,
    member: &crate::pipes::catalog::IdeCatalogMember,
    route: &str,
    created: i64,
) -> Option<(PipeConfig, crate::pipes::catalog::IdeModelEntry)> {
    if !member.expose {
        return None;
    }
    let member_pipe = pipe_store
        .get(&member.pipe_id)
        .await?;
    if !member_pipe
        .status
        .is_enabled()
    {
        return None;
    }
    let resolved = member_pipe
        .resolve_variant(
            member
                .variant_alias
                .as_deref(),
        )
        .ok()?;
    let (model, provider) = llm_model_of(&resolved.pipe_type)?;
    let entry = crate::pipes::catalog::IdeModelEntry::from_member(
        member,
        route.to_string(),
        Some(model),
        Some(provider),
        created,
    );
    Some((resolved, entry))
}

/// Build the **unfiltered** IDE catalogue for an IDE Surface — every exposed,
/// enabled, LLM member entry, ordered like the live menu — but WITHOUT the
/// per-caller access gates (source auth / OPA / team / model scope). This is the
/// admin-facing "what does this catalogue publish" preview backing the IDE
/// editor's Sandbox tab; the live `/v1/models` path additionally filters per
/// caller, so a real caller may receive a subset.
pub(crate) async fn build_ide_catalog_preview(
    pipe_store: &FileSystemPipeStore,
    ide_pipe: &PipeConfig,
) -> crate::pipes::catalog::IdeModelsResponse {
    let members = match &ide_pipe.pipe_type {
        crate::pipes::PipeType::IDECatalog { config } => config.members.clone(),
        _ => Vec::new(),
    };
    let route = ide_pipe
        .route
        .clone()
        .unwrap_or_default();
    let created = chrono::Utc::now().timestamp();
    let mut entries: Vec<crate::pipes::catalog::IdeModelEntry> = Vec::new();
    for member in &members {
        if let Some((_resolved, entry)) = ide_member_entry(pipe_store, member, &route, created).await {
            entries.push(entry);
        }
    }
    entries.sort_by(|a, b| {
        a.agent_stream
            .order
            .cmp(&b.agent_stream.order)
            .then_with(|| {
                a.agent_stream
                    .display_name
                    .cmp(&b.agent_stream.display_name)
            })
    });
    crate::pipes::catalog::IdeModelsResponse::list(entries)
}

/// Answer `GET {route}/v1/models` for an **IDE Surface** with the caller's
/// governed, per-caller-filtered model menu.
///
/// The IDE Surface is a dispatching front door: this discovery step runs the
/// front-door gates (the surface's own source auth + OPA) to establish the
/// caller identity, then filters each exposed member surface by re-running that
/// member's own access gates (OPA, team access, virtual-key model scope) under
/// the same caller identity. Only members the caller may actually use are
/// published, so an IDE client never sees — or can select — a model it is
/// barred from. Quota exhaustion is intentionally *not* a discovery filter: a
/// model the caller may access stays listed even when a monthly cap is
/// currently spent (that surfaces as a 429 at call time, not a vanished model).
async fn serve_ide_models(
    state: &PipeHandlerState,
    headers: &axum::http::HeaderMap,
    peer_cert: Option<&crate::source_auth::models::PeerCertInfo>,
    ide_pipe: PipeConfig,
) -> Response {
    let members = match &ide_pipe.pipe_type {
        crate::pipes::PipeType::IDECatalog { config } => config.members.clone(),
        _ => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": { "message": "surface is not an IDE catalog", "type": "internal_error" }
                })),
            )
                .into_response();
        }
    };

    // ── Front-door source authentication ──
    // Establish the caller identity against the IDE Surface's own credential so
    // per-member filtering can be applied. A surface with no source auth admits
    // an anonymous caller (identity = None), which member gates then resolve to
    // the built-in anonymous member/team.
    let mut caller_identity: Option<crate::source_auth::AuthenticatedIdentity> = None;
    let source_auth = crate::source_auth::source_auth_gate(
        ide_pipe.source_auth.as_ref(),
        state
            .source_auth_middleware
            .as_deref(),
    );
    if let crate::source_auth::SourceAuthGate::Unavailable = source_auth {
        return source_auth_unavailable_response(&ide_pipe.id);
    }
    if let crate::source_auth::SourceAuthGate::Required(sa_middleware, auth_config) = source_auth {
        match sa_middleware
            .authenticate(auth_config, headers, &ide_pipe.name, ide_pipe.tenant_id.as_deref(), peer_cert)
            .await
        {
            Ok(identity) => caller_identity = Some(identity),
            Err(e) => {
                warn!(pipe_id = %ide_pipe.id, reason = %e, "IDE Surface source auth failed — returning 401");
                return source_auth_failed_response();
            }
        }
    }

    // ── Front-door OPA ──
    if ide_pipe.opa_enabled()
        && let Some(policy_mgr) = &state.pipe_policy_manager
    {
        let mut policy_input = crate::surface_context::PolicyInput::new(
            "GET",
            "/v1/models",
            crate::surface_context::filter_sensitive_headers(headers),
            "inbound",
            None,
            None,
            Some(ide_pipe.id.clone()),
            &ide_pipe.name,
        );
        policy_input.source_auth = caller_identity
            .as_ref()
            .map(crate::surface_context::SourceAuthContext::from);
        policy_input.request = Some(crate::surface_context::RequestContext {
            purpose: crate::surface_context::RequestPurpose::Discovery,
            forwarded_upstream_auth: false,
        });
        let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
        match policy_mgr.evaluate(&ide_pipe.id, None, input_value) {
            Ok(true) => {}
            Ok(false) => {
                warn!(pipe_id = %ide_pipe.id, "IDE Surface OPA denied discovery — returning 403");
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": { "message": "Request denied by surface policy", "type": "permission_error", "code": "policy_denied" }
                    })),
                )
                    .into_response();
            }
            Err(e) => {
                warn!(pipe_id = %ide_pipe.id, error = %e, "IDE Surface OPA evaluation error on discovery — returning 403");
                return (
                    StatusCode::FORBIDDEN,
                    Json(serde_json::json!({
                        "error": { "message": "Surface policy could not be evaluated", "type": "permission_error", "code": "policy_evaluation_error" }
                    })),
                )
                    .into_response();
            }
        }
    }

    // ── Per-member filtering ──
    // The optional `route` hint is the IDE Surface's own front-door route: every
    // published model is reached by POSTing to it with the model id in the body.
    let route = ide_pipe
        .route
        .clone()
        .unwrap_or_default();
    let created = chrono::Utc::now().timestamp();
    let empty_body = serde_json::Value::Null;
    let mut entries: Vec<crate::pipes::catalog::IdeModelEntry> = Vec::new();

    for member in &members {
        let Some((resolved, entry)) = ide_member_entry(&state.pipe_store, member, &route, created).await else {
            continue;
        };

        // Member OPA under the front-door caller identity. Deny/error hides it.
        if resolved.opa_enabled() {
            let Some(policy_mgr) = &state.pipe_policy_manager else {
                continue;
            };
            let mut policy_input = crate::surface_context::PolicyInput::new(
                "GET",
                "/v1/models",
                crate::surface_context::filter_sensitive_headers(headers),
                "inbound",
                None,
                None,
                Some(member.pipe_id.clone()),
                &resolved.name,
            );
            policy_input.source_auth = caller_identity
                .as_ref()
                .map(crate::surface_context::SourceAuthContext::from);
            let input_value = serde_json::to_value(&policy_input).unwrap_or_default();
            if !matches!(
                policy_mgr.evaluate(
                    &member.pipe_id,
                    member
                        .variant_alias
                        .as_deref(),
                    input_value
                ),
                Ok(true)
            ) {
                continue;
            }
        }

        // Member team access under the same identity. Access denials (403) hide
        // the model; quota (429) does not — see the fn doc.
        if let crate::teams::TeamGateDecision::Block { status, .. } = crate::teams::team_pre_check(
            resolved
                .team_attribution
                .as_ref(),
            headers,
            caller_identity.as_ref(),
            &empty_body,
        )
        .await
            && status == StatusCode::FORBIDDEN
        {
            continue;
        }

        // Virtual-key model scope when the member has no active team attribution
        // (mirrors the standalone model-scope gate on the POST path).
        if resolved
            .team_attribution
            .is_none()
            && !crate::teams::model_scope_allows(
                caller_identity.as_ref(),
                entry
                    .agent_stream
                    .model
                    .as_deref(),
            )
            .await
        {
            continue;
        }

        entries.push(entry);
    }

    // Stable ordering: explicit `order`, then display name.
    entries.sort_by(|a, b| {
        a.agent_stream
            .order
            .cmp(&b.agent_stream.order)
            .then_with(|| {
                a.agent_stream
                    .display_name
                    .cmp(&b.agent_stream.display_name)
            })
    });

    (StatusCode::OK, Json(crate::pipes::catalog::IdeModelsResponse::list(entries))).into_response()
}

/// Serve the dashboard SPA's `index.html` so a direct browser refresh of a
/// dashboard route that lives under the pipe ingress prefix (e.g. `/llm/new`)
/// loads the app shell instead of a "no pipe configured" error. Falls back to
/// a 404 when no SPA shell is configured or it cannot be read.
async fn serve_spa_shell(
    state: &PipeHandlerState,
    path: &str,
) -> Response {
    if let Some(index_path) = &state.spa_index_path {
        match tokio::fs::read(index_path).await {
            Ok(bytes) => {
                return (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], bytes)
                    .into_response();
            }
            Err(e) => {
                error!("Failed to read SPA shell at {} for path {}: {}", index_path, path, e);
            }
        }
    }

    (
        StatusCode::NOT_FOUND,
        Json(serde_json::json!({
            "error": format!("No pipe configured for path: {}", path)
        })),
    )
        .into_response()
}

/// Get metrics for a specific pipe
///
/// GET {pipe.route}/metrics
#[allow(dead_code)]
pub async fn handle_pipe_metrics(
    State(state): State<PipeHandlerState>,
    uri: axum::http::Uri,
) -> Response {
    // Extract route from request path (remove /metrics suffix)
    let path = uri.path();
    let route = path
        .strip_suffix("/metrics")
        .unwrap_or(path);

    // Look up pipe ID from route
    let pipe_id = {
        let route_map = state
            .route_to_pipe
            .read()
            .await;
        match route_map
            .iter()
            .find(|(key, _)| key.route == route && route_key_matches_listener(key, &state.listener_scopes))
        {
            Some((_, id)) => id.clone(),
            None => {
                return (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": format!("No pipe configured for route: {}", route)
                    })),
                )
                    .into_response();
            }
        }
    };

    debug!("Metrics request for pipe: {} (route: {})", pipe_id, route);

    // Check if metrics store is available
    let metrics_store = match &state.metrics_store {
        Some(store) => store,
        None => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(serde_json::json!({
                    "error": "Metrics storage not configured"
                })),
            )
                .into_response();
        }
    };

    // Get time range (default: last 24 hours)
    let end = chrono::Utc::now();
    let start = end - chrono::Duration::hours(24);

    match metrics_store
        .get_aggregated_metrics(&pipe_id, start, end)
        .await
    {
        Ok(metrics) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "pipe_id": pipe_id,
                "period": {
                    "start": start,
                    "end": end,
                    "duration_hours": 24,
                },
                "summary": {
                    "total_requests": metrics.total_requests,
                    "successful_requests": metrics.successful_requests,
                    "failed_requests": metrics.failed_requests,
                    "success_rate": if metrics.total_requests > 0 {
                        (metrics.successful_requests as f64 / metrics.total_requests as f64) * 100.0
                    } else {
                        0.0
                    },
                },
                "tokens": {
                    "total_input_tokens": metrics.total_input_tokens,
                    "total_output_tokens": metrics.total_output_tokens,
                    "total_tokens": metrics.total_tokens,
                },
                "cost": {
                    "total_cost_usd": metrics.total_cost,
                    "avg_cost_per_request": if metrics.total_requests > 0 {
                        metrics.total_cost / metrics.total_requests as f64
                    } else {
                        0.0
                    },
                },
                "performance": {
                    "avg_latency_ms": metrics.avg_latency_ms,
                    "min_latency_ms": metrics.min_latency_ms,
                    "max_latency_ms": metrics.max_latency_ms,
                    "p50_latency_ms": metrics.p50_latency_ms,
                    "p95_latency_ms": metrics.p95_latency_ms,
                    "p99_latency_ms": metrics.p99_latency_ms,
                },
                "throughput": {
                    "requests_per_hour": metrics.total_requests as f64 / 24.0,
                    "tokens_per_hour": metrics.total_tokens as f64 / 24.0,
                },
            })),
        )
            .into_response(),
        Err(e) => {
            error!("Failed to fetch metrics for pipe {}: {}", pipe_id, e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({
                    "error": format!("Failed to fetch metrics: {}", e)
                })),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod routing_tests {
    use super::*;
    use crate::pipes::config::{CanaryConfig, CanarySplit, PipeType, RoutingMatch, RoutingRule, RoutingTarget};
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

    fn llm_pipe_type(provider: LLMProvider) -> PipeType {
        PipeType::LLM {
            provider: Box::new(provider),
            endpoint_path: None,
        }
    }

    #[test]
    fn realtime_only_openai_model_is_rejected_for_chat() {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-realtime".to_string(),
            api_key_secret: None,
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        let msg = realtime_only_chat_rejection(&llm_pipe_type(provider))
            .expect("a realtime-only model must be rejected on the chat path");
        assert!(msg.contains("gpt-realtime"), "message names the model: {msg}");
        assert!(msg.contains("/v1/realtime"), "message points to the realtime endpoint: {msg}");
    }

    #[test]
    fn realtime_only_gemini_native_audio_model_is_rejected_for_chat() {
        let provider = LLMProvider::Gemini {
            provider_type: "gemini".to_string(),
            model: "gemini-2.5-flash-native-audio-latest".to_string(),
            api_key_secret: None,
            project_id: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        let msg = realtime_only_chat_rejection(&llm_pipe_type(provider))
            .expect("a realtime-only Gemini native-audio model must be rejected on the chat path");
        assert!(msg.contains("native-audio"), "message names the model: {msg}");
    }

    #[test]
    fn chat_capable_model_is_not_rejected() {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key_secret: None,
            organization_id: None,
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };
        assert!(realtime_only_chat_rejection(&llm_pipe_type(provider)).is_none());
    }

    fn header_rule(
        name: &str,
        equals: &str,
        variant: &str,
    ) -> RoutingRule {
        RoutingRule {
            match_on: RoutingMatch::Header {
                name: name.to_string(),
                equals: equals.to_string(),
            },
            target: RoutingTarget {
                variant: Some(variant.to_string()),
                llm: None,
            },
        }
    }

    fn canary_to(alias: &str) -> CanaryConfig {
        CanaryConfig {
            enabled: true,
            splits: vec![CanarySplit {
                variant: Some(alias.to_string()),
                weight: 1,
            }],
        }
    }

    fn headers_with(
        name: &str,
        value: &str,
    ) -> axum::http::HeaderMap {
        let mut h = axum::http::HeaderMap::new();
        h.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            axum::http::HeaderValue::from_str(value).unwrap(),
        );
        h
    }

    fn modality_rule(
        has: &str,
        variant: &str,
    ) -> RoutingRule {
        RoutingRule {
            match_on: RoutingMatch::Modality { has: has.to_string() },
            target: RoutingTarget {
                variant: Some(variant.to_string()),
                llm: None,
            },
        }
    }

    fn image_body() -> serde_json::Value {
        serde_json::json!({
            "messages": [{ "role": "user", "content": [
                { "type": "text", "text": "look" },
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,AAAA" } }
            ]}]
        })
    }

    fn audio_body() -> serde_json::Value {
        serde_json::json!({
            "messages": [{ "role": "user", "content": [
                { "type": "input_audio", "input_audio": { "data": "AAAA", "format": "wav" } }
            ]}]
        })
    }

    fn text_body() -> serde_json::Value {
        serde_json::json!({ "messages": [{ "role": "user", "content": "hello" }] })
    }

    #[test]
    fn modality_rule_routes_image_to_variant() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = true;
        pipe.routing_rules = vec![modality_rule("image", "vision")];
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &image_body());
        assert_eq!(d.alias.as_deref(), Some("vision"));
        assert_eq!(d.decision, "routing_rule");
    }

    #[test]
    fn modality_rule_routes_audio_to_variant() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = true;
        pipe.routing_rules = vec![modality_rule("audio", "voice-chat")];
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &audio_body());
        assert_eq!(d.alias.as_deref(), Some("voice-chat"));
    }

    #[test]
    fn modality_text_matches_only_a_medialess_request() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = true;
        pipe.routing_rules = vec![modality_rule("text", "plain")];
        // A pure-text request matches `text`.
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &text_body());
        assert_eq!(d.alias.as_deref(), Some("plain"));
        // An image request must NOT match a `text` rule (falls through to base).
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &image_body());
        assert_ne!(d.alias.as_deref(), Some("plain"));
    }

    #[test]
    fn modality_first_matching_rule_wins() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = true;
        // Image rule ordered first; an image request takes it even though a
        // later text rule exists.
        pipe.routing_rules = vec![modality_rule("image", "vision"), modality_rule("text", "plain")];
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &image_body());
        assert_eq!(d.alias.as_deref(), Some("vision"));
    }

    #[test]
    fn modality_realtime_never_matches_on_chat_body() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = true;
        pipe.routing_rules = vec![modality_rule("realtime", "voice")];
        // `realtime` is a transport signal, so a chat request never matches it.
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &audio_body());
        assert_ne!(d.alias.as_deref(), Some("voice"));
    }

    #[test]
    fn explicit_alias_beats_rule_and_canary() {
        let mut pipe = base_pipe();
        pipe.variants = vec![crate::pipes::pipe_variants::PipeVariant {
            id: "v1".to_string(),
            alias: "explicit".to_string(),
            name: "Explicit".to_string(),
            description: String::new(),
            enabled: true,
            overrides: Default::default(),
        }];
        pipe.routing_rules = vec![header_rule("x-route", "eu", "eu")];
        pipe.canary = Some(canary_to("canary"));
        let d = resolve_route_decision(
            &pipe,
            Some("explicit".to_string()),
            &headers_with("x-route", "eu"),
            &serde_json::json!({}),
        );
        assert_eq!(d.alias.as_deref(), Some("explicit"));
        assert_eq!(d.decision, "explicit_alias");
        // A configured alias is safe to use verbatim as the metric label.
        assert_eq!(d.metric_variant, "explicit");
    }

    #[test]
    fn explicit_unconfigured_alias_uses_fixed_label() {
        // A caller-supplied alias that is NOT a configured variant must collapse
        // to the fixed `unconfigured` label so it cannot explode Prometheus
        // cardinality — while the raw alias still flows through for resolution.
        let pipe = base_pipe(); // no variants configured
        let d = resolve_route_decision(
            &pipe,
            Some("totally-random-123".to_string()),
            &axum::http::HeaderMap::new(),
            &serde_json::json!({}),
        );
        assert_eq!(d.alias.as_deref(), Some("totally-random-123"));
        assert_eq!(d.decision, "explicit_alias");
        assert_eq!(d.metric_variant, UNCONFIGURED_VARIANT_LABEL);
    }

    #[test]
    fn routing_rule_beats_canary() {
        let mut pipe = base_pipe();
        pipe.routing_rules = vec![header_rule("x-route", "eu", "eu")];
        pipe.canary = Some(canary_to("canary"));
        let d = resolve_route_decision(&pipe, None, &headers_with("x-route", "eu"), &serde_json::json!({}));
        assert_eq!(d.alias.as_deref(), Some("eu"));
        assert_eq!(d.decision, "routing_rule");
        assert_eq!(d.metric_variant, "eu");
    }

    #[test]
    fn disabled_routing_falls_through_to_canary() {
        let mut pipe = base_pipe();
        pipe.routing_enabled = false;
        pipe.routing_rules = vec![header_rule("x-route", "eu", "eu")];
        pipe.canary = Some(canary_to("canary"));
        let d = resolve_route_decision(&pipe, None, &headers_with("x-route", "eu"), &serde_json::json!({}));
        assert_eq!(d.alias.as_deref(), Some("canary"));
        assert_eq!(d.decision, "canary");
    }

    #[test]
    fn canary_selected_when_no_alias_or_rule() {
        let mut pipe = base_pipe();
        pipe.canary = Some(canary_to("canary"));
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &serde_json::json!({}));
        assert_eq!(d.alias.as_deref(), Some("canary"));
        assert_eq!(d.decision, "canary");
        assert_eq!(d.metric_variant, "canary");
    }

    #[test]
    fn canary_skip_reason_is_attributed() {
        let mut pipe = base_pipe();
        pipe.canary = Some(CanaryConfig {
            enabled: false,
            splits: vec![CanarySplit {
                variant: Some("canary".to_string()),
                weight: 1,
            }],
        });
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &serde_json::json!({}));
        assert_eq!(d.alias, None);
        assert_eq!(d.decision, "canary_skipped_disabled");
        assert_eq!(d.metric_variant, "base");
    }

    #[test]
    fn base_default_when_nothing_configured() {
        let pipe = base_pipe();
        let d = resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &serde_json::json!({}));
        assert_eq!(d.alias, None);
        assert!(d.inline_target.is_none());
        assert_eq!(d.decision, "base_default");
        assert_eq!(d.metric_variant, "base");
    }

    #[test]
    fn routing_rule_inline_target_selected() {
        let mut pipe = base_pipe();
        let llm: crate::pipes::judge_jury::LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "openai",
            "model": "gpt-4o-mini",
            "endpoint_url": "https://api.openai.com/v1",
        }))
        .unwrap();
        pipe.routing_rules = vec![RoutingRule {
            match_on: RoutingMatch::Header {
                name: "x-route".to_string(),
                equals: "cheap".to_string(),
            },
            target: RoutingTarget { variant: None, llm: Some(llm) },
        }];
        let d = resolve_route_decision(&pipe, None, &headers_with("x-route", "cheap"), &serde_json::json!({}));
        assert_eq!(d.alias, None);
        assert!(d.inline_target.is_some());
        assert_eq!(d.decision, "routing_rule_inline");
        assert_eq!(d.metric_variant, "base");
    }

    #[test]
    fn execution_cache_isolates_inline_targets_from_base() {
        let base = base_pipe();
        let inline_target: crate::pipes::judge_jury::LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "endpoint_url": "https://api.anthropic.com/v1",
        }))
        .unwrap();
        let inline = base.clone_with_failover_target(&inline_target);

        assert_ne!(
            execution_cache_key(&base.id, None, &effective_target_identity(&base), true),
            execution_cache_key(&base.id, None, &effective_target_identity(&inline), true),
            "base and inline targets must never share an executor"
        );
    }

    #[test]
    fn a_secondary_upstream_never_shares_the_primary_executor() {
        let base = base_pipe();
        let identity = effective_target_identity(&base);
        assert_ne!(
            execution_cache_key(&base.id, None, &identity, true),
            execution_cache_key(&base.id, None, &identity, false),
            "an inline target identical to the base must not reuse the executor that offers the caller's key"
        );
    }

    #[test]
    fn execution_cache_isolates_distinct_inline_targets() {
        let base = base_pipe();
        let target_a: crate::pipes::judge_jury::LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "openai",
            "model": "gpt-4o-mini",
            "endpoint_url": "https://api.openai.com/v1",
        }))
        .unwrap();
        let target_b: crate::pipes::judge_jury::LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "anthropic",
            "model": "claude-sonnet-4-20250514",
            "endpoint_url": "https://api.anthropic.com/v1",
        }))
        .unwrap();

        assert_ne!(
            execution_cache_key(
                &base.id,
                None,
                &effective_target_identity(&base.clone_with_failover_target(&target_a)),
                true,
            ),
            execution_cache_key(
                &base.id,
                None,
                &effective_target_identity(&base.clone_with_failover_target(&target_b)),
                true,
            ),
            "distinct inline targets must never share an executor"
        );
    }

    #[test]
    fn execution_cache_isolates_an_inline_target_that_differs_from_the_base_only_in_headers() {
        // Same provider, model and endpoint as the base, but the target's own
        // ingress header: sharing the base's executor would send the base's
        // headers (and price) instead of the target's.
        let mut base = base_pipe();
        base.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "base-tunnel-key".to_string(),
        }];
        let crate::pipes::config::PipeType::LLM { provider, .. } = &base.pipe_type else {
            panic!("base_pipe is an LLM surface");
        };
        let same_upstream = crate::pipes::config::PipeType::LLM {
            provider: provider.clone(),
            endpoint_path: None,
        };
        let mut inline = base.clone();
        inline.pipe_type = same_upstream;
        inline.upstream_headers = vec![crate::pipes::upstream_headers::UpstreamHeader {
            name: "x-asp-api-key".to_string(),
            secret_id: "target-tunnel-key".to_string(),
        }];
        let mut priced = inline.clone();
        priced.upstream_pricing = Some(crate::pipes::types::llm::TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        });

        let key = |pipe: &crate::pipes::config::PipeConfig| {
            execution_cache_key(&base.id, None, &effective_target_identity(pipe), true)
        };
        assert_ne!(key(&base), key(&inline), "a target's own headers must not share the base's executor");
        assert_ne!(key(&inline), key(&priced), "a target's own price must not share an unpriced executor");
    }

    #[tokio::test]
    async fn concurrent_first_requests_create_one_executor_per_identity() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let cache = RwLock::new(HashMap::new());
        let creations = AtomicUsize::new(0);
        let first = get_or_insert_cached(&cache, "target-a".to_string(), || {
            creations.fetch_add(1, Ordering::SeqCst);
            "first"
        });
        let second = get_or_insert_cached(&cache, "target-a".to_string(), || {
            creations.fetch_add(1, Ordering::SeqCst);
            "second"
        });
        let (first, second) = tokio::join!(first, second);

        assert!(Arc::ptr_eq(&first, &second));
        assert_eq!(creations.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn body_field_rule_matches() {
        let mut pipe = base_pipe();
        pipe.routing_rules = vec![RoutingRule {
            match_on: RoutingMatch::BodyField {
                field: "tier".to_string(),
                equals: "gold".to_string(),
            },
            target: RoutingTarget {
                variant: Some("premium".to_string()),
                llm: None,
            },
        }];
        let d =
            resolve_route_decision(&pipe, None, &axum::http::HeaderMap::new(), &serde_json::json!({ "tier": "gold" }));
        assert_eq!(d.alias.as_deref(), Some("premium"));
        assert_eq!(d.decision, "routing_rule");
    }

    #[test]
    fn variant_errors_map_to_expected_http_statuses() {
        use crate::pipes::pipe_variants::VariantResolveError;
        // Disabled variant → 503 Service Unavailable.
        let (status, code, decision) =
            variant_error_response(&VariantResolveError::DisabledVariant("fast".to_string()));
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(code, "variant_disabled");
        assert_eq!(decision, "rejected_disabled");
        // Unknown alias → 404 Not Found.
        let (status, code, decision) = variant_error_response(&VariantResolveError::UnknownAlias("nope".to_string()));
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(code, "variant_not_found");
        assert_eq!(decision, "rejected_unknown");
        // Misconfigured default → 500 Internal Server Error.
        let (status, code, decision) =
            variant_error_response(&VariantResolveError::MisconfiguredDefault("x".to_string()));
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(code, "variant_misconfigured");
        assert_eq!(decision, "rejected_misconfigured");
    }

    #[test]
    fn track_variant_routing_increments_counter() {
        use crate::metrics::backends::prometheus::{VARIANT_ROUTING_DECISIONS, track_variant_routing};
        // Process-global counter — assert a delta on this exact label tuple, not
        // an absolute value (tests may share the process outside nextest).
        let before = VARIANT_ROUTING_DECISIONS
            .with_label_values(&["canary", "canary"])
            .get();
        track_variant_routing("canary", "canary");
        let after = VARIANT_ROUTING_DECISIONS
            .with_label_values(&["canary", "canary"])
            .get();
        assert_eq!(after, before + 1);
    }
}

#[cfg(test)]
mod response_cache_scope_tests {
    use super::*;
    use crate::pipes::config::PipeType;
    use crate::pipes::key_source::CallerCredentials;
    use crate::pipes::types::llm::LLMProvider;

    fn pipe(forward_caller_token: bool) -> PipeConfig {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4o".to_string(),
            api_key_secret: None,
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
            "Copilot".to_string(),
            PipeType::LLM {
                provider: Box::new(provider),
                endpoint_path: None,
            },
        );
        pipe.forward_caller_token = forward_caller_token;
        pipe
    }

    fn caller(
        authorization: Option<&str>,
        upstream_authorization: Option<&str>,
    ) -> CallerCredentials {
        CallerCredentials {
            authorization: authorization.map(str::to_string),
            upstream_authorization: upstream_authorization.map(str::to_string),
            provider_key: None,
        }
    }

    fn scope(
        pipe: &PipeConfig,
        caller: &CallerCredentials,
    ) -> Option<String> {
        response_cache_scope(pipe, caller, "pipe-1", None, "target-a")
    }

    #[test]
    fn a_surface_without_identity_pass_through_shares_one_scope() {
        let shared = crate::pipes::response_cache::ResponseCache::scope_key_for_target("pipe-1", None, "target-a");
        let surface = pipe(false);
        assert_eq!(scope(&surface, &caller(Some("Bearer alice"), None)).as_deref(), Some(shared.as_str()));
        assert_eq!(scope(&surface, &caller(Some("Bearer bob"), None)).as_deref(), Some(shared.as_str()));
        assert_eq!(scope(&surface, &caller(None, None)).as_deref(), Some(shared.as_str()));
    }

    #[test]
    fn identity_pass_through_gives_each_forwarded_token_its_own_scope() {
        let surface = pipe(true);
        let alice = scope(&surface, &caller(Some("Bearer alice"), None)).expect("alice is cached");
        let bob = scope(&surface, &caller(Some("Bearer bob"), None)).expect("bob is cached");
        assert_ne!(alice, bob);
        assert_eq!(scope(&surface, &caller(Some("Bearer alice"), None)).as_deref(), Some(alice.as_str()));
        assert!(alice.starts_with("pipe-1$"), "the caller scope stays under the Surface's scopes: {alice}");
        assert!(!alice.contains("alice"), "the token is not stored in the key: {alice}");

        // The upstream token is the one forwarded, so it decides the scope.
        let alice_upstream = scope(&surface, &caller(Some("Bearer front-door"), Some("Bearer alice"))).unwrap();
        let bob_upstream = scope(&surface, &caller(Some("Bearer front-door"), Some("Bearer bob"))).unwrap();
        assert_ne!(alice_upstream, bob_upstream);
        assert_eq!(alice_upstream, alice);
    }

    #[test]
    fn identity_pass_through_without_a_token_to_forward_is_not_cached() {
        let surface = pipe(true);
        assert_eq!(scope(&surface, &caller(None, None)), None);
        assert_eq!(scope(&surface, &caller(Some("Bearer "), Some("Basic abc"))), None);
    }
}

#[cfg(test)]
mod ingress_skin_tests {
    use super::*;
    use crate::pipes::ingress::IngressSchema;
    use serde_json::json;

    #[test]
    fn normalize_passes_through_openai_chat() {
        let body = json!({ "messages": [ { "role": "user", "content": "hi" } ] });
        let out = normalize_ingress_request(IngressSchema::OpenAiChat, body.clone());
        assert_eq!(out, body);
    }

    #[test]
    fn normalize_maps_anthropic_to_openai() {
        let body = json!({
            "model": "claude-x",
            "system": "be nice",
            "max_tokens": 64,
            "messages": [ { "role": "user", "content": "hi" } ]
        });
        let out = normalize_ingress_request(IngressSchema::AnthropicMessages, body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0]["role"], json!("system"));
        assert_eq!(messages[1], json!({ "role": "user", "content": "hi" }));
        assert_eq!(out["max_tokens"], json!(64));
    }

    #[test]
    fn normalize_maps_responses_to_openai() {
        let body = json!({ "model": "gpt-x", "instructions": "sys", "input": "hello" });
        let out = normalize_ingress_request(IngressSchema::OpenAiResponses, body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0], json!({ "role": "system", "content": "sys" }));
        assert_eq!(messages[1], json!({ "role": "user", "content": "hello" }));
    }

    #[test]
    fn skin_success_body_shapes_each_dialect() {
        let openai = json!({
            "id": "chatcmpl-1",
            "choices": [ { "index": 0, "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3 }
        });
        assert_eq!(skin_success_body(IngressSchema::OpenAiChat, openai.clone(), "m"), openai);

        let anthropic = skin_success_body(IngressSchema::AnthropicMessages, openai.clone(), "claude-x");
        assert_eq!(anthropic["type"], json!("message"));
        assert_eq!(anthropic["content"][0]["text"], json!("hi"));

        let responses = skin_success_body(IngressSchema::OpenAiResponses, openai, "gpt-x");
        assert_eq!(responses["object"], json!("response"));
        assert_eq!(responses["output_text"], json!("hi"));
    }

    #[tokio::test]
    async fn reskin_error_rewrites_anthropic_envelope() {
        let resp = (
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": { "message": "bad key", "type": "invalid_request_error" } })),
        )
            .into_response();
        let out = reskin_error_response(IngressSchema::AnthropicMessages, resp).await;
        assert_eq!(out.status(), StatusCode::UNAUTHORIZED);
        let bytes = axum::body::to_bytes(out.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["type"], json!("error"));
        assert_eq!(body["error"]["type"], json!("authentication_error"));
        assert_eq!(body["error"]["message"], json!("bad key"));
    }

    #[tokio::test]
    async fn reskin_error_leaves_openai_and_success_untouched() {
        // OpenAI Chat egress: unchanged.
        let resp = (StatusCode::BAD_REQUEST, Json(json!({ "error": { "message": "x" } }))).into_response();
        let out = reskin_error_response(IngressSchema::OpenAiChat, resp).await;
        let bytes = axum::body::to_bytes(out.into_body(), 1 << 20)
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"]["message"], json!("x"));
        assert!(body.get("type").is_none());

        // Success (2xx) responses are never re-skinned.
        let ok = (StatusCode::OK, Json(json!({ "id": "1" }))).into_response();
        let out = reskin_error_response(IngressSchema::AnthropicMessages, ok).await;
        assert_eq!(out.status(), StatusCode::OK);
    }
}

#[cfg(test)]
mod billing_header_tests {
    use super::*;
    use crate::pipes::key_source::KeySource;

    fn headers(billing: ResponseBilling) -> axum::http::HeaderMap {
        build_response_headers(
            "t", "openai", "gpt-4o", 10, 20, 30, 0, 0, 0, None, 1.5, billing, "miss", None, None, None, None,
        )
    }

    fn value<'a>(
        headers: &'a axum::http::HeaderMap,
        name: &str,
    ) -> Option<&'a str> {
        headers
            .get(name)
            .and_then(|v| v.to_str().ok())
    }

    #[test]
    fn responses_report_the_catalog_cost_the_billed_cost_and_the_key_source() {
        let owned = headers(ResponseBilling {
            billed_cost: 0.0,
            key_source: Some(KeySource::Client),
        });
        assert_eq!(value(&owned, "x-agent-stream-cost-usd"), Some("1.500000"));
        assert_eq!(value(&owned, "x-agent-stream-billed-cost-usd"), Some("0.000000"));
        assert_eq!(value(&owned, "x-agent-stream-key-source"), Some("client"));

        let platform = headers(ResponseBilling {
            billed_cost: 1.5,
            key_source: Some(KeySource::Platform),
        });
        assert_eq!(value(&platform, "x-agent-stream-billed-cost-usd"), Some("1.500000"));
        assert_eq!(value(&platform, "x-agent-stream-key-source"), Some("platform"));

        let cache_hit = headers(ResponseBilling::default());
        assert_eq!(value(&cache_hit, "x-agent-stream-billed-cost-usd"), Some("0.000000"));
        assert_eq!(value(&cache_hit, "x-agent-stream-key-source"), None, "no model call, no key source");
    }

    #[test]
    fn a_refused_caller_key_answers_with_the_upstreams_status() {
        let refused = crate::pipes::executor::PipeError::CallerKeyRejected { status: 401 };
        assert_eq!(
            provider_failure_status(&refused),
            (StatusCode::UNAUTHORIZED, "authentication_error", CALLER_KEY_REJECTED)
        );
        let forbidden = crate::pipes::executor::PipeError::CallerKeyRejected { status: 403 };
        assert_eq!(provider_failure_status(&forbidden).0, StatusCode::FORBIDDEN);
        let upstream = crate::pipes::executor::PipeError::UpstreamResponse {
            status: 401,
            message: "operator key refused".to_string(),
        };
        assert_eq!(provider_failure_status(&upstream).0, StatusCode::BAD_GATEWAY);
    }

    #[test]
    fn a_request_offers_tools_through_tools_or_legacy_functions() {
        let tool = serde_json::json!({ "type": "function", "function": { "name": "weather", "parameters": {} } });
        let function = serde_json::json!({ "name": "weather", "parameters": {} });
        assert!(offers_tools(&serde_json::json!({ "tools": [tool] })));
        assert!(offers_tools(&serde_json::json!({ "functions": [function] })));
        assert!(!offers_tools(&serde_json::json!({ "tools": [], "functions": [] })));
        assert!(!offers_tools(&serde_json::json!({ "functions": "weather" })));
        assert!(!offers_tools(&serde_json::json!({ "messages": [] })));
    }

    #[test]
    fn content_the_upstream_cannot_read_answers_400() {
        let reason = crate::pipes::request_shaping::CLAUDE_UNREADABLE_FILE;
        let refused = crate::pipes::executor::PipeError::UnsupportedContent(reason);
        assert_eq!(
            provider_failure_status(&refused),
            (StatusCode::BAD_REQUEST, "invalid_request_error", "unsupported_content")
        );
        let wrapped = crate::pipes::executor::PipeError::UnsupportedContent(reason).with_incurred_usage(
            crate::pipes::config::StageUsage {
                input_tokens: 10,
                ..Default::default()
            },
            Default::default(),
        );
        assert_eq!(provider_failure_status(&wrapped).0, StatusCode::BAD_REQUEST);
        let failed = crate::pipes::executor::PipeError::RequestFailed("connection reset".to_string());
        assert_eq!(provider_failure_status(&failed).0, StatusCode::BAD_GATEWAY);
    }

    mod caller_provider_key {
        use super::super::caller_credentials;
        use crate::source_auth::SourceAuthConfig;
        use crate::source_auth::models::{ApiKeyAuthConfig, CredentialExtraction};

        fn headers(pairs: &[(&'static str, &'static str)]) -> axum::http::HeaderMap {
            let mut headers = axum::http::HeaderMap::new();
            for (name, value) in pairs {
                headers.insert(*name, axum::http::HeaderValue::from_static(value));
            }
            headers
        }

        fn api_key_front_door(header: &str) -> SourceAuthConfig {
            SourceAuthConfig::ApiKey(ApiKeyAuthConfig {
                extraction: CredentialExtraction::HttpHeader { field: header.to_string() },
                secret_id: "front-door-keys".to_string(),
            })
        }

        async fn provider_key(
            headers: &axum::http::HeaderMap,
            front_door: Option<&SourceAuthConfig>,
            dispatched: bool,
        ) -> Option<String> {
            caller_credentials(None, headers, front_door.map(|auth| (auth, None)), dispatched)
                .await
                .provider_key
        }

        #[tokio::test]
        async fn a_jwt_front_door_never_offers_its_token_and_takes_the_key_from_its_own_header() {
            let jwt = SourceAuthConfig::JwtBearer(crate::jwt_bearer::models::JwtBearerAuthConfig::default());
            let only_jwt = headers(&[("authorization", "Bearer eyJ.front-door")]);
            assert_eq!(provider_key(&only_jwt, Some(&jwt), false).await, None);
            let credentials = caller_credentials(None, &only_jwt, Some((&jwt, None)), false).await;
            assert_eq!(
                credentials
                    .authorization
                    .as_deref(),
                Some("Bearer eyJ.front-door"),
                "identity pass-through still forwards the validated token"
            );

            let with_key = headers(&[
                ("authorization", "Bearer eyJ.front-door"),
                ("x-agent-stream-upstream-authorization", "Bearer sk-caller"),
            ]);
            assert_eq!(
                provider_key(&with_key, Some(&jwt), false)
                    .await
                    .as_deref(),
                Some("sk-caller")
            );
        }

        #[tokio::test]
        async fn a_front_door_on_another_header_keeps_authorization_for_the_callers_key() {
            let boris = api_key_front_door("x-boris-api-key");
            let request = headers(&[("x-boris-api-key", "project-key"), ("authorization", "Bearer sk-caller")]);
            assert_eq!(
                provider_key(&request, Some(&boris), false)
                    .await
                    .as_deref(),
                Some("sk-caller")
            );
            assert_eq!(
                provider_key(&headers(&[("authorization", "Bearer sk-caller")]), None, false)
                    .await
                    .as_deref(),
                Some("sk-caller"),
                "no front door"
            );
        }

        #[tokio::test]
        async fn a_key_equal_to_the_front_door_credential_is_never_offered() {
            // An SDK that fills `Authorization` from the project key it also
            // sends in the front door's own header.
            let boris = api_key_front_door("x-boris-api-key");
            let repeated = headers(&[("x-boris-api-key", "project-key"), ("authorization", "Bearer project-key")]);
            assert_eq!(provider_key(&repeated, Some(&boris), false).await, None);

            // The Anthropic ingress copies a front-door `x-api-key` into
            // `Authorization`.
            let anthropic = api_key_front_door("x-api-key");
            let copied = headers(&[("x-api-key", "front-door-key"), ("authorization", "Bearer front-door-key")]);
            assert_eq!(provider_key(&copied, Some(&anthropic), false).await, None);
        }

        #[tokio::test]
        async fn a_dispatched_request_never_offers_a_provider_key() {
            let open_front_door = headers(&[("authorization", "Bearer ide-token")]);
            assert_eq!(provider_key(&open_front_door, None, true).await, None);
            // The dedicated header is the IDE dual-token channel: a member's
            // upstream identity (a Graph token for a Copilot member) is never
            // sent to another member's provider as a key.
            let dual_token = headers(&[
                ("authorization", "Bearer ide-token"),
                ("x-agent-stream-upstream-authorization", "Bearer graph-token"),
            ]);
            assert_eq!(provider_key(&dual_token, None, true).await, None);
            let credentials = caller_credentials(None, &dual_token, None, true).await;
            assert_eq!(
                credentials
                    .upstream_authorization
                    .as_deref(),
                Some("Bearer graph-token"),
                "identity pass-through still forwards the member's identity token"
            );
        }

        #[tokio::test]
        async fn authorization_is_the_callers_key_where_the_front_door_does_not_read_it() {
            let both = headers(&[
                ("authorization", "Bearer sk-caller"),
                ("x-agent-stream-upstream-authorization", "Bearer upstream-identity"),
            ]);
            assert_eq!(
                provider_key(&both, None, false)
                    .await
                    .as_deref(),
                Some("sk-caller"),
                "no front door"
            );
            let boris = api_key_front_door("x-boris-api-key");
            let mut fronted = both.clone();
            fronted.insert("x-boris-api-key", axum::http::HeaderValue::from_static("project-key"));
            assert_eq!(
                provider_key(&fronted, Some(&boris), false)
                    .await
                    .as_deref(),
                Some("sk-caller"),
                "a front door on another header"
            );
            assert_eq!(
                provider_key(&headers(&[("x-agent-stream-upstream-authorization", "Bearer sk-caller")]), None, false)
                    .await
                    .as_deref(),
                Some("sk-caller"),
                "the dedicated header alone still carries the key"
            );
        }

        #[tokio::test]
        async fn a_front_door_on_the_dedicated_header_leaves_authorization() {
            let odd = api_key_front_door("x-agent-stream-upstream-authorization");
            let request = headers(&[
                ("x-agent-stream-upstream-authorization", "Bearer front-door-key"),
                ("authorization", "Bearer sk-caller"),
            ]);
            assert_eq!(
                provider_key(&request, Some(&odd), false)
                    .await
                    .as_deref(),
                Some("sk-caller")
            );
        }

        #[test]
        fn caller_credentials_never_print_their_values() {
            let credentials = crate::pipes::key_source::CallerCredentials {
                authorization: Some("Bearer eyJ.secret".to_string()),
                upstream_authorization: None,
                provider_key: Some("sk-secret".to_string()),
            };
            let printed = format!("{credentials:?}");
            assert!(!printed.contains("secret"), "{printed}");
        }
    }

    #[test]
    fn a_platform_call_refused_for_budget_answers_with_the_team_gates_429() {
        use crate::pipes::executor::{BudgetedCall, PipeError};
        let reason = "member 'Alice' monthly budget $5.00 reached (spent $5.10)";
        for call in [BudgetedCall::Upstream, BudgetedCall::Stage] {
            let refused = PipeError::BudgetExhausted {
                reason: reason.to_string(),
                call,
            };
            let answer = platform_refused(&refused).expect("a budget refusal");
            assert_eq!(answer.response.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!((answer.stage, answer.code), ("team_gate", "team_quota_exceeded"));
            assert_eq!(
                answer.body,
                serde_json::json!({
                    "error": { "message": reason, "type": "rate_limit_error", "code": "team_quota_exceeded" }
                }),
                "the body the team gate returned for a spent budget"
            );
            let wrapped = PipeError::BudgetExhausted {
                reason: reason.to_string(),
                call,
            }
            .with_incurred_usage(
                crate::pipes::config::StageUsage::call(1, 1, 0.5, 0, crate::pipes::key_source::KeySource::Customer),
                crate::pipes::config::StageUsage::default(),
            );
            assert!(platform_refused(&wrapped).is_some(), "seen through the incurred-usage wrapper");
        }
        assert!(platform_refused(&PipeError::RequestFailed("down".to_string())).is_none());
    }

    #[test]
    fn a_team_gate_that_cannot_run_answers_an_api_error() {
        assert_eq!(team_gate_error_type(StatusCode::SERVICE_UNAVAILABLE), "api_error");
        assert_eq!(team_gate_error_type(StatusCode::TOO_MANY_REQUESTS), "rate_limit_error");
        assert_eq!(team_gate_error_type(StatusCode::FORBIDDEN), "permission_error");
    }

    #[test]
    fn a_platform_call_refused_as_unmetered_answers_403_with_its_own_code_off_the_team_gate() {
        use crate::pipes::executor::{BudgetedCall, PipeError};
        use crate::pipes::metering::Unmetered;
        for (unmetered, code) in [
            (Unmetered::Batch, "batch_not_metered"),
            (Unmetered::Endpoint, "endpoint_not_metered"),
            (Unmetered::UnpricedModel, "model_not_metered"),
        ] {
            let refused = PipeError::NotMetered {
                unmetered,
                call: BudgetedCall::Upstream,
            }
            .with_incurred_usage(
                crate::pipes::config::StageUsage::call(1, 1, 0.5, 0, crate::pipes::key_source::KeySource::Customer),
                crate::pipes::config::StageUsage::default(),
            );
            let answer = platform_refused(&refused).expect("an unmetered refusal");
            assert_eq!(answer.response.status(), StatusCode::FORBIDDEN, "not retried by SDKs, unlike a 429");
            assert_eq!((answer.stage, answer.code), (METERING_STAGE, code));
            assert_ne!(answer.stage, "team_gate");
            assert_eq!(
                answer.body,
                serde_json::json!({
                    "error": { "message": unmetered.message(), "type": "permission_error", "code": code }
                })
            );
        }
    }
}
