//! Integration triggers for pipe events
//!
//! Handles integration notifications for:
//! - pipe.created - When a new pipe is created
//! - pipe.updated - When pipe configuration changes
//! - pipe.deleted - When a pipe is removed
//! - pipe.executed - When a pipe request is executed
//! - pipe.error - When a pipe execution fails
//! - pipe.budget.threshold_reached - When budget threshold is reached
//! - pipe.budget.exceeded - When budget limit is exceeded
//! - pipe.cost_spike - When an execution's cost spikes above the rolling baseline
//! - pipe.usage_alert - When a usage alert (cost/token/error-rate breach) trips
//! - member.auto_provisioned - When a caller is auto-provisioned into a member

use super::filesystem::FileSystemNotificationStore;
use crate::pipes::config::{PipeConfig, PipeIntegrationMapping, PipeType};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, info, warn};

/// Currency of every cost Agent Stream reports.
pub fn usd_currency() -> String {
    crate::governance::USAGE_CURRENCY.to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipeExecution {
    pub pipe_id: String,
    pub pipe_name: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub latency_ms: u64,
    pub provider: String,
    pub model: String,
    pub trace_id: String,
    /// Whether the execution completed: `false` for a stream that aborted
    /// before it finished.
    pub success: bool,
    /// Why the execution did not complete (`None` when `success`).
    pub error_message: Option<String>,
    /// Currency of `cost` (and of every stage cost in `usage_by_stage`).
    #[serde(default = "usd_currency")]
    pub currency: String,
    /// Usage of each stage that called a model, each under its own provider and
    /// model. `cost`, `input_tokens` and `output_tokens` above are grand totals.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usage_by_stage: Vec<crate::governance::StageUsageEntry>,
    /// `true` when the response was streamed to the caller.
    #[serde(default)]
    pub streaming: bool,
    /// Id of the signed governance record written for this interaction, when
    /// governance recording is on, so a consumer receiving both can drop the
    /// duplicate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_id: Option<String>,
    /// Member, teams and tenant the execution is attributed to.
    #[serde(flatten)]
    pub attribution: crate::governance::UsageAttribution,
    /// Full request body (JSON string), captured only when the surface enables
    /// `log_requests`. Feeds I/O-capturing observability (Langfuse / webhook).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_content: Option<String>,
    /// Full response body (JSON string), captured only when the surface enables
    /// `log_responses`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BudgetAlert {
    /// Currency of `total_spent`, `budget_limit` and `remaining_budget`.
    #[serde(default = "usd_currency")]
    pub currency: String,
    pub pipe_id: String,
    pub pipe_name: String,
    pub month: String,
    pub total_spent: f64,
    pub budget_limit: f64,
    pub usage_percentage: f64,
    pub remaining_budget: f64,
    pub alert_threshold_percent: u8,
    pub budget_exceeded: bool,
    /// Tenant that owns the surface; absent for an appliance-wide surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Pipe integrations for triggering events
    #[serde(skip)]
    pub integrations: Vec<PipeIntegrationMapping>,
}

/// A breach/anomaly usage alert ready to dispatch through the integration system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UsageAlertEvent {
    /// Currency of `threshold`, `observed` and `baseline` when the alert is a
    /// cost alert (`cost_threshold`, `cost_spike`).
    #[serde(default = "usd_currency")]
    pub currency: String,
    pub pipe_id: String,
    pub pipe_name: String,
    /// Integration event type: `pipe.cost_spike` or `pipe.usage_alert`.
    pub event_type: String,
    /// Lower-snake alert kind: `cost_threshold`, `token_threshold`, `error_rate`, `cost_spike`.
    pub alert_type: String,
    pub threshold: f64,
    pub observed: f64,
    pub baseline: Option<f64>,
    pub message: String,
    /// Tenant that owns the surface; absent for an appliance-wide surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Per-alert notification-channel integration IDs to notify in addition to
    /// the pipe's own event-matched integrations.
    #[serde(skip)]
    pub channels: Vec<String>,
    /// The pipe's configured integrations.
    #[serde(skip)]
    pub integrations: Vec<PipeIntegrationMapping>,
}

/// Snapshot of a surface as reported by the lifecycle events: identity, type,
/// provider/model, tenant, and its governance recording and export status.
/// Secrets and routing detail never leave the appliance in this payload.
pub fn surface_lifecycle_state(pipe: &PipeConfig) -> serde_json::Value {
    let governance = pipe
        .governance_recording
        .as_ref()
        .filter(|g| g.is_active());
    let export = governance.and_then(|g| g.export.as_ref());
    serde_json::json!({
        "id": pipe.id,
        "name": pipe.name,
        "description": pipe.description,
        "surface_type": surface_type(pipe),
        "provider": surface_provider(pipe),
        "model": surface_model(pipe),
        "enabled": pipe.status.is_enabled(),
        "status": pipe.status,
        "tenant_id": pipe.tenant_id,
        "governance_enabled": governance.is_some(),
        "governance_export_otel": export.is_some_and(|e| e.otel),
        "governance_export_integrations": export.map(|e| e.integrations.clone()).unwrap_or_default(),
        "created_at": pipe.created_at,
        "updated_at": pipe.updated_at,
    })
}

fn surface_type(pipe: &PipeConfig) -> &'static str {
    match &pipe.pipe_type {
        PipeType::LLM { .. } => "llm",
        PipeType::Webhook { .. } => "webhook",
        PipeType::IDECatalog { .. } => "ide_catalog",
    }
}

fn surface_provider(pipe: &PipeConfig) -> Option<String> {
    match &pipe.pipe_type {
        PipeType::LLM { provider, .. } => Some(
            provider
                .provider_type()
                .to_string(),
        ),
        _ => None,
    }
}

fn surface_model(pipe: &PipeConfig) -> Option<String> {
    match &pipe.pipe_type {
        PipeType::LLM { provider, .. } => Some(
            provider
                .model_name()
                .to_string(),
        ),
        _ => None,
    }
}

fn lifecycle_runtime_values(
    event_type: &str,
    old: Option<&PipeConfig>,
    new: Option<&PipeConfig>,
) -> HashMap<String, String> {
    let current = new
        .or(old)
        .expect("a lifecycle event carries at least one surface state");
    let state_of = |p: Option<&PipeConfig>| {
        p.map(|p| surface_lifecycle_state(p).to_string())
            .unwrap_or_default()
    };
    let mut values = HashMap::new();
    values.insert("OLD_STATE".to_string(), state_of(old));
    values.insert("NEW_STATE".to_string(), state_of(new));
    values.insert("EVENT_TYPE".to_string(), event_type.to_string());
    values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    values.insert("SURFACE_ID".to_string(), current.id.clone());
    values.insert("SURFACE_NAME".to_string(), current.name.clone());
    values.insert("SURFACE_TYPE".to_string(), surface_type(current).to_string());
    values.insert(
        "SURFACE_ENABLED".to_string(),
        current
            .status
            .is_enabled()
            .to_string(),
    );
    if let Some(provider) = surface_provider(current) {
        values.insert("SURFACE_PROVIDER".to_string(), provider);
    }
    if let Some(model) = surface_model(current) {
        values.insert("SURFACE_MODEL".to_string(), model);
    }
    if let Some(tenant) = &current.tenant_id {
        values.insert("TENANT_ID".to_string(), tenant.clone());
    }
    let state = surface_lifecycle_state(current);
    values.insert("GOVERNANCE_ENABLED".to_string(), state["governance_enabled"].to_string());
    values
}

/// A lifecycle event's target mappings and runtime values, taken from the live
/// copy of each surface state (`live` applies the appliance-wide
/// `[surface_defaults]`, as for `pipe.executed`): the event reaches the default
/// `pipe` integrations as well as the surface's own, and reports the governance
/// status the data plane applies.
fn lifecycle_event(
    event_type: &str,
    old: Option<&PipeConfig>,
    new: Option<&PipeConfig>,
    live: impl Fn(PipeConfig) -> PipeConfig,
) -> (Vec<PipeIntegrationMapping>, HashMap<String, String>) {
    let old = old.cloned().map(&live);
    let new = new.cloned().map(&live);
    let values = lifecycle_runtime_values(event_type, old.as_ref(), new.as_ref());
    let targets = new
        .as_ref()
        .or(old.as_ref())
        .map(|pipe| pipe.integrations.clone())
        .unwrap_or_default();
    (targets, values)
}

/// Trigger integrations when a pipe is created
pub async fn trigger_pipe_created(
    integration_store: &FileSystemNotificationStore,
    pipe: &PipeConfig,
) {
    let (targets, values) = lifecycle_event("pipe.created", None, Some(pipe), PipeConfig::with_global_surface_defaults);
    trigger_pipe_integrations(integration_store, &targets, &values, "pipe.created").await;
}

/// Trigger integrations when a pipe is updated
pub async fn trigger_pipe_updated(
    integration_store: &FileSystemNotificationStore,
    old_pipe: &PipeConfig,
    new_pipe: &PipeConfig,
) {
    let (targets, values) =
        lifecycle_event("pipe.updated", Some(old_pipe), Some(new_pipe), PipeConfig::with_global_surface_defaults);
    trigger_pipe_integrations(integration_store, &targets, &values, "pipe.updated").await;
}

/// Trigger integrations when a pipe is deleted
pub async fn trigger_pipe_deleted(
    integration_store: &FileSystemNotificationStore,
    pipe: &PipeConfig,
) {
    let (targets, values) = lifecycle_event("pipe.deleted", Some(pipe), None, PipeConfig::with_global_surface_defaults);
    trigger_pipe_integrations(integration_store, &targets, &values, "pipe.deleted").await;
}

/// Trigger integrations when a pipe is executed successfully
pub async fn trigger_pipe_executed(
    integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    execution: &PipeExecution,
) {
    info!("[PIPE:{}] trigger_pipe_executed called for pipe: {}", execution.pipe_id, execution.pipe_name);
    info!("[PIPE:{}] Received {} pipe_integrations", execution.pipe_id, pipe_integrations.len());
    for (idx, mapping) in pipe_integrations
        .iter()
        .enumerate()
    {
        info!(
            "[PIPE:{}] Integration {}: id={}, event_types={:?}",
            execution.pipe_id, idx, mapping.integration_id, mapping.event_types
        );
    }

    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&execution).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "pipe.executed".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add execution-specific variables
    runtime_values.insert("SURFACE_ID".to_string(), execution.pipe_id.clone());
    runtime_values.insert("SURFACE_NAME".to_string(), execution.pipe_name.clone());
    runtime_values.insert("SURFACE_PROVIDER".to_string(), execution.provider.clone());
    runtime_values.insert("SURFACE_MODEL".to_string(), execution.model.clone());
    runtime_values.insert(
        "INPUT_TOKENS".to_string(),
        execution
            .input_tokens
            .to_string(),
    );
    runtime_values.insert(
        "OUTPUT_TOKENS".to_string(),
        execution
            .output_tokens
            .to_string(),
    );
    runtime_values.insert(
        "TOTAL_TOKENS".to_string(),
        execution
            .total_tokens
            .to_string(),
    );
    runtime_values.insert("COST_USD".to_string(), format!("{:.6}", execution.cost));
    runtime_values.insert(
        "LATENCY_MS".to_string(),
        execution
            .latency_ms
            .to_string(),
    );
    runtime_values.insert("TRACE_ID".to_string(), execution.trace_id.clone());
    if let Some(tenant) = &execution
        .attribution
        .tenant_id
    {
        runtime_values.insert("TENANT_ID".to_string(), tenant.clone());
    }
    runtime_values.insert("CURRENCY".to_string(), execution.currency.clone());
    runtime_values.insert(
        "STREAMING".to_string(),
        execution
            .streaming
            .to_string(),
    );
    runtime_values.insert("SUCCESS".to_string(), execution.success.to_string());
    runtime_values.insert(
        "RECORD_ID".to_string(),
        execution
            .record_id
            .clone()
            .unwrap_or_default(),
    );

    // I/O content, present only when the surface enabled log_requests /
    // log_responses. Feeds Langfuse-style tracing and content webhooks.
    runtime_values.insert(
        "REQUEST_CONTENT".to_string(),
        execution
            .request_content
            .clone()
            .unwrap_or_default(),
    );
    runtime_values.insert(
        "RESPONSE_CONTENT".to_string(),
        execution
            .response_content
            .clone()
            .unwrap_or_default(),
    );

    trigger_pipe_integrations(integration_store, pipe_integrations, &runtime_values, "pipe.executed").await;
}

/// Trigger integrations when a pipe execution fails
pub async fn trigger_pipe_error(
    integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    event: &PipeErrorEvent,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(event).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "pipe.error".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add error-specific variables
    runtime_values.insert("SURFACE_ID".to_string(), event.pipe_id.clone());
    runtime_values.insert("SURFACE_NAME".to_string(), event.pipe_name.clone());
    runtime_values.insert("ERROR_MESSAGE".to_string(), event.error.clone());
    if let Some(tenant) = &event.tenant_id {
        runtime_values.insert("TENANT_ID".to_string(), tenant.clone());
    }

    trigger_pipe_integrations(integration_store, pipe_integrations, &runtime_values, "pipe.error").await;
}

/// A failed or refused execution: the `new_state` of `pipe.error`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PipeErrorEvent {
    pub pipe_id: String,
    pub pipe_name: String,
    /// The error returned to the caller.
    pub error: String,
    /// The stage that refused or failed the request (`judge`, `jury`,
    /// `prompt_guard_request`, `team_gate`, `usage_limit`, …).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// Machine-readable refusal code of a team-gate or usage-limit block, e.g.
    /// `team_quota_exceeded`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Canonical rejection categories of a content block, with their labels.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<crate::rejection_taxonomy::CategoryDef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Tenant that owns the surface; absent for an appliance-wide surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

impl PipeErrorEvent {
    /// An error on `pipe`, carrying the current request's trace id.
    pub fn new(
        pipe: &PipeConfig,
        error: impl Into<String>,
    ) -> Self {
        Self {
            pipe_id: pipe.id.clone(),
            pipe_name: pipe.name.clone(),
            error: error.into(),
            trace_id: crate::observability::request_context::trace_id(),
            tenant_id: pipe.tenant_id.clone(),
            ..Default::default()
        }
    }

    pub fn at_stage(
        mut self,
        stage: impl Into<String>,
    ) -> Self {
        self.stage = Some(stage.into());
        self
    }

    pub fn with_code(
        mut self,
        code: impl Into<String>,
    ) -> Self {
        self.code = Some(code.into());
        self
    }

    /// Attach canonical rejection-category ids, labelled from the taxonomy.
    pub fn with_categories(
        mut self,
        ids: &[String],
    ) -> Self {
        self.categories = crate::rejection_taxonomy::labelled_categories(ids);
        self
    }
}

/// One evaluated drift dimension, as carried in a drift event's `dimensions`.
/// An unmeasured `baseline` / `current` / `delta` is `null`, never `0`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriftDimensionReport {
    pub id: String,
    pub label: String,
    pub unit: String,
    /// `stable`, `warn`, `drift` or `unknown`.
    pub status: String,
    pub baseline: Option<f64>,
    pub current: Option<f64>,
    pub delta: Option<f64>,
}

/// The evaluation behind a drift event: overall status, window and every dimension.
#[derive(Debug, Clone)]
pub struct DriftEvaluation {
    /// Overall status string (`stable`, `warn`, `drift` or `unknown`).
    pub status: String,
    /// Length of the trailing window the current values were measured over.
    pub window_seconds: i64,
    pub dimensions: Vec<DriftDimensionReport>,
    /// Tenant that owns the surface; absent for an appliance-wide surface.
    pub tenant_id: Option<String>,
}

/// Build the JSON `new_state` shared by `drift.detected` and `drift.resolved`.
fn drift_state_json(
    pipe_id: &str,
    pipe_name: &str,
    eval: &DriftEvaluation,
) -> serde_json::Value {
    let mut state = serde_json::json!({
        "surface_id": pipe_id,
        "surface_name": pipe_name,
        "status": eval.status,
        "window_seconds": eval.window_seconds,
        "dimensions": eval.dimensions,
    });
    if let (Some(tenant), Some(obj)) = (&eval.tenant_id, state.as_object_mut()) {
        obj.insert("tenant_id".into(), serde_json::json!(tenant));
    }
    state
}

/// Trigger integrations when a surface's behaviour drifts past its baseline.
/// Fired by the periodic drift evaluator when a surface enters/stays in drift.
/// `new_state` carries the headline (worst) dimension as `dimension` /
/// `baseline` / `current` / `delta`, plus `status`, `window_seconds` and every
/// evaluated dimension in `dimensions`.
/// When `alert_integration_ids` is set (the surface's Drift Harness selected
/// explicit integrations), the alert fires to exactly those; otherwise it falls
/// back to the surface's own integration mappings for `drift.detected`.
#[allow(clippy::too_many_arguments)]
pub async fn trigger_pipe_drift_detected(
    integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    alert_integration_ids: Option<&[String]>,
    pipe_id: &str,
    pipe_name: &str,
    worst: &DriftDimensionReport,
    eval: &DriftEvaluation,
) {
    let mut runtime_values = HashMap::new();

    let mut drift_state = drift_state_json(pipe_id, pipe_name, eval);
    if let Some(obj) = drift_state.as_object_mut() {
        obj.insert("dimension".into(), serde_json::json!(worst.label));
        obj.insert("baseline".into(), serde_json::json!(worst.baseline));
        obj.insert("current".into(), serde_json::json!(worst.current));
        obj.insert("delta".into(), serde_json::json!(worst.delta));
    }

    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&drift_state).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "drift.detected".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("SURFACE_ID".to_string(), pipe_id.to_string());
    runtime_values.insert("SURFACE_NAME".to_string(), pipe_name.to_string());
    runtime_values.insert("DRIFT_STATUS".to_string(), eval.status.clone());
    runtime_values.insert("DRIFT_DIMENSION".to_string(), worst.label.clone());
    let fmt = |v: Option<f64>| {
        v.map(|x| format!("{x:.4}"))
            .unwrap_or_default()
    };
    runtime_values.insert("DRIFT_BASELINE".to_string(), fmt(worst.baseline));
    runtime_values.insert("DRIFT_CURRENT".to_string(), fmt(worst.current));
    runtime_values.insert("DRIFT_DELTA".to_string(), fmt(worst.delta));

    let mappings = drift_mappings(pipe_integrations, alert_integration_ids, "drift.detected");
    trigger_pipe_integrations(integration_store, &mappings, &runtime_values, "drift.detected").await;
}

/// Resolve which mappings a drift event fires to. An explicit Drift Harness
/// selection wins: a mapping per selected id for `event_type`, so the event
/// fires to exactly those integrations; otherwise the surface's own mappings.
fn drift_mappings(
    pipe_integrations: &[PipeIntegrationMapping],
    alert_integration_ids: Option<&[String]>,
    event_type: &str,
) -> Vec<PipeIntegrationMapping> {
    match alert_integration_ids {
        Some(ids) if !ids.is_empty() => ids
            .iter()
            .map(|id| PipeIntegrationMapping {
                integration_id: id.clone(),
                event_types: vec![event_type.to_string()],
                variables: serde_json::Value::Null,
            })
            .collect(),
        _ => pipe_integrations.to_vec(),
    }
}

/// Trigger integrations when a surface leaves drift (its overall status is no
/// longer `drift`). `new_state` has the same shape as `drift.detected` minus the
/// headline dimension; `status` is the new overall status.
pub async fn trigger_pipe_drift_resolved(
    integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    alert_integration_ids: Option<&[String]>,
    pipe_id: &str,
    pipe_name: &str,
    eval: &DriftEvaluation,
) {
    let mut runtime_values = HashMap::new();
    let state = drift_state_json(pipe_id, pipe_name, eval);

    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&state).unwrap_or_default());
    runtime_values.insert("EVENT_TYPE".to_string(), "drift.resolved".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());
    runtime_values.insert("SURFACE_ID".to_string(), pipe_id.to_string());
    runtime_values.insert("SURFACE_NAME".to_string(), pipe_name.to_string());
    runtime_values.insert("DRIFT_STATUS".to_string(), eval.status.clone());

    let mappings = drift_mappings(pipe_integrations, alert_integration_ids, "drift.resolved");
    trigger_pipe_integrations(integration_store, &mappings, &runtime_values, "drift.resolved").await;
}

/// Trigger integrations when budget threshold is reached
pub async fn trigger_pipe_budget_threshold(
    integration_store: &FileSystemNotificationStore,
    alert: &BudgetAlert,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&alert).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "pipe.budget.threshold_reached".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add budget-specific variables
    runtime_values.insert("SURFACE_ID".to_string(), alert.pipe_id.clone());
    runtime_values.insert("SURFACE_NAME".to_string(), alert.pipe_name.clone());
    runtime_values.insert("MONTH".to_string(), alert.month.clone());
    runtime_values.insert("TOTAL_SPENT_USD".to_string(), format!("{:.2}", alert.total_spent));
    runtime_values.insert("BUDGET_LIMIT_USD".to_string(), format!("{:.2}", alert.budget_limit));
    runtime_values.insert("USAGE_PERCENTAGE".to_string(), format!("{:.1}", alert.usage_percentage));
    runtime_values.insert("REMAINING_BUDGET_USD".to_string(), format!("{:.2}", alert.remaining_budget));
    runtime_values.insert(
        "ALERT_THRESHOLD_PERCENT".to_string(),
        alert
            .alert_threshold_percent
            .to_string(),
    );

    trigger_pipe_integrations(integration_store, &alert.integrations, &runtime_values, "pipe.budget.threshold_reached")
        .await;
}

/// Trigger integrations when budget is exceeded
pub async fn trigger_pipe_budget_exceeded(
    integration_store: &FileSystemNotificationStore,
    alert: &BudgetAlert,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&alert).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "pipe.budget.exceeded".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    // Add budget-specific variables
    runtime_values.insert("SURFACE_ID".to_string(), alert.pipe_id.clone());
    runtime_values.insert("SURFACE_NAME".to_string(), alert.pipe_name.clone());
    runtime_values.insert("MONTH".to_string(), alert.month.clone());
    runtime_values.insert("TOTAL_SPENT_USD".to_string(), format!("{:.2}", alert.total_spent));
    runtime_values.insert("BUDGET_LIMIT_USD".to_string(), format!("{:.2}", alert.budget_limit));
    runtime_values.insert("USAGE_PERCENTAGE".to_string(), format!("{:.1}", alert.usage_percentage));
    runtime_values.insert("OVERSPEND_USD".to_string(), format!("{:.2}", alert.total_spent - alert.budget_limit));

    trigger_pipe_integrations(integration_store, &alert.integrations, &runtime_values, "pipe.budget.exceeded").await;
}

/// Trigger integrations when a usage alert (breach or cost-spike anomaly) trips.
pub async fn trigger_pipe_usage_alert(
    integration_store: &FileSystemNotificationStore,
    event: &UsageAlertEvent,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&event).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), event.event_type.clone());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("SURFACE_ID".to_string(), event.pipe_id.clone());
    runtime_values.insert("SURFACE_NAME".to_string(), event.pipe_name.clone());
    runtime_values.insert("ALERT_TYPE".to_string(), event.alert_type.clone());
    runtime_values.insert("THRESHOLD".to_string(), format!("{:.6}", event.threshold));
    runtime_values.insert("OBSERVED".to_string(), format!("{:.6}", event.observed));
    if let Some(baseline) = event.baseline {
        runtime_values.insert("BASELINE".to_string(), format!("{:.6}", baseline));
    }
    runtime_values.insert("MESSAGE".to_string(), event.message.clone());

    // Synthesize a mapping per notification channel so a channel that is not
    // already an event-matched pipe integration still fires for this event.
    let mut combined: Vec<PipeIntegrationMapping> = event.integrations.clone();
    for channel in &event.channels {
        combined.push(PipeIntegrationMapping {
            integration_id: channel.clone(),
            event_types: vec![event.event_type.clone()],
            variables: serde_json::Value::Null,
        });
    }

    trigger_pipe_integrations(integration_store, &combined, &runtime_values, &event.event_type).await;
}

/// Details of an auto-provisioned member, dispatched to a surface's
/// integrations so operators can be notified the moment a new caller is minted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberProvisionedEvent {
    pub member_id: String,
    pub member_label: String,
    /// The primary identifier the caller was recognised by.
    pub identifier: String,
    pub team_ids: Vec<String>,
    pub team_names: Vec<String>,
}

/// Trigger integrations when a caller is auto-provisioned into a new member.
/// Fired against the originating surface's integrations, so a surface can wire
/// "notify on first-sight member creation" the same way it wires execution
/// events. Fires at most once per caller (first sight only).
pub async fn trigger_member_auto_provisioned(
    integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    event: &MemberProvisionedEvent,
) {
    let mut runtime_values = HashMap::new();

    runtime_values.insert("NEW_STATE".to_string(), serde_json::to_string(&event).unwrap_or_default());
    runtime_values.insert("OLD_STATE".to_string(), String::new());
    runtime_values.insert("EVENT_TYPE".to_string(), "member.auto_provisioned".to_string());
    runtime_values.insert("TIMESTAMP".to_string(), chrono::Utc::now().to_rfc3339());

    runtime_values.insert("MEMBER_ID".to_string(), event.member_id.clone());
    runtime_values.insert("MEMBER_LABEL".to_string(), event.member_label.clone());
    runtime_values.insert("MEMBER_IDENTIFIER".to_string(), event.identifier.clone());
    runtime_values.insert("TEAM_IDS".to_string(), event.team_ids.join(","));
    runtime_values.insert("TEAM_NAMES".to_string(), event.team_names.join(","));

    trigger_pipe_integrations(integration_store, pipe_integrations, &runtime_values, "member.auto_provisioned").await;
}

/// Internal helper to trigger integrations with the 'pipe' category
async fn trigger_pipe_integrations(
    _integration_store: &FileSystemNotificationStore,
    pipe_integrations: &[PipeIntegrationMapping],
    runtime_values: &HashMap<String, String>,
    event_type: &str,
) {
    let pipe_id = runtime_values
        .get("SURFACE_ID")
        .map(|s| s.as_str())
        .unwrap_or("unknown");
    info!("[PIPE:{}] trigger_pipe_integrations called for event_type: {}", pipe_id, event_type);
    info!("[PIPE:{}] Total pipe_integrations passed in: {}", pipe_id, pipe_integrations.len());

    // Get integration storage to load full integration definitions
    let storage = match crate::storage::get_integration_storage() {
        Some(storage) => {
            info!("[PIPE:{}] Integration storage is available", pipe_id);
            storage
        }
        None => {
            warn!(
                "[PIPE:{}] Integration storage not initialized for {}; skipping integration trigger",
                pipe_id, event_type
            );
            return;
        }
    };

    // Filter pipe integrations by event type
    info!("[PIPE:{}] Filtering integrations for event_type: {}", pipe_id, event_type);
    let matching_integrations: Vec<_> = pipe_integrations
        .iter()
        .enumerate()
        .filter_map(|(idx, mapping)| {
            let matches = mapping.event_types.is_empty()
                || mapping
                    .event_types
                    .contains(&event_type.to_string());
            info!(
                "[PIPE:{}] Integration {}: id={}, event_types={:?}, matches={}",
                pipe_id, idx, mapping.integration_id, mapping.event_types, matches
            );
            if matches {
                Some(mapping)
            } else {
                None
            }
        })
        .collect();

    if matching_integrations.is_empty() {
        info!("[PIPE:{}] No pipe integrations configured for event {}", pipe_id, event_type);
        return;
    }

    info!(
        "[PIPE:{}] Found {} pipe integration mappings for event {}",
        pipe_id,
        matching_integrations.len(),
        event_type
    );

    // Trigger each matching integration
    for mapping in matching_integrations {
        info!("[PIPE:{}] Processing integration: {}", pipe_id, mapping.integration_id);

        // Load the full integration definition
        let integration = match storage
            .load(&mapping.integration_id)
            .await
        {
            Ok(integration) => {
                info!(
                    "[PIPE:{}] Loaded integration: {} (type: {}, status: {})",
                    pipe_id, integration.name, integration.integration_type, integration.status
                );
                integration
            }
            Err(e) => {
                error!("[PIPE:{}] Failed to load integration {}: {}", pipe_id, mapping.integration_id, e);
                continue;
            }
        };

        // Check if integration is active
        if integration.status != "active" {
            info!("[PIPE:{}] Skipping inactive integration {}", pipe_id, integration.name);
            continue;
        }

        info!(
            "[PIPE:{}] Triggering pipe integration: {} (type: {}) for event {}",
            pipe_id, integration.name, integration.integration_type, event_type
        );

        // Build subject and message from event
        let subject = format!("Pipe Event: {}", event_type);
        let message = format!("Pipe event '{}' occurred", event_type);

        // Merge runtime variables with mapping-specific variables
        let mut all_variables = runtime_values.clone();

        // Add mapping-specific variables, but substitute any templates first
        // This allows mapping variables to reference runtime values
        if let Some(obj) = mapping.variables.as_object() {
            for (key, value) in obj {
                if let Some(str_value) = value.as_str() {
                    // Substitute variables in the mapping value using runtime values
                    let substituted = crate::integrations::runtime_variables::substitute_variables(
                        str_value,
                        Some("pipe"),
                        runtime_values,
                    );
                    all_variables.insert(key.clone(), substituted);
                }
            }
        }

        // Use the integration trigger service with merged variables
        if let Err(e) = crate::integrations::integration_service::trigger_integration_with_variables(
            &integration.id,
            &subject,
            &message,
            &all_variables,
        )
        .await
        {
            error!(
                "[PIPE:{}] Failed to trigger integration {} for event {}: {}",
                pipe_id, integration.name, event_type, e
            );
        } else {
            info!("[PIPE:{}] Successfully triggered pipe integration: {}", pipe_id, integration.name);
        }
    }
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    use crate::governance::{GovernanceExport, GovernanceRecordingConfig};

    fn webhook_pipe() -> PipeConfig {
        PipeConfig::new(
            "surf-1".to_string(),
            "Support bot".to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        )
    }

    #[test]
    fn created_values_carry_tenant_and_governance_status() {
        let mut pipe = webhook_pipe();
        pipe.tenant_id = Some("tenant-a".to_string());
        pipe.governance_recording = Some(GovernanceRecordingConfig {
            export: Some(GovernanceExport {
                otel: true,
                integrations: vec!["int-1".to_string()],
            }),
            ..Default::default()
        });
        let values = lifecycle_runtime_values("pipe.created", None, Some(&pipe));
        assert_eq!(values["EVENT_TYPE"], "pipe.created");
        assert_eq!(values["SURFACE_ID"], "surf-1");
        assert_eq!(values["SURFACE_TYPE"], "webhook");
        assert_eq!(values["TENANT_ID"], "tenant-a");
        assert_eq!(values["GOVERNANCE_ENABLED"], "true");
        assert_eq!(values["OLD_STATE"], "");
        let new_state: serde_json::Value = serde_json::from_str(&values["NEW_STATE"]).unwrap();
        assert_eq!(new_state["tenant_id"], "tenant-a");
        assert_eq!(new_state["governance_enabled"], true);
        assert_eq!(new_state["governance_export_otel"], true);
        assert_eq!(new_state["governance_export_integrations"], serde_json::json!(["int-1"]));
    }

    #[test]
    fn updated_values_carry_both_states_so_renames_are_visible() {
        let old = webhook_pipe();
        let mut new = webhook_pipe();
        new.name = "Renamed".to_string();
        let values = lifecycle_runtime_values("pipe.updated", Some(&old), Some(&new));
        assert_eq!(values["SURFACE_NAME"], "Renamed");
        let old_state: serde_json::Value = serde_json::from_str(&values["OLD_STATE"]).unwrap();
        let new_state: serde_json::Value = serde_json::from_str(&values["NEW_STATE"]).unwrap();
        assert_eq!(old_state["name"], "Support bot");
        assert_eq!(new_state["name"], "Renamed");
    }

    #[test]
    fn deleted_values_have_empty_new_state_and_no_governance_without_config() {
        let pipe = webhook_pipe();
        let values = lifecycle_runtime_values("pipe.deleted", Some(&pipe), None);
        assert_eq!(values["NEW_STATE"], "");
        assert_eq!(values["GOVERNANCE_ENABLED"], "false");
        assert!(!values.contains_key("TENANT_ID"));
    }

    fn llm_pipe() -> PipeConfig {
        PipeConfig::new(
            "surf-llm".to_string(),
            "Chat".to_string(),
            PipeType::LLM {
                provider: Box::new(
                    serde_json::from_value(serde_json::json!({
                        "type": "openai", "provider_type": "openai", "model": "gpt-4o"
                    }))
                    .unwrap(),
                ),
                endpoint_path: None,
            },
        )
    }

    fn mapping(id: &str) -> PipeIntegrationMapping {
        PipeIntegrationMapping {
            integration_id: id.to_string(),
            event_types: vec!["pipe.created".into(), "pipe.updated".into(), "pipe.deleted".into()],
            variables: serde_json::Value::Null,
        }
    }

    fn with_watch_defaults(pipe: PipeConfig) -> PipeConfig {
        pipe.with_surface_defaults(&crate::pipes::surface_defaults::SurfaceDefaultsConfig {
            governance_recording: true,
            governance_export: GovernanceExport {
                otel: false,
                integrations: vec!["watch-governance".to_string()],
            },
            pipe_integrations: vec![mapping("watch-pipe")],
            ..Default::default()
        })
    }

    fn target_ids(targets: &[PipeIntegrationMapping]) -> Vec<&str> {
        targets
            .iter()
            .map(|m| m.integration_id.as_str())
            .collect()
    }

    #[test]
    fn lifecycle_events_reach_the_default_pipe_integrations_with_the_effective_governance() {
        let (targets, values) = lifecycle_event("pipe.created", None, Some(&llm_pipe()), with_watch_defaults);
        assert_eq!(target_ids(&targets), vec!["watch-pipe"]);
        assert_eq!(values["GOVERNANCE_ENABLED"], "true");
        let new_state: serde_json::Value = serde_json::from_str(&values["NEW_STATE"]).unwrap();
        assert_eq!(new_state["governance_export_integrations"], serde_json::json!(["watch-governance"]));

        let (targets, values) = lifecycle_event("pipe.deleted", Some(&llm_pipe()), None, with_watch_defaults);
        assert_eq!(target_ids(&targets), vec!["watch-pipe"]);
        assert_eq!(values["NEW_STATE"], "");
    }

    #[test]
    fn lifecycle_events_keep_the_surface_own_integrations_beside_the_defaults() {
        let old = llm_pipe();
        let mut new = llm_pipe();
        new.name = "Renamed".to_string();
        new.integrations = vec![mapping("own")];
        let (targets, _) = lifecycle_event("pipe.updated", Some(&old), Some(&new), with_watch_defaults);
        assert_eq!(target_ids(&targets), vec!["own", "watch-pipe"]);
    }

    #[test]
    fn lifecycle_events_without_defaults_reach_only_the_surface_own_integrations() {
        let mut pipe = llm_pipe();
        pipe.integrations = vec![mapping("own")];
        let (targets, values) = lifecycle_event("pipe.created", None, Some(&pipe), |p| p);
        assert_eq!(target_ids(&targets), vec!["own"]);
        assert_eq!(values["GOVERNANCE_ENABLED"], "false");
    }
}

#[cfg(test)]
mod usage_and_drift_event_tests {
    use super::*;

    #[test]
    fn drift_state_lists_every_dimension_with_nulls_for_unknown() {
        let eval = DriftEvaluation {
            status: "warn".to_string(),
            window_seconds: 3600,
            dimensions: vec![
                DriftDimensionReport {
                    id: "latency_ms".into(),
                    label: "Latency".into(),
                    unit: "ms".into(),
                    status: "warn".into(),
                    baseline: Some(1000.0),
                    current: Some(1300.0),
                    delta: Some(300.0),
                },
                DriftDimensionReport {
                    id: "quality".into(),
                    label: "Quality score".into(),
                    unit: "ratio".into(),
                    status: "unknown".into(),
                    baseline: None,
                    current: None,
                    delta: None,
                },
            ],
            tenant_id: None,
        };
        let v = drift_state_json("s1", "Support", &eval);
        assert_eq!(v["status"], "warn");
        assert_eq!(v["window_seconds"], 3600);
        assert_eq!(v["dimensions"][0]["baseline"], 1000.0);
        assert!(v["dimensions"][1]["baseline"].is_null());
        assert!(v["dimensions"][1]["current"].is_null());
        assert!(v.get("tenant_id").is_none(), "an appliance-wide surface has no tenant");

        let owned = DriftEvaluation {
            tenant_id: Some("acme".to_string()),
            ..eval
        };
        assert_eq!(drift_state_json("s1", "Support", &owned)["tenant_id"], "acme");
    }

    #[test]
    fn drift_mappings_prefer_the_selected_integrations_for_the_event() {
        let own = vec![PipeIntegrationMapping {
            integration_id: "own".into(),
            event_types: vec!["drift.detected".into()],
            variables: serde_json::Value::Null,
        }];
        let picked = vec!["picked".to_string()];
        let m = drift_mappings(&own, Some(&picked), "drift.resolved");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].integration_id, "picked");
        assert_eq!(m[0].event_types, vec!["drift.resolved".to_string()]);
        // No explicit selection falls back to the surface's own mappings.
        assert_eq!(drift_mappings(&own, None, "drift.resolved")[0].integration_id, "own");
        assert_eq!(drift_mappings(&own, Some(&[]), "drift.resolved")[0].integration_id, "own");
    }

    #[test]
    fn execution_event_carries_currency_stage_usage_and_record_id() {
        let exec = PipeExecution {
            pipe_id: "s1".into(),
            pipe_name: "S".into(),
            input_tokens: 1,
            output_tokens: 2,
            total_tokens: 3,
            cost: 0.1,
            latency_ms: 5,
            provider: "openai".into(),
            model: "gpt-4o".into(),
            trace_id: "t".into(),
            success: false,
            error_message: Some("stream aborted before completion".into()),
            currency: usd_currency(),
            usage_by_stage: vec![crate::governance::StageUsageEntry {
                stage: "llm".into(),
                provider: Some("openai".into()),
                model: Some("gpt-4o".into()),
                input_tokens: 1,
                output_tokens: 2,
                cost: 0.1,
                ..Default::default()
            }],
            streaming: true,
            record_id: Some("rec-1".into()),
            attribution: Default::default(),
            request_content: None,
            response_content: None,
        };
        let v = serde_json::to_value(&exec).unwrap();
        assert_eq!(v["currency"], "USD");
        assert_eq!(v["streaming"], true);
        assert_eq!(v["success"], false);
        assert_eq!(v["record_id"], "rec-1");
        assert_eq!(v["usage_by_stage"][0]["stage"], "llm");
        // An older event without the new fields still parses.
        let old: PipeExecution = serde_json::from_value(serde_json::json!({
            "pipe_id": "s", "pipe_name": "S", "input_tokens": 0, "output_tokens": 0, "total_tokens": 0,
            "cost": 0.0, "latency_ms": 0, "provider": "", "model": "", "trace_id": "",
            "success": true, "error_message": null
        }))
        .unwrap();
        assert_eq!(old.currency, "USD");
        assert!(!old.streaming && old.record_id.is_none() && old.usage_by_stage.is_empty());
    }
}

#[cfg(test)]
mod error_and_attribution_tests {
    use super::*;

    fn pipe(tenant: Option<&str>) -> PipeConfig {
        let mut pipe = PipeConfig::new(
            "surf-1".to_string(),
            "Support bot".to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        pipe.tenant_id = tenant.map(str::to_string);
        pipe
    }

    #[tokio::test]
    async fn pipe_error_carries_stage_code_categories_trace_and_tenant() {
        use crate::observability::request_context::{RequestContext, scope};
        let ctx = RequestContext {
            trace_id: "trace-1".to_string(),
            ..Default::default()
        };
        let event = scope(ctx, async {
            PipeErrorEvent::new(&pipe(Some("acme")), "{\"error\":{}}")
                .at_stage("judge")
                .with_categories(&["prompt_injection".to_string()])
        })
        .await;
        let v = serde_json::to_value(&event).unwrap();
        assert_eq!(v["pipe_id"], "surf-1");
        assert_eq!(v["pipe_name"], "Support bot");
        assert_eq!(v["error"], "{\"error\":{}}");
        assert_eq!(v["stage"], "judge");
        assert_eq!(v["categories"], serde_json::json!([{"id": "prompt_injection", "label": "Prompt Injection"}]));
        assert_eq!(v["trace_id"], "trace-1");
        assert_eq!(v["tenant_id"], "acme");
        assert!(v.get("code").is_none());

        let gate = PipeErrorEvent::new(&pipe(None), "quota")
            .at_stage("team_gate")
            .with_code("team_quota_exceeded");
        let v = serde_json::to_value(&gate).unwrap();
        assert_eq!(v["code"], "team_quota_exceeded");
        for absent in ["categories", "trace_id", "tenant_id"] {
            assert!(v.get(absent).is_none(), "{absent} is omitted when unknown");
        }
    }

    #[test]
    fn executions_and_alerts_carry_member_teams_and_tenant() {
        let attribution = crate::governance::UsageAttribution {
            member_id: Some("m-1".to_string()),
            team_ids: vec!["t-1".to_string()],
            team_names: vec!["Payments".to_string()],
            tenant_id: Some("acme".to_string()),
        };
        let exec = PipeExecution {
            pipe_id: "s1".into(),
            pipe_name: "S".into(),
            input_tokens: 1,
            output_tokens: 2,
            total_tokens: 3,
            cost: 0.1,
            latency_ms: 5,
            provider: "openai".into(),
            model: "gpt-4o".into(),
            trace_id: "t".into(),
            success: true,
            error_message: None,
            currency: usd_currency(),
            usage_by_stage: Vec::new(),
            streaming: false,
            record_id: None,
            attribution,
            request_content: None,
            response_content: None,
        };
        let v = serde_json::to_value(&exec).unwrap();
        assert_eq!(v["member_id"], "m-1");
        assert_eq!(v["team_ids"], serde_json::json!(["t-1"]));
        assert_eq!(v["team_names"], serde_json::json!(["Payments"]));
        assert_eq!(v["tenant_id"], "acme");
        let back: PipeExecution = serde_json::from_value(v).unwrap();
        assert_eq!(
            back.attribution
                .member_id
                .as_deref(),
            Some("m-1")
        );

        let alert = UsageAlertEvent {
            currency: usd_currency(),
            pipe_id: "s1".into(),
            pipe_name: "S".into(),
            event_type: "pipe.usage_alert".into(),
            alert_type: "error_rate".into(),
            threshold: 0.1,
            observed: 0.5,
            baseline: None,
            message: "m".into(),
            tenant_id: Some("acme".into()),
            channels: Vec::new(),
            integrations: Vec::new(),
        };
        assert_eq!(serde_json::to_value(&alert).unwrap()["tenant_id"], "acme");
    }
}
