//! Structured audit logging for OPA policy decisions.
//!
//! Every policy evaluation point in the request pipeline — pipe front-door,
//! IDE-member model policy, gateway/fabric policy, and surface policy — emits a
//! single structured event through [`record_policy_decision`]. Denials,
//! evaluation errors, and missing-engine outcomes are emitted at `WARN` so they
//! reach the OpenTelemetry log exporter; allows are emitted at `DEBUG` so the
//! allow/deny ratio is observable when the operator opts into a more verbose
//! level, without flooding default-level logs.
//!
//! The event carries the full decision context — trace id, policy scope, policy
//! id/version, a redacted caller-identity summary, workload-binding presence,
//! HTTP method/path, and the route/pipe/surface identifier — so a single log
//! line (or its OTEL counterpart) fully describes the decision.
//!
//! Three sinks are driven from the one entry point:
//!   1. structured `tracing` events (always, for operational observability);
//!   2. Prometheus counters (decision counts + evaluation failures, always);
//!   3. a durable, redacted JSONL audit record — gated by
//!      [`record_policy_decisions_enabled`], the operator opt-in toggle
//!      (defaults off).
//!
//! This module is logging-only: it never alters the response returned to a
//! caller, and it never records request bodies, headers, credentials, tokens,
//! or raw VP material.

/// Whether durable policy-decision recording (the JSONL audit record) is
/// enabled. Reads the live runtime setting (`Settings › Security` →
/// `audit_enabled` + `audit_categories.policies`), so operators can turn
/// auditing on/off from the UI with no restart. Off by
/// default; the structured `policy_audit` tracing events and the Prometheus
/// counters are always emitted regardless, for operational observability.
pub fn record_policy_decisions_enabled() -> bool {
    // Reads a single bool under the settings lock without cloning the whole
    // `DashboardSettings` — this runs on every policy decision (the hot path).
    crate::storage::settings_store::global_audit_category_enabled("policies")
}

/// Caller / HTTP / workload-binding context for a policy decision, extracted
/// from the `PolicyInput` JSON the manager already evaluates. This keeps the
/// extraction at exactly the layer that has the data — no task-local scoping or
/// signature threading required. All fields are redacted summaries
/// (identifiers, not credentials): the `PolicyInput`'s headers are already
/// stripped by [`crate::surface_context::filter_sensitive_headers`].
#[derive(Debug, Clone, Default)]
pub struct InputContext {
    /// Authentication method (`jwt_bearer` | `api_key` | `mtls`).
    pub caller_auth_method: Option<String>,
    /// Caller principal (JWT subject, API-key name, or mTLS principal).
    pub caller_principal: Option<String>,
    /// Caller DID, when the request carried an extension/workload identity.
    pub caller_did: Option<String>,
    /// HTTP method of the request under evaluation.
    pub http_method: Option<String>,
    /// Request path/route under evaluation.
    pub http_path: Option<String>,
    /// Whether workload-binding identity was present for this request.
    pub workload_binding_present: bool,
    /// Id of the routing unit (pipe / surface) the request targets
    /// (`channel.config_id`).
    pub surface_id: Option<String>,
}

/// Extract the redacted caller / HTTP / workload-binding summary from a
/// `PolicyInput` JSON value. Tolerant of missing sub-objects (every field is
/// optional). Never reads bodies, headers, credentials, or tokens.
pub fn extract_input_context(input: &serde_json::Value) -> InputContext {
    let source_auth = input.get("source_auth");
    let caller_auth_method = source_auth
        .and_then(|s| s.get("method"))
        .and_then(|m| m.as_str())
        .map(str::to_string);
    // Principal is the first identifier present across the auth variants.
    let caller_principal = source_auth
        .and_then(|s| {
            ["subject", "key_name", "principal"]
                .iter()
                .find_map(|k| {
                    s.get(*k)
                        .and_then(|v| v.as_str())
                })
        })
        .map(str::to_string);
    let extension_identity = input.get("extension_identity");
    let caller_did = extension_identity
        .and_then(|e| e.get("did"))
        .and_then(|d| d.as_str())
        .map(str::to_string);
    let http = input.get("http");
    let http_method = http
        .and_then(|h| h.get("method"))
        .and_then(|m| m.as_str())
        .map(str::to_string);
    let http_path = http
        .and_then(|h| h.get("path"))
        .and_then(|p| p.as_str())
        .map(str::to_string);
    // Workload binding is "present" when a verified identity-binding context or
    // an extension/workload DID accompanied the request.
    let identity_binding_verified = input
        .get("identity_binding")
        .and_then(|b| b.get("verified"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let workload_binding_present = identity_binding_verified || caller_did.is_some();
    let surface_id = input
        .get("channel")
        .and_then(|c| c.get("config_id"))
        .and_then(|id| id.as_str())
        .map(str::to_string);

    InputContext {
        caller_auth_method,
        caller_principal,
        caller_did,
        http_method,
        http_path,
        workload_binding_present,
        surface_id,
    }
}

tokio::task_local! {
    /// Per-request trace id installable by non-HTTP entry points (e.g. a future
    /// fabric message dispatch, seeded from the inbound message's `trace_id`) so
    /// a request's audit events share a `trace_id` even when no OTEL exporter is
    /// configured. Absent elsewhere (`try_with` errs), in which case the active
    /// OTEL span's trace id is used instead.
    pub static REQUEST_TRACE_ID: String;
}

/// Best-effort trace id for the current request, as a lowercase hex string.
/// Prefers the explicit `REQUEST_TRACE_ID` task-local (set by non-HTTP paths),
/// then falls back to the active OTEL span. `None` when neither is available.
pub fn current_span_trace_id() -> Option<String> {
    if let Some(id) = REQUEST_TRACE_ID
        .try_with(|t| (!t.is_empty()).then(|| t.clone()))
        .ok()
        .flatten()
    {
        return Some(id);
    }
    use opentelemetry::trace::TraceContextExt;
    use tracing_opentelemetry::OpenTelemetrySpanExt;
    let cx = tracing::Span::current().context();
    let span_context = cx
        .span()
        .span_context()
        .clone();
    span_context
        .is_valid()
        .then(|| {
            span_context
                .trace_id()
                .to_string()
        })
}

/// Which policy evaluation point produced a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyScope {
    /// Pipe front-door OPA (inbound pipe / IDE dispatch).
    Pipe,
    /// IDE per-member model policy.
    Ide,
    /// Gateway / fabric OPA (evaluated before surface policy).
    Gateway,
    /// Surface-level OPA.
    #[default]
    Surface,
}

impl PolicyScope {
    /// Stable, low-cardinality label used in the structured event + metrics.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyScope::Pipe => "pipe",
            PolicyScope::Ide => "ide",
            PolicyScope::Gateway => "gateway",
            PolicyScope::Surface => "surface",
        }
    }
}

/// Which request flow a policy decision belongs to, so the audit log can tell
/// ingress from egress. Defaults to [`PolicyFlow::AccessPoint`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyFlow {
    /// Inbound request at the surface's Access Point (direct listener).
    #[default]
    AccessPoint,
    /// Outbound request leaving through a Transit Point (egress). Reserved for
    /// the response/egress-side policy slot, which is compiled but not yet
    /// enforced (documented exception).
    #[allow(dead_code)]
    TransitPoint,
    /// Inbound request received over Fabric (G2G) at a connection point.
    Fabric,
}

impl PolicyFlow {
    /// Stable, low-cardinality label used in the structured event.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyFlow::AccessPoint => "access_point",
            PolicyFlow::TransitPoint => "transit_point",
            PolicyFlow::Fabric => "fabric",
        }
    }
}

/// The outcome of a policy evaluation. Distinguishes a policy-driven deny from
/// an infrastructure failure (evaluation error / missing compiled engine) so
/// operators can alert on evaluation health separately from the allow/deny
/// ratio, and so the configured security posture (fail-open vs fail-closed) is
/// itself auditable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PolicyOutcome {
    /// The policy allowed the request.
    Allow,
    /// The policy denied the request.
    #[default]
    Deny,
    /// The engine returned an evaluation error.
    Error,
    /// No compiled engine existed for an OPA-enabled surface. Whether this
    /// results in an allow (fail-open) or deny (fail-closed) is the caller's
    /// posture; recording it makes that posture auditable.
    MissingEngine,
}

impl PolicyOutcome {
    /// Stable, low-cardinality label used in the structured event + metrics + record.
    pub fn as_str(self) -> &'static str {
        match self {
            PolicyOutcome::Allow => "allow",
            PolicyOutcome::Deny => "deny",
            PolicyOutcome::Error => "error",
            PolicyOutcome::MissingEngine => "missing_engine",
        }
    }

    /// Whether the request was permitted through (drives the WARN/DEBUG split).
    fn is_allow(self) -> bool {
        matches!(self, PolicyOutcome::Allow)
    }

    /// Whether this outcome represents an evaluation failure (for the failures counter).
    fn is_failure(self) -> bool {
        matches!(self, PolicyOutcome::Error | PolicyOutcome::MissingEngine)
    }
}

/// A single policy decision to be recorded. Optional fields are tolerated so
/// the same shape works at every evaluation point regardless of how much
/// context has been resolved by the time the decision is made.
#[derive(Debug, Default)]
pub struct PolicyDecisionEvent<'a> {
    /// Which evaluation point produced the decision.
    pub scope: PolicyScope,
    /// The evaluation outcome (allow / deny / error / missing-engine). For a
    /// missing-engine outcome the reason should note the caller's posture
    /// (fail-open allow vs fail-closed deny) so the disposition is auditable.
    pub outcome: PolicyOutcome,
    /// Human-readable reason (deny reason, evaluation error, missing-engine note).
    pub reason: Option<&'a str>,
    /// Policy identifier — the evaluated Rego query path (e.g. `data.llm.policy.allow`).
    pub policy_id: Option<&'a str>,
    /// The stored policy-definition record id, when the policy is backed by a definition.
    pub policy_definition_id: Option<&'a str>,
    /// Policy-definition version — the monotonic revision number in force at
    /// decision time (see `PolicyVersion::version`).
    pub policy_version: Option<&'a str>,
    /// Content hash (`sha256:<hex>`) of the enforced revision — makes the
    /// decision reproducible against exact Rego bytes.
    pub policy_content_hash: Option<&'a str>,
    /// Human-readable policy name (operator-assigned). Falls back to `policy_id`.
    pub policy_name: Option<&'a str>,
    /// Route/pipe/surface identifier the decision applies to.
    pub surface_id: Option<&'a str>,
    /// Key of the compiled surface-policy engine that decided: `{pipe_id}`,
    /// `{pipe_id}${alias}`, `{ide}#ide-member:{model}` or `global:{type}`.
    pub policy_key: Option<&'a str>,
    /// Per-request trace identifier for log/trace correlation.
    pub trace_id: Option<&'a str>,
    /// HTTP method of the request under evaluation.
    pub http_method: Option<&'a str>,
    /// Request path/route under evaluation.
    pub path: Option<&'a str>,
    /// Redacted caller authentication method (`jwt_bearer` | `api_key` | `mtls`).
    pub caller_auth_method: Option<&'a str>,
    /// Redacted caller principal (JWT subject / API-key name / mTLS principal).
    pub caller_principal: Option<&'a str>,
    /// Resolved/derived caller DID for the request, when available.
    pub caller_did: Option<&'a str>,
    /// Identifier (or DID) of the gateway making the decision.
    pub gateway_did: Option<&'a str>,
    /// Whether workload-binding identity was present for this request.
    pub workload_binding_present: bool,
    /// Which request flow produced the decision. Defaults to `AccessPoint`.
    pub flow: PolicyFlow,
}

/// Emit one structured event describing a policy decision, drive the Prometheus
/// counters, and — when recording is enabled — write the durable JSONL record.
///
/// Denials / errors / missing-engine outcomes are logged at `WARN` (reaching
/// the OTEL log exporter); allows at `DEBUG`. The event is emitted within the
/// active request span, so it is correlated to the distributed trace.
pub fn record_policy_decision(event: PolicyDecisionEvent<'_>) {
    let auth_method = event
        .caller_auth_method
        .unwrap_or("none");
    let principal = event
        .caller_principal
        .unwrap_or_default();
    let caller_did = event
        .caller_did
        .unwrap_or_default();

    let decision = event.outcome.as_str();
    let scope = event.scope.as_str();
    let flow = event.flow.as_str();
    let reason = event
        .reason
        .unwrap_or_default();
    let policy_id = event
        .policy_id
        .unwrap_or_default();
    let policy_definition_id = event
        .policy_definition_id
        .unwrap_or_default();
    let policy_version = event
        .policy_version
        .unwrap_or_default();
    let policy_content_hash = event
        .policy_content_hash
        .unwrap_or_default();
    let surface_id = event
        .surface_id
        .unwrap_or_default();
    let policy_name = event
        .policy_name
        .unwrap_or(policy_id);
    // Fall back to the active span's OTEL trace id when the caller didn't set
    // one, so every decision for a request shares a `trace_id`.
    let resolved_trace_id: Option<String> = event
        .trace_id
        .map(str::to_string)
        .or_else(current_span_trace_id);
    let trace_id = resolved_trace_id
        .as_deref()
        .unwrap_or_default();
    let http_method = event
        .http_method
        .unwrap_or_default();
    let path = event.path.unwrap_or_default();
    let gateway_did = event
        .gateway_did
        .unwrap_or_default();

    if event.outcome.is_allow() {
        tracing::debug!(
            target: "policy_audit",
            policy_scope = scope,
            policy_flow = flow,
            policy_decision = decision,
            policy_id = policy_id,
            policy_name = policy_name,
            policy_definition_id = policy_definition_id,
            policy_version = policy_version,
            policy_content_hash = policy_content_hash,
            deny_reason = reason,
            surface_id = surface_id,
            gateway_did = gateway_did,
            caller_auth_method = auth_method,
            caller_principal = principal,
            caller_did = caller_did,
            workload_binding_present = event.workload_binding_present,
            http_method = http_method,
            http_path = path,
            trace_id = trace_id,
            "policy decision: allow"
        );
    } else {
        tracing::warn!(
            target: "policy_audit",
            policy_scope = scope,
            policy_flow = flow,
            policy_decision = decision,
            policy_id = policy_id,
            policy_name = policy_name,
            policy_definition_id = policy_definition_id,
            policy_version = policy_version,
            policy_content_hash = policy_content_hash,
            deny_reason = reason,
            surface_id = surface_id,
            gateway_did = gateway_did,
            caller_auth_method = auth_method,
            caller_principal = principal,
            caller_did = caller_did,
            workload_binding_present = event.workload_binding_present,
            http_method = http_method,
            http_path = path,
            trace_id = trace_id,
            "policy decision: {}",
            decision
        );
    }

    // Metrics: every decision counts; failures (engine error / missing engine)
    // are also broken out so operators can alert on evaluation health.
    crate::metrics::backends::prometheus::POLICY_DECISIONS
        .with_label_values(&[scope, decision])
        .inc();
    if event.outcome.is_failure() {
        crate::metrics::backends::prometheus::POLICY_EVALUATION_FAILURES
            .with_label_values(&[scope])
            .inc();
    }

    // The deny reason is meaningful on any non-allow outcome.
    let deny_reason_opt = if event.outcome.is_allow() || reason.is_empty() {
        None
    } else {
        Some(reason)
    };

    // Durable JSONL record — gated by the operator opt-in toggle.
    if record_policy_decisions_enabled() {
        crate::delegation_vault::audit::audit_policy_decision(
            scope,
            decision,
            policy_id,
            event.policy_name,
            event.policy_definition_id,
            event.policy_version,
            event.policy_content_hash,
            deny_reason_opt,
            (!surface_id.is_empty()).then_some(surface_id),
            event.policy_key,
            (!caller_did.is_empty()).then_some(caller_did),
            (auth_method != "none").then_some(auth_method),
            (!principal.is_empty()).then_some(principal),
            event.workload_binding_present,
            (!http_method.is_empty()).then_some(http_method),
            (!path.is_empty()).then_some(path),
            resolved_trace_id.as_deref(),
            flow,
        );
    }
}

/// Manager-facing entry point: record a policy decision, merging the policy
/// metadata + outcome (known to the policy manager) with the caller / HTTP /
/// workload-binding [`InputContext`] the manager extracted from the request's
/// `PolicyInput` (via [`extract_input_context`]). This keeps the `evaluate`
/// method signatures unchanged and needs no task-local scoping — the manager
/// simply calls this at each decision point with what it already holds.
#[allow(clippy::too_many_arguments)]
pub fn record_decision(
    scope: PolicyScope,
    flow: PolicyFlow,
    outcome: PolicyOutcome,
    reason: Option<&str>,
    policy_id: &str,
    policy_definition_id: Option<&str>,
    policy_version: Option<&str>,
    policy_content_hash: Option<&str>,
    policy_name: Option<&str>,
    surface_id: Option<&str>,
    policy_key: Option<&str>,
    ctx: &InputContext,
) {
    record_policy_decision(PolicyDecisionEvent {
        scope,
        outcome,
        reason,
        policy_id: (!policy_id.is_empty()).then_some(policy_id),
        policy_definition_id,
        policy_version,
        policy_content_hash,
        policy_name,
        surface_id,
        policy_key,
        trace_id: None,
        http_method: ctx.http_method.as_deref(),
        path: ctx.http_path.as_deref(),
        caller_auth_method: ctx
            .caller_auth_method
            .as_deref(),
        caller_principal: ctx
            .caller_principal
            .as_deref(),
        caller_did: ctx.caller_did.as_deref(),
        gateway_did: None,
        workload_binding_present: ctx.workload_binding_present,
        flow,
    });
}

/// A policy-decision event captured from the `policy_audit` tracing target, for
/// test assertions on the real emitted output.
#[cfg(test)]
pub(crate) struct CapturedDecision {
    pub level: String,
    pub scope: String,
    pub flow: String,
    pub decision: String,
    pub policy_name: Option<String>,
    pub policy_version: Option<String>,
    pub policy_definition_id: Option<String>,
    pub deny_reason: Option<String>,
    pub caller_auth_method: Option<String>,
    pub http_method: Option<String>,
}

/// Run `f` with a subscriber that captures `policy_audit` decision events, and
/// return them. Used across the policy-manager test modules to assert that each
/// enforcement path emits the expected decision evidence.
#[cfg(test)]
pub(crate) fn capture_decisions<F: FnOnce()>(f: F) -> Vec<CapturedDecision> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    use tracing::field::{Field, Visit};
    use tracing_subscriber::Layer;
    use tracing_subscriber::layer::{Context, SubscriberExt};

    // Install a process-global TRACE-level no-op subscriber ONCE so every
    // `policy_audit` callsite registers as enabled process-wide. Without it, a
    // DEBUG-level `allow` event's callsite can be cached as disabled by a
    // concurrent test running under no subscriber and then dropped — making
    // capture-based tests flaky (or deterministically short) under parallel
    // execution. The thread-local capture below layers on top and reliably
    // observes every event.
    static GLOBAL: OnceLock<()> = OnceLock::new();
    GLOBAL.get_or_init(|| {
        use tracing_subscriber::filter::LevelFilter;
        let _ = tracing::subscriber::set_global_default(tracing_subscriber::registry().with(LevelFilter::TRACE));
    });

    // Serialize capture-based tests: `with_default` is thread-scoped, but
    // tracing's callsite interest cache is process-global, so two concurrent
    // captures can race and drop events. A process-wide lock keeps captures
    // deterministic under parallel test execution.
    static CAPTURE_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    let _capture_guard = CAPTURE_LOCK
        .get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    #[derive(Default)]
    struct Fields(HashMap<String, String>);
    impl Visit for Fields {
        fn record_debug(
            &mut self,
            field: &Field,
            value: &dyn std::fmt::Debug,
        ) {
            self.0
                .insert(field.name().to_string(), format!("{:?}", value));
        }
        fn record_str(
            &mut self,
            field: &Field,
            value: &str,
        ) {
            self.0
                .insert(field.name().to_string(), value.to_string());
        }
        fn record_bool(
            &mut self,
            field: &Field,
            value: bool,
        ) {
            self.0
                .insert(field.name().to_string(), value.to_string());
        }
    }

    type Captured = (String, HashMap<String, String>);
    struct CapLayer(Arc<Mutex<Vec<Captured>>>);
    impl<S: tracing::Subscriber> Layer<S> for CapLayer {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: Context<'_, S>,
        ) {
            if event.metadata().target() != "policy_audit" {
                return;
            }
            let mut fields = Fields::default();
            event.record(&mut fields);
            self.0.lock().unwrap().push((
                event
                    .metadata()
                    .level()
                    .to_string(),
                fields.0,
            ));
        }
    }

    let store: Arc<Mutex<Vec<Captured>>> = Arc::new(Mutex::new(Vec::new()));
    let subscriber = tracing_subscriber::registry().with(CapLayer(store.clone()));
    tracing::subscriber::with_default(subscriber, f);

    let opt = |m: &HashMap<String, String>, k: &str| {
        m.get(k)
            .filter(|s| !s.is_empty())
            .cloned()
    };
    store
        .lock()
        .unwrap()
        .iter()
        .map(|(level, m)| CapturedDecision {
            level: level.clone(),
            scope: m
                .get("policy_scope")
                .cloned()
                .unwrap_or_default(),
            flow: m
                .get("policy_flow")
                .cloned()
                .unwrap_or_default(),
            decision: m
                .get("policy_decision")
                .cloned()
                .unwrap_or_default(),
            policy_name: opt(m, "policy_name"),
            policy_version: opt(m, "policy_version"),
            policy_definition_id: opt(m, "policy_definition_id"),
            deny_reason: opt(m, "deny_reason"),
            caller_auth_method: opt(m, "caller_auth_method"),
            http_method: opt(m, "http_method"),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_and_outcome_labels_are_stable() {
        assert_eq!(PolicyScope::Pipe.as_str(), "pipe");
        assert_eq!(PolicyScope::Ide.as_str(), "ide");
        assert_eq!(PolicyScope::Gateway.as_str(), "gateway");
        assert_eq!(PolicyScope::Surface.as_str(), "surface");
        assert_eq!(PolicyOutcome::Allow.as_str(), "allow");
        assert_eq!(PolicyOutcome::Deny.as_str(), "deny");
        assert_eq!(PolicyOutcome::Error.as_str(), "error");
        assert_eq!(PolicyOutcome::MissingEngine.as_str(), "missing_engine");
    }

    #[test]
    fn extract_input_context_reads_caller_http_and_binding() {
        // JWT caller with http context and a workload/extension DID.
        let input = serde_json::json!({
            "http": { "method": "POST", "path": "/v1/chat/completions" },
            "source_auth": { "method": "jwt_bearer", "subject": "sub-123", "claims": {} },
            "extension_identity": { "did": "did:web:caller" },
        });
        let ctx = extract_input_context(&input);
        assert_eq!(
            ctx.caller_auth_method
                .as_deref(),
            Some("jwt_bearer")
        );
        assert_eq!(
            ctx.caller_principal
                .as_deref(),
            Some("sub-123")
        );
        assert_eq!(ctx.caller_did.as_deref(), Some("did:web:caller"));
        assert_eq!(ctx.http_method.as_deref(), Some("POST"));
        assert_eq!(ctx.http_path.as_deref(), Some("/v1/chat/completions"));
        // A caller DID implies workload binding is present.
        assert!(ctx.workload_binding_present);

        // API-key caller, no DID → principal from key_name, no workload binding.
        let api = serde_json::json!({
            "source_auth": { "method": "api_key", "key_name": "key-a" },
        });
        let ctx = extract_input_context(&api);
        assert_eq!(
            ctx.caller_auth_method
                .as_deref(),
            Some("api_key")
        );
        assert_eq!(
            ctx.caller_principal
                .as_deref(),
            Some("key-a")
        );
        assert!(ctx.caller_did.is_none());
        assert!(!ctx.workload_binding_present);

        // Empty input → all-None, no panic.
        let ctx = extract_input_context(&serde_json::json!({}));
        assert!(
            ctx.caller_auth_method
                .is_none()
        );
        assert!(!ctx.workload_binding_present);
        assert!(ctx.surface_id.is_none());
    }

    #[test]
    fn extract_input_context_reads_the_targeted_surface() {
        let input = serde_json::json!({ "channel": { "config_id": "pipe-1", "name": "Support" } });
        assert_eq!(
            extract_input_context(&input)
                .surface_id
                .as_deref(),
            Some("pipe-1")
        );
    }

    #[test]
    fn record_decision_does_not_panic_with_minimal_context() {
        record_policy_decision(PolicyDecisionEvent {
            scope: PolicyScope::Gateway,
            outcome: PolicyOutcome::Deny,
            reason: Some("blocked"),
            ..Default::default()
        });
        record_policy_decision(PolicyDecisionEvent {
            scope: PolicyScope::Surface,
            outcome: PolicyOutcome::Allow,
            ..Default::default()
        });
    }

    #[test]
    fn record_decisions_disabled_without_global_settings() {
        // In a unit-test process no global settings store is registered, so the
        // gate is closed (auditing off by default until Settings enables it).
        assert!(!record_policy_decisions_enabled());
    }

    #[test]
    fn capture_observes_emitted_decision_event() {
        let decisions = capture_decisions(|| {
            record_decision(
                PolicyScope::Surface,
                PolicyFlow::AccessPoint,
                PolicyOutcome::Deny,
                Some("trust check failed"),
                "data.channel.policy.allow",
                Some("def-7"),
                Some("2026-08-01T00:00:00Z"),
                Some("sha256:deadbeef"),
                Some("My Surface Policy"),
                Some("surface-a"),
                None,
                &InputContext {
                    caller_auth_method: Some("api_key".to_string()),
                    caller_principal: Some("alpha".to_string()),
                    http_method: Some("POST".to_string()),
                    ..Default::default()
                },
            );
        });
        assert_eq!(decisions.len(), 1);
        let d = &decisions[0];
        assert_eq!(d.level, "WARN");
        assert_eq!(d.scope, "surface");
        assert_eq!(d.flow, "access_point");
        assert_eq!(d.decision, "deny");
        assert_eq!(d.policy_name.as_deref(), Some("My Surface Policy"));
        assert_eq!(d.policy_version.as_deref(), Some("2026-08-01T00:00:00Z"));
        assert_eq!(
            d.policy_definition_id
                .as_deref(),
            Some("def-7")
        );
        assert_eq!(d.deny_reason.as_deref(), Some("trust check failed"));
        assert_eq!(
            d.caller_auth_method
                .as_deref(),
            Some("api_key")
        );
        assert_eq!(d.http_method.as_deref(), Some("POST"));
    }

    #[test]
    fn allow_is_debug_deny_and_error_are_warn() {
        let decisions = capture_decisions(|| {
            record_decision(
                PolicyScope::Pipe,
                PolicyFlow::AccessPoint,
                PolicyOutcome::Allow,
                None,
                "data.llm.policy.allow",
                None,
                None,
                None,
                None,
                Some("p1"),
                None,
                &InputContext::default(),
            );
            record_decision(
                PolicyScope::Pipe,
                PolicyFlow::AccessPoint,
                PolicyOutcome::Error,
                Some("boom"),
                "data.llm.policy.allow",
                None,
                None,
                None,
                None,
                Some("p1"),
                None,
                &InputContext::default(),
            );
        });
        assert_eq!(decisions.len(), 2);
        assert_eq!(decisions[0].decision, "allow");
        assert_eq!(decisions[0].level, "DEBUG");
        assert_eq!(decisions[1].decision, "error");
        assert_eq!(decisions[1].level, "WARN");
    }
}
