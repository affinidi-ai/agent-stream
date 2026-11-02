//! Delegation vault audit logger
//!
//! Writes structured JSONL events to a dedicated audit log file for every
//! credential delegation operation: consent granted, token injected, token refreshed,
//! token revoked, consent required, and audit-control changes. This provides an
//! append-only local audit trail separate from the general application logs. Audit
//! events may also be forwarded to a central logging platform for independent retention.
//!
//! The audit file rotates daily and is written under `{log_directory}/delegation-audit.jsonl`
//! or `_storage/audit/delegation-audit.jsonl` if no log directory is configured.

use chrono::Utc;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use tokio::sync::mpsc;
use tracing::{error, info, warn};

tokio::task_local! {
    /// Per-task buffer that intercepts audit events while the request handler
    /// is still computing the canonical workload-binding VP. The handler
    /// installs this via [`AUDIT_DEFER_QUEUE::scope`] around
    /// `resolve_delegation_credentials`, then drains the queue and re-stamps
    /// each event with the final VP (carrying `delegationAction`) before
    /// flushing to the audit sink.
    pub static AUDIT_DEFER_QUEUE: Arc<Mutex<Vec<DelegationAuditEvent>>>;
}

/// Global audit sender — events are sent to a background writer task
static AUDIT_SENDER: OnceLock<mpsc::UnboundedSender<DelegationAuditEvent>> = OnceLock::new();

/// Global audit file path — for reading the log
static AUDIT_PATH: OnceLock<PathBuf> = OnceLock::new();

/// When true, identity-binding VP injection events (the channel's own
/// AgentIdentityCredential VP added to requests/responses) are recorded in
/// the credential audit log. Defaults to false.
static AUDIT_IDENTITY_BINDING_VP: AtomicBool = AtomicBool::new(false);

/// A delegation vault audit event
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DelegationAuditEvent {
    /// ISO-8601 timestamp
    pub timestamp: String,
    /// The type of audit event
    pub event: DelegationAuditAction,
    /// Agent endpoint used as vault namespace key (equals target_endpoint)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_did: Option<String>,
    /// Actual DID identity of the agent (e.g. did:webvh:...)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent_identity_did: Option<String>,
    /// Peppered hash of the user's identity.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_identity_hash: Option<String>,
    /// Credential provider ID (machine-readable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
    /// Human-readable provider name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider_name: Option<String>,
    /// Channel config ID where the action originated
    #[serde(skip_serializing_if = "Option::is_none")]
    pub surface_id: Option<String>,
    /// Human-readable channel name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub channel_name: Option<String>,
    /// Target endpoint the channel proxies to
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_endpoint: Option<String>,
    /// Protocol of the channel (a2a, mcp, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// OAuth scopes involved
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Delegation token ID (for token-specific events)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_id: Option<String>,
    /// How the credential was injected (bearer_header, custom_header, meta)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inject_as: Option<String>,
    /// Whether the operation traversed the fabric (G2G)
    #[serde(default)]
    pub via_fabric: bool,
    /// MCP tool name (if this was an MCP tool call)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mcp_tool_name: Option<String>,
    /// VP JWT injected into the upstream response (if identity VP was sent)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_jwt: Option<String>,
    /// SHA-256 fingerprint of the VP JWT for correlation without displaying raw evidence
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vp_fingerprint: Option<String>,
    /// Request trace ID — correlates all audit events for the same request
    /// (policy decisions, VP injection, credential delegation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Tenant that owns the surface the record was written for; absent for an
    /// appliance-wide surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// Additional context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Serde default for `PolicyDecision.flow` so pre-existing audit entries (all of
/// which were access-point/ingress decisions) deserialize correctly.
fn default_policy_flow() -> String {
    "access_point".to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct AuditConfigurationState {
    pub enabled: bool,
    pub policies: bool,
    pub trust_checks: bool,
    pub identity: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditConfigurationOperation {
    Update,
    Reset,
}

impl AuditConfigurationOperation {
    fn as_str(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::Reset => "reset",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditConfigurationOutcome {
    Succeeded,
    PersistenceFailed,
}

impl AuditConfigurationOutcome {
    fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::PersistenceFailed => "persistence_failed",
        }
    }
}

/// The type of delegation audit action
// The `PolicyDecision` variant is intentionally larger than the unit variants:
// it is the durable evidence record and its externally-tagged JSON shape is a
// wire contract, so boxing it to equalize variant sizes
// would change serialization for no runtime benefit — audit events are not a
// hot allocation path.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DelegationAuditAction {
    /// User granted OAuth consent — token stored in vault
    ConsentGranted,
    /// A cached token was injected into an outbound request
    TokenInjected,
    /// An expired token was refreshed and injected
    TokenRefreshed,
    /// Token refresh failed — consent required again
    RefreshFailed,
    /// A consent_required signal was returned to the caller
    ConsentRequired,
    /// A token was revoked via management API
    TokenRevoked,
    /// All tokens for a user were revoked
    UserTokensRevoked,
    /// Token lookup found no match
    TokenNotFound,
    /// A Verifiable Presentation was injected into the response
    VpInjected,
    /// An MCP `elicitation/create` request was sent to the client
    ElicitationSent,
    /// Client returned `action: "accept"` on the elicitation
    ElicitationAccepted,
    /// Client returned `action: "decline"`
    ElicitationDeclined,
    /// Client returned `action: "cancel"`
    ElicitationCancelled,
    /// No response within `elicit_timeout_secs`
    ElicitationTimedOut,
    /// `consent_mode = pre_authorize` blocked a session/bind because at least
    /// one required credential was missing
    PreAuthorizeBlocked,
    /// An administrator changed the runtime policy-audit recording controls.
    AuditConfigurationChanged {
        actor_id: String,
        operation: AuditConfigurationOperation,
        outcome: AuditConfigurationOutcome,
        previous: AuditConfigurationState,
        requested: AuditConfigurationState,
    },
    /// An OPA policy decision (allow / deny / evaluation-error / missing-engine)
    /// at one of the enforcement points (pipe, IDE-member, gateway, surface).
    ///
    /// This is the durable, redacted evidence record for a policy decision. It
    /// records *which* policy version governed the request, *why* it was
    /// allowed/denied, a redacted caller-identity summary, whether workload
    /// binding was present, and the correlating trace ID — never request
    /// bodies, headers, credentials, tokens, or raw VP material.
    PolicyDecision {
        /// Evaluation point: `pipe` | `ide` | `gateway` | `surface`.
        scope: String,
        /// Which request flow produced the decision: `access_point` |
        /// `transit_point` | `fabric`.
        #[serde(default = "default_policy_flow")]
        flow: String,
        /// Policy/definition identifier — the Rego query package the decision
        /// was evaluated against (e.g. `data.llm.policy.allow`).
        policy_id: String,
        /// Resolved human-readable policy name (operator-assigned definition
        /// name); falls back to `policy_id` when unset.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_name: Option<String>,
        /// Stored policy-definition record id, when the policy is backed by a
        /// definition — links the entry to the policy record.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_definition_id: Option<String>,
        /// Policy-definition version — the monotonic revision number in force at
        /// decision time, so operators can prove which revision was enforced.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_version: Option<String>,
        /// Content hash (`sha256:<hex>`) of the enforced revision — makes the
        /// decision reproducible against exact Rego bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_content_hash: Option<String>,
        /// `allow` | `deny` | `error` | `missing_engine`.
        decision: String,
        /// Human-readable reason (deny reason, evaluation error, or missing-engine note).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        deny_reason: Option<String>,
        /// Route/pipe/surface identifier the decision applies to.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        surface_id: Option<String>,
        /// Key of the compiled surface-policy engine that decided: the pipe id,
        /// `{pipe_id}${alias}`, `{ide}#ide-member:{model}` or `global:{type}`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_key: Option<String>,
        /// Caller DID, when the caller identity resolved to one.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_did: Option<String>,
        /// Redacted caller-identity summary: authentication method
        /// (`jwt_bearer` | `api_key` | `mtls`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_auth_method: Option<String>,
        /// Redacted caller-identity summary: the caller principal (JWT subject,
        /// API-key name, or mTLS principal) — an identifier, never a credential.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        caller_principal: Option<String>,
        /// Whether workload-binding identity was present for this request.
        #[serde(default)]
        workload_binding_present: bool,
        /// HTTP method of the request under evaluation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_method: Option<String>,
        /// Request path/route under evaluation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        http_path: Option<String>,
    },
}

impl DelegationAuditAction {
    /// Whether this action belongs only to the unified Audit view rather than
    /// the Credential Delegation Audit view. The delegation view filters policy
    /// decisions and audit-control changes out.
    pub fn is_vp_audit(&self) -> bool {
        matches!(self, Self::PolicyDecision { .. } | Self::AuditConfigurationChanged { .. })
    }
}

pub fn vp_fingerprint(vp_jwt: &str) -> String {
    let hash = Sha256::digest(vp_jwt.as_bytes());
    format!("sha256:{}", hex::encode(hash))
}

impl DelegationAuditEvent {
    pub fn set_vp_jwt(
        &mut self,
        vp_jwt: String,
    ) {
        self.vp_fingerprint = Some(vp_fingerprint(&vp_jwt));
        self.vp_jwt = Some(vp_jwt);
    }
}

/// Initialize the audit logger with the given log directory.
///
/// Spawns a background task that writes events as JSONL to the audit file.
/// Call once at startup from the orchestrator.
pub fn init_audit_logger(
    log_directory: Option<&str>,
    audit_identity_binding_vp: bool,
) {
    AUDIT_IDENTITY_BINDING_VP.store(audit_identity_binding_vp, Ordering::Relaxed);
    let dir = log_directory
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("_storage/audit"));

    // Ensure directory exists
    if let Err(e) = std::fs::create_dir_all(&dir) {
        error!(
            target: "credential_delegation",
            path = %dir.display(),
            error = %e,
            "Failed to create delegation audit log directory"
        );
        return;
    }

    let (tx, rx) = mpsc::unbounded_channel();

    if AUDIT_SENDER.set(tx).is_err() {
        warn!(target: "credential_delegation", "Delegation audit logger already initialized");
        return;
    }

    let audit_path = dir.join("delegation-audit.jsonl");
    let _ = AUDIT_PATH.set(audit_path.clone());
    info!(
        target: "credential_delegation",
        path = %audit_path.display(),
        "Delegation audit logger initialized"
    );

    tokio::spawn(audit_writer_task(audit_path, rx, crate::integrations::audit_integration_triggers::forward));
}

/// Background task that receives audit events, appends them to the JSONL file,
/// and hands each persisted event to `on_persisted`.
async fn audit_writer_task(
    path: PathBuf,
    mut rx: mpsc::UnboundedReceiver<DelegationAuditEvent>,
    on_persisted: impl Fn(DelegationAuditEvent),
) {
    use tokio::fs::OpenOptions;
    use tokio::io::AsyncWriteExt;

    // Open once and keep the handle alive for all writes; avoid per-event
    // open/close overhead and the flush race that causes the last write to be
    // invisible when the file handle is dropped before the OS flushes it.
    let mut file = match OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .await
    {
        Ok(f) => f,
        Err(e) => {
            error!(
                target: "credential_delegation",
                path = %path.display(),
                error = %e,
                "Failed to open delegation audit log"
            );
            return;
        }
    };

    while let Some(event) = rx.recv().await {
        let line = match serde_json::to_string(&event) {
            Ok(json) => format!("{}\n", json),
            Err(e) => {
                error!(
                    target: "credential_delegation",
                    error = %e,
                    "Failed to serialize audit event"
                );
                continue;
            }
        };

        // A tokio `File` finishes a write on the blocking pool and can report
        // its error (a full disk) only on flush, so an event counts as
        // persisted once the flush succeeds.
        match async {
            file.write_all(line.as_bytes())
                .await?;
            file.flush().await
        }
        .await
        {
            Ok(()) => on_persisted(event),
            Err(e) => {
                error!(
                    target: "credential_delegation",
                    error = %e,
                    "Failed to write delegation audit event"
                );
            }
        }
    }
}

/// Emit an audit event. Non-blocking; returns immediately.
///
/// If a task-local [`AUDIT_DEFER_QUEUE`] is installed in the current task,
/// the event is buffered there instead of being sent to the writer. The
/// caller (typically the proxy request handler) is responsible for draining
/// the queue once it has minted the canonical workload-binding VP and
/// stamping `vp_jwt` on every event before invoking [`audit`] again — which
/// will then emit directly because the drain happens outside the
/// `task_local!` scope.
pub fn try_audit(event: DelegationAuditEvent) -> anyhow::Result<()> {
    if let Ok(queue) = AUDIT_DEFER_QUEUE.try_with(|q| q.clone())
        && let Ok(mut guard) = queue.lock()
    {
        guard.push(event);
        return Ok(());
    }

    let sender = AUDIT_SENDER
        .get()
        .ok_or_else(|| anyhow::anyhow!("audit logger is not initialized"))?;
    sender
        .send(event)
        .map_err(|_| anyhow::anyhow!("audit channel is closed"))
}

pub fn audit(event: DelegationAuditEvent) {
    if let Ok(queue) = AUDIT_DEFER_QUEUE.try_with(|q| q.clone())
        && let Ok(mut guard) = queue.lock()
    {
        guard.push(event);
        return;
    }
    if let Some(sender) = AUDIT_SENDER.get()
        && sender.send(event).is_err()
    {
        warn!(
            target: "credential_delegation",
            "Delegation audit channel closed — event dropped"
        );
    }
}

pub fn record_audit_configuration_change(
    actor_id: &str,
    operation: AuditConfigurationOperation,
    outcome: AuditConfigurationOutcome,
    previous: AuditConfigurationState,
    requested: AuditConfigurationState,
    trace_id: Option<String>,
) -> anyhow::Result<()> {
    warn!(
        target: "audit_control",
        actor_id = %actor_id,
        operation = operation.as_str(),
        outcome = outcome.as_str(),
        trace_id = trace_id.as_deref().unwrap_or(""),
        previous_enabled = previous.enabled,
        previous_policies = previous.policies,
        previous_trust_checks = previous.trust_checks,
        previous_identity = previous.identity,
        requested_enabled = requested.enabled,
        requested_policies = requested.policies,
        requested_trust_checks = requested.trust_checks,
        requested_identity = requested.identity,
        "Audit recording configuration changed"
    );

    try_audit(audit_configuration_event(actor_id, operation, outcome, previous, requested, trace_id))
}

pub fn audit_configuration_event(
    actor_id: &str,
    operation: AuditConfigurationOperation,
    outcome: AuditConfigurationOutcome,
    previous: AuditConfigurationState,
    requested: AuditConfigurationState,
    trace_id: Option<String>,
) -> DelegationAuditEvent {
    DelegationAuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        event: DelegationAuditAction::AuditConfigurationChanged {
            actor_id: actor_id.to_string(),
            operation,
            outcome,
            previous,
            requested,
        },
        agent_did: None,
        agent_identity_did: None,
        user_identity_hash: None,
        provider_id: None,
        provider_name: None,
        surface_id: None,
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: false,
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id,
        tenant_id: None,
        detail: None,
    }
}

/// Convenience: build an audit event with common fields pre-filled
pub fn audit_event(
    action: DelegationAuditAction,
    agent_did: Option<&str>,
    user_hash: Option<&str>,
    provider_id: Option<&str>,
    channel_id: Option<&str>,
) -> DelegationAuditEvent {
    DelegationAuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        event: action,
        agent_did: agent_did.map(String::from),
        agent_identity_did: None,
        user_identity_hash: user_hash.map(String::from),
        provider_id: provider_id.map(String::from),
        provider_name: None,
        surface_id: channel_id.map(String::from),
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: false,
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: None,
        tenant_id: None,
        detail: None,
    }
}

/// Paginated audit log response
#[derive(Debug, Serialize)]
pub struct AuditLogPage {
    pub events: Vec<DelegationAuditEvent>,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    pub total_pages: usize,
    /// Per-category event counts across the text-filtered set, computed
    /// **before** the category filter so a dropdown can show how many entries
    /// each category holds regardless of which one is currently selected.
    #[serde(default)]
    pub category_counts: std::collections::BTreeMap<String, usize>,
}

/// Return the stable category string for an audit action.
///
/// Used by [`read_audit_log`] to apply the category filter before pagination
/// so `total` and `total_pages` reflect the filtered set.
pub fn action_category(action: &DelegationAuditAction) -> &'static str {
    match action {
        DelegationAuditAction::PolicyDecision { .. } => "policy_decision",
        DelegationAuditAction::AuditConfigurationChanged { .. } => "audit_configuration_changed",
        DelegationAuditAction::ConsentGranted => "consent_granted",
        DelegationAuditAction::TokenInjected => "token_injected",
        DelegationAuditAction::TokenRefreshed => "token_refreshed",
        DelegationAuditAction::RefreshFailed => "refresh_failed",
        DelegationAuditAction::ConsentRequired => "consent_required",
        DelegationAuditAction::TokenRevoked => "token_revoked",
        DelegationAuditAction::UserTokensRevoked => "user_tokens_revoked",
        DelegationAuditAction::TokenNotFound => "token_not_found",
        DelegationAuditAction::VpInjected => "vp_injected",
        DelegationAuditAction::ElicitationSent => "elicitation_sent",
        DelegationAuditAction::ElicitationAccepted => "elicitation_accepted",
        DelegationAuditAction::ElicitationDeclined => "elicitation_declined",
        DelegationAuditAction::ElicitationCancelled => "elicitation_cancelled",
        DelegationAuditAction::ElicitationTimedOut => "elicitation_timed_out",
        DelegationAuditAction::PreAuthorizeBlocked => "pre_authorize_blocked",
    }
}

/// Tally per-category event counts (via [`action_category`]) across a set of
/// events. Used by [`read_audit_log`] to report how many entries each category
/// holds, computed before the category filter is applied.
pub fn tally_categories(events: &[DelegationAuditEvent]) -> std::collections::BTreeMap<String, usize> {
    let mut counts = std::collections::BTreeMap::new();
    for event in events {
        *counts
            .entry(action_category(&event.event).to_string())
            .or_insert(0) += 1;
    }
    counts
}

/// Filters for [`read_audit_log`]. All are applied **before** pagination and
/// the category tally so `total`, `total_pages`, and `category_counts` stay
/// consistent with the returned page.
#[derive(Debug, Default, Clone, Copy)]
pub struct AuditLogFilter<'a> {
    /// Case-insensitive substring match on the raw JSON line.
    pub text: Option<&'a str>,
    /// OR set of action-type categories (comma-separated).
    pub category: Option<&'a str>,
    /// Restrict to policy decisions with this flow (`access_point` | `transit_point` | `fabric`).
    pub flow: Option<&'a str>,
    /// Restrict to policy decisions with this scope (`pipe` | `ide` | `gateway` | `surface`).
    pub scope: Option<&'a str>,
    /// Restrict to policy decisions with this decision (`allow` | `deny` | `error` | `missing_engine`).
    pub decision: Option<&'a str>,
    /// Drop policy-decision events entirely (keeps the delegation view clean).
    pub exclude_vp_audit: bool,
}

/// Read the audit log file with pagination (newest first). Every [`AuditLogFilter`]
/// is applied **before** pagination and the category tally so `total`,
/// `total_pages`, and `category_counts` stay consistent with the returned page.
pub async fn read_audit_log(
    page: usize,
    page_size: usize,
    opts: AuditLogFilter<'_>,
) -> anyhow::Result<AuditLogPage> {
    let path = AUDIT_PATH
        .get()
        .ok_or_else(|| anyhow::anyhow!("Audit logger not initialized"))?;

    let content = tokio::fs::read_to_string(path)
        .await
        .unwrap_or_default();

    let filter_lower = opts
        .text
        .map(|f| f.to_lowercase());

    // Parse all lines, most-recent first, applying the text filter before parsing.
    let events: Vec<DelegationAuditEvent> = content
        .lines()
        .rev()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            // Apply text filter before parsing (cheap substring check)
            if let Some(ref f) = filter_lower
                && !line
                    .to_lowercase()
                    .contains(f)
            {
                return None;
            }
            serde_json::from_str::<DelegationAuditEvent>(line).ok()
        })
        .collect();

    Ok(filter_and_paginate(events, page, page_size, opts))
}

/// Apply the [`AuditLogFilter`] (excluding the text filter, which is applied at
/// parse time) and paginate an already-ordered (newest-first) event list.
/// Extracted from [`read_audit_log`] so the filtering/pagination/tally logic is
/// unit-testable without a live audit file.
fn filter_and_paginate(
    mut events: Vec<DelegationAuditEvent>,
    page: usize,
    page_size: usize,
    opts: AuditLogFilter<'_>,
) -> AuditLogPage {
    // Drop policy-decision events up front so the count, pagination, and
    // category tally all reflect the same filtered set.
    if opts.exclude_vp_audit {
        events.retain(|event| !event.event.is_vp_audit());
    }

    // Policy-decision refinement filters (flow / scope / decision). When any is
    // set the view is restricted to matching PolicyDecision events, so these
    // compose with the category filter and drive the counts/pagination.
    let flow_f = opts
        .flow
        .filter(|s| !s.is_empty());
    let scope_f = opts
        .scope
        .filter(|s| !s.is_empty());
    let decision_f = opts
        .decision
        .filter(|s| !s.is_empty());
    if flow_f.is_some() || scope_f.is_some() || decision_f.is_some() {
        events.retain(|event| match &event.event {
            DelegationAuditAction::PolicyDecision { flow, scope, decision, .. } => {
                flow_f.is_none_or(|f| flow == f)
                    && scope_f.is_none_or(|s| scope == s)
                    && decision_f.is_none_or(|d| decision == d)
            }
            _ => false,
        });
    }

    // Tally per-category counts across the (text + refinement) filtered set,
    // before the category filter narrows it.
    let category_counts = tally_categories(&events);

    // Apply the category filter after counting so total/total_pages reflect the
    // selected category while category_counts still reflect every category. A
    // comma-separated list is treated as an OR set.
    if let Some(cat) = opts.category {
        let wanted: std::collections::HashSet<&str> = cat
            .split(',')
            .map(|c| c.trim())
            .filter(|c| !c.is_empty())
            .collect();
        if !wanted.is_empty() {
            events.retain(|event| wanted.contains(action_category(&event.event)));
        }
    }

    let total = events.len();
    let total_pages = if total == 0 {
        1
    } else {
        total.div_ceil(page_size)
    };
    let clamped_page = page.clamp(1, total_pages);
    let start = (clamped_page - 1) * page_size;
    let page_events: Vec<DelegationAuditEvent> = events
        .drain(start..)
        .take(page_size)
        .collect();

    AuditLogPage {
        events: page_events,
        total,
        page: clamped_page,
        page_size,
        total_pages,
        category_counts,
    }
}

/// Emit a policy-decision audit event. Called from
/// [`crate::observability::policy_audit::record_policy_decision`] only when
/// policy-decision recording is enabled. Stores only redacted structured
/// evidence — never request bodies, headers, credentials, tokens, or raw VP.
#[allow(clippy::too_many_arguments)]
pub fn audit_policy_decision(
    scope: &str,
    decision: &str,
    policy_id: &str,
    policy_name: Option<&str>,
    policy_definition_id: Option<&str>,
    policy_version: Option<&str>,
    policy_content_hash: Option<&str>,
    deny_reason: Option<&str>,
    surface_id: Option<&str>,
    policy_key: Option<&str>,
    caller_did: Option<&str>,
    caller_auth_method: Option<&str>,
    caller_principal: Option<&str>,
    workload_binding_present: bool,
    http_method: Option<&str>,
    http_path: Option<&str>,
    trace_id: Option<&str>,
    flow: &str,
) {
    let event = DelegationAuditEvent {
        timestamp: Utc::now().to_rfc3339(),
        event: DelegationAuditAction::PolicyDecision {
            scope: scope.to_string(),
            flow: flow.to_string(),
            policy_id: policy_id.to_string(),
            policy_name: policy_name
                .filter(|n| !n.is_empty())
                .map(str::to_string),
            policy_definition_id: policy_definition_id
                .filter(|d| !d.is_empty())
                .map(str::to_string),
            policy_version: policy_version
                .filter(|v| !v.is_empty())
                .map(str::to_string),
            policy_content_hash: policy_content_hash
                .filter(|h| !h.is_empty())
                .map(str::to_string),
            decision: decision.to_string(),
            deny_reason: deny_reason
                .filter(|r| !r.is_empty())
                .map(str::to_string),
            surface_id: surface_id
                .filter(|s| !s.is_empty())
                .map(str::to_string),
            policy_key: policy_key
                .filter(|k| !k.is_empty())
                .map(str::to_string),
            caller_did: caller_did
                .filter(|d| !d.is_empty())
                .map(str::to_string),
            caller_auth_method: caller_auth_method
                .filter(|m| !m.is_empty())
                .map(str::to_string),
            caller_principal: caller_principal
                .filter(|p| !p.is_empty())
                .map(str::to_string),
            workload_binding_present,
            http_method: http_method
                .filter(|m| !m.is_empty())
                .map(str::to_string),
            http_path: http_path
                .filter(|p| !p.is_empty())
                .map(str::to_string),
        },
        agent_did: None,
        agent_identity_did: None,
        user_identity_hash: None,
        provider_id: None,
        provider_name: None,
        surface_id: surface_id
            .filter(|s| !s.is_empty())
            .map(str::to_string),
        channel_name: None,
        target_endpoint: None,
        protocol: None,
        scopes: None,
        token_id: None,
        inject_as: None,
        via_fabric: flow == "fabric",
        mcp_tool_name: None,
        vp_jwt: None,
        vp_fingerprint: None,
        trace_id: trace_id
            .filter(|t| !t.is_empty())
            .map(str::to_string),
        tenant_id: crate::observability::request_context::current().and_then(|ctx| ctx.usage.tenant_id),
        detail: None,
    };
    audit(event);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_event_builder_fills_fields() {
        let evt = audit_event(
            DelegationAuditAction::TokenInjected,
            Some("did:web:agent"),
            Some("sha256:user1"),
            Some("github"),
            Some("ch-1"),
        );
        assert!(matches!(evt.event, DelegationAuditAction::TokenInjected));
        assert_eq!(evt.agent_did.as_deref(), Some("did:web:agent"));
        assert_eq!(
            evt.user_identity_hash
                .as_deref(),
            Some("sha256:user1")
        );
        assert_eq!(evt.provider_id.as_deref(), Some("github"));
        assert_eq!(evt.surface_id.as_deref(), Some("ch-1"));
        assert!(!evt.via_fabric);
        assert!(evt.scopes.is_none());
        assert!(evt.token_id.is_none());
        assert!(evt.detail.is_none());
    }

    #[test]
    fn test_audit_event_set_vp_jwt_sets_fingerprint() {
        let mut evt = audit_event(DelegationAuditAction::VpInjected, None, None, None, None);
        evt.set_vp_jwt("header.payload.signature".to_string());
        assert_eq!(evt.vp_jwt.as_deref(), Some("header.payload.signature"));
        assert_eq!(
            evt.vp_fingerprint.as_deref(),
            Some("sha256:256d04db4e5e4ac308751ed0885b722b758630567c53a7125ed9fbd068e5c3f6")
        );
    }

    #[test]
    fn test_audit_event_builder_with_none_fields() {
        let evt = audit_event(DelegationAuditAction::ConsentRequired, None, None, None, None);
        assert!(evt.agent_did.is_none());
        assert!(
            evt.user_identity_hash
                .is_none()
        );
        assert!(evt.provider_id.is_none());
        assert!(evt.surface_id.is_none());
    }

    #[test]
    fn test_audit_event_serialization_includes_event_type() {
        let evt = audit_event(
            DelegationAuditAction::ConsentGranted,
            Some("did:web:agent"),
            Some("sha256:user"),
            Some("github"),
            Some("ch-1"),
        );
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"event\":\"consent_granted\""), "Event should serialize to snake_case, got: {}", json);
        assert!(json.contains("\"agent_did\":\"did:web:agent\""));
        // via_fabric defaults to false
        assert!(json.contains("\"via_fabric\":false"));
    }

    #[test]
    fn test_audit_event_serialization_skips_none_fields() {
        let evt = audit_event(DelegationAuditAction::TokenRevoked, None, None, None, None);
        let json = serde_json::to_string(&evt).unwrap();
        assert!(!json.contains("agent_did"), "None fields should be skipped");
        assert!(!json.contains("scopes"), "None scopes should be skipped");
        assert!(!json.contains("token_id"), "None token_id should be skipped");
        assert!(!json.contains("detail"), "None detail should be skipped");
        assert!(json.contains("\"event\":\"token_revoked\""));
    }

    #[test]
    fn test_audit_event_via_fabric_flag() {
        let mut evt = audit_event(DelegationAuditAction::TokenInjected, None, None, None, None);
        evt.via_fabric = true;
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"via_fabric\":true"));
    }

    #[test]
    fn test_audit_event_with_scopes_and_detail() {
        let mut evt = audit_event(
            DelegationAuditAction::ConsentGranted,
            Some("did:web:agent"),
            Some("sha256:user"),
            Some("github"),
            Some("ch-1"),
        );
        evt.scopes = Some(vec!["repo".to_string(), "read:user".to_string()]);
        evt.detail = Some("User clicked authorize".to_string());
        let json = serde_json::to_string(&evt).unwrap();
        assert!(json.contains("\"scopes\":[\"repo\",\"read:user\"]"));
        assert!(json.contains("\"detail\":\"User clicked authorize\""));
    }

    #[test]
    fn test_all_action_variants_serialize() {
        let actions = vec![
            (DelegationAuditAction::ConsentGranted, "consent_granted"),
            (DelegationAuditAction::TokenInjected, "token_injected"),
            (DelegationAuditAction::TokenRefreshed, "token_refreshed"),
            (DelegationAuditAction::RefreshFailed, "refresh_failed"),
            (DelegationAuditAction::ConsentRequired, "consent_required"),
            (DelegationAuditAction::TokenRevoked, "token_revoked"),
            (DelegationAuditAction::UserTokensRevoked, "user_tokens_revoked"),
            (DelegationAuditAction::TokenNotFound, "token_not_found"),
            (DelegationAuditAction::VpInjected, "vp_injected"),
            (DelegationAuditAction::ElicitationSent, "elicitation_sent"),
            (DelegationAuditAction::ElicitationAccepted, "elicitation_accepted"),
            (DelegationAuditAction::ElicitationDeclined, "elicitation_declined"),
            (DelegationAuditAction::ElicitationCancelled, "elicitation_cancelled"),
            (DelegationAuditAction::ElicitationTimedOut, "elicitation_timed_out"),
            (DelegationAuditAction::PreAuthorizeBlocked, "pre_authorize_blocked"),
        ];

        for (action, expected_name) in actions {
            let json = serde_json::to_string(&action).unwrap();
            assert_eq!(
                json,
                format!("\"{}\"", expected_name),
                "Action {:?} should serialize to {}",
                expected_name,
                expected_name
            );
        }
    }

    #[test]
    fn test_audit_without_init_does_not_panic() {
        // audit() should silently drop when logger is not initialized
        let evt = audit_event(DelegationAuditAction::TokenInjected, None, None, None, None);
        audit(evt); // Should not panic
    }

    #[test]
    fn audit_configuration_event_records_actor_transition_outcome_and_trace() {
        let previous = AuditConfigurationState {
            enabled: true,
            policies: true,
            trust_checks: false,
            identity: false,
        };
        let requested = AuditConfigurationState {
            enabled: false,
            policies: false,
            trust_checks: false,
            identity: false,
        };

        let event = audit_configuration_event(
            "admin-1",
            AuditConfigurationOperation::Update,
            AuditConfigurationOutcome::Succeeded,
            previous.clone(),
            requested.clone(),
            Some("trace-1".to_string()),
        );
        let value = serde_json::to_value(&event).unwrap();

        assert_eq!(value["event"]["audit_configuration_changed"]["actor_id"], "admin-1");
        assert_eq!(value["event"]["audit_configuration_changed"]["operation"], "update");
        assert_eq!(value["event"]["audit_configuration_changed"]["outcome"], "succeeded");
        assert_eq!(value["event"]["audit_configuration_changed"]["previous"], serde_json::to_value(previous).unwrap());
        assert_eq!(
            value["event"]["audit_configuration_changed"]["requested"],
            serde_json::to_value(requested).unwrap()
        );
        assert_eq!(value["trace_id"], "trace-1");
        assert_eq!(action_category(&event.event), "audit_configuration_changed");
        assert!(event.event.is_vp_audit());

        let page = filter_and_paginate(
            vec![event, audit_event(DelegationAuditAction::TokenInjected, None, None, None, None)],
            1,
            50,
            AuditLogFilter {
                exclude_vp_audit: true,
                ..Default::default()
            },
        );
        assert_eq!(page.events.len(), 1);
        assert_eq!(action_category(&page.events[0].event), "token_injected");
    }

    #[test]
    fn audit_configuration_delivery_is_attempted_without_policy_audit_enablement() {
        let state = AuditConfigurationState {
            enabled: false,
            policies: false,
            trust_checks: false,
            identity: false,
        };

        let error = record_audit_configuration_change(
            "admin-1",
            AuditConfigurationOperation::Reset,
            AuditConfigurationOutcome::PersistenceFailed,
            state.clone(),
            state,
            None,
        )
        .expect_err("the uninitialized sink must report delivery failure");

        assert!(
            error
                .to_string()
                .contains("not initialized")
        );
    }

    /// Build a `PolicyDecision` event for filter/serialization tests.
    fn policy_decision_event(
        scope: &str,
        flow: &str,
        decision: &str,
    ) -> DelegationAuditEvent {
        DelegationAuditEvent {
            timestamp: "2026-08-07T00:00:00Z".to_string(),
            event: DelegationAuditAction::PolicyDecision {
                scope: scope.to_string(),
                flow: flow.to_string(),
                policy_id: "data.llm.policy.allow".to_string(),
                policy_name: Some("My Policy".to_string()),
                policy_definition_id: Some("def-1".to_string()),
                policy_version: Some("2026-08-01T00:00:00Z".to_string()),
                policy_content_hash: Some("sha256:cafe".to_string()),
                decision: decision.to_string(),
                deny_reason: (decision != "allow").then(|| "nope".to_string()),
                surface_id: Some("pipe-1".to_string()),
                policy_key: Some("pipe-1$canary".to_string()),
                caller_did: None,
                caller_auth_method: Some("jwt_bearer".to_string()),
                caller_principal: Some("sub-1".to_string()),
                workload_binding_present: false,
                http_method: Some("POST".to_string()),
                http_path: Some("/v1/chat".to_string()),
            },
            agent_did: None,
            agent_identity_did: None,
            user_identity_hash: None,
            provider_id: None,
            provider_name: None,
            surface_id: Some("pipe-1".to_string()),
            channel_name: None,
            target_endpoint: None,
            protocol: None,
            scopes: None,
            token_id: None,
            inject_as: None,
            via_fabric: flow == "fabric",
            mcp_tool_name: None,
            vp_jwt: None,
            vp_fingerprint: None,
            trace_id: Some("trace-1".to_string()),
            tenant_id: None,
            detail: None,
        }
    }

    #[test]
    fn policy_decision_serializes_snake_case_and_skips_none() {
        let evt = policy_decision_event("pipe", "access_point", "deny");
        let json = serde_json::to_string(&evt).unwrap();
        // Struct enum variants are externally tagged: `"event":{"policy_decision":{…}}`.
        assert!(json.contains("\"event\":{\"policy_decision\":{"), "got: {json}");
        assert!(json.contains("\"scope\":\"pipe\""));
        assert!(json.contains("\"decision\":\"deny\""));
        assert!(json.contains("\"policy_version\":\"2026-08-01T00:00:00Z\""));
        assert!(json.contains("\"policy_content_hash\":\"sha256:cafe\""));
        assert!(json.contains("\"caller_auth_method\":\"jwt_bearer\""));
        // None fields are skipped.
        assert!(!json.contains("caller_did"), "caller_did (None) should be skipped: {json}");
        // Round-trips.
        let back: DelegationAuditEvent = serde_json::from_str(&json).unwrap();
        assert!(back.event.is_vp_audit());
    }

    #[test]
    fn delegation_view_excludes_policy_decisions() {
        assert!(
            policy_decision_event("surface", "fabric", "allow")
                .event
                .is_vp_audit()
        );
        let consent = audit_event(DelegationAuditAction::ConsentGranted, None, None, None, None);
        assert!(!consent.event.is_vp_audit());
    }

    #[test]
    fn action_category_and_tally_count_policy_decisions() {
        let events = vec![
            policy_decision_event("pipe", "access_point", "allow"),
            policy_decision_event("gateway", "fabric", "deny"),
            audit_event(DelegationAuditAction::TokenInjected, None, None, None, None),
        ];
        assert_eq!(action_category(&events[0].event), "policy_decision");
        let counts = tally_categories(&events);
        assert_eq!(counts.get("policy_decision"), Some(&2));
        assert_eq!(counts.get("token_injected"), Some(&1));
    }

    #[test]
    fn filter_excludes_vp_audit_keeps_delegation_view_clean() {
        let events = vec![
            policy_decision_event("pipe", "access_point", "allow"),
            audit_event(DelegationAuditAction::TokenInjected, None, None, None, None),
        ];
        let page = filter_and_paginate(
            events,
            1,
            50,
            AuditLogFilter {
                exclude_vp_audit: true,
                ..Default::default()
            },
        );
        assert_eq!(page.total, 1);
        assert!(
            !page.events[0]
                .event
                .is_vp_audit()
        );
    }

    #[test]
    fn filter_by_scope_and_decision_restricts_to_matching_policy_decisions() {
        let events = vec![
            policy_decision_event("pipe", "access_point", "allow"),
            policy_decision_event("gateway", "fabric", "deny"),
            policy_decision_event("surface", "access_point", "deny"),
            audit_event(DelegationAuditAction::TokenInjected, None, None, None, None),
        ];
        // scope=gateway → only the gateway deny.
        let page = filter_and_paginate(
            events.clone(),
            1,
            50,
            AuditLogFilter {
                scope: Some("gateway"),
                ..Default::default()
            },
        );
        assert_eq!(page.total, 1);
        // decision=deny → both denies (gateway + surface), never the token event.
        let page = filter_and_paginate(
            events,
            1,
            50,
            AuditLogFilter {
                decision: Some("deny"),
                ..Default::default()
            },
        );
        assert_eq!(page.total, 2);
    }

    #[test]
    fn category_counts_computed_before_category_filter() {
        let events = vec![
            policy_decision_event("pipe", "access_point", "allow"),
            audit_event(DelegationAuditAction::TokenInjected, None, None, None, None),
        ];
        let page = filter_and_paginate(
            events,
            1,
            50,
            AuditLogFilter {
                category: Some("policy_decision"),
                ..Default::default()
            },
        );
        // The page is narrowed to policy decisions...
        assert_eq!(page.total, 1);
        // ...but category_counts still reflect every category before narrowing.
        assert_eq!(
            page.category_counts
                .get("policy_decision"),
            Some(&1)
        );
        assert_eq!(
            page.category_counts
                .get("token_injected"),
            Some(&1)
        );
    }

    #[tokio::test]
    async fn test_audit_writer_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let audit_path = dir
            .path()
            .join("test-audit.jsonl");

        let (tx, rx) = mpsc::unbounded_channel();

        // Spawn writer
        let path_clone = audit_path.clone();
        let forwarded = Arc::new(Mutex::new(Vec::new()));
        let sink = forwarded.clone();
        let handle = tokio::spawn(audit_writer_task(path_clone, rx, move |event: DelegationAuditEvent| {
            sink.lock()
                .unwrap()
                .push(action_category(&event.event).to_string())
        }));

        // Send a couple of events
        let evt1 = audit_event(
            DelegationAuditAction::ConsentGranted,
            Some("did:web:agent1"),
            Some("sha256:user1"),
            Some("github"),
            Some("ch-1"),
        );
        let mut evt2 =
            audit_event(DelegationAuditAction::TokenInjected, Some("did:web:agent2"), None, Some("google"), None);
        evt2.via_fabric = true;

        tx.send(evt1).unwrap();
        tx.send(evt2).unwrap();

        // Drop sender to signal EOF
        drop(tx);

        // Wait for writer to finish
        handle.await.unwrap();

        // Read and verify
        let contents = std::fs::read_to_string(&audit_path).unwrap();
        let lines: Vec<&str> = contents
            .trim()
            .split('\n')
            .collect();
        assert_eq!(lines.len(), 2, "Should have 2 JSONL lines");

        let line1: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(line1["event"], "consent_granted");
        assert_eq!(line1["agent_did"], "did:web:agent1");
        assert_eq!(line1["via_fabric"], false);

        let line2: serde_json::Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(line2["event"], "token_injected");
        assert_eq!(line2["provider_id"], "google");
        assert_eq!(line2["via_fabric"], true);
        // None fields should not appear
        assert!(
            line2
                .get("user_identity_hash")
                .is_none()
        );
        assert!(
            line2
                .get("channel_id")
                .is_none()
        );
        assert_eq!(
            *forwarded.lock().unwrap(),
            vec!["consent_granted".to_string(), "token_injected".to_string()],
            "every persisted record is forwarded, in order"
        );
    }

    #[tokio::test]
    async fn a_record_that_cannot_be_written_is_not_forwarded() {
        let dir = tempfile::tempdir().unwrap();
        let (tx, rx) = mpsc::unbounded_channel();
        let forwarded = Arc::new(Mutex::new(0usize));
        let sink = forwarded.clone();
        let handle = tokio::spawn(audit_writer_task(dir.path().to_path_buf(), rx, move |_| {
            *sink.lock().unwrap() += 1;
        }));
        tx.send(audit_event(DelegationAuditAction::TokenInjected, None, None, None, None))
            .unwrap();
        drop(tx);
        handle.await.unwrap();
        assert_eq!(*forwarded.lock().unwrap(), 0, "a directory cannot be opened as the audit log");
    }

    #[test]
    fn policy_decision_records_the_policy_key_and_tenant() {
        let evt = policy_decision_event("pipe", "access_point", "deny");
        let json = serde_json::to_value(&evt).unwrap();
        assert_eq!(json["event"]["policy_decision"]["surface_id"], "pipe-1");
        assert_eq!(json["event"]["policy_decision"]["policy_key"], "pipe-1$canary");
        assert!(
            json.get("tenant_id")
                .is_none(),
            "an appliance-wide surface has no tenant"
        );

        let mut owned = evt;
        owned.tenant_id = Some("acme".to_string());
        assert_eq!(serde_json::to_value(&owned).unwrap()["tenant_id"], "acme");
    }

    #[tokio::test]
    async fn a_recorded_decision_carries_the_engine_key_and_the_request_tenant() {
        use crate::observability::request_context::{RequestContext, scope};
        let queue = Arc::new(Mutex::new(Vec::new()));
        let ctx = RequestContext {
            trace_id: "trace-1".to_string(),
            usage: crate::governance::UsageAttribution {
                tenant_id: Some("acme".to_string()),
                ..Default::default()
            },
            ..Default::default()
        };
        scope(
            ctx,
            AUDIT_DEFER_QUEUE.scope(queue.clone(), async {
                audit_policy_decision(
                    "pipe",
                    "deny",
                    "data.llm.policy.allow",
                    Some("Block unknown callers"),
                    Some("def-1"),
                    Some("4"),
                    Some("sha256:abc"),
                    Some("caller not recognised"),
                    Some("pipe-1"),
                    Some("pipe-1$canary"),
                    None,
                    Some("api_key"),
                    Some("billing-bot"),
                    false,
                    Some("POST"),
                    Some("/llm/v1/chat/completions"),
                    Some("trace-1"),
                    "access_point",
                );
            }),
        )
        .await;

        let events = queue.lock().unwrap();
        assert_eq!(events.len(), 1);
        let json = serde_json::to_value(&events[0]).unwrap();
        assert_eq!(json["surface_id"], "pipe-1");
        assert_eq!(json["tenant_id"], "acme");
        assert_eq!(json["trace_id"], "trace-1");
        let decision = &json["event"]["policy_decision"];
        assert_eq!(decision["surface_id"], "pipe-1");
        assert_eq!(decision["policy_key"], "pipe-1$canary");
        assert_eq!(decision["policy_name"], "Block unknown callers");
        assert_eq!(decision["caller_principal"], "billing-bot");
        assert_eq!(decision["caller_auth_method"], "api_key");
    }
}
