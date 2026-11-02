//! Capture entry point: builds a [`GovernanceRecord`] from an interaction's
//! request, response, and metrics, then submits it to the process-wide
//! [`GovernanceStore`] for chaining, signing, and durable storage.
//!
//! Wiring uses a global store (initialised once at startup) so request handlers
//! need only call [`capture`] with what they already hold — mirroring the
//! delegation-audit and identity-hash-pepper globals rather than threading a new
//! dependency through every layer. Capture is fire-and-forget: it never blocks
//! or fails the request.

use std::collections::HashMap;
use std::sync::OnceLock;

use serde_json::Value;
use tracing::warn;

use super::config::CapturePolicy;
use super::record::{
    GENESIS_HASH, GovernanceRecord, LlmCall, RecordMetrics, RecordOutcome, StageEntry, StageOutcome, digest_bytes,
};
use super::store::GovernanceStore;

/// Process-wide governance store, set once at startup when the appliance signer
/// and encryption service are ready.
static GOVERNANCE_STORE: OnceLock<GovernanceStore> = OnceLock::new();

/// Install the global governance store. Idempotent-safe: a second call is
/// ignored with a warning.
pub fn init_store(store: GovernanceStore) {
    if GOVERNANCE_STORE
        .set(store)
        .is_err()
    {
        warn!("governance store already initialized");
    }
}

/// Whether governance recording can run (the global store is installed).
pub fn is_ready() -> bool {
    GOVERNANCE_STORE
        .get()
        .is_some()
}

/// The installed governance store, for the read/verify API. `None` before the
/// store is initialised at startup.
pub fn store() -> Option<&'static GovernanceStore> {
    GOVERNANCE_STORE.get()
}

/// The disposition of a captured interaction — drives which stage evidence the
/// record synthesizes.
pub enum InteractionOutcome {
    /// Reached the model and returned a completion. Synthesizes the main
    /// `llm_call` stage from the metrics + request/response digests.
    Completed,
    /// Blocked before a usable completion (policy deny, prompt-guard rejection,
    /// rate limit). Records a `Block` stage; no completion. `input`/`output`
    /// carry the rejecting stage's evaluated content and verdict when available
    /// (a content rejection from the Judge/Jury/expert-witness); `None` for
    /// non-content blocks (rate limit / circuit breaker). `categories` are the
    /// canonical rejection-category ids of a content block.
    Blocked {
        stage: String,
        reason: Option<String>,
        input: Option<String>,
        output: Option<String>,
        categories: Vec<String>,
    },
    /// Failed with an infrastructure/transport error. Records an `Error` stage.
    Failed { stage: String, reason: Option<String> },
    /// The caller supplied the full stage transcript (including the deciding
    /// stage, which carries its own policy evidence) via `extra_stages`.
    /// Synthesize no stage and record no completion — used for policy denials.
    Denied,
}

impl InteractionOutcome {
    /// How the interaction ends once its record is built: the same answer as
    /// [`RecordOutcome::of_stages`] on the finished record, known before it is
    /// built so a surface that records only some outcomes builds nothing else.
    fn class(
        &self,
        extra_stages: &[StageEntry],
    ) -> RecordOutcome {
        let extra = RecordOutcome::of_stages(extra_stages);
        match self {
            Self::Blocked { .. } => RecordOutcome::Blocked,
            Self::Failed { .. } if extra == RecordOutcome::Blocked => RecordOutcome::Blocked,
            Self::Failed { .. } => RecordOutcome::Failed,
            Self::Completed | Self::Denied => extra,
        }
    }
}

/// Everything needed to build one interaction record. Bodies are optional so a
/// surface can capture digests-only, or text for blocked interactions only.
pub struct CaptureInput {
    pub surface_id: String,
    pub surface_name: Option<String>,
    pub trace_id: Option<String>,
    /// Raw caller identifier (DID / principal); hashed with the identity pepper
    /// before it enters the record — never stored in the clear. A capture inside
    /// a request context records the request's canonical caller instead.
    pub caller_identity: Option<String>,
    /// Full request payload (chat/completions body) for prompt extraction + digest.
    pub request: Option<Value>,
    /// Full response payload for completion extraction + digest.
    pub response: Option<Value>,
    /// Pre-reassembled completion text (streaming path, where the completion is
    /// accumulated from SSE deltas rather than a single response body). When
    /// present it takes precedence over extracting from `response`.
    pub completion_text: Option<String>,
    /// Which outcomes are recorded and which keep their prompt/completion
    /// text (the rest keep digests + stages only), and the retention window.
    pub policy: CapturePolicy,
    /// Grand-total interaction metrics (zeroed for blocked/failed interactions).
    pub metrics: RecordMetrics,
    /// The interaction's disposition — decides the synthesized main stage.
    pub outcome: InteractionOutcome,
    /// Stage evidence resolved by the caller (policy/guard/judge/jury verdicts,
    /// recovered redrive rejections), recorded before the synthesized main stage.
    pub extra_stages: Vec<StageEntry>,
    /// Optional export targets for the signed record, in addition to the local
    /// store (OpenTelemetry and/or integrations). `None` = local-only.
    pub export: Option<super::config::GovernanceExport>,
}

/// Build and submit a governance record for one interaction. No-op when the
/// store is not installed or the surface does not record this outcome. Runs the
/// build + signing + IO on a background task so the caller's response path is
/// untouched.
pub fn capture(input: CaptureInput) {
    capture_with_id(input, new_record_id());
}

/// A fresh governance record id. Mint one up front when something emitted before
/// the record is written (such as `pipe.executed`) must name the record.
pub fn new_record_id() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// [`capture`] with a caller-chosen record id (from [`new_record_id`]).
/// Answers whether a record was submitted under that id: `false` when the store
/// is not installed or the surface does not record this outcome, so nothing
/// emitted alongside should name it.
pub fn capture_with_id(
    input: CaptureInput,
    record_id: String,
) -> bool {
    let Some(store) = GOVERNANCE_STORE.get() else {
        return false;
    };
    let Some(keep_bodies) = decide(&input) else {
        return false;
    };
    let retention_days = input.policy.retention_days;
    let store = store.clone();
    let export = input.export.clone();
    let request = crate::observability::request_context::current();
    tokio::spawn(async move {
        // Persist any binary attachments (audio / documents / images) to the
        // multimedia store and record hash-only references - the VC never embeds
        // the raw bytes. Bytes are stored only when this interaction keeps its
        // bodies (else digests-only mode still yields the hashes). Runs on this
        // background task, off the request's response path.
        let attachments = match input.request.as_ref() {
            Some(req) if keep_bodies => super::multimedia_store::extract_and_store(req).await,
            Some(req) => super::multimedia_store::extract_refs(req),
            None => Vec::new(),
        };
        let mut record = build_record(input, keep_bodies);
        record.record_id = record_id;
        record.attachments = attachments;
        if let Some(request) = request {
            attribute_to_request(&mut record, request).await;
        }
        match store
            .record(record, retention_days)
            .await
        {
            Ok(stored) => {
                if let Some(export) = export.filter(|e| !e.is_empty()) {
                    super::sink::export(&export, &stored).await;
                }
            }
            Err(e) => warn!(error = %e, "failed to persist governance record"),
        }
    });
    true
}

/// Convenience for the blocked/failed paths: submit a record for an interaction
/// that never produced a completion (policy deny, prompt-guard rejection, rate
/// limit, circuit breaker, transport error). No-op when `active` is false.
/// Carries the prompt (when the policy keeps this outcome's text) and the
/// blocking/failing stage; no response and default (zeroed) metrics.
#[allow(clippy::too_many_arguments)]
pub fn capture_failure(
    active: bool,
    policy: CapturePolicy,
    surface_id: String,
    surface_name: String,
    request: Option<Value>,
    caller_identity: Option<String>,
    outcome: InteractionOutcome,
    export: Option<super::config::GovernanceExport>,
) {
    if !active {
        return;
    }
    capture(CaptureInput {
        surface_id,
        surface_name: Some(surface_name),
        trace_id: None,
        caller_identity,
        request,
        response: None,
        completion_text: None,
        policy,
        metrics: RecordMetrics::default(),
        outcome,
        extra_stages: Vec::new(),
        export,
    });
}

/// [`capture_failure`] for a blocked or failed interaction that had already spent
/// tokens before it stopped (a Judge or Jury block, or a failure after a Judge or
/// Decider ran): the record carries `metrics` — the spend per stage — instead of
/// zeros.
#[allow(clippy::too_many_arguments)]
pub fn capture_failure_with_metrics(
    active: bool,
    policy: CapturePolicy,
    surface_id: String,
    surface_name: String,
    request: Option<Value>,
    caller_identity: Option<String>,
    outcome: InteractionOutcome,
    metrics: RecordMetrics,
    export: Option<super::config::GovernanceExport>,
) {
    if !active {
        return;
    }
    capture(CaptureInput {
        surface_id,
        surface_name: Some(surface_name),
        trace_id: None,
        caller_identity,
        request,
        response: None,
        completion_text: None,
        policy,
        metrics,
        outcome,
        extra_stages: Vec::new(),
        export,
    });
}

/// Capture a governance record for an OPA policy **denial** (or evaluation
/// error) at an enforcement point. The deciding policy stage carries the
/// policy-definition id, name, version, and content hash so the block is
/// attestable and reproducible against exact Rego bytes. No-op when `active` is false.
/// `is_error` records an `Error` stage (evaluation failure) rather than a
/// `Block` (policy deny).
#[allow(clippy::too_many_arguments)]
pub fn capture_policy_denial(
    active: bool,
    policy: CapturePolicy,
    surface_id: String,
    surface_name: String,
    request: Option<Value>,
    caller_identity: Option<String>,
    stage_label: &str,
    reason: Option<String>,
    is_error: bool,
    policy_definition_id: Option<String>,
    policy_name: Option<String>,
    policy_version: Option<String>,
    policy_content_hash: Option<String>,
    export: Option<super::config::GovernanceExport>,
) {
    if !active {
        return;
    }
    let outcome = if is_error {
        StageOutcome::Error
    } else {
        StageOutcome::Block
    };
    let mut stage = StageEntry::decision(stage_label, outcome, reason);
    stage.policy_id = policy_definition_id;
    stage.policy_name = policy_name;
    stage.policy_version = policy_version;
    stage.policy_content_hash = policy_content_hash;
    capture(CaptureInput {
        surface_id,
        surface_name: Some(surface_name),
        trace_id: None,
        caller_identity,
        request,
        response: None,
        completion_text: None,
        policy,
        metrics: RecordMetrics::default(),
        outcome: InteractionOutcome::Denied,
        extra_stages: vec![stage],
        export,
    });
}

/// Whether the surface records this interaction (`None` when it does not), and
/// if so whether the record keeps its prompt, completion and stage bodies.
fn decide(input: &CaptureInput) -> Option<bool> {
    let outcome = input
        .outcome
        .class(&input.extra_stages);
    input
        .policy
        .outcomes
        .records(outcome)
        .then(|| {
            input
                .policy
                .bodies
                .keeps(outcome)
        })
}

/// Build the record for `input`. `keep_bodies` is whether this interaction
/// keeps its prompt, completion and stage bodies (digests are kept either way).
fn build_record(
    input: CaptureInput,
    keep_bodies: bool,
) -> GovernanceRecord {
    let request_digest = input
        .request
        .as_ref()
        .map(digest_value);
    let response_digest = input
        .response
        .as_ref()
        .map(digest_value);

    let prompt = keep_bodies
        .then(|| {
            input
                .request
                .as_ref()
                .and_then(extract_prompt)
        })
        .flatten();
    let completion = keep_bodies
        .then(|| {
            input
                .completion_text
                .clone()
                .or_else(|| {
                    input
                        .response
                        .as_ref()
                        .and_then(extract_completion)
                })
        })
        .flatten();

    let caller_identity_hash = input
        .caller_identity
        .as_deref()
        .map(hash_caller);

    let mut stages = input.extra_stages;
    match input.outcome {
        InteractionOutcome::Completed => {
            stages.push(StageEntry::llm(LlmCall {
                provider: input
                    .metrics
                    .provider
                    .clone()
                    .unwrap_or_default(),
                model: input
                    .metrics
                    .model
                    .clone()
                    .unwrap_or_default(),
                retry_index: 0,
                request_digest: request_digest.unwrap_or_else(|| digest_bytes(b"")),
                response_digest,
                input_tokens: input.metrics.input_tokens,
                output_tokens: input.metrics.output_tokens,
                cost: input.metrics.cost,
            }));
        }
        InteractionOutcome::Blocked {
            stage,
            reason,
            input: stage_input,
            output: stage_output,
            categories,
        } => {
            let mut entry = StageEntry::decision(stage, StageOutcome::Block, reason);
            entry.categories = categories;
            // Prefer the rejecting stage's own evaluated content/verdict; fall
            // back to the whole-request digest for non-content blocks.
            if stage_input.is_some() || stage_output.is_some() {
                entry.input = stage_input;
                entry.output = stage_output;
            } else {
                entry.input_digest = request_digest;
            }
            stages.push(entry);
        }
        InteractionOutcome::Failed { stage, reason } => {
            let mut entry = StageEntry::decision(stage, StageOutcome::Error, reason);
            entry.input_digest = request_digest;
            stages.push(entry);
        }
        InteractionOutcome::Denied => {
            // The deciding policy stage is already in `extra_stages`; attach the
            // request digest to it as input evidence when it has none.
            if let Some(last) = stages.last_mut()
                && last.input_digest.is_none()
            {
                last.input_digest = request_digest;
            }
        }
    }

    // Digest each stage's input/output body, then drop the bodies unless body
    // capture is enabled — mirroring the prompt/completion gating so digests-only
    // mode still retains per-stage evidence without raw content. Runs after the
    // match so it also covers the synthesized block stage's bodies.
    for stage in &mut stages {
        if let Some(text) = &stage.input {
            stage.input_digest = Some(digest_bytes(text.as_bytes()));
        }
        if let Some(text) = &stage.output {
            stage.output_digest = Some(digest_bytes(text.as_bytes()));
        }
        if !keep_bodies {
            stage.input = None;
            stage.output = None;
        }
    }

    GovernanceRecord {
        record_id: uuid::Uuid::new_v4().to_string(),
        trace_id: input.trace_id,
        surface_id: input.surface_id,
        surface_name: input.surface_name,
        caller_identity_hash,
        caller_identity_kind: None,
        principal_key: None,
        attribution: Default::default(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        // The store assigns the real chain head and computes the content hash.
        prev_record_hash: GENESIS_HASH.to_string(),
        stages,
        prompt,
        completion,
        attachments: Vec::new(),
        metrics: input.metrics,
        content_hash: None,
    }
}

/// Attribute a record to the request it was captured in: the request's trace id
/// (unless the capture named one), its canonical caller, the caller's
/// `principal_key`, and the member, teams and tenant. Inside a request the
/// canonical caller replaces whatever caller the capture named, so every record
/// a person produces carries the same hash.
async fn attribute_to_request(
    record: &mut GovernanceRecord,
    request: crate::observability::request_context::RequestContext,
) {
    if record.trace_id.is_none() && !request.trace_id.is_empty() {
        record.trace_id = Some(request.trace_id.clone());
    }
    if let Some(caller) = request.caller().await {
        record.caller_identity_hash = Some(hash_caller(&caller.value));
        record.caller_identity_kind = Some(caller.kind);
    }
    record.principal_key = request.principal_key;
    record.attribution = request.usage;
}

/// Digest the exact serialized bytes of a JSON body (compact form).
fn digest_value(value: &Value) -> String {
    let bytes = serde_json::to_vec(value).unwrap_or_default();
    digest_bytes(&bytes)
}

/// Peppered HMAC-SHA256 of a raw caller identifier, so the record links to a
/// caller without storing raw PII.
fn hash_caller(identity: &str) -> String {
    let mut fields = HashMap::new();
    fields.insert("caller".to_string(), Value::String(identity.to_string()));
    crate::identity::identity_hash::compute_canonical_identity_hash(&fields)
}

/// Extract a readable prompt from a chat/completions request body: each message
/// as `role: content`, newline-joined. Falls back to a legacy `prompt` string.
fn extract_prompt(request: &Value) -> Option<String> {
    if let Some(messages) = request
        .get("messages")
        .and_then(Value::as_array)
    {
        let mut lines = Vec::with_capacity(messages.len());
        for m in messages {
            let role = m
                .get("role")
                .and_then(Value::as_str)
                .unwrap_or("user");
            let content = content_to_text(m.get("content"));
            lines.push(format!("{role}: {content}"));
        }
        if !lines.is_empty() {
            return Some(lines.join("\n"));
        }
    }
    request
        .get("prompt")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Extract the assistant completion from a chat/completions response body.
fn extract_completion(response: &Value) -> Option<String> {
    let choices = response
        .get("choices")
        .and_then(Value::as_array)?;
    let first = choices.first()?;
    // Non-streaming chat shape: choices[0].message.content.
    if let Some(text) = first
        .get("message")
        .and_then(|m| m.get("content"))
        .and_then(Value::as_str)
    {
        return Some(text.to_string());
    }
    // Legacy completion shape: choices[0].text.
    first
        .get("text")
        .and_then(Value::as_str)
        .map(str::to_string)
}

/// Render a message `content` field (string, or an array of content parts) into
/// plain text for the prompt transcript.
fn content_to_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|p| {
                p.get("text")
                    .and_then(Value::as_str)
                    .map(str::to_string)
            })
            .collect::<Vec<_>>()
            .join(" "),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::config::{BodyCapture, RecordScope};
    use serde_json::json;

    /// The record `capture` would submit for `input`; panics when the policy
    /// records nothing.
    fn built(input: CaptureInput) -> GovernanceRecord {
        let keep_bodies = decide(&input).expect("the policy records this interaction");
        build_record(input, keep_bodies)
    }

    fn policy_for(capture_bodies: bool) -> CapturePolicy {
        if capture_bodies {
            CapturePolicy::default()
        } else {
            CapturePolicy::digests_only()
        }
    }

    #[test]
    fn extracts_chat_prompt_and_completion() {
        let req = json!({
            "messages": [
                { "role": "system", "content": "be nice" },
                { "role": "user", "content": "hi" }
            ]
        });
        assert_eq!(extract_prompt(&req).unwrap(), "system: be nice\nuser: hi");

        let resp = json!({ "choices": [ { "message": { "content": "hello" } } ] });
        assert_eq!(extract_completion(&resp).unwrap(), "hello");
    }

    #[test]
    fn extracts_multimodal_content_parts() {
        let req = json!({
            "messages": [
                { "role": "user", "content": [ { "type": "text", "text": "part1" }, { "type": "text", "text": "part2" } ] }
            ]
        });
        assert_eq!(extract_prompt(&req).unwrap(), "user: part1 part2");
    }

    #[test]
    fn build_record_omits_bodies_when_disabled() {
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: None,
            trace_id: Some("t1".to_string()),
            caller_identity: Some("did:example:alice".to_string()),
            request: Some(json!({ "messages": [ { "role": "user", "content": "secret" } ] })),
            response: Some(json!({ "choices": [ { "message": { "content": "answer" } } ] })),
            completion_text: None,
            policy: CapturePolicy::digests_only(),
            metrics: RecordMetrics {
                provider: Some("openai".to_string()),
                model: Some("gpt-4o".to_string()),
                input_tokens: 3,
                output_tokens: 4,
                total_tokens: 7,
                cost: 0.01,
                latency_ms: 5,
                ..Default::default()
            },
            outcome: InteractionOutcome::Completed,
            extra_stages: vec![],
            export: None,
        };
        let rec = built(input);
        assert!(rec.prompt.is_none());
        assert!(rec.completion.is_none());
        // Digest of the body is still recorded on the llm_call stage.
        let call = rec
            .stages
            .iter()
            .find_map(|s| s.llm_call.as_ref())
            .unwrap();
        assert!(
            call.request_digest
                .starts_with("sha256:")
        );
        assert!(call.response_digest.is_some());
        // Caller identity is hashed, never the raw DID.
        assert!(
            rec.caller_identity_hash
                .is_some()
        );
        assert_ne!(
            rec.caller_identity_hash
                .as_deref(),
            Some("did:example:alice")
        );
    }

    #[test]
    fn build_record_captures_bodies_when_enabled() {
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: Some("S1".to_string()),
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [ { "role": "user", "content": "hi" } ] })),
            response: Some(json!({ "choices": [ { "message": { "content": "yo" } } ] })),
            completion_text: None,
            policy: CapturePolicy::default(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Completed,
            extra_stages: vec![StageEntry::decision("policy", StageOutcome::Allow, None)],
            export: None,
        };
        let rec = built(input);
        assert_eq!(rec.prompt.as_deref(), Some("user: hi"));
        assert_eq!(rec.completion.as_deref(), Some("yo"));
        // extra stage preserved, llm_call appended after it.
        assert_eq!(rec.stages.len(), 2);
        assert_eq!(rec.stages[0].stage, "policy");
        assert_eq!(rec.stages[1].stage, "llm_call");
    }

    #[test]
    fn completion_text_override_wins_for_streaming() {
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [ { "role": "user", "content": "hi" } ] })),
            response: None,
            completion_text: Some("streamed answer".to_string()),
            policy: CapturePolicy::default(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Completed,
            extra_stages: vec![],
            export: None,
        };
        let rec = built(input);
        assert_eq!(rec.prompt.as_deref(), Some("user: hi"));
        assert_eq!(rec.completion.as_deref(), Some("streamed answer"));
    }

    #[test]
    fn blocked_outcome_records_block_stage_not_llm_call() {
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [ { "role": "user", "content": "blocked prompt" } ] })),
            response: None,
            completion_text: None,
            policy: CapturePolicy::default(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Blocked {
                stage: "prompt_guard_request".to_string(),
                reason: Some("pii detected".to_string()),
                input: None,
                output: None,
                categories: vec!["pii".to_string()],
            },
            extra_stages: vec![],
            export: None,
        };
        let rec = built(input);
        // Prompt captured, no completion, no synthesized llm_call.
        assert_eq!(rec.prompt.as_deref(), Some("user: blocked prompt"));
        assert!(rec.completion.is_none());
        assert_eq!(rec.stages.len(), 1);
        let stage = &rec.stages[0];
        assert_eq!(stage.stage, "prompt_guard_request");
        assert_eq!(stage.outcome, StageOutcome::Block);
        assert_eq!(stage.reason.as_deref(), Some("pii detected"));
        assert_eq!(stage.categories, vec!["pii".to_string()]);
        assert!(stage.llm_call.is_none());
        // Request evidence retained via input_digest.
        assert!(
            stage
                .input_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn blocked_outcome_carries_rejecting_stage_io_gated_by_capture_bodies() {
        let make = |capture_bodies: bool| {
            built(CaptureInput {
                surface_id: "s1".to_string(),
                surface_name: None,
                trace_id: None,
                caller_identity: None,
                request: Some(json!({ "messages": [ { "role": "user", "content": "hi" } ] })),
                response: None,
                completion_text: None,
                policy: policy_for(capture_bodies),
                metrics: RecordMetrics::default(),
                outcome: InteractionOutcome::Blocked {
                    stage: "judge".to_string(),
                    reason: Some("rule matched".to_string()),
                    input: Some("what the judge saw".to_string()),
                    output: Some("blocked: policy".to_string()),
                    categories: Vec::new(),
                },
                extra_stages: vec![],
                export: None,
            })
        };

        // Bodies on: the block stage retains the judge's input/output + digests.
        let stage = &make(true).stages[0];
        assert_eq!(stage.stage, "judge");
        assert_eq!(stage.outcome, StageOutcome::Block);
        assert_eq!(stage.input.as_deref(), Some("what the judge saw"));
        assert_eq!(stage.output.as_deref(), Some("blocked: policy"));
        assert!(
            stage
                .input_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            stage
                .output_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );

        // Bodies off: the block stage keeps digests only.
        let stage = &make(false).stages[0];
        assert!(stage.input.is_none());
        assert!(stage.output.is_none());
        assert!(stage.input_digest.is_some());
        assert!(stage.output_digest.is_some());
    }

    #[test]
    fn failed_outcome_records_error_stage() {
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [] })),
            response: None,
            completion_text: None,
            policy: CapturePolicy::default(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Failed {
                stage: "llm_call".to_string(),
                reason: Some("upstream timeout".to_string()),
            },
            extra_stages: vec![],
            export: None,
        };
        let rec = built(input);
        assert_eq!(rec.stages.len(), 1);
        assert_eq!(rec.stages[0].outcome, StageOutcome::Error);
        assert!(
            rec.stages[0]
                .llm_call
                .is_none()
        );
    }

    #[test]
    fn denied_outcome_records_single_policy_stage_with_evidence() {
        let mut stage = StageEntry::decision("policy", StageOutcome::Block, Some("blocked by policy".to_string()));
        stage.policy_id = Some("def-1".to_string());
        stage.policy_version = Some("3".to_string());
        stage.policy_content_hash = Some("sha256:abc".to_string());
        let input = CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: Some("Surface One".to_string()),
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [{ "role": "user", "content": "hi" }] })),
            response: None,
            completion_text: None,
            policy: CapturePolicy::default(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Denied,
            extra_stages: vec![stage],
            export: None,
        };
        let rec = built(input);
        // Exactly the deciding policy stage — no synthesized duplicate, no completion.
        assert_eq!(rec.stages.len(), 1);
        assert!(rec.completion.is_none());
        let s = &rec.stages[0];
        assert_eq!(s.stage, "policy");
        assert_eq!(s.outcome, StageOutcome::Block);
        assert_eq!(s.policy_id.as_deref(), Some("def-1"));
        assert_eq!(s.policy_version.as_deref(), Some("3"));
        assert_eq!(
            s.policy_content_hash
                .as_deref(),
            Some("sha256:abc")
        );
        // The request digest is attached as the stage's input evidence.
        assert!(
            s.input_digest
                .as_deref()
                .unwrap_or_default()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn capture_is_noop_without_store() {
        // No store installed in unit tests → capture must not panic, and says
        // no record was written under the id it was given.
        let recorded = capture_with_id(
            CaptureInput {
                surface_id: "s".to_string(),
                surface_name: None,
                trace_id: None,
                caller_identity: None,
                request: None,
                response: None,
                completion_text: None,
                policy: CapturePolicy::default(),
                metrics: RecordMetrics::default(),
                outcome: InteractionOutcome::Completed,
                extra_stages: vec![],
                export: None,
            },
            new_record_id(),
        );
        assert!(!recorded);
    }

    fn record_for(caller_identity: Option<&str>) -> GovernanceRecord {
        built(CaptureInput {
            surface_id: "s1".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: caller_identity.map(str::to_string),
            request: None,
            response: None,
            completion_text: None,
            policy: CapturePolicy::digests_only(),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Failed {
                stage: "execution".to_string(),
                reason: None,
            },
            extra_stages: vec![],
            export: None,
        })
    }

    #[tokio::test]
    async fn a_record_is_attributed_to_its_request() {
        use crate::observability::request_context::RequestContext;
        let mut request = RequestContext {
            trace_id: "trace-1".to_string(),
            ..Default::default()
        };
        request.set_identity(Some(&crate::source_auth::AuthenticatedIdentity::ApiKey {
            key_name: "billing-bot".to_string(),
        }));
        request.usage.tenant_id = Some("acme".to_string());

        let mut before_gate = record_for(Some("whatever-the-call-site-named"));
        attribute_to_request(&mut before_gate, request.clone()).await;
        assert_eq!(
            before_gate
                .trace_id
                .as_deref(),
            Some("trace-1")
        );
        assert_eq!(before_gate.caller_identity_kind, Some(crate::governance::CallerIdentityKind::ApiKey));
        assert_eq!(before_gate.caller_identity_hash, Some(hash_caller("billing-bot")));
        assert_eq!(
            before_gate
                .attribution
                .tenant_id
                .as_deref(),
            Some("acme")
        );

        request.usage.member_id = Some("m-1".to_string());
        request.usage.team_ids = vec!["t-1".to_string()];
        request.usage.team_names = vec!["Payments".to_string()];
        let mut after_gate = record_for(None);
        attribute_to_request(&mut after_gate, request).await;
        assert_eq!(after_gate.caller_identity_kind, Some(crate::governance::CallerIdentityKind::Member));
        assert_eq!(after_gate.caller_identity_hash, Some(hash_caller("m-1")));
        assert_eq!(
            after_gate
                .attribution
                .member_id
                .as_deref(),
            Some("m-1")
        );
        assert_eq!(
            after_gate
                .attribution
                .team_names,
            vec!["Payments".to_string()]
        );
    }

    #[tokio::test]
    async fn a_record_keeps_the_trace_id_its_capture_named() {
        let mut record = record_for(None);
        record.trace_id = Some("exec-trace".to_string());
        attribute_to_request(
            &mut record,
            crate::observability::request_context::RequestContext {
                trace_id: "request-trace".to_string(),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(record.trace_id.as_deref(), Some("exec-trace"));
        assert!(
            record
                .caller_identity_kind
                .is_none(),
            "no caller is known"
        );
    }

    fn stage_body_input(capture_bodies: bool) -> CaptureInput {
        let stage = StageEntry::decision("judge", StageOutcome::Allow, Some("approved".to_string()))
            .with_io(Some("judge input".to_string()), Some("judge output".to_string()));
        CaptureInput {
            surface_id: "s".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: None,
            request: None,
            response: None,
            completion_text: None,
            policy: policy_for(capture_bodies),
            metrics: RecordMetrics::default(),
            outcome: InteractionOutcome::Completed,
            extra_stages: vec![stage],
            export: None,
        }
    }

    #[test]
    fn stage_bodies_retained_and_digested_when_capture_on() {
        let rec = built(stage_body_input(true));
        // stages[0] is the judge stage; the synthesized llm_call follows.
        let s = &rec.stages[0];
        assert_eq!(s.stage, "judge");
        assert_eq!(s.input.as_deref(), Some("judge input"));
        assert_eq!(s.output.as_deref(), Some("judge output"));
        assert!(
            s.input_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            s.output_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn stage_bodies_dropped_but_digested_when_capture_off() {
        let rec = built(stage_body_input(false));
        let s = &rec.stages[0];
        assert!(s.input.is_none());
        assert!(s.output.is_none());
        // Digests survive so digests-only mode keeps per-stage evidence.
        assert!(
            s.input_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
        assert!(
            s.output_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:")
        );
    }

    /// One interaction of each kind a surface can end in, captured under
    /// `policy`: completed, completed but cut off mid-stream, blocked, failed,
    /// policy-denied and policy-errored.
    fn every_outcome(policy: CapturePolicy) -> Vec<(&'static str, CaptureInput)> {
        let base = |outcome: InteractionOutcome, extra_stages: Vec<StageEntry>| CaptureInput {
            surface_id: "s".to_string(),
            surface_name: None,
            trace_id: None,
            caller_identity: None,
            request: Some(json!({ "messages": [ { "role": "user", "content": "the prompt" } ] })),
            response: Some(json!({ "choices": [ { "message": { "content": "the reply" } } ] })),
            completion_text: None,
            policy,
            metrics: RecordMetrics::default(),
            outcome,
            extra_stages,
            export: None,
        };
        let judge = || {
            StageEntry::decision("judge", StageOutcome::Allow, None)
                .with_io(Some("judge input".to_string()), Some("judge output".to_string()))
        };
        vec![
            ("completed", base(InteractionOutcome::Completed, vec![judge()])),
            (
                "aborted",
                base(InteractionOutcome::Completed, vec![StageEntry::decision("stream", StageOutcome::Error, None)]),
            ),
            (
                "blocked",
                base(
                    InteractionOutcome::Blocked {
                        stage: "jury".to_string(),
                        reason: Some("unsafe".to_string()),
                        input: Some("the reply".to_string()),
                        output: Some("verdict".to_string()),
                        categories: vec!["harm".to_string()],
                    },
                    vec![judge()],
                ),
            ),
            (
                "failed",
                base(
                    InteractionOutcome::Failed {
                        stage: "llm_call".to_string(),
                        reason: Some("timeout".to_string()),
                    },
                    vec![],
                ),
            ),
            (
                "denied",
                base(InteractionOutcome::Denied, vec![StageEntry::decision("policy", StageOutcome::Block, None)]),
            ),
            (
                "policy_error",
                base(InteractionOutcome::Denied, vec![StageEntry::decision("policy", StageOutcome::Error, None)]),
            ),
        ]
    }

    fn recorded(policy: CapturePolicy) -> Vec<&'static str> {
        every_outcome(policy)
            .into_iter()
            .filter(|(_, input)| decide(input).is_some())
            .map(|(name, _)| name)
            .collect()
    }

    #[test]
    fn the_outcome_known_before_the_record_matches_the_records_own() {
        for (name, input) in every_outcome(CapturePolicy::default()) {
            let expected = input
                .outcome
                .class(&input.extra_stages);
            assert_eq!(built(input).outcome(), expected, "{name}");
        }
    }

    #[test]
    fn every_outcome_is_recorded_by_default() {
        assert_eq!(
            recorded(CapturePolicy::default()),
            ["completed", "aborted", "blocked", "failed", "denied", "policy_error"]
        );
    }

    #[test]
    fn a_blocked_only_surface_records_blocks_and_denials_only() {
        let policy = CapturePolicy {
            outcomes: RecordScope::Blocked,
            ..CapturePolicy::default()
        };
        assert_eq!(recorded(policy), ["blocked", "denied"]);
    }

    #[test]
    fn a_blocked_and_failed_surface_skips_only_completed_interactions() {
        let policy = CapturePolicy {
            outcomes: RecordScope::BlockedAndFailed,
            ..CapturePolicy::default()
        };
        assert_eq!(recorded(policy), ["aborted", "blocked", "failed", "denied", "policy_error"]);
    }

    #[test]
    fn blocked_body_capture_keeps_text_for_blocks_only() {
        let policy = CapturePolicy {
            bodies: BodyCapture::Blocked,
            ..CapturePolicy::default()
        };
        for (name, input) in every_outcome(policy) {
            let rec = built(input);
            let kept = rec.prompt.is_some();
            assert_eq!(kept, matches!(name, "blocked" | "denied"), "{name}: prompt kept only for a block");
            assert!(rec.completion.is_none() || kept, "{name}: no completion without the prompt");
            if !kept {
                assert!(
                    rec.stages
                        .iter()
                        .all(|s| s.input.is_none() && s.output.is_none()),
                    "{name}: stage bodies dropped"
                );
            }
        }
        let blocked = built(
            every_outcome(policy)
                .remove(2)
                .1,
        );
        assert_eq!(blocked.prompt.as_deref(), Some("user: the prompt"));
        let jury = blocked
            .deciding_stage()
            .expect("the jury blocked it");
        assert_eq!(jury.input.as_deref(), Some("the reply"));
        assert_eq!(jury.output.as_deref(), Some("verdict"));
        assert!(
            blocked.stages[0]
                .input
                .is_some(),
            "the judge that ran before the block keeps its text too"
        );
    }

    #[test]
    fn no_body_capture_keeps_digests_for_blocks_too() {
        let rec = built(
            every_outcome(CapturePolicy::digests_only())
                .remove(2)
                .1,
        );
        assert!(rec.prompt.is_none());
        let jury = rec
            .deciding_stage()
            .expect("blocked");
        assert!(jury.input.is_none() && jury.output.is_none());
        assert!(jury.input_digest.is_some() && jury.output_digest.is_some());
    }
}
