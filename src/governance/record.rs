//! The `GovernanceRecord` domain model, canonical JSON serialization, and the
//! per-record content hash used to build the tamper-evident chain.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Chain-head value used for the first record on a surface's chain (genesis).
pub const GENESIS_HASH: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Whether a stage let the interaction proceed, blocked it, or flagged it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StageOutcome {
    /// The stage permitted the interaction to continue.
    Allow,
    /// The stage blocked the interaction (policy deny, guard rejection, etc.).
    Block,
    /// The stage flagged the interaction but did not block it.
    Flag,
    /// The stage ran informationally with no allow/block disposition.
    Observed,
    /// The stage failed with an infrastructure/transport error (not a
    /// policy-driven block) — e.g. an upstream timeout or connection failure.
    Error,
}

/// Evidence for a single `llm_call` attempt. Retries append additional entries
/// (`retry_index` increasing) so the record reflects every attempt, not only the
/// final one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LlmCall {
    /// Upstream provider that served (or was asked to serve) the attempt.
    pub provider: String,
    /// Model identifier requested upstream.
    pub model: String,
    /// 0-based attempt index within the interaction (0 = first call).
    pub retry_index: u32,
    /// `sha256:{hex}` digest of the request body sent upstream.
    pub request_digest: String,
    /// `sha256:{hex}` digest of the response body received upstream, when a
    /// response was produced (absent on transport failure).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_digest: Option<String>,
    /// Input tokens attributed to this attempt.
    #[serde(default)]
    pub input_tokens: u64,
    /// Output tokens attributed to this attempt.
    #[serde(default)]
    pub output_tokens: u64,
    /// USD cost attributed to this attempt.
    #[serde(default)]
    pub cost: f64,
}

/// One processing stage in the interaction transcript.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StageEntry {
    /// Stable stage name (`inbound`, `policy`, `prompt_guard_request`,
    /// `witness_request`, `decider`, `judge`, `llm_call`, `response_transform`,
    /// `jury`, `prompt_guard_response`, `witness_response`, `outbound`).
    pub stage: String,
    /// Disposition of the stage.
    pub outcome: StageOutcome,
    /// Human-readable reason (deny reason, verdict, routing choice).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Policy/definition identifier governing the stage, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    /// Policy-definition version in force at decision time, when applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,
    /// Content hash (`sha256:<hex>`) of the enforced policy revision, when
    /// applicable — makes a policy stage reproducible against exact Rego bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_content_hash: Option<String>,
    /// Name of the policy that decided a policy stage (its policy definition
    /// name, else its Rego query).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_name: Option<String>,
    /// Canonical rejection-category ids (`rejection_categories.json`) of a
    /// content block, e.g. `prompt_injection`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub categories: Vec<String>,
    /// `sha256:{hex}` digest of the request body at this stage, so a
    /// blocked/failed interaction keeps request evidence even in digests-only
    /// mode (where the prompt body is omitted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_digest: Option<String>,
    /// `sha256:{hex}` digest of this stage's output body, retained even in
    /// digests-only mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_digest: Option<String>,
    /// This stage's full input body (e.g. the content sent to the Judge/Jury/
    /// Decider model or the expert-witness provider). Present only when body
    /// capture is enabled; digests-only mode keeps just `input_digest`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    /// This stage's full output body (e.g. the model verdict or the witness
    /// provider response). Present only when body capture is enabled.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    /// `llm_call` evidence, present only on the main/target call stages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm_call: Option<LlmCall>,
    /// Source of the key this stage's model or provider call sent (`client`,
    /// `customer` or `platform`), on a stage that made one. Never the key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<crate::pipes::key_source::KeySource>,
}

impl StageEntry {
    /// A non-LLM disposition stage (policy/guard/judge/jury/etc.).
    pub fn decision(
        stage: impl Into<String>,
        outcome: StageOutcome,
        reason: Option<String>,
    ) -> Self {
        Self {
            stage: stage.into(),
            outcome,
            reason,
            policy_id: None,
            policy_version: None,
            policy_content_hash: None,
            policy_name: None,
            categories: Vec::new(),
            input_digest: None,
            output_digest: None,
            input: None,
            output: None,
            llm_call: None,
            key_source: None,
        }
    }

    /// Attach this stage's input/output bodies (governance capture applies the
    /// digest + body-gating downstream). Chainable on top of [`Self::decision`].
    pub fn with_io(
        mut self,
        input: Option<String>,
        output: Option<String>,
    ) -> Self {
        self.input = input;
        self.output = output;
        self
    }

    /// Attach the source of the key this stage's call sent. Chainable on top
    /// of [`Self::decision`].
    pub fn with_key_source(
        mut self,
        key_source: Option<crate::pipes::key_source::KeySource>,
    ) -> Self {
        self.key_source = key_source;
        self
    }

    /// An `llm_call` attempt stage carrying request/response evidence.
    pub fn llm(call: LlmCall) -> Self {
        Self {
            stage: "llm_call".to_string(),
            outcome: StageOutcome::Observed,
            reason: None,
            policy_id: None,
            policy_version: None,
            policy_content_hash: None,
            policy_name: None,
            categories: Vec::new(),
            input_digest: None,
            output_digest: None,
            input: None,
            output: None,
            llm_call: Some(call),
            key_source: None,
        }
    }
}

/// A grand-total metrics summary for the interaction, mirroring the fields of
/// the executor's `ExecutionMetrics` that matter for governance.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct RecordMetrics {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    pub cost: f64,
    pub latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Currency of every cost on the record (`USD`). Absent on records written
    /// before currencies were stated, which are US dollars.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    /// Usage of each stage that called a model (main LLM, judge, jury, decider),
    /// each under its own provider and model. The grand totals above include all
    /// of them under the main call's provider and model.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub usage_by_stage: Vec<StageUsageEntry>,
    /// The part of `cost` billed to the account: `cost` less the spend served
    /// on owned keys (the caller's or the customer's). `cost` stays the
    /// catalog-priced spend.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billed_cost: Option<f64>,
    /// Source of the key the main call sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_source: Option<crate::pipes::key_source::KeySource>,
    /// Every metered model call (main, judge, jury, decider), counted by the
    /// source of its key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sources: Option<crate::pipes::key_source::KeySourceCounts>,
    /// `true` when the main call's tokens, and the cost billed for them, are
    /// an estimate: a stream on a key that bills that ended without reporting
    /// its usage (see `pipes::streaming::StreamOutcome::billed_tokens`).
    /// Absent otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage_estimated: Option<bool>,
}

/// The currency every cost in Agent Stream is expressed in.
pub const USAGE_CURRENCY: &str = "USD";

impl RecordMetrics {
    /// The currency tag for a record that carries a cost (`Some("USD")`).
    pub fn usd() -> Option<String> {
        Some(USAGE_CURRENCY.to_string())
    }
}

/// One model-calling stage's usage within an interaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct StageUsageEntry {
    /// `llm`, `judge`, `jury` or `decider`.
    pub stage: String,
    /// Provider the stage called (`null` when the stage spans several, e.g. a
    /// jury of mixed providers).
    pub provider: Option<String>,
    /// Model the stage called (`null` when the stage spans several).
    pub model: Option<String>,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost: f64,
    /// The part of `cost` billed to the account (zero for calls on owned keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub billed_cost: Option<f64>,
    /// The stage's model calls, by the source of the key each one sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_sources: Option<crate::pipes::key_source::KeySourceCounts>,
}

/// A signed-record's transcript of one LLM-surface interaction. This is the
/// `credentialSubject` of the governance VC. The `content_hash` and
/// `prev_record_hash` fields make the log a tamper-evident chain.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRecord {
    /// Unique record id (UUID).
    pub record_id: String,
    /// Correlating request trace id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trace_id: Option<String>,
    /// Surface (pipe) id the interaction ran on.
    pub surface_id: String,
    /// Human-readable surface name at capture time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_name: Option<String>,
    /// Peppered HMAC-SHA256 hash of the caller identity — never raw PII.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_identity_hash: Option<String>,
    /// What `caller_identity_hash` was computed over.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller_identity_kind: Option<super::attribution::CallerIdentityKind>,
    /// Keyed hash of the authenticated caller shared with Agent Gateway, when a
    /// shared secret is configured.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_key: Option<String>,
    /// Member, teams and tenant the interaction is attributed to.
    #[serde(flatten)]
    pub attribution: super::attribution::UsageAttribution,
    /// ISO-8601 capture timestamp.
    pub timestamp: String,
    /// Content hash of the previous record on this surface's chain
    /// (`GENESIS_HASH` for the first record).
    pub prev_record_hash: String,
    /// Ordered stage transcript.
    #[serde(default)]
    pub stages: Vec<StageEntry>,
    /// Full caller input prompt (encrypted at rest by the store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt: Option<String>,
    /// Full model output completion (encrypted at rest by the store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion: Option<String>,
    /// Hash-only references to binary attachments (audio, documents, images) the
    /// caller sent. The raw bytes live in the multimedia store keyed by these
    /// hashes; the record never embeds them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attachments: Vec<super::multimedia_store::MediaRef>,
    /// Grand-total metrics summary.
    #[serde(default)]
    pub metrics: RecordMetrics,
    /// `sha256:{hex}` content hash over every field above (self-referential
    /// `content_hash` excluded). Set by [`GovernanceRecord::finalize`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_hash: Option<String>,
}

/// How an interaction ended, read off its stages: `blocked` when any stage
/// blocked it, else `failed` when any stage failed, else `ok`. Derived, never
/// stored in the record, so it leaves content hashes unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordOutcome {
    Ok,
    Blocked,
    Failed,
}

impl RecordOutcome {
    /// The outcome of an interaction with these stages.
    pub fn of_stages(stages: &[StageEntry]) -> Self {
        if stages
            .iter()
            .any(|s| s.outcome == StageOutcome::Block)
        {
            Self::Blocked
        } else if stages
            .iter()
            .any(|s| s.outcome == StageOutcome::Error)
        {
            Self::Failed
        } else {
            Self::Ok
        }
    }

    /// Parse `ok`, `blocked` or `failed`.
    pub fn parse(value: &str) -> Option<Self> {
        match value {
            "ok" => Some(Self::Ok),
            "blocked" => Some(Self::Blocked),
            "failed" => Some(Self::Failed),
            _ => None,
        }
    }
}

impl GovernanceRecord {
    /// How the recorded interaction ended.
    pub fn outcome(&self) -> RecordOutcome {
        RecordOutcome::of_stages(&self.stages)
    }

    /// The stage that decided a blocked or failed interaction: its last `Block`
    /// stage, else its last `Error` stage. `None` for an `ok` interaction.
    pub fn deciding_stage(&self) -> Option<&StageEntry> {
        let last = |outcome: StageOutcome| {
            self.stages
                .iter()
                .rev()
                .find(move |s| s.outcome == outcome)
        };
        last(StageOutcome::Block).or_else(|| last(StageOutcome::Error))
    }

    /// Compute this record's content hash over its canonical JSON form, with the
    /// self-referential `content_hash` field excluded, and store it. Returns the
    /// hash. Deterministic: independent of map ordering.
    pub fn finalize(&mut self) -> String {
        self.content_hash = None;
        let value = serde_json::to_value(&*self).unwrap_or(Value::Null);
        let hash = hash_canonical(&value);
        self.content_hash = Some(hash.clone());
        hash
    }

    /// Recompute the content hash and check it matches the stored value — the
    /// per-record integrity check used during verification.
    pub fn verify_content_hash(&self) -> bool {
        let Some(stored) = self.content_hash.clone() else {
            return false;
        };
        let mut probe = self.clone();
        probe.content_hash = None;
        let value = serde_json::to_value(&probe).unwrap_or(Value::Null);
        hash_canonical(&value) == stored
    }
}

/// `sha256:{hex}` over the canonical (recursively key-sorted) JSON encoding of a
/// value, so the digest is stable regardless of serializer map ordering.
pub fn hash_canonical(value: &Value) -> String {
    let mut hasher = Sha256::new();
    write_canonical(value, &mut hasher);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Serialize `value` into `hasher` in a canonical form: object keys sorted, no
/// insignificant whitespace. Arrays keep order (order is significant); scalars
/// use serde_json's canonical scalar encoding.
fn write_canonical(
    value: &Value,
    hasher: &mut Sha256,
) {
    match value {
        Value::Object(map) => {
            hasher.update(b"{");
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (k, v)) in entries
                .into_iter()
                .enumerate()
            {
                if i > 0 {
                    hasher.update(b",");
                }
                // Keys are strings; encode via serde_json to escape correctly.
                let key = Value::String(k.clone());
                hasher.update(
                    serde_json::to_string(&key)
                        .unwrap_or_default()
                        .as_bytes(),
                );
                hasher.update(b":");
                write_canonical(v, hasher);
            }
            hasher.update(b"}");
        }
        Value::Array(items) => {
            hasher.update(b"[");
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    hasher.update(b",");
                }
                write_canonical(v, hasher);
            }
            hasher.update(b"]");
        }
        other => {
            hasher.update(
                serde_json::to_string(other)
                    .unwrap_or_default()
                    .as_bytes(),
            );
        }
    }
}

/// `sha256:{hex}` digest of an arbitrary body (e.g. an upstream request or
/// response), used for the `llm_call` request/response digests.
pub fn digest_bytes(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{}", hex::encode(hasher.finalize()))
}

/// Build a canonical JSON string (key-sorted) for a value — used when the whole
/// canonical form is needed as text, not just its hash.
pub fn to_canonical_string(value: &Value) -> String {
    let mut buf = String::new();
    write_canonical_string(value, &mut buf);
    buf
}

fn write_canonical_string(
    value: &Value,
    out: &mut String,
) {
    match value {
        Value::Object(map) => {
            out.push('{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|a, b| a.0.cmp(b.0));
            for (i, (k, v)) in entries
                .into_iter()
                .enumerate()
            {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(&Value::String(k.clone())).unwrap_or_default());
                out.push(':');
                write_canonical_string(v, out);
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical_string(v, out);
            }
            out.push(']');
        }
        other => out.push_str(&serde_json::to_string(other).unwrap_or_default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sample_record() -> GovernanceRecord {
        GovernanceRecord {
            record_id: "rec-1".to_string(),
            trace_id: Some("trace-1".to_string()),
            surface_id: "surf-1".to_string(),
            surface_name: Some("Cost-guarded GPT".to_string()),
            caller_identity_hash: Some("abc123".to_string()),
            caller_identity_kind: None,
            principal_key: None,
            attribution: Default::default(),
            timestamp: "2026-08-12T00:00:00Z".to_string(),
            prev_record_hash: GENESIS_HASH.to_string(),
            stages: vec![
                StageEntry::decision("policy", StageOutcome::Allow, None),
                StageEntry::llm(LlmCall {
                    provider: "openai".to_string(),
                    model: "gpt-4o".to_string(),
                    retry_index: 0,
                    request_digest: digest_bytes(b"{\"messages\":[]}"),
                    response_digest: Some(digest_bytes(b"{\"choices\":[]}")),
                    input_tokens: 10,
                    output_tokens: 20,
                    cost: 0.001,
                }),
            ],
            prompt: Some("hello".to_string()),
            completion: Some("hi there".to_string()),
            attachments: Vec::new(),
            metrics: RecordMetrics {
                input_tokens: 10,
                output_tokens: 20,
                total_tokens: 30,
                cost: 0.001,
                latency_ms: 42,
                provider: Some("openai".to_string()),
                model: Some("gpt-4o".to_string()),
                ..Default::default()
            },
            content_hash: None,
        }
    }

    #[test]
    fn metrics_without_currency_or_stage_usage_serialize_unchanged() {
        // A record written before `currency` / `usage_by_stage` existed hashes
        // the same: the absent fields are skipped on serialization.
        let value = serde_json::to_value(RecordMetrics::default()).unwrap();
        assert!(
            value
                .get("currency")
                .is_none()
        );
        assert!(
            value
                .get("usage_by_stage")
                .is_none()
        );
        let old: RecordMetrics = serde_json::from_value(json!({
            "input_tokens": 1, "output_tokens": 2, "total_tokens": 3, "cost": 0.5, "latency_ms": 4
        }))
        .unwrap();
        assert_eq!(old.currency, None);
        assert!(old.usage_by_stage.is_empty());
        assert_eq!(
            serde_json::to_value(&old)
                .unwrap()
                .get("currency"),
            None
        );
    }

    #[test]
    fn billing_fields_are_absent_until_set_and_carry_only_labels() {
        use crate::pipes::key_source::{KeySource, KeySourceCounts};
        let value = serde_json::to_value(RecordMetrics::default()).unwrap();
        for field in ["billed_cost", "key_source", "key_sources"] {
            assert!(value.get(field).is_none(), "{field} must not change an existing record's hash");
        }
        let stage = serde_json::to_value(StageEntry::decision("judge", StageOutcome::Allow, None)).unwrap();
        assert!(
            stage
                .get("key_source")
                .is_none()
        );

        let metrics = RecordMetrics {
            cost: 0.5,
            billed_cost: Some(0.0),
            key_source: Some(KeySource::Customer),
            key_sources: Some(KeySourceCounts::one(KeySource::Customer)),
            ..Default::default()
        };
        let value = serde_json::to_value(&metrics).unwrap();
        assert_eq!(value["cost"], json!(0.5));
        assert_eq!(value["billed_cost"], json!(0.0));
        assert_eq!(value["key_source"], json!("customer"));
        assert_eq!(value["key_sources"], json!({ "client": 0, "customer": 1, "platform": 0 }));
        let stage = StageEntry::decision("judge", StageOutcome::Allow, None).with_key_source(Some(KeySource::Platform));
        assert_eq!(serde_json::to_value(stage).unwrap()["key_source"], json!("platform"));
    }

    #[test]
    fn metrics_carry_currency_and_stage_usage() {
        let m = RecordMetrics {
            currency: RecordMetrics::usd(),
            usage_by_stage: vec![StageUsageEntry {
                stage: "judge".into(),
                provider: Some("openai".into()),
                model: Some("gpt-4o-mini".into()),
                input_tokens: 10,
                output_tokens: 2,
                cost: 0.001,
                ..Default::default()
            }],
            ..Default::default()
        };
        let v = serde_json::to_value(&m).unwrap();
        assert_eq!(v["currency"], "USD");
        assert_eq!(v["usage_by_stage"][0]["stage"], "judge");
        assert_eq!(v["usage_by_stage"][0]["model"], "gpt-4o-mini");
        assert_eq!(v["usage_by_stage"][0]["input_tokens"], 10);
        let mut a = sample_record();
        a.metrics = m;
        let mut b = sample_record();
        assert_ne!(a.finalize(), b.finalize());
    }

    #[test]
    fn a_record_is_blocked_failed_or_ok_by_its_stages() {
        let mut rec = sample_record();
        assert_eq!(rec.outcome(), RecordOutcome::Ok);
        assert!(rec.deciding_stage().is_none());

        rec.stages
            .push(StageEntry::decision("stream", StageOutcome::Error, None));
        assert_eq!(rec.outcome(), RecordOutcome::Failed);
        assert_eq!(
            rec.deciding_stage()
                .map(|s| s.stage.as_str()),
            Some("stream")
        );

        rec.stages
            .push(StageEntry::decision("judge", StageOutcome::Block, None));
        rec.stages
            .push(StageEntry::decision("jury", StageOutcome::Allow, None));
        assert_eq!(rec.outcome(), RecordOutcome::Blocked, "a block outranks a failure");
        assert_eq!(
            rec.deciding_stage()
                .map(|s| s.stage.as_str()),
            Some("judge")
        );

        let flagged = vec![StageEntry::decision("jury", StageOutcome::Flag, None)];
        assert_eq!(RecordOutcome::of_stages(&flagged), RecordOutcome::Ok, "a flag does not block");
    }

    #[test]
    fn outcomes_parse_their_wire_names_only() {
        assert_eq!(RecordOutcome::parse("ok"), Some(RecordOutcome::Ok));
        assert_eq!(RecordOutcome::parse("blocked"), Some(RecordOutcome::Blocked));
        assert_eq!(RecordOutcome::parse("failed"), Some(RecordOutcome::Failed));
        assert_eq!(RecordOutcome::parse("Blocked"), None);
        assert_eq!(RecordOutcome::parse("block"), None);
        assert_eq!(serde_json::to_value(RecordOutcome::Blocked).unwrap(), json!("blocked"));
    }

    #[test]
    fn canonical_hash_is_order_independent() {
        let a = json!({ "b": 1, "a": 2, "c": [1, 2, 3] });
        let b = json!({ "c": [1, 2, 3], "a": 2, "b": 1 });
        assert_eq!(hash_canonical(&a), hash_canonical(&b));
    }

    #[test]
    fn canonical_hash_respects_array_order() {
        let a = json!({ "x": [1, 2, 3] });
        let b = json!({ "x": [3, 2, 1] });
        assert_ne!(hash_canonical(&a), hash_canonical(&b));
    }

    #[test]
    fn finalize_sets_and_verifies_content_hash() {
        let mut rec = sample_record();
        let hash = rec.finalize();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(rec.content_hash.as_deref(), Some(hash.as_str()));
        assert!(rec.verify_content_hash());
    }

    #[test]
    fn tampering_breaks_content_hash() {
        let mut rec = sample_record();
        rec.finalize();
        // Mutate a body after finalize — verification must fail.
        rec.completion = Some("a different answer".to_string());
        assert!(!rec.verify_content_hash());
    }

    #[test]
    fn finalize_is_deterministic() {
        let mut a = sample_record();
        let mut b = sample_record();
        assert_eq!(a.finalize(), b.finalize());
    }

    #[test]
    fn canonical_string_matches_hash_input() {
        let v = json!({ "b": 1, "a": 2 });
        assert_eq!(to_canonical_string(&v), "{\"a\":2,\"b\":1}");
        assert_eq!(hash_canonical(&v), digest_bytes(to_canonical_string(&v).as_bytes()));
    }

    #[test]
    fn unset_attribution_leaves_earlier_records_hashes_unchanged() {
        let mut rec = sample_record();
        rec.finalize();
        let legacy = serde_json::to_value(&rec).unwrap();
        for key in ["caller_identity_kind", "principal_key", "member_id", "team_ids", "team_names", "tenant_id"] {
            assert!(legacy.get(key).is_none(), "{key} is absent when unset");
        }
        assert!(
            legacy["stages"][0]
                .get("policy_name")
                .is_none()
        );
        assert!(
            legacy["stages"][0]
                .get("categories")
                .is_none()
        );

        let read_back: GovernanceRecord = serde_json::from_value(legacy).unwrap();
        assert!(read_back.verify_content_hash(), "a record written without the new fields still verifies");
    }

    #[test]
    fn attribution_and_block_evidence_are_recorded_flat_and_hashed() {
        let mut rec = sample_record();
        rec.caller_identity_kind = Some(super::super::attribution::CallerIdentityKind::Member);
        rec.principal_key = Some("pk".to_string());
        rec.attribution.member_id = Some("m-1".to_string());
        rec.attribution.team_ids = vec!["t-1".to_string()];
        rec.attribution.team_names = vec!["Payments".to_string()];
        rec.attribution.tenant_id = Some("acme".to_string());
        rec.stages[0].policy_name = Some("Block PII".to_string());
        rec.stages[0].categories = vec!["pii".to_string()];
        let before = sample_record().finalize();
        let hash = rec.finalize();
        assert_ne!(hash, before);
        assert!(rec.verify_content_hash());

        let value = serde_json::to_value(&rec).unwrap();
        assert_eq!(value["caller_identity_kind"], "member");
        assert_eq!(value["principal_key"], "pk");
        assert_eq!(value["member_id"], "m-1");
        assert_eq!(value["team_ids"], json!(["t-1"]));
        assert_eq!(value["team_names"], json!(["Payments"]));
        assert_eq!(value["tenant_id"], "acme");
        assert_eq!(value["stages"][0]["policy_name"], "Block PII");
        assert_eq!(value["stages"][0]["categories"], json!(["pii"]));
        let back: GovernanceRecord = serde_json::from_value(value).unwrap();
        assert_eq!(back, rec);
    }
}
