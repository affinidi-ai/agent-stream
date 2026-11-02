//! Judge & Jury configuration types

use serde::{Deserialize, Serialize};

/// LLM target configuration for Judge/Jury calls.
/// Contains all information needed to make an LLM API call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LLMTarget {
    /// Provider type (e.g., "openai", "anthropic", "gemini")
    pub provider_type: String,
    /// Model identifier (e.g., "gpt-4o-mini", "claude-3-haiku")
    pub model: String,
    /// API endpoint URL
    pub endpoint_url: String,
    /// Secret ID for the API key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    /// Provider-specific model parameters (temperature, max_tokens, etc.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<serde_json::Value>,
    /// Request timeout in seconds (default: 30)
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Model capabilities (e.g., supports_json_mode). Populated from pipes.json model definitions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<serde_json::Value>,
    /// API request/response wire format: "openai", "anthropic", "gemini", etc.
    /// Populated from pipes.json provider `api_schema` field.
    /// Determines how requests are built and responses are parsed.
    #[serde(default = "default_api_schema")]
    pub api_schema: String,
    /// Extra headers sent with every call to this target, beside its own
    /// credential, each value resolved from the secrets store at request time.
    /// They are this target's alone: never sent to the surface's own upstream,
    /// to another target, or across a redirect.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub headers: Vec<crate::pipes::upstream_headers::UpstreamHeader>,
    /// Declared price of this target. When set it is used as-is, zero
    /// included, ahead of the surface's price override and the catalog.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pricing: Option<crate::pipes::types::llm::TargetPricing>,
}

impl LLMTarget {
    /// The absolute URL a call to this target is sent to: `endpoint_url` with
    /// `{model}` filled in, a relative path resolved against the provider's
    /// default base. This is the endpoint the target's `headers` are
    /// configured for.
    pub fn resolved_endpoint(&self) -> String {
        let raw = self
            .endpoint_url
            .replace("{model}", &self.model);
        crate::pipes::defaults::resolve_endpoint_url(&self.provider_type, &raw)
    }
}

/// How to evaluate the Jury LLM's response to determine approval/rejection.
/// Used by Jury/Jurors (not Judge — Judge uses its own rule-based system).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum DecisionMode {
    /// Parse response as JSON, check a field value
    Json {
        /// JSON field name to check (default: "decision")
        #[serde(default = "default_json_field")]
        field: String,
        /// Value that means approved (default: "approve")
        #[serde(default = "default_approve_value")]
        approve_value: String,
    },
    /// Match response text against regex patterns
    Regex {
        /// Pattern that, if matched, means approved
        approve_pattern: String,
        /// Pattern that, if matched, means rejected (checked first)
        #[serde(skip_serializing_if = "Option::is_none")]
        reject_pattern: Option<String>,
    },
}

impl Default for DecisionMode {
    fn default() -> Self {
        DecisionMode::Json {
            field: default_json_field(),
            approve_value: default_approve_value(),
        }
    }
}

// ── Judge-specific types ──

/// How the Judge operates
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JudgeMode {
    /// Use the OpenAI Moderations API for content classification
    Moderation,
    /// Use a Chat Completions LLM with a custom system prompt
    #[default]
    Llm,
}

/// A single Judge rejection rule.
/// Rules are evaluated in order — first matching rule triggers rejection.
/// If no rules match, the request is approved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeRule {
    /// Human-readable name for this rule
    pub name: String,
    /// Condition that triggers this rule
    pub condition: JudgeCondition,
    /// HTTP status code when this rule triggers (default: 403)
    #[serde(default = "default_rejection_status")]
    pub status_code: u16,
    /// Response body when this rule triggers
    #[serde(default)]
    pub body: String,
    /// Content-Type header (default: application/json)
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

/// Condition for a Judge rule.
/// Uses a flat struct rather than a tagged enum to avoid serde issues
/// with f64 in internally-tagged enums.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct JudgeCondition {
    /// Condition type: "flagged", "category_flagged", "category_score",
    /// "json_field_equals", "json_field_not_equals", "regex_match"
    #[serde(rename = "type")]
    pub condition_type: String,
    /// Category name (for category_flagged and category_score)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Comparison operator (for category_score): ">=", ">", "<=", "<", "=="
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator: Option<String>,
    /// Score threshold (for category_score)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<f64>,
    /// JSON field name (for json_field_equals and json_field_not_equals)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    /// Value to compare against (for json_field_equals and json_field_not_equals)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Regex pattern (for regex_match)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
}

/// Judge configuration — pre-processing validation with multiple rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeConfig {
    /// Whether the Judge is active
    #[serde(default)]
    pub enabled: bool,
    /// Judge mode: "moderation" (OpenAI Moderations API) or "llm" (Chat Completions)
    #[serde(default)]
    pub mode: JudgeMode,
    /// LLM target (provider, model, endpoint, api_key, timeout)
    pub llm: LLMTarget,
    /// System prompt (only used in LLM mode)
    #[serde(default)]
    pub system_prompt: String,
    /// Strictness level: "strict", "balanced", "lenient" (UI metadata, used for prompt generation)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<String>,
    /// Focus areas for content evaluation (UI metadata, injected into system prompt)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus_areas: Option<Vec<String>>,
    /// Confidence threshold (0.0–1.0, UI metadata): asks the model for a confidence; never changes the verdict
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_threshold: Option<f64>,
    /// Custom domain-specific instructions (UI metadata, appended to system prompt)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Disable thinking/chain-of-thought for reasoning models (e.g. qwen3).
    /// When true: injects /no_think into the system prompt and adds "think": false to Ollama requests.
    /// When false or absent: thinking is allowed but the system will auto-retry with thinking
    /// disabled if the model exhausts max_tokens on reasoning without producing a JSON decision.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_thinking: Option<bool>,
    /// Rejection rules evaluated in order. First matching rule triggers rejection.
    /// If no rules match, the request is approved.
    #[serde(default)]
    pub rules: Vec<JudgeRule>,
}

impl JudgeConfig {
    /// Validate that every rule uses a condition type of the Judge's mode, that
    /// category rules name a category, that JSON field rules name a field, and
    /// that a `regex_match` pattern is non-empty and compiles. A disabled Judge
    /// always passes.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let (mode, allowed): (&str, &[&str]) = match self.mode {
            JudgeMode::Moderation => ("moderation", &["flagged", "category_flagged", "category_score"]),
            JudgeMode::Llm => ("llm", &["json_field_equals", "json_field_not_equals", "regex_match"]),
        };
        for rule in &self.rules {
            let condition_type = rule
                .condition
                .condition_type
                .as_str();
            if !allowed.contains(&condition_type) {
                return Err(format!(
                    "Judge rule '{}': condition type '{}' is not valid in {} mode",
                    rule.name, condition_type, mode
                ));
            }
            match condition_type {
                "regex_match" => {
                    let pattern = rule
                        .condition
                        .pattern
                        .as_deref()
                        .unwrap_or("");
                    if pattern.is_empty() {
                        return Err(format!("Judge rule '{}': regex_match requires a pattern", rule.name));
                    }
                    regex::Regex::new(pattern)
                        .map_err(|e| format!("Judge rule '{}': invalid regex pattern: {}", rule.name, e))?;
                }
                "json_field_equals" | "json_field_not_equals" => {
                    let field = rule
                        .condition
                        .field
                        .as_deref()
                        .unwrap_or("");
                    if field.trim().is_empty() {
                        return Err(format!("Judge rule '{}': {} requires a field", rule.name, condition_type));
                    }
                }
                "category_flagged" | "category_score" => {
                    let category = rule
                        .condition
                        .category
                        .as_deref()
                        .unwrap_or("");
                    if category.trim().is_empty() {
                        return Err(format!("Judge rule '{}': {} requires a category", rule.name, condition_type));
                    }
                }
                _ => {}
            }
        }
        Ok(())
    }
}

fn default_timeout_secs() -> u64 {
    30
}

fn default_api_schema() -> String {
    "openai".to_string()
}

fn default_json_field() -> String {
    "decision".to_string()
}

fn default_approve_value() -> String {
    "approve".to_string()
}

#[allow(dead_code)]
fn default_score_operator() -> String {
    ">=".to_string()
}

/// Jury configuration — LLM-based post-processing validation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JuryConfig {
    /// Whether the Jury is active
    #[serde(default)]
    pub enabled: bool,
    /// Execution mode for jurors
    #[serde(default)]
    pub mode: JuryExecutionMode,
    /// One or more juror definitions
    #[serde(default)]
    pub jurors: Vec<JurorConfig>,
    /// Maximum number of retry loops when the Jury rejects the LLM response.
    /// When > 0, the Jury rejection reason is appended to the conversation and the
    /// LLM is called again, up to this many times.  0 = no retries (default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_retries: Option<u32>,
    /// Prompt template for the retry message sent back to the LLM.
    /// Use `{reason}` as a placeholder for the Jury's rejection reason.
    /// Default: "Your previous response was rejected by quality review: {reason}. Please revise your response to address these concerns."
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_prompt: Option<String>,
    /// Custom rejection response when Jury rejects (after all retries exhausted)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection: Option<JudgeJuryRejection>,
}

impl JuryConfig {
    /// Validate that every enabled Juror's regex decision patterns compile.
    /// A disabled Jury always passes.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        for juror in self
            .jurors
            .iter()
            .filter(|j| j.enabled)
        {
            if let DecisionMode::Regex {
                approve_pattern,
                reject_pattern,
            } = &juror.decision
            {
                regex::Regex::new(approve_pattern)
                    .map_err(|e| format!("Juror '{}': invalid approve_pattern: {}", juror.name, e))?;
                if let Some(reject_pattern) = reject_pattern {
                    regex::Regex::new(reject_pattern)
                        .map_err(|e| format!("Juror '{}': invalid reject_pattern: {}", juror.name, e))?;
                }
            }
        }
        Ok(())
    }
}

/// How jurors are executed
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum JuryExecutionMode {
    /// All jurors run in parallel; ALL must approve
    #[default]
    Parallel,
    /// Jurors run sequentially; stop on first rejection
    Serial,
    /// All jurors run in parallel; more than half must approve
    Majority,
}

/// A single juror definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JurorConfig {
    /// Whether this juror participates in evaluation. Disabled jurors keep
    /// their configuration but are skipped at runtime. Defaults to true so
    /// existing saved juries (without the field) stay active.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Human-readable name for this juror
    pub name: String,
    /// LLM to use for this juror
    pub llm: LLMTarget,
    /// System prompt for this juror
    pub system_prompt: String,
    /// How to interpret this juror's response
    #[serde(default)]
    pub decision: DecisionMode,
    /// Strictness level: "strict", "balanced", "lenient" (UI metadata)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strictness: Option<String>,
    /// Focus areas for content evaluation (UI metadata)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub focus_areas: Option<Vec<String>>,
    /// Confidence threshold (0.0–1.0, UI metadata): asks the model for a confidence; never changes the verdict
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence_threshold: Option<f64>,
    /// Custom domain-specific instructions (UI metadata)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_instructions: Option<String>,
    /// Disable thinking/chain-of-thought for reasoning models (e.g. qwen3).
    /// When true: injects /no_think and adds "think": false to Ollama requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_thinking: Option<bool>,
}

/// Custom rejection response for Judge/Jury
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JudgeJuryRejection {
    /// HTTP status code (default: 403)
    #[serde(default = "default_rejection_status")]
    pub status_code: u16,
    /// Response body
    #[serde(default = "default_judge_rejection_body")]
    pub body: String,
    /// Content-Type header
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

impl Default for JudgeJuryRejection {
    fn default() -> Self {
        Self {
            status_code: default_rejection_status(),
            body: default_judge_rejection_body(),
            content_type: default_content_type(),
        }
    }
}

fn default_true() -> bool {
    true
}

fn default_rejection_status() -> u16 {
    403
}

fn default_judge_rejection_body() -> String {
    r#"{"error":{"message":"Request rejected by Judge/Jury evaluation","type":"judge_jury_violation","code":"content_policy_violation"}}"#.to_string()
}

fn default_content_type() -> String {
    "application/json".to_string()
}

// ── Decider types ──

/// Upper bound on Mirror-strategy candidates. Every candidate is called on every
/// request, so the fan-out is capped to keep per-request egress, latency, and
/// cost bounded regardless of how the surface is configured.
pub const MAX_MIRROR_CANDIDATES: usize = 10;

/// How the Decider dispatches a request across its candidates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeciderStrategy {
    /// The router LLM inspects the request and selects a single candidate whose
    /// provider then serves the request (the classic content-based router).
    #[default]
    Route,
    /// Fan the request out to every candidate concurrently, then aggregate the
    /// answers (see [`MirrorMode`]). No router LLM runs in this strategy.
    Mirror,
}

/// How Mirror strategy aggregates the fanned-out candidate answers.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MirrorMode {
    /// A dedicated merger LLM synthesizes all candidate answers into one best
    /// answer, which then continues through the Jury/guard pipeline as normal.
    #[default]
    Merge,
    /// Return every candidate answer verbatim so a human can compare and choose.
    /// No merger and no Jury run; the response carries all answers.
    Collect,
}

/// Mirror-strategy settings. Only consulted when
/// [`DeciderConfig::strategy`] is [`DeciderStrategy::Mirror`].
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MirrorConfig {
    /// Aggregation applied to the fanned-out candidate answers.
    #[serde(default)]
    pub mode: MirrorMode,
    /// The LLM that synthesizes the candidate answers into one. Independently
    /// configured (its own provider/model/prompt) and required when
    /// `mode == Merge`; ignored in `Collect` mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merger: Option<LLMTarget>,
    /// System prompt steering the merge. The candidate answers are appended
    /// automatically, so this only needs the synthesis policy/criteria. Falls
    /// back to a built-in synthesis instruction when empty.
    #[serde(default)]
    pub merge_system_prompt: String,
    /// Disable thinking/chain-of-thought for a reasoning merger model (e.g. qwen3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_thinking: Option<bool>,
}

/// Decider configuration — content-based routing across candidate upstreams.
///
/// In the default [`DeciderStrategy::Route`] strategy a small, fast "router" LLM
/// inspects the incoming request and selects one of the configured
/// [`DeciderCandidate`]s, whose `llm` target then serves the main upstream call.
/// In [`DeciderStrategy::Mirror`] the request is fanned out to every candidate
/// and the answers are aggregated per [`MirrorConfig`]. When disabled the pipe
/// uses its base provider unchanged.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeciderConfig {
    /// Whether the Decider is active.
    #[serde(default)]
    pub enabled: bool,
    /// Dispatch strategy: route to one candidate (default) or mirror to all.
    #[serde(default)]
    pub strategy: DeciderStrategy,
    /// The router LLM that makes the routing decision (typically small and
    /// fast). Required by [`DeciderStrategy::Route`]; unused (and typically
    /// absent) in `Mirror`, which fans out to every candidate instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub llm: Option<LLMTarget>,
    /// System prompt steering the routing decision. The candidate menu is
    /// appended automatically, so this only needs the routing policy/criteria.
    #[serde(default)]
    pub system_prompt: String,
    /// Candidate upstreams. In `Route` the router selects one; in `Mirror` every
    /// candidate is called. Must be non-empty when the Decider is enabled.
    #[serde(default)]
    pub candidates: Vec<DeciderCandidate>,
    /// Id of the candidate used when the router returns an unknown id or fails.
    /// When unset, the first candidate is the fallback. (Route strategy only.)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_candidate_id: Option<String>,
    /// Mirror-strategy aggregation settings. Consulted only when
    /// `strategy == Mirror`.
    #[serde(default)]
    pub mirror: MirrorConfig,
    /// Disable thinking/chain-of-thought for reasoning router models (e.g. qwen3).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_thinking: Option<bool>,
}

/// A single routable upstream the Decider may select.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeciderCandidate {
    /// Stable identifier the router returns to select this candidate.
    pub id: String,
    /// Human-readable name (UI + router menu).
    pub name: String,
    /// What this candidate is best suited for. Fed into the router menu so the
    /// model can reason about which upstream to pick.
    #[serde(default)]
    pub description: String,
    /// The upstream LLM target used for the main call when this candidate wins.
    pub llm: LLMTarget,
}

impl DeciderConfig {
    /// Resolve the candidate matching `id`, falling back to the configured
    /// default and then the first candidate. Returns `None` only when there are
    /// no candidates at all — so an enabled, validated Decider always resolves.
    pub fn resolve_candidate(
        &self,
        id: &str,
    ) -> Option<&DeciderCandidate> {
        self.candidates
            .iter()
            .find(|c| c.id == id)
            .or_else(|| {
                self.default_candidate_id
                    .as_deref()
                    .and_then(|d| {
                        self.candidates
                            .iter()
                            .find(|c| c.id == d)
                    })
            })
            .or_else(|| self.candidates.first())
    }

    /// Validate the Decider configuration. A disabled Decider always passes.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        if self.candidates.is_empty() {
            return Err("Decider is enabled but has no candidates".to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for candidate in &self.candidates {
            if candidate.id.trim().is_empty() {
                return Err("Decider candidate id must not be empty".to_string());
            }
            if !seen.insert(candidate.id.as_str()) {
                return Err(format!("duplicate Decider candidate id '{}'", candidate.id));
            }
        }
        if let Some(default_id) = &self.default_candidate_id
            && !self
                .candidates
                .iter()
                .any(|c| &c.id == default_id)
        {
            return Err(format!("Decider default_candidate_id '{}' is not a candidate", default_id));
        }
        // Route selects one candidate via the router LLM, so it must be present.
        // Mirror fans out to every candidate and never calls a router.
        if self.strategy == DeciderStrategy::Route && self.llm.is_none() {
            return Err("Decider Route strategy requires a router LLM".to_string());
        }
        // Mirror strategy fans out to every candidate; the Merge aggregation
        // needs a dedicated merger LLM to synthesize the answers.
        if self.strategy == DeciderStrategy::Mirror
            && self.mirror.mode == MirrorMode::Merge
            && self.mirror.merger.is_none()
        {
            return Err("Decider Mirror strategy with Merge mode requires a merger LLM".to_string());
        }
        // Mirror calls every candidate on every request, so cap the fan-out to
        // keep per-request egress, latency, and cost bounded.
        if self.strategy == DeciderStrategy::Mirror && self.candidates.len() > MAX_MIRROR_CANDIDATES {
            return Err(format!(
                "Decider Mirror strategy allows at most {} candidates (got {})",
                MAX_MIRROR_CANDIDATES,
                self.candidates.len()
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_judge_config_llm_mode() {
        let json = r#"{
            "enabled": true,
            "mode": "llm",
            "llm": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "endpoint_url": "https://api.openai.com/v1/chat/completions",
                "api_key_secret": "secret-123"
            },
            "system_prompt": "You are a safety reviewer.",
            "rules": [
                {
                    "name": "Reject harmful",
                    "condition": { "type": "json_field_equals", "field": "decision", "value": "reject" },
                    "status_code": 403,
                    "body": "{\"error\":\"Rejected\"}",
                    "content_type": "application/json"
                }
            ]
        }"#;

        let config: JudgeConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mode, JudgeMode::Llm);
        assert_eq!(config.llm.provider_type, "openai");
        assert_eq!(config.system_prompt, "You are a safety reviewer.");
        assert_eq!(config.rules.len(), 1);
        assert_eq!(config.rules[0].name, "Reject harmful");
        assert_eq!(config.rules[0].status_code, 403);
    }

    #[test]
    fn test_deserialize_judge_config_moderation_mode() {
        let json = r#"{
            "enabled": true,
            "mode": "moderation",
            "llm": {
                "provider_type": "openai",
                "model": "omni-moderation-latest",
                "endpoint_url": "https://api.openai.com/v1/moderations",
                "api_key_secret": "secret-123"
            },
            "system_prompt": "",
            "rules": [
                {
                    "name": "Violence check",
                    "condition": { "type": "category_flagged", "category": "violence" },
                    "status_code": 403,
                    "body": "Violence detected",
                    "content_type": "text/plain"
                },
                {
                    "name": "Harassment threshold",
                    "condition": { "type": "category_score", "category": "harassment", "operator": ">=", "threshold": 0.7 },
                    "status_code": 403,
                    "body": "{\"error\":\"Harassment score too high\"}",
                    "content_type": "application/json"
                }
            ]
        }"#;

        let config: JudgeConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mode, JudgeMode::Moderation);
        assert_eq!(config.rules.len(), 2);
        match &config.rules[0].condition {
            c if c.condition_type == "category_flagged" => {
                assert_eq!(c.category.as_deref(), Some("violence"));
            }
            _ => panic!("Expected category_flagged condition"),
        }
        match &config.rules[1].condition {
            c if c.condition_type == "category_score" => {
                assert_eq!(c.category.as_deref(), Some("harassment"));
                assert_eq!(c.operator.as_deref(), Some(">="));
                assert!((c.threshold.unwrap() - 0.7).abs() < f64::EPSILON);
            }
            _ => panic!("Expected category_score condition"),
        }
    }

    #[test]
    fn test_judge_condition_flagged() {
        let json = r#"{"type": "flagged"}"#;
        let condition: JudgeCondition = serde_json::from_str(json).unwrap();
        assert_eq!(condition.condition_type, "flagged");
    }

    #[test]
    fn test_judge_condition_regex_match() {
        let json = r#"{"type": "regex_match", "pattern": "(?i)\\bBLOCKED\\b"}"#;
        let condition: JudgeCondition = serde_json::from_str(json).unwrap();
        assert_eq!(condition.condition_type, "regex_match");
        assert!(
            condition
                .pattern
                .unwrap()
                .contains("BLOCKED")
        );
    }

    #[test]
    fn test_judge_mode_default() {
        let json = r#"{
            "enabled": false,
            "llm": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "endpoint_url": "https://api.openai.com/v1/chat/completions"
            }
        }"#;

        let config: JudgeConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.mode, JudgeMode::Llm);
        assert!(config.rules.is_empty());
    }

    #[test]
    fn test_deserialize_jury_config() {
        let json = r#"{
            "enabled": true,
            "mode": "parallel",
            "jurors": [
                {
                    "name": "Factuality Check",
                    "llm": {
                        "provider_type": "openai",
                        "model": "gpt-4o-mini",
                        "endpoint_url": "https://api.openai.com/v1/chat/completions",
                        "api_key_secret": "secret-123"
                    },
                    "system_prompt": "Check for factual accuracy.",
                    "decision": {
                        "mode": "regex",
                        "approve_pattern": "(?i)\\bAPPROVED\\b",
                        "reject_pattern": "(?i)\\bREJECTED\\b"
                    }
                },
                {
                    "name": "Tone Check",
                    "llm": {
                        "provider_type": "openai",
                        "model": "gpt-4o",
                        "endpoint_url": "https://api.openai.com/v1/chat/completions"
                    },
                    "system_prompt": "Check for appropriate tone.",
                    "decision": {
                        "mode": "json"
                    }
                }
            ]
        }"#;

        let config: JuryConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.mode, JuryExecutionMode::Parallel);
        assert_eq!(config.jurors.len(), 2);
        assert_eq!(config.jurors[0].name, "Factuality Check");
        assert_eq!(config.jurors[1].name, "Tone Check");
    }

    #[test]
    fn test_default_decision_mode_jury() {
        let json = r#"{
            "name": "Test Juror",
            "llm": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "endpoint_url": "https://api.openai.com/v1/chat/completions"
            },
            "system_prompt": "Check this."
        }"#;

        let config: JurorConfig = serde_json::from_str(json).unwrap();
        match config.decision {
            DecisionMode::Json { field, approve_value } => {
                assert_eq!(field, "decision");
                assert_eq!(approve_value, "approve");
            }
            _ => panic!("Expected default JSON decision mode"),
        }
    }

    #[test]
    fn test_jury_execution_modes() {
        for (mode_str, expected) in [
            ("\"parallel\"", JuryExecutionMode::Parallel),
            ("\"serial\"", JuryExecutionMode::Serial),
            ("\"majority\"", JuryExecutionMode::Majority),
        ] {
            let mode: JuryExecutionMode = serde_json::from_str(mode_str).unwrap();
            assert_eq!(mode, expected);
        }
    }

    #[test]
    fn test_serialize_roundtrip_judge() {
        let config = JudgeConfig {
            enabled: true,
            mode: JudgeMode::Llm,
            llm: LLMTarget {
                provider_type: "openai".to_string(),
                model: "gpt-4o-mini".to_string(),
                endpoint_url: "https://api.openai.com/v1/chat/completions".to_string(),
                api_key_secret: Some("secret-123".to_string()),
                parameters: Some(serde_json::json!({"temperature": 0.1, "max_tokens": 500})),
                timeout_secs: 30,
                capabilities: None,
                api_schema: "openai".to_string(),
                headers: Vec::new(),
                pricing: None,
            },
            system_prompt: "You are a safety reviewer.".to_string(),
            strictness: None,
            focus_areas: None,
            confidence_threshold: None,
            custom_instructions: None,
            disable_thinking: None,
            rules: vec![JudgeRule {
                name: "Reject harmful".to_string(),
                condition: JudgeCondition {
                    condition_type: "json_field_equals".to_string(),
                    field: Some("decision".to_string()),
                    value: Some("reject".to_string()),
                    ..Default::default()
                },
                status_code: 403,
                body: "Blocked".to_string(),
                content_type: "text/plain".to_string(),
            }],
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: JudgeConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.llm.model, "gpt-4o-mini");
        assert_eq!(deserialized.rules.len(), 1);
        assert_eq!(deserialized.rules[0].status_code, 403);
    }

    #[test]
    fn test_llm_target_with_parameters() {
        let json = r#"{
            "provider_type": "openai",
            "model": "gpt-4o-mini",
            "endpoint_url": "https://api.openai.com/v1/chat/completions",
            "api_key_secret": "secret-123",
            "parameters": {
                "temperature": 0.1,
                "max_tokens": 500
            }
        }"#;

        let target: LLMTarget = serde_json::from_str(json).unwrap();
        assert_eq!(target.provider_type, "openai");
        let params = target.parameters.unwrap();
        assert_eq!(params["temperature"], 0.1);
        assert_eq!(params["max_tokens"], 500);
    }

    fn decider_target(model: &str) -> LLMTarget {
        LLMTarget {
            provider_type: "openai".to_string(),
            model: model.to_string(),
            endpoint_url: "https://api.openai.com/v1/chat/completions".to_string(),
            api_key_secret: None,
            parameters: None,
            timeout_secs: 30,
            capabilities: None,
            api_schema: "openai".to_string(),
            headers: Vec::new(),
            pricing: None,
        }
    }

    fn decider_candidate(
        id: &str,
        model: &str,
    ) -> DeciderCandidate {
        DeciderCandidate {
            id: id.to_string(),
            name: id.to_string(),
            description: String::new(),
            llm: decider_target(model),
        }
    }

    fn decider_with(candidates: Vec<DeciderCandidate>) -> DeciderConfig {
        DeciderConfig {
            enabled: true,
            strategy: DeciderStrategy::Route,
            llm: Some(decider_target("gpt-4o-mini")),
            system_prompt: "Route the request.".to_string(),
            candidates,
            default_candidate_id: None,
            mirror: MirrorConfig::default(),
            disable_thinking: None,
        }
    }

    #[test]
    fn decider_resolve_candidate_exact_match() {
        let decider =
            decider_with(vec![decider_candidate("fast", "gpt-4o-mini"), decider_candidate("smart", "gpt-4o")]);
        let resolved = decider
            .resolve_candidate("smart")
            .unwrap();
        assert_eq!(resolved.id, "smart");
        assert_eq!(resolved.llm.model, "gpt-4o");
    }

    #[test]
    fn decider_resolve_unknown_id_falls_back_to_default() {
        let mut decider =
            decider_with(vec![decider_candidate("fast", "gpt-4o-mini"), decider_candidate("smart", "gpt-4o")]);
        decider.default_candidate_id = Some("smart".to_string());
        let resolved = decider
            .resolve_candidate("nonexistent")
            .unwrap();
        assert_eq!(resolved.id, "smart");
    }

    #[test]
    fn decider_resolve_unknown_id_without_default_uses_first() {
        let decider =
            decider_with(vec![decider_candidate("fast", "gpt-4o-mini"), decider_candidate("smart", "gpt-4o")]);
        let resolved = decider
            .resolve_candidate("nonexistent")
            .unwrap();
        assert_eq!(resolved.id, "fast");
    }

    fn judge_with_rule(
        enabled: bool,
        mode: &str,
        condition: serde_json::Value,
    ) -> JudgeConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": enabled,
            "mode": mode,
            "llm": { "provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "https://api.openai.com/v1" },
            "rules": [{ "name": "Rule", "condition": condition }]
        }))
        .unwrap()
    }

    #[test]
    fn judge_validate_accepts_rules_of_its_mode() {
        let llm = judge_with_rule(true, "llm", serde_json::json!({ "type": "regex_match", "pattern": "(?i)reject" }));
        let moderation = judge_with_rule(true, "moderation", serde_json::json!({ "type": "flagged" }));

        assert_eq!(llm.validate(), Ok(()));
        assert_eq!(moderation.validate(), Ok(()));
    }

    #[test]
    fn judge_validate_rejects_condition_type_of_the_other_mode() {
        let judge = judge_with_rule(true, "llm", serde_json::json!({ "type": "flagged" }));

        assert_eq!(
            judge.validate(),
            Err("Judge rule 'Rule': condition type 'flagged' is not valid in llm mode".to_string())
        );
    }

    #[test]
    fn judge_validate_rejects_unknown_condition_type() {
        let judge = judge_with_rule(true, "moderation", serde_json::json!({ "type": "json_field_contains" }));

        assert_eq!(
            judge.validate(),
            Err("Judge rule 'Rule': condition type 'json_field_contains' is not valid in moderation mode".to_string())
        );
    }

    #[test]
    fn judge_validate_rejects_invalid_regex() {
        let judge = judge_with_rule(true, "llm", serde_json::json!({ "type": "regex_match", "pattern": "(unclosed" }));

        let err = judge.validate().unwrap_err();
        assert!(err.starts_with("Judge rule 'Rule': invalid regex pattern"), "unexpected message: {err}");
    }

    #[test]
    fn judge_validate_rejects_regex_match_without_pattern() {
        let missing = judge_with_rule(true, "llm", serde_json::json!({ "type": "regex_match" }));
        let empty = judge_with_rule(true, "llm", serde_json::json!({ "type": "regex_match", "pattern": "" }));

        let expected = Err("Judge rule 'Rule': regex_match requires a pattern".to_string());
        assert_eq!(missing.validate(), expected);
        assert_eq!(empty.validate(), expected);
    }

    #[test]
    fn judge_validate_rejects_json_field_equals_without_field() {
        let judge = judge_with_rule(true, "llm", serde_json::json!({ "type": "json_field_equals", "value": "reject" }));

        assert_eq!(judge.validate(), Err("Judge rule 'Rule': json_field_equals requires a field".to_string()));
    }

    #[test]
    fn judge_validate_rejects_json_field_not_equals_with_blank_field() {
        let judge = judge_with_rule(
            true,
            "llm",
            serde_json::json!({ "type": "json_field_not_equals", "field": " ", "value": "approve" }),
        );

        assert_eq!(judge.validate(), Err("Judge rule 'Rule': json_field_not_equals requires a field".to_string()));
    }

    #[test]
    fn judge_validate_rejects_category_rules_without_category() {
        for condition_type in ["category_flagged", "category_score"] {
            let missing = judge_with_rule(true, "moderation", serde_json::json!({ "type": condition_type }));
            let blank =
                judge_with_rule(true, "moderation", serde_json::json!({ "type": condition_type, "category": " " }));

            let expected = Err(format!("Judge rule 'Rule': {condition_type} requires a category"));
            assert_eq!(missing.validate(), expected);
            assert_eq!(blank.validate(), expected);
        }
    }

    #[test]
    fn judge_validate_accepts_category_rules_with_category() {
        let flagged = judge_with_rule(
            true,
            "moderation",
            serde_json::json!({ "type": "category_flagged", "category": "violence" }),
        );
        let score = judge_with_rule(
            true,
            "moderation",
            serde_json::json!({ "type": "category_score", "category": "violence", "operator": ">=", "threshold": 0.5 }),
        );

        assert_eq!(flagged.validate(), Ok(()));
        assert_eq!(score.validate(), Ok(()));
    }

    #[test]
    fn judge_validate_accepts_json_field_rule_with_field() {
        let judge = judge_with_rule(
            true,
            "llm",
            serde_json::json!({ "type": "json_field_equals", "field": "decision", "value": "reject" }),
        );

        assert_eq!(judge.validate(), Ok(()));
    }

    fn jury_with_decision(
        enabled: bool,
        decision: serde_json::Value,
    ) -> JuryConfig {
        serde_json::from_value(serde_json::json!({
            "enabled": enabled,
            "jurors": [{
                "enabled": true,
                "name": "Juror",
                "system_prompt": "",
                "llm": { "provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "https://api.openai.com/v1" },
                "decision": decision
            }]
        }))
        .unwrap()
    }

    #[test]
    fn jury_validate_accepts_valid_regex_decision() {
        let jury = jury_with_decision(
            true,
            serde_json::json!({ "mode": "regex", "approve_pattern": "OK", "reject_pattern": "unsafe" }),
        );

        assert_eq!(jury.validate(), Ok(()));
    }

    #[test]
    fn jury_validate_rejects_invalid_reject_pattern() {
        let jury = jury_with_decision(
            true,
            serde_json::json!({ "mode": "regex", "approve_pattern": "OK", "reject_pattern": "(unsafe" }),
        );

        let err = jury.validate().unwrap_err();
        assert!(err.starts_with("Juror 'Juror': invalid reject_pattern"), "unexpected message: {err}");
    }

    #[test]
    fn jury_validate_rejects_invalid_approve_pattern() {
        let jury = jury_with_decision(true, serde_json::json!({ "mode": "regex", "approve_pattern": "(OK" }));

        let err = jury.validate().unwrap_err();
        assert!(err.starts_with("Juror 'Juror': invalid approve_pattern"), "unexpected message: {err}");
    }

    #[test]
    fn jury_validate_skips_disabled_jury() {
        let jury = jury_with_decision(false, serde_json::json!({ "mode": "regex", "approve_pattern": "(OK" }));

        assert_eq!(jury.validate(), Ok(()));
    }

    #[test]
    fn judge_validate_skips_disabled_judge() {
        let judge = judge_with_rule(false, "llm", serde_json::json!({ "type": "flagged" }));

        assert_eq!(judge.validate(), Ok(()));
    }

    #[test]
    fn decider_disabled_always_validates() {
        let mut decider = decider_with(vec![]);
        decider.enabled = false;
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_enabled_rejects_empty_candidates() {
        let decider = decider_with(vec![]);
        assert_eq!(decider.validate(), Err("Decider is enabled but has no candidates".to_string()));
    }

    #[test]
    fn decider_enabled_rejects_duplicate_candidate_ids() {
        let decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini"), decider_candidate("fast", "gpt-4o")]);
        assert_eq!(decider.validate(), Err("duplicate Decider candidate id 'fast'".to_string()));
    }

    #[test]
    fn decider_enabled_rejects_empty_candidate_id() {
        let decider = decider_with(vec![decider_candidate("", "gpt-4o-mini")]);
        assert_eq!(decider.validate(), Err("Decider candidate id must not be empty".to_string()));
    }

    #[test]
    fn decider_enabled_rejects_unknown_default() {
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.default_candidate_id = Some("ghost".to_string());
        assert_eq!(decider.validate(), Err("Decider default_candidate_id 'ghost' is not a candidate".to_string()));
    }

    #[test]
    fn decider_valid_config_passes() {
        let mut decider =
            decider_with(vec![decider_candidate("fast", "gpt-4o-mini"), decider_candidate("smart", "gpt-4o")]);
        decider.default_candidate_id = Some("fast".to_string());
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_mirror_merge_requires_merger() {
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.strategy = DeciderStrategy::Mirror;
        decider.mirror = MirrorConfig {
            mode: MirrorMode::Merge,
            merger: None,
            ..Default::default()
        };
        assert_eq!(
            decider.validate(),
            Err("Decider Mirror strategy with Merge mode requires a merger LLM".to_string())
        );
    }

    #[test]
    fn decider_mirror_merge_with_merger_passes() {
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.strategy = DeciderStrategy::Mirror;
        decider.mirror = MirrorConfig {
            mode: MirrorMode::Merge,
            merger: Some(decider_target("gpt-4o")),
            merge_system_prompt: String::new(),
            disable_thinking: None,
        };
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_mirror_collect_needs_no_merger() {
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.strategy = DeciderStrategy::Mirror;
        decider.mirror = MirrorConfig {
            mode: MirrorMode::Collect,
            merger: None,
            ..Default::default()
        };
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_mirror_needs_no_router_llm() {
        // Mirror never calls a router, so an absent router LLM must still validate.
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.strategy = DeciderStrategy::Mirror;
        decider.llm = None;
        decider.mirror = MirrorConfig {
            mode: MirrorMode::Collect,
            merger: None,
            ..Default::default()
        };
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_route_requires_router_llm() {
        let mut decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        decider.llm = None;
        assert_eq!(decider.validate(), Err("Decider Route strategy requires a router LLM".to_string()));
    }

    #[test]
    fn decider_mirror_caps_candidate_fan_out() {
        let candidates: Vec<DeciderCandidate> = (0..MAX_MIRROR_CANDIDATES + 1)
            .map(|i| decider_candidate(&format!("c{i}"), "gpt-4o-mini"))
            .collect();
        let mut decider = decider_with(candidates);
        decider.strategy = DeciderStrategy::Mirror;
        decider.mirror = MirrorConfig {
            mode: MirrorMode::Collect,
            merger: None,
            ..Default::default()
        };
        assert!(
            decider
                .validate()
                .unwrap_err()
                .contains("at most")
        );

        // Route with the same many candidates is fine — only one is ever called.
        decider.strategy = DeciderStrategy::Route;
        assert_eq!(decider.validate(), Ok(()));
    }

    #[test]
    fn decider_strategy_defaults_to_route_on_deserialize() {
        // A stored decider without `strategy`/`mirror` (pre-Mirror configs) must
        // deserialize as a Route decider so existing surfaces are unchanged.
        let json = r#"{
            "enabled": true,
            "llm": {
                "provider_type": "openai",
                "model": "gpt-4o-mini",
                "endpoint_url": "https://api.openai.com/v1/chat/completions"
            },
            "candidates": [
                {"id": "fast", "name": "Fast", "llm": {"provider_type": "openai", "model": "gpt-4o-mini", "endpoint_url": "/chat/completions"}}
            ]
        }"#;
        let decider: DeciderConfig = serde_json::from_str(json).unwrap();
        assert_eq!(decider.strategy, DeciderStrategy::Route);
        assert_eq!(decider.mirror.mode, MirrorMode::Merge);
        assert!(
            decider
                .mirror
                .merger
                .is_none()
        );
    }

    #[test]
    fn decider_serialize_roundtrip() {
        let decider = decider_with(vec![decider_candidate("fast", "gpt-4o-mini")]);
        let json = serde_json::to_string(&decider).unwrap();
        let deserialized: DeciderConfig = serde_json::from_str(&json).unwrap();
        assert!(deserialized.enabled);
        assert_eq!(deserialized.candidates.len(), 1);
        assert_eq!(deserialized.candidates[0].id, "fast");
        assert_eq!(
            deserialized.candidates[0]
                .llm
                .model,
            "gpt-4o-mini"
        );
    }
}
