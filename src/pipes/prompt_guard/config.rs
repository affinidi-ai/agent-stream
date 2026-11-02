//! Prompt guard configuration types

use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize};

/// Top-level prompt guard configuration for a pipe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGuardConfig {
    /// Whether prompt guarding is active. Defaults to `true` so existing
    /// stored configs (which predate this flag) keep enforcing their rules.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Guards applied to client requests before they reach the LLM
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub request: Vec<RequestGuard>,
    /// Guards applied to LLM responses before they reach the client
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub response: Vec<ResponseGuard>,
    /// Optional external HTTP guardrail provider (e.g. EnkryptAI) invoked in
    /// addition to the local regex guards, on the request and/or response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalGuardrailConfig>,
    /// Model-backed PII detection on the request (Phase 2b of NER IDs): one or
    /// more detection models return typed PII entities (names, addresses, …) that
    /// are then masked or rejected, catching PII regex cannot. Detectors run in
    /// parallel and share one NEAR-ID allocator. Deserialisation also accepts a
    /// single object (the pre-list shape) for back-compat.
    #[serde(default, deserialize_with = "deserialize_llm_pii", skip_serializing_if = "Vec::is_empty")]
    pub llm_pii: Vec<LlmPiiConfig>,
}

/// Model-backed PII detection for a surface's request Prompt Guard. When
/// configured, the request text is sent to an OpenAI-compatible detection model
/// that returns typed PII entities (names, addresses, orgs, …); each detected
/// value is then masked (redacted or pseudonymized as NER IDs) in the request
/// before it reaches the provider. Send the text only to a **trusted** detection
/// endpoint — ideally self-hosted/local — since the raw content is submitted to it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmPiiConfig {
    /// Whether model-backed detection is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Provider type used to resolve the endpoint, mirroring the judge/jury LLM
    /// config (e.g. "openai", "ollama", "azure", "custom"). Combined with
    /// `endpoint_url` (which may be a relative path like `/v1/chat/completions`)
    /// to form the full detection URL. Empty means `endpoint_url` is a full URL.
    #[serde(default)]
    pub provider_type: String,
    /// OpenAI-compatible chat-completions endpoint of the detection model. May be
    /// a full URL, or a path resolved against `provider_type`'s base URL.
    pub endpoint_url: String,
    /// Model name to request from the detection endpoint.
    pub model: String,
    /// Secret reference for the detection endpoint's API key (secrets store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    /// Entity types the model should return. Defaults to the entities regex
    /// cannot reliably match (PERSON, ADDRESS, ORG, LOCATION).
    #[serde(default = "default_pii_entity_types")]
    pub entity_types: Vec<String>,
    /// What to do when the detector finds PII: `mask` (default — rewrite the
    /// values per `mask_mode`) or `reject` (block the request, like a regex
    /// `reject` guard). With `reject`, `mask_mode` and the restore/coreference
    /// options do not apply.
    #[serde(default = "default_mask_action")]
    pub action: GuardAction,
    /// How detected values are rewritten when `action = mask`. Defaults to
    /// pseudonymize (NER IDs). Ignored when `action = reject`.
    #[serde(default = "default_pseudonymize_mode")]
    pub mask_mode: MaskMode,
    /// Custom rejection response used when `action = reject` (status code, body,
    /// content-type). Falls back to the default 403 policy response when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<RejectionConfig>,
    /// Restore the detected values in the response, like a regex pseudonymize
    /// guard's `restore_in_response`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub restore_in_response: bool,
    /// Collapse the model's coreference groups (aliases / repeated mentions of
    /// one real-world entity, e.g. `Bob` and `Robert Smith`) to a single NER ID
    /// (Phase 3c). Off by default; only meaningful with `mask_mode = pseudonymize`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub link_coreferences: bool,
    /// Cache detection results in memory so repeated messages (multi-turn chat
    /// re-sends the prior history) skip the model. Defaults to `true`. Per-message
    /// granularity, unless `link_coreferences` is set (then whole-prompt, so
    /// cross-message grouping is preserved and only exact repeats are cached).
    #[serde(default = "default_true")]
    pub cache_detection: bool,
    /// Per-detection-call timeout, seconds.
    #[serde(default = "default_external_timeout_secs")]
    pub timeout_secs: u64,
    /// If the detector is **unavailable** (the call errors or times out), reject
    /// the request (`true`, default) or continue with only the local regex/NER
    /// masking applied (`false`). The regex guards always run regardless. This
    /// is separate from `action = reject`, which rejects when PII *is detected*.
    #[serde(default = "default_true")]
    pub fail_closed: bool,
}

impl LlmPiiConfig {
    /// Full detection endpoint URL, resolving a relative `endpoint_url` against
    /// the provider's base URL — the same resolution the judge/jury LLM calls use.
    pub fn resolved_endpoint_url(&self) -> String {
        crate::pipes::defaults::resolve_endpoint_url(&self.provider_type, &self.endpoint_url)
    }

    /// Validate the configuration at ingestion time (SSRF + non-empty URL/model).
    /// A disabled detector is not validated.
    pub fn validate(&self) -> Result<(), String> {
        if !self.enabled {
            return Ok(());
        }
        let resolved = self.resolved_endpoint_url();
        if resolved.trim().is_empty() {
            return Err("Model PII detection endpoint_url cannot be empty".to_string());
        }
        crate::url_validation::validate_service_endpoint_url_blocking(&resolved)?;
        if self.model.trim().is_empty() {
            return Err("Model PII detection model cannot be empty".to_string());
        }
        if self.timeout_secs == 0 {
            return Err("Model PII detection timeout_secs must be greater than zero".to_string());
        }
        Ok(())
    }
}

fn default_pii_entity_types() -> Vec<String> {
    ["PERSON", "ADDRESS", "ORG", "LOCATION", "EMAIL_ADDRESS", "PHONE_NUMBER"]
        .iter()
        .map(|s| s.to_string())
        .collect()
}

fn default_pseudonymize_mode() -> MaskMode {
    MaskMode::Pseudonymize
}

fn default_mask_action() -> GuardAction {
    GuardAction::Mask
}

/// Accept either a single object (the pre-list shape) or an array of detectors,
/// so existing stored configs keep loading after `llm_pii` became a list.
fn deserialize_llm_pii<'de, D>(deserializer: D) -> Result<Vec<LlmPiiConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum OneOrMany {
        One(Box<LlmPiiConfig>),
        Many(Vec<LlmPiiConfig>),
    }
    Ok(match Option::<OneOrMany>::deserialize(deserializer)? {
        None => Vec::new(),
        Some(OneOrMany::One(cfg)) => vec![*cfg],
        Some(OneOrMany::Many(list)) => list,
    })
}

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Configuration for an external HTTP guardrail provider invoked alongside the
/// local regex guards. The provider is called with the (already regex-masked)
/// request and/or response content; a "flagged" verdict blocks the call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalGuardrailConfig {
    /// Whether the external guardrail is active. Defaults to `true`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Which provider's request/response wire format to use.
    #[serde(default)]
    pub provider: ExternalGuardrailProvider,
    /// Absolute URL of the provider's detection endpoint.
    pub endpoint_url: String,
    /// Secret reference for the provider API key (resolved via the secrets store).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api_key_secret: Option<String>,
    /// Per-call timeout in seconds. Defaults to 10.
    #[serde(default = "default_external_timeout_secs")]
    pub timeout_secs: u64,
    /// Behaviour when the provider errors or times out: `true` = allow the call
    /// through (fail-open), `false` = block it (fail-closed). Defaults to
    /// fail-closed so a guardrail outage cannot silently disable protection.
    #[serde(default)]
    pub fail_open: bool,
    /// Check the request before it reaches the LLM. Defaults to `true`.
    #[serde(default = "default_true")]
    pub check_request: bool,
    /// Check the LLM response before it reaches the client. Defaults to `true`.
    #[serde(default = "default_true")]
    pub check_response: bool,
    /// Arbitrary static headers sent on every provider call, in addition to the
    /// profile's auth header. The literal `{key}` in a value is replaced by the
    /// resolved API key. Used for provider-specific routing headers such as
    /// EnkryptAI's `X-Enkrypt-Deployment` or any custom header a `generic`
    /// endpoint requires.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Optional `model` field injected into the request body. Required by the
    /// EnkryptAI AI Proxy (`enkryptai_ai_proxy`), whose deployment selects the
    /// guardrail policy while the body still carries the model saved-name; left
    /// unset for providers that do not take a model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Provider-specific detector configuration passed through verbatim. When
    /// absent, a sensible default detector set is sent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detectors: Option<serde_json::Value>,
    /// Custom rejection response returned when the provider flags content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection: Option<RejectionConfig>,
    /// Declarative profile overriding the built-in wire format for `provider`.
    /// Lets a new HTTP guardrail provider be onboarded by configuration instead
    /// of code; when absent the built-in profile for `provider` is used.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<GuardrailProfile>,
}

impl ExternalGuardrailConfig {
    /// Validate the configuration at ingestion time.
    pub fn validate(&self) -> Result<(), String> {
        if self
            .endpoint_url
            .trim()
            .is_empty()
        {
            return Err("External guardrail endpoint_url cannot be empty".to_string());
        }
        crate::url_validation::validate_service_endpoint_url_blocking(&self.endpoint_url)?;
        if self.timeout_secs == 0 {
            return Err("External guardrail timeout_secs must be greater than zero".to_string());
        }
        for name in self.headers.keys() {
            if name.trim().is_empty() {
                return Err("External guardrail header name cannot be empty".to_string());
            }
        }
        if let Some(profile) = &self.profile {
            profile.validate()?;
        }
        Ok(())
    }
}

/// A named, individually-addressable external safety classifier — an
/// **expert witness** — consulted at the request and/or response seam of an
/// LLM pipe. Sibling to the Judge and Jury: where those are general reasoning
/// LLMs you instruct, an expert witness is a purpose-trained classifier
/// (EnkryptAI / Lakera / Azure / generic) whose structured verdict you consume.
///
/// A pipe carries a *list* of witnesses, so different providers can sit on
/// different seams (e.g. Azure Prompt Shields on the request and Azure Content
/// Safety on the response). The provider connector configuration is the
/// existing [`ExternalGuardrailConfig`], flattened so the wire shape stays a
/// single flat object plus a stable `id`/`name`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExpertWitnessConfig {
    /// Stable identifier (frontend addressing / canvas node id).
    #[serde(default)]
    pub id: String,
    /// Human-readable label shown in the dashboard.
    #[serde(default)]
    pub name: String,
    /// Provider connector configuration: endpoint, provider preset, seams
    /// (`check_request` / `check_response`), timeout, fail-open, and optional
    /// inline profile override.
    #[serde(flatten)]
    pub guardrail: ExternalGuardrailConfig,
}

impl ExpertWitnessConfig {
    /// Build a witness from a legacy `prompt_guard.external` block, used by the
    /// backward-compat migration in `PipeConfig::normalize_guardrails`.
    pub fn from_legacy_external(guardrail: ExternalGuardrailConfig) -> Self {
        Self {
            id: "migrated-external-guardrail".to_string(),
            name: "External guardrail".to_string(),
            guardrail,
        }
    }

    /// Validate the witness at ingestion time (delegates to the connector
    /// config's SSRF + non-empty-URL + profile checks).
    pub fn validate(&self) -> Result<(), String> {
        self.guardrail.validate()
    }
}

/// Wire format / provider preset for an external guardrail.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalGuardrailProvider {
    /// EnkryptAI Guardrails detection API (`/guardrails/detect`). The cleaner
    /// fit for an expert witness: a pure classifier that returns a verdict
    /// without running its own LLM.
    #[default]
    Enkryptai,
    /// EnkryptAI saved-**guardrail** detection API (`/guardrails/guardrail/detect`)
    /// — EnkryptAI's current named-config detect endpoint. A pure classifier (no
    /// LLM call) whose detectors are bound by a saved *guardrail* selected via the
    /// `X-Enkrypt-Guardrail` header (supplied through
    /// [`ExternalGuardrailConfig::headers`]); the required `X-Enkrypt-Mode` header
    /// (`prompt` on the request seam, `response` on the response seam) is injected
    /// automatically from the witness seam. The request body is just `{text}`.
    /// Prefer this over [`ExternalGuardrailProvider::EnkryptaiPolicyDetect`],
    /// which calls EnkryptAI's deprecated policy endpoint.
    EnkryptaiGuardrail,
    /// EnkryptAI AI Proxy (`/ai-proxy/chat/completions`). The deployment named
    /// in the `X-Enkrypt-Deployment` header binds both the guardrail policy and
    /// the underlying model; the verdict is read from `enkrypt_policy_detections`.
    /// Note: the proxy runs its own LLM completion, so as a witness it incurs an
    /// extra model call — prefer the detect API where possible.
    EnkryptaiAiProxy,
    /// EnkryptAI **legacy** saved-policy detection API (`/guardrails/policy/detect`).
    /// EnkryptAI has deprecated this endpoint in favour of
    /// [`ExternalGuardrailProvider::EnkryptaiGuardrail`]; it is retained for
    /// back-compat. Like [`ExternalGuardrailProvider::Enkryptai`] it is a pure
    /// classifier with no LLM call, but the detectors are bound by a named policy
    /// selected via the `X-Enkrypt-Policy` header (supplied through
    /// [`ExternalGuardrailConfig::headers`]); the request body is just `{text}`.
    EnkryptaiPolicyDetect,
    /// Generic OpenAI-moderation-style API returning a flagged/blocked verdict.
    Generic,
    /// Lakera Guard (Check Point) detection API (`POST /v2/guard`).
    Lakera,
    /// Azure AI Content Safety Prompt Shields (`text:shieldPrompt`) —
    /// prompt-injection / jailbreak detection on the request.
    AzurePromptShields,
    /// Azure AI Content Safety harm-category moderation (`text:analyze`) —
    /// severity-scored Hate / Sexual / SelfHarm / Violence detection.
    AzureContentSafety,
}

impl ExternalGuardrailProvider {
    /// Stable lowercase identifier for this provider, used as the rejection
    /// `source` label when classifying rejections into the canonical taxonomy.
    pub fn as_str(&self) -> &'static str {
        match self {
            ExternalGuardrailProvider::Enkryptai => "enkryptai",
            ExternalGuardrailProvider::EnkryptaiGuardrail => "enkryptai_guardrail",
            ExternalGuardrailProvider::EnkryptaiAiProxy => "enkryptai_ai_proxy",
            ExternalGuardrailProvider::EnkryptaiPolicyDetect => "enkryptai_policy_detect",
            ExternalGuardrailProvider::Generic => "generic",
            ExternalGuardrailProvider::Lakera => "lakera",
            ExternalGuardrailProvider::AzurePromptShields => "azure_prompt_shields",
            ExternalGuardrailProvider::AzureContentSafety => "azure_content_safety",
        }
    }
}

/// Declarative description of how to call an HTTP guardrail provider and read
/// its verdict, so a new provider can be onboarded by configuration instead of
/// code. Each [`ExternalGuardrailProvider`] preset has a built-in profile; an
/// operator may override it inline via [`ExternalGuardrailConfig::profile`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GuardrailProfile {
    /// Header carrying the API key (e.g. `apikey` or `Authorization`).
    pub auth_header: String,
    /// Template for the auth header value; the literal `{key}` is replaced by
    /// the resolved API key (e.g. `{key}` or `Bearer {key}`).
    #[serde(default = "default_auth_value_template")]
    pub auth_value_template: String,
    /// Request body template. Any string value equal to `{text}` is replaced by
    /// the inspected content; any string value equal to `{detectors}` is
    /// replaced by the detector value.
    pub request_template: serde_json::Value,
    /// When true, merge the (object) detector value into the root of the
    /// rendered body instead of substituting a `{detectors}` placeholder.
    #[serde(default)]
    pub spread_detectors: bool,
    /// Detector value used when [`ExternalGuardrailConfig::detectors`] is unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_detectors: Option<serde_json::Value>,
    /// How to read the provider's JSON response into an allow/block verdict.
    pub verdict: VerdictRule,
}

impl GuardrailProfile {
    /// Validate the profile at ingestion time.
    pub fn validate(&self) -> Result<(), String> {
        if self
            .auth_header
            .trim()
            .is_empty()
        {
            return Err("Guardrail profile auth_header cannot be empty".to_string());
        }
        match &self.verdict {
            VerdictRule::DetectorMap { paths } if paths.is_empty() => {
                Err("Guardrail profile detector_map verdict requires at least one path".to_string())
            }
            VerdictRule::Flag { flag_paths, action_path, .. } if flag_paths.is_empty() && action_path.is_none() => {
                Err("Guardrail profile flag verdict requires a flag_path or action_path".to_string())
            }
            VerdictRule::SeverityList {
                items_path,
                severity_field,
                threshold,
                ..
            } => {
                if items_path.trim().is_empty() {
                    return Err("Guardrail profile severity_list verdict requires a non-empty items_path".to_string());
                }
                if severity_field
                    .trim()
                    .is_empty()
                {
                    return Err(
                        "Guardrail profile severity_list verdict requires a non-empty severity_field".to_string()
                    );
                }
                if !threshold.is_finite() || *threshold <= 0.0 {
                    return Err("Guardrail profile severity_list verdict requires a positive threshold".to_string());
                }
                Ok(())
            }
            _ => Ok(()),
        }
    }
}

fn default_auth_value_template() -> String {
    "{key}".to_string()
}

/// How to interpret a guardrail provider's JSON response into a verdict.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum VerdictRule {
    /// Block when any value in the object at the first matching `paths` entry is
    /// a "hit" (boolean `true`, a non-zero number, or a nested
    /// `{"detected": true}`). The triggered keys form the rejection detail.
    DetectorMap {
        /// Dot-separated candidate paths to the detector object, tried in order.
        paths: Vec<String>,
    },
    /// Block when the boolean at any `flag_paths` entry is `true`, or the string
    /// at `action_path` equals `block`. Triggered categories are read from the
    /// string arrays at `category_paths`.
    Flag {
        /// Dot-separated paths to boolean "flagged" fields.
        flag_paths: Vec<String>,
        /// Optional dot-separated path to a string action field (`block`/`allow`).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        action_path: Option<String>,
        /// Dot-separated paths to string arrays naming the triggered categories.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        category_paths: Vec<String>,
    },
    /// Block when any element of the array at `items_path` carries a numeric
    /// `severity_field` value greater than or equal to `threshold`. Triggered
    /// `category_field` values form the rejection detail. Models severity-scored
    /// moderation APIs (e.g. Azure Content Safety `text:analyze`) whose response
    /// is a list of `{category, severity}` objects.
    SeverityList {
        /// Dot-separated path to the array of scored items.
        items_path: String,
        /// Field on each item naming the category. Defaults to `category`.
        #[serde(default = "default_category_field")]
        category_field: String,
        /// Numeric field on each item carrying the severity. Defaults to `severity`.
        #[serde(default = "default_severity_field")]
        severity_field: String,
        /// Block when an item's severity is greater than or equal to this value.
        threshold: f64,
    },
}

fn default_category_field() -> String {
    "category".to_string()
}

fn default_severity_field() -> String {
    "severity".to_string()
}

fn default_external_timeout_secs() -> u64 {
    10
}

/// A guard applied to incoming requests
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestGuard {
    /// Regex-based content rules
    pub regex: RegexRules,
    /// Custom rejection response (optional)
    #[serde(default)]
    pub rejection: Option<RejectionConfig>,
}

/// A guard applied to outgoing responses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseGuard {
    /// Regex-based content rules
    pub regex: RegexRules,
    /// Custom rejection response (optional, only used with action=reject)
    #[serde(default)]
    pub rejection: Option<RejectionConfig>,
}

/// Regex-based content filtering rules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegexRules {
    /// Action to take when a match is found
    #[serde(default)]
    pub action: GuardAction,
    /// How matched content is rewritten when `action = mask`. Ignored for `reject`.
    #[serde(default)]
    pub mask_mode: MaskMode,
    /// Restore the original values in the final response. Set on the inbound
    /// (request) pseudonymize guard: the request's NER ID map is carried
    /// through the pipeline so the models only ever see pseudonyms, and the real
    /// values are put back in the completion before it reaches the client.
    /// Only meaningful for a request-side `mask_mode = pseudonymize` guard.
    #[serde(default, skip_serializing_if = "is_false")]
    pub restore_in_response: bool,
    /// Link singular gendered pronouns (`he`/`she`/…) to a person's NER ID when
    /// exactly one person has been named so far in the message, so references to
    /// that individual share one pseudonym. Off by default; only meaningful for a
    /// request-side `mask_mode = pseudonymize` guard.
    #[serde(default, skip_serializing_if = "is_false")]
    pub link_pronouns: bool,
    /// List of rules to match against
    pub rules: Vec<RegexRule>,
}

/// A single regex rule — either a built-in PII pattern or a custom regex
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RegexRule {
    /// Use a built-in pattern (key references a defined_pattern from prompt-guard.json)
    Builtin { builtin: String },
    /// Custom regex pattern
    Pattern {
        pattern: String,
        /// Optional label for this pattern (used in logs and mask replacement)
        #[serde(default)]
        label: Option<String>,
    },
}

/// Action to take when content matches a guard rule
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum GuardAction {
    /// Reject the request/response with an error
    #[default]
    Reject,
    /// Mask the matched content with a placeholder
    Mask,
}

/// How matched content is rewritten when `action = mask`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MaskMode {
    /// Replace every match of a type with the same static token (`<EMAIL>`).
    /// Distinct values and their relationships are lost.
    #[default]
    Redact,
    /// Replace each distinct value with a stable NER ID (`[EMAIL_NER_001]`).
    /// The same value reuses the same id across the whole request/response, so
    /// entity relationships survive while the raw value is hidden. The value→id
    /// map is request-scoped and never persisted.
    Pseudonymize,
}

/// Custom rejection response configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionConfig {
    /// HTTP status code (default: 403)
    #[serde(default = "default_status_code")]
    pub status_code: u16,
    /// Response body text
    #[serde(default = "default_rejection_body")]
    pub body: String,
    /// Content-Type header (default: application/json)
    #[serde(default = "default_content_type")]
    pub content_type: String,
}

impl Default for RejectionConfig {
    fn default() -> Self {
        Self {
            status_code: default_status_code(),
            body: default_rejection_body(),
            content_type: default_content_type(),
        }
    }
}

fn default_status_code() -> u16 {
    403
}

fn default_rejection_body() -> String {
    r#"{"error":{"message":"Request rejected: content violates prompt guard policy","type":"prompt_guard_violation","code":"content_policy_violation"}}"#.to_string()
}

fn default_content_type() -> String {
    "application/json".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_prompt_guard_config() {
        let json = r#"{
            "request": [
                {
                    "regex": {
                        "action": "reject",
                        "rules": [
                            { "builtin": "ssn" },
                            { "builtin": "credit_card" },
                            { "pattern": "password[=:]\\s*\\S+" }
                        ]
                    },
                    "rejection": {
                        "status_code": 400,
                        "body": "Blocked"
                    }
                }
            ],
            "response": [
                {
                    "regex": {
                        "action": "mask",
                        "rules": [
                            { "builtin": "email" }
                        ]
                    }
                }
            ]
        }"#;

        let config: PromptGuardConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.request.len(), 1);
        assert_eq!(config.request[0].regex.action, GuardAction::Reject);
        assert_eq!(
            config.request[0]
                .regex
                .rules
                .len(),
            3
        );
        assert_eq!(config.response.len(), 1);
        assert_eq!(
            config.response[0]
                .regex
                .action,
            GuardAction::Mask
        );
    }

    #[test]
    fn test_deserialize_builtin_patterns() {
        let json = r#"{ "builtin": "ssn" }"#;
        let rule: RegexRule = serde_json::from_str(json).unwrap();
        match rule {
            RegexRule::Builtin { builtin } => assert_eq!(builtin, "ssn"),
            _ => panic!("Expected builtin rule"),
        }
    }

    #[test]
    fn test_deserialize_custom_pattern() {
        let json = r#"{ "pattern": "secret\\d+", "label": "secrets" }"#;
        let rule: RegexRule = serde_json::from_str(json).unwrap();
        match rule {
            RegexRule::Pattern { pattern, label } => {
                assert_eq!(pattern, "secret\\d+");
                assert_eq!(label, Some("secrets".to_string()));
            }
            _ => panic!("Expected pattern rule"),
        }
    }

    #[test]
    fn test_default_guard_action_is_reject() {
        let json = r#"{ "rules": [{ "builtin": "ssn" }] }"#;
        let rules: RegexRules = serde_json::from_str(json).unwrap();
        assert_eq!(rules.action, GuardAction::Reject);
    }

    #[test]
    fn test_serialize_roundtrip() {
        let config = PromptGuardConfig {
            enabled: true,
            request: vec![RequestGuard {
                regex: RegexRules {
                    action: GuardAction::Reject,
                    mask_mode: MaskMode::Redact,
                    restore_in_response: false,
                    link_pronouns: false,
                    rules: vec![
                        RegexRule::Builtin { builtin: "ssn".to_string() },
                        RegexRule::Pattern {
                            pattern: "api_key=\\S+".to_string(),
                            label: Some("api_keys".to_string()),
                        },
                    ],
                },
                rejection: None,
            }],
            response: vec![],
            external: None,
            llm_pii: Vec::new(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: PromptGuardConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.request.len(), 1);
        assert_eq!(
            deserialized.request[0]
                .regex
                .rules
                .len(),
            2
        );
    }

    #[test]
    fn test_enabled_defaults_true_for_legacy_configs() {
        // Stored configs predating the `enabled` flag must keep enforcing.
        let json = r#"{ "request": [], "response": [] }"#;
        let config: PromptGuardConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
    }

    #[test]
    fn test_enabled_false_is_preserved() {
        let json = r#"{ "enabled": false, "request": [], "response": [] }"#;
        let config: PromptGuardConfig = serde_json::from_str(json).unwrap();
        assert!(!config.enabled);
    }

    #[test]
    fn llm_pii_action_defaults_to_mask_and_fail_closed_true() {
        // Configs predating `action`/`fail_closed` must keep masking, and default
        // to fail-closed (reject when the detector itself is unavailable).
        let json = r#"{ "endpoint_url": "https://d/v1/chat/completions", "model": "m" }"#;
        let cfg: LlmPiiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.action, GuardAction::Mask);
        assert_eq!(cfg.mask_mode, MaskMode::Pseudonymize);
        assert!(cfg.fail_closed);
        assert!(cfg.rejection.is_none());
    }

    #[test]
    fn llm_pii_reject_action_with_custom_rejection_deserializes() {
        let json = r#"{
            "endpoint_url": "https://d/v1/chat/completions",
            "model": "m",
            "action": "reject",
            "fail_closed": false,
            "rejection": { "status_code": 451, "body": "no PII" }
        }"#;
        let cfg: LlmPiiConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.action, GuardAction::Reject);
        assert!(!cfg.fail_closed);
        let rej = cfg
            .rejection
            .expect("rejection present");
        assert_eq!(rej.status_code, 451);
        assert_eq!(rej.body, "no PII");
    }

    #[test]
    fn llm_pii_accepts_single_object_or_array() {
        // Absent → empty.
        let none: PromptGuardConfig = serde_json::from_str(r#"{ "request": [] }"#).unwrap();
        assert!(none.llm_pii.is_empty());

        // Single object (the pre-list shape) → one detector.
        let single: PromptGuardConfig =
            serde_json::from_str(r#"{ "llm_pii": { "endpoint_url": "https://d/v1/chat/completions", "model": "m" } }"#)
                .unwrap();
        assert_eq!(single.llm_pii.len(), 1);

        // Array → many detectors.
        let many: PromptGuardConfig = serde_json::from_str(
            r#"{ "llm_pii": [
                { "endpoint_url": "https://a/v1/chat/completions", "model": "a" },
                { "endpoint_url": "https://b/v1/chat/completions", "model": "b" }
            ] }"#,
        )
        .unwrap();
        assert_eq!(many.llm_pii.len(), 2);
    }

    #[test]
    fn llm_pii_resolves_relative_endpoint_from_provider() {
        let cfg: LlmPiiConfig = serde_json::from_str(
            r#"{ "provider_type": "openai", "endpoint_url": "/v1/chat/completions", "model": "m" }"#,
        )
        .unwrap();
        let resolved = cfg.resolved_endpoint_url();
        assert!(resolved.starts_with("http"), "resolved: {resolved}");
        assert!(resolved.ends_with("/v1/chat/completions"), "resolved: {resolved}");
        // A full URL is passed through unchanged.
        let full: LlmPiiConfig = serde_json::from_str(r#"{ "endpoint_url": "https://x/y", "model": "m" }"#).unwrap();
        assert_eq!(full.resolved_endpoint_url(), "https://x/y");
    }

    // ── Wire-shape drift guards ──────────────────────────────────────────────
    // Pin the field names and provider enum strings the frontend
    // `ExternalGuardrail` interface hand-mirrors (see
    // `www/default/src/components/builder/elements/pipe/PipePromptGuardFullscreenPanel.tsx`).

    #[test]
    fn external_guardrail_provider_wire_strings() {
        assert_eq!(serde_json::to_value(ExternalGuardrailProvider::Enkryptai).unwrap(), serde_json::json!("enkryptai"));
        assert_eq!(
            serde_json::to_value(ExternalGuardrailProvider::EnkryptaiGuardrail).unwrap(),
            serde_json::json!("enkryptai_guardrail")
        );
        assert_eq!(
            serde_json::to_value(ExternalGuardrailProvider::EnkryptaiAiProxy).unwrap(),
            serde_json::json!("enkryptai_ai_proxy")
        );
        assert_eq!(
            serde_json::to_value(ExternalGuardrailProvider::EnkryptaiPolicyDetect).unwrap(),
            serde_json::json!("enkryptai_policy_detect")
        );
        assert_eq!(serde_json::to_value(ExternalGuardrailProvider::Generic).unwrap(), serde_json::json!("generic"));
        assert_eq!(serde_json::to_value(ExternalGuardrailProvider::Lakera).unwrap(), serde_json::json!("lakera"));
        assert_eq!(
            serde_json::to_value(ExternalGuardrailProvider::AzurePromptShields).unwrap(),
            serde_json::json!("azure_prompt_shields")
        );
        assert_eq!(
            serde_json::to_value(ExternalGuardrailProvider::AzureContentSafety).unwrap(),
            serde_json::json!("azure_content_safety")
        );
    }

    #[test]
    fn external_guardrail_config_wire_shape_keys() {
        let cfg = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Enkryptai,
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
        };
        let value = serde_json::to_value(&cfg).expect("serialize");
        let obj = value
            .as_object()
            .expect("object");
        for key in [
            "enabled",
            "provider",
            "endpoint_url",
            "api_key_secret",
            "timeout_secs",
            "fail_open",
            "check_request",
            "check_response",
        ] {
            assert!(obj.contains_key(key), "missing key {key}");
        }
        // Optional fields stay absent when unset so the frontend round-trips
        // the blob without inventing nulls.
        assert!(!obj.contains_key("headers"));
        assert!(!obj.contains_key("model"));
        assert!(!obj.contains_key("detectors"));
        assert!(!obj.contains_key("rejection"));
        assert!(!obj.contains_key("profile"));

        let back: ExternalGuardrailConfig = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back.provider, ExternalGuardrailProvider::Enkryptai);
        assert_eq!(back.api_key_secret.as_deref(), Some("sec-1"));
    }

    #[test]
    fn external_guardrail_inline_profile_round_trips() {
        let cfg = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Generic,
            endpoint_url: "https://198.51.100.1/guard".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: Some(GuardrailProfile {
                auth_header: "x-api-key".to_string(),
                auth_value_template: "{key}".to_string(),
                request_template: serde_json::json!({ "prompt": "{text}" }),
                spread_detectors: false,
                default_detectors: None,
                verdict: VerdictRule::Flag {
                    flag_paths: vec!["results.flagged".to_string()],
                    action_path: None,
                    category_paths: vec![],
                },
            }),
        };
        cfg.validate().expect("valid");
        let value = serde_json::to_value(&cfg).expect("serialize");
        assert_eq!(value["profile"]["verdict"]["kind"], "flag");
        let back: ExternalGuardrailConfig = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back.profile, cfg.profile);
    }

    #[test]
    fn guardrail_profile_validate_rejects_empty_auth_and_rules() {
        let blank_auth = GuardrailProfile {
            auth_header: "  ".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: serde_json::json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::DetectorMap {
                paths: vec!["summary".to_string()],
            },
        };
        assert!(blank_auth.validate().is_err());

        let empty_paths = GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: serde_json::json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::DetectorMap { paths: vec![] },
        };
        assert!(
            empty_paths
                .validate()
                .is_err()
        );

        let empty_flag = GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: serde_json::json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::Flag {
                flag_paths: vec![],
                action_path: None,
                category_paths: vec![],
            },
        };
        assert!(empty_flag.validate().is_err());
    }

    #[test]
    fn severity_list_verdict_round_trips_and_defaults_fields() {
        // category_field / severity_field default when omitted on the wire.
        let json = serde_json::json!({
            "kind": "severity_list",
            "items_path": "categoriesAnalysis",
            "threshold": 4.0
        });
        let rule: VerdictRule = serde_json::from_value(json).expect("deserialize");
        match &rule {
            VerdictRule::SeverityList {
                items_path,
                category_field,
                severity_field,
                threshold,
            } => {
                assert_eq!(items_path, "categoriesAnalysis");
                assert_eq!(category_field, "category");
                assert_eq!(severity_field, "severity");
                assert_eq!(*threshold, 4.0);
            }
            other => panic!("expected severity_list, got {other:?}"),
        }
        let back = serde_json::to_value(&rule).expect("serialize");
        assert_eq!(back["kind"], "severity_list");
    }

    #[test]
    fn severity_list_verdict_validation() {
        let valid = GuardrailProfile {
            auth_header: "Ocp-Apim-Subscription-Key".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: serde_json::json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::SeverityList {
                items_path: "categoriesAnalysis".to_string(),
                category_field: "category".to_string(),
                severity_field: "severity".to_string(),
                threshold: 4.0,
            },
        };
        valid
            .validate()
            .expect("valid");

        let bad_threshold = GuardrailProfile {
            verdict: VerdictRule::SeverityList {
                items_path: "categoriesAnalysis".to_string(),
                category_field: "category".to_string(),
                severity_field: "severity".to_string(),
                threshold: 0.0,
            },
            ..valid.clone()
        };
        assert!(
            bad_threshold
                .validate()
                .is_err()
        );

        let blank_items = GuardrailProfile {
            verdict: VerdictRule::SeverityList {
                items_path: "  ".to_string(),
                category_field: "category".to_string(),
                severity_field: "severity".to_string(),
                threshold: 4.0,
            },
            ..valid
        };
        assert!(
            blank_items
                .validate()
                .is_err()
        );
    }

    #[test]
    fn expert_witness_flattens_guardrail_on_the_wire() {
        let witness = ExpertWitnessConfig {
            id: "azure-shields".to_string(),
            name: "Azure Prompt Shields".to_string(),
            guardrail: ExternalGuardrailConfig {
                enabled: true,
                provider: ExternalGuardrailProvider::AzurePromptShields,
                endpoint_url: "https://res.cognitiveservices.azure.com/contentsafety/text:shieldPrompt".to_string(),
                api_key_secret: Some("sec-azure".to_string()),
                timeout_secs: 10,
                fail_open: false,
                check_request: true,
                check_response: false,
                headers: Default::default(),
                model: None,
                detectors: None,
                rejection: None,
                profile: None,
            },
        };
        let value = serde_json::to_value(&witness).expect("serialize");
        let obj = value
            .as_object()
            .expect("object");
        // id/name sit alongside the flattened connector fields (no nesting).
        assert_eq!(obj["id"], "azure-shields");
        assert_eq!(obj["name"], "Azure Prompt Shields");
        assert_eq!(obj["provider"], "azure_prompt_shields");
        assert_eq!(obj["check_request"], true);
        assert_eq!(obj["check_response"], false);
        assert!(!obj.contains_key("guardrail"));

        let back: ExpertWitnessConfig = serde_json::from_value(value).expect("deserialize");
        assert_eq!(back.id, "azure-shields");
        assert_eq!(back.guardrail.provider, ExternalGuardrailProvider::AzurePromptShields);
        assert!(!back.guardrail.check_response);
    }

    #[test]
    fn expert_witness_from_legacy_external_carries_connector() {
        let external = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Enkryptai,
            endpoint_url: "https://api.enkryptai.com/guardrails/detect".to_string(),
            api_key_secret: Some("sec-1".to_string()),
            timeout_secs: 7,
            fail_open: true,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: None,
        };
        let witness = ExpertWitnessConfig::from_legacy_external(external.clone());
        assert_eq!(witness.id, "migrated-external-guardrail");
        assert_eq!(witness.name, "External guardrail");
        assert_eq!(witness.guardrail.timeout_secs, 7);
        assert!(witness.guardrail.fail_open);
        // validate() delegates to the connector config.
        witness
            .validate()
            .expect("valid");
    }

    #[test]
    fn expert_witness_validate_rejects_empty_endpoint() {
        let witness = ExpertWitnessConfig {
            id: "bad".to_string(),
            name: "Bad".to_string(),
            guardrail: ExternalGuardrailConfig {
                enabled: true,
                provider: ExternalGuardrailProvider::Enkryptai,
                endpoint_url: "   ".to_string(),
                api_key_secret: None,
                timeout_secs: 10,
                fail_open: false,
                check_request: true,
                check_response: true,
                headers: Default::default(),
                model: None,
                detectors: None,
                rejection: None,
                profile: None,
            },
        };
        assert!(witness.validate().is_err());
    }
}
