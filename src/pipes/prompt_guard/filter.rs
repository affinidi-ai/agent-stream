//! Prompt guard filter — core filtering logic for request/response content
//!
//! Applies regex-based content filtering to LLM messages, supporting both
//! built-in PII detectors and custom regex patterns with reject or mask actions.

use super::config::*;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use regex::Regex;
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;
use tracing::{info, warn};

/// Result of applying a prompt guard to content
#[derive(Debug)]
pub enum GuardOutcome {
    /// No rules matched — content passes through unchanged
    Allowed,
    /// Content was modified (masked) — the modified request body is returned
    Masked,
    /// Content was rejected — return the rejection response to the client
    Rejected(GuardRejection),
}

/// Rejection details to return to the client
#[derive(Debug, Clone)]
pub struct GuardRejection {
    pub status_code: u16,
    pub body: String,
    pub content_type: String,
    /// Human-readable reason describing which rule matched, surfaced in the
    /// activity log. Never includes the matched text (which may be sensitive).
    pub reason: Option<String>,
    /// Provider/detector category tokens behind the rejection, used to classify
    /// the rejection into a canonical taxonomy for telemetry. Empty for regex
    /// guards (which carry only a `reason`).
    pub categories: Vec<String>,
}

impl Default for GuardRejection {
    fn default() -> Self {
        let rejection = RejectionConfig::default();
        Self {
            status_code: rejection.status_code,
            body: rejection.body,
            content_type: rejection.content_type,
            reason: None,
            categories: Vec::new(),
        }
    }
}

impl From<&RejectionConfig> for GuardRejection {
    fn from(r: &RejectionConfig) -> Self {
        Self {
            status_code: r.status_code,
            body: r.body.clone(),
            content_type: r.content_type.clone(),
            reason: None,
            categories: Vec::new(),
        }
    }
}

/// Cached custom regex patterns, keyed by pattern string; `None` for a pattern
/// that did not compile, so it is compiled once rather than per request.
static COMPILED_REGEX_CACHE: LazyLock<std::sync::Mutex<HashMap<String, Option<Regex>>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn get_or_compile_regex(pattern: &str) -> Option<Regex> {
    let mut cache = COMPILED_REGEX_CACHE
        .lock()
        .ok()?;
    if let Some(cached) = cache.get(pattern) {
        return cached.clone();
    }
    let compiled = Regex::new(pattern).ok();
    cache.insert(pattern.to_string(), compiled.clone());
    compiled
}

/// Allocates stable NER IDs for detected values within a single guard pass.
///
/// The same `(entity_type, value)` always maps to the same token; each entity
/// type numbers independently in reading order (`EMAIL_NER_001`, `SSN_NER_001`).
/// The value→token map is scoped to one request/response pass and is never
/// persisted — it holds the raw PII we are hiding.
#[derive(Default)]
pub(crate) struct PseudonymAllocator {
    tokens: HashMap<(String, String), String>,
    counters: HashMap<String, u32>,
    /// Name-token sets of every distinct `PERSON` value seen, with its NER ID,
    /// used to link name variants (`John` ↔ `John Smith`) to one id (Phase 3).
    persons: Vec<(HashSet<String>, String)>,
}

impl PseudonymAllocator {
    /// Return the stable NER ID for a value, allocating a new one on first sight.
    ///
    /// For `PERSON` entities, a value whose name tokens are a subset (or superset)
    /// of a single previously-seen person reuses that person's NER ID, so name
    /// variants that refer to the same individual share one pseudonym.
    pub(crate) fn token_for(
        &mut self,
        entity_type: &str,
        value: &str,
    ) -> String {
        let key = (entity_type.to_string(), value.to_string());
        if let Some(token) = self.tokens.get(&key) {
            return token.clone();
        }

        let person = (entity_type == "PERSON")
            .then(|| person_tokens(value))
            .filter(|tokens| !tokens.is_empty());
        if let Some(tokens) = &person
            && let Some(existing) = self.linked_person(tokens)
        {
            self.tokens
                .insert(key, existing.clone());
            return existing;
        }

        let counter = self
            .counters
            .entry(entity_type.to_string())
            .or_insert(0);
        *counter += 1;
        let token = format!("[{entity_type}_NER_{counter:03}]");
        self.tokens
            .insert(key, token.clone());
        if let Some(tokens) = person {
            self.persons
                .push((tokens, token.clone()));
        }
        token
    }

    /// Find the NER ID of the single previously-seen person whose name tokens
    /// relate to `tokens` by subset/superset. Returns `None` when there is no
    /// match or the match is ambiguous (relates to two or more distinct people).
    fn linked_person(
        &self,
        tokens: &HashSet<String>,
    ) -> Option<String> {
        let mut matched: Option<&String> = None;
        for (existing, token) in &self.persons {
            let related = existing.is_subset(tokens) || tokens.is_subset(existing);
            if !related {
                continue;
            }
            match matched {
                Some(prev) if prev != token => return None,
                _ => matched = Some(token),
            }
        }
        matched.cloned()
    }

    /// Build the reverse map (`token → original value`) used to restore
    /// pseudonymized content in the response.
    pub(crate) fn rehydration_map(&self) -> RehydrationMap {
        self.tokens
            .iter()
            .map(|((_entity, value), token)| (token.clone(), value.clone()))
            .collect()
    }
}

/// Honorifics stripped when comparing person names so a title does not defeat
/// variant linking (`Mr. Smith` ↔ `Smith`).
const NAME_HONORIFICS: &[&str] = &["mr", "mrs", "ms", "miss", "dr", "prof", "sir", "mx"];

/// Normalise a `PERSON` value to its comparable name tokens: lower-cased,
/// possessive- and punctuation-stripped, with honorifics removed.
fn person_tokens(value: &str) -> HashSet<String> {
    value
        .split_whitespace()
        .map(|word| {
            word.trim_end_matches("'s")
                .trim_end_matches("’s")
                .trim_matches(|c: char| !c.is_alphanumeric())
                .to_lowercase()
        })
        .filter(|word| !word.is_empty() && !NAME_HONORIFICS.contains(&word.as_str()))
        .collect()
}

/// A PII entity detected by a model-backed recognizer (Phase 2b), located in the
/// text by exact value rather than by (unreliable) model-provided offsets.
#[derive(Debug, Clone)]
pub struct DetectedEntity {
    pub entity_type: String,
    pub text: String,
    /// Optional coreference group the model assigned (Phase 3c): mentions sharing
    /// a group (e.g. `Bob` and `Robert Smith`) are the same real-world entity and
    /// collapse to one NER ID when coreference linking is enabled.
    pub group: Option<String>,
}

/// Maps a NER ID token back to its original value, for restoring pseudonymized
/// content in the response. Holds raw PII — request-scoped, never persisted.
pub type RehydrationMap = HashMap<String, String>;

/// A single-pass token → value replacer built from a [`RehydrationMap`]. Uses an
/// Aho-Corasick automaton so a response is scanned once regardless of how many
/// NER IDs the map holds (instead of one `str::replace` pass per token).
pub(crate) struct TokenReplacer {
    automaton: AhoCorasick,
    values: Vec<String>,
}

impl TokenReplacer {
    /// Build a replacer for a non-empty map, else `None`.
    pub(crate) fn new(map: &RehydrationMap) -> Option<Self> {
        if map.is_empty() {
            return None;
        }
        let mut tokens: Vec<&str> = Vec::with_capacity(map.len());
        let mut values: Vec<String> = Vec::with_capacity(map.len());
        for (token, value) in map {
            tokens.push(token.as_str());
            values.push(value.clone());
        }
        let automaton = AhoCorasickBuilder::new()
            .match_kind(MatchKind::LeftmostLongest)
            .build(&tokens)
            .ok()?;
        Some(Self { automaton, values })
    }

    /// Replace every token occurrence in `text` with its value, in one pass.
    pub(crate) fn replace(
        &self,
        text: &str,
    ) -> String {
        self.automaton
            .replace_all(text, &self.values)
    }
}

/// Matches a `[PERSON_NER_n]` token or a singular gendered pronoun, so pronoun
/// linking can scan both in one reading-order pass. Plural/neutral "they" is
/// deliberately excluded — it is far more likely to refer to a group or
/// organisation than to the single person this conservative linker targets.
static PERSON_OR_PRONOUN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:\[PERSON_NER_\d+\])|(?i:\b(?:he|him|his|himself|she|her|hers|herself)\b)")
        .expect("valid pronoun-linking regex")
});

/// Link singular gendered pronouns to a person's NER ID within one text, but
/// only when exactly one distinct `[PERSON_NER_n]` token has appeared before
/// the pronoun — so there is no antecedent ambiguity. Returns the rewritten text
/// when at least one pronoun was linked, else `None`.
fn link_pronouns_in_text(text: &str) -> Option<String> {
    let mut seen: Vec<&str> = Vec::new();
    let mut replacements: Vec<(std::ops::Range<usize>, &str)> = Vec::new();
    for m in PERSON_OR_PRONOUN.find_iter(text) {
        let matched = m.as_str();
        if matched.starts_with('[') {
            if !seen.contains(&matched) {
                seen.push(matched);
            }
        } else if let [token] = seen.as_slice() {
            replacements.push((m.range(), token));
        }
    }
    if replacements.is_empty() {
        return None;
    }
    let mut out = text.to_string();
    for (range, token) in replacements.into_iter().rev() {
        out.replace_range(range, token);
    }
    Some(out)
}

/// Apply single-antecedent pronoun linking to every message in a request body,
/// mutating `content` in place. Returns `true` when any message changed. A safe
/// no-op unless the request already contains exactly one pseudonymized person.
pub fn link_pronouns_in_body(body: &mut Value) -> bool {
    let Some(messages) = body
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
    else {
        return false;
    };
    let mut changed = false;
    for message in messages {
        let linked = message
            .get("content")
            .and_then(|c| c.as_str())
            .and_then(link_pronouns_in_text);
        if let Some(linked) = linked {
            message["content"] = Value::String(linked);
            changed = true;
            continue;
        }
        if let Some(parts) = message
            .get_mut("content")
            .and_then(|c| c.as_array_mut())
        {
            for part in parts {
                let linked = part
                    .get("text")
                    .and_then(|t| t.as_str())
                    .and_then(link_pronouns_in_text);
                if let Some(linked) = linked {
                    part["text"] = Value::String(linked);
                    changed = true;
                }
            }
        }
    }
    changed
}

/// Apply request prompt guards to a request body.
///
/// Inspects the `messages` array in an OpenAI-compatible request and checks
/// each message's `content` against all guard rules. Returns the outcome:
/// - `Allowed`: no rules matched
/// - `Masked`: content was modified in place (the `request_body` is mutated)
/// - `Rejected`: content matched a reject rule
pub fn apply_request_guards(
    request_body: &mut Value,
    guards: &[RequestGuard],
) -> GuardOutcome {
    let mut allocator = PseudonymAllocator::default();
    apply_request_guards_into(request_body, guards, &mut allocator)
}

/// Core request-guard loop, masking into a caller-provided allocator so the same
/// NER ID scheme can be shared with other detectors (e.g. model-backed PII) in
/// the same request.
pub(crate) fn apply_request_guards_into(
    request_body: &mut Value,
    guards: &[RequestGuard],
    allocator: &mut PseudonymAllocator,
) -> GuardOutcome {
    let mut any_masked = false;
    for guard in guards {
        let rejection = guard
            .rejection
            .as_ref()
            .map(GuardRejection::from)
            .unwrap_or_default();

        match apply_regex_guard_to_messages(request_body, &guard.regex, &rejection, allocator) {
            GuardOutcome::Rejected(r) => {
                info!("Prompt guard REJECTED request — matched {} rule(s)", guard.regex.rules.len());
                return GuardOutcome::Rejected(r);
            }
            GuardOutcome::Masked => {
                info!("Prompt guard MASKED content in request");
                any_masked = true;
            }
            GuardOutcome::Allowed => {}
        }
    }
    if any_masked {
        GuardOutcome::Masked
    } else {
        GuardOutcome::Allowed
    }
}

/// Mask model-detected PII entities in an OpenAI-compatible request body, sharing
/// `allocator` (and thus the NER ID scheme) with the regex/NER guards. Each
/// entity value is located by exact substring match across `messages[].content`
/// (string and multimodal text parts); overlapping matches keep the first,
/// longest span. Returns `true` if anything was masked.
pub fn mask_detected_entities(
    request_body: &mut Value,
    entities: &[DetectedEntity],
    mask_mode: MaskMode,
    link_coreferences: bool,
    allocator: &mut PseudonymAllocator,
) -> bool {
    if entities.is_empty() {
        return false;
    }
    // Phase 3c: map each coreference group to a canonical value (its longest
    // mention) so every alias in the group shares one NER ID.
    let canonical = if link_coreferences {
        coreference_canonicals(entities)
    } else {
        HashMap::new()
    };
    let Some(Value::Array(messages)) = request_body.get_mut("messages") else {
        return false;
    };
    let mut changed = false;
    for message in messages.iter_mut() {
        if let Some(Value::String(content)) = message.get_mut("content") {
            changed |= mask_entities_in_text(content, entities, mask_mode, &canonical, allocator);
        }
        if let Some(Value::Array(parts)) = message.get_mut("content") {
            for part in parts.iter_mut() {
                if part
                    .get("type")
                    .and_then(|t| t.as_str())
                    == Some("text")
                    && let Some(Value::String(text)) = part.get_mut("text")
                {
                    changed |= mask_entities_in_text(text, entities, mask_mode, &canonical, allocator);
                }
            }
        }
        // Tool-call arguments (assistant function calls) — a JSON string that can
        // carry PII; NER IDs remain valid inside it.
        if let Some(Value::Array(calls)) = message.get_mut("tool_calls") {
            for call in calls.iter_mut() {
                if let Some(Value::String(args)) = call
                    .get_mut("function")
                    .and_then(|f| f.get_mut("arguments"))
                {
                    changed |= mask_entities_in_text(args, entities, mask_mode, &canonical, allocator);
                }
            }
        }
    }
    changed
}

/// The canonical value (longest mention) for each coreference group present in
/// `entities`. Only entities carrying a `group` participate.
fn coreference_canonicals(entities: &[DetectedEntity]) -> HashMap<String, String> {
    let mut canonical: HashMap<String, String> = HashMap::new();
    for entity in entities {
        let Some(group) = &entity.group else {
            continue;
        };
        canonical
            .entry(group.clone())
            .and_modify(|current| {
                if entity.text.len() > current.len() {
                    *current = entity.text.clone();
                }
            })
            .or_insert_with(|| entity.text.clone());
    }
    canonical
}

fn mask_entities_in_text(
    text: &mut String,
    entities: &[DetectedEntity],
    mask_mode: MaskMode,
    canonical: &HashMap<String, String>,
    allocator: &mut PseudonymAllocator,
) -> bool {
    // Every occurrence of every detected value, tagged with its entity type and
    // the value that keys its NER ID (a group's canonical value, or its own).
    let mut spans: Vec<(std::ops::Range<usize>, &str, &str)> = Vec::new();
    for entity in entities {
        if entity.text.trim().is_empty() {
            continue;
        }
        let key = entity
            .group
            .as_ref()
            .and_then(|g| canonical.get(g))
            .map(String::as_str)
            .unwrap_or(entity.text.as_str());
        let mut from = 0;
        while let Some(pos) = text[from..].find(&entity.text) {
            let start = from + pos;
            let end = start + entity.text.len();
            spans.push((start..end, entity.entity_type.as_str(), key));
            from = end;
        }
    }
    if spans.is_empty() {
        return false;
    }
    // Reading order; prefer the longest span at a given start. Drop overlaps.
    spans.sort_by(|a, b| {
        a.0.start
            .cmp(&b.0.start)
            .then(b.0.end.cmp(&a.0.end))
    });
    let mut replacements: Vec<(std::ops::Range<usize>, String)> = Vec::new();
    let mut last_end = 0;
    for (range, entity_type, key) in spans {
        if range.start < last_end {
            continue;
        }
        last_end = range.end;
        let entity = entity_type.to_uppercase();
        let token = match mask_mode {
            MaskMode::Redact => format!("<{entity}>"),
            MaskMode::Pseudonymize => allocator.token_for(&entity, key),
        };
        replacements.push((range, token));
    }
    for (range, token) in replacements.into_iter().rev() {
        text.replace_range(range, &token);
    }
    true
}

/// Restore pseudonymized values in an OpenAI-compatible response body, replacing
/// each NER ID token with its original value across `choices[].message.content`
/// and `choices[].delta.content`. Best-effort literal substitution; returns
/// `true` if anything was restored.
pub fn rehydrate_response(
    response_body: &mut Value,
    map: &RehydrationMap,
) -> bool {
    let Some(replacer) = TokenReplacer::new(map) else {
        return false;
    };
    let Some(choices) = response_body
        .get_mut("choices")
        .and_then(|c| c.as_array_mut())
    else {
        return false;
    };

    let mut changed = false;
    for choice in choices.iter_mut() {
        for field in ["message", "delta"] {
            let Some(container) = choice.get_mut(field) else {
                continue;
            };
            if let Some(Value::String(content)) = container.get_mut("content") {
                let restored = replacer.replace(content);
                if restored != *content {
                    *content = restored;
                    changed = true;
                }
            }
            // Tool-call arguments the model emitted may echo NER IDs back.
            if let Some(Value::Array(calls)) = container.get_mut("tool_calls") {
                for call in calls.iter_mut() {
                    if let Some(Value::String(args)) = call
                        .get_mut("function")
                        .and_then(|f| f.get_mut("arguments"))
                    {
                        let restored = replacer.replace(args);
                        if restored != *args {
                            *args = restored;
                            changed = true;
                        }
                    }
                }
            }
        }
    }
    changed
}

/// Apply response prompt guards to a response body.
///
/// For OpenAI-compatible responses, inspects `choices[].message.content`.
/// For other formats, inspects top-level text fields.
pub fn apply_response_guards(
    response_body: &mut Value,
    guards: &[ResponseGuard],
) -> GuardOutcome {
    let mut any_masked = false;
    // One allocator per response, independent of the request pass.
    let mut allocator = PseudonymAllocator::default();

    for guard in guards {
        let rejection = guard
            .rejection
            .as_ref()
            .map(GuardRejection::from)
            .unwrap_or_default();

        match apply_regex_guard_to_response(response_body, &guard.regex, &rejection, &mut allocator) {
            GuardOutcome::Rejected(r) => {
                info!("Prompt guard REJECTED response");
                return GuardOutcome::Rejected(r);
            }
            GuardOutcome::Masked => {
                info!("Prompt guard MASKED content in response");
                any_masked = true;
            }
            GuardOutcome::Allowed => {}
        }
    }

    if any_masked {
        GuardOutcome::Masked
    } else {
        GuardOutcome::Allowed
    }
}

/// Body returned when a Prompt Guard rule cannot be evaluated.
const RULE_UNAVAILABLE_BODY: &str = r#"{"error":{"message":"Prompt Guard rule unavailable","type":"guardrail_unavailable","code":"prompt_guard_pattern_unavailable"}}"#;

/// The side of a Prompt Guard a regex guard is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardSide {
    Request,
    Response,
}

impl GuardSide {
    fn as_str(self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Response => "response",
        }
    }
}

/// How a rule is named in logs, errors and rejection reasons. An unlabelled
/// custom pattern is named by its 1-based position in its guard, never by its
/// regex, which may be written to catch secrets.
fn rule_name(
    rule: &RegexRule,
    position: usize,
) -> String {
    match rule {
        RegexRule::Builtin { builtin } => format!("built-in pattern '{builtin}'"),
        RegexRule::Pattern { label: Some(label), .. } => format!("custom pattern '{label}'"),
        RegexRule::Pattern { label: None, .. } => format!("custom pattern #{position}"),
    }
}

/// Why `rule` cannot be evaluated, or `None` when it can. `compiles` decides
/// whether a custom pattern compiles.
fn rule_issue(
    rule: &RegexRule,
    position: usize,
    compiles: impl Fn(&str) -> bool,
) -> Option<String> {
    let name = rule_name(rule, position);
    match rule {
        RegexRule::Builtin { builtin } => {
            super::definitions::builtin_issue(builtin).map(|issue| format!("{name} {}", issue.description()))
        }
        RegexRule::Pattern { pattern, .. } => (!compiles(pattern)).then(|| format!("{name} does not compile")),
    }
}

/// The first rule in `config`'s request and response regex guards that cannot
/// be evaluated: its side, and a description for logs and errors.
fn first_rule_issue(
    config: &PromptGuardConfig,
    compiles: impl Fn(&str) -> bool,
) -> Option<(GuardSide, String)> {
    let request = config
        .request
        .iter()
        .map(|guard| (GuardSide::Request, &guard.regex));
    let response = config
        .response
        .iter()
        .map(|guard| (GuardSide::Response, &guard.regex));
    request
        .chain(response)
        .find_map(|(side, rules)| {
            rules
                .rules
                .iter()
                .enumerate()
                .find_map(|(index, rule)| rule_issue(rule, index + 1, &compiles))
                .map(|issue| (side, format!("{issue} on the {} side", side.as_str())))
        })
}

/// Refuse a Surface save whose enabled Prompt Guard has a regex rule that
/// cannot be evaluated: a built-in pattern that is not loaded and compiled, or
/// a custom pattern that does not compile. Custom patterns are compiled here
/// without being cached, so a refused save leaves nothing behind.
pub fn validate_regex_rules(config: &PromptGuardConfig) -> Result<(), String> {
    if !config.enabled {
        return Ok(());
    }
    match first_rule_issue(config, |pattern| Regex::new(pattern).is_ok()) {
        Some((_, issue)) => Err(format!("Prompt Guard {issue}")),
        None => Ok(()),
    }
}

/// When an enabled Prompt Guard has a request or response regex rule that
/// cannot be evaluated, the side the rule is on and a 502 rejection, so the
/// request is refused before any upstream call instead of passing unchecked.
/// `None` when every rule can be evaluated.
pub fn unusable_rule_rejection(config: &PromptGuardConfig) -> Option<(GuardSide, GuardRejection)> {
    if !config.enabled {
        return None;
    }
    let (side, issue) = first_rule_issue(config, |pattern| get_or_compile_regex(pattern).is_some())?;
    warn!("Prompt guard rule unavailable, refusing the request: {issue}");
    Some((side, rule_unavailable_rejection(&issue)))
}

/// The 502 rejection for a rule that cannot be evaluated. The guard's own
/// `rejection` is not used: the content was not flagged.
fn rule_unavailable_rejection(issue: &str) -> GuardRejection {
    GuardRejection {
        status_code: 502,
        body: RULE_UNAVAILABLE_BODY.to_string(),
        content_type: "application/json".to_string(),
        reason: Some(format!("prompt guard rule unavailable: {issue}")),
        categories: vec![RULE_UNAVAILABLE_CATEGORY.to_string()],
    }
}

/// Rejection category token for a rule that cannot be evaluated. Rejection
/// telemetry classifies this token rather than the reason, which names the rule
/// (`ssn`, `credit_card`) and would otherwise read as flagged content.
pub const RULE_UNAVAILABLE_CATEGORY: &str = "prompt_guard_pattern_unavailable";

/// Apply regex guard rules to request messages.
///
/// Scans `messages[].content` in an OpenAI-compatible request body.
fn apply_regex_guard_to_messages(
    request_body: &mut Value,
    rules: &RegexRules,
    rejection: &GuardRejection,
    allocator: &mut PseudonymAllocator,
) -> GuardOutcome {
    let messages = match request_body.get_mut("messages") {
        Some(Value::Array(msgs)) => msgs,
        _ => return GuardOutcome::Allowed,
    };

    let mut any_masked = false;

    for message in messages.iter_mut() {
        if let Some(Value::String(content)) = message.get_mut("content") {
            match apply_regex_rules_to_text(content, rules, allocator) {
                RegexResult::Reject(reason) => {
                    let mut r = rejection.clone();
                    r.reason = Some(reason);
                    return GuardOutcome::Rejected(r);
                }
                RegexResult::Unavailable(issue) => return GuardOutcome::Rejected(rule_unavailable_rejection(&issue)),
                RegexResult::Mask(new_content) => {
                    *content = new_content;
                    any_masked = true;
                }
                RegexResult::NoMatch => {}
            }
        }
        // Also handle content arrays (multimodal messages):
        // [{"type": "text", "text": "..."}, {"type": "image_url", ...}]
        if let Some(Value::Array(parts)) = message.get_mut("content") {
            for part in parts.iter_mut() {
                if part
                    .get("type")
                    .and_then(|t| t.as_str())
                    == Some("text")
                    && let Some(Value::String(text)) = part.get_mut("text")
                {
                    match apply_regex_rules_to_text(text, rules, allocator) {
                        RegexResult::Reject(reason) => {
                            let mut r = rejection.clone();
                            r.reason = Some(reason);
                            return GuardOutcome::Rejected(r);
                        }
                        RegexResult::Unavailable(issue) => {
                            return GuardOutcome::Rejected(rule_unavailable_rejection(&issue));
                        }
                        RegexResult::Mask(new_text) => {
                            *text = new_text;
                            any_masked = true;
                        }
                        RegexResult::NoMatch => {}
                    }
                }
            }
        }
        // Tool-call arguments (assistant function calls) — a JSON string that
        // can carry PII the caller passed through a tool.
        if let Some(Value::Array(calls)) = message.get_mut("tool_calls") {
            for call in calls.iter_mut() {
                if let Some(Value::String(args)) = call
                    .get_mut("function")
                    .and_then(|f| f.get_mut("arguments"))
                {
                    match apply_regex_rules_to_tool_arguments(args, rules, allocator) {
                        RegexResult::Reject(reason) => {
                            let mut r = rejection.clone();
                            r.reason = Some(reason);
                            return GuardOutcome::Rejected(r);
                        }
                        RegexResult::Unavailable(issue) => {
                            return GuardOutcome::Rejected(rule_unavailable_rejection(&issue));
                        }
                        RegexResult::Mask(new_args) => {
                            *args = new_args;
                            any_masked = true;
                        }
                        RegexResult::NoMatch => {}
                    }
                }
            }
        }
    }

    if any_masked {
        GuardOutcome::Masked
    } else {
        GuardOutcome::Allowed
    }
}

/// Apply regex guard rules to response content.
///
/// Handles OpenAI-compatible format: `choices[].message.content`
fn apply_regex_guard_to_response(
    response_body: &mut Value,
    rules: &RegexRules,
    rejection: &GuardRejection,
    allocator: &mut PseudonymAllocator,
) -> GuardOutcome {
    let choices = match response_body.get_mut("choices") {
        Some(Value::Array(choices)) => choices,
        _ => return GuardOutcome::Allowed,
    };

    let mut any_masked = false;

    for choice in choices.iter_mut() {
        // OpenAI format: choices[].message.content
        if let Some(Value::String(content)) = choice
            .get_mut("message")
            .and_then(|m| m.get_mut("content"))
        {
            match apply_regex_rules_to_text(content, rules, allocator) {
                RegexResult::Reject(reason) => {
                    let mut r = rejection.clone();
                    r.reason = Some(reason);
                    return GuardOutcome::Rejected(r);
                }
                RegexResult::Unavailable(issue) => return GuardOutcome::Rejected(rule_unavailable_rejection(&issue)),
                RegexResult::Mask(new_content) => {
                    *content = new_content;
                    any_masked = true;
                }
                RegexResult::NoMatch => {}
            }
        }
        // Also check delta content for streaming responses
        if let Some(Value::String(content)) = choice
            .get_mut("delta")
            .and_then(|d| d.get_mut("content"))
        {
            match apply_regex_rules_to_text(content, rules, allocator) {
                RegexResult::Reject(reason) => {
                    let mut r = rejection.clone();
                    r.reason = Some(reason);
                    return GuardOutcome::Rejected(r);
                }
                RegexResult::Unavailable(issue) => return GuardOutcome::Rejected(rule_unavailable_rejection(&issue)),
                RegexResult::Mask(new_content) => {
                    *content = new_content;
                    any_masked = true;
                }
                RegexResult::NoMatch => {}
            }
        }
    }

    if any_masked {
        GuardOutcome::Masked
    } else {
        GuardOutcome::Allowed
    }
}

/// Result of applying regex rules to a single text string
enum RegexResult {
    NoMatch,
    Reject(String),
    Mask(String),
    /// A rule could not be evaluated; the request is refused with the 502
    /// [`rule_unavailable_rejection`], not the guard's own rejection.
    Unavailable(String),
}

fn is_credit_card(rule: &RegexRule) -> bool {
    matches!(rule, RegexRule::Builtin { builtin } if builtin == "credit_card")
}

/// The order a guard applies its rules in, each with its 1-based listed
/// position. A mask guard applies `credit_card` before its other rules, which
/// keep their listed order: the card pattern masks a whole run of digits joined
/// by single spaces or dashes, so a phone number, SSN or other rule cannot take
/// part of a card before it does. Any other guard applies its rules as listed.
fn application_order(rules: &RegexRules) -> Vec<(usize, &RegexRule)> {
    let mut ordered: Vec<(usize, &RegexRule)> = rules
        .rules
        .iter()
        .enumerate()
        .map(|(index, rule)| (index + 1, rule))
        .collect();
    if rules.action == GuardAction::Mask {
        ordered.sort_by_key(|(_, rule)| !is_credit_card(rule));
    }
    ordered
}

/// Whether `byte` can be part of a bare JSON number.
fn is_json_number_byte(byte: u8) -> bool {
    byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E')
}

/// Where a replacement token lands, which decides how it is written.
#[derive(Clone, Copy)]
enum TokenPlace {
    /// Plain text: the token is written as is.
    Text,
    /// Inside a JSON string: the token is JSON-escaped.
    JsonString,
    /// In place of a bare JSON value: the token is written as a JSON string.
    JsonValue,
}

/// The ranges of `text` to replace for `matches`, each with where its token
/// lands. In JSON tool-call arguments, a match outside a string is part of a bare
/// number: its range covers the whole number, which is replaced by a JSON string
/// token so the arguments still parse. `matches` are in ascending order, so the
/// arguments are scanned once; a range overlapping the one before is dropped.
fn replacement_ranges(
    text: &str,
    matches: Vec<std::ops::Range<usize>>,
    json_arguments: bool,
) -> Vec<(std::ops::Range<usize>, TokenPlace)> {
    let bytes = text.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut scanned = 0;
    let mut ranges: Vec<(std::ops::Range<usize>, TokenPlace)> = Vec::with_capacity(matches.len());
    for mut range in matches {
        let mut place = TokenPlace::Text;
        if json_arguments {
            for &byte in &bytes[scanned..range.start.max(scanned)] {
                if escaped {
                    escaped = false;
                } else if in_string && byte == b'\\' {
                    escaped = true;
                } else if byte == b'"' {
                    in_string = !in_string;
                }
            }
            scanned = scanned.max(range.start);
            if in_string {
                place = TokenPlace::JsonString;
            } else {
                while range.start > 0 && is_json_number_byte(bytes[range.start - 1]) {
                    range.start -= 1;
                }
                while range.end < bytes.len() && is_json_number_byte(bytes[range.end]) {
                    range.end += 1;
                }
                place = TokenPlace::JsonValue;
            }
        }
        if ranges
            .last()
            .is_some_and(|(previous, _)| range.start < previous.end)
        {
            continue;
        }
        ranges.push((range, place));
    }
    ranges
}

/// Replace each range with its token, last first so earlier offsets stay valid.
fn splice_tokens(
    text: &mut String,
    replacements: Vec<(std::ops::Range<usize>, String)>,
) {
    for (range, token) in replacements.into_iter().rev() {
        text.replace_range(range, &token);
    }
}

/// The token for one replaced value, allocated from the whole replaced text so a
/// pseudonym and its restore value cover exactly what was removed.
fn replacement_token(
    value: &str,
    place: TokenPlace,
    redact_token: &str,
    entity: &str,
    mask_mode: MaskMode,
    allocator: &mut PseudonymAllocator,
) -> String {
    let token = match mask_mode {
        MaskMode::Redact => redact_token.to_string(),
        MaskMode::Pseudonymize => allocator.token_for(entity, value),
    };
    let json = || serde_json::to_string(&token).unwrap_or_else(|_| format!("\"{token}\""));
    match place {
        TokenPlace::Text => token,
        TokenPlace::JsonValue => json(),
        TokenPlace::JsonString => {
            let quoted = json();
            quoted[1..quoted.len() - 1].to_string()
        }
    }
}

/// Apply all regex rules to a text string.
///
/// Rules are processed sequentially in [`application_order`] — each rule operates on
/// the output of the previous one (for mask action). For reject action, processing
/// stops at the first match.
fn apply_regex_rules_to_text(
    text: &str,
    rules: &RegexRules,
    allocator: &mut PseudonymAllocator,
) -> RegexResult {
    apply_regex_rules(text, rules, allocator, false)
}

/// [`apply_regex_rules_to_text`] on a tool call's `arguments`; when they are
/// JSON, a masked value outside a string is replaced by a quoted token.
fn apply_regex_rules_to_tool_arguments(
    arguments: &str,
    rules: &RegexRules,
    allocator: &mut PseudonymAllocator,
) -> RegexResult {
    let json_arguments = serde_json::from_str::<Value>(arguments).is_ok();
    apply_regex_rules(arguments, rules, allocator, json_arguments)
}

fn apply_regex_rules(
    text: &str,
    rules: &RegexRules,
    allocator: &mut PseudonymAllocator,
    json_arguments: bool,
) -> RegexResult {
    let mut current = text.to_string();
    let mut any_modified = false;

    for (position, rule) in application_order(rules) {
        match rule {
            RegexRule::Builtin { builtin } => {
                let ranges: Vec<std::ops::Range<usize>> =
                    if let Some(regex) = super::definitions::get_compiled_regex(builtin) {
                        regex
                            .find_iter(&current)
                            .map(|m| m.range())
                            .collect()
                    } else {
                        let issue = rule_issue(rule, position, |_| true).unwrap_or_else(|| rule_name(rule, position));
                        warn!("Prompt guard: {issue} — refusing");
                        return RegexResult::Unavailable(issue);
                    };
                let label = super::definitions::get_pattern_definition(builtin)
                    .map(|d| d.label.as_str())
                    .unwrap_or(builtin.as_str());

                if !ranges.is_empty() {
                    match rules.action {
                        GuardAction::Reject => {
                            info!("Prompt guard: {} detected — rejecting", label);
                            return RegexResult::Reject(format!("{label} detected"));
                        }
                        GuardAction::Mask => {
                            let entity = builtin.to_uppercase();
                            let redact_token = format!("<{entity}>");
                            // Allocate in reading order, then splice in reverse
                            // so earlier byte offsets stay valid.
                            let replacements: Vec<(std::ops::Range<usize>, String)> =
                                replacement_ranges(&current, ranges, json_arguments)
                                    .into_iter()
                                    .map(|(range, place)| {
                                        let token = replacement_token(
                                            &current[range.clone()],
                                            place,
                                            &redact_token,
                                            &entity,
                                            rules.mask_mode,
                                            allocator,
                                        );
                                        (range, token)
                                    })
                                    .collect();
                            splice_tokens(&mut current, replacements);
                            any_modified = true;
                        }
                    }
                }
            }
            RegexRule::Pattern { pattern, label } => {
                if let Some(regex) = get_or_compile_regex(pattern) {
                    let ranges: Vec<std::ops::Range<usize>> = regex
                        .find_iter(&current)
                        .map(|m| m.range())
                        .collect();

                    if !ranges.is_empty() {
                        match rules.action {
                            GuardAction::Reject => {
                                let name = rule_name(rule, position);
                                info!("Prompt guard: {name} matched — rejecting");
                                return RegexResult::Reject(format!("Matched {name}"));
                            }
                            GuardAction::Mask => {
                                let redact_token = label
                                    .as_deref()
                                    .map(|l| format!("<{}>", l.to_uppercase()))
                                    .unwrap_or_else(|| "<MASKED>".to_string());
                                let entity = label
                                    .as_deref()
                                    .map(|l| l.to_uppercase())
                                    .unwrap_or_else(|| "CUSTOM".to_string());
                                // Allocate in reading order, then splice in reverse.
                                let replacements: Vec<(std::ops::Range<usize>, String)> =
                                    replacement_ranges(&current, ranges, json_arguments)
                                        .into_iter()
                                        .map(|(range, place)| {
                                            let token = replacement_token(
                                                &current[range.clone()],
                                                place,
                                                &redact_token,
                                                &entity,
                                                rules.mask_mode,
                                                allocator,
                                            );
                                            (range, token)
                                        })
                                        .collect();
                                splice_tokens(&mut current, replacements);
                                any_modified = true;
                            }
                        }
                    }
                } else {
                    let issue = format!("{} does not compile", rule_name(rule, position));
                    warn!("Prompt guard: {issue} — refusing");
                    return RegexResult::Unavailable(issue);
                }
            }
        }
    }

    if any_modified {
        RegexResult::Mask(current)
    } else {
        RegexResult::NoMatch
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Test definitions JSON matching the config file patterns
    const TEST_DEFINITIONS: &str = r#"{
        "defined_patterns": [
            {"key": "ssn", "label": "US SSN", "icon": "fa-id-card", "description": "SSN", "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"},
            {"key": "credit_card", "label": "Credit Card", "icon": "fa-credit-card", "description": "CC", "regex": "(?-u:\\b)(?:[0-9](?:[ -]?[0-9]){13,}|4[0-9]{12})(?-u:\\b)|[0-9]*[\\d&&[^0-9]](?:[ -]?\\d){13,}"},
            {"key": "email", "label": "Email", "icon": "fa-envelope", "description": "Email", "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
            {"key": "phone_number", "label": "Phone", "icon": "fa-phone", "description": "Phone", "regex": "(?:\\+\\d{1,3}[-. ]?(?:\\d[-. ]?){6,12}\\d)|(?:\\([2-9]\\d{2}\\)[-. ]?\\d{3}[-. ]?\\d{4}\\b)|(?:\\b(?:1[-. ]?)?[2-9]\\d{2}[-. ]?\\d{3}[-. ]?\\d{4}\\b)|(?:\\b0[45]\\d{2}[-. ]?\\d{3}[-. ]?\\d{3}\\b)"},
            {"key": "ip_address", "label": "IP Address", "icon": "fa-network-wired", "description": "IP", "regex": "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"},
            {"key": "street_address", "label": "Street Address", "icon": "fa-map-marker-alt", "description": "Address", "regex": "\\d{1,5}\\s\\w.\\s(\\b\\w*\\b\\s){1,2}\\w*.?"},
            {"key": "broken", "label": "Broken", "icon": "fa-ban", "description": "Does not compile", "regex": "(?!x)y"}
        ]
    }"#;

    fn init_test_definitions() {
        let _ = super::super::definitions::init_definitions_from_str(TEST_DEFINITIONS);
    }

    fn make_request(content: &str) -> Value {
        json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": content}
            ]
        })
    }

    fn make_response(content: &str) -> Value {
        json!({
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": content
                    }
                }
            ]
        })
    }

    // === Request guard tests ===

    #[test]
    fn test_request_no_match_passes() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
            },
            rejection: None,
        }];

        let mut body = make_request("Hello, how are you?");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Allowed));
    }

    #[test]
    fn test_request_ssn_rejected() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
            },
            rejection: None,
        }];

        let mut body = make_request("My SSN is 123-45-6789");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Rejected(_)));
    }

    #[test]
    fn test_request_email_masked() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "email".to_string() }],
            },
            rejection: None,
        }];

        let mut body = make_request("Email me at test@example.com");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));

        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<EMAIL>"));
        assert!(!content.contains("test@example.com"));
    }

    #[test]
    fn test_request_custom_pattern_rejected() {
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Pattern {
                    pattern: r"password[=:]\s*\S+".to_string(),
                    label: Some("credentials".to_string()),
                }],
            },
            rejection: Some(RejectionConfig {
                status_code: 400,
                body: "Credentials detected".to_string(),
                content_type: "application/json".to_string(),
            }),
        }];

        let mut body = make_request("My password= hunter2");
        let result = apply_request_guards(&mut body, &guards);
        match result {
            GuardOutcome::Rejected(r) => {
                assert_eq!(r.status_code, 400);
                assert_eq!(r.body, "Credentials detected");
                assert_eq!(r.reason.as_deref(), Some("Matched custom pattern 'credentials'"));
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_request_custom_pattern_masked() {
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Pattern {
                    pattern: r"api_key=\S+".to_string(),
                    label: Some("api_key".to_string()),
                }],
            },
            rejection: None,
        }];

        let mut body = make_request("Use api_key=sk-abc123 for auth");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));

        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<API_KEY>"));
        assert!(!content.contains("sk-abc123"));
    }

    #[test]
    fn test_request_multiple_guards() {
        init_test_definitions();
        let guards = vec![
            // First guard: mask emails
            RequestGuard {
                regex: RegexRules {
                    action: GuardAction::Mask,
                    mask_mode: MaskMode::Redact,
                    restore_in_response: false,
                    link_pronouns: false,
                    rules: vec![RegexRule::Builtin { builtin: "email".to_string() }],
                },
                rejection: None,
            },
            // Second guard: reject SSNs
            RequestGuard {
                regex: RegexRules {
                    action: GuardAction::Reject,
                    mask_mode: MaskMode::Redact,
                    restore_in_response: false,
                    link_pronouns: false,
                    rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
                },
                rejection: None,
            },
        ];

        // Contains email but no SSN — should be masked (not rejected)
        let mut body = make_request("Email: test@example.com");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));

        // Contains SSN — should be rejected
        let mut body2 = make_request("SSN: 123-45-6789");
        let result2 = apply_request_guards(&mut body2, &guards);
        assert!(matches!(result2, GuardOutcome::Rejected(_)));
    }

    #[test]
    fn test_request_credit_card_rejected() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin {
                    builtin: "credit_card".to_string(),
                }],
            },
            rejection: None,
        }];

        let mut body = make_request("Pay with 4111111111111111");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Rejected(_)));
    }

    #[test]
    fn test_request_phone_masked() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin {
                    builtin: "phone_number".to_string(),
                }],
            },
            rejection: None,
        }];

        let mut body = make_request("Call me at 555-123-4567");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<PHONE_NUMBER>"));
    }

    #[test]
    fn test_request_ip_address_masked() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin {
                    builtin: "ip_address".to_string(),
                }],
            },
            rejection: None,
        }];

        let mut body = make_request("Server at 192.168.1.100");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<IP_ADDRESS>"));
    }

    // === Response guard tests ===

    #[test]
    fn test_response_no_match_passes() {
        init_test_definitions();
        let guards = vec![ResponseGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
            },
            rejection: None,
        }];

        let mut body = make_response("The weather is nice today.");
        let result = apply_response_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Allowed));
    }

    #[test]
    fn test_response_email_masked() {
        init_test_definitions();
        let guards = vec![ResponseGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "email".to_string() }],
            },
            rejection: None,
        }];

        let mut body = make_response("Contact support@company.com for help");
        let result = apply_response_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<EMAIL>"));
        assert!(!content.contains("support@company.com"));
    }

    #[test]
    fn test_response_ssn_rejected() {
        init_test_definitions();
        let guards = vec![ResponseGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
            },
            rejection: Some(RejectionConfig {
                status_code: 500,
                body: "LLM response contains PII".to_string(),
                content_type: "text/plain".to_string(),
            }),
        }];

        let mut body = make_response("Your SSN is 123-45-6789");
        let result = apply_response_guards(&mut body, &guards);
        match result {
            GuardOutcome::Rejected(r) => {
                assert_eq!(r.status_code, 500);
                assert_eq!(r.body, "LLM response contains PII");
            }
            _ => panic!("Expected rejection"),
        }
    }

    #[test]
    fn test_multimodal_content_filtered() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "email".to_string() }],
            },
            rejection: None,
        }];

        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": "Send to user@test.com"},
                        {"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}
                    ]
                }
            ]
        });

        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));
        let text = body["messages"][0]["content"][0]["text"]
            .as_str()
            .unwrap();
        assert!(text.contains("<EMAIL>"));
    }

    #[test]
    fn test_empty_messages_passes() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "ssn".to_string() }],
            },
            rejection: None,
        }];

        let mut body = json!({"model": "gpt-4"});
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Allowed));
    }

    #[test]
    fn test_multiple_rules_in_single_guard() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![
                    RegexRule::Builtin { builtin: "email".to_string() },
                    RegexRule::Builtin {
                        builtin: "phone_number".to_string(),
                    },
                ],
            },
            rejection: None,
        }];

        let mut body = make_request("Email: a@b.com, Phone: 555-123-4567");
        let result = apply_request_guards(&mut body, &guards);
        assert!(matches!(result, GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("<EMAIL>"));
        assert!(content.contains("<PHONE_NUMBER>"));
    }

    // === NER ID pseudonymization tests ===

    fn pseudonymize_guard(builtins: &[&str]) -> Vec<RequestGuard> {
        vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Pseudonymize,
                restore_in_response: false,
                link_pronouns: false,
                rules: builtins
                    .iter()
                    .map(|b| RegexRule::Builtin { builtin: b.to_string() })
                    .collect(),
            },
            rejection: None,
        }]
    }

    #[test]
    fn pseudonymize_reuses_one_id_for_a_repeated_value() {
        init_test_definitions();
        let guards = pseudonymize_guard(&["email"]);
        let mut body = make_request("Mail a@b.com then reply to a@b.com again");
        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            content
                .matches("[EMAIL_NER_001]")
                .count(),
            2
        );
        assert!(!content.contains("[EMAIL_NER_002]"));
        assert!(!content.contains("a@b.com"));
    }

    #[test]
    fn pseudonymize_numbers_distinct_values_in_reading_order() {
        init_test_definitions();
        let guards = pseudonymize_guard(&["email"]);
        let mut body = make_request("From a@b.com to c@d.com");
        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap()
            .to_string();
        let first = content
            .find("[EMAIL_NER_001]")
            .unwrap();
        let second = content
            .find("[EMAIL_NER_002]")
            .unwrap();
        assert!(first < second, "ids must number in reading order");
    }

    #[test]
    fn pseudonymize_is_consistent_across_messages() {
        init_test_definitions();
        let guards = pseudonymize_guard(&["email"]);
        let mut body = json!({
            "model": "gpt-4",
            "messages": [
                {"role": "user", "content": "first mention a@b.com"},
                {"role": "user", "content": "second mention a@b.com"}
            ]
        });
        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));
        assert!(
            body["messages"][0]["content"]
                .as_str()
                .unwrap()
                .contains("[EMAIL_NER_001]")
        );
        assert!(
            body["messages"][1]["content"]
                .as_str()
                .unwrap()
                .contains("[EMAIL_NER_001]")
        );
    }

    #[test]
    fn pseudonymize_numbers_each_entity_type_independently() {
        init_test_definitions();
        let guards = pseudonymize_guard(&["ssn", "email"]);
        let mut body = make_request("SSN 123-45-6789 email a@b.com");
        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("[SSN_NER_001]"));
        assert!(content.contains("[EMAIL_NER_001]"));
    }

    #[test]
    fn pseudonymize_masks_response_content() {
        init_test_definitions();
        let guards = vec![ResponseGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Pseudonymize,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Builtin { builtin: "email".to_string() }],
            },
            rejection: None,
        }];
        let mut body = make_response("contact a@b.com or a@b.com");
        assert!(matches!(apply_response_guards(&mut body, &guards), GuardOutcome::Masked));
        let content = body["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            content
                .matches("[EMAIL_NER_001]")
                .count(),
            2
        );
    }

    #[test]
    fn pseudonymize_custom_pattern_uses_label_as_entity() {
        init_test_definitions();
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Pseudonymize,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Pattern {
                    pattern: r"token-\d+".to_string(),
                    label: Some("api_token".to_string()),
                }],
            },
            rejection: None,
        }];
        let mut body = make_request("use token-111 and token-222 and token-111");
        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            content
                .matches("[API_TOKEN_NER_001]")
                .count(),
            2
        );
        assert!(content.contains("[API_TOKEN_NER_002]"));
    }

    #[test]
    fn redact_remains_the_default_mode() {
        // A config without mask_mode deserializes to Redact, preserving the
        // static-token behavior for existing surfaces.
        let rules: RegexRules =
            serde_json::from_value(json!({ "action": "mask", "rules": [{ "builtin": "email" }] })).unwrap();
        assert_eq!(rules.mask_mode, MaskMode::Redact);
    }

    #[test]
    fn allocator_returns_a_stable_token_per_value() {
        let mut alloc = PseudonymAllocator::default();
        let a = alloc.token_for("EMAIL", "a@b.com");
        let b = alloc.token_for("EMAIL", "c@d.com");
        assert_eq!(alloc.token_for("EMAIL", "a@b.com"), a);
        assert_eq!(a, "[EMAIL_NER_001]");
        assert_eq!(b, "[EMAIL_NER_002]");
        assert_eq!(alloc.token_for("SSN", "111"), "[SSN_NER_001]");
    }

    #[test]
    fn person_variants_link_to_one_near_id() {
        // A fuller name and its short/possessive variants map to one pseudonym,
        // regardless of the order in which they are first seen.
        let mut alloc = PseudonymAllocator::default();
        let full = alloc.token_for("PERSON", "John Smith");
        assert_eq!(full, "[PERSON_NER_001]");
        assert_eq!(alloc.token_for("PERSON", "John"), full);
        assert_eq!(alloc.token_for("PERSON", "John's"), full);
        assert_eq!(alloc.token_for("PERSON", "Dr. Smith"), full);
        // A short name seen first still links to the later fuller name.
        let jane = alloc.token_for("PERSON", "Jane");
        assert_eq!(jane, "[PERSON_NER_002]");
        assert_eq!(alloc.token_for("PERSON", "Jane Doe"), jane);
    }

    #[test]
    fn ambiguous_person_variant_gets_its_own_near_id() {
        // A surname shared by two known people is ambiguous, so it must not be
        // linked to either — it gets a fresh id instead of guessing.
        let mut alloc = PseudonymAllocator::default();
        let john = alloc.token_for("PERSON", "John Smith");
        let jane = alloc.token_for("PERSON", "Jane Smith");
        assert_ne!(john, jane);
        let smith = alloc.token_for("PERSON", "Smith");
        assert_ne!(smith, john);
        assert_ne!(smith, jane);
        assert_eq!(smith, "[PERSON_NER_003]");
    }

    #[test]
    fn pronoun_links_to_a_lone_person() {
        // With only one person present, a following gendered pronoun is linked.
        let linked = link_pronouns_in_text("[PERSON_NER_001] is a doctor. She was born in 1980.");
        assert_eq!(linked.unwrap(), "[PERSON_NER_001] is a doctor. [PERSON_NER_001] was born in 1980.");
    }

    #[test]
    fn pronoun_is_left_alone_when_ambiguous() {
        // Two people => the antecedent is ambiguous, so nothing is linked.
        assert!(link_pronouns_in_text("[PERSON_NER_001] met [PERSON_NER_002]. He smiled.").is_none());
        // A pronoun before any person mention is never linked (no antecedent).
        assert!(link_pronouns_in_text("He arrived before [PERSON_NER_001].").is_none());
        // No person token at all => nothing to link.
        assert!(link_pronouns_in_text("She waved at the crowd.").is_none());
    }

    #[test]
    fn link_pronouns_in_body_rewrites_message_content() {
        let mut body = json!({
            "messages": [
                { "role": "user", "content": "[PERSON_NER_001] left. Her keys are gone." }
            ]
        });
        assert!(link_pronouns_in_body(&mut body));
        assert_eq!(body["messages"][0]["content"], "[PERSON_NER_001] left. [PERSON_NER_001] keys are gone.");
    }

    // === Response re-hydration tests ===

    #[test]
    fn regex_guards_and_detected_entities_share_the_allocator() {
        init_test_definitions();
        let mut alloc = PseudonymAllocator::default();
        let guards = pseudonymize_guard(&["email"]);
        let mut body = make_request("email a@b.com and speak to Jane Doe");
        apply_request_guards_into(&mut body, &guards, &mut alloc);
        let entities = vec![DetectedEntity {
            entity_type: "PERSON".to_string(),
            text: "Jane Doe".to_string(),
            group: None,
        }];
        assert!(mask_detected_entities(&mut body, &entities, MaskMode::Pseudonymize, false, &mut alloc));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("[EMAIL_NER_001]"));
        assert!(content.contains("[PERSON_NER_001]"));
        let map = alloc.rehydration_map();
        assert_eq!(
            map.get("[EMAIL_NER_001]")
                .map(String::as_str),
            Some("a@b.com")
        );
        assert_eq!(
            map.get("[PERSON_NER_001]")
                .map(String::as_str),
            Some("Jane Doe")
        );
    }

    #[test]
    fn mask_detected_entities_pseudonymizes_and_reuses_ids() {
        let mut alloc = PseudonymAllocator::default();
        let mut body = make_request("Contact Jane Doe; cc Jane Doe at Acme Corp.");
        let entities = vec![
            DetectedEntity {
                entity_type: "PERSON".to_string(),
                text: "Jane Doe".to_string(),
                group: None,
            },
            DetectedEntity {
                entity_type: "ORG".to_string(),
                text: "Acme Corp".to_string(),
                group: None,
            },
        ];
        assert!(mask_detected_entities(&mut body, &entities, MaskMode::Pseudonymize, false, &mut alloc));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            content
                .matches("[PERSON_NER_001]")
                .count(),
            2
        );
        assert!(content.contains("[ORG_NER_001]"));
        assert!(!content.contains("Jane Doe"));
    }

    #[test]
    fn coreference_group_collapses_aliases_to_one_id() {
        // With linking on, `Bob` and `Robert Smith` share the group's canonical
        // (longest) value and thus one NER ID; both restore to that value.
        let mut alloc = PseudonymAllocator::default();
        let mut body = make_request("Bob called. Robert Smith signed. Ask Bob again.");
        let entities = vec![
            DetectedEntity {
                entity_type: "PERSON".to_string(),
                text: "Bob".to_string(),
                group: Some("p1".to_string()),
            },
            DetectedEntity {
                entity_type: "PERSON".to_string(),
                text: "Robert Smith".to_string(),
                group: Some("p1".to_string()),
            },
        ];
        assert!(mask_detected_entities(&mut body, &entities, MaskMode::Pseudonymize, true, &mut alloc));
        let content = body["messages"][0]["content"]
            .as_str()
            .unwrap();
        assert_eq!(
            content
                .matches("[PERSON_NER_001]")
                .count(),
            3
        );
        assert!(!content.contains("[PERSON_NER_002]"));
        assert_eq!(
            alloc
                .rehydration_map()
                .get("[PERSON_NER_001]")
                .map(String::as_str),
            Some("Robert Smith")
        );
    }

    #[test]
    fn mask_detected_entities_masks_tool_call_arguments() {
        let mut alloc = PseudonymAllocator::default();
        let mut body = json!({
            "messages": [
                { "role": "assistant", "content": Value::Null, "tool_calls": [
                    { "type": "function", "function": { "name": "email", "arguments": "{\"to\":\"Jane Doe\"}" } }
                ] }
            ]
        });
        let entities = vec![DetectedEntity {
            entity_type: "PERSON".to_string(),
            text: "Jane Doe".to_string(),
            group: None,
        }];
        assert!(mask_detected_entities(&mut body, &entities, MaskMode::Pseudonymize, false, &mut alloc));
        let args = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(args.contains("[PERSON_NER_001]"));
        assert!(!args.contains("Jane Doe"));
    }

    #[test]
    fn masking_a_number_in_tool_call_arguments_keeps_them_valid_json() {
        init_test_definitions();
        for mask_mode in [MaskMode::Redact, MaskMode::Pseudonymize] {
            let mut guards = mask_guard(&["credit_card"]);
            guards[0].regex.mask_mode = mask_mode;
            let arguments =
                r#"{"order_id": 12345678901234567, "note": "card 4545 4545 4545 4545", "ids": [45454545454545454]}"#;
            let mut body = json!({
                "messages": [
                    { "role": "assistant", "content": Value::Null, "tool_calls": [
                        { "type": "function", "function": { "name": "lookup", "arguments": arguments } }
                    ] }
                ]
            });

            assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));

            let masked = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
                .as_str()
                .expect("arguments stay a string");
            let parsed: Value = serde_json::from_str(masked).unwrap_or_else(|e| panic!("{masked}: {e}"));
            for (field, value) in [("order_id", &parsed["order_id"]), ("ids", &parsed["ids"][0])] {
                let token = value
                    .as_str()
                    .unwrap_or_else(|| panic!("{field} is masked as a string: {masked}"));
                assert!(token.contains("CREDIT_CARD"), "{field}: {masked}");
            }
            let note = parsed["note"]
                .as_str()
                .expect("note stays a string");
            assert!(note.starts_with("card ") && note.contains("CREDIT_CARD"), "{masked}");
            assert!(!masked.contains("4545 4545"), "{masked}");
        }
    }

    #[test]
    fn masking_part_of_a_json_number_in_tool_call_arguments_replaces_the_whole_number() {
        init_test_definitions();
        let arguments = r#"{"a": -4545454545454545, "b": 4545454545454545.25, "c": 0.4545454545454545, "e": "x"}"#;
        let mut body = json!({
            "messages": [
                { "role": "assistant", "content": Value::Null, "tool_calls": [
                    { "type": "function", "function": { "name": "lookup", "arguments": arguments } }
                ] }
            ]
        });

        assert!(matches!(apply_request_guards(&mut body, &mask_guard(&["credit_card"])), GuardOutcome::Masked));

        let masked = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments stay a string");
        let parsed: Value = serde_json::from_str(masked).unwrap_or_else(|e| panic!("{masked}: {e}"));
        for field in ["a", "b", "c"] {
            assert_eq!(parsed[field], "<CREDIT_CARD>", "{field}: {masked}");
        }
        assert_eq!(parsed["e"], "x", "{masked}");
    }

    #[test]
    fn masking_tool_call_arguments_that_are_not_json_leaves_tokens_unquoted() {
        init_test_definitions();
        let mut body = json!({
            "messages": [
                { "role": "assistant", "content": Value::Null, "tool_calls": [
                    { "type": "function", "function": { "name": "lookup", "arguments": "card 4545454545454545" } }
                ] }
            ]
        });

        assert!(matches!(apply_request_guards(&mut body, &mask_guard(&["credit_card"])), GuardOutcome::Masked));

        assert_eq!(body["messages"][0]["tool_calls"][0]["function"]["arguments"], "card <CREDIT_CARD>");
    }

    #[test]
    fn rehydrate_response_restores_tool_call_arguments() {
        let mut map = RehydrationMap::new();
        map.insert("[PERSON_NER_001]".to_string(), "Jane Doe".to_string());
        let mut resp = json!({
            "choices": [
                { "message": { "content": Value::Null, "tool_calls": [
                    { "function": { "arguments": "{\"to\":\"[PERSON_NER_001]\"}" } }
                ] } }
            ]
        });
        assert!(rehydrate_response(&mut resp, &map));
        let args = resp["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(args.contains("Jane Doe"));
        assert!(!args.contains("PERSON_NEAR"));
    }

    #[test]
    fn rehydration_round_trips_pseudonymized_values() {
        init_test_definitions();
        let mut alloc = PseudonymAllocator::default();
        let guards = pseudonymize_guard(&["email"]);
        let mut req = make_request("email a@b.com");
        apply_request_guards_into(&mut req, &guards, &mut alloc);
        let map = alloc.rehydration_map();
        assert_eq!(
            map.get("[EMAIL_NER_001]")
                .map(String::as_str),
            Some("a@b.com")
        );

        // The provider echoes the NER ID; restoration puts the real value back.
        let mut resp = make_response("Sent to [EMAIL_NER_001] as requested");
        assert!(rehydrate_response(&mut resp, &map));
        let content = resp["choices"][0]["message"]["content"]
            .as_str()
            .unwrap();
        assert!(content.contains("a@b.com"));
        assert!(!content.contains("[EMAIL_NER_001]"));
    }

    #[test]
    fn pseudonymizing_numbers_in_tool_call_arguments_restores_each_whole_number() {
        init_test_definitions();
        let mut alloc = PseudonymAllocator::default();
        let guards = pseudonymize_guard(&["credit_card"]);
        let arguments = r#"{"a": -4545454545454545, "b": 4545454545454545.25, "c": -122.41941550000001, "d": 4545454545454545.12345678901234}"#;
        let mut body = json!({
            "messages": [
                { "role": "assistant", "content": Value::Null, "tool_calls": [
                    { "type": "function", "function": { "name": "lookup", "arguments": arguments } }
                ] }
            ]
        });

        apply_request_guards_into(&mut body, &guards, &mut alloc);

        let masked = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments stay a string");
        let parsed: Value = serde_json::from_str(masked).unwrap_or_else(|e| panic!("{masked}: {e}"));
        let map = alloc.rehydration_map();
        let restored = |field: &str| {
            let token = parsed[field]
                .as_str()
                .unwrap_or_else(|| panic!("{field} is a token: {masked}"));
            map.get(token)
                .cloned()
                .unwrap_or_else(|| panic!("{field} token {token} has a restore value"))
        };
        assert_ne!(parsed["a"], parsed["b"], "distinct numbers get distinct NER IDs: {masked}");
        assert_eq!(restored("a"), "-4545454545454545");
        assert_eq!(restored("b"), "4545454545454545.25");
        assert_eq!(restored("c"), "-122.41941550000001");
        assert_eq!(restored("d"), "4545454545454545.12345678901234");
        assert_eq!(map.len(), 4, "a number holding two matches gets one NER ID, with no orphan: {map:?}");
    }

    #[test]
    fn a_masked_token_is_json_escaped_in_tool_call_arguments() {
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![RegexRule::Pattern {
                    pattern: r"\d{17}".to_string(),
                    label: Some(r#"Acct "ID" \x"#.to_string()),
                }],
            },
            rejection: None,
        }];
        let arguments = r#"{"order": 12345678901234567, "note": "id 12345678901234567"}"#;
        let mut body = json!({
            "messages": [
                { "role": "assistant", "content": Value::Null, "tool_calls": [
                    { "type": "function", "function": { "name": "lookup", "arguments": arguments } }
                ] }
            ]
        });

        assert!(matches!(apply_request_guards(&mut body, &guards), GuardOutcome::Masked));

        let masked = body["messages"][0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .expect("arguments stay a string");
        let parsed: Value = serde_json::from_str(masked).unwrap_or_else(|e| panic!("{masked}: {e}"));
        assert_eq!(parsed["order"], r#"<ACCT "ID" \X>"#, "{masked}");
        assert_eq!(parsed["note"], r#"id <ACCT "ID" \X>"#, "{masked}");
    }

    #[test]
    fn rehydrate_response_with_empty_map_is_noop() {
        let mut resp = make_response("nothing to restore here");
        assert!(!rehydrate_response(&mut resp, &RehydrationMap::new()));
    }

    fn reject_guard(rule: RegexRule) -> Vec<RequestGuard> {
        vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![rule],
            },
            rejection: None,
        }]
    }

    #[tokio::test]
    async fn rejecting_a_builtin_pattern_logs_the_label_but_not_the_matched_value() {
        init_test_definitions();
        let guards = reject_guard(RegexRule::Builtin { builtin: "ssn".to_string() });
        let mut body = make_request("My SSN is 123-45-6789");

        let (logs, result) =
            crate::observability::log_capture::capture_logs(async { apply_request_guards(&mut body, &guards) }).await;

        assert!(matches!(result, GuardOutcome::Rejected(_)));
        assert!(logs.contains("US SSN detected"), "{logs}");
        assert!(!logs.contains("123-45-6789"), "a log holds the matched value: {logs}");
    }

    #[tokio::test]
    async fn rejecting_a_custom_pattern_logs_the_label_but_not_the_matched_value() {
        let guards = reject_guard(RegexRule::Pattern {
            pattern: r"password[=:]\s*\S+".to_string(),
            label: Some("credentials".to_string()),
        });
        let mut body = make_request("My password= hunter2");

        let (logs, result) =
            crate::observability::log_capture::capture_logs(async { apply_request_guards(&mut body, &guards) }).await;

        assert!(matches!(result, GuardOutcome::Rejected(_)));
        assert!(logs.contains("custom pattern 'credentials' matched"), "{logs}");
        assert!(!logs.contains("hunter2"), "a log holds the matched value: {logs}");
    }

    #[tokio::test]
    async fn rejecting_an_unlabelled_custom_pattern_names_it_by_position_not_by_its_regex() {
        let regex = r"secret-[0-9]{4}";
        let guards = vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Reject,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: vec![
                    RegexRule::Pattern {
                        pattern: "never-matches-here".to_string(),
                        label: None,
                    },
                    RegexRule::Pattern {
                        pattern: regex.to_string(),
                        label: None,
                    },
                ],
            },
            rejection: None,
        }];
        let mut body = make_request("Use secret-1234 now");

        let (logs, result) =
            crate::observability::log_capture::capture_logs(async { apply_request_guards(&mut body, &guards) }).await;

        match result {
            GuardOutcome::Rejected(r) => assert_eq!(r.reason.as_deref(), Some("Matched custom pattern #2")),
            other => panic!("expected a rejection, got {other:?}"),
        }
        assert!(logs.contains("custom pattern #2 matched"), "{logs}");
        assert!(!logs.contains(regex), "a log holds the regex: {logs}");
    }

    fn mask_guard(builtins: &[&str]) -> Vec<RequestGuard> {
        vec![RequestGuard {
            regex: RegexRules {
                action: GuardAction::Mask,
                mask_mode: MaskMode::Redact,
                restore_in_response: false,
                link_pronouns: false,
                rules: builtins
                    .iter()
                    .map(|b| RegexRule::Builtin { builtin: b.to_string() })
                    .collect(),
            },
            rejection: None,
        }]
    }

    #[test]
    fn a_mask_guard_masks_a_card_and_the_number_written_right_after_it_as_one_card() {
        init_test_definitions();
        for (other, text) in
            [("ssn", "4545 4545 4545 4545 123-45-6789"), ("phone_number", "4545 4545 4545 4545 212-555-1234")]
        {
            for rules in [["credit_card", other], [other, "credit_card"]] {
                let mut body = make_request(text);
                assert!(matches!(apply_request_guards(&mut body, &mask_guard(&rules)), GuardOutcome::Masked));
                assert_eq!(body["messages"][0]["content"], "<CREDIT_CARD>", "{text:?}, rules in order {rules:?}");
            }
        }
    }

    #[test]
    fn a_mask_guard_masks_an_international_phone_number_and_the_card_after_it_as_one_card() {
        init_test_definitions();
        for phone in ["+1 415 555 0100", "+65 6123 4567"] {
            for card in ["4545 4545 4545 4545", "4545454545454545"] {
                for rules in [["phone_number", "credit_card"], ["credit_card", "phone_number"]] {
                    let mut body = make_request(&format!("{phone} {card}"));
                    assert!(matches!(apply_request_guards(&mut body, &mask_guard(&rules)), GuardOutcome::Masked));
                    assert_eq!(
                        body["messages"][0]["content"], "+<CREDIT_CARD>",
                        "{phone} then card {card:?}, rules in order {rules:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn a_mask_guard_with_credit_card_still_masks_a_phone_number_and_ssn_on_their_own() {
        init_test_definitions();
        let mut body = make_request("Call +65 6123 4567, SSN 123-45-6789");
        let rules = mask_guard(&["phone_number", "ssn", "credit_card"]);
        assert!(matches!(apply_request_guards(&mut body, &rules), GuardOutcome::Masked));
        assert_eq!(body["messages"][0]["content"], "Call <PHONE_NUMBER>, SSN <SSN>");

        let mut long_number = make_request("Call +49 1512 3456 7890");
        assert!(matches!(apply_request_guards(&mut long_number, &rules), GuardOutcome::Masked));
        assert_eq!(long_number["messages"][0]["content"], "Call +<CREDIT_CARD>");
    }

    #[test]
    fn a_mask_guard_masks_a_whole_card_before_street_address_can_take_its_last_group() {
        init_test_definitions();
        for rules in [["credit_card", "street_address"], ["street_address", "credit_card"]] {
            for card in ["4545 4545 4545 4545", "4545454545454545"] {
                let mut body = make_request(&format!("{card} is my card"));
                assert!(matches!(apply_request_guards(&mut body, &mask_guard(&rules)), GuardOutcome::Masked));
                assert_eq!(
                    body["messages"][0]["content"], "<CREDIT_CARD> is my card",
                    "card {card:?}, rules in order {rules:?}"
                );
            }
        }
    }

    #[test]
    fn a_reject_guard_keeps_its_rule_order() {
        init_test_definitions();
        for (rules, expected) in
            [(["ssn", "credit_card"], "US SSN detected"), (["credit_card", "ssn"], "Credit Card detected")]
        {
            let guards = vec![RequestGuard {
                regex: RegexRules {
                    action: GuardAction::Reject,
                    mask_mode: MaskMode::Redact,
                    restore_in_response: false,
                    link_pronouns: false,
                    rules: rules
                        .iter()
                        .map(|b| RegexRule::Builtin { builtin: b.to_string() })
                        .collect(),
                },
                rejection: None,
            }];
            let mut body = make_request("4545 4545 4545 4545 and 123-45-6789");
            match apply_request_guards(&mut body, &guards) {
                GuardOutcome::Rejected(rejection) => {
                    assert_eq!(rejection.reason.as_deref(), Some(expected), "rules in order {rules:?}")
                }
                other => panic!("expected a rejection, got {other:?}"),
            }
        }
    }

    // === Unusable rules ===

    fn prompt_guard_with(
        enabled: bool,
        request_rule: Option<serde_json::Value>,
        response_rule: Option<serde_json::Value>,
    ) -> PromptGuardConfig {
        let guard = |rule: serde_json::Value| json!({ "regex": { "action": "reject", "rules": [rule] } });
        serde_json::from_value(json!({
            "enabled": enabled,
            "request": request_rule.map(guard).into_iter().collect::<Vec<_>>(),
            "response": response_rule.map(guard).into_iter().collect::<Vec<_>>(),
        }))
        .expect("prompt guard config parses")
    }

    fn assert_rule_unavailable(
        config: &PromptGuardConfig,
        expected_side: GuardSide,
        expected_issue: &str,
    ) {
        let (side, rejection) = unusable_rule_rejection(config).expect("an unusable rule refuses the request");
        assert_eq!(side, expected_side);
        assert_eq!(rejection.status_code, 502);
        let body: Value = serde_json::from_str(&rejection.body).expect("rejection body is JSON");
        assert_eq!(body["error"]["type"], "guardrail_unavailable");
        assert_eq!(body["error"]["code"], "prompt_guard_pattern_unavailable");
        assert_eq!(rejection.categories, vec![RULE_UNAVAILABLE_CATEGORY.to_string()]);
        assert_eq!(rejection.reason, Some(format!("prompt guard rule unavailable: {expected_issue}")));
    }

    #[test]
    fn a_rule_naming_a_builtin_that_did_not_compile_refuses_the_request_on_either_side() {
        init_test_definitions();
        let request = prompt_guard_with(true, Some(json!({ "builtin": "broken" })), None);
        assert_rule_unavailable(
            &request,
            GuardSide::Request,
            "built-in pattern 'broken' did not compile on the request side",
        );
        let response = prompt_guard_with(true, None, Some(json!({ "builtin": "broken" })));
        assert_rule_unavailable(
            &response,
            GuardSide::Response,
            "built-in pattern 'broken' did not compile on the response side",
        );
    }

    #[test]
    fn a_rule_naming_an_unknown_builtin_refuses_the_request_on_either_side() {
        init_test_definitions();
        let request = prompt_guard_with(true, Some(json!({ "builtin": "not_a_pattern" })), None);
        assert_rule_unavailable(
            &request,
            GuardSide::Request,
            "built-in pattern 'not_a_pattern' is not defined on the request side",
        );
        let response = prompt_guard_with(true, None, Some(json!({ "builtin": "not_a_pattern" })));
        assert_rule_unavailable(
            &response,
            GuardSide::Response,
            "built-in pattern 'not_a_pattern' is not defined on the response side",
        );
    }

    #[test]
    fn a_custom_pattern_that_does_not_compile_refuses_the_request_without_naming_its_regex() {
        init_test_definitions();
        let request = prompt_guard_with(true, Some(json!({ "pattern": "(?!x)y", "label": "lookahead" })), None);
        assert_rule_unavailable(
            &request,
            GuardSide::Request,
            "custom pattern 'lookahead' does not compile on the request side",
        );
        let response = prompt_guard_with(true, None, Some(json!({ "pattern": "(?!secret)y" })));
        assert_rule_unavailable(
            &response,
            GuardSide::Response,
            "custom pattern #1 does not compile on the response side",
        );
    }

    #[test]
    fn usable_rules_and_a_disabled_prompt_guard_refuse_nothing() {
        init_test_definitions();
        let usable = prompt_guard_with(true, Some(json!({ "builtin": "ssn" })), Some(json!({ "pattern": r"\d+" })));
        assert!(unusable_rule_rejection(&usable).is_none());
        assert_eq!(validate_regex_rules(&usable), Ok(()));
        let disabled = prompt_guard_with(false, Some(json!({ "builtin": "broken" })), None);
        assert!(unusable_rule_rejection(&disabled).is_none());
        assert_eq!(validate_regex_rules(&disabled), Ok(()));
    }

    #[test]
    fn saving_unusable_rules_is_refused_naming_the_rule() {
        init_test_definitions();
        for (config, expected) in [
            (
                prompt_guard_with(true, Some(json!({ "builtin": "not_a_pattern" })), None),
                "Prompt Guard built-in pattern 'not_a_pattern' is not defined on the request side",
            ),
            (
                prompt_guard_with(true, None, Some(json!({ "builtin": "broken" }))),
                "Prompt Guard built-in pattern 'broken' did not compile on the response side",
            ),
            (
                prompt_guard_with(true, Some(json!({ "pattern": "(?!x)y", "label": "lookahead" })), None),
                "Prompt Guard custom pattern 'lookahead' does not compile on the request side",
            ),
        ] {
            assert_eq!(validate_regex_rules(&config), Err(expected.to_string()));
        }
    }

    #[test]
    fn a_refused_save_does_not_cache_its_custom_pattern() {
        let pattern = "(?!refused-save-only)y";
        let config = prompt_guard_with(true, Some(json!({ "pattern": pattern })), None);
        assert!(validate_regex_rules(&config).is_err());
        let cached = COMPILED_REGEX_CACHE
            .lock()
            .expect("cache lock")
            .contains_key(pattern);
        assert!(!cached, "a refused save left its pattern in the regex cache");
    }

    #[test]
    fn applying_a_rule_that_cannot_be_evaluated_refuses_with_the_unavailable_rejection() {
        init_test_definitions();
        for (rule, issue) in [
            (RegexRule::Builtin { builtin: "broken".to_string() }, "built-in pattern 'broken' did not compile"),
            (
                RegexRule::Builtin {
                    builtin: "not_a_pattern".to_string(),
                },
                "built-in pattern 'not_a_pattern' is not defined",
            ),
            (
                RegexRule::Pattern {
                    pattern: "(?!x)y".to_string(),
                    label: None,
                },
                "custom pattern #1 does not compile",
            ),
        ] {
            let mut body = make_request("Summarize the release notes");
            match apply_request_guards(&mut body, &reject_guard(rule)) {
                GuardOutcome::Rejected(rejection) => {
                    assert_eq!(rejection.status_code, 502);
                    assert_eq!(rejection.categories, vec![RULE_UNAVAILABLE_CATEGORY.to_string()]);
                    assert_eq!(rejection.reason, Some(format!("prompt guard rule unavailable: {issue}")));
                }
                other => panic!("expected the unusable rule to be refused, got {other:?}"),
            }
        }
    }
}
