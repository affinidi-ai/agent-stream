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

/// Cached compiled regex patterns, keyed by pattern string
static COMPILED_REGEX_CACHE: LazyLock<std::sync::Mutex<HashMap<String, Regex>>> =
    LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

fn get_or_compile_regex(pattern: &str) -> Option<Regex> {
    let mut cache = COMPILED_REGEX_CACHE
        .lock()
        .ok()?;
    if let Some(regex) = cache.get(pattern) {
        return Some(regex.clone());
    }
    match Regex::new(pattern) {
        Ok(regex) => {
            cache.insert(pattern.to_string(), regex.clone());
            Some(regex)
        }
        Err(e) => {
            warn!("Invalid prompt guard regex pattern '{}': {}", pattern, e);
            None
        }
    }
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
                    match apply_regex_rules_to_text(args, rules, allocator) {
                        RegexResult::Reject(reason) => {
                            let mut r = rejection.clone();
                            r.reason = Some(reason);
                            return GuardOutcome::Rejected(r);
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
}

/// Apply all regex rules to a text string.
///
/// Rules are processed sequentially — each rule operates on the output of the previous one
/// (for mask action). For reject action, processing stops at the first match.
fn apply_regex_rules_to_text(
    text: &str,
    rules: &RegexRules,
    allocator: &mut PseudonymAllocator,
) -> RegexResult {
    let mut current = text.to_string();
    let mut any_modified = false;

    for rule in &rules.rules {
        match rule {
            RegexRule::Builtin { builtin } => {
                let ranges: Vec<(std::ops::Range<usize>, String)> =
                    if let Some(regex) = super::definitions::get_compiled_regex(builtin) {
                        regex
                            .find_iter(&current)
                            .map(|m| (m.range(), m.as_str().to_string()))
                            .collect()
                    } else {
                        warn!("Prompt guard: built-in pattern '{}' not found in definitions — skipping", builtin);
                        continue;
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
                            // Allocate in reading order, then splice in reverse
                            // so earlier byte offsets stay valid.
                            let replacements: Vec<(std::ops::Range<usize>, String)> = ranges
                                .into_iter()
                                .map(|(range, value)| {
                                    let token = match rules.mask_mode {
                                        MaskMode::Redact => format!("<{entity}>"),
                                        MaskMode::Pseudonymize => allocator.token_for(&entity, &value),
                                    };
                                    (range, token)
                                })
                                .collect();
                            for (range, token) in replacements.into_iter().rev() {
                                current.replace_range(range, &token);
                            }
                            any_modified = true;
                        }
                    }
                }
            }
            RegexRule::Pattern { pattern, label } => {
                if let Some(regex) = get_or_compile_regex(pattern) {
                    let ranges: Vec<(std::ops::Range<usize>, String)> = regex
                        .find_iter(&current)
                        .map(|m| (m.range(), m.as_str().to_string()))
                        .collect();

                    if !ranges.is_empty() {
                        match rules.action {
                            GuardAction::Reject => {
                                let rule_name = label
                                    .as_deref()
                                    .unwrap_or(pattern);
                                info!("Prompt guard: custom pattern '{}' matched — rejecting", rule_name);
                                return RegexResult::Reject(format!("Matched pattern '{rule_name}'"));
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
                                let replacements: Vec<(std::ops::Range<usize>, String)> = ranges
                                    .into_iter()
                                    .map(|(range, value)| {
                                        let token = match rules.mask_mode {
                                            MaskMode::Redact => redact_token.clone(),
                                            MaskMode::Pseudonymize => allocator.token_for(&entity, &value),
                                        };
                                        (range, token)
                                    })
                                    .collect();
                                for (range, token) in replacements.into_iter().rev() {
                                    current.replace_range(range, &token);
                                }
                                any_modified = true;
                            }
                        }
                    }
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
            {"key": "credit_card", "label": "Credit Card", "icon": "fa-credit-card", "description": "CC", "regex": "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b"},
            {"key": "email", "label": "Email", "icon": "fa-envelope", "description": "Email", "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"},
            {"key": "phone_number", "label": "Phone", "icon": "fa-phone", "description": "Phone", "regex": "\\b(?:(?:\\+1|1)[-. ]?)?(?:\\([2-9]\\d{2}\\)|[2-9]\\d{2})[-. ]?\\d{3}[-. ]?\\d{4}\\b"},
            {"key": "ip_address", "label": "IP Address", "icon": "fa-network-wired", "description": "IP", "regex": "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b"}
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
                assert_eq!(r.reason.as_deref(), Some("Matched pattern 'credentials'"));
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
}
