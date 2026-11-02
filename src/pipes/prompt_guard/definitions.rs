//! Prompt guard definitions — loaded once from prompt-guard.json
//!
//! Provides the single source of truth for built-in pattern definitions.
//! Both the backend filter and the frontend (via API) use these definitions.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{info, warn};

/// Global singleton holding the loaded prompt guard definitions.
/// Initialized once at startup via `init_definitions()`.
static DEFINITIONS: OnceLock<PromptGuardDefinitions> = OnceLock::new();

/// Top-level structure of prompt-guard.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PromptGuardDefinitions {
    /// The list of defined built-in patterns
    pub defined_patterns: Vec<PatternDefinition>,
    /// System prompt for the model-backed PII detector (`llm_pii`). Admin-editable
    /// in prompt-guard.json; the built-in default is used when absent. Not served
    /// to the UI (the definitions endpoint only needs the pattern list).
    #[serde(default = "default_pii_detection_prompt", skip_serializing)]
    pub pii_detection_prompt: String,
}

/// Built-in fallback for [`PromptGuardDefinitions::pii_detection_prompt`]. The
/// authoritative, admin-editable copy lives in prompt-guard.json; this is used
/// only when that file omits the field or fails to load.
const DEFAULT_PII_DETECTION_PROMPT: &str = "You are a strict PII detection engine. Read the user's message and \
identify every span of personally identifiable information. Respond with ONLY a JSON object of the \
form {\"entities\":[{\"type\":\"<TYPE>\",\"text\":\"<exact substring>\",\"group\":\"<id>\"}]}. Copy \
each PII value exactly as it appears in the text (same casing and spacing). Set \"group\" to a \
short stable id that is the SAME for every mention referring to the same real-world entity \
(aliases, nicknames and repeated names, e.g. \"Bob\" and \"Robert Smith\"), and DIFFERENT for \
distinct entities; omit it if unsure. Do not translate, summarise, or explain. If there is no PII, \
respond with {\"entities\":[]}.";

fn default_pii_detection_prompt() -> String {
    DEFAULT_PII_DETECTION_PROMPT.to_string()
}

/// A single pattern definition from prompt-guard.json
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternDefinition {
    /// Unique key used in pipe configs (e.g. "ssn", "email")
    pub key: String,
    /// Human-readable label (e.g. "US Social Security Numbers")
    pub label: String,
    /// FontAwesome icon class (e.g. "fa-id-card")
    pub icon: String,
    /// Description of what the pattern matches
    pub description: String,
    /// The regex pattern string.
    #[serde(default)]
    pub regex: String,
}

/// Initialize the prompt guard definitions from a JSON file.
/// Must be called once at startup. Returns an error if the file can't be read or parsed.
pub fn init_definitions(path: &str) -> Result<(), String> {
    let content =
        std::fs::read_to_string(path).map_err(|e| format!("Failed to read prompt-guard.json from {}: {}", path, e))?;

    let defs: PromptGuardDefinitions =
        serde_json::from_str(&content).map_err(|e| format!("Failed to parse prompt-guard.json: {}", e))?;

    // Pre-validate all regex patterns at startup.
    let mut compiled: HashMap<String, Regex> = HashMap::new();
    for pattern in &defs.defined_patterns {
        match Regex::new(&pattern.regex) {
            Ok(re) => {
                compiled.insert(pattern.key.clone(), re);
            }
            Err(e) => {
                warn!(
                    "Invalid regex for prompt guard pattern '{}': {} — pattern will be skipped at runtime",
                    pattern.key, e
                );
            }
        }
    }

    info!("Loaded {} prompt guard pattern definitions ({} valid regexes)", defs.defined_patterns.len(), compiled.len());

    // Store compiled regexes in a separate OnceLock
    COMPILED_REGEXES
        .set(compiled)
        .map_err(|_| "Prompt guard compiled regexes already initialized".to_string())?;

    DEFINITIONS
        .set(defs)
        .map_err(|_| "Prompt guard definitions already initialized".to_string())?;

    Ok(())
}

/// Pre-compiled regexes for built-in patterns, keyed by pattern key.
static COMPILED_REGEXES: OnceLock<HashMap<String, Regex>> = OnceLock::new();

/// Get the loaded definitions. Returns None if not yet initialized.
pub fn get_definitions() -> Option<&'static PromptGuardDefinitions> {
    DEFINITIONS.get()
}

/// The model-backed PII detector's system prompt: the value loaded from
/// prompt-guard.json, or the built-in default when definitions are absent.
pub fn get_pii_detection_prompt() -> String {
    DEFINITIONS
        .get()
        .map(|d| d.pii_detection_prompt.clone())
        .unwrap_or_else(default_pii_detection_prompt)
}

/// Look up a compiled regex by pattern key. Returns None if the key doesn't exist
/// or the regex was invalid at load time.
pub fn get_compiled_regex(key: &str) -> Option<&'static Regex> {
    COMPILED_REGEXES
        .get()
        .and_then(|map| map.get(key))
}

/// Get the pattern definition by key.
pub fn get_pattern_definition(key: &str) -> Option<&'static PatternDefinition> {
    DEFINITIONS
        .get()
        .and_then(|defs| {
            defs.defined_patterns
                .iter()
                .find(|p| p.key == key)
        })
}

/// Initialize definitions from a JSON string (for testing).
/// Silently succeeds if already initialized.
#[allow(dead_code)]
pub fn init_definitions_from_str(json: &str) -> Result<(), String> {
    // If already initialized, skip
    if DEFINITIONS.get().is_some() {
        return Ok(());
    }

    let defs: PromptGuardDefinitions =
        serde_json::from_str(json).map_err(|e| format!("Failed to parse prompt guard JSON: {}", e))?;

    let mut compiled: HashMap<String, Regex> = HashMap::new();
    for pattern in &defs.defined_patterns {
        if let Ok(re) = Regex::new(&pattern.regex) {
            compiled.insert(pattern.key.clone(), re);
        }
    }

    let _ = COMPILED_REGEXES.set(compiled);
    let _ = DEFINITIONS.set(defs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deserialize_definitions() {
        let json = r#"{
            "defined_patterns": [
                {
                    "key": "email",
                    "label": "Email Addresses",
                    "icon": "fa-envelope",
                    "description": "Matches email addresses",
                    "regex": "\\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}\\b"
                },
                {
                    "key": "ssn",
                    "label": "US Social Security Numbers",
                    "icon": "fa-id-card",
                    "description": "Matches US SSNs",
                    "regex": "\\b\\d{3}-\\d{2}-\\d{4}\\b"
                }
            ]
        }"#;

        let defs: PromptGuardDefinitions = serde_json::from_str(json).unwrap();
        assert_eq!(defs.defined_patterns.len(), 2);
        assert_eq!(defs.defined_patterns[0].key, "email");
        assert_eq!(defs.defined_patterns[1].key, "ssn");
    }

    #[test]
    fn pii_detection_prompt_defaults_when_absent() {
        let defs: PromptGuardDefinitions = serde_json::from_str(r#"{ "defined_patterns": [] }"#).unwrap();
        assert!(
            defs.pii_detection_prompt
                .contains("PII detection engine")
        );
    }

    #[test]
    fn pii_detection_prompt_is_read_from_config() {
        let defs: PromptGuardDefinitions =
            serde_json::from_str(r#"{ "defined_patterns": [], "pii_detection_prompt": "custom prompt" }"#).unwrap();
        assert_eq!(defs.pii_detection_prompt, "custom prompt");
    }

    #[test]
    fn test_pattern_definition_fields() {
        let json = r#"{
            "key": "credit_card",
            "label": "Credit Card Numbers",
            "icon": "fa-credit-card",
            "description": "Matches credit card numbers",
            "regex": "\\b4[0-9]{12}(?:[0-9]{3})?\\b"
        }"#;

        let def: PatternDefinition = serde_json::from_str(json).unwrap();
        assert_eq!(def.key, "credit_card");
        assert_eq!(def.icon, "fa-credit-card");
        // Verify the regex compiles
        assert!(Regex::new(&def.regex).is_ok());
    }

    #[test]
    fn shipped_phone_pattern_matches_us_intl_and_au_formats() {
        // Validate the actual shipped built-in phone pattern: it must compile (an
        // invalid regex is silently skipped at load) and cover US, international
        // (+country code) and Australian mobile formats.
        let defs: PromptGuardDefinitions =
            serde_json::from_str(include_str!("../../../config/examples/prompt-guard.example.json"))
                .expect("example prompt-guard JSON parses");
        let phone = defs
            .defined_patterns
            .iter()
            .find(|p| p.key == "phone_number")
            .expect("phone_number pattern present");
        let re = Regex::new(&phone.regex).expect("phone_number regex compiles");

        for good in [
            "0412400962",
            "0412 400 962",
            "+61412400962",
            "+61 412 400 962",
            "(212) 555-1234",
            "212-555-1234",
            "+1 212 555 1234",
        ] {
            assert!(re.is_match(good), "expected phone match: {good}");
        }
        for bad in ["0123456789", "not a phone", "42"] {
            assert!(!re.is_match(bad), "unexpected phone match: {bad}");
        }
    }
}
