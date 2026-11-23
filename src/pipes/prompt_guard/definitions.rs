//! Prompt guard definitions — loaded once from prompt-guard.json
//!
//! Provides the single source of truth for built-in pattern definitions.
//! Both the backend filter and the frontend (via API) use these definitions.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::OnceLock;
use tracing::{error, info};

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

    // Pre-compile all regex patterns at startup. A pattern that does not compile
    // is left out and reported by `report_definition_problems` once logging is up.
    let (compiled, problems) = compile_patterns(&defs);

    info!("Loaded {} prompt guard pattern definitions ({} valid regexes)", defs.defined_patterns.len(), compiled.len());

    // Store compiled regexes in a separate OnceLock
    COMPILED_REGEXES
        .set(compiled)
        .map_err(|_| "Prompt guard compiled regexes already initialized".to_string())?;
    COMPILE_PROBLEMS
        .set(problems)
        .map_err(|_| "Prompt guard compile problems already initialized".to_string())?;

    DEFINITIONS
        .set(defs)
        .map_err(|_| "Prompt guard definitions already initialized".to_string())?;

    Ok(())
}

/// Pre-compiled regexes for built-in patterns, keyed by pattern key.
static COMPILED_REGEXES: OnceLock<HashMap<String, Regex>> = OnceLock::new();

/// The built-in patterns that did not compile at load, with their errors.
static COMPILE_PROBLEMS: OnceLock<Vec<DefinitionProblem>> = OnceLock::new();

/// Compile every defined pattern: the regexes that compile, keyed by pattern key,
/// and a problem for each one that does not.
fn compile_patterns(defs: &PromptGuardDefinitions) -> (HashMap<String, Regex>, Vec<DefinitionProblem>) {
    let mut compiled = HashMap::new();
    let mut problems = Vec::new();
    for pattern in &defs.defined_patterns {
        match Regex::new(&pattern.regex) {
            Ok(re) => {
                compiled.insert(pattern.key.clone(), re);
            }
            Err(e) => problems.push(DefinitionProblem {
                pattern: pattern.key.clone(),
                issue: PatternIssue::CompileFailed,
                detail: e.to_string(),
            }),
        }
    }
    (compiled, problems)
}

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

/// Why a built-in pattern named by a Prompt Guard rule cannot be evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatternIssue {
    /// `prompt-guard.json` was not loaded, so no built-in pattern is available.
    DefinitionsMissing,
    /// The pattern is defined, but its regex did not compile.
    CompileFailed,
    /// No pattern with this key is defined.
    Unknown,
}

impl PatternIssue {
    /// Stable label used in logs, errors and the `reason` metric label.
    pub fn reason(self) -> &'static str {
        match self {
            Self::DefinitionsMissing => "definitions_missing",
            Self::CompileFailed => "compile_failed",
            Self::Unknown => "unknown",
        }
    }

    /// Plain description used in log lines, rejection reasons and save errors.
    pub fn description(self) -> &'static str {
        match self {
            Self::DefinitionsMissing => "is unavailable because prompt-guard.json did not load",
            Self::CompileFailed => "did not compile",
            Self::Unknown => "is not defined",
        }
    }
}

/// Why the built-in pattern `key` cannot be evaluated, or `None` when it can.
pub fn builtin_issue(key: &str) -> Option<PatternIssue> {
    builtin_issue_in(DEFINITIONS.get(), COMPILED_REGEXES.get(), key)
}

fn builtin_issue_in(
    defs: Option<&PromptGuardDefinitions>,
    compiled: Option<&HashMap<String, Regex>>,
    key: &str,
) -> Option<PatternIssue> {
    let (Some(defs), Some(compiled)) = (defs, compiled) else {
        return Some(PatternIssue::DefinitionsMissing);
    };
    if compiled.contains_key(key) {
        None
    } else if defs
        .defined_patterns
        .iter()
        .any(|p| p.key == key)
    {
        Some(PatternIssue::CompileFailed)
    } else {
        Some(PatternIssue::Unknown)
    }
}

/// A built-in pattern problem found at load.
#[derive(Debug, Clone, PartialEq, Eq)]
struct DefinitionProblem {
    /// The pattern key, empty when the whole file did not load.
    pattern: String,
    issue: PatternIssue,
    detail: String,
}

/// The problems to report: the compile problems kept at load, or one
/// `DefinitionsMissing` problem when `prompt-guard.json` did not load.
fn definition_problems_in(
    compile_problems: Option<&[DefinitionProblem]>,
    load_error: Option<&str>,
) -> Vec<DefinitionProblem> {
    match compile_problems {
        Some(problems) => problems.to_vec(),
        None => vec![DefinitionProblem {
            pattern: String::new(),
            issue: PatternIssue::DefinitionsMissing,
            detail: load_error
                .unwrap_or("not loaded")
                .to_string(),
        }],
    }
}

/// Log each built-in pattern problem found at load at `ERROR` and count it in
/// `agent_stream_prompt_guard_pattern_errors_total`. The definitions load before
/// logging starts, so this runs once logging is up. `load_error` is why
/// `prompt-guard.json` did not load, when it did not.
pub fn report_definition_problems(load_error: Option<&str>) {
    for problem in definition_problems_in(
        COMPILE_PROBLEMS
            .get()
            .map(Vec::as_slice),
        load_error,
    ) {
        if problem.issue == PatternIssue::DefinitionsMissing {
            error!(
                "Prompt guard definitions not loaded: {} — requests to Surfaces whose rules name a built-in pattern are refused",
                problem.detail
            );
        } else {
            error!(
                "Prompt guard built-in pattern '{}' did not compile: {} — requests to Surfaces whose rules name it are refused",
                problem.pattern, problem.detail
            );
        }
        crate::metrics::backends::prometheus::track_prompt_guard_pattern_error(
            &problem.pattern,
            problem.issue.reason(),
        );
    }
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

    fn shipped_definitions() -> PromptGuardDefinitions {
        serde_json::from_str(include_str!("../../../config/examples/prompt-guard.example.json"))
            .expect("example prompt-guard JSON parses")
    }

    fn shipped_regex(key: &str) -> Regex {
        let defs = shipped_definitions();
        let pattern = defs
            .defined_patterns
            .iter()
            .find(|p| p.key == key)
            .unwrap_or_else(|| panic!("{key} pattern present"));
        Regex::new(&pattern.regex).unwrap_or_else(|e| panic!("{key} regex compiles: {e}"))
    }

    #[test]
    fn every_shipped_pattern_compiles() {
        assert_eq!(compile_patterns(&shipped_definitions()).1, Vec::new());
    }

    #[test]
    fn shipped_credit_card_pattern_matches_cards_in_any_grouping() {
        let re = shipped_regex("credit_card");
        for good in [
            "4545 4545 4545 4545",
            "4545-4545-4545-4545",
            "4111 1111 11111111",
            "4545454545454545",
            "My credit card number is 4545 4545 4545 4545",
            "20261123120000",
        ] {
            assert!(re.is_match(good), "expected card match: {good}");
        }
        for bad in ["+55 11 91234 5678", "212-555-1234", "123-45-6789", "123456789"] {
            assert!(!re.is_match(bad), "unexpected card match: {bad}");
        }
    }

    #[test]
    fn shipped_ssn_pattern_matches_valid_ssns_with_a_dash_or_space() {
        let re = shipped_regex("ssn");
        for good in ["123-45-6789", "123 45 6789", "899-99-9999", "001-01-0001", "My SSN is 123 45 6789"] {
            assert!(re.is_match(good), "expected SSN match: {good}");
        }
        for bad in [
            "666-12-3456",
            "000-12-3456",
            "912-34-5678",
            "123-00-4567",
            "123-45-0000",
            "123456789",
            "212-555-1234",
            "+55 11 91234 5678",
        ] {
            assert!(!re.is_match(bad), "unexpected SSN match: {bad}");
        }
    }

    #[test]
    fn shipped_ssn_simple_pattern_matches_a_dash_or_space() {
        let re = shipped_regex("ssn_simple");
        for good in ["123-45-6789", "123 45 6789", "666-00-0000"] {
            assert!(re.is_match(good), "expected simple SSN match: {good}");
        }
        for bad in ["123456789", "212-555-1234", "+55 11 91234 5678"] {
            assert!(!re.is_match(bad), "unexpected simple SSN match: {bad}");
        }
    }

    fn definitions_with(patterns: &[(&str, &str)]) -> PromptGuardDefinitions {
        PromptGuardDefinitions {
            defined_patterns: patterns
                .iter()
                .map(|(key, regex)| PatternDefinition {
                    key: key.to_string(),
                    label: key.to_string(),
                    icon: String::new(),
                    description: String::new(),
                    regex: regex.to_string(),
                })
                .collect(),
            pii_detection_prompt: default_pii_detection_prompt(),
        }
    }

    #[test]
    fn builtin_issue_names_why_a_pattern_cannot_be_used() {
        let defs = definitions_with(&[("good", r"\d+"), ("broken", r"(?!x)y")]);
        let (map, _) = compile_patterns(&defs);
        assert_eq!(builtin_issue_in(Some(&defs), Some(&map), "good"), None);
        assert_eq!(builtin_issue_in(Some(&defs), Some(&map), "broken"), Some(PatternIssue::CompileFailed));
        assert_eq!(builtin_issue_in(Some(&defs), Some(&map), "absent"), Some(PatternIssue::Unknown));
        assert_eq!(builtin_issue_in(None, None, "good"), Some(PatternIssue::DefinitionsMissing));
    }

    #[test]
    fn definition_problems_report_each_pattern_that_does_not_compile() {
        let defs = definitions_with(&[("good", r"\d+"), ("broken", r"(?!x)y")]);
        let (compiled, kept) = compile_patterns(&defs);
        assert_eq!(compiled.len(), 1);
        let problems = definition_problems_in(Some(&kept), None);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].pattern, "broken");
        assert_eq!(problems[0].issue, PatternIssue::CompileFailed);
        assert_eq!(problems[0].issue.reason(), "compile_failed");
        assert!(
            problems[0]
                .detail
                .contains("look-around"),
            "unexpected detail: {}",
            problems[0].detail
        );
    }

    #[test]
    fn definition_problems_report_a_file_that_did_not_load_with_an_empty_pattern() {
        let problems = definition_problems_in(None, Some("Failed to read prompt-guard.json"));
        assert_eq!(
            problems,
            vec![DefinitionProblem {
                pattern: String::new(),
                issue: PatternIssue::DefinitionsMissing,
                detail: "Failed to read prompt-guard.json".to_string(),
            }]
        );
        assert_eq!(problems[0].issue.reason(), "definitions_missing");
    }

    #[test]
    fn tracking_a_pattern_error_increments_the_counter_for_its_labels() {
        let counter = crate::metrics::backends::prometheus::PROMPT_GUARD_PATTERN_ERRORS
            .with_label_values(&["test-pattern", "compile_failed"]);
        let before = counter.get();
        crate::metrics::backends::prometheus::track_prompt_guard_pattern_error("test-pattern", "compile_failed");
        assert_eq!(counter.get(), before + 1);
    }
}
