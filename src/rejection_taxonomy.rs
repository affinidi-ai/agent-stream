//! Canonical rejection-reason taxonomy + classifier.
//!
//! Judge, jury, and expert-witness blocks each emit provider-specific reason
//! tokens — EnkryptAI detector names, Azure harm categories, OpenAI-moderation
//! categories, user-defined judge rule names, and free-text jury reasons. This
//! module maps those heterogeneous tokens onto a small, stable set of canonical
//! categories (hate, toxicity, prompt_injection, …) so rejection counts can be
//! aggregated per surface / team / member / stage and charted on the dashboard.
//!
//! The mapping lives in a separate JSON config file (`rejection_categories.json`)
//! resolved relative to the config dir and read through an mtime-gated cache, so
//! edits hot-reload without a restart (mirroring the LLM catalog). The same file
//! is embedded at compile time and used as the built-in fallback when the runtime
//! file is absent or invalid, so classification always works.

use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, OnceLock, RwLock};
use std::time::SystemTime;
use tracing::warn;

/// Canonical category id used when no mapping rule matches a reason token.
pub const DEFAULT_CATEGORY: &str = "uncategorized";

/// The shipped taxonomy, embedded at compile time so the built-in fallback is
/// always the exact same content as the editable config file (single source of
/// truth, no drift).
const BUILTIN_TAXONOMY_JSON: &str = include_str!("../config/examples/rejection_categories.example.json");

/// A canonical category: a stable id plus a human-readable label for the UI.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryDef {
    pub id: String,
    #[serde(default)]
    pub label: String,
}

/// One mapping rule: provider/judge/jury reason tokens that resolve to a single
/// canonical `category`. A token matches when the rule's `sources` allow it
/// (empty = any source) **and** the token equals one of `exact` (case-insensitive)
/// or matches one of `patterns` (regex). A rule with `sources` but no `exact`
/// or `patterns` is a *source-only* rule: any block from those sources maps to
/// the category (for providers that flag without naming a category, e.g. Azure
/// Prompt Shields).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MappingRule {
    pub category: String,
    #[serde(default)]
    pub exact: Vec<String>,
    #[serde(default)]
    pub patterns: Vec<String>,
    #[serde(default)]
    pub sources: Vec<String>,
}

/// On-disk shape of the taxonomy config file.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RejectionTaxonomy {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default = "default_default_category")]
    pub default_category: String,
    #[serde(default)]
    pub categories: Vec<CategoryDef>,
    #[serde(default)]
    pub mappings: Vec<MappingRule>,
}

fn default_version() -> u32 {
    1
}

fn default_default_category() -> String {
    DEFAULT_CATEGORY.to_string()
}

impl RejectionTaxonomy {
    /// Check referential integrity: the default category and every mapping
    /// category must be a declared category id. Returns the comma-separated
    /// undeclared ids on failure, so a typo'd category can't record counts that
    /// the read endpoint (which enumerates declared categories) never reports —
    /// which would otherwise make `_total` silently exceed the per-category sum.
    fn validate(&self) -> Result<(), String> {
        let declared: std::collections::HashSet<&str> = self
            .categories
            .iter()
            .map(|c| c.id.as_str())
            .collect();
        let mut missing: Vec<String> = Vec::new();
        for id in std::iter::once(self.default_category.as_str()).chain(
            self.mappings
                .iter()
                .map(|m| m.category.as_str()),
        ) {
            if !declared.contains(id)
                && !missing
                    .iter()
                    .any(|m| m == id)
            {
                missing.push(id.to_string());
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            Err(missing.join(", "))
        }
    }
}

/// Strictly parse the embedded built-in taxonomy, surfacing any parse error.
/// Used by the test that guards the checked-in config file.
fn parse_builtin_taxonomy() -> Result<RejectionTaxonomy, serde_json::Error> {
    serde_json::from_str(BUILTIN_TAXONOMY_JSON)
}

/// The built-in taxonomy used as the runtime fallback. Panic-free: if the
/// embedded JSON somehow fails to parse (guarded against by a test), it degrades
/// to a minimal taxonomy so classification keeps working and the process never
/// crashes.
fn builtin_taxonomy() -> RejectionTaxonomy {
    match parse_builtin_taxonomy() {
        Ok(tax) => tax,
        Err(e) => {
            warn!(error = %e, "embedded built-in rejection taxonomy failed to parse — using minimal fallback");
            minimal_fallback_taxonomy()
        }
    }
}

/// Minimal hardcoded taxonomy used only if the embedded built-in fails to parse.
/// Everything classifies to [`DEFAULT_CATEGORY`], so the feature degrades rather
/// than panicking. Intentionally tiny to avoid duplicating the category list.
fn minimal_fallback_taxonomy() -> RejectionTaxonomy {
    RejectionTaxonomy {
        version: default_version(),
        default_category: DEFAULT_CATEGORY.to_string(),
        categories: vec![CategoryDef {
            id: DEFAULT_CATEGORY.to_string(),
            label: "Uncategorized".to_string(),
        }],
        mappings: Vec::new(),
    }
}

/// The process-wide compiled built-in taxonomy, parsed and compiled once. Shared
/// by [`RejectionClassifier`] and the [`classify_global`] / [`global_categories`]
/// fallbacks so the embedded taxonomy is never re-parsed or re-compiled per call.
fn builtin_compiled() -> Arc<CompiledTaxonomy> {
    static BUILTIN: OnceLock<Arc<CompiledTaxonomy>> = OnceLock::new();
    BUILTIN
        .get_or_init(|| Arc::new(CompiledTaxonomy::compile(&builtin_taxonomy())))
        .clone()
}

/// A compiled mapping rule with lowercased tokens and pre-compiled regexes.
struct CompiledRule {
    category: String,
    exact: Vec<String>,
    patterns: Vec<Regex>,
    sources: Vec<String>,
    source_only: bool,
}

/// The taxonomy in its ready-to-classify form: category metadata for the UI plus
/// compiled rules. Cheap to share via `Arc`.
pub struct CompiledTaxonomy {
    default_category: String,
    categories: Vec<CategoryDef>,
    rules: Vec<CompiledRule>,
}

impl CompiledTaxonomy {
    /// Compile a parsed taxonomy: lowercase tokens/sources and compile regexes.
    /// Invalid regexes are dropped with a warning rather than failing the whole
    /// taxonomy, so one bad pattern can't disable classification.
    fn compile(tax: &RejectionTaxonomy) -> Self {
        let mut rules = Vec::with_capacity(tax.mappings.len());
        for m in &tax.mappings {
            let exact: Vec<String> = m
                .exact
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            let sources: Vec<String> = m
                .sources
                .iter()
                .map(|s| s.trim().to_lowercase())
                .filter(|s| !s.is_empty())
                .collect();
            let mut patterns = Vec::with_capacity(m.patterns.len());
            for p in &m.patterns {
                match Regex::new(p) {
                    Ok(re) => patterns.push(re),
                    Err(e) => {
                        warn!(pattern = %p, error = %e, "rejection taxonomy: invalid regex pattern, skipping")
                    }
                }
            }
            let source_only = exact.is_empty() && patterns.is_empty() && !sources.is_empty();
            rules.push(CompiledRule {
                category: m.category.clone(),
                exact,
                patterns,
                sources,
                source_only,
            });
        }
        let default_category = if tax
            .default_category
            .trim()
            .is_empty()
        {
            DEFAULT_CATEGORY.to_string()
        } else {
            tax.default_category.clone()
        };
        Self {
            default_category,
            categories: tax.categories.clone(),
            rules,
        }
    }

    /// The canonical category metadata (id + label), for the dashboard breakdown.
    pub fn categories(&self) -> &[CategoryDef] {
        &self.categories
    }

    /// Classify one raw reason token from a given source into a canonical
    /// category id. Falls back to [`Self::default_category`] when no rule matches.
    fn classify_one(
        &self,
        raw: &str,
        source: &str,
    ) -> String {
        let raw_l = raw.trim().to_lowercase();
        let source_l = source.trim().to_lowercase();
        for rule in &self.rules {
            let source_ok = rule.sources.is_empty()
                || rule
                    .sources
                    .contains(&source_l);
            if !source_ok {
                continue;
            }
            if rule.source_only {
                return rule.category.clone();
            }
            if raw_l.is_empty() {
                continue;
            }
            if rule.exact.contains(&raw_l) {
                return rule.category.clone();
            }
            if rule
                .patterns
                .iter()
                .any(|re| re.is_match(&raw_l))
            {
                return rule.category.clone();
            }
        }
        self.default_category.clone()
    }

    /// Map a set of raw reason tokens from one source to the distinct canonical
    /// categories they trigger (order-preserving, deduped). An empty token set
    /// still yields one classification, so a provider that flags without naming a
    /// category (e.g. a bare `flagged: true`) is still attributed via a
    /// source-only rule or the default category.
    pub fn classify(
        &self,
        raw_reasons: &[String],
        source: &str,
    ) -> Vec<String> {
        if raw_reasons.is_empty() {
            return vec![self.classify_one("", source)];
        }
        let mut out: Vec<String> = Vec::new();
        for r in raw_reasons {
            let c = self.classify_one(r, source);
            if !out.contains(&c) {
                out.push(c);
            }
        }
        out
    }
}

/// File-backed classifier with an mtime-gated cache and an embedded built-in
/// fallback. Reads the runtime config file only when it changes; falls back to
/// the compiled-in taxonomy when no file is configured or it can't be parsed.
pub struct RejectionClassifier {
    path: Option<PathBuf>,
    cache: RwLock<Option<(Option<SystemTime>, Arc<CompiledTaxonomy>)>>,
    builtin: Arc<CompiledTaxonomy>,
}

impl RejectionClassifier {
    /// Build a classifier reading from `path` (config-relative file). Pass `None`
    /// to always use the built-in taxonomy (used in tests).
    pub fn new(path: Option<PathBuf>) -> Self {
        Self {
            path,
            cache: RwLock::new(None),
            builtin: builtin_compiled(),
        }
    }

    /// Resolve the active compiled taxonomy via the mtime-gated cache. Reads the
    /// config file only when it has changed since the last read; otherwise serves
    /// the cached form. Falls back to the built-in taxonomy when no file is
    /// configured or it can't be read/parsed.
    pub fn current(&self) -> Arc<CompiledTaxonomy> {
        let Some(path) = &self.path else {
            return self.builtin.clone();
        };
        let mtime = std::fs::metadata(path)
            .and_then(|m| m.modified())
            .ok();
        if let Ok(guard) = self.cache.read()
            && let Some((cached_mt, compiled)) = guard.as_ref()
            && *cached_mt == mtime
        {
            return compiled.clone();
        }
        let compiled = match std::fs::read_to_string(path) {
            Ok(text) => match serde_json::from_str::<RejectionTaxonomy>(&text) {
                Ok(tax) => match tax.validate() {
                    Ok(()) => Arc::new(CompiledTaxonomy::compile(&tax)),
                    Err(undeclared) => {
                        warn!(path = %path.display(), undeclared = %undeclared, "rejection taxonomy references undeclared categories — using built-in taxonomy");
                        self.builtin.clone()
                    }
                },
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "rejection taxonomy file is not valid JSON — using built-in taxonomy");
                    self.builtin.clone()
                }
            },
            Err(_) => self.builtin.clone(),
        };
        if let Ok(mut guard) = self.cache.write() {
            *guard = Some((mtime, compiled.clone()));
        }
        compiled
    }

    /// Classify raw reason tokens from a source into canonical category ids.
    pub fn classify(
        &self,
        raw_reasons: &[String],
        source: &str,
    ) -> Vec<String> {
        self.current()
            .classify(raw_reasons, source)
    }
}

static GLOBAL: OnceLock<Arc<RejectionClassifier>> = OnceLock::new();

/// Register the process-wide rejection classifier (called once by the orchestrator).
pub fn set_global_rejection_classifier(classifier: Arc<RejectionClassifier>) {
    let _ = GLOBAL.set(classifier);
}

/// Access the process-wide rejection classifier, if one has been registered.
pub fn global_rejection_classifier() -> Option<Arc<RejectionClassifier>> {
    GLOBAL.get().cloned()
}

/// Classify via the global classifier, falling back to the built-in taxonomy
/// when no classifier is registered (e.g. in unit tests without an orchestrator).
pub fn classify_global(
    raw_reasons: &[String],
    source: &str,
) -> Vec<String> {
    match global_rejection_classifier() {
        Some(c) => c.classify(raw_reasons, source),
        None => builtin_compiled().classify(raw_reasons, source),
    }
}

/// Each category id with its label from the global taxonomy; an id the
/// taxonomy does not declare keeps the id as its label.
pub fn labelled_categories(ids: &[String]) -> Vec<CategoryDef> {
    if ids.is_empty() {
        return Vec::new();
    }
    let known = global_categories();
    ids.iter()
        .map(|id| {
            known
                .iter()
                .find(|c| &c.id == id)
                .cloned()
                .unwrap_or_else(|| CategoryDef {
                    id: id.clone(),
                    label: id.clone(),
                })
        })
        .collect()
}

/// The canonical category metadata (id + label) from the global classifier,
/// falling back to the built-in taxonomy when none is registered. Used by the
/// rejection read endpoint to enumerate the categories to report.
pub fn global_categories() -> Vec<CategoryDef> {
    match global_rejection_classifier() {
        Some(c) => c
            .current()
            .categories()
            .to_vec(),
        None => builtin_compiled()
            .categories()
            .to_vec(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn builtin() -> CompiledTaxonomy {
        CompiledTaxonomy::compile(&builtin_taxonomy())
    }

    #[test]
    fn labelled_categories_name_each_id() {
        let labelled = labelled_categories(&["prompt_injection".to_string(), "made_up".to_string()]);
        assert_eq!(
            labelled[0],
            CategoryDef {
                id: "prompt_injection".to_string(),
                label: "Prompt Injection".to_string()
            }
        );
        assert_eq!(labelled[1].label, "made_up", "an undeclared id is its own label");
        assert!(labelled_categories(&[]).is_empty());
    }

    #[test]
    fn embedded_taxonomy_parses() {
        let tax = parse_builtin_taxonomy().expect("embedded built-in taxonomy must be valid JSON");
        assert_eq!(tax.default_category, "uncategorized");
        assert!(tax.categories.len() >= 10);
        assert!(!tax.mappings.is_empty());
    }

    #[test]
    fn builtin_taxonomy_passes_validation() {
        parse_builtin_taxonomy()
            .expect("embedded taxonomy parses")
            .validate()
            .expect("every mapping and default category must be declared");
    }

    #[test]
    fn builtin_taxonomy_classifies_indeterminate_judge_verdicts() {
        let tax = builtin();
        let indeterminate = vec!["judge_verdict_indeterminate".to_string()];

        assert_eq!(tax.classify(&indeterminate, "judge"), vec!["judge_indeterminate".to_string()]);
        assert_eq!(tax.classify(&indeterminate, "jury"), vec!["uncategorized".to_string()]);
    }

    #[test]
    fn builtin_taxonomy_declares_redrive_category() {
        // The synthetic `redrive` category must be enumerable so the rejection
        // read endpoint reports recovered redrives, even though no mapping rule
        // ever classifies raw reasons into it.
        let tax = parse_builtin_taxonomy().expect("embedded taxonomy parses");
        assert!(
            tax.categories
                .iter()
                .any(|c| c.id == "redrive"),
            "built-in taxonomy must declare the redrive category"
        );
        assert!(
            !tax.mappings
                .iter()
                .any(|m| m.category == "redrive"),
            "redrive is produced explicitly, never by a mapping rule"
        );
    }

    #[test]
    fn validate_rejects_undeclared_category() {
        let tax = RejectionTaxonomy {
            version: 1,
            default_category: "uncategorized".to_string(),
            categories: vec![CategoryDef {
                id: "uncategorized".to_string(),
                label: "Uncategorized".to_string(),
            }],
            mappings: vec![MappingRule {
                category: "ghost".to_string(),
                exact: vec!["x".to_string()],
                patterns: vec![],
                sources: vec![],
            }],
        };
        let err = tax
            .validate()
            .expect_err("a mapping to an undeclared category must fail validation");
        assert!(err.contains("ghost"), "error names the offending category: {err}");
    }

    #[test]
    fn enkryptai_detector_names_map_to_canonical() {
        let t = builtin();
        assert_eq!(t.classify(&["injection_attack".into()], "enkryptai"), vec!["prompt_injection"]);
        assert_eq!(t.classify(&["toxicity".into()], "enkryptai"), vec!["toxicity"]);
        assert_eq!(t.classify(&["nsfw".into()], "enkryptai"), vec!["sexual_nsfw"]);
    }

    #[test]
    fn azure_content_safety_categories_map() {
        let t = builtin();
        // Azure returns capitalised harm categories; matching is case-insensitive.
        assert_eq!(t.classify(&["Hate".into()], "azure_content_safety"), vec!["hate"]);
        assert_eq!(t.classify(&["SelfHarm".into()], "azure_content_safety"), vec!["self_harm"]);
        assert_eq!(t.classify(&["Violence".into()], "azure_content_safety"), vec!["violence"]);
        assert_eq!(t.classify(&["Sexual".into()], "azure_content_safety"), vec!["sexual_nsfw"]);
    }

    #[test]
    fn source_only_rule_handles_categoryless_provider() {
        let t = builtin();
        // Azure Prompt Shields flags without naming a category: an empty token
        // set from that source still attributes to prompt_injection.
        assert_eq!(t.classify(&[], "azure_prompt_shields"), vec!["prompt_injection"]);
    }

    #[test]
    fn free_text_jury_reason_matched_by_pattern() {
        let t = builtin();
        let reasons = vec!["The response contained toxic and abusive language".to_string()];
        assert_eq!(t.classify(&reasons, "jury"), vec!["toxicity"]);
    }

    #[test]
    fn unmatched_token_falls_back_to_default() {
        let t = builtin();
        assert_eq!(t.classify(&["something_unknown_xyz".into()], "judge"), vec!["uncategorized"]);
    }

    #[test]
    fn multiple_tokens_dedupe_distinct_categories() {
        let t = builtin();
        let reasons = vec!["injection_attack".to_string(), "prompt_injection".to_string(), "toxicity".to_string()];
        // injection_attack + prompt_injection collapse to one category; toxicity adds a second.
        assert_eq!(t.classify(&reasons, "enkryptai"), vec!["prompt_injection", "toxicity"]);
    }

    #[test]
    fn empty_reasons_unknown_source_yields_default() {
        let t = builtin();
        assert_eq!(t.classify(&[], "lakera"), vec!["uncategorized"]);
    }
}
