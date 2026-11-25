use regex::Regex;
use tracing::{error, info};

use super::config::PromptGuardConfig;
use super::filter::{RuleIssue, rule_issues};
use crate::pipes::{FileSystemPipeStore, PipeConfig};

/// A Prompt Guard rule of a stored Surface, or of one of its Variants, that
/// cannot be evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnusableSurfaceRule {
    /// The Surface, and the Variant when the rule is in its override.
    pub owner: String,
    pub issue: RuleIssue,
}

fn unusable_rules(
    surface: &PipeConfig,
    compiles: &dyn Fn(&str) -> bool,
) -> Vec<UnusableSurfaceRule> {
    let surface_owner = format!("Surface {:?} ({})", surface.name, surface.id);
    let own = surface
        .prompt_guard
        .iter()
        .map(|guard| (surface_owner.clone(), guard));
    let variants = surface
        .variants
        .iter()
        .filter_map(|variant| {
            variant
                .overrides
                .prompt_guard
                .as_ref()
                .map(|guard| (format!("{surface_owner} Variant {:?}", variant.alias), guard))
        });
    own.chain(variants)
        .filter(|(_, guard): &(String, &PromptGuardConfig)| guard.enabled)
        .flat_map(|(owner, guard)| {
            rule_issues(guard, compiles)
                .map(|issue| UnusableSurfaceRule { owner: owner.clone(), issue })
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Log one `ERROR` for each enabled Prompt Guard regex rule of `surface` or of
/// one of its Variants that cannot be evaluated, naming the Surface and the
/// rule, and count it in `agent_stream_prompt_guard_unusable_rules_total`.
/// Requests that rule guards are refused with `502`. Returns how many were
/// found.
pub fn report_unusable_rules(surface: &PipeConfig) -> usize {
    let found = unusable_rules(surface, &|pattern| Regex::new(pattern).is_ok());
    for rule in &found {
        error!(
            "{} has a Prompt Guard rule that cannot be evaluated: {} — requests it guards are refused with 502 prompt_guard_pattern_unavailable",
            rule.owner, rule.issue.description
        );
        crate::metrics::backends::prometheus::track_prompt_guard_unusable_rule(
            rule.issue.side.as_str(),
            rule.issue.reason,
        );
    }
    found.len()
}

/// Check every Surface in `store` with [`report_unusable_rules`]: run once the
/// store has loaded at startup.
pub async fn report_unusable_rules_in_store(store: &FileSystemPipeStore) {
    let surfaces = store.list().await;
    let found: usize = surfaces
        .iter()
        .map(report_unusable_rules)
        .sum();
    info!(
        "Checked {} stored Surface(s) for Prompt Guard rules that cannot be evaluated: {found} found",
        surfaces.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metrics::backends::prometheus::PROMPT_GUARD_UNUSABLE_RULES;
    use crate::pipes::PipeType;
    use serde_json::json;

    fn surface(prompt_guard: Option<serde_json::Value>) -> PipeConfig {
        let mut surface = PipeConfig::new(
            "surface-1".to_string(),
            "alpha-chat".to_string(),
            PipeType::Webhook {
                endpoint: "https://example.com".to_string(),
            },
        );
        surface.prompt_guard = prompt_guard.map(|guard| serde_json::from_value(guard).expect("prompt guard parses"));
        surface
    }

    fn guard(
        enabled: bool,
        request: serde_json::Value,
        response: serde_json::Value,
    ) -> serde_json::Value {
        let side = |rules: serde_json::Value| json!([{ "regex": { "action": "reject", "rules": rules } }]);
        json!({ "enabled": enabled, "request": side(request), "response": side(response) })
    }

    fn with_variant(
        mut surface: PipeConfig,
        alias: &str,
        prompt_guard: serde_json::Value,
    ) -> PipeConfig {
        surface.variants.push(
            serde_json::from_value(json!({
                "id": format!("variant-{alias}"),
                "alias": alias,
                "name": alias,
                "overrides": { "prompt_guard": prompt_guard },
            }))
            .expect("variant parses"),
        );
        surface
    }

    fn found(surface: &PipeConfig) -> Vec<(String, RuleIssue)> {
        super::super::definitions::init_test_definitions();
        unusable_rules(surface, &|pattern| Regex::new(pattern).is_ok())
            .into_iter()
            .map(|rule| (rule.owner, rule.issue))
            .collect()
    }

    #[test]
    fn a_surface_with_only_usable_rules_has_nothing_to_report() {
        let usable = surface(Some(guard(true, json!([{ "builtin": "email" }]), json!([{ "pattern": r"\d+" }]))));

        assert_eq!(found(&usable), Vec::new());
        assert_eq!(found(&surface(None)), Vec::new());
    }

    #[test]
    fn every_unusable_rule_of_the_surface_is_named_with_its_side_and_reason() {
        let broken = surface(Some(guard(
            true,
            json!([{ "builtin": "email" }, { "builtin": "not_a_pattern" }]),
            json!([{ "builtin": "broken" }]),
        )));

        assert_eq!(
            found(&broken),
            vec![
                (
                    "Surface \"alpha-chat\" (surface-1)".to_string(),
                    RuleIssue {
                        side: super::super::GuardSide::Request,
                        reason: "unknown",
                        description: "built-in pattern 'not_a_pattern' is not defined on the request side".to_string(),
                    }
                ),
                (
                    "Surface \"alpha-chat\" (surface-1)".to_string(),
                    RuleIssue {
                        side: super::super::GuardSide::Response,
                        reason: "compile_failed",
                        description: "built-in pattern 'broken' did not compile on the response side".to_string(),
                    }
                ),
            ]
        );
    }

    #[test]
    fn a_variant_rule_is_named_with_its_variant_and_a_custom_pattern_by_position_never_its_regex() {
        let secret_regex = "(?!secret-token)y";
        let variant = with_variant(
            surface(None),
            "canary",
            guard(true, json!([{ "builtin": "email" }, { "pattern": secret_regex }]), json!([])),
        );

        let found = found(&variant);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].0, "Surface \"alpha-chat\" (surface-1) Variant \"canary\"");
        assert_eq!(found[0].1.reason, "custom_pattern_invalid");
        assert_eq!(found[0].1.description, "custom pattern #2 does not compile on the request side");
        assert!(!format!("{found:?}").contains("secret-token"));
    }

    #[test]
    fn a_disabled_prompt_guard_is_not_reported() {
        let disabled = with_variant(
            surface(Some(guard(false, json!([{ "builtin": "broken" }]), json!([])))),
            "canary",
            guard(false, json!([{ "pattern": "(?!x)y" }]), json!([])),
        );

        assert_eq!(found(&disabled), Vec::new());
    }

    #[tokio::test]
    async fn the_startup_check_reports_every_stored_surface() {
        super::super::definitions::init_test_definitions();
        let counter = || {
            PROMPT_GUARD_UNUSABLE_RULES
                .with_label_values(&["request", "compile_failed"])
                .get()
        };
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemPipeStore::new(
            dir.path()
                .to_string_lossy()
                .into_owned(),
        )
        .await
        .unwrap();
        let mut broken = surface(Some(guard(true, json!([{ "builtin": "broken" }]), json!([]))));
        broken.id = "stored-broken".to_string();
        let mut usable = surface(Some(guard(true, json!([{ "builtin": "email" }]), json!([]))));
        usable.id = "stored-usable".to_string();
        store
            .save(broken)
            .await
            .unwrap();
        store
            .save(usable)
            .await
            .unwrap();
        let before = counter();

        report_unusable_rules_in_store(&store).await;

        assert_eq!(counter() - before, 1);
    }

    #[test]
    fn reporting_counts_each_unusable_rule_by_side_and_reason() {
        super::super::definitions::init_test_definitions();
        let counter = || {
            PROMPT_GUARD_UNUSABLE_RULES
                .with_label_values(&["response", "custom_pattern_invalid"])
                .get()
        };
        let before = counter();
        let broken = surface(Some(guard(
            true,
            json!([{ "builtin": "email" }]),
            json!([{ "pattern": "(?!a)b" }, { "pattern": "(?!c)d", "label": "lookahead" }]),
        )));

        assert_eq!(report_unusable_rules(&broken), 2);
        assert_eq!(report_unusable_rules(&surface(None)), 0);
        assert!(counter() - before >= 2, "counted {}", counter() - before);
    }
}
