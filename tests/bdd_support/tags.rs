pub fn include_known_bugs_from_env() -> bool {
    std::env::var("BDD_INCLUDE_KNOWN_BUGS")
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

pub fn should_run_for_tags<'a>(
    tags: impl IntoIterator<Item = &'a String>,
    include_known_bugs: bool,
    debug: bool,
) -> bool {
    if debug {
        tags.into_iter()
            .any(|tag| tag == "debug")
    } else {
        !tags
            .into_iter()
            .any(|tag| tag == "wip" || (!include_known_bugs && tag == "known-bug"))
    }
}

#[cfg(test)]
mod tests {
    #[allow(dead_code)]
    fn tags(values: &[&str]) -> Vec<String> {
        values
            .iter()
            .map(|value| value.to_string())
            .collect()
    }

    #[test]
    fn scenarios_without_control_tags_run_by_default() {
        assert!(super::should_run_for_tags(&tags(&[]), false, false));
    }

    #[test]
    fn wip_scenarios_do_not_run_by_default() {
        assert!(!super::should_run_for_tags(&tags(&["wip"]), false, false));
    }

    #[test]
    fn known_bug_scenarios_are_opt_in() {
        assert!(!super::should_run_for_tags(&tags(&["known-bug"]), false, false));
        assert!(super::should_run_for_tags(&tags(&["known-bug"]), true, false));
    }
}
