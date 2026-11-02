//! Reads operator environment variables under their `AS_*` name or one of their
//! deprecated names, so existing deployments keep working.

use std::collections::HashSet;
use std::env::VarError;
use std::sync::{LazyLock, Mutex};

use tracing::warn;

const RENAMED: &[(&str, &[&str])] = &[
    ("AS_MASTER_KEY", &["AGENT_STREAM_MASTER_KEY", "TRUST_GATEWAY_MASTER_KEY"]),
    ("AS_BACKUP_ENCRYPTION_KEY", &["AGENT_STREAM_BACKUP_ENCRYPTION_KEY"]),
    ("AS_LEGACY_BACKUP_KEYS", &["AGENT_STREAM_LEGACY_BACKUP_KEYS"]),
    ("AS_CERT", &["AGENT_STREAM_CERT"]),
    ("AS_KEY", &["AGENT_STREAM_KEY"]),
    ("AS_ALLOW_INSECURE_LOCAL_MEDIATOR_TRANSPORT", &["AGENT_STREAM_ALLOW_INSECURE_LOCAL_MEDIATOR_TRANSPORT"]),
    ("AS_MEDIATOR_DISCOVERY_PRIVATE_HOST_ALLOWLIST", &["AGENT_STREAM_MEDIATOR_DISCOVERY_PRIVATE_HOST_ALLOWLIST"]),
];

static WARNED: LazyLock<Mutex<HashSet<&'static str>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

/// Reads `name`; when it is unset and `name` is one of the renamed variables,
/// reads the other names of its row instead, current name first. Works in both
/// directions so a config that still names a deprecated variable finds the `AS_*` one.
pub fn var(name: &str) -> Result<String, VarError> {
    var_with(name, |key| std::env::var(key))
}

fn var_with(
    name: &str,
    lookup: impl Fn(&str) -> Result<String, VarError>,
) -> Result<String, VarError> {
    let result = lookup(name);
    if !matches!(result, Err(VarError::NotPresent)) {
        return result;
    }
    let Some(&(current, legacy)) = RENAMED
        .iter()
        .find(|(current, legacy)| *current == name || legacy.contains(&name))
    else {
        return result;
    };
    let names = || std::iter::once(current).chain(legacy.iter().copied());
    let Some(requested) = names().find(|candidate| *candidate == name) else {
        return result;
    };
    for other in names().filter(|candidate| *candidate != name) {
        match lookup(other) {
            Err(VarError::NotPresent) => continue,
            Err(error) => return Err(error),
            Ok(value) => {
                let deprecated = if other == current {
                    requested
                } else {
                    other
                };
                warn_once(current, deprecated);
                return Ok(value);
            }
        }
    }
    result
}

fn warn_once(
    current: &'static str,
    deprecated: &'static str,
) {
    let first = WARNED
        .lock()
        .map(|mut warned| warned.insert(deprecated))
        .unwrap_or(false);
    if first {
        warn!("{deprecated} is deprecated; set {current} instead (reading whichever name is set)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Result<String, VarError> {
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| *name == key)
                .map(|(_, value)| (*value).to_string())
                .ok_or(VarError::NotPresent)
        }
    }

    #[test]
    fn reads_the_current_name() {
        assert_eq!(var_with("AS_MASTER_KEY", env(&[("AS_MASTER_KEY", "new")])), Ok("new".to_string()));
    }

    #[test]
    fn falls_back_to_the_legacy_name() {
        assert_eq!(var_with("AS_MASTER_KEY", env(&[("AGENT_STREAM_MASTER_KEY", "old")])), Ok("old".to_string()));
    }

    #[test]
    fn falls_back_to_the_second_legacy_name() {
        assert_eq!(var_with("AS_MASTER_KEY", env(&[("TRUST_GATEWAY_MASTER_KEY", "older")])), Ok("older".to_string()));
    }

    #[test]
    fn earlier_legacy_name_wins_over_a_later_one() {
        assert_eq!(
            var_with(
                "AS_MASTER_KEY",
                env(&[("AGENT_STREAM_MASTER_KEY", "old"), ("TRUST_GATEWAY_MASTER_KEY", "older")])
            ),
            Ok("old".to_string())
        );
    }

    #[test]
    fn legacy_reference_prefers_the_current_name_over_other_legacy_names() {
        assert_eq!(
            var_with("TRUST_GATEWAY_MASTER_KEY", env(&[("AS_MASTER_KEY", "new"), ("AGENT_STREAM_MASTER_KEY", "old")])),
            Ok("new".to_string())
        );
    }

    #[test]
    fn second_legacy_reference_finds_the_current_name() {
        assert_eq!(var_with("TRUST_GATEWAY_MASTER_KEY", env(&[("AS_MASTER_KEY", "new")])), Ok("new".to_string()));
    }

    #[test]
    fn current_name_wins_when_both_are_set() {
        assert_eq!(
            var_with("AS_CERT", env(&[("AS_CERT", "new"), ("AGENT_STREAM_CERT", "old")])),
            Ok("new".to_string())
        );
    }

    #[test]
    fn legacy_reference_finds_the_current_name() {
        assert_eq!(
            var_with("AGENT_STREAM_BACKUP_ENCRYPTION_KEY", env(&[("AS_BACKUP_ENCRYPTION_KEY", "new")])),
            Ok("new".to_string())
        );
    }

    #[test]
    fn reports_not_present_when_neither_is_set() {
        assert_eq!(var_with("AS_KEY", env(&[])), Err(VarError::NotPresent));
    }

    #[test]
    fn names_outside_the_table_have_no_fallback() {
        assert_eq!(
            var_with("AS_IDENTITY_HASH_PEPPER", env(&[("AGENT_STREAM_IDENTITY_HASH_PEPPER", "old")])),
            Err(VarError::NotPresent)
        );
        assert_eq!(var_with("MY_KEY", env(&[("AS_MY_KEY", "x")])), Err(VarError::NotPresent));
    }
}
