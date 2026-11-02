//! Prompt template types and rendering.

use crate::entity_status::EntityStatus;
use crate::storage::filesystem::StorableEntity;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

/// A single chat message in a prompt version. `content` may contain
/// `{{variable}}` placeholders substituted at render time.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptMessage {
    /// OpenAI message role (`system` / `user` / `assistant`).
    pub role: String,
    /// Message content, possibly containing `{{variable}}` placeholders.
    pub content: String,
}

/// One immutable version of a prompt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PromptVersion {
    /// Monotonic version number, unique within the prompt.
    pub version: u32,
    /// The message list rendered for this version.
    pub messages: Vec<PromptMessage>,
    /// Optional human label (e.g. "prod", "experiment-a").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: DateTime<Utc>,
}

impl PromptVersion {
    /// The distinct `{{variable}}` names referenced across this version's
    /// messages, in first-seen order.
    pub fn variables(&self) -> Vec<String> {
        let mut names = Vec::new();
        for message in &self.messages {
            for name in scan_variables(&message.content) {
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
        names
    }
}

/// A named, versioned prompt template.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Prompt {
    /// Server-assigned or caller-supplied id; the storage filename.
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Lifecycle status. A `Deleted` prompt is tombstoned (hidden, retained).
    #[serde(default)]
    pub status: EntityStatus,
    /// Marks an ephemeral test-fixture prompt (parity with `Member.test_fixture`).
    #[serde(default, skip_serializing_if = "is_false")]
    pub test_fixture: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    /// All versions, newest not guaranteed last (resolution is by number).
    #[serde(default)]
    pub versions: Vec<PromptVersion>,
    /// Version selected when a caller references the prompt without one.
    /// Falls back to the highest version number when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_version: Option<u32>,
    #[serde(default)]
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub updated_at: DateTime<Utc>,
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Error rendering a prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenderError {
    /// The prompt has no versions to render.
    NoVersions,
    /// The requested version does not exist.
    UnknownVersion(u32),
    /// One or more `{{variable}}` placeholders had no supplied value.
    MissingVariables(Vec<String>),
}

impl std::fmt::Display for RenderError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::NoVersions => write!(f, "prompt has no versions"),
            Self::UnknownVersion(v) => write!(f, "prompt has no version {v}"),
            Self::MissingVariables(names) => {
                write!(f, "missing prompt variables: {}", names.join(", "))
            }
        }
    }
}

impl std::error::Error for RenderError {}

/// Whether `id` is a valid prompt id: non-empty, ≤128 chars, and only
/// `[A-Za-z0-9_-]` so it is safe as a storage filename (no path traversal) and
/// safe to use as a lookup key from an untrusted request body.
pub fn is_valid_prompt_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

impl Prompt {
    /// Validate the prompt's invariants.
    pub fn validate(&self) -> Result<(), String> {
        if self.id.trim().is_empty() {
            return Err("prompt id must not be empty".to_string());
        }
        if self.name.trim().is_empty() {
            return Err("prompt name must not be empty".to_string());
        }
        let mut seen = std::collections::HashSet::new();
        for version in &self.versions {
            if !seen.insert(version.version) {
                return Err(format!("duplicate prompt version {}", version.version));
            }
            if version.messages.is_empty() {
                return Err(format!("prompt version {} has no messages", version.version));
            }
            for message in &version.messages {
                if message.role.trim().is_empty() {
                    return Err(format!("prompt version {} has a message with an empty role", version.version));
                }
            }
        }
        if let Some(default_version) = self.default_version
            && !self
                .versions
                .iter()
                .any(|v| v.version == default_version)
        {
            return Err(format!("default_version {default_version} does not exist"));
        }
        Ok(())
    }

    /// The highest version number present, if any.
    pub fn max_version(&self) -> Option<u32> {
        self.versions
            .iter()
            .map(|v| v.version)
            .max()
    }

    /// Resolve which version to render: the requested one, else the
    /// `default_version`, else the highest number.
    pub fn resolve_version(
        &self,
        requested: Option<u32>,
    ) -> Result<&PromptVersion, RenderError> {
        if self.versions.is_empty() {
            return Err(RenderError::NoVersions);
        }
        let target = match requested.or(self.default_version) {
            Some(v) => v,
            None => self
                .max_version()
                .ok_or(RenderError::NoVersions)?,
        };
        self.versions
            .iter()
            .find(|v| v.version == target)
            .ok_or(RenderError::UnknownVersion(target))
    }

    /// Render the selected version into an OpenAI `messages` array with the
    /// supplied variable values substituted. Reports every missing variable at
    /// once so callers see the full set.
    pub fn render(
        &self,
        version: Option<u32>,
        variables: &serde_json::Map<String, Value>,
    ) -> Result<Vec<Value>, RenderError> {
        let selected = self.resolve_version(version)?;
        let mut messages = Vec::with_capacity(selected.messages.len());
        let mut missing: Vec<String> = Vec::new();
        for message in &selected.messages {
            match render_template(&message.content, variables) {
                Ok(content) => messages.push(json!({ "role": message.role, "content": content })),
                Err(RenderError::MissingVariables(names)) => {
                    for name in names {
                        if !missing.contains(&name) {
                            missing.push(name);
                        }
                    }
                }
                Err(other) => return Err(other),
            }
        }
        if !missing.is_empty() {
            return Err(RenderError::MissingVariables(missing));
        }
        Ok(messages)
    }
}

impl StorableEntity for Prompt {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Substitute `{{variable}}` placeholders in `template` with values from
/// `variables` (string values used verbatim, others JSON-stringified).
/// Unmatched placeholders are collected and returned as a `MissingVariables`
/// error; malformed (unclosed) `{{` are left literal.
pub fn render_template(
    template: &str,
    variables: &serde_json::Map<String, Value>,
) -> Result<String, RenderError> {
    let mut out = String::with_capacity(template.len());
    let mut missing: Vec<String> = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        out.push_str(&rest[..open]);
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            // Unclosed placeholder: emit the rest literally and stop.
            out.push_str(&rest[open..]);
            rest = "";
            break;
        };
        let name = after_open[..close].trim();
        match variables.get(name) {
            Some(Value::String(value)) => out.push_str(value),
            Some(value) => out.push_str(&value.to_string()),
            None => {
                if !missing.contains(&name.to_string()) {
                    missing.push(name.to_string());
                }
            }
        }
        rest = &after_open[close + 2..];
    }
    out.push_str(rest);
    if missing.is_empty() {
        Ok(out)
    } else {
        Err(RenderError::MissingVariables(missing))
    }
}

/// Extract `{{variable}}` names from a template string, in first-seen order.
fn scan_variables(template: &str) -> Vec<String> {
    let mut names = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find("{{") {
        let after_open = &rest[open + 2..];
        let Some(close) = after_open.find("}}") else {
            break;
        };
        let name = after_open[..close]
            .trim()
            .to_string();
        if !name.is_empty() && !names.contains(&name) {
            names.push(name);
        }
        rest = &after_open[close + 2..];
    }
    names
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn vars(pairs: &[(&str, &str)]) -> serde_json::Map<String, Value> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), json!(v)))
            .collect()
    }

    fn prompt() -> Prompt {
        Prompt {
            id: "p1".to_string(),
            name: "Greeter".to_string(),
            description: None,
            status: EntityStatus::Enabled,
            test_fixture: false,
            tenant_id: None,
            versions: vec![
                PromptVersion {
                    version: 1,
                    messages: vec![PromptMessage {
                        role: "system".to_string(),
                        content: "v1".to_string(),
                    }],
                    label: None,
                    created_at: Utc::now(),
                },
                PromptVersion {
                    version: 2,
                    messages: vec![
                        PromptMessage {
                            role: "system".to_string(),
                            content: "You are {{persona}}.".to_string(),
                        },
                        PromptMessage {
                            role: "user".to_string(),
                            content: "Hello {{name}}".to_string(),
                        },
                    ],
                    label: Some("prod".to_string()),
                    created_at: Utc::now(),
                },
            ],
            default_version: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn render_template_substitutes_and_reports_missing() {
        let v = vars(&[("name", "Ada")]);
        assert_eq!(render_template("Hi {{name}}!", &v).unwrap(), "Hi Ada!");
        assert_eq!(
            render_template("Hi {{ name }} from {{place}}", &v).unwrap_err(),
            RenderError::MissingVariables(vec!["place".to_string()])
        );
    }

    #[test]
    fn legacy_prompt_without_tenant_id_is_global() {
        let mut value = serde_json::to_value(prompt()).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .remove("tenant_id");
        let prompt: Prompt = serde_json::from_value(value).unwrap();

        assert_eq!(prompt.tenant_id, None);
    }

    #[test]
    fn render_template_leaves_unclosed_literal() {
        let v = vars(&[]);
        assert_eq!(render_template("a {{ b", &v).unwrap(), "a {{ b");
    }

    #[test]
    fn variables_lists_distinct_names() {
        let p = prompt();
        let v2 = p
            .resolve_version(Some(2))
            .unwrap();
        assert_eq!(v2.variables(), vec!["persona".to_string(), "name".to_string()]);
    }

    #[test]
    fn resolve_version_prefers_requested_then_default_then_max() {
        let mut p = prompt();
        assert_eq!(
            p.resolve_version(Some(1))
                .unwrap()
                .version,
            1
        );
        // No request, no default => highest.
        assert_eq!(
            p.resolve_version(None)
                .unwrap()
                .version,
            2
        );
        // Default overrides the "highest" fallback.
        p.default_version = Some(1);
        assert_eq!(
            p.resolve_version(None)
                .unwrap()
                .version,
            1
        );
        // Unknown request errors.
        assert_eq!(
            p.resolve_version(Some(9))
                .unwrap_err(),
            RenderError::UnknownVersion(9)
        );
    }

    #[test]
    fn render_produces_messages_array() {
        let p = prompt();
        let rendered = p
            .render(Some(2), &vars(&[("persona", "a poet"), ("name", "Ada")]))
            .unwrap();
        assert_eq!(
            rendered,
            vec![
                json!({"role": "system", "content": "You are a poet."}),
                json!({"role": "user", "content": "Hello Ada"})
            ]
        );
    }

    #[test]
    fn render_reports_all_missing_variables() {
        let p = prompt();
        assert_eq!(
            p.render(Some(2), &vars(&[]))
                .unwrap_err(),
            RenderError::MissingVariables(vec!["persona".to_string(), "name".to_string()])
        );
    }

    #[test]
    fn validate_rejects_duplicate_versions_and_bad_default() {
        let mut p = prompt();
        p.default_version = Some(5);
        assert!(p.validate().is_err());
        p.default_version = Some(2);
        assert!(p.validate().is_ok());
        p.versions[1].version = 1;
        assert!(p.validate().is_err());
    }
}
