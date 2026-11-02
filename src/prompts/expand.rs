//! Request-time prompt reference expansion.
//!
//! A client may include a `prompt` block in a chat request body to have the
//! gateway render a stored [`crate::prompts::Prompt`] into `messages` before the
//! request enters the pipeline:
//!
//! ```json
//! { "model": "gpt-4o", "prompt": { "id": "greeter", "version": 2, "variables": { "name": "Ada" } } }
//! ```
//!
//! The handler [`take_prompt_reference`]s the block (removing it so it is never
//! forwarded upstream), resolves + renders the prompt, then
//! [`inject_messages`]es the result.

use serde::Deserialize;
use serde_json::Value;

/// A `prompt` reference block from a request body.
#[derive(Debug, Deserialize, PartialEq)]
pub struct PromptReference {
    /// Id of the stored prompt to render.
    pub id: String,
    /// Specific version to render; falls back to the prompt's default / latest.
    #[serde(default)]
    pub version: Option<u32>,
    /// Variable values substituted into the template.
    #[serde(default)]
    pub variables: serde_json::Map<String, Value>,
}

/// Extract and remove the `prompt` reference block from a request body.
///
/// Returns `Ok(None)` when absent, `Ok(Some(reference))` when present and
/// well-formed, and `Err` when present but malformed. The block is always
/// removed so it is never forwarded to the provider.
pub fn take_prompt_reference(payload: &mut Value) -> Result<Option<PromptReference>, String> {
    let Some(obj) = payload.as_object_mut() else {
        return Ok(None);
    };
    let Some(raw) = obj.remove("prompt") else {
        return Ok(None);
    };
    let reference: PromptReference =
        serde_json::from_value(raw).map_err(|e| format!("invalid prompt reference: {e}"))?;
    if !crate::prompts::is_valid_prompt_id(&reference.id) {
        return Err("prompt reference id must be 1–128 chars of [A-Za-z0-9_-]".to_string());
    }
    Ok(Some(reference))
}

/// Inject rendered prompt messages into the request body: the rendered prompt
/// messages come first, followed by any client-supplied `messages` (so a client
/// can append user turns to a templated system prompt).
pub fn inject_messages(
    payload: &mut Value,
    rendered: Vec<Value>,
) {
    let existing = payload
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned();
    let Some(obj) = payload.as_object_mut() else {
        return;
    };
    let mut messages = rendered;
    if let Some(existing) = existing {
        messages.extend(existing);
    }
    obj.insert("messages".to_string(), Value::Array(messages));
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn take_reference_extracts_and_removes() {
        let mut payload = json!({
            "model": "gpt-4o",
            "prompt": { "id": "greeter", "version": 2, "variables": { "name": "Ada" } }
        });
        let reference = take_prompt_reference(&mut payload)
            .unwrap()
            .unwrap();
        assert_eq!(reference.id, "greeter");
        assert_eq!(reference.version, Some(2));
        assert_eq!(
            reference
                .variables
                .get("name")
                .unwrap(),
            &json!("Ada")
        );
        assert!(
            payload
                .get("prompt")
                .is_none(),
            "prompt block must be removed"
        );
    }

    #[test]
    fn take_reference_absent_is_none() {
        let mut payload = json!({ "model": "gpt-4o", "messages": [] });
        assert_eq!(take_prompt_reference(&mut payload).unwrap(), None);
    }

    #[test]
    fn take_reference_malformed_errors() {
        let mut payload = json!({ "prompt": { "version": 2 } });
        assert!(take_prompt_reference(&mut payload).is_err());
    }

    #[test]
    fn take_reference_rejects_traversal_id() {
        // A path-traversal-style id must be rejected before it is ever used as a
        // lookup key (defense-in-depth on top of cache-keyed storage reads).
        let mut payload = json!({ "prompt": { "id": "../../etc/passwd" } });
        assert!(take_prompt_reference(&mut payload).is_err());
        let mut slashed = json!({ "prompt": { "id": "a/b" } });
        assert!(take_prompt_reference(&mut slashed).is_err());
    }

    #[test]
    fn inject_prepends_rendered_before_existing() {
        let mut payload = json!({ "messages": [{ "role": "user", "content": "hi" }] });
        let rendered = vec![json!({ "role": "system", "content": "You are helpful." })];
        inject_messages(&mut payload, rendered);
        assert_eq!(
            payload["messages"],
            json!([
                { "role": "system", "content": "You are helpful." },
                { "role": "user", "content": "hi" }
            ])
        );
    }

    #[test]
    fn inject_sets_messages_when_absent() {
        let mut payload = json!({ "model": "gpt-4o" });
        inject_messages(&mut payload, vec![json!({ "role": "system", "content": "s" })]);
        assert_eq!(payload["messages"], json!([{ "role": "system", "content": "s" }]));
    }
}
