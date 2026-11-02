//! Structured outputs (`response_format: { type: "json_schema", … }`),
//! normalized across providers.
//!
//! OpenAI and Azure accept a strict `json_schema` response format natively
//! (constrained decoding), so we pass it straight through. Providers without
//! native support (Anthropic, Gemini, and OpenAI-compatible endpoints that only
//! do `json_object`) are steered with a system instruction carrying the schema,
//! and the completion is validated locally against the schema so callers get a
//! conformance signal on every surface. See
//! `docs/INFERENCE_CONTROLS.md`.

use serde_json::Value;

/// A parsed `response_format: { type: "json_schema", json_schema: { name,
/// strict, schema } }`.
#[derive(Debug, Clone, PartialEq)]
pub struct StructuredOutputSpec {
    pub name: String,
    pub strict: bool,
    pub schema: Value,
}

/// Parse a canonical body's `response_format` into a [`StructuredOutputSpec`],
/// or `None` when it is absent or is not a `json_schema` request.
pub fn parse_spec(body: &Value) -> Option<StructuredOutputSpec> {
    let response_format = body.get("response_format")?;
    if response_format
        .get("type")
        .and_then(|t| t.as_str())
        != Some("json_schema")
    {
        return None;
    }
    let json_schema = response_format.get("json_schema")?;
    let schema = json_schema
        .get("schema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({}));
    Some(StructuredOutputSpec {
        name: json_schema
            .get("name")
            .and_then(|n| n.as_str())
            .unwrap_or("response")
            .to_string(),
        strict: json_schema
            .get("strict")
            .and_then(|s| s.as_bool())
            .unwrap_or(false),
        schema,
    })
}

/// A system-message instruction that steers a model without native
/// `json_schema` support to emit JSON conforming to the schema.
pub fn schema_instruction(spec: &StructuredOutputSpec) -> String {
    let schema = serde_json::to_string(&spec.schema).unwrap_or_else(|_| "{}".to_string());
    format!(
        "You must respond with a single JSON object that strictly conforms to the JSON Schema below (schema name: \"{}\"). Output only the JSON object — no prose, no markdown, no code fences.\n\nJSON Schema:\n{schema}",
        spec.name
    )
}

/// Whether a wire schema natively enforces `json_schema` structured outputs.
pub fn schema_is_native(
    api_schema: &str,
    supports_json_schema: bool,
) -> bool {
    supports_json_schema && matches!(api_schema, "openai" | "azure")
}

/// Shape a canonical (OpenAI-format) body for its upstream so `json_schema`
/// works everywhere, in place.
///
/// Native schemas keep `response_format` untouched (the upstream enforces it).
/// Non-native schemas get a schema **system instruction** prepended and their
/// `response_format` downgraded to `json_object` (or removed when the model does
/// not even do JSON mode), so the request is accepted and steered toward the
/// schema; local validation then checks conformance.
pub fn shape_body(
    body: &mut Value,
    api_schema: &str,
    supports_json_schema: bool,
    supports_json_mode: bool,
) {
    let Some(spec) = parse_spec(body) else {
        return;
    };
    if schema_is_native(api_schema, supports_json_schema) {
        return;
    }

    let instruction = schema_instruction(&spec);
    let Some(obj) = body.as_object_mut() else {
        return;
    };

    if supports_json_mode {
        obj.insert("response_format".to_string(), serde_json::json!({ "type": "json_object" }));
    } else {
        obj.remove("response_format");
    }

    if let Some(messages) = obj
        .get_mut("messages")
        .and_then(|m| m.as_array_mut())
    {
        messages.insert(0, serde_json::json!({ "role": "system", "content": instruction }));
    }
}

/// Validate a completion string against `schema`. `Ok(())` when the completion
/// parses as JSON and conforms; `Err(message)` (first few failures) otherwise.
/// A completion wrapped in a markdown code fence is unwrapped first, since
/// steered (non-native) models often add one despite the instruction.
pub fn validate(
    content: &str,
    schema: &Value,
) -> Result<(), String> {
    let cleaned = unwrap_fenced_json(content).unwrap_or_else(|| content.trim().to_string());
    let instance: Value = serde_json::from_str(&cleaned).map_err(|e| format!("output was not valid JSON: {e}"))?;
    let validator = jsonschema::Validator::options()
        .build(schema)
        .map_err(|e| format!("invalid JSON schema: {e}"))?;
    let errors: Vec<String> = validator
        .iter_errors(&instance)
        .map(|e| e.to_string())
        .take(5)
        .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// If `content` is a single markdown code fence wrapping a JSON body
/// (```` ```json … ``` ```` or ```` ``` … ``` ````), return the inner JSON text;
/// otherwise `None`. Steered models frequently fence structured output despite
/// being told not to, so the gateway unwraps it to hand the caller clean JSON.
pub fn unwrap_fenced_json(content: &str) -> Option<String> {
    let trimmed = content.trim();
    let after_open = trimmed.strip_prefix("```")?;
    // Drop an optional language tag (e.g. `json`) on the opening fence line.
    let after_open = after_open
        .strip_prefix("json")
        .or_else(|| after_open.strip_prefix("JSON"))
        .unwrap_or(after_open);
    let body = after_open
        .strip_suffix("```")?
        .trim();
    if body.starts_with('{') || body.starts_with('[') {
        Some(body.to_string())
    } else {
        None
    }
}

/// Validate the assistant completion in an OpenAI-canonical response against the
/// structured-output spec on the original request. Returns `None` when the
/// request did not ask for a `json_schema` output; otherwise `Some(Ok/Err)`.
pub fn validate_response(
    request_body: &Value,
    response_body: &Value,
) -> Option<Result<(), String>> {
    let spec = parse_spec(request_body)?;
    let content = response_body
        .pointer("/choices/0/message/content")
        .and_then(|c| c.as_str())
        .unwrap_or("");
    Some(validate(content, &spec.schema))
}

/// When the request asked for a `json_schema` output and the model wrapped the
/// completion in a markdown code fence, replace the completion with the
/// unwrapped JSON in place so the caller receives parseable content. No-op when
/// no structured output was requested or the content is not fenced.
pub fn unwrap_response_content(
    request_body: &Value,
    response_body: &mut Value,
) {
    if parse_spec(request_body).is_none() {
        return;
    }
    let Some(message) = response_body
        .pointer_mut("/choices/0/message")
        .and_then(|m| m.as_object_mut())
    else {
        return;
    };
    let Some(content) = message
        .get("content")
        .and_then(|c| c.as_str())
    else {
        return;
    };
    if let Some(unwrapped) = unwrap_fenced_json(content) {
        message.insert("content".to_string(), Value::String(unwrapped));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema_body() -> Value {
        json!({
            "messages": [{ "role": "user", "content": "Give me a person." }],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "person",
                    "strict": true,
                    "schema": {
                        "type": "object",
                        "properties": { "name": { "type": "string" }, "age": { "type": "integer" } },
                        "required": ["name", "age"],
                        "additionalProperties": false
                    }
                }
            }
        })
    }

    #[test]
    fn parse_spec_reads_json_schema() {
        let spec = parse_spec(&schema_body()).unwrap();
        assert_eq!(spec.name, "person");
        assert!(spec.strict);
        assert_eq!(spec.schema["required"], json!(["name", "age"]));
    }

    #[test]
    fn parse_spec_none_for_json_object() {
        let body = json!({ "response_format": { "type": "json_object" } });
        assert!(parse_spec(&body).is_none());
    }

    #[test]
    fn parse_spec_none_when_absent() {
        assert!(parse_spec(&json!({ "messages": [] })).is_none());
    }

    #[test]
    fn native_openai_passes_through_untouched() {
        let mut body = schema_body();
        shape_body(&mut body, "openai", true, true);
        assert_eq!(body["response_format"]["type"], json!("json_schema"));
        // No injected system message.
        assert_eq!(
            body["messages"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn non_native_json_mode_downgrades_and_injects_instruction() {
        let mut body = schema_body();
        shape_body(&mut body, "openai", false, true);
        assert_eq!(body["response_format"]["type"], json!("json_object"));
        let messages = body["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0]["role"], json!("system"));
        assert!(
            messages[0]["content"]
                .as_str()
                .unwrap()
                .contains("JSON Schema")
        );
    }

    #[test]
    fn non_native_no_json_mode_removes_response_format() {
        let mut body = schema_body();
        shape_body(&mut body, "anthropic", false, false);
        assert!(
            body.get("response_format")
                .is_none()
        );
        let messages = body["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0]["role"], json!("system"));
    }

    #[test]
    fn shape_body_noop_without_json_schema() {
        let mut body = json!({ "messages": [], "response_format": { "type": "json_object" } });
        shape_body(&mut body, "anthropic", false, false);
        assert_eq!(body["response_format"]["type"], json!("json_object"));
    }

    #[test]
    fn validate_accepts_conforming_json() {
        let schema = schema_body()["response_format"]["json_schema"]["schema"].clone();
        assert!(validate(r#"{"name":"Alice","age":30}"#, &schema).is_ok());
    }

    #[test]
    fn validate_rejects_missing_field() {
        let schema = schema_body()["response_format"]["json_schema"]["schema"].clone();
        let err = validate(r#"{"name":"Alice"}"#, &schema).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn validate_rejects_non_json() {
        let schema = schema_body()["response_format"]["json_schema"]["schema"].clone();
        let err = validate("not json at all", &schema).unwrap_err();
        assert!(err.contains("not valid JSON"));
    }

    #[test]
    fn validate_response_reads_content() {
        let request = schema_body();
        let good = json!({ "choices": [ { "message": { "content": "{\"name\":\"Al\",\"age\":9}" } } ] });
        assert!(
            validate_response(&request, &good)
                .unwrap()
                .is_ok()
        );
        let bad = json!({ "choices": [ { "message": { "content": "{\"name\":\"Al\"}" } } ] });
        assert!(
            validate_response(&request, &bad)
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn validate_response_none_without_spec() {
        let request = json!({ "messages": [] });
        let response = json!({ "choices": [ { "message": { "content": "hi" } } ] });
        assert!(validate_response(&request, &response).is_none());
    }

    #[test]
    fn unwrap_fenced_json_variants() {
        assert_eq!(unwrap_fenced_json("```json\n{\"a\":1}\n```").as_deref(), Some("{\"a\":1}"));
        assert_eq!(unwrap_fenced_json("```\n{\"a\":1}\n```").as_deref(), Some("{\"a\":1}"));
        assert_eq!(unwrap_fenced_json("  ```json\n[1,2]\n```  ").as_deref(), Some("[1,2]"));
        // Not a fence, or fence not wrapping JSON → None.
        assert!(unwrap_fenced_json("{\"a\":1}").is_none());
        assert!(unwrap_fenced_json("```\nhello\n```").is_none());
    }

    #[test]
    fn validate_tolerates_fenced_json() {
        let schema = schema_body()["response_format"]["json_schema"]["schema"].clone();
        assert!(validate("```json\n{\"name\":\"Al\",\"age\":9}\n```", &schema).is_ok());
    }

    #[test]
    fn unwrap_response_content_cleans_fenced_completion() {
        let request = schema_body();
        let mut response = json!({
            "choices": [ { "message": { "role": "assistant", "content": "```json\n{\"name\":\"Al\",\"age\":9}\n```" } } ]
        });
        unwrap_response_content(&request, &mut response);
        assert_eq!(response["choices"][0]["message"]["content"], json!("{\"name\":\"Al\",\"age\":9}"));
    }

    #[test]
    fn unwrap_response_content_noop_without_spec() {
        let request = json!({ "messages": [] });
        let mut response = json!({ "choices": [ { "message": { "content": "```json\n{}\n```" } } ] });
        unwrap_response_content(&request, &mut response);
        // No structured output requested → content is left untouched.
        assert_eq!(response["choices"][0]["message"]["content"], json!("```json\n{}\n```"));
    }
}
