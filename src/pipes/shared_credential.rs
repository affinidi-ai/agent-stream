//! What a surface may send through a provider credential its tenant does not
//! own: an appliance-wide (operator) provider key, or an operator secret in
//! `upstream_headers`, spent by a tenant's surface.
//!
//! The provider keeps files, batches, vector stores, stored responses and
//! conversations per key, so every tenant whose surfaces spend the same key
//! shares one store. Through such a credential a surface runs inference only:
//!
//! - a caller-chosen path must name a stateless endpoint that reads no stored
//!   object ([`is_inference_path`]);
//! - the body must not name a provider-stored object
//!   ([`names_stored_object`]);
//! - file and batch reads ([`SharedCredentialRefusal::Read`]) and file uploads
//!   ([`SharedCredentialRefusal::Upload`]) are refused outright.
//!
//! Speech to text stays allowed: the provider stores nothing for it.
//!
//! This rule overlaps the metering rule ([`crate::pipes::metering`]) on
//! purpose; they answer different questions. Metering follows the key's
//! source: while a budget is in scope it refuses a platform-key call whose
//! spend Agent Stream cannot price, on any surface, appliance-wide ones too.
//! This rule follows ownership: budget or not, it refuses a call that would
//! reach the store other tenants share through a credential the surface's
//! tenant does not own (a forwarded identity token on a tenant's surface
//! included). Both run before anything is sent, in this order: a spent budget,
//! then metering, then this rule. So where a budget is in scope (always, on
//! Boris) a tenant's file read, upload or batch on the operator's key gets the
//! metering code, and this rule's codes are seen there only for a call
//! metering admits, such as a chat completion naming a stored file. Where no
//! budget is in scope this rule is what holds.

use serde_json::Value;

/// Why a call through a shared credential was refused before it was sent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SharedCredentialRefusal {
    /// A file or batch read (list, retrieval, content) through the GET
    /// passthrough.
    Read,
    /// A file upload (`POST /v1/files`).
    Upload,
    /// A JSON call to an endpoint outside the inference allowlist, or whose
    /// body names a provider-stored object.
    Call,
}

impl SharedCredentialRefusal {
    /// The stable error code the caller receives with the 403.
    pub fn code(self) -> &'static str {
        match self {
            Self::Read => "shared_credential_read_refused",
            Self::Upload => "shared_credential_upload_refused",
            Self::Call => "shared_credential_call_refused",
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Read => {
                "This surface cannot read provider files or batches through a provider key shared with other tenants"
            }
            Self::Upload => "This surface cannot upload files through a provider key shared with other tenants",
            Self::Call => {
                "Through a provider key shared with other tenants this surface runs only inference calls that name no provider-stored file, response, conversation, vector store or batch"
            }
        }
    }
}

impl std::fmt::Display for SharedCredentialRefusal {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// The stateless endpoints a caller may name through a shared credential, each
/// also accepted with a leading `/v1`: inference, text to speech, image
/// generation and moderations. None of them reads a stored object by path;
/// image edits and variations are left out because they can name stored files.
const INFERENCE_PATHS: &[&str] = &[
    "/chat/completions",
    "/completions",
    "/responses",
    "/embeddings",
    "/messages",
    "/audio/speech",
    "/images/generations",
    "/moderations",
];

/// Whether `suffix`, the path a caller appended to the provider's endpoint, is
/// a stateless endpoint that reads no stored object: chat completions,
/// completions, responses, embeddings, messages, text to speech, image
/// generation and moderations (each bare or under `/v1`), or a Gemini
/// `models/{model}:generateContent` / `:streamGenerateContent` (bare, under
/// `/v1` or under `/v1beta`). Streaming uses the same paths (`"stream": true`)
/// or `:streamGenerateContent`. An exact match, so a dot segment, an encoded
/// character or any other endpoint is refused. An empty suffix sends to the
/// endpoint the operator configured and is allowed. The body is checked
/// separately ([`names_stored_object`]) whatever the path.
pub fn is_inference_path(suffix: &str) -> bool {
    if suffix.is_empty() || suffix == "/" {
        return true;
    }
    let path = suffix
        .strip_suffix('/')
        .unwrap_or(suffix);
    let unversioned = |prefixes: &[&str]| {
        prefixes
            .iter()
            .find_map(|prefix| {
                path.strip_prefix(prefix)
                    .filter(|rest| rest.starts_with('/'))
            })
            .unwrap_or(path)
    };
    INFERENCE_PATHS.contains(&unversioned(&["/v1"])) || is_generate_content_path(unversioned(&["/v1beta", "/v1"]))
}

fn is_generate_content_path(path: &str) -> bool {
    let Some((model, method)) = path
        .strip_prefix("/models/")
        .and_then(|rest| rest.split_once(':'))
    else {
        return false;
    };
    model
        .bytes()
        .any(|b| b.is_ascii_alphanumeric())
        && model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        && matches!(method, "generateContent" | "streamGenerateContent")
}

/// Keys that name a provider-stored object wherever they appear: files
/// (OpenAI and Anthropic `file_id`, Gemini `file_uri`), vector stores, stored
/// responses, batches, Gemini cached content and the Gemini file search tool
/// over its file search stores.
///
/// A denylist: a new provider field that names a stored object must be added
/// here (or to [`STORED_OBJECT_TYPES`]) before it is refused.
const STORED_OBJECT_KEYS: &[&str] = &[
    "file_id",
    "file_ids",
    "file_uri",
    "fileUri",
    "previous_response_id",
    "vector_store_id",
    "vector_store_ids",
    "batch_id",
    "cached_content",
    "cachedContent",
    "file_search",
    "fileSearch",
    "file_search_store_names",
    "fileSearchStoreNames",
];

/// Part and tool types that read a provider store: a reference to a stored
/// conversation item, and the file search tool over vector stores.
const STORED_OBJECT_TYPES: &[&str] = &["item_reference", "file_search"];

/// Keys whose values are JSON Schema the caller defines (function tool
/// parameters, structured-output schemas), never references to stored
/// objects, so a property named `file_id` there is not a reference.
const SCHEMA_KEYS: &[&str] = &["parameters", "input_schema", "schema"];

/// Whether a request body names a provider-stored object: any
/// [`STORED_OBJECT_KEYS`] key outside a JSON Schema, a part or tool whose
/// `type` is in [`STORED_OBJECT_TYPES`], a `container` given by id (an OpenAI
/// code interpreter or Anthropic code execution container, which holds files),
/// a skill other than an Anthropic built-in (a custom skill stored per
/// workspace), a top-level `conversation` (a stored Responses conversation),
/// or a top-level `prompt` object with an `id` (a stored prompt). Inline
/// content (`file_data`, `image_url`, `input_audio`, a `file_url` the provider
/// fetches) names nothing stored.
pub fn names_stored_object(body: &Value) -> bool {
    if let Some(object) = body.as_object() {
        if object.contains_key("conversation") {
            return true;
        }
        if object
            .get("prompt")
            .and_then(Value::as_object)
            .is_some_and(|prompt| prompt.contains_key("id"))
        {
            return true;
        }
    }
    references_stored_object(body)
}

fn references_stored_object(value: &Value) -> bool {
    match value {
        Value::Object(object) => {
            if object
                .get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| STORED_OBJECT_TYPES.contains(&kind))
            {
                return true;
            }
            if is_custom_skill(object) {
                return true;
            }
            object
                .iter()
                .any(|(key, value)| {
                    let is_stored_object_key = STORED_OBJECT_KEYS.contains(&key.as_str());
                    let is_stored_container = key == "container" && names_container(value);
                    let is_schema_key = SCHEMA_KEYS.contains(&key.as_str());
                    is_stored_object_key || is_stored_container || (!is_schema_key && references_stored_object(value))
                })
        }
        Value::Array(items) => items
            .iter()
            .any(references_stored_object),
        _ => false,
    }
}

/// Whether a `container` value names an existing container: an id string, or
/// an object with an `id`. `{ "type": "auto" }` asks for a new one; its
/// `file_ids` are caught as a stored-object key.
fn names_container(value: &Value) -> bool {
    value.is_string()
        || value
            .as_object()
            .is_some_and(|container| container.contains_key("id"))
}

/// Whether `object` is a skill reference other than an Anthropic built-in
/// (`"type": "anthropic"`): a custom skill is stored per workspace.
fn is_custom_skill(object: &serde_json::Map<String, Value>) -> bool {
    object.contains_key("skill_id")
        && object
            .get("type")
            .and_then(Value::as_str)
            != Some("anthropic")
}

/// Admit a JSON call that sends `body` to the provider, where `caller_suffix`
/// is the path the caller appended to the provider's endpoint (`None` when
/// the endpoint is the one configured). Every call through credentials the
/// surface's tenant owns is admitted.
pub fn admit_call(
    credentials_owned: bool,
    caller_suffix: Option<&str>,
    body: &Value,
) -> Result<(), SharedCredentialRefusal> {
    if credentials_owned {
        return Ok(());
    }
    if caller_suffix.is_some_and(|suffix| !is_inference_path(suffix)) || names_stored_object(body) {
        return Err(SharedCredentialRefusal::Call);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn chat(content: Value) -> Value {
        json!({ "model": "gpt-4o", "messages": [{ "role": "user", "content": content }] })
    }

    #[test]
    fn inference_endpoints_are_allowed() {
        for suffix in [
            "",
            "/",
            "/v1/chat/completions",
            "/chat/completions",
            "/v1/chat/completions/",
            "/v1/completions",
            "/v1/responses",
            "/v1/embeddings",
            "/v1/messages",
            "/messages",
            "/v1beta/models/gemini-2.0-flash:generateContent",
            "/v1beta/models/gemini-2.0-flash:streamGenerateContent",
            "/v1/models/gemini-1.5-pro-002:generateContent",
            "/models/gemini-2.0-flash:generateContent",
        ] {
            assert!(is_inference_path(suffix), "{suffix:?}");
        }
    }

    #[test]
    fn stateless_speech_image_and_moderation_endpoints_are_allowed() {
        for suffix in [
            "/v1/audio/speech",
            "/audio/speech",
            "/v1/images/generations",
            "/images/generations",
            "/v1/moderations",
            "/moderations",
            "/v1/moderations/",
        ] {
            assert!(is_inference_path(suffix), "{suffix:?}");
        }
    }

    #[test]
    fn endpoints_that_reach_a_provider_store_are_refused() {
        for suffix in [
            "/v1/files",
            "/v1/vector_stores",
            "/v1/vector_stores/vs_abc/search",
            "/v1/batches",
            "/v1/batches/batch_abc/cancel",
            "/v1/responses/resp_abc/cancel",
            "/v1/conversations",
            "/v1/assistants",
            "/v1/threads/thread_abc/runs",
            "/v1/fine_tuning/jobs",
            "/v1/images/edits",
            "/v1/images/variations",
            "/images/edits",
            "/v1/images/generations/../edits",
            "/v1beta/audio/speech",
            "/v1beta/moderations",
            "/v1/chat/completions/../../v1/vector_stores",
            "/v1/chat/completions/%2e%2e/files",
            "/v1/chat%2fcompletions",
            "/v1/chat/completions;x",
            "/v2/chat/completions",
            "/v1/v1/chat/completions",
            "/v1beta/models/..:generateContent",
            "/v1beta/models/gemini:countTokens",
            "/v1beta/models/:generateContent",
            "/v1beta/cachedContents",
        ] {
            assert!(!is_inference_path(suffix), "{suffix:?}");
        }
    }

    #[test]
    fn plain_and_inline_inference_bodies_name_nothing_stored() {
        for body in [
            chat(json!("hello")),
            chat(json!([{ "type": "text", "text": "a file_id is just words here" }])),
            chat(json!([{ "type": "image_url", "image_url": { "url": "data:image/png;base64,AAAA" } }])),
            chat(
                json!([{ "type": "file", "file": { "filename": "a.pdf", "file_data": "data:application/pdf;base64,AAAA" } }]),
            ),
            json!({ "model": "gpt-4o", "input": [{ "role": "user", "content": [
                { "type": "input_text", "text": "hi" },
                { "type": "input_file", "filename": "a.pdf", "file_data": "data:application/pdf;base64,AAAA" },
                { "type": "input_file", "file_url": "https://example.test/a.pdf" }
            ] }] }),
            json!({ "model": "text-embedding-3-small", "input": ["one", "two"] }),
            json!({ "model": "gpt-4o", "messages": [], "tools": [{ "type": "function", "function": {
                "name": "fetch", "parameters": { "type": "object", "properties": { "file_id": { "type": "string" } } }
            } }] }),
            json!({ "model": "gpt-4o", "messages": [], "response_format": { "type": "json_schema", "json_schema": {
                "name": "out", "schema": { "type": "object", "properties": { "vector_store_ids": { "type": "array" } } }
            } } }),
            json!({ "model": "claude", "messages": [], "tools": [{ "name": "t", "input_schema": {
                "type": "object", "properties": { "batch_id": { "type": "string" } }
            } }] }),
            json!({ "model": "gpt-3.5-turbo-instruct", "prompt": "Say hi" }),
            json!({ "model": "gpt-4o", "input": "hi", "tools": [{ "type": "code_interpreter", "container": { "type": "auto" } }] }),
            json!({ "model": "claude", "messages": [], "container": { "skills": [
                { "type": "anthropic", "skill_id": "pptx", "version": "latest" }
            ] } }),
        ] {
            assert!(!names_stored_object(&body), "{body}");
        }
    }

    #[test]
    fn bodies_that_name_a_stored_object_are_caught() {
        for body in [
            chat(json!([{ "type": "file", "file": { "file_id": "file-abc" } }])),
            json!({ "model": "gpt-4o", "input": [{ "role": "user", "content": [{ "type": "input_file", "file_id": "file-abc" }] }] }),
            json!({ "model": "gpt-4o", "input": [{ "role": "user", "content": [{ "type": "input_image", "file_id": "file-abc" }] }] }),
            json!({ "model": "gpt-4o", "input": "hi", "previous_response_id": "resp_abc" }),
            json!({ "model": "gpt-4o", "input": "hi", "conversation": "conv_abc" }),
            json!({ "model": "gpt-4o", "input": [{ "type": "item_reference", "id": "msg_abc" }] }),
            json!({ "model": "gpt-4o", "input": "hi", "tools": [{ "type": "file_search", "vector_store_ids": ["vs_abc"] }] }),
            json!({ "model": "gpt-4o", "input": "hi", "tools": [{ "type": "file_search" }] }),
            json!({ "model": "gpt-4o", "input": "hi", "tools": [{ "type": "code_interpreter", "container": { "type": "auto", "file_ids": ["file-abc"] } }] }),
            json!({ "model": "gpt-4o", "input": "hi", "prompt": { "id": "pmpt_abc", "version": "2" } }),
            json!({ "name": "store", "file_ids": ["file-abc"] }),
            json!({ "batch_id": "batch_abc" }),
            json!({ "model": "claude", "messages": [{ "role": "user", "content": [
                { "type": "document", "source": { "type": "file", "file_id": "file_abc" } }
            ] }] }),
            json!({ "contents": [{ "parts": [{ "fileData": { "mimeType": "application/pdf", "fileUri": "https://generativelanguage.googleapis.com/v1beta/files/abc" } }] }] }),
            json!({ "contents": [], "cachedContent": "cachedContents/abc" }),
            json!({ "model": "gpt-4o", "input": "hi", "tools": [{ "type": "code_interpreter", "container": "cntr_abc" }] }),
            json!({ "model": "claude", "messages": [], "container": "container_abc" }),
            json!({ "model": "claude", "messages": [], "container": { "id": "container_abc" } }),
            json!({ "model": "claude", "messages": [], "container": { "skills": [
                { "type": "custom", "skill_id": "skill_abc", "version": "latest" }
            ] } }),
            json!({ "contents": [], "tools": [{ "fileSearch": { "fileSearchStoreNames": ["fileSearchStores/abc"] } }] }),
            json!({ "contents": [], "tools": [{ "file_search": { "file_search_store_names": ["fileSearchStores/abc"] } }] }),
        ] {
            assert!(names_stored_object(&body), "{body}");
        }
    }

    #[test]
    fn a_call_through_owned_credentials_is_always_admitted() {
        let stored = chat(json!([{ "type": "file", "file": { "file_id": "file-abc" } }]));
        assert_eq!(admit_call(true, Some("/v1/vector_stores"), &stored), Ok(()));
    }

    #[test]
    fn a_call_through_a_shared_credential_runs_inference_only() {
        let plain = chat(json!("hello"));
        let stored = chat(json!([{ "type": "file", "file": { "file_id": "file-abc" } }]));
        assert_eq!(admit_call(false, Some("/v1/chat/completions"), &plain), Ok(()));
        assert_eq!(admit_call(false, None, &plain), Ok(()));
        assert_eq!(admit_call(false, Some("/v1/vector_stores"), &plain), Err(SharedCredentialRefusal::Call));
        assert_eq!(admit_call(false, Some("/v1/chat/completions"), &stored), Err(SharedCredentialRefusal::Call));
        assert_eq!(admit_call(false, None, &stored), Err(SharedCredentialRefusal::Call));
    }

    #[test]
    fn a_stored_object_body_is_refused_on_every_allowed_path() {
        let stored = json!({ "model": "m", "input": "hi", "file_id": "file-of-another-tenant" });
        for suffix in ["/v1/audio/speech", "/v1/images/generations", "/v1/moderations", "/v1/embeddings"] {
            assert_eq!(admit_call(false, Some(suffix), &stored), Err(SharedCredentialRefusal::Call), "{suffix}");
            assert_eq!(admit_call(false, Some(suffix), &json!({ "model": "m", "input": "hi" })), Ok(()), "{suffix}");
        }
    }
}
