//! Catalog-driven request shaping for LLM calls.
//!
//! A [`ModelRequestProfile`] captures everything the gateway needs to turn a
//! provider-neutral, OpenAI-format request body into a body the upstream model
//! actually accepts: which generation parameters it rejects, which ones must be
//! renamed, which ones must always be present, whether it is a reasoning model,
//! and whether it supports JSON response mode.
//!
//! Profiles are resolved from the LLM provider catalog (`llm.json`) when an
//! entry exists, and fall back to a schema-derived [`builtin_profile`] otherwise,
//! so behaviour degrades gracefully when the catalog is absent or incomplete.
//!
//! Two distinct concerns are kept separate:
//!   * **Parameter rules** ([`ModelRequestProfile::apply_param_rules`]) mutate the
//!     OpenAI-format body in place — alias, strip, then inject — and are schema
//!     agnostic.
//!   * **Wire transforms** ([`shape_request`]) reshape the already-normalised
//!     body into the target vendor's structure (Anthropic Messages, Gemini
//!     generateContent, or OpenAI-compatible passthrough).

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use serde_json::Value;

/// A resolved description of how to shape a request for one model.
#[derive(Debug, Clone, PartialEq)]
pub struct ModelRequestProfile {
    /// Wire format of the upstream: `openai`, `anthropic`, `gemini`, ...
    pub api_schema: String,
    /// Reasoning models reject sampling params and rename `max_tokens`.
    pub reasoning: bool,
    /// Whether the model accepts `response_format: { type: json_object }`.
    pub supports_json_mode: bool,
    /// Whether the model natively enforces `response_format: { type:
    /// json_schema }` (strict structured outputs). When false, a json_schema
    /// request is steered with a system instruction and validated locally.
    pub supports_json_schema: bool,
    /// Whether the model accepts inline **audio input** (an OpenAI `input_audio`
    /// content part, carried to Gemini as an `inline_data` audio part). A model
    /// that cannot understand audio has the request rejected at the front door
    /// rather than leaking the audio upstream or silently dropping it.
    pub supports_audio_input: bool,
    /// Whether the model supports a **realtime** (WebSocket) voice session
    /// (Mode C). Resolved from the catalog (`capabilities.supports_realtime` /
    /// `request_profile.supports_realtime`) else a narrow name-based default.
    pub supports_realtime: bool,
    /// Generation parameters to remove from the body before sending.
    pub unsupported_params: Vec<String>,
    /// Parameter renames applied before stripping (`old -> new`).
    pub param_aliases: BTreeMap<String, String>,
    /// Parameters to inject when absent.
    pub required_params: BTreeMap<String, Value>,
}

impl ModelRequestProfile {
    /// Normalise an OpenAI-format body in place: alias, then strip, then inject.
    ///
    /// Aliasing runs first so a stripped parameter can never resurrect a renamed
    /// one. Injection runs last so required defaults never overwrite caller intent.
    pub fn apply_param_rules(
        &self,
        body: &mut Value,
    ) {
        let Some(obj) = body.as_object_mut() else {
            return;
        };

        for (old, new) in &self.param_aliases {
            if old == new {
                continue;
            }
            if let Some(val) = obj.remove(old.as_str()) {
                obj.entry(new.clone())
                    .or_insert(val);
            }
        }

        for param in &self.unsupported_params {
            obj.remove(param.as_str());
        }

        for (key, value) in &self.required_params {
            obj.entry(key.clone())
                .or_insert_with(|| value.clone());
        }

        // OpenAI Chat Completions only understands the `reasoning_effort`
        // scalar; fold the canonical `reasoning` object into it (or strip it on
        // non-reasoning models). Other schemas keep the object for their own
        // wire transform to map into `thinking` / `thinkingConfig`.
        if self.api_schema == "openai" {
            crate::pipes::reasoning::shape_openai_body(body, self.reasoning);
        }

        // Make `response_format: json_schema` work on every upstream: native
        // schemas keep it; others get a schema system instruction + a JSON-mode
        // downgrade, and the completion is validated after the call.
        crate::pipes::structured_output::shape_body(
            body,
            &self.api_schema,
            self.supports_json_schema,
            self.supports_json_mode,
        );
    }
}

/// Shape a normalised OpenAI-format body for the profile's wire format.
///
/// Applies [`ModelRequestProfile::apply_param_rules`] first, then performs the
/// structural transform for Anthropic / Gemini (OpenAI-compatible passes through).
pub fn shape_request(
    profile: &ModelRequestProfile,
    openai_body: Value,
) -> Value {
    let mut body = openai_body;
    profile.apply_param_rules(&mut body);
    match profile.api_schema.as_str() {
        "anthropic" => transform_to_anthropic_format(body),
        "bedrock-anthropic" => transform_to_bedrock_anthropic_format(body),
        "gemini" => transform_to_gemini_format(body),
        "copilot" => transform_to_copilot_format(body),
        _ => body,
    }
}

/// Bedrock's InvokeModel API takes the Anthropic Messages body, with three differences from the
/// native Anthropic API: the model id travels in the URL (so it must NOT appear in the body),
/// `anthropic_version` is a required BODY field (native Anthropic sends it as a header), and
/// `metadata` and `service_tier` are rejected as extraneous keys.
pub(crate) fn transform_to_bedrock_anthropic_format(request: Value) -> Value {
    let mut body = transform_to_anthropic_format(request);
    if let Some(obj) = body.as_object_mut() {
        obj.remove("model");
        obj.remove("metadata");
        obj.remove("service_tier");
        obj.insert(
            "anthropic_version".to_string(),
            Value::String(crate::pipes::defaults::BEDROCK_ANTHROPIC_VERSION.to_string()),
        );
    }
    body
}

/// Why Claude on Bedrock cannot take an Anthropic Messages body, when it cannot: Bedrock reads
/// image and document sources only inline, never as a `url` or a Files API `file`. Blocks
/// nested in a `tool_result` are checked too.
pub(crate) fn bedrock_unsupported_source(body: &Value) -> Option<&'static str> {
    body.get("messages")?
        .as_array()?
        .iter()
        .filter_map(|m| {
            m.get("content")
                .and_then(Value::as_array)
        })
        .flatten()
        .flat_map(|block| {
            std::iter::once(block).chain(
                block
                    .get("content")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten(),
            )
        })
        .find_map(|block| {
            match block
                .pointer("/source/type")
                .and_then(Value::as_str)
            {
                Some("url") => Some(BEDROCK_URL_SOURCE_UNSUPPORTED),
                Some("file") => Some(BEDROCK_FILE_SOURCE_UNSUPPORTED),
                _ => None,
            }
        })
}

pub(crate) const BEDROCK_URL_SOURCE_UNSUPPORTED: &str =
    "Claude on Bedrock cannot read an image or document given by URL; send it inline as base64";
pub(crate) const BEDROCK_FILE_SOURCE_UNSUPPORTED: &str =
    "Claude on Bedrock cannot read a stored file reference; send the file inline as base64";

/// True when a model is a reasoning model based on the OpenAI naming heuristic.
///
/// Used only as a last resort when the catalog does not declare `reasoning`.
fn is_reasoning_heuristic(
    api_schema: &str,
    model: &str,
) -> bool {
    api_schema == "openai"
        && (model.starts_with("o1") || model.starts_with("o3") || model.starts_with("o4") || model.starts_with("gpt-5"))
}

/// Default JSON-mode support when neither the catalog nor caller declare it.
///
/// OpenAI-compatible endpoints overwhelmingly accept
/// `response_format: { type: "json_object" }`, so the optimistic default is
/// right for almost every model — but it is not free to be wrong. A model that
/// does not accept the parameter answers **HTTP 400**, failing the whole call,
/// where omitting it merely loses a guard rail the caller's prompt already asks
/// for in words. So the small, closed set of OpenAI models that predate JSON
/// mode is excluded by name.
///
/// JSON mode arrived with the `1106` generation (November 2023). Everything
/// older is a frozen snapshot that will never gain it, so this list is complete
/// and does not grow: the undated `gpt-4` / `gpt-3.5-turbo` aliases and their
/// pre-`1106` dated and `32k` / `16k` variants, plus the base and `instruct`
/// completion models, which have no chat JSON mode at all.
fn default_json_mode(
    api_schema: &str,
    model: &str,
) -> bool {
    api_schema == "openai" && !predates_openai_json_mode(model)
}

/// True for an OpenAI model released before JSON mode existed. See
/// [`default_json_mode`].
fn predates_openai_json_mode(model: &str) -> bool {
    // Completion-era models: no chat JSON mode, now or ever.
    if model.starts_with("davinci-") || model.starts_with("babbage-") || model.contains("-instruct") {
        return true;
    }
    let Some(rest) = model
        .strip_prefix("gpt-4")
        .or_else(|| model.strip_prefix("gpt-3.5-turbo"))
    else {
        return false;
    };
    // `gpt-4o*`, `gpt-4.1*`, `gpt-4-turbo*` and the `1106`+ snapshots all have it.
    if rest.starts_with('o') || rest.starts_with('.') || rest.contains("turbo") {
        return false;
    }
    // What is left is the undated alias (""), a `32k`/`16k` variant, or a dated
    // snapshot — of which only the pre-`1106` ones lack JSON mode.
    !["1106", "0125", "2024", "2025"]
        .iter()
        .any(|generation| rest.contains(generation))
}

/// Default native `json_schema` support when the catalog does not declare it.
fn default_json_schema(api_schema: &str) -> bool {
    matches!(api_schema, "openai" | "azure")
}

/// Default audio-input support when the catalog does not declare it. Audio input
/// is a narrow, per-model capability, so the default is conservative: only a
/// model that natively accepts audio defaults to `true`. Gemini is natively
/// multimodal (`inline_data`); OpenAI carries audio only on its audio/realtime
/// models (name contains `audio` or `realtime`) — a generic chat/reasoning model
/// (e.g. `gpt-4o`, `o4-mini`) does not, so the gateway rejects audio with a clear
/// `audio_not_supported` instead of forwarding an `input_audio` block the
/// upstream 400s on. Anthropic has no audio-input wire form. An explicit catalog
/// `supports_audio_input` always overrides this.
fn default_audio_input(
    api_schema: &str,
    model: &str,
) -> bool {
    match api_schema {
        "gemini" => true,
        "anthropic" => false,
        _ => {
            let m = model.to_ascii_lowercase();
            m.contains("audio") || m.contains("realtime")
        }
    }
}

/// Whether a model natively supports a **realtime** (WebSocket) voice session
/// (Mode C). This is an even narrower capability than audio input, so the check
/// is conservative and name-based: OpenAI/Azure `*realtime*` models and Gemini
/// Live models. Everything else — including a plain audio-input model like
/// `gpt-4o-audio-preview`, which speaks Mode A but not the realtime socket —
/// returns `false`, so the gateway refuses the upgrade with a clear reason
/// rather than opening a socket the upstream will drop.
pub fn model_supports_realtime(
    api_schema: &str,
    model: &str,
) -> bool {
    let m = model.to_ascii_lowercase();
    match api_schema {
        "openai" | "azure" => m.contains("realtime"),
        // Gemini Live models: `*-flash-live-*`, `gemini-live-*`, and the
        // `*-native-audio-*` dialog models.
        "gemini" => m.contains("live") || m.contains("native-audio") || m.contains("realtime"),
        _ => false,
    }
}

/// Schema-level defaults that apply before any per-model catalog overrides.
///
/// OpenAI reasoning models rename `max_tokens` and reject sampling parameters.
fn schema_defaults(
    api_schema: &str,
    reasoning: bool,
) -> (Vec<String>, BTreeMap<String, String>) {
    if api_schema == "openai" && reasoning {
        let unsupported = ["temperature", "top_p", "frequency_penalty", "presence_penalty"]
            .into_iter()
            .map(String::from)
            .collect();
        let mut aliases = BTreeMap::new();
        aliases.insert("max_tokens".to_string(), "max_completion_tokens".to_string());
        (unsupported, aliases)
    } else {
        (Vec::new(), BTreeMap::new())
    }
}

/// Combine schema defaults with per-model catalog rules into a final profile.
fn build_profile(
    api_schema: &str,
    reasoning: bool,
    supports_json_mode: bool,
    supports_json_schema: bool,
    supports_audio_input: bool,
    supports_realtime: bool,
    extra_unsupported: Vec<String>,
    extra_aliases: BTreeMap<String, String>,
    required_params: BTreeMap<String, Value>,
) -> ModelRequestProfile {
    let (mut unsupported_params, mut param_aliases) = schema_defaults(api_schema, reasoning);

    for param in extra_unsupported {
        if !unsupported_params.contains(&param) {
            unsupported_params.push(param);
        }
    }
    for (old, new) in extra_aliases {
        param_aliases.insert(old, new);
    }

    ModelRequestProfile {
        api_schema: api_schema.to_string(),
        reasoning,
        supports_json_mode,
        supports_json_schema,
        supports_audio_input,
        supports_realtime,
        unsupported_params,
        param_aliases,
        required_params,
    }
}

/// Build a profile from schema/heuristic alone, with no catalog entry.
pub fn builtin_profile(
    api_schema: &str,
    model: &str,
    supports_json_mode: Option<bool>,
) -> ModelRequestProfile {
    let reasoning = is_reasoning_heuristic(api_schema, model);
    let json_mode = supports_json_mode.unwrap_or_else(|| default_json_mode(api_schema, model));
    build_profile(
        api_schema,
        reasoning,
        json_mode,
        default_json_schema(api_schema),
        default_audio_input(api_schema, model),
        model_supports_realtime(api_schema, model),
        Vec::new(),
        BTreeMap::new(),
        BTreeMap::new(),
    )
}

/// Resolve a profile from raw catalog provider documents.
///
/// `providers` is the `providers` array of `llm.json`, each entry a JSON object
/// keyed by `enum_value` with `api_schema` and a `models` array. Per-model rules
/// live under an optional `request_profile` object; `supports_json_mode` also
/// falls back to the model's `capabilities`. Any missing piece degrades to the
/// schema default or the caller-supplied fallbacks.
pub fn resolve_profile_from_providers(
    providers: &[Value],
    provider_enum: &str,
    model: &str,
    fallback_api_schema: &str,
    fallback_supports_json_mode: Option<bool>,
) -> ModelRequestProfile {
    let provider = providers.iter().find(|p| {
        p.get("enum_value")
            .and_then(|v| v.as_str())
            == Some(provider_enum)
    });

    let api_schema = provider
        .and_then(|p| {
            p.get("api_schema")
                .and_then(|v| v.as_str())
        })
        .unwrap_or(fallback_api_schema)
        .to_string();

    let model_entry = provider
        .and_then(|p| {
            p.get("models")
                .and_then(|m| m.as_array())
        })
        .and_then(|models| {
            models.iter().find(|m| {
                m.get("value")
                    .and_then(|v| v.as_str())
                    == Some(model)
            })
        });

    let request_profile = model_entry.and_then(|m| m.get("request_profile"));

    let reasoning = request_profile
        .and_then(|r| r.get("reasoning"))
        .and_then(|v| v.as_bool())
        .unwrap_or_else(|| is_reasoning_heuristic(&api_schema, model));

    let supports_json_mode = request_profile
        .and_then(|r| r.get("supports_json_mode"))
        .and_then(|v| v.as_bool())
        .or_else(|| {
            model_entry
                .and_then(|m| m.get("capabilities"))
                .and_then(|c| c.get("supports_json_mode"))
                .and_then(|v| v.as_bool())
        })
        .or(fallback_supports_json_mode)
        .unwrap_or_else(|| default_json_mode(&api_schema, model));

    let supports_json_schema = request_profile
        .and_then(|r| r.get("supports_json_schema"))
        .and_then(|v| v.as_bool())
        .or_else(|| {
            model_entry
                .and_then(|m| m.get("capabilities"))
                .and_then(|c| c.get("supports_json_schema"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or_else(|| default_json_schema(&api_schema));

    let supports_audio_input = request_profile
        .and_then(|r| r.get("supports_audio_input"))
        .and_then(|v| v.as_bool())
        .or_else(|| {
            model_entry
                .and_then(|m| m.get("capabilities"))
                .and_then(|c| c.get("supports_audio_input"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or_else(|| default_audio_input(&api_schema, model));

    let supports_realtime = request_profile
        .and_then(|r| r.get("supports_realtime"))
        .and_then(|v| v.as_bool())
        .or_else(|| {
            model_entry
                .and_then(|m| m.get("capabilities"))
                .and_then(|c| c.get("supports_realtime"))
                .and_then(|v| v.as_bool())
        })
        .unwrap_or_else(|| model_supports_realtime(&api_schema, model));

    let extra_unsupported = request_profile
        .and_then(|r| r.get("unsupported_params"))
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    let extra_aliases = request_profile
        .and_then(|r| r.get("param_aliases"))
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| {
                    v.as_str()
                        .map(|s| (k.clone(), s.to_string()))
                })
                .collect()
        })
        .unwrap_or_default();

    let required_params = request_profile
        .and_then(|r| r.get("required_params"))
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        })
        .unwrap_or_default();

    build_profile(
        &api_schema,
        reasoning,
        supports_json_mode,
        supports_json_schema,
        supports_audio_input,
        supports_realtime,
        extra_unsupported,
        extra_aliases,
        required_params,
    )
}

/// Convert an OpenAI `content` value into Gemini `parts`. Text stays text; an
/// inline image (`image_url` data URL) and an `input_audio` part become
/// `inline_data` blobs. Remote image URLs (which Gemini cannot inline) and
/// unknown parts are dropped.
fn openai_content_to_gemini_parts(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(s)) => {
            if s.is_empty() {
                Vec::new()
            } else {
                vec![serde_json::json!({ "text": s })]
            }
        }
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(gemini_part_from_openai)
            .collect(),
        _ => Vec::new(),
    }
}

/// Convert one OpenAI content part into a Gemini part.
fn gemini_part_from_openai(part: &Value) -> Option<Value> {
    match part
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("text") => {
            let text = part
                .get("text")
                .and_then(|t| t.as_str())
                .unwrap_or("");
            (!text.is_empty()).then(|| serde_json::json!({ "text": text }))
        }
        Some("image_url") => {
            let url = part
                .get("image_url")
                .and_then(|i| i.get("url"))
                .and_then(|u| u.as_str())?;
            gemini_inline_data_from_data_url(url)
        }
        Some("input_audio") => {
            let audio = part.get("input_audio")?;
            let data = audio
                .get("data")
                .and_then(|d| d.as_str())?;
            if let Some(inline) = gemini_inline_data_from_data_url(data) {
                return Some(inline);
            }
            let mime = gemini_audio_mime(
                audio
                    .get("format")
                    .and_then(|f| f.as_str()),
            );
            Some(serde_json::json!({ "inline_data": { "mime_type": mime, "data": data } }))
        }
        _ => None,
    }
}

/// Parse a `data:{mime};base64,{payload}` URL into a Gemini `inline_data` part.
/// Returns `None` for a non-data URL (e.g. a remote image Gemini cannot inline).
fn gemini_inline_data_from_data_url(url: &str) -> Option<Value> {
    let rest = url.strip_prefix("data:")?;
    let (meta, payload) = rest.split_once(',')?;
    let mime = meta
        .split(';')
        .next()
        .filter(|m| !m.is_empty())
        .unwrap_or("application/octet-stream");
    Some(serde_json::json!({ "inline_data": { "mime_type": mime, "data": payload } }))
}

/// Gemini audio MIME from an OpenAI `input_audio.format` (`wav` → `audio/wav`,
/// `mp3` → `audio/mp3`).
fn gemini_audio_mime(format: Option<&str>) -> String {
    match format
        .map(|f| f.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("mp3") | Some("mpeg") => "audio/mp3".to_string(),
        Some("") | None => "audio/wav".to_string(),
        Some(other) => format!("audio/{other}"),
    }
}

/// Transform an OpenAI-format request to Google Gemini generateContent format.
///
/// OpenAI: { messages: [{role, content}], temperature, max_tokens, top_p }
/// Gemini: { contents: [{role, parts: [{text}]}], generationConfig: {temperature, maxOutputTokens, topP} }
///
/// System messages are prepended as a user message in contents.
pub(crate) fn transform_to_gemini_format(request: Value) -> Value {
    let mut gemini_request = serde_json::json!({});

    if let Some(messages) = request
        .get("messages")
        .and_then(|m| m.as_array())
    {
        let mut contents = Vec::new();

        for msg in messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user");

            // Map OpenAI roles to Gemini roles:
            // system → user (Gemini has no system role, prepend as user context)
            // assistant → model
            // user → user
            let gemini_role = match role {
                "assistant" => "model",
                _ => "user",
            };
            let mut parts = openai_content_to_gemini_parts(msg.get("content"));
            // Gemini requires each content to carry at least one part.
            if parts.is_empty() {
                parts.push(serde_json::json!({ "text": "" }));
            }
            contents.push(serde_json::json!({
                "role": gemini_role,
                "parts": parts
            }));
        }

        gemini_request["contents"] = Value::Array(contents);
    }

    // Build generationConfig from OpenAI parameters
    let mut gen_config = serde_json::Map::new();
    if let Some(temp) = request.get("temperature") {
        gen_config.insert("temperature".to_string(), temp.clone());
    }
    if let Some(max_tokens) = request.get("max_tokens") {
        gen_config.insert("maxOutputTokens".to_string(), max_tokens.clone());
    }
    if let Some(top_p) = request.get("top_p") {
        gen_config.insert("topP".to_string(), top_p.clone());
    }
    if let Some(thinking) = crate::pipes::reasoning::gemini_thinking_config(&request) {
        gen_config.insert("thinkingConfig".to_string(), thinking);
    }
    if !gen_config.is_empty() {
        gemini_request["generationConfig"] = Value::Object(gen_config);
    }

    gemini_request
}

/// Default IANA time zone sent as the Copilot `locationHint`. The Chat API
/// requires a `locationHint`; UTC is a safe, location-neutral default.
const DEFAULT_COPILOT_TIME_ZONE: &str = "UTC";

/// Transform a normalised OpenAI-format chat body into a Microsoft 365 Copilot
/// Chat API request body.
///
/// The Copilot Chat API takes a single natural-language prompt plus optional
/// grounding context, not an OpenAI `messages` array. We map the **last user**
/// message to `message.text` (the prompt Copilot answers), and every other
/// message (system instructions and prior turns) to `additionalContext` entries
/// so they still ground the answer. A `locationHint` is always included because
/// the Chat API requires it. Sampling parameters are dropped — Copilot does not
/// accept them.
pub fn transform_to_copilot_format(openai_body: Value) -> Value {
    transform_to_copilot_format_with(openai_body, true)
}

/// Copilot request transform with control over history replay.
///
/// `include_history = true` (default, a **fresh** conversation): the final user
/// message becomes `message.text` and every other message (system + prior
/// turns) becomes `additionalContext` grounding, so a stateless one-shot call
/// still carries the whole thread.
///
/// `include_history = false` (a **reused** conversation): the Copilot
/// conversation already holds the prior turns server-side, so only the final
/// user message is sent as `message.text` with no `additionalContext` — this is
/// what gives true multi-turn memory (e.g. the sandbox reusing a conversation
/// id across follow-ups) without re-sending / duplicating the history.
pub fn transform_to_copilot_format_with(
    openai_body: Value,
    include_history: bool,
) -> Value {
    let messages = openai_body
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
        .unwrap_or_default();

    // Locate the final user message: that is the prompt Copilot should answer.
    let last_user_idx = messages
        .iter()
        .rposition(|m| {
            m.get("role")
                .and_then(|r| r.as_str())
                == Some("user")
        });

    let prompt_text = last_user_idx
        .map(|i| openai_content_to_text(messages[i].get("content")))
        .unwrap_or_default();

    // Every other message becomes extra grounding context, prefixed with its
    // role so Copilot can tell system instructions from prior turns. Skipped
    // entirely when the conversation is reused (Copilot already has the turns).
    let mut additional_context: Vec<Value> = Vec::new();
    if include_history {
        for (i, message) in messages.iter().enumerate() {
            if Some(i) == last_user_idx {
                continue;
            }
            let role = message
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user");
            let text = openai_content_to_text(message.get("content"));
            if !text.trim().is_empty() {
                additional_context.push(serde_json::json!({ "text": format!("{}: {}", role, text) }));
            }
        }
    }

    let mut body = serde_json::json!({
        "message": { "text": prompt_text },
        "locationHint": { "timeZone": DEFAULT_COPILOT_TIME_ZONE },
    });
    if !additional_context.is_empty() {
        body["additionalContext"] = Value::Array(additional_context);
    }
    body
}

/// Flatten an OpenAI message `content` field (string or content-part array)
/// into plain text, keeping only `text` parts.
fn openai_content_to_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(parts)) => parts
            .iter()
            .filter_map(|part| {
                if part
                    .get("type")
                    .and_then(|t| t.as_str())
                    == Some("text")
                {
                    part.get("text")
                        .and_then(|t| t.as_str())
                } else {
                    part.as_str()
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// True when any content part carries an Anthropic `cache_control` breakpoint.
fn content_has_cache_control(content: Option<&Value>) -> bool {
    matches!(
        content,
        Some(Value::Array(parts)) if parts.iter().any(|p| p.get("cache_control").is_some())
    )
}

/// Convert an OpenAI `content` field into Anthropic content blocks, in order,
/// preserving any `cache_control` breakpoints so provider prompt caching works.
///
/// Each part maps through [`anthropic_block_from_openai_part`]: `text` parts
/// become `text` blocks, `image_url` parts `image` blocks, and `file` parts
/// `image` or `document` blocks (see [`anthropic_file_block`]). A part that
/// cannot be expressed (an unknown type, a malformed data URL, a URL that is
/// neither `data:` nor http(s), a file type Claude does not read) is dropped.
/// Content that yields only text and carries no breakpoint collapses to a
/// single text block, so plain requests keep their flattened form.
fn openai_content_to_anthropic_blocks(content: Option<&Value>) -> Vec<Value> {
    match content {
        Some(Value::String(s)) if !s.is_empty() => {
            vec![serde_json::json!({ "type": "text", "text": s })]
        }
        Some(Value::Array(parts)) => {
            let blocks: Vec<Value> = parts
                .iter()
                .filter_map(anthropic_block_from_openai_part)
                .collect();
            let text_only = blocks.iter().all(|b| {
                b.get("type")
                    .and_then(Value::as_str)
                    == Some("text")
            });
            if !text_only || content_has_cache_control(content) {
                return blocks;
            }
            let text: String = blocks
                .iter()
                .filter_map(|b| {
                    b.get("text")
                        .and_then(Value::as_str)
                })
                .collect();
            if text.is_empty() {
                Vec::new()
            } else {
                vec![serde_json::json!({ "type": "text", "text": text })]
            }
        }
        _ => Vec::new(),
    }
}

/// Convert one OpenAI content part into an Anthropic content block, carrying
/// its `cache_control`. `None` for a part Anthropic cannot take.
fn anthropic_block_from_openai_part(part: &Value) -> Option<Value> {
    let mut block = match part
        .get("type")
        .and_then(Value::as_str)
    {
        Some("text") => {
            let text = part
                .get("text")
                .and_then(Value::as_str)
                .filter(|t| !t.is_empty())?;
            serde_json::json!({ "type": "text", "text": text })
        }
        Some("image_url") => {
            let url = part
                .get("image_url")
                .and_then(|i| i.get("url"))
                .and_then(Value::as_str)?;
            anthropic_image_block(url)?
        }
        Some("file") => anthropic_file_block(part.get("file")?)?,
        None => {
            let text = part
                .as_str()
                .filter(|t| !t.is_empty())?;
            return Some(serde_json::json!({ "type": "text", "text": text }));
        }
        _ => return None,
    };
    if let Some(cache_control) = part.get("cache_control") {
        block["cache_control"] = cache_control.clone();
    }
    Some(block)
}

/// An Anthropic `image` block for an OpenAI `image_url`: a base64 `data:` URL
/// is sent inline, and an http(s) URL is handed to Anthropic to fetch (the
/// gateway never fetches it). Any other scheme is dropped.
fn anthropic_image_block(url: &str) -> Option<Value> {
    if is_http_url(url) {
        return Some(serde_json::json!({ "type": "image", "source": { "type": "url", "url": url } }));
    }
    let (mime, data) = parse_base64_data_url(url)?;
    let media_type = if mime == "image/jpg" {
        "image/jpeg".to_string()
    } else {
        mime
    };
    Some(serde_json::json!({
        "type": "image",
        "source": { "type": "base64", "media_type": media_type, "data": data }
    }))
}

/// An Anthropic block for an OpenAI `file` part's `file` object. Inline
/// `file_data` becomes what Claude reads it as: an `image` block for a JPEG,
/// PNG, GIF or WebP image, a `document` with a plain-text `text` source for a
/// text-like file, or a `document` with a `base64` source for a PDF; any other
/// type is dropped (see [`claude_unreadable_file`], which refuses it first). A
/// `file_id` becomes a `document` with a Files API `file` source. The
/// `filename` becomes a document's `title`.
fn anthropic_file_block(file: &Value) -> Option<Value> {
    let source = match file
        .get("file_data")
        .and_then(Value::as_str)
    {
        Some(file_data) => {
            let (mime, data) = parse_base64_data_url(file_data)?;
            if let Some(media_type) = claude_image_media_type(&mime) {
                return Some(serde_json::json!({
                    "type": "image",
                    "source": { "type": "base64", "media_type": media_type, "data": data }
                }));
            }
            if is_text_like_mime(&mime) {
                serde_json::json!({ "type": "text", "media_type": "text/plain", "data": inline_file_text(data)? })
            } else if mime == PDF_MIME {
                serde_json::json!({ "type": "base64", "media_type": mime, "data": data })
            } else {
                return None;
            }
        }
        None => {
            let file_id = file
                .get("file_id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())?;
            serde_json::json!({ "type": "file", "file_id": file_id })
        }
    };
    let mut block = serde_json::json!({ "type": "document", "source": source });
    if let Some(title) = file
        .get("filename")
        .and_then(Value::as_str)
        .filter(|t| !t.is_empty())
    {
        block["title"] = Value::String(title.to_string());
    }
    Some(block)
}

/// Split a `data:<mime>;base64,<payload>` URL into its lower-cased MIME and
/// payload. `None` unless it names a MIME, is base64-encoded and has a payload.
fn parse_base64_data_url(url: &str) -> Option<(String, &str)> {
    let (meta, payload) = url
        .strip_prefix("data:")?
        .split_once(',')?;
    let mut params = meta.split(';');
    let mime = params
        .next()?
        .trim()
        .to_ascii_lowercase();
    let is_base64 = params.any(|p| {
        p.trim()
            .eq_ignore_ascii_case("base64")
    });
    let payload = payload.trim();
    (is_base64 && mime.contains('/') && !payload.is_empty()).then_some((mime, payload))
}

/// The `content` of an Anthropic `tool_result`: the flattened text, or the
/// block array when the tool's output carries an image or document.
fn anthropic_tool_result_content(content: Option<&Value>) -> Value {
    let blocks = openai_content_to_anthropic_blocks(content);
    if blocks.iter().any(|b| {
        b.get("type")
            .and_then(Value::as_str)
            != Some("text")
    }) {
        Value::Array(blocks)
    } else {
        Value::String(openai_content_to_text(content))
    }
}

fn is_http_url(url: &str) -> bool {
    let lower = url
        .get(..8)
        .unwrap_or(url)
        .to_ascii_lowercase();
    lower.starts_with("https://") || lower.starts_with("http://")
}

fn is_text_like_mime(mime: &str) -> bool {
    mime.starts_with("text/") || mime == "application/json"
}

/// The text of a text-like file's base64 payload, when it decodes to UTF-8.
fn inline_file_text(data: &str) -> Option<String> {
    String::from_utf8(BASE64.decode(data).ok()?).ok()
}

const PDF_MIME: &str = "application/pdf";

/// The media type Claude takes for an inline image of this MIME, if it reads it.
fn claude_image_media_type(mime: &str) -> Option<&'static str> {
    match mime {
        "image/jpeg" | "image/jpg" => Some("image/jpeg"),
        "image/png" => Some("image/png"),
        "image/gif" => Some("image/gif"),
        "image/webp" => Some("image/webp"),
        _ => None,
    }
}

pub(crate) const CLAUDE_UNREADABLE_FILE: &str = "Claude reads an attached file only as a PDF, plain text, or a JPEG, PNG, \
     GIF or WebP image; extract other documents with the Surface's document ingestion, or convert them first";

/// Why Claude cannot take an OpenAI-canonical body, when it attaches an inline
/// `file` Claude cannot read (a DOCX, a spreadsheet, an unrecognised binary, a
/// text file that is not base64-encoded UTF-8, or a malformed data URL). Checked before an Anthropic call, so the request is
/// refused rather than answered as if nothing was attached.
pub(crate) fn claude_unreadable_file(body: &Value) -> Option<&'static str> {
    body.get("messages")?
        .as_array()?
        .iter()
        .filter_map(|m| {
            m.get("content")
                .and_then(Value::as_array)
        })
        .flatten()
        .filter(|part| {
            part.get("type")
                .and_then(Value::as_str)
                == Some("file")
        })
        .filter_map(|part| {
            part.pointer("/file/file_data")
                .and_then(Value::as_str)
        })
        .any(|file_data| match parse_base64_data_url(file_data) {
            Some((mime, data)) if is_text_like_mime(&mime) => inline_file_text(data).is_none(),
            Some((mime, _)) => claude_image_media_type(&mime).is_none() && mime != PDF_MIME,
            None => true,
        })
        .then_some(CLAUDE_UNREADABLE_FILE)
}

/// Append a content block to the Anthropic `messages` array, merging into the
/// previous message when it shares the same role. Anthropic requires strictly
/// alternating user/assistant turns, so consecutive same-role blocks (e.g. two
/// `tool_result`s, or a `tool_result` followed by the next user turn) must live
/// in one message.
fn push_anthropic_block(
    messages: &mut Vec<Value>,
    role: &str,
    block: Value,
) {
    if let Some(last) = messages.last_mut()
        && last
            .get("role")
            .and_then(|r| r.as_str())
            == Some(role)
        && let Some(arr) = last
            .get_mut("content")
            .and_then(|c| c.as_array_mut())
    {
        arr.push(block);
        return;
    }
    messages.push(serde_json::json!({ "role": role, "content": [block] }));
}

/// Convert an OpenAI tool definition to Anthropic's tool shape.
///
/// OpenAI: `{ "type": "function", "function": { name, description, parameters } }`
/// Anthropic: `{ name, description, input_schema }`
fn openai_tool_to_anthropic(tool: &Value) -> Option<Value> {
    let function = tool
        .get("function")
        .unwrap_or(tool);
    let name = function
        .get("name")
        .and_then(|v| v.as_str())?;
    let description = function
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let input_schema = function
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} }));
    Some(serde_json::json!({
        "name": name,
        "description": description,
        "input_schema": input_schema,
    }))
}

/// Convert an OpenAI `tool_choice` into Anthropic's object form.
///
/// Returns `None` when the choice should be omitted entirely (OpenAI `"none"`
/// has no direct Anthropic equivalent short of removing the tools, so the field
/// is simply dropped and the model defaults to auto).
fn openai_tool_choice_to_anthropic(choice: &Value) -> Option<Value> {
    match choice {
        Value::String(s) => match s.as_str() {
            "required" | "any" => Some(serde_json::json!({ "type": "any" })),
            "none" => None,
            // "auto" and any unknown string fall back to Anthropic's auto.
            _ => Some(serde_json::json!({ "type": "auto" })),
        },
        Value::Object(_) => {
            if let Some(name) = choice
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
            {
                Some(serde_json::json!({ "type": "tool", "name": name }))
            } else {
                match choice
                    .get("type")
                    .and_then(|t| t.as_str())
                {
                    Some("any") | Some("required") => Some(serde_json::json!({ "type": "any" })),
                    Some("none") => None,
                    _ => Some(serde_json::json!({ "type": "auto" })),
                }
            }
        }
        _ => None,
    }
}

/// Transform an OpenAI-format request to Anthropic Messages format.
///
/// System messages are lifted to a top-level `system` field (text only); user
/// images and documents become `image` and `document` blocks in their original
/// order (see [`openai_content_to_anthropic_blocks`]); assistant
/// `tool_calls` become `tool_use` content blocks and `role: "tool"` messages
/// become `user` `tool_result` blocks (with consecutive same-role turns merged
/// to satisfy Anthropic's strict role alternation); OpenAI `tools`/`tool_choice`
/// are rewritten to Anthropic's shapes; `max_tokens` is guaranteed present
/// (Anthropic requires it); and OpenAI-only fields (including `stream`, which
/// would otherwise force SSE on the buffered path) are removed.
pub(crate) fn transform_to_anthropic_format(mut request: Value) -> Value {
    // Map canonical reasoning → Anthropic `thinking` before reshaping messages,
    // so `max_tokens` headroom and the sampling-param drops are in effect.
    crate::pipes::reasoning::shape_anthropic_body(&mut request);
    upgrade_legacy_functions(&mut request);
    if let Some(messages) = request
        .get("messages")
        .and_then(|m| m.as_array())
        .cloned()
    {
        let mut system_parts: Vec<String> = Vec::new();
        let mut system_blocks: Vec<Value> = Vec::new();
        let mut system_has_cache_control = false;
        let mut anthropic_messages: Vec<Value> = Vec::new();

        for msg in &messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user");
            match role {
                "system" => {
                    if content_has_cache_control(msg.get("content")) {
                        system_has_cache_control = true;
                    }
                    system_blocks.extend(
                        openai_content_to_anthropic_blocks(msg.get("content"))
                            .into_iter()
                            .filter(|b| {
                                b.get("type")
                                    .and_then(Value::as_str)
                                    == Some("text")
                            }),
                    );
                    let text = openai_content_to_text(msg.get("content"));
                    if !text.is_empty() {
                        system_parts.push(text);
                    }
                }
                "tool" => {
                    let tool_use_id = msg
                        .get("tool_call_id")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    let block = serde_json::json!({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": anthropic_tool_result_content(msg.get("content")),
                    });
                    push_anthropic_block(&mut anthropic_messages, "user", block);
                }
                "assistant" => {
                    for block in openai_content_to_anthropic_blocks(msg.get("content")) {
                        push_anthropic_block(&mut anthropic_messages, "assistant", block);
                    }
                    if let Some(tool_calls) = msg
                        .get("tool_calls")
                        .and_then(|t| t.as_array())
                    {
                        for tc in tool_calls {
                            let id = tc
                                .get("id")
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let function = tc.get("function");
                            let name = function
                                .and_then(|f| f.get("name"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("")
                                .to_string();
                            let args = function
                                .and_then(|f| f.get("arguments"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("{}");
                            let input: Value = serde_json::from_str(args).unwrap_or_else(|_| serde_json::json!({}));
                            push_anthropic_block(
                                &mut anthropic_messages,
                                "assistant",
                                serde_json::json!({
                                    "type": "tool_use",
                                    "id": id,
                                    "name": name,
                                    "input": input,
                                }),
                            );
                        }
                    }
                }
                _ => {
                    for block in openai_content_to_anthropic_blocks(msg.get("content")) {
                        push_anthropic_block(&mut anthropic_messages, "user", block);
                    }
                }
            }
        }

        // Preserve `cache_control` breakpoints on the system prompt by emitting
        // a block array; otherwise keep the flattened string form.
        if system_has_cache_control {
            request["system"] = Value::Array(system_blocks);
        } else if !system_parts.is_empty() {
            request["system"] = Value::String(system_parts.join("\n\n"));
        }
        request["messages"] = Value::Array(anthropic_messages);
    }

    // Anthropic requires max_tokens — ensure it's present
    if request
        .get("max_tokens")
        .is_none()
    {
        // Check for OpenAI's max_completion_tokens alias
        if let Some(max) = request
            .get("max_completion_tokens")
            .cloned()
        {
            request["max_tokens"] = max;
        } else {
            // Default to 4096 if not specified
            request["max_tokens"] = Value::Number(serde_json::Number::from(4096));
        }
    }

    // Convert OpenAI tools → Anthropic tools
    if let Some(tools) = request
        .get("tools")
        .and_then(|t| t.as_array())
        .cloned()
    {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(openai_tool_to_anthropic)
            .collect();
        if converted.is_empty() {
            if let Some(obj) = request.as_object_mut() {
                obj.remove("tools");
            }
        } else {
            request["tools"] = Value::Array(converted);
        }
    }

    // Convert OpenAI tool_choice → Anthropic object form (or drop it)
    if let Some(choice) = request
        .get("tool_choice")
        .cloned()
    {
        match openai_tool_choice_to_anthropic(&choice) {
            Some(v) => request["tool_choice"] = v,
            None => {
                if let Some(obj) = request.as_object_mut() {
                    obj.remove("tool_choice");
                }
            }
        }
    }

    // OpenAI `stop` → Anthropic `stop_sequences` (a string or array of strings).
    // Anthropic rejects an unknown `stop` field, so it must be renamed.
    if let Some(stop) = request.get("stop").cloned() {
        let seqs = match stop {
            Value::String(s) => vec![Value::String(s)],
            Value::Array(a) => a,
            _ => Vec::new(),
        };
        if let Some(obj) = request.as_object_mut() {
            obj.remove("stop");
            if !seqs.is_empty() {
                obj.insert("stop_sequences".to_string(), Value::Array(seqs));
            }
        }
    }

    // Remove OpenAI-only fields Anthropic rejects, and `stream`/`stream_options`
    // which would otherwise force an SSE response on the buffered path.
    if let Some(obj) = request.as_object_mut() {
        shape_anthropic_metadata(obj);
        shape_anthropic_service_tier(obj);
        for key in [
            "response_format",
            "max_completion_tokens",
            "stream",
            "stream_options",
            "parallel_tool_calls",
            "n",
            "seed",
            "logprobs",
            "top_logprobs",
            "logit_bias",
            "frequency_penalty",
            "presence_penalty",
            "store",
            "modalities",
            "audio",
            "prediction",
            "web_search_options",
            "safety_identifier",
            "prompt_cache_key",
            "verbosity",
        ] {
            obj.remove(key);
        }
    }

    request
}

/// Rewrite OpenAI's legacy function calling as tools, so it reaches Anthropic
/// as tools rather than as fields Anthropic rejects: `functions` becomes
/// `tools` and `function_call` becomes `tool_choice` (each only when the
/// modern field is absent), an assistant `function_call` becomes a one-entry
/// `tool_calls`, and a `role: "function"` result becomes a `role: "tool"`
/// message answering the latest call of that name. Legacy calls carry no id,
/// so each gets one derived from its message's position.
fn upgrade_legacy_functions(request: &mut Value) {
    let Some(obj) = request.as_object_mut() else {
        return;
    };
    if let Some(functions) = obj.remove("functions")
        && !obj.contains_key("tools")
        && let Value::Array(functions) = functions
    {
        let tools = functions
            .into_iter()
            .map(|function| serde_json::json!({ "type": "function", "function": function }))
            .collect();
        obj.insert("tools".to_string(), Value::Array(tools));
    }
    if let Some(function_call) = obj.remove("function_call")
        && !obj.contains_key("tool_choice")
    {
        let choice = match function_call
            .get("name")
            .and_then(Value::as_str)
        {
            Some(name) => serde_json::json!({ "type": "function", "function": { "name": name } }),
            None => function_call,
        };
        obj.insert("tool_choice".to_string(), choice);
    }
    let Some(messages) = obj
        .get_mut("messages")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let mut call_ids: BTreeMap<String, String> = BTreeMap::new();
    for (index, msg) in messages
        .iter_mut()
        .enumerate()
    {
        let Some(msg) = msg.as_object_mut() else {
            continue;
        };
        if let Some(call) = msg.remove("function_call")
            && !msg.contains_key("tool_calls")
        {
            let name = call
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let id = format!("call_legacy_{index}");
            msg.insert(
                "tool_calls".to_string(),
                serde_json::json!([{ "id": id, "type": "function", "function": {
                    "name": name,
                    "arguments": call.get("arguments").cloned().unwrap_or_else(|| Value::String("{}".to_string())),
                } }]),
            );
            call_ids.insert(name, id);
        }
        if msg
            .get("role")
            .and_then(Value::as_str)
            == Some("function")
        {
            let name = msg
                .remove("name")
                .and_then(|n| n.as_str().map(str::to_string))
                .unwrap_or_default();
            let id = call_ids
                .get(&name)
                .cloned()
                .unwrap_or_default();
            msg.insert("role".to_string(), Value::String("tool".to_string()));
            msg.insert("tool_call_id".to_string(), Value::String(id));
        }
    }
}

/// Anthropic's `service_tier` accepts only `auto` and `standard_only`: OpenAI
/// `default` maps to `standard_only`, and any other tier is dropped.
fn shape_anthropic_service_tier(obj: &mut serde_json::Map<String, Value>) {
    let tier = match obj
        .remove("service_tier")
        .as_ref()
        .and_then(Value::as_str)
    {
        Some("auto") => "auto",
        Some("default" | "standard_only") => "standard_only",
        _ => return,
    };
    obj.insert("service_tier".to_string(), Value::String(tier.to_string()));
}

/// Anthropic's `metadata` accepts only `user_id`: carry OpenAI `user`, else
/// `safety_identifier`, there (an existing `metadata.user_id` wins) and drop
/// every other metadata key.
fn shape_anthropic_metadata(obj: &mut serde_json::Map<String, Value>) {
    let user = obj.remove("user");
    let safety_identifier = obj.remove("safety_identifier");
    let user_id = obj
        .remove("metadata")
        .and_then(|m| m.get("user_id").cloned())
        .filter(Value::is_string)
        .or_else(|| user.filter(Value::is_string))
        .or_else(|| safety_identifier.filter(Value::is_string));
    if let Some(user_id) = user_id {
        obj.insert("metadata".to_string(), serde_json::json!({ "user_id": user_id }));
    }
}

// ────────────────────────────────────────────────────────────────────────────
// Inbound skins → OpenAI Chat (canonical), and OpenAI Chat → skin (responses).
//
// These are the reverse of the outbound transforms above and power native
// Anthropic Messages / OpenAI Responses ingress. See `docs/CLIENT_API_DIALECTS.md`.
// ────────────────────────────────────────────────────────────────────────────

/// Flatten an Anthropic content field (string, or an array of `text`/`tool_result`
/// blocks) into plain text. Used for `tool_result` content and system blocks.
fn anthropic_content_to_text(content: Option<&Value>) -> String {
    match content {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Array(blocks)) => blocks
            .iter()
            .filter_map(|b| {
                match b
                    .get("type")
                    .and_then(|t| t.as_str())
                {
                    Some("text") => b
                        .get("text")
                        .and_then(|t| t.as_str())
                        .map(|s| s.to_string()),
                    // A tool_result's own content may nest text blocks.
                    Some("tool_result") => Some(anthropic_content_to_text(b.get("content"))),
                    None => b
                        .as_str()
                        .map(|s| s.to_string()),
                    _ => None,
                }
            })
            .collect::<Vec<_>>()
            .join(""),
        _ => String::new(),
    }
}

/// `part` carrying the Anthropic `block`'s `cache_control` breakpoint, if any.
fn with_cache_control(
    mut part: Value,
    block: &Value,
) -> Value {
    if let Some(cache_control) = block.get("cache_control") {
        part["cache_control"] = cache_control.clone();
    }
    part
}

/// Convert an Anthropic `image` block source into an OpenAI `image_url` part.
fn anthropic_image_to_openai(source: &Value) -> Option<Value> {
    match source
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("base64") => {
            let media_type = source
                .get("media_type")
                .and_then(|m| m.as_str())
                .unwrap_or("image/png");
            let data = source
                .get("data")
                .and_then(|d| d.as_str())?;
            Some(serde_json::json!({
                "type": "image_url",
                "image_url": { "url": format!("data:{media_type};base64,{data}") }
            }))
        }
        Some("url") => {
            let url = source
                .get("url")
                .and_then(|u| u.as_str())?;
            Some(serde_json::json!({ "type": "image_url", "image_url": { "url": url } }))
        }
        _ => None,
    }
}

/// Convert an Anthropic `document` block into an OpenAI content part: a `base64`
/// source becomes a canonical `{ type:"file" }` part with `file_data` (so
/// document ingestion can extract it), a Files API `file` source a `file` part
/// with its `file_id`, and a `text` source a plain text part. Other source
/// kinds (`url`/`content`) are dropped.
fn anthropic_document_to_openai(block: &Value) -> Option<Value> {
    let source = block.get("source")?;
    let title = block
        .get("title")
        .and_then(|t| t.as_str());
    match source
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("base64") => {
            let media_type = source
                .get("media_type")
                .and_then(|m| m.as_str())
                .unwrap_or("application/octet-stream");
            let data = source
                .get("data")
                .and_then(|d| d.as_str())?;
            let mut file = serde_json::json!({ "file_data": format!("data:{media_type};base64,{data}") });
            if let Some(name) = title {
                file["filename"] = Value::String(name.to_string());
            }
            Some(serde_json::json!({ "type": "file", "file": file }))
        }
        Some("file") => {
            let file_id = source
                .get("file_id")
                .and_then(|d| d.as_str())
                .filter(|id| !id.is_empty())?;
            let mut file = serde_json::json!({ "file_id": file_id });
            if let Some(name) = title {
                file["filename"] = Value::String(name.to_string());
            }
            Some(serde_json::json!({ "type": "file", "file": file }))
        }
        Some("text") => {
            let data = source
                .get("data")
                .and_then(|d| d.as_str())?;
            Some(serde_json::json!({ "type": "text", "text": data }))
        }
        _ => None,
    }
}

/// Convert an Anthropic tool definition (`{ name, description, input_schema }`)
/// into OpenAI's `{ type:"function", function:{ name, description, parameters } }`.
fn anthropic_tool_to_openai(tool: &Value) -> Option<Value> {
    let name = tool
        .get("name")
        .and_then(|n| n.as_str())?;
    let description = tool
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let parameters = tool
        .get("input_schema")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} }));
    Some(serde_json::json!({
        "type": "function",
        "function": { "name": name, "description": description, "parameters": parameters }
    }))
}

/// Convert an Anthropic `tool_choice` object into OpenAI's form.
fn anthropic_tool_choice_to_openai(choice: &Value) -> Option<Value> {
    match choice
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("auto") => Some(Value::String("auto".to_string())),
        Some("any") => Some(Value::String("required".to_string())),
        Some("none") => Some(Value::String("none".to_string())),
        Some("tool") => choice
            .get("name")
            .and_then(|n| n.as_str())
            .map(|name| serde_json::json!({ "type": "function", "function": { "name": name } })),
        _ => None,
    }
}

/// Transform an Anthropic Messages request body into an OpenAI Chat Completions
/// body (the canonical internal form). The inverse of
/// [`transform_to_anthropic_format`].
pub fn transform_from_anthropic_request(body: Value) -> Value {
    let mut out = serde_json::Map::new();

    if let Some(model) = body.get("model").cloned() {
        out.insert("model".to_string(), model);
    }

    let mut messages: Vec<Value> = Vec::new();

    // Top-level `system` (string or content-block array) → leading system message.
    match body.get("system") {
        Some(Value::String(s)) if !s.is_empty() => {
            messages.push(serde_json::json!({ "role": "system", "content": s }));
        }
        Some(Value::Array(blocks)) => {
            // Preserve `cache_control` breakpoints by keeping content parts;
            // otherwise flatten to a plain string (the common case).
            if blocks.iter().any(|b| {
                b.get("cache_control")
                    .is_some()
            }) {
                let parts: Vec<Value> = blocks
                    .iter()
                    .filter(|b| {
                        b.get("type")
                            .and_then(|t| t.as_str())
                            == Some("text")
                    })
                    .filter_map(|b| {
                        let text = b
                            .get("text")
                            .and_then(|t| t.as_str())?;
                        let mut part = serde_json::json!({ "type": "text", "text": text });
                        if let Some(cache_control) = b.get("cache_control") {
                            part["cache_control"] = cache_control.clone();
                        }
                        Some(part)
                    })
                    .collect();
                if !parts.is_empty() {
                    messages.push(serde_json::json!({ "role": "system", "content": parts }));
                }
            } else {
                let text = anthropic_content_to_text(body.get("system"));
                if !text.is_empty() {
                    messages.push(serde_json::json!({ "role": "system", "content": text }));
                }
            }
        }
        _ => {}
    }

    if let Some(input_messages) = body
        .get("messages")
        .and_then(|m| m.as_array())
    {
        for msg in input_messages {
            let role = msg
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user");
            match msg.get("content") {
                // Simple string content passes through unchanged.
                Some(Value::String(s)) => {
                    messages.push(serde_json::json!({ "role": role, "content": s }));
                }
                Some(Value::Array(blocks)) => {
                    anthropic_blocks_to_openai_messages(role, blocks, &mut messages);
                }
                _ => {}
            }
        }
    }

    out.insert("messages".to_string(), Value::Array(messages));

    // max_tokens (required by Anthropic) is accepted by OpenAI as-is.
    if let Some(max) = body
        .get("max_tokens")
        .cloned()
    {
        out.insert("max_tokens".to_string(), max);
    }
    if let Some(stop) = body
        .get("stop_sequences")
        .cloned()
    {
        out.insert("stop".to_string(), stop);
    }
    for key in ["temperature", "top_p", "stream"] {
        if let Some(v) = body.get(key).cloned() {
            out.insert(key.to_string(), v);
        }
    }
    // metadata.user_id → OpenAI `user`.
    if let Some(user) = body
        .get("metadata")
        .and_then(|m| m.get("user_id"))
        .and_then(|u| u.as_str())
    {
        out.insert("user".to_string(), Value::String(user.to_string()));
    }

    if let Some(tools) = body
        .get("tools")
        .and_then(|t| t.as_array())
    {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(anthropic_tool_to_openai)
            .collect();
        if !converted.is_empty() {
            out.insert("tools".to_string(), Value::Array(converted));
        }
    }
    if let Some(choice) = body.get("tool_choice")
        && let Some(v) = anthropic_tool_choice_to_openai(choice)
    {
        out.insert("tool_choice".to_string(), v);
    }

    // Anthropic `thinking` → canonical `reasoning`.
    if let Some(reasoning) = body
        .get("thinking")
        .and_then(crate::pipes::reasoning::reasoning_from_anthropic_thinking)
    {
        out.insert("reasoning".to_string(), reasoning);
    }

    Value::Object(out)
}

/// Expand one Anthropic message's content-block array into OpenAI messages.
///
/// `tool_result` blocks become standalone `{ role:"tool" }` messages (emitted in
/// order); assistant `tool_use` blocks become `tool_calls`; remaining
/// `text`/`image` blocks become the message's content.
fn anthropic_blocks_to_openai_messages(
    role: &str,
    blocks: &[Value],
    messages: &mut Vec<Value>,
) {
    let mut content_parts: Vec<Value> = Vec::new();
    let mut tool_calls: Vec<Value> = Vec::new();

    for block in blocks {
        match block
            .get("type")
            .and_then(|t| t.as_str())
        {
            Some("text") => {
                if let Some(text) = block
                    .get("text")
                    .and_then(|t| t.as_str())
                {
                    let part = serde_json::json!({ "type": "text", "text": text });
                    content_parts.push(with_cache_control(part, block));
                }
            }
            Some("image") => {
                if let Some(part) = block
                    .get("source")
                    .and_then(anthropic_image_to_openai)
                {
                    content_parts.push(with_cache_control(part, block));
                }
            }
            Some("document") => {
                if let Some(part) = anthropic_document_to_openai(block) {
                    content_parts.push(with_cache_control(part, block));
                }
            }
            Some("tool_use") => {
                let id = block
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let name = block
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let input = block
                    .get("input")
                    .cloned()
                    .unwrap_or_else(|| serde_json::json!({}));
                let arguments = serde_json::to_string(&input).unwrap_or_else(|_| "{}".to_string());
                tool_calls.push(serde_json::json!({
                    "id": id,
                    "type": "function",
                    "function": { "name": name, "arguments": arguments }
                }));
            }
            Some("tool_result") => {
                let tool_use_id = block
                    .get("tool_use_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                messages.push(serde_json::json!({
                    "role": "tool",
                    "tool_call_id": tool_use_id,
                    "content": anthropic_tool_result_to_openai(block.get("content")),
                }));
            }
            _ => {}
        }
    }

    let content = collapse_content_parts(content_parts);

    if role == "assistant" && !tool_calls.is_empty() {
        let mut m = serde_json::Map::new();
        m.insert("role".to_string(), Value::String("assistant".to_string()));
        m.insert("content".to_string(), content.unwrap_or(Value::Null));
        m.insert("tool_calls".to_string(), Value::Array(tool_calls));
        messages.push(Value::Object(m));
    } else if let Some(content) = content {
        messages.push(serde_json::json!({ "role": role, "content": content }));
    }
}

/// The OpenAI `tool` message content for an Anthropic `tool_result`'s content:
/// the flattened text, or, when the tool returned an image or document, a parts
/// array keeping them in order (see [`anthropic_image_to_openai`] and
/// [`anthropic_document_to_openai`]).
fn anthropic_tool_result_to_openai(content: Option<&Value>) -> Value {
    let Some(Value::Array(blocks)) = content else {
        return Value::String(anthropic_content_to_text(content));
    };
    let has_media = blocks.iter().any(|b| {
        matches!(
            b.get("type")
                .and_then(Value::as_str),
            Some("image" | "document")
        )
    });
    if !has_media {
        return Value::String(anthropic_content_to_text(content));
    }
    let parts = blocks
        .iter()
        .filter_map(|block| {
            match block
                .get("type")
                .and_then(Value::as_str)
            {
                Some("text") => block
                    .get("text")
                    .and_then(Value::as_str)
                    .map(|text| serde_json::json!({ "type": "text", "text": text })),
                Some("image") => block
                    .get("source")
                    .and_then(anthropic_image_to_openai),
                Some("document") => anthropic_document_to_openai(block),
                _ => None,
            }
        })
        .collect();
    Value::Array(parts)
}

/// OpenAI Chat takes only text in a `tool` message, so the image and file parts
/// a tool returned move, in order, into a `user` message after that run of tool
/// messages, leaving each tool message its text.
pub(crate) fn move_tool_media_to_user_message(body: &mut Value) {
    let Some(messages) = body
        .get_mut("messages")
        .and_then(Value::as_array_mut)
    else {
        return;
    };
    let is_tool_with_media = |m: &Value| {
        m.get("role")
            .and_then(Value::as_str)
            == Some("tool")
            && m.get("content")
                .and_then(Value::as_array)
                .is_some_and(|parts| {
                    parts.iter().any(|p| {
                        p.get("type")
                            .and_then(Value::as_str)
                            != Some("text")
                    })
                })
    };
    if !messages
        .iter()
        .any(is_tool_with_media)
    {
        return;
    }
    let mut out: Vec<Value> = Vec::with_capacity(messages.len() + 1);
    let mut media: Vec<Value> = Vec::new();
    for mut message in std::mem::take(messages) {
        let is_tool = message
            .get("role")
            .and_then(Value::as_str)
            == Some("tool");
        if !is_tool && !media.is_empty() {
            out.push(serde_json::json!({ "role": "user", "content": std::mem::take(&mut media) }));
        }
        if is_tool_with_media(&message) {
            let text = openai_content_to_text(message.get("content"));
            if let Some(Value::Array(parts)) = message
                .get_mut("content")
                .map(Value::take)
            {
                media.extend(parts.into_iter().filter(|p| {
                    p.get("type")
                        .and_then(Value::as_str)
                        != Some("text")
                }));
            }
            message["content"] = Value::String(text);
        }
        out.push(message);
    }
    if !media.is_empty() {
        out.push(serde_json::json!({ "role": "user", "content": media }));
    }
    *messages = out;
}

/// Collapse OpenAI content parts into a single string when they are all text,
/// otherwise keep the multimodal parts array. `None` when empty. A part carrying
/// a `cache_control` breakpoint is never collapsed away.
fn collapse_content_parts(parts: Vec<Value>) -> Option<Value> {
    if parts.is_empty() {
        return None;
    }
    let has_cache_control = parts.iter().any(|p| {
        p.get("cache_control")
            .is_some()
    });
    if !has_cache_control
        && parts.iter().all(|p| {
            p.get("type")
                .and_then(|t| t.as_str())
                == Some("text")
        })
    {
        let text: String = parts
            .iter()
            .filter_map(|p| {
                p.get("text")
                    .and_then(|t| t.as_str())
            })
            .collect::<Vec<_>>()
            .join("");
        return Some(Value::String(text));
    }
    Some(Value::Array(parts))
}

/// Map an OpenAI `finish_reason` to an Anthropic `stop_reason`.
fn finish_reason_to_anthropic(
    finish: Option<&str>,
    has_tool_calls: bool,
) -> &'static str {
    match finish {
        Some("length") => "max_tokens",
        Some("tool_calls") => "tool_use",
        Some("stop") => "end_turn",
        Some("content_filter") => "end_turn",
        _ if has_tool_calls => "tool_use",
        _ => "end_turn",
    }
}

/// Transform an OpenAI Chat Completions response into an Anthropic Messages
/// response. The inverse of `executor::transform_from_anthropic_format`.
pub fn transform_to_anthropic_response(
    openai: &Value,
    model: &str,
) -> Value {
    let choice = openai
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first());
    let message = choice.and_then(|c| c.get("message"));

    let text = message
        .and_then(|m| m.get("content"))
        .map(|c| openai_content_to_text(Some(c)))
        .unwrap_or_default();

    let mut content: Vec<Value> = Vec::new();
    // Reasoning (thinking) blocks come first in an Anthropic response.
    if let Some(details) = message
        .and_then(|m| m.get("reasoning_details"))
        .and_then(|d| d.as_array())
    {
        content.extend(crate::pipes::reasoning::details_to_anthropic_thinking_blocks(details));
    } else if let Some(reasoning) = message
        .and_then(|m| m.get("reasoning"))
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
    {
        content.push(serde_json::json!({ "type": "thinking", "thinking": reasoning }));
    }
    // Anthropic always carries at least one text block, even when empty.
    if !text.is_empty() {
        content.push(serde_json::json!({ "type": "text", "text": text }));
    }

    let tool_calls = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array());
    let has_tool_calls = tool_calls
        .map(|t| !t.is_empty())
        .unwrap_or(false);
    if let Some(tool_calls) = tool_calls {
        for tc in tool_calls {
            let id = tc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let function = tc.get("function");
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let args = function
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            let input: Value = serde_json::from_str(args).unwrap_or_else(|_| serde_json::json!({}));
            content.push(serde_json::json!({
                "type": "tool_use",
                "id": id,
                "name": name,
                "input": input,
            }));
        }
    }
    // Guarantee an answer block (text or tool_use), even for a thinking-only turn.
    let has_answer = content.iter().any(|b| {
        matches!(
            b.get("type")
                .and_then(|t| t.as_str()),
            Some("text") | Some("tool_use")
        )
    });
    if !has_answer {
        content.push(serde_json::json!({ "type": "text", "text": "" }));
    }

    let finish = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(|f| f.as_str());
    let stop_reason = finish_reason_to_anthropic(finish, has_tool_calls);

    let (input_tokens, output_tokens) = openai_usage_tokens(openai);
    // Preserve provider prompt-cache accounting in the re-skinned Anthropic
    // usage so an Anthropic client sees `cache_read_input_tokens` /
    // `cache_creation_input_tokens` as it would from the native API.
    let cache_read = openai
        .pointer("/usage/prompt_tokens_details/cached_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let cache_write = openai
        .pointer("/usage/cache_creation_input_tokens")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let id = openai
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| {
            if s.starts_with("msg_") {
                s.to_string()
            } else {
                format!("msg_{s}")
            }
        })
        .unwrap_or_else(|| format!("msg_{}", uuid::Uuid::new_v4()));
    let resolved_model = if model.is_empty() {
        openai
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        model.to_string()
    };

    let mut usage = serde_json::json!({ "input_tokens": input_tokens, "output_tokens": output_tokens });
    if cache_read > 0 {
        usage["cache_read_input_tokens"] = serde_json::json!(cache_read);
    }
    if cache_write > 0 {
        usage["cache_creation_input_tokens"] = serde_json::json!(cache_write);
    }

    serde_json::json!({
        "id": id,
        "type": "message",
        "role": "assistant",
        "model": resolved_model,
        "content": content,
        "stop_reason": stop_reason,
        "stop_sequence": Value::Null,
        "usage": usage
    })
}

/// Read `(input_tokens, output_tokens)` from an OpenAI `usage` block.
fn openai_usage_tokens(openai: &Value) -> (u64, u64) {
    let usage = openai.get("usage");
    let input = usage
        .and_then(|u| u.get("prompt_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let output = usage
        .and_then(|u| u.get("completion_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    (input, output)
}

/// Transform an OpenAI Responses request body into an OpenAI Chat Completions
/// body (the canonical internal form).
pub fn transform_from_responses_request(body: Value) -> Value {
    let mut out = serde_json::Map::new();

    if let Some(model) = body.get("model").cloned() {
        out.insert("model".to_string(), model);
    }

    let mut messages: Vec<Value> = Vec::new();

    if let Some(instructions) = body
        .get("instructions")
        .and_then(|i| i.as_str())
        && !instructions.is_empty()
    {
        messages.push(serde_json::json!({ "role": "system", "content": instructions }));
    }

    match body.get("input") {
        Some(Value::String(s)) => {
            messages.push(serde_json::json!({ "role": "user", "content": s }));
        }
        Some(Value::Array(items)) => {
            for item in items {
                responses_item_to_openai_messages(item, &mut messages);
            }
        }
        _ => {}
    }

    out.insert("messages".to_string(), Value::Array(messages));

    if let Some(max) = body
        .get("max_output_tokens")
        .cloned()
    {
        out.insert("max_tokens".to_string(), max);
    }
    for key in ["temperature", "top_p", "stream", "parallel_tool_calls"] {
        if let Some(v) = body.get(key).cloned() {
            out.insert(key.to_string(), v);
        }
    }
    if let Some(user) = body
        .get("user")
        .filter(|u| u.is_string())
        .or_else(|| {
            body.get("metadata")
                .and_then(|m| m.get("user_id"))
                .filter(|u| u.is_string())
        })
    {
        out.insert("user".to_string(), user.clone());
    }
    // Responses `text.format` → OpenAI `response_format`.
    if let Some(format) = body
        .get("text")
        .and_then(|t| t.get("format"))
        .cloned()
    {
        out.insert("response_format".to_string(), format);
    }

    if let Some(tools) = body
        .get("tools")
        .and_then(|t| t.as_array())
    {
        let converted: Vec<Value> = tools
            .iter()
            .filter_map(responses_tool_to_openai)
            .collect();
        if !converted.is_empty() {
            out.insert("tools".to_string(), Value::Array(converted));
        }
    }
    if let Some(choice) = body
        .get("tool_choice")
        .cloned()
    {
        out.insert("tool_choice".to_string(), responses_tool_choice_to_openai(choice));
    }

    // Responses `reasoning` → canonical `reasoning`.
    if let Some(reasoning) = body
        .get("reasoning")
        .and_then(crate::pipes::reasoning::reasoning_from_responses)
    {
        out.insert("reasoning".to_string(), reasoning);
    }

    Value::Object(out)
}

/// Convert one Responses `input` item into OpenAI message(s).
fn responses_item_to_openai_messages(
    item: &Value,
    messages: &mut Vec<Value>,
) {
    match item
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("message") | None => {
            let role = item
                .get("role")
                .and_then(|r| r.as_str())
                .unwrap_or("user");
            let content = match item.get("content") {
                Some(Value::String(s)) => Some(Value::String(s.clone())),
                Some(Value::Array(parts)) => collapse_content_parts(
                    parts
                        .iter()
                        .filter_map(responses_content_part_to_openai)
                        .collect(),
                ),
                _ => None,
            };
            if let Some(content) = content {
                messages.push(serde_json::json!({ "role": role, "content": content }));
            }
        }
        Some("function_call") => {
            let call_id = item
                .get("call_id")
                .or_else(|| item.get("id"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = item
                .get("arguments")
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            let tool_call = serde_json::json!({
                "id": call_id,
                "type": "function",
                "function": { "name": name, "arguments": arguments }
            });
            // Merge into a preceding assistant tool-call message when adjacent.
            if let Some(last) = messages.last_mut()
                && last
                    .get("role")
                    .and_then(|r| r.as_str())
                    == Some("assistant")
                && let Some(calls) = last
                    .get_mut("tool_calls")
                    .and_then(|c| c.as_array_mut())
            {
                calls.push(tool_call);
            } else {
                messages.push(serde_json::json!({
                    "role": "assistant",
                    "content": Value::Null,
                    "tool_calls": [tool_call]
                }));
            }
        }
        Some("function_call_output") => {
            let call_id = item
                .get("call_id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let output = match item.get("output") {
                Some(Value::String(s)) => s.clone(),
                Some(other) => serde_json::to_string(other).unwrap_or_default(),
                None => String::new(),
            };
            messages.push(serde_json::json!({ "role": "tool", "tool_call_id": call_id, "content": output }));
        }
        // `reasoning` and unknown item types are dropped inbound.
        _ => {}
    }
}

/// Convert a Responses content part (`input_text`/`output_text`/`input_image`/
/// `input_audio`) into an OpenAI content part.
fn responses_content_part_to_openai(part: &Value) -> Option<Value> {
    match part
        .get("type")
        .and_then(|t| t.as_str())
    {
        Some("input_text") | Some("output_text") | Some("text") => {
            let text = part
                .get("text")
                .and_then(|t| t.as_str())?;
            Some(serde_json::json!({ "type": "text", "text": text }))
        }
        Some("input_audio") => {
            // Responses carries audio as `{ type:"input_audio", input_audio:{
            // data, format } }` — the same shape the canonical pipeline uses.
            let audio = part.get("input_audio")?;
            Some(serde_json::json!({ "type": "input_audio", "input_audio": audio.clone() }))
        }
        Some("input_image") => {
            let url = part
                .get("image_url")
                .and_then(|u| u.as_str())
                .or_else(|| {
                    part.get("image_url")
                        .and_then(|u| u.get("url"))
                        .and_then(|u| u.as_str())
                })?;
            Some(serde_json::json!({ "type": "image_url", "image_url": { "url": url } }))
        }
        Some("input_file") => {
            let mut file = serde_json::Map::new();
            if let Some(name) = part
                .get("filename")
                .and_then(|n| n.as_str())
            {
                file.insert("filename".to_string(), Value::String(name.to_string()));
            }
            if let Some(data) = part
                .get("file_data")
                .and_then(|d| d.as_str())
            {
                file.insert("file_data".to_string(), Value::String(data.to_string()));
            } else {
                let id = part
                    .get("file_id")
                    .and_then(|d| d.as_str())?;
                file.insert("file_id".to_string(), Value::String(id.to_string()));
            }
            Some(serde_json::json!({ "type": "file", "file": Value::Object(file) }))
        }
        _ => None,
    }
}

/// Convert a Responses tool (flattened `{ type:"function", name, description,
/// parameters }`) into the OpenAI nested form. Non-function tools are dropped.
fn responses_tool_to_openai(tool: &Value) -> Option<Value> {
    if tool
        .get("type")
        .and_then(|t| t.as_str())
        != Some("function")
    {
        return None;
    }
    // A Responses function tool may already be nested; handle both.
    if tool.get("function").is_some() {
        return Some(tool.clone());
    }
    let name = tool
        .get("name")
        .and_then(|n| n.as_str())?;
    let description = tool
        .get("description")
        .and_then(|d| d.as_str())
        .unwrap_or("");
    let parameters = tool
        .get("parameters")
        .cloned()
        .unwrap_or_else(|| serde_json::json!({ "type": "object", "properties": {} }));
    Some(serde_json::json!({
        "type": "function",
        "function": { "name": name, "description": description, "parameters": parameters }
    }))
}

/// Convert a Responses `tool_choice` into OpenAI's form.
fn responses_tool_choice_to_openai(choice: Value) -> Value {
    match &choice {
        Value::String(_) => choice,
        Value::Object(_) => {
            if let Some(name) = choice
                .get("name")
                .and_then(|n| n.as_str())
            {
                serde_json::json!({ "type": "function", "function": { "name": name } })
            } else {
                choice
            }
        }
        _ => Value::String("auto".to_string()),
    }
}

/// Transform an OpenAI Chat Completions response into an OpenAI Responses
/// response object.
pub fn transform_to_responses_response(
    openai: &Value,
    model: &str,
) -> Value {
    let choice = openai
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|c| c.first());
    let message = choice.and_then(|c| c.get("message"));

    let text = message
        .and_then(|m| m.get("content"))
        .map(|c| openai_content_to_text(Some(c)))
        .unwrap_or_default();

    let mut output: Vec<Value> = Vec::new();
    // A reasoning item precedes the message in a Responses output.
    if let Some(reasoning) = message
        .and_then(|m| m.get("reasoning"))
        .and_then(|r| r.as_str())
        .filter(|r| !r.is_empty())
    {
        output.push(serde_json::json!({
            "type": "reasoning",
            "id": format!("rs_{}", uuid::Uuid::new_v4()),
            "summary": [ { "type": "summary_text", "text": reasoning } ]
        }));
    }
    if !text.is_empty() {
        output.push(serde_json::json!({
            "type": "message",
            "id": format!("msg_{}", uuid::Uuid::new_v4()),
            "role": "assistant",
            "status": "completed",
            "content": [ { "type": "output_text", "text": text, "annotations": [] } ]
        }));
    }

    if let Some(tool_calls) = message
        .and_then(|m| m.get("tool_calls"))
        .and_then(|t| t.as_array())
    {
        for tc in tool_calls {
            let call_id = tc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let function = tc.get("function");
            let name = function
                .and_then(|f| f.get("name"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let arguments = function
                .and_then(|f| f.get("arguments"))
                .and_then(|v| v.as_str())
                .unwrap_or("{}");
            output.push(serde_json::json!({
                "type": "function_call",
                "id": format!("fc_{}", uuid::Uuid::new_v4()),
                "call_id": call_id,
                "name": name,
                "arguments": arguments,
                "status": "completed"
            }));
        }
    }

    let finish = choice
        .and_then(|c| c.get("finish_reason"))
        .and_then(|f| f.as_str());
    let (status, incomplete_details) = match finish {
        Some("length") => ("incomplete", serde_json::json!({ "reason": "max_output_tokens" })),
        Some("content_filter") => ("incomplete", serde_json::json!({ "reason": "content_filter" })),
        _ => ("completed", Value::Null),
    };

    let (input_tokens, output_tokens) = openai_usage_tokens(openai);
    let id = openai
        .get("id")
        .and_then(|v| v.as_str())
        .map(|s| {
            if s.starts_with("resp_") {
                s.to_string()
            } else {
                format!("resp_{s}")
            }
        })
        .unwrap_or_else(|| format!("resp_{}", uuid::Uuid::new_v4()));
    let resolved_model = if model.is_empty() {
        openai
            .get("model")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown")
            .to_string()
    } else {
        model.to_string()
    };

    serde_json::json!({
        "id": id,
        "object": "response",
        "status": status,
        "model": resolved_model,
        "output": output,
        "output_text": text,
        "incomplete_details": incomplete_details,
        "usage": {
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "total_tokens": input_tokens + output_tokens
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn bedrock_anthropic_transform_strips_model_and_sets_body_version() {
        let openai = json!({
            "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "max_tokens": 64,
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "user", "content": "hello"}
            ]
        });
        let out = transform_to_bedrock_anthropic_format(openai);
        // model travels in the URL for InvokeModel — it must NOT be in the body
        assert!(out.get("model").is_none(), "model must be removed for Bedrock InvokeModel");
        // anthropic_version is a required BODY field for Bedrock (a header for native Anthropic)
        assert_eq!(out["anthropic_version"], json!("bedrock-2023-05-31"));
        // still the Anthropic Messages shape: system lifted out, max_tokens preserved
        assert_eq!(out["system"], json!("be brief"));
        assert_eq!(out["max_tokens"], json!(64));
        assert!(
            out["messages"]
                .as_array()
                .is_some()
        );
    }

    #[test]
    fn copilot_transform_maps_last_user_message_to_prompt() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "You are helpful." },
                { "role": "user", "content": "First question" },
                { "role": "assistant", "content": "First answer" },
                { "role": "user", "content": "Summarize my latest doc" }
            ]
        });
        let out = transform_to_copilot_format(body);

        assert_eq!(out["message"]["text"], json!("Summarize my latest doc"));
        assert_eq!(out["locationHint"]["timeZone"], json!("UTC"));

        let context = out["additionalContext"]
            .as_array()
            .expect("additionalContext array");
        // System + prior user + prior assistant, but NOT the final user prompt.
        assert_eq!(context.len(), 3);
        assert_eq!(context[0]["text"], json!("system: You are helpful."));
        assert_eq!(context[1]["text"], json!("user: First question"));
        assert_eq!(context[2]["text"], json!("assistant: First answer"));
    }

    #[test]
    fn copilot_transform_single_user_message_has_no_context() {
        let body = json!({ "messages": [{ "role": "user", "content": "Hello" }] });
        let out = transform_to_copilot_format(body);

        assert_eq!(out["message"]["text"], json!("Hello"));
        // No other messages, so additionalContext must be absent (not empty array).
        assert!(
            out.get("additionalContext")
                .is_none()
        );
    }

    #[test]
    fn copilot_transform_reuse_mode_omits_history() {
        // When a conversation is reused, Copilot already holds the prior turns,
        // so only the final user message is sent — no additionalContext replay.
        let body = json!({
            "messages": [
                { "role": "system", "content": "You are helpful." },
                { "role": "user", "content": "First question" },
                { "role": "assistant", "content": "First answer" },
                { "role": "user", "content": "What did I just ask?" }
            ]
        });
        let out = transform_to_copilot_format_with(body, false);

        assert_eq!(out["message"]["text"], json!("What did I just ask?"));
        assert_eq!(out["locationHint"]["timeZone"], json!("UTC"));
        assert!(
            out.get("additionalContext")
                .is_none(),
            "reused conversation must not replay history as additionalContext"
        );
    }

    #[test]
    fn copilot_transform_empty_messages_yields_empty_prompt() {
        let out = transform_to_copilot_format(json!({ "messages": [] }));
        assert_eq!(out["message"]["text"], json!(""));
        assert!(
            out.get("additionalContext")
                .is_none()
        );
    }

    #[test]
    fn copilot_transform_flattens_content_part_array() {
        let body = json!({
            "messages": [{
                "role": "user",
                "content": [
                    { "type": "text", "text": "Part one. " },
                    { "type": "text", "text": "Part two." }
                ]
            }]
        });
        let out = transform_to_copilot_format(body);
        assert_eq!(out["message"]["text"], json!("Part one. Part two."));
    }

    fn catalog() -> Vec<Value> {
        json!([
            {
                "enum_value": "openai",
                "api_schema": "openai",
                "models": [
                    { "value": "gpt-4o", "capabilities": { "supports_json_mode": true } },
                    {
                        "value": "gpt-5",
                        "request_profile": { "reasoning": true, "supports_json_mode": true }
                    }
                ]
            },
            {
                "enum_value": "anthropic",
                "api_schema": "anthropic",
                "models": [
                    {
                        "value": "claude-opus-4-8",
                        "request_profile": {
                            "unsupported_params": ["temperature"],
                            "supports_json_mode": false
                        }
                    }
                ]
            },
            {
                "enum_value": "gemini",
                "api_schema": "gemini",
                "models": [
                    { "value": "gemini-2.0-flash", "capabilities": { "supports_json_mode": true } }
                ]
            }
        ])
        .as_array()
        .unwrap()
        .clone()
    }

    #[test]
    fn apply_param_rules_strips_unsupported() {
        let profile = ModelRequestProfile {
            api_schema: "anthropic".into(),
            reasoning: false,
            supports_json_mode: false,
            supports_json_schema: false,
            supports_audio_input: false,
            supports_realtime: false,
            unsupported_params: vec!["temperature".into()],
            param_aliases: BTreeMap::new(),
            required_params: BTreeMap::new(),
        };
        let mut body = json!({ "model": "claude", "temperature": 0.7, "max_tokens": 100 });
        profile.apply_param_rules(&mut body);
        assert!(
            body.get("temperature")
                .is_none(),
            "temperature should be stripped"
        );
        assert_eq!(body["max_tokens"], json!(100));
    }

    #[test]
    fn apply_param_rules_aliases_then_strips() {
        let profile = ModelRequestProfile {
            api_schema: "openai".into(),
            reasoning: true,
            supports_json_mode: true,
            supports_json_schema: true,
            supports_audio_input: true,
            supports_realtime: false,
            unsupported_params: vec!["temperature".into(), "top_p".into()],
            param_aliases: BTreeMap::from([("max_tokens".to_string(), "max_completion_tokens".to_string())]),
            required_params: BTreeMap::new(),
        };
        let mut body = json!({ "temperature": 0.3, "top_p": 0.9, "max_tokens": 256 });
        profile.apply_param_rules(&mut body);
        assert!(
            body.get("temperature")
                .is_none()
        );
        assert!(body.get("top_p").is_none());
        assert!(
            body.get("max_tokens")
                .is_none()
        );
        assert_eq!(body["max_completion_tokens"], json!(256));
    }

    #[test]
    fn apply_param_rules_alias_does_not_overwrite_existing() {
        let profile = ModelRequestProfile {
            api_schema: "openai".into(),
            reasoning: true,
            supports_json_mode: true,
            supports_json_schema: true,
            supports_audio_input: true,
            supports_realtime: false,
            unsupported_params: vec![],
            param_aliases: BTreeMap::from([("max_tokens".to_string(), "max_completion_tokens".to_string())]),
            required_params: BTreeMap::new(),
        };
        let mut body = json!({ "max_tokens": 256, "max_completion_tokens": 1000 });
        profile.apply_param_rules(&mut body);
        assert!(
            body.get("max_tokens")
                .is_none(),
            "source key removed"
        );
        assert_eq!(body["max_completion_tokens"], json!(1000), "existing target preserved");
    }

    #[test]
    fn apply_param_rules_injects_required_when_absent() {
        let profile = ModelRequestProfile {
            api_schema: "anthropic".into(),
            reasoning: false,
            supports_json_mode: false,
            supports_json_schema: false,
            supports_audio_input: false,
            supports_realtime: false,
            unsupported_params: vec![],
            param_aliases: BTreeMap::new(),
            required_params: BTreeMap::from([("max_tokens".to_string(), json!(4096))]),
        };
        let mut body = json!({ "model": "claude" });
        profile.apply_param_rules(&mut body);
        assert_eq!(body["max_tokens"], json!(4096));

        let mut body2 = json!({ "model": "claude", "max_tokens": 10 });
        profile.apply_param_rules(&mut body2);
        assert_eq!(body2["max_tokens"], json!(10), "existing value not overwritten");
    }

    #[test]
    fn resolve_anthropic_model_strips_temperature() {
        let profile = resolve_profile_from_providers(&catalog(), "anthropic", "claude-opus-4-8", "openai", None);
        assert_eq!(profile.api_schema, "anthropic");
        assert!(
            profile
                .unsupported_params
                .contains(&"temperature".to_string())
        );
        assert!(!profile.supports_json_mode);
        assert!(!profile.reasoning);
    }

    #[test]
    fn resolve_openai_reasoning_via_request_profile() {
        let profile = resolve_profile_from_providers(&catalog(), "openai", "gpt-5", "openai", None);
        assert!(profile.reasoning);
        assert!(profile.supports_json_mode);
        assert!(
            profile
                .unsupported_params
                .contains(&"temperature".to_string())
        );
        assert_eq!(
            profile
                .param_aliases
                .get("max_tokens"),
            Some(&"max_completion_tokens".to_string())
        );
    }

    #[test]
    fn resolve_openai_reasoning_via_heuristic_without_request_profile() {
        // gpt-5-turbo is not in the catalog model list, but the heuristic still fires.
        let profile = resolve_profile_from_providers(&catalog(), "openai", "gpt-5-turbo", "openai", None);
        assert!(profile.reasoning, "heuristic should detect gpt-5* as reasoning");
        assert!(
            profile
                .unsupported_params
                .contains(&"temperature".to_string())
        );
    }

    #[test]
    fn resolve_non_reasoning_openai_keeps_params() {
        let profile = resolve_profile_from_providers(&catalog(), "openai", "gpt-4o", "openai", None);
        assert!(!profile.reasoning);
        assert!(
            profile
                .unsupported_params
                .is_empty()
        );
        assert!(profile.supports_json_mode);
    }

    #[test]
    fn resolve_unknown_provider_uses_fallback_schema() {
        let profile = resolve_profile_from_providers(&catalog(), "mystery", "some-model", "anthropic", Some(false));
        assert_eq!(profile.api_schema, "anthropic");
        assert!(!profile.supports_json_mode);
    }

    #[test]
    fn builtin_profile_detects_reasoning() {
        let profile = builtin_profile("openai", "gpt-5", None);
        assert!(profile.reasoning);
        assert!(profile.supports_json_mode, "openai defaults to json mode");
        assert!(
            profile
                .unsupported_params
                .contains(&"temperature".to_string())
        );
    }

    #[test]
    fn shape_request_anthropic_lifts_system_and_strips_temperature() {
        let profile = resolve_profile_from_providers(&catalog(), "anthropic", "claude-opus-4-8", "openai", None);
        let body = json!({
            "model": "claude-opus-4-8",
            "messages": [
                { "role": "system", "content": "You are a judge." },
                { "role": "user", "content": "Evaluate this." }
            ],
            "temperature": 0.1,
            "max_tokens": 500
        });
        let shaped = shape_request(&profile, body);
        assert_eq!(shaped["system"], json!("You are a judge."));
        assert!(
            shaped
                .get("temperature")
                .is_none(),
            "temperature stripped for claude"
        );
        assert_eq!(shaped["max_tokens"], json!(500));
        let messages = shaped["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages.len(), 1, "system message removed from array");
        assert_eq!(messages[0]["role"], json!("user"));
    }

    #[test]
    fn shape_request_gemini_builds_generation_config() {
        let profile = resolve_profile_from_providers(&catalog(), "gemini", "gemini-2.0-flash", "openai", None);
        let body = json!({
            "model": "gemini-2.0-flash",
            "messages": [{ "role": "user", "content": "Hi" }],
            "temperature": 0.4,
            "max_tokens": 200
        });
        let shaped = shape_request(&profile, body);
        assert!(
            shaped
                .get("contents")
                .is_some()
        );
        assert_eq!(shaped["generationConfig"]["temperature"], json!(0.4));
        assert_eq!(shaped["generationConfig"]["maxOutputTokens"], json!(200));
    }

    #[test]
    fn audio_input_defaults_by_schema() {
        // Audio input is a narrow, per-model capability. A generic OpenAI model
        // (gpt-4o, o4-mini) defaults OFF; only OpenAI audio/realtime models and
        // native-multimodal Gemini default ON. Anthropic has no audio wire form.
        // No catalog declaration needed.
        assert!(!resolve_profile_from_providers(&catalog(), "openai", "gpt-4o", "openai", None).supports_audio_input);
        assert!(
            resolve_profile_from_providers(&catalog(), "openai", "gpt-4o-audio-preview", "openai", None)
                .supports_audio_input
        );
        assert!(
            resolve_profile_from_providers(&catalog(), "gemini", "gemini-2.0-flash", "openai", None)
                .supports_audio_input
        );
        assert!(
            !resolve_profile_from_providers(&catalog(), "anthropic", "claude-opus-4-8", "openai", None)
                .supports_audio_input
        );
    }

    #[test]
    fn audio_input_capability_overrides_default() {
        let providers = json!([
            {
                "enum_value": "anthropic",
                "api_schema": "anthropic",
                "models": [ { "value": "claude-audio", "capabilities": { "supports_audio_input": true } } ]
            },
            {
                "enum_value": "openai",
                "api_schema": "openai",
                "models": [ { "value": "gpt-text-only", "request_profile": { "supports_audio_input": false } } ]
            }
        ])
        .as_array()
        .unwrap()
        .clone();
        // Explicit `true` lifts the Anthropic default block; explicit `false`
        // blocks an otherwise-allowed OpenAI model.
        assert!(
            resolve_profile_from_providers(&providers, "anthropic", "claude-audio", "anthropic", None)
                .supports_audio_input
        );
        assert!(
            !resolve_profile_from_providers(&providers, "openai", "gpt-text-only", "openai", None).supports_audio_input
        );
    }

    #[test]
    fn builtin_profile_audio_default_by_schema() {
        assert!(builtin_profile("openai", "gpt-4o-audio-preview", None).supports_audio_input);
        assert!(!builtin_profile("openai", "o4-mini", None).supports_audio_input);
        assert!(!builtin_profile("anthropic", "claude-3-5", None).supports_audio_input);
    }

    #[test]
    fn realtime_capability_from_catalog_flag() {
        let providers = json!([
            {
                "enum_value": "openai",
                "api_schema": "openai",
                "models": [
                    { "value": "custom-voice", "capabilities": { "supports_realtime": true } },
                    { "value": "gpt-realtime-lite", "request_profile": { "supports_realtime": false } }
                ]
            }
        ])
        .as_array()
        .unwrap()
        .clone();
        // The catalog flag is authoritative: it lifts a non-`*realtime*`-named
        // model into realtime, and can force a realtime-named model off.
        assert!(resolve_profile_from_providers(&providers, "openai", "custom-voice", "openai", None).supports_realtime);
        assert!(
            !resolve_profile_from_providers(&providers, "openai", "gpt-realtime-lite", "openai", None)
                .supports_realtime
        );
        // Unset in the catalog → narrow name-based default.
        assert!(!resolve_profile_from_providers(&catalog(), "openai", "o4-mini", "openai", None).supports_realtime);
        assert!(resolve_profile_from_providers(&catalog(), "openai", "gpt-realtime", "openai", None).supports_realtime);
    }

    #[test]
    fn realtime_capability_is_narrow_and_name_based() {
        // Realtime is narrower than audio: only *realtime* / Live models qualify.
        assert!(model_supports_realtime("openai", "gpt-realtime"));
        assert!(model_supports_realtime("openai", "gpt-4o-realtime-preview"));
        assert!(model_supports_realtime("gemini", "gemini-2.0-flash-live"));
        assert!(model_supports_realtime("gemini", "gemini-2.5-flash-preview-native-audio-dialog"));
        // A plain audio-input model speaks Mode A but not the realtime socket.
        assert!(!model_supports_realtime("openai", "gpt-4o-audio-preview"));
        assert!(!model_supports_realtime("openai", "gpt-4o"));
        assert!(!model_supports_realtime("gemini", "gemini-2.5-pro"));
        assert!(!model_supports_realtime("anthropic", "claude-opus-4-8"));
    }

    #[test]
    fn gemini_wire_carries_audio_as_inline_data() {
        let shaped = transform_to_gemini_format(json!({
            "messages": [ { "role": "user", "content": [
                { "type": "text", "text": "what is said?" },
                { "type": "input_audio", "input_audio": { "data": "QUJDRA==", "format": "mp3" } }
            ] } ]
        }));
        let parts = shaped["contents"][0]["parts"]
            .as_array()
            .unwrap();
        assert_eq!(parts[0]["text"], json!("what is said?"));
        assert_eq!(parts[1]["inline_data"]["mime_type"], json!("audio/mp3"));
        assert_eq!(parts[1]["inline_data"]["data"], json!("QUJDRA=="));
    }

    #[test]
    fn gemini_wire_carries_inline_image_and_drops_remote() {
        let shaped = transform_to_gemini_format(json!({
            "messages": [ { "role": "user", "content": [
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,QUJD" } },
                { "type": "image_url", "image_url": { "url": "https://example.com/x.png" } }
            ] } ]
        }));
        let parts = shaped["contents"][0]["parts"]
            .as_array()
            .unwrap();
        assert_eq!(parts.len(), 1, "remote image URL dropped, data URL inlined");
        assert_eq!(parts[0]["inline_data"]["mime_type"], json!("image/png"));
    }

    #[test]
    fn gemini_wire_extracts_text_from_multipart_content() {
        // Previously multi-part content flattened to empty; text parts now survive.
        let shaped = transform_to_gemini_format(json!({
            "messages": [ { "role": "user", "content": [ { "type": "text", "text": "hello" } ] } ]
        }));
        assert_eq!(shaped["contents"][0]["parts"][0]["text"], json!("hello"));
    }

    #[test]
    fn shape_request_openai_reasoning_renames_max_tokens() {
        let profile = resolve_profile_from_providers(&catalog(), "openai", "gpt-5", "openai", None);
        let body = json!({
            "model": "gpt-5",
            "messages": [{ "role": "user", "content": "Hi" }],
            "temperature": 0.5,
            "max_tokens": 300
        });
        let shaped = shape_request(&profile, body);
        assert!(
            shaped
                .get("temperature")
                .is_none()
        );
        assert!(
            shaped
                .get("max_tokens")
                .is_none()
        );
        assert_eq!(shaped["max_completion_tokens"], json!(300));
    }

    #[test]
    fn anthropic_converts_tools_and_string_tool_choice() {
        let body = json!({
            "model": "claude-opus-4-8",
            "messages": [{ "role": "user", "content": "What's the weather?" }],
            "tools": [{
                "type": "function",
                "function": {
                    "name": "get_weather",
                    "description": "Look up the weather",
                    "parameters": { "type": "object", "properties": { "city": { "type": "string" } } }
                }
            }],
            "tool_choice": "required",
            "stream": true,
            "stream_options": { "include_usage": true },
            "parallel_tool_calls": true
        });
        let shaped = transform_to_anthropic_format(body);

        let tools = shaped["tools"]
            .as_array()
            .unwrap();
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0]["name"], json!("get_weather"));
        assert_eq!(tools[0]["description"], json!("Look up the weather"));
        assert_eq!(tools[0]["input_schema"]["properties"]["city"]["type"], json!("string"));
        assert!(
            tools[0]
                .get("function")
                .is_none(),
            "OpenAI function wrapper removed"
        );

        assert_eq!(shaped["tool_choice"], json!({ "type": "any" }));

        assert!(shaped.get("stream").is_none(), "stream stripped for buffered path");
        assert!(
            shaped
                .get("stream_options")
                .is_none()
        );
        assert!(
            shaped
                .get("parallel_tool_calls")
                .is_none()
        );
        assert_eq!(shaped["max_tokens"], json!(4096), "default max_tokens injected");
    }

    #[test]
    fn anthropic_maps_chat_user_to_metadata_user_id() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "user": "u-42"
        }));
        assert!(shaped.get("user").is_none(), "top-level `user` must be removed (Anthropic rejects it)");
        assert_eq!(shaped["metadata"], json!({ "user_id": "u-42" }));
    }

    #[test]
    fn anthropic_messages_metadata_user_id_round_trips() {
        let canonical = transform_from_anthropic_request(json!({
            "model": "claude-x",
            "max_tokens": 64,
            "metadata": { "user_id": "claude-code-session" },
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        let shaped = transform_to_anthropic_format(canonical);
        assert!(shaped.get("user").is_none());
        assert_eq!(shaped["metadata"], json!({ "user_id": "claude-code-session" }));
    }

    #[test]
    fn anthropic_existing_metadata_user_id_wins_and_other_keys_dropped() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "user": "from-user",
            "metadata": { "user_id": "from-metadata", "trace": "t-1" }
        }));
        assert!(shaped.get("user").is_none());
        assert_eq!(shaped["metadata"], json!({ "user_id": "from-metadata" }));
    }

    #[test]
    fn anthropic_openai_metadata_without_user_id_takes_user() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "user": "u-7",
            "metadata": { "trace": "t-1" }
        }));
        assert_eq!(shaped["metadata"], json!({ "user_id": "u-7" }));
    }

    #[test]
    fn anthropic_non_string_user_is_dropped_not_mapped() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "user": 42
        }));
        assert!(shaped.get("user").is_none());
        assert!(
            shaped
                .get("metadata")
                .is_none()
        );
    }

    #[test]
    fn anthropic_without_user_adds_no_metadata() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        assert!(shaped.get("user").is_none());
        assert!(
            shaped
                .get("metadata")
                .is_none()
        );

        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "metadata": { "trace": "t-1" }
        }));
        assert!(
            shaped
                .get("metadata")
                .is_none(),
            "metadata without user_id is dropped"
        );
    }

    #[test]
    fn anthropic_strips_openai_only_sampling_fields() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "temperature": 0.2,
            "top_p": 0.9,
            "n": 1,
            "seed": 7,
            "logprobs": true,
            "top_logprobs": 2,
            "logit_bias": { "50256": -100 },
            "frequency_penalty": 0.1,
            "presence_penalty": 0.2,
            "store": false,
            "modalities": ["text", "audio"],
            "audio": { "voice": "alloy", "format": "wav" },
            "prediction": { "type": "content", "content": "draft" },
            "web_search_options": {},
            "safety_identifier": "hashed-user",
            "prompt_cache_key": "k-1",
            "verbosity": "low"
        }));
        for key in [
            "n",
            "seed",
            "logprobs",
            "top_logprobs",
            "logit_bias",
            "frequency_penalty",
            "presence_penalty",
            "store",
            "modalities",
            "audio",
            "prediction",
            "web_search_options",
            "safety_identifier",
            "prompt_cache_key",
            "verbosity",
        ] {
            assert!(shaped.get(key).is_none(), "`{key}` must be removed (Anthropic rejects it)");
        }
        assert_eq!(shaped["temperature"], json!(0.2));
        assert_eq!(shaped["top_p"], json!(0.9));
    }

    #[test]
    fn bedrock_anthropic_drops_user_metadata_and_service_tier() {
        let shaped = transform_to_bedrock_anthropic_format(json!({
            "model": "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
            "messages": [{ "role": "user", "content": "hi" }],
            "user": "u-42",
            "service_tier": "auto"
        }));
        assert!(shaped.get("user").is_none());
        assert!(
            shaped
                .get("service_tier")
                .is_none(),
            "Bedrock rejects `service_tier`"
        );
        assert!(
            shaped
                .get("metadata")
                .is_none(),
            "Bedrock rejects `metadata`"
        );
        assert_eq!(shaped["anthropic_version"], json!("bedrock-2023-05-31"));
    }

    fn bedrock_body(parts: Value) -> Value {
        transform_to_bedrock_anthropic_format(json!({
            "model": "anthropic.claude-3-5-haiku-20241022-v1:0",
            "messages": [{ "role": "user", "content": parts }]
        }))
    }

    #[test]
    fn anthropic_runs_legacy_functions_as_tools() {
        let shaped = transform_to_anthropic_format(json!({
            "model": "claude-haiku-4-5",
            "functions": [{ "name": "weather", "description": "Weather", "parameters": { "type": "object" } }],
            "function_call": { "name": "weather" },
            "messages": [
                { "role": "user", "content": "Weather in Paris?" },
                { "role": "assistant", "content": null,
                  "function_call": { "name": "weather", "arguments": "{\"city\":\"Paris\"}" } },
                { "role": "function", "name": "weather", "content": "Sunny" }
            ]
        }));
        assert!(
            shaped
                .get("functions")
                .is_none()
        );
        assert!(
            shaped
                .get("function_call")
                .is_none()
        );
        assert_eq!(
            shaped["tools"],
            json!([{ "name": "weather", "description": "Weather", "input_schema": { "type": "object" } }])
        );
        assert_eq!(shaped["tool_choice"], json!({ "type": "tool", "name": "weather" }));
        let messages = shaped["messages"]
            .as_array()
            .expect("messages");
        assert_eq!(messages.len(), 3);
        assert_eq!(
            messages[1]["content"][0],
            json!({ "type": "tool_use", "id": "call_legacy_1", "name": "weather", "input": { "city": "Paris" } })
        );
        assert_eq!(messages[2]["role"], json!("user"));
        assert_eq!(
            messages[2]["content"][0],
            json!({ "type": "tool_result", "tool_use_id": "call_legacy_1", "content": "Sunny" })
        );
    }

    #[test]
    fn anthropic_legacy_function_call_strings_and_modern_fields_win() {
        let auto = transform_to_anthropic_format(json!({
            "functions": [{ "name": "a", "parameters": {} }],
            "function_call": "auto",
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        assert_eq!(auto["tool_choice"], json!({ "type": "auto" }));

        let none = transform_to_anthropic_format(json!({
            "functions": [{ "name": "a", "parameters": {} }],
            "function_call": "none",
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        assert!(
            none.get("tool_choice")
                .is_none()
        );

        let modern = transform_to_anthropic_format(json!({
            "tools": [{ "type": "function", "function": { "name": "modern", "parameters": {} } }],
            "functions": [{ "name": "legacy", "parameters": {} }],
            "function_call": { "name": "legacy" },
            "tool_choice": "required",
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        assert_eq!(modern["tools"][0]["name"], json!("modern"));
        assert_eq!(
            modern["tools"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(modern["tool_choice"], json!({ "type": "any" }));
        assert!(
            modern
                .get("functions")
                .is_none()
        );
    }

    #[test]
    fn anthropic_takes_safety_identifier_when_no_user_is_given() {
        let only_safety = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "safety_identifier": "hashed-7"
        }));
        assert_eq!(only_safety["metadata"], json!({ "user_id": "hashed-7" }));
        assert!(
            only_safety
                .get("safety_identifier")
                .is_none()
        );

        let both = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "user": "u-42",
            "safety_identifier": "hashed-7"
        }));
        assert_eq!(both["metadata"], json!({ "user_id": "u-42" }));

        let not_a_string = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "safety_identifier": 7
        }));
        assert!(
            not_a_string
                .get("metadata")
                .is_none()
        );
    }

    #[test]
    fn bedrock_refuses_url_and_file_sources() {
        let url_image = bedrock_body(json!([
            { "type": "image_url", "image_url": { "url": "https://example.com/cat.png" } }
        ]));
        assert_eq!(bedrock_unsupported_source(&url_image), Some(BEDROCK_URL_SOURCE_UNSUPPORTED));

        let file_id = bedrock_body(json!([
            { "type": "text", "text": "Summarise" },
            { "type": "file", "file": { "file_id": "file_011abc" } }
        ]));
        assert_eq!(bedrock_unsupported_source(&file_id), Some(BEDROCK_FILE_SOURCE_UNSUPPORTED));

        let in_tool_result = transform_to_bedrock_anthropic_format(json!({
            "model": "anthropic.claude-3-5-haiku-20241022-v1:0",
            "messages": [
                { "role": "assistant", "tool_calls": [{ "id": "t1", "type": "function",
                    "function": { "name": "snap", "arguments": "{}" } }] },
                { "role": "tool", "tool_call_id": "t1", "content": [
                    { "type": "image_url", "image_url": { "url": "https://example.com/shot.png" } }
                ] }
            ]
        }));
        assert_eq!(bedrock_unsupported_source(&in_tool_result), Some(BEDROCK_URL_SOURCE_UNSUPPORTED));
    }

    #[test]
    fn bedrock_takes_inline_sources_and_text() {
        let inline = bedrock_body(json!([
            { "type": "text", "text": "What is this?" },
            { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0KGgo=" } },
            { "type": "file", "file": { "file_data": "data:application/pdf;base64,JVBERi0=", "filename": "a.pdf" } }
        ]));
        assert_eq!(inline["messages"][0]["content"][1]["source"]["type"], json!("base64"));
        assert_eq!(bedrock_unsupported_source(&inline), None);
        assert_eq!(bedrock_unsupported_source(&bedrock_body(json!("hello"))), None);
        assert_eq!(bedrock_unsupported_source(&json!({})), None);
    }

    #[test]
    fn anthropic_maps_openai_service_tier() {
        let tier_of = |tier: Value| {
            transform_to_anthropic_format(json!({
                "messages": [{ "role": "user", "content": "hi" }],
                "service_tier": tier
            }))
            .get("service_tier")
            .cloned()
        };
        assert_eq!(tier_of(json!("auto")), Some(json!("auto")));
        assert_eq!(tier_of(json!("default")), Some(json!("standard_only")));
        assert_eq!(tier_of(json!("standard_only")), Some(json!("standard_only")));
        assert_eq!(tier_of(json!("flex")), None);
        assert_eq!(tier_of(json!("priority")), None);
        assert_eq!(tier_of(json!(1)), None);

        let shaped = transform_to_anthropic_format(json!({ "messages": [{ "role": "user", "content": "hi" }] }));
        assert!(
            shaped
                .get("service_tier")
                .is_none(),
            "no tier is added when none was sent"
        );
    }

    #[test]
    fn anthropic_named_tool_choice_becomes_tool_object() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tool_choice": { "type": "function", "function": { "name": "search" } }
        });
        let shaped = transform_to_anthropic_format(body);
        assert_eq!(shaped["tool_choice"], json!({ "type": "tool", "name": "search" }));
    }

    #[test]
    fn anthropic_none_tool_choice_is_dropped() {
        let body = json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "tool_choice": "none"
        });
        let shaped = transform_to_anthropic_format(body);
        assert!(
            shaped
                .get("tool_choice")
                .is_none(),
            "'none' tool_choice dropped (defaults to auto)"
        );
    }

    #[test]
    fn anthropic_renames_stop_to_stop_sequences() {
        // Array form.
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "stop": ["4", "STOP"]
        }));
        assert!(shaped.get("stop").is_none(), "raw `stop` must be removed (Anthropic rejects it)");
        assert_eq!(shaped["stop_sequences"], json!(["4", "STOP"]));

        // String form is wrapped into an array.
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "stop": "4"
        }));
        assert!(shaped.get("stop").is_none());
        assert_eq!(shaped["stop_sequences"], json!(["4"]));
    }

    #[test]
    fn anthropic_converts_tool_call_round_trip_messages() {
        let body = json!({
            "messages": [
                { "role": "user", "content": "Weather in Paris?" },
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": { "name": "get_weather", "arguments": "{\"city\":\"Paris\"}" }
                    }]
                },
                { "role": "tool", "tool_call_id": "call_1", "content": "18C sunny" }
            ]
        });
        let shaped = transform_to_anthropic_format(body);
        let messages = shaped["messages"]
            .as_array()
            .unwrap();
        // user, assistant(tool_use), user(tool_result)
        assert_eq!(messages.len(), 3);

        assert_eq!(messages[0]["role"], json!("user"));
        assert_eq!(messages[0]["content"][0]["type"], json!("text"));
        assert_eq!(messages[0]["content"][0]["text"], json!("Weather in Paris?"));

        assert_eq!(messages[1]["role"], json!("assistant"));
        let use_block = &messages[1]["content"][0];
        assert_eq!(use_block["type"], json!("tool_use"));
        assert_eq!(use_block["id"], json!("call_1"));
        assert_eq!(use_block["name"], json!("get_weather"));
        assert_eq!(use_block["input"], json!({ "city": "Paris" }));

        assert_eq!(messages[2]["role"], json!("user"));
        let result_block = &messages[2]["content"][0];
        assert_eq!(result_block["type"], json!("tool_result"));
        assert_eq!(result_block["tool_use_id"], json!("call_1"));
        assert_eq!(result_block["content"], json!("18C sunny"));
    }

    #[test]
    fn anthropic_merges_consecutive_same_role_turns() {
        // Two tool results in a row must collapse into a single user message so
        // Anthropic's strict user/assistant alternation is preserved.
        let body = json!({
            "messages": [
                { "role": "assistant", "content": null, "tool_calls": [
                    { "id": "a", "type": "function", "function": { "name": "f", "arguments": "{}" } },
                    { "id": "b", "type": "function", "function": { "name": "g", "arguments": "{}" } }
                ] },
                { "role": "tool", "tool_call_id": "a", "content": "ra" },
                { "role": "tool", "tool_call_id": "b", "content": "rb" }
            ]
        });
        let shaped = transform_to_anthropic_format(body);
        let messages = shaped["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages.len(), 2, "assistant turn, then one merged user turn");
        assert_eq!(
            messages[0]["content"]
                .as_array()
                .unwrap()
                .len(),
            2,
            "both tool_use blocks in one assistant message"
        );
        assert_eq!(messages[1]["role"], json!("user"));
        assert_eq!(
            messages[1]["content"]
                .as_array()
                .unwrap()
                .len(),
            2,
            "both tool_result blocks merged into one user message"
        );
    }

    // ── Inbound skin transforms (Anthropic / Responses → OpenAI) ──

    #[test]
    fn anthropic_request_lifts_system_and_maps_roles() {
        let body = json!({
            "model": "claude-x",
            "system": "You are helpful.",
            "max_tokens": 256,
            "stop_sequences": ["STOP"],
            "temperature": 0.5,
            "top_k": 40,
            "metadata": { "user_id": "u-123" },
            "messages": [
                { "role": "user", "content": "Hello" },
                { "role": "assistant", "content": [ { "type": "text", "text": "Hi" } ] }
            ]
        });
        let out = transform_from_anthropic_request(body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0]["role"], json!("system"));
        assert_eq!(messages[0]["content"], json!("You are helpful."));
        assert_eq!(messages[1], json!({ "role": "user", "content": "Hello" }));
        assert_eq!(messages[2], json!({ "role": "assistant", "content": "Hi" }));
        assert_eq!(out["max_tokens"], json!(256));
        assert_eq!(out["stop"], json!(["STOP"]));
        assert_eq!(out["temperature"], json!(0.5));
        assert_eq!(out["user"], json!("u-123"));
        // top_k has no OpenAI equivalent and must be dropped.
        assert!(out.get("top_k").is_none());
    }

    #[test]
    fn anthropic_request_maps_tools_and_tool_choice() {
        let body = json!({
            "messages": [ { "role": "user", "content": "hi" } ],
            "tools": [ { "name": "get_weather", "description": "w", "input_schema": { "type": "object" } } ],
            "tool_choice": { "type": "tool", "name": "get_weather" }
        });
        let out = transform_from_anthropic_request(body);
        assert_eq!(out["tools"][0]["type"], json!("function"));
        assert_eq!(out["tools"][0]["function"]["name"], json!("get_weather"));
        assert_eq!(out["tools"][0]["function"]["parameters"], json!({ "type": "object" }));
        assert_eq!(out["tool_choice"], json!({ "type": "function", "function": { "name": "get_weather" } }));
    }

    #[test]
    fn anthropic_request_tool_use_and_tool_result_roundtrip() {
        let body = json!({
            "messages": [
                { "role": "assistant", "content": [
                    { "type": "text", "text": "calling" },
                    { "type": "tool_use", "id": "call_1", "name": "get_weather", "input": { "city": "Paris" } }
                ]},
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "call_1", "content": "sunny" }
                ]}
            ]
        });
        let out = transform_from_anthropic_request(body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0]["role"], json!("assistant"));
        assert_eq!(messages[0]["content"], json!("calling"));
        assert_eq!(messages[0]["tool_calls"][0]["id"], json!("call_1"));
        assert_eq!(messages[0]["tool_calls"][0]["function"]["name"], json!("get_weather"));
        let args = messages[0]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert_eq!(serde_json::from_str::<Value>(args).unwrap(), json!({ "city": "Paris" }));
        assert_eq!(messages[1], json!({ "role": "tool", "tool_call_id": "call_1", "content": "sunny" }));
    }

    #[test]
    fn anthropic_request_maps_base64_image_block() {
        let body = json!({
            "messages": [ { "role": "user", "content": [
                { "type": "text", "text": "what is this?" },
                { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "AAAA" } }
            ]}]
        });
        let out = transform_from_anthropic_request(body);
        let content = out["messages"][0]["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[0], json!({ "type": "text", "text": "what is this?" }));
        assert_eq!(content[1]["type"], json!("image_url"));
        assert_eq!(content[1]["image_url"]["url"], json!("data:image/png;base64,AAAA"));
    }

    #[test]
    fn anthropic_request_maps_base64_document_block_to_file_part() {
        let body = json!({
            "messages": [ { "role": "user", "content": [
                { "type": "text", "text": "summarise" },
                { "type": "document", "title": "report.pdf",
                  "source": { "type": "base64", "media_type": "application/pdf", "data": "QUJD" } }
            ]}]
        });
        let out = transform_from_anthropic_request(body);
        let content = out["messages"][0]["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[1]["type"], json!("file"));
        assert_eq!(content[1]["file"]["filename"], json!("report.pdf"));
        assert_eq!(content[1]["file"]["file_data"], json!("data:application/pdf;base64,QUJD"));
    }

    #[test]
    fn anthropic_request_maps_text_document_block_to_text_part() {
        let body = json!({
            "messages": [ { "role": "user", "content": [
                { "type": "document", "source": { "type": "text", "media_type": "text/plain", "data": "hello body" } }
            ]}]
        });
        let out = transform_from_anthropic_request(body);
        let content = &out["messages"][0]["content"];
        // A lone text part collapses to a string.
        assert_eq!(content, &json!("hello body"));
    }

    #[test]
    fn anthropic_response_from_openai_text() {
        let openai = json!({
            "id": "chatcmpl-1",
            "choices": [ { "index": 0, "message": { "role": "assistant", "content": "Hello there" }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15 }
        });
        let out = transform_to_anthropic_response(&openai, "claude-x");
        assert_eq!(out["type"], json!("message"));
        assert_eq!(out["role"], json!("assistant"));
        assert_eq!(out["model"], json!("claude-x"));
        assert_eq!(out["content"][0], json!({ "type": "text", "text": "Hello there" }));
        assert_eq!(out["stop_reason"], json!("end_turn"));
        assert_eq!(out["usage"], json!({ "input_tokens": 10, "output_tokens": 5 }));
        assert!(
            out["id"]
                .as_str()
                .unwrap()
                .starts_with("msg_")
        );
    }

    #[test]
    fn anthropic_response_from_openai_tool_calls() {
        let openai = json!({
            "id": "chatcmpl-2",
            "choices": [ { "index": 0, "message": { "role": "assistant", "content": Value::Null, "tool_calls": [
                { "id": "call_9", "type": "function", "function": { "name": "lookup", "arguments": "{\"q\":\"x\"}" } }
            ]}, "finish_reason": "tool_calls" } ],
            "usage": { "prompt_tokens": 3, "completion_tokens": 7 }
        });
        let out = transform_to_anthropic_response(&openai, "");
        assert_eq!(out["stop_reason"], json!("tool_use"));
        assert_eq!(out["content"][0]["type"], json!("tool_use"));
        assert_eq!(out["content"][0]["id"], json!("call_9"));
        assert_eq!(out["content"][0]["name"], json!("lookup"));
        assert_eq!(out["content"][0]["input"], json!({ "q": "x" }));
    }

    #[test]
    fn anthropic_response_always_has_a_content_block() {
        let openai =
            json!({ "choices": [ { "message": { "role": "assistant", "content": "" }, "finish_reason": "stop" } ] });
        let out = transform_to_anthropic_response(&openai, "m");
        assert_eq!(out["content"][0], json!({ "type": "text", "text": "" }));
    }

    #[test]
    fn responses_request_string_input_and_instructions() {
        let body = json!({
            "model": "gpt-x",
            "instructions": "Be terse.",
            "input": "Hello",
            "max_output_tokens": 128,
            "temperature": 0.2,
            "text": { "format": { "type": "json_object" } }
        });
        let out = transform_from_responses_request(body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0], json!({ "role": "system", "content": "Be terse." }));
        assert_eq!(messages[1], json!({ "role": "user", "content": "Hello" }));
        assert_eq!(out["max_tokens"], json!(128));
        assert_eq!(out["response_format"], json!({ "type": "json_object" }));
    }

    #[test]
    fn responses_request_carries_user_to_anthropic_metadata_user_id() {
        let canonical = transform_from_responses_request(json!({ "input": "hi", "user": "u-42" }));
        assert_eq!(canonical["user"], json!("u-42"));
        let shaped = transform_to_anthropic_format(canonical);
        assert!(shaped.get("user").is_none());
        assert_eq!(shaped["metadata"], json!({ "user_id": "u-42" }));
    }

    #[test]
    fn responses_request_takes_metadata_user_id_when_user_is_absent() {
        let out = transform_from_responses_request(json!({
            "input": "hi",
            "metadata": { "user_id": "m-7", "trace": "t-1" }
        }));
        assert_eq!(out["user"], json!("m-7"));
        assert!(out.get("metadata").is_none(), "Responses metadata is not forwarded");

        let out = transform_from_responses_request(json!({
            "input": "hi",
            "user": "u-42",
            "metadata": { "user_id": "m-7" }
        }));
        assert_eq!(out["user"], json!("u-42"), "an explicit `user` wins");
    }

    #[test]
    fn responses_request_without_a_string_user_sets_none() {
        for body in [
            json!({ "input": "hi" }),
            json!({ "input": "hi", "user": 42 }),
            json!({ "input": "hi", "metadata": { "user_id": 7 } }),
            json!({ "input": "hi", "metadata": { "trace": "t-1" } }),
        ] {
            let out = transform_from_responses_request(body.clone());
            assert!(out.get("user").is_none(), "{body}");
        }
    }

    #[test]
    fn responses_request_maps_input_file_to_file_part() {
        let body = json!({
            "input": [
                { "type": "message", "role": "user", "content": [
                    { "type": "input_text", "text": "read this" },
                    { "type": "input_file", "filename": "a.docx", "file_data": "data:application/octet-stream;base64,QUJD" }
                ] }
            ]
        });
        let out = transform_from_responses_request(body);
        let content = out["messages"][0]["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[1]["type"], json!("file"));
        assert_eq!(content[1]["file"]["filename"], json!("a.docx"));
        assert_eq!(content[1]["file"]["file_data"], json!("data:application/octet-stream;base64,QUJD"));
    }

    #[test]
    fn responses_request_maps_input_audio() {
        let body = json!({
            "input": [
                { "type": "message", "role": "user", "content": [
                    { "type": "input_audio", "input_audio": { "data": "QUJD", "format": "wav" } }
                ] }
            ]
        });
        let out = transform_from_responses_request(body);
        let content = out["messages"][0]["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[0]["type"], json!("input_audio"));
        assert_eq!(content[0]["input_audio"]["format"], json!("wav"));
        assert_eq!(content[0]["input_audio"]["data"], json!("QUJD"));
    }

    #[test]
    fn responses_request_item_array_with_tools() {
        let body = json!({
            "input": [
                { "type": "message", "role": "user", "content": [ { "type": "input_text", "text": "hi" } ] },
                { "type": "function_call", "call_id": "call_1", "name": "f", "arguments": "{}" },
                { "type": "function_call_output", "call_id": "call_1", "output": "42" }
            ],
            "tools": [ { "type": "function", "name": "f", "description": "d", "parameters": { "type": "object" } } ],
            "tool_choice": { "type": "function", "name": "f" }
        });
        let out = transform_from_responses_request(body);
        let messages = out["messages"]
            .as_array()
            .unwrap();
        assert_eq!(messages[0], json!({ "role": "user", "content": "hi" }));
        assert_eq!(messages[1]["role"], json!("assistant"));
        assert_eq!(messages[1]["tool_calls"][0]["id"], json!("call_1"));
        assert_eq!(messages[2], json!({ "role": "tool", "tool_call_id": "call_1", "content": "42" }));
        assert_eq!(out["tools"][0]["function"]["name"], json!("f"));
        assert_eq!(out["tool_choice"], json!({ "type": "function", "function": { "name": "f" } }));
    }

    #[test]
    fn responses_response_from_openai_text() {
        let openai = json!({
            "id": "chatcmpl-3",
            "choices": [ { "index": 0, "message": { "role": "assistant", "content": "Answer" }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 8, "completion_tokens": 2, "total_tokens": 10 }
        });
        let out = transform_to_responses_response(&openai, "gpt-x");
        assert_eq!(out["object"], json!("response"));
        assert_eq!(out["status"], json!("completed"));
        assert_eq!(out["output"][0]["type"], json!("message"));
        assert_eq!(out["output"][0]["content"][0]["type"], json!("output_text"));
        assert_eq!(out["output"][0]["content"][0]["text"], json!("Answer"));
        assert_eq!(out["output_text"], json!("Answer"));
        assert_eq!(out["usage"], json!({ "input_tokens": 8, "output_tokens": 2, "total_tokens": 10 }));
        assert!(
            out["id"]
                .as_str()
                .unwrap()
                .starts_with("resp_")
        );
    }

    #[test]
    fn responses_response_tool_call_and_incomplete() {
        let openai = json!({
            "choices": [ { "message": { "role": "assistant", "content": Value::Null, "tool_calls": [
                { "id": "call_5", "type": "function", "function": { "name": "f", "arguments": "{\"a\":1}" } }
            ]}, "finish_reason": "length" } ],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 }
        });
        let out = transform_to_responses_response(&openai, "m");
        assert_eq!(out["status"], json!("incomplete"));
        assert_eq!(out["incomplete_details"]["reason"], json!("max_output_tokens"));
        let fc = out["output"]
            .as_array()
            .unwrap()
            .iter()
            .find(|i| i["type"] == json!("function_call"))
            .unwrap();
        assert_eq!(fc["call_id"], json!("call_5"));
        assert_eq!(fc["name"], json!("f"));
        assert_eq!(fc["arguments"], json!("{\"a\":1}"));
    }

    #[test]
    fn anthropic_ingress_maps_thinking_to_reasoning() {
        let out = transform_from_anthropic_request(json!({
            "model": "claude-haiku-4-5",
            "max_tokens": 1024,
            "thinking": { "type": "enabled", "budget_tokens": 2048 },
            "messages": [{ "role": "user", "content": "Hi" }]
        }));
        assert_eq!(out["reasoning"]["enabled"], json!(true));
        assert_eq!(out["reasoning"]["max_tokens"], json!(2048));
    }

    #[test]
    fn responses_ingress_maps_reasoning_effort() {
        let out = transform_from_responses_request(json!({
            "model": "gpt-5",
            "input": "Hi",
            "reasoning": { "effort": "high", "summary": "auto" }
        }));
        assert_eq!(out["reasoning"]["effort"], json!("high"));
        assert!(
            out["reasoning"]
                .get("summary")
                .is_none()
        );
    }

    #[test]
    fn anthropic_wire_maps_reasoning_to_thinking() {
        // Canonical reasoning on an OpenAI-shaped body → Anthropic `thinking`.
        let shaped = transform_to_anthropic_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 32000,
            "temperature": 0.7,
            "reasoning": { "effort": "high" }
        }));
        assert_eq!(shaped["thinking"]["type"], json!("enabled"));
        assert_eq!(shaped["thinking"]["budget_tokens"], json!(crate::pipes::reasoning::BUDGET_HIGH));
        assert!(
            shaped
                .get("reasoning")
                .is_none(),
            "canonical reasoning stripped for Anthropic"
        );
        assert!(
            shaped
                .get("temperature")
                .is_none(),
            "temperature dropped with thinking on"
        );
    }

    #[test]
    fn gemini_wire_maps_reasoning_to_thinking_config() {
        let shaped = transform_to_gemini_format(json!({
            "messages": [{ "role": "user", "content": "hi" }],
            "max_tokens": 200,
            "reasoning": { "effort": "low" }
        }));
        assert_eq!(
            shaped["generationConfig"]["thinkingConfig"]["thinkingBudget"],
            json!(crate::pipes::reasoning::BUDGET_LOW)
        );
        assert_eq!(shaped["generationConfig"]["thinkingConfig"]["includeThoughts"], json!(true));
    }

    #[test]
    fn openai_reasoning_model_folds_reasoning_object_to_effort() {
        let profile = resolve_profile_from_providers(&catalog(), "openai", "gpt-5", "openai", None);
        let shaped = shape_request(
            &profile,
            json!({
                "model": "gpt-5",
                "messages": [{ "role": "user", "content": "Hi" }],
                "reasoning": { "effort": "high" }
            }),
        );
        assert_eq!(shaped["reasoning_effort"], json!("high"));
        assert!(
            shaped
                .get("reasoning")
                .is_none(),
            "reasoning object not sent to Chat Completions"
        );
    }

    #[test]
    fn anthropic_response_emits_thinking_from_details() {
        let openai = json!({
            "id": "chatcmpl_1",
            "choices": [ { "message": {
                "role": "assistant",
                "content": "final answer",
                "reasoning": "because",
                "reasoning_details": [ { "type": "reasoning.text", "text": "because", "signature": "sig" } ]
            }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 3, "completion_tokens": 4 }
        });
        let out = transform_to_anthropic_response(&openai, "claude-haiku-4-5");
        let content = out["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[0]["type"], json!("thinking"), "thinking block comes first");
        assert_eq!(content[0]["thinking"], json!("because"));
        assert_eq!(content[0]["signature"], json!("sig"));
        assert_eq!(content[1]["type"], json!("text"));
        assert_eq!(content[1]["text"], json!("final answer"));
    }

    #[test]
    fn anthropic_response_emits_thinking_from_plain_reasoning() {
        let openai = json!({
            "choices": [ { "message": { "role": "assistant", "content": "answer", "reasoning": "steps" }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 }
        });
        let out = transform_to_anthropic_response(&openai, "m");
        let content = out["content"]
            .as_array()
            .unwrap();
        assert_eq!(content[0]["type"], json!("thinking"));
        assert_eq!(content[0]["thinking"], json!("steps"));
    }

    #[test]
    fn responses_response_emits_reasoning_item_first() {
        let openai = json!({
            "choices": [ { "message": { "role": "assistant", "content": "answer", "reasoning": "steps" }, "finish_reason": "stop" } ],
            "usage": { "prompt_tokens": 1, "completion_tokens": 1 }
        });
        let out = transform_to_responses_response(&openai, "m");
        let output = out["output"]
            .as_array()
            .unwrap();
        assert_eq!(output[0]["type"], json!("reasoning"));
        assert_eq!(output[0]["summary"][0]["text"], json!("steps"));
        assert_eq!(output[1]["type"], json!("message"));
    }

    #[test]
    fn anthropic_wire_preserves_cache_control_on_system() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [
                { "role": "system", "content": [
                    { "type": "text", "text": "big context", "cache_control": { "type": "ephemeral" } }
                ]},
                { "role": "user", "content": "hi" }
            ],
            "max_tokens": 64
        }));
        // System is emitted as a block array carrying the breakpoint.
        let system = shaped["system"]
            .as_array()
            .expect("system block array");
        assert_eq!(system[0]["type"], json!("text"));
        assert_eq!(system[0]["text"], json!("big context"));
        assert_eq!(system[0]["cache_control"], json!({ "type": "ephemeral" }));
    }

    #[test]
    fn anthropic_wire_preserves_cache_control_on_user_message() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [
                { "role": "user", "content": [
                    { "type": "text", "text": "cache me", "cache_control": { "type": "ephemeral" } }
                ]}
            ],
            "max_tokens": 64
        }));
        let user = &shaped["messages"][0];
        assert_eq!(user["role"], json!("user"));
        assert_eq!(user["content"][0]["cache_control"], json!({ "type": "ephemeral" }));
    }

    #[test]
    fn anthropic_wire_without_cache_control_keeps_flattened_system() {
        // Regression: no breakpoint → system stays a plain string.
        let shaped = transform_to_anthropic_format(json!({
            "messages": [
                { "role": "system", "content": "plain" },
                { "role": "user", "content": "hi" }
            ],
            "max_tokens": 64
        }));
        assert_eq!(shaped["system"], json!("plain"));
    }

    fn anthropic_user_content(parts: Value) -> Value {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [ { "role": "user", "content": parts } ],
            "max_tokens": 64
        }));
        assert_eq!(shaped["messages"][0]["role"], json!("user"));
        shaped["messages"][0]["content"].clone()
    }

    #[test]
    fn anthropic_wire_sends_base64_image_after_its_text() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "what is this?" },
            { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0K" } }
        ]));
        assert_eq!(
            content,
            json!([
                { "type": "text", "text": "what is this?" },
                { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0K" } }
            ])
        );
    }

    #[test]
    fn anthropic_wire_normalises_jpg_media_type() {
        let content = anthropic_user_content(
            json!([{ "type": "image_url", "image_url": { "url": "data:image/JPG;base64,/9j/" } }]),
        );
        assert_eq!(content[0]["source"], json!({ "type": "base64", "media_type": "image/jpeg", "data": "/9j/" }));
    }

    #[test]
    fn anthropic_wire_hands_remote_image_url_to_the_provider() {
        let content = anthropic_user_content(json!([
            { "type": "image_url", "image_url": { "url": "https://example.test/cat.png" } }
        ]));
        assert_eq!(
            content,
            json!([{ "type": "image", "source": { "type": "url", "url": "https://example.test/cat.png" } }])
        );
    }

    #[test]
    fn anthropic_wire_keeps_mixed_part_order() {
        let content = anthropic_user_content(json!([
            { "type": "image_url", "image_url": { "url": "data:image/gif;base64,R0lG" } },
            { "type": "text", "text": "compare with" },
            { "type": "image_url", "image_url": { "url": "http://example.test/b.webp" } },
            { "type": "text", "text": "done" }
        ]));
        let kinds: Vec<&str> = content
            .as_array()
            .unwrap()
            .iter()
            .map(|b| b["type"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, vec!["image", "text", "image", "text"]);
        assert_eq!(content[0]["source"]["media_type"], json!("image/gif"));
        assert_eq!(content[1]["text"], json!("compare with"));
        assert_eq!(content[2]["source"]["url"], json!("http://example.test/b.webp"));
        assert_eq!(content[3]["text"], json!("done"));
    }

    #[test]
    fn anthropic_wire_sends_inline_pdf_as_document() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "summarise" },
            { "type": "file", "file": { "filename": "report.pdf", "file_data": "data:application/pdf;base64,JVBERi0x" } }
        ]));
        assert_eq!(
            content[1],
            json!({
                "type": "document",
                "title": "report.pdf",
                "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0x" }
            })
        );
    }

    #[test]
    fn anthropic_wire_sends_inline_text_document_as_text_source() {
        let content = anthropic_user_content(json!([
            { "type": "file", "file": { "file_data": "data:text/markdown;base64,IyBUaXRsZQ==" } }
        ]));
        assert_eq!(
            content,
            json!([{ "type": "document", "source": { "type": "text", "media_type": "text/plain", "data": "# Title" } }])
        );
    }

    #[test]
    fn anthropic_wire_sends_an_inline_image_file_as_an_image_block() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "what is this?" },
            { "type": "file", "file": { "filename": "cat.jpg", "file_data": "data:image/jpg;base64,/9j/4AAQ" } }
        ]));
        assert_eq!(
            content[1],
            json!({ "type": "image", "source": { "type": "base64", "media_type": "image/jpeg", "data": "/9j/4AAQ" } })
        );
    }

    #[test]
    fn anthropic_wire_drops_a_file_claude_cannot_read() {
        for mime in [
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/octet-stream",
            "image/bmp",
        ] {
            let content = anthropic_user_content(json!([
                { "type": "text", "text": "read this" },
                { "type": "file", "file": { "file_data": format!("data:{mime};base64,UEsDBA==") } }
            ]));
            assert_eq!(content, json!([{ "type": "text", "text": "read this" }]), "{mime}");
        }
    }

    fn with_file(file: Value) -> Value {
        json!({ "messages": [{ "role": "user", "content": [
            { "type": "text", "text": "read this" },
            { "type": "file", "file": file }
        ] }] })
    }

    #[test]
    fn claude_refuses_a_file_it_cannot_read() {
        for file_data in [
            "data:application/vnd.openxmlformats-officedocument.wordprocessingml.document;base64,UEsDBA==",
            "data:application/octet-stream;base64,AAEC",
            "data:image/tiff;base64,SUkqAA==",
            "data:application/pdf,not-base64",
            "data:text/plain;base64,@@not base64@@",
            "data:text/csv;base64,6WzpbA==",
        ] {
            assert_eq!(
                claude_unreadable_file(&with_file(json!({ "file_data": file_data }))),
                Some(CLAUDE_UNREADABLE_FILE),
                "{file_data}"
            );
        }
    }

    #[test]
    fn claude_takes_pdf_text_image_and_file_id() {
        for file in [
            json!({ "file_data": "data:application/pdf;base64,JVBERi0x" }),
            json!({ "file_data": "data:text/csv;base64,YSxi" }),
            json!({ "file_data": "data:application/json;base64,e30=" }),
            json!({ "file_data": "data:image/png;base64,iVBORw0KGgo=" }),
            json!({ "file_id": "file_011abc" }),
        ] {
            assert_eq!(claude_unreadable_file(&with_file(file.clone())), None, "{file}");
        }
        assert_eq!(claude_unreadable_file(&json!({ "messages": [{ "role": "user", "content": "hi" }] })), None);
        assert_eq!(claude_unreadable_file(&json!({})), None);
    }

    #[test]
    fn anthropic_wire_sends_file_id_as_files_api_source() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "read this" },
            { "type": "file", "file": { "file_id": "file_011abc" } }
        ]));
        assert_eq!(content[1], json!({ "type": "document", "source": { "type": "file", "file_id": "file_011abc" } }));
    }

    #[test]
    fn anthropic_wire_keeps_cache_control_on_an_image() {
        let content = anthropic_user_content(json!([
            { "type": "image_url", "image_url": { "url": "data:image/png;base64,AAAA" },
              "cache_control": { "type": "ephemeral" } },
            { "type": "text", "text": "describe" }
        ]));
        assert_eq!(content[0]["type"], json!("image"));
        assert_eq!(content[0]["cache_control"], json!({ "type": "ephemeral" }));
        assert!(
            content[1]
                .get("cache_control")
                .is_none()
        );
    }

    #[test]
    fn anthropic_wire_still_collapses_text_parts_without_a_breakpoint() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "one " },
            { "type": "input_audio", "input_audio": { "data": "AAAA", "format": "wav" } },
            { "type": "text", "text": "two" }
        ]));
        assert_eq!(content, json!([{ "type": "text", "text": "one two" }]));
    }

    #[test]
    fn anthropic_wire_drops_malformed_data_urls() {
        for url in [
            "data:image/png,not-base64",
            "data:image/png;base64,",
            "data:;base64,AAAA",
            "data:image/png;base64",
            "data:",
        ] {
            let content = anthropic_user_content(json!([
                { "type": "text", "text": "x" },
                { "type": "image_url", "image_url": { "url": url } }
            ]));
            assert_eq!(content, json!([{ "type": "text", "text": "x" }]), "{url}");
        }
    }

    #[test]
    fn anthropic_wire_never_forwards_non_http_image_urls() {
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://example.test/a.png",
            "gopher://127.0.0.1:6379/",
            "//example.test/a.png",
        ] {
            let content = anthropic_user_content(json!([
                { "type": "text", "text": "x" },
                { "type": "image_url", "image_url": { "url": url } }
            ]));
            assert_eq!(content, json!([{ "type": "text", "text": "x" }]), "{url}");
        }
    }

    #[test]
    fn anthropic_wire_drops_unknown_and_empty_parts() {
        let content = anthropic_user_content(json!([
            { "type": "text", "text": "x" },
            { "type": "video_url", "video_url": { "url": "https://example.test/a.mp4" } },
            { "type": "file", "file": {} },
            { "type": "file", "file": { "file_id": "" } },
            { "type": "image_url" }
        ]));
        assert_eq!(content, json!([{ "type": "text", "text": "x" }]));
    }

    #[test]
    fn anthropic_wire_system_prompt_stays_text_only() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [
                { "role": "system", "content": [
                    { "type": "text", "text": "rules", "cache_control": { "type": "ephemeral" } },
                    { "type": "image_url", "image_url": { "url": "data:image/png;base64,AAAA" } }
                ]},
                { "role": "user", "content": "hi" }
            ],
            "max_tokens": 64
        }));
        assert_eq!(
            shaped["system"],
            json!([{ "type": "text", "text": "rules", "cache_control": { "type": "ephemeral" } }])
        );
    }

    #[test]
    fn anthropic_wire_carries_an_image_in_a_tool_result() {
        let shaped = transform_to_anthropic_format(json!({
            "messages": [
                { "role": "user", "content": "screenshot please" },
                { "role": "assistant", "content": null, "tool_calls": [
                    { "id": "call_1", "type": "function", "function": { "name": "shot", "arguments": "{}" } }
                ]},
                { "role": "tool", "tool_call_id": "call_1", "content": [
                    { "type": "text", "text": "here" },
                    { "type": "image_url", "image_url": { "url": "data:image/png;base64,AAAA" } }
                ]},
                { "role": "tool", "tool_call_id": "call_2", "content": "plain" }
            ],
            "max_tokens": 64
        }));
        let results = shaped["messages"][2]["content"]
            .as_array()
            .unwrap();
        assert_eq!(
            results[0]["content"],
            json!([
                { "type": "text", "text": "here" },
                { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "AAAA" } }
            ])
        );
        assert_eq!(results[1]["content"], json!("plain"));
    }

    #[test]
    fn anthropic_request_maps_files_api_document_to_file_id_part() {
        let out = transform_from_anthropic_request(json!({
            "messages": [ { "role": "user", "content": [
                { "type": "document", "title": "q3.pdf", "source": { "type": "file", "file_id": "file_011abc" } }
            ]}]
        }));
        assert_eq!(
            out["messages"][0]["content"],
            json!([{ "type": "file", "file": { "file_id": "file_011abc", "filename": "q3.pdf" } }])
        );
        let empty = transform_from_anthropic_request(json!({
            "messages": [ { "role": "user", "content": [
                { "type": "text", "text": "x" },
                { "type": "document", "source": { "type": "file", "file_id": "" } }
            ]}]
        }));
        assert_eq!(empty["messages"][0]["content"], json!("x"));
    }

    #[test]
    fn anthropic_media_blocks_round_trip_through_the_canonical_body() {
        let blocks = json!([
            { "type": "text", "text": "look" },
            { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0K" },
              "cache_control": { "type": "ephemeral" } },
            { "type": "image", "source": { "type": "url", "url": "https://example.test/cat.png" } },
            { "type": "document", "title": "report.pdf",
              "source": { "type": "base64", "media_type": "application/pdf", "data": "JVBERi0x" } },
            { "type": "document", "title": "q3.pdf", "source": { "type": "file", "file_id": "file_011abc" } },
            { "type": "document", "source": { "type": "text", "media_type": "text/plain", "data": "notes" } }
        ]);
        let canonical = transform_from_anthropic_request(json!({
            "model": "claude-sonnet-4",
            "max_tokens": 64,
            "messages": [ { "role": "user", "content": blocks } ]
        }));
        let shaped = transform_to_anthropic_format(canonical);
        let mut expected = blocks;
        expected[5] = json!({ "type": "text", "text": "notes" });
        assert_eq!(shaped["messages"][0]["content"], expected);
    }

    fn claude_code_screenshot_turn() -> Value {
        json!({
            "model": "claude-sonnet-4",
            "max_tokens": 64,
            "messages": [
                { "role": "user", "content": "What is on screen?" },
                { "role": "assistant", "content": [
                    { "type": "tool_use", "id": "toolu_1", "name": "screenshot", "input": {} }
                ] },
                { "role": "user", "content": [
                    { "type": "tool_result", "tool_use_id": "toolu_1", "content": [
                        { "type": "text", "text": "Captured." },
                        { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0K" } }
                    ] },
                    { "type": "text", "text": "Describe it." }
                ] }
            ]
        })
    }

    #[test]
    fn anthropic_tool_result_images_reach_the_canonical_tool_message() {
        let canonical = transform_from_anthropic_request(claude_code_screenshot_turn());
        let tool = &canonical["messages"][2];
        assert_eq!(tool["role"], json!("tool"));
        assert_eq!(tool["tool_call_id"], json!("toolu_1"));
        assert_eq!(
            tool["content"],
            json!([
                { "type": "text", "text": "Captured." },
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0K" } }
            ])
        );
    }

    #[test]
    fn anthropic_tool_result_images_round_trip_to_claude() {
        let shaped = transform_to_anthropic_format(transform_from_anthropic_request(claude_code_screenshot_turn()));
        assert_eq!(
            shaped["messages"][2]["content"],
            json!([
                { "type": "tool_result", "tool_use_id": "toolu_1", "content": [
                    { "type": "text", "text": "Captured." },
                    { "type": "image", "source": { "type": "base64", "media_type": "image/png", "data": "iVBORw0K" } }
                ] },
                { "type": "text", "text": "Describe it." }
            ])
        );
    }

    #[test]
    fn anthropic_text_tool_result_stays_a_string() {
        let canonical = transform_from_anthropic_request(json!({
            "messages": [{ "role": "user", "content": [
                { "type": "tool_result", "tool_use_id": "t1", "content": [{ "type": "text", "text": "42" }] },
                { "type": "tool_result", "tool_use_id": "t2", "content": "done" }
            ] }]
        }));
        assert_eq!(canonical["messages"][0]["content"], json!("42"));
        assert_eq!(canonical["messages"][1]["content"], json!("done"));
    }

    #[test]
    fn openai_wire_moves_tool_images_into_a_user_message() {
        let mut body = transform_from_anthropic_request(claude_code_screenshot_turn());
        move_tool_media_to_user_message(&mut body);
        let messages = body["messages"]
            .as_array()
            .expect("messages");
        assert_eq!(messages.len(), 5);
        assert_eq!(messages[2], json!({ "role": "tool", "tool_call_id": "toolu_1", "content": "Captured." }));
        assert_eq!(
            messages[3],
            json!({ "role": "user", "content": [
                { "type": "image_url", "image_url": { "url": "data:image/png;base64,iVBORw0K" } }
            ] })
        );
        assert_eq!(messages[4], json!({ "role": "user", "content": "Describe it." }));
    }

    #[test]
    fn openai_wire_flushes_tool_images_after_a_final_tool_run() {
        let mut body = json!({ "messages": [
            { "role": "tool", "tool_call_id": "a", "content": [
                { "type": "image_url", "image_url": { "url": "https://example.test/a.png" } }
            ] },
            { "role": "tool", "tool_call_id": "b", "content": "plain" }
        ] });
        move_tool_media_to_user_message(&mut body);
        assert_eq!(
            body["messages"],
            json!([
                { "role": "tool", "tool_call_id": "a", "content": "" },
                { "role": "tool", "tool_call_id": "b", "content": "plain" },
                { "role": "user", "content": [ { "type": "image_url", "image_url": { "url": "https://example.test/a.png" } } ] }
            ])
        );
    }

    #[test]
    fn openai_wire_leaves_text_only_tool_messages_untouched() {
        let original = json!({ "messages": [
            { "role": "user", "content": [ { "type": "image_url", "image_url": { "url": "https://example.test/u.png" } } ] },
            { "role": "tool", "tool_call_id": "a", "content": [ { "type": "text", "text": "ok" } ] }
        ] });
        let mut body = original.clone();
        move_tool_media_to_user_message(&mut body);
        assert_eq!(body, original);
    }

    #[test]
    fn anthropic_ingress_preserves_system_cache_control_round_trip() {
        // Anthropic client sends a cache_control breakpoint on the system prompt;
        // it must survive normalization and re-shape back to the Anthropic wire.
        let canonical = transform_from_anthropic_request(json!({
            "model": "claude-haiku-4-5",
            "max_tokens": 64,
            "system": [ { "type": "text", "text": "sys ctx", "cache_control": { "type": "ephemeral" } } ],
            "messages": [{ "role": "user", "content": "hi" }]
        }));
        // Canonical keeps the breakpoint as an OpenAI content part.
        let sys = &canonical["messages"][0];
        assert_eq!(sys["role"], json!("system"));
        assert_eq!(sys["content"][0]["cache_control"], json!({ "type": "ephemeral" }));

        let reshaped = transform_to_anthropic_format(canonical);
        assert_eq!(reshaped["system"][0]["cache_control"], json!({ "type": "ephemeral" }));
    }

    #[test]
    fn anthropic_response_carries_cache_usage() {
        let openai = json!({
            "choices": [ { "message": { "role": "assistant", "content": "hi" }, "finish_reason": "stop" } ],
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 5,
                "prompt_tokens_details": { "cached_tokens": 40 },
                "cache_creation_input_tokens": 512
            }
        });
        let out = transform_to_anthropic_response(&openai, "m");
        assert_eq!(out["usage"]["cache_read_input_tokens"], json!(40));
        assert_eq!(out["usage"]["cache_creation_input_tokens"], json!(512));
    }
}

#[cfg(test)]
mod json_mode_default_tests {
    use super::*;

    /// The catalog declares nothing for most OpenAI models, so this default is
    /// what actually decides whether `response_format` goes on the wire.
    fn defaults_to_json_mode(model: &str) -> bool {
        builtin_profile("openai", model, None).supports_json_mode
    }

    /// Regression: a Jury juror on plain `gpt-4` was sent
    /// `response_format: {"type":"json_object"}` and the whole turn failed with
    /// HTTP 400 "not supported with this model". These models predate JSON mode
    /// and are frozen, so they must never be guessed into it.
    #[test]
    fn models_that_predate_json_mode_do_not_get_response_format() {
        for model in [
            "gpt-4",
            "gpt-4-0314",
            "gpt-4-0613",
            "gpt-4-32k",
            "gpt-4-32k-0613",
            "gpt-3.5-turbo",
            "gpt-3.5-turbo-0301",
            "gpt-3.5-turbo-0613",
            "gpt-3.5-turbo-16k",
            "gpt-3.5-turbo-instruct",
            "davinci-002",
            "babbage-002",
        ] {
            assert!(!defaults_to_json_mode(model), "{model} must not default to JSON mode");
        }
    }

    /// The exclusion is by name, so it must stay narrow: everything from the
    /// `1106` generation on does support JSON mode, and silently dropping
    /// `response_format` for those would weaken every structured call.
    #[test]
    fn current_models_keep_json_mode() {
        for model in [
            "gpt-4-1106-preview",
            "gpt-4-turbo",
            "gpt-4-turbo-2024-04-09",
            "gpt-3.5-turbo-1106",
            "gpt-3.5-turbo-0125",
            "gpt-4o",
            "gpt-4o-mini",
            "gpt-4o-2024-08-06",
            "gpt-4.1",
            "gpt-5",
            "gpt-5.4",
            "o3",
            "o4-mini",
        ] {
            assert!(defaults_to_json_mode(model), "{model} must keep JSON mode");
        }
    }

    /// The default is only ever a last resort: an explicit declaration, from the
    /// catalog or the caller, still wins in both directions.
    #[test]
    fn an_explicit_declaration_still_wins() {
        assert!(builtin_profile("openai", "gpt-4", Some(true)).supports_json_mode);
        assert!(!builtin_profile("openai", "gpt-4o", Some(false)).supports_json_mode);
    }

    /// Non-OpenAI wire formats are unaffected — they never defaulted to it.
    #[test]
    fn other_wire_formats_are_untouched() {
        assert!(!builtin_profile("anthropic", "claude-opus-5", None).supports_json_mode);
        assert!(!builtin_profile("gemini", "gemini-3-pro", None).supports_json_mode);
    }
}
