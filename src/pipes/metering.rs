//! Which platform-key calls Agent Stream meters.
//!
//! A call on a platform key (the operator's) bills its cost to the member's
//! and teams' budgets, which works only where Agent Stream knows the cost when
//! the call returns. While a budget is in scope (see
//! [`crate::teams::call_budget`]), a platform-key call is therefore admitted
//! only where Stream meters it:
//! - a model call to an endpoint configured for it (the provider's fixed
//!   endpoint, a Decider candidate's, a stage's), which Stream prices from the
//!   response's usage;
//! - a JSON model call whose path the caller chose (an OpenAI-compatible
//!   upstream appends the request's path) only on chat completions, messages,
//!   embeddings and Responses outside the background (see [`json_call`]);
//! - a binary passthrough only on `audio/speech` for a priced model (see
//!   [`binary_call`]).
//!
//! Everything else is refused with one of the [`Unmetered`] codes: batch jobs,
//! file uploads and speech-to-text, polls, fine-tuning, realtime client
//! secrets, image generation, background responses, any other path, an
//! unpriced text-to-speech model, and a realtime session. A call on the
//! caller's own key or the customer's stored key is never refused here, nor is
//! any call where no budget is in scope.
//!
//! The shared-credential rule ([`crate::pipes::shared_credential`]) overlaps
//! this one on purpose: on a tenant's surface that spends a credential the
//! tenant does not own, it keeps every call stateless and off stored objects,
//! budget or not, to protect the other tenants' data rather than the bill.
//! This rule is asked first (just after the budget), so where both would
//! refuse a call the caller gets this rule's code.
//!
//! Paths are matched percent-decoded, with dot segments resolved and empty
//! segments dropped. A path whose decoding is ambiguous (an encoded `/`, `\`,
//! `?` or `#`, a `%` left after decoding, a control character) is never on the
//! allowlist, so an upstream edge that decodes differently cannot turn an
//! allowed path into another endpoint.

use serde_json::Value;

/// What a platform-key call would spend that Agent Stream does not meter, so
/// it is refused while a budget is in scope. Each kind has its own error
/// code; all answer HTTP 403 with the type `permission_error`, which SDKs do
/// not retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unmetered {
    /// A batch job: the provider runs and bills it after the create call
    /// returns.
    Batch,
    /// Any other endpoint whose spend is not metered: a file upload or
    /// speech-to-text passthrough, a poll, fine-tuning, realtime client
    /// secrets, image generation, a background response, any path not on the
    /// allowlist.
    Endpoint,
    /// A binary passthrough (text-to-speech) on a model with no price, or
    /// priced by its audio output (a catalog output rate), which the binary
    /// path cannot measure.
    UnpricedModel,
    /// A realtime session, or one whose voice-safety jurors run on a platform
    /// key: realtime audio has no price.
    Realtime,
    /// A hosted tool or search the provider bills per call beside the
    /// tokens: a `tools[]` entry whose `type` is not `function` or `custom`
    /// (web search, file search, code interpreter, image generation, server
    /// tools), a `plugins`, `web_search_options` or `search_parameters`
    /// field, or a search model (an id with `search-preview` or `search-api`,
    /// which searches on every call).
    Tool,
    /// An output modality priced apart from text: audio output (`modalities`
    /// with `audio`, an `audio` request object) or image output (`modalities`
    /// or Gemini `responseModalities` with an image, a Gemini image-output
    /// model).
    Modality,
    /// A request above the model's long-context threshold (Gemini Pro's 200k
    /// tokens), whose higher tier the catalog does not price.
    LongContext,
    /// A Responses call that builds on context the provider stores
    /// (`previous_response_id`, `conversation`): billed as input, but not in
    /// the request, so no estimate can count it.
    StoredContext,
}

impl Unmetered {
    /// The `error.code` a caller gets.
    pub fn code(self) -> &'static str {
        match self {
            Self::Batch => "batch_not_metered",
            Self::Endpoint => "endpoint_not_metered",
            Self::UnpricedModel => "model_not_metered",
            Self::Realtime => "realtime_not_metered",
            Self::Tool => "tool_not_metered",
            Self::Modality => "modality_not_metered",
            Self::LongContext => "context_not_metered",
            Self::StoredContext => "stored_context_not_metered",
        }
    }

    /// What a caller is told.
    pub fn message(self) -> &'static str {
        match self {
            Self::Batch => {
                "Batch jobs cannot run on the operator's provider key while a budget is enforced: the provider \
                 bills them after this call returns, where their spend is not metered. Send your own provider key \
                 to create a batch."
            }
            Self::Endpoint => {
                "This endpoint cannot run on the operator's provider key while a budget is enforced: its spend is \
                 not metered. Send your own provider key to use it."
            }
            Self::UnpricedModel => {
                "This model has no price on this appliance that Agent Stream can meter, so it cannot run on the \
                 operator's provider key while a budget is enforced. Send your own provider key to use it."
            }
            Self::Realtime => {
                "Realtime sessions cannot run on the operator's provider key while a budget is enforced: realtime \
                 audio is not metered. The surface and its voice-safety jurors need the customer's own provider key."
            }
            Self::Tool => {
                "Hosted tools, plugins and search options cannot run on the operator's provider key while a budget \
                 is enforced: the provider bills them per call, which is not metered. Use function tools, or send \
                 your own provider key."
            }
            Self::Modality => {
                "Audio and image output cannot run on the operator's provider key while a budget is enforced: they \
                 are priced apart from text, which is not metered. Ask for text, or send your own provider key."
            }
            Self::LongContext => {
                "This request is above the model's long-context threshold, whose price is not metered on this \
                 appliance, so it cannot run on the operator's provider key while a budget is enforced. Shorten it, \
                 or send your own provider key."
            }
            Self::StoredContext => {
                "Stored provider context (previous_response_id, conversation) cannot be used on the operator's \
                 provider key while a budget is enforced: it is billed as input but cannot be metered. Send the \
                 whole input instead, or send your own provider key."
            }
        }
    }
}

impl std::fmt::Display for Unmetered {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(self.message())
    }
}

/// Whether a JSON model call to `url`, a path the caller chose, is metered:
/// chat completions, messages, embeddings, or Responses unless `body` asks
/// for a background response (billed when it finishes, after the call
/// returns).
pub fn json_call(
    url: &str,
    body: &Value,
) -> Result<(), Unmetered> {
    let segments = normalised_segments(url).ok_or(Unmetered::Endpoint)?;
    let path: Vec<&str> = segments
        .iter()
        .map(String::as_str)
        .collect();
    let metered = match path.as_slice() {
        [.., "chat", "completions"] | [.., "messages"] | [.., "embeddings"] => true,
        [.., "responses"] => body.get("background") != Some(&Value::Bool(true)),
        _ => false,
    };
    if metered {
        Ok(())
    } else if is_batch(&segments) {
        Err(Unmetered::Batch)
    } else {
        Err(Unmetered::Endpoint)
    }
}

/// The `stream_options.include_usage` shape: chat completions or legacy
/// completions, the only endpoints that define it (Responses and Messages
/// report their usage in their own events).
pub fn is_completions_call(url: &str) -> bool {
    matches!(normalised_segments(url).as_deref(), Some([.., last]) if last == "completions")
}

/// Whether a model call's body asks only for what Agent Stream prices on the
/// operator's key (`model` is the model it runs): no hosted tool, search
/// option or search model ([`Unmetered::Tool`]), no audio or image output
/// ([`Unmetered::Modality`]; an image-output model is checked against the
/// catalog apart, see [`is_image_output_model`]) and no stored provider
/// context ([`Unmetered::StoredContext`]). Read on every body shape a call
/// may carry (OpenAI chat and Responses, Anthropic, Gemini).
pub fn request_body(
    body: &Value,
    model: &str,
) -> Result<(), Unmetered> {
    if is_search_model(model) {
        return Err(Unmetered::Tool);
    }
    let present = |field: &str| {
        body.get(field)
            .is_some_and(|value| !value.is_null())
    };
    let hosted_tool = body
        .get("tools")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .any(|tool| {
            tool.get("type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind != "function" && kind != "custom")
        });
    if hosted_tool || present("plugins") || present("web_search_options") || present("search_parameters") {
        return Err(Unmetered::Tool);
    }
    if present("previous_response_id") || present("conversation") {
        return Err(Unmetered::StoredContext);
    }
    let names_a_modality = |value: Option<&Value>, modality: &str| {
        value
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .any(|name| name.eq_ignore_ascii_case(modality))
    };
    let modalities = body.get("modalities");
    let gemini_modalities = body.pointer("/generationConfig/responseModalities");
    if present("audio")
        || names_a_modality(modalities, "audio")
        || names_a_modality(modalities, "image")
        || names_a_modality(gemini_modalities, "audio")
        || names_a_modality(gemini_modalities, "image")
    {
        return Err(Unmetered::Modality);
    }
    Ok(())
}

/// Whether a model outputs images whatever the request asks (an id with
/// `-image`, as `gemini-2.5-flash-image` or OpenRouter's `openai/gpt-5-image`,
/// or Gemini's `nano-banana`): its image tokens are priced well above its text
/// rate, so it runs on the operator's key only where the catalog prices its
/// image output (`cost_per_1k_output_image`).
pub fn is_image_output_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.contains("-image") || model.contains("nano-banana")
}

/// Whether a model searches the web on every call, billed per call beside
/// its tokens (`gpt-4o-search-preview`, `gpt-4o-mini-search-preview`,
/// `gpt-5-search-api` and their dated or provider-prefixed ids). The catalog
/// marks no model as searching, so the id is what tells.
pub fn is_search_model(model: &str) -> bool {
    let model = model.to_ascii_lowercase();
    model.contains("search-preview") || model.contains("search-api")
}

/// The long-context threshold of a model whose price rises above it, in input
/// tokens: Gemini Pro models (2.5 Pro, 3.x Pro) price input and output higher
/// above 200,000 tokens. `None` for a model with one price.
pub fn long_context_threshold(model: &str) -> Option<u64> {
    let model = model.to_ascii_lowercase();
    (model.contains("gemini") && model.contains("-pro")).then_some(GEMINI_LONG_CONTEXT_THRESHOLD)
}

/// Gemini Pro's long-context threshold, in input tokens.
pub const GEMINI_LONG_CONTEXT_THRESHOLD: u64 = 200_000;

/// Whether a binary passthrough to `url`, a path the caller chose, is on the
/// metered binary endpoint (`audio/speech`). Its price is checked apart.
pub fn binary_call(url: &str) -> Result<(), Unmetered> {
    match normalised_segments(url).as_deref() {
        Some([.., audio, speech]) if audio == "audio" && speech == "speech" => Ok(()),
        _ => Err(Unmetered::Endpoint),
    }
}

/// Whether a path names provider batch jobs (`/v1/batches`,
/// `/v1/messages/batches`), in any case.
fn is_batch(segments: &[String]) -> bool {
    segments
        .iter()
        .any(|segment| segment.eq_ignore_ascii_case("batches"))
}

/// The segments of `url`'s path as an upstream that decodes them would read
/// them: dot segments resolved (the URL parser does that, `%2e` included, and
/// it is what is sent), each segment percent-decoded, empty segments dropped.
/// `None` when `url` does not parse or a decoded segment is ambiguous: it
/// holds a `/` or `\` (an encoded separator), a `?` or `#` (an encoded query
/// or fragment delimiter, which an edge that decodes it would cut the path
/// at), a `%` (encoded twice), a dot segment, or a control character.
fn normalised_segments(url: &str) -> Option<Vec<String>> {
    let url = url::Url::parse(url).ok()?;
    let mut segments = Vec::new();
    for raw in url.path_segments()? {
        let decoded = urlencoding::decode(raw).ok()?;
        if decoded.contains(['/', '\\', '%', '?', '#'])
            || decoded == "."
            || decoded == ".."
            || decoded
                .chars()
                .any(char::is_control)
        {
            return None;
        }
        if !decoded.is_empty() {
            segments.push(decoded.into_owned());
        }
    }
    Some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn json_path(path: &str) -> Result<(), Unmetered> {
        json_call(&format!("https://api.example.com{path}"), &json!({ "model": "m" }))
    }

    #[test]
    fn chat_messages_embeddings_and_responses_are_metered() {
        for path in [
            "/v1/chat/completions",
            "/openai/v1/chat/completions/",
            "/v1/messages",
            "/v1/embeddings",
            "/v1/responses",
            "/v1/chat/completion%73",
            "/v1/x/../chat/completions",
            "/v1//embeddings",
        ] {
            assert_eq!(json_path(path), Ok(()), "{path}");
        }
        let url = "https://api.example.com/v1/responses";
        assert_eq!(json_call(url, &json!({ "background": false })), Ok(()));
        assert_eq!(json_call(url, &json!({ "background": true })), Err(Unmetered::Endpoint));
    }

    #[test]
    fn batches_are_refused_with_their_own_code_however_the_path_is_spelled() {
        for path in [
            "/v1/batches",
            "/v1/batches/",
            "/v1/batche%73",
            "/v1/messages/batches",
            "/v1/Batches",
            "/v1/chat/completions/../../batches",
            "/v1/%2e%2e/v1/batches",
        ] {
            assert_eq!(json_path(path), Err(Unmetered::Batch), "{path}");
        }
    }

    #[test]
    fn every_other_path_is_refused() {
        for path in [
            "/v1/fine_tuning/jobs",
            "/v1/realtime/client_secrets",
            "/v1/realtime/sessions",
            "/v1/images/generations",
            "/v1/audio/transcriptions",
            "/v1/audio/speech",
            "/v1/files",
            "/v1/completions",
            "/v1/moderations",
            "/v1/messages/count_tokens",
            "/v1/responses/resp_1/cancel",
            "/v1/threads/thread_1/runs",
            "/v1/Chat/Completions",
            "/v1/chat/completions;x",
            "/",
        ] {
            assert_eq!(json_path(path), Err(Unmetered::Endpoint), "{path}");
        }
    }

    #[test]
    fn an_ambiguous_encoding_is_never_metered() {
        for path in [
            "/v1/chat%2Fcompletions",
            "/v1/batches%2F..%2Fchat/completions",
            "/v1/chat%5Ccompletions",
            "/v1/chat/completions%2500",
            "/v1/chat/%252e%252e/completions",
            "/v1/chat/completions%00",
            "/v1/embeddings%3F/x/chat/completions",
        ] {
            assert!(json_path(path).is_err(), "{path}");
        }
        assert_eq!(json_call("not a url", &json!({})), Err(Unmetered::Endpoint));
    }

    #[test]
    fn only_speech_is_a_metered_binary_endpoint() {
        assert_eq!(binary_call("https://api.example.com/v1/audio/speech"), Ok(()));
        assert_eq!(binary_call("https://api.example.com/v1/audio/spee%63h"), Ok(()));
        for path in [
            "/v1/audio/transcriptions",
            "/v1/batches%2F..%2Faudio/speech",
            "/v1/speech",
            "/v1/chat/completions%3F/audio/speech",
            "/v1/chat/completions%23/audio/speech",
        ] {
            assert_eq!(binary_call(&format!("https://api.example.com{path}")), Err(Unmetered::Endpoint), "{path}");
        }
    }

    #[test]
    fn hosted_tools_and_search_options_are_refused_and_function_tools_are_not() {
        for body in [
            json!({ "tools": [{ "type": "function", "function": { "name": "f" } }, { "type": "custom", "name": "c" }] }),
            json!({ "tools": [{ "name": "anthropic_client_tool", "input_schema": {} }] }),
            json!({ "messages": [], "plugins": null }),
        ] {
            assert_eq!(request_body(&body, "gpt-4o"), Ok(()), "{body}");
        }
        for body in [
            json!({ "tools": [{ "type": "function" }, { "type": "web_search" }] }),
            json!({ "tools": [{ "type": "image_generation" }] }),
            json!({ "tools": [{ "type": "code_interpreter", "container": { "type": "auto" } }] }),
            json!({ "tools": [{ "type": "web_search_20250305", "name": "web_search" }] }),
            json!({ "plugins": [{ "id": "web" }] }),
            json!({ "web_search_options": {} }),
            json!({ "search_parameters": { "mode": "on" } }),
        ] {
            assert_eq!(request_body(&body, "gpt-4o"), Err(Unmetered::Tool), "{body}");
        }
    }

    #[test]
    fn search_models_are_refused_whatever_the_body() {
        for model in [
            "gpt-4o-search-preview",
            "gpt-4o-mini-search-preview-2025-03-11",
            "gpt-5-search-api",
            "gpt-5-search-api-2025-10-14",
            "openai/gpt-4o-search-preview",
        ] {
            assert_eq!(request_body(&json!({ "messages": [] }), model), Err(Unmetered::Tool), "{model}");
        }
        for model in ["gpt-4o", "gpt-5", "research-assistant"] {
            assert_eq!(request_body(&json!({ "messages": [] }), model), Ok(()), "{model}");
        }
    }

    #[test]
    fn audio_and_image_output_are_refused() {
        for (body, model) in [
            (json!({ "modalities": ["text", "audio"], "audio": { "voice": "alloy" } }), "gpt-audio"),
            (json!({ "audio": { "voice": "alloy", "format": "wav" } }), "gpt-audio"),
            (json!({ "modalities": ["text", "image"] }), "google/gemini-2.5-flash"),
            (json!({ "generationConfig": { "responseModalities": ["TEXT", "IMAGE"] } }), "gemini-2.5-flash"),
        ] {
            assert_eq!(request_body(&body, model), Err(Unmetered::Modality), "{model}: {body}");
        }
        assert_eq!(request_body(&json!({ "modalities": ["text"] }), "gpt-4o"), Ok(()));
        assert_eq!(request_body(&json!({ "contents": [] }), "gemini-2.5-pro"), Ok(()));
    }

    #[test]
    fn any_image_output_model_is_named_by_its_id() {
        for model in [
            "gemini-2.5-flash-image",
            "gemini-3-pro-image-preview",
            "openai/gpt-5-image",
            "openai/gpt-5-image-mini",
            "openai/gpt-5.4-image-2",
            "nano-banana-pro-preview",
        ] {
            assert!(is_image_output_model(model), "{model}");
        }
        for model in ["gpt-5", "gemini-2.5-pro", "llama-3.2-11b-vision"] {
            assert!(!is_image_output_model(model), "{model}");
        }
    }

    #[test]
    fn stored_provider_context_is_refused() {
        for body in [
            json!({ "input": "next", "previous_response_id": "resp_1" }),
            json!({ "input": "next", "conversation": "conv_1" }),
            json!({ "input": "next", "conversation": { "id": "conv_1" } }),
        ] {
            assert_eq!(request_body(&body, "gpt-4.1-mini"), Err(Unmetered::StoredContext), "{body}");
        }
        assert_eq!(
            request_body(&json!({ "input": "all of it", "previous_response_id": null }), "gpt-4.1-mini"),
            Ok(())
        );
    }

    #[test]
    fn include_usage_belongs_to_the_completions_shape_only() {
        assert!(is_completions_call("https://api.example.com/v1/chat/completions"));
        assert!(is_completions_call("https://api.example.com/v1/completions"));
        assert!(is_completions_call("https://x.openai.azure.com/openai/deployments/d/chat/completions?api-version=1"));
        for path in ["/v1/responses", "/v1/respons%65s", "/v1/messages", "/v1/messag%65s", "/"] {
            assert!(!is_completions_call(&format!("https://api.example.com{path}")), "{path}");
        }
    }

    #[test]
    fn only_gemini_pro_models_have_a_long_context_tier() {
        for model in ["gemini-2.5-pro", "gemini-3-pro-preview", "google/gemini-3.1-pro"] {
            assert_eq!(long_context_threshold(model), Some(200_000), "{model}");
        }
        for model in ["gemini-2.5-flash", "gpt-4o", "claude-sonnet-4"] {
            assert_eq!(long_context_threshold(model), None, "{model}");
        }
    }

    #[test]
    fn every_kind_has_its_own_code() {
        let kinds = [
            Unmetered::Batch,
            Unmetered::Endpoint,
            Unmetered::UnpricedModel,
            Unmetered::Realtime,
            Unmetered::Tool,
            Unmetered::Modality,
            Unmetered::LongContext,
            Unmetered::StoredContext,
        ];
        let codes: std::collections::HashSet<_> = kinds
            .iter()
            .map(|kind| kind.code())
            .collect();
        assert_eq!(codes.len(), kinds.len());
        assert!(kinds.iter().all(|kind| {
            kind.code()
                .ends_with("_not_metered")
                && kind.to_string() == kind.message()
        }));
    }
}
