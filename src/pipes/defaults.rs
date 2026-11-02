//! Default constants for LLM providers
//!
//! Centralizes all default URLs, API versions, and configuration values
//! to avoid hardcoding throughout the codebase.

/// Default base URL for OpenAI API
pub const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com";

/// Default endpoint for Anthropic Messages API
pub const DEFAULT_ANTHROPIC_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

/// Default base URL for Google Gemini API
pub const DEFAULT_GEMINI_BASE_URL: &str = "https://generativelanguage.googleapis.com";

/// Default AWS region for Bedrock Gateway
pub const DEFAULT_BEDROCK_REGION: &str = "us-east-1";

/// Build the Bedrock Gateway base URL for a given AWS region.
///
/// The Bedrock Gateway (`bedrock-mantle.{region}.api.aws`) is an OpenAI-compatible
/// proxy that uses Bearer API key auth rather than SigV4/IAM.
///
/// # Examples
///
/// ```
/// use crate::pipes::defaults::bedrock_gateway_url;
/// assert_eq!(bedrock_gateway_url("us-east-1"), "https://bedrock-mantle.us-east-1.api.aws");
/// assert_eq!(bedrock_gateway_url("eu-west-1"), "https://bedrock-mantle.eu-west-1.api.aws");
/// ```
pub fn bedrock_gateway_url(region: &str) -> String {
    format!("https://bedrock-mantle.{}.api.aws", region)
}

/// Build the native AWS Bedrock runtime InvokeModel URL for a region + model id.
///
/// Anthropic (Claude) models on Bedrock require the Anthropic Messages schema against
/// `bedrock-runtime.{region}.amazonaws.com/model/{model}/invoke` — NOT the OpenAI
/// chat-completions schema the `bedrock-mantle` gateway serves. The model id is
/// URL-encoded because inference-profile ids contain `:` (e.g. `...-v1:0`).
///
/// # Examples
///
/// ```
/// use crate::pipes::defaults::bedrock_runtime_invoke_url;
/// assert_eq!(
///     bedrock_runtime_invoke_url("us-east-1", "us.anthropic.claude-sonnet-4-5-20250929-v1:0"),
///     "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
/// );
/// ```
pub fn bedrock_runtime_invoke_url(
    region: &str,
    model_id: &str,
) -> String {
    format!("https://bedrock-runtime.{}.amazonaws.com/model/{}/invoke", region, urlencoding::encode(model_id))
}

/// `anthropic_version` value Bedrock's InvokeModel expects in the request BODY.
/// (The native Anthropic API takes this as the `anthropic-version` header instead.)
pub const BEDROCK_ANTHROPIC_VERSION: &str = "bedrock-2023-05-31";

/// Default base URL for Cohere API
pub const DEFAULT_COHERE_BASE_URL: &str = "https://api.cohere.ai";

/// Default base URL for Mistral API
pub const DEFAULT_MISTRAL_BASE_URL: &str = "https://api.mistral.ai";

/// Default base URL for Together AI API
pub const DEFAULT_TOGETHERAI_BASE_URL: &str = "https://api.together.xyz";

// OpenAI-compatible provider presets. Each is a base URL **without** the
// `/v1` prefix; the client's `/v1/chat/completions` (etc.) path suffix is
// appended by the executor, exactly like the OpenAI provider.
/// Default base URL for Groq (OpenAI-compatible).
pub const DEFAULT_GROQ_BASE_URL: &str = "https://api.groq.com/openai";
/// Default base URL for xAI (Grok, OpenAI-compatible).
pub const DEFAULT_XAI_BASE_URL: &str = "https://api.x.ai";
/// Default base URL for OpenRouter (OpenAI-compatible).
pub const DEFAULT_OPENROUTER_BASE_URL: &str = "https://openrouter.ai/api";
/// Default base URL for Fireworks AI (OpenAI-compatible).
pub const DEFAULT_FIREWORKS_BASE_URL: &str = "https://api.fireworks.ai/inference";
/// Default base URL for Cerebras (OpenAI-compatible).
pub const DEFAULT_CEREBRAS_BASE_URL: &str = "https://api.cerebras.ai";
/// Default base URL for DeepSeek (OpenAI-compatible).
pub const DEFAULT_DEEPSEEK_BASE_URL: &str = "https://api.deepseek.com";
/// Default base URL for Moonshot AI / Kimi (OpenAI-compatible).
pub const DEFAULT_MOONSHOT_BASE_URL: &str = "https://api.moonshot.ai";
/// Default base URL for SambaNova Cloud (OpenAI-compatible).
pub const DEFAULT_SAMBANOVA_BASE_URL: &str = "https://api.sambanova.ai";
/// Default base URL for Hyperbolic (OpenAI-compatible).
pub const DEFAULT_HYPERBOLIC_BASE_URL: &str = "https://api.hyperbolic.xyz";
/// Default base URL for NVIDIA NIM / build.nvidia.com (OpenAI-compatible).
pub const DEFAULT_NVIDIA_BASE_URL: &str = "https://integrate.api.nvidia.com";
/// Default base URL for Nebius AI Studio (OpenAI-compatible).
pub const DEFAULT_NEBIUS_BASE_URL: &str = "https://api.studio.nebius.com";

/// Default base URL for Replicate API
pub const DEFAULT_REPLICATE_BASE_URL: &str = "https://api.replicate.com";

/// Default base URL for HuggingFace Inference API
pub const DEFAULT_HUGGINGFACE_BASE_URL: &str = "https://api-inference.huggingface.co";

/// Default base URL for local Ollama instance
pub const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";

/// Default base URL (Microsoft Graph) for the Microsoft 365 Copilot Chat API.
/// The two-call conversation endpoints (`/beta/copilot/conversations` and
/// `.../{id}/chat`) are built from this base by the executor.
pub const DEFAULT_M365_COPILOT_BASE_URL: &str = "https://graph.microsoft.com";

/// Default Anthropic API version header value
pub const DEFAULT_ANTHROPIC_VERSION: &str = "2023-06-01";

/// Default Azure OpenAI API version
pub const DEFAULT_AZURE_API_VERSION: &str = "2024-02-15-preview";

/// Default timeout for health check / test connection HTTP requests (seconds)
pub const HEALTH_CHECK_TIMEOUT_SECS: u64 = 10;

/// Provider default configuration — base URL and API version prefix.
/// These MUST match the values in pipes.json `default_base_url` and `api_version_prefix`.
pub struct ProviderDefaults {
    pub base_url: &'static str,
    pub api_version_prefix: &'static str,
}

/// Look up the default base URL and API version prefix for a given provider type.
/// Returns `None` for unknown provider types.
pub fn provider_defaults(provider_type: &str) -> Option<ProviderDefaults> {
    match provider_type {
        "openai" => Some(ProviderDefaults {
            base_url: DEFAULT_OPENAI_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "anthropic" => Some(ProviderDefaults {
            base_url: "https://api.anthropic.com",
            api_version_prefix: "/v1",
        }),
        "gemini" => Some(ProviderDefaults {
            base_url: DEFAULT_GEMINI_BASE_URL,
            api_version_prefix: "/v1beta",
        }),
        "bedrock" => Some(ProviderDefaults {
            base_url: "https://bedrock-mantle.us-east-1.api.aws",
            api_version_prefix: "/v1",
        }),
        "azure" => Some(ProviderDefaults {
            base_url: DEFAULT_OPENAI_BASE_URL, // Azure requires full URL; fallback only
            api_version_prefix: "",
        }),
        "cohere" => Some(ProviderDefaults {
            base_url: DEFAULT_COHERE_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "mistral" => Some(ProviderDefaults {
            base_url: DEFAULT_MISTRAL_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "together_ai" => Some(ProviderDefaults {
            base_url: DEFAULT_TOGETHERAI_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "replicate" => Some(ProviderDefaults {
            base_url: DEFAULT_REPLICATE_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "huggingface" => Some(ProviderDefaults {
            base_url: DEFAULT_HUGGINGFACE_BASE_URL,
            api_version_prefix: "",
        }),
        "ollama" => Some(ProviderDefaults {
            base_url: DEFAULT_OLLAMA_BASE_URL,
            api_version_prefix: "/v1",
        }),
        "m365_copilot" => Some(ProviderDefaults {
            base_url: DEFAULT_M365_COPILOT_BASE_URL,
            api_version_prefix: "/beta",
        }),
        _ => None,
    }
}

/// Resolve a potentially relative endpoint URL to a full URL.
///
/// If `endpoint_url` starts with '/', it's treated as a relative path and resolved
/// against the provider's `default_base_url` + `api_version_prefix` from the provider
/// defaults (which mirror the pipes.json configuration).
///
/// If `endpoint_url` is already an absolute URL (starts with http:// or https://),
/// it's returned as-is.
pub fn resolve_endpoint_url(
    provider_type: &str,
    endpoint_url: &str,
) -> String {
    if !endpoint_url.starts_with('/') {
        // Already a full URL
        return endpoint_url.to_string();
    }

    match provider_defaults(provider_type) {
        Some(defaults) => {
            let base = defaults
                .base_url
                .trim_end_matches('/');
            let prefix = defaults.api_version_prefix;
            // Avoid doubling the prefix: if the path already starts with the
            // api_version_prefix, don't add it again.
            if !prefix.is_empty() && endpoint_url.starts_with(prefix) {
                format!("{}{}", base, endpoint_url)
            } else {
                format!("{}{}{}", base, prefix, endpoint_url)
            }
        }
        None => {
            // Not a built-in provider — it may be a user-defined catalog
            // provider. Resolve the base URL from the catalog's
            // `default_base_url` so a relative endpoint still yields an absolute
            // URL (used by save-time SSRF validation). Path exactness is not
            // required here — the runtime builds the concrete provider variant.
            if let Some(base) = catalog_base_url(provider_type) {
                return format!("{}{}", base.trim_end_matches('/'), endpoint_url);
            }
            tracing::warn!(
                "Cannot resolve relative endpoint '{}' — unknown provider '{}'; using as-is",
                endpoint_url,
                provider_type
            );
            endpoint_url.to_string()
        }
    }
}

/// Look up a custom catalog provider's `default_base_url` by `provider_type`
/// (case-insensitive on `enum_value`). Returns `None` when no catalog is
/// registered or the provider is absent — callers then fall back to treating a
/// relative endpoint as unresolvable.
fn catalog_base_url(provider_type: &str) -> Option<String> {
    let catalog = crate::llm_catalog::global_catalog()?;
    let providers = catalog.cached_providers();
    providers
        .iter()
        .find(|p| {
            p.get("enum_value")
                .and_then(|v| v.as_str())
                .is_some_and(|e| e.eq_ignore_ascii_case(provider_type))
        })
        .and_then(|p| p.get("default_base_url"))
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_endpoint_url_passes_absolute_urls_through_unchanged() {
        let url = "https://example.com/v1/messages";
        assert_eq!(resolve_endpoint_url("anthropic", url), url);
        assert_eq!(
            resolve_endpoint_url("openai", "http://localhost:11434/v1/chat/completions"),
            "http://localhost:11434/v1/chat/completions"
        );
    }

    #[test]
    fn resolve_endpoint_url_expands_relative_anthropic_messages_path() {
        // The decider fix relies on this: a candidate stored with the relative
        // path `/messages` must resolve to the absolute Anthropic endpoint so
        // the main executor can POST to it without a reqwest builder error.
        assert_eq!(resolve_endpoint_url("anthropic", "/messages"), "https://api.anthropic.com/v1/messages");
    }

    #[test]
    fn resolve_endpoint_url_expands_relative_openai_chat_completions_path() {
        assert_eq!(
            resolve_endpoint_url("openai", "/chat/completions"),
            format!("{}/v1/chat/completions", DEFAULT_OPENAI_BASE_URL)
        );
    }

    #[test]
    fn resolve_endpoint_url_does_not_double_the_version_prefix() {
        // A relative path that already carries the api_version_prefix must not
        // get it prepended twice.
        assert_eq!(resolve_endpoint_url("anthropic", "/v1/messages"), "https://api.anthropic.com/v1/messages");
        assert_eq!(
            resolve_endpoint_url("openai", "/v1/chat/completions"),
            format!("{}/v1/chat/completions", DEFAULT_OPENAI_BASE_URL)
        );
    }

    #[test]
    fn resolve_endpoint_url_returns_relative_path_unchanged_for_unknown_provider() {
        assert_eq!(resolve_endpoint_url("not-a-provider", "/messages"), "/messages");
    }
}
