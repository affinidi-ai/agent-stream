//! LLM Provider extensions for parameter extraction and request building
//!
//! This module provides trait-based methods to eliminate code duplication
//! in parameter extraction and HTTP header configuration.

use super::llm::LLMProvider;
use crate::pipes::defaults;

/// Represents a parameter value that can be extracted from a provider
#[derive(Debug, Clone)]
pub enum ParameterValue {
    Float(f64),
    Int(u32),
    String(String),
}

impl ParameterValue {
    pub fn as_json(&self) -> serde_json::Value {
        match self {
            ParameterValue::Float(v) => serde_json::json!(v),
            ParameterValue::Int(v) => serde_json::json!(v),
            ParameterValue::String(v) => serde_json::json!(v),
        }
    }
}

/// Extension trait for LLMProvider with utility methods
pub trait LLMProviderExt {
    /// Get a parameter value by name
    fn get_parameter(
        &self,
        param: &str,
    ) -> Option<ParameterValue>;

    /// Get the model name
    fn get_model(&self) -> &str;

    /// Get the API key (if any)
    fn get_api_key(&self) -> Option<&str>;

    /// Get the endpoint URL
    fn get_endpoint(&self) -> String;

    /// Check if this provider supports dynamic path appending (OpenAI-compatible)
    /// Returns true for providers that accept arbitrary paths like /v1/chat/completions
    /// Returns false for providers with fixed endpoint structures
    fn supports_path_suffix(&self) -> bool;

    /// Build provider-specific HTTP headers
    fn build_headers(&self) -> Vec<(String, String)>;

    /// Build provider-specific HTTP headers with a resolved API key
    fn build_headers_with_key(
        &self,
        api_key: &str,
    ) -> Vec<(String, String)>;

    /// Get the provider type string (vendor identity: "openai", "anthropic", etc.)
    /// Used for auth headers, logging, cost lookup — NOT for request/response format.
    fn provider_type_str(&self) -> &str;

    /// Get the API schema identifier for this provider.
    /// Determines the wire format for requests and responses:
    /// - "openai"     — OpenAI Chat Completions format (also used by Azure, Mistral, Together, Ollama, Cohere)
    /// - "anthropic"  — Anthropic Messages API format
    /// - "gemini"     — Google Gemini generateContent format
    /// - "bedrock"    — AWS Bedrock InvokeModel format (legacy, not used with API key auth)
    /// - "replicate"  — Replicate Predictions format
    /// - "huggingface" — HuggingFace Inference format
    fn api_schema(&self) -> &str;

    /// Whether the upstream runs the model the request body names. False
    /// where the endpoint or deployment fixes the model (Gemini, Claude on
    /// Bedrock, Azure OpenAI, Replicate, Hugging Face) or names none
    /// (Microsoft 365 Copilot), so only the configured model can run there.
    fn runs_requested_model(&self) -> bool;

    /// Whether the provider serves only the signed-in caller's own delegated
    /// token (identity pass-through, `forward_caller_token`), so its calls are
    /// billed to that user's licence: the `copilot` wire schema (Microsoft 365
    /// Copilot, or a custom catalog provider on the Copilot API).
    fn requires_forward_caller_token(&self) -> bool {
        self.api_schema() == "copilot"
    }
}

/// True for a Bedrock model id that names an Anthropic (Claude) model. Such models must be
/// called through Bedrock's native InvokeModel endpoint with the Anthropic Messages schema;
/// the OpenAI chat-completions schema used for every other Bedrock model is rejected by Claude.
///
/// Keep this anchored to Bedrock's real Anthropic id forms so unrelated model ids that merely
/// contain words like `claude` or `anthropic` do not switch endpoint/schema accidentally:
/// `anthropic.claude-*` or cross-region inference profile ids like
/// `us.anthropic.claude-*`, `eu.anthropic.claude-*`, `apac.anthropic.claude-*`.
fn bedrock_model_is_anthropic(model: &str) -> bool {
    let model = model
        .trim()
        .to_ascii_lowercase();
    if model.starts_with("anthropic.claude-") {
        return true;
    }
    let Some((prefix, rest)) = model.split_once('.') else {
        return false;
    };
    matches!(prefix, "us" | "eu" | "apac" | "global") && rest.starts_with("anthropic.claude-")
}

impl LLMProviderExt for LLMProvider {
    fn get_parameter(
        &self,
        param: &str,
    ) -> Option<ParameterValue> {
        match param {
            "temperature" => match self {
                LLMProvider::OpenAI { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Anthropic { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Gemini { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Bedrock { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::AzureOpenAI { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Cohere { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Mistral { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::TogetherAI { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Replicate { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::HuggingFace { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Ollama { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::Custom { temperature, .. } => temperature.map(ParameterValue::Float),
                LLMProvider::M365Copilot { temperature, .. } => temperature.map(ParameterValue::Float),
            },
            "max_tokens" => match self {
                LLMProvider::OpenAI { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Anthropic { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Gemini { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Bedrock { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::AzureOpenAI { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Cohere { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Mistral { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::TogetherAI { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Replicate { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::HuggingFace { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Ollama { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::Custom { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
                LLMProvider::M365Copilot { max_tokens, .. } => max_tokens.map(ParameterValue::Int),
            },
            "top_p" => match self {
                LLMProvider::OpenAI { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Anthropic { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Gemini { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Bedrock { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::AzureOpenAI { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Cohere { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Mistral { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::TogetherAI { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Replicate { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::HuggingFace { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Ollama { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::Custom { top_p, .. } => top_p.map(ParameterValue::Float),
                LLMProvider::M365Copilot { top_p, .. } => top_p.map(ParameterValue::Float),
            },
            "frequency_penalty" => match self {
                LLMProvider::OpenAI { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Anthropic { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Gemini { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Bedrock { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::AzureOpenAI { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Cohere { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Mistral { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::TogetherAI { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Replicate { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::HuggingFace { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Ollama { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::Custom { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
                LLMProvider::M365Copilot { frequency_penalty, .. } => frequency_penalty.map(ParameterValue::Float),
            },
            "presence_penalty" => match self {
                LLMProvider::OpenAI { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Anthropic { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Gemini { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Bedrock { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::AzureOpenAI { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Cohere { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Mistral { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::TogetherAI { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Replicate { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::HuggingFace { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Ollama { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::Custom { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
                LLMProvider::M365Copilot { presence_penalty, .. } => presence_penalty.map(ParameterValue::Float),
            },
            _ => None,
        }
    }

    fn get_model(&self) -> &str {
        self.model_name()
    }

    fn get_api_key(&self) -> Option<&str> {
        match self {
            LLMProvider::OpenAI { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Anthropic { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Gemini { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Bedrock { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::AzureOpenAI { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Cohere { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Mistral { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::TogetherAI { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Replicate { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::HuggingFace { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Ollama { api_key_secret, .. } => api_key_secret.as_deref(),
            LLMProvider::Custom { auth_secret, .. } => auth_secret.as_deref(),
            LLMProvider::M365Copilot { api_key_secret, .. } => api_key_secret.as_deref(),
        }
    }

    fn get_endpoint(&self) -> String {
        match self {
            LLMProvider::OpenAI { base_url, .. } => {
                // OpenAI-compatible: return base URL WITHOUT /v1, path suffix will include /v1/chat/completions
                base_url
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_OPENAI_BASE_URL)
                    .to_string()
            }
            LLMProvider::Anthropic { .. } => {
                // Anthropic uses /v1/messages — do NOT append the client's path suffix
                defaults::DEFAULT_ANTHROPIC_ENDPOINT.to_string()
            }
            LLMProvider::Gemini { project_id, model, .. } => {
                // Fixed endpoint - doesn't support path suffix appending
                if let Some(project) = project_id {
                    format!(
                        "{}/v1beta/projects/{}/models/{}:generateContent",
                        defaults::DEFAULT_GEMINI_BASE_URL,
                        project,
                        model
                    )
                } else {
                    format!("{}/v1beta/models/{}:generateContent", defaults::DEFAULT_GEMINI_BASE_URL, model)
                }
            }
            LLMProvider::Bedrock { base_url, region, model, .. } => {
                let r = region
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_BEDROCK_REGION);
                if bedrock_model_is_anthropic(model) {
                    // Claude on Bedrock: native InvokeModel endpoint (Anthropic Messages schema).
                    // Fixed, complete URL — the client path suffix is not appended.
                    defaults::bedrock_runtime_invoke_url(r, model)
                } else if let Some(url) = base_url {
                    // Other models: OpenAI-compatible Bedrock Gateway. `base_url` takes full
                    // precedence; otherwise derive the gateway URL from `region`.
                    url.to_string()
                } else {
                    defaults::bedrock_gateway_url(r)
                }
            }
            LLMProvider::AzureOpenAI {
                endpoint,
                deployment_name,
                api_version,
                ..
            } => {
                // Fixed endpoint - doesn't support path suffix appending
                format!(
                    "{}/openai/deployments/{}/chat/completions?api-version={}",
                    endpoint, deployment_name, api_version
                )
            }
            LLMProvider::Cohere { .. } => {
                // OpenAI-compatible: return base URL, path suffix will be appended
                defaults::DEFAULT_COHERE_BASE_URL.to_string()
            }
            LLMProvider::Mistral { endpoint, .. } => {
                // OpenAI-compatible: return base URL, path suffix will be appended
                endpoint
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_MISTRAL_BASE_URL)
                    .to_string()
            }
            LLMProvider::TogetherAI { .. } => {
                // OpenAI-compatible: return base URL, path suffix will be appended
                defaults::DEFAULT_TOGETHERAI_BASE_URL.to_string()
            }
            LLMProvider::Replicate { model, .. } => {
                // Fixed endpoint - doesn't support path suffix appending
                format!("{}/v1/models/{}/predictions", defaults::DEFAULT_REPLICATE_BASE_URL, model)
            }
            LLMProvider::HuggingFace { model, .. } => {
                // Fixed endpoint - doesn't support path suffix appending
                format!("{}/models/{}", defaults::DEFAULT_HUGGINGFACE_BASE_URL, model)
            }
            LLMProvider::Ollama { base_url, .. } => {
                // OpenAI-compatible: return base URL, path suffix will be appended
                base_url
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_OLLAMA_BASE_URL)
                    .to_string()
            }
            LLMProvider::Custom { endpoint, .. } => endpoint.clone(),
            LLMProvider::M365Copilot { base_url, .. } => {
                // Microsoft Graph base. The executor builds the two-call
                // Copilot Chat API URLs (create conversation, then chat) from
                // this base; the client path suffix is never appended.
                base_url
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_M365_COPILOT_BASE_URL)
                    .trim_end_matches('/')
                    .to_string()
            }
        }
    }

    fn build_headers(&self) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        match self {
            LLMProvider::OpenAI { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::Anthropic { api_key_secret, version, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("x-api-key".to_string(), key.clone()));
                }
                let ver = version
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_ANTHROPIC_VERSION);
                headers.push(("anthropic-version".to_string(), ver.to_string()));
            }
            LLMProvider::Gemini { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("x-goog-api-key".to_string(), key.clone()));
                }
            }
            LLMProvider::Bedrock { api_key_secret, .. } => {
                // Bedrock Gateway uses Bearer token auth (OpenAI-compatible)
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::AzureOpenAI { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("api-key".to_string(), key.clone()));
                }
            }
            LLMProvider::Cohere { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::Mistral { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::TogetherAI { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::Replicate { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Token {}", key)));
                }
            }
            LLMProvider::HuggingFace { api_key_secret, .. } => {
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
            LLMProvider::Ollama { .. } => {
                // Ollama runs locally — no auth needed by default
            }
            LLMProvider::Custom { auth_header, auth_secret, .. } => {
                if let (Some(header), Some(secret)) = (auth_header, auth_secret) {
                    headers.push((header.clone(), secret.clone()));
                }
            }
            LLMProvider::M365Copilot { api_key_secret, .. } => {
                // Delegated by design: auth normally comes from the caller's
                // forwarded token. Only fall back to a stored key if configured.
                if let Some(key) = api_key_secret {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", key)));
                }
            }
        }

        headers
    }

    fn build_headers_with_key(
        &self,
        api_key: &str,
    ) -> Vec<(String, String)> {
        let mut headers = Vec::new();

        match self {
            LLMProvider::OpenAI { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::Anthropic { version, .. } => {
                headers.push(("x-api-key".to_string(), api_key.to_string()));
                let ver = version
                    .as_deref()
                    .unwrap_or(defaults::DEFAULT_ANTHROPIC_VERSION);
                headers.push(("anthropic-version".to_string(), ver.to_string()));
            }
            LLMProvider::Gemini { .. } => {
                headers.push(("x-goog-api-key".to_string(), api_key.to_string()));
            }
            LLMProvider::Bedrock { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::AzureOpenAI { .. } => {
                headers.push(("api-key".to_string(), api_key.to_string()));
            }
            LLMProvider::Cohere { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::Mistral { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::TogetherAI { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::Replicate { .. } => {
                headers.push(("Authorization".to_string(), format!("Token {}", api_key)));
            }
            LLMProvider::HuggingFace { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
            LLMProvider::Ollama { .. } => {
                // Ollama runs locally — typically no auth, but pass key if provided
                if !api_key.is_empty() {
                    headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
                }
            }
            LLMProvider::Custom { auth_header, .. } => {
                if let Some(header) = auth_header {
                    headers.push((header.clone(), api_key.to_string()));
                }
            }
            LLMProvider::M365Copilot { .. } => {
                headers.push(("Authorization".to_string(), format!("Bearer {}", api_key)));
            }
        }

        headers
    }

    fn provider_type_str(&self) -> &str {
        self.provider_type()
    }

    fn api_schema(&self) -> &str {
        match self {
            // OpenAI-compatible wire format
            LLMProvider::OpenAI { .. } => "openai",
            LLMProvider::AzureOpenAI { .. } => "openai",
            LLMProvider::Mistral { .. } => "openai",
            LLMProvider::TogetherAI { .. } => "openai",
            LLMProvider::Cohere { .. } => "openai",
            LLMProvider::Ollama { api_schema, .. } => api_schema
                .as_deref()
                .unwrap_or("openai"),
            // Claude on Bedrock uses the Anthropic Messages wire format (via InvokeModel);
            // every other Bedrock model is OpenAI-compatible.
            LLMProvider::Bedrock { model, .. } => {
                if bedrock_model_is_anthropic(model) {
                    "bedrock-anthropic"
                } else {
                    "openai"
                }
            }
            LLMProvider::Custom { .. } => "openai",

            // Microsoft 365 Copilot Chat API (Microsoft Graph) wire format
            LLMProvider::M365Copilot { .. } => "copilot",

            // Provider-specific wire formats
            LLMProvider::Anthropic { .. } => "anthropic",
            LLMProvider::Gemini { .. } => "gemini",
            LLMProvider::Replicate { .. } => "replicate",
            LLMProvider::HuggingFace { .. } => "huggingface",
        }
    }

    fn supports_path_suffix(&self) -> bool {
        match self {
            // OpenAI-compatible providers that support arbitrary path appending
            LLMProvider::OpenAI { .. } => true,
            LLMProvider::Anthropic { .. } => false,
            LLMProvider::Mistral { .. } => true,
            LLMProvider::TogetherAI { .. } => true,
            LLMProvider::Cohere { .. } => true,

            // Providers with fixed endpoint structures
            LLMProvider::Gemini { .. } => false,
            // Claude-on-Bedrock returns a complete InvokeModel URL; other Bedrock models
            // use the OpenAI-compatible gateway and append the chat-completions suffix.
            LLMProvider::Bedrock { model, .. } => !bedrock_model_is_anthropic(model),
            LLMProvider::AzureOpenAI { .. } => false,
            LLMProvider::Replicate { .. } => false,
            LLMProvider::HuggingFace { .. } => false,
            LLMProvider::Ollama { .. } => true,
            LLMProvider::Custom { .. } => false,
            // Copilot Chat API uses fixed two-call conversation endpoints.
            LLMProvider::M365Copilot { .. } => false,
        }
    }

    fn runs_requested_model(&self) -> bool {
        match self {
            LLMProvider::OpenAI { .. }
            | LLMProvider::Anthropic { .. }
            | LLMProvider::Mistral { .. }
            | LLMProvider::TogetherAI { .. }
            | LLMProvider::Cohere { .. }
            | LLMProvider::Ollama { .. }
            | LLMProvider::Custom { .. } => true,
            LLMProvider::Bedrock { model, .. } => !bedrock_model_is_anthropic(model),
            LLMProvider::Gemini { .. }
            | LLMProvider::AzureOpenAI { .. }
            | LLMProvider::Replicate { .. }
            | LLMProvider::HuggingFace { .. }
            | LLMProvider::M365Copilot { .. } => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_parameter_temperature() {
        let provider = LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: "gpt-4".to_string(),
            api_key_secret: Some("test".to_string()),
            organization_id: None,
            base_url: None,
            temperature: Some(0.7),
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        };

        let temp = provider.get_parameter("temperature");
        assert!(temp.is_some());

        if let Some(ParameterValue::Float(v)) = temp {
            assert_eq!(v, 0.7);
        } else {
            panic!("Expected Float value");
        }
    }

    fn bedrock(model: &str) -> LLMProvider {
        LLMProvider::Bedrock {
            provider_type: "bedrock".to_string(),
            model: model.to_string(),
            api_key_secret: Some("test".to_string()),
            region: Some("us-east-1".to_string()),
            base_url: None,
            temperature: None,
            max_tokens: None,
            top_p: None,
            frequency_penalty: None,
            presence_penalty: None,
        }
    }

    #[test]
    fn bedrock_claude_uses_anthropic_schema_and_invoke_endpoint() {
        let p = bedrock("us.anthropic.claude-sonnet-4-5-20250929-v1:0");
        assert_eq!(p.api_schema(), "bedrock-anthropic");
        assert!(!p.supports_path_suffix(), "InvokeModel URL is complete; no suffix");
        assert_eq!(
            p.get_endpoint(),
            "https://bedrock-runtime.us-east-1.amazonaws.com/model/us.anthropic.claude-sonnet-4-5-20250929-v1%3A0/invoke"
        );
    }

    #[test]
    fn bedrock_claude_detection_accepts_native_and_inference_profile_ids() {
        for model in [
            "anthropic.claude-3-5-sonnet-20241022-v2:0",
            "US.Anthropic.Claude-Sonnet-4-5-20250929-v1:0",
            "eu.anthropic.claude-3-haiku-20240307-v1:0",
            "apac.anthropic.claude-opus-4-1-20250805-v1:0",
        ] {
            let p = bedrock(model);
            assert_eq!(p.api_schema(), "bedrock-anthropic", "{model}");
            assert!(!p.supports_path_suffix(), "{model}");
        }
    }

    #[test]
    fn bedrock_non_anthropic_substring_false_positives_stay_openai_compatible() {
        for model in [
            "mistral.claude-compatible-7b",
            "amazon.anthropic-router-test",
            "meta.llama-3-anthropic-eval",
            "notanthropic.claude-sonnet-4",
        ] {
            let p = bedrock(model);
            assert_eq!(p.api_schema(), "openai", "{model}");
            assert!(p.supports_path_suffix(), "{model}");
            assert_eq!(p.get_endpoint(), "https://bedrock-mantle.us-east-1.api.aws", "{model}");
        }
    }

    #[test]
    fn bedrock_non_claude_stays_openai_compatible() {
        let p = bedrock("mistral.ministral-3-3b-instruct");
        assert_eq!(p.api_schema(), "openai");
        assert!(p.supports_path_suffix());
        assert_eq!(p.get_endpoint(), "https://bedrock-mantle.us-east-1.api.aws");
    }
}
