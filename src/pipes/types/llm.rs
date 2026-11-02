//! LLM-specific types and configurations

use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// Supported LLM providers with model parameters
#[derive(Debug, Clone, PartialEq)]
pub enum LLMProvider {
    OpenAI {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        organization_id: Option<String>,
        base_url: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Anthropic {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        version: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Gemini {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        project_id: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Bedrock {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        /// AWS region for Bedrock Gateway (e.g. "us-east-1"). Derives the base URL
        /// `https://bedrock-mantle.{region}.api.aws` unless `base_url` is also set.
        region: Option<String>,
        /// Full base URL override. Takes precedence over `region` when set.
        base_url: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    AzureOpenAI {
        provider_type: String,
        deployment_name: String,
        endpoint: String,
        api_key_secret: Option<String>,
        api_version: String,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Cohere {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Mistral {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        endpoint: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    TogetherAI {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Replicate {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    HuggingFace {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        endpoint: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Ollama {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        base_url: Option<String>,
        api_schema: Option<String>,
        #[allow(dead_code)]
        _marketplace_source: Option<serde_json::Value>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    Custom {
        provider_type: String,
        name: String,
        endpoint: String,
        auth_header: Option<String>,
        auth_secret: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
    /// Microsoft 365 Copilot Chat API (Microsoft Graph). Delegated-only: the
    /// caller's Entra bearer token is forwarded via `forward_caller_token`, so
    /// answers are grounded on the signed-in user's M365 content under their
    /// own ACLs. Uses the `copilot` wire schema, not OpenAI. Sampling params are
    /// accepted for enum uniformity but ignored by the Copilot Chat API.
    M365Copilot {
        provider_type: String,
        model: String,
        api_key_secret: Option<String>,
        base_url: Option<String>,
        temperature: Option<f64>,
        max_tokens: Option<u32>,
        top_p: Option<f64>,
        frequency_penalty: Option<f64>,
        presence_penalty: Option<f64>,
    },
}

// Helper macro to serialize optional fields
macro_rules! serialize_opt {
    ($map:expr, $key:expr, $value:expr) => {
        if let Some(v) = $value {
            $map.serialize_entry($key, v)?;
        }
    };
}

// Custom serializer for LLMProvider
impl Serialize for LLMProvider {
    fn serialize<S>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(None)?;

        match self {
            LLMProvider::OpenAI {
                provider_type,
                model,
                api_key_secret,
                organization_id,
                base_url,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "organization_id", organization_id);
                serialize_opt!(map, "base_url", base_url);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Anthropic {
                provider_type,
                model,
                api_key_secret,
                version,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "version", version);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Gemini {
                provider_type,
                model,
                api_key_secret,
                project_id,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "project_id", project_id);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Bedrock {
                provider_type,
                model,
                api_key_secret,
                region,
                base_url,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "region", region);
                serialize_opt!(map, "base_url", base_url);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::AzureOpenAI {
                provider_type,
                deployment_name,
                endpoint,
                api_key_secret,
                api_version,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("deployment_name", deployment_name)?;
                map.serialize_entry("endpoint", endpoint)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                map.serialize_entry("api_version", api_version)?;
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Cohere {
                provider_type,
                model,
                api_key_secret,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Mistral {
                provider_type,
                model,
                api_key_secret,
                endpoint,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "endpoint", endpoint);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::TogetherAI {
                provider_type,
                model,
                api_key_secret,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Replicate {
                provider_type,
                model,
                api_key_secret,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::HuggingFace {
                provider_type,
                model,
                api_key_secret,
                endpoint,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "endpoint", endpoint);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Ollama {
                provider_type,
                model,
                api_key_secret,
                base_url,
                api_schema,
                _marketplace_source,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "base_url", base_url);
                serialize_opt!(map, "api_schema", api_schema);
                if let Some(ms) = _marketplace_source {
                    map.serialize_entry("_marketplace_source", ms)?;
                }
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::Custom {
                provider_type,
                name,
                endpoint,
                auth_header,
                auth_secret,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("endpoint", endpoint)?;
                serialize_opt!(map, "auth_header", auth_header);
                serialize_opt!(map, "auth_secret", auth_secret);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
            LLMProvider::M365Copilot {
                provider_type,
                model,
                api_key_secret,
                base_url,
                temperature,
                max_tokens,
                top_p,
                frequency_penalty,
                presence_penalty,
            } => {
                map.serialize_entry("provider_type", provider_type)?;
                map.serialize_entry("model", model)?;
                serialize_opt!(map, "api_key_secret", api_key_secret);
                serialize_opt!(map, "base_url", base_url);
                serialize_opt!(map, "temperature", temperature);
                serialize_opt!(map, "max_tokens", max_tokens);
                serialize_opt!(map, "top_p", top_p);
                serialize_opt!(map, "frequency_penalty", frequency_penalty);
                serialize_opt!(map, "presence_penalty", presence_penalty);
            }
        }

        map.end()
    }
}

// Custom deserializer for LLMProvider
/// Build the concrete `LLMProvider` variant implied by a catalog `api_schema`
/// for a provider whose `provider_type` isn't one of the hardcoded built-ins
/// (i.e. a user-defined custom catalog provider). `provider_type` is preserved
/// so pricing and request-shaping still resolve against the catalog entry.
#[allow(clippy::too_many_arguments)]
fn build_catalog_provider(
    api_schema: &str,
    provider_type: String,
    model: String,
    api_key_secret: Option<String>,
    resolved_base: Option<String>,
    organization_id: Option<String>,
    version: Option<String>,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
    top_p: Option<f64>,
    frequency_penalty: Option<f64>,
    presence_penalty: Option<f64>,
) -> LLMProvider {
    match api_schema
        .to_ascii_lowercase()
        .as_str()
    {
        "anthropic" => LLMProvider::Anthropic {
            provider_type,
            model,
            api_key_secret,
            version,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty,
            presence_penalty,
        },
        "gemini" => LLMProvider::Gemini {
            provider_type,
            model,
            api_key_secret,
            project_id: None,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty,
            presence_penalty,
        },
        "copilot" => LLMProvider::M365Copilot {
            provider_type,
            model,
            api_key_secret,
            base_url: resolved_base,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty,
            presence_penalty,
        },
        // `openai` and every other OpenAI-compatible schema.
        _ => LLMProvider::OpenAI {
            provider_type,
            model,
            api_key_secret,
            organization_id,
            base_url: resolved_base,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty,
            presence_penalty,
        },
    }
}

/// Resolve an unknown `provider_type` against the merged LLM catalog (built-in +
/// custom `custom_llm.json`). A user-defined custom provider maps to the
/// concrete `LLMProvider` variant its catalog `api_schema` implies, using the
/// catalog's `default_base_url` when the surface didn't override it. Returns
/// `None` when no catalog is registered or no provider matches, so callers fall
/// back to the unknown-variant error.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_custom_catalog_provider(
    provider_type: String,
    model: String,
    api_key_secret: Option<String>,
    base_url: Option<String>,
    organization_id: Option<String>,
    version: Option<String>,
    temperature: Option<f64>,
    max_tokens: Option<u32>,
    top_p: Option<f64>,
    frequency_penalty: Option<f64>,
    presence_penalty: Option<f64>,
) -> Option<LLMProvider> {
    let catalog = crate::llm_catalog::global_catalog()?;
    let providers = catalog.cached_providers();
    let entry = providers.iter().find(|p| {
        p.get("enum_value")
            .and_then(|v| v.as_str())
            .is_some_and(|e| e.eq_ignore_ascii_case(&provider_type))
    })?;
    let api_schema = entry
        .get("api_schema")
        .and_then(|v| v.as_str())
        .unwrap_or("openai")
        .to_string();
    let default_base = entry
        .get("default_base_url")
        .and_then(|v| v.as_str())
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let resolved_base = base_url.or(default_base);
    Some(build_catalog_provider(
        &api_schema,
        provider_type,
        model,
        api_key_secret,
        resolved_base,
        organization_id,
        version,
        temperature,
        max_tokens,
        top_p,
        frequency_penalty,
        presence_penalty,
    ))
}

impl<'de> Deserialize<'de> for LLMProvider {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct LLMProviderVisitor;

        impl<'de> Visitor<'de> for LLMProviderVisitor {
            type Value = LLMProvider;

            fn expecting(
                &self,
                formatter: &mut fmt::Formatter,
            ) -> fmt::Result {
                formatter.write_str("an LLM provider object with a 'provider_type' field")
            }

            fn visit_map<A>(
                self,
                mut map: A,
            ) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut provider_type: Option<String> = None;
                let mut model: Option<String> = None;
                let mut api_key_secret: Option<String> = None;
                let mut organization_id: Option<String> = None;
                let mut base_url: Option<String> = None;
                let mut region: Option<String> = None;
                let mut version: Option<String> = None;
                let mut project_id: Option<String> = None;
                let mut deployment_name: Option<String> = None;
                let mut endpoint: Option<String> = None;
                let mut api_version: Option<String> = None;
                let mut name: Option<String> = None;
                let mut auth_header: Option<String> = None;
                let mut auth_secret: Option<String> = None;
                let mut api_schema: Option<String> = None;
                let mut _marketplace_source: Option<serde_json::Value> = None;
                let mut temperature: Option<f64> = None;
                let mut max_tokens: Option<u32> = None;
                let mut top_p: Option<f64> = None;
                let mut frequency_penalty: Option<f64> = None;
                let mut presence_penalty: Option<f64> = None;

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "provider_type" => provider_type = Some(map.next_value()?),
                        "model" => model = Some(map.next_value()?),
                        "api_key_secret" => api_key_secret = map.next_value()?,
                        "organization_id" => organization_id = map.next_value()?,
                        "base_url" => base_url = map.next_value()?,
                        "region" => region = map.next_value()?,
                        "version" => version = map.next_value()?,
                        "project_id" => project_id = map.next_value()?,
                        "deployment_name" => deployment_name = Some(map.next_value()?),
                        "endpoint" => endpoint = Some(map.next_value()?),
                        "api_version" => api_version = Some(map.next_value()?),
                        "name" => name = Some(map.next_value()?),
                        "auth_header" => auth_header = map.next_value()?,
                        "auth_secret" => auth_secret = map.next_value()?,
                        "api_schema" => api_schema = map.next_value()?,
                        "_marketplace_source" => _marketplace_source = map.next_value()?,
                        "temperature" => temperature = map.next_value()?,
                        "max_tokens" => max_tokens = map.next_value()?,
                        "top_p" => top_p = map.next_value()?,
                        "frequency_penalty" => frequency_penalty = map.next_value()?,
                        "presence_penalty" => presence_penalty = map.next_value()?,
                        _ => {
                            // Ignore unknown fields
                            let _: serde_json::Value = map.next_value()?;
                        }
                    }
                }

                let provider_type = provider_type.ok_or_else(|| de::Error::missing_field("provider_type"))?;

                match provider_type.as_str() {
                    "openai" => Ok(LLMProvider::OpenAI {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        organization_id,
                        base_url,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "anthropic" => Ok(LLMProvider::Anthropic {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        version,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "gemini" => Ok(LLMProvider::Gemini {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        project_id,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "bedrock" => Ok(LLMProvider::Bedrock {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        region,
                        base_url,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "azure" => Ok(LLMProvider::AzureOpenAI {
                        provider_type,
                        deployment_name: deployment_name.ok_or_else(|| de::Error::missing_field("deployment_name"))?,
                        endpoint: endpoint.ok_or_else(|| de::Error::missing_field("endpoint"))?,
                        api_key_secret,
                        api_version: api_version.ok_or_else(|| de::Error::missing_field("api_version"))?,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "cohere" => Ok(LLMProvider::Cohere {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "mistral" => Ok(LLMProvider::Mistral {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        endpoint,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "together_ai" => Ok(LLMProvider::TogetherAI {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    // OpenAI-compatible provider presets. These map to the OpenAI
                    // variant with a preset base URL (client path suffix appended),
                    // so they reuse the OpenAI schema, headers, and path handling
                    // while keeping their own `provider_type` for attribution.
                    "groq" | "xai" | "openrouter" | "fireworks" | "cerebras" | "deepseek" | "moonshot"
                    | "sambanova" | "hyperbolic" | "nvidia" | "nebius" => {
                        let preset_base = match provider_type.as_str() {
                            "groq" => crate::pipes::defaults::DEFAULT_GROQ_BASE_URL,
                            "xai" => crate::pipes::defaults::DEFAULT_XAI_BASE_URL,
                            "openrouter" => crate::pipes::defaults::DEFAULT_OPENROUTER_BASE_URL,
                            "fireworks" => crate::pipes::defaults::DEFAULT_FIREWORKS_BASE_URL,
                            "cerebras" => crate::pipes::defaults::DEFAULT_CEREBRAS_BASE_URL,
                            "deepseek" => crate::pipes::defaults::DEFAULT_DEEPSEEK_BASE_URL,
                            "moonshot" => crate::pipes::defaults::DEFAULT_MOONSHOT_BASE_URL,
                            "sambanova" => crate::pipes::defaults::DEFAULT_SAMBANOVA_BASE_URL,
                            "hyperbolic" => crate::pipes::defaults::DEFAULT_HYPERBOLIC_BASE_URL,
                            "nvidia" => crate::pipes::defaults::DEFAULT_NVIDIA_BASE_URL,
                            _ => crate::pipes::defaults::DEFAULT_NEBIUS_BASE_URL,
                        };
                        Ok(LLMProvider::OpenAI {
                            provider_type,
                            model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                            api_key_secret,
                            organization_id,
                            base_url: base_url.or_else(|| Some(preset_base.to_string())),
                            temperature,
                            max_tokens,
                            top_p,
                            frequency_penalty,
                            presence_penalty,
                        })
                    }
                    "replicate" => Ok(LLMProvider::Replicate {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "huggingface" => Ok(LLMProvider::HuggingFace {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        endpoint,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "ollama" => Ok(LLMProvider::Ollama {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        base_url,
                        api_schema,
                        _marketplace_source,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "custom" => Ok(LLMProvider::Custom {
                        provider_type,
                        name: name.ok_or_else(|| de::Error::missing_field("name"))?,
                        endpoint: endpoint.ok_or_else(|| de::Error::missing_field("endpoint"))?,
                        auth_header,
                        auth_secret,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    "m365_copilot" => Ok(LLMProvider::M365Copilot {
                        provider_type,
                        model: model.ok_or_else(|| de::Error::missing_field("model"))?,
                        api_key_secret,
                        base_url,
                        temperature,
                        max_tokens,
                        top_p,
                        frequency_penalty,
                        presence_penalty,
                    }),
                    _ => {
                        // An unknown `provider_type` may be a user-defined custom
                        // catalog provider (from `custom_llm.json`). Resolve it
                        // against the merged catalog and map it to the variant its
                        // `api_schema` implies, so custom providers are usable in a
                        // surface exactly like built-ins. Only fall through to the
                        // unknown-variant error when it isn't a catalog provider.
                        if let Some(model_val) = model
                            && let Some(mapped) = resolve_custom_catalog_provider(
                                provider_type.clone(),
                                model_val,
                                api_key_secret,
                                base_url,
                                organization_id,
                                version,
                                temperature,
                                max_tokens,
                                top_p,
                                frequency_penalty,
                                presence_penalty,
                            )
                        {
                            return Ok(mapped);
                        }
                        Err(de::Error::unknown_variant(
                            &provider_type,
                            &[
                                "openai",
                                "anthropic",
                                "gemini",
                                "bedrock",
                                "azure",
                                "cohere",
                                "mistral",
                                "together_ai",
                                "groq",
                                "xai",
                                "openrouter",
                                "fireworks",
                                "cerebras",
                                "deepseek",
                                "moonshot",
                                "sambanova",
                                "hyperbolic",
                                "nvidia",
                                "nebius",
                                "replicate",
                                "huggingface",
                                "ollama",
                                "custom",
                                "m365_copilot",
                            ],
                        ))
                    }
                }
            }
        }

        deserializer.deserialize_map(LLMProviderVisitor)
    }
}

impl LLMProvider {
    /// Get the model name for this provider
    #[allow(dead_code)]
    pub fn model_name(&self) -> &str {
        match self {
            LLMProvider::OpenAI { model, .. } => model,
            LLMProvider::Anthropic { model, .. } => model,
            LLMProvider::Gemini { model, .. } => model,
            LLMProvider::Bedrock { model, .. } => model,
            LLMProvider::AzureOpenAI { deployment_name, .. } => deployment_name,
            LLMProvider::Cohere { model, .. } => model,
            LLMProvider::Mistral { model, .. } => model,
            LLMProvider::TogetherAI { model, .. } => model,
            LLMProvider::Replicate { model, .. } => model,
            LLMProvider::HuggingFace { model, .. } => model,
            LLMProvider::Ollama { model, .. } => model,
            LLMProvider::Custom { name, .. } => name,
            LLMProvider::M365Copilot { model, .. } => model,
        }
    }

    /// Get the provider type as a string
    #[allow(dead_code)]
    pub fn provider_type(&self) -> &str {
        match self {
            LLMProvider::OpenAI { provider_type, .. } => provider_type,
            LLMProvider::Anthropic { provider_type, .. } => provider_type,
            LLMProvider::Gemini { provider_type, .. } => provider_type,
            LLMProvider::Bedrock { provider_type, .. } => provider_type,
            LLMProvider::AzureOpenAI { provider_type, .. } => provider_type,
            LLMProvider::Cohere { provider_type, .. } => provider_type,
            LLMProvider::Mistral { provider_type, .. } => provider_type,
            LLMProvider::TogetherAI { provider_type, .. } => provider_type,
            LLMProvider::Replicate { provider_type, .. } => provider_type,
            LLMProvider::HuggingFace { provider_type, .. } => provider_type,
            LLMProvider::Ollama { provider_type, .. } => provider_type,
            LLMProvider::Custom { provider_type, .. } => provider_type,
            LLMProvider::M365Copilot { provider_type, .. } => provider_type,
        }
    }
}

/// LLM-specific metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
#[allow(dead_code)]
pub struct LLMMetrics {
    pub provider: String,
    pub model: String,
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub total_tokens: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimated_cost_usd: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_to_first_token_ms: Option<u64>,
    #[serde(default)]
    pub streaming: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_tokens: Option<u64>,
}

/// Override policy for parameter injection/override
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
#[derive(Default)]
pub enum OverridePolicy {
    /// Gateway settings always override client values
    GatewayWins,
    /// Client is authoritative: the gateway never injects its value, even
    /// when the client omits the parameter (true passthrough).
    ClientWins,
    /// Only inject if client didn't provide a value
    #[default]
    InjectIfMissing,
}

/// Configuration for parameter override policies
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ParameterOverrideConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort: Option<OverridePolicy>,
    /// The reasoning-effort level the gateway injects when `reasoning_effort`
    /// policy applies (e.g. "minimal", "low", "medium", "high"). Defaults to
    /// "medium" when unset or blank. This is what lets `$high`/`$low` variants
    /// send a distinct effort per variant.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_effort_value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<OverridePolicy>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_key: Option<OverridePolicy>,
}

/// Token pricing for cost estimation (per 1M tokens)
#[derive(Debug, Clone)]
pub struct TokenPricing {
    pub input_price_per_million: f64,
    pub output_price_per_million: f64,
}

impl TokenPricing {
    /// Get pricing for a specific model
    pub fn for_model(
        provider: &str,
        model: &str,
    ) -> Option<Self> {
        match (provider, model) {
            // OpenAI GPT-4 Turbo
            ("openai", m) if m.starts_with("gpt-4-turbo") => Some(Self {
                input_price_per_million: 10.0,
                output_price_per_million: 30.0,
            }),
            // OpenAI GPT-4
            ("openai", m) if m.starts_with("gpt-4") => Some(Self {
                input_price_per_million: 30.0,
                output_price_per_million: 60.0,
            }),
            // OpenAI GPT-3.5 Turbo
            ("openai", m) if m.starts_with("gpt-3.5-turbo") => Some(Self {
                input_price_per_million: 0.5,
                output_price_per_million: 1.5,
            }),
            // Anthropic Claude 3 Opus
            ("anthropic", m) if m.contains("opus") => Some(Self {
                input_price_per_million: 15.0,
                output_price_per_million: 75.0,
            }),
            // Anthropic Claude 3 Sonnet
            ("anthropic", m) if m.contains("sonnet") => Some(Self {
                input_price_per_million: 3.0,
                output_price_per_million: 15.0,
            }),
            // Anthropic Claude 3 Haiku
            ("anthropic", m) if m.contains("haiku") => Some(Self {
                input_price_per_million: 0.25,
                output_price_per_million: 1.25,
            }),
            // Anthropic Claude models served via AWS Bedrock — same list prices as the
            // native API (provider string is "bedrock", model id names the Claude tier).
            ("bedrock", m) if m.contains("opus") => Some(Self {
                input_price_per_million: 15.0,
                output_price_per_million: 75.0,
            }),
            ("bedrock", m) if m.contains("sonnet") => Some(Self {
                input_price_per_million: 3.0,
                output_price_per_million: 15.0,
            }),
            ("bedrock", m) if m.contains("haiku") => Some(Self {
                input_price_per_million: 0.25,
                output_price_per_million: 1.25,
            }),
            _ => None,
        }
    }

    /// Calculate cost for given token usage. Never below zero, so no price can
    /// turn a call into a credit against a budget.
    pub fn calculate_cost(
        &self,
        input_tokens: u64,
        output_tokens: u64,
    ) -> f64 {
        let input_cost = (input_tokens as f64 / 1_000_000.0) * self.input_price_per_million;
        let output_cost = (output_tokens as f64 / 1_000_000.0) * self.output_price_per_million;
        billable_cost(input_cost + output_cost)
    }
}

/// A cost as it may be added to a running total: a negative or NaN cost counts
/// as zero, so no price, however it was set, can credit a budget.
pub fn billable_cost(cost: f64) -> f64 {
    if cost > 0.0 {
        cost
    } else {
        0.0
    }
}

/// The highest price a surface or target may declare, in USD per million
/// tokens (the same ceiling as 100 USD per thousand on the `cost_tracking`
/// override).
pub const MAX_PRICE_PER_MILLION_TOKENS: f64 = 100_000.0;

/// Check one price in USD per million tokens: finite, zero or more, and no
/// more than [`MAX_PRICE_PER_MILLION_TOKENS`].
pub fn validate_price_per_million(
    field: &str,
    price: f64,
) -> Result<(), String> {
    if !price.is_finite() || !(0.0..=MAX_PRICE_PER_MILLION_TOKENS).contains(&price) {
        return Err(format!(
            "pricing {field} must be between 0 and {MAX_PRICE_PER_MILLION_TOKENS} USD per million tokens (got {price})"
        ));
    }
    Ok(())
}

/// The price an operator declares for one upstream (USD per 1M tokens): a
/// surface's own upstream (`PipeConfig.upstream_pricing`) or a target
/// (`LLMTarget.pricing`). A declared price is used as-is, zero included, ahead
/// of the surface's `cost_tracking` override and the catalog, so a model the
/// operator runs themselves is never charged from the catalog because its name
/// happens to look like a catalog model's (an own model named `gpt-4o`).
///
/// Both prices are checked whenever one is read (`try_from`), so a price that
/// is negative, not finite or above [`MAX_PRICE_PER_MILLION_TOKENS`] cannot be
/// parsed from any request body or stored file.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "DeclaredPrices")]
pub struct TargetPricing {
    pub input_per_million: f64,
    pub output_per_million: f64,
}

/// The wire shape of [`TargetPricing`], before its prices are checked.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeclaredPrices {
    input_per_million: f64,
    output_per_million: f64,
}

impl TryFrom<DeclaredPrices> for TargetPricing {
    type Error = String;

    fn try_from(prices: DeclaredPrices) -> Result<Self, Self::Error> {
        let pricing = TargetPricing {
            input_per_million: prices.input_per_million,
            output_per_million: prices.output_per_million,
        };
        pricing.validate()?;
        Ok(pricing)
    }
}

impl TargetPricing {
    /// Both prices must be finite, zero or more, and no more than
    /// [`MAX_PRICE_PER_MILLION_TOKENS`].
    pub fn validate(&self) -> Result<(), String> {
        validate_price_per_million("input_per_million", self.input_per_million)?;
        validate_price_per_million("output_per_million", self.output_per_million)
    }

    pub fn token_pricing(&self) -> TokenPricing {
        TokenPricing {
            input_price_per_million: self.input_per_million,
            output_price_per_million: self.output_per_million,
        }
    }
}

/// The cost of one call whose upstream may carry prices of its own beside its
/// catalog price: `own`, in precedence order (a declared price, then the
/// surface's `cost_tracking` override).
///
/// When `own_price_honoured`, the first own price is billed as is (zero
/// included). Otherwise (the call sent a credential the surface's tenant does
/// not own, so no own price was the tenant's to set) the call is billed the
/// highest of every own price and the catalog price, so an own price can raise
/// that bill but never lower it. The catalog price is looked up only when it
/// is needed.
pub fn priced_cost(
    own: &[TokenPricing],
    own_price_honoured: bool,
    catalog: impl FnOnce() -> Option<TokenPricing>,
    input_tokens: u64,
    output_tokens: u64,
) -> f64 {
    let cost_at = |pricing: &TokenPricing| pricing.calculate_cost(input_tokens, output_tokens);
    match own.first() {
        Some(first) if own_price_honoured => cost_at(first),
        Some(_) => own
            .iter()
            .chain(catalog().as_ref())
            .map(cost_at)
            .fold(0.0, f64::max),
        None => catalog()
            .as_ref()
            .map(cost_at)
            .unwrap_or(0.0),
    }
}

/// The catalog price of `model` from `provider` for a call to `endpoint_url`:
/// the editable catalog (the endpoint's path, then the model), else the
/// built-in table. `None` when the catalog prices neither.
pub fn catalog_price(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
) -> Option<TokenPricing> {
    let provider = provider.to_lowercase();
    let endpoint_path = endpoint_url
        .and_then(|endpoint| url::Url::parse(endpoint).ok())
        .map(|url| url.path().to_string());
    match crate::llm_catalog::global_catalog() {
        Some(catalog) => catalog.resolve_model_pricing(&provider, model, endpoint_path.as_deref()),
        None => resolve_pricing_from_providers(&[], &provider, model, endpoint_path.as_deref()),
    }
}

/// What the caller of a surface, and its governance record, are told when a
/// call would spend the operator's credential on a model the catalog does not
/// price.
pub const MODEL_NOT_PRICED: &str =
    "The model this call names is not priced on this appliance, so the call was not sent";

/// Refuse, before it is sent, a call that spends a credential the surface's
/// tenant does not own (`own_price_honoured` false: an operator secret on a
/// tenant's surface) on a model the catalog does not price (`catalog`), since
/// nothing would bill it and the operator's key would serve it for free. A
/// call on the tenant's own credentials, or on an appliance-wide surface, is
/// billed as before: its declared price, the cost override or zero.
pub fn ensure_priced_spend(
    pipe_id: &str,
    own_price_honoured: bool,
    provider: &str,
    model: &str,
    catalog: Option<&TokenPricing>,
) -> Result<(), crate::pipes::executor::PipeError> {
    if own_price_honoured || catalog.is_some() {
        return Ok(());
    }
    tracing::warn!(
        pipe = ?pipe_id,
        provider = ?provider,
        model = ?model,
        "call refused: it spends an operator credential on a model the catalog does not price"
    );
    Err(crate::pipes::executor::PipeError::RequestFailed(MODEL_NOT_PRICED.to_string()))
}

/// Prompt-cache tokens a provider bills beside the input it reports:
/// Anthropic's `cache_creation_input_tokens` (written to the cache) and
/// `cache_read_input_tokens` (read from it), both excluded from its
/// `input_tokens`. OpenAI's `prompt_tokens_details.cached_tokens` are part of
/// its prompt tokens, so they are not these.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CacheTokens {
    /// Every token written to the cache (`cache_creation_input_tokens`).
    pub write: u64,
    /// The part of `write` written with the 1-hour TTL
    /// (`cache_creation.ephemeral_1h_input_tokens`), priced higher.
    pub write_1h: u64,
    pub read: u64,
}

impl CacheTokens {
    /// The Anthropic cache counts in a `usage` object.
    pub fn of_usage(usage: &serde_json::Value) -> Self {
        let count = |pointer: &str| {
            usage
                .pointer(pointer)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0)
        };
        let write = count("/cache_creation_input_tokens");
        Self {
            write,
            write_1h: count("/cache_creation/ephemeral_1h_input_tokens").min(write),
            read: count("/cache_read_input_tokens"),
        }
    }

    /// The Anthropic cache counts in a response body's `usage`: a raw
    /// Anthropic body, or one Agent Stream transformed to OpenAI's shape,
    /// which keeps the same fields.
    pub fn of_response(body: &serde_json::Value) -> Self {
        body.get("usage")
            .map(Self::of_usage)
            .unwrap_or_default()
    }

    pub fn is_empty(&self) -> bool {
        self.write == 0 && self.read == 0
    }

    pub fn add(
        &mut self,
        other: CacheTokens,
    ) {
        self.write += other.write;
        self.write_1h += other.write_1h;
        self.read += other.read;
    }

    /// The larger of each count (counts reported cumulatively).
    pub fn max(
        &mut self,
        other: CacheTokens,
    ) {
        self.write = self.write.max(other.write);
        self.write_1h = self
            .write_1h
            .max(other.write_1h);
        self.read = self.read.max(other.read);
    }
}

/// Anthropic's published price of a 5-minute prompt-cache write relative to
/// the model's input price, used where the catalog declares none.
pub const CACHE_WRITE_INPUT_RATIO: f64 = 1.25;

/// Anthropic's published price of a 1-hour prompt-cache write relative to the
/// model's input price, used where the catalog declares none.
pub const CACHE_WRITE_1H_INPUT_RATIO: f64 = 2.0;

/// Anthropic's published price of a prompt-cache read relative to the model's
/// input price, used where the catalog declares none.
pub const CACHE_READ_INPUT_RATIO: f64 = 0.1;

/// The catalog's prompt-cache prices for a model, per million tokens, each
/// only when declared.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CachePrices {
    /// `cost_per_1k_cache_write`: a 5-minute write.
    pub write: Option<f64>,
    /// `cost_per_1k_cache_write_1h`: a 1-hour write.
    pub write_1h: Option<f64>,
    /// `cost_per_1k_cache_read`.
    pub read: Option<f64>,
}

/// The catalog's prompt-cache prices for `model`, on the endpoint
/// `endpoint_url` names, else on the model.
pub fn catalog_cache_prices(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
) -> CachePrices {
    let [write, write_1h, read] = catalog_field_values(
        provider,
        model,
        endpoint_url,
        ["cost_per_1k_cache_write", "cost_per_1k_cache_write_1h", "cost_per_1k_cache_read"],
    )
    .map(|per_1k| per_1k.map(|per_1k| per_1k * 1000.0));
    CachePrices { write, write_1h, read }
}

/// The values of numeric catalog `fields` for `model`: each on the endpoint
/// `endpoint_url` names, else on the model; `None` where not declared (or
/// negative, or not finite).
fn catalog_field_values<const N: usize>(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
    fields: [&str; N],
) -> [Option<f64>; N] {
    let endpoint_path = endpoint_url
        .and_then(|endpoint| url::Url::parse(endpoint).ok())
        .map(|url| url.path().to_string());
    match crate::llm_catalog::global_catalog() {
        Some(catalog) => resolve_field_values_from_providers(
            &catalog.cached_providers(),
            &provider.to_lowercase(),
            model,
            endpoint_path.as_deref(),
            fields,
        ),
        None => [None; N],
    }
}

/// [`catalog_field_values`] over a catalog `providers` array.
pub fn resolve_field_values_from_providers<const N: usize>(
    providers: &[serde_json::Value],
    provider_enum: &str,
    model: &str,
    endpoint_path: Option<&str>,
    fields: [&str; N],
) -> [Option<f64>; N] {
    let Some(provider) = providers.iter().find(|p| {
        p.get("enum_value")
            .and_then(|v| v.as_str())
            == Some(provider_enum)
    }) else {
        return [None; N];
    };
    let entry_in = |list: &str, key: &str, value: Option<&str>| {
        let value = value?;
        provider
            .get(list)
            .and_then(|entries| entries.as_array())?
            .iter()
            .find(|entry| {
                entry
                    .get(key)
                    .and_then(|v| v.as_str())
                    == Some(value)
            })
    };
    let value_of = |entry: Option<&serde_json::Value>, field: &str| {
        entry
            .and_then(|entry| entry.get(field))
            .and_then(|v| v.as_f64())
            .filter(|value| value.is_finite() && *value >= 0.0)
    };
    let endpoint_entry = entry_in("endpoints", "path", endpoint_path);
    let model_entry = entry_in("models", "value", Some(model));
    fields.map(|field| value_of(endpoint_entry, field).or_else(|| value_of(model_entry, field)))
}

/// The cost of `cache` tokens on a call whose input is priced at
/// `input_per_million`: each kind at the catalog's price when `catalog`
/// declares one (see [`catalog_cache_prices`]), else at Anthropic's published
/// ratio to the input price ([`CACHE_WRITE_INPUT_RATIO`] for a 5-minute write,
/// [`CACHE_WRITE_1H_INPUT_RATIO`] for a 1-hour write, [`CACHE_READ_INPUT_RATIO`]
/// for a read).
pub fn cache_cost(
    cache: CacheTokens,
    input_per_million: f64,
    catalog: CachePrices,
) -> f64 {
    let write = catalog
        .write
        .unwrap_or(input_per_million * CACHE_WRITE_INPUT_RATIO);
    let write_1h = catalog
        .write_1h
        .unwrap_or(input_per_million * CACHE_WRITE_1H_INPUT_RATIO);
    let read = catalog
        .read
        .unwrap_or(input_per_million * CACHE_READ_INPUT_RATIO);
    let per_million = |tokens: u64, price: f64| (tokens as f64 / 1_000_000.0) * price;
    billable_cost(
        per_million(
            cache
                .write
                .saturating_sub(cache.write_1h),
            write,
        ) + per_million(cache.write_1h, write_1h)
            + per_million(cache.read, read),
    )
}

/// The catalog's long-context tier for `model`: its input threshold
/// (`long_context_threshold`, else the model's built-in threshold, see
/// [`crate::pipes::metering::long_context_threshold`]) and its prices
/// (`cost_per_1k_input_long_context`, `cost_per_1k_output_long_context`),
/// when the catalog declares both prices.
pub fn catalog_long_context_price(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
) -> Option<(u64, TokenPricing)> {
    let [threshold, input, output] = catalog_field_values(
        provider,
        model,
        endpoint_url,
        ["long_context_threshold", "cost_per_1k_input_long_context", "cost_per_1k_output_long_context"],
    );
    let threshold = threshold
        .map(|threshold| threshold as u64)
        .or_else(|| crate::pipes::metering::long_context_threshold(model))?;
    Some((
        threshold,
        TokenPricing {
            input_price_per_million: input? * 1000.0,
            output_price_per_million: output? * 1000.0,
        },
    ))
}

/// Google's published long-context price relative to the standard input
/// price (Gemini Pro above 200,000 input tokens), used where the catalog
/// prices no tier.
pub const LONG_CONTEXT_INPUT_RATIO: f64 = 2.0;

/// Google's published long-context price relative to the standard output
/// price, used where the catalog prices no tier.
pub const LONG_CONTEXT_OUTPUT_RATIO: f64 = 1.5;

/// The catalog's price for `model`'s image output, per million tokens
/// (`cost_per_1k_output_image`), when declared.
pub fn catalog_image_output_price(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
) -> Option<f64> {
    let [price] = catalog_field_values(provider, model, endpoint_url, ["cost_per_1k_output_image"]);
    price.map(|per_1k| per_1k * 1000.0)
}

/// The catalog price of a call with `input_tokens` of input: above the
/// model's long-context threshold (the catalog's `long_context_threshold`,
/// else the built-in one), the tier's price when the catalog declares it
/// (see [`catalog_long_context_price`]), else the standard price at Google's
/// published ratios ([`LONG_CONTEXT_INPUT_RATIO`], [`LONG_CONTEXT_OUTPUT_RATIO`]);
/// otherwise [`catalog_price`]. An image-output model's output is priced at
/// least at its catalog image rate (see [`catalog_image_output_price`]).
pub fn catalog_price_for_input(
    provider: &str,
    model: &str,
    endpoint_url: Option<&str>,
    input_tokens: u64,
) -> Option<TokenPricing> {
    let [threshold] = catalog_field_values(provider, model, endpoint_url, ["long_context_threshold"]);
    let threshold = threshold
        .map(|threshold| threshold as u64)
        .or_else(|| crate::pipes::metering::long_context_threshold(model));
    let tier = catalog_long_context_price(provider, model, endpoint_url).map(|(_, tier)| tier);
    let price = price_for_input(threshold, tier, input_tokens, || catalog_price(provider, model, endpoint_url));
    let image_rate = crate::pipes::metering::is_image_output_model(model)
        .then(|| catalog_image_output_price(provider, model, endpoint_url))
        .flatten();
    price.map(|price| at_least_image_rate(price, image_rate))
}

/// `price` with its output raised to `image_rate` (USD per million) when that
/// is higher: an image-output model's output may be an image.
fn at_least_image_rate(
    mut price: TokenPricing,
    image_rate: Option<f64>,
) -> TokenPricing {
    if let Some(image_rate) = image_rate {
        price.output_price_per_million = price
            .output_price_per_million
            .max(image_rate);
    }
    price
}

/// The price of a call with `input_tokens` of input: above `threshold`, the
/// long-context `tier` when declared, else the `standard` price at Google's
/// published ratios; otherwise the `standard` price.
fn price_for_input(
    threshold: Option<u64>,
    tier: Option<TokenPricing>,
    input_tokens: u64,
    standard: impl FnOnce() -> Option<TokenPricing>,
) -> Option<TokenPricing> {
    match threshold {
        Some(threshold) if input_tokens > threshold => tier.or_else(|| {
            standard().map(|price| TokenPricing {
                input_price_per_million: price.input_price_per_million * LONG_CONTEXT_INPUT_RATIO,
                output_price_per_million: price.output_price_per_million * LONG_CONTEXT_OUTPUT_RATIO,
            })
        }),
        _ => standard(),
    }
}

/// Parse the catalog pricing fields on a model or endpoint entry into
/// [`TokenPricing`]. The catalog stores published rates as `cost_per_1k_input`
/// / `cost_per_1k_output` (USD per 1,000 tokens); they are scaled to the
/// per-1,000,000-token basis [`TokenPricing`] uses. Returns `None` unless both
/// fields are present.
fn parse_catalog_pricing(entry: &serde_json::Value) -> Option<TokenPricing> {
    let input_per_1k = entry
        .get("cost_per_1k_input")
        .and_then(|v| v.as_f64())?;
    let output_per_1k = entry
        .get("cost_per_1k_output")
        .and_then(|v| v.as_f64())?;
    Some(TokenPricing {
        input_price_per_million: input_per_1k * 1000.0,
        output_price_per_million: output_per_1k * 1000.0,
    })
}

/// Resolve token pricing for a model from the catalog `providers` array.
///
/// Resolution order, most specific first:
/// 1. The matched endpoint's `cost_per_1k_*` fields (per-endpoint override, e.g.
///    a discounted batch endpoint).
/// 2. The model's `cost_per_1k_*` fields.
/// 3. The built-in [`TokenPricing::for_model`] table.
///
/// Returns `None` when no pricing is known, in which case callers treat the
/// computed cost as `0.0` (matching the prior behavior when a model had no
/// known rate).
pub fn resolve_pricing_from_providers(
    providers: &[serde_json::Value],
    provider_enum: &str,
    model: &str,
    endpoint_path: Option<&str>,
) -> Option<TokenPricing> {
    let provider = providers.iter().find(|p| {
        p.get("enum_value")
            .and_then(|v| v.as_str())
            == Some(provider_enum)
    });

    // 1. Per-endpoint override (most specific).
    if let (Some(provider), Some(path)) = (provider, endpoint_path)
        && let Some(endpoint) = provider
            .get("endpoints")
            .and_then(|e| e.as_array())
            .and_then(|endpoints| {
                endpoints.iter().find(|e| {
                    e.get("path")
                        .and_then(|v| v.as_str())
                        == Some(path)
                })
            })
        && let Some(pricing) = parse_catalog_pricing(endpoint)
    {
        return Some(pricing);
    }

    // 2. Per-model pricing.
    if let Some(provider) = provider
        && let Some(model_entry) = provider
            .get("models")
            .and_then(|m| m.as_array())
            .and_then(|models| {
                models.iter().find(|m| {
                    m.get("value")
                        .and_then(|v| v.as_str())
                        == Some(model)
                })
            })
        && let Some(pricing) = parse_catalog_pricing(model_entry)
    {
        return Some(pricing);
    }

    // 3. Built-in fallback table.
    TokenPricing::for_model(provider_enum, model)
}

#[cfg(test)]
mod pricing_tests {
    use super::*;
    use serde_json::json;

    fn catalog() -> Vec<serde_json::Value> {
        vec![json!({
            "enum_value": "openai",
            "endpoints": [
                { "path": "/chat/completions", "cost_per_1k_input": 0.0025, "cost_per_1k_output": 0.01 },
                { "path": "/batch", "cost_per_1k_input": 0.00125, "cost_per_1k_output": 0.005 }
            ],
            "models": [
                { "value": "gpt-4o", "cost_per_1k_input": 0.0025, "cost_per_1k_output": 0.01 },
                { "value": "gpt-4o-mini" }
            ]
        })]
    }

    #[test]
    fn cache_tokens_are_priced_at_the_catalogs_rates_else_at_anthropics_ratios() {
        let cache = CacheTokens {
            write: 1_000_000,
            write_1h: 0,
            read: 1_000_000,
        };
        // Sonnet-like input price, $3 per million: writes at $3.75, reads at $0.30.
        let none = CachePrices::default();
        assert!((cache_cost(cache, 3.0, none) - (3.75 + 0.30)).abs() < 1e-9);
        // Declared catalog prices win, each on its own.
        let write = CachePrices { write: Some(6.0), ..none };
        assert!((cache_cost(cache, 3.0, write) - (6.0 + 0.30)).abs() < 1e-9);
        let read = CachePrices { read: Some(1.5), ..none };
        assert!((cache_cost(cache, 3.0, read) - (3.75 + 1.5)).abs() < 1e-9);
        assert_eq!(cache_cost(CacheTokens::default(), 3.0, none), 0.0);

        let providers = vec![json!({
            "enum_value": "anthropic",
            "endpoints": [{ "path": "/v1/messages", "cost_per_1k_cache_read": 0.0005 }],
            "models": [{ "value": "claude-x", "cost_per_1k_cache_write": 0.006, "cost_per_1k_cache_read": 0.0003 }]
        })];
        let fields = ["cost_per_1k_cache_write", "cost_per_1k_cache_read"];
        assert_eq!(
            resolve_field_values_from_providers(&providers, "anthropic", "claude-x", None, fields),
            [Some(0.006), Some(0.0003)]
        );
        assert_eq!(
            resolve_field_values_from_providers(&providers, "anthropic", "claude-x", Some("/v1/messages"), fields),
            [Some(0.006), Some(0.0005)],
            "the endpoint's price wins over the model's"
        );
        assert_eq!(resolve_field_values_from_providers(&providers, "anthropic", "other", None, fields), [None, None]);

        let usage = json!({ "usage": { "input_tokens": 10, "cache_creation_input_tokens": 512, "cache_read_input_tokens": 40 } });
        assert_eq!(
            CacheTokens::of_response(&usage),
            CacheTokens {
                write: 512,
                write_1h: 0,
                read: 40
            }
        );
        let openai = json!({ "usage": { "prompt_tokens": 100, "prompt_tokens_details": { "cached_tokens": 64 } } });
        assert!(CacheTokens::of_response(&openai).is_empty(), "OpenAI's cached tokens are part of its prompt tokens");
    }

    #[test]
    fn a_1_hour_cache_write_is_priced_at_twice_the_input_unless_the_catalog_prices_it() {
        let usage = json!({ "usage": {
            "cache_creation_input_tokens": 1_000_000,
            "cache_creation": { "ephemeral_5m_input_tokens": 400_000, "ephemeral_1h_input_tokens": 600_000 }
        } });
        let cache = CacheTokens::of_response(&usage);
        assert_eq!(
            cache,
            CacheTokens {
                write: 1_000_000,
                write_1h: 600_000,
                read: 0
            }
        );
        // $3 input: 400k at $3.75 and 600k at $6.
        assert!((cache_cost(cache, 3.0, CachePrices::default()) - (0.4 * 3.75 + 0.6 * 6.0)).abs() < 1e-9);
        let declared = CachePrices {
            write_1h: Some(9.0),
            ..CachePrices::default()
        };
        assert!((cache_cost(cache, 3.0, declared) - (0.4 * 3.75 + 0.6 * 9.0)).abs() < 1e-9);
    }

    #[test]
    fn a_long_context_tier_prices_input_above_its_threshold() {
        let standard = || {
            Some(TokenPricing {
                input_price_per_million: 1.25,
                output_price_per_million: 10.0,
            })
        };
        let tier = Some(TokenPricing {
            input_price_per_million: 2.6,
            output_price_per_million: 15.5,
        });
        let input_price = |input| {
            price_for_input(Some(200_000), tier.clone(), input, standard)
                .expect("priced")
                .input_price_per_million
        };
        assert_eq!(input_price(200_000), 1.25);
        assert_eq!(input_price(200_001), 2.6);
        assert_eq!(price_for_input(None, None, 900_000, standard).map(|p| p.input_price_per_million), Some(1.25));

        let providers = vec![json!({
            "enum_value": "gemini",
            "models": [{ "value": "gemini-2.5-pro", "long_context_threshold": 200000,
                         "cost_per_1k_input_long_context": 0.0025, "cost_per_1k_output_long_context": 0.015 }]
        })];
        assert_eq!(
            resolve_field_values_from_providers(
                &providers,
                "gemini",
                "gemini-2.5-pro",
                None,
                ["long_context_threshold", "cost_per_1k_input_long_context", "cost_per_1k_output_long_context"]
            ),
            [Some(200000.0), Some(0.0025), Some(0.015)]
        );
    }

    #[test]
    fn without_a_tier_price_long_context_is_billed_at_googles_ratios() {
        let standard = || {
            Some(TokenPricing {
                input_price_per_million: 1.25,
                output_price_per_million: 10.0,
            })
        };
        let above = price_for_input(Some(200_000), None, 600_000, standard).expect("priced");
        assert_eq!((above.input_price_per_million, above.output_price_per_million), (2.5, 15.0));
        let below = price_for_input(Some(200_000), None, 150_000, standard).expect("priced");
        assert_eq!((below.input_price_per_million, below.output_price_per_million), (1.25, 10.0));
    }

    #[test]
    fn an_image_output_model_bills_output_at_least_at_its_image_rate() {
        let text = TokenPricing {
            input_price_per_million: 1.25,
            output_price_per_million: 10.0,
        };
        assert_eq!(at_least_image_rate(text.clone(), Some(40.0)).output_price_per_million, 40.0);
        assert_eq!(at_least_image_rate(text.clone(), Some(5.0)).output_price_per_million, 10.0);
        assert_eq!(at_least_image_rate(text, None).output_price_per_million, 10.0);
    }

    #[test]
    fn resolves_model_level_pricing() {
        let pricing = resolve_pricing_from_providers(&catalog(), "openai", "gpt-4o", None).expect("model pricing");
        assert_eq!(pricing.input_price_per_million, 2.5);
        assert_eq!(pricing.output_price_per_million, 10.0);
    }

    #[test]
    fn openai_compatible_preset_resolves_base_url_and_provider_type() {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let json = r#"{"provider_type":"groq","model":"llama-3.1-8b-instant","api_key_secret":"sec-1"}"#;
        let provider: LLMProvider = serde_json::from_str(json).expect("groq preset deserializes");
        // Stored as an OpenAI variant but keeps its own provider_type + preset base.
        assert_eq!(provider.provider_type_str(), "groq");
        assert_eq!(provider.get_endpoint(), "https://api.groq.com/openai");
        assert_eq!(provider.api_schema(), "openai");
        assert!(provider.supports_path_suffix());

        // An explicit base_url still overrides the preset.
        let json2 = r#"{"provider_type":"xai","model":"grok-2","base_url":"https://proxy.internal/x"}"#;
        let provider2: LLMProvider = serde_json::from_str(json2).expect("xai preset deserializes");
        assert_eq!(provider2.get_endpoint(), "https://proxy.internal/x");

        // Newer presets resolve their own base URL too.
        let ds = r#"{"provider_type":"deepseek","model":"deepseek-chat","api_key_secret":"sec-2"}"#;
        let provider3: LLMProvider = serde_json::from_str(ds).expect("deepseek preset deserializes");
        assert_eq!(provider3.provider_type_str(), "deepseek");
        assert_eq!(provider3.get_endpoint(), "https://api.deepseek.com");
        assert!(provider3.supports_path_suffix());
    }

    #[test]
    fn m365_copilot_deserializes_with_graph_defaults_and_copilot_schema() {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;
        let json = r#"{"provider_type":"m365_copilot","model":"copilot"}"#;
        let provider: LLMProvider = serde_json::from_str(json).expect("copilot deserializes");
        assert!(matches!(provider, LLMProvider::M365Copilot { .. }));
        assert_eq!(provider.provider_type_str(), "m365_copilot");
        assert_eq!(provider.get_model(), "copilot");
        // Defaults to the Microsoft Graph base and never appends a path suffix.
        assert_eq!(provider.get_endpoint(), "https://graph.microsoft.com");
        assert_eq!(provider.api_schema(), "copilot");
        assert!(!provider.supports_path_suffix());

        // An explicit base_url (e.g. a sovereign Graph cloud) overrides the default.
        let json2 = r#"{"provider_type":"m365_copilot","model":"copilot","base_url":"https://graph.microsoft.us"}"#;
        let provider2: LLMProvider = serde_json::from_str(json2).expect("copilot with base deserializes");
        assert_eq!(provider2.get_endpoint(), "https://graph.microsoft.us");

        // Round-trips: serialize preserves provider_type/model/base_url.
        let reserialized = serde_json::to_value(&provider2).expect("serialize");
        assert_eq!(reserialized["provider_type"], serde_json::json!("m365_copilot"));
        assert_eq!(reserialized["model"], serde_json::json!("copilot"));
        assert_eq!(reserialized["base_url"], serde_json::json!("https://graph.microsoft.us"));
    }

    #[test]
    fn build_catalog_provider_maps_schema_to_variant_preserving_provider_type() {
        use crate::pipes::types::llm_provider_ext::LLMProviderExt;

        // A custom provider whose enum_value isn't a built-in maps by api_schema
        // to the matching variant while keeping its own provider_type (so pricing
        // / request-shaping still resolve against the catalog entry).
        let openai_like = build_catalog_provider(
            "openai",
            "m365_copilot_custom".to_string(),
            "my-model".to_string(),
            Some("sec-1".to_string()),
            Some("https://my.host".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(openai_like, LLMProvider::OpenAI { .. }));
        assert_eq!(openai_like.provider_type_str(), "m365_copilot_custom");
        assert_eq!(openai_like.get_model(), "my-model");
        assert_eq!(openai_like.api_schema(), "openai");
        assert_eq!(openai_like.get_endpoint(), "https://my.host");

        let copilot_like = build_catalog_provider(
            "copilot",
            "my_copilot".to_string(),
            "copilot".to_string(),
            None,
            Some("https://graph.microsoft.com".to_string()),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(copilot_like, LLMProvider::M365Copilot { .. }));
        assert_eq!(copilot_like.provider_type_str(), "my_copilot");
        assert_eq!(copilot_like.api_schema(), "copilot");

        let anthropic_like = build_catalog_provider(
            "anthropic",
            "my_claude".to_string(),
            "claude-x".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(anthropic_like, LLMProvider::Anthropic { .. }));
        assert_eq!(anthropic_like.api_schema(), "anthropic");

        let gemini_like = build_catalog_provider(
            "gemini",
            "my_gemini".to_string(),
            "gemini-x".to_string(),
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
        );
        assert!(matches!(gemini_like, LLMProvider::Gemini { .. }));
        assert_eq!(gemini_like.api_schema(), "gemini");
    }

    #[test]
    fn endpoint_override_wins_over_model() {
        let pricing =
            resolve_pricing_from_providers(&catalog(), "openai", "gpt-4o", Some("/batch")).expect("endpoint pricing");
        assert_eq!(pricing.input_price_per_million, 1.25);
        assert_eq!(pricing.output_price_per_million, 5.0);
    }

    #[test]
    fn unknown_endpoint_falls_through_to_model_pricing() {
        let pricing = resolve_pricing_from_providers(&catalog(), "openai", "gpt-4o", Some("/missing"))
            .expect("model pricing fallback");
        assert_eq!(pricing.input_price_per_million, 2.5);
    }

    #[test]
    fn model_without_pricing_block_falls_back_to_builtin_table() {
        // gpt-4o-mini is present in the catalog but carries no cost fields;
        // the built-in table matches it via the `gpt-4` prefix (30/60).
        let pricing =
            resolve_pricing_from_providers(&catalog(), "openai", "gpt-4o-mini", None).expect("builtin pricing");
        assert_eq!(pricing.input_price_per_million, 30.0);
        assert_eq!(pricing.output_price_per_million, 60.0);
    }

    #[test]
    fn model_absent_from_catalog_uses_builtin_table() {
        // gpt-3.5-turbo is not in the catalog at all; builtin table => 0.5/1.5.
        let pricing =
            resolve_pricing_from_providers(&catalog(), "openai", "gpt-3.5-turbo", None).expect("builtin pricing");
        assert_eq!(pricing.input_price_per_million, 0.5);
        assert_eq!(pricing.output_price_per_million, 1.5);
    }

    #[test]
    fn returns_none_for_unknown_provider_and_model() {
        assert!(resolve_pricing_from_providers(&catalog(), "mystery", "x", None).is_none());
    }

    #[test]
    fn resolved_pricing_computes_cost() {
        let pricing = resolve_pricing_from_providers(&catalog(), "openai", "gpt-4o", None).expect("model pricing");
        // 1M input @ $2.5 + 1M output @ $10 = $12.5
        let cost = pricing.calculate_cost(1_000_000, 1_000_000);
        assert!((cost - 12.5).abs() < 1e-9);
    }

    #[test]
    fn target_pricing_accepts_zero_and_refuses_negative_or_non_finite() {
        let free = TargetPricing {
            input_per_million: 0.0,
            output_per_million: 0.0,
        };
        assert_eq!(free.validate(), Ok(()));
        assert_eq!(
            free.token_pricing()
                .calculate_cost(1_000_000, 1_000_000),
            0.0
        );
        for (input, output) in [
            (-0.01, 1.0),
            (1.0, -1.0),
            (f64::NAN, 1.0),
            (1.0, f64::INFINITY),
            (MAX_PRICE_PER_MILLION_TOKENS + 0.01, 1.0),
            (1.0, f64::MAX),
        ] {
            let pricing = TargetPricing {
                input_per_million: input,
                output_per_million: output,
            };
            assert!(pricing.validate().is_err(), "{input}/{output} must be refused");
        }
        let ceiling = TargetPricing {
            input_per_million: MAX_PRICE_PER_MILLION_TOKENS,
            output_per_million: MAX_PRICE_PER_MILLION_TOKENS,
        };
        assert_eq!(ceiling.validate(), Ok(()));
    }

    #[test]
    fn a_price_out_of_range_is_refused_as_it_is_read() {
        for (input, output) in [(-1.0, 0.0), (0.0, -0.01), (MAX_PRICE_PER_MILLION_TOKENS + 1.0, 0.0), (0.0, 1e300)] {
            let parsed = serde_json::from_value::<TargetPricing>(
                json!({ "input_per_million": input, "output_per_million": output }),
            );
            assert!(parsed.is_err(), "{input}/{output} must not parse, got {parsed:?}");
        }
        let parsed = serde_json::from_value::<TargetPricing>(
            json!({ "input_per_million": MAX_PRICE_PER_MILLION_TOKENS, "output_per_million": 0.0 }),
        );
        assert!(parsed.is_ok(), "the ceiling itself parses, got {parsed:?}");
    }

    #[test]
    fn a_computed_cost_is_never_below_zero() {
        let negative = TokenPricing {
            input_price_per_million: -5.0,
            output_price_per_million: -5.0,
        };
        assert_eq!(negative.calculate_cost(1_000_000, 1_000_000), 0.0);
        assert_eq!(billable_cost(-1.0), 0.0);
        assert_eq!(billable_cost(f64::NAN), 0.0);
        assert_eq!(billable_cost(2.5), 2.5);
    }

    fn per_million(
        input: f64,
        output: f64,
    ) -> TokenPricing {
        TokenPricing {
            input_price_per_million: input,
            output_price_per_million: output,
        }
    }

    #[test]
    fn an_own_price_is_billed_as_is_only_when_honoured() {
        let catalog = || Some(per_million(2.5, 10.0));
        let catalog_cost = per_million(2.5, 10.0).calculate_cost(1_000_000, 1_000_000);
        let free = per_million(0.0, 0.0);
        let dear = per_million(20.0, 40.0);
        let dear_cost = dear.calculate_cost(1_000_000, 1_000_000);

        assert_eq!(priced_cost(std::slice::from_ref(&free), true, catalog, 1_000_000, 1_000_000), 0.0);
        assert_eq!(priced_cost(std::slice::from_ref(&free), false, catalog, 1_000_000, 1_000_000), catalog_cost);
        assert_eq!(priced_cost(std::slice::from_ref(&dear), false, catalog, 1_000_000, 1_000_000), dear_cost);
        assert_eq!(priced_cost(&[free.clone(), dear.clone()], true, catalog, 1_000_000, 1_000_000), 0.0);
        assert_eq!(priced_cost(&[free, dear], false, catalog, 1_000_000, 1_000_000), dear_cost);
        assert_eq!(priced_cost(&[], true, catalog, 1_000_000, 1_000_000), catalog_cost);
        assert_eq!(priced_cost(&[], false, || None, 1_000_000, 1_000_000), 0.0);
    }

    #[test]
    fn an_honoured_own_price_never_looks_the_catalog_up() {
        let looked_up = std::cell::Cell::new(false);
        let catalog = || {
            looked_up.set(true);
            None
        };
        priced_cost(&[per_million(0.0, 0.0)], true, catalog, 1, 1);
        assert!(!looked_up.get());
    }

    #[test]
    fn target_pricing_needs_both_prices_and_no_others() {
        let parsed: TargetPricing =
            serde_json::from_value(json!({"input_per_million": 0.0, "output_per_million": 0.0})).expect("parses");
        assert_eq!(parsed.input_per_million, 0.0);
        assert!(serde_json::from_value::<TargetPricing>(json!({"input_per_million": 1.0})).is_err());
        assert!(
            serde_json::from_value::<TargetPricing>(
                json!({"input_per_million": 1.0, "output_per_million": 1.0, "currency": "USD"})
            )
            .is_err()
        );
    }
}
