//! LLM response parsing for token extraction

use crate::pipes::types::llm::LLMMetrics;
use serde_json::Value;

pub struct LLMResponseParser;

impl LLMResponseParser {
    /// Parse OpenAI-compatible response
    #[allow(dead_code)]
    pub fn parse_openai_response(
        body: &[u8],
        provider: &str,
        model: &str,
    ) -> Option<LLMMetrics> {
        let json: Value = serde_json::from_slice(body).ok()?;

        let usage = json.get("usage")?;
        let input_tokens = usage
            .get("prompt_tokens")?
            .as_u64()?;
        let output_tokens = usage
            .get("completion_tokens")?
            .as_u64()?;
        let total_tokens = usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| input_tokens.saturating_add(output_tokens));

        // Calculate cost if we have pricing info
        let estimated_cost_usd = crate::pipes::types::llm::TokenPricing::for_model(provider, model)
            .map(|pricing| pricing.calculate_cost(input_tokens, output_tokens));

        Some(LLMMetrics {
            provider: provider.to_string(),
            model: model.to_string(),
            input_tokens,
            output_tokens,
            total_tokens,
            estimated_cost_usd,
            time_to_first_token_ms: None,
            streaming: false,
            cached_tokens: None,
        })
    }

    /// Parse Anthropic Claude response
    pub fn parse_anthropic_response(
        body: &[u8],
        model: &str,
    ) -> Option<LLMMetrics> {
        let json: Value = serde_json::from_slice(body).ok()?;

        let usage = json.get("usage")?;
        let input_tokens = usage
            .get("input_tokens")?
            .as_u64()?;
        let output_tokens = usage
            .get("output_tokens")?
            .as_u64()?;
        let total_tokens = input_tokens.saturating_add(output_tokens);

        // Check for cache tokens
        let cached_tokens = usage
            .get("cache_read_input_tokens")
            .and_then(|v| v.as_u64());

        // Calculate cost
        let estimated_cost_usd = crate::pipes::types::llm::TokenPricing::for_model("anthropic", model)
            .map(|pricing| pricing.calculate_cost(input_tokens, output_tokens));

        Some(LLMMetrics {
            provider: "anthropic".to_string(),
            model: model.to_string(),
            input_tokens,
            output_tokens,
            total_tokens,
            estimated_cost_usd,
            time_to_first_token_ms: None,
            streaming: false,
            cached_tokens,
        })
    }

    /// Parse Gemini response
    pub fn parse_gemini_response(
        body: &[u8],
        model: &str,
    ) -> Option<LLMMetrics> {
        let json: Value = serde_json::from_slice(body).ok()?;

        let usage_metadata = json.get("usageMetadata")?;
        let input_tokens = usage_metadata
            .get("promptTokenCount")?
            .as_u64()?;
        // Thinking tokens are billed at the output rate and reported apart.
        let output_tokens = usage_metadata
            .get("candidatesTokenCount")?
            .as_u64()?
            .saturating_add(
                usage_metadata
                    .get("thoughtsTokenCount")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(0),
            );
        let total_tokens = usage_metadata
            .get("totalTokenCount")
            .and_then(|v| v.as_u64())
            .unwrap_or_else(|| input_tokens.saturating_add(output_tokens));

        Some(LLMMetrics {
            provider: "gemini".to_string(),
            model: model.to_string(),
            input_tokens,
            output_tokens,
            total_tokens,
            estimated_cost_usd: None, // Add pricing if available
            time_to_first_token_ms: None,
            streaming: false,
            cached_tokens: None,
        })
    }

    /// Try to parse response with auto-detection of provider format
    pub fn parse_auto(
        body: &[u8],
        provider: &str,
        model: &str,
    ) -> Option<LLMMetrics> {
        match provider {
            "openai" | "azure_openai" => Self::parse_openai_response(body, provider, model),
            "anthropic" => Self::parse_anthropic_response(body, model),
            "gemini" => Self::parse_gemini_response(body, model),
            _ => {
                // Try OpenAI format first (most common)
                Self::parse_openai_response(body, provider, model)
                    .or_else(|| Self::parse_anthropic_response(body, model))
                    .or_else(|| Self::parse_gemini_response(body, model))
            }
        }
    }
}

/// Parse tokens from a JSON response value (used by executor)
pub fn parse_auto(response: &Value) -> Result<(u64, u64, u64), String> {
    // Try OpenAI format first
    if let Some(usage) = response.get("usage") {
        if let Some(input) = usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
        {
            let output = usage
                .get("completion_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total = usage
                .get("total_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or_else(|| input.saturating_add(output));
            return Ok((input, output, total));
        }

        // Try Anthropic format
        if let Some(input) = usage
            .get("input_tokens")
            .and_then(|v| v.as_u64())
        {
            let output = usage
                .get("output_tokens")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let total = input.saturating_add(output);
            return Ok((input, output, total));
        }
    }

    Err("No usage information found in response".to_string())
}

/// Extract the number of **provider-side cached prompt tokens** from a response
/// `usage` block, across the common provider shapes:
///
/// - OpenAI / Azure / OpenAI-compatible: `usage.prompt_tokens_details.cached_tokens`
/// - Anthropic: `usage.cache_read_input_tokens`
/// - DeepSeek: `usage.prompt_cache_hit_tokens`
///
/// Returns `0` when the response reports no provider cache usage. This measures
/// the upstream provider's own prompt cache (distinct from Agent Stream's
/// response cache) so operators can see provider-side cache hit volume.
pub fn parse_cached_tokens(response: &Value) -> u64 {
    let Some(usage) = response.get("usage") else {
        return 0;
    };
    usage
        .get("prompt_tokens_details")
        .and_then(|d| d.get("cached_tokens"))
        .and_then(|v| v.as_u64())
        .or_else(|| {
            usage
                .get("cache_read_input_tokens")
                .and_then(|v| v.as_u64())
        })
        .or_else(|| {
            usage
                .get("prompt_cache_hit_tokens")
                .and_then(|v| v.as_u64())
        })
        .unwrap_or(0)
}

/// Extract the provider-reported **reasoning** (thinking) token count.
///
/// OpenAI reasoning models and the Responses API report this at
/// `usage.completion_tokens_details.reasoning_tokens`. Anthropic and Gemini fold
/// thinking tokens into their output count and do not break them out, so this
/// returns `0` for them. Reasoning tokens are a **sub-count of output tokens**
/// (already billed as output) surfaced for visibility, not an additional charge.
pub fn parse_reasoning_tokens(response: &Value) -> u64 {
    response
        .get("usage")
        .and_then(|u| u.get("completion_tokens_details"))
        .and_then(|d| d.get("reasoning_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

/// Extract provider-reported **cache-write** (cache-creation) prompt tokens.
///
/// Anthropic reports `usage.cache_creation_input_tokens` when a request writes
/// new entries into the provider prompt cache (billed at a premium over normal
/// input). Distinct from cache **read** tokens ([`parse_cached_tokens`]).
/// Returns `0` when the provider reports none.
pub fn parse_cache_write_tokens(response: &Value) -> u64 {
    response
        .get("usage")
        .and_then(|u| u.get("cache_creation_input_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cached_tokens_reads_each_provider_shape() {
        use serde_json::json;
        // OpenAI shape.
        let openai = json!({ "usage": { "prompt_tokens": 100, "prompt_tokens_details": { "cached_tokens": 64 } } });
        assert_eq!(parse_cached_tokens(&openai), 64);
        // Anthropic shape.
        let anthropic = json!({ "usage": { "input_tokens": 100, "cache_read_input_tokens": 40 } });
        assert_eq!(parse_cached_tokens(&anthropic), 40);
        // DeepSeek shape.
        let deepseek = json!({ "usage": { "prompt_tokens": 100, "prompt_cache_hit_tokens": 24 } });
        assert_eq!(parse_cached_tokens(&deepseek), 24);
        // No cache usage / no usage block → 0.
        assert_eq!(parse_cached_tokens(&json!({ "usage": { "prompt_tokens": 10 } })), 0);
        assert_eq!(parse_cached_tokens(&json!({})), 0);
    }

    #[test]
    fn parse_reasoning_tokens_reads_completion_details() {
        use serde_json::json;
        let openai =
            json!({ "usage": { "completion_tokens": 200, "completion_tokens_details": { "reasoning_tokens": 128 } } });
        assert_eq!(parse_reasoning_tokens(&openai), 128);
        // Anthropic-shaped usage (no details) → 0.
        assert_eq!(parse_reasoning_tokens(&json!({ "usage": { "completion_tokens": 50 } })), 0);
        assert_eq!(parse_reasoning_tokens(&json!({})), 0);
    }

    #[test]
    fn parse_cache_write_tokens_reads_creation() {
        use serde_json::json;
        let anthropic = json!({ "usage": { "input_tokens": 100, "cache_creation_input_tokens": 512 } });
        assert_eq!(parse_cache_write_tokens(&anthropic), 512);
        assert_eq!(parse_cache_write_tokens(&json!({ "usage": { "input_tokens": 10 } })), 0);
        assert_eq!(parse_cache_write_tokens(&json!({})), 0);
    }

    #[test]
    fn test_parse_openai_response() {
        let response = r#"{
            "model": "gpt-4-turbo",
            "usage": {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "total_tokens": 150
            }
        }"#;

        let metrics = LLMResponseParser::parse_openai_response(response.as_bytes(), "openai", "gpt-4-turbo").unwrap();

        assert_eq!(metrics.input_tokens, 100);
        assert_eq!(metrics.output_tokens, 50);
        assert_eq!(metrics.total_tokens, 150);
        assert!(
            metrics
                .estimated_cost_usd
                .is_some()
        );
    }

    #[test]
    fn test_parse_anthropic_response() {
        let response = r#"{
            "model": "claude-3-sonnet-20240229",
            "usage": {
                "input_tokens": 200,
                "output_tokens": 100
            }
        }"#;

        let metrics =
            LLMResponseParser::parse_anthropic_response(response.as_bytes(), "claude-3-sonnet-20240229").unwrap();

        assert_eq!(metrics.input_tokens, 200);
        assert_eq!(metrics.output_tokens, 100);
        assert_eq!(metrics.total_tokens, 300);
    }

    #[test]
    fn test_parse_anthropic_response_saturates_instead_of_overflowing() {
        let response = r#"{"usage":{"input_tokens":18446744073709551615,"output_tokens":1}}"#;

        let metrics =
            LLMResponseParser::parse_anthropic_response(response.as_bytes(), "claude-3-sonnet-20240229").unwrap();

        assert_eq!(metrics.input_tokens, u64::MAX);
        assert_eq!(metrics.output_tokens, 1);
        assert_eq!(metrics.total_tokens, u64::MAX);
    }

    #[test]
    fn test_parse_gemini_response_saturates_instead_of_overflowing() {
        let response = r#"{"usageMetadata":{"promptTokenCount":18446744073709551615,"candidatesTokenCount":5,"totalTokenCount":-1}}"#;

        let metrics = LLMResponseParser::parse_gemini_response(response.as_bytes(), "gemini-1.5-pro").unwrap();

        assert_eq!(metrics.input_tokens, u64::MAX);
        assert_eq!(metrics.output_tokens, 5);
        assert_eq!(metrics.total_tokens, u64::MAX);
    }

    #[test]
    fn test_parse_gemini_response_counts_thinking_as_output() {
        let response = r#"{"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":5,"thoughtsTokenCount":300}}"#;
        let metrics = LLMResponseParser::parse_gemini_response(response.as_bytes(), "gemini-2.5-pro").unwrap();
        assert_eq!(metrics.output_tokens, 305);
    }

    #[test]
    fn test_parse_auto_openai_saturates_instead_of_overflowing() {
        let response: Value =
            serde_json::from_str(r#"{"usage":{"prompt_tokens":18446744073709551615,"completion_tokens":100}}"#)
                .unwrap();

        let (input, output, total) = parse_auto(&response).unwrap();

        assert_eq!(input, u64::MAX);
        assert_eq!(output, 100);
        assert_eq!(total, u64::MAX);
    }

    #[test]
    fn test_parse_auto_embeddings_usage_input_only() {
        // Embeddings responses carry `usage.prompt_tokens` + `total_tokens` but
        // NO `completion_tokens` and no `choices`. The gateway meters these as
        // input-only (output = 0), so cost resolves against the embedding
        // model's input price.
        let response: Value = serde_json::from_str(
            r#"{"object":"list","data":[{"embedding":[0.1,0.2]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":8,"total_tokens":8}}"#,
        )
        .unwrap();

        let (input, output, total) = parse_auto(&response).unwrap();

        assert_eq!(input, 8);
        assert_eq!(output, 0);
        assert_eq!(total, 8);
    }

    #[test]
    fn test_parse_auto_errs_without_usage_block() {
        // Moderations/rerank responses carry no `usage` block. `parse_auto`
        // reports this as an error; the executor treats that as zero tokens for
        // non-chat endpoints rather than failing the request.
        let moderation: Value =
            serde_json::from_str(r#"{"id":"modr-1","model":"omni-moderation","results":[{"flagged":false}]}"#).unwrap();
        assert!(parse_auto(&moderation).is_err());

        let rerank: Value =
            serde_json::from_str(r#"{"id":"rrnk-1","results":[{"index":0,"relevance_score":0.9}]}"#).unwrap();
        assert!(parse_auto(&rerank).is_err());
    }

    #[test]
    fn test_parse_auto_anthropic_saturates_instead_of_overflowing() {
        let response: Value =
            serde_json::from_str(r#"{"usage":{"input_tokens":18446744073709551615,"output_tokens":1}}"#).unwrap();

        let (input, output, total) = parse_auto(&response).unwrap();

        assert_eq!(input, u64::MAX);
        assert_eq!(output, 1);
        assert_eq!(total, u64::MAX);
    }
}
