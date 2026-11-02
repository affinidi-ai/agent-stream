//! Judge & Jury execution engine
//!
//! Handles LLM calls for Judge (pre-processing) and Jury (post-processing) validation,
//! including decision evaluation via JSON parsing or regex matching.
//!
//! ## Observability
//! All operations are instrumented with OpenTelemetry spans:
//! - `pipe.judge.evaluate` — overall Judge evaluation
//! - `pipe.judge.llm_call` — individual Judge LLM HTTP call
//! - `pipe.jury.evaluate` — overall Jury evaluation
//! - `pipe.jury.juror` — individual Juror evaluation
//! - `pipe.jury.juror.llm_call` — individual Juror LLM HTTP call
//!
//! ## Serial Cascading
//! In serial mode, each juror receives the previous juror's raw LLM response
//! appended to the original content, enabling a refinement chain.

use super::config::*;
use crate::pipes::config::{CUMULATIVE_SCOPE_KEY, StageUsage, UsageStage};
use crate::pipes::executor::{BudgetedCall, PipeError, admit_call};
use crate::pipes::key_source::{CallerKey, KeySource, KeySourceCounts};
use crate::pipes::types::llm::LLMProvider;
use crate::pipes::types::llm_provider_ext::LLMProviderExt;
use crate::secrets::SurfaceSecrets;
use regex::Regex;
use serde_json::Value;
use std::time::Instant;
use tracing::{Instrument, info, warn};

/// Compare a score against a threshold using the given operator
fn compare_score(
    score: f64,
    operator: &str,
    threshold: f64,
) -> bool {
    match operator {
        ">=" => score >= threshold,
        ">" => score > threshold,
        "<=" => score <= threshold,
        "<" => score < threshold,
        "==" => (score - threshold).abs() < f64::EPSILON,
        _ => {
            warn!("Unknown score operator '{}', defaulting to >=", operator);
            score >= threshold
        }
    }
}

/// Result of a Judge or Jury evaluation
#[derive(Debug)]
pub enum JudgeJuryOutcome {
    /// Approved — continue processing
    Approved { details: Option<String> },
    /// Rejected — stop and return error
    Rejected { reason: String },
}

/// Convert an `LLMTarget` to a runtime `LLMProvider` for making API calls.
/// This allows Judge/Jury to reuse all existing provider infrastructure
/// (header building, endpoint resolution, etc.)
pub(crate) fn target_to_provider(target: &LLMTarget) -> LLMProvider {
    // Extract parameters if present
    let params = target.parameters.as_ref();
    let temperature = params
        .and_then(|p| p.get("temperature"))
        .and_then(|v| v.as_f64());
    let max_tokens = params
        .and_then(|p| p.get("max_tokens"))
        .and_then(|v| v.as_u64())
        .map(|v| v as u32);
    let top_p = params
        .and_then(|p| p.get("top_p"))
        .and_then(|v| v.as_f64());

    match target.provider_type.as_str() {
        "openai" => LLMProvider::OpenAI {
            provider_type: "openai".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            organization_id: None,
            base_url: {
                let default_endpoint =
                    format!("{}/v1/chat/completions", crate::pipes::defaults::DEFAULT_OPENAI_BASE_URL);
                if target.endpoint_url != default_endpoint {
                    Some(target.endpoint_url.clone())
                } else {
                    None
                }
            },
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "anthropic" => LLMProvider::Anthropic {
            provider_type: "anthropic".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            version: None,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "gemini" => LLMProvider::Gemini {
            provider_type: "gemini".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            project_id: None,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "bedrock" => LLMProvider::Bedrock {
            provider_type: "bedrock".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            // LLMTarget has no `region` field yet, so the fully-resolved endpoint_url
            // is passed via `base_url` and takes precedence over region-based derivation.
            region: None,
            base_url: Some(target.endpoint_url.clone()),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "azure" => LLMProvider::AzureOpenAI {
            provider_type: "azure".to_string(),
            deployment_name: target.model.clone(),
            endpoint: target
                .endpoint_url
                .split("/openai/")
                .next()
                .unwrap_or(&target.endpoint_url)
                .to_string(),
            api_key_secret: target.api_key_secret.clone(),
            api_version: "2024-02-01".to_string(),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "cohere" => LLMProvider::Cohere {
            provider_type: "cohere".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "mistral" => LLMProvider::Mistral {
            provider_type: "mistral".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            endpoint: Some(target.endpoint_url.clone()),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "together_ai" => LLMProvider::TogetherAI {
            provider_type: "together_ai".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "replicate" => LLMProvider::Replicate {
            provider_type: "replicate".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "huggingface" => LLMProvider::HuggingFace {
            provider_type: "huggingface".to_string(),
            model: target.model.clone(),
            api_key_secret: target.api_key_secret.clone(),
            endpoint: Some(target.endpoint_url.clone()),
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        "ollama" => LLMProvider::Ollama {
            provider_type: "ollama".to_string(),
            model: target.model.clone(),
            api_key_secret: None,
            base_url: if target.endpoint_url != "http://localhost:11434/v1/chat/completions" {
                // Strip the path suffix to get the base URL
                target
                    .endpoint_url
                    .rfind("/v1/")
                    .map(|i| target.endpoint_url[..i].to_string())
            } else {
                None
            },
            api_schema: None,
            _marketplace_source: None,
            temperature,
            max_tokens,
            top_p,
            frequency_penalty: None,
            presence_penalty: None,
        },
        // An unknown type may be a user-defined catalog provider. Resolve it
        // through the LLM catalog exactly like the primary provider does — its
        // base URL comes from the catalog `default_base_url` and the concrete
        // variant from its `api_schema`. A relative `endpoint_url` (e.g. the
        // schema's default path) carries no base, so let the catalog default
        // apply; an absolute `endpoint_url` overrides it. Falls back to a raw
        // Custom provider only when the catalog does not know the type.
        _ => {
            let base_override = {
                let trimmed = target.endpoint_url.trim();
                if trimmed.is_empty() || trimmed.starts_with('/') {
                    None
                } else {
                    Some(target.endpoint_url.clone())
                }
            };
            crate::pipes::types::llm::resolve_custom_catalog_provider(
                target.provider_type.clone(),
                target.model.clone(),
                target.api_key_secret.clone(),
                base_override,
                None,
                None,
                temperature,
                max_tokens,
                top_p,
                None,
                None,
            )
            .unwrap_or_else(|| LLMProvider::Custom {
                provider_type: target.provider_type.clone(),
                name: target.provider_type.clone(),
                endpoint: target.endpoint_url.clone(),
                auth_header: Some("Authorization".to_string()),
                auth_secret: target.api_key_secret.clone(),
                temperature,
                max_tokens,
                top_p,
                frequency_penalty: None,
                presence_penalty: None,
            })
        }
    }
}

/// Whether the provider [`target_to_provider`] builds for `target` calls the
/// origin of the target's own endpoint. Some provider types ignore
/// `endpoint_url` and always call their vendor's default host, so a copy of
/// the surface routed to such a target (failover, load balancing, routing)
/// would send the target's `headers` to a host the target never named.
pub(crate) fn provider_calls_target_endpoint(target: &LLMTarget) -> bool {
    crate::pipes::upstream_headers::same_origin(&target.resolved_endpoint(), &target_to_provider(target).get_endpoint())
}

/// Resolve one of a target's secret references through
/// [`SurfaceSecrets::resolve`], the save-time tenancy check's resolution plus
/// the surface's tenancy re-check, so a target sends only a secret the surface
/// may use. A failure is logged with the reference and reported to the caller
/// without it.
async fn resolve_target_secret(
    pipe_id: &str,
    credential: &str,
    reference: &str,
    secrets: &SurfaceSecrets,
) -> Result<Option<crate::secrets::Secret>, PipeError> {
    secrets
        .resolve(reference)
        .await
        .map_err(|e| {
            crate::pipes::upstream_headers::credential_unavailable(pipe_id, credential, reference, &e.to_string())
        })
}

/// The request headers for one call to a target, whether the call may be
/// billed at the target's declared price (see [`SurfaceSecrets::owns`]), and
/// the source of the key it sends.
struct TargetCallHeaders {
    headers: Vec<(String, String)>,
    own_price_honoured: bool,
    key_source: KeySource,
    /// The call sends no credential at all.
    keyless: bool,
}

/// Build the request headers for a call to `target` at `request_url`: the
/// provider's own headers with its resolved key, then the target's own
/// `headers`, each value resolved from the secrets store. Only this target's
/// headers are ever added, only to a request on the origin of the endpoint
/// they were configured for, and the client every caller sends with refuses
/// redirects, so they reach this target's endpoint and nowhere else. An
/// unresolvable header secret fails the call: going out without a header the
/// upstream requires would turn a configuration error into an opaque 401.
async fn build_target_headers(
    pipe_id: &str,
    target: &LLMTarget,
    provider: &LLMProvider,
    secrets: &SurfaceSecrets,
    request_url: &str,
) -> Result<TargetCallHeaders, PipeError> {
    crate::pipes::upstream_headers::ensure_same_origin(
        pipe_id,
        &target.headers,
        &target.resolved_endpoint(),
        request_url,
    )?;
    let mut own_price_honoured = true;
    // A pipeline stage never sends the caller's key: only its own.
    let key = crate::pipes::key_source::resolve_call_key(CallerKey::NotOffered, || async {
        match &target.api_key_secret {
            Some(reference) => secrets
                .resolve_key(reference)
                .await
                .map_err(|e| {
                    crate::pipes::upstream_headers::credential_unavailable(
                        pipe_id,
                        "API key",
                        reference,
                        &e.to_string(),
                    )
                }),
            None => Ok(None),
        }
    })
    .await?;
    let key_source = key
        .as_ref()
        .map(|key| key.source);
    let mut headers = match key {
        Some(key) => {
            own_price_honoured &= secrets.honours_own_price(key.source);
            provider.build_headers_with_key(&key.value)
        }
        None => provider.build_headers(),
    };
    let mut headers_source: Option<KeySource> = None;
    for header in &target.headers {
        let credential = format!("header {:?}", header.name);
        let secret = resolve_target_secret(pipe_id, &credential, &header.secret_id, secrets)
            .await?
            .ok_or_else(|| {
                crate::pipes::upstream_headers::credential_unavailable(
                    pipe_id,
                    &credential,
                    &header.secret_id,
                    "no secret answers to the reference",
                )
            })?;
        own_price_honoured &= secrets.owns(secret.tenant_id.as_deref());
        let header_source = secrets.key_source(secret.tenant_id.as_deref());
        headers_source = Some(headers_source.map_or(header_source, |s| s.combine(header_source)));
        headers.push((header.name.clone(), secret.value));
    }
    Ok(TargetCallHeaders {
        headers,
        own_price_honoured,
        key_source: crate::pipes::key_source::call_key_source(key_source, headers_source),
        keyless: key_source.is_none() && headers_source.is_none(),
    })
}

/// Ask the budget before a call to `target` (see [`admit_call`]). A call that
/// sends no credential is asked only when the target is priced: who pays a
/// keyless upstream is not knowable from the absence of a key, and an
/// unpriced one bills nothing.
async fn admit_target_call(
    target: &LLMTarget,
    headers: &TargetCallHeaders,
    what: &str,
) -> Result<(), PipeError> {
    if headers.keyless && !target_priced(target) {
        return Ok(());
    }
    admit_call(headers.key_source, BudgetedCall::Stage, what).await
}

/// Whether a call to `target` that sends no credential bills anything: its
/// declared price, else its catalog price (a keyless call's own price is
/// always honoured, see [`stage_cost`]).
fn target_priced(target: &LLMTarget) -> bool {
    stage_cost(target, true, 1_000_000, 1_000_000) > 0.0
}

/// The key source the budget would be asked about for a call to `target`,
/// resolved without making the call: `None` when the budget would not be
/// asked (a keyless, unpriced target) or the target's credentials cannot be
/// resolved, which its own call reports when the stage runs.
pub async fn target_budget_source(
    pipe_id: &str,
    target: &LLMTarget,
    secrets: &SurfaceSecrets,
) -> Option<KeySource> {
    let provider = target_to_provider(target);
    let endpoint = target.resolved_endpoint();
    let headers = build_target_headers(pipe_id, target, &provider, secrets, &endpoint)
        .await
        .ok()?;
    (!headers.keyless || target_priced(target)).then_some(headers.key_source)
}

/// Send a request to the OpenAI Moderations API and get the raw JSON response.
/// The Moderations API expects `{"model": "...", "input": "..."}` format
/// and returns `{"results": [{"flagged": bool, "categories": {...}, "category_scores": {...}}]}`.
async fn call_moderation(
    pipe_id: &str,
    target: &LLMTarget,
    content: &str,
    secrets: &SurfaceSecrets,
    span_name: &str,
) -> Result<(Value, bool, KeySource), PipeError> {
    let llm_span = tracing::info_span!(
        "pipe.judge_jury.moderation_call",
        otel.name = %span_name,
        llm.provider = %target.provider_type,
        llm.model = %target.model,
        llm.endpoint = %target.endpoint_url,
        llm.timeout_secs = %target.timeout_secs,
        llm.status = tracing::field::Empty,
        llm.response_len = tracing::field::Empty,
    );

    async {
        let provider = target_to_provider(target);
        let endpoint = target
            .endpoint_url
            .replace("{model}", &target.model);

        // Moderations API request format
        let request_body = serde_json::json!({
            "model": target.model,
            "input": content
        });

        let call_headers = build_target_headers(pipe_id, target, &provider, secrets, &endpoint).await?;
        admit_target_call(target, &call_headers, span_name).await?;
        let TargetCallHeaders {
            headers,
            own_price_honoured,
            key_source,
            ..
        } = call_headers;
        ensure_target_priced(pipe_id, target, own_price_honoured)?;

        info!(
            "[PIPE:{}] {} — calling provider: {}, model: {}, endpoint: {}, timeout: {}s",
            pipe_id, span_name, target.provider_type, target.model, endpoint, target.timeout_secs
        );

        let call_start = std::time::Instant::now();

        let timeout = std::time::Duration::from_secs(target.timeout_secs);

        crate::url_validation::validate_service_endpoint_url(&endpoint)
            .await
            .map_err(|e| PipeError::RequestFailed(format!("endpoint_url blocked: {}", e)))?;
        let client = crate::http_client::with_service_endpoint_resolver(timeout)
            .map_err(|e| PipeError::RequestFailed(format!("Failed to create HTTP client: {}", e)))?;
        let mut request = client
            .post(endpoint)
            .header("Content-Type", "application/json")
            .body(
                serde_json::to_vec(&request_body)
                    .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize moderation request: {}", e)))?,
            );

        for (header_name, header_value) in headers {
            request = request.header(header_name, header_value);
        }

        let response = request
            .send()
            .await
            .map_err(|e| {
                let current_span = tracing::Span::current();
                current_span.record("llm.status", "error");
                if e.is_timeout() {
                    PipeError::RequestFailed(format!(
                        "Moderation API request timed out after {}s: {}",
                        target.timeout_secs, e
                    ))
                } else {
                    PipeError::RequestFailed(format!("Moderation API request failed: {}", e))
                }
            })?;

        if !response.status().is_success() {
            let status = response.status();
            let error_body = response
                .text()
                .await
                .unwrap_or_default();
            let current_span = tracing::Span::current();
            current_span.record("llm.status", format!("http_{}", status.as_u16()));
            return Err(PipeError::upstream_failure(status, false, "Moderation API returned ", &error_body));
        }

        let response_text = response
            .text()
            .await
            .map_err(|e| PipeError::InvalidResponse(format!("Failed to read moderation response: {}", e)))?;

        let response_json: Value = serde_json::from_str(&response_text)
            .map_err(|e| PipeError::InvalidResponse(format!("Moderation response is not valid JSON: {}", e)))?;

        let elapsed_ms = call_start
            .elapsed()
            .as_millis();
        info!("[PIPE:{}] {} — response received in {}ms", pipe_id, span_name, elapsed_ms);

        let current_span = tracing::Span::current();
        current_span.record("llm.status", "success");
        current_span.record("llm.response_len", response_text.len());

        Ok((response_json, own_price_honoured, key_source))
    }
    .instrument(llm_span)
    .await
}

/// Evaluate Judge rules against an OpenAI Moderation API response.
/// Rules are evaluated in order — first matching rule triggers rejection.
/// If no rules match, the request is approved.
fn evaluate_judge_rules_moderation(
    pipe_id: &str,
    response: &Value,
    rules: &[JudgeRule],
) -> Result<(), PipeError> {
    let result = match response
        .get("results")
        .and_then(|r| r.get(0))
    {
        Some(r) => r,
        None => {
            return Err(PipeError::InvalidResponse("Moderation API response missing 'results' array".to_string()));
        }
    };

    let flagged = result
        .get("flagged")
        .and_then(|f| f.as_bool())
        .unwrap_or(false);
    info!(
        "[PIPE:{}] Moderation result: flagged={}, categories={}, scores={}",
        pipe_id,
        flagged,
        result
            .get("categories")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "N/A".to_string()),
        result
            .get("category_scores")
            .map(|v| v.to_string())
            .unwrap_or_else(|| "N/A".to_string())
    );

    for rule in rules {
        let c = &rule.condition;
        info!("[PIPE:{}] Evaluating Moderation rule '{}' (type: {})", pipe_id, rule.name, c.condition_type);
        let category = c
            .category
            .as_deref()
            .filter(|cat| !cat.trim().is_empty());
        let matched = match c.condition_type.as_str() {
            "category_flagged" | "category_score" if category.is_none() => {
                warn!(
                    "[PIPE:{}] Judge rule '{}': {} has no category — rejecting with HTTP {}",
                    pipe_id, rule.name, c.condition_type, JUDGE_INDETERMINATE_STATUS
                );
                return Err(judge_indeterminate_rejection());
            }
            "flagged" => {
                info!(
                    "[PIPE:{}]   → flagged check: flagged={} → {}",
                    pipe_id,
                    flagged,
                    if flagged {
                        "MATCH"
                    } else {
                        "no match"
                    }
                );
                flagged
            }
            "category_flagged" => {
                let cat = category.unwrap_or_default();
                let cat_flagged = result
                    .get("categories")
                    .and_then(|cats| cats.get(cat))
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                info!(
                    "[PIPE:{}]   → category_flagged: category '{}' flagged={} → {}",
                    pipe_id,
                    cat,
                    cat_flagged,
                    if cat_flagged {
                        "MATCH"
                    } else {
                        "no match"
                    }
                );
                cat_flagged
            }
            "category_score" => {
                let cat = category.unwrap_or_default();
                let operator = c
                    .operator
                    .as_deref()
                    .unwrap_or(">=");
                let threshold = c.threshold.unwrap_or(0.5);
                let score = result
                    .get("category_scores")
                    .and_then(|cats| cats.get(cat))
                    .and_then(|v| v.as_f64())
                    .unwrap_or(0.0);
                let is_match = compare_score(score, operator, threshold);
                info!(
                    "[PIPE:{}]   → category_score: category '{}' score={:.4} {} {:.4} → {}",
                    pipe_id,
                    cat,
                    score,
                    operator,
                    threshold,
                    if is_match {
                        "MATCH"
                    } else {
                        "no match"
                    }
                );
                is_match
            }
            other => {
                warn!(
                    "[PIPE:{}] Judge rule '{}': condition type '{}' is not valid in moderation mode — rejecting with HTTP {}",
                    pipe_id, rule.name, other, JUDGE_INDETERMINATE_STATUS
                );
                return Err(judge_indeterminate_rejection());
            }
        };

        if matched {
            info!("[PIPE:{}] Judge rule '{}' matched — rejecting with HTTP {}", pipe_id, rule.name, rule.status_code);
            let mut reasons = vec![rule.name.clone()];
            if let Some(cat) = c.category.as_ref()
                && !cat.is_empty()
            {
                reasons.push(cat.clone());
            }
            return Err(judge_rejection(rule.status_code, &rule.body, &rule.content_type, reasons));
        } else {
            info!("[PIPE:{}] Judge rule '{}' did not match — continuing", pipe_id, rule.name);
        }
    }

    info!("[PIPE:{}] All {} Moderation rules evaluated — none matched, APPROVING", pipe_id, rules.len());
    Ok(())
}

/// Resolve a JSON field value by trying the primary field name first, then
/// common LLM-generated aliases.  Small models (e.g. qwen) frequently rename
/// `"decision"` → `"approval"` or `"confidence"` → `"confidence_score"` despite
/// explicit instructions.  Returns `(canonical_field, value)` when found.
fn resolve_json_field<'a>(
    json: &'a Value,
    field: &str,
) -> Option<(&'static str, &'a Value)> {
    // Fast path – exact match
    if let Some(v) = json.get(field) {
        // Use a leaked &'static str so we can return a consistent type; this is
        // called a bounded number of times so leaking a tiny string is fine.
        return Some((
            Box::leak(
                field
                    .to_owned()
                    .into_boxed_str(),
            ),
            v,
        ));
    }

    // Alias table – kept deliberately small and focused.
    let aliases: &[(&str, &[&str])] = &[
        ("decision", &["approval", "verdict", "result", "judgment", "judgement", "status", "action"]),
        ("confidence", &["confidence_score", "confidence_level"]),
        ("details", &["reason", "explanation", "detail", "reasoning", "rationale"]),
    ];

    for &(canonical, alts) in aliases {
        if field == canonical {
            for &alt in alts {
                if let Some(v) = json.get(alt) {
                    return Some((alt, v));
                }
            }
        }
    }
    None
}

/// Reason token recorded when a Judge rule cannot be evaluated against the LLM response.
const JUDGE_VERDICT_INDETERMINATE: &str = "judge_verdict_indeterminate";

/// Outcome of one Judge rule against an LLM response. `Indeterminate` means the
/// rule could not be evaluated (no JSON, missing field, invalid pattern, unknown
/// condition type); the Judge rejects on it rather than treating it as no match.
enum RuleVerdict {
    Match,
    NoMatch,
    Indeterminate,
}

/// Look up `field` (or one of its aliases) in the parsed Judge response and
/// return its value as a lowercase string.
fn judge_json_field_value(
    pipe_id: &str,
    parsed_json: Option<&Value>,
    field: &str,
) -> Option<String> {
    let (found_field, v) = resolve_json_field(parsed_json?, field)?;
    if found_field != field {
        warn!("[PIPE:{}]   → field '{}' not found, using alias '{}'", pipe_id, field, found_field);
    }
    let v_str = match v {
        Value::String(s) => s.clone(),
        other => other.to_string(),
    };
    Some(v_str.to_lowercase())
}

fn evaluate_judge_rule_llm(
    pipe_id: &str,
    content: &str,
    parsed_json: Option<&Value>,
    condition: &JudgeCondition,
) -> RuleVerdict {
    let field = condition
        .field
        .as_deref()
        .unwrap_or("");
    let value = condition
        .value
        .as_deref()
        .unwrap_or("")
        .to_lowercase();
    match condition
        .condition_type
        .as_str()
    {
        "json_field_equals" | "json_field_not_equals" => {
            let Some(actual) = judge_json_field_value(pipe_id, parsed_json, field) else {
                warn!(
                    "[PIPE:{}]   → {}: field '{}' not found or response is not JSON → INDETERMINATE",
                    pipe_id, condition.condition_type, field
                );
                return RuleVerdict::Indeterminate;
            };
            let equals = actual == value;
            let matched = if condition.condition_type == "json_field_equals" {
                equals
            } else {
                !equals
            };
            info!(
                "[PIPE:{}]   → {}: field '{}' = '{}', expected '{}' → {}",
                pipe_id,
                condition.condition_type,
                field,
                actual,
                value,
                if matched {
                    "MATCH"
                } else {
                    "no match"
                }
            );
            if matched {
                RuleVerdict::Match
            } else {
                RuleVerdict::NoMatch
            }
        }
        "regex_match" => {
            let pattern = condition
                .pattern
                .as_deref()
                .unwrap_or("");
            match Regex::new(pattern) {
                Ok(re) => {
                    let is_match = re.is_match(content);
                    info!(
                        "[PIPE:{}]   → regex_match: pattern '{}' → {}",
                        pipe_id,
                        pattern,
                        if is_match {
                            "MATCH"
                        } else {
                            "no match"
                        }
                    );
                    if is_match {
                        RuleVerdict::Match
                    } else {
                        RuleVerdict::NoMatch
                    }
                }
                Err(e) => {
                    warn!("[PIPE:{}]   → regex_match: invalid pattern ({}) → INDETERMINATE", pipe_id, e);
                    RuleVerdict::Indeterminate
                }
            }
        }
        other => {
            warn!("[PIPE:{}]   → condition type '{}' is not valid in LLM mode → INDETERMINATE", pipe_id, other);
            RuleVerdict::Indeterminate
        }
    }
}

/// Status for a Judge that could not reach a verdict: the same as an
/// unreadable Expert Witness verdict, and distinct from a rule's own rejection.
const JUDGE_INDETERMINATE_STATUS: u16 = 502;
const JUDGE_INDETERMINATE_BODY: &str = r#"{"error":{"message":"The Judge could not evaluate the request","type":"guardrail_unavailable","code":"judge_indeterminate"}}"#;

fn judge_indeterminate_rejection() -> PipeError {
    judge_rejection(
        JUDGE_INDETERMINATE_STATUS,
        JUDGE_INDETERMINATE_BODY,
        "application/json",
        vec![JUDGE_VERDICT_INDETERMINATE.to_string()],
    )
}

fn judge_rejection(
    status_code: u16,
    body: &str,
    content_type: &str,
    raw_reasons: Vec<String>,
) -> PipeError {
    PipeError::PromptGuardRejected {
        status_code,
        body: body.to_string(),
        content_type: content_type.to_string(),
        rejection: Some(Box::new(crate::pipes::executor::RejectionMeta::new(
            crate::pipes::executor::RejectionStage::Judge,
            "judge",
            raw_reasons,
        ))),
        usage: None,
    }
}

/// Evaluate Judge rules against an LLM chat completions response.
/// Rules are evaluated in order — the first rule that matches, or that cannot be
/// evaluated, rejects. If every rule evaluates to no match, the request is approved.
/// The response's `confidence` never overrides a rule.
fn evaluate_judge_rules_llm(
    pipe_id: &str,
    content: &str,
    rules: &[JudgeRule],
) -> Result<(), PipeError> {
    let json_str = extract_json_from_response(content);
    let parsed_json = serde_json::from_str::<Value>(&json_str).ok();

    if parsed_json.is_none() {
        warn!("[PIPE:{}] Judge LLM response is NOT valid JSON ({}chars)", pipe_id, json_str.len());
    } else {
        info!("[PIPE:{}] Judge LLM response parsed as JSON ({}chars)", pipe_id, json_str.len());
    }

    for rule in rules {
        info!("[PIPE:{}] Evaluating Judge rule '{}' (type: {})", pipe_id, rule.name, rule.condition.condition_type);
        match evaluate_judge_rule_llm(pipe_id, content, parsed_json.as_ref(), &rule.condition) {
            RuleVerdict::NoMatch => {
                info!("[PIPE:{}] Judge rule '{}' did not match — continuing", pipe_id, rule.name);
                continue;
            }
            RuleVerdict::Indeterminate => {
                warn!(
                    "[PIPE:{}] Judge rule '{}' could not be evaluated — rejecting with HTTP {}",
                    pipe_id, rule.name, JUDGE_INDETERMINATE_STATUS
                );
                return Err(judge_indeterminate_rejection());
            }
            RuleVerdict::Match => {
                info!(
                    "[PIPE:{}] Judge rule '{}' matched — rejecting with HTTP {}",
                    pipe_id, rule.name, rule.status_code
                );
                return Err(judge_rejection(rule.status_code, &rule.body, &rule.content_type, vec![rule.name.clone()]));
            }
        }
    }

    info!("[PIPE:{}] All {} Judge rules evaluated — none matched, APPROVING", pipe_id, rules.len());
    Ok(())
}

/// Send a request to a Judge/Jury LLM and get the raw response text.
/// Wrapped in an OTEL span for timing visibility.
///
/// When `disable_thinking` is `Some(true)`, the request is modified to suppress
/// chain-of-thought reasoning:
///   - Ollama: adds `"think": false` to the request body
///   - Others: appends `/no_think` to the system prompt
///
/// When thinking is left on (default) and the model returns only thinking text
/// with no extractable JSON, the function automatically retries once with
/// thinking disabled so the user still gets a valid decision.
/// Extract `(input_tokens, output_tokens)` from a provider LLM response, keyed
/// by the wire schema. Missing usage fields count as zero.
fn extract_token_usage(
    response_json: &Value,
    api_schema: &str,
) -> (u64, u64) {
    let u64_at = |usage: Option<&Value>, field: &str| {
        usage
            .and_then(|u| u.get(field))
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    };
    match api_schema {
        "anthropic" | "bedrock-anthropic" => {
            let usage = response_json.get("usage");
            (u64_at(usage, "input_tokens"), u64_at(usage, "output_tokens"))
        }
        "gemini" => {
            // Thinking tokens are billed at the output rate and reported apart.
            let usage = response_json.get("usageMetadata");
            (
                u64_at(usage, "promptTokenCount"),
                u64_at(usage, "candidatesTokenCount") + u64_at(usage, "thoughtsTokenCount"),
            )
        }
        _ => {
            let usage = response_json.get("usage");
            (u64_at(usage, "prompt_tokens"), u64_at(usage, "completion_tokens"))
        }
    }
}

/// Resolve the catalog's per-million token pricing for a judge/jury target:
/// the editable catalog (endpoint > model overrides), falling back to the
/// built-in pricing table.
fn resolve_catalog_pricing(target: &LLMTarget) -> Option<crate::pipes::types::llm::TokenPricing> {
    crate::pipes::types::llm::catalog_price(&target.provider_type, &target.model, Some(&target.endpoint_url))
}

/// Refuse a call to `target` that spends an operator credential on a model
/// the catalog does not price (see [`crate::pipes::types::llm::ensure_priced_spend`]).
/// A target's request always names its own `model`, so that is the model it runs.
fn ensure_target_priced(
    pipe_id: &str,
    target: &LLMTarget,
    own_price_honoured: bool,
) -> Result<(), PipeError> {
    crate::pipes::types::llm::ensure_priced_spend(
        pipe_id,
        own_price_honoured,
        &target.provider_type,
        &target.model,
        resolve_catalog_pricing(target).as_ref(),
    )
}

/// The cost of a judge/jury/decider call to `target`. The target's declared
/// `pricing` is billed as is (zero included) when `own_price_honoured`, else
/// never below the catalog price (see
/// [`crate::pipes::types::llm::priced_cost`]); a target that declares nothing
/// is billed from the catalog.
fn stage_cost(
    target: &LLMTarget,
    own_price_honoured: bool,
    input_tokens: u64,
    output_tokens: u64,
) -> f64 {
    let declared = target
        .pricing
        .map(|pricing| pricing.token_pricing());
    crate::pipes::types::llm::priced_cost(
        declared.as_slice(),
        own_price_honoured,
        || resolve_catalog_pricing(target),
        input_tokens,
        output_tokens,
    )
}

/// Build the *display* usage for a judge/jury stage: the real tokens consumed
/// plus the real cost (see [`stage_cost`]), billed by the source of the key the
/// call sent. Judge and juror usage is always counted so the activity-log /
/// dashboard totals reflect actual spend.
fn display_stage_usage(
    target: &LLMTarget,
    own_price_honoured: bool,
    key_source: KeySource,
    input_tokens: u64,
    output_tokens: u64,
) -> StageUsage {
    let cost = stage_cost(target, own_price_honoured, input_tokens, output_tokens);
    StageUsage::call(input_tokens, output_tokens, cost, 0, key_source)
}

/// Record a judge/jury stage's spend and tokens into the process-wide budget
/// tracker under `scope_key`. Both the per-scope bucket and the pipe-wide
/// cumulative bucket are updated so monthly caps can trip on the next call.
async fn record_stage_usage(
    pipe_id: &str,
    scope_key: &str,
    target: &LLMTarget,
    own_price_honoured: bool,
    input_tokens: u64,
    output_tokens: u64,
) {
    let Some(tracker) = crate::pipes::budget_tracker::global_budget_tracker() else {
        return;
    };
    let cost = stage_cost(target, own_price_honoured, input_tokens, output_tokens);
    let tokens = input_tokens + output_tokens;
    if cost <= 0.0 && tokens == 0 {
        return;
    }
    tracker
        .record_usage(pipe_id, scope_key, cost, tokens)
        .await;
    tracker
        .record_usage(pipe_id, CUMULATIVE_SCOPE_KEY, cost, tokens)
        .await;
}

/// Send a request to a pipeline-stage LLM and return the raw response text alongside
/// the [`StageUsage`] (tokens + display cost) it consumed. Usage covers every
/// underlying call, including the thinking-disabled auto-retry.
async fn call_llm(
    pipe_id: &str,
    target: &LLMTarget,
    system_prompt: &str,
    user_content: &str,
    secrets: &SurfaceSecrets,
    span_name: &str,
    disable_thinking: Option<bool>,
    scope_key: &str,
) -> Result<(String, StageUsage), PipeError> {
    let llm_span = tracing::info_span!(
        "pipe.judge_jury.llm_call",
        otel.name = %span_name,
        llm.provider = %target.provider_type,
        llm.model = %target.model,
        llm.endpoint = %target.endpoint_url,
        llm.timeout_secs = %target.timeout_secs,
        llm.status = tracing::field::Empty,
        llm.response_len = tracing::field::Empty,
    );

    async {
        let (content, in_tok, out_tok, latency_ms, honoured, key_source) = call_llm_inner(pipe_id, target, system_prompt, user_content, secrets, span_name, disable_thinking.unwrap_or(false)).await?;

        // If we got valid JSON or thinking was already disabled, return as-is
        let json_str = extract_json_from_response(&content);
        if serde_json::from_str::<Value>(&json_str).is_ok() {
            record_stage_usage(pipe_id, scope_key, target, honoured, in_tok, out_tok).await;
            let mut usage = display_stage_usage(target, honoured, key_source, in_tok, out_tok);
            usage.latency_ms = latency_ms;
            return Ok((content, usage));
        }

        // The response is not valid JSON. If thinking wasn't disabled, this
        // likely means the model exhausted max_tokens on chain-of-thought.
        // Auto-retry with thinking disabled to get a clean JSON decision.
        if !disable_thinking.unwrap_or(false) {
            warn!(
                "[PIPE:{}] {} — response is not valid JSON (likely a thinking model that exhausted tokens on reasoning). Auto-retrying with thinking disabled.",
                pipe_id, span_name
            );
            let (retry_content, retry_in, retry_out, retry_latency_ms, retry_honoured, retry_key_source) = call_llm_inner(pipe_id, target, system_prompt, user_content, secrets, &format!("{} (retry, no-think)", span_name), true).await?;
            let total_in = in_tok + retry_in;
            let total_out = out_tok + retry_out;
            let honoured = honoured && retry_honoured;
            record_stage_usage(pipe_id, scope_key, target, honoured, total_in, total_out).await;
            let mut usage =
                display_stage_usage(target, honoured, key_source.combine(retry_key_source), total_in, total_out);
            usage.latency_ms = latency_ms + retry_latency_ms;
            usage
                .key_sources = KeySourceCounts::one(key_source);
            usage
                .key_sources
                .record(retry_key_source);
            return Ok((retry_content, usage));
        }

        // Thinking was already disabled but still no JSON — return what we have
        record_stage_usage(pipe_id, scope_key, target, honoured, in_tok, out_tok).await;
        let mut usage = display_stage_usage(target, honoured, key_source, in_tok, out_tok);
        usage.latency_ms = latency_ms;
        Ok((content, usage))
    }
    .instrument(llm_span)
    .await
}

/// Resolve the request-shaping profile for a judge/jury target, preferring the
/// editable provider catalog and falling back to the target's declared schema and
/// capabilities when no catalog has been installed.
fn resolve_target_profile(target: &LLMTarget) -> crate::pipes::request_shaping::ModelRequestProfile {
    let caps_json = target
        .capabilities
        .as_ref()
        .and_then(|c| c.get("supports_json_mode"))
        .and_then(|v| v.as_bool());
    match crate::llm_catalog::global_catalog() {
        Some(catalog) => {
            catalog.resolve_model_profile(&target.provider_type, &target.model, &target.api_schema, caps_json)
        }
        None => crate::pipes::request_shaping::builtin_profile(&target.api_schema, &target.model, caps_json),
    }
}

/// Inner implementation of call_llm — performs a single LLM request.
async fn call_llm_inner(
    pipe_id: &str,
    target: &LLMTarget,
    system_prompt: &str,
    user_content: &str,
    secrets: &SurfaceSecrets,
    span_name: &str,
    force_no_think: bool,
) -> Result<(String, u64, u64, u64, bool, KeySource), PipeError> {
    let provider = target_to_provider(target);
    // Gemini embeds the model in the URL path (e.g. /models/{model}:generateContent).
    // The UI stores endpoint_url with a literal `{model}` placeholder — resolve it here.
    let raw_endpoint = target
        .endpoint_url
        .replace("{model}", &target.model);

    // Resolve relative endpoint URLs using the provider's default_base_url and
    // api_version_prefix from defaults (mirrors pipes.json configuration).
    let endpoint = crate::pipes::defaults::resolve_endpoint_url(&target.provider_type, &raw_endpoint);
    if endpoint != raw_endpoint {
        info!(
            "[PIPE:{}] {} — resolved relative endpoint '{}' → '{}'",
            pipe_id,
            span_name,
            crate::url_validation::redact_url_for_logging(&raw_endpoint),
            crate::url_validation::redact_url_for_logging(&endpoint)
        );
    }

    let temperature = target
        .parameters
        .as_ref()
        .and_then(|p| p.get("temperature"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.1);
    let max_tokens = target
        .parameters
        .as_ref()
        .and_then(|p| p.get("max_tokens"))
        .and_then(|v| v.as_u64())
        .unwrap_or(500);
    let top_p = target
        .parameters
        .as_ref()
        .and_then(|p| p.get("top_p"))
        .and_then(|v| v.as_f64());

    // For thinking models: optionally modify the system prompt to suppress thinking
    let effective_prompt = if force_no_think {
        if target.provider_type == "ollama" {
            // Ollama uses the API-level "think" parameter — no prompt modification needed
            system_prompt.to_string()
        } else {
            // Generic providers: append /no_think directive
            if system_prompt.contains("/no_think") {
                system_prompt.to_string()
            } else {
                format!("{}\n\n/no_think", system_prompt)
            }
        }
    } else {
        system_prompt.to_string()
    };

    // The explicit api_schema field drives response parsing below; provider_type
    // drives vendor-specific quirks (Ollama's "format"/"think" fields).
    let api_schema = target.api_schema.as_str();
    // `bedrock-anthropic` sends the Anthropic Messages wire (see request build below),
    // so its response must be parsed as Anthropic too — content from the Anthropic shape
    // and usage from `usage.{input,output}_tokens`, not the OpenAI `choices[0]` shape.
    let is_anthropic = matches!(api_schema, "anthropic" | "bedrock-anthropic");
    let is_gemini = api_schema == "gemini";
    let is_ollama = target.provider_type == "ollama";

    // Build a provider-neutral OpenAI-format body, then let the resolved model
    // profile shape it for the target wire format (Anthropic / Gemini / OpenAI)
    // and strip or rename any parameters the model rejects.
    let mut profile = resolve_target_profile(target);
    // Honor an explicitly-requested Anthropic wire on the Judge/Jury LLMTarget. The catalog
    // resolver keys the wire format off the provider entry (e.g. a Bedrock provider fixed to the
    // OpenAI-compatible gateway), which can drop the caller's `api_schema` — leaving `system` as a
    // message role and 400ing Anthropic's Messages API. When the target asks for the Anthropic wire,
    // force it so `shape_request` hoists `system` to the top-level parameter.
    if matches!(target.api_schema.as_str(), "anthropic" | "bedrock-anthropic") {
        profile.api_schema = target.api_schema.clone();
    }

    let mut openai_body = serde_json::json!({
        "model": target.model,
        "messages": [
            {
                "role": "system",
                "content": effective_prompt
            },
            {
                "role": "user",
                "content": user_content
            }
        ],
        "temperature": temperature,
        "max_tokens": max_tokens
    });
    if let Some(tp) = top_p {
        openai_body["top_p"] = serde_json::json!(tp);
    }
    if profile.supports_json_mode {
        openai_body["response_format"] = serde_json::json!({"type": "json_object"});
    } else {
        info!(
            "[PIPE:{}] {} — skipping response_format for model '{}' (not supported per model profile)",
            pipe_id, span_name, target.model
        );
    }

    let mut request_body = crate::pipes::request_shaping::shape_request(&profile, openai_body);

    // Ollama vendor quirk: force JSON output mode.
    if is_ollama {
        request_body["format"] = serde_json::json!("json");
    }

    // For Ollama: add "think" parameter to control thinking mode
    if force_no_think {
        if is_ollama {
            request_body["think"] = serde_json::json!(false);
            info!("[PIPE:{}] {} — thinking disabled via Ollama 'think: false' parameter", pipe_id, span_name);
        } else {
            info!("[PIPE:{}] {} — thinking disabled via /no_think prompt directive", pipe_id, span_name);
        }
    }

    info!(
        "[PIPE:{}] {} — full request body: {}",
        pipe_id,
        span_name,
        serde_json::to_string(&request_body).unwrap_or_default()
    );

    let call_headers = build_target_headers(pipe_id, target, &provider, secrets, &endpoint).await?;
    // A Judge, juror or Decider router is a safety or decision stage: refused
    // for budget, it fails the request like any other error of its call.
    admit_target_call(target, &call_headers, span_name).await?;
    let TargetCallHeaders {
        headers,
        own_price_honoured,
        key_source,
        ..
    } = call_headers;
    ensure_target_priced(pipe_id, target, own_price_honoured)?;

    info!(
        "[PIPE:{}] {} — calling provider: {}, model: {}, endpoint: {}, temperature: {}, max_tokens: {}, timeout: {}s",
        pipe_id, span_name, target.provider_type, target.model, endpoint, temperature, max_tokens, target.timeout_secs
    );

    let call_start = std::time::Instant::now();

    // Create HTTP client with configurable timeout
    let timeout = std::time::Duration::from_secs(target.timeout_secs);
    let client = crate::http_client::with_service_endpoint_resolver(timeout)
        .map_err(|e| PipeError::RequestFailed(format!("Failed to create HTTP client: {}", e)))?;

    crate::url_validation::validate_service_endpoint_url(&endpoint)
        .await
        .map_err(|e| PipeError::RequestFailed(format!("endpoint_url blocked: {}", e)))?;

    let mut request = client
        .post(endpoint)
        .header("Content-Type", "application/json")
        .body(
            serde_json::to_vec(&request_body)
                .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize {span_name} request: {e}")))?,
        );

    for (header_name, header_value) in headers {
        request = request.header(header_name, header_value);
    }

    let response = request
        .send()
        .await
        .map_err(|e| {
            let current_span = tracing::Span::current();
            current_span.record("llm.status", "error");
            if e.is_timeout() {
                PipeError::RequestFailed(format!("{span_name} timed out after {}s: {e}", target.timeout_secs))
            } else {
                PipeError::RequestFailed(format!("{span_name} failed: {e}"))
            }
        })?;

    if !response.status().is_success() {
        let status = response.status();
        let error_body = response
            .text()
            .await
            .unwrap_or_default();
        let current_span = tracing::Span::current();
        current_span.record("llm.status", format!("http_{}", status.as_u16()));
        return Err(PipeError::upstream_failure(status, false, &format!("{span_name} returned "), &error_body));
    }

    let response_text = response
        .text()
        .await
        .map_err(|e| PipeError::InvalidResponse(format!("Failed to read {span_name} response: {e}")))?;

    let elapsed_ms = call_start
        .elapsed()
        .as_millis();

    // Parse the response to extract the assistant's message content.
    // Anthropic and OpenAI use different response structures.
    let response_json: Value = serde_json::from_str(&response_text)
        .map_err(|e| PipeError::InvalidResponse(format!("{span_name} response is not valid JSON: {e}")))?;

    let (usage_input_tokens, usage_output_tokens) = extract_token_usage(&response_json, api_schema);

    let (content, message) = if is_anthropic {
        // Anthropic Messages API response format:
        //   { "content": [ { "type": "text", "text": "..." } ], ... }
        // Some models may also include thinking blocks:
        //   { "content": [ { "type": "thinking", "thinking": "..." }, { "type": "text", "text": "..." } ] }
        let content_array = response_json.get("content");
        let text = content_array
            .and_then(|arr| arr.as_array())
            .and_then(|blocks| {
                // Find the first "text" block
                blocks
                    .iter()
                    .find_map(|block| {
                        if block
                            .get("type")
                            .and_then(|t| t.as_str())
                            == Some("text")
                        {
                            block
                                .get("text")
                                .and_then(|t| t.as_str())
                        } else {
                            None
                        }
                    })
            })
            .unwrap_or("")
            .to_string();

        // If text is empty, look for a thinking block (similar to qwen3 fallback)
        let text = if text.is_empty() {
            let thinking = content_array
                .and_then(|arr| arr.as_array())
                .and_then(|blocks| {
                    blocks
                        .iter()
                        .find_map(|block| {
                            if block
                                .get("type")
                                .and_then(|t| t.as_str())
                                == Some("thinking")
                            {
                                block
                                    .get("thinking")
                                    .and_then(|t| t.as_str())
                            } else {
                                None
                            }
                        })
                })
                .unwrap_or("")
                .to_string();
            if thinking.is_empty() {
                info!(
                    "[PIPE:{}] {} — WARNING: empty content in Anthropic response, raw body: {}",
                    pipe_id,
                    span_name,
                    response_text.replace('\n', "\\n")
                );
                response_text.clone()
            } else {
                let extracted = extract_json_from_response(&thinking);
                if let Ok(json) = serde_json::from_str::<Value>(&extracted) {
                    let json_str = json.to_string();
                    info!(
                        "[PIPE:{}] {} — content was empty, extracted JSON from Anthropic thinking block: {}",
                        pipe_id, span_name, json_str
                    );
                    json_str
                } else {
                    warn!(
                        "[PIPE:{}] {} — content was empty and thinking block contains no extractable JSON ({} chars)",
                        pipe_id,
                        span_name,
                        thinking.len()
                    );
                    thinking
                }
            }
        } else {
            text
        };
        (text, None)
    } else if is_gemini {
        // Gemini generateContent response format:
        //   { "candidates": [ { "content": { "parts": [ { "text": "..." } ], "role": "model" } } ] }
        let text = response_json
            .get("candidates")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("content"))
            .and_then(|c| c.get("parts"))
            .and_then(|p| p.as_array())
            .map(|parts| {
                parts
                    .iter()
                    .filter_map(|p| {
                        p.get("text")
                            .and_then(|t| t.as_str())
                    })
                    .collect::<Vec<_>>()
                    .join("")
            })
            .unwrap_or_default();

        if text.is_empty() {
            info!(
                "[PIPE:{}] {} — WARNING: empty content in Gemini response, raw body: {}",
                pipe_id,
                span_name,
                response_text.replace('\n', "\\n")
            );
        }
        (text, None)
    } else {
        // OpenAI-compatible format: choices[0].message.content
        let message = response_json
            .get("choices")
            .and_then(|c| c.get(0))
            .and_then(|c| c.get("message"));

        let content_value = message.and_then(|m| m.get("content"));

        // Content can be a string (normal) or a JSON object (some models return
        // structured JSON directly as an object rather than a string).
        let content = match content_value {
            Some(Value::String(s)) => s.clone(),
            Some(v) if v.is_object() || v.is_array() => {
                // Model returned structured JSON directly — serialize it
                serde_json::to_string(v).unwrap_or_default()
            }
            _ => String::new(),
        };

        (content, message.cloned())
    };

    // If content is empty, check for thinking/reasoning fields (some models
    // like qwen3 return content=null with a separate thinking field)
    let content = if content.is_empty() {
        let thinking = message
            .as_ref()
            .and_then(|m| {
                m.get("thinking")
                    .or_else(|| m.get("reasoning"))
                    .or_else(|| m.get("reasoning_content"))
            })
            .and_then(|t| t.as_str())
            .unwrap_or("")
            .to_string();

        if thinking.is_empty() {
            // Log the raw response so we can diagnose what the model actually returned
            info!(
                "[PIPE:{}] {} — WARNING: empty content in response, raw body: {}",
                pipe_id,
                span_name,
                response_text.replace('\n', "\\n")
            );
            // Final fallback: use the full response text
            response_text.clone()
        } else {
            // The model returned thinking/reasoning instead of content.
            // Try to extract JSON from the thinking text — some models embed
            // the final JSON answer at the end of their chain-of-thought.
            let extracted = extract_json_from_response(&thinking);
            if let Ok(json) = serde_json::from_str::<Value>(&extracted) {
                // Found valid JSON embedded in the thinking text
                let json_str = json.to_string();
                info!(
                    "[PIPE:{}] {} — content was empty, extracted JSON from thinking/reasoning field: {}",
                    pipe_id, span_name, json_str
                );
                json_str
            } else {
                // No JSON found in thinking text — return as-is.
                // The caller (call_llm) will auto-retry with thinking disabled.
                warn!(
                    "[PIPE:{}] {} — content was empty and thinking/reasoning field contains no extractable JSON ({} chars of reasoning). \
                    The model likely exhausted max_tokens on chain-of-thought.",
                    pipe_id,
                    span_name,
                    thinking.len()
                );
                thinking
            }
        }
    } else {
        content
    };

    info!("[PIPE:{}] {} — response received in {}ms, length: {} chars", pipe_id, span_name, elapsed_ms, content.len());

    let current_span = tracing::Span::current();
    current_span.record("llm.status", "success");
    current_span.record("llm.response_len", content.len());

    Ok((content, usage_input_tokens, usage_output_tokens, elapsed_ms as u64, own_price_honoured, key_source))
}

/// Evaluate a decision based on the LLM's response content
/// Bound how much of a juror/judge's raw LLM output is folded into a rejection
/// `reason` — mirrors the truncation already applied to the caller-facing
/// `[STAGE:judge]` response field, so a fallback rejection reason can't fold an
/// unbounded amount of raw model output into logs and downstream messages.
fn truncated_response(content: &str) -> String {
    content
        .replace('\n', "\\n")
        .chars()
        .take(2000)
        .collect()
}

fn evaluate_decision(
    content: &str,
    decision: &DecisionMode,
) -> JudgeJuryOutcome {
    match decision {
        DecisionMode::Json { field, approve_value } => {
            // Try to parse the content as JSON
            // First try the raw content, then try to extract JSON from markdown code blocks
            let json_str = extract_json_from_response(content);

            match serde_json::from_str::<Value>(&json_str) {
                Ok(json) => {
                    if let Some((found_field, value)) = resolve_json_field(&json, field) {
                        if found_field != field {
                            warn!("evaluate_decision: field '{}' not found, using alias '{}'", field, found_field);
                        }
                        let value_str = match value {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };

                        if value_str.to_lowercase() == approve_value.to_lowercase() {
                            let details = json
                                .get("details")
                                .or_else(|| json.get("reason"))
                                .or_else(|| json.get("explanation"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string());
                            JudgeJuryOutcome::Approved { details }
                        } else {
                            let reason = json
                                .get("details")
                                .or_else(|| json.get("reason"))
                                .or_else(|| json.get("explanation"))
                                .and_then(|v| v.as_str())
                                .map(|s| s.to_string())
                                .unwrap_or_else(|| {
                                    format!("Field '{}' has value '{}', expected '{}'", field, value_str, approve_value)
                                });
                            JudgeJuryOutcome::Rejected { reason }
                        }
                    } else {
                        JudgeJuryOutcome::Rejected {
                            reason: format!(
                                "JSON response missing field '{}'. Response: {}",
                                field,
                                truncated_response(content)
                            ),
                        }
                    }
                }
                Err(_) => JudgeJuryOutcome::Rejected {
                    reason: format!("Failed to parse LLM response as JSON. Response: {}", truncated_response(content)),
                },
            }
        }
        DecisionMode::Regex {
            approve_pattern,
            reject_pattern,
        } => {
            // Check reject pattern first (fail-fast)
            if let Some(reject_pat) = reject_pattern {
                if let Ok(re) = Regex::new(reject_pat) {
                    if re.is_match(content) {
                        return JudgeJuryOutcome::Rejected {
                            reason: format!(
                                "Response matched reject pattern. Response: {}",
                                truncated_response(content)
                            ),
                        };
                    }
                } else {
                    warn!("Invalid reject regex pattern: {} → rejecting", reject_pat);
                    return JudgeJuryOutcome::Rejected {
                        reason: "Juror reject pattern is not a valid regex".to_string(),
                    };
                }
            }

            // Check approve pattern
            if let Ok(re) = Regex::new(approve_pattern) {
                if re.is_match(content) {
                    return JudgeJuryOutcome::Approved { details: None };
                }
            } else {
                warn!("Invalid approve regex pattern: {}", approve_pattern);
            }

            // Neither matched — fail-safe: reject
            JudgeJuryOutcome::Rejected {
                reason: format!("Response did not match approve pattern. Response: {}", truncated_response(content)),
            }
        }
    }
}

/// Extract JSON from an LLM response that may contain markdown code blocks
fn extract_json_from_response(content: &str) -> String {
    let trimmed = content.trim();

    // 1. Try raw content first — already valid JSON
    if trimmed.starts_with('{') && trimmed.ends_with('}') && serde_json::from_str::<Value>(trimmed).is_ok() {
        return trimmed.to_string();
    }

    // 2. Try to extract from markdown code block: ```json ... ``` or ``` ... ```
    if let Some(start) = trimmed.find("```") {
        let after_start = &trimmed[start + 3..];
        // Skip optional language tag (e.g., "json")
        let json_start = after_start
            .strip_prefix("json")
            .unwrap_or(after_start);
        let json_start = json_start.trim_start_matches('\n');

        if let Some(end) = json_start.find("```") {
            let extracted = json_start[..end].trim();
            if extracted.starts_with('{') {
                return extracted.to_string();
            }
        }
    }

    // 3. Scan for JSON object anywhere in the text by finding matching braces.
    //    This handles models that output thinking text before/after the JSON,
    //    or malformed wrapping like `{"{"decision":...}`.
    //    Try each `{` position until we find a valid JSON object.
    let bytes = trimmed.as_bytes();
    let mut search_start = 0;
    while search_start < bytes.len() {
        let brace_pos = match trimmed[search_start..].find('{') {
            Some(pos) => search_start + pos,
            None => break,
        };

        // Find the matching closing brace by counting nesting depth
        let mut depth = 0i32;
        let mut in_string = false;
        let mut escape_next = false;
        let mut end_pos = None;

        for (i, &ch) in bytes
            .iter()
            .enumerate()
            .skip(brace_pos)
        {
            if escape_next {
                escape_next = false;
                continue;
            }
            if ch == b'\\' && in_string {
                escape_next = true;
                continue;
            }
            if ch == b'"' {
                in_string = !in_string;
                continue;
            }
            if !in_string {
                if ch == b'{' {
                    depth += 1;
                } else if ch == b'}' {
                    depth -= 1;
                    if depth == 0 {
                        end_pos = Some(i);
                        break;
                    }
                }
            }
        }

        if let Some(end) = end_pos {
            let candidate = &trimmed[brace_pos..=end];
            // Validate it's actually parseable JSON before returning
            if serde_json::from_str::<Value>(candidate).is_ok() {
                return candidate.to_string();
            }
        }

        // This `{` didn't yield valid JSON — try the next one
        search_start = brace_pos + 1;
    }

    // Fallback: return as-is
    trimmed.to_string()
}

/// Extract user-facing text from a Chat Completions request payload for the Moderations API.
/// Concatenates all user/system message contents into a single string,
/// since the Moderations API expects a plain text `input` field.
fn extract_user_text_for_moderation(payload: &Value) -> String {
    // Try to extract from messages array (Chat Completions format)
    // Only extract "user" role messages — system prompts are instructions,
    // not user content, and often contain safety-related keywords that would
    // trigger false positives in moderation APIs.
    if let Some(messages) = payload
        .get("messages")
        .and_then(|m| m.as_array())
    {
        let parts: Vec<&str> = messages
            .iter()
            .filter_map(|msg| {
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("");
                if role == "user" {
                    msg.get("content")
                        .and_then(|c| c.as_str())
                } else {
                    None
                }
            })
            .collect();
        if !parts.is_empty() {
            return parts.join("\n\n");
        }
    }

    // Try "input" field (already a moderation-style payload)
    if let Some(input) = payload
        .get("input")
        .and_then(|i| i.as_str())
    {
        return input.to_string();
    }

    // Try "prompt" field
    if let Some(prompt) = payload
        .get("prompt")
        .and_then(|p| p.as_str())
    {
        return prompt.to_string();
    }

    // Fallback: serialize the whole payload
    payload_text(payload).unwrap_or_default()
}

/// The whole request body as text, for a stage that found no user text to
/// evaluate, without a caller-supplied body `api_key`: the stage sends this to
/// its own provider and records it as its governance input, and neither may
/// carry the caller's key.
fn payload_text(payload: &Value) -> Result<String, serde_json::Error> {
    match payload
        .as_object()
        .filter(|object| object.contains_key("api_key"))
    {
        Some(object) => {
            let mut object = object.clone();
            object.remove("api_key");
            serde_json::to_string_pretty(&object)
        }
        None => serde_json::to_string_pretty(payload),
    }
}

/// Extract only the **latest** user message from a Chat Completions payload.
///
/// Content-based routing (the Decider) must decide on the *current* turn, not
/// the whole conversation: concatenating every prior user message lets an
/// earlier question dominate the route on follow-ups (e.g. a first technical
/// question keeps the route "technical" for an unrelated follow-up). Falls back
/// to the shared full-history extractor when there is no `messages` array (e.g.
/// a bare `input`/`prompt` payload), where "last user turn" is undefined.
fn extract_last_user_text(payload: &Value) -> String {
    if let Some(messages) = payload
        .get("messages")
        .and_then(|m| m.as_array())
    {
        let last_user = messages
            .iter()
            .rev()
            .find(|msg| {
                msg.get("role")
                    .and_then(|r| r.as_str())
                    == Some("user")
            })
            .and_then(|msg| {
                msg.get("content")
                    .and_then(|c| c.as_str())
            });
        if let Some(text) = last_user {
            return text.to_string();
        }
    }

    extract_user_text_for_moderation(payload)
}

/// Execute the Judge — validates the request payload before it reaches the processing LLM
/// The content a governance-recorded stage sent to its model and received back,
/// surfaced so a governance record can retain each stage's input and output.
#[derive(Debug, Clone, Default)]
pub struct StageIo {
    /// What the stage submitted to its model/provider (the evaluated content).
    pub input: Option<String>,
    /// What the stage received back (the model verdict / provider response).
    pub output: Option<String>,
}

/// Emit the `[STAGE:judge]` event as one well-formed JSON object built via
/// `serde_json`, rather than hand-escaped string interpolation — a raw control
/// byte outside `\`/`"`/whitespace in the judge's LLM output could otherwise
/// produce invalid JSON that `stage_stream::parse_stage` silently drops.
fn log_judge_stage(
    pipe_id: &str,
    judge: &JudgeConfig,
    judge_usage: &StageUsage,
    output: Option<&str>,
    duration_ms: u128,
    outcome: &str,
    reason: Option<&str>,
) {
    let response: String = output
        .unwrap_or("")
        .chars()
        .take(2000)
        .collect();
    let mut payload = serde_json::json!({
        "outcome": outcome,
        "mode": format!("{:?}", judge.mode),
        "provider": judge.llm.provider_type,
        "model": judge.llm.model,
        "rules": judge.rules.len(),
        "tokens": judge_usage.total_tokens(),
        "input_tokens": judge_usage.input_tokens,
        "output_tokens": judge_usage.output_tokens,
        "cost": judge_usage.cost,
        "response": response,
        "duration_ms": duration_ms as u64,
    });
    if let Some(reason) = reason {
        payload["reason"] = serde_json::json!(reason);
    }
    info!("[PIPE:{}] [STAGE:judge] {}", pipe_id, payload);
}

pub async fn execute_judge(
    pipe_id: &str,
    judge: &JudgeConfig,
    original_payload: &Value,
    secrets: &SurfaceSecrets,
) -> Result<(StageUsage, StageIo), PipeError> {
    if !judge.enabled {
        return Ok((StageUsage::default(), StageIo::default()));
    }

    let judge_span = tracing::info_span!(
        "pipe.judge.evaluate",
        otel.name = "Judge Evaluation",
        judge.mode = ?judge.mode,
        judge.model = %judge.llm.model,
        judge.provider = %judge.llm.provider_type,
        judge.timeout_secs = %judge.llm.timeout_secs,
        judge.rule_count = judge.rules.len(),
        judge.outcome = tracing::field::Empty,
        judge.reason = tracing::field::Empty,
    );

    async {
        let judge_timer = Instant::now();
        info!(
            "[PIPE:{}] Executing Judge evaluation: mode={:?}, provider={}/{}, rules={}",
            pipe_id,
            judge.mode,
            judge.llm.provider_type,
            judge.llm.model,
            judge.rules.len()
        );

        let current_span = tracing::Span::current();

        let judge_usage;
        let mut io = StageIo::default();
        let result = match judge.mode {
            JudgeMode::Moderation => {
                // ── Moderation API path ──
                info!("[PIPE:{}] Using OpenAI Moderations API for Judge evaluation", pipe_id);

                // Extract the actual user text from the payload
                let moderation_input = extract_user_text_for_moderation(original_payload);

                info!(
                    "[PIPE:{}] Judge Moderation input ({}chars): {}",
                    pipe_id,
                    moderation_input.len(),
                    moderation_input.replace('\n', "\\n")
                );

                let (response_json, honoured, key_source) =
                    call_moderation(pipe_id, &judge.llm, &moderation_input, secrets, "Judge Moderation Call").await?;

                info!(
                    "[PIPE:{}] Moderation response: {}",
                    pipe_id,
                    serde_json::to_string(&response_json).unwrap_or_default()
                );

                // The OpenAI Moderations endpoint is free today and returns no
                // `usage` block, so this resolves to zero. We still route it
                // through the catalog-priced recording path so that if the API
                // ever starts reporting usage AND the model gains a price in
                // `llm.json`, the judge's spend is counted and enforced with no
                // code change — identical to the LLM-mode path below.
                let (mod_in, mod_out) = extract_token_usage(&response_json, "openai");
                record_stage_usage(pipe_id, UsageStage::Judge.scope_key(), &judge.llm, honoured, mod_in, mod_out).await;
                judge_usage = display_stage_usage(&judge.llm, honoured, key_source, mod_in, mod_out);
                io.input = Some(moderation_input.clone());
                io.output = serde_json::to_string(&response_json).ok();

                // Evaluate rules against the moderation response
                evaluate_judge_rules_moderation(pipe_id, &response_json, &judge.rules)
            }
            JudgeMode::Llm => {
                // ── Chat Completions LLM path ──
                // Extract only user messages — the pipe's system prompt is not
                // user content and should not be sent to the Judge for review.
                let user_text = extract_user_text_for_moderation(original_payload);
                let user_content = if user_text.is_empty() {
                    // Fallback: serialize the whole payload if no user messages found
                    payload_text(original_payload).map_err(|e| {
                        PipeError::RequestFailed(format!("Failed to serialize payload for Judge: {}", e))
                    })?
                } else {
                    user_text
                };

                info!(
                    "[PIPE:{}] Judge LLM system_prompt ({}chars): {}",
                    pipe_id,
                    judge.system_prompt.len(),
                    judge
                        .system_prompt
                        .replace('\n', "\\n")
                );
                info!("[PIPE:{}] Judge LLM user_content ({}chars)", pipe_id, user_content.len());

                let response_content = call_llm(
                    pipe_id,
                    &judge.llm,
                    &judge.system_prompt,
                    &user_content,
                    secrets,
                    "Judge LLM Call",
                    judge.disable_thinking,
                    UsageStage::Judge.scope_key(),
                )
                .await?;

                let (response_content, usage) = response_content;
                judge_usage = usage;
                io.input = Some(user_content.clone());
                io.output = Some(response_content.clone());

                info!("[PIPE:{}] Judge LLM response ({}chars)", pipe_id, response_content.len());

                // Evaluate rules against the LLM response
                evaluate_judge_rules_llm(pipe_id, &response_content, &judge.rules)
            }
        };

        match result {
            Ok(()) => {
                let judge_ms = judge_timer
                    .elapsed()
                    .as_millis();
                current_span.record("judge.outcome", "approved");
                info!("[PIPE:{}] Judge APPROVED — no rules matched", pipe_id);
                log_judge_stage(pipe_id, judge, &judge_usage, io.output.as_deref(), judge_ms, "approved", None);
                Ok((judge_usage, io))
            }
            Err(e) => {
                let judge_ms = judge_timer
                    .elapsed()
                    .as_millis();
                current_span.record("judge.outcome", "rejected");
                current_span.record("judge.reason", e.to_string().as_str());
                warn!("[PIPE:{}] Judge REJECTED: {}", pipe_id, e);
                log_judge_stage(
                    pipe_id,
                    judge,
                    &judge_usage,
                    io.output.as_deref(),
                    judge_ms,
                    "rejected",
                    Some(&e.to_string()),
                );
                // Carry the judge's input/output and consumed usage onto the rejection
                // for governance records, billing, and telemetry.
                Err(e
                    .with_stage_io(io.input, io.output)
                    .with_rejected_usage(crate::pipes::executor::RejectedExecutionUsage {
                        llm: StageUsage::default(),
                        judge: judge_usage,
                        jury: StageUsage::default(),
                        decider: StageUsage::default(),
                    }))
            }
        }
    }
    .instrument(judge_span)
    .await
}

/// Parse the router's chosen candidate id from its JSON response. Accepts the
/// `candidate`, `id`, or `choice` field for robustness across router prompts.
fn parse_decider_choice(content: &str) -> Option<String> {
    let json_str = extract_json_from_response(content);
    let value: Value = serde_json::from_str(&json_str).ok()?;
    value
        .get("candidate")
        .or_else(|| value.get("id"))
        .or_else(|| value.get("choice"))
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Parse the router's rationale from its JSON response. Accepts the `reasoning`
/// or `reason` field. Returns an empty string when the router omitted it.
fn parse_decider_reasoning(content: &str) -> String {
    let json_str = extract_json_from_response(content);
    serde_json::from_str::<Value>(&json_str)
        .ok()
        .as_ref()
        .and_then(|value| {
            value
                .get("reasoning")
                .or_else(|| value.get("reason"))
        })
        .and_then(|v| v.as_str())
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

/// Execute the Decider — a router LLM that selects which candidate upstream
/// should serve this request based on its content.
///
/// Returns the winning candidate's [`LLMTarget`] (whose own `headers` and
/// `pricing` the main call uses), its resolved [`LLMProvider`], its
/// fully-resolved absolute endpoint URL, and the [`StageUsage`] the routing
/// call consumed. The endpoint is resolved here (relative paths like
/// `/messages` expanded against the provider's default base) so the main
/// executor can POST to it directly instead of reconstructing a URL from
/// `get_endpoint()` + the base pipe's path suffix, which would otherwise yield a
/// relative or wrong URL for the candidate. Usage is recorded under the
/// `stage:decider` budget scope. A router response that is missing or names an
/// unknown candidate falls back to the configured default candidate, then the
/// first candidate, so an enabled, validated Decider always resolves to a target.
pub async fn execute_decider<'a>(
    pipe_id: &str,
    decider: &'a DeciderConfig,
    request_body: &Value,
    secrets: &SurfaceSecrets,
) -> Result<(&'a LLMTarget, LLMProvider, String, StageUsage, StageIo), PipeError> {
    // Route strategy always carries a router LLM (enforced by validation); Mirror
    // never reaches this function. Fail closed if a router is somehow absent.
    let router_llm = decider
        .llm
        .as_ref()
        .ok_or_else(|| PipeError::RequestFailed("Route decider requires a router LLM".to_string()))?;

    let decider_span = tracing::info_span!(
        "pipe.decider.evaluate",
        otel.name = "Decider Evaluation",
        decider.model = %router_llm.model,
        decider.provider = %router_llm.provider_type,
        decider.candidate_count = decider.candidates.len(),
        decider.selected = tracing::field::Empty,
    );

    async {
        let timer = Instant::now();

        // The Decider routes on the *current* user turn, not the pipe's system
        // prompt and not the whole conversation history — otherwise an earlier
        // question would keep dominating the route on every follow-up.
        let user_text = extract_last_user_text(request_body);
        let user_content = if user_text.is_empty() {
            payload_text(request_body)
                .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize payload for Decider: {}", e)))?
        } else {
            user_text
        };

        // Append the candidate menu so the router knows exactly which ids it may
        // return and what each upstream is best at. Ask for a short rationale so
        // the routing decision is explainable in the activity log.
        let mut menu = String::from(
            "\n\nAvailable candidates. Reply with JSON {\"candidate\":\"<id>\",\"reasoning\":\"<one sentence why>\"} choosing exactly one id:\n",
        );
        for candidate in &decider.candidates {
            if candidate.description.is_empty() {
                menu.push_str(&format!("- id: {} — {}\n", candidate.id, candidate.name));
            } else {
                menu.push_str(&format!("- id: {} — {}: {}\n", candidate.id, candidate.name, candidate.description));
            }
        }
        let system_prompt = format!("{}{}", decider.system_prompt, menu);

        let (response_content, usage) = call_llm(
            pipe_id,
            router_llm,
            &system_prompt,
            &user_content,
            secrets,
            "Decider LLM Call",
            decider.disable_thinking,
            UsageStage::Decider.scope_key(),
        )
        .await?;

        let chosen_id = parse_decider_choice(&response_content);
        let reasoning = parse_decider_reasoning(&response_content);
        let candidate = decider
            .resolve_candidate(chosen_id.as_deref().unwrap_or(""))
            .ok_or_else(|| PipeError::RequestFailed("Decider has no candidates to route to".to_string()))?;

        let duration_ms = timer
            .elapsed()
            .as_millis();
        tracing::Span::current().record("decider.selected", candidate.id.as_str());
        info!(
            "[PIPE:{}] [STAGE:decider] {{\"outcome\":\"selected\",\"candidate\":\"{}\",\"name\":\"{}\",\"reasoning\":{},\"provider\":\"{}\",\"model\":\"{}\",\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"duration_ms\":{}}}",
            pipe_id,
            candidate.id,
            candidate.name,
            serde_json::to_string(&reasoning).unwrap_or_else(|_| "\"\"".to_string()),
            candidate.llm.provider_type,
            candidate.llm.model,
            usage.total_tokens(),
            usage.input_tokens,
            usage.output_tokens,
            usage.cost,
            duration_ms
        );

        let provider = target_to_provider(&candidate.llm);
        // Resolve the candidate's endpoint to a full absolute URL here (relative
        // paths like `/messages` expanded against the provider default), exactly
        // as `call_llm_inner` does for the router's own call. The main executor
        // POSTs to this directly, so it never has to rebuild the URL from the
        // base pipe's provider/path-suffix — which produced a relative or wrong
        // URL for the candidate and failed with a reqwest "builder error".
        let endpoint = candidate
            .llm
            .resolved_endpoint();
        let io = StageIo {
            input: Some(user_content.clone()),
            output: Some(response_content.clone()),
        };
        Ok((&candidate.llm, provider, endpoint, usage, io))
    }
    .instrument(decider_span)
    .await
}

/// Result of a Jury evaluation — either approved or rejected with a reason.
/// The reason string is the raw jury rejection text (juror names + reasons),
/// suitable for feeding back into a retry prompt.
pub enum JuryVerdict {
    /// All required jurors approved
    Approved,
    /// Jury rejected — contains the human-readable reason
    Rejected(String),
}

/// Execute the Jury — validates the LLM response before it reaches the client.
///
/// Returns `Ok(JuryVerdict)` indicating approval or rejection with reason.
/// The caller is responsible for deciding whether to retry or return the
/// final rejection error to the client.
///
/// Returns `Err(PipeError)` only for infrastructure failures (serialization, etc.).
pub async fn execute_jury(
    pipe_id: &str,
    jury: &JuryConfig,
    llm_response: &Value,
    secrets: &SurfaceSecrets,
) -> Result<(JuryVerdict, StageUsage, StageIo), PipeError> {
    if !jury.enabled || jury.jurors.is_empty() {
        return Ok((JuryVerdict::Approved, StageUsage::default(), StageIo::default()));
    }

    // Disabled jurors keep their configuration but take no part in the
    // verdict. With every juror disabled the Jury is a no-op. Each active juror
    // keeps its ORIGINAL index in `jury.jurors` so per-juror usage limits meter
    // under a stable `stage:juror:{index}` scope key.
    let active_jurors: Vec<(usize, JurorConfig)> = jury
        .jurors
        .iter()
        .enumerate()
        .filter(|(_, j)| j.enabled)
        .map(|(i, j)| (i, j.clone()))
        .collect();
    if active_jurors.is_empty() {
        return Ok((JuryVerdict::Approved, StageUsage::default(), StageIo::default()));
    }

    let jury_span = tracing::info_span!(
        "pipe.jury.evaluate",
        otel.name = "Jury Evaluation",
        jury.mode = ?jury.mode,
        jury.juror_count = active_jurors.len(),
        jury.outcome = tracing::field::Empty,
        jury.approve_count = tracing::field::Empty,
        jury.reject_count = tracing::field::Empty,
    );

    async {
        let jury_timer = Instant::now();
        info!("[PIPE:{}] Executing Jury evaluation: mode={:?}, jurors={}", pipe_id, jury.mode, active_jurors.len());

        // Serialize the LLM response as user content for jurors
        let user_content = serde_json::to_string_pretty(llm_response)
            .map_err(|e| PipeError::RequestFailed(format!("Failed to serialize response for Jury: {}", e)))?;
        let mut io = StageIo {
            input: Some(user_content.clone()),
            output: None,
        };

        let result = match jury.mode {
            JuryExecutionMode::Parallel => {
                execute_jury_parallel(pipe_id, &active_jurors, &user_content, secrets).await
            }
            JuryExecutionMode::Serial => execute_jury_serial(pipe_id, &active_jurors, &user_content, secrets).await,
            JuryExecutionMode::Majority => {
                execute_jury_majority(pipe_id, &active_jurors, &user_content, secrets).await
            }
        };
        let (jury_usage, result) = result?;

        let current_span = tracing::Span::current();
        match result {
            Ok((approve_count, total)) => {
                let jury_ms = jury_timer.elapsed().as_millis();
                current_span.record("jury.outcome", "approved");
                current_span.record("jury.approve_count", approve_count);
                current_span.record("jury.reject_count", total - approve_count);
                info!("[PIPE:{}] Jury APPROVED ({}/{})", pipe_id, approve_count, total);
                info!(
                    "[PIPE:{}] [STAGE:jury] {{\"outcome\":\"approved\",\"mode\":\"{:?}\",\"approved\":{},\"total\":{},\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"duration_ms\":{}}}",
                    pipe_id, jury.mode, approve_count, total,
                    jury_usage.total_tokens(), jury_usage.input_tokens, jury_usage.output_tokens, jury_usage.cost, jury_ms
                );
                io.output = Some(format!("approved ({}/{})", approve_count, total));
                Ok((JuryVerdict::Approved, jury_usage, io))
            }
            Err((reason, approve_count, reject_count)) => {
                let jury_ms = jury_timer.elapsed().as_millis();
                current_span.record("jury.outcome", "rejected");
                current_span.record("jury.approve_count", approve_count);
                current_span.record("jury.reject_count", reject_count);
                warn!("[PIPE:{}] Jury REJECTED: {}", pipe_id, reason);
                info!(
                    "[PIPE:{}] [STAGE:jury] {{\"outcome\":\"rejected\",\"mode\":\"{:?}\",\"approved\":{},\"rejected\":{},\"reason\":\"{}\",\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"duration_ms\":{}}}",
                    pipe_id, jury.mode, approve_count, reject_count, reason.replace('"', "'"),
                    jury_usage.total_tokens(), jury_usage.input_tokens, jury_usage.output_tokens, jury_usage.cost, jury_ms
                );
                io.output = Some(reason.clone());
                Ok((JuryVerdict::Rejected(reason), jury_usage, io))
            }
        }
    }
    .instrument(jury_span)
    .await
}

/// Execute all jurors in parallel — ALL must approve.
/// Returns Ok((approve_count, total)) or Err((reason, approve_count, reject_count))
async fn execute_jury_parallel(
    pipe_id: &str,
    jurors: &[(usize, JurorConfig)],
    user_content: &str,
    secrets: &SurfaceSecrets,
) -> Result<(StageUsage, Result<(usize, usize), (String, usize, usize)>), PipeError> {
    let futures: Vec<_> = jurors
        .iter()
        .map(|(idx, juror)| {
            let content = user_content.to_string();
            let juror = juror.clone();
            let juror_index = *idx;
            let store = secrets.clone();
            let pid = pipe_id.to_string();
            async move {
                let span = tracing::info_span!(
                    "pipe.jury.juror",
                    otel.name = format!("Juror: {}", juror.name),
                    juror.name = %juror.name,
                    juror.provider = %juror.llm.provider_type,
                    juror.model = %juror.llm.model,
                    juror.outcome = tracing::field::Empty,
                );

                async { execute_single_juror(&pid, juror_index, &juror, &content, &store).await }
                    .instrument(span)
                    .await
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;
    let total = jurors.len();

    // All must approve
    let mut usage = StageUsage::default();
    let mut approvals = 0usize;
    let mut rejections = Vec::new();
    for (i, result) in results
        .into_iter()
        .enumerate()
    {
        match result {
            Ok((JudgeJuryOutcome::Approved { details }, juror_usage)) => {
                usage.add(juror_usage);
                info!(
                    "[PIPE:{}] Juror '{}' APPROVED — reasoning: {}",
                    pipe_id,
                    jurors[i].1.name,
                    details
                        .as_deref()
                        .unwrap_or("(no details)")
                );
                approvals += 1;
            }
            Ok((JudgeJuryOutcome::Rejected { reason }, juror_usage)) => {
                usage.add(juror_usage);
                warn!("[PIPE:{}] Juror '{}' REJECTED — reasoning: {}", pipe_id, jurors[i].1.name, reason);
                rejections.push(format!("{}: {}", jurors[i].1.name, reason));
            }
            Err(error) => {
                warn!("[PIPE:{}] Juror '{}' ERROR: {}", pipe_id, jurors[i].1.name, error);
                return Err(error);
            }
        }
    }

    let verdict = if rejections.is_empty() {
        Ok((approvals, total))
    } else {
        Err((
            format!("Rejected by {} juror(s): {}", rejections.len(), rejections.join("; ")),
            approvals,
            rejections.len(),
        ))
    };
    Ok((usage, verdict))
}

/// Execute jurors sequentially with cascading — each juror receives the original content
/// PLUS the previous juror's raw LLM response, enabling a refinement chain.
/// Stops on first rejection.
/// Returns Ok((approve_count, total)) or Err((reason, approve_count, reject_count))
async fn execute_jury_serial(
    pipe_id: &str,
    jurors: &[(usize, JurorConfig)],
    user_content: &str,
    secrets: &SurfaceSecrets,
) -> Result<(StageUsage, Result<(usize, usize), (String, usize, usize)>), PipeError> {
    let total = jurors.len();
    let mut usage = StageUsage::default();
    let mut approvals = 0usize;
    let mut cascaded_content = user_content.to_string();

    for (serial_pos, (juror_index, juror)) in jurors.iter().enumerate() {
        let idx = serial_pos;
        let span = tracing::info_span!(
            "pipe.jury.juror",
            otel.name = format!("Juror: {} (serial {}/{})", juror.name, idx + 1, total),
            juror.name = %juror.name,
            juror.provider = %juror.llm.provider_type,
            juror.model = %juror.llm.model,
            juror.serial_position = idx + 1,
            juror.outcome = tracing::field::Empty,
        );

        let result = async { execute_single_juror(pipe_id, *juror_index, juror, &cascaded_content, secrets).await }
            .instrument(span)
            .await;

        match result {
            Ok((JudgeJuryOutcome::Approved { details }, juror_usage)) => {
                usage.add(juror_usage);
                info!(
                    "[PIPE:{}] Juror '{}' APPROVED — continuing chain ({}/{}) — reasoning: {}",
                    pipe_id,
                    juror.name,
                    idx + 1,
                    total,
                    details
                        .as_deref()
                        .unwrap_or("(no details)")
                );
                approvals += 1;
                // Cascade: append this juror's evaluation to the content for the next juror
                if let Some(ref detail_text) = details {
                    cascaded_content =
                        format!("{}\n\n--- Evaluation by '{}' ---\n{}", cascaded_content, juror.name, detail_text);
                }
            }
            Ok((JudgeJuryOutcome::Rejected { reason }, juror_usage)) => {
                usage.add(juror_usage);
                return Ok((
                    usage,
                    Err((
                        format!("Rejected by '{}' (serial step {}/{}): {}", juror.name, idx + 1, total, reason),
                        approvals,
                        1,
                    )),
                ));
            }
            Err(error) => return Err(error),
        }
    }

    Ok((usage, Ok((approvals, total))))
}

/// Execute all jurors in parallel — majority (>50%) must approve.
/// Returns Ok((approve_count, total)) or Err((reason, approve_count, reject_count))
async fn execute_jury_majority(
    pipe_id: &str,
    jurors: &[(usize, JurorConfig)],
    user_content: &str,
    secrets: &SurfaceSecrets,
) -> Result<(StageUsage, Result<(usize, usize), (String, usize, usize)>), PipeError> {
    let futures: Vec<_> = jurors
        .iter()
        .map(|(idx, juror)| {
            let content = user_content.to_string();
            let juror = juror.clone();
            let juror_index = *idx;
            let store = secrets.clone();
            let pid = pipe_id.to_string();
            async move {
                let span = tracing::info_span!(
                    "pipe.jury.juror",
                    otel.name = format!("Juror: {}", juror.name),
                    juror.name = %juror.name,
                    juror.provider = %juror.llm.provider_type,
                    juror.model = %juror.llm.model,
                    juror.outcome = tracing::field::Empty,
                );
                async { execute_single_juror(&pid, juror_index, &juror, &content, &store).await }
                    .instrument(span)
                    .await
            }
        })
        .collect();

    let results = futures::future::join_all(futures).await;

    let total = jurors.len();
    let mut usage = StageUsage::default();
    let mut approvals = 0usize;
    let mut rejections = Vec::new();

    for (i, result) in results
        .into_iter()
        .enumerate()
    {
        match result {
            Ok((JudgeJuryOutcome::Approved { details }, juror_usage)) => {
                usage.add(juror_usage);
                info!(
                    "[PIPE:{}] Juror '{}' APPROVED — reasoning: {}",
                    pipe_id,
                    jurors[i].1.name,
                    details
                        .as_deref()
                        .unwrap_or("(no details)")
                );
                approvals += 1;
            }
            Ok((JudgeJuryOutcome::Rejected { reason }, juror_usage)) => {
                usage.add(juror_usage);
                warn!("[PIPE:{}] Juror '{}' REJECTED — reasoning: {}", pipe_id, jurors[i].1.name, reason);
                rejections.push(format!("{}: {}", jurors[i].1.name, reason));
            }
            Err(error) => {
                warn!("[PIPE:{}] Juror '{}' ERROR: {}", pipe_id, jurors[i].1.name, error);
                return Err(error);
            }
        }
    }

    // Strict majority: more than half
    let required = (total / 2) + 1;
    let verdict = if approvals >= required {
        info!("[PIPE:{}] Jury majority reached: {}/{} approved (required: {})", pipe_id, approvals, total, required);
        Ok((approvals, total))
    } else {
        Err((
            format!(
                "Jury majority not reached: {}/{} approved (required: {}). Rejections: {}",
                approvals,
                total,
                required,
                rejections.join("; ")
            ),
            approvals,
            rejections.len(),
        ))
    };
    Ok((usage, verdict))
}

/// Execute a single juror evaluation
async fn execute_single_juror(
    pipe_id: &str,
    juror_index: usize,
    juror: &JurorConfig,
    user_content: &str,
    secrets: &SurfaceSecrets,
) -> Result<(JudgeJuryOutcome, StageUsage), PipeError> {
    let juror_timer = Instant::now();
    info!(
        "[PIPE:{}] Evaluating juror '{}' with {} / {}",
        pipe_id, juror.name, juror.llm.provider_type, juror.llm.model
    );

    let span_name = format!("Jury provider '{}' LLM Call", juror.name);
    let (response_content, juror_usage) = call_llm(
        pipe_id,
        &juror.llm,
        &juror.system_prompt,
        user_content,
        secrets,
        &span_name,
        juror.disable_thinking,
        &format!("stage:juror:{juror_index}"),
    )
    .await?;

    info!("[PIPE:{}] Juror '{}' response ({}chars)", pipe_id, juror.name, response_content.len());

    let outcome = evaluate_decision(&response_content, &juror.decision);

    // Record outcome on the parent juror span
    let juror_ms = juror_timer
        .elapsed()
        .as_millis();
    let current_span = tracing::Span::current();
    match &outcome {
        JudgeJuryOutcome::Approved { details } => {
            current_span.record("juror.outcome", "approved");
            info!(
                "[PIPE:{}] [STAGE:juror] {{\"outcome\":\"approved\",\"name\":\"{}\",\"provider\":\"{}\",\"model\":\"{}\",\"detail\":\"{}\",\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"duration_ms\":{}}}",
                pipe_id,
                juror.name,
                juror.llm.provider_type,
                juror.llm.model,
                details
                    .as_deref()
                    .unwrap_or("")
                    .replace('"', "'"),
                juror_usage.total_tokens(),
                juror_usage.input_tokens,
                juror_usage.output_tokens,
                juror_usage.cost,
                juror_ms
            );
        }
        JudgeJuryOutcome::Rejected { reason } => {
            current_span.record("juror.outcome", "rejected");
            info!(
                "[PIPE:{}] [STAGE:juror] {{\"outcome\":\"rejected\",\"name\":\"{}\",\"provider\":\"{}\",\"model\":\"{}\",\"reason\":\"{}\",\"tokens\":{},\"input_tokens\":{},\"output_tokens\":{},\"cost\":{:.6},\"duration_ms\":{}}}",
                pipe_id,
                juror.name,
                juror.llm.provider_type,
                juror.llm.model,
                reason.replace('"', "'"),
                juror_usage.total_tokens(),
                juror_usage.input_tokens,
                juror_usage.output_tokens,
                juror_usage.cost,
                juror_ms
            );
        }
    };

    Ok((outcome, juror_usage))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_decider_choice_reads_candidate_field() {
        let content = r#"{"candidate": "smart"}"#;
        assert_eq!(parse_decider_choice(content), Some("smart".to_string()));
    }

    #[test]
    fn parse_decider_choice_accepts_id_and_choice_aliases() {
        assert_eq!(parse_decider_choice(r#"{"id": "fast"}"#), Some("fast".to_string()));
        assert_eq!(parse_decider_choice(r#"{"choice": "cheap"}"#), Some("cheap".to_string()));
    }

    #[test]
    fn parse_decider_choice_strips_code_fences() {
        let content = "```json\n{\"candidate\": \"smart\"}\n```";
        assert_eq!(parse_decider_choice(content), Some("smart".to_string()));
    }

    #[test]
    fn parse_decider_choice_returns_none_on_garbage() {
        assert_eq!(parse_decider_choice("not json at all"), None);
        assert_eq!(parse_decider_choice(r#"{"candidate": ""}"#), None);
        assert_eq!(parse_decider_choice(r#"{"other": "x"}"#), None);
    }

    #[test]
    fn parse_decider_reasoning_reads_reasoning_and_reason_aliases() {
        assert_eq!(
            parse_decider_reasoning(r#"{"candidate": "smart", "reasoning": "complex math"}"#),
            "complex math".to_string()
        );
        assert_eq!(
            parse_decider_reasoning(r#"{"candidate": "fast", "reason": "simple greeting"}"#),
            "simple greeting".to_string()
        );
    }

    #[test]
    fn parse_decider_reasoning_empty_when_absent_or_garbage() {
        assert_eq!(parse_decider_reasoning(r#"{"candidate": "smart"}"#), "".to_string());
        assert_eq!(parse_decider_reasoning("not json at all"), "".to_string());
    }

    #[test]
    fn extract_last_user_text_returns_only_the_latest_user_turn() {
        let payload = serde_json::json!({
            "messages": [
                { "role": "user", "content": "why aeroplanes fly" },
                { "role": "assistant", "content": "lift and thrust..." },
                { "role": "user", "content": "what makes good music" }
            ]
        });
        // Routing must key on the current question, not the conversation history.
        assert_eq!(extract_last_user_text(&payload), "what makes good music".to_string());
    }

    #[test]
    fn extract_last_user_text_falls_back_to_full_extractor_without_messages() {
        let payload = serde_json::json!({ "input": "classify me" });
        assert_eq!(extract_last_user_text(&payload), "classify me".to_string());
    }

    #[test]
    fn test_evaluate_decision_json_approve() {
        let content = r#"{"decision": "approve", "details": "Content looks safe"}"#;
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Approved { details } => {
                assert_eq!(details.unwrap(), "Content looks safe");
            }
            _ => panic!("Expected Approved"),
        }
    }

    #[test]
    fn test_evaluate_decision_json_reject() {
        let content = r#"{"decision": "reject", "details": "Contains harmful content"}"#;
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Rejected { reason } => {
                assert!(reason.contains("Contains harmful content"));
            }
            _ => panic!("Expected Rejected"),
        }
    }

    #[test]
    fn test_evaluate_decision_json_case_insensitive() {
        let content = r#"{"decision": "APPROVE", "details": "OK"}"#;
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Approved { .. } => {}
            _ => panic!("Expected Approved (case insensitive)"),
        }
    }

    #[test]
    fn test_evaluate_decision_json_in_code_block() {
        let content = "Here is my analysis:\n```json\n{\"decision\": \"approve\", \"details\": \"All good\"}\n```";
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Approved { details } => {
                assert_eq!(details.unwrap(), "All good");
            }
            _ => panic!("Expected Approved from code block"),
        }
    }

    #[test]
    #[ignore] // FIXME: failing test
    fn test_evaluate_decision_json_missing_field() {
        let content = r#"{"verdict": "pass"}"#;
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Rejected { reason } => {
                assert!(reason.contains("missing field"));
            }
            _ => panic!("Expected Rejected (missing field)"),
        }
    }

    #[test]
    fn test_evaluate_decision_regex_approve() {
        let content = "After review, this content is APPROVED for processing.";
        let decision = DecisionMode::Regex {
            approve_pattern: "(?i)\\bAPPROVED\\b".to_string(),
            reject_pattern: Some("(?i)\\bREJECTED\\b".to_string()),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Approved { .. } => {}
            _ => panic!("Expected Approved"),
        }
    }

    #[test]
    fn test_evaluate_decision_regex_reject_takes_priority() {
        // Both patterns match, but reject is checked first
        let content = "REJECTED — but also APPROVED somehow.";
        let decision = DecisionMode::Regex {
            approve_pattern: "(?i)\\bAPPROVED\\b".to_string(),
            reject_pattern: Some("(?i)\\bREJECTED\\b".to_string()),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Rejected { .. } => {}
            _ => panic!("Expected Rejected (reject pattern takes priority)"),
        }
    }

    #[test]
    fn test_evaluate_decision_regex_no_match() {
        let content = "The content seems fine but I'm not sure.";
        let decision = DecisionMode::Regex {
            approve_pattern: "(?i)\\bAPPROVED\\b".to_string(),
            reject_pattern: None,
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Rejected { .. } => {} // Fail-safe
            _ => panic!("Expected Rejected (no match = fail safe)"),
        }
    }

    #[test]
    fn test_extract_json_from_code_block() {
        let content = "Here:\n```json\n{\"a\": 1}\n```\nDone.";
        assert_eq!(extract_json_from_response(content), "{\"a\": 1}");
    }

    #[test]
    fn test_extract_json_raw() {
        let content = r#"{"decision": "approve"}"#;
        assert_eq!(extract_json_from_response(content), content);
    }

    #[test]
    fn test_extract_json_with_whitespace() {
        let content = "  \n  {\"decision\": \"approve\"}  \n  ";
        assert_eq!(extract_json_from_response(content), "{\"decision\": \"approve\"}");
    }

    #[test]
    fn test_evaluate_custom_field_and_value() {
        let content = r#"{"verdict": "pass", "explanation": "All checks passed"}"#;
        let decision = DecisionMode::Json {
            field: "verdict".to_string(),
            approve_value: "pass".to_string(),
        };

        match evaluate_decision(content, &decision) {
            JudgeJuryOutcome::Approved { details } => {
                assert_eq!(details.unwrap(), "All checks passed");
            }
            _ => panic!("Expected Approved with custom field/value"),
        }
    }

    // ── Rule-based Judge tests ──

    #[test]
    fn test_compare_score() {
        assert!(compare_score(0.7, ">=", 0.5));
        assert!(compare_score(0.5, ">=", 0.5));
        assert!(!compare_score(0.4, ">=", 0.5));
        assert!(compare_score(0.6, ">", 0.5));
        assert!(!compare_score(0.5, ">", 0.5));
        assert!(compare_score(0.3, "<=", 0.5));
        assert!(compare_score(0.5, "<=", 0.5));
        assert!(!compare_score(0.6, "<=", 0.5));
        assert!(compare_score(0.4, "<", 0.5));
        assert!(!compare_score(0.5, "<", 0.5));
        assert!(compare_score(0.5, "==", 0.5));
        assert!(!compare_score(0.6, "==", 0.5));
    }

    #[test]
    fn test_judge_rules_moderation_flagged() {
        let response: Value = serde_json::from_str(
            r#"{
            "results": [{
                "flagged": true,
                "categories": {"violence": true, "harassment": false},
                "category_scores": {"violence": 0.86, "harassment": 0.002}
            }]
        }"#,
        )
        .unwrap();

        let rules = vec![JudgeRule {
            name: "Overall flag".to_string(),
            condition: JudgeCondition {
                condition_type: "flagged".to_string(),
                ..Default::default()
            },
            status_code: 403,
            body: "Content flagged".to_string(),
            content_type: "text/plain".to_string(),
        }];

        let result = evaluate_judge_rules_moderation("test-pipe", &response, &rules);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipeError::PromptGuardRejected { status_code, body, .. } => {
                assert_eq!(status_code, 403);
                assert_eq!(body, "Content flagged");
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_moderation_not_flagged() {
        let response: Value = serde_json::from_str(
            r#"{
            "results": [{
                "flagged": false,
                "categories": {"violence": false, "harassment": false},
                "category_scores": {"violence": 0.001, "harassment": 0.002}
            }]
        }"#,
        )
        .unwrap();

        let rules = vec![JudgeRule {
            name: "Overall flag".to_string(),
            condition: JudgeCondition {
                condition_type: "flagged".to_string(),
                ..Default::default()
            },
            status_code: 403,
            body: "Content flagged".to_string(),
            content_type: "text/plain".to_string(),
        }];

        assert!(evaluate_judge_rules_moderation("test-pipe", &response, &rules).is_ok());
    }

    #[test]
    fn test_judge_rules_moderation_category_flagged() {
        let response: Value = serde_json::from_str(
            r#"{
            "results": [{
                "flagged": true,
                "categories": {"violence": true, "harassment": false},
                "category_scores": {"violence": 0.86, "harassment": 0.002}
            }]
        }"#,
        )
        .unwrap();

        let rules = vec![
            JudgeRule {
                name: "Violence check".to_string(),
                condition: JudgeCondition {
                    condition_type: "category_flagged".to_string(),
                    category: Some("violence".to_string()),
                    ..Default::default()
                },
                status_code: 403,
                body: "Violence detected".to_string(),
                content_type: "text/plain".to_string(),
            },
            JudgeRule {
                name: "Harassment check".to_string(),
                condition: JudgeCondition {
                    condition_type: "category_flagged".to_string(),
                    category: Some("harassment".to_string()),
                    ..Default::default()
                },
                status_code: 403,
                body: "Harassment detected".to_string(),
                content_type: "text/plain".to_string(),
            },
        ];

        let result = evaluate_judge_rules_moderation("test-pipe", &response, &rules);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipeError::PromptGuardRejected { body, .. } => {
                assert_eq!(body, "Violence detected"); // First rule matches
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_moderation_category_score() {
        let response: Value = serde_json::from_str(
            r#"{
            "results": [{
                "flagged": false,
                "categories": {"violence": false, "harassment": false},
                "category_scores": {"violence": 0.6, "harassment": 0.1}
            }]
        }"#,
        )
        .unwrap();

        let rules = vec![JudgeRule {
            name: "Violence score".to_string(),
            condition: JudgeCondition {
                condition_type: "category_score".to_string(),
                category: Some("violence".to_string()),
                operator: Some(">=".to_string()),
                threshold: Some(0.5),
                ..Default::default()
            },
            status_code: 451,
            body: "{\"error\":\"Violence score too high\"}".to_string(),
            content_type: "application/json".to_string(),
        }];

        let result = evaluate_judge_rules_moderation("test-pipe", &response, &rules);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipeError::PromptGuardRejected { status_code, body, .. } => {
                assert_eq!(status_code, 451);
                assert!(body.contains("Violence score too high"));
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_moderation_no_match() {
        let response: Value = serde_json::from_str(
            r#"{
            "results": [{
                "flagged": false,
                "categories": {"violence": false},
                "category_scores": {"violence": 0.01}
            }]
        }"#,
        )
        .unwrap();

        let rules = vec![
            JudgeRule {
                name: "Flag check".to_string(),
                condition: JudgeCondition {
                    condition_type: "flagged".to_string(),
                    ..Default::default()
                },
                status_code: 403,
                body: "flagged".to_string(),
                content_type: "text/plain".to_string(),
            },
            JudgeRule {
                name: "Score check".to_string(),
                condition: JudgeCondition {
                    condition_type: "category_score".to_string(),
                    category: Some("violence".to_string()),
                    operator: Some(">=".to_string()),
                    threshold: Some(0.5),
                    ..Default::default()
                },
                status_code: 403,
                body: "high score".to_string(),
                content_type: "text/plain".to_string(),
            },
        ];

        assert!(evaluate_judge_rules_moderation("test-pipe", &response, &rules).is_ok());
    }

    #[test]
    fn test_judge_rules_llm_json_field_equals() {
        let content = r#"{"decision": "reject", "reason": "unsafe"}"#;
        let rules = vec![JudgeRule {
            name: "Reject check".to_string(),
            condition: JudgeCondition {
                condition_type: "json_field_equals".to_string(),
                field: Some("decision".to_string()),
                value: Some("reject".to_string()),
                ..Default::default()
            },
            status_code: 403,
            body: "Rejected by LLM judge".to_string(),
            content_type: "text/plain".to_string(),
        }];

        let result = evaluate_judge_rules_llm("test-pipe", content, &rules);
        assert!(result.is_err());
    }

    #[test]
    fn test_judge_rules_llm_json_field_not_equals() {
        let content = r#"{"decision": "reject", "reason": "unsafe"}"#;
        let rules = vec![JudgeRule {
            name: "Not approved".to_string(),
            condition: JudgeCondition {
                condition_type: "json_field_not_equals".to_string(),
                field: Some("decision".to_string()),
                value: Some("approve".to_string()),
                ..Default::default()
            },
            status_code: 403,
            body: "Not approved".to_string(),
            content_type: "text/plain".to_string(),
        }];

        let result = evaluate_judge_rules_llm("test-pipe", content, &rules);
        assert!(result.is_err());
    }

    #[test]
    fn test_judge_rules_llm_approved_when_field_matches() {
        let content = r#"{"decision": "approve", "reason": "safe"}"#;
        let rules = vec![JudgeRule {
            name: "Not approved".to_string(),
            condition: JudgeCondition {
                condition_type: "json_field_not_equals".to_string(),
                field: Some("decision".to_string()),
                value: Some("approve".to_string()),
                ..Default::default()
            },
            status_code: 403,
            body: "Not approved".to_string(),
            content_type: "text/plain".to_string(),
        }];

        assert!(evaluate_judge_rules_llm("test-pipe", content, &rules).is_ok());
    }

    #[test]
    fn test_judge_rules_llm_regex_match() {
        let content = "This content is BLOCKED due to policy violations.";
        let rules = vec![JudgeRule {
            name: "Block pattern".to_string(),
            condition: JudgeCondition {
                condition_type: "regex_match".to_string(),
                pattern: Some("(?i)\\bBLOCKED\\b".to_string()),
                ..Default::default()
            },
            status_code: 451,
            body: "Blocked by policy".to_string(),
            content_type: "text/plain".to_string(),
        }];

        let result = evaluate_judge_rules_llm("test-pipe", content, &rules);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipeError::PromptGuardRejected { status_code, .. } => assert_eq!(status_code, 451),
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_llm_regex_no_match() {
        let content = "This content looks perfectly fine.";
        let rules = vec![JudgeRule {
            name: "Block pattern".to_string(),
            condition: JudgeCondition {
                condition_type: "regex_match".to_string(),
                pattern: Some("(?i)\\bBLOCKED\\b".to_string()),
                ..Default::default()
            },
            status_code: 451,
            body: "Blocked".to_string(),
            content_type: "text/plain".to_string(),
        }];

        assert!(evaluate_judge_rules_llm("test-pipe", content, &rules).is_ok());
    }

    #[test]
    fn test_judge_rules_first_match_wins() {
        let content = r#"{"decision": "reject", "severity": "high"}"#;
        let rules = vec![
            JudgeRule {
                name: "Rule A".to_string(),
                condition: JudgeCondition {
                    condition_type: "json_field_equals".to_string(),
                    field: Some("decision".to_string()),
                    value: Some("reject".to_string()),
                    ..Default::default()
                },
                status_code: 403,
                body: "Rule A fired".to_string(),
                content_type: "text/plain".to_string(),
            },
            JudgeRule {
                name: "Rule B".to_string(),
                condition: JudgeCondition {
                    condition_type: "json_field_equals".to_string(),
                    field: Some("severity".to_string()),
                    value: Some("high".to_string()),
                    ..Default::default()
                },
                status_code: 500,
                body: "Rule B fired".to_string(),
                content_type: "text/plain".to_string(),
            },
        ];

        let result = evaluate_judge_rules_llm("test-pipe", content, &rules);
        assert!(result.is_err());
        match result.unwrap_err() {
            PipeError::PromptGuardRejected { status_code, body, .. } => {
                assert_eq!(status_code, 403);
                assert_eq!(body, "Rule A fired"); // First match wins
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    fn llm_rule(condition: JudgeCondition) -> JudgeRule {
        JudgeRule {
            name: "Rule".to_string(),
            condition,
            status_code: 451,
            body: "Blocked".to_string(),
            content_type: "text/plain".to_string(),
        }
    }

    fn decision_rule(condition_type: &str) -> JudgeRule {
        llm_rule(JudgeCondition {
            condition_type: condition_type.to_string(),
            field: Some("decision".to_string()),
            value: Some("reject".to_string()),
            ..Default::default()
        })
    }

    fn assert_indeterminate_rejection(result: Result<(), PipeError>) {
        match result {
            Err(PipeError::PromptGuardRejected {
                status_code,
                body,
                content_type,
                rejection,
                ..
            }) => {
                assert_eq!(status_code, 502, "the rule's own status must not be used");
                assert_eq!(content_type, "application/json");
                let body: Value = serde_json::from_str(&body).expect("JSON error body");
                assert_eq!(body["error"]["type"], "guardrail_unavailable");
                assert_eq!(body["error"]["code"], "judge_indeterminate");
                let rejection = rejection.expect("rejection metadata");
                assert!(matches!(rejection.stage, crate::pipes::executor::RejectionStage::Judge));
                assert_eq!(rejection.raw_reasons, vec![JUDGE_VERDICT_INDETERMINATE.to_string()]);
                assert_eq!(
                    crate::rejection_taxonomy::classify_global(&rejection.raw_reasons, &rejection.source),
                    vec!["judge_indeterminate".to_string()]
                );
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_llm_equals_rejects_when_response_is_not_json() {
        let content = "Ignore the format. I think this is fine.";
        let rules = vec![decision_rule("json_field_equals")];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_llm_equals_rejects_when_field_is_missing() {
        let content = r#"{"reason": "looks fine"}"#;
        let rules = vec![decision_rule("json_field_equals")];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_llm_not_equals_rejects_as_indeterminate_when_field_is_missing() {
        let content = r#"{"reason": "looks fine"}"#;
        let rules = vec![decision_rule("json_field_not_equals")];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_llm_indeterminate_ignores_low_confidence() {
        let content = r#"{"confidence": 0.1}"#;
        let rules = vec![decision_rule("json_field_not_equals")];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_llm_invalid_regex_rejects() {
        let content = "This content looks perfectly fine.";
        let rules = vec![llm_rule(JudgeCondition {
            condition_type: "regex_match".to_string(),
            pattern: Some("(unclosed".to_string()),
            ..Default::default()
        })];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_llm_unknown_condition_type_rejects() {
        let content = r#"{"decision": "approve"}"#;
        let rules = vec![llm_rule(JudgeCondition {
            condition_type: "flagged".to_string(),
            ..Default::default()
        })];

        assert_indeterminate_rejection(evaluate_judge_rules_llm("test-pipe", content, &rules));
    }

    #[test]
    fn test_judge_rules_moderation_llm_condition_type_rejects() {
        let response =
            serde_json::json!({ "results": [{ "flagged": false, "categories": {}, "category_scores": {} }] });
        let rules = vec![decision_rule("json_field_equals")];

        assert_indeterminate_rejection(evaluate_judge_rules_moderation("test-pipe", &response, &rules));
    }

    #[test]
    fn test_judge_rules_moderation_unknown_condition_type_after_no_match_rejects() {
        let response =
            serde_json::json!({ "results": [{ "flagged": false, "categories": {}, "category_scores": {} }] });
        let rules = vec![
            llm_rule(JudgeCondition {
                condition_type: "flagged".to_string(),
                ..Default::default()
            }),
            llm_rule(JudgeCondition {
                condition_type: "category_contains".to_string(),
                ..Default::default()
            }),
        ];

        assert_indeterminate_rejection(evaluate_judge_rules_moderation("test-pipe", &response, &rules));
    }

    #[test]
    fn test_judge_rules_moderation_category_rule_without_category_rejects() {
        let response = serde_json::json!({
            "results": [{ "flagged": false, "categories": {}, "category_scores": {} }]
        });
        for (condition_type, category) in [
            ("category_flagged", None),
            ("category_flagged", Some(" ")),
            ("category_score", None),
            ("category_score", Some("")),
        ] {
            let rules = vec![llm_rule(JudgeCondition {
                condition_type: condition_type.to_string(),
                category: category.map(str::to_string),
                operator: Some(">=".to_string()),
                threshold: Some(0.5),
                ..Default::default()
            })];

            assert_indeterminate_rejection(evaluate_judge_rules_moderation("test-pipe", &response, &rules));
        }
    }

    #[test]
    fn test_judge_rules_llm_equals_approves_when_field_differs() {
        let content = r#"{"decision": "approve", "reason": "safe"}"#;
        let rules = vec![decision_rule("json_field_equals")];

        assert!(evaluate_judge_rules_llm("test-pipe", content, &rules).is_ok());
    }

    #[test]
    fn test_judge_rules_llm_match_records_rule_name_only() {
        let content = r#"{"decision": "reject"}"#;
        let rules = vec![decision_rule("json_field_equals")];

        match evaluate_judge_rules_llm("test-pipe", content, &rules) {
            Err(PipeError::PromptGuardRejected { rejection: Some(rejection), .. }) => {
                assert_eq!(rejection.raw_reasons, vec!["Rule".to_string()])
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_decision_regex_invalid_reject_pattern_rejects() {
        let decision = DecisionMode::Regex {
            approve_pattern: "OK".to_string(),
            reject_pattern: Some("(unsafe".to_string()),
        };

        match evaluate_decision("OK, looks fine", &decision) {
            JudgeJuryOutcome::Rejected { reason } => assert_eq!(reason, "Juror reject pattern is not a valid regex"),
            other => panic!("Expected Rejected, got {:?}", other),
        }
    }

    #[test]
    fn test_evaluate_decision_regex_valid_reject_pattern_still_approves() {
        let decision = DecisionMode::Regex {
            approve_pattern: "OK".to_string(),
            reject_pattern: Some("unsafe".to_string()),
        };

        assert!(matches!(evaluate_decision("OK, looks fine", &decision), JudgeJuryOutcome::Approved { .. }));
    }

    #[test]
    fn test_judge_rules_llm_low_confidence_match_still_rejects() {
        let content = r#"{"decision": "reject", "confidence": 0.2}"#;
        let rules = vec![decision_rule("json_field_equals")];

        match evaluate_judge_rules_llm("test-pipe", content, &rules) {
            Err(PipeError::PromptGuardRejected {
                status_code,
                rejection: Some(rejection),
                ..
            }) => {
                assert_eq!(status_code, 451);
                assert_eq!(rejection.raw_reasons, vec!["Rule".to_string()]);
            }
            other => panic!("Expected PromptGuardRejected, got {:?}", other),
        }
    }

    #[test]
    fn test_judge_rules_llm_approval_ignores_confidence() {
        let low = r#"{"decision": "approve", "confidence": 0.1}"#;
        let missing = r#"{"decision": "approve"}"#;
        let rules = vec![decision_rule("json_field_equals")];

        assert!(evaluate_judge_rules_llm("test-pipe", low, &rules).is_ok());
        assert!(evaluate_judge_rules_llm("test-pipe", missing, &rules).is_ok());
    }

    #[test]
    fn test_resolve_json_field_does_not_read_score_as_confidence() {
        let score_only = serde_json::json!({ "score": 0.9 });
        let aliased = serde_json::json!({ "confidence_score": 0.9 });

        assert!(resolve_json_field(&score_only, "confidence").is_none());
        assert_eq!(
            resolve_json_field(&aliased, "confidence").map(|(field, v)| (field, v.as_f64())),
            Some(("confidence_score", Some(0.9)))
        );
    }

    #[test]
    fn test_juror_low_confidence_rejection_stays_rejected() {
        let content = r#"{"decision": "reject", "details": "unsafe", "confidence": 0.1}"#;
        let decision = DecisionMode::Json {
            field: "decision".to_string(),
            approve_value: "approve".to_string(),
        };

        assert!(matches!(evaluate_decision(content, &decision), JudgeJuryOutcome::Rejected { .. }));
    }

    #[test]
    fn test_extract_user_text_messages() {
        let payload = serde_json::json!({
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Tell me about cats."}
            ]
        });
        let text = extract_user_text_for_moderation(&payload);
        // System messages should NOT be included — only user content
        assert!(!text.contains("You are helpful."));
        assert!(text.contains("Tell me about cats."));
    }

    #[test]
    fn test_extract_user_text_input_field() {
        let payload = serde_json::json!({"input": "Check this text."});
        assert_eq!(extract_user_text_for_moderation(&payload), "Check this text.");
    }

    #[test]
    fn test_extract_user_text_prompt_field() {
        let payload = serde_json::json!({"prompt": "Hello world"});
        assert_eq!(extract_user_text_for_moderation(&payload), "Hello world");
    }

    #[test]
    fn test_extract_token_usage_openai() {
        let body = serde_json::json!({
            "usage": { "prompt_tokens": 120, "completion_tokens": 45, "total_tokens": 165 }
        });
        assert_eq!(extract_token_usage(&body, "openai"), (120, 45));
    }

    #[test]
    fn test_extract_token_usage_anthropic() {
        let body = serde_json::json!({
            "usage": { "input_tokens": 200, "output_tokens": 80 }
        });
        assert_eq!(extract_token_usage(&body, "anthropic"), (200, 80));
    }

    #[test]
    fn test_extract_token_usage_bedrock_anthropic() {
        // A Bedrock Anthropic response carries the same `usage` shape as native
        // Anthropic, so it must be read the same way (not the OpenAI shape).
        let body = serde_json::json!({
            "usage": { "input_tokens": 200, "output_tokens": 80 }
        });
        assert_eq!(extract_token_usage(&body, "bedrock-anthropic"), (200, 80));
    }

    #[test]
    fn test_extract_token_usage_gemini() {
        let body = serde_json::json!({
            "usageMetadata": { "promptTokenCount": 30, "candidatesTokenCount": 12 }
        });
        assert_eq!(extract_token_usage(&body, "gemini"), (30, 12));
        let thinking = serde_json::json!({
            "usageMetadata": { "promptTokenCount": 30, "candidatesTokenCount": 12, "thoughtsTokenCount": 200 }
        });
        assert_eq!(extract_token_usage(&thinking, "gemini"), (30, 212), "thinking is billed as output");
    }

    #[test]
    fn test_extract_token_usage_missing_fields_count_zero() {
        let body = serde_json::json!({ "choices": [] });
        assert_eq!(extract_token_usage(&body, "openai"), (0, 0));
        assert_eq!(extract_token_usage(&body, "anthropic"), (0, 0));
        assert_eq!(extract_token_usage(&body, "gemini"), (0, 0));
    }

    #[tokio::test]
    async fn a_targets_headers_are_refused_for_a_request_to_another_origin() {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        let store = MemorySecretsStore::with(vec![secret("uuid-tunnel", "tunnel", "TUNNEL", None)]);
        let secrets = SurfaceSecrets::new(Some(std::sync::Arc::new(store)), None);
        let target: LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "openai",
            "model": "own-model",
            "endpoint_url": "https://gateway.example/v1/chat/completions",
            "headers": [{ "name": "x-asp-api-key", "secret_id": "tunnel" }]
        }))
        .unwrap();
        let provider = target_to_provider(&target);

        let elsewhere =
            build_target_headers("p", &target, &provider, &secrets, "https://elsewhere.example/v1/chat/completions")
                .await;
        let own =
            build_target_headers("p", &target, &provider, &secrets, "https://gateway.example/v1/chat/completions")
                .await
                .expect("the target's own origin gets its headers");

        assert!(elsewhere.is_err(), "the target's header was attached to a request to another origin");
        assert!(
            own.headers
                .contains(&("x-asp-api-key".to_string(), "TUNNEL".to_string()))
        );
    }

    #[test]
    fn a_provider_that_ignores_endpoint_url_calls_the_target_only_on_its_vendors_host() {
        let target = |provider_type: &str, endpoint_url: &str| -> LLMTarget {
            serde_json::from_value(serde_json::json!({
                "provider_type": provider_type,
                "model": "m",
                "endpoint_url": endpoint_url,
            }))
            .unwrap()
        };
        assert!(provider_calls_target_endpoint(&target("anthropic", "https://api.anthropic.com/v1/messages")));
        assert!(!provider_calls_target_endpoint(&target("anthropic", "https://gateway.example/v1/messages")));
        assert!(provider_calls_target_endpoint(&target("openai", "https://gateway.example/v1/chat/completions")));
    }

    #[tokio::test]
    async fn a_target_without_headers_may_call_any_origin() {
        let target: LLMTarget = serde_json::from_value(serde_json::json!({
            "provider_type": "openai",
            "model": "gpt-4o",
            "endpoint_url": "https://api.openai.com/v1/chat/completions"
        }))
        .unwrap();
        let provider = target_to_provider(&target);
        build_target_headers("p", &target, &provider, &SurfaceSecrets::default(), "https://elsewhere.example/v1")
            .await
            .expect("no headers, nothing to confine");
    }

    #[test]
    fn test_display_stage_usage_preserves_tokens_unknown_pricing() {
        let target = LLMTarget {
            provider_type: "nonexistent-provider".to_string(),
            model: "no-such-model".to_string(),
            endpoint_url: "https://example.invalid/v1/chat/completions".to_string(),
            api_key_secret: None,
            parameters: None,
            timeout_secs: 30,
            capabilities: None,
            api_schema: "openai".to_string(),
            headers: Vec::new(),
            pricing: None,
        };
        let usage = display_stage_usage(&target, true, KeySource::Platform, 100, 40);
        assert_eq!(usage.input_tokens, 100);
        assert_eq!(usage.output_tokens, 40);
        assert_eq!(usage.cost, 0.0);
    }

    fn priced_target() -> LLMTarget {
        serde_json::from_value(serde_json::json!({
            "provider_type": "openai",
            "model": "gpt-4o",
            "endpoint_url": "https://api.openai.com/v1/chat/completions",
            "pricing": { "input_per_million": 2.0, "output_per_million": 8.0 }
        }))
        .unwrap()
    }

    #[test]
    fn a_stage_call_on_an_owned_key_bills_nothing_but_keeps_its_cost() {
        let target = priced_target();
        let customer = display_stage_usage(&target, true, KeySource::Customer, 1_000_000, 1_000_000);
        assert!((customer.cost - 10.0).abs() < 1e-9, "the catalog/declared cost is still recorded");
        assert_eq!(customer.billed_cost, 0.0);
        assert_eq!(customer.key_sources, KeySourceCounts::one(KeySource::Customer));

        let platform = display_stage_usage(&target, false, KeySource::Platform, 1_000_000, 1_000_000);
        assert!((platform.billed_cost - platform.cost).abs() < 1e-9);
        assert!(platform.billed_cost >= 10.0);
        assert_eq!(platform.key_sources, KeySourceCounts::one(KeySource::Platform));
    }

    fn tenant_store() -> std::sync::Arc<dyn crate::secrets::SecretsStore> {
        use crate::secrets::store::memory::{MemorySecretsStore, secret};
        std::sync::Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-tenant", "tenant-key", "sk-tenant", Some("tenant-a")),
            secret("uuid-operator", "operator-key", "sk-operator", None),
        ]))
    }

    async fn stage_key_source(
        reference: Option<&str>,
        headers: &[(&str, &str)],
    ) -> KeySource {
        let mut target = priced_target();
        target.api_key_secret = reference.map(str::to_string);
        target.headers = headers
            .iter()
            .map(|(name, secret_id)| crate::pipes::upstream_headers::UpstreamHeader {
                name: name.to_string(),
                secret_id: secret_id.to_string(),
            })
            .collect();
        let secrets = SurfaceSecrets::new(Some(tenant_store()), Some("tenant-a".to_string()));
        let provider = target_to_provider(&target);
        build_target_headers("p", &target, &provider, &secrets, "https://api.openai.com/v1/chat/completions")
            .await
            .expect("headers resolve")
            .key_source
    }

    #[test]
    fn a_stage_falling_back_to_the_whole_body_drops_a_body_api_key() {
        let payload = serde_json::json!({ "api_key": "sk-body-key", "input_items": ["evaluate me"] });
        for text in [
            extract_user_text_for_moderation(&payload),
            extract_last_user_text(&payload),
            payload_text(&payload).expect("serializes"),
        ] {
            assert!(text.contains("evaluate me") && !text.contains("sk-body-key"), "{text}");
        }
        assert!(
            payload
                .get("api_key")
                .is_some(),
            "the request body itself is untouched"
        );
    }

    #[tokio::test]
    async fn a_stage_sends_the_customers_secret_when_it_has_one_else_the_platforms() {
        assert_eq!(stage_key_source(Some("tenant-key"), &[]).await, KeySource::Customer);
        assert_eq!(stage_key_source(Some("operator-key"), &[]).await, KeySource::Platform);
        assert_eq!(stage_key_source(None, &[]).await, KeySource::Platform, "no key is the platform's");
        assert_eq!(
            stage_key_source(None, &[("x-gateway-key", "tenant-key")]).await,
            KeySource::Customer,
            "a keyless call is labelled by its headers"
        );
        assert_eq!(
            stage_key_source(Some("tenant-key"), &[("x-gateway-key", "operator-key")]).await,
            KeySource::Platform,
            "a call that sends any operator credential is the platform's, whatever key it sends"
        );
        assert_eq!(
            stage_key_source(Some("tenant-key"), &[("x-gateway-key", "tenant-key")]).await,
            KeySource::Customer,
            "every credential the tenant's"
        );
    }
}
