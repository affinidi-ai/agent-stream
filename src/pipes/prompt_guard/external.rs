//! External HTTP guardrail connector.
//!
//! Calls a third-party guardrail service (e.g. EnkryptAI) with request and/or
//! response content and turns a "flagged" verdict into a [`GuardOutcome`]. This
//! lets the appliance *orchestrate* an external guardrail rather than replace
//! it: the provider runs alongside the local regex guards on the already-masked
//! content.
//!
//! The connector is detect-and-block: a flagged verdict rejects the call.
//! Local masking remains the job of the regex guards.

use super::config::{
    ExternalGuardrailConfig, ExternalGuardrailProvider, GuardrailProfile, RejectionConfig, VerdictRule,
};
use super::filter::{GuardOutcome, GuardRejection};
use serde_json::{Value, json};
use std::time::Duration;
use tracing::warn;

/// Run the external guardrail against request content.
///
/// Returns the [`GuardOutcome`] plus the content submitted to the provider and
/// the provider's raw response (serialized), so a governance record can retain
/// the witness stage's input/output. Both are `None` when the guardrail is
/// disabled, not configured for requests, or the request carries no inspectable
/// text (no provider call is made). A flagged verdict returns
/// [`GuardOutcome::Rejected`]. The external connector never masks.
pub async fn check_request_external(
    client: &reqwest::Client,
    config: &ExternalGuardrailConfig,
    api_key: Option<&str>,
    request_body: &Value,
) -> (GuardOutcome, Option<String>, Option<String>) {
    if !config.enabled || !config.check_request {
        return (GuardOutcome::Allowed, None, None);
    }
    let text = extract_request_text(request_body);
    if text.trim().is_empty() {
        return (GuardOutcome::Allowed, None, None);
    }
    let (outcome, output) = evaluate(client, config, api_key, &text, "prompt").await;
    (outcome, Some(text), output)
}

/// Run the external guardrail against response content. Mirrors
/// [`check_request_external`], returning the checked content and the provider's
/// raw response alongside the outcome.
pub async fn check_response_external(
    client: &reqwest::Client,
    config: &ExternalGuardrailConfig,
    api_key: Option<&str>,
    response_body: &Value,
) -> (GuardOutcome, Option<String>, Option<String>) {
    if !config.enabled || !config.check_response {
        return (GuardOutcome::Allowed, None, None);
    }
    let text = extract_response_text(response_body);
    if text.trim().is_empty() {
        return (GuardOutcome::Allowed, None, None);
    }
    let (outcome, output) = evaluate(client, config, api_key, &text, "response").await;
    (outcome, Some(text), output)
}

/// Perform the HTTP call and interpret the verdict. Returns the outcome and the
/// provider's raw response body (serialized) when a call was made.
///
/// `seam_mode` is the seam the witness runs on (`prompt` for the request seam,
/// `response` for the response seam); it is injected as the provider's seam-mode
/// header when one applies (EnkryptAI Guardrail's required `X-Enkrypt-Mode`).
async fn evaluate(
    client: &reqwest::Client,
    config: &ExternalGuardrailConfig,
    api_key: Option<&str>,
    text: &str,
    seam_mode: &str,
) -> (GuardOutcome, Option<String>) {
    // Defence in depth: the endpoint is also SSRF-checked at ingestion.
    if let Err(e) = crate::url_validation::validate_service_endpoint_url(&config.endpoint_url).await {
        return (guard_error(config, &format!("endpoint rejected by SSRF guard: {e}")), None);
    }

    let profile = resolve_profile(config);
    let (body, mut headers) = build_provider_request(&profile, config, api_key, text);
    apply_seam_mode_header(&mut headers, &config.provider, seam_mode);

    let mut req = client
        .post(&config.endpoint_url)
        .timeout(Duration::from_secs(config.timeout_secs))
        .json(&body);
    for (name, value) in headers {
        req = req.header(name, value);
    }

    let response = match req.send().await {
        Ok(r) => r,
        Err(e) => return (guard_error(config, &format!("request to external guardrail failed: {e}")), None),
    };

    let status = response.status();
    if !status.is_success() {
        let body = response
            .text()
            .await
            .unwrap_or_default();
        return (guard_error(config, &http_error_detail(status, &body)), Some(body));
    }

    let payload: Value = match response.json().await {
        Ok(j) => j,
        Err(e) => return (guard_error(config, &format!("could not parse external guardrail response: {e}")), None),
    };

    let output = serde_json::to_string(&payload).ok();
    match eval_verdict(&profile.verdict, &payload) {
        Some(Verdict::Allow) => (GuardOutcome::Allowed, output),
        Some(Verdict::Block(detectors)) => {
            let detail = if detectors.is_empty() {
                "policy violation".to_string()
            } else {
                detectors.join(", ")
            };
            let reason = format!("External guardrail ({}) flagged: {detail}", provider_label(&config.provider));
            let mut rej = rejection_from(config, reason);
            rej.categories = detectors;
            (GuardOutcome::Rejected(rej), output)
        }
        // A 200 response whose body lacks any recognisable verdict shape is
        // treated as a provider error, not an implicit allow: honour
        // fail-closed by default so a malformed/unexpected response cannot
        // silently disable the guardrail.
        None => (guard_error(config, "external guardrail response did not contain a recognisable verdict"), output),
    }
}

/// Resolve the profile driving the request/verdict wire format: an inline
/// override when configured, otherwise the built-in profile for the preset.
fn resolve_profile(config: &ExternalGuardrailConfig) -> GuardrailProfile {
    config
        .profile
        .clone()
        .unwrap_or_else(|| builtin_profile(&config.provider))
}

/// Built-in profile for each [`ExternalGuardrailProvider`] preset.
fn builtin_profile(provider: &ExternalGuardrailProvider) -> GuardrailProfile {
    match provider {
        ExternalGuardrailProvider::Enkryptai => GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: json!({ "text": "{text}", "detectors": "{detectors}" }),
            spread_detectors: false,
            default_detectors: Some(default_enkryptai_detectors()),
            verdict: VerdictRule::DetectorMap {
                paths: vec!["summary".to_string(), "detectors".to_string(), "details".to_string()],
            },
        },
        ExternalGuardrailProvider::EnkryptaiGuardrail => GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            // The guardrail (X-Enkrypt-Guardrail header) binds the detectors, so
            // the body carries only the text. The guardrail header is supplied via
            // `ExternalGuardrailConfig::headers`; the required X-Enkrypt-Mode
            // header is injected per seam in `evaluate`.
            request_template: json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::DetectorMap {
                paths: vec!["summary".to_string(), "detectors".to_string(), "details".to_string()],
            },
        },
        ExternalGuardrailProvider::EnkryptaiAiProxy => GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            // The deployment (X-Enkrypt-Deployment header) selects the guardrail
            // policy; the body still carries the model saved-name, injected from
            // `ExternalGuardrailConfig::model`. The deployment header itself is
            // supplied via `ExternalGuardrailConfig::headers`.
            request_template: json!({ "messages": [ { "role": "user", "content": "{text}" } ] }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::DetectorMap {
                paths: vec![
                    "enkrypt_policy_detections.input_guardrails.summary".to_string(),
                    "enkrypt_policy_detections.output_guardrails.summary".to_string(),
                ],
            },
        },
        ExternalGuardrailProvider::EnkryptaiPolicyDetect => GuardrailProfile {
            auth_header: "apikey".to_string(),
            auth_value_template: "{key}".to_string(),
            // The policy (X-Enkrypt-Policy header) binds the detectors, so the
            // body carries only the text. The policy header is supplied via
            // `ExternalGuardrailConfig::headers`.
            request_template: json!({ "text": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::DetectorMap {
                paths: vec!["summary".to_string(), "detectors".to_string(), "details".to_string()],
            },
        },
        ExternalGuardrailProvider::Generic => GuardrailProfile {
            auth_header: "Authorization".to_string(),
            auth_value_template: "Bearer {key}".to_string(),
            request_template: json!({ "input": "{text}" }),
            spread_detectors: true,
            default_detectors: None,
            verdict: VerdictRule::Flag {
                flag_paths: vec!["flagged".to_string(), "blocked".to_string()],
                action_path: Some("action".to_string()),
                category_paths: vec![
                    "violations".to_string(),
                    "categories".to_string(),
                    "flagged_categories".to_string(),
                ],
            },
        },
        ExternalGuardrailProvider::Lakera => GuardrailProfile {
            auth_header: "Authorization".to_string(),
            auth_value_template: "Bearer {key}".to_string(),
            request_template: json!({ "messages": [ { "role": "user", "content": "{text}" } ] }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::Flag {
                flag_paths: vec!["flagged".to_string()],
                action_path: None,
                category_paths: vec![],
            },
        },
        ExternalGuardrailProvider::AzurePromptShields => GuardrailProfile {
            auth_header: "Ocp-Apim-Subscription-Key".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: json!({ "userPrompt": "{text}" }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::Flag {
                flag_paths: vec!["userPromptAnalysis.attackDetected".to_string()],
                action_path: None,
                category_paths: vec![],
            },
        },
        ExternalGuardrailProvider::AzureContentSafety => GuardrailProfile {
            auth_header: "Ocp-Apim-Subscription-Key".to_string(),
            auth_value_template: "{key}".to_string(),
            request_template: json!({
                "text": "{text}",
                "categories": ["Hate", "Sexual", "SelfHarm", "Violence"],
                "outputType": "FourSeverityLevels"
            }),
            spread_detectors: false,
            default_detectors: None,
            verdict: VerdictRule::SeverityList {
                items_path: "categoriesAnalysis".to_string(),
                category_field: "category".to_string(),
                severity_field: "severity".to_string(),
                threshold: 4.0,
            },
        },
    }
}

/// Build the provider request body and headers from the resolved profile.
fn build_provider_request(
    profile: &GuardrailProfile,
    config: &ExternalGuardrailConfig,
    api_key: Option<&str>,
    text: &str,
) -> (Value, Vec<(String, String)>) {
    let detectors = config
        .detectors
        .clone()
        .or_else(|| {
            profile
                .default_detectors
                .clone()
        })
        .unwrap_or(Value::Null);

    let mut body = render_template(&profile.request_template, text, &detectors);
    if profile.spread_detectors
        && let Value::Object(extra) = &detectors
        && let Value::Object(map) = &mut body
    {
        for (k, v) in extra {
            map.insert(k.clone(), v.clone());
        }
    }
    // Some providers (EnkryptAI AI Proxy) require a `model` in the body; inject
    // the per-instance value when set so it overrides any template default.
    if let Some(model) = config
        .model
        .as_deref()
        .map(str::trim)
        .filter(|m| !m.is_empty())
        && let Value::Object(map) = &mut body
    {
        map.insert("model".to_string(), Value::String(model.to_string()));
    }

    let mut headers = Vec::new();
    if let Some(key) = api_key {
        headers.push((
            profile.auth_header.clone(),
            profile
                .auth_value_template
                .replace("{key}", key),
        ));
    }
    // Arbitrary static headers (e.g. EnkryptAI's `X-Enkrypt-Deployment` or any
    // header a `generic` endpoint requires); `{key}` is substituted when set.
    for (name, value) in &config.headers {
        let rendered = match api_key {
            Some(key) => value.replace("{key}", key),
            None => value.clone(),
        };
        headers.push((name.clone(), rendered));
    }
    (body, headers)
}

/// Header carrying the seam mode (request vs response detectors) for providers
/// that require it. EnkryptAI's Guardrail detect endpoint takes
/// `X-Enkrypt-Mode: prompt|response`; other providers have no seam-mode header.
fn seam_mode_header(provider: &ExternalGuardrailProvider) -> Option<&'static str> {
    match provider {
        ExternalGuardrailProvider::EnkryptaiGuardrail => Some("X-Enkrypt-Mode"),
        _ => None,
    }
}

/// Inject the provider's seam-mode header from the witness seam, replacing any
/// operator-supplied value so the seam (request/response) is authoritative.
fn apply_seam_mode_header(
    headers: &mut Vec<(String, String)>,
    provider: &ExternalGuardrailProvider,
    seam_mode: &str,
) {
    if let Some(name) = seam_mode_header(provider) {
        headers.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        headers.push((name.to_string(), seam_mode.to_string()));
    }
}

/// Substitute `{text}` and `{detectors}` placeholders throughout a template.
fn render_template(
    template: &Value,
    text: &str,
    detectors: &Value,
) -> Value {
    match template {
        Value::String(s) if s == "{text}" => Value::String(text.to_string()),
        Value::String(s) if s == "{detectors}" => detectors.clone(),
        Value::String(s) if s.contains("{text}") => Value::String(s.replace("{text}", text)),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|v| render_template(v, text, detectors))
                .collect(),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, v)| (k.clone(), render_template(v, text, detectors)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Resolve a dot-separated path against a JSON value.
fn value_at_path<'a>(
    root: &'a Value,
    path: &str,
) -> Option<&'a Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Verdict returned by the provider's response.
enum Verdict {
    Allow,
    /// Blocked, carrying the list of triggered detector names (may be empty).
    Block(Vec<String>),
}

/// Interpret a provider response into an allow/block verdict using the profile's
/// rule. Returns `None` when the response lacks the rule's expected shape so the
/// caller can fail closed instead of treating it as an implicit allow.
fn eval_verdict(
    rule: &VerdictRule,
    payload: &Value,
) -> Option<Verdict> {
    match rule {
        VerdictRule::DetectorMap { paths } => {
            let map = paths
                .iter()
                .find_map(|p| value_at_path(payload, p).and_then(Value::as_object))?;
            let mut triggered: Vec<String> = map
                .iter()
                .filter(|(_, value)| is_detector_hit(value))
                .map(|(detector, _)| detector.clone())
                .collect();
            if triggered.is_empty() {
                Some(Verdict::Allow)
            } else {
                triggered.sort();
                Some(Verdict::Block(triggered))
            }
        }
        VerdictRule::Flag {
            flag_paths,
            action_path,
            category_paths,
        } => {
            let mut found = false;
            let mut flagged = false;
            for path in flag_paths {
                if let Some(value) = value_at_path(payload, path)
                    && let Some(b) = value.as_bool()
                {
                    found = true;
                    flagged |= b;
                }
            }
            if let Some(path) = action_path
                && let Some(value) = value_at_path(payload, path)
                && let Some(action) = value.as_str()
            {
                found = true;
                flagged |= action.eq_ignore_ascii_case("block");
            }
            if !found {
                return None;
            }
            if !flagged {
                return Some(Verdict::Allow);
            }
            let mut categories = Vec::new();
            for key in category_paths {
                if let Some(Value::Array(items)) = value_at_path(payload, key) {
                    for item in items {
                        if let Some(s) = item.as_str() {
                            categories.push(s.to_string());
                        }
                    }
                }
            }
            Some(Verdict::Block(categories))
        }
        VerdictRule::SeverityList {
            items_path,
            category_field,
            severity_field,
            threshold,
        } => {
            let items = value_at_path(payload, items_path).and_then(Value::as_array)?;
            let mut triggered: Vec<String> = items
                .iter()
                .filter_map(|item| {
                    let severity = item
                        .get(severity_field)
                        .and_then(Value::as_f64)?;
                    if severity < *threshold {
                        return None;
                    }
                    Some(
                        item.get(category_field)
                            .and_then(Value::as_str)
                            .map(str::to_string)
                            .unwrap_or_else(|| severity.to_string()),
                    )
                })
                .collect();
            if triggered.is_empty() {
                Some(Verdict::Allow)
            } else {
                triggered.sort();
                Some(Verdict::Block(triggered))
            }
        }
    }
}

/// Whether a single detector value counts as a hit.
fn is_detector_hit(value: &Value) -> bool {
    match value {
        Value::Bool(b) => *b,
        Value::Number(n) => n
            .as_f64()
            .map(|v| v > 0.0)
            .unwrap_or(false),
        Value::Object(map) => map
            .get("detected")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        _ => false,
    }
}

/// Default EnkryptAI detector set when the operator does not supply one.
fn default_enkryptai_detectors() -> Value {
    json!({
        "injection_attack": { "enabled": true },
        "toxicity": { "enabled": true },
        "nsfw": { "enabled": true },
        "pii": { "enabled": true }
    })
}

/// Build a human-readable detail for a non-2xx provider response, including a
/// trimmed snippet of the provider's error body so the real cause (e.g. an
/// unknown deployment or rejected model) is visible in the activity log.
fn http_error_detail(
    status: reqwest::StatusCode,
    body: &str,
) -> String {
    let snippet = body.trim();
    if snippet.is_empty() {
        format!("external guardrail returned HTTP {status}")
    } else {
        let truncated: String = snippet
            .chars()
            .take(500)
            .collect();
        format!("external guardrail returned HTTP {status}: {truncated}")
    }
}

/// Map a provider error to an outcome, honouring fail-open / fail-closed.
fn guard_error(
    config: &ExternalGuardrailConfig,
    detail: &str,
) -> GuardOutcome {
    if config.fail_open {
        warn!("External guardrail unavailable, failing open: {detail}");
        GuardOutcome::Allowed
    } else {
        warn!("External guardrail unavailable, failing closed: {detail}");
        GuardOutcome::Rejected(GuardRejection {
            status_code: 502,
            body: r#"{"error":{"message":"Guardrail provider unavailable","type":"guardrail_unavailable","code":"guardrail_provider_error"}}"#
                .to_string(),
            content_type: "application/json".to_string(),
            reason: Some(format!("external guardrail unavailable: {detail}")),
            categories: Vec::new(),
        })
    }
}

/// Build a rejection response from the configured (or default) rejection,
/// stamping the human-readable reason for the activity log.
fn rejection_from(
    config: &ExternalGuardrailConfig,
    reason: String,
) -> GuardRejection {
    let base = config
        .rejection
        .clone()
        .unwrap_or_default();
    let RejectionConfig {
        status_code,
        body,
        content_type,
    } = base;
    GuardRejection {
        status_code,
        body,
        content_type,
        reason: Some(reason),
        categories: Vec::new(),
    }
}

fn provider_label(provider: &ExternalGuardrailProvider) -> &'static str {
    provider.as_str()
}

/// Concatenate inspectable text from an OpenAI-format request body.
fn extract_request_text(request_body: &Value) -> String {
    let mut out = String::new();
    if let Some(Value::Array(messages)) = request_body.get("messages") {
        for message in messages {
            append_content_text(message.get("content"), &mut out);
        }
    }
    out
}

/// Concatenate inspectable text from an OpenAI-compatible response body.
fn extract_response_text(response_body: &Value) -> String {
    let mut out = String::new();
    if let Some(Value::Array(choices)) = response_body.get("choices") {
        for choice in choices {
            let content = choice
                .get("message")
                .and_then(|m| m.get("content"))
                .or_else(|| choice.get("text"));
            append_content_text(content, &mut out);
        }
    }
    out
}

/// Append a message `content` field (string, or array of `{type:text,text}`)
/// to the accumulator.
fn append_content_text(
    content: Option<&Value>,
    out: &mut String,
) {
    match content {
        Some(Value::String(s)) => push_segment(out, s),
        Some(Value::Array(parts)) => {
            for part in parts {
                if part
                    .get("type")
                    .and_then(Value::as_str)
                    == Some("text")
                    && let Some(s) = part
                        .get("text")
                        .and_then(Value::as_str)
                {
                    push_segment(out, s);
                }
            }
        }
        _ => {}
    }
}

fn push_segment(
    out: &mut String,
    segment: &str,
) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str(segment);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_request_text_from_string_and_array_content() {
        let body = json!({
            "messages": [
                { "role": "system", "content": "be helpful" },
                { "role": "user", "content": [
                    { "type": "text", "text": "hello" },
                    { "type": "image_url", "image_url": { "url": "x" } },
                    { "type": "text", "text": "world" }
                ]}
            ]
        });
        let text = extract_request_text(&body);
        assert_eq!(text, "be helpful\nhello\nworld");
    }

    #[test]
    fn extracts_response_text_from_choices() {
        let body = json!({
            "choices": [ { "message": { "content": "the answer" } } ]
        });
        assert_eq!(extract_response_text(&body), "the answer");
    }

    #[test]
    fn enkryptai_summary_with_nonzero_flag_blocks() {
        let payload = json!({ "summary": { "injection_attack": 1, "toxicity": 0 } });
        match eval_verdict(&enkryptai_verdict(), &payload) {
            Some(Verdict::Block(detectors)) => {
                assert_eq!(detectors, vec!["injection_attack".to_string()])
            }
            other => panic!("expected block, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn enkryptai_clean_summary_allows() {
        let payload = json!({ "summary": { "injection_attack": 0, "toxicity": 0 } });
        assert!(matches!(eval_verdict(&enkryptai_verdict(), &payload), Some(Verdict::Allow)));
    }

    #[test]
    fn enkryptai_nested_detected_flag_blocks() {
        let payload = json!({ "summary": { "pii": { "detected": true } } });
        match eval_verdict(&enkryptai_verdict(), &payload) {
            Some(Verdict::Block(detectors)) => assert_eq!(detectors, vec!["pii".to_string()]),
            other => panic!("expected block, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn enkryptai_missing_summary_is_unparseable() {
        // A 200 body with no recognisable verdict shape must NOT default to
        // allow; `eval_verdict` returns None so the caller fails closed.
        let payload = json!({ "status": "ok" });
        assert!(eval_verdict(&enkryptai_verdict(), &payload).is_none());
    }

    #[test]
    fn generic_flagged_true_blocks_with_categories() {
        let payload = json!({ "flagged": true, "categories": ["hate", "violence"] });
        match eval_verdict(&generic_verdict(), &payload) {
            Some(Verdict::Block(categories)) => {
                assert_eq!(categories, vec!["hate".to_string(), "violence".to_string()])
            }
            other => panic!("expected block, got {:?}", other.is_some()),
        }
    }

    #[test]
    fn generic_action_block_blocks() {
        let payload = json!({ "action": "BLOCK" });
        assert!(matches!(eval_verdict(&generic_verdict(), &payload), Some(Verdict::Block(_))));
    }

    #[test]
    fn generic_not_flagged_allows() {
        let payload = json!({ "flagged": false });
        assert!(matches!(eval_verdict(&generic_verdict(), &payload), Some(Verdict::Allow)));
    }

    #[test]
    fn generic_missing_verdict_is_unparseable() {
        // None of flagged/blocked/action present => unparseable => fail closed.
        let payload = json!({ "id": "mod-1" });
        assert!(eval_verdict(&generic_verdict(), &payload).is_none());
    }

    #[test]
    fn enkryptai_request_uses_apikey_header_and_default_detectors() {
        let config = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Enkryptai,
            endpoint_url: "https://api.enkryptai.com/guardrails/detect".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: None,
        };
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("secret-key"), "hi");
        assert_eq!(body["text"], "hi");
        assert!(
            body["detectors"]["injection_attack"]["enabled"]
                .as_bool()
                .unwrap()
        );
        assert_eq!(headers, vec![("apikey".to_string(), "secret-key".to_string())]);
    }

    #[test]
    fn generic_request_uses_bearer_header_and_merges_detectors() {
        let config = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Generic,
            endpoint_url: "https://example.com/moderate".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: Some(json!({ "model": "moderation-latest" })),
            rejection: None,
            profile: None,
        };
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("k"), "text");
        assert_eq!(body["input"], "text");
        assert_eq!(body["model"], "moderation-latest");
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer k".to_string())]);
    }

    #[test]
    fn inline_profile_overrides_builtin_for_request_and_verdict() {
        let config = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Generic,
            endpoint_url: "https://lakera.example/guard".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: Some(GuardrailProfile {
                auth_header: "x-api-key".to_string(),
                auth_value_template: "{key}".to_string(),
                request_template: json!({ "prompt": "{text}" }),
                spread_detectors: false,
                default_detectors: None,
                verdict: VerdictRule::Flag {
                    flag_paths: vec!["results.flagged".to_string()],
                    action_path: None,
                    category_paths: vec![],
                },
            }),
        };
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("tok"), "hi there");
        assert_eq!(body["prompt"], "hi there");
        assert_eq!(headers, vec![("x-api-key".to_string(), "tok".to_string())]);

        let blocked = json!({ "results": { "flagged": true } });
        assert!(matches!(eval_verdict(&profile.verdict, &blocked), Some(Verdict::Block(_))));
        let clean = json!({ "results": { "flagged": false } });
        assert!(matches!(eval_verdict(&profile.verdict, &clean), Some(Verdict::Allow)));
        let unknown = json!({ "results": {} });
        assert!(eval_verdict(&profile.verdict, &unknown).is_none());
    }

    #[test]
    fn guardrail_profile_round_trips_through_json() {
        let profile = builtin_profile(&ExternalGuardrailProvider::Enkryptai);
        let value = serde_json::to_value(&profile).unwrap();
        assert_eq!(value["auth_header"], "apikey");
        assert_eq!(value["verdict"]["kind"], "detector_map");
        let back: GuardrailProfile = serde_json::from_value(value).unwrap();
        assert_eq!(back, profile);
    }

    #[test]
    fn lakera_request_uses_bearer_header_and_messages_template() {
        let config = config_with(ExternalGuardrailProvider::Lakera);
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("lk"), "danger");
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "danger");
        assert_eq!(headers, vec![("Authorization".to_string(), "Bearer lk".to_string())]);
    }

    #[test]
    fn lakera_flagged_blocks_clean_allows_missing_unparseable() {
        let verdict = builtin_profile(&ExternalGuardrailProvider::Lakera).verdict;
        assert!(matches!(eval_verdict(&verdict, &json!({ "flagged": true })), Some(Verdict::Block(_))));
        assert!(matches!(eval_verdict(&verdict, &json!({ "flagged": false })), Some(Verdict::Allow)));
        assert!(eval_verdict(&verdict, &json!({ "id": "x" })).is_none());
    }

    #[test]
    fn azure_prompt_shields_request_and_verdict() {
        let config = config_with(ExternalGuardrailProvider::AzurePromptShields);
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("az"), "ignore previous");
        assert_eq!(body["userPrompt"], "ignore previous");
        assert_eq!(headers, vec![("Ocp-Apim-Subscription-Key".to_string(), "az".to_string())]);

        let blocked = json!({ "userPromptAnalysis": { "attackDetected": true } });
        assert!(matches!(eval_verdict(&profile.verdict, &blocked), Some(Verdict::Block(_))));
        let clean = json!({ "userPromptAnalysis": { "attackDetected": false } });
        assert!(matches!(eval_verdict(&profile.verdict, &clean), Some(Verdict::Allow)));
        let unknown = json!({ "documentsAnalysis": [] });
        assert!(eval_verdict(&profile.verdict, &unknown).is_none());
    }

    #[test]
    fn azure_content_safety_severity_threshold() {
        let config = config_with(ExternalGuardrailProvider::AzureContentSafety);
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("az"), "harmful");
        assert_eq!(body["text"], "harmful");
        assert_eq!(body["outputType"], "FourSeverityLevels");
        assert_eq!(headers, vec![("Ocp-Apim-Subscription-Key".to_string(), "az".to_string())]);

        // severity 4 >= threshold 4 => block, naming the triggered category.
        let blocked = json!({ "categoriesAnalysis": [
            { "category": "Hate", "severity": 4 },
            { "category": "Violence", "severity": 0 }
        ]});
        match eval_verdict(&profile.verdict, &blocked) {
            Some(Verdict::Block(cats)) => assert_eq!(cats, vec!["Hate".to_string()]),
            other => panic!("expected block, got {:?}", other.is_some()),
        }

        // all below threshold => allow.
        let clean = json!({ "categoriesAnalysis": [ { "category": "Hate", "severity": 2 } ] });
        assert!(matches!(eval_verdict(&profile.verdict, &clean), Some(Verdict::Allow)));

        // no array at items_path => unparseable => fail closed.
        let unknown = json!({ "status": "ok" });
        assert!(eval_verdict(&profile.verdict, &unknown).is_none());
    }

    #[test]
    fn custom_headers_are_sent_with_key_substitution() {
        let mut config = config_with(ExternalGuardrailProvider::EnkryptaiAiProxy);
        config
            .headers
            .insert("X-Enkrypt-Deployment".to_string(), "Stream deployment".to_string());
        config
            .headers
            .insert("X-Trace".to_string(), "tok-{key}".to_string());
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("ek"), "hello");
        // AI-Proxy sends an OpenAI-style messages body; `model` is omitted when
        // not configured on the witness.
        assert_eq!(body["messages"][0]["content"], "hello");
        assert!(body.get("model").is_none());
        // Auth header first, then the custom headers (BTreeMap order), with
        // `{key}` substituted.
        assert_eq!(headers[0], ("apikey".to_string(), "ek".to_string()));
        assert!(headers.contains(&("X-Enkrypt-Deployment".to_string(), "Stream deployment".to_string())));
        assert!(headers.contains(&("X-Trace".to_string(), "tok-ek".to_string())));
    }

    #[test]
    fn enkryptai_ai_proxy_injects_model_into_body() {
        let mut config = config_with(ExternalGuardrailProvider::EnkryptaiAiProxy);
        config.model = Some("Stream test".to_string());
        let profile = resolve_profile(&config);
        let (body, _headers) = build_provider_request(&profile, &config, Some("ek"), "hello");
        assert_eq!(body["model"], "Stream test");
        assert_eq!(body["messages"][0]["content"], "hello");
    }

    #[test]
    fn enkryptai_policy_detect_sends_text_only_with_policy_header() {
        let mut config = config_with(ExternalGuardrailProvider::EnkryptaiPolicyDetect);
        config
            .headers
            .insert("X-Enkrypt-Policy".to_string(), "Stream Guardail".to_string());
        let profile = resolve_profile(&config);
        let (body, headers) = build_provider_request(&profile, &config, Some("ek"), "hello");
        // Policy-detect carries only the text; the policy header binds detectors.
        assert_eq!(body["text"], "hello");
        assert!(
            body.get("detectors")
                .is_none()
        );
        assert_eq!(headers[0], ("apikey".to_string(), "ek".to_string()));
        assert!(headers.contains(&("X-Enkrypt-Policy".to_string(), "Stream Guardail".to_string())));
    }

    #[test]
    fn enkryptai_guardrail_sends_text_with_guardrail_and_seam_mode() {
        let mut config = config_with(ExternalGuardrailProvider::EnkryptaiGuardrail);
        config
            .headers
            .insert("X-Enkrypt-Guardrail".to_string(), "Stream Guardail".to_string());
        let profile = resolve_profile(&config);
        let (body, mut headers) = build_provider_request(&profile, &config, Some("ek"), "hello");
        // Guardrail detect carries only the text; the guardrail header binds detectors.
        assert_eq!(body["text"], "hello");
        assert!(
            body.get("detectors")
                .is_none()
        );
        assert_eq!(headers[0], ("apikey".to_string(), "ek".to_string()));
        assert!(headers.contains(&("X-Enkrypt-Guardrail".to_string(), "Stream Guardail".to_string())));

        // The request seam injects `prompt`; the response seam injects `response`.
        apply_seam_mode_header(&mut headers, &config.provider, "prompt");
        assert!(headers.contains(&("X-Enkrypt-Mode".to_string(), "prompt".to_string())));

        let mut response_headers = headers.clone();
        apply_seam_mode_header(&mut response_headers, &config.provider, "response");
        assert!(response_headers.contains(&("X-Enkrypt-Mode".to_string(), "response".to_string())));
        // The seam value is authoritative: no duplicate `prompt` survives.
        assert_eq!(
            response_headers
                .iter()
                .filter(|(n, _)| n == "X-Enkrypt-Mode")
                .count(),
            1
        );
    }

    #[test]
    fn seam_mode_header_only_applies_to_guardrail_provider() {
        let mut headers = vec![("apikey".to_string(), "ek".to_string())];
        apply_seam_mode_header(&mut headers, &ExternalGuardrailProvider::EnkryptaiPolicyDetect, "prompt");
        assert!(
            !headers
                .iter()
                .any(|(n, _)| n == "X-Enkrypt-Mode")
        );
    }

    #[test]
    fn enkryptai_ai_proxy_reads_nested_policy_detections() {
        let verdict = builtin_profile(&ExternalGuardrailProvider::EnkryptaiAiProxy).verdict;
        // A non-zero summary count under input_guardrails blocks, naming the detector.
        let blocked = json!({
            "enkrypt_policy_detections": {
                "input_guardrails": { "summary": { "nsfw": 1, "injection_attack": 0 } },
                "output_guardrails": { "summary": { "nsfw": 0 } }
            }
        });
        match eval_verdict(&verdict, &blocked) {
            Some(Verdict::Block(cats)) => assert_eq!(cats, vec!["nsfw".to_string()]),
            other => panic!("expected block, got {:?}", other.is_some()),
        }
        // All-zero summary => allow.
        let clean = json!({
            "enkrypt_policy_detections": {
                "input_guardrails": { "summary": { "nsfw": 0, "injection_attack": 0 } }
            }
        });
        assert!(matches!(eval_verdict(&verdict, &clean), Some(Verdict::Allow)));
        // No recognisable detections object => unparseable => fail closed.
        let unknown = json!({ "choices": [] });
        assert!(eval_verdict(&verdict, &unknown).is_none());
    }

    fn config_with(provider: ExternalGuardrailProvider) -> ExternalGuardrailConfig {
        ExternalGuardrailConfig {
            enabled: true,
            provider,
            endpoint_url: "https://provider.example/guard".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: None,
        }
    }

    fn enkryptai_verdict() -> VerdictRule {
        builtin_profile(&ExternalGuardrailProvider::Enkryptai).verdict
    }

    fn generic_verdict() -> VerdictRule {
        builtin_profile(&ExternalGuardrailProvider::Generic).verdict
    }

    #[test]
    fn guard_error_fails_closed_by_default() {
        let config = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Enkryptai,
            endpoint_url: "https://api.enkryptai.com/guardrails/detect".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: false,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: None,
        };
        match guard_error(&config, "boom") {
            GuardOutcome::Rejected(r) => assert_eq!(r.status_code, 502),
            other => panic!("expected rejection, got {other:?}"),
        }
    }

    #[test]
    fn guard_error_fails_open_when_configured() {
        let config = ExternalGuardrailConfig {
            enabled: true,
            provider: ExternalGuardrailProvider::Enkryptai,
            endpoint_url: "https://api.enkryptai.com/guardrails/detect".to_string(),
            api_key_secret: None,
            timeout_secs: 10,
            fail_open: true,
            check_request: true,
            check_response: true,
            headers: Default::default(),
            model: None,
            detectors: None,
            rejection: None,
            profile: None,
        };
        assert!(matches!(guard_error(&config, "boom"), GuardOutcome::Allowed));
    }

    #[test]
    fn http_error_detail_includes_provider_body() {
        let detail = http_error_detail(reqwest::StatusCode::BAD_REQUEST, "  {\"error\":\"deployment not found\"}  ");
        assert_eq!(detail, "external guardrail returned HTTP 400 Bad Request: {\"error\":\"deployment not found\"}");
    }

    #[test]
    fn http_error_detail_omits_empty_body() {
        let detail = http_error_detail(reqwest::StatusCode::BAD_REQUEST, "   ");
        assert_eq!(detail, "external guardrail returned HTTP 400 Bad Request");
    }
}
