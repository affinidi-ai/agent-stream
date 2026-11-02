//! Production-sampling acquisition: derive a surface's drift dimensions from the
//! signals already produced on the request path and fold one observation per
//! sampled interaction into the drift store, off the hot path.

use chrono::Utc;
use serde_json::Value;

use super::config::DriftConfig;
use super::dimension::{DriftDimension, surface_dimension_key};
use super::session_store::{RecordedSession, global_drift_session_store};
use super::store::{DriftSample, global_drift_store};

/// The per-interaction signals a surface execution yields, from which the drift
/// dimensions are derived. All are already computed on the request path — this
/// adds no upstream calls.
pub struct DriftSignals<'a> {
    /// Model completion length in output tokens (LLM stage only).
    pub output_tokens: u64,
    /// Provider spend for the interaction in USD.
    pub cost: f64,
    /// End-to-end gateway latency in milliseconds.
    pub latency_ms: u64,
    /// Whether the interaction was blocked or flagged by a safety stage
    /// (Judge / Jury / expert witness), including recovered redrives.
    pub safety_flagged: bool,
    /// Structured-output conformance, when a JSON schema was requested.
    pub schema_valid: Option<bool>,
    /// The completion text, when available (buffered path only), used to detect
    /// refusals and to capture the session for replay. `None` on the streaming
    /// passthrough path (no server-side text).
    pub completion_text: Option<&'a str>,
    /// The request `messages` array, captured alongside the completion as
    /// "indicative surface data" the replay evaluation re-runs. `None` when the
    /// request body isn't in scope (then no session is captured).
    pub prompt_messages: Option<&'a Value>,
}

/// Record one sampled interaction's drift dimensions for `surface_id`. No-op
/// when drift monitoring is disabled for the surface, the interaction falls
/// outside the sampled fraction, or the store is not configured. The write is
/// fire-and-forget so it never sits on the request's hot path.
pub fn record_interaction(
    config: Option<&DriftConfig>,
    surface_id: &str,
    signals: DriftSignals,
) {
    let Some(cfg) = config else {
        return;
    };
    if !cfg.should_sample() {
        return;
    }
    let Some(store) = global_drift_store() else {
        return;
    };

    let mut samples: Vec<(String, DriftSample)> = Vec::with_capacity(DriftDimension::ALL.len());
    samples.push((
        surface_dimension_key(surface_id, DriftDimension::OutputTokens),
        DriftSample::observation(signals.output_tokens as f64),
    ));
    samples.push((surface_dimension_key(surface_id, DriftDimension::Cost), DriftSample::observation(signals.cost)));
    samples.push((
        surface_dimension_key(surface_id, DriftDimension::LatencyMs),
        DriftSample::observation(signals.latency_ms as f64),
    ));
    samples.push((
        surface_dimension_key(surface_id, DriftDimension::SafetyFlagRate),
        DriftSample::observation(if signals.safety_flagged {
            1.0
        } else {
            0.0
        }),
    ));
    if let Some(valid) = signals.schema_valid {
        samples.push((
            surface_dimension_key(surface_id, DriftDimension::SchemaValidRate),
            DriftSample::observation(if valid { 1.0 } else { 0.0 }),
        ));
    }
    if let Some(text) = signals.completion_text {
        // Response length is the completion text length in characters; only the
        // buffered path carries the text, like refusal detection.
        samples.push((
            surface_dimension_key(surface_id, DriftDimension::ResponseLength),
            DriftSample::observation(text.chars().count() as f64),
        ));
        samples.push((
            surface_dimension_key(surface_id, DriftDimension::RefusalRate),
            DriftSample::observation(if is_refusal(text) {
                1.0
            } else {
                0.0
            }),
        ));
    }

    let ts = Utc::now();
    tokio::spawn(async move {
        store
            .record_many(samples, ts)
            .await;
    });

    // Capture the indicative session (input + output) for replay evaluation,
    // when both the prompt messages and the completion are in scope. Off the hot
    // path; a missing capture store just means no session is recorded.
    if let (Some(messages), Some(output)) = (signals.prompt_messages, signals.completion_text)
        && let Some(session_store) = global_drift_session_store()
    {
        let session = RecordedSession {
            id: uuid::Uuid::new_v4().to_string(),
            surface_id: surface_id.to_string(),
            captured_at: Utc::now().to_rfc3339(),
            messages: messages.clone(),
            output: output.to_string(),
            latency_ms: signals.latency_ms,
            output_tokens: signals.output_tokens,
        };
        tokio::spawn(async move {
            if let Err(e) = session_store
                .append(&session)
                .await
            {
                tracing::warn!("[DRIFT] failed to capture session for {}: {e}", session.surface_id);
            }
        });
    }
}

/// Common refusal openers. A coarse heuristic — drift tracks the *relative*
/// change in refusal rate over time, so exact per-response accuracy is not
/// required, and a graded classifier can replace this in a later phase.
const REFUSAL_MARKERS: &[&str] = &[
    "i'm sorry",
    "i am sorry",
    "i can't",
    "i cannot",
    "i can not",
    "i'm not able",
    "i am not able",
    "i'm unable",
    "i am unable",
    "as an ai",
    "i won't",
    "i will not",
    "i'm not able to help",
    "unable to assist",
    "can't help with that",
    "cannot assist with",
];

/// Whether a completion looks like a refusal — a leading refusal marker in the
/// first sentence or so of the (lowercased) text.
pub(crate) fn is_refusal(text: &str) -> bool {
    let head: String = text
        .trim_start()
        .chars()
        .take(80)
        .collect::<String>()
        .to_lowercase();
    REFUSAL_MARKERS
        .iter()
        .any(|m| head.contains(m))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusal_detection_matches_leading_markers() {
        assert!(is_refusal("I'm sorry, but I can't help with that."));
        assert!(is_refusal("  As an AI language model, I cannot do this."));
        assert!(!is_refusal("Sure! Here is the answer you asked for."));
        assert!(!is_refusal("The capital of France is Paris."));
    }

    #[test]
    fn record_is_noop_without_config_or_store() {
        // No global store installed in unit tests, and None config → no panic.
        record_interaction(
            None,
            "p1",
            DriftSignals {
                output_tokens: 10,
                cost: 0.0,
                latency_ms: 5,
                safety_flagged: false,
                schema_valid: None,
                completion_text: None,
                prompt_messages: None,
            },
        );
        let cfg = DriftConfig {
            enabled: true,
            sample_rate: 1.0,
            ..Default::default()
        };
        record_interaction(
            Some(&cfg),
            "p1",
            DriftSignals {
                output_tokens: 10,
                cost: 0.0,
                latency_ms: 5,
                safety_flagged: false,
                schema_valid: Some(true),
                completion_text: Some("hi"),
                prompt_messages: None,
            },
        );
    }
}
