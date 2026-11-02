//! The drift dimensions — the independent axes a surface can drift on. Each is
//! stored as its own gauge series `drift:surface:{id}:{dimension}` so a surface
//! can drift on one axis while staying stable on the others.

use serde::{Deserialize, Serialize};

/// One measurable axis of surface behaviour tracked over time.
///
/// Most dimensions are derived from data already captured on the request path
/// (`ExecutionMetrics` + the rejection outcome) via production sampling.
/// `Quality` (a stability rate) and `SemanticDistance` are produced by the
/// replay evaluation of a surface's captured sessions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DriftDimension {
    /// Answer-stability rate: fraction of replays whose answer stayed close to
    /// the originally-captured one (`0..1`).
    Quality,
    /// Fraction of responses that are refusals (`0..1`).
    RefusalRate,
    /// Fraction of interactions blocked or flagged by Judge / Jury / witness (`0..1`).
    SafetyFlagRate,
    /// Mean model completion text length in characters (buffered path only).
    ResponseLength,
    /// Mean model completion length in output tokens.
    OutputTokens,
    /// Mean provider spend per interaction in USD.
    Cost,
    /// Mean end-to-end gateway latency in milliseconds.
    LatencyMs,
    /// Structured-output schema conformance rate (`0..1`).
    SchemaValidRate,
    /// Mean embedding distance of a replayed answer from the originally-captured one.
    SemanticDistance,
}

impl DriftDimension {
    /// Every dimension, in display order.
    pub const ALL: [DriftDimension; 9] = [
        DriftDimension::Quality,
        DriftDimension::RefusalRate,
        DriftDimension::SafetyFlagRate,
        DriftDimension::ResponseLength,
        DriftDimension::OutputTokens,
        DriftDimension::Cost,
        DriftDimension::LatencyMs,
        DriftDimension::SchemaValidRate,
        DriftDimension::SemanticDistance,
    ];

    /// The stable wire/series identifier for this dimension.
    pub fn as_str(&self) -> &'static str {
        match self {
            DriftDimension::Quality => "quality",
            DriftDimension::RefusalRate => "refusal_rate",
            DriftDimension::SafetyFlagRate => "safety_flag_rate",
            DriftDimension::ResponseLength => "response_length",
            DriftDimension::OutputTokens => "output_tokens",
            DriftDimension::Cost => "cost",
            DriftDimension::LatencyMs => "latency_ms",
            DriftDimension::SchemaValidRate => "schema_valid_rate",
            DriftDimension::SemanticDistance => "semantic_distance",
        }
    }

    /// Human-readable label for the LLM Drift page chart title.
    pub fn label(&self) -> &'static str {
        match self {
            DriftDimension::Quality => "Quality score",
            DriftDimension::RefusalRate => "Refusal rate",
            DriftDimension::SafetyFlagRate => "Safety-flag rate",
            DriftDimension::ResponseLength => "Response length",
            DriftDimension::OutputTokens => "Output tokens",
            DriftDimension::Cost => "Cost",
            DriftDimension::LatencyMs => "Latency",
            DriftDimension::SchemaValidRate => "Schema validity",
            DriftDimension::SemanticDistance => "Semantic distance",
        }
    }

    /// The unit the mean is expressed in, for the chart's y-axis.
    pub fn unit(&self) -> &'static str {
        match self {
            DriftDimension::Quality
            | DriftDimension::RefusalRate
            | DriftDimension::SafetyFlagRate
            | DriftDimension::SchemaValidRate => "ratio",
            DriftDimension::ResponseLength => "chars",
            DriftDimension::OutputTokens => "tokens",
            DriftDimension::Cost => "usd",
            DriftDimension::LatencyMs => "ms",
            DriftDimension::SemanticDistance => "distance",
        }
    }

    /// Whether the dimension is a `0..1` rate (as opposed to an absolute gauge),
    /// so the page can fix the y-axis to `[0, 1]`.
    pub fn is_rate(&self) -> bool {
        matches!(
            self,
            DriftDimension::Quality
                | DriftDimension::RefusalRate
                | DriftDimension::SafetyFlagRate
                | DriftDimension::SchemaValidRate
        )
    }

    /// What produces this dimension's observations, so an empty chart can say
    /// why it is empty instead of a bare "no data". Several dimensions only fill
    /// under specific conditions — structured-output traffic, or a replay
    /// evaluation having run — and without this an operator cannot tell "not
    /// applicable to this surface" from "something is broken".
    pub fn source_hint(&self) -> &'static str {
        match self {
            DriftDimension::Quality | DriftDimension::SemanticDistance => {
                "Measured by replay evaluation. Run one from Indicative surface data below, or enable a schedule."
            }
            DriftDimension::SchemaValidRate => {
                "Only recorded for requests that ask for structured output (`response_format: json_schema`), on the non-streaming path. Empty when this surface's callers don't use it."
            }
            DriftDimension::ResponseLength | DriftDimension::RefusalRate => {
                "Derived from the completion text, which only the non-streaming path carries (or a streamed response that governance reassembled)."
            }
            DriftDimension::SafetyFlagRate => {
                "Recorded from Judge / Jury / expert-witness outcomes on the non-streaming path."
            }
            DriftDimension::LatencyMs | DriftDimension::OutputTokens | DriftDimension::Cost => {
                "Recorded from every sampled interaction. Empty means no traffic reached this surface in the window while drift monitoring was on."
            }
        }
    }

    /// Floor on the baseline magnitude used as the denominator when computing a
    /// relative change, so a near-zero baseline (e.g. a `0.0` refusal rate)
    /// doesn't make any non-zero current value read as infinite drift. Chosen
    /// per dimension to be "a change this small is noise".
    pub fn baseline_floor(&self) -> f64 {
        match self {
            DriftDimension::Quality
            | DriftDimension::RefusalRate
            | DriftDimension::SafetyFlagRate
            | DriftDimension::SchemaValidRate
            | DriftDimension::SemanticDistance => 0.05,
            DriftDimension::LatencyMs => 100.0,
            DriftDimension::ResponseLength => 80.0,
            DriftDimension::OutputTokens => 20.0,
            DriftDimension::Cost => 0.0005,
        }
    }
}

/// The gauge series key for one surface's dimension:
/// `drift:surface:{surface_id}:{dimension}`. This `drift:*` namespace is
/// disjoint from the usage (`surface:*`) and operational (`ops`) namespaces, so
/// the main dashboard's series reads can never surface a drift line.
pub fn surface_dimension_key(
    surface_id: &str,
    dim: DriftDimension,
) -> String {
    format!("drift:surface:{surface_id}:{}", dim.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dimension_keys_are_namespaced_and_stable() {
        assert_eq!(surface_dimension_key("p1", DriftDimension::LatencyMs), "drift:surface:p1:latency_ms");
        assert_eq!(surface_dimension_key("p1", DriftDimension::RefusalRate), "drift:surface:p1:refusal_rate");
        assert_eq!(surface_dimension_key("p1", DriftDimension::OutputTokens), "drift:surface:p1:output_tokens");
        assert_eq!(surface_dimension_key("p1", DriftDimension::Cost), "drift:surface:p1:cost");
        // Every dimension has a distinct, snake_case identifier.
        let mut seen = std::collections::HashSet::new();
        for d in DriftDimension::ALL {
            assert!(seen.insert(d.as_str()), "duplicate dimension id {}", d.as_str());
        }
    }
}
