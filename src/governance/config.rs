//! Per-surface configuration for signed governance recording.

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::record::RecordOutcome;

fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Where signed records are exported in addition to the durable local append-only
/// store. Delivery is best-effort and asynchronous; the local store remains the
/// source of truth. A record can fan out to the OpenTelemetry exporter and to any
/// number of configured integrations (webhook, Slack, email, Kafka/Kinesis/Pulsar/
/// Redis stream, Langfuse) resolved from the integration store.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GovernanceExport {
    /// Emit each signed VC to the OpenTelemetry log/trace exporter.
    #[serde(default, skip_serializing_if = "is_false")]
    pub otel: bool,
    /// Integration ids to dispatch each signed record to, resolved against the
    /// integration store. Each id names a configured integration of any type.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub integrations: Vec<String>,
}

impl GovernanceExport {
    /// True when no export target is configured (local store only).
    pub fn is_empty(&self) -> bool {
        !self.otel && self.integrations.is_empty()
    }
}

/// Which recorded interactions keep their prompt and completion text (and
/// stage bodies and attachment bytes). The rest keep digests only.
///
/// On the wire `true` (or `"all"`) is [`Self::All`], `false` (or `"none"`) is
/// [`Self::None`] and `"blocked"` is [`Self::Blocked`]; `All` and `None` are
/// written back as the booleans, so a configuration written before the modes
/// existed reads and round-trips unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BodyCapture {
    /// Every recorded interaction.
    #[default]
    All,
    /// Blocked interactions only.
    Blocked,
    /// None (digests only).
    None,
}

impl BodyCapture {
    /// Whether an interaction that ended in `outcome` keeps its text.
    pub fn keeps(
        self,
        outcome: RecordOutcome,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Blocked => outcome == RecordOutcome::Blocked,
            Self::None => false,
        }
    }

    /// Whether any interaction keeps its text, so text must be gathered before
    /// the outcome is known (the realtime relay's turn audio).
    pub fn keeps_any(self) -> bool {
        self != Self::None
    }
}

impl Serialize for BodyCapture {
    fn serialize<S: Serializer>(
        &self,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match self {
            Self::All => serializer.serialize_bool(true),
            Self::None => serializer.serialize_bool(false),
            Self::Blocked => serializer.serialize_str("blocked"),
        }
    }
}

impl<'de> Deserialize<'de> for BodyCapture {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Mode {
            All,
            Blocked,
            None,
        }
        #[derive(Deserialize)]
        #[serde(untagged)]
        enum Wire {
            Flag(bool),
            Mode(Mode),
        }
        Ok(
            match Wire::deserialize(deserializer).map_err(|_| {
                serde::de::Error::custom("capture_bodies must be true, false, \"all\", \"blocked\" or \"none\"")
            })? {
                Wire::Flag(true) | Wire::Mode(Mode::All) => Self::All,
                Wire::Flag(false) | Wire::Mode(Mode::None) => Self::None,
                Wire::Mode(Mode::Blocked) => Self::Blocked,
            },
        )
    }
}

/// Which interactions a surface records at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordScope {
    /// Every interaction.
    #[default]
    All,
    /// Blocked interactions only.
    Blocked,
    /// Blocked and failed interactions.
    BlockedAndFailed,
}

impl RecordScope {
    /// Whether an interaction that ended in `outcome` is recorded.
    pub fn records(
        self,
        outcome: RecordOutcome,
    ) -> bool {
        match self {
            Self::All => true,
            Self::Blocked => outcome == RecordOutcome::Blocked,
            Self::BlockedAndFailed => outcome != RecordOutcome::Ok,
        }
    }

    fn is_all(&self) -> bool {
        *self == Self::All
    }
}

/// What one capture applies, resolved from the surface's recording block:
/// which interactions are recorded, which keep their text, and the local
/// retention window the store enforces on write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct CapturePolicy {
    pub bodies: BodyCapture,
    pub outcomes: RecordScope,
    /// Days records are kept locally; `0` keeps them indefinitely.
    pub retention_days: u32,
}

impl CapturePolicy {
    /// Record everything and keep no text.
    pub fn digests_only() -> Self {
        Self {
            bodies: BodyCapture::None,
            ..Self::default()
        }
    }
}

/// Per-surface signed-governance-recording configuration. Off by default; when
/// enabled, every interaction on the surface (or, with `record_outcomes`, every
/// blocked or failed one) produces one signed VC record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GovernanceRecordingConfig {
    /// Master switch. When `false` the block round-trips but nothing is recorded.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Which recorded interactions keep their prompt and completion text
    /// (default all; `true`/`false` read as all/none). The rest record digests
    /// and stage evidence only.
    #[serde(default)]
    pub capture_bodies: BodyCapture,

    /// Which interactions are recorded: `all` (default), `blocked`, or
    /// `blocked_and_failed`.
    #[serde(default, skip_serializing_if = "RecordScope::is_all")]
    pub record_outcomes: RecordScope,

    /// Buffer-and-sign streamed interactions too (reassemble SSE server-side).
    /// When `false`, streamed requests on this surface are not recorded.
    #[serde(default = "default_true")]
    pub include_streaming: bool,

    /// Local retention window in days: older records are pruned behind a
    /// signed chain anchor. `0` keeps records indefinitely.
    #[serde(default)]
    pub retention_days: u32,

    /// Optional export targets (OpenTelemetry and/or integrations), in addition
    /// to the local store. `None` = local-only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub export: Option<GovernanceExport>,
}

impl Default for GovernanceRecordingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            capture_bodies: BodyCapture::All,
            record_outcomes: RecordScope::All,
            include_streaming: true,
            retention_days: 0,
            export: None,
        }
    }
}

impl GovernanceRecordingConfig {
    /// Whether recording is active (the block exists and is enabled).
    pub fn is_active(&self) -> bool {
        self.enabled
    }

    /// The policy a capture on this surface applies.
    pub fn capture_policy(&self) -> CapturePolicy {
        CapturePolicy {
            bodies: self.capture_bodies,
            outcomes: self.record_outcomes,
            retention_days: self.retention_days,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_full_capture() {
        let cfg = GovernanceRecordingConfig::default();
        assert!(cfg.enabled);
        assert_eq!(cfg.capture_bodies, BodyCapture::All);
        assert_eq!(cfg.record_outcomes, RecordScope::All);
        assert!(cfg.include_streaming);
        assert_eq!(cfg.retention_days, 0);
        assert!(cfg.export.is_none());
    }

    #[test]
    fn minimal_json_fills_defaults() {
        let cfg: GovernanceRecordingConfig = serde_json::from_str("{}").unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.capture_bodies, BodyCapture::All);
        assert_eq!(cfg.record_outcomes, RecordScope::All);
        assert!(cfg.include_streaming);
    }

    #[test]
    fn export_round_trips() {
        let json = r#"{
            "enabled": true,
            "capture_bodies": true,
            "include_streaming": false,
            "retention_days": 90,
            "export": { "otel": true, "integrations": ["wh-1", "kafka-2"] }
        }"#;
        let cfg: GovernanceRecordingConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.include_streaming);
        assert_eq!(cfg.retention_days, 90);
        let export = cfg.export.as_ref().unwrap();
        assert!(export.otel);
        assert_eq!(export.integrations, vec!["wh-1".to_string(), "kafka-2".to_string()]);
        assert!(!export.is_empty());

        // Round-trips back to JSON without losing fields.
        let reser = serde_json::to_value(&cfg).unwrap();
        assert_eq!(reser["export"]["otel"], true);
        assert_eq!(reser["export"]["integrations"][1], "kafka-2");
    }

    #[test]
    fn disabled_block_round_trips() {
        let cfg = GovernanceRecordingConfig {
            enabled: false,
            ..Default::default()
        };
        assert!(!cfg.is_active());
        let v = serde_json::to_value(&cfg).unwrap();
        let back: GovernanceRecordingConfig = serde_json::from_value(v).unwrap();
        assert!(!back.enabled);
    }

    #[test]
    fn a_boolean_body_capture_keeps_its_meaning_and_its_shape() {
        for (wire, mode) in [(true, BodyCapture::All), (false, BodyCapture::None)] {
            let cfg: GovernanceRecordingConfig =
                serde_json::from_value(serde_json::json!({ "capture_bodies": wire })).unwrap();
            assert_eq!(cfg.capture_bodies, mode);
            let back = serde_json::to_value(&cfg).unwrap();
            assert_eq!(back["capture_bodies"], wire, "written back as the boolean it was");
            assert!(
                back.get("record_outcomes")
                    .is_none(),
                "the default scope is not written"
            );
        }
    }

    #[test]
    fn body_capture_and_record_scope_read_their_named_modes() {
        let cfg: GovernanceRecordingConfig = serde_json::from_value(serde_json::json!({
            "capture_bodies": "blocked",
            "record_outcomes": "blocked_and_failed"
        }))
        .unwrap();
        assert_eq!(cfg.capture_bodies, BodyCapture::Blocked);
        assert_eq!(cfg.record_outcomes, RecordScope::BlockedAndFailed);
        let back = serde_json::to_value(&cfg).unwrap();
        assert_eq!(back["capture_bodies"], "blocked");
        assert_eq!(back["record_outcomes"], "blocked_and_failed");

        for (wire, mode) in [("all", BodyCapture::All), ("none", BodyCapture::None)] {
            let cfg: GovernanceRecordingConfig =
                serde_json::from_value(serde_json::json!({ "capture_bodies": wire })).unwrap();
            assert_eq!(cfg.capture_bodies, mode);
        }
    }

    #[test]
    fn unknown_capture_modes_are_refused() {
        for bad in [serde_json::json!("failed"), serde_json::json!(1), serde_json::json!("Blocked")] {
            assert!(
                serde_json::from_value::<GovernanceRecordingConfig>(serde_json::json!({ "capture_bodies": bad }))
                    .is_err()
            );
        }
        assert!(
            serde_json::from_value::<GovernanceRecordingConfig>(serde_json::json!({ "record_outcomes": "ok" }))
                .is_err()
        );
    }

    #[test]
    fn modes_decide_per_outcome() {
        use RecordOutcome::{Blocked, Failed, Ok};
        assert!(
            [Ok, Blocked, Failed]
                .iter()
                .all(|o| BodyCapture::All.keeps(*o))
        );
        assert!(
            ![Ok, Blocked, Failed]
                .iter()
                .any(|o| BodyCapture::None.keeps(*o))
        );
        assert!(BodyCapture::Blocked.keeps(Blocked));
        assert!(!BodyCapture::Blocked.keeps(Ok) && !BodyCapture::Blocked.keeps(Failed));
        assert!(BodyCapture::Blocked.keeps_any() && !BodyCapture::None.keeps_any());

        assert!(
            [Ok, Blocked, Failed]
                .iter()
                .all(|o| RecordScope::All.records(*o))
        );
        assert!(RecordScope::Blocked.records(Blocked));
        assert!(!RecordScope::Blocked.records(Failed) && !RecordScope::Blocked.records(Ok));
        assert!(RecordScope::BlockedAndFailed.records(Blocked) && RecordScope::BlockedAndFailed.records(Failed));
        assert!(!RecordScope::BlockedAndFailed.records(Ok));
    }

    #[test]
    fn the_capture_policy_carries_the_block() {
        let cfg = GovernanceRecordingConfig {
            capture_bodies: BodyCapture::Blocked,
            record_outcomes: RecordScope::Blocked,
            retention_days: 7,
            ..Default::default()
        };
        assert_eq!(
            cfg.capture_policy(),
            CapturePolicy {
                bodies: BodyCapture::Blocked,
                outcomes: RecordScope::Blocked,
                retention_days: 7,
            }
        );
    }
}
