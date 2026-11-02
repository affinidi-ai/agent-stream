//! Appliance-wide defaults for LLM surfaces (bootstrap config `[surface_defaults]`).
//!
//! One setting sends every LLM surface's governance records and `pipe` events to
//! the same integrations, so a surface added later is not silently left out of an
//! observer's data. The defaults are applied in memory when a surface is loaded for
//! the data plane ([`PipeConfig::with_surface_defaults`]); the saved surface
//! configuration is never rewritten, so the surface editor still shows only what
//! the surface itself says.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};

use super::config::{PipeConfig, PipeIntegrationMapping, PipeType};
use crate::governance::{BodyCapture, GovernanceExport, GovernanceRecordingConfig, RecordScope};

fn default_true() -> bool {
    true
}

/// `[surface_defaults]` in the bootstrap `config.toml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurfaceDefaultsConfig {
    /// Turn governance recording on for every LLM surface that has no
    /// `governance_recording` block of its own. A surface with its own block
    /// (including one with `enabled = false`) keeps its choice.
    #[serde(default)]
    pub governance_recording: bool,
    /// Which interactions keep their prompt and completion text on surfaces
    /// recorded by default (`true` all, `false` none, `"blocked"` blocks only).
    #[serde(default)]
    pub capture_bodies: BodyCapture,
    /// Which interactions surfaces recorded by default record (`all`,
    /// `blocked`, `blocked_and_failed`).
    #[serde(default)]
    pub record_outcomes: RecordScope,
    /// Record streamed interactions on surfaces recorded by default.
    #[serde(default = "default_true")]
    pub include_streaming: bool,
    /// Local rotation window in days for surfaces recorded by default (`0` = keep).
    #[serde(default)]
    pub retention_days: u32,
    /// Export targets added to every recording surface's own export (OpenTelemetry
    /// and/or integration ids), merged with it.
    #[serde(default)]
    pub governance_export: GovernanceExport,
    /// `pipe` event integrations added to every LLM surface, merged with the
    /// surface's own mappings (an integration the surface already maps gains any
    /// missing event types).
    #[serde(default)]
    pub pipe_integrations: Vec<PipeIntegrationMapping>,
}

impl Default for SurfaceDefaultsConfig {
    fn default() -> Self {
        Self {
            governance_recording: false,
            capture_bodies: BodyCapture::All,
            record_outcomes: RecordScope::All,
            include_streaming: true,
            retention_days: 0,
            governance_export: GovernanceExport::default(),
            pipe_integrations: Vec::new(),
        }
    }
}

static SURFACE_DEFAULTS: OnceLock<SurfaceDefaultsConfig> = OnceLock::new();

/// Register the appliance-wide surface defaults. First write wins.
pub fn set_surface_defaults(defaults: SurfaceDefaultsConfig) {
    let _ = SURFACE_DEFAULTS.set(defaults);
}

/// Union of two export targets.
fn merge_export(
    own: Option<GovernanceExport>,
    default: &GovernanceExport,
) -> Option<GovernanceExport> {
    if default.is_empty() {
        return own;
    }
    let mut merged = own.unwrap_or_default();
    merged.otel |= default.otel;
    for id in &default.integrations {
        if !merged
            .integrations
            .contains(id)
        {
            merged
                .integrations
                .push(id.clone());
        }
    }
    Some(merged)
}

impl PipeConfig {
    /// This surface with the appliance-wide defaults applied (see
    /// [`SurfaceDefaultsConfig`]). Only LLM surfaces are affected.
    pub fn with_surface_defaults(
        mut self,
        defaults: &SurfaceDefaultsConfig,
    ) -> Self {
        if !matches!(self.pipe_type, PipeType::LLM { .. }) {
            return self;
        }
        match self
            .governance_recording
            .as_mut()
        {
            None if defaults.governance_recording => {
                self.governance_recording = Some(GovernanceRecordingConfig {
                    enabled: true,
                    capture_bodies: defaults.capture_bodies,
                    record_outcomes: defaults.record_outcomes,
                    include_streaming: defaults.include_streaming,
                    retention_days: defaults.retention_days,
                    export: merge_export(None, &defaults.governance_export),
                });
            }
            Some(own) if own.enabled => {
                own.export = merge_export(own.export.take(), &defaults.governance_export);
            }
            _ => {}
        }
        for default in &defaults.pipe_integrations {
            match self
                .integrations
                .iter_mut()
                .find(|m| m.integration_id == default.integration_id)
            {
                Some(existing) => {
                    for event in &default.event_types {
                        if !existing
                            .event_types
                            .contains(event)
                        {
                            existing
                                .event_types
                                .push(event.clone());
                        }
                    }
                }
                None => self
                    .integrations
                    .push(default.clone()),
            }
        }
        self
    }

    /// [`Self::with_surface_defaults`] with the registered appliance defaults.
    pub fn with_global_surface_defaults(self) -> Self {
        match SURFACE_DEFAULTS.get() {
            Some(defaults) => self.with_surface_defaults(defaults),
            None => self,
        }
    }

    /// Whether this surface records governance (own block or default), exports
    /// those records anywhere beyond the local store, and maps any `pipe` event
    /// integration. Computed on the surface as saved plus the registered defaults.
    pub fn export_coverage(&self) -> SurfaceExportCoverage {
        let effective = self
            .clone()
            .with_global_surface_defaults();
        let recording = effective
            .governance_recording
            .as_ref()
            .filter(|g| g.enabled);
        SurfaceExportCoverage {
            governance_recording: recording.is_some(),
            governance_export: recording
                .and_then(|g| g.export.as_ref())
                .is_some_and(|e| !e.is_empty()),
            pipe_events: effective
                .integrations
                .iter()
                .any(|m| !m.event_types.is_empty()),
        }
    }
}

/// Whether a surface's records and events reach an observer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SurfaceExportCoverage {
    /// Governance recording is on (the surface's own block or the default).
    pub governance_recording: bool,
    /// Recorded interactions are exported beyond the local store.
    pub governance_export: bool,
    /// At least one integration is mapped to `pipe` events.
    pub pipe_events: bool,
}

impl SurfaceExportCoverage {
    /// True when recording or export is off (the surface is invisible to an observer).
    pub fn has_gap(&self) -> bool {
        !self.governance_recording || !self.governance_export
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn llm() -> PipeConfig {
        PipeConfig::new(
            "s1".into(),
            "S1".into(),
            PipeType::LLM {
                provider: Box::new(
                    serde_json::from_value(serde_json::json!({
                        "type": "openai", "provider_type": "openai", "model": "gpt-4o"
                    }))
                    .unwrap(),
                ),
                endpoint_path: None,
            },
        )
    }

    fn mapping(
        id: &str,
        events: &[&str],
    ) -> PipeIntegrationMapping {
        PipeIntegrationMapping {
            integration_id: id.into(),
            event_types: events
                .iter()
                .map(|e| e.to_string())
                .collect(),
            variables: serde_json::Value::Null,
        }
    }

    fn defaults() -> SurfaceDefaultsConfig {
        SurfaceDefaultsConfig {
            governance_recording: true,
            governance_export: GovernanceExport {
                otel: false,
                integrations: vec!["watch".into()],
            },
            pipe_integrations: vec![mapping("watch", &["pipe.executed", "pipe.error"])],
            ..Default::default()
        }
    }

    #[test]
    fn nothing_changes_without_defaults() {
        let out = llm().with_surface_defaults(&SurfaceDefaultsConfig::default());
        assert!(
            out.governance_recording
                .is_none()
        );
        assert!(out.integrations.is_empty());
    }

    #[test]
    fn surface_without_a_block_is_recorded_and_exported_by_default() {
        let out = llm().with_surface_defaults(&defaults());
        let rec = out
            .governance_recording
            .unwrap();
        assert!(rec.enabled && rec.capture_bodies == BodyCapture::All && rec.include_streaming);
        assert_eq!(rec.record_outcomes, RecordScope::All);
        assert_eq!(
            rec.export
                .unwrap()
                .integrations,
            vec!["watch".to_string()]
        );
        assert_eq!(out.integrations.len(), 1);
        assert_eq!(out.integrations[0].integration_id, "watch");
    }

    #[test]
    fn defaults_can_record_and_keep_text_for_blocks_only() {
        let defaults: SurfaceDefaultsConfig = toml::from_str(
            r#"
governance_recording = true
capture_bodies = "blocked"
record_outcomes = "blocked"
retention_days = 30
"#,
        )
        .unwrap();
        let rec = llm()
            .with_surface_defaults(&defaults)
            .governance_recording
            .unwrap();
        assert_eq!(rec.capture_bodies, BodyCapture::Blocked);
        assert_eq!(rec.record_outcomes, RecordScope::Blocked);
        assert_eq!(rec.retention_days, 30);

        let boolean: SurfaceDefaultsConfig = toml::from_str("capture_bodies = false").unwrap();
        assert_eq!(boolean.capture_bodies, BodyCapture::None, "a boolean keeps its meaning");
        assert_eq!(boolean.record_outcomes, RecordScope::All);
    }

    #[test]
    fn an_explicit_opt_out_is_kept_and_not_exported() {
        let mut pipe = llm();
        pipe.governance_recording = Some(GovernanceRecordingConfig {
            enabled: false,
            ..Default::default()
        });
        let out = pipe.with_surface_defaults(&defaults());
        let rec = out
            .governance_recording
            .unwrap();
        assert!(!rec.enabled);
        assert!(rec.export.is_none());
    }

    #[test]
    fn default_export_merges_with_the_surfaces_own() {
        let mut pipe = llm();
        pipe.governance_recording = Some(GovernanceRecordingConfig {
            export: Some(GovernanceExport {
                otel: true,
                integrations: vec!["own".into(), "watch".into()],
            }),
            ..Default::default()
        });
        let out = pipe.with_surface_defaults(&defaults());
        let export = out
            .governance_recording
            .unwrap()
            .export
            .unwrap();
        assert!(export.otel);
        assert_eq!(export.integrations, vec!["own".to_string(), "watch".to_string()]);
    }

    #[test]
    fn default_pipe_integrations_merge_event_types_without_duplicates() {
        let mut pipe = llm();
        pipe.integrations = vec![mapping("watch", &["pipe.executed"]), mapping("other", &["pipe.error"])];
        let out = pipe.with_surface_defaults(&defaults());
        assert_eq!(out.integrations.len(), 2);
        assert_eq!(out.integrations[0].event_types, vec!["pipe.executed".to_string(), "pipe.error".to_string()]);
        assert_eq!(out.integrations[1].event_types, vec!["pipe.error".to_string()]);
    }

    #[test]
    fn non_llm_surfaces_are_untouched() {
        let pipe = PipeConfig::new(
            "w".into(),
            "W".into(),
            PipeType::Webhook {
                endpoint: "https://x.test".into(),
            },
        );
        let out = pipe.with_surface_defaults(&defaults());
        assert!(
            out.governance_recording
                .is_none()
        );
        assert!(out.integrations.is_empty());
    }

    #[test]
    fn coverage_flags_recording_and_export_gaps() {
        let off = SurfaceExportCoverage {
            governance_recording: false,
            governance_export: false,
            pipe_events: false,
        };
        assert!(off.has_gap());
        let recorded_local_only = SurfaceExportCoverage {
            governance_recording: true,
            governance_export: false,
            pipe_events: true,
        };
        assert!(recorded_local_only.has_gap());
        let full = SurfaceExportCoverage {
            governance_recording: true,
            governance_export: true,
            pipe_events: true,
        };
        assert!(!full.has_gap());
    }
}
