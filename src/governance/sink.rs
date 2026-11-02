//! Export of signed governance records to operator-configured targets — the
//! OpenTelemetry log/trace exporter and/or any number of configured integrations
//! (webhook, Slack, email, Kafka/Kinesis/Pulsar/Redis stream, Langfuse) — in
//! addition to the durable local store. Best-effort and asynchronous: a delivery
//! failure is logged but never affects the request nor the local record.

use std::collections::HashMap;

use tracing::{info, warn};

use super::config::GovernanceExport;
use super::store::StoredRecord;

/// Export a stored (signed) record to every configured target. Best-effort; any
/// failure is logged and swallowed.
pub async fn export(
    export: &GovernanceExport,
    stored: &StoredRecord,
) {
    if export.otel {
        emit_otel(stored);
    }
    for integration_id in &export.integrations {
        dispatch_integration(integration_id, stored).await;
    }
}

/// Emit the signed record as a structured tracing event so it reaches the
/// OpenTelemetry log exporter (target `governance_record`).
fn emit_otel(stored: &StoredRecord) {
    let vc = serde_json::to_string(&stored.signed_vc).unwrap_or_default();
    info!(
        target: "governance_record",
        record_id = %stored.record.record_id,
        surface_id = %stored.record.surface_id,
        content_hash = stored
            .record
            .content_hash
            .as_deref()
            .unwrap_or(""),
        prev_record_hash = %stored.record.prev_record_hash,
        vc = %vc,
        "governance record"
    );
}

/// Dispatch the signed record through a configured integration. The integration
/// publisher (webhook, Slack, email, stream, Langfuse) renders its own content
/// template using the governance runtime variables exposed here; the signed VC
/// is passed as the message body for templates that emit it verbatim.
async fn dispatch_integration(
    integration_id: &str,
    stored: &StoredRecord,
) {
    let record = &stored.record;
    let credential = serde_json::to_string(&stored.signed_vc).unwrap_or_default();
    let record_json = serde_json::to_string(record).unwrap_or_default();

    let subject = format!(
        "Governance record {} for surface {}",
        record.record_id,
        record
            .surface_name
            .as_deref()
            .unwrap_or(&record.surface_id)
    );

    let mut variables: HashMap<String, String> = HashMap::new();
    variables.insert("EVENT_TYPE".to_string(), "governance.record".to_string());
    variables.insert("RECORD_ID".to_string(), record.record_id.clone());
    variables.insert("SURFACE_ID".to_string(), record.surface_id.clone());
    variables.insert(
        "SURFACE_NAME".to_string(),
        record
            .surface_name
            .clone()
            .unwrap_or_default(),
    );
    variables.insert(
        "CONTENT_HASH".to_string(),
        record
            .content_hash
            .clone()
            .unwrap_or_default(),
    );
    variables.insert(
        "PREV_RECORD_HASH".to_string(),
        record
            .prev_record_hash
            .clone(),
    );
    variables.insert("TIMESTAMP".to_string(), record.timestamp.clone());
    variables.insert("CREDENTIAL".to_string(), credential.clone());
    variables.insert("RECORD".to_string(), record_json);
    variables.insert("NEW_STATE".to_string(), credential.clone());

    if let Err(e) =
        crate::integrations::trigger_integration_with_variables(integration_id, &subject, &credential, &variables).await
    {
        warn!(integration_id = %integration_id, error = %e, "governance integration export failed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::record::{GENESIS_HASH, GovernanceRecord, RecordMetrics};
    use serde_json::Value;

    fn stored() -> StoredRecord {
        let mut record = GovernanceRecord {
            record_id: "rec-1".to_string(),
            trace_id: None,
            surface_id: "surf-1".to_string(),
            surface_name: None,
            caller_identity_hash: None,
            caller_identity_kind: None,
            principal_key: None,
            attribution: Default::default(),
            timestamp: "2026-08-12T00:00:00Z".to_string(),
            prev_record_hash: GENESIS_HASH.to_string(),
            stages: vec![],
            prompt: None,
            completion: None,
            attachments: Vec::new(),
            metrics: RecordMetrics::default(),
            content_hash: None,
        };
        record.finalize();
        StoredRecord {
            record,
            signed_vc: Value::Null,
            seq: None,
        }
    }

    #[tokio::test]
    async fn otel_export_does_not_panic() {
        let targets = GovernanceExport {
            otel: true,
            integrations: vec![],
        };
        export(&targets, &stored()).await;
    }

    #[tokio::test]
    async fn empty_export_is_noop() {
        let targets = GovernanceExport::default();
        assert!(targets.is_empty());
        export(&targets, &stored()).await;
    }

    #[tokio::test]
    async fn unknown_integration_is_swallowed() {
        // No integration store is installed in unit tests, so dispatch fails
        // internally and is logged; export must still return cleanly.
        let targets = GovernanceExport {
            otel: false,
            integrations: vec!["does-not-exist".to_string()],
        };
        export(&targets, &stored()).await;
    }
}
