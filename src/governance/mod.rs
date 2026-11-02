//! Signed governance records for LLM surfaces.
//!
//! Captures a cryptographically signed, tamper-evident transcript of each
//! interaction that traverses an LLM Surface — the caller's input prompt, the
//! intermediate processing stages, and the model's output completion — attested
//! by the appliance's own DID as a W3C Verifiable Credential.
//!
//! See `docs/GOVERNANCE_RECORDS.md` for the north-star design. This module is
//! the phase-1 foundation: the record schema, canonical hashing, the per-surface
//! hash chain, the VC envelope + signer, and the encrypted append-only store.
//! Pipeline capture wiring and the read/verify API land in later phases, so some
//! of the record/digest surface is intentionally ahead of its first caller.
#![allow(dead_code, unused_imports)]

mod anchor;
mod attribution;
mod capture;
mod config;
mod credential;
mod index;
mod multimedia_store;
mod record;
mod retention;
mod sink;
mod store;

pub use anchor::ChainAnchor;
pub use attribution::{CallerIdentityKind, CallerKey, UsageAttribution};
pub use capture::{
    CaptureInput, InteractionOutcome, capture, capture_failure, capture_failure_with_metrics, capture_policy_denial,
    capture_with_id, init_store, is_ready, new_record_id, store,
};
pub use config::{BodyCapture, CapturePolicy, GovernanceExport, GovernanceRecordingConfig, RecordScope};
pub use credential::{GovernanceSigner, build_record_credential};
pub use multimedia_store::{
    MediaRef, MultimediaStore, extract_and_store, extract_refs, global_multimedia_store,
    init_store as init_multimedia_store,
};
pub use record::{
    GENESIS_HASH, GovernanceRecord, LlmCall, RecordMetrics, RecordOutcome, StageEntry, StageOutcome, StageUsageEntry,
    USAGE_CURRENCY,
};
pub use retention::periodic_retention_sweep;
pub use store::{
    ChainProblem, ChainSummary, GovernanceStore, RecordOrder, RecordPage, RecordQuery, StoredRecord, TenantFilter,
    archived_surface_id, chain_problem,
};
