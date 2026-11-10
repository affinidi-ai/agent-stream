//! Encrypted, append-only, per-surface store for signed governance records.
//!
//! Each surface has its own worker task, which owns that surface's files: for
//! each record it assigns the surface's chain head to `prev_record_hash`,
//! finalizes the content hash, signs the record into a VC, encrypts the line,
//! appends it to the log and its entry to the index, and advances the head.
//! Serializing a surface's writes through its worker keeps its hash chain
//! correct under concurrency, and slow work on one surface (indexing a large
//! log, pruning) never holds up another. The request thread only enqueues and
//! awaits a reply.
//!
//! Beside each surface's log the worker keeps its record index (`index.rs`), so
//! filtered, paged and single-record reads touch only the records they answer.
//! Retention prunes a surface's oldest records behind a signed chain anchor
//! (`anchor.rs`); verification then starts from the anchor instead of genesis.
//! Verification checks every record's signature, the index and the chain head
//! as well as the hash chain.
//!
//! Layout per surface: `records.jsonl` (one encrypted line per record),
//! `index.jsonl`, `chain-head.json`, `retention.json` (the surface's last
//! retention window) and, once records have been pruned, `anchor.json`. The
//! root keeps `signing-keys.jsonl`, each key records have been signed with. A
//! deleted surface's directory is archived as `<id>.deleted-<UTC time>`.

use std::collections::{HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::{Context, Result, anyhow};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tracing::{error, warn};

use crate::encryption::EncryptionService;
use crate::identity::ssi::vc_issuer::{verify_eddsa_jcs_2022, verify_eddsa_rdfc_2022};

use super::anchor::{AnchorLink, ChainAnchor, anchor_of};
use super::credential::{GOVERNANCE_CREDENTIAL_TYPE, GovernanceSigner};
use super::index::{Direction, ENTRY_WIDTH, Index, IndexEntry, stage_label, timestamp_ms};
use super::record::{GENESIS_HASH, GovernanceRecord, RecordOutcome};

const RECORDS_FILE: &str = "records.jsonl";
const INDEX_FILE: &str = "index.jsonl";
const HEAD_FILE: &str = "chain-head.json";
const ANCHOR_FILE: &str = "anchor.json";
const RETENTION_FILE: &str = "retention.json";
const KEYS_FILE: &str = "signing-keys.jsonl";

/// Separates a deleted surface's id from its deletion time in the name of its
/// archived directory. A surface id never holds a `.`.
const ARCHIVE_MARK: &str = ".deleted-";

/// How far a record's timestamp may trail its place in the log (it is taken
/// when the interaction ends, before the record queues for the writer). A scan
/// bounded by time stops only once it is this far past the bound.
const TIMESTAMP_SKEW_MS: i64 = 60 * 60 * 1000;

/// How far past its retention window a surface's oldest record may get before
/// it is pruned, so a busy surface rewrites its log at most about hourly.
const PRUNE_GRACE_MS: i64 = 60 * 60 * 1000;

const DAY_MS: i64 = 24 * 60 * 60 * 1000;

/// A record after it has been chained, signed, and persisted.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredRecord {
    /// The finalized record (with `prev_record_hash` + `content_hash` set).
    pub record: GovernanceRecord,
    /// The signed W3C VC wrapping the record (with its EdDSA proof).
    pub signed_vc: Value,
    /// The record's position on its surface's chain (1 for the first record
    /// ever written). Set when a record is read back or written; never part of
    /// the stored line, the record or its proof.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

/// Persisted chain head for a surface: the last record's hash and position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ChainHead {
    content_hash: String,
    count: u64,
    /// The head the chain had reached when a restart found the log ending
    /// before it, so its newest records are missing. Kept from then on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    missing_from: Option<HeadMark>,
}

/// A chain position: a record's `seq` and `content_hash`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct HeadMark {
    content_hash: String,
    count: u64,
}

impl ChainHead {
    fn genesis() -> Self {
        Self {
            content_hash: GENESIS_HASH.to_string(),
            count: 0,
            missing_from: None,
        }
    }
}

/// Which end of a surface's records a read starts from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecordOrder {
    /// Oldest first.
    #[default]
    Asc,
    /// Newest first.
    Desc,
}

/// Confines a read to the records of one tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantFilter {
    pub tenant_id: String,
    /// Records that name no tenant are the caller's when written at or after
    /// this time (unix milliseconds): the creation of the caller's surface.
    pub unattributed_since_ms: Option<i64>,
}

impl TenantFilter {
    fn admits(
        &self,
        record: &GovernanceRecord,
    ) -> bool {
        match record
            .attribution
            .tenant_id
            .as_deref()
        {
            Some(tenant_id) => tenant_id == self.tenant_id,
            None => self
                .unattributed_since_ms
                .is_some_and(|since| timestamp_ms(&record.timestamp).is_some_and(|ts| ts >= since)),
        }
    }
}

/// One read of a surface's records. Every filter is optional; together they
/// narrow the read.
///
/// `Asc` without a cursor keeps the established meaning of `limit`: the most
/// recent `limit` records, oldest first. A cursor is a record's `seq`: `Desc`
/// continues with the records before it, `Asc` with the records after it
/// (`cursor = 0` reads from the start).
#[derive(Debug, Clone, Default)]
pub struct RecordQuery {
    pub order: RecordOrder,
    /// Outcomes to keep; empty keeps every outcome.
    pub outcomes: Vec<RecordOutcome>,
    /// Labels of the stage that blocked or failed the interaction; empty keeps
    /// every record.
    pub stages: Vec<String>,
    /// Keep records at or after this time (unix milliseconds).
    pub since_ms: Option<i64>,
    /// Keep records before this time (unix milliseconds).
    pub until_ms: Option<i64>,
    pub cursor: Option<u64>,
    /// Most records answered; `None` answers every match.
    pub limit: Option<usize>,
    /// Keep only this tenant's records.
    pub tenant: Option<TenantFilter>,
}

impl RecordQuery {
    fn matches(
        &self,
        entry: &IndexEntry,
    ) -> bool {
        (self.outcomes.is_empty()
            || self
                .outcomes
                .contains(&entry.outcome))
            && (self.stages.is_empty()
                || entry
                    .stage
                    .as_ref()
                    .is_some_and(|stage| self.stages.contains(stage)))
            && self
                .since_ms
                .is_none_or(|since| {
                    entry
                        .ts
                        .is_some_and(|ts| ts >= since)
                })
            && self
                .until_ms
                .is_none_or(|until| {
                    entry
                        .ts
                        .is_some_and(|ts| ts < until)
                })
    }

    /// Whether a scan walking `direction` has gone past every record its time
    /// bounds can still admit.
    fn exhausted_at(
        &self,
        entry: &IndexEntry,
        direction: Direction,
    ) -> bool {
        let Some(ts) = entry.ts else {
            return false;
        };
        match direction {
            Direction::Backward => self
                .since_ms
                .is_some_and(|since| ts < since.saturating_sub(TIMESTAMP_SKEW_MS)),
            Direction::Forward => self
                .until_ms
                .is_some_and(|until| ts >= until.saturating_add(TIMESTAMP_SKEW_MS)),
        }
    }

    /// Where a scan of an index whose first entry is `first_seq`, holding
    /// `count` entries, starts, which way it walks, and whether it collects the
    /// newest matches to answer oldest first. `None` when nothing can match.
    fn plan(
        &self,
        first_seq: u64,
        count: u64,
    ) -> Option<(u64, Direction, bool)> {
        let last = count.checked_sub(1)?;
        let position = |seq: u64| seq.checked_sub(first_seq);
        match (self.order, self.cursor) {
            (RecordOrder::Desc, None) => Some((last, Direction::Backward, false)),
            (RecordOrder::Desc, Some(cursor)) => {
                let below = position(cursor.checked_sub(1)?)?;
                Some((below.min(last), Direction::Backward, false))
            }
            (RecordOrder::Asc, Some(cursor)) => {
                let after = position(cursor.saturating_add(1)).unwrap_or(0);
                (after <= last).then_some((after, Direction::Forward, false))
            }
            (RecordOrder::Asc, None) if self.limit.is_some() => Some((last, Direction::Backward, true)),
            (RecordOrder::Asc, None) => Some((0, Direction::Forward, false)),
        }
    }
}

/// One page of a records read.
#[derive(Debug, Default)]
pub struct RecordPage {
    pub records: Vec<StoredRecord>,
    /// The cursor for the next page: present only when another matching
    /// record exists beyond this page.
    pub next_cursor: Option<u64>,
}

/// The outcome of verifying a surface's chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainSummary {
    /// Records verified.
    pub count: u64,
    /// Sequence number of the first record kept.
    pub first_seq: Option<u64>,
    /// Sequence number of the last record.
    pub last_seq: Option<u64>,
    /// The retention anchor the chain was verified from, when records have
    /// been pruned.
    pub anchor: Option<ChainAnchor>,
    /// Records whose proof verified with a key the appliance signed with
    /// before its current one.
    pub previous_key_records: u64,
}

/// Why a surface's chain failed verification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChainProblem {
    /// A record, a chain link, a proof or the retention anchor does not hold,
    /// or a line is not stored as the store writes it.
    Broken,
    /// A proof names a key this appliance has no record of signing with.
    UnknownKey,
    /// The log ends before the chain head it once reached: its newest records
    /// are missing.
    Truncated,
    /// The record index disagrees with the log, so reads could miss or
    /// misreport records. The store rebuilds the index when it finds this.
    IndexMismatch,
}

/// A verification or read failure that names its [`ChainProblem`].
#[derive(Debug)]
pub struct ChainError {
    pub problem: ChainProblem,
    pub message: String,
}

impl std::fmt::Display for ChainError {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ChainError {}

fn chain_error(
    problem: ChainProblem,
    message: impl Into<String>,
) -> anyhow::Error {
    ChainError {
        problem,
        message: message.into(),
    }
    .into()
}

fn broken(message: impl Into<String>) -> anyhow::Error {
    chain_error(ChainProblem::Broken, message)
}

fn index_mismatch(message: impl Into<String>) -> anyhow::Error {
    chain_error(ChainProblem::IndexMismatch, message)
}

/// The [`ChainProblem`] behind `error`, when it is a chain failure rather than
/// a failure to read.
pub fn chain_problem(error: &anyhow::Error) -> Option<ChainProblem> {
    error
        .downcast_ref::<ChainError>()
        .map(|e| e.problem)
}

/// Whether `id` can name a live surface (a pipe id).
fn is_surface_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// The surface id an archived surface directory was deleted from, when `name`
/// is an archive name (`<id>.deleted-<YYYYMMDDTHHMMSSmmm>Z`, with `-<n>` added
/// when two deletions share a millisecond).
pub fn archived_surface_id(name: &str) -> Option<&str> {
    let (id, stamp) = name.split_once(ARCHIVE_MARK)?;
    let (time, counter) = stamp
        .split_once('-')
        .map_or((stamp, None), |(time, n)| (time, Some(n)));
    let digits = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_digit())
    };
    let well_formed = time.len() == 19
        && time.is_ascii()
        && digits(&time[..8])
        && &time[8..9] == "T"
        && digits(&time[9..18])
        && &time[18..] == "Z"
        && counter.is_none_or(digits);
    (well_formed && is_surface_id(id)).then_some(id)
}

/// The surface whose chain a directory holds: an archive's surface, else the
/// directory's own name.
fn chain_surface(surface_id: &str) -> &str {
    archived_surface_id(surface_id).unwrap_or(surface_id)
}

enum Job {
    Record { draft: Box<GovernanceRecord>, retention_days: u32, reply: oneshot::Sender<Result<StoredRecord>> },
    Prune { retention_days: u32, reply: oneshot::Sender<Result<Option<ChainAnchor>>> },
    Reconcile { rebuild: bool, reply: oneshot::Sender<Result<()>> },
    Archive { reply: oneshot::Sender<Result<Option<String>>> },
    Invalidate { reply: oneshot::Sender<()> },
}

/// A key the appliance has signed governance credentials with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct KnownKey {
    verification_method: String,
    /// The Ed25519 public key as a Multikey (`z6Mk...`).
    public_key: String,
}

impl KnownKey {
    fn new(
        verification_method: &str,
        key: &VerifyingKey,
    ) -> Self {
        Self {
            verification_method: verification_method.to_string(),
            public_key: multibase::encode(
                multibase::Base::Base58Btc,
                [&[0xed, 0x01], key.as_bytes().as_slice()].concat(),
            ),
        }
    }

    fn key(&self) -> Option<VerifyingKey> {
        let (_, bytes) = multibase::decode(&self.public_key).ok()?;
        let raw: [u8; 32] = bytes
            .strip_prefix(&[0xed, 0x01])?
            .try_into()
            .ok()?;
        VerifyingKey::from_bytes(&raw).ok()
    }
}

/// State shared by the store handles and the surface workers.
#[derive(Default)]
struct Shared {
    /// Held shared while a reader opens a surface's files and exclusively
    /// while retention swaps them or a surface is archived, so a reader never
    /// pairs an index with a log from either side of a prune. Open files
    /// outlive a swap.
    files: RwLock<()>,
    /// Each surface's append lock: held while a record's line and index entry
    /// are appended, and while a reader measures the surface's files, so a
    /// reader sees both or neither.
    appends: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Surfaces whose index has been brought in step with the log in this
    /// process. After that the surface's worker keeps it in step.
    reconciled: Mutex<HashSet<String>>,
    /// Each surface's worker.
    workers: Mutex<HashMap<String, mpsc::UnboundedSender<Job>>>,
    /// The signing keys recorded in `signing-keys.jsonl`, once read.
    keys: Mutex<Option<Vec<KnownKey>>>,
}

impl Shared {
    fn append_lock(
        &self,
        surface_id: &str,
    ) -> Result<Arc<Mutex<()>>> {
        let mut locks = self
            .appends
            .lock()
            .map_err(|_| anyhow!("governance store lock poisoned"))?;
        Ok(locks
            .entry(surface_id.to_string())
            .or_default()
            .clone())
    }

    fn is_reconciled(
        &self,
        surface_id: &str,
    ) -> bool {
        self.reconciled
            .lock()
            .map(|set| set.contains(surface_id))
            .unwrap_or(false)
    }

    fn set_reconciled(
        &self,
        surface_id: &str,
        reconciled: bool,
    ) {
        if let Ok(mut set) = self.reconciled.lock() {
            if reconciled {
                set.insert(surface_id.to_string());
            } else {
                set.remove(surface_id);
            }
        }
    }

    fn knows_key(
        &self,
        key: &KnownKey,
    ) -> bool {
        self.keys
            .lock()
            .map(|keys| {
                keys.as_ref()
                    .is_some_and(|keys| keys.contains(key))
            })
            .unwrap_or(false)
    }
}

/// Handle to the governance record store. Cheap to clone.
#[derive(Clone)]
pub struct GovernanceStore {
    root: PathBuf,
    encryption: Option<EncryptionService>,
    signer: GovernanceSigner,
    shared: Arc<Shared>,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for GovernanceStore {
    /// Make each surface's next record link to the chain head on disk, which
    /// the previous Active may have moved, instead of a head cached here.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.forget_cached_state()
            .await
            .map_err(std::io::Error::other)
    }
}

impl GovernanceStore {
    /// Create a store rooted at `root` (e.g. `_storage/governance`), signing with
    /// `signer` and optionally encrypting each line with `encryption`. Each
    /// surface's worker task starts on the surface's first job.
    pub fn new(
        root: impl Into<PathBuf>,
        signer: GovernanceSigner,
        encryption: Option<EncryptionService>,
    ) -> Self {
        Self {
            root: root.into(),
            encryption,
            signer,
            shared: Arc::new(Shared::default()),
        }
    }

    /// Chain, sign, and persist a record draft. Returns the stored record (the
    /// signed VC included). Awaits the surface's worker so the caller learns of
    /// any signing/IO failure, but the request thread does no signing/IO itself.
    /// The surface keeps `retention_days` as its retention window; a non-zero
    /// window prunes its expired records once its oldest is more than an hour
    /// past the window.
    pub async fn record(
        &self,
        draft: GovernanceRecord,
        retention_days: u32,
    ) -> Result<StoredRecord> {
        let surface_id = draft.surface_id.clone();
        let (reply, rx) = oneshot::channel();
        self.send(
            &surface_id,
            Job::Record {
                draft: Box::new(draft),
                retention_days,
                reply,
            },
        )?;
        rx.await
            .map_err(|_| anyhow!("governance store worker dropped the job"))?
    }

    /// Keep `retention_days` as `surface_id`'s retention window and prune its
    /// records older than that, once its oldest record is more than an hour
    /// past it, leaving a signed anchor in their place. Answers the new
    /// anchor, or `None` when nothing was due.
    pub async fn prune(
        &self,
        surface_id: &str,
        retention_days: u32,
    ) -> Result<Option<ChainAnchor>> {
        let (reply, rx) = oneshot::channel();
        self.send(surface_id, Job::Prune { retention_days, reply })?;
        rx.await
            .map_err(|_| anyhow!("governance store worker dropped the job"))?
    }

    /// Move a deleted surface's governance directory aside as
    /// `<id>.deleted-<UTC time>`, so a surface created later with the same id
    /// starts a new chain. Answers the archive's name, or `None` when the
    /// surface has no directory.
    pub async fn archive(
        &self,
        surface_id: &str,
    ) -> Result<Option<String>> {
        let (reply, rx) = oneshot::channel();
        self.send(surface_id, Job::Archive { reply })?;
        rx.await
            .map_err(|_| anyhow!("governance store worker dropped the job"))?
    }

    /// The retention window `surface_id` last recorded or was pruned with (0
    /// when it has none).
    pub fn retention_window(
        &self,
        surface_id: &str,
    ) -> u32 {
        read_window(&self.surface_dir(surface_id))
    }

    /// Queue `job` for the surface's worker, starting the worker when the
    /// surface has none.
    fn send(
        &self,
        surface_id: &str,
        job: Job,
    ) -> Result<()> {
        let mut workers = self
            .shared
            .workers
            .lock()
            .map_err(|_| anyhow!("governance store lock poisoned"))?;
        let job = match workers.get(surface_id) {
            Some(tx) => match tx.send(job) {
                Ok(()) => return Ok(()),
                Err(mpsc::error::SendError(job)) => job,
            },
            None => job,
        };
        let (tx, rx) = mpsc::unbounded_channel();
        let worker = Worker {
            surface_id: surface_id.to_string(),
            root: self.root.clone(),
            signer: self.signer.clone(),
            encryption: self.encryption.clone(),
            shared: self.shared.clone(),
            state: None,
            window: None,
        };
        tokio::spawn(worker.run(rx));
        tx.send(job)
            .map_err(|_| anyhow!("governance store worker is not running"))?;
        workers.insert(surface_id.to_string(), tx);
        Ok(())
    }

    /// Have the surface's worker bring its index in step with its log before
    /// the first read of it in this process (builds the index of a log written
    /// before indexes existed). Only that surface's work waits. Nothing to do
    /// for a surface with no log.
    async fn ensure_indexed(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        if self
            .shared
            .is_reconciled(surface_id)
            || !self
                .surface_dir(surface_id)
                .join(RECORDS_FILE)
                .exists()
        {
            return Ok(());
        }
        self.reconcile(surface_id, false)
            .await
    }

    /// Have the surface's worker rebuild its index from the log.
    async fn rebuild_index(
        &self,
        surface_id: &str,
    ) -> Result<()> {
        self.reconcile(surface_id, true)
            .await
    }

    async fn reconcile(
        &self,
        surface_id: &str,
        rebuild: bool,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.send(surface_id, Job::Reconcile { rebuild, reply })?;
        rx.await
            .map_err(|_| anyhow!("governance store worker dropped the job"))?
    }

    /// Drop every surface's cached chain head and retention window, and the
    /// cached signing keys, so the next use reads them from disk. Each worker
    /// applies it after the jobs already queued for it.
    async fn forget_cached_state(&self) -> Result<()> {
        let workers: Vec<_> = self
            .shared
            .workers
            .lock()
            .map_err(|_| anyhow!("governance store lock poisoned"))?
            .values()
            .cloned()
            .collect();
        for tx in workers {
            let (reply, rx) = oneshot::channel();
            if tx
                .send(Job::Invalidate { reply })
                .is_ok()
            {
                let _ = rx.await;
            }
        }
        *self
            .shared
            .keys
            .lock()
            .map_err(|_| anyhow!("governance store lock poisoned"))? = None;
        Ok(())
    }

    fn surface_dir(
        &self,
        surface_id: &str,
    ) -> PathBuf {
        self.root.join(surface_id)
    }

    /// List the surface ids that have a governance log on disk, archived
    /// surfaces included. Empty when the governance root does not yet exist.
    pub fn list_surfaces(&self) -> Result<Vec<String>> {
        let entries = match std::fs::read_dir(&self.root) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(e) => return Err(e).context("read governance root"),
        };
        let mut surfaces = Vec::new();
        for entry in entries.flatten() {
            let is_dir = entry
                .file_type()
                .map(|t| t.is_dir())
                .unwrap_or(false);
            if !is_dir {
                continue;
            }
            if let Some(name) = entry.file_name().to_str()
                && self
                    .surface_dir(name)
                    .join(RECORDS_FILE)
                    .exists()
            {
                surfaces.push(name.to_string());
            }
        }
        surfaces.sort();
        Ok(surfaces)
    }

    /// Read a page of a surface's records (see [`RecordQuery`]). Only the
    /// index is scanned; only the records answered (and, for a tenant read,
    /// the records the index admits) are read and decrypted. A line that does
    /// not decode is skipped and logged; an index that disagrees with the log
    /// is rebuilt and the read repeated. Empty when the surface has no log.
    /// Does not verify the chain.
    pub async fn query(
        &self,
        surface_id: &str,
        mut query: RecordQuery,
    ) -> Result<RecordPage> {
        self.ensure_indexed(surface_id)
            .await?;
        query.stages = query
            .stages
            .iter()
            .map(|stage| stage_label(stage))
            .collect();
        let query = Arc::new(query);
        self.read_repairing_index(surface_id, move |store, surface| store.run_query(surface, &query))
            .await
    }

    /// One record of a surface by its record id, or `None` (also when
    /// `tenant` does not admit it).
    pub async fn get(
        &self,
        surface_id: &str,
        record_id: &str,
        tenant: Option<TenantFilter>,
    ) -> Result<Option<StoredRecord>> {
        self.ensure_indexed(surface_id)
            .await?;
        let record_id: Arc<str> = record_id.into();
        let tenant = Arc::new(tenant);
        self.read_repairing_index(surface_id, move |store, surface| {
            store.find(surface, &record_id, tenant.as_ref().as_ref())
        })
        .await
    }

    /// Run `read` off the async workers; when it finds the index out of step
    /// with the log, rebuild the index and run it once more.
    async fn read_repairing_index<T: Send + 'static>(
        &self,
        surface_id: &str,
        read: impl Fn(&GovernanceStore, &str) -> Result<T> + Send + Sync + 'static,
    ) -> Result<T> {
        let read = Arc::new(read);
        let attempt = || {
            let store = self.clone();
            let surface = surface_id.to_string();
            let read = read.clone();
            blocking(move || read(&store, &surface))
        };
        match attempt().await {
            Err(e) if chain_problem(&e) == Some(ChainProblem::IndexMismatch) => {
                warn!(surface_id = %surface_id, error = %e, "rebuilding a governance index that disagrees with its log");
                self.rebuild_index(surface_id)
                    .await?;
                attempt().await
            }
            other => other,
        }
    }

    /// Read and decrypt just the most recent stored record for a surface (the
    /// last line of its log, read from the end), or `None` when the surface has
    /// no records. Does not verify the chain.
    pub fn latest_record(
        &self,
        surface_id: &str,
    ) -> Result<Option<StoredRecord>> {
        let Some(mut file) = open_existing(
            &self
                .surface_dir(surface_id)
                .join(RECORDS_FILE),
        )?
        else {
            return Ok(None);
        };
        let Some(line) = last_line(&mut file)? else {
            return Ok(None);
        };
        decode_line::<StoredRecord>(&self.encryption, &line)
            .context("parse latest governance record")
            .map(Some)
    }

    /// Verify a surface's whole chain, streaming its log. Every line must be
    /// stored as the store writes it (encrypted when the store encrypts) and
    /// parse; each record's `content_hash` must recompute and its
    /// `prev_record_hash` equal the prior record's `content_hash`; each
    /// record's signed credential must state the record and carry a proof that
    /// verifies with the appliance's current key or one it signed with before
    /// (`eddsa-jcs-2022`, or `eddsa-rdfc-2022` for records signed before it);
    /// and every index entry must describe its record. The first record links
    /// to genesis or, once records have been pruned, to the retention anchor or
    /// the anchor that one replaced, and the anchor must name this surface and
    /// carry a verifying proof. The log must reach the chain head. Failures
    /// carry a [`ChainProblem`]; an index that disagrees with the log is
    /// rebuilt after it is reported. Memory stays at one record.
    pub async fn verify_chain(
        &self,
        surface_id: &str,
    ) -> Result<ChainSummary> {
        self.ensure_indexed(surface_id)
            .await?;
        let keys = self.key_ring().await?;
        let store = self.clone();
        let surface = surface_id.to_string();
        let verdict = blocking(move || store.walk_chain(&surface, &keys)).await;
        if let Err(e) = &verdict
            && chain_problem(e) == Some(ChainProblem::IndexMismatch)
        {
            warn!(surface_id = %surface_id, error = %e, "rebuilding a governance index that disagrees with its log");
            if let Err(e) = self
                .rebuild_index(surface_id)
                .await
            {
                warn!(surface_id = %surface_id, error = %e, "failed to rebuild a governance index");
            }
        }
        verdict
    }

    /// The keys a proof may verify with: the signer's current key and every
    /// key recorded in `signing-keys.jsonl`.
    async fn key_ring(&self) -> Result<KeyRing> {
        let current = self
            .signer
            .verifying_key()
            .await
            .ok();
        let root = self.root.clone();
        let encryption = self.encryption.clone();
        let history = blocking(move || load_keys(&root, &encryption)).await?;
        Ok(KeyRing {
            current,
            issuer_did: self
                .signer
                .issuer_did()
                .to_string(),
            history,
        })
    }

    /// Open a consistent view of a surface's files: the index and log as far
    /// as both describe the same records, and (when `full`) the anchor and the
    /// chain head, read before the log is measured so the log reaches it.
    fn snapshot(
        &self,
        surface_id: &str,
        full: bool,
    ) -> Result<Snapshot> {
        let dir = self.surface_dir(surface_id);
        let _files = self
            .shared
            .files
            .read()
            .map_err(|_| anyhow!("governance store lock poisoned"))?;
        let appends = self
            .shared
            .append_lock(surface_id)?;
        let _appends = appends
            .lock()
            .map_err(|_| anyhow!("governance store lock poisoned"))?;
        let head = if full {
            read_head(&dir)
        } else {
            None
        };
        let records = open_existing(&dir.join(RECORDS_FILE))?;
        let records_len = match &records {
            Some(file) => file
                .metadata()
                .context("stat governance log")?
                .len(),
            None => 0,
        };
        Ok(Snapshot {
            index: Index::open(&dir.join(INDEX_FILE))?,
            records,
            records_len,
            anchor: if full {
                read_anchor_credential(&dir)?
            } else {
                None
            },
            head,
        })
    }

    fn run_query(
        &self,
        surface_id: &str,
        query: &RecordQuery,
    ) -> Result<RecordPage> {
        let snapshot = self.snapshot(surface_id, false)?;
        let (Some(mut index), Some(mut records)) = (snapshot.index, snapshot.records) else {
            return Ok(RecordPage::default());
        };
        if index.count() == 0 || query.limit == Some(0) {
            return Ok(RecordPage::default());
        }
        let first_seq = index.entry(0)?.seq;
        let Some((start, direction, newest_window)) = query.plan(first_seq, index.count()) else {
            return Ok(RecordPage::default());
        };
        let mut picked: Vec<StoredRecord> = Vec::new();
        let mut more = false;
        let mut previous: Option<IndexEntry> = None;
        index.scan(start, direction, |entry| {
            step(&mut previous, entry, direction)?;
            if query.exhausted_at(entry, direction) {
                return Ok(false);
            }
            if !query.matches(entry) {
                return Ok(true);
            }
            let full = query
                .limit
                .is_some_and(|limit| picked.len() >= limit);
            if full && (query.tenant.is_none() || newest_window) {
                more = true;
                return Ok(false);
            }
            let Some(stored) = read_record_at(&mut records, &self.encryption, entry)? else {
                return Ok(true);
            };
            if query
                .tenant
                .as_ref()
                .is_some_and(|tenant| !tenant.admits(&stored.record))
            {
                return Ok(true);
            }
            if full {
                more = true;
                return Ok(false);
            }
            picked.push(stored);
            Ok(true)
        })?;
        let next_cursor = if newest_window {
            picked.reverse();
            None
        } else if more {
            picked
                .last()
                .and_then(|stored| stored.seq)
        } else {
            None
        };
        Ok(RecordPage { records: picked, next_cursor })
    }

    fn find(
        &self,
        surface_id: &str,
        record_id: &str,
        tenant: Option<&TenantFilter>,
    ) -> Result<Option<StoredRecord>> {
        let snapshot = self.snapshot(surface_id, false)?;
        let (Some(mut index), Some(mut records)) = (snapshot.index, snapshot.records) else {
            return Ok(None);
        };
        let mut found = None;
        let mut previous: Option<IndexEntry> = None;
        index.scan(u64::MAX, Direction::Backward, |entry| {
            step(&mut previous, entry, Direction::Backward)?;
            if entry.id == record_id {
                found = Some(entry.clone());
                return Ok(false);
            }
            Ok(true)
        })?;
        let Some(entry) = found else {
            return Ok(None);
        };
        Ok(read_record_at(&mut records, &self.encryption, &entry)?
            .filter(|stored| tenant.is_none_or(|tenant| tenant.admits(&stored.record))))
    }

    /// The chain walk behind [`Self::verify_chain`].
    fn walk_chain(
        &self,
        surface_id: &str,
        keys: &KeyRing,
    ) -> Result<ChainSummary> {
        let snapshot = self.snapshot(surface_id, true)?;
        let anchor = snapshot
            .anchor
            .as_ref()
            .map(|credential| anchor_of(credential).map_err(|e| broken(format!("retention anchor: {e:#}"))))
            .transpose()?;
        if let Some(anchor) = &anchor
            && anchor.surface_id != chain_surface(surface_id)
        {
            return Err(broken(format!("retention anchor belongs to surface {}", anchor.surface_id)));
        }
        if let Some(credential) = &snapshot.anchor {
            keys.check(credential, "retention anchor")?;
        }
        let mut summary = ChainSummary {
            count: 0,
            first_seq: None,
            last_seq: None,
            anchor: anchor.clone(),
            previous_key_records: 0,
        };
        let mut index = snapshot.index;
        let mut position = 0u64;
        if let Some(file) = snapshot.records {
            let mut reader = BufReader::new(file.take(snapshot.records_len));
            let mut line = Vec::new();
            let mut off = 0u64;
            let mut expected_prev: Option<String> = None;
            let mut seq = 0u64;
            loop {
                line.clear();
                let read = reader
                    .read_until(b'\n', &mut line)
                    .context("read governance log")? as u64;
                if read == 0 {
                    break;
                }
                let start = off;
                off += read;
                let text = trim_line(&line);
                if text.is_empty() {
                    continue;
                }
                let at = match &expected_prev {
                    Some(_) => seq + 1,
                    None => anchor
                        .as_ref()
                        .map_or(1, |a| a.seq + 1),
                };
                let stored: StoredRecord = decode_line(&self.encryption, text)
                    .map_err(|e| broken(format!("record {at} cannot be read: {e:#}")))?;
                let record = &stored.record;
                match &expected_prev {
                    None => {
                        seq = chain_start(record, anchor.as_ref())?;
                        summary.first_seq = Some(seq);
                    }
                    Some(expected) => {
                        seq += 1;
                        if record.prev_record_hash != *expected {
                            return Err(broken(format!(
                                "chain break at record {}: prev_record_hash {} != expected {}",
                                seq, record.prev_record_hash, expected
                            )));
                        }
                    }
                }
                if !record.verify_content_hash() {
                    return Err(broken(format!("content hash mismatch at record {seq}")));
                }
                let hash = record
                    .content_hash
                    .clone()
                    .ok_or_else(|| broken(format!("record {seq} missing content_hash")))?;
                if let Some(anchor) = &anchor
                    && anchor.seq == seq
                    && anchor.content_hash != hash
                {
                    return Err(broken(format!("record {seq} does not match the retention anchor")));
                }
                if check_record_credential(&stored, seq, keys)? {
                    summary.previous_key_records += 1;
                }
                let leading = (line.len() - line.trim_ascii_start().len()) as u64;
                let expected_entry = IndexEntry::for_record(seq, start + leading, text.len() as u64, record);
                check_index_entry(index.as_mut(), position, &expected_entry)?;
                position += 1;
                expected_prev = Some(hash);
                summary.count += 1;
                summary.last_seq = Some(seq);
            }
        }
        if let Some(index) = &index
            && index.count() > position
        {
            return Err(index_mismatch(format!(
                "the index lists {} records past the end of the log",
                index.count() - position
            )));
        }
        if let (Some(anchor), Some(last)) = (&anchor, summary.last_seq)
            && last < anchor.seq
        {
            return Err(broken(format!(
                "retention anchor (record {}) is ahead of the chain (record {})",
                anchor.seq, last
            )));
        }
        let reached = summary
            .last_seq
            .or(anchor.as_ref().map(|a| a.seq))
            .unwrap_or(0);
        if let Some(head) = &snapshot.head {
            let lost = head
                .missing_from
                .as_ref()
                .map(|mark| mark.count)
                .or((head.count > reached).then_some(head.count));
            if let Some(lost) = lost {
                return Err(chain_error(
                    ChainProblem::Truncated,
                    format!(
                        "the log ends at record {reached}, but its chain once reached record {lost}: the newest records are missing"
                    ),
                ));
            }
        }
        Ok(summary)
    }
}

/// The keys a proof may verify with.
struct KeyRing {
    current: Option<VerifyingKey>,
    issuer_did: String,
    history: Vec<KnownKey>,
}

impl KeyRing {
    /// Check `credential`'s proof (`what` names it in a failure): `Ok(true)`
    /// when it verifies only with a previous key. A proof that verifies with
    /// no key is [`ChainProblem::Broken`] when it names one of this appliance's
    /// keys and [`ChainProblem::UnknownKey`] when it names another.
    fn check(
        &self,
        credential: &Value,
        what: &str,
    ) -> Result<bool> {
        let proof = &credential["proof"];
        if !proof.is_object() {
            return Err(broken(format!("{what} is unsigned")));
        }
        let suite = proof["cryptosuite"]
            .as_str()
            .unwrap_or_default();
        if !matches!(suite, "eddsa-jcs-2022" | "eddsa-rdfc-2022") {
            return Err(broken(format!("{what} has a proof of an unsupported suite")));
        }
        let verifies = |key: &VerifyingKey| match suite {
            "eddsa-jcs-2022" => verify_eddsa_jcs_2022(credential, key).is_ok(),
            _ => futures::executor::block_on(verify_eddsa_rdfc_2022(credential, key)).is_ok(),
        };
        if self
            .current
            .as_ref()
            .is_some_and(&verifies)
        {
            return Ok(false);
        }
        if self
            .history
            .iter()
            .filter_map(KnownKey::key)
            .filter(|key| Some(key) != self.current.as_ref())
            .any(|key| verifies(&key))
        {
            return Ok(true);
        }
        let method = proof_method(credential);
        let known = method.starts_with(&format!("{}#", self.issuer_did))
            || self
                .history
                .iter()
                .any(|key| key.verification_method == method);
        if known {
            Err(broken(format!("{what} proof does not verify")))
        } else {
            Err(chain_error(
                ChainProblem::UnknownKey,
                format!("{what} is signed by a key this appliance has no record of ({method})"),
            ))
        }
    }
}

/// The `verificationMethod` a credential's proof names (empty when none).
fn proof_method(credential: &Value) -> &str {
    let method = &credential["proof"]["verificationMethod"];
    method
        .as_str()
        .or_else(|| method["id"].as_str())
        .unwrap_or_default()
}

/// Check that a record's signed credential states the record and that its
/// proof verifies: `Ok(true)` when it verifies only with a previous key.
fn check_record_credential(
    stored: &StoredRecord,
    seq: u64,
    keys: &KeyRing,
) -> Result<bool> {
    let credential = &stored.signed_vc;
    let typed = credential["type"]
        .as_array()
        .is_some_and(|types| {
            types
                .iter()
                .any(|t| t == GOVERNANCE_CREDENTIAL_TYPE)
        });
    if !typed {
        return Err(broken(format!("record {seq} has no signed governance credential")));
    }
    let subject = &credential["credentialSubject"];
    let record = &stored.record;
    let states_record = subject["content_hash"].as_str() == record.content_hash.as_deref()
        && subject["record_id"] == record.record_id.as_str()
        && subject["timestamp"] == record.timestamp.as_str()
        && subject["surface_id"] == record.surface_id.as_str()
        && subject["prev_record_hash"]
            == record
                .prev_record_hash
                .as_str();
    if !states_record {
        return Err(broken(format!("record {seq} differs from its signed credential")));
    }
    keys.check(credential, &format!("record {seq}"))
}

/// Check the index entry at `position` against the entry the log's record
/// there makes.
fn check_index_entry(
    index: Option<&mut Index>,
    position: u64,
    expected: &IndexEntry,
) -> Result<()> {
    let entry = match index {
        Some(index) if position < index.count() => index.entry(position)?,
        _ => return Err(index_mismatch(format!("the index has no entry for record {}", expected.seq))),
    };
    if entry.same_as(expected)? {
        Ok(())
    } else {
        Err(index_mismatch(format!("the index entry for record {} does not match the log", expected.seq)))
    }
}

/// The sequence number of the first record of a log: 1 when it links to
/// genesis, else the one after the retention anchor it continues from, or
/// after the anchor that one replaced (a prune interrupted before its log was
/// swapped in).
fn chain_start(
    record: &GovernanceRecord,
    anchor: Option<&ChainAnchor>,
) -> Result<u64> {
    let prev = &record.prev_record_hash;
    let Some(anchor) = anchor else {
        if *prev == GENESIS_HASH {
            return Ok(1);
        }
        return Err(broken(format!(
            "chain break at record 1: prev_record_hash {prev} is not genesis and no retention anchor is kept"
        )));
    };
    if anchor.content_hash == *prev {
        return Ok(anchor.seq + 1);
    }
    match &anchor.prev_anchor {
        Some(before) if before.content_hash == *prev => Ok(before.seq + 1),
        None if *prev == GENESIS_HASH => Ok(1),
        _ => Err(broken(format!(
            "chain break at record {}: prev_record_hash {} does not continue from the retention anchor {}",
            anchor.seq + 1,
            prev,
            anchor.content_hash
        ))),
    }
}

/// A surface's files, opened together.
struct Snapshot {
    index: Option<Index>,
    records: Option<File>,
    /// The log's length when the index was opened: every record within it is
    /// indexed and the chain head describes one of them.
    records_len: u64,
    anchor: Option<Value>,
    head: Option<ChainHead>,
}

/// Per-surface state the worker keeps in memory.
#[derive(Clone)]
struct SurfaceState {
    head: ChainHead,
    /// Timestamp of the oldest record kept (unix milliseconds).
    oldest_ms: Option<i64>,
}

/// The task that owns one surface's files.
struct Worker {
    surface_id: String,
    root: PathBuf,
    signer: GovernanceSigner,
    encryption: Option<EncryptionService>,
    shared: Arc<Shared>,
    state: Option<SurfaceState>,
    /// The retention window kept in `retention.json`, once read.
    window: Option<u32>,
}

impl Worker {
    async fn run(
        mut self,
        mut rx: mpsc::UnboundedReceiver<Job>,
    ) {
        while let Some(job) = rx.recv().await {
            // A receiver may have gone away (caller timed out): ignore send errors.
            match job {
                Job::Record { draft, retention_days, reply } => {
                    let _ = reply.send(
                        self.record(*draft, retention_days)
                            .await,
                    );
                }
                Job::Prune { retention_days, reply } => {
                    let _ = reply.send(
                        self.prune(retention_days)
                            .await,
                    );
                }
                Job::Reconcile { rebuild, reply } => {
                    let _ = reply.send(
                        self.reconcile(rebuild)
                            .await
                            .map(|_| ()),
                    );
                }
                Job::Archive { reply } => {
                    let _ = reply.send(self.archive().await);
                }
                Job::Invalidate { reply } => {
                    self.invalidate();
                    self.window = None;
                    let _ = reply.send(());
                }
            }
        }
    }

    fn dir(&self) -> PathBuf {
        self.root
            .join(&self.surface_id)
    }

    /// The surface's state, reconciling its index with its log on first use.
    async fn state(&mut self) -> Result<SurfaceState> {
        match &self.state {
            Some(state) => Ok(state.clone()),
            None => self.reconcile(false).await,
        }
    }

    /// Bring the index in step with the log (rebuilding it from the log when
    /// `rebuild`) and take the surface's state from the log.
    async fn reconcile(
        &mut self,
        rebuild: bool,
    ) -> Result<SurfaceState> {
        if !rebuild && let Some(state) = &self.state {
            return Ok(state.clone());
        }
        let dir = self.dir();
        let encryption = self.encryption.clone();
        let state = blocking(move || reconcile(&dir, &encryption, rebuild)).await?;
        self.state = Some(state.clone());
        self.shared
            .set_reconciled(&self.surface_id, true);
        Ok(state)
    }

    /// Forget the surface's state so the next use reconciles it with the log.
    fn invalidate(&mut self) {
        self.state = None;
        self.shared
            .set_reconciled(&self.surface_id, false);
    }

    async fn record(
        &mut self,
        mut draft: GovernanceRecord,
        retention_days: u32,
    ) -> Result<StoredRecord> {
        let mut state = self.state().await?;

        draft.prev_record_hash = state
            .head
            .content_hash
            .clone();
        let content_hash = draft.finalize();
        let signed_vc = self
            .signer
            .sign_record(&draft)
            .await
            .context("sign governance record")?;
        self.note_key(&signed_vc)
            .await;
        let mut stored = StoredRecord {
            record: draft,
            signed_vc,
            seq: None,
        };
        let line = encode_line(&self.encryption, &stored)?;
        let seq = state.head.count + 1;

        let dir = self.dir();
        let appended = {
            let dir = dir.clone();
            let lock = self
                .shared
                .append_lock(&self.surface_id)?;
            let record = stored.record.clone();
            blocking(move || append_record(&dir, &lock, &line, seq, &record)).await
        };
        let (entry, indexed) = match appended {
            Ok(appended) => appended,
            Err(e) => {
                self.invalidate();
                return Err(e).context("append governance record");
            }
        };

        state.head = ChainHead {
            content_hash,
            count: seq,
            missing_from: state
                .head
                .missing_from
                .clone(),
        };
        if state.oldest_ms.is_none() {
            state.oldest_ms = entry.ts;
        }
        if let Err(e) = persist_head(&dir, &state.head).await {
            // The record is durably appended; the head is rebuilt from the log.
            warn!(surface_id = %self.surface_id, error = %e, "failed to persist governance chain head");
        }
        match indexed {
            Ok(()) => self.state = Some(state.clone()),
            Err(e) => {
                // The record is durably appended; the index catches up from the
                // log the next time the surface is used.
                warn!(surface_id = %self.surface_id, error = %e, "failed to index governance record");
                self.invalidate();
            }
        }
        stored.seq = Some(seq);
        self.remember_window(retention_days)
            .await;

        if retention_days > 0
            && prune_due(state.oldest_ms, retention_days)
            && let Err(e) = self
                .prune(retention_days)
                .await
        {
            warn!(surface_id = %self.surface_id, error = %e, "failed to prune governance records");
        }
        Ok(stored)
    }

    /// Keep `retention_days` in `retention.json` when it differs from the
    /// window kept there, so the surface's records are still pruned once the
    /// surface is deleted. Nothing is written for a surface with no directory.
    async fn remember_window(
        &mut self,
        retention_days: u32,
    ) {
        let dir = self.dir();
        let kept = match self.window {
            Some(kept) => kept,
            None => {
                let dir = dir.clone();
                blocking(move || Ok(read_window(&dir)))
                    .await
                    .unwrap_or(0)
            }
        };
        self.window = Some(kept);
        if kept == retention_days || !dir.exists() {
            return;
        }
        let json = serde_json::json!({ "retention_days": retention_days }).to_string();
        match tokio::fs::write(dir.join(RETENTION_FILE), json).await {
            Ok(()) => self.window = Some(retention_days),
            Err(e) => {
                warn!(surface_id = %self.surface_id, error = %e, "failed to keep the governance retention window")
            }
        }
    }

    /// Record the key `signed` was signed with in `signing-keys.jsonl`, unless
    /// it is there already.
    async fn note_key(
        &self,
        signed: &Value,
    ) {
        let method = proof_method(signed);
        if method.is_empty() {
            return;
        }
        let Ok(key) = self
            .signer
            .verifying_key()
            .await
        else {
            return;
        };
        let known = KnownKey::new(method, &key);
        if self.shared.knows_key(&known) {
            return;
        }
        let root = self.root.clone();
        let encryption = self.encryption.clone();
        let shared = self.shared.clone();
        if let Err(e) = blocking(move || record_key(&root, &encryption, &shared, known)).await {
            warn!(error = %e, "failed to record the governance signing key");
        }
    }

    async fn prune(
        &mut self,
        retention_days: u32,
    ) -> Result<Option<ChainAnchor>> {
        self.remember_window(retention_days)
            .await;
        if retention_days == 0 {
            return Ok(None);
        }
        let state = self.state().await?;
        if !prune_due(state.oldest_ms, retention_days) {
            return Ok(None);
        }
        let cutoff = chrono::Utc::now().timestamp_millis() - i64::from(retention_days) * DAY_MS;
        let dir = self.dir();
        let encryption = self.encryption.clone();
        let plan_now = move |dir: PathBuf, encryption: Option<EncryptionService>| {
            blocking(move || plan_prune(&dir, &encryption, cutoff))
        };
        let plan = match plan_now(dir.clone(), encryption.clone()).await {
            Err(e) if chain_problem(&e) == Some(ChainProblem::IndexMismatch) => {
                warn!(surface_id = %self.surface_id, error = %e, "rebuilding a governance index that disagrees with its log");
                self.reconcile(true).await?;
                plan_now(dir.clone(), encryption).await?
            }
            planned => planned?,
        };
        let Some(plan) = plan else {
            return Ok(None);
        };
        let anchor = ChainAnchor {
            surface_id: chain_surface(&self.surface_id).to_string(),
            seq: plan.last_seq,
            content_hash: plan.last_hash.clone(),
            timestamp: plan.last_timestamp.clone(),
            pruned_at: chrono::Utc::now().to_rfc3339(),
            retention_days,
            prev_anchor: plan.continues_from.clone(),
        };
        let credential = self
            .signer
            .sign_anchor(&anchor)
            .await?;
        self.note_key(&credential)
            .await;
        let applied = {
            let shared = self.shared.clone();
            blocking(move || apply_prune(&dir, &shared, &plan, &credential)).await
        };
        match applied {
            Ok(oldest_ms) => {
                if let Some(state) = &mut self.state {
                    state.oldest_ms = oldest_ms;
                }
                Ok(Some(anchor))
            }
            Err(e) => {
                self.invalidate();
                Err(e).context("prune governance records")
            }
        }
    }

    /// Move the surface's directory aside as `<id>.deleted-<UTC time>`.
    async fn archive(&mut self) -> Result<Option<String>> {
        let root = self.root.clone();
        let surface_id = self.surface_id.clone();
        let shared = self.shared.clone();
        let archived = blocking(move || archive_dir(&root, &surface_id, &shared)).await?;
        self.invalidate();
        self.window = None;
        Ok(archived)
    }
}

/// Rename `surface_id`'s directory to a new archive name, under the exclusive
/// file lock; `None` when it has no directory.
fn archive_dir(
    root: &Path,
    surface_id: &str,
    shared: &Shared,
) -> Result<Option<String>> {
    let dir = root.join(surface_id);
    if !dir.is_dir() {
        return Ok(None);
    }
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%S%3fZ");
    let mut name = format!("{surface_id}{ARCHIVE_MARK}{stamp}");
    let mut n = 1;
    while root.join(&name).exists() {
        n += 1;
        name = format!("{surface_id}{ARCHIVE_MARK}{stamp}-{n}");
    }
    let _files = shared
        .files
        .write()
        .map_err(|_| anyhow!("governance store lock poisoned"))?;
    std::fs::rename(&dir, root.join(&name)).context("archive governance surface directory")?;
    sync_dir(root)?;
    Ok(Some(name))
}

/// Whether a surface whose oldest record is at `oldest_ms` is due a prune.
fn prune_due(
    oldest_ms: Option<i64>,
    retention_days: u32,
) -> bool {
    let window = i64::from(retention_days) * DAY_MS + PRUNE_GRACE_MS;
    oldest_ms.is_some_and(|oldest| oldest < chrono::Utc::now().timestamp_millis() - window)
}

/// What a prune removes: the first `keep_from` index entries, the log bytes
/// before `base`, and the last removed record's position, hash and time; and
/// the anchor the log continues from before the prune (`None` for genesis).
struct PrunePlan {
    keep_from: u64,
    base: u64,
    last_seq: u64,
    last_hash: String,
    last_timestamp: String,
    continues_from: Option<AnchorLink>,
}

/// Plan the prune of every leading record older than `cutoff` (unix ms).
/// Refuses a log that continues from neither genesis nor its retention anchor,
/// so no anchor is ever signed over a chain that does not verify.
fn plan_prune(
    dir: &Path,
    encryption: &Option<EncryptionService>,
    cutoff: i64,
) -> Result<Option<PrunePlan>> {
    let (Some(mut index), Some(mut records)) =
        (Index::open(&dir.join(INDEX_FILE))?, open_existing(&dir.join(RECORDS_FILE))?)
    else {
        return Ok(None);
    };
    let mut expired = 0u64;
    index.scan(0, Direction::Forward, |entry| {
        if entry
            .ts
            .is_some_and(|ts| ts < cutoff)
        {
            expired += 1;
            return Ok(true);
        }
        Ok(false)
    })?;
    if expired == 0 {
        return Ok(None);
    }
    let read = |records: &mut File, position: u64, index: &mut Index| -> Result<GovernanceRecord> {
        let entry = index.entry(position)?;
        read_record_at(records, encryption, &entry)?
            .map(|stored| stored.record)
            .ok_or_else(|| anyhow!("governance record {} cannot be read", entry.seq))
    };
    let first = read(&mut records, 0, &mut index)?;
    let anchor = read_anchor_credential(dir)?
        .map(|credential| anchor_of(&credential))
        .transpose()?;
    let continues_from = continues_from(&first, anchor.as_ref())
        .context("not pruning a governance log that does not continue from its retention anchor")?;
    let last = index.entry(expired - 1)?;
    let record = read(&mut records, expired - 1, &mut index)?;
    let base = if expired < index.count() {
        let kept = read(&mut records, expired, &mut index)?;
        if Some(&kept.prev_record_hash) != record.content_hash.as_ref() {
            return Err(index_mismatch(format!(
                "not pruning: the index places record {} after a record it does not link to",
                last.seq + 1
            )));
        }
        index.entry(expired)?.off
    } else {
        records
            .metadata()
            .context("stat governance log")?
            .len()
    };
    Ok(Some(PrunePlan {
        keep_from: expired,
        base,
        last_seq: last.seq,
        last_hash: record
            .content_hash
            .ok_or_else(|| anyhow!("record {} missing content_hash", last.seq))?,
        last_timestamp: record.timestamp,
        continues_from,
    }))
}

/// The anchor a log whose first record is `first` continues from: `None` for
/// genesis, else the retention anchor or the one it replaced.
fn continues_from(
    first: &GovernanceRecord,
    anchor: Option<&ChainAnchor>,
) -> Result<Option<AnchorLink>> {
    chain_start(first, anchor)?;
    let Some(anchor) = anchor else {
        return Ok(None);
    };
    if anchor.content_hash == first.prev_record_hash {
        return Ok(Some(AnchorLink {
            seq: anchor.seq,
            content_hash: anchor.content_hash.clone(),
        }));
    }
    Ok(anchor
        .prev_anchor
        .clone()
        .filter(|before| before.content_hash == first.prev_record_hash))
}

/// Write the pruned log, its rebased index and the signed anchor beside the
/// live files, then swap all three in under the exclusive file lock: the
/// anchor first, made durable before the log is renamed, so an interrupted
/// swap leaves an anchor whose log still continues from the anchor it
/// replaced (which the new anchor names, so verification accepts it), never
/// kept records with no anchor. Answers the oldest kept record's timestamp.
fn apply_prune(
    dir: &Path,
    shared: &Shared,
    plan: &PrunePlan,
    anchor: &Value,
) -> Result<Option<i64>> {
    let staged = |name: &str| dir.join(format!("{name}.pruning"));

    let anchor_json = serde_json::to_vec_pretty(anchor).context("serialize retention anchor")?;
    write_synced(&staged(ANCHOR_FILE), |file| file.write_all(&anchor_json))?;

    let mut records = File::open(dir.join(RECORDS_FILE)).context("open governance log")?;
    records
        .seek(SeekFrom::Start(plan.base))
        .context("seek governance log")?;
    write_synced(&staged(RECORDS_FILE), |file| std::io::copy(&mut records, file).map(|_| ()))?;

    let mut index = Index::open(&dir.join(INDEX_FILE))?.ok_or_else(|| anyhow!("governance index is missing"))?;
    let rebased_path = staged(INDEX_FILE);
    let rebased = File::create(&rebased_path).with_context(|| format!("create {}", rebased_path.display()))?;
    let mut writer = BufWriter::new(&rebased);
    let mut oldest_ms = None;
    index.scan(plan.keep_from, Direction::Forward, |entry| {
        let mut entry = entry.clone();
        entry.off -= plan.base;
        if oldest_ms.is_none() {
            oldest_ms = entry.ts;
        }
        writer
            .write_all(&entry.encode()?)
            .context("write rebased governance index")?;
        Ok(true)
    })?;
    writer
        .flush()
        .context("write rebased governance index")?;
    drop(writer);
    rebased
        .sync_all()
        .context("sync rebased governance index")?;

    let _files = shared
        .files
        .write()
        .map_err(|_| anyhow!("governance store lock poisoned"))?;
    std::fs::rename(staged(ANCHOR_FILE), dir.join(ANCHOR_FILE)).context("install retention anchor")?;
    sync_dir(dir)?;
    for name in [RECORDS_FILE, INDEX_FILE] {
        std::fs::rename(staged(name), dir.join(name)).with_context(|| format!("install pruned {name}"))?;
    }
    sync_dir(dir)?;
    Ok(oldest_ms)
}

/// Make the renames in `dir` durable.
fn sync_dir(dir: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(dir)
        .and_then(|d| d.sync_all())
        .with_context(|| format!("sync {}", dir.display()))?;
    #[cfg(not(unix))]
    let _ = dir;
    Ok(())
}

/// Create `path`, fill it with `write`, and flush it to disk.
fn write_synced(
    path: &Path,
    write: impl FnOnce(&mut File) -> std::io::Result<()>,
) -> Result<()> {
    let mut file = File::create(path).with_context(|| format!("create {}", path.display()))?;
    write(&mut file).with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))
}

/// Move a scan walking `direction` from `previous` on to `entry`, refusing an
/// entry that cannot follow it ([`ChainProblem::IndexMismatch`]).
fn step(
    previous: &mut Option<IndexEntry>,
    entry: &IndexEntry,
    direction: Direction,
) -> Result<()> {
    if let Some(previous) = previous.as_ref()
        && !in_order(previous, entry, direction)
    {
        return Err(index_mismatch(format!(
            "the index entries for records {} and {} are out of order",
            previous.seq, entry.seq
        )));
    }
    *previous = Some(entry.clone());
    Ok(())
}

/// Whether `entry` can follow `previous` in a scan walking `direction`: the
/// next position, its line after the previous one's (before it, walking back).
fn in_order(
    previous: &IndexEntry,
    entry: &IndexEntry,
    direction: Direction,
) -> bool {
    match direction {
        Direction::Forward => entry.seq == previous.seq + 1 && entry.off >= previous.end(),
        Direction::Backward => entry.seq + 1 == previous.seq && entry.end() <= previous.off,
    }
}

/// Whether every whole entry of `index` can describe a log of `records_len`
/// bytes: positions contiguous, lines in order without overlap and inside the
/// log, every record id present. A read of an entry that fails this would
/// answer the wrong record.
fn index_in_shape(
    index: &mut Index,
    records_len: u64,
) -> bool {
    let mut previous: Option<IndexEntry> = None;
    let mut in_shape = true;
    let scanned = index.scan(0, Direction::Forward, |entry| {
        let follows = previous
            .as_ref()
            .is_none_or(|p| in_order(p, entry, Direction::Forward));
        in_shape = follows && !entry.id.is_empty() && entry.end() <= records_len;
        previous = Some(entry.clone());
        Ok(in_shape)
    });
    scanned.is_ok() && in_shape
}

/// Bring a surface's index in step with its log and derive its state from
/// the log (the log, not `chain-head.json`, is the truth): cut a torn index
/// entry, rebuild an index that cannot describe the log (or every index when
/// `rebuild`), index any records appended after the last entry, and take the
/// head from the last record (or the retention anchor once every record is
/// pruned). A log that ends before the head `chain-head.json` recorded has
/// lost its newest records: the head keeps that mark from then on.
fn reconcile(
    dir: &Path,
    encryption: &Option<EncryptionService>,
    rebuild: bool,
) -> Result<SurfaceState> {
    let anchor = read_anchor_credential(dir)
        .ok()
        .flatten()
        .and_then(|credential| anchor_of(&credential).ok());
    let anchor_head = || {
        anchor
            .as_ref()
            .map_or_else(ChainHead::genesis, |a| ChainHead {
                content_hash: a.content_hash.clone(),
                count: a.seq,
                missing_from: None,
            })
    };
    let stored_head = read_head(dir);
    let records_path = dir.join(RECORDS_FILE);
    let Some(mut records) = open_existing_rw(&records_path)? else {
        return Ok(SurfaceState {
            head: with_missing(dir, stored_head.as_ref(), anchor_head()),
            oldest_ms: None,
        });
    };
    let mut records_len = records
        .metadata()
        .context("stat governance log")?
        .len();
    if records_len > 0 {
        let mut last = [0u8; 1];
        records
            .seek(SeekFrom::Start(records_len - 1))
            .context("seek governance log")?;
        records
            .read_exact(&mut last)
            .context("read governance log")?;
        if last[0] != b'\n' {
            warn!(path = %records_path.display(), "terminating a torn governance record line");
            records
                .seek(SeekFrom::End(0))
                .context("seek governance log")?;
            records
                .write_all(b"\n")
                .context("terminate governance log")?;
            records_len += 1;
        }
    }

    let index_file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(dir.join(INDEX_FILE))
        .context("open governance index")?;
    let index_len = index_file
        .metadata()
        .context("stat governance index")?
        .len();
    if index_len % ENTRY_WIDTH != 0 {
        index_file
            .set_len(index_len - index_len % ENTRY_WIDTH)
            .context("cut torn governance index entry")?;
    }
    let open_index = || -> Result<Index> {
        Index::from_file(
            index_file
                .try_clone()
                .context("open governance index")?,
        )
    };
    let mut index = open_index()?;
    let reset = if rebuild {
        warn!(path = %records_path.display(), "rebuilding a governance index from its log");
        true
    } else if !index_in_shape(&mut index, records_len) {
        warn!(path = %records_path.display(), "rebuilding a governance index that cannot describe its log");
        true
    } else {
        false
    };
    if reset {
        index_file
            .set_len(0)
            .context("reset governance index")?;
        index = open_index()?;
    }

    // The last indexed record, read back to prove the index describes this log.
    let mut last: Option<(IndexEntry, GovernanceRecord)> = None;
    if index.count() > 0 {
        let entry = index.entry(index.count() - 1)?;
        let in_step = read_record_at(&mut records, encryption, &entry)
            .ok()
            .flatten()
            .map(|stored| stored.record);
        match in_step {
            Some(record) => last = Some((entry, record)),
            None => {
                warn!(path = %records_path.display(), "rebuilding a governance index out of step with its log");
                index_file
                    .set_len(0)
                    .context("reset governance index")?;
            }
        }
    }

    let covered = last
        .as_ref()
        .map_or(0, |(entry, _)| entry.end());
    if covered < records_len {
        records
            .seek(SeekFrom::Start(covered))
            .context("seek governance log")?;
        let mut reader = BufReader::new(&mut records);
        let mut appender = BufWriter::new(&index_file);
        appender
            .seek(SeekFrom::End(0))
            .context("seek governance index")?;
        let mut off = covered;
        let mut line = Vec::new();
        loop {
            line.clear();
            let read = reader
                .read_until(b'\n', &mut line)
                .context("read governance log")? as u64;
            if read == 0 {
                break;
            }
            let start = off;
            off += read;
            let text = trim_line(&line);
            if text.is_empty() {
                continue;
            }
            let record = match decode_line::<StoredRecord>(encryption, text) {
                Ok(stored) => stored.record,
                Err(e) => {
                    warn!(path = %records_path.display(), offset = start, error = %e, "skipping an unreadable governance record line");
                    continue;
                }
            };
            let seq = match &last {
                Some((entry, _)) => entry.seq + 1,
                None => chain_start(&record, anchor.as_ref()).unwrap_or_else(|e| {
                    warn!(path = %records_path.display(), error = %e, "governance log does not start at genesis or its anchor");
                    anchor
                        .as_ref()
                        .map_or(1, |a| a.seq + 1)
                }),
            };
            let leading = (line.len() - line.trim_ascii_start().len()) as u64;
            let entry = IndexEntry::for_record(seq, start + leading, text.len() as u64, &record);
            appender
                .write_all(&entry.encode()?)
                .context("write governance index")?;
            last = Some((entry, record));
        }
        appender
            .flush()
            .context("write governance index")?;
    }

    let head = match &last {
        Some((entry, record)) => match &record.content_hash {
            Some(hash) => ChainHead {
                content_hash: hash.clone(),
                count: entry.seq,
                missing_from: None,
            },
            None => return Err(anyhow!("governance record {} has no content_hash", entry.seq)),
        },
        None => anchor_head(),
    };
    let mut index = Index::from_file(index_file)?;
    let oldest_ms = if index.count() > 0 {
        index.entry(0)?.ts
    } else {
        None
    };
    Ok(SurfaceState {
        head: with_missing(dir, stored_head.as_ref(), head),
        oldest_ms,
    })
}

/// `head` (taken from the log) with the mark of a chain head the log no
/// longer reaches: the one `stored` (`chain-head.json`) carries, or `stored`
/// itself when it is ahead of the log. A newly found mark is logged and kept
/// in `chain-head.json` at once.
fn with_missing(
    dir: &Path,
    stored: Option<&ChainHead>,
    mut head: ChainHead,
) -> ChainHead {
    let Some(stored) = stored else {
        return head;
    };
    if let Some(mark) = &stored.missing_from {
        head.missing_from = Some(mark.clone());
    } else if stored.count > head.count {
        error!(
            path = %dir.display(),
            log_ends_at = head.count,
            head_was = stored.count,
            "a governance log ends before its chain head: its newest records are missing"
        );
        head.missing_from = Some(HeadMark {
            content_hash: stored.content_hash.clone(),
            count: stored.count,
        });
        if let Err(e) = write_head(dir, &head) {
            warn!(path = %dir.display(), error = %e, "failed to persist governance chain head");
        }
    }
    head
}

/// Run blocking file work off the async workers.
async fn blocking<T: Send + 'static>(work: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(work)
        .await
        .map_err(|e| anyhow!("governance store task failed: {e}"))?
}

/// Serialize + optionally encrypt a stored record into a single log line.
fn encode_line(
    encryption: &Option<EncryptionService>,
    stored: &impl Serialize,
) -> Result<String> {
    let json = serde_json::to_string(stored).context("serialize stored governance record")?;
    match encryption {
        Some(enc) => enc
            .encrypt_field(&json)
            .context("encrypt governance record line"),
        None => Ok(json),
    }
}

/// A line written by [`encode_line`] back into its value. When the store
/// encrypts, a line that is not encrypted is refused: the store never wrote it.
fn decode_line<T: serde::de::DeserializeOwned>(
    encryption: &Option<EncryptionService>,
    line: &[u8],
) -> Result<T> {
    let text = std::str::from_utf8(line).context("governance record line is not UTF-8")?;
    let json = match encryption {
        Some(enc) if text.starts_with("ENC[") => enc
            .decrypt_field(text)
            .context("decrypt governance record line")?,
        Some(_) => return Err(anyhow!("the line is not encrypted, though this store encrypts every line")),
        None => text.to_string(),
    };
    serde_json::from_str(&json).context("parse governance record")
}

/// The record an index entry points at, checked against the entry; `None`
/// (logged) when the line does not decode. A record the entry does not
/// describe is a [`ChainProblem::IndexMismatch`].
fn read_record_at(
    records: &mut File,
    encryption: &Option<EncryptionService>,
    entry: &IndexEntry,
) -> Result<Option<StoredRecord>> {
    let mut line = vec![0u8; entry.len as usize];
    records
        .seek(SeekFrom::Start(entry.off))
        .context("seek governance log")?;
    records
        .read_exact(&mut line)
        .context("read governance log")?;
    let mut stored: StoredRecord = match decode_line(encryption, &line) {
        Ok(stored) => stored,
        Err(e) => {
            warn!(seq = entry.seq, error = %e, "skipping an unreadable governance record");
            return Ok(None);
        }
    };
    if !entry.describes(&stored.record)? {
        return Err(index_mismatch(format!(
            "the index entry for record {} does not describe the record it points at",
            entry.seq
        )));
    }
    stored.seq = Some(entry.seq);
    Ok(Some(stored))
}

fn trim_line(line: &[u8]) -> &[u8] {
    line.trim_ascii()
}

/// The last non-blank line of a file, read backwards from its end.
fn last_line(file: &mut File) -> Result<Option<Vec<u8>>> {
    const CHUNK: u64 = 64 * 1024;
    let mut pos = file
        .metadata()
        .context("stat governance log")?
        .len();
    let mut tail: Vec<u8> = Vec::new();
    while pos > 0 {
        let start = pos.saturating_sub(CHUNK);
        let mut chunk = vec![0u8; (pos - start) as usize];
        file.seek(SeekFrom::Start(start))
            .context("seek governance log")?;
        file.read_exact(&mut chunk)
            .context("read governance log")?;
        chunk.extend_from_slice(&tail);
        tail = chunk;
        pos = start;
        let Some(end) = tail
            .iter()
            .rposition(|b| !b.is_ascii_whitespace())
        else {
            continue;
        };
        if let Some(newline) = tail[..end]
            .iter()
            .rposition(|b| *b == b'\n')
        {
            return Ok(Some(tail[newline + 1..=end].to_vec()));
        }
    }
    let text = trim_line(&tail);
    Ok((!text.is_empty()).then(|| text.to_vec()))
}

fn open_existing(path: &Path) -> Result<Option<File>> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open {}", path.display())),
    }
}

fn open_existing_rw(path: &Path) -> Result<Option<File>> {
    match OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
    {
        Ok(file) => Ok(Some(file)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("open {}", path.display())),
    }
}

/// The signed anchor credential of a surface, when one is kept.
fn read_anchor_credential(dir: &Path) -> Result<Option<Value>> {
    match std::fs::read(dir.join(ANCHOR_FILE)) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .context("parse retention anchor"),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).context("read retention anchor"),
    }
}

/// The chain head `chain-head.json` records, when it holds one.
fn read_head(dir: &Path) -> Option<ChainHead> {
    let bytes = std::fs::read(dir.join(HEAD_FILE)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// The retention window `retention.json` keeps (0 when none).
fn read_window(dir: &Path) -> u32 {
    std::fs::read(dir.join(RETENTION_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
        .and_then(|value| value["retention_days"].as_u64())
        .and_then(|days| u32::try_from(days).ok())
        .unwrap_or(0)
}

/// The keys `signing-keys.jsonl` records. When the store encrypts, a line that
/// is not encrypted is ignored (and logged): the store never wrote it.
fn load_keys(
    root: &Path,
    encryption: &Option<EncryptionService>,
) -> Result<Vec<KnownKey>> {
    let path = root.join(KEYS_FILE);
    let Some(file) = open_existing(&path)? else {
        return Ok(Vec::new());
    };
    let mut keys = Vec::new();
    for line in BufReader::new(file).split(b'\n') {
        let line = line.context("read governance signing keys")?;
        let text = trim_line(&line);
        if text.is_empty() {
            continue;
        }
        match decode_line::<KnownKey>(encryption, text) {
            Ok(key) => keys.push(key),
            Err(e) => warn!(path = %path.display(), error = %e, "ignoring an unreadable governance signing key"),
        }
    }
    Ok(keys)
}

/// Add `key` to `signing-keys.jsonl` unless it is recorded already.
fn record_key(
    root: &Path,
    encryption: &Option<EncryptionService>,
    shared: &Shared,
    key: KnownKey,
) -> Result<()> {
    let mut keys = shared
        .keys
        .lock()
        .map_err(|_| anyhow!("governance store lock poisoned"))?;
    if keys.is_none() {
        *keys = Some(load_keys(root, encryption)?);
    }
    let known = keys.get_or_insert_with(Vec::new);
    if known.contains(&key) {
        return Ok(());
    }
    std::fs::create_dir_all(root).context("create governance root")?;
    let mut line = encode_line(encryption, &key)?;
    line.push('\n');
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(root.join(KEYS_FILE))
        .context("open governance signing keys")?;
    file.write_all(line.as_bytes())
        .context("write governance signing keys")?;
    file.sync_data()
        .context("sync governance signing keys")?;
    known.push(key);
    Ok(())
}

/// Append a record's line to the surface's log (made durable before the
/// chain head can name it) and its entry to the index, together under the
/// surface's append lock. Answers the entry and whether indexing it succeeded.
fn append_record(
    dir: &Path,
    lock: &Mutex<()>,
    line: &str,
    seq: u64,
    record: &GovernanceRecord,
) -> Result<(IndexEntry, Result<()>)> {
    std::fs::create_dir_all(dir).context("create governance surface dir")?;
    let _appends = lock
        .lock()
        .map_err(|_| anyhow!("governance store lock poisoned"))?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(RECORDS_FILE))
        .context("open governance log")?;
    let off = file
        .metadata()
        .context("stat governance log")?
        .len();
    let mut bytes = Vec::with_capacity(line.len() + 1);
    bytes.extend_from_slice(line.as_bytes());
    bytes.push(b'\n');
    file.write_all(&bytes)
        .context("write governance log")?;
    file.sync_data()
        .context("sync governance log")?;
    let entry = IndexEntry::for_record(seq, off, line.len() as u64, record);
    let indexed = append_entry(dir, &entry);
    Ok((entry, indexed))
}

fn append_entry(
    dir: &Path,
    entry: &IndexEntry,
) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(dir.join(INDEX_FILE))
        .context("open governance index")?;
    file.write_all(&entry.encode()?)
        .context("write governance index")
}

async fn persist_head(
    dir: &Path,
    head: &ChainHead,
) -> Result<()> {
    use tokio::fs::{create_dir_all, write};
    create_dir_all(dir)
        .await
        .context("create governance surface dir")?;
    let json = serde_json::to_string(head).context("serialize chain head")?;
    write(dir.join(HEAD_FILE), json)
        .await
        .context("write chain head")?;
    Ok(())
}

fn write_head(
    dir: &Path,
    head: &ChainHead,
) -> Result<()> {
    let json = serde_json::to_string(head).context("serialize chain head")?;
    std::fs::write(dir.join(HEAD_FILE), json).context("write chain head")
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::governance::record::{RecordMetrics, StageEntry, StageOutcome};
    use crate::identity::ssi::vc_issuer::{VcSigner, sign_eddsa_jcs_2022};
    use async_trait::async_trait;

    /// Signs `eddsa-jcs-2022` proofs with a fixed Ed25519 key under a DID's
    /// `#key-2`, as the appliance signer does.
    struct KeySigner {
        key: ed25519_dalek::SigningKey,
        method: String,
    }

    #[async_trait]
    impl VcSigner for KeySigner {
        async fn sign(
            &self,
            payload: Value,
        ) -> anyhow::Result<Value> {
            sign_eddsa_jcs_2022(payload, &self.key, &self.method)
        }

        async fn verifying_key(&self) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
            Ok(self.key.verifying_key())
        }
    }

    /// The appliance signer of these tests: key 9 of `did:web:example.com`.
    pub(in crate::governance) fn signer() -> GovernanceSigner {
        signer_with(9, "did:web:example.com")
    }

    fn signer_with(
        seed: u8,
        did: &str,
    ) -> GovernanceSigner {
        GovernanceSigner::new(
            did.to_string(),
            Arc::new(KeySigner {
                key: ed25519_dalek::SigningKey::from_bytes(&[seed; 32]),
                method: format!("{did}#key-2"),
            }),
        )
    }

    fn draft(
        surface: &str,
        prompt: &str,
    ) -> GovernanceRecord {
        draft_at(surface, prompt, "2026-08-12T00:00:00Z", None)
    }

    /// A draft at `timestamp`; `blocked_by` names the stage that blocked it.
    pub(in crate::governance) fn draft_at(
        surface: &str,
        prompt: &str,
        timestamp: &str,
        blocked_by: Option<&str>,
    ) -> GovernanceRecord {
        GovernanceRecord {
            record_id: uuid::Uuid::new_v4().to_string(),
            trace_id: None,
            surface_id: surface.to_string(),
            surface_name: Some("Test Surface".to_string()),
            caller_identity_hash: Some("hash".to_string()),
            caller_identity_kind: None,
            principal_key: None,
            attribution: Default::default(),
            timestamp: timestamp.to_string(),
            prev_record_hash: GENESIS_HASH.to_string(),
            stages: match blocked_by {
                Some(stage) => vec![StageEntry::decision(stage, StageOutcome::Block, Some("no".to_string()))],
                None => vec![StageEntry::decision("judge", StageOutcome::Allow, None)],
            },
            prompt: Some(prompt.to_string()),
            completion: Some("answer".to_string()),
            attachments: Vec::new(),
            metrics: RecordMetrics::default(),
            content_hash: None,
        }
    }

    fn temp_root() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    fn prompts(page: &RecordPage) -> Vec<String> {
        page.records
            .iter()
            .map(|s| {
                s.record
                    .prompt
                    .clone()
                    .unwrap_or_default()
            })
            .collect()
    }

    fn seqs(page: &RecordPage) -> Vec<u64> {
        page.records
            .iter()
            .map(|s| s.seq.unwrap())
            .collect()
    }

    async fn all(
        store: &GovernanceStore,
        surface: &str,
    ) -> RecordPage {
        store
            .query(surface, RecordQuery::default())
            .await
            .unwrap()
    }

    /// Write `n` records numbered from `from`, alternating ok and blocked by
    /// the judge, one minute apart from 2026-08-12T00:00Z on.
    async fn write_mixed(
        store: &GovernanceStore,
        surface: &str,
        from: u32,
        n: u32,
    ) {
        for i in from..from + n {
            let at = format!("2026-08-12T{:02}:{:02}:00Z", i / 60, i % 60);
            let blocked_by = (i % 2 == 0).then_some("judge");
            store
                .record(draft_at(surface, &format!("p{i}"), &at, blocked_by), 0)
                .await
                .unwrap();
        }
    }

    fn path(
        root: &tempfile::TempDir,
        surface: &str,
        file: &str,
    ) -> PathBuf {
        root.path()
            .join(surface)
            .join(file)
    }

    #[tokio::test]
    async fn records_chain_and_verify() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);

        let first = store
            .record(draft("surf-a", "one"), 0)
            .await
            .unwrap();
        let second = store
            .record(draft("surf-a", "two"), 0)
            .await
            .unwrap();

        // Genesis link on the first, then chained.
        assert_eq!(first.record.prev_record_hash, GENESIS_HASH);
        assert_eq!(
            second.record.prev_record_hash,
            first
                .record
                .content_hash
                .clone()
                .unwrap()
        );
        assert!(first.signed_vc["proof"].is_object());
        assert_eq!((first.seq, second.seq), (Some(1), Some(2)));

        let summary = store
            .verify_chain("surf-a")
            .await
            .unwrap();
        assert_eq!(summary.count, 2);
        assert_eq!((summary.first_seq, summary.last_seq), (Some(1), Some(2)));
        assert!(summary.anchor.is_none());
        assert_eq!(prompts(&all(&store, "surf-a").await), ["one", "two"]);
    }

    #[tokio::test]
    async fn separate_surfaces_have_independent_chains() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);

        store
            .record(draft("surf-a", "a1"), 0)
            .await
            .unwrap();
        let b1 = store
            .record(draft("surf-b", "b1"), 0)
            .await
            .unwrap();
        // surf-b's first record is genesis-linked, independent of surf-a.
        assert_eq!(b1.record.prev_record_hash, GENESIS_HASH);
        assert_eq!(b1.seq, Some(1));

        for surface in ["surf-a", "surf-b"] {
            assert_eq!(
                store
                    .verify_chain(surface)
                    .await
                    .unwrap()
                    .count,
                1
            );
        }
        assert_eq!(store.list_surfaces().unwrap(), ["surf-a", "surf-b"]);
    }

    #[tokio::test]
    async fn verify_detects_tampered_line() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        store
            .record(draft("surf-t", "orig"), 0)
            .await
            .unwrap();

        // Corrupt the persisted body without updating the content hash.
        let log = path(&root, "surf-t", RECORDS_FILE);
        let raw = std::fs::read_to_string(&log).unwrap();
        std::fs::write(&log, raw.replace("orig", "hacked")).unwrap();

        let err = store
            .verify_chain("surf-t")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("content hash mismatch at record 1"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn verify_detects_a_dropped_first_record() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-d", 0, 3).await;

        let log = path(&root, "surf-d", RECORDS_FILE);
        let raw = std::fs::read_to_string(&log).unwrap();
        let rest: Vec<&str> = raw.lines().skip(1).collect();
        std::fs::write(&log, format!("{}\n", rest.join("\n"))).unwrap();

        let err = store
            .verify_chain("surf-d")
            .await
            .unwrap_err();
        assert!(
            err.to_string()
                .contains("no retention anchor is kept"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn empty_surface_verifies_as_empty_chain() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let summary = store
            .verify_chain("never-used")
            .await
            .unwrap();
        assert_eq!(summary.count, 0);
        assert!(
            all(&store, "never-used")
                .await
                .records
                .is_empty()
        );
        assert!(
            !root
                .path()
                .join("never-used")
                .exists(),
            "reading a surface creates nothing"
        );
    }

    #[tokio::test]
    async fn latest_record_returns_the_most_recent() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        // No log yet → None.
        assert!(
            store
                .latest_record("surf-l")
                .unwrap()
                .is_none()
        );

        store
            .record(draft("surf-l", "one"), 0)
            .await
            .unwrap();
        // A prompt longer than one backwards read, so the last line spans chunks.
        let long = "x".repeat(200 * 1024);
        store
            .record(draft("surf-l", &long), 0)
            .await
            .unwrap();

        let latest = store
            .latest_record("surf-l")
            .unwrap()
            .unwrap();
        assert_eq!(
            latest
                .record
                .prompt
                .as_deref(),
            Some(long.as_str())
        );
        assert_eq!(
            latest
                .record
                .surface_name
                .as_deref(),
            Some("Test Surface")
        );
    }

    #[tokio::test]
    async fn reads_filter_by_outcome_stage_and_time() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-q", 0, 10).await;
        store
            .record(draft_at("surf-q", "policy", "2026-08-12T00:10:00Z", Some("policy")), 0)
            .await
            .unwrap();

        let blocked = store
            .query(
                "surf-q",
                RecordQuery {
                    outcomes: vec![RecordOutcome::Blocked],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&blocked), ["p0", "p2", "p4", "p6", "p8", "policy"]);
        assert_eq!(seqs(&blocked), [1, 3, 5, 7, 9, 11], "each record keeps its chain position");

        let ok = store
            .query(
                "surf-q",
                RecordQuery {
                    outcomes: vec![RecordOutcome::Ok],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&ok), ["p1", "p3", "p5", "p7", "p9"]);

        let by_policy = store
            .query(
                "surf-q",
                RecordQuery {
                    stages: vec!["policy".to_string()],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&by_policy), ["policy"]);

        let failed = store
            .query(
                "surf-q",
                RecordQuery {
                    outcomes: vec![RecordOutcome::Failed],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert!(failed.records.is_empty());

        let window = store
            .query(
                "surf-q",
                RecordQuery {
                    since_ms: super::super::index::timestamp_ms("2026-08-12T00:03:00Z"),
                    until_ms: super::super::index::timestamp_ms("2026-08-12T00:06:00Z"),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&window), ["p3", "p4", "p5"], "since is inclusive, until exclusive");

        let newest_blocks_since = store
            .query(
                "surf-q",
                RecordQuery {
                    order: RecordOrder::Desc,
                    outcomes: vec![RecordOutcome::Blocked],
                    since_ms: super::super::index::timestamp_ms("2026-08-12T00:05:00Z"),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&newest_blocks_since), ["policy", "p8", "p6"]);
    }

    #[tokio::test]
    async fn newest_first_pages_follow_the_cursor_to_the_end() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-p", 0, 9).await;

        let page = |cursor: Option<u64>| RecordQuery {
            order: RecordOrder::Desc,
            outcomes: vec![RecordOutcome::Blocked],
            cursor,
            limit: Some(2),
            ..Default::default()
        };
        let mut cursor = None;
        let mut pages = Vec::new();
        loop {
            let got = store
                .query("surf-p", page(cursor))
                .await
                .unwrap();
            pages.push(prompts(&got));
            match got.next_cursor {
                Some(next) => {
                    assert_eq!(
                        Some(next),
                        got.records
                            .last()
                            .and_then(|r| r.seq)
                    );
                    cursor = Some(next);
                }
                None => break,
            }
            assert!(pages.len() < 10, "paging ends");
        }
        assert_eq!(pages, [vec!["p8", "p6"], vec!["p4", "p2"], vec!["p0"]]);

        // An exactly full last page carries no cursor.
        let exact = store
            .query(
                "surf-p",
                RecordQuery {
                    order: RecordOrder::Desc,
                    outcomes: vec![RecordOutcome::Blocked],
                    cursor: Some(5),
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&exact), ["p2", "p0"]);
        assert_eq!(exact.next_cursor, None);

        // Cursors outside the chain answer nothing rather than failing.
        for cursor in [0, 1] {
            assert!(
                store
                    .query("surf-p", page(Some(cursor)))
                    .await
                    .unwrap()
                    .records
                    .is_empty()
            );
        }
        assert_eq!(
            prompts(
                &store
                    .query("surf-p", page(Some(1000)))
                    .await
                    .unwrap()
            ),
            ["p8", "p6"]
        );
    }

    #[tokio::test]
    async fn oldest_first_keeps_its_limit_meaning_and_pages_from_a_cursor() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-o", 0, 5).await;

        let legacy = store
            .query(
                "surf-o",
                RecordQuery {
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&legacy), ["p3", "p4"], "the most recent records, oldest first");
        assert_eq!(legacy.next_cursor, None);

        let from_start = store
            .query(
                "surf-o",
                RecordQuery {
                    cursor: Some(0),
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&from_start), ["p0", "p1"]);
        assert_eq!(from_start.next_cursor, Some(2));
        let next = store
            .query(
                "surf-o",
                RecordQuery {
                    cursor: from_start.next_cursor,
                    limit: Some(2),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&next), ["p2", "p3"]);
        assert_eq!(next.next_cursor, Some(4));

        assert!(
            store
                .query(
                    "surf-o",
                    RecordQuery {
                        limit: Some(0),
                        ..Default::default()
                    }
                )
                .await
                .unwrap()
                .records
                .is_empty()
        );
    }

    #[tokio::test]
    async fn one_record_is_found_by_its_id_and_no_other() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-g", 0, 4).await;
        let wanted = all(&store, "surf-g")
            .await
            .records[2]
            .clone();

        let found = store
            .get("surf-g", &wanted.record.record_id, None)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(found.record, wanted.record);
        assert_eq!(found.seq, Some(3));
        assert_eq!(found.signed_vc, wanted.signed_vc);

        assert!(
            store
                .get("surf-g", "no-such-record", None)
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .get("other-surface", &wanted.record.record_id, None)
                .await
                .unwrap()
                .is_none(),
            "a record is found only on its own surface"
        );
    }

    #[tokio::test]
    async fn an_encrypted_log_keeps_text_out_of_the_index() {
        let root = temp_root();
        let encryption =
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap();
        let store = GovernanceStore::new(root.path(), signer(), Some(encryption));
        store
            .record(draft_at("surf-e", "secret prompt", "2026-08-12T00:00:00Z", Some("judge")), 0)
            .await
            .unwrap();

        for file in [RECORDS_FILE, INDEX_FILE] {
            let raw = std::fs::read_to_string(path(&root, "surf-e", file)).unwrap();
            assert!(!raw.contains("secret prompt"), "{file} holds no prompt text");
        }
        let index = std::fs::read_to_string(path(&root, "surf-e", INDEX_FILE)).unwrap();
        assert!(index.contains("\"outcome\":\"blocked\"") && index.contains("\"stage\":\"judge\""));

        let blocked = store
            .query(
                "surf-e",
                RecordQuery {
                    outcomes: vec![RecordOutcome::Blocked],
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        assert_eq!(prompts(&blocked), ["secret prompt"]);
        assert_eq!(
            store
                .verify_chain("surf-e")
                .await
                .unwrap()
                .count,
            1
        );
    }

    #[tokio::test]
    async fn a_log_without_an_index_is_indexed_on_first_read() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-x", 0, 4).await;
        std::fs::remove_file(path(&root, "surf-x", INDEX_FILE)).unwrap();

        // A new process over the same files.
        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let page = all(&restarted, "surf-x").await;
        assert_eq!(seqs(&page), [1, 2, 3, 4]);
        assert!(path(&root, "surf-x", INDEX_FILE).exists(), "the index was rebuilt from the log");
    }

    #[tokio::test]
    async fn the_index_catches_up_with_records_it_missed_and_cuts_a_torn_entry() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-c", 0, 3).await;
        // Lose the last entry and leave half of one behind, as an interrupted
        // append would.
        let index = path(&root, "surf-c", INDEX_FILE);
        let bytes = std::fs::read(&index).unwrap();
        let cut = bytes.len() - ENTRY_WIDTH as usize;
        std::fs::write(&index, [&bytes[..cut], &bytes[cut..cut + 40]].concat()).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        assert_eq!(seqs(&all(&restarted, "surf-c").await), [1, 2, 3]);
        let next = restarted
            .record(draft("surf-c", "after"), 0)
            .await
            .unwrap();
        assert_eq!(next.seq, Some(4));
        assert_eq!(
            restarted
                .verify_chain("surf-c")
                .await
                .unwrap()
                .count,
            4
        );
    }

    #[tokio::test]
    async fn a_restart_continues_the_chain_from_the_log_not_a_stale_head() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-r", 0, 2).await;
        std::fs::write(path(&root, "surf-r", HEAD_FILE), r#"{"content_hash":"sha256:stale","count":1}"#).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let third = restarted
            .record(draft("surf-r", "third"), 0)
            .await
            .unwrap();
        assert_eq!(third.seq, Some(3));
        assert_eq!(
            restarted
                .verify_chain("surf-r")
                .await
                .unwrap()
                .count,
            3
        );
    }

    #[tokio::test]
    async fn a_promoted_instance_continues_the_chain_another_instance_extended() {
        use crate::server::mode::ReloadOnPromotion;

        let root = temp_root();
        let standby = GovernanceStore::new(root.path(), signer(), None);
        standby
            .record(draft("surf-p", "before"), 0)
            .await
            .unwrap();
        let active = GovernanceStore::new(root.path(), signer(), None);
        let extended = active
            .record(draft("surf-p", "on the active"), 0)
            .await
            .unwrap();

        standby
            .reload_from_storage()
            .await
            .unwrap();
        let next = standby
            .record(draft("surf-p", "after promotion"), 0)
            .await
            .unwrap();

        assert_eq!(next.seq, Some(3));
        assert_eq!(Some(next.record.prev_record_hash), extended.record.content_hash);
        let summary = standby
            .verify_chain("surf-p")
            .await
            .unwrap();
        assert_eq!(summary.count, 3);
    }

    #[tokio::test]
    async fn without_a_reload_a_stale_head_forks_the_chain() {
        let root = temp_root();
        let standby = GovernanceStore::new(root.path(), signer(), None);
        standby
            .record(draft("surf-f", "before"), 0)
            .await
            .unwrap();
        let active = GovernanceStore::new(root.path(), signer(), None);
        active
            .record(draft("surf-f", "on the active"), 0)
            .await
            .unwrap();

        let forked = standby
            .record(draft("surf-f", "stale"), 0)
            .await
            .unwrap();

        assert_eq!(forked.seq, Some(2), "the cached head reuses a sequence number");
    }

    /// Two records from 2020 and two from now, with the 2020 ones prunable
    /// under a 30-day window.
    async fn old_and_new(
        store: &GovernanceStore,
        surface: &str,
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        for (prompt, at) in
            [("old-1", "2020-01-01T00:00:00Z"), ("old-2", "2020-01-02T00:00:00Z"), ("new-1", &now), ("new-2", &now)]
        {
            store
                .record(draft_at(surface, prompt, at, None), 0)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn retention_prunes_behind_a_signed_anchor_and_the_chain_still_verifies() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        old_and_new(&store, "surf-ret").await;
        let before = all(&store, "surf-ret").await;
        let last_pruned = before.records[1].clone();

        assert!(
            store
                .prune("surf-ret", 0)
                .await
                .unwrap()
                .is_none(),
            "0 keeps everything"
        );
        let anchor = store
            .prune("surf-ret", 30)
            .await
            .unwrap()
            .expect("the 2020 records are due");
        assert_eq!(anchor.seq, 2);
        assert_eq!(
            anchor.content_hash,
            last_pruned
                .record
                .content_hash
                .clone()
                .unwrap()
        );
        assert_eq!(anchor.timestamp, "2020-01-02T00:00:00Z");
        assert_eq!(anchor.retention_days, 30);

        let kept = all(&store, "surf-ret").await;
        assert_eq!(prompts(&kept), ["new-1", "new-2"]);
        assert_eq!(seqs(&kept), [3, 4], "kept records keep their chain positions");
        assert!(
            store
                .get("surf-ret", &last_pruned.record.record_id, None)
                .await
                .unwrap()
                .is_none()
        );

        let summary = store
            .verify_chain("surf-ret")
            .await
            .unwrap();
        assert_eq!(summary.count, 2);
        assert_eq!((summary.first_seq, summary.last_seq), (Some(3), Some(4)));
        assert_eq!(summary.anchor, Some(anchor.clone()));

        let credential: Value =
            serde_json::from_slice(&std::fs::read(path(&root, "surf-ret", ANCHOR_FILE)).unwrap()).unwrap();
        assert_eq!(credential["type"][1], super::super::anchor::ANCHOR_CREDENTIAL_TYPE);
        assert_eq!(credential["proof"]["cryptosuite"], "eddsa-jcs-2022");

        assert!(
            store
                .prune("surf-ret", 30)
                .await
                .unwrap()
                .is_none(),
            "nothing more is due"
        );

        // The chain grows on from the kept records.
        let fifth = store
            .record(draft("surf-ret", "fifth"), 0)
            .await
            .unwrap();
        assert_eq!(fifth.seq, Some(5));
        assert_eq!(
            store
                .verify_chain("surf-ret")
                .await
                .unwrap()
                .count,
            3
        );
        let restarted = GovernanceStore::new(root.path(), signer(), None);
        assert_eq!(seqs(&all(&restarted, "surf-ret").await), [3, 4, 5]);
        assert_eq!(
            restarted
                .verify_chain("surf-ret")
                .await
                .unwrap()
                .first_seq,
            Some(3)
        );
    }

    /// Prune `surface`'s 2020 records and answer the anchor file's credential.
    async fn pruned(
        root: &tempfile::TempDir,
        store: &GovernanceStore,
        surface: &str,
    ) -> Value {
        old_and_new(store, surface).await;
        store
            .prune(surface, 30)
            .await
            .unwrap()
            .unwrap();
        serde_json::from_slice(&std::fs::read(path(root, surface, ANCHOR_FILE)).unwrap()).unwrap()
    }

    fn write_anchor(
        root: &tempfile::TempDir,
        surface: &str,
        credential: &Value,
    ) {
        std::fs::write(path(root, surface, ANCHOR_FILE), serde_json::to_vec(credential).unwrap()).unwrap();
    }

    async fn verify_error(
        store: &GovernanceStore,
        surface: &str,
    ) -> String {
        store
            .verify_chain(surface)
            .await
            .expect_err("tampering must fail verification")
            .to_string()
    }

    #[tokio::test]
    async fn verify_fails_when_the_anchor_hash_is_altered() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let mut credential = pruned(&root, &store, "surf-h").await;
        credential["credentialSubject"]["content_hash"] = Value::String(format!("sha256:{}", "0".repeat(63) + "1"));
        write_anchor(&root, "surf-h", &credential);
        assert!(
            verify_error(&store, "surf-h")
                .await
                .contains("retention anchor proof does not verify")
        );
    }

    #[tokio::test]
    async fn verify_fails_when_any_anchor_field_is_altered_without_resigning() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let original = pruned(&root, &store, "surf-s").await;
        for (field, value) in [
            ("pruned_at", Value::String("2020-01-01T00:00:00Z".to_string())),
            ("retention_days", Value::from(3650)),
            ("timestamp", Value::String("2019-01-01T00:00:00Z".to_string())),
            ("seq", Value::from(1)),
        ] {
            let mut credential = original.clone();
            credential["credentialSubject"][field] = value;
            write_anchor(&root, "surf-s", &credential);
            assert!(
                verify_error(&store, "surf-s")
                    .await
                    .contains("proof does not verify"),
                "{field}"
            );
        }
        write_anchor(&root, "surf-s", &original);
        assert!(
            store
                .verify_chain("surf-s")
                .await
                .is_ok(),
            "the untouched anchor verifies"
        );
    }

    #[tokio::test]
    async fn verify_fails_when_an_anchor_is_forged_with_another_key() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let credential = pruned(&root, &store, "surf-f").await;
        let mut unsigned = credential.clone();
        unsigned
            .as_object_mut()
            .unwrap()
            .remove("proof");
        let forged = sign_eddsa_jcs_2022(
            unsigned,
            &ed25519_dalek::SigningKey::from_bytes(&[3u8; 32]),
            "did:web:example.com#key-2",
        )
        .unwrap();
        write_anchor(&root, "surf-f", &forged);
        assert!(
            verify_error(&store, "surf-f")
                .await
                .contains("proof does not verify")
        );
    }

    #[tokio::test]
    async fn verify_fails_when_a_kept_record_is_altered_or_the_anchor_removed() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        pruned(&root, &store, "surf-k").await;

        let log = path(&root, "surf-k", RECORDS_FILE);
        let original = std::fs::read_to_string(&log).unwrap();
        std::fs::write(&log, original.replace("new-2", "forged")).unwrap();
        assert!(
            verify_error(&store, "surf-k")
                .await
                .contains("content hash mismatch at record 4")
        );

        std::fs::write(&log, &original).unwrap();
        std::fs::remove_file(path(&root, "surf-k", ANCHOR_FILE)).unwrap();
        assert!(
            verify_error(&store, "surf-k")
                .await
                .contains("no retention anchor is kept")
        );
    }

    #[tokio::test]
    async fn verify_refuses_another_surfaces_anchor() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let theirs = pruned(&root, &store, "surf-other").await;
        pruned(&root, &store, "surf-mine").await;
        write_anchor(&root, "surf-mine", &theirs);
        assert!(
            verify_error(&store, "surf-mine")
                .await
                .contains("belongs to surface surf-other")
        );
    }

    #[tokio::test]
    async fn an_interrupted_prune_still_verifies_and_completes_later() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        old_and_new(&store, "surf-i").await;
        let log = std::fs::read(path(&root, "surf-i", RECORDS_FILE)).unwrap();
        let index = std::fs::read(path(&root, "surf-i", INDEX_FILE)).unwrap();
        store
            .prune("surf-i", 30)
            .await
            .unwrap()
            .unwrap();
        // The anchor was installed but the log and index were not.
        std::fs::write(path(&root, "surf-i", RECORDS_FILE), &log).unwrap();
        std::fs::write(path(&root, "surf-i", INDEX_FILE), &index).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let summary = restarted
            .verify_chain("surf-i")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq), (4, Some(1)));
        assert_eq!(seqs(&all(&restarted, "surf-i").await), [1, 2, 3, 4]);
        restarted
            .prune("surf-i", 30)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            restarted
                .verify_chain("surf-i")
                .await
                .unwrap()
                .first_seq,
            Some(3)
        );
    }

    #[tokio::test]
    async fn a_log_pruned_but_not_reindexed_is_reindexed() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        old_and_new(&store, "surf-n").await;
        let index = std::fs::read(path(&root, "surf-n", INDEX_FILE)).unwrap();
        store
            .prune("surf-n", 30)
            .await
            .unwrap()
            .unwrap();
        // The log was swapped but the old index was left behind.
        std::fs::write(path(&root, "surf-n", INDEX_FILE), &index).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let page = all(&restarted, "surf-n").await;
        assert_eq!(prompts(&page), ["new-1", "new-2"]);
        assert_eq!(seqs(&page), [3, 4]);
    }

    #[tokio::test]
    async fn pruning_every_record_leaves_the_anchor_as_the_chain_head() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        for (prompt, at) in [("old-1", "2020-01-01T00:00:00Z"), ("old-2", "2020-01-02T00:00:00Z")] {
            store
                .record(draft_at("surf-all", prompt, at, None), 0)
                .await
                .unwrap();
        }
        let anchor = store
            .prune("surf-all", 30)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(anchor.seq, 2);
        assert!(
            all(&store, "surf-all")
                .await
                .records
                .is_empty()
        );
        assert_eq!(store.list_surfaces().unwrap(), ["surf-all"], "the surface stays listed");
        let summary = store
            .verify_chain("surf-all")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.anchor.map(|a| a.seq)), (0, Some(2)));

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let next = restarted
            .record(draft("surf-all", "next"), 0)
            .await
            .unwrap();
        assert_eq!(next.seq, Some(3));
        assert_eq!(next.record.prev_record_hash, anchor.content_hash);
        assert_eq!(
            restarted
                .verify_chain("surf-all")
                .await
                .unwrap()
                .first_seq,
            Some(3)
        );
    }

    #[tokio::test]
    async fn a_write_prunes_its_surface_once_the_oldest_record_is_due() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let now = chrono::Utc::now();
        store
            .record(draft_at("surf-w", "old", "2020-01-01T00:00:00Z", None), 0)
            .await
            .unwrap();
        // Just inside the grace period past a one-day window: not due yet.
        let recent = (now - chrono::Duration::hours(24 + 1) + chrono::Duration::minutes(30)).to_rfc3339();
        store
            .record(draft_at("surf-w-grace", "recent", &recent, None), 0)
            .await
            .unwrap();

        store
            .record(draft_at("surf-w", "kept-without-window", "2020-06-01T00:00:00Z", None), 0)
            .await
            .unwrap();
        assert_eq!(
            all(&store, "surf-w")
                .await
                .records
                .len(),
            2,
            "no window, no pruning"
        );

        store
            .record(draft_at("surf-w", "new", &now.to_rfc3339(), None), 30)
            .await
            .unwrap();
        assert_eq!(prompts(&all(&store, "surf-w").await), ["new"]);
        assert!(path(&root, "surf-w", ANCHOR_FILE).exists());

        store
            .record(draft_at("surf-w-grace", "now", &now.to_rfc3339(), None), 1)
            .await
            .unwrap();
        assert_eq!(
            all(&store, "surf-w-grace")
                .await
                .records
                .len(),
            2,
            "within the grace period"
        );
    }

    #[tokio::test]
    async fn an_index_that_cannot_describe_its_log_is_out_of_shape() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        two_blocks_two_oks(&store, "surf-shape").await;
        let log_len = std::fs::metadata(path(&root, "surf-shape", RECORDS_FILE))
            .unwrap()
            .len();
        let index_path = path(&root, "surf-shape", INDEX_FILE);
        let in_shape = |len: u64| {
            let mut index = Index::open(&index_path)
                .unwrap()
                .unwrap();
            index_in_shape(&mut index, len)
        };
        assert!(in_shape(log_len));
        assert!(!in_shape(log_len - 1), "an entry past the end of the log");
        let original = std::fs::read(&index_path).unwrap();

        let edits: [fn(&mut IndexEntry, &IndexEntry); 3] =
            [|entry, next| entry.off = next.off, |entry, _| entry.seq += 7, |entry, _| entry.id = String::new()];
        for edit in edits {
            std::fs::write(&index_path, &original).unwrap();
            let next = index_entry(&root, "surf-shape", 2);
            let mut entry = index_entry(&root, "surf-shape", 1);
            edit(&mut entry, &next);
            rewrite_index_entry(&root, "surf-shape", 1, &entry);
            assert!(!in_shape(log_len), "{entry:?}");
        }
    }

    fn problem_of(
        result: Result<ChainSummary>,
        what: &str,
    ) -> (ChainProblem, String) {
        let error = result.expect_err(what);
        (chain_problem(&error).expect("a chain failure"), error.to_string())
    }

    fn blocked_only() -> RecordQuery {
        RecordQuery {
            outcomes: vec![RecordOutcome::Blocked],
            ..Default::default()
        }
    }

    fn index_entry(
        root: &tempfile::TempDir,
        surface: &str,
        position: u64,
    ) -> IndexEntry {
        Index::open(&path(root, surface, INDEX_FILE))
            .unwrap()
            .unwrap()
            .entry(position)
            .unwrap()
    }

    fn rewrite_index_entry(
        root: &tempfile::TempDir,
        surface: &str,
        position: u64,
        entry: &IndexEntry,
    ) {
        let file = path(root, surface, INDEX_FILE);
        let mut bytes = std::fs::read(&file).unwrap();
        let start = (position * ENTRY_WIDTH) as usize;
        bytes[start..start + ENTRY_WIDTH as usize].copy_from_slice(&entry.encode().unwrap());
        std::fs::write(&file, bytes).unwrap();
    }

    /// Blocked by the judge, ok, blocked, ok: prompts b0, ok1, b2, ok3, all now.
    async fn two_blocks_two_oks(
        store: &GovernanceStore,
        surface: &str,
    ) {
        let now = chrono::Utc::now().to_rfc3339();
        for (prompt, blocked_by) in [("b0", Some("judge")), ("ok1", None), ("b2", Some("judge")), ("ok3", None)] {
            store
                .record(draft_at(surface, prompt, &now, blocked_by), 0)
                .await
                .unwrap();
        }
    }

    /// Rewrite every kept record of `surface`'s log as an `ok` record with
    /// prompt `forged`, linked afresh from genesis with recomputed hashes, and
    /// remove the anchor and index: what someone with file access but no key
    /// can do. With `restate`, each credential's subject is rewritten too.
    fn forge_from_genesis(
        root: &tempfile::TempDir,
        surface: &str,
        restate: bool,
    ) {
        let log = path(root, surface, RECORDS_FILE);
        let text = std::fs::read_to_string(&log).unwrap();
        let mut prev = GENESIS_HASH.to_string();
        let mut forged = String::new();
        for line in text
            .lines()
            .filter(|l| !l.trim().is_empty())
        {
            let mut stored: StoredRecord = serde_json::from_str(line).unwrap();
            stored.record.prompt = Some("forged".to_string());
            stored.record.stages.clear();
            stored.record.prev_record_hash = prev.clone();
            prev = stored.record.finalize();
            if restate {
                stored.signed_vc["credentialSubject"] = serde_json::to_value(&stored.record).unwrap();
            }
            forged.push_str(&serde_json::to_string(&stored).unwrap());
            forged.push('\n');
        }
        std::fs::write(&log, forged).unwrap();
        for file in [ANCHOR_FILE, INDEX_FILE] {
            let _ = std::fs::remove_file(path(root, surface, file));
        }
    }

    #[tokio::test]
    async fn verify_rejects_a_chain_rewritten_without_the_signing_key() {
        for restate in [false, true] {
            let root = temp_root();
            let store = GovernanceStore::new(root.path(), signer(), None);
            let now = chrono::Utc::now().to_rfc3339();
            for (prompt, at) in [
                ("old-1", "2020-01-01T00:00:00Z"),
                ("old-2", "2020-01-02T00:00:00Z"),
                ("new-1", now.as_str()),
                ("new-2", now.as_str()),
            ] {
                store
                    .record(draft_at("surf-forge", prompt, at, Some("judge")), 0)
                    .await
                    .unwrap();
            }
            store
                .prune("surf-forge", 30)
                .await
                .unwrap()
                .unwrap();
            forge_from_genesis(&root, "surf-forge", restate);

            let restarted = GovernanceStore::new(root.path(), signer(), None);
            let (problem, message) = problem_of(
                restarted
                    .verify_chain("surf-forge")
                    .await,
                "a forged chain",
            );
            assert_eq!(problem, ChainProblem::Broken, "{message}");
            let says = if restate {
                "record 1 proof does not verify"
            } else {
                "record 1 differs from its signed credential"
            };
            assert!(message.contains(says), "{message}");
        }
    }

    #[tokio::test]
    async fn verify_rejects_a_record_without_a_proof() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-u", 0, 2).await;
        let log = path(&root, "surf-u", RECORDS_FILE);
        let text = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = text
            .lines()
            .map(str::to_string)
            .collect();
        let mut stored: StoredRecord = serde_json::from_str(&lines[1]).unwrap();
        stored.signed_vc["proof"] = Value::Null;
        lines[1] = serde_json::to_string(&stored).unwrap();
        std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();

        let (problem, message) = problem_of(
            store
                .verify_chain("surf-u")
                .await,
            "an unsigned record",
        );
        assert_eq!(problem, ChainProblem::Broken);
        assert!(message.contains("record 2 is unsigned"), "{message}");
    }

    #[tokio::test]
    async fn an_encrypted_store_refuses_a_plaintext_line() {
        let encryption =
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap();
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), Some(encryption.clone()));
        let now = chrono::Utc::now().to_rfc3339();
        store
            .record(draft_at("surf-p", "real", &now, Some("judge")), 0)
            .await
            .unwrap();
        let log = path(&root, "surf-p", RECORDS_FILE);
        assert!(
            std::fs::read_to_string(&log)
                .unwrap()
                .starts_with("ENC[")
        );

        let mut forged = draft_at("surf-p", "forged", &now, None);
        forged.finalize();
        let line = serde_json::to_string(&StoredRecord {
            record: forged,
            signed_vc: Value::Null,
            seq: None,
        })
        .unwrap();
        std::fs::write(&log, format!("{line}\n")).unwrap();
        std::fs::remove_file(path(&root, "surf-p", INDEX_FILE)).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), Some(encryption));
        assert!(
            all(&restarted, "surf-p")
                .await
                .records
                .is_empty(),
            "reads skip the plaintext line"
        );
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-p")
                .await,
            "a plaintext line",
        );
        assert_eq!(problem, ChainProblem::Broken);
        assert!(message.contains("record 1 cannot be read") && message.contains("not encrypted"), "{message}");
    }

    /// Signs as the appliance signed records before they were signed
    /// `eddsa-jcs-2022`: `eddsa-rdfc-2022`, through the JSON-LD signer.
    struct RdfcSigner(crate::identity::ssi::vc_issuer::LocalVcSigner);

    #[async_trait]
    impl VcSigner for RdfcSigner {
        async fn sign(
            &self,
            payload: Value,
        ) -> anyhow::Result<Value> {
            self.0.sign(payload).await
        }

        async fn verifying_key(&self) -> anyhow::Result<ed25519_dalek::VerifyingKey> {
            self.0.verifying_key().await
        }
    }

    fn appliance_signer() -> crate::identity::ssi::vc_issuer::LocalVcSigner {
        let config = crate::identity::VCIssuerConfig {
            storage_path: "".into(),
            proxy_did: "did:web:did.example.com:agent-stream".to_string(),
            signing_key: serde_json::from_value(serde_json::json!({
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "B7hiAU-eeRjFFNXtswXSQhmzwmYfBuZF9f1c3wODZJI",
                "d": "prjVZyovt_E5tC-MCfjcpCNXTw7bEAbrbsgma7VJT64"
            }))
            .unwrap(),
        };
        crate::identity::ssi::vc_issuer::LocalVcSigner::new(Arc::new(tokio::sync::RwLock::new(config)))
    }

    #[tokio::test]
    async fn records_signed_before_jcs_proofs_still_verify_and_tampering_with_them_fails() {
        let root = temp_root();
        let did = "did:web:did.example.com:agent-stream".to_string();
        let legacy = GovernanceStore::new(
            root.path(),
            GovernanceSigner::new(did.clone(), Arc::new(RdfcSigner(appliance_signer()))),
            None,
        );
        write_mixed(&legacy, "surf-legacy", 0, 2).await;
        let first = all(&legacy, "surf-legacy")
            .await
            .records[0]
            .clone();
        assert_eq!(first.signed_vc["proof"]["cryptosuite"], "eddsa-rdfc-2022");
        let _ = std::fs::remove_file(root.path().join(KEYS_FILE));

        let upgraded =
            GovernanceStore::new(root.path(), GovernanceSigner::new(did, Arc::new(appliance_signer())), None);
        let next = upgraded
            .record(draft("surf-legacy", "after the upgrade"), 0)
            .await
            .unwrap();
        assert_eq!(next.signed_vc["proof"]["cryptosuite"], "eddsa-jcs-2022");
        let summary = upgraded
            .verify_chain("surf-legacy")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.previous_key_records), (3, 0));

        let log = path(&root, "surf-legacy", RECORDS_FILE);
        let text = std::fs::read_to_string(&log).unwrap();
        let mut lines: Vec<String> = text
            .lines()
            .map(str::to_string)
            .collect();
        let mut stored: StoredRecord = serde_json::from_str(&lines[0]).unwrap();
        stored.signed_vc["credentialSubject"]["prompt"] = Value::String("altered".to_string());
        lines[0] = serde_json::to_string(&stored).unwrap();
        std::fs::write(&log, format!("{}\n", lines.join("\n"))).unwrap();
        let (problem, message) = problem_of(
            upgraded
                .verify_chain("surf-legacy")
                .await,
            "an altered legacy proof",
        );
        assert_eq!(problem, ChainProblem::Broken);
        assert!(message.contains("record 1 proof does not verify"), "{message}");
    }

    #[tokio::test]
    async fn records_signed_with_a_previous_key_verify_from_the_key_history() {
        let root = temp_root();
        let before = GovernanceStore::new(root.path(), signer_with(1, "did:web:example.com"), None);
        write_mixed(&before, "surf-rot", 0, 2).await;
        let history = std::fs::read_to_string(root.path().join(KEYS_FILE)).unwrap();
        assert_eq!(history.lines().count(), 1, "the key is recorded once");

        let rotated = GovernanceStore::new(root.path(), signer_with(2, "did:web:example.com"), None);
        rotated
            .record(draft("surf-rot", "after rotation"), 0)
            .await
            .unwrap();
        let summary = rotated
            .verify_chain("surf-rot")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.previous_key_records), (3, 2));
        assert_eq!(
            std::fs::read_to_string(root.path().join(KEYS_FILE))
                .unwrap()
                .lines()
                .count(),
            2
        );
    }

    #[tokio::test]
    async fn a_key_the_appliance_has_no_record_of_is_reported_apart_from_a_broken_chain() {
        let root = temp_root();
        let elsewhere = GovernanceStore::new(root.path(), signer_with(1, "did:web:elsewhere.example"), None);
        write_mixed(&elsewhere, "surf-moved", 0, 2).await;
        std::fs::remove_file(root.path().join(KEYS_FILE)).unwrap();

        let here = GovernanceStore::new(root.path(), signer(), None);
        let (problem, message) = problem_of(
            here.verify_chain("surf-moved")
                .await,
            "records signed elsewhere",
        );
        assert_eq!(problem, ChainProblem::UnknownKey, "{message}");
        assert!(message.contains("did:web:elsewhere.example#key-2"), "{message}");

        let reset_key = GovernanceStore::new(root.path(), signer_with(2, "did:web:elsewhere.example"), None);
        let (problem, _) = problem_of(
            reset_key
                .verify_chain("surf-moved")
                .await,
            "a key of this DID that fails",
        );
        assert_eq!(
            problem,
            ChainProblem::Broken,
            "a proof naming this appliance's key that fails is not explained by an unknown key"
        );
    }

    #[tokio::test]
    async fn a_key_planted_in_the_history_of_an_encrypted_store_is_not_trusted() {
        let encryption =
            crate::encryption::EncryptionService::new(crate::encryption::KeySource::Raw { key: [7u8; 32] }).unwrap();
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), Some(encryption.clone()));
        let first = store
            .record(draft("surf-k", "real"), 0)
            .await
            .unwrap();
        let history = std::fs::read_to_string(root.path().join(KEYS_FILE)).unwrap();
        assert!(history.starts_with("ENC["), "the key history is encrypted with the records");

        let forger = ed25519_dalek::SigningKey::from_bytes(&[66u8; 32]);
        let method = "did:web:forger.example#key-1";
        let planted = KnownKey::new(method, &forger.verifying_key());
        std::fs::write(root.path().join(KEYS_FILE), format!("{history}{}\n", serde_json::to_string(&planted).unwrap()))
            .unwrap();
        let mut record = draft("surf-k", "forged");
        record.prev_record_hash = first
            .record
            .content_hash
            .clone()
            .unwrap();
        record.finalize();
        let credential = crate::governance::build_record_credential(&record, "did:web:forger.example").unwrap();
        let signed_vc = sign_eddsa_jcs_2022(credential, &forger, method).unwrap();
        let line = encode_line(&Some(encryption.clone()), &StoredRecord { record, signed_vc, seq: None }).unwrap();
        let mut log = OpenOptions::new()
            .append(true)
            .open(path(&root, "surf-k", RECORDS_FILE))
            .unwrap();
        log.write_all(format!("{line}\n").as_bytes())
            .unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), Some(encryption));
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-k")
                .await,
            "a planted key",
        );
        assert_eq!(problem, ChainProblem::UnknownKey, "{message}");
        assert!(message.contains("record 2"), "{message}");
    }

    #[tokio::test]
    async fn an_index_edit_that_hides_a_block_is_reported_and_the_index_rebuilt() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        two_blocks_two_oks(&store, "surf-hide").await;
        assert_eq!(
            prompts(
                &store
                    .query("surf-hide", blocked_only())
                    .await
                    .unwrap()
            ),
            ["b0", "b2"]
        );

        let mut entry = index_entry(&root, "surf-hide", 0);
        entry.outcome = RecordOutcome::Ok;
        entry.stage = None;
        rewrite_index_entry(&root, "surf-hide", 0, &entry);

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-hide")
                .await,
            "an edited index",
        );
        assert_eq!(problem, ChainProblem::IndexMismatch);
        assert!(message.contains("record 1"), "{message}");
        assert_eq!(
            prompts(
                &restarted
                    .query("surf-hide", blocked_only())
                    .await
                    .unwrap()
            ),
            ["b0", "b2"],
            "verify rebuilt the index"
        );
        assert_eq!(
            restarted
                .verify_chain("surf-hide")
                .await
                .unwrap()
                .count,
            4
        );
    }

    #[tokio::test]
    async fn a_read_that_meets_an_edited_index_entry_rebuilds_the_index() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        two_blocks_two_oks(&store, "surf-live").await;
        let mut entry = index_entry(&root, "surf-live", 0);
        entry.outcome = RecordOutcome::Ok;
        entry.stage = None;
        rewrite_index_entry(&root, "surf-live", 0, &entry);

        assert_eq!(prompts(&all(&store, "surf-live").await), ["b0", "ok1", "b2", "ok3"]);
        assert_eq!(
            prompts(
                &store
                    .query("surf-live", blocked_only())
                    .await
                    .unwrap()
            ),
            ["b0", "b2"]
        );
    }

    #[tokio::test]
    async fn an_index_entry_pointed_at_another_record_is_never_answered() {
        for keep_id in [false, true] {
            let root = temp_root();
            let store = GovernanceStore::new(root.path(), signer(), None);
            two_blocks_two_oks(&store, "surf-redirect").await;
            let target = index_entry(&root, "surf-redirect", 3);
            let mut entry = index_entry(&root, "surf-redirect", 1);
            let ok1_id = entry.id.clone();
            entry.off = target.off;
            entry.len = target.len;
            entry.id = if keep_id {
                target.id
            } else {
                String::new()
            };
            rewrite_index_entry(&root, "surf-redirect", 1, &entry);
            let tampered = std::fs::read(path(&root, "surf-redirect", INDEX_FILE)).unwrap();

            let restarted = GovernanceStore::new(root.path(), signer(), None);
            let found = restarted
                .get("surf-redirect", &ok1_id, None)
                .await
                .unwrap()
                .expect("the redirected record is found by its id");
            assert_eq!((found.seq, found.record.prompt.as_deref()), (Some(2), Some("ok1")));
            let page = all(&restarted, "surf-redirect").await;
            assert_eq!(prompts(&page), ["b0", "ok1", "b2", "ok3"]);
            assert_eq!(seqs(&page), [1, 2, 3, 4]);

            // The same edit made while the surface is in use is found by the read.
            std::fs::write(path(&root, "surf-redirect", INDEX_FILE), &tampered).unwrap();
            assert!(
                restarted
                    .get("surf-redirect", &ok1_id, None)
                    .await
                    .unwrap()
                    .is_some()
            );
            std::fs::write(path(&root, "surf-redirect", INDEX_FILE), &tampered).unwrap();
            let page = all(&restarted, "surf-redirect").await;
            assert_eq!(prompts(&page), ["b0", "ok1", "b2", "ok3"], "keep_id {keep_id}");
            assert_eq!(seqs(&page), [1, 2, 3, 4]);
        }
    }

    #[tokio::test]
    async fn a_prune_never_cuts_the_log_where_an_edited_index_says() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        old_and_new(&store, "surf-cut-at").await;
        let target = index_entry(&root, "surf-cut-at", 3);
        let mut entry = index_entry(&root, "surf-cut-at", 2);
        entry.off = target.off;
        entry.len = target.len;
        entry.id = target.id;
        rewrite_index_entry(&root, "surf-cut-at", 2, &entry);

        let anchor = store
            .prune("surf-cut-at", 30)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(anchor.seq, 2);
        let kept = all(&store, "surf-cut-at").await;
        assert_eq!(prompts(&kept), ["new-1", "new-2"], "no record inside the window was removed");
        assert_eq!(seqs(&kept), [3, 4]);
        assert_eq!(
            store
                .verify_chain("surf-cut-at")
                .await
                .unwrap()
                .count,
            2
        );
    }

    #[tokio::test]
    async fn verify_reports_a_missing_or_extra_index_entry() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        two_blocks_two_oks(&store, "surf-gap").await;
        let index = path(&root, "surf-gap", INDEX_FILE);
        let whole = std::fs::read(&index).unwrap();

        std::fs::write(&index, &whole[..3 * ENTRY_WIDTH as usize]).unwrap();
        let (problem, message) = problem_of(
            store
                .verify_chain("surf-gap")
                .await,
            "a missing entry",
        );
        assert_eq!(problem, ChainProblem::IndexMismatch);
        assert!(message.contains("no entry for record 4"), "{message}");

        let mut extra = whole.clone();
        extra.extend_from_slice(&whole[3 * ENTRY_WIDTH as usize..]);
        std::fs::write(&index, &extra).unwrap();
        let (problem, message) = problem_of(
            store
                .verify_chain("surf-gap")
                .await,
            "an extra entry",
        );
        assert_eq!(problem, ChainProblem::IndexMismatch);
        assert!(message.contains("1 records past the end of the log"), "{message}");

        assert_eq!(
            store
                .verify_chain("surf-gap")
                .await
                .unwrap()
                .count,
            4,
            "the index was rebuilt"
        );
    }

    /// old-1, old-2 (2020), mid-1, mid-2 (20 days ago), new (now).
    async fn three_ages(
        store: &GovernanceStore,
        surface: &str,
    ) {
        let now = chrono::Utc::now();
        let mid = (now - chrono::Duration::days(20)).to_rfc3339();
        let now = now.to_rfc3339();
        for (prompt, at) in [
            ("old-1", "2020-01-01T00:00:00Z"),
            ("old-2", "2020-01-02T00:00:00Z"),
            ("mid-1", mid.as_str()),
            ("mid-2", mid.as_str()),
            ("new", now.as_str()),
        ] {
            store
                .record(draft_at(surface, prompt, at, None), 0)
                .await
                .unwrap();
        }
    }

    #[tokio::test]
    async fn a_second_prune_interrupted_after_its_anchor_still_verifies_and_keeps_its_numbering() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        three_ages(&store, "surf-2nd").await;
        let first = store
            .prune("surf-2nd", 30)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((first.seq, first.prev_anchor.clone()), (2, None));
        let log = std::fs::read(path(&root, "surf-2nd", RECORDS_FILE)).unwrap();
        let index = std::fs::read(path(&root, "surf-2nd", INDEX_FILE)).unwrap();
        let second = store
            .prune("surf-2nd", 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(second.seq, 4);
        let first_link = AnchorLink {
            seq: 2,
            content_hash: first.content_hash.clone(),
        };
        assert_eq!(second.prev_anchor, Some(first_link.clone()), "the second anchor names the first");
        // Interrupted after the anchor was installed: the old log and index remain.
        std::fs::write(path(&root, "surf-2nd", RECORDS_FILE), &log).unwrap();
        std::fs::write(path(&root, "surf-2nd", INDEX_FILE), &index).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let summary = restarted
            .verify_chain("surf-2nd")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq, summary.last_seq), (3, Some(3), Some(5)));
        assert_eq!(seqs(&all(&restarted, "surf-2nd").await), [3, 4, 5]);

        // An index rebuilt in that state numbers the records from the first anchor.
        std::fs::remove_file(path(&root, "surf-2nd", INDEX_FILE)).unwrap();
        let rebuilt = GovernanceStore::new(root.path(), signer(), None);
        assert_eq!(seqs(&all(&rebuilt, "surf-2nd").await), [3, 4, 5]);
        let completed = rebuilt
            .prune("surf-2nd", 10)
            .await
            .unwrap()
            .unwrap();
        assert_eq!((completed.seq, &completed.content_hash), (second.seq, &second.content_hash));
        assert_eq!(
            completed.prev_anchor,
            Some(first_link),
            "the completing anchor names the anchor its log continued from"
        );
        let summary = rebuilt
            .verify_chain("surf-2nd")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq), (1, Some(5)));
    }

    #[tokio::test]
    async fn a_second_prune_interrupted_before_its_index_still_verifies() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        three_ages(&store, "surf-idx").await;
        store
            .prune("surf-idx", 30)
            .await
            .unwrap()
            .unwrap();
        let index = std::fs::read(path(&root, "surf-idx", INDEX_FILE)).unwrap();
        store
            .prune("surf-idx", 10)
            .await
            .unwrap()
            .unwrap();
        // The anchor and log were installed but not the rebased index.
        std::fs::write(path(&root, "surf-idx", INDEX_FILE), &index).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let page = all(&restarted, "surf-idx").await;
        assert_eq!((prompts(&page), seqs(&page)), (vec!["new".to_string()], vec![5]));
        let summary = restarted
            .verify_chain("surf-idx")
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq), (1, Some(5)));
    }

    #[tokio::test]
    async fn a_pruned_log_installed_without_its_anchor_fails_and_is_not_pruned_again() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        three_ages(&store, "surf-rev").await;
        store
            .prune("surf-rev", 30)
            .await
            .unwrap()
            .unwrap();
        let first_anchor = std::fs::read(path(&root, "surf-rev", ANCHOR_FILE)).unwrap();
        // The reverse order on a first prune: the pruned log is in, its anchor is not.
        std::fs::remove_file(path(&root, "surf-rev", ANCHOR_FILE)).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-rev")
                .await,
            "kept records with no anchor",
        );
        assert_eq!(problem, ChainProblem::Broken);
        assert!(message.contains("no retention anchor is kept"), "{message}");
        let refused = restarted
            .prune("surf-rev", 10)
            .await
            .expect_err("no anchor is signed over a chain that does not verify");
        assert!(format!("{refused:#}").contains("not pruning"), "{refused:#}");

        // And on a second prune: its log is in, the first anchor is still there.
        std::fs::write(path(&root, "surf-rev", ANCHOR_FILE), &first_anchor).unwrap();
        restarted
            .prune("surf-rev", 10)
            .await
            .unwrap()
            .unwrap();
        std::fs::write(path(&root, "surf-rev", ANCHOR_FILE), &first_anchor).unwrap();
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-rev")
                .await,
            "a log ahead of its anchor",
        );
        assert_eq!(problem, ChainProblem::Broken);
        assert!(message.contains("does not continue from the retention anchor"), "{message}");
    }

    #[tokio::test]
    async fn a_log_missing_its_newest_records_is_reported_as_truncated() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        write_mixed(&store, "surf-cut", 0, 4).await;
        let log = path(&root, "surf-cut", RECORDS_FILE);
        let text = std::fs::read_to_string(&log).unwrap();
        let kept: Vec<&str> = text.lines().take(2).collect();
        std::fs::write(&log, format!("{}\n", kept.join("\n"))).unwrap();
        let index = path(&root, "surf-cut", INDEX_FILE);
        let entries = std::fs::read(&index).unwrap();
        std::fs::write(&index, &entries[..2 * ENTRY_WIDTH as usize]).unwrap();

        let restarted = GovernanceStore::new(root.path(), signer(), None);
        let (problem, message) = problem_of(
            restarted
                .verify_chain("surf-cut")
                .await,
            "a truncated log",
        );
        assert_eq!(problem, ChainProblem::Truncated);
        assert!(message.contains("ends at record 2") && message.contains("reached record 4"), "{message}");

        let next = restarted
            .record(draft("surf-cut", "after"), 0)
            .await
            .unwrap();
        assert_eq!(next.seq, Some(3));
        let (problem, _) = problem_of(
            restarted
                .verify_chain("surf-cut")
                .await,
            "the loss stays on record",
        );
        assert_eq!(problem, ChainProblem::Truncated);
    }

    #[tokio::test]
    async fn the_retention_window_is_kept_and_archived_with_the_surface() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        assert_eq!(store.retention_window("surf-win"), 0);
        let now = chrono::Utc::now().to_rfc3339();
        store
            .record(draft_at("surf-win", "first", &now, None), 30)
            .await
            .unwrap();
        assert_eq!(store.retention_window("surf-win"), 30);
        store
            .prune("surf-win", 0)
            .await
            .unwrap();
        assert_eq!(store.retention_window("surf-win"), 0, "a cleared window is kept too");
        store
            .record(draft_at("surf-win", "second", &now, None), 7)
            .await
            .unwrap();

        let archive = store
            .archive("surf-win")
            .await
            .unwrap()
            .expect("the surface had a log");
        assert_eq!(store.retention_window(&archive), 7);
        assert_eq!(store.retention_window("surf-win"), 0, "the id starts afresh");
    }

    #[tokio::test]
    async fn a_deleted_surfaces_archive_is_pruned_and_still_verifies() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        old_and_new(&store, "surf-gone").await;
        let archive = store
            .archive("surf-gone")
            .await
            .unwrap()
            .unwrap();
        let anchor = store
            .prune(&archive, 30)
            .await
            .unwrap()
            .expect("the archive's 2020 records are due");
        assert_eq!((anchor.surface_id.as_str(), anchor.seq), ("surf-gone", 2));
        assert_eq!(store.retention_window(&archive), 30);
        let summary = store
            .verify_chain(&archive)
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq), (2, Some(3)));
    }

    #[tokio::test]
    async fn archiving_a_surface_starts_a_new_chain_for_its_id() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        let old = pruned(&root, &store, "surf-del").await;
        let archive = store
            .archive("surf-del")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(archived_surface_id(&archive), Some("surf-del"));
        assert_eq!(store.list_surfaces().unwrap(), std::slice::from_ref(&archive));
        assert!(
            store
                .archive("surf-del")
                .await
                .unwrap()
                .is_none(),
            "nothing left to archive"
        );

        let fresh = store
            .record(draft("surf-del", "new owner"), 0)
            .await
            .unwrap();
        assert_eq!(
            (
                fresh.seq,
                fresh
                    .record
                    .prev_record_hash
                    .as_str()
            ),
            (Some(1), GENESIS_HASH)
        );
        assert_eq!(prompts(&all(&store, "surf-del").await), ["new owner"]);

        let summary = store
            .verify_chain(&archive)
            .await
            .unwrap();
        assert_eq!((summary.count, summary.first_seq), (2, Some(3)));
        assert_eq!(
            summary
                .anchor
                .map(|a| a.content_hash),
            Some(
                old["credentialSubject"]["content_hash"]
                    .as_str()
                    .unwrap()
                    .to_string()
            )
        );
        assert_eq!(prompts(&all(&store, &archive).await), ["new-1", "new-2"]);
    }

    #[test]
    fn only_a_surface_id_and_a_deletion_time_make_an_archive_name() {
        assert_eq!(archived_surface_id("support-bot.deleted-20261005T101112345Z"), Some("support-bot"));
        assert_eq!(archived_surface_id("support_bot.deleted-20261005T101112345Z-2"), Some("support_bot"));
        for name in [
            "support-bot",
            "support-bot.deleted-",
            "support-bot.deleted-20261005T101112Z",
            "support-bot.deleted-20261005T101112345Z-",
            "support-bot.deleted-2026100XT101112345Z",
            "../x.deleted-20261005T101112345Z",
            ".deleted-20261005T101112345Z",
            "a.b.deleted-20261005T101112345Z",
            "x.deleted-20261005T10111234éZ",
        ] {
            assert_eq!(archived_surface_id(name), None, "{name}");
        }
    }

    #[tokio::test]
    async fn a_tenant_reads_only_its_own_records() {
        let root = temp_root();
        let store = GovernanceStore::new(root.path(), signer(), None);
        for (prompt, at, tenant) in [
            ("before-unattributed", "2026-08-01T00:00:00Z", None),
            ("theirs", "2026-08-12T00:00:00Z", Some("tenant-b")),
            ("since-unattributed", "2026-08-12T00:01:00Z", None),
            ("mine", "2026-08-12T00:02:00Z", Some("tenant-a")),
        ] {
            let mut record = draft_at("surf-t", prompt, at, Some("judge"));
            record.attribution.tenant_id = tenant.map(str::to_string);
            store
                .record(record, 0)
                .await
                .unwrap();
        }
        let a = TenantFilter {
            tenant_id: "tenant-a".to_string(),
            unattributed_since_ms: super::super::index::timestamp_ms("2026-08-10T00:00:00Z"),
        };
        let read = |order, limit, cursor| RecordQuery {
            order,
            limit,
            cursor,
            tenant: Some(a.clone()),
            ..Default::default()
        };
        assert_eq!(
            prompts(
                &store
                    .query("surf-t", read(RecordOrder::Asc, None, None))
                    .await
                    .unwrap()
            ),
            ["since-unattributed", "mine"]
        );
        let page = store
            .query("surf-t", read(RecordOrder::Desc, Some(1), None))
            .await
            .unwrap();
        assert_eq!((prompts(&page), page.next_cursor), (vec!["mine".to_string()], Some(4)));
        let page = store
            .query("surf-t", read(RecordOrder::Desc, Some(1), Some(4)))
            .await
            .unwrap();
        assert_eq!(
            (prompts(&page), page.next_cursor),
            (vec!["since-unattributed".to_string()], None),
            "no page follows: the older records are not tenant-a's"
        );
        assert_eq!(
            prompts(
                &store
                    .query("surf-t", read(RecordOrder::Asc, Some(5), None))
                    .await
                    .unwrap()
            ),
            ["since-unattributed", "mine"]
        );

        let everything = all(&store, "surf-t").await;
        let id_of = |prompt: &str| {
            everything
                .records
                .iter()
                .find(|r| r.record.prompt.as_deref() == Some(prompt))
                .unwrap()
                .record
                .record_id
                .clone()
        };
        for (prompt, visible) in [("theirs", false), ("before-unattributed", false), ("mine", true)] {
            assert_eq!(
                store
                    .get("surf-t", &id_of(prompt), Some(a.clone()))
                    .await
                    .unwrap()
                    .is_some(),
                visible,
                "{prompt}"
            );
        }
        let no_creation_time = TenantFilter {
            unattributed_since_ms: None,
            ..a.clone()
        };
        assert_eq!(
            prompts(
                &store
                    .query(
                        "surf-t",
                        RecordQuery {
                            tenant: Some(no_creation_time),
                            ..Default::default()
                        }
                    )
                    .await
                    .unwrap()
            ),
            ["mine"]
        );
    }

    /// Signs like [`KeySigner`], but holds every record of surface `slow` until
    /// the gate opens.
    struct GatedSigner {
        inner: KeySigner,
        gate: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl VcSigner for GatedSigner {
        async fn sign(
            &self,
            payload: Value,
        ) -> anyhow::Result<Value> {
            if payload["credentialSubject"]["surface_id"] == "slow" {
                self.gate.notified().await;
            }
            self.inner.sign(payload).await
        }
    }

    #[tokio::test]
    async fn one_surfaces_slow_work_does_not_hold_up_another() {
        let root = temp_root();
        let gate = Arc::new(tokio::sync::Notify::new());
        let store = GovernanceStore::new(
            root.path(),
            GovernanceSigner::new(
                "did:web:example.com".to_string(),
                Arc::new(GatedSigner {
                    inner: KeySigner {
                        key: ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]),
                        method: "did:web:example.com#key-2".to_string(),
                    },
                    gate: gate.clone(),
                }),
            ),
            None,
        );
        let slow = tokio::spawn({
            let store = store.clone();
            async move {
                store
                    .record(draft("slow", "waits"), 0)
                    .await
            }
        });
        tokio::task::yield_now().await;
        let fast = tokio::time::timeout(std::time::Duration::from_secs(10), store.record(draft("fast", "goes"), 0))
            .await
            .expect("another surface's record is not queued behind the slow one")
            .unwrap();
        assert_eq!(fast.seq, Some(1));
        assert!(!slow.is_finished());
        gate.notify_one();
        assert_eq!(
            slow.await
                .unwrap()
                .unwrap()
                .seq,
            Some(1)
        );
    }
}
