//! The per-surface record index: one fixed-width line per stored record, so a
//! filtered, paged or single-record read finds its records without decrypting
//! or parsing the log.
//!
//! Each entry carries only what a read filters on and where the record lies:
//! its chain position (`seq`), byte offset and length in `records.jsonl`, its
//! timestamp, outcome, deciding stage label and record id. It holds no prompt,
//! completion or attribution, so it is kept in plain text (a read never pays a
//! decryption, which under a KMS key is one KMS call per line); it does show,
//! per interaction, when it happened, whether it was blocked and by which
//! stage. Entries are [`ENTRY_WIDTH`] bytes, so entry `n` sits at byte
//! `n * ENTRY_WIDTH` and a position is found from a sequence number without a
//! scan (positions are contiguous: the log only grows at its end and retention
//! only removes its head). The index is derived data and is not trusted: a read
//! checks each record it answers against its entry, verification checks every
//! entry, and the store rebuilds the index from the log when it is missing,
//! out of step or found to disagree.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result, anyhow};
use serde::{Deserialize, Serialize};

use super::record::{GovernanceRecord, RecordOutcome};

/// Bytes per entry, its trailing newline included.
pub(super) const ENTRY_WIDTH: u64 = 256;

/// Longest stage label an entry keeps.
const STAGE_MAX: usize = 48;

/// Longest record id an entry keeps (record ids are UUIDs).
const ID_MAX: usize = 64;

/// Entries read per chunk while scanning.
const SCAN_CHUNK: u64 = 256;

/// One stored record's index entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(super) struct IndexEntry {
    /// Position on the surface's chain: 1 for the first record ever written.
    pub seq: u64,
    /// Byte offset of the record's line in `records.jsonl`.
    pub off: u64,
    /// Length of the line, its newline excluded.
    pub len: u64,
    /// The record's timestamp, unix milliseconds (absent when it does not parse).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<i64>,
    pub outcome: RecordOutcome,
    /// The label of the stage that blocked or failed the interaction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<String>,
    /// The record id (empty when it is too long to index, which no record
    /// written by this appliance is).
    #[serde(default)]
    pub id: String,
}

impl IndexEntry {
    /// The entry for `record`, stored as line `len` bytes long at `off`.
    pub fn for_record(
        seq: u64,
        off: u64,
        len: u64,
        record: &GovernanceRecord,
    ) -> Self {
        Self {
            seq,
            off,
            len,
            ts: timestamp_ms(&record.timestamp),
            outcome: record.outcome(),
            stage: record
                .deciding_stage()
                .map(|s| stage_label(&s.stage)),
            id: if record.record_id.len() <= ID_MAX {
                record.record_id.clone()
            } else {
                String::new()
            },
        }
    }

    /// Byte offset just past the record's line (its newline included).
    pub fn end(&self) -> u64 {
        self.off + self.len + 1
    }

    /// Whether this entry, as read back from the index, is `expected` as it
    /// would be written (an over-long entry is written without its stage).
    pub fn same_as(
        &self,
        expected: &IndexEntry,
    ) -> Result<bool> {
        Ok(*self == Self::decode(&expected.encode()?)?)
    }

    /// Whether this entry was made for `record`: its id, timestamp, outcome
    /// and deciding stage.
    pub fn describes(
        &self,
        record: &GovernanceRecord,
    ) -> Result<bool> {
        self.same_as(&Self::for_record(self.seq, self.off, self.len, record))
    }

    /// The entry as exactly [`ENTRY_WIDTH`] bytes: compact JSON, space-padded,
    /// newline-terminated.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let width = ENTRY_WIDTH as usize;
        let mut line = serde_json::to_vec(self).context("serialize governance index entry")?;
        if line.len() >= width {
            let mut slim = self.clone();
            slim.stage = None;
            line = serde_json::to_vec(&slim).context("serialize governance index entry")?;
        }
        if line.len() >= width {
            return Err(anyhow!("governance index entry exceeds {width} bytes"));
        }
        line.resize(width - 1, b' ');
        line.push(b'\n');
        Ok(line)
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).context("governance index entry is not UTF-8")?;
        serde_json::from_str(text.trim_end()).context("parse governance index entry")
    }
}

/// A stage label as the index keeps it (and as a `stage` filter is compared):
/// characters outside `[A-Za-z0-9_.:-]` become `_`, cut to [`STAGE_MAX`].
pub(super) fn stage_label(raw: &str) -> String {
    raw.chars()
        .take(STAGE_MAX)
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | ':' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// An RFC 3339 timestamp as unix milliseconds.
pub(super) fn timestamp_ms(rfc3339: &str) -> Option<i64> {
    chrono::DateTime::parse_from_rfc3339(rfc3339)
        .ok()
        .map(|t| t.timestamp_millis())
}

/// Which way a scan walks the index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Direction {
    Forward,
    Backward,
}

/// An open index file. Only whole entries count: a torn trailing entry (from
/// an interrupted append) is ignored here and cut off when the store reconciles.
pub(super) struct Index {
    file: File,
    count: u64,
}

impl Index {
    /// Open the index at `path`; `None` when there is none.
    pub fn open(path: &Path) -> Result<Option<Self>> {
        match File::open(path) {
            Ok(file) => Self::from_file(file).map(Some),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).context("open governance index"),
        }
    }

    pub fn from_file(file: File) -> Result<Self> {
        let len = file
            .metadata()
            .context("stat governance index")?
            .len();
        Ok(Self { file, count: len / ENTRY_WIDTH })
    }

    /// Number of whole entries.
    pub fn count(&self) -> u64 {
        self.count
    }

    /// The entry at position `pos` (0-based).
    pub fn entry(
        &mut self,
        pos: u64,
    ) -> Result<IndexEntry> {
        let mut entries = self.read_range(pos, 1)?;
        entries
            .pop()
            .ok_or_else(|| anyhow!("governance index has no entry {pos}"))
    }

    /// Up to `n` entries from position `start` on.
    fn read_range(
        &mut self,
        start: u64,
        n: u64,
    ) -> Result<Vec<IndexEntry>> {
        let n = n.min(
            self.count
                .saturating_sub(start),
        );
        if n == 0 {
            return Ok(Vec::new());
        }
        let width = ENTRY_WIDTH as usize;
        let mut buf = vec![0u8; n as usize * width];
        self.file
            .seek(SeekFrom::Start(start * ENTRY_WIDTH))
            .context("seek governance index")?;
        self.file
            .read_exact(&mut buf)
            .context("read governance index")?;
        buf.chunks(width)
            .map(IndexEntry::decode)
            .collect()
    }

    /// Visit entries one by one from position `from` (inclusive) in `direction`,
    /// reading [`SCAN_CHUNK`] at a time, until `visit` answers `false` or the
    /// index ends. Memory stays at one chunk whatever the index's size.
    pub fn scan(
        &mut self,
        from: u64,
        direction: Direction,
        mut visit: impl FnMut(&IndexEntry) -> Result<bool>,
    ) -> Result<()> {
        match direction {
            Direction::Forward => {
                let mut start = from;
                while start < self.count {
                    for entry in self.read_range(start, SCAN_CHUNK)? {
                        if !visit(&entry)? {
                            return Ok(());
                        }
                    }
                    start += SCAN_CHUNK;
                }
            }
            Direction::Backward => {
                if self.count == 0 {
                    return Ok(());
                }
                let mut end = from.min(self.count - 1) + 1;
                while end > 0 {
                    let start = end.saturating_sub(SCAN_CHUNK);
                    for entry in self
                        .read_range(start, end - start)?
                        .iter()
                        .rev()
                    {
                        if !visit(entry)? {
                            return Ok(());
                        }
                    }
                    end = start;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::record::{GENESIS_HASH, RecordMetrics, StageEntry, StageOutcome};

    fn record(
        id: &str,
        stage: Option<&str>,
    ) -> GovernanceRecord {
        GovernanceRecord {
            record_id: id.to_string(),
            trace_id: None,
            surface_id: "s".to_string(),
            surface_name: None,
            caller_identity_hash: None,
            caller_identity_kind: None,
            principal_key: None,
            attribution: Default::default(),
            timestamp: "2026-08-12T00:00:01.500Z".to_string(),
            prev_record_hash: GENESIS_HASH.to_string(),
            stages: stage
                .map(|s| vec![StageEntry::decision(s, StageOutcome::Block, None)])
                .unwrap_or_default(),
            prompt: None,
            completion: None,
            attachments: Vec::new(),
            metrics: RecordMetrics::default(),
            content_hash: None,
        }
    }

    #[test]
    fn an_entry_is_fixed_width_and_reads_back() {
        let entry = IndexEntry::for_record(7, 1234, 99, &record("rec-1", Some("judge")));
        assert_eq!(entry.ts, Some(1_786_492_801_500));
        assert_eq!(entry.outcome, RecordOutcome::Blocked);
        assert_eq!(entry.stage.as_deref(), Some("judge"));
        assert_eq!(entry.end(), 1234 + 99 + 1);
        let bytes = entry.encode().unwrap();
        assert_eq!(bytes.len() as u64, ENTRY_WIDTH);
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(IndexEntry::decode(&bytes).unwrap(), entry);
    }

    #[test]
    fn an_ok_record_has_no_deciding_stage() {
        let entry = IndexEntry::for_record(1, 0, 10, &record("rec-ok", None));
        assert_eq!(entry.outcome, RecordOutcome::Ok);
        assert!(entry.stage.is_none());
    }

    #[test]
    fn an_entry_describes_only_the_record_it_was_made_for() {
        let blocked = record("rec-1", Some("judge"));
        let entry = IndexEntry::for_record(3, 10, 20, &blocked);
        assert!(
            entry
                .describes(&blocked)
                .unwrap()
        );

        let edits: [fn(&mut IndexEntry); 5] = [
            |e| e.outcome = RecordOutcome::Ok,
            |e| e.stage = Some("policy".to_string()),
            |e| e.stage = None,
            |e| e.ts = Some(0),
            |e| e.id = String::new(),
        ];
        for edit in edits {
            let mut altered = entry.clone();
            edit(&mut altered);
            assert!(
                !altered
                    .describes(&blocked)
                    .unwrap(),
                "{altered:?}"
            );
        }
        assert!(
            !entry
                .describes(&record("rec-2", Some("judge")))
                .unwrap()
        );
    }

    #[test]
    fn oversized_fields_never_break_the_width() {
        let long_stage = "s".repeat(500);
        let entry = IndexEntry::for_record(u64::MAX, u64::MAX, u64::MAX, &record(&"i".repeat(500), Some(&long_stage)));
        assert_eq!(entry.id, "", "an unindexable id is dropped, not truncated into another id");
        assert_eq!(
            entry
                .stage
                .as_deref()
                .map(str::len),
            Some(STAGE_MAX)
        );
        assert_eq!(entry.encode().unwrap().len() as u64, ENTRY_WIDTH);
    }

    #[test]
    fn stage_labels_are_sanitized() {
        assert_eq!(stage_label("prompt_guard_request"), "prompt_guard_request");
        assert_eq!(stage_label("a b/\"c\"\n"), "a_b__c__");
    }

    #[test]
    fn scans_walk_both_ways_across_chunks_and_stop_when_asked() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("index.jsonl");
        let total = SCAN_CHUNK * 2 + 3;
        let mut bytes = Vec::new();
        for seq in 1..=total {
            bytes.extend(
                IndexEntry::for_record(seq, seq * 10, 5, &record(&format!("r{seq}"), None))
                    .encode()
                    .unwrap(),
            );
        }
        bytes.extend(b"{\"torn\""); // an interrupted append
        std::fs::write(&path, bytes).unwrap();

        let mut index = Index::open(&path)
            .unwrap()
            .unwrap();
        assert_eq!(index.count(), total, "a torn entry is not counted");
        assert_eq!(index.entry(0).unwrap().seq, 1);
        assert_eq!(
            index
                .entry(total - 1)
                .unwrap()
                .seq,
            total
        );
        assert!(index.entry(total).is_err());

        let mut forward = Vec::new();
        index
            .scan(0, Direction::Forward, |e| {
                forward.push(e.seq);
                Ok(true)
            })
            .unwrap();
        assert_eq!(forward, (1..=total).collect::<Vec<_>>());

        let mut backward = Vec::new();
        index
            .scan(total + 50, Direction::Backward, |e| {
                backward.push(e.seq);
                Ok(true)
            })
            .unwrap();
        assert_eq!(
            backward,
            (1..=total)
                .rev()
                .collect::<Vec<_>>()
        );

        let mut stopped = Vec::new();
        index
            .scan(300, Direction::Backward, |e| {
                stopped.push(e.seq);
                Ok(stopped.len() < 3)
            })
            .unwrap();
        assert_eq!(stopped, vec![301, 300, 299]);

        assert!(
            Index::open(&dir.path().join("missing"))
                .unwrap()
                .is_none()
        );
    }
}
