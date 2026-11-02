//! A usage tracker's counters on shared storage, one file per process.
//!
//! Each process writes only its own file, `usage.<process-id>.json`, holding what
//! it recorded since it started. Every other `usage*.json` in the directory is
//! what another instance of the Active/Standby group, or an earlier run of this
//! one, recorded, and the tracker adds it to its own counts. No file has two
//! writers, so no instance can lose or lower spend another one stored.
//!
//! Writes are coalesced: while one is queued, later changes ride on it. Each
//! write is flushed to a temporary file and renamed into place, then the
//! directory is flushed, so a reader never sees a partial file and a completed
//! write survives a power loss.
//!
//! A file that cannot be parsed is renamed to `<name>.corrupt-<timestamp>` and
//! not counted. A file that cannot be read is an error, so the caller can keep
//! the instance from reporting ready until a read succeeds. A file nobody has
//! written for longer than any budget period is deleted.

use chrono::{DateTime, Datelike, Utc};
use serde::{Serialize, de::DeserializeOwned};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};
use tokio::io::AsyncWriteExt;
use tokio::sync::{Mutex, MutexGuard};
use tracing::error;

const PREFIX: &str = "usage.";
const SUFFIX: &str = ".json";
const TEMP_SUFFIX: &str = ".tmp";

/// No budget period is longer than 31 days, so a file nobody wrote for longer
/// than this holds nothing that still counts.
const STALE_AFTER: Duration = Duration::from_secs(35 * 24 * 60 * 60);

/// A temporary file this old belongs to a write that never finished.
const ABANDONED_TEMP_AFTER: Duration = Duration::from_secs(60 * 60);

/// The calendar-month key (`YYYY-MM`) monthly counters are recorded under.
pub fn month_key(now: DateTime<Utc>) -> String {
    format!("{}-{:02}", now.year(), now.month())
}

/// Counters kept as this process's own shard plus the sum of every other one.
#[async_trait::async_trait]
pub trait ShardedCounters: Send + Sync + 'static {
    type Shard: Serialize + DeserializeOwned + Send + Sync;

    /// What this process has recorded, as written to its own file.
    async fn own_shard(&self) -> Self::Shard;

    /// Replace what the other files hold with `shards`.
    async fn set_other_shards(
        &self,
        shards: Vec<Self::Shard>,
    );
}

pub struct UsageShards {
    dir: PathBuf,
    own: PathBuf,
    write_lock: Mutex<()>,
    queued: AtomicBool,
}

impl UsageShards {
    pub async fn open(dir: impl Into<PathBuf>) -> Self {
        let dir = dir.into();
        if let Err(e) = tokio::fs::create_dir_all(&dir).await {
            error!("Cannot create usage directory {}: {e}", dir.display());
        }
        let own = dir.join(format!("{PREFIX}{}{SUFFIX}", uuid::Uuid::new_v4()));
        Self {
            dir,
            own,
            write_lock: Mutex::new(()),
            queued: AtomicBool::new(false),
        }
    }

    /// Fold every other file into `counters`.
    pub async fn reload<C: ShardedCounters>(
        &self,
        counters: &C,
    ) -> std::io::Result<()> {
        let others = self
            .read_others::<C::Shard>()
            .await?;
        counters
            .set_other_shards(others)
            .await;
        Ok(())
    }

    /// Write this process's shard in the background, then refresh the others.
    pub fn sync<C: ShardedCounters>(
        self: &Arc<Self>,
        counters: &Arc<C>,
    ) {
        if !self.queue_write() {
            return;
        }
        let shards = self.clone();
        let counters = counters.clone();
        tokio::spawn(async move {
            let _write = shards.begin_write().await;
            let own = counters.own_shard().await;
            shards.write(&own).await;
            if let Err(e) = shards
                .reload(&*counters)
                .await
            {
                error!("Cannot read usage files in {}: {e}", shards.dir.display());
            }
        });
    }

    /// Claim the next write. `false` means a write is already queued and will
    /// carry the caller's change.
    fn queue_write(&self) -> bool {
        !self
            .queued
            .swap(true, Ordering::AcqRel)
    }

    /// Wait for the write in progress, then start the queued one. A change
    /// made after this returns needs its own [`Self::queue_write`].
    async fn begin_write(&self) -> MutexGuard<'_, ()> {
        let guard = self.write_lock.lock().await;
        self.queued
            .store(false, Ordering::Release);
        guard
    }

    async fn read_others<T: DeserializeOwned>(&self) -> std::io::Result<Vec<T>> {
        let mut entries = match tokio::fs::read_dir(&self.dir).await {
            Ok(entries) => entries,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(e),
        };
        let mut shards = Vec::new();
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path == self.own {
                continue;
            }
            let Some(name) = entry
                .file_name()
                .to_str()
                .map(str::to_owned)
            else {
                continue;
            };
            if !name.starts_with(PREFIX) {
                continue;
            }
            let is_shard = name.ends_with(SUFFIX);
            let max_age = if is_shard {
                STALE_AFTER
            } else if name.ends_with(TEMP_SUFFIX) {
                ABANDONED_TEMP_AFTER
            } else {
                continue;
            };
            let Some(age) = age(&path).await? else {
                continue;
            };
            if age > max_age {
                remove(&path).await?;
                continue;
            }
            if !is_shard {
                continue;
            }
            let bytes = match tokio::fs::read(&path).await {
                Ok(bytes) => bytes,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(e),
            };
            match serde_json::from_slice(&bytes) {
                Ok(shard) => shards.push(shard),
                Err(e) => quarantine(&path, &e).await?,
            }
        }
        Ok(shards)
    }

    async fn write<T: Serialize>(
        &self,
        value: &T,
    ) {
        let bytes = match serde_json::to_vec_pretty(value) {
            Ok(bytes) => bytes,
            Err(e) => {
                error!("Cannot serialise usage file {}: {e}", self.own.display());
                return;
            }
        };
        let tmp = PathBuf::from(format!("{}{TEMP_SUFFIX}", self.own.display()));
        if let Err(e) = write_durably(&tmp, &self.own, &bytes).await {
            error!("Cannot write usage file {}: {e}", self.own.display());
            let _ = tokio::fs::remove_file(&tmp).await;
        }
    }

    /// Wait until no write is queued or running.
    #[cfg(test)]
    pub async fn wait_idle(&self) {
        loop {
            if !self
                .queued
                .load(Ordering::Acquire)
            {
                drop(self.write_lock.lock().await);
                if !self
                    .queued
                    .load(Ordering::Acquire)
                {
                    return;
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        }
    }

    #[cfg(test)]
    pub fn own_path(&self) -> &Path {
        &self.own
    }
}

/// Time since `path` was last written, or `None` when it is already gone.
async fn age(path: &Path) -> std::io::Result<Option<Duration>> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) => Ok(Some(
            SystemTime::now()
                .duration_since(metadata.modified()?)
                .unwrap_or_default(),
        )),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

async fn remove(path: &Path) -> std::io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

async fn quarantine(
    path: &Path,
    cause: &serde_json::Error,
) -> std::io::Result<()> {
    let aside = PathBuf::from(format!("{}.corrupt-{}", path.display(), Utc::now().format("%Y%m%dT%H%M%S%.3fZ")));
    match tokio::fs::rename(path, &aside).await {
        Ok(()) => {
            error!("Unreadable usage file {} moved to {} and not counted: {cause}", path.display(), aside.display());
            Ok(())
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

async fn write_durably(
    tmp: &Path,
    path: &Path,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut file = tokio::fs::File::create(tmp).await?;
    file.write_all(bytes).await?;
    file.sync_all().await?;
    drop(file);
    tokio::fs::rename(tmp, path).await?;
    #[cfg(unix)]
    if let Some(dir) = path.parent() {
        tokio::fs::File::open(dir)
            .await?
            .sync_all()
            .await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    type Shard = HashMap<String, u64>;

    #[derive(Default)]
    struct Recorded {
        own: std::sync::Mutex<Shard>,
        others: std::sync::Mutex<Vec<Shard>>,
    }

    #[async_trait::async_trait]
    impl ShardedCounters for Recorded {
        type Shard = Shard;

        async fn own_shard(&self) -> Shard {
            self.own
                .lock()
                .unwrap()
                .clone()
        }

        async fn set_other_shards(
            &self,
            shards: Vec<Shard>,
        ) {
            *self.others.lock().unwrap() = shards;
        }
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut names: Vec<_> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| {
                e.unwrap()
                    .file_name()
                    .into_string()
                    .unwrap()
            })
            .collect();
        names.sort();
        names
    }

    fn set_age(
        path: &Path,
        age: Duration,
    ) {
        std::fs::File::options()
            .write(true)
            .open(path)
            .unwrap()
            .set_modified(SystemTime::now() - age)
            .unwrap();
    }

    async fn synced(
        shards: &Arc<UsageShards>,
        counters: &Arc<Recorded>,
    ) {
        shards.sync(counters);
        shards.wait_idle().await;
    }

    #[tokio::test]
    async fn each_instance_reads_what_the_others_wrote_but_not_its_own() {
        let dir = tempfile::tempdir().unwrap();
        let a = Arc::new(UsageShards::open(dir.path()).await);
        let b = Arc::new(UsageShards::open(dir.path()).await);
        let a_counters = Arc::new(Recorded::default());
        let b_counters = Arc::new(Recorded::default());
        a_counters
            .own
            .lock()
            .unwrap()
            .insert("k".into(), 3);
        b_counters
            .own
            .lock()
            .unwrap()
            .insert("k".into(), 4);

        synced(&a, &a_counters).await;
        synced(&b, &b_counters).await;

        assert_eq!(
            *b_counters
                .others
                .lock()
                .unwrap(),
            vec![HashMap::from([("k".to_string(), 3)])]
        );
        a.reload(&*a_counters)
            .await
            .unwrap();
        assert_eq!(
            *a_counters
                .others
                .lock()
                .unwrap(),
            vec![HashMap::from([("k".to_string(), 4)])]
        );
        assert_eq!(names(dir.path()).len(), 2, "one file per instance and no temporary file");
    }

    #[tokio::test]
    async fn an_empty_or_missing_directory_holds_no_other_shards() {
        let dir = tempfile::tempdir().unwrap();
        let shards = UsageShards::open(dir.path().join("usage")).await;
        let counters = Recorded::default();
        shards
            .reload(&counters)
            .await
            .unwrap();
        assert!(
            counters
                .others
                .lock()
                .unwrap()
                .is_empty()
        );

        let gone = UsageShards::open(dir.path().join("gone")).await;
        std::fs::remove_dir(dir.path().join("gone")).unwrap();
        gone.reload(&counters)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn a_corrupt_file_is_moved_aside_and_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path()
                .join("usage.peer.json"),
            b"{not json",
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("usage.empty.json"),
            b"",
        )
        .unwrap();
        std::fs::write(
            dir.path()
                .join("usage.good.json"),
            br#"{"k":2}"#,
        )
        .unwrap();
        let shards = UsageShards::open(dir.path()).await;
        let counters = Recorded::default();

        shards
            .reload(&counters)
            .await
            .unwrap();

        assert_eq!(
            *counters
                .others
                .lock()
                .unwrap(),
            vec![HashMap::from([("k".to_string(), 2)])]
        );
        let names = names(dir.path());
        assert!(names.contains(&"usage.good.json".to_string()));
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("usage.peer.json.corrupt-")),
            "the corrupt file is kept as evidence: {names:?}"
        );
        assert!(
            names
                .iter()
                .any(|n| n.starts_with("usage.empty.json.corrupt-"))
        );
        assert!(!names.contains(&"usage.peer.json".to_string()));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_directory_that_cannot_be_read_is_an_error() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let shards = UsageShards::open(dir.path()).await;
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o000)).unwrap();
        let denied = std::fs::read_dir(dir.path()).is_err();

        let result = shards
            .reload(&Recorded::default())
            .await;

        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        if denied {
            assert!(result.is_err(), "an unreadable directory is never read as empty");
        }
    }

    #[tokio::test]
    async fn files_nobody_wrote_for_a_budget_period_are_deleted() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["usage.old.json", "usage.new.json", "usage.old.json.tmp", "usage.new.json.tmp"] {
            std::fs::write(dir.path().join(name), b"{}").unwrap();
        }
        std::fs::write(
            dir.path()
                .join("usage.x.json.corrupt-1"),
            b"{",
        )
        .unwrap();
        set_age(
            &dir.path()
                .join("usage.old.json"),
            STALE_AFTER + Duration::from_secs(60),
        );
        set_age(
            &dir.path()
                .join("usage.old.json.tmp"),
            ABANDONED_TEMP_AFTER + Duration::from_secs(60),
        );
        set_age(
            &dir.path()
                .join("usage.x.json.corrupt-1"),
            STALE_AFTER + Duration::from_secs(60),
        );
        let shards = UsageShards::open(dir.path()).await;
        let counters = Recorded::default();

        shards
            .reload(&counters)
            .await
            .unwrap();

        assert_eq!(
            names(dir.path()),
            vec!["usage.new.json", "usage.new.json.tmp", "usage.x.json.corrupt-1"],
            "a recent temporary file may be a peer's write in progress; a corrupt file is kept"
        );
        assert_eq!(
            counters
                .others
                .lock()
                .unwrap()
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn a_queued_write_absorbs_later_requests_until_it_starts() {
        let dir = tempfile::tempdir().unwrap();
        let file = UsageShards::open(dir.path()).await;

        assert!(file.queue_write());
        assert!(!file.queue_write(), "a queued write carries the second change");
        let guard = file.begin_write().await;
        assert!(file.queue_write(), "a change after the write started queues another");
        drop(guard);
    }

    #[tokio::test]
    async fn the_own_file_holds_the_latest_shard() {
        let dir = tempfile::tempdir().unwrap();
        let shards = Arc::new(UsageShards::open(dir.path()).await);
        let counters = Arc::new(Recorded::default());
        counters
            .own
            .lock()
            .unwrap()
            .insert("k".into(), 1);
        synced(&shards, &counters).await;
        counters
            .own
            .lock()
            .unwrap()
            .insert("k".into(), 5);
        synced(&shards, &counters).await;

        let stored: Shard = serde_json::from_slice(&std::fs::read(shards.own_path()).unwrap()).unwrap();
        assert_eq!(stored, HashMap::from([("k".to_string(), 5)]));
    }

    #[test]
    fn month_keys_are_zero_padded() {
        let at = DateTime::parse_from_rfc3339("2026-03-31T23:59:59Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(month_key(at), "2026-03");
    }
}
