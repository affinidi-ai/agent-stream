//! Retention policy for the per-surface drift stores (run history + captured
//! sessions), plus a periodic sweep. The stores enforce the **count** cap on
//! every write; the sweep re-applies count **and** age across every surface so
//! age-based expiry also reaches surfaces that have gone idle (an on-write prune
//! only touches a surface when it produces a new record).

use std::time::Duration;

use chrono::{DateTime, Utc};

use super::run::global_drift_run_store;
use super::session_store::global_drift_session_store;

/// Retention policy for a per-surface drift store.
#[derive(Debug, Clone, Copy)]
pub struct DriftRetention {
    /// Keep at most this many newest records per surface.
    pub max_per_surface: usize,
    /// Also drop records older than this many days (`None` / `0` = no age limit).
    pub max_age_days: Option<u64>,
}

impl DriftRetention {
    /// The instant before which records are considered expired, if an age limit
    /// is configured. Computed once per prune pass, then checked per record.
    pub fn age_cutoff(&self) -> Option<DateTime<Utc>> {
        self.max_age_days
            .filter(|d| *d > 0)
            .map(|d| Utc::now() - chrono::Duration::days(d as i64))
    }

    /// Whether an RFC3339 timestamp is before `cutoff` (older). `false` when there
    /// is no cutoff, or the timestamp doesn't parse — never delete on a bad parse.
    pub fn is_expired(
        rfc3339: &str,
        cutoff: Option<DateTime<Utc>>,
    ) -> bool {
        cutoff
            .and_then(|c| {
                DateTime::parse_from_rfc3339(rfc3339)
                    .ok()
                    .map(|t| t.with_timezone(&Utc) < c)
            })
            .unwrap_or(false)
    }

    /// Whether a periodic age sweep is worthwhile (an age limit is set).
    pub fn has_age_limit(&self) -> bool {
        self.max_age_days
            .map(|d| d > 0)
            .unwrap_or(false)
    }
}

/// How often the retention sweep re-applies the policy across all surfaces.
const SWEEP_INTERVAL_SECS: u64 = 6 * 3600;

/// Periodically re-apply the count + age retention policy to every surface, so
/// age-based expiry also reaches surfaces that have gone idle. Spawned by the
/// orchestrator only when an age limit is configured (count is enforced on
/// write, so a sweep adds nothing without an age limit). It prunes as soon as
/// the instance is Active and ready, at startup and after every promotion.
pub async fn periodic_retention_sweep() {
    let mut ticker = crate::server::mode::ReadyTicker::new(Duration::from_secs(SWEEP_INTERVAL_SECS));
    loop {
        // Pruning deletes shared files, which only the Active instance may do.
        ticker.tick().await;
        if let Some(runs) = global_drift_run_store() {
            runs.prune_all().await;
        }
        if let Some(sessions) = global_drift_session_store() {
            sessions.prune_all().await;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_age_limit_never_expires() {
        assert!(!DriftRetention::is_expired("2000-01-01T00:00:00Z", None));
        let r = DriftRetention {
            max_per_surface: 50,
            max_age_days: None,
        };
        assert!(r.age_cutoff().is_none());
        assert!(!r.has_age_limit());
    }

    #[test]
    fn age_limit_expires_old_but_not_recent() {
        let r = DriftRetention {
            max_per_surface: 50,
            max_age_days: Some(7),
        };
        let cutoff = r.age_cutoff();
        assert!(cutoff.is_some());
        assert!(r.has_age_limit());
        // A very old timestamp is expired; "now" is not.
        assert!(DriftRetention::is_expired("2000-01-01T00:00:00Z", cutoff));
        assert!(!DriftRetention::is_expired(&Utc::now().to_rfc3339(), cutoff));
    }

    #[test]
    fn zero_age_is_treated_as_no_limit() {
        let r = DriftRetention {
            max_per_surface: 50,
            max_age_days: Some(0),
        };
        assert!(r.age_cutoff().is_none());
        assert!(!r.has_age_limit());
    }

    #[test]
    fn unparseable_timestamp_is_kept() {
        let cutoff = DriftRetention {
            max_per_surface: 1,
            max_age_days: Some(1),
        }
        .age_cutoff();
        assert!(!DriftRetention::is_expired("not-a-date", cutoff));
    }
}
