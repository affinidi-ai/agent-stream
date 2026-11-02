//! Process-wide counters for the model-backed PII detector.
//!
//! A lightweight, in-memory success/error tally (mirroring the response cache's
//! atomic counters) so operators can see the detector's health and error rate —
//! e.g. a spike in `failed_calls` means requests are proceeding fail-open with
//! only the regex/NER masking applied. Surfaced read-only via
//! `GET /v1/prompt-guard/detector-stats`.

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::Serialize;

/// Cumulative detector call counters since process start.
#[derive(Default)]
pub struct DetectorStats {
    successful_calls: AtomicU64,
    failed_calls: AtomicU64,
}

impl DetectorStats {
    /// Record a detection call that returned a usable result.
    pub fn record_success(&self) {
        self.successful_calls
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Record a detection call that failed (transport / non-success / parse / timeout).
    pub fn record_error(&self) {
        self.failed_calls
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A point-in-time view of the counters.
    pub fn snapshot(&self) -> DetectorStatsSnapshot {
        let successful_calls = self
            .successful_calls
            .load(Ordering::Relaxed);
        let failed_calls = self
            .failed_calls
            .load(Ordering::Relaxed);
        let total_calls = successful_calls + failed_calls;
        let error_rate = if total_calls == 0 {
            0.0
        } else {
            failed_calls as f64 / total_calls as f64
        };
        DetectorStatsSnapshot {
            successful_calls,
            failed_calls,
            total_calls,
            error_rate,
        }
    }
}

/// Serializable snapshot of [`DetectorStats`] for the stats endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct DetectorStatsSnapshot {
    pub successful_calls: u64,
    pub failed_calls: u64,
    pub total_calls: u64,
    pub error_rate: f64,
}

static GLOBAL: LazyLock<DetectorStats> = LazyLock::new(DetectorStats::default);

/// The process-wide detector stats.
pub fn global() -> &'static DetectorStats {
    &GLOBAL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_computes_error_rate() {
        let stats = DetectorStats::default();
        assert_eq!(stats.snapshot().error_rate, 0.0);
        stats.record_success();
        stats.record_success();
        stats.record_success();
        stats.record_error();
        let snap = stats.snapshot();
        assert_eq!(snap.successful_calls, 3);
        assert_eq!(snap.failed_calls, 1);
        assert_eq!(snap.total_calls, 4);
        assert!((snap.error_rate - 0.25).abs() < f64::EPSILON);
    }
}
