//! The shared RRD resolution pyramid used by every embedded time-series store.
//!
//! Tiers are additive: a coarse bucket is exactly the sum (per the sample's own
//! `merge`) of the finer buckets it spans. The finest tier sits nearest *now*
//! and the coarsest reaches back over a year, so the union covers
//! `now … > 1 year ago`. This is the single source of truth for the pyramid —
//! the usage telemetry store re-exports it so the two engines can never drift.

/// One resolution tier: a fixed bucket step plus how many buckets to retain.
#[derive(Debug, Clone, Copy)]
pub struct Tier {
    /// Stable label used as the on-disk snapshot file name and in API responses.
    pub label: &'static str,
    /// Bucket width in seconds.
    pub step_secs: i64,
    /// Number of buckets kept before the oldest is evicted.
    pub retain: usize,
}

/// The resolution pyramid, finest first. Retention is chosen so each tier hands
/// off to the next before its window ends, and the coarsest spans several years.
pub const TIERS: &[Tier] = &[
    Tier {
        label: "30s",
        step_secs: 30,
        retain: 240,
    }, // 2 hours
    Tier {
        label: "1m",
        step_secs: 60,
        retain: 360,
    }, // 6 hours
    Tier {
        label: "5m",
        step_secs: 300,
        retain: 288,
    }, // 24 hours
    Tier {
        label: "30m",
        step_secs: 1_800,
        retain: 336,
    }, // 7 days
    Tier {
        label: "1h",
        step_secs: 3_600,
        retain: 336,
    }, // 14 days
    Tier {
        label: "12h",
        step_secs: 43_200,
        retain: 120,
    }, // 60 days
    Tier {
        label: "24h",
        step_secs: 86_400,
        retain: 180,
    }, // 180 days
    Tier {
        label: "7d",
        step_secs: 604_800,
        retain: 80,
    }, // ~1.5 years
    Tier {
        label: "30d",
        step_secs: 2_592_000,
        retain: 24,
    }, // ~2 years
    Tier {
        label: "1y",
        step_secs: 31_536_000,
        retain: 5,
    }, // 5 years
];
