//! Fixed resolution tiers and value types for the in-process usage telemetry
//! store. Counters are additive (cost, tokens, request count), so a coarse
//! bucket is simply the sum of the finer buckets it spans.

use serde::{Deserialize, Serialize};

use crate::pipes::key_source::KeySourceCounts;

fn is_zero(value: &f64) -> bool {
    *value == 0.0
}

/// Accumulated additive counters for one bucket of one series.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Sample {
    pub cost: f64,
    pub tokens: u64,
    pub requests: u64,
    /// The part of `cost` spent on owned keys (the caller's or the customer's),
    /// which is never billed. A bucket that carries none bills its whole cost.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub owned_cost: f64,
    /// Requests counted by the source of the key that served them (see
    /// [`crate::telemetry::record_pipe_execution`]).
    #[serde(default, skip_serializing_if = "KeySourceCounts::is_empty")]
    pub key_sources: KeySourceCounts,
}

impl Sample {
    /// The part of `cost` billed to the account.
    pub fn billed_cost(&self) -> f64 {
        (self.cost - self.owned_cost).max(0.0)
    }
}

impl crate::timeseries::RrdSample for Sample {
    fn merge(
        &mut self,
        other: &Self,
    ) {
        self.cost += other.cost;
        self.tokens += other.tokens;
        self.requests += other.requests;
        self.owned_cost += other.owned_cost;
        self.key_sources
            .add(other.key_sources);
    }
}

/// One point returned by a range query: bucket start (unix seconds) + counters.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SeriesPoint {
    pub t: i64,
    /// Spend at the priced (catalog) rate, whoever's key served it.
    pub cost: f64,
    /// The part of `cost` billed to the account: spend on platform keys only.
    pub billed_cost: f64,
    pub tokens: u64,
    pub requests: u64,
    /// Requests by the source of the key that served them.
    pub requests_by_key_source: KeySourceCounts,
}

/// A single series' range-query result: which tier served it plus the points.
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SeriesResponse {
    pub key: String,
    pub resolution: String,
    pub step_secs: i64,
    pub points: Vec<SeriesPoint>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipes::key_source::KeySource;
    use crate::timeseries::RrdSample;

    #[test]
    fn a_bucket_without_the_owned_split_bills_its_whole_cost() {
        let old: Sample =
            serde_json::from_value(serde_json::json!({ "cost": 1.5, "tokens": 10, "requests": 2 })).unwrap();
        assert_eq!(old.billed_cost(), 1.5);
        assert!(old.key_sources.is_empty());
    }

    #[test]
    fn merged_buckets_add_owned_cost_and_key_sources() {
        let mut bucket = Sample {
            cost: 1.0,
            tokens: 10,
            requests: 1,
            owned_cost: 1.0,
            key_sources: KeySourceCounts::one(KeySource::Customer),
        };
        bucket.merge(&Sample {
            cost: 0.5,
            tokens: 5,
            requests: 1,
            owned_cost: 0.0,
            key_sources: KeySourceCounts::one(KeySource::Platform),
        });
        assert!((bucket.billed_cost() - 0.5).abs() < 1e-9);
        assert_eq!(bucket.key_sources.customer, 1);
        assert_eq!(bucket.key_sources.platform, 1);
        assert_eq!(bucket.requests, 2);
    }

    #[test]
    fn an_empty_split_is_not_written_to_a_snapshot() {
        let value = serde_json::to_value(Sample {
            cost: 1.0,
            tokens: 1,
            requests: 1,
            ..Default::default()
        })
        .unwrap();
        assert!(
            value
                .get("owned_cost")
                .is_none()
        );
        assert!(
            value
                .get("key_sources")
                .is_none()
        );
    }
}
