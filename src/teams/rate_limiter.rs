//! Per-member ("virtual key") per-minute rate limiter.
//!
//! Enforces a member's `requests_per_minute` / `tokens_per_minute` caps over a
//! trailing 60-second window, in addition to the member's monthly budget/token
//! ceilings. This is the per-key RPM/TPM tier hosted gateways expose: a single
//! member's short-term burst rate is bounded across every team and surface they
//! touch.
//!
//! In-memory only (a `DashMap` of sliding windows), registered process-wide via
//! a global `OnceLock`, mirroring the [`crate::teams::usage_tracker`]. Request
//! events are recorded at the request boundary (RPM) and token events after
//! execution (TPM), so the token window reflects *completed* spend.

use std::collections::VecDeque;
use std::sync::{Arc, OnceLock};

use chrono::Utc;
use dashmap::DashMap;

/// Trailing window width for the per-minute caps.
const WINDOW_SECS: i64 = 60;

/// Process-wide member rate limiter, registered at startup.
static GLOBAL_MEMBER_RATE_LIMITER: OnceLock<Arc<MemberRateLimiter>> = OnceLock::new();

/// Register the process-wide member rate limiter. First write wins.
pub fn set_global_member_rate_limiter(limiter: Arc<MemberRateLimiter>) {
    let _ = GLOBAL_MEMBER_RATE_LIMITER.set(limiter);
}

/// Access the process-wide member rate limiter, if one has been registered.
pub fn global_member_rate_limiter() -> Option<Arc<MemberRateLimiter>> {
    GLOBAL_MEMBER_RATE_LIMITER
        .get()
        .cloned()
}

/// A trailing-window rate limiter keyed by member id. Request timestamps and
/// token events are kept in separate deques so RPM (request count) and TPM
/// (token sum) can be enforced independently over the last [`WINDOW_SECS`].
#[derive(Debug, Default)]
pub struct MemberRateLimiter {
    /// Request-start timestamps per key (for RPM).
    requests: DashMap<String, VecDeque<i64>>,
    /// `(timestamp, tokens)` events per key (for TPM).
    tokens: DashMap<String, VecDeque<(i64, u64)>>,
}

impl MemberRateLimiter {
    pub fn new() -> Self {
        Self::default()
    }

    /// Check whether a new request from `key` is allowed under the given caps
    /// (either may be `None` = unlimited). Prunes expired events first. Returns
    /// `Err(reason)` when a cap is already met by the trailing window (the
    /// current request is **not** counted here — call [`record_request`] on
    /// allow). `None`/absent caps never block.
    pub fn check(
        &self,
        key: &str,
        requests_per_minute: Option<u32>,
        tokens_per_minute: Option<u64>,
    ) -> Result<(), String> {
        if requests_per_minute.is_none() && tokens_per_minute.is_none() {
            return Ok(());
        }
        let now = Utc::now().timestamp();
        let cutoff = now - WINDOW_SECS;

        if let Some(rpm) = requests_per_minute {
            let count = {
                let mut window = self
                    .requests
                    .entry(key.to_string())
                    .or_default();
                while window
                    .front()
                    .is_some_and(|ts| *ts < cutoff)
                {
                    window.pop_front();
                }
                window.len() as u32
            };
            if rpm == 0 || count >= rpm {
                return Err(format!("per-key request rate limit exceeded ({rpm}/min)"));
            }
        }

        if let Some(tpm) = tokens_per_minute {
            let sum = {
                let mut window = self
                    .tokens
                    .entry(key.to_string())
                    .or_default();
                while window
                    .front()
                    .is_some_and(|(ts, _)| *ts < cutoff)
                {
                    window.pop_front();
                }
                window
                    .iter()
                    .map(|(_, t)| *t)
                    .sum::<u64>()
            };
            if tpm == 0 || sum >= tpm {
                return Err(format!("per-key token rate limit exceeded ({tpm}/min)"));
            }
        }

        Ok(())
    }

    /// Record a request start (for RPM). Call once per allowed request.
    pub fn record_request(
        &self,
        key: &str,
    ) {
        let now = Utc::now().timestamp();
        self.requests
            .entry(key.to_string())
            .or_default()
            .push_back(now);
    }

    /// Record token usage for a completed request (for TPM).
    pub fn record_tokens(
        &self,
        key: &str,
        tokens: u64,
    ) {
        if tokens == 0 {
            return;
        }
        let now = Utc::now().timestamp();
        self.tokens
            .entry(key.to_string())
            .or_default()
            .push_back((now, tokens));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_caps_never_blocks() {
        let limiter = MemberRateLimiter::new();
        assert!(
            limiter
                .check("m1", None, None)
                .is_ok()
        );
        // A record without caps still stores events but check stays open.
        limiter.record_request("m1");
        assert!(
            limiter
                .check("m1", None, None)
                .is_ok()
        );
    }

    #[test]
    fn rpm_blocks_after_limit() {
        let limiter = MemberRateLimiter::new();
        // Allow 2 requests/min.
        assert!(
            limiter
                .check("m1", Some(2), None)
                .is_ok()
        );
        limiter.record_request("m1");
        assert!(
            limiter
                .check("m1", Some(2), None)
                .is_ok()
        );
        limiter.record_request("m1");
        // Trailing window now holds 2 → the next check is blocked.
        assert!(
            limiter
                .check("m1", Some(2), None)
                .is_err()
        );
        // A different key is independent.
        assert!(
            limiter
                .check("m2", Some(2), None)
                .is_ok()
        );
    }

    #[test]
    fn tpm_blocks_after_token_sum() {
        let limiter = MemberRateLimiter::new();
        assert!(
            limiter
                .check("m1", None, Some(100))
                .is_ok()
        );
        limiter.record_tokens("m1", 60);
        assert!(
            limiter
                .check("m1", None, Some(100))
                .is_ok()
        );
        limiter.record_tokens("m1", 50);
        // 110 >= 100 → blocked.
        assert!(
            limiter
                .check("m1", None, Some(100))
                .is_err()
        );
    }

    #[test]
    fn zero_cap_blocks() {
        let limiter = MemberRateLimiter::new();
        assert!(
            limiter
                .check("m1", Some(0), None)
                .is_err()
        );
        assert!(
            limiter
                .check("m2", None, Some(0))
                .is_err()
        );
    }
}
