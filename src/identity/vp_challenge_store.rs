//! Single-use challenges for the presentations this appliance verifies, held in
//! memory only. An issued challenge is redeemed once, on its Surface, and only by
//! the principal it was issued to; a Fabric envelope id is claimed once per
//! sender, and only the same presentation redelivered in it is accepted again.
//! Each Surface and sender has its own lock, so one never holds up another; the
//! sweep retires an emptied entry, and a writer that holds one starts again.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use base64::Engine;
use chrono::{DateTime, TimeDelta, Utc};
use dashmap::DashMap;
use parking_lot::Mutex;
use rand::RngCore;
use tracing::debug;

pub const VP_CHALLENGE_TTL: TimeDelta = TimeDelta::minutes(5);

const VP_CHALLENGE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(60);

const MAX_ISSUED_PER_SURFACE: usize = 100_000;

const MAX_ISSUED_PER_CALLER: usize = 32;

const MAX_CLAIMED_PER_SENDER: usize = 100_000;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum IssueRefused {
    #[error("this caller already holds the most unused VP challenges allowed on this surface")]
    CallerLimit,
    #[error("too many VP challenges are waiting to be redeemed on this surface")]
    SurfaceFull,
}

/// An address only counts towards the per-caller limit: unlike a principal, it
/// can change between asking for a challenge and presenting it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ChallengeCaller {
    Principal(String),
    Address(IpAddr),
}

struct Issued {
    caller: ChallengeCaller,
    expires_at: DateTime<Utc>,
}

struct Claim {
    /// The `proofValue` of the presentation that claimed the envelope id.
    presentation: String,
    forget_at: DateTime<Utc>,
}

#[derive(Default)]
struct SurfaceChallenges {
    retired: bool,
    issued: HashMap<String, Issued>,
    by_caller: HashMap<ChallengeCaller, Vec<String>>,
}

impl SurfaceChallenges {
    /// Forget `caller`'s expired challenges and return how many it still holds.
    fn held_by(
        &mut self,
        caller: &ChallengeCaller,
        now: DateTime<Utc>,
    ) -> usize {
        let Self { issued, by_caller, .. } = self;
        let Some(held) = by_caller.get_mut(caller) else {
            return 0;
        };
        held.retain(|challenge| match issued.get(challenge) {
            Some(entry) if entry.expires_at > now => true,
            _ => {
                issued.remove(challenge);
                false
            }
        });
        let count = held.len();
        if count == 0 {
            by_caller.remove(caller);
        }
        count
    }

    fn redeem(
        &mut self,
        challenge: &str,
        principal: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        let Some(entry) = self.issued.get(challenge) else {
            return false;
        };
        if let ChallengeCaller::Principal(owner) = &entry.caller
            && principal != Some(owner.as_str())
        {
            return false;
        }
        let Some(entry) = self.issued.remove(challenge) else {
            return false;
        };
        if let Some(held) = self
            .by_caller
            .get_mut(&entry.caller)
        {
            held.retain(|other| other != challenge);
            if held.is_empty() {
                self.by_caller
                    .remove(&entry.caller);
            }
        }
        entry.expires_at > now
    }

    fn forget_expired(
        &mut self,
        now: DateTime<Utc>,
    ) -> usize {
        let before = self.issued.len();
        self.issued
            .retain(|_, entry| entry.expires_at > now);
        let Self { issued, by_caller, .. } = self;
        by_caller.retain(|_, held| {
            held.retain(|challenge| issued.contains_key(challenge));
            !held.is_empty()
        });
        before - issued.len()
    }
}

#[derive(Default)]
struct SenderClaims {
    retired: bool,
    claims: HashMap<String, Claim>,
}

pub struct VpChallengeStore {
    max_issued_per_surface: usize,
    max_issued_per_caller: usize,
    max_claimed_per_sender: usize,
    issued: DashMap<String, Arc<Mutex<SurfaceChallenges>>>,
    claimed: DashMap<String, Arc<Mutex<SenderClaims>>>,
}

impl Default for VpChallengeStore {
    fn default() -> Self {
        Self::with_capacity(MAX_ISSUED_PER_SURFACE, MAX_ISSUED_PER_CALLER, MAX_CLAIMED_PER_SENDER)
    }
}

impl VpChallengeStore {
    fn with_capacity(
        max_issued_per_surface: usize,
        max_issued_per_caller: usize,
        max_claimed_per_sender: usize,
    ) -> Self {
        Self {
            max_issued_per_surface,
            max_issued_per_caller,
            max_claimed_per_sender,
            issued: DashMap::new(),
            claimed: DashMap::new(),
        }
    }

    /// Refused while `caller` holds [`MAX_ISSUED_PER_CALLER`] unexpired challenges on
    /// the Surface, or the Surface holds [`MAX_ISSUED_PER_SURFACE`] until the sweep.
    pub fn issue(
        &self,
        surface_id: &str,
        caller: &ChallengeCaller,
        now: DateTime<Utc>,
    ) -> Result<(String, DateTime<Utc>), IssueRefused> {
        loop {
            let surface = Arc::clone(
                &self
                    .issued
                    .entry(surface_id.to_string())
                    .or_default(),
            );
            let mut surface = surface.lock();
            if surface.retired {
                continue;
            }
            if surface.held_by(caller, now) >= self.max_issued_per_caller {
                return Err(IssueRefused::CallerLimit);
            }
            if surface.issued.len() >= self.max_issued_per_surface {
                return Err(IssueRefused::SurfaceFull);
            }
            let challenge = random_challenge();
            let expires_at = now + VP_CHALLENGE_TTL;
            surface.issued.insert(
                challenge.clone(),
                Issued {
                    caller: caller.clone(),
                    expires_at,
                },
            );
            surface
                .by_caller
                .entry(caller.clone())
                .or_default()
                .push(challenge.clone());
            return Ok((challenge, expires_at));
        }
    }

    /// A challenge refused for another Surface or principal is left for its owner.
    pub fn redeem(
        &self,
        challenge: &str,
        surface_ids: &[&str],
        principal: Option<&str>,
        now: DateTime<Utc>,
    ) -> bool {
        surface_ids
            .iter()
            .any(|surface_id| {
                self.issued
                    .get(*surface_id)
                    .map(|surface| Arc::clone(surface.value()))
                    .is_some_and(|surface| {
                        surface
                            .lock()
                            .redeem(challenge, principal, now)
                    })
            })
    }

    /// The same presentation, redelivered, is accepted again; another one is refused
    /// while the claim is live.
    pub fn claim(
        &self,
        sender: &str,
        envelope_id: &str,
        presentation: &str,
        until: DateTime<Utc>,
        now: DateTime<Utc>,
    ) -> Result<()> {
        loop {
            let sender_claims = Arc::clone(
                &self
                    .claimed
                    .entry(sender.to_string())
                    .or_default(),
            );
            let mut sender_claims = sender_claims.lock();
            if sender_claims.retired {
                continue;
            }
            let claims = &mut sender_claims.claims;
            if let Some(claim) = claims
                .get(envelope_id)
                .filter(|claim| claim.forget_at > now)
            {
                anyhow::ensure!(claim.presentation == presentation, "VP challenge was already used");
                return Ok(());
            }
            anyhow::ensure!(
                claims.contains_key(envelope_id) || claims.len() < self.max_claimed_per_sender,
                "too many VP challenges are claimed by this sender"
            );
            claims.insert(
                envelope_id.to_string(),
                Claim {
                    presentation: presentation.to_string(),
                    forget_at: until,
                },
            );
            return Ok(());
        }
    }

    pub fn sweep(
        &self,
        now: DateTime<Utc>,
    ) -> usize {
        let surfaces: Vec<_> = self
            .issued
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let senders: Vec<_> = self
            .claimed
            .iter()
            .map(|entry| Arc::clone(entry.value()))
            .collect();
        let mut removed = 0;
        for surface in surfaces {
            removed += surface
                .lock()
                .forget_expired(now);
        }
        for sender in senders {
            let mut sender = sender.lock();
            let before = sender.claims.len();
            sender
                .claims
                .retain(|_, claim| claim.forget_at > now);
            removed += before - sender.claims.len();
        }
        self.issued
            .retain(|_, surface| {
                let mut surface = surface.lock();
                surface.retired = surface.issued.is_empty();
                !surface.retired
            });
        self.claimed
            .retain(|_, sender| {
                let mut sender = sender.lock();
                sender.retired = sender.claims.is_empty();
                !sender.retired
            });
        removed
    }

    pub async fn sweep_periodically(self: Arc<Self>) {
        let mut ticker = tokio::time::interval(VP_CHALLENGE_SWEEP_INTERVAL);
        loop {
            ticker.tick().await;
            let removed = self.sweep(Utc::now());
            if removed > 0 {
                debug!(removed, "Swept expired VP challenges");
            }
        }
    }
}

fn random_challenge() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn later(
        now: DateTime<Utc>,
        seconds: i64,
    ) -> DateTime<Utc> {
        now + TimeDelta::seconds(seconds)
    }

    fn address(last: u8) -> ChallengeCaller {
        ChallengeCaller::Address(IpAddr::from([192, 0, 2, last]))
    }

    fn principal(name: &str) -> ChallengeCaller {
        ChallengeCaller::Principal(name.to_string())
    }

    #[test]
    fn test_issue_returns_distinct_challenges_expiring_after_the_ttl() {
        let store = VpChallengeStore::default();
        let now = Utc::now();

        let (first, expires_at) = store
            .issue("alpha", &address(1), now)
            .expect("issue");
        let (second, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert_ne!(first, second);
        assert_eq!(first.len(), 43);
        assert_eq!(expires_at, now + VP_CHALLENGE_TTL);
    }

    #[test]
    fn test_redeem_succeeds_once() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (challenge, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert!(store.redeem(&challenge, &["alpha"], None, later(now, 1)));
        assert!(
            !store.redeem(&challenge, &["alpha"], None, later(now, 2)),
            "a redeemed challenge cannot be redeemed again"
        );
    }

    #[test]
    fn test_redeem_refuses_another_surface_and_leaves_the_challenge() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (challenge, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert!(!store.redeem(&challenge, &["bravo"], None, now));
        assert!(store.redeem(&challenge, &["bravo", "alpha"], None, now), "the issuing surface can still redeem it");
    }

    #[test]
    fn test_redeem_binds_a_principal_challenge_to_that_principal() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (challenge, _) = store
            .issue("alpha", &principal("agent-a"), now)
            .expect("issue");

        assert!(!store.redeem(&challenge, &["alpha"], None, now), "an unauthenticated presenter cannot use it");
        assert!(!store.redeem(&challenge, &["alpha"], Some("agent-b"), now), "another principal cannot use it");
        assert!(store.redeem(&challenge, &["alpha"], Some("agent-a"), now), "it was left for its owner");
    }

    #[test]
    fn test_redeem_lets_any_presenter_use_an_address_challenge() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (challenge, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert!(store.redeem(&challenge, &["alpha"], Some("agent-a"), now));
    }

    #[test]
    fn test_redeem_refuses_an_expired_challenge() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (challenge, expires_at) = store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert!(!store.redeem(&challenge, &["alpha"], None, expires_at));
    }

    #[test]
    fn test_redeem_refuses_an_unknown_challenge() {
        let store = VpChallengeStore::default();

        assert!(!store.redeem("never-issued", &["alpha"], None, Utc::now()));
    }

    #[test]
    fn test_redeem_refuses_a_claimed_envelope_id() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        store
            .claim("did:example:peer", "envelope-1", "vp-1", later(now, 60), now)
            .expect("claim");

        assert!(
            !store.redeem("envelope-1", &["did:example:peer"], None, now),
            "a claimed envelope id is not an issued challenge"
        );
    }

    #[test]
    fn test_issue_is_refused_on_a_full_surface_only() {
        let store = VpChallengeStore::with_capacity(2, 32, 2);
        let now = Utc::now();
        store
            .issue("alpha", &address(1), now)
            .expect("issue");
        store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert_eq!(
            store
                .issue("alpha", &address(1), now)
                .err(),
            Some(IssueRefused::SurfaceFull)
        );
        assert!(
            store
                .issue("bravo", &address(1), now)
                .is_ok(),
            "another surface still issues challenges"
        );
        let after_ttl = now + VP_CHALLENGE_TTL;
        assert_eq!(
            store
                .issue("alpha", &address(2), after_ttl)
                .err(),
            Some(IssueRefused::SurfaceFull),
            "a full surface is not scanned on issue"
        );
        store.sweep(after_ttl);
        assert!(
            store
                .issue("alpha", &address(2), after_ttl)
                .is_ok(),
            "the sweep makes room"
        );
    }

    #[test]
    fn test_issue_is_refused_to_a_caller_holding_its_limit_only() {
        let store = VpChallengeStore::with_capacity(10, 2, 2);
        let now = Utc::now();
        let (first, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");
        store
            .issue("alpha", &address(1), now)
            .expect("issue");

        assert_eq!(
            store
                .issue("alpha", &address(1), now)
                .err(),
            Some(IssueRefused::CallerLimit)
        );
        assert!(
            store
                .issue("alpha", &address(2), now)
                .is_ok(),
            "another caller is unaffected"
        );
        assert!(
            store
                .issue("bravo", &address(1), now)
                .is_ok(),
            "the caller's limit is per surface"
        );
        assert!(store.redeem(&first, &["alpha"], None, now));
        assert!(
            store
                .issue("alpha", &address(1), now)
                .is_ok(),
            "a redeemed challenge frees a slot"
        );
        assert!(
            store
                .issue("alpha", &address(1), now + VP_CHALLENGE_TTL)
                .is_ok(),
            "expired challenges free slots"
        );
    }

    #[test]
    fn test_claim_accepts_a_redelivery_of_the_same_presentation_only() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let until = later(now, 300);
        store
            .claim("did:example:peer", "envelope-1", "vp-1", until, now)
            .expect("first claim");

        assert!(
            store
                .claim("did:example:peer", "envelope-1", "vp-1", until, later(now, 1))
                .is_ok(),
            "a redelivered envelope keeps its identity"
        );
        let reuse = store.claim("did:example:peer", "envelope-1", "vp-2", until, later(now, 1));
        assert!(matches!(reuse, Err(e) if e.to_string().contains("already used")));
        assert!(
            store
                .claim("did:example:peer", "envelope-1", "vp-2", later(until, 300), until)
                .is_ok(),
            "a forgotten claim can be made again"
        );
    }

    #[test]
    fn test_claims_are_kept_per_sender() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        store
            .claim("did:example:alpha", "envelope-1", "vp-1", later(now, 300), now)
            .expect("claim");

        assert!(
            store
                .claim("did:example:bravo", "envelope-1", "vp-2", later(now, 300), now)
                .is_ok(),
            "another sender's envelope id does not collide"
        );
    }

    #[test]
    fn test_claim_is_refused_when_the_sender_is_full_of_live_claims() {
        let store = VpChallengeStore::with_capacity(2, 32, 1);
        let now = Utc::now();
        store
            .claim("did:example:alpha", "envelope-1", "vp-1", later(now, 60), now)
            .expect("claim");

        let refused = store.claim("did:example:alpha", "envelope-2", "vp-2", later(now, 60), now);
        assert!(matches!(refused, Err(e) if e.to_string().contains("too many")));
        assert!(
            store
                .claim("did:example:bravo", "envelope-2", "vp-2", later(now, 60), now)
                .is_ok(),
            "another sender is unaffected"
        );
        store.sweep(later(now, 60));
        assert!(
            store
                .claim("did:example:alpha", "envelope-2", "vp-2", later(now, 120), later(now, 60))
                .is_ok(),
            "the sweep makes room"
        );
    }

    #[test]
    fn test_a_surface_being_swept_does_not_hold_up_another() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        store
            .issue("bravo", &address(1), now)
            .expect("issue");
        let bravo = store
            .issued
            .get("bravo")
            .map(|surface| Arc::clone(surface.value()))
            .expect("bravo");
        let _held_by_the_sweep = bravo.lock();

        assert!(
            store
                .issue("alpha", &address(1), now)
                .is_ok()
        );
        assert!(!store.redeem("unknown", &["alpha"], None, now));
    }

    #[test]
    fn test_sweep_forgets_expired_challenges_and_drops_emptied_entries() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        let (issued, _) = store
            .issue("alpha", &address(1), now)
            .expect("issue");
        store
            .claim("did:example:peer", "short", "vp-1", later(now, 10), now)
            .expect("claim");
        store
            .claim("did:example:peer", "long", "vp-2", later(now, 600), now)
            .expect("claim");

        assert_eq!(store.sweep(later(now, 30)), 1);
        assert_eq!(store.sweep(now + VP_CHALLENGE_TTL), 1);
        assert!(!store.redeem(&issued, &["alpha"], None, now), "a swept challenge is gone");
        assert!(
            store
                .issued
                .get("alpha")
                .is_none(),
            "an emptied surface entry is dropped"
        );
        assert!(
            store
                .claimed
                .get("did:example:peer")
                .is_some(),
            "a sender with a live claim is kept"
        );
        let reuse = store.claim("did:example:peer", "long", "vp-3", later(now, 900), later(now, 400));
        assert!(reuse.is_err(), "an unexpired claim survives");

        assert_eq!(store.sweep(later(now, 600)), 1);
        assert!(
            store
                .claimed
                .get("did:example:peer")
                .is_none(),
            "an emptied sender entry is dropped"
        );
    }

    #[test]
    fn test_issue_starts_again_on_a_fresh_entry_after_the_sweep_retires_one() {
        let store = VpChallengeStore::default();
        let now = Utc::now();
        store
            .issue("alpha", &address(1), now)
            .expect("issue");
        let retired = store
            .issued
            .get("alpha")
            .map(|surface| Arc::clone(surface.value()))
            .expect("alpha");
        store.sweep(now + VP_CHALLENGE_TTL);
        assert!(retired.lock().retired);

        let (challenge, _) = store
            .issue("alpha", &address(1), now + VP_CHALLENGE_TTL)
            .expect("issue on a fresh entry");

        assert!(store.redeem(&challenge, &["alpha"], None, now + VP_CHALLENGE_TTL));
    }
}
