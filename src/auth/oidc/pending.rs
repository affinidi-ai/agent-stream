//! Sign-ins started at `/oidc/login` and not yet finished at the callback,
//! keyed by their `state`. Each is used once and expires.

use std::time::{Duration, Instant};

use dashmap::DashMap;

/// How long a started sign-in waits for the provider to send the browser
/// back. Long enough for a sign-in with a second factor at the provider.
pub const PENDING_SIGN_IN_TTL: Duration = Duration::from_secs(10 * 60);

/// Most sign-ins outstanding at once. `/oidc/login` is public, so a flood of
/// starts must not grow memory without bound; at the cap the entry closest to
/// expiry is dropped so a new sign-in still proceeds. The request rate is
/// limited per client by `auth::throttle`.
const MAX_PENDING_SIGN_INS: usize = 10_000;

/// What the callback needs from the start of its sign-in.
pub struct PendingSignIn {
    pub nonce: String,
    pub code_verifier: String,
    expires_at: Instant,
}

#[derive(Default)]
pub struct PendingSignIns {
    entries: DashMap<String, PendingSignIn>,
}

impl PendingSignIns {
    pub fn insert(
        &self,
        state: String,
        nonce: String,
        code_verifier: String,
    ) {
        let now = Instant::now();
        self.entries
            .retain(|_, pending| pending.expires_at > now);
        if self.entries.len() >= MAX_PENDING_SIGN_INS {
            // Collect the key first so no shard lock is held across the remove.
            let soonest = self
                .entries
                .iter()
                .min_by_key(|entry| entry.value().expires_at)
                .map(|entry| entry.key().clone());
            if let Some(key) = soonest {
                self.entries.remove(&key);
            }
        }
        self.entries.insert(
            state,
            PendingSignIn {
                nonce,
                code_verifier,
                expires_at: now + PENDING_SIGN_IN_TTL,
            },
        );
    }

    /// Remove and return the sign-in `state` names, unless it has expired.
    pub fn take(
        &self,
        state: &str,
    ) -> Option<PendingSignIn> {
        self.entries
            .remove(state)
            .map(|(_, pending)| pending)
            .filter(|pending| pending.expires_at > Instant::now())
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_sign_in_can_be_taken_once() {
        let pending = PendingSignIns::default();
        pending.insert("s1".into(), "n1".into(), "v1".into());

        let taken = pending.take("s1").unwrap();
        assert_eq!(taken.nonce, "n1");
        assert_eq!(taken.code_verifier, "v1");
        assert!(pending.take("s1").is_none(), "a state works once");
        assert!(
            pending
                .take("unknown")
                .is_none()
        );
    }

    #[test]
    fn an_expired_sign_in_cannot_be_taken() {
        let pending = PendingSignIns::default();
        pending.insert("s1".into(), "n1".into(), "v1".into());
        pending
            .entries
            .get_mut("s1")
            .unwrap()
            .expires_at = Instant::now();

        assert!(pending.take("s1").is_none());
    }

    #[test]
    fn at_the_cap_the_oldest_sign_in_makes_room() {
        let pending = PendingSignIns::default();
        for index in 0..MAX_PENDING_SIGN_INS {
            pending.insert(format!("s{index}"), String::new(), String::new());
        }
        pending
            .entries
            .get_mut("s7")
            .unwrap()
            .expires_at -= Duration::from_secs(60);

        pending.insert("newest".into(), String::new(), String::new());

        assert_eq!(pending.len(), MAX_PENDING_SIGN_INS);
        assert!(
            pending
                .take("newest")
                .is_some()
        );
        assert!(pending.take("s7").is_none(), "the entry closest to expiry was dropped");
    }
}
