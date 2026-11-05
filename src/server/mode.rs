use std::sync::{
    OnceLock,
    atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ServerMode {
    #[default]
    Active,
    Standby,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModeChange {
    pub mode: ServerMode,
    pub generation: u64,
}

/// State shared through storage that an instance re-reads before it reports
/// ready, at startup in Active mode and on every promotion. An error holds
/// readiness back and the reload is retried.
#[async_trait::async_trait]
pub trait ReloadOnPromotion: Send + Sync {
    async fn reload_from_storage(&self) -> std::io::Result<()>;
}

const STATE_MASK: u64 = 0b11;
const STATE_STANDBY: u64 = 0;
const STATE_ACTIVATING: u64 = 1;
const STATE_ACTIVE: u64 = 2;
static SERVE_STATE: AtomicU64 = AtomicU64::new(STATE_ACTIVE);
static MODE_CHANGE_TX: OnceLock<broadcast::Sender<ModeChange>> = OnceLock::new();

/// Serializes tests that change the process-wide mode.
#[cfg(test)]
pub(crate) static MODE_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(unix)]
static PENDING_SIGNAL_HANDLES: std::sync::Mutex<Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>> =
    std::sync::Mutex::new(None);

fn pack(
    generation: u64,
    state: u64,
) -> u64 {
    (generation << 2) | state
}

fn state(packed: u64) -> u64 {
    packed & STATE_MASK
}

fn generation(packed: u64) -> u64 {
    packed >> 2
}

fn mode_change_tx() -> &'static broadcast::Sender<ModeChange> {
    MODE_CHANGE_TX.get_or_init(|| broadcast::channel(16).0)
}

pub fn subscribe_mode_changes() -> broadcast::Receiver<ModeChange> {
    mode_change_tx().subscribe()
}

pub fn set_server_mode(mode: ServerMode) {
    let next_state = match mode {
        ServerMode::Active => STATE_ACTIVATING,
        ServerMode::Standby => STATE_STANDBY,
    };
    let previous = SERVE_STATE
        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |packed| {
            Some(pack(generation(packed).wrapping_add(1), next_state))
        })
        .expect("fetch_update always returns Some");
    let next_generation = generation(previous).wrapping_add(1);
    let _ = mode_change_tx().send(ModeChange {
        mode,
        generation: next_generation,
    });
}

/// Mark the instance ready for `observed_generation`. Returns `false` when a
/// later mode change has superseded that generation, in which case nothing
/// changes and the caller must not act on the activation (for example by
/// starting listeners).
#[must_use]
pub fn mark_activation_ready(observed_generation: u64) -> bool {
    SERVE_STATE
        .compare_exchange(
            pack(observed_generation, STATE_ACTIVATING),
            pack(observed_generation, STATE_ACTIVE),
            Ordering::SeqCst,
            Ordering::SeqCst,
        )
        .is_ok()
}

pub fn current_activation_generation() -> u64 {
    generation(SERVE_STATE.load(Ordering::SeqCst))
}

pub fn current_mode() -> ServerMode {
    match state(SERVE_STATE.load(Ordering::SeqCst)) {
        STATE_STANDBY => ServerMode::Standby,
        _ => ServerMode::Active,
    }
}

pub fn is_ready_to_serve() -> bool {
    state(SERVE_STATE.load(Ordering::SeqCst)) == STATE_ACTIVE
}

/// Whether the instance is still ready in `generation`. False once a later
/// mode change has superseded it, even if a re-promotion made it ready again.
pub fn is_serving_generation(generation: u64) -> bool {
    SERVE_STATE.load(Ordering::SeqCst) == pack(generation, STATE_ACTIVE)
}

#[cfg(unix)]
fn register_raw_signals() -> Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)> {
    use tokio::signal::unix::{SignalKind, signal};

    // Runs before logging is initialised, so report straight to stderr.
    match (signal(SignalKind::user_defined1()), signal(SignalKind::user_defined2())) {
        (Ok(sigusr1), Ok(sigusr2)) => Some((sigusr1, sigusr2)),
        (sigusr1, sigusr2) => {
            eprintln!(
                "ERROR: Active/Standby signal handlers unavailable (SIGUSR1: {:?}, SIGUSR2: {:?}); mode changes are disabled",
                sigusr1.err(),
                sigusr2.err()
            );
            None
        }
    }
}

#[cfg(unix)]
pub fn install_signal_handlers() {
    if let Some(handles) = register_raw_signals() {
        let mut pending = PENDING_SIGNAL_HANDLES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *pending = Some(handles);
    }
}

#[cfg(not(unix))]
pub fn install_signal_handlers() {}

#[cfg(unix)]
pub fn spawn_signal_handlers() {
    let handles = {
        let mut pending = PENDING_SIGNAL_HANDLES
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        pending.take()
    }
    .or_else(register_raw_signals);

    let Some((mut sigusr1, mut sigusr2)) = handles else {
        return;
    };

    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = sigusr1.recv() => set_server_mode(ServerMode::Active),
                _ = sigusr2.recv() => set_server_mode(ServerMode::Standby),
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_signal_handlers() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Deserialize)]
    struct Config {
        server_mode: ServerMode,
    }

    #[test]
    fn defaults_to_active() {
        assert_eq!(ServerMode::default(), ServerMode::Active);
    }

    #[test]
    fn deserializes_active_and_standby() {
        assert_eq!(
            toml::from_str::<Config>("server_mode = \"active\"")
                .unwrap()
                .server_mode,
            ServerMode::Active
        );
        assert_eq!(
            toml::from_str::<Config>("server_mode = \"standby\"")
                .unwrap()
                .server_mode,
            ServerMode::Standby
        );
    }

    #[test]
    fn superseded_generation_cannot_be_marked_ready() {
        let _guard = MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_server_mode(ServerMode::Active);
        let superseded = current_activation_generation();
        set_server_mode(ServerMode::Active);

        assert!(!mark_activation_ready(superseded));
        assert!(!is_ready_to_serve());
        assert!(mark_activation_ready(current_activation_generation()));
        assert!(!mark_activation_ready(current_activation_generation()), "already ready");
        assert!(is_ready_to_serve());
    }

    #[test]
    fn serving_generation_ends_on_demotion_and_stays_ended_after_repromotion() {
        let _guard = MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_server_mode(ServerMode::Active);
        let activating = current_activation_generation();
        assert!(!is_serving_generation(activating), "not serving until ready");
        assert!(mark_activation_ready(activating));
        assert!(is_serving_generation(activating));

        set_server_mode(ServerMode::Standby);
        assert!(!is_serving_generation(activating), "a demotion ends the generation");

        set_server_mode(ServerMode::Active);
        assert!(mark_activation_ready(current_activation_generation()));
        assert!(is_ready_to_serve());
        assert!(!is_serving_generation(activating), "a re-promotion starts a new generation");
        assert!(is_serving_generation(current_activation_generation()));
    }

    #[test]
    fn mode_controls_readiness() {
        let _guard = MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        set_server_mode(ServerMode::Standby);
        assert!(!is_ready_to_serve());
        set_server_mode(ServerMode::Active);
        assert!(!is_ready_to_serve());
        assert!(mark_activation_ready(current_activation_generation()));
        assert!(is_ready_to_serve());
    }
}
