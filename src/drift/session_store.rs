//! Indicative Surface Data: the real prompt/response pairs a drift-monitored
//! surface produces, captured during production sampling and persisted so the
//! drift evaluation can **replay** them and measure how the surface's answers
//! move over time. Stored like the run / baseline stores — keyed by session id
//! and capped per surface so it can't grow without bound.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::retention::DriftRetention;
use crate::storage::filesystem::{StorableEntity, StorageBackend, rwlock_storage};

/// One captured request/response the surface actually served — the "indicative
/// surface data" a drift evaluation replays.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecordedSession {
    pub id: String,
    pub surface_id: String,
    /// RFC3339 timestamp the interaction was captured.
    pub captured_at: String,
    /// The request `messages` array as sent, so a replay is faithful.
    pub messages: Value,
    /// The completion text the surface produced.
    pub output: String,
    /// End-to-end latency of the captured interaction, in milliseconds.
    #[serde(default)]
    pub latency_ms: u64,
    /// Completion length of the captured interaction, in output tokens.
    #[serde(default)]
    pub output_tokens: u64,
}

impl StorableEntity for RecordedSession {
    fn id(&self) -> &str {
        &self.id
    }
}

/// File-backed store of captured surface sessions.
pub struct RecordedSessionStore {
    storage: Box<dyn StorageBackend<RecordedSession>>,
    retention: DriftRetention,
}

#[async_trait::async_trait]
impl crate::server::mode::ReloadOnPromotion for RecordedSessionStore {
    /// Re-read the recorded sessions another instance stored, so retention counts and prunes them.
    async fn reload_from_storage(&self) -> std::io::Result<()> {
        self.storage
            .refresh_from_disk()
            .await
            .map_err(std::io::Error::other)
    }
}

impl RecordedSessionStore {
    pub async fn new(
        storage_dir: String,
        retention: DriftRetention,
    ) -> Result<Self> {
        let storage = rwlock_storage(PathBuf::from(storage_dir), "drift_session").await?;
        Ok(Self { storage, retention })
    }

    async fn list(&self) -> Vec<RecordedSession> {
        self.storage
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// A surface's captured sessions, newest first.
    pub async fn list_for_surface(
        &self,
        surface_id: &str,
    ) -> Vec<RecordedSession> {
        let mut sessions: Vec<RecordedSession> = self
            .list()
            .await
            .into_iter()
            .filter(|s| s.surface_id == surface_id)
            .collect();
        sessions.sort_by(|a, b| {
            b.captured_at
                .cmp(&a.captured_at)
        });
        sessions
    }

    /// How many sessions a surface currently has captured.
    pub async fn count_for_surface(
        &self,
        surface_id: &str,
    ) -> usize {
        self.list()
            .await
            .into_iter()
            .filter(|s| s.surface_id == surface_id)
            .count()
    }

    /// Persist a captured session, then prune the surface's history to the
    /// configured retention (newest N per surface + any older than the age cap).
    pub async fn append(
        &self,
        session: &RecordedSession,
    ) -> Result<()> {
        self.storage
            .save(session)
            .await?;
        self.prune_surface(&session.surface_id)
            .await;
        Ok(())
    }

    async fn prune_surface(
        &self,
        surface_id: &str,
    ) {
        // list_for_surface is already newest-first.
        let sessions = self
            .list_for_surface(surface_id)
            .await;
        let cutoff = self.retention.age_cutoff();
        for (idx, session) in sessions.iter().enumerate() {
            if idx >= self.retention.max_per_surface || DriftRetention::is_expired(&session.captured_at, cutoff) {
                let _ = self
                    .storage
                    .delete(&session.id)
                    .await;
            }
        }
    }

    /// Re-apply the retention policy to every surface (the periodic sweep), so
    /// age-based expiry also reaches surfaces that have gone idle.
    pub async fn prune_all(&self) {
        let ids: HashSet<String> = self
            .list()
            .await
            .iter()
            .map(|s| s.surface_id.clone())
            .collect();
        for id in ids {
            self.prune_surface(&id).await;
        }
    }

    /// Delete every captured session for `surface_id` (surface soft-delete cleanup).
    pub async fn delete_for_surface(
        &self,
        surface_id: &str,
    ) {
        for session in self.list().await {
            if session.surface_id == surface_id {
                let _ = self
                    .storage
                    .delete(&session.id)
                    .await;
            }
        }
    }
}

static GLOBAL: OnceLock<Arc<RecordedSessionStore>> = OnceLock::new();

/// Register the process-wide captured-session store (orchestrator, once).
pub fn set_global_drift_session_store(store: Arc<RecordedSessionStore>) {
    let _ = GLOBAL.set(store);
}

/// Access the process-wide captured-session store, if registered.
pub fn global_drift_session_store() -> Option<Arc<RecordedSessionStore>> {
    GLOBAL.get().cloned()
}
