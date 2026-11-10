//! Periodic session cleanup task

use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, info};

/// Periodically clean up expired SAML/Passkey sessions
/// Runs every 5 minutes to keep disk storage clean and prevent accumulation
pub async fn periodic_session_cleanup(saml_session_manager: Option<Arc<crate::auth::SessionManager>>) {
    // Clean up every 5 minutes
    let mut ticker = crate::server::mode::ReadyTicker::new(Duration::from_secs(300));

    info!("Starting periodic session cleanup task (interval: 5 minutes)");

    loop {
        // Deleting session files changes shared storage, which only the Active
        // instance may do; a Standby's expiry times are those it loaded at startup.
        ticker.tick().await;

        debug!("Running periodic session cleanup...");

        // Clean up SAML/Passkey sessions if available
        if let Some(ref session_mgr) = saml_session_manager {
            session_mgr
                .cleanup_expired()
                .await;
        }

        debug!("Periodic session cleanup completed");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::mode::{
        MODE_TEST_LOCK, ServerMode, current_activation_generation, mark_activation_ready, set_server_mode,
    };

    fn session_files(dir: &std::path::Path) -> usize {
        std::fs::read_dir(dir)
            .unwrap()
            .count()
    }

    #[test]
    fn cleanup_runs_as_soon_as_the_instance_is_ready_not_after_a_full_period() {
        let _guard = MODE_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap()
            .block_on(async {
                let dir = tempfile::tempdir().unwrap();
                let manager = Arc::new(
                    crate::auth::SessionManager::with_storage(0, dir.path().to_path_buf())
                        .await
                        .unwrap(),
                );
                manager
                    .create_session("alice".into(), "user-a".into())
                    .await;
                assert_eq!(session_files(dir.path()), 1);

                set_server_mode(ServerMode::Standby);
                let task = tokio::spawn(periodic_session_cleanup(Some(manager)));
                tokio::time::sleep(Duration::from_millis(200)).await;
                assert_eq!(session_files(dir.path()), 1, "a Standby leaves the shared session files alone");

                set_server_mode(ServerMode::Active);
                assert!(mark_activation_ready(current_activation_generation()));
                tokio::time::timeout(Duration::from_secs(5), async {
                    while session_files(dir.path()) != 0 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                })
                .await
                .expect("the expired session is removed once ready, well before the 5 minute period");
                task.abort();
            });
    }
}
