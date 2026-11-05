//! Periodic session cleanup task

use std::sync::Arc;
use tokio::time::Duration;
use tracing::{debug, info};

/// Periodically clean up expired SAML/Passkey sessions
/// Runs every 5 minutes to keep disk storage clean and prevent accumulation
pub async fn periodic_session_cleanup(saml_session_manager: Option<Arc<crate::auth::SessionManager>>) {
    // Clean up every 5 minutes
    let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 minutes
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    info!("Starting periodic session cleanup task (interval: 5 minutes)");

    loop {
        // Deleting session files changes shared storage, which only the Active
        // instance may do; a Standby's expiry times are those it loaded at startup.
        crate::server::mode::tick_when_ready(&mut interval).await;

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
