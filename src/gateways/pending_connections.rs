//! Pending OOB connection state management

use crate::storage::filesystem::{StorableEntity, StorageBackend, cached_storage};
use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{debug, error};

/// State for a pending OOB connection
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingOOBConnection {
    /// Unique ID for this pending connection
    pub id: String,

    /// Our temporary/ephemeral DID used for the handshake
    pub our_temporary_did: String,

    /// Our secure/permanent DID for the established connection
    pub our_secure_did: String,

    /// Their temporary/ephemeral DID (from the invitation or connection-setup)
    pub their_temporary_did: String,

    /// Their secure DID (set when we receive it)
    pub their_secure_did: Option<String>,

    /// The mediator DID we're using
    pub mediator_did: String,

    /// Which connection point we're using
    pub connection_point_id: String,

    /// Invitation message ID (for thread tracking)
    pub invitation_id: String,

    /// Role in the connection flow
    pub role: ConnectionRole,

    /// Current state of the connection
    pub state: ConnectionState,

    /// When this pending connection was created
    pub created_at: DateTime<Utc>,

    /// When this pending connection expires
    pub expires_at: DateTime<Utc>,

    #[serde(default)]
    pub secure_cp_id: Option<String>,

    #[serde(default)]
    pub temporary_cp_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionRole {
    /// We created the OOB invitation (inviter/responder)
    Inviter,
    /// We're accepting an OOB invitation (acceptor/initiator)
    Acceptor,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    /// Waiting for connection-setup (inviter) or connection-accepted (acceptor)
    WaitingForResponse,
    /// Connection established, ready to create gateway
    ReadyToFinalize,
    /// Connection failed
    Failed(String),
}

/// Simpler pending connection for approval workflow
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingConnection {
    /// Gateway ID this connection belongs to
    pub gateway_id: String,

    /// Invitation/connection point ID
    pub invitation_id: String,

    /// Our temporary DID
    pub our_temporary_did: String,

    /// Our secure DID for the connection
    pub our_secure_did: String,

    /// Their temporary DID
    pub their_temporary_did: String,

    /// Their secure DID (from connection-setup)
    pub their_secure_did: Option<String>,

    /// Current state
    pub state: PendingConnectionState,

    /// When created
    pub created_at: DateTime<Utc>,

    /// Approval must occur before this time. Legacy records without an expiry
    /// remain readable and keep their previous behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum PendingConnectionState {
    /// Waiting for administrator approval
    AwaitingApproval,
    /// Waiting for response from remote
    WaitingForResponse,
    /// Ready to finalize
    ReadyToFinalize,
    /// Failed
    Failed(String),
}

impl PendingConnection {
    pub fn is_expired(
        &self,
        now: DateTime<Utc>,
    ) -> bool {
        self.expires_at
            .is_some_and(|expires_at| expires_at <= now)
    }
}

impl StorableEntity for PendingOOBConnection {
    fn id(&self) -> &str {
        &self.id
    }
}

impl StorableEntity for PendingConnection {
    fn id(&self) -> &str {
        &self.gateway_id
    }
}

/// Store for pending OOB connections with filesystem persistence
pub struct PendingConnectionStore {
    connections: Box<dyn StorageBackend<PendingOOBConnection>>,
    approval_connections: Box<dyn StorageBackend<PendingConnection>>,
}

impl PendingConnectionStore {
    pub async fn new(storage_dir: PathBuf) -> Result<Self> {
        let connections = cached_storage(storage_dir.join("oob"), "pending_oob_connection").await?;
        let approval_connections = cached_storage(storage_dir.join("approval"), "pending_approval_connection").await?;

        Ok(Self {
            connections,
            approval_connections,
        })
    }

    /// Store a pending connection for approval
    pub async fn store_approval(
        &self,
        connection: &PendingConnection,
    ) -> Result<(), String> {
        self.approval_connections
            .save(connection)
            .await
            .map_err(|e| format!("Failed to store approval connection: {}", e))
    }

    /// Get pending connection for approval by gateway ID
    pub async fn get_approval_by_gateway_id(
        &self,
        gateway_id: &str,
    ) -> Option<PendingConnection> {
        self.approval_connections
            .get(gateway_id)
            .await
            .ok()
            .flatten()
    }

    /// Remove pending approval connection
    pub async fn remove_approval(
        &self,
        gateway_id: &str,
    ) -> Option<PendingConnection> {
        let existing = self
            .approval_connections
            .get(gateway_id)
            .await
            .ok()
            .flatten();
        if existing.is_some()
            && let Err(e) = self
                .approval_connections
                .delete(gateway_id)
                .await
        {
            debug!("Failed to remove pending approval connection: {}", e);
        }
        existing
    }

    /// Store a pending connection
    pub async fn store(
        &self,
        connection: PendingOOBConnection,
    ) {
        if let Err(e) = self
            .connections
            .save(&connection)
            .await
        {
            error!("Failed to store OOB connection: {}", e);
        }
    }

    /// Get a pending connection by ID
    #[allow(dead_code)]
    pub async fn get(
        &self,
        id: &str,
    ) -> Option<PendingOOBConnection> {
        self.connections
            .get(id)
            .await
            .ok()
            .flatten()
    }

    /// Get a pending connection by temporary DID
    pub async fn get_by_temporary_did(
        &self,
        did: &str,
    ) -> Option<PendingOOBConnection> {
        let cache = self
            .connections
            .hash_map()
            .await
            .unwrap_or_default();
        cache
            .values()
            .find(|conn| conn.our_temporary_did == did || conn.their_temporary_did == did)
            .cloned()
    }

    /// Get a pending connection by invitation ID
    #[allow(dead_code)]
    pub async fn get_by_invitation_id(
        &self,
        invitation_id: &str,
    ) -> Option<PendingOOBConnection> {
        let cache = self
            .connections
            .hash_map()
            .await
            .unwrap_or_default();
        cache
            .values()
            .find(|conn| conn.invitation_id == invitation_id)
            .cloned()
    }

    /// Update a pending connection
    pub async fn update(
        &self,
        connection: PendingOOBConnection,
    ) {
        if let Err(e) = self
            .connections
            .save(&connection)
            .await
        {
            error!("Failed to update OOB connection: {}", e);
        }
    }

    /// Remove a pending connection
    pub async fn remove(
        &self,
        id: &str,
    ) -> Option<PendingOOBConnection> {
        let existing = self
            .connections
            .get(id)
            .await
            .ok()
            .flatten();
        if existing.is_some()
            && let Err(e) = self
                .connections
                .delete(id)
                .await
        {
            debug!("Failed to remove OOB connection: {}", e);
        }
        existing
    }

    /// List all pending connections
    #[allow(dead_code)]
    pub async fn list_all(&self) -> Vec<PendingOOBConnection> {
        self.connections
            .list_all()
            .await
            .unwrap_or_default()
    }

    /// Clean up expired connections
    pub async fn cleanup_expired(&self) -> usize {
        let now = Utc::now();
        let connection_ids: Vec<String> = self
            .connections
            .list_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|connection| connection.expires_at <= now)
            .map(|connection| connection.id)
            .collect();
        let approval_ids: Vec<String> = self
            .approval_connections
            .list_all()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|connection| connection.is_expired(now))
            .map(|connection| connection.gateway_id)
            .collect();

        let mut removed = 0usize;
        for id in connection_ids {
            match self
                .connections
                .delete(&id)
                .await
            {
                Ok(()) => removed += 1,
                Err(error) => debug!("Failed to remove expired OOB connection: {error}"),
            }
        }
        for id in approval_ids {
            match self
                .approval_connections
                .delete(&id)
                .await
            {
                Ok(()) => removed += 1,
                Err(error) => debug!("Failed to remove expired OOB approval: {error}"),
            }
        }
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pending(expires_at: Option<DateTime<Utc>>) -> PendingConnection {
        PendingConnection {
            gateway_id: "gateway-1".to_string(),
            invitation_id: "invitation-1".to_string(),
            our_temporary_did: "did:example:ours-temp".to_string(),
            our_secure_did: "did:example:ours".to_string(),
            their_temporary_did: "did:example:theirs-temp".to_string(),
            their_secure_did: Some("did:example:theirs".to_string()),
            state: PendingConnectionState::AwaitingApproval,
            created_at: Utc::now(),
            expires_at,
        }
    }

    #[tokio::test]
    async fn cleanup_removes_expired_approval_state_only() {
        let directory = tempfile::tempdir().unwrap();
        let store = PendingConnectionStore::new(directory.path().to_path_buf())
            .await
            .unwrap();
        let now = Utc::now();
        let expired = pending(Some(now - chrono::Duration::seconds(1)));
        let mut active = pending(Some(now + chrono::Duration::minutes(1)));
        active.gateway_id = "gateway-2".to_string();
        store
            .store_approval(&expired)
            .await
            .unwrap();
        store
            .store_approval(&active)
            .await
            .unwrap();

        assert_eq!(store.cleanup_expired().await, 1);
        assert!(
            store
                .get_approval_by_gateway_id("gateway-1")
                .await
                .is_none()
        );
        assert!(
            store
                .get_approval_by_gateway_id("gateway-2")
                .await
                .is_some()
        );
    }

    #[test]
    fn approval_expiry_is_enforced_when_present() {
        let now = Utc::now();
        assert!(pending(Some(now)).is_expired(now));
        assert!(!pending(Some(now + chrono::Duration::seconds(1))).is_expired(now));
        assert!(!pending(None).is_expired(now));
    }
}
