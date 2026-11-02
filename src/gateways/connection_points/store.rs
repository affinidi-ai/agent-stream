//! Connection Point Store Trait

use anyhow::Result;
use async_trait::async_trait;

use super::types::GatewayConnectionPoint;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum InvitationConsumeError {
    #[error("connection point not found")]
    NotFound,
    #[error("connection point is not an active OOB invitation")]
    InvalidState,
    #[error("connection point invitation has expired")]
    Expired,
    #[error("message parent thread does not match the invitation")]
    ThreadMismatch,
    #[error("invalid invitation capability")]
    InvalidCapability,
    #[error("invitation capability has already been consumed")]
    AlreadyConsumed,
    #[error("failed to persist invitation consumption: {0}")]
    Storage(String),
}

/// Trait for storing and retrieving gateway connection points
#[async_trait]
pub trait ConnectionPointStore: Send + Sync {
    /// Create a new connection point
    async fn create(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()>;

    /// Get a connection point by ID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<GatewayConnectionPoint>>;

    /// List all connection points
    async fn list_all(&self) -> Result<Vec<GatewayConnectionPoint>>;

    /// List connection points for a specific gateway
    async fn list_by_gateway(
        &self,
        gateway_id: &str,
    ) -> Result<Vec<GatewayConnectionPoint>>;

    /// Update a connection point
    async fn update(
        &self,
        connection_point: &GatewayConnectionPoint,
    ) -> Result<()>;

    /// Delete a connection point
    async fn delete(
        &self,
        id: &str,
    ) -> Result<()>;

    /// Atomically validate and consume an OOB invitation capability before any
    /// gateway, key, notification, or integration side effects occur.
    async fn consume_invitation(
        &self,
        id: &str,
        parent_thread_id: &str,
        presented_capability: &str,
        now: chrono::DateTime<chrono::Utc>,
    ) -> std::result::Result<GatewayConnectionPoint, InvitationConsumeError>;

    /// Refresh any in-memory cache from disk.
    async fn refresh_from_disk(&self) -> Result<()> {
        Ok(())
    }
}
