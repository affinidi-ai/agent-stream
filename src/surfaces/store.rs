//! Agent Surface Store Trait

use async_trait::async_trait;

use crate::config::agent_surface::AgentSurface;

/// Trait for storing and retrieving Agent Surface configurations
#[async_trait]
pub trait AgentSurfaceStore: Send + Sync {
    /// Create or update an Agent Surface
    #[allow(dead_code)]
    async fn save(
        &self,
        surface: &AgentSurface,
    ) -> anyhow::Result<()>;

    /// Get an Agent Surface by surface_id
    async fn get(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<Option<AgentSurface>>;

    /// List all Agent Surfaces
    async fn list_all(&self) -> anyhow::Result<Vec<AgentSurface>>;

    /// Delete an Agent Surface by surface_id
    #[allow(dead_code)]
    async fn delete(
        &self,
        surface_id: &str,
    ) -> anyhow::Result<()>;
}
