//! Filesystem storage for delegation vault tokens

use super::{DelegationToken, VaultLookupResult};
use anyhow::{Context, Result};
use async_trait::async_trait;
use chrono::Utc;
use std::path::PathBuf;
use tracing::{debug, info};

use crate::storage::filesystem::{StorageBackend, uncached_storage};

/// Trait for delegation vault storage operations
#[async_trait]
pub trait DelegationVaultStorage: Send + Sync {
    /// Store a delegation token
    async fn store(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken>;

    /// Get a token by its UUID
    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<DelegationToken>>;

    /// Lookup token by composite key (agent_did, user_hash, provider_id)
    async fn lookup(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<VaultLookupResult>;

    /// List all tokens (metadata only traversal)
    async fn list_all(&self) -> Result<Vec<DelegationToken>>;

    /// Delete a token by ID (revoke)
    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool>;

    /// Delete all tokens for a user hash
    async fn delete_by_user(
        &self,
        user_identity_hash: &str,
    ) -> Result<usize>;

    /// Update a token (e.g. after refresh)
    async fn update(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken>;

    /// Mark a token as used (update last_used_at)
    async fn mark_used(
        &self,
        id: &str,
    ) -> Result<()>;
}

/// Filesystem-backed delegation vault using uncached storage (security-sensitive)
pub struct FileSystemDelegationVaultStore {
    storage: Box<dyn StorageBackend<DelegationToken>>,
}

impl FileSystemDelegationVaultStore {
    pub async fn new(path: PathBuf) -> Result<Self> {
        // Use uncached storage for security — tokens should not linger in memory
        let storage = uncached_storage(path.clone(), "delegation_token").await?;
        info!(
            target: "credential_delegation",
            path = %path.display(),
            "Delegation vault store initialized (uncached, encrypted)"
        );
        Ok(Self { storage })
    }
}

#[async_trait]
impl DelegationVaultStorage for FileSystemDelegationVaultStore {
    async fn store(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken> {
        self.storage
            .save(&token)
            .await
            .context("Failed to store delegation token")?;
        info!(
            target: "credential_delegation",
            id = %token.id,
            agent_did = %token.agent_did,
            user_hash = %token.user_identity_hash,
            provider_id = %token.provider_id,
            scopes = ?token.scopes,
            expires_at = ?token.expires_at,
            "Delegation token stored in vault"
        );
        Ok(token)
    }

    async fn get(
        &self,
        id: &str,
    ) -> Result<Option<DelegationToken>> {
        self.storage.get(id).await
    }

    async fn lookup(
        &self,
        agent_did: &str,
        user_identity_hash: &str,
        provider_id: &str,
    ) -> Result<VaultLookupResult> {
        let all = self
            .storage
            .list_all()
            .await?;
        let found = all.into_iter().find(|t| {
            t.agent_did == agent_did
                && t.user_identity_hash == user_identity_hash
                && t.credential_provider_id == provider_id
        });

        match found {
            Some(token) => {
                if token.is_expired() {
                    if token.can_refresh() {
                        debug!(
                            target: "credential_delegation",
                            agent_did = %agent_did,
                            user_hash = %user_identity_hash,
                            provider_id = %provider_id,
                            "Vault lookup: token expired but refreshable"
                        );
                        Ok(VaultLookupResult::ExpiredRefreshable(token))
                    } else {
                        debug!(
                            target: "credential_delegation",
                            agent_did = %agent_did,
                            user_hash = %user_identity_hash,
                            provider_id = %provider_id,
                            "Vault lookup: token expired, no refresh token"
                        );
                        Ok(VaultLookupResult::ExpiredNoRefresh(token))
                    }
                } else {
                    debug!(
                        target: "credential_delegation",
                        agent_did = %agent_did,
                        user_hash = %user_identity_hash,
                        provider_id = %provider_id,
                        "Vault lookup: valid token found"
                    );
                    Ok(VaultLookupResult::Found(token))
                }
            }
            None => {
                debug!(
                    target: "credential_delegation",
                    agent_did = %agent_did,
                    user_hash = %user_identity_hash,
                    provider_id = %provider_id,
                    "Vault lookup: no token found"
                );
                Ok(VaultLookupResult::NotFound)
            }
        }
    }

    async fn list_all(&self) -> Result<Vec<DelegationToken>> {
        self.storage.list_all().await
    }

    async fn delete(
        &self,
        id: &str,
    ) -> Result<bool> {
        let exists = self
            .storage
            .get(id)
            .await?
            .is_some();
        if exists {
            self.storage
                .delete(id)
                .await?;
            info!(
                target: "credential_delegation",
                id = %id,
                "Delegation token revoked"
            );
        }
        Ok(exists)
    }

    async fn delete_by_user(
        &self,
        user_identity_hash: &str,
    ) -> Result<usize> {
        let all = self
            .storage
            .list_all()
            .await?;
        let to_delete: Vec<String> = all
            .iter()
            .filter(|t| t.user_identity_hash == user_identity_hash)
            .map(|t| t.id.clone())
            .collect();
        let count = to_delete.len();
        for id in to_delete {
            self.storage
                .delete(&id)
                .await?;
        }
        if count > 0 {
            info!(
                target: "credential_delegation",
                user_hash = %user_identity_hash,
                count = %count,
                "All delegation tokens revoked for user"
            );
        }
        Ok(count)
    }

    async fn update(
        &self,
        token: DelegationToken,
    ) -> Result<DelegationToken> {
        self.storage
            .save(&token)
            .await
            .context("Failed to update delegation token")?;
        Ok(token)
    }

    async fn mark_used(
        &self,
        id: &str,
    ) -> Result<()> {
        if let Some(mut token) = self.storage.get(id).await? {
            token.last_used_at = Some(Utc::now());
            self.storage
                .save(&token)
                .await?;
        }
        Ok(())
    }
}
