//! Shared secret caching helpers with TTL.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::anyhow;
use dashmap::DashMap;
use tracing::debug;

use crate::secrets::SecretsStore;

/// Cached secret value with TTL
#[derive(Debug, Clone)]
pub struct CachedSecret {
    pub value: String,
    /// The tenant that owns the secret, re-checked against every surface the
    /// cached value is used for.
    pub tenant_id: Option<String>,
    pub cached_at: Instant,
    pub ttl: Duration,
}

impl CachedSecret {
    pub fn is_expired(&self) -> bool {
        self.cached_at.elapsed() > self.ttl
    }

    pub fn get_credentials(&self) -> Vec<String> {
        self.value
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect()
    }
}

/// Shared cache for secrets keyed by the reference they were resolved from
pub type SecretsCache = Arc<DashMap<String, CachedSecret>>;

/// Retrieve the credentials a surface owned by `owner_tenant_id` holds in the
/// secret `reference` names, honoring a short-lived cache to avoid hitting the
/// backend on every request.
///
/// The reference resolves through [`crate::secrets::resolve_reference`], the
/// resolution the save-time tenancy check uses, and the secret must still be
/// one the surface's tenant may reference, cached or not.
pub async fn get_cached_secret(
    reference: &str,
    owner_tenant_id: Option<&str>,
    secrets_store: &Option<Arc<dyn SecretsStore>>,
    secrets_cache: &SecretsCache,
) -> anyhow::Result<Vec<String>> {
    let usable = |tenant_id: Option<&str>| {
        if crate::tenancy::can_reference(owner_tenant_id, tenant_id) {
            Ok(())
        } else {
            Err(anyhow!("the secret is not one this surface may use"))
        }
    };

    if let Some(entry) = secrets_cache.get(reference)
        && !entry.is_expired()
    {
        debug!("Secrets cache hit");
        usable(entry.tenant_id.as_deref())?;
        return Ok(entry.get_credentials());
    }

    let store = secrets_store
        .as_ref()
        .ok_or_else(|| anyhow!("Secrets store not configured"))?;

    let secret = crate::secrets::resolve_reference(store.as_ref(), reference)
        .await?
        .ok_or_else(|| anyhow!("no secret answers to the reference"))?;
    usable(secret.tenant_id.as_deref())?;

    let cached = CachedSecret {
        value: secret.value,
        tenant_id: secret.tenant_id,
        cached_at: Instant::now(),
        ttl: Duration::from_secs(60),
    };
    let credentials = cached.get_credentials();
    secrets_cache.insert(reference.to_string(), cached);
    Ok(credentials)
}

/// Remove a secret's cached entries after rotation: a surface may name it by
/// its public `secret_id` or its internal `id`.
pub fn clear_secret_cache(
    secret: &crate::secrets::Secret,
    secrets_cache: &SecretsCache,
) {
    secrets_cache.remove(&secret.secret_id);
    secrets_cache.remove(&secret.id);
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Result;
    use async_trait::async_trait;
    use chrono::Utc;

    use crate::secrets::{CreateSecretRequest, Secret, SecretListItem, UpdateSecretRequest};

    struct TestSecretsStore {
        secret: Secret,
    }

    #[async_trait]
    impl SecretsStore for TestSecretsStore {
        async fn create(
            &self,
            _request: CreateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not needed in test")
        }

        async fn get(
            &self,
            _id: &str,
        ) -> Result<Option<Secret>> {
            Ok(None)
        }

        async fn get_by_secret_id(
            &self,
            secret_id: &str,
        ) -> Result<Option<Secret>> {
            Ok((self.secret.secret_id == secret_id).then(|| self.secret.clone()))
        }

        async fn list_all(&self) -> Result<Vec<SecretListItem>> {
            Ok(vec![self.secret.clone().into()])
        }

        async fn update(
            &self,
            _id: &str,
            _request: UpdateSecretRequest,
        ) -> Result<Secret> {
            anyhow::bail!("not needed in test")
        }

        async fn delete(
            &self,
            _id: &str,
        ) -> Result<()> {
            anyhow::bail!("not needed in test")
        }

        async fn find_by_tag(
            &self,
            _tag: &str,
        ) -> Result<Vec<SecretListItem>> {
            Ok(vec![])
        }
    }

    #[tokio::test]
    async fn test_get_cached_secret_uses_public_secret_id_lookup() {
        let secret = Secret {
            id: "internal-id".to_string(),
            name: "API Key Secret".to_string(),
            secret_id: "public-secret-id".to_string(),
            description: None,
            value: "key-a, key-b".to_string(),
            secret_type: "General".to_string(),
            tags: vec![],
            tenant_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        let store: Arc<dyn SecretsStore> = Arc::new(TestSecretsStore { secret });
        let cache = Arc::new(DashMap::new());

        let credentials = get_cached_secret("public-secret-id", None, &Some(store), &cache)
            .await
            .unwrap();

        assert_eq!(credentials, vec!["key-a".to_string(), "key-b".to_string()]);
    }
}
