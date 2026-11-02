//! Secrets module for secure secret storage
//!
//! Provides a unified interface for storing and retrieving secrets in
//! filesystem-based storage (encrypted JSON files).

pub mod cache;
mod filesystem;
pub mod handlers;
pub mod router;
pub mod store;

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

pub use cache::{SecretsCache, clear_secret_cache, get_cached_secret};
pub use filesystem::FilesystemSecretsStore;
pub use store::SecretsStore;

use crate::storage::filesystem::StorableEntity;

/// Secret metadata and value
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// Unique identifier for the secret
    pub id: String,

    /// Human-readable name for the secret
    pub name: String,

    /// Machine-readable identifier derived from name (used in $SECRET:xxx syntax)
    pub secret_id: String,

    /// Optional description of what this secret is for
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The actual secret value
    pub value: String,

    /// Type of secret (ApiKey, General, etc.) - configured in gateway.json
    #[serde(default = "default_secret_type")]
    pub secret_type: String,

    /// Tags for categorization and filtering
    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// When the secret was created
    pub created_at: DateTime<Utc>,

    /// When the secret was last updated
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedSecret {
    pub id: String,
    pub name: String,
    pub secret_id: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// The actual secret value (encrypted at rest)
    #[serde(with = "crate::encryption::serde_encrypted::string")]
    pub value: String,

    #[serde(default = "default_secret_type")]
    pub secret_type: String,

    #[serde(default)]
    pub tags: Vec<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    pub created_at: DateTime<Utc>,

    pub updated_at: DateTime<Utc>,
}

fn default_secret_type() -> String {
    "General".to_string()
}

// Implement StorableEntity for EncryptedSecret to use with UncachedFilesystemStorage
impl StorableEntity for EncryptedSecret {
    fn id(&self) -> &str {
        &self.id
    }
}

/// Secret creation request (without sensitive fields)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSecretRequest {
    pub name: String,
    pub secret_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    pub value: String,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
}

/// Secret update request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateSecretRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// Flag indicating whether the value field should be updated.
    /// If false or not provided, the value field will be ignored even if present.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_value: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
}

/// Whether a read of one secret answers with its stored value
/// (`secrets.reveal_values` in agent-stream.json). Off, the record comes back
/// as a [`SecretListItem`]: the value can be replaced but never read.
#[derive(Debug, Clone, Copy)]
pub struct RevealSecretValues(pub bool);

/// Secret list response (without sensitive values by default)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretListItem {
    pub id: String,
    pub name: String,
    pub secret_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default = "default_secret_type")]
    pub secret_type: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl From<Secret> for EncryptedSecret {
    fn from(secret: Secret) -> Self {
        Self {
            id: secret.id,
            name: secret.name,
            secret_id: secret.secret_id,
            description: secret.description,
            secret_type: secret.secret_type,
            value: secret.value,
            tags: secret.tags,
            tenant_id: secret.tenant_id,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
        }
    }
}

impl From<EncryptedSecret> for Secret {
    fn from(encrypted_secret: EncryptedSecret) -> Self {
        Self {
            id: encrypted_secret.id,
            name: encrypted_secret.name,
            secret_id: encrypted_secret.secret_id,
            description: encrypted_secret.description,
            secret_type: encrypted_secret.secret_type,
            value: encrypted_secret.value,
            tags: encrypted_secret.tags,
            tenant_id: encrypted_secret.tenant_id,
            created_at: encrypted_secret.created_at,
            updated_at: encrypted_secret.updated_at,
        }
    }
}

impl From<Secret> for SecretListItem {
    fn from(secret: Secret) -> Self {
        Self {
            id: secret.id,
            name: secret.name,
            secret_id: secret.secret_id,
            description: secret.description,
            secret_type: secret.secret_type,
            tags: secret.tags,
            tenant_id: secret.tenant_id,
            created_at: secret.created_at,
            updated_at: secret.updated_at,
        }
    }
}

/// Resolve a secret reference held in a surface's configuration to the one
/// secret it names.
///
/// A reference is a secret's internal `id` or its public `secret_id`, so the
/// internal id is tried first and then the public one. The internal id comes
/// first because the store generates it: a tenant can choose any public
/// `secret_id`, including one spelled like another secret's internal id, but
/// can never mint an internal id that shadows a public one.
///
/// The save-time tenancy check and every request-time resolver call this one
/// function, so the secret a request sends is always the secret that was
/// checked. Any other lookup order in either place would let a reference that
/// is one secret's public id and another's internal id pass the check on the
/// first and run with the second.
///
/// A reference that is not shaped like an id (see [`is_reference_shaped`])
/// resolves to nothing without reaching the store, so no reference can name a
/// path a store would build from it.
pub async fn resolve_reference(
    store: &dyn SecretsStore,
    reference: &str,
) -> Result<Option<Secret>> {
    let reference = reference.trim();
    if !is_reference_shaped(reference) {
        return Ok(None);
    }
    if let Some(secret) = store.get(reference).await? {
        return Ok(Some(secret));
    }
    store
        .get_by_secret_id(reference)
        .await
}

/// The longest secret reference [`resolve_reference`] looks up.
const MAX_REFERENCE_LEN: usize = 256;

/// Whether `reference` can name a secret: 1 to 256 letters, digits, `-`, `_`
/// or `.`, and never `..`. Internal ids (UUIDs) and every public `secret_id`
/// the dashboard derives (`generate_secret_id`) fit; a path separator, a
/// parent-directory step, a NUL or any other character does not.
pub fn is_reference_shaped(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= MAX_REFERENCE_LEN
        && !reference.contains("..")
        && reference
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Check a new secret's public `secret_id`: it must be a reference
/// [`resolve_reference`] can name, or no surface could ever use the secret.
pub fn validate_secret_id(secret_id: &str) -> std::result::Result<(), String> {
    if is_reference_shaped(secret_id) {
        return Ok(());
    }
    Err(format!(
        "secret_id must be 1 to {MAX_REFERENCE_LEN} letters, digits, '-', '_' or '.', and may not contain '..'"
    ))
}

/// Log every stored secret whose `secret_id` no reference can name, so an
/// operator can re-create it under a valid id, and return those ids. Only the
/// internal id and the public `secret_id` are logged, both escaped.
pub async fn report_unreferenceable_secrets(store: &dyn SecretsStore) -> Vec<String> {
    let secrets = match store.list_all().await {
        Ok(secrets) => secrets,
        Err(e) => {
            tracing::debug!(error = ?e.to_string(), "secret_id check skipped: the secrets store cannot list");
            return Vec::new();
        }
    };
    secrets
        .into_iter()
        .filter(|secret| !is_reference_shaped(&secret.secret_id))
        .map(|secret| {
            tracing::warn!(
                id = ?secret.id,
                secret_id = ?secret.secret_id,
                "stored secret has a secret_id no surface can reference; re-create it under an id of letters, \
                 digits, '-', '_' or '.'"
            );
            secret.secret_id
        })
        .collect()
}

/// The secrets one surface sends, resolved for that surface at request time.
///
/// Every request-time resolver of a surface's secret references goes through
/// [`SurfaceSecrets::resolve`]: the reference is resolved with
/// [`resolve_reference`], the save-time tenancy check's own resolution, and the
/// secret it names must still be one the surface's tenant may reference. A
/// public `secret_id` freed and re-created by someone the surface may not
/// reference therefore fails the call instead of being sent.
#[derive(Clone, Default)]
pub struct SurfaceSecrets {
    store: Option<Arc<dyn SecretsStore>>,
    owner_tenant_id: Option<String>,
}

impl SurfaceSecrets {
    /// The secrets of a surface owned by `owner_tenant_id` (`None` for an
    /// appliance-wide surface).
    pub fn new(
        store: Option<Arc<dyn SecretsStore>>,
        owner_tenant_id: Option<String>,
    ) -> Self {
        Self { store, owner_tenant_id }
    }

    pub fn store(&self) -> Option<&Arc<dyn SecretsStore>> {
        self.store.as_ref()
    }

    /// Resolve `reference` to the secret this surface sends, `None` when
    /// nothing answers to it (or no store is configured). Fails when the
    /// secret belongs to a tenant the surface's owner may not reference.
    pub async fn resolve(
        &self,
        reference: &str,
    ) -> Result<Option<Secret>> {
        let Some(store) = &self.store else {
            return Ok(None);
        };
        let Some(secret) = resolve_reference(store.as_ref(), reference).await? else {
            return Ok(None);
        };
        if !crate::tenancy::can_reference(
            self.owner_tenant_id
                .as_deref(),
            secret.tenant_id.as_deref(),
        ) {
            anyhow::bail!("the secret is not one this surface may use");
        }
        Ok(Some(secret))
    }

    /// Resolve `reference` to the key a model call sends, labelled with where
    /// it comes from (see [`Self::key_source`]). Every stored key a model call
    /// sends is resolved here.
    pub async fn resolve_key(
        &self,
        reference: &str,
    ) -> Result<Option<crate::pipes::key_source::CallKey>> {
        Ok(self
            .resolve(reference)
            .await?
            .map(|secret| crate::pipes::key_source::CallKey {
                source: self.key_source(secret.tenant_id.as_deref()),
                value: secret.value,
            }))
    }

    /// Where a secret owned by `secret_tenant_id` comes from: the customer's
    /// own when it belongs to the surface's tenant, else the platform's (an
    /// appliance-wide secret the operator pays for).
    pub fn key_source(
        &self,
        secret_tenant_id: Option<&str>,
    ) -> crate::pipes::key_source::KeySource {
        match (
            self.owner_tenant_id
                .as_deref(),
            secret_tenant_id,
        ) {
            (Some(owner), Some(secret)) if owner == secret => crate::pipes::key_source::KeySource::Customer,
            _ => crate::pipes::key_source::KeySource::Platform,
        }
    }

    /// Whether a call whose key came from `source` may be billed at a price the
    /// surface sets itself: [`Self::owns`] for a key.
    pub fn honours_own_price(
        &self,
        source: crate::pipes::key_source::KeySource,
    ) -> bool {
        source.owned() || self.owner_tenant_id.is_none()
    }

    /// Whether a call that sent a secret owned by `secret_tenant_id` may be
    /// billed at a price the surface sets itself. Not when a tenant's surface
    /// spends an appliance-wide (operator) secret: the operator pays that
    /// upstream, so its price is not the tenant's to lower.
    pub fn owns(
        &self,
        secret_tenant_id: Option<&str>,
    ) -> bool {
        match self
            .owner_tenant_id
            .as_deref()
        {
            Some(owner) => secret_tenant_id == Some(owner),
            None => true,
        }
    }
}

/// Generate a secret ID from a name
/// Converts to lowercase and allows only A-Z, a-z, 0-9, underscore, and hyphen
#[allow(dead_code)]
pub fn generate_secret_id(name: &str) -> String {
    name.to_lowercase()
        .trim()
        // Replace whitespace and common separators with underscore
        .replace(|c: char| c.is_whitespace() || c == '.' || c == '/', "_")
        // Remove any characters that aren't alphanumeric, underscore, or hyphen
        .chars()
        .filter(|c| c.is_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>()
        // Replace multiple consecutive underscores with single underscore
        .split('_')
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("_")
        // Remove leading/trailing underscores or hyphens
        .trim_matches(|c| c == '_' || c == '-')
        .to_string()
}

/// Create the secrets store
pub async fn create_secrets_store(storage_path: Option<String>) -> Result<Arc<dyn SecretsStore>> {
    let path = storage_path.unwrap_or_else(|| "_storage/secrets".to_string());
    let store = FilesystemSecretsStore::new_async(&path).await?;
    Ok(Arc::new(store) as Arc<dyn SecretsStore>)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_secret_without_tenant_id_is_global() {
        let now = Utc::now();
        let secret: Secret = serde_json::from_value(serde_json::json!({
            "id": "secret-id",
            "name": "Legacy secret",
            "secret_id": "legacy-secret",
            "description": null,
            "value": "value",
            "secret_type": "General",
            "tags": [],
            "created_at": now,
            "updated_at": now
        }))
        .unwrap();

        assert_eq!(secret.tenant_id, None);
    }

    use crate::secrets::store::memory::{MemorySecretsStore, secret};

    async fn resolved_value(
        store: &MemorySecretsStore,
        reference: &str,
    ) -> Option<String> {
        resolve_reference(store, reference)
            .await
            .unwrap()
            .map(|secret| secret.value)
    }

    #[tokio::test]
    async fn a_reference_resolves_by_internal_id_or_by_public_id() {
        let store = MemorySecretsStore::with(vec![secret("uuid-1", "model-key", "value-1", None)]);

        assert_eq!(
            resolved_value(&store, "uuid-1")
                .await
                .as_deref(),
            Some("value-1")
        );
        assert_eq!(
            resolved_value(&store, "model-key")
                .await
                .as_deref(),
            Some("value-1")
        );
        assert_eq!(
            resolved_value(&store, " model-key ")
                .await
                .as_deref(),
            Some("value-1")
        );
        assert_eq!(resolved_value(&store, "unknown").await, None);
        assert_eq!(resolved_value(&store, "  ").await, None);
    }

    #[tokio::test]
    async fn an_internal_id_wins_over_a_public_id_spelled_the_same() {
        // Tenant A names its own secret with tenant B's internal id. The
        // reference must mean tenant B's secret everywhere, so the tenancy
        // check refuses it rather than approving A's secret and a request
        // then sending B's.
        let store = MemorySecretsStore::with(vec![
            secret("uuid-of-b", "b-key", "value-b", Some("tenant-b")),
            secret("uuid-of-a", "uuid-of-b", "value-a", Some("tenant-a")),
        ]);

        let resolved = resolve_reference(&store, "uuid-of-b")
            .await
            .unwrap()
            .expect("resolves");
        assert_eq!(resolved.id, "uuid-of-b");
        assert_eq!(resolved.tenant_id.as_deref(), Some("tenant-b"));
    }

    /// References that are not ids: a path, a parent-directory step, a
    /// separator, a NUL, or a character outside the id alphabet.
    const NOT_IDS: &[&str] = &[
        "../elsewhere/uuid-1",
        "/abs/path/uuid-1",
        "dir\\uuid-1",
        "uuid\u{0}1",
        "..",
        "a..b",
        "has space",
        "acct:key",
    ];

    #[test]
    fn ids_and_dashboard_secret_ids_are_reference_shaped() {
        for reference in
            ["0b5c3f1e-9a8d-4c4e-8f1a-2d3e4f5a6b7c", "openai_api_key", "acct-ms-1-tunnel-key", "model.key", "cl\u{e9}"]
        {
            assert!(is_reference_shaped(reference), "{reference:?} must be accepted");
        }
        assert!(!is_reference_shaped(""));
        assert!(!is_reference_shaped(&"a".repeat(MAX_REFERENCE_LEN + 1)));
        for reference in NOT_IDS {
            assert!(!is_reference_shaped(reference), "{reference:?} must be refused");
        }
    }

    #[test]
    fn a_new_secret_id_must_be_reference_shaped() {
        assert_eq!(validate_secret_id("openai_api_key"), Ok(()));
        for secret_id in NOT_IDS
            .iter()
            .chain(&["", " padded ", "key@corp", "key+1", "team/key"])
        {
            assert!(validate_secret_id(secret_id).is_err(), "{secret_id:?} must be refused");
        }
    }

    #[tokio::test]
    async fn the_startup_scan_names_every_stored_secret_no_reference_can_name() {
        let store = MemorySecretsStore::with(vec![
            secret("uuid-1", "openai_api_key", "value", None),
            secret("uuid-2", "acct:key", "value", Some("tenant-a")),
            secret("uuid-3", "model.key", "value", None),
            secret("uuid-4", "my key", "value", None),
        ]);

        let mut named = report_unreferenceable_secrets(&store).await;
        named.sort();
        assert_eq!(named, vec!["acct:key", "my key"]);
        assert!(
            report_unreferenceable_secrets(&MemorySecretsStore::default())
                .await
                .is_empty()
        );
    }

    #[tokio::test]
    async fn a_reference_that_is_not_an_id_never_reaches_the_store() {
        // The store answers to every one of these as an internal id, so only
        // the shape check stands between the reference and the lookup.
        let store = MemorySecretsStore::with(
            NOT_IDS
                .iter()
                .map(|reference| secret(reference, "public", "value", None))
                .collect(),
        );
        for reference in NOT_IDS {
            assert!(
                store
                    .get(reference)
                    .await
                    .unwrap()
                    .is_some(),
                "precondition: the store holds {reference:?}"
            );
            assert_eq!(resolved_value(&store, reference).await, None, "{reference:?} reached the store");
        }
    }

    fn tenant_store() -> Arc<dyn SecretsStore> {
        Arc::new(MemorySecretsStore::with(vec![
            secret("uuid-own", "own-key", "OWN", Some("tenant-a")),
            secret("uuid-operator", "operator-key", "OPERATOR", None),
            secret("uuid-foreign", "foreign-key", "FOREIGN", Some("tenant-b")),
        ]))
    }

    async fn surface_value(
        secrets: &SurfaceSecrets,
        reference: &str,
    ) -> std::result::Result<Option<String>, String> {
        secrets
            .resolve(reference)
            .await
            .map(|secret| secret.map(|secret| secret.value))
            .map_err(|e| e.to_string())
    }

    #[tokio::test]
    async fn a_surface_resolves_only_secrets_its_tenant_may_reference() {
        let tenant_surface = SurfaceSecrets::new(Some(tenant_store()), Some("tenant-a".to_string()));
        assert_eq!(surface_value(&tenant_surface, "own-key").await, Ok(Some("OWN".to_string())));
        assert_eq!(surface_value(&tenant_surface, "operator-key").await, Ok(Some("OPERATOR".to_string())));
        assert!(
            surface_value(&tenant_surface, "foreign-key")
                .await
                .is_err()
        );
        assert!(
            surface_value(&tenant_surface, "uuid-foreign")
                .await
                .is_err()
        );
        assert_eq!(surface_value(&tenant_surface, "unknown").await, Ok(None));

        let appliance_surface = SurfaceSecrets::new(Some(tenant_store()), None);
        assert_eq!(surface_value(&appliance_surface, "operator-key").await, Ok(Some("OPERATOR".to_string())));
        assert!(
            surface_value(&appliance_surface, "own-key")
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn a_public_id_re_registered_by_another_tenant_fails_the_call() {
        // Tenant A's surface names the operator's `groq_api_key`. The operator
        // deleted it and tenant B created a secret with the same public id:
        // the reference now names B's secret, which A may not send.
        let store: Arc<dyn SecretsStore> =
            Arc::new(MemorySecretsStore::with(vec![secret("uuid-b", "groq_api_key", "B-VALUE", Some("tenant-b"))]));
        let secrets = SurfaceSecrets::new(Some(store.clone()), Some("tenant-a".to_string()));

        assert!(
            resolve_reference(store.as_ref(), "groq_api_key")
                .await
                .unwrap()
                .is_some(),
            "precondition: the reference resolves to tenant B's secret"
        );
        assert!(
            surface_value(&secrets, "groq_api_key")
                .await
                .is_err()
        );
    }

    #[test]
    fn a_tenants_surface_owns_only_its_tenants_secrets() {
        let tenant_surface = SurfaceSecrets::new(None, Some("tenant-a".to_string()));
        assert!(tenant_surface.owns(Some("tenant-a")));
        assert!(!tenant_surface.owns(None), "an operator secret is not the tenant's to price");
        assert!(!tenant_surface.owns(Some("tenant-b")));
        assert!(SurfaceSecrets::default().owns(None));
    }
}
