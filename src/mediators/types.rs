use serde::{Deserialize, Serialize};

use crate::storage::filesystem::StorableEntity;

/// Represents the status of a mediator
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum MediatorStatus {
    #[default]
    Active,
    Disabled,
}

/// Represents a mediator record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mediator {
    /// Unique identifier for this mediator
    pub id: String,

    /// Mediator name
    pub name: String,

    /// Mediator description
    pub description: String,

    /// Decentralized Identifier (DID) for this mediator
    pub did: String,

    /// Status of the mediator
    pub status: MediatorStatus,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,

    /// Resolved DID Document (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,

    /// Our DID for connecting to this mediator
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_did: Option<String>,

    /// Secrets for our DID (stored as JSON array)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_secrets: Option<serde_json::Value>,

    /// Timestamp when this record was created
    pub created_at: chrono::DateTime<chrono::Utc>,

    /// Timestamp when this record was last updated
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl StorableEntity for Mediator {
    fn id(&self) -> &str {
        &self.id
    }
}

impl Mediator {
    pub fn new(
        name: String,
        description: String,
        did: String,
        did_document: Option<serde_json::Value>,
    ) -> Self {
        let now = chrono::Utc::now();
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            description,
            did,
            status: MediatorStatus::Active,
            tenant_id: None,
            did_document,
            our_did: None,
            our_secrets: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// Public, response-only projection of a [`Mediator`].
///
/// It has no field for `our_secrets`, so it is structurally impossible to
/// serialize private key material into an API response. The only conversion
/// from storage to the wire is `Mediator -> MediatorResponse`, which drops the
/// secrets; the internal [`Mediator`] retains them for persistence. The
/// exhaustive destructuring in the `From` impl makes adding a new field to
/// [`Mediator`] a compile error here, forcing a deliberate decision about
/// whether it may be exposed.
#[derive(Debug, Clone, Serialize)]
pub struct MediatorResponse {
    pub id: String,
    pub name: String,
    pub description: String,
    pub did: String,
    pub status: MediatorStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub our_did: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<Mediator> for MediatorResponse {
    fn from(mediator: Mediator) -> Self {
        let Mediator {
            id,
            name,
            description,
            did,
            status,
            tenant_id,
            did_document,
            our_did,
            our_secrets: _,
            created_at,
            updated_at,
        } = mediator;
        Self {
            id,
            name,
            description,
            did,
            status,
            tenant_id,
            did_document,
            our_did,
            created_at,
            updated_at,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn mediator_with_secrets() -> Mediator {
        let mut mediator = Mediator::new(
            "Test Mediator".to_string(),
            "description".to_string(),
            "did:web:example.com".to_string(),
            Some(json!({ "id": "did:web:example.com" })),
        );
        mediator.tenant_id = Some("tenant-a".into());
        mediator.our_did = Some("did:peer:2.abc".to_string());
        mediator.our_secrets = Some(json!([
            {
                "id": "did:peer:2.abc#key-1",
                "type": "JsonWebKey2020",
                "privateKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": "public-component",
                    "d": "PRIVATE_KEY_MATERIAL"
                }
            }
        ]));
        mediator
    }

    #[test]
    fn response_omits_private_key_material() {
        let response = MediatorResponse::from(mediator_with_secrets());

        let serialized = serde_json::to_string(&response).expect("serialize response");
        assert!(!serialized.contains("our_secrets"));
        assert!(!serialized.contains("privateKeyJwk"));
        assert!(!serialized.contains("PRIVATE_KEY_MATERIAL"));
    }

    #[test]
    fn response_preserves_public_fields() {
        let original = mediator_with_secrets();
        let response = MediatorResponse::from(original.clone());

        assert_eq!(response.id, original.id);
        assert_eq!(response.name, original.name);
        assert_eq!(response.description, original.description);
        assert_eq!(response.did, original.did);
        assert_eq!(response.our_did, original.our_did);
        assert_eq!(response.status, original.status);
        assert_eq!(response.tenant_id, original.tenant_id);
        assert_eq!(response.did_document, original.did_document);
        assert_eq!(response.created_at, original.created_at);
        assert_eq!(response.updated_at, original.updated_at);
    }
}
