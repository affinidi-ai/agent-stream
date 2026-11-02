use affinidi_messaging_sdk::protocols::oob_discovery::OOBDiscovery;
use affinidi_tdk_common::secrets_resolver::secrets::Secret;
use anyhow::Result;
use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, warn};

use super::filesystem::ConnectionPointStore;
use super::types::ConnectionPointDidMethod;
use super::types::{ConnectionPointView, GatewayConnectionPoint};
use super::ws_listener::ConnectionPointListenerManager;
use crate::auth_manager::pat::PatResourceScope;
use crate::comm::didcomm::client::DIDCommClient;
use crate::gateways::filesystem::GatewayStore;
use crate::gateways::types::{Gateway, GatewayType};
use crate::identity::VCIssuer;
use crate::mediators::filesystem::MediatorStore;
use crate::mediators::utils::set_acl_to_allow_everything_and_more;
use crate::messages::MessageType;
use crate::surfaces::AgentSurfaceStore;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, can_reference, scope_allows_resource};

/// Generates a `did:webvh` identity for a connection point.
///
/// Creates a birth log entry (`did.jsonl`), persists it to
/// `{storage_path}/{connection_point_id}/did.jsonl`, and returns the
/// canonical `did:webvh:<SCID>:<domain>:connection-points:<uuid>` DID, the
/// generated secret set, and the parallel `did:web` document for
/// `.well-known` resolution.
///
#[cfg(feature = "didwebvh")]
pub async fn generate_connection_point_identity_webvh(
    connection_point_id: &str,
    domain: &str,
    storage_path: &std::path::Path,
    mediator_url: &str,
    log_storage: Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    identity_store: Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
) -> Result<(String, Vec<Secret>, serde_json::Value)> {
    use crate::identity::didwebvh::create::{create_webvh_did, extract_public_jwk, strip_jwk_private_key};
    use affinidi_secrets_resolver::secrets::SecretMaterial;

    let cp_keys_path = storage_path.join(connection_point_id);
    tokio::fs::create_dir_all(&cp_keys_path).await?;

    let safe_domain = domain.replace(':', "%3A");
    let placeholder_did = format!("did:webvh:{{SCID}}:{}:connection-points:{}", safe_domain, connection_point_id);

    // --- 1. Generate key material (Ed25519 + X25519 + P-256) ---
    let mut ed25519_secret = affinidi_secrets_resolver::secrets::Secret::generate_ed25519(None, None);
    let mut x25519_secret = affinidi_secrets_resolver::secrets::Secret::generate_x25519(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
    let mut p256_secret = affinidi_secrets_resolver::secrets::Secret::generate_p256(None, None)
        .map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {:?}", e))?;

    ed25519_secret.id = format!("{}#key-1", placeholder_did);
    x25519_secret.id = format!("{}#key-2", placeholder_did);
    p256_secret.id = format!("{}#key-3", placeholder_did);

    // --- 2. Extract Ed25519 JWK ---
    let ed25519_jwk_value = match &ed25519_secret.secret_material {
        SecretMaterial::JWK(jwk) => {
            serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?
        }
        _ => return Err(anyhow::anyhow!("Ed25519 secret is not a JWK")),
    };
    let ed25519_pub_jwk = strip_jwk_private_key(&ed25519_jwk_value);

    // --- 3. Extract X25519 and P-256 public JWKs for the DID document ---
    let x25519_pub_jwk = extract_public_jwk(&x25519_secret)?;
    let p256_pub_jwk = extract_public_jwk(&p256_secret)?;

    // --- 4. Build DID document JSON with {SCID} placeholder ---
    let did_document_json = serde_json::json!({
        "id": placeholder_did,
        "@context": ["https://www.w3.org/ns/did/v1"],
        "verificationMethod": [
            {
                "id": format!("{}#key-1", placeholder_did),
                "type": "JsonWebKey2020",
                "controller": placeholder_did,
                "publicKeyJwk": ed25519_pub_jwk
            },
            {
                "id": format!("{}#key-2", placeholder_did),
                "type": "JsonWebKey2020",
                "controller": placeholder_did,
                "publicKeyJwk": x25519_pub_jwk
            },
            {
                "id": format!("{}#key-3", placeholder_did),
                "type": "JsonWebKey2020",
                "controller": placeholder_did,
                "publicKeyJwk": p256_pub_jwk
            }
        ],
        "authentication": [format!("{}#key-1", placeholder_did)],
        "assertionMethod": [format!("{}#key-1", placeholder_did)],
        "keyAgreement": [
            format!("{}#key-2", placeholder_did),
            format!("{}#key-3", placeholder_did)
        ],
        "service": [{
            "id": format!("{}#service", placeholder_did),
            "type": "DIDCommMessaging",
            "serviceEndpoint": [{
                "uri": mediator_url,
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }]
        }]
    });

    // --- 5. Create DID:webvh via shared helper ---
    let base_url = format!("https://{}/", domain);
    let result = create_webvh_did(&ed25519_jwk_value, did_document_json, &base_url).await?;

    let final_did = result.final_did;
    let scid = result.scid;
    let log_entry_json = result.log_entry_json;
    let signed_entry = result.signed_entry;

    // --- 6. Persist birth log to {cp_id}/did.jsonl ---
    tokio::fs::write(cp_keys_path.join("did.jsonl"), format!("{}\n", log_entry_json)).await?;

    if let Some(storage) = log_storage
        && let Err(e) = storage
            .append_raw(&final_did, &log_entry_json)
            .await
    {
        warn!("Failed to register connection point DID in log storage: {}", e);
    }

    // --- 7. Update secret IDs to reference the final DID ---
    ed25519_secret.id = format!("{}#key-1", final_did);
    x25519_secret.id = format!("{}#key-2", final_did);
    p256_secret.id = format!("{}#key-3", final_did);
    let secrets = vec![ed25519_secret, x25519_secret, p256_secret];

    for (i, secret) in secrets.iter().enumerate() {
        let secret_json = serde_json::to_string_pretty(secret)?;
        crate::encryption::secret_file::write_secret_file(&cp_keys_path.join(format!("key_{}.json", i)), &secret_json)
            .await?;
    }

    // --- 8. Persist identity record to DidWebVhIdentityStore ---
    if let Some(id_store) = identity_store {
        use crate::identity::didwebvh::generate_random_dna;
        use crate::identity::didwebvh::identity_manager::DidWebVhIdentity;
        use crate::identity::didwebvh::types::KeyPair;

        let ed25519_key_pair = KeyPair {
            public_key: ed25519_pub_jwk.clone(),
            private_key: ed25519_jwk_value.clone(),
            key_type: "Ed25519".to_string(),
        };

        let id = uuid::Uuid::new_v4();
        let now = chrono::Utc::now();
        let agent_dna = generate_random_dna(&scid);
        let mut metadata = std::collections::HashMap::new();
        if let Ok(dna_value) = serde_json::to_value(&agent_dna) {
            metadata.insert("agentDNA".to_string(), dna_value);
        }
        metadata.insert(
            crate::identity::didwebvh::identity_manager::CONNECTION_POINT_METADATA_KEY.to_string(),
            serde_json::Value::String(connection_point_id.to_string()),
        );

        let identity = DidWebVhIdentity {
            id,
            did: final_did.clone(),
            key_pair: Some(ed25519_key_pair),
            version: 1,
            created_at: now,
            updated_at: now,
            metadata,
            active: true,
            owner_user_id: None,
        };

        if let Err(e) = id_store
            .create(identity)
            .await
        {
            warn!("Failed to persist connection point identity to store: {}", e);
        }
    }

    // --- 9. Generate parallel did:web document ---
    let state_json = serde_json::to_string(&signed_entry.state)?;
    let state_doc: serde_json::Value = serde_json::from_str(&state_json)?;
    let parallel_doc = crate::identity::didwebvh::generate_parallel_did_web(&state_doc, &final_did, &scid);

    // Save did.json so the legacy /did.json route still resolves
    let did_doc_json = serde_json::to_string_pretty(&parallel_doc)?;
    tokio::fs::write(cp_keys_path.join("did.json"), did_doc_json).await?;

    info!("Generated connection point did:webvh: {}", final_did);
    info!("  Service endpoint (mediator): {}", mediator_url);

    // Return state_doc (did:webvh-keyed) for ATM resolver caching — not parallel_doc.
    // The parallel_doc uses did:web: key IDs which would mismatch the did:webvh: secret IDs.
    Ok((final_did, secrets, state_doc))
}

/// Dispatcher that generates a connection point identity using the specified DID method.
pub async fn generate_connection_point_identity(
    connection_point_id: &str,
    domain: &str,
    storage_path: &std::path::Path,
    mediator_url: &str,
    did_method: &ConnectionPointDidMethod,
    #[cfg(feature = "didwebvh")] log_storage: Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    #[cfg(feature = "didwebvh")] identity_store: Option<
        std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>,
    >,
) -> Result<(String, Vec<Secret>, serde_json::Value)> {
    match did_method {
        #[cfg(feature = "didwebvh")]
        ConnectionPointDidMethod::Webvh => {
            generate_connection_point_identity_webvh(
                connection_point_id,
                domain,
                storage_path,
                mediator_url,
                log_storage,
                identity_store,
            )
            .await
        }
        ConnectionPointDidMethod::Web => {
            generate_connection_point_identity_web(connection_point_id, domain, storage_path, mediator_url).await
        }
        ConnectionPointDidMethod::Peer => {
            generate_connection_point_identity_peer(connection_point_id, storage_path, mediator_url).await
        }
    }
}
/// Generates a `did:web` identity for a connection point.
/// Creates 2 key pairs (P-256 for verification, secp256k1 for key agreement)
/// and a W3C DID document with DIDComm service endpoint.
pub async fn generate_connection_point_identity_web(
    connection_point_id: &str,
    domain: &str,
    storage_path: &std::path::Path,
    mediator_url: &str,
) -> Result<(String, Vec<Secret>, serde_json::Value)> {
    let cp_keys_path = storage_path.join(connection_point_id);
    tokio::fs::create_dir_all(&cp_keys_path).await?;

    let safe_domain = domain.replace(':', "%3A");
    let did = format!("did:web:{}:connection-points:{}", safe_domain, connection_point_id);

    info!("Generating connection point did:web: {}", did);
    info!("  Service endpoint (mediator): {}", mediator_url);

    // Generate key material: Ed25519 (verification) + X25519 + P-256 (key agreement)
    // Consistent with the did:webvh connection-point identity.
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret =
        Secret::generate_x25519(None, None).map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
    let mut p256_secret =
        Secret::generate_p256(None, None).map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {:?}", e))?;

    ed25519_secret.id = format!("{}#key-1", did);
    x25519_secret.id = format!("{}#key-2", did);
    p256_secret.id = format!("{}#key-3", did);

    // Build DID document
    let did_document = build_did_web_document(
        &did,
        &[ed25519_secret.clone(), x25519_secret.clone(), p256_secret.clone()],
        mediator_url,
    )?;

    let secrets = vec![ed25519_secret, x25519_secret, p256_secret];

    // Save secrets to disk
    for (i, secret) in secrets.iter().enumerate() {
        let secret_json = serde_json::to_string_pretty(&secret)?;
        crate::encryption::secret_file::write_secret_file(&cp_keys_path.join(format!("key_{}.json", i)), &secret_json)
            .await?;
    }

    // Save DID document to disk
    let did_doc_json = serde_json::to_string_pretty(&did_document)?;
    tokio::fs::write(&cp_keys_path.join("did.json"), did_doc_json).await?;

    info!("Generated connection point did:web: {}", did);

    Ok((did, secrets, did_document))
}

/// Generates a `did:peer` identity for a connection point.
///
/// Creates 3 key pairs: Ed25519 (verification) + X25519 and P-256 (key
/// agreement) — consistent with the did:webvh connection-point identity.
pub async fn generate_connection_point_identity_peer(
    connection_point_id: &str,
    storage_path: &std::path::Path,
    mediator_url: &str,
) -> Result<(String, Vec<Secret>, serde_json::Value)> {
    use affinidi_did_common::{DID, PeerCreateKey, PeerKeyPurpose, PeerService, PeerServiceEndpoint};

    let cp_keys_path = storage_path.join(connection_point_id);
    tokio::fs::create_dir_all(&cp_keys_path).await?;

    // Generate key material: Ed25519 (verification) + X25519 + P-256 (key agreement)
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret =
        Secret::generate_x25519(None, None).map_err(|e| anyhow::anyhow!("Failed to generate X25519 key: {:?}", e))?;
    let mut p256_secret =
        Secret::generate_p256(None, None).map_err(|e| anyhow::anyhow!("Failed to generate P-256 key: {:?}", e))?;

    info!("Generating connection point did:peer for: {}", connection_point_id);
    info!("  Service endpoint (mediator): {}", mediator_url);

    let v_multibase = ed25519_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get Ed25519 multibase: {:?}", e))?;
    let x_multibase = x25519_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get X25519 multibase: {:?}", e))?;
    let p_multibase = p256_secret
        .get_public_keymultibase()
        .map_err(|e| anyhow::anyhow!("Failed to get P-256 multibase: {:?}", e))?;

    let keys = vec![
        PeerCreateKey::from_multibase(PeerKeyPurpose::Verification, v_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, x_multibase),
        PeerCreateKey::from_multibase(PeerKeyPurpose::Encryption, p_multibase),
    ];
    let services = vec![PeerService {
        id: None,
        type_: "dm".into(),
        endpoint: PeerServiceEndpoint::Uri(mediator_url.to_string()),
    }];

    let (peer_did, _) = DID::generate_peer(&keys, Some(&services))
        .map_err(|e| anyhow::anyhow!("Failed to generate did:peer: {:?}", e))?;

    let did_str = peer_did.to_string();

    // Update secret IDs to reference the DID
    ed25519_secret.id = format!("{}#key-1", did_str);
    x25519_secret.id = format!("{}#key-2", did_str);
    p256_secret.id = format!("{}#key-3", did_str);

    let did_document = peer_did
        .resolve()
        .map_err(|e| anyhow::anyhow!("Failed to resolve did:peer document: {:?}", e))?;
    let did_document = serde_json::to_value(&did_document)
        .map_err(|e| anyhow::anyhow!("Failed to serialize did:peer document: {}", e))?;

    let secrets = vec![ed25519_secret, x25519_secret, p256_secret];

    // Save secrets to disk
    for (i, secret) in secrets.iter().enumerate() {
        let secret_json = serde_json::to_string_pretty(&secret)?;
        crate::encryption::secret_file::write_secret_file(&cp_keys_path.join(format!("key_{}.json", i)), &secret_json)
            .await?;
    }

    // Save DID document to disk
    let did_doc_json = serde_json::to_string_pretty(&did_document)?;
    tokio::fs::write(&cp_keys_path.join("did.json"), did_doc_json).await?;

    info!("Generated connection point did:peer: {}", did_str);

    Ok((did_str, secrets, did_document))
}

/// Builds a W3C compliant DID document for did:web from generated secrets.
/// Uses Ed25519 (verification, #key-1) + X25519 (#key-2) and P-256 (#key-3)
/// for key agreement — consistent with the did:webvh connection-point identity.
fn build_did_web_document(
    did: &str,
    secrets: &[Secret],
    mediator_url: &str,
) -> Result<serde_json::Value> {
    let mut public_jwks = Vec::new();

    for secret in secrets {
        if let affinidi_secrets_resolver::secrets::SecretMaterial::JWK(jwk) = &secret.secret_material {
            let mut jwk_value =
                serde_json::to_value(jwk).map_err(|e| anyhow::anyhow!("Failed to serialize JWK: {}", e))?;
            if let Some(obj) = jwk_value.as_object_mut() {
                obj.remove("d");
            }
            public_jwks.push(jwk_value);
        } else {
            return Err(anyhow::anyhow!("Secret is not a JWK"));
        }
    }

    let did_document = json!({
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1"
        ],
        "id": did,
        "verificationMethod": [
            {
                "id": format!("{}#key-1", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwks[0]
            },
            {
                "id": format!("{}#key-2", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwks[1]
            },
            {
                "id": format!("{}#key-3", did),
                "type": "JsonWebKey2020",
                "controller": did,
                "publicKeyJwk": public_jwks[2]
            }
        ],
        "authentication": [format!("{}#key-1", did)],
        "assertionMethod": [format!("{}#key-1", did)],
        "keyAgreement": [
            format!("{}#key-2", did),
            format!("{}#key-3", did)
        ],
        "service": [{
            "id": format!("{}#service", did),
            "type": ["DIDCommMessaging"],
            "serviceEndpoint": [{
                "uri": mediator_url,
                "accept": ["didcomm/v2"],
                "routingKeys": []
            }]
        }]
    });

    Ok(did_document)
}

/// Loads secrets for a connection point from disk
pub async fn load_connection_point_secrets(
    connection_point_id: &str,
    storage_path: &std::path::Path,
) -> Result<Vec<Secret>> {
    // storage_path is already the connection_points keys directory, just add the ID
    let cp_keys_path = storage_path.join(connection_point_id);

    let mut secrets = vec![];

    // Load all key files dynamically (did:peer uses 2 keys, did:webvh uses 3)
    for i in 0.. {
        let key_file = cp_keys_path.join(format!("key_{}.json", i));
        let Some(content) = crate::encryption::secret_file::read_secret_file(&key_file).await? else {
            break;
        };

        let secret: Secret = serde_json::from_str(&content)?;
        secrets.push(secret);
    }

    if secrets.is_empty() {
        return Err(anyhow::anyhow!("No key files found in {:?}", cp_keys_path));
    }

    Ok(secrets)
}

/// Request body for creating a connection point
#[derive(Debug, Deserialize)]
pub struct CreateConnectionPointRequest {
    pub gateway_id: String,
    pub mediator_id: String,
    pub name: String,
    pub description: String,
    pub expiry_seconds: Option<u64>,
    /// Optional integration ID to reference a configured integration (deprecated - use integrations array)
    pub integration_id: Option<String>,
    /// Template variable values for integration configuration (deprecated - use integrations array)
    #[serde(default)]
    pub integration_variables: serde_json::Value,
    /// List of integration integrations (email, Slack, etc.)
    #[serde(default)]
    pub integrations: Vec<super::types::IntegrationIntegration>,
    /// Secret required for accepting the OOB invitation
    pub secret: String,
    #[serde(default)]
    pub did_method: Option<ConnectionPointDidMethod>,
}

fn validate_invitation_capability(capability: &str) -> Result<(), String> {
    if !(32..=256).contains(&capability.len()) {
        return Err("Connection secret must contain 32-256 bytes".to_string());
    }
    Ok(())
}

/// Response for connection point creation
#[derive(Debug, Serialize)]
pub struct CreateConnectionPointResponse {
    pub connection_point: GatewayConnectionPoint,
}

fn tenant_context(context: &Option<Extension<PatTenantContext>>) -> Option<&PatTenantContext> {
    context
        .as_ref()
        .map(|Extension(context)| context)
}

fn resource_scope(scope: &Option<Extension<PatResourceScope>>) -> Option<&PatResourceScope> {
    scope
        .as_ref()
        .map(|Extension(scope)| scope)
}

fn connection_point_allowed(
    connection_point: &GatewayConnectionPoint,
    gateway: &Gateway,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(gateway.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::ConnectionPoints,
            &connection_point.id,
        )
}

async fn load_accessible_connection_point<S: ConnectionPointStore>(
    store: &S,
    gateway_store: &crate::gateways::FileSystemGatewayStore,
    id: &str,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
    mutation: bool,
) -> Result<(GatewayConnectionPoint, Gateway), (StatusCode, String)> {
    let connection_point = store
        .get(id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get connection point: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Connection point not found".to_string()))?;
    let gateway = gateway_store
        .get(&connection_point.gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get parent gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Connection point not found".to_string()))?;
    if !connection_point_allowed(&connection_point, &gateway, context, scope) {
        let status = if mutation {
            StatusCode::FORBIDDEN
        } else {
            StatusCode::NOT_FOUND
        };
        return Err((status, "Connection point not accessible".to_string()));
    }
    Ok((connection_point, gateway))
}

async fn validate_integration_references(
    owner_tenant_id: Option<&str>,
    legacy_id: Option<&str>,
    integrations: &[super::types::IntegrationIntegration],
    integration_store: Option<&Arc<crate::storage::IntegrationStorage>>,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> Result<(), (StatusCode, String)> {
    let mut ids = integrations
        .iter()
        .map(|integration| {
            integration
                .integration_id
                .as_str()
        })
        .collect::<std::collections::HashSet<_>>();
    if let Some(legacy_id) = legacy_id {
        ids.insert(legacy_id);
    }
    if ids.is_empty() {
        return Ok(());
    }
    let store = integration_store
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Integration store not configured".to_string()))?;
    for id in ids {
        let integration = store
            .load(id)
            .await
            .map_err(|_| (StatusCode::BAD_REQUEST, "Integration reference is not accessible".to_string()))?;
        if !can_reference(
            owner_tenant_id,
            integration
                .tenant_id
                .as_deref(),
        ) || !scope_allows_resource(
            resource_scope(scope),
            tenant_context(context),
            ResourceKind::Integrations,
            &integration.id,
        ) {
            return Err((StatusCode::BAD_REQUEST, "Integration reference is not accessible".to_string()));
        }
        if crate::integrations::audit_integration_triggers::is_audit_integration(&integration) {
            return Err((
                StatusCode::BAD_REQUEST,
                crate::integrations::audit_integration_triggers::AUDIT_INTEGRATION_NOT_LINKABLE.to_string(),
            ));
        }
    }
    Ok(())
}

/// List all connection points
pub async fn list_connection_points<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<ConnectionPointView>>, (StatusCode, String)> {
    let connection_points = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list connection points: {}", e)))?;

    let gateways = gateway_store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list parent gateways: {}", e)))?;
    let gateways: std::collections::HashMap<_, _> = gateways
        .into_iter()
        .map(|gateway| (gateway.id.clone(), gateway))
        .collect();
    let user_connection_points: Vec<ConnectionPointView> = connection_points
        .into_iter()
        .filter(|cp| {
            cp.cp_type == super::types::ConnectionPointType::User
                && gateways
                    .get(&cp.gateway_id)
                    .is_some_and(|gateway| connection_point_allowed(cp, gateway, &context, &scope))
        })
        .map(ConnectionPointView::from)
        .collect();

    Ok(Json(user_connection_points))
}

/// List connection points for a specific gateway
pub async fn list_gateway_connection_points<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<ConnectionPointView>>, (StatusCode, String)> {
    let gateway = gateway_store
        .get(&gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !can_access(gateway.tenant_id.as_deref(), tenant_context(&context)) {
        return Err((StatusCode::NOT_FOUND, "Gateway not found".to_string()));
    }
    let connection_points = store
        .list_by_gateway(&gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list connection points: {}", e)))?;

    // Filter to only show User type connection points
    let user_connection_points: Vec<ConnectionPointView> = connection_points
        .into_iter()
        .filter(|cp| {
            cp.cp_type == super::types::ConnectionPointType::User
                && connection_point_allowed(cp, &gateway, &context, &scope)
        })
        .map(ConnectionPointView::from)
        .collect();

    Ok(Json(user_connection_points))
}

/// Get a connection point by ID
pub async fn get_connection_point<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<ConnectionPointView>, (StatusCode, String)> {
    let (connection_point, _) =
        load_accessible_connection_point(store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, false).await?;

    Ok(Json(connection_point.into()))
}

/// Create a new connection point (OOB invitation)
pub async fn create_connection_point<P: ConnectionPointStore, G: GatewayStore, M: MediatorStore>(
    Extension(pub_store): Extension<std::sync::Arc<P>>,
    Extension(gateway_store): Extension<std::sync::Arc<G>>,
    Extension(mediator_store): Extension<std::sync::Arc<M>>,
    Extension(_vc_issuer): Extension<std::sync::Arc<VCIssuer>>,
    Extension(_config): Extension<std::sync::Arc<crate::config::GatewayConfig>>,
    Extension(bootstrap_config): Extension<std::sync::Arc<crate::config::BootstrapConfig>>,
    Extension(network_config): Extension<std::sync::Arc<crate::config::NetworkConfig>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(notif_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(integration_store): Extension<Option<Arc<crate::storage::IntegrationStorage>>>,
    #[cfg(feature = "didwebvh")] Extension(log_storage): Extension<
        Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    >,
    #[cfg(feature = "didwebvh")] Extension(identity_store): Extension<
        Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    >,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<CreateConnectionPointRequest>,
) -> Result<Json<CreateConnectionPointResponse>, (StatusCode, String)> {
    info!(
        "Creating connection point for gateway '{}' with mediator '{}', name: '{}', expiry: {:?}s",
        req.gateway_id, req.mediator_id, req.name, req.expiry_seconds
    );
    validate_invitation_capability(&req.secret).map_err(|error| (StatusCode::BAD_REQUEST, error))?;

    // Enforce the appliance connection-point limit (plus the connections total).
    if let Err(e) = crate::config::enforce_add("connections.connectionpoints").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    // Verify the gateway exists and is a self gateway
    let gateway = gateway_store
        .get(&req.gateway_id)
        .await
        .map_err(|e| {
            error!("Failed to get gateway '{}': {}", req.gateway_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e))
        })?
        .ok_or_else(|| {
            warn!("Gateway '{}' not found", req.gateway_id);
            (StatusCode::NOT_FOUND, "Gateway not found".to_string())
        })?;

    if gateway.gateway_type != GatewayType::SelfGateway {
        warn!(
            "Attempted to create connection point for non-self gateway: {} (type: {:?})",
            req.gateway_id, gateway.gateway_type
        );
        return Err((StatusCode::BAD_REQUEST, "Can only create connection points for self gateway".to_string()));
    }

    if !can_access(gateway.tenant_id.as_deref(), tenant_context(&context)) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }

    info!("Gateway '{}' validated (DID: {})", gateway.name, gateway.did);

    // Verify the mediator exists
    let mediator = mediator_store
        .get(&req.mediator_id)
        .await
        .map_err(|e| {
            error!("Failed to get mediator '{}': {}", req.mediator_id, e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e))
        })?
        .ok_or_else(|| {
            warn!("Mediator '{}' not found", req.mediator_id);
            (StatusCode::NOT_FOUND, "Mediator not found".to_string())
        })?;

    if !can_reference(gateway.tenant_id.as_deref(), mediator.tenant_id.as_deref())
        || !scope_allows_resource(
            resource_scope(&scope),
            tenant_context(&context),
            ResourceKind::Mediators,
            &mediator.id,
        )
    {
        return Err((StatusCode::BAD_REQUEST, "Mediator reference is not accessible".to_string()));
    }

    validate_integration_references(
        gateway.tenant_id.as_deref(),
        req.integration_id.as_deref(),
        &req.integrations,
        integration_store.as_ref(),
        &context,
        &scope,
    )
    .await?;

    info!("Mediator '{}' validated (DID: {})", mediator.name, mediator.did);

    // Generate unique DID and keys for this connection point
    // Each connection point gets its own DID to avoid duplicate WebSocket connections
    let temp_cp_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(
        resource_scope(&scope),
        tenant_context(&context),
        ResourceKind::ConnectionPoints,
        &temp_cp_id,
    ) {
        return Err((StatusCode::FORBIDDEN, "Connection point is outside this token's permitted scope".to_string()));
    }
    let storage_path = std::path::Path::new(
        &bootstrap_config
            .storage_paths
            .connection_points,
    );

    info!("Generating unique DID for connection point '{}'", req.name);
    let domain = &network_config.did.domain;

    let mediator_url =
        crate::mediators::transport::resolve_mediator_rest_endpoint(&mediator.did, mediator.did_document.clone())
            .await
            .map_err(|e| {
                error!("Failed to resolve mediator endpoint for DID '{}': {}", mediator.did, e);
                (StatusCode::BAD_REQUEST, format!("Failed to resolve mediator endpoint: {}", e))
            })?;

    let (connection_point_did, cp_secrets, did_document) = generate_connection_point_identity(
        &temp_cp_id,
        domain,
        storage_path,
        &mediator_url,
        req.did_method
            .as_ref()
            .unwrap_or(&ConnectionPointDidMethod::Web),
        #[cfg(feature = "didwebvh")]
        log_storage,
        #[cfg(feature = "didwebvh")]
        identity_store,
    )
    .await
    .map_err(|e| {
        error!("Failed to generate connection point identity: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate connection point DID: {}", e))
    })?;

    info!("✓ Generated connection point DID: {}", connection_point_did);
    info!("✓ Generated {} key(s) for connection point", cp_secrets.len());

    // Calculate expiry time (default 24 hours if not specified)
    let expiry_seconds = req
        .expiry_seconds
        .unwrap_or(86400); // 24 hours default
    let expiry_duration = std::time::Duration::from_secs(expiry_seconds);

    info!("Creating OOB invitation with expiry of {} seconds ({} hours)", expiry_seconds, expiry_seconds / 3600);

    info!("✓ Resolved mediator URL: {} (from DID: {})", mediator_url, mediator.did);
    if let Some(ref doc) = mediator.did_document
        && let Some(services) = doc
            .get("service")
            .and_then(|s| s.as_array())
    {
        info!("  Mediator has {} service endpoint(s) in DID document", services.len());
        for (i, service) in services.iter().enumerate() {
            if let Some(endpoints) = service.get("serviceEndpoint") {
                if let Some(uri_array) = endpoints.as_array() {
                    for ep in uri_array {
                        if let Some(uri) = ep
                            .get("uri")
                            .and_then(|u| u.as_str())
                        {
                            info!("    Service {}: {}", i, uri);
                        }
                    }
                } else if let Some(uri) = endpoints.as_str() {
                    info!("    Service {}: {}", i, uri);
                }
            }
        }
    }

    // did:key DIDs are self-describing - no need to manually build/cache DID document
    // The SDK's DID resolver can automatically generate the document from the DID string

    // Create OOB invitation using the connection point's DID (not gateway DID)
    info!("Creating OOB invitation with configuration:");
    info!("  Mediator URL: {}", mediator_url);
    info!("  Mediator DID: {}", mediator.did);
    info!("  Connection Point DID: {}", connection_point_did);
    info!("  Label: {}", req.name);

    let oob_result = create_oob_invitation(
        &mediator_url,
        &mediator.did,         // Use actual mediator DID from record
        &connection_point_did, // Use connection point DID, not gateway DID
        &req.name,
        &req.description,
        cp_secrets.clone(), // Use connection point secrets
        did_document,       // Pass DID document for caching
        Some(expiry_duration),
    )
    .await;

    let (oob_id, oob_url, oob_message) = oob_result.map_err(|e| {
        error!("Failed to create OOB invitation: {}", e);

        // TODO: Temporarily disabled cleanup for debugging
        // Clean up the generated keys since we're failing
        // let cp_keys_path = storage_path.join("connection_points").join(&temp_cp_id);
        // if let Err(cleanup_err) = std::fs::remove_dir_all(&cp_keys_path) {
        //     warn!("Failed to cleanup keys directory after OOB creation failure: {}", cleanup_err);
        // }

        warn!("Keys NOT cleaned up for debugging - ID: {}", temp_cp_id);

        (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create OOB invitation: {}", e))
    })?;

    info!("Successfully created OOB invitation");

    // Convert expiry to DateTime
    let expires_at = Some(
        chrono::Utc::now()
            + chrono::Duration::try_seconds(expiry_seconds as i64)
                .unwrap_or_else(|| chrono::Duration::try_hours(24).unwrap()),
    );

    // Move values instead of cloning to reduce allocations
    let mut connection_point = GatewayConnectionPoint::new(
        req.gateway_id,
        req.mediator_id,
        connection_point_did, // Store the connection point's DID (moved)
        req.name,
        req.description,
        oob_id,
        oob_url,
        oob_message,
        expires_at,
        super::types::ConnectionPointType::User, // User-created via UX
        req.secret,
    );

    // Override the generated ID with our temp_cp_id to match where keys were stored
    connection_point.id = temp_cp_id;

    // Apply DID method preference
    connection_point.did_method = req
        .did_method
        .unwrap_or_default();

    // Apply integration configuration (move values instead of clone)
    connection_point.integration_id = req.integration_id;
    connection_point.integration_variables = req.integration_variables;
    connection_point.integrations = req.integrations;

    // Log integration configuration
    if !connection_point
        .integrations
        .is_empty()
    {
        info!(
            "Connection point '{}' configured with {} integration(s)",
            connection_point.name,
            connection_point
                .integrations
                .len()
        );
        for integration_integration in &connection_point.integrations {
            info!("  - integration: {}", integration_integration.integration_id);
        }
    } else if connection_point
        .integration_id
        .is_some()
    {
        info!(
            "Connection point '{}' configured with legacy single integration: {}",
            connection_point.name,
            connection_point
                .integration_id
                .as_ref()
                .unwrap()
        );
    }

    debug!("Creating connection point with ID: {}", connection_point.id);

    pub_store
        .create(&connection_point)
        .await
        .map_err(|e| {
            error!("Failed to create connection point: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create connection point: {}", e))
        })?;

    info!(
        "Connection point created successfully: ID={}, Gateway={}, Mediator={}, URL={}",
        connection_point.id,
        connection_point.gateway_id,
        connection_point.mediator_id,
        crate::url_validation::redact_url_for_logging(&connection_point.oob_url)
    );

    // Start WebSocket listener for this connection point
    info!("Starting WebSocket listener for connection point '{}'", connection_point.name);
    if let Err(e) = listener_manager
        .start_listener(&connection_point, mediator.did.clone(), bootstrap_config)
        .await
    {
        error!("Failed to start WebSocket listener for connection point '{}': {}", connection_point.name, e);
        warn!("Connection point created but WebSocket listener failed to start - manual intervention may be required");
        // Don't fail the whole operation if listener fails to start
        // The connection point is still valid, just not actively listening
    } else {
        info!("✓ WebSocket listener started successfully for connection point '{}'", connection_point.name);
    }

    // Trigger connection_point.created integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        crate::integrations::trigger_connection_point_created_async(Some(notif.clone()), &connection_point);
    }

    Ok(Json(CreateConnectionPointResponse { connection_point }))
}

/// The stored invitation record. `id` is the invitation message id that the
/// acceptor's connection-setup must name as its `pthid`.
fn invitation_record(
    oobid: &str,
    invitation_id: &str,
    label: &str,
    goal: &str,
    from_did: &str,
    expiry: Option<std::time::Duration>,
) -> serde_json::Value {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let expiry_secs = expiry
        .map(|d| d.as_secs())
        .unwrap_or(86400);

    json!({
        "@type": MessageType::OOBInvitation.to_string(),
        "id": invitation_id,
        "label": label,
        "goal_code": "gateway-connection",
        "goal": goal,
        "from": from_did,
        "created_time": now,
        "expires_time": now + expiry_secs,
        "_oobid": oobid,
    })
}

/// Create OOB invitation using Affinidi Messaging SDK with proper DID authentication
/// This creates the invitation via the mediator endpoint with authentication
async fn create_oob_invitation(
    mediator_url: &str,
    mediator_did: &str,
    from_did: &str,
    label: &str,
    goal: &str,
    secrets: Vec<Secret>,
    did_document: serde_json::Value,
    expiry: Option<std::time::Duration>,
) -> Result<(String, String, serde_json::Value), String> {
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("Creating OOB invitation via SDK");
    info!("  Mediator URL: {}", mediator_url);
    info!("  Mediator DID: {}", mediator_did);
    info!("  From DID: {}", from_did);
    info!("  Label: {}", label);
    info!("  Goal: {}", goal);
    info!("  Expiry: {:?}", expiry);
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    // Build a fresh DIDComm client for this connection point's own DID.
    //
    // The connection point's own DID document must be cached in the resolver
    // BEFORE enabling the WebSocket: enabling triggers mediator authentication,
    // which resolves our did:webvh over HTTPS — and at creation time our own
    // did.jsonl may not be served yet, so the resolver must find it in cache.
    // Caching after `new()` (which builds the profile) but before
    // `enable_websocket()` is sufficient.
    let alias = format!("gateway-{}", uuid::Uuid::new_v4());
    let mut client = DIDCommClient::new(from_did.to_string(), secrets, Some(mediator_did.to_string()), Some(alias))
        .await
        .map_err(|e| format!("Failed to build DIDComm client: {}", e))?;

    client
        .cache_did_document(from_did, did_document)
        .await
        .map_err(|e| format!("Failed to cache connection point DID document: {}", e))?;
    info!("✓ Connection point DID document cached in resolver");

    info!("Enabling WebSocket for connection point profile...");
    client
        .enable_websocket()
        .await
        .map_err(|e| format!("Failed to enable WebSocket: {}", e))?;
    info!("✓ Profile added to ATM with WebSocket enabled");

    // CRITICAL: Set ACL to allow ANYONE to send to this OOB connection point
    // Mediator is in ExplicitAllow mode, so we need to set ACL flags to OOB_ACL_FLAGS (allow all)
    info!("🔐 Setting ACL to allow anyone to send connection-setup messages...");
    set_acl_to_allow_everything_and_more(client.atm().as_ref(), Arc::clone(client.profile()))
        .await
        .map_err(|e| {
            warn!("  ⚠️  Failed to set ACL on mediator: {:?}", e);
            warn!("  OOB connections may FAIL if mediator is in ExplicitAllow mode");
        })
        .ok();

    // Create OOB Discovery instance
    let oob_discovery = OOBDiscovery::default();

    // Create the invitation with DID authentication
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("Calling OOBDiscovery::create_invite...");
    info!("  This will POST to: {}/oob", mediator_url);
    info!("  With authentication as: {}", from_did);
    info!("  To mediator: {}", mediator_did);
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    let oob_result = async {
        let oobid = oob_discovery
            .create_invite(client.atm().as_ref(), client.profile(), expiry)
            .await
            .map_err(|e| format!("OOB creation failed: {:?}", e))?;
        // The acceptor uses the invitation message id as its pthid, and the SDK
        // generates that id without returning it, so read the invitation back.
        let rest_endpoint = client
            .profile()
            .get_mediator_rest_endpoint()
            .ok_or_else(|| "Mediator REST endpoint is missing".to_string())?;
        let invitation = oob_discovery
            .retrieve_invite(client.atm().as_ref(), &format!("{rest_endpoint}/oob?_oobid={oobid}"))
            .await
            .map_err(|e| format!("Failed to read back OOB invitation: {:?}", e))?;
        Ok::<_, String>((oobid, invitation.id))
    }
    .await;

    // Cleanup: Graceful shutdown of ATM
    client
        .atm()
        .graceful_shutdown()
        .await;

    match oob_result {
        Ok((oobid, invitation_id)) => {
            info!("✓ OOB invitation created successfully");

            // Construct the OOB URL
            let oob_url = format!("{}/oob?_oobid={}", mediator_url, oobid);
            let oob_message = invitation_record(&oobid, &invitation_id, label, goal, from_did, expiry);

            info!("OOB URL: {}", crate::url_validation::redact_url_for_logging(&oob_url));

            Ok((oobid, oob_url, oob_message))
        }
        Err(e) => {
            error!("✗ Failed to create OOB invitation via SDK: {}", e);
            Err(e)
        }
    }
}

/// Delete a connection point
pub async fn delete_connection_point<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(notif_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    info!("Deleting connection point: {}", id);

    // Get connection point before deletion for trigger
    let (connection_point, _) =
        load_accessible_connection_point(store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, true).await?;

    // Stop the WebSocket listener first
    if let Err(e) = listener_manager
        .stop_listener(&id)
        .await
    {
        warn!("Failed to stop WebSocket listener for connection point '{}': {}", id, e);
        // Continue with deletion even if listener stop fails
    } else {
        info!("✓ WebSocket listener stopped for connection point '{}'", id);
    }

    // Delete from storage
    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete connection point: {}", e)))?;

    // Trigger connection_point.deleted integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        crate::integrations::trigger_connection_point_deleted_async(Some(notif.clone()), &connection_point);
    }

    info!("Connection point '{}' deleted successfully", id);
    Ok(StatusCode::NO_CONTENT)
}

/// Increment use count for a connection point
pub async fn use_connection_point<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<ConnectionPointView>, (StatusCode, String)> {
    let (mut connection_point, _) =
        load_accessible_connection_point(store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, true).await?;

    connection_point.use_count += 1;
    connection_point.last_used_at = Some(chrono::Utc::now());

    store
        .update(&connection_point)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update connection point: {}", e)))?;

    Ok(Json(connection_point.into()))
}

/// Request body for updating connection point basic information
#[derive(Debug, Deserialize)]
pub struct UpdateConnectionPointRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub integration_integrations: Option<Vec<super::types::IntegrationIntegration>>,
    pub enabled: Option<bool>,
}

/// Update basic information for a connection point
pub async fn update_connection_point<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(notif_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(integration_store): Extension<Option<Arc<crate::storage::IntegrationStorage>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateConnectionPointRequest>,
) -> Result<Json<ConnectionPointView>, (StatusCode, String)> {
    info!("Updating connection point: {}", id);

    let (old_connection_point, gateway) =
        load_accessible_connection_point(store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, true).await?;

    if let Some(integrations) = req
        .integration_integrations
        .as_ref()
    {
        validate_integration_references(
            gateway.tenant_id.as_deref(),
            old_connection_point
                .integration_id
                .as_deref(),
            integrations,
            integration_store.as_ref(),
            &context,
            &scope,
        )
        .await?;
    }

    let mut connection_point = old_connection_point.clone();

    // Track if name changed to update listener
    let name_changed = req
        .name
        .as_ref()
        .map(|n| n != &connection_point.name)
        .unwrap_or(false);

    // Update fields if provided
    if let Some(name) = req.name {
        connection_point.name = name;
    }
    if let Some(description) = req.description {
        connection_point.description = description;
    }
    if let Some(integration_integrations) = req.integration_integrations {
        connection_point.integrations = integration_integrations;
    }
    if let Some(enabled) = req.enabled {
        connection_point.enabled = enabled;
    }

    store
        .update(&connection_point)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update connection point: {}", e)))?;

    // Update listener name if it changed
    if name_changed
        && let Err(e) = listener_manager
            .update_listener_name(&id, connection_point.name.clone())
            .await
    {
        warn!("Failed to update listener name: {}", e);
        // Don't fail the update if listener name update fails
    }

    // Trigger connection_point.updated integration (async, non-blocking)
    if let Some(notif) = notif_store.as_ref() {
        crate::integrations::trigger_connection_point_updated_async(
            Some(notif.clone()),
            &old_connection_point,
            &connection_point,
        );
    }

    info!("✓ Connection point '{}' updated successfully", connection_point.name);

    Ok(Json(connection_point.into()))
}

/// Request body for updating connection point exposed channels
#[derive(Debug, Deserialize)]
pub struct UpdateExposedChannelsRequest {
    pub exposed_channels: Vec<String>,
}

/// Update exposed channels configuration for a connection point
pub async fn update_connection_point_exposed_channels<S: ConnectionPointStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(surface_store): Extension<Option<Arc<dyn AgentSurfaceStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateExposedChannelsRequest>,
) -> Result<Json<ConnectionPointView>, (StatusCode, String)> {
    info!("Updating exposed channels for connection point: {}", id);

    let (mut connection_point, gateway) =
        load_accessible_connection_point(store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, true).await?;

    if !req
        .exposed_channels
        .is_empty()
    {
        let surface_store = surface_store
            .as_ref()
            .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Surface store not configured".to_string()))?;
        for surface_id in &req.exposed_channels {
            let surface = surface_store
                .get(surface_id)
                .await
                .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
                .ok_or_else(|| (StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()))?;
            if !can_reference(gateway.tenant_id.as_deref(), surface.tenant_id.as_deref())
                || !scope_allows_resource(
                    resource_scope(&scope),
                    tenant_context(&context),
                    ResourceKind::Surfaces,
                    &surface.surface_id,
                )
            {
                return Err((StatusCode::BAD_REQUEST, "Surface reference is not accessible".to_string()));
            }
        }
    }

    connection_point.exposed_channels = req.exposed_channels.clone();

    store
        .update(&connection_point)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update connection point: {}", e)))?;

    if connection_point
        .exposed_channels
        .is_empty()
    {
        info!("✓ Connection point '{}' now exposes all channels (no filter)", connection_point.name);
    } else {
        info!(
            "✓ Connection point '{}' now exposes {} specific channels",
            connection_point.name,
            connection_point
                .exposed_channels
                .len()
        );
    }

    Ok(Json(connection_point.into()))
}

/// Get messages for a connection point
pub async fn get_connection_point_messages(
    Extension(message_store): Extension<std::sync::Arc<crate::gateways::MessageStore>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<crate::gateways::ReceivedMessage>>, (StatusCode, String)> {
    load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, false).await?;
    info!("Retrieving messages for connection point: {}", id);

    let messages = message_store
        .list_by_connection_point(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to retrieve messages: {}", e)))?;

    info!("Found {} messages for connection point '{}'", messages.len(), id);
    Ok(Json(messages))
}

/// Get a specific message by ID
pub async fn get_connection_point_message(
    Extension(message_store): Extension<std::sync::Arc<crate::gateways::MessageStore>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path((cp_id, msg_id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<crate::gateways::ReceivedMessage>, (StatusCode, String)> {
    load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &cp_id, &context, &scope, false)
        .await?;
    info!("Retrieving message {} for connection point: {}", msg_id, cp_id);

    let message = message_store
        .get(&cp_id, &msg_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to retrieve message: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Message not found".to_string()))?;

    Ok(Json(message))
}

/// Mark a message as read
pub async fn mark_message_read(
    Extension(message_store): Extension<std::sync::Arc<crate::gateways::MessageStore>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path((cp_id, msg_id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &cp_id, &context, &scope, true).await?;
    info!("Marking message {} as read for connection point: {}", msg_id, cp_id);

    message_store
        .mark_read(&cp_id, &msg_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to mark message as read: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Delete a message
pub async fn delete_message(
    Extension(message_store): Extension<std::sync::Arc<crate::gateways::MessageStore>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path((cp_id, msg_id)): Path<(String, String)>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &cp_id, &context, &scope, true).await?;
    info!("Deleting message {} for connection point: {}", msg_id, cp_id);

    message_store
        .delete(&cp_id, &msg_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete message: {}", e)))?;

    Ok(StatusCode::NO_CONTENT)
}

/// Get unread message count for a connection point
pub async fn get_unread_message_count(
    Extension(message_store): Extension<std::sync::Arc<crate::gateways::MessageStore>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, false).await?;
    let count = message_store
        .get_unread_count(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get unread count: {}", e)))?;

    Ok(Json(json!({ "unread_count": count })))
}

/// Get metrics for a connection point's WebSocket listener
pub async fn get_connection_point_metrics(
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Extension(cp_store): Extension<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<super::ws_listener::ConnectionPointMetrics>, (StatusCode, String)> {
    info!("Getting metrics for connection point: {}", id);

    let (connection_point, _) =
        load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, false)
            .await?;

    let listeners = listener_manager
        .get_active_listeners()
        .await;

    if let Some(listener) = listeners
        .iter()
        .find(|l| l.id == id)
    {
        let metrics = listener.metrics.read().await;
        return Ok(Json(metrics.clone()));
    }

    // No active listener (the connection is down, or this node holds none):
    // synthesize metrics from the persisted runtime status so the endpoint does
    // not 404 and the UI can still show why the connection is not up.
    let runtime = connection_point
        .runtime_status
        .unwrap_or_default();
    let metrics = super::ws_listener::ConnectionPointMetrics {
        status: runtime.status,
        started_at: runtime
            .last_active_at
            .unwrap_or_else(chrono::Utc::now),
        last_activity: runtime.last_active_at,
        message_count: 0,
        error_count: 0,
        reconnect_attempts: runtime.consecutive_failures,
        in_flight_dispatches: 0,
        max_in_flight_dispatches: 0,
    };
    Ok(Json(metrics))
}

/// Response for a manual connection point reconnect.
#[derive(Debug, Serialize)]
pub struct ReconnectConnectionPointResponse {
    pub connection_point: ConnectionPointView,
}

/// Manually retry (reconnect) a connection point's DIDComm link.
///
/// Resets the reconnect backoff and clears the scheduled next retry so the
/// listener attempts immediately, persists that, then restarts the listener on
/// this node. Restarting only takes effect on an Active instance (a Standby
/// holds no listeners); the persisted reset is picked up when it is promoted.
pub async fn reconnect_connection_point<P: ConnectionPointStore, M: MediatorStore>(
    Extension(cp_store): Extension<std::sync::Arc<P>>,
    Extension(gateway_store): Extension<std::sync::Arc<crate::gateways::FileSystemGatewayStore>>,
    Extension(mediator_store): Extension<std::sync::Arc<M>>,
    Extension(listener_manager): Extension<std::sync::Arc<ConnectionPointListenerManager>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<ReconnectConnectionPointResponse>, (StatusCode, String)> {
    info!("Manual reconnect requested for connection point: {}", id);

    let (mut connection_point, gateway) =
        load_accessible_connection_point(cp_store.as_ref(), gateway_store.as_ref(), &id, &context, &scope, true)
            .await?;

    // mediator_id may be a DID or a stored mediator's ID.
    let mediator_did = if connection_point
        .mediator_id
        .starts_with("did:")
    {
        connection_point
            .mediator_id
            .clone()
    } else {
        let mediator = mediator_store
            .get(&connection_point.mediator_id)
            .await
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
            .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
        if !can_reference(gateway.tenant_id.as_deref(), mediator.tenant_id.as_deref())
            || !scope_allows_resource(
                resource_scope(&scope),
                tenant_context(&context),
                ResourceKind::Mediators,
                &mediator.id,
            )
        {
            return Err((StatusCode::BAD_REQUEST, "Mediator reference is not accessible".to_string()));
        }
        mediator.did
    };

    // Reset the backoff so the fresh listener attempts immediately.
    let mut runtime = connection_point
        .runtime_status
        .clone()
        .unwrap_or_default();
    runtime.status = crate::comm::connection_health::ConnectionStatus::Reconnecting;
    runtime.consecutive_failures = 0;
    runtime.next_retry_at = None;
    runtime.current_backoff_seconds = None;
    connection_point.runtime_status = Some(runtime);
    cp_store
        .update(&connection_point)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update connection point: {}", e)))?;

    // Restart the listener on this node (safe if it is not currently running).
    let _ = listener_manager
        .stop_listener(&id)
        .await;
    if let Err(e) = listener_manager.request_start_listener(connection_point.clone(), mediator_did) {
        warn!("Failed to request listener restart for connection point '{}': {}", id, e);
    }

    Ok(Json(ReconnectConnectionPointResponse {
        connection_point: connection_point.into(),
    }))
}

/// Serves the DID document for a connection point (did:web resolution)
/// Route: /.well-known/connection-points/{cp_id}/did.json
pub async fn serve_connection_point_did_document<P: ConnectionPointStore>(
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<std::sync::Arc<P>>,
    Path(cp_id): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    debug!("Serving DID document for connection point: {}", cp_id);

    let cp_dir = format!(
        "{}/{}",
        config
            .storage_paths
            .connection_points,
        cp_id
    );

    // If a did.jsonl log exists for this connection point, serve the
    // parallel did:web document derived from the latest log entry.
    #[cfg(feature = "didwebvh")]
    {
        let log_path = std::path::Path::new(&cp_dir).join("did.jsonl");
        if let Some(state_doc) = load_latest_cp_log_state(&log_path).await {
            // Extract the DID from the document to build the parallel form
            let webvh_did = state_doc
                .get("id")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let scid = extract_scid_from_webvh_did(&webvh_did);
            if !scid.is_empty() {
                let parallel = crate::identity::didwebvh::generate_parallel_did_web(&state_doc, &webvh_did, &scid);
                return Ok(Json(parallel));
            }
        }
    }

    // Legacy fallback: read did.json from storage
    let did_doc_path = format!("{}/did.json", cp_dir);

    let did_doc_content = tokio::fs::read_to_string(&did_doc_path)
        .await
        .map_err(|e| {
            warn!("Failed to read DID document for {}: {}", cp_id, e);
            (StatusCode::NOT_FOUND, format!("DID document not found for connection point: {}", cp_id))
        })?;

    let did_document: serde_json::Value = serde_json::from_str(&did_doc_content).map_err(|e| {
        error!("Failed to parse DID document for {}: {}", cp_id, e);
        (StatusCode::INTERNAL_SERVER_ERROR, "Invalid DID document".to_string())
    })?;

    Ok(Json(did_document))
}

/// Extract the SCID from a `did:webvh:<SCID>:...` DID string.
fn extract_scid_from_webvh_did(did: &str) -> String {
    let parts: Vec<&str> = did.splitn(4, ':').collect();
    if parts.len() >= 3 {
        parts[2].to_string()
    } else {
        String::new()
    }
}

/// Read the latest log entry state from a `did.jsonl` file, returning it as JSON.
#[cfg(feature = "didwebvh")]
async fn load_latest_cp_log_state(path: &std::path::Path) -> Option<serde_json::Value> {
    use crate::identity::didwebvh::types::LogEntry;

    let content = tokio::fs::read_to_string(path)
        .await
        .ok()?;
    let latest: LogEntry = content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| serde_json::from_str(line).ok())
        .next_back()?;
    serde_json::to_value(&latest.state).ok()
}

/// Handler for `GET /connection-points/{cp_id}/did.jsonl` (and the `.well-known` variant).
///
/// Serves the connection point's verifiable DID log for did:webvh resolution.
/// Returns 404 (RFC 9457 problem-details) when the log has not been created yet.
///
pub async fn serve_connection_point_did_jsonl<P: ConnectionPointStore>(
    Extension(config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(_store): Extension<std::sync::Arc<P>>,
    Path(cp_id): Path<String>,
) -> axum::response::Response {
    use axum::http::{StatusCode, header};
    use axum::response::IntoResponse;

    let log_path = std::path::Path::new(
        &config
            .storage_paths
            .connection_points,
    )
    .join(&cp_id)
    .join("did.jsonl");

    match tokio::fs::read_to_string(&log_path).await {
        Ok(content) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/jsonl"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
            content,
        )
            .into_response(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "notFound",
                "status": 404,
                "detail": format!("DID log not found for connection point: {}", cp_id)
            });
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "application/problem+json"), (header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
                problem.to_string(),
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(error = %e, cp_id = %cp_id, "Failed to read connection point did.jsonl");
            let problem = serde_json::json!({
                "type": "https://identity.foundation/didwebvh/v1.0/#problem-details",
                "title": "internalError",
                "status": 500,
                "detail": "Failed to read DID log"
            });
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "application/problem+json")],
                problem.to_string(),
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Gateway, GatewayConnectionPoint, GatewayType, PatResourceScope, PatTenantContext, connection_point_allowed,
        generate_connection_point_identity_webvh, invitation_record, load_connection_point_secrets,
        validate_invitation_capability,
    };
    use crate::gateways::connection_points::filesystem::{ConnectionPointStore, FileSystemConnectionPointStore};
    use crate::gateways::connection_points::store::InvitationConsumeError;
    use crate::gateways::connection_points::types::ConnectionPointType;
    use axum::{Extension, Json};

    async fn stored_invitation() -> (tempfile::TempDir, FileSystemConnectionPointStore, GatewayConnectionPoint) {
        let dir = tempfile::tempdir().unwrap();
        let store = FileSystemConnectionPointStore::new(dir.path().to_path_buf())
            .await
            .unwrap();
        let invitation = GatewayConnectionPoint::new(
            "gateway-1".into(),
            "mediator-1".into(),
            "did:example:inviter".into(),
            "Invitation".into(),
            String::new(),
            "mediator-oob-1".into(),
            String::new(),
            invitation_record("mediator-oob-1", "invitation-message-1", "Invitation", "", "did:example:inviter", None),
            Some(chrono::Utc::now() + chrono::Duration::minutes(5)),
            ConnectionPointType::User,
            "correct-secret".into(),
        );
        store
            .create(&invitation)
            .await
            .unwrap();
        (dir, store, invitation)
    }

    struct ReadFixture {
        _dir: tempfile::TempDir,
        store: std::sync::Arc<FileSystemConnectionPointStore>,
        gateways: std::sync::Arc<crate::gateways::FileSystemGatewayStore>,
        invitation: GatewayConnectionPoint,
    }

    async fn stored_invitation_with_gateway() -> ReadFixture {
        use crate::gateways::filesystem::GatewayStore;
        let (dir, store, invitation) = stored_invitation().await;
        let gateways = crate::gateways::FileSystemGatewayStore::new(dir.path().join("gateways"), None)
            .await
            .unwrap();
        let mut gateway = Gateway::new("Peer".into(), String::new(), "did:web:peer".into(), GatewayType::Remote);
        gateway.id = invitation.gateway_id.clone();
        gateways
            .create(&gateway)
            .await
            .unwrap();
        ReadFixture {
            _dir: dir,
            store: std::sync::Arc::new(store),
            gateways: std::sync::Arc::new(gateways),
            invitation,
        }
    }

    fn assert_no_secret(
        returned: serde_json::Value,
        invitation: &GatewayConnectionPoint,
    ) {
        assert_eq!(returned["id"], invitation.id, "{returned}");
        assert!(
            returned
                .get("secret")
                .is_none(),
            "{returned}"
        );
        assert!(
            !returned
                .to_string()
                .contains(&invitation.secret),
            "{returned}"
        );
    }

    #[tokio::test]
    async fn reading_a_connection_point_never_returns_its_secret() {
        let fixture = stored_invitation_with_gateway().await;
        let id = fixture.invitation.id.clone();

        let Json(one) = super::get_connection_point(
            Extension(fixture.store.clone()),
            Extension(fixture.gateways.clone()),
            axum::extract::Path(id),
            None,
            None,
        )
        .await
        .unwrap();
        assert_no_secret(serde_json::to_value(one).unwrap(), &fixture.invitation);

        let Json(all) = super::list_connection_points(
            Extension(fixture.store.clone()),
            Extension(fixture.gateways.clone()),
            None,
            None,
        )
        .await
        .unwrap();
        let all = serde_json::to_value(all).unwrap();
        assert_eq!(all.as_array().map(Vec::len), Some(1), "{all}");
        assert_no_secret(all[0].clone(), &fixture.invitation);

        let Json(by_gateway) = super::list_gateway_connection_points(
            Extension(fixture.store.clone()),
            Extension(fixture.gateways.clone()),
            axum::extract::Path(
                fixture
                    .invitation
                    .gateway_id
                    .clone(),
            ),
            None,
            None,
        )
        .await
        .unwrap();
        let by_gateway = serde_json::to_value(by_gateway).unwrap();
        assert_eq!(
            by_gateway
                .as_array()
                .map(Vec::len),
            Some(1),
            "{by_gateway}"
        );
        assert_no_secret(by_gateway[0].clone(), &fixture.invitation);
    }

    #[tokio::test]
    async fn changing_a_connection_point_never_returns_its_secret() {
        let fixture = stored_invitation_with_gateway().await;
        let id = fixture.invitation.id.clone();

        let Json(used) = super::use_connection_point(
            Extension(fixture.store.clone()),
            axum::extract::Path(id.clone()),
            Extension(fixture.gateways.clone()),
            None,
            None,
        )
        .await
        .unwrap();
        assert_no_secret(serde_json::to_value(used).unwrap(), &fixture.invitation);

        let Json(exposed) = super::update_connection_point_exposed_channels(
            Extension(fixture.store.clone()),
            Extension(fixture.gateways.clone()),
            Extension(None),
            axum::extract::Path(id.clone()),
            None,
            None,
            Json(super::UpdateExposedChannelsRequest { exposed_channels: Vec::new() }),
        )
        .await
        .unwrap();
        assert_no_secret(serde_json::to_value(exposed).unwrap(), &fixture.invitation);

        let stored = fixture
            .store
            .get(&id)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(stored.secret, "correct-secret", "the stored secret still redeems the invitation");
    }

    #[test]
    fn the_create_response_returns_the_secret() {
        let invitation = GatewayConnectionPoint::new(
            "gateway-1".into(),
            "mediator-1".into(),
            "did:example:inviter".into(),
            "Invitation".into(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::json!({}),
            None,
            ConnectionPointType::User,
            "correct-secret".into(),
        );

        let created =
            serde_json::to_value(super::CreateConnectionPointResponse { connection_point: invitation }).unwrap();

        assert!(created["connection_point"]["secret"].is_string(), "{created}");
        let returned: GatewayConnectionPoint = serde_json::from_value(created["connection_point"].clone()).unwrap();
        assert_eq!(returned.secret, "correct-secret");
    }

    #[tokio::test]
    async fn stored_invitation_accepts_the_invitation_message_id_as_parent_thread() {
        let (_dir, store, invitation) = stored_invitation().await;

        let consumed = store
            .consume_invitation(&invitation.id, "invitation-message-1", "correct-secret", chrono::Utc::now())
            .await
            .unwrap();

        assert_eq!(consumed.use_count, 1);
    }

    #[tokio::test]
    async fn stored_invitation_rejects_the_mediator_oobid_as_parent_thread() {
        let (_dir, store, invitation) = stored_invitation().await;

        let result = store
            .consume_invitation(&invitation.id, "mediator-oob-1", "correct-secret", chrono::Utc::now())
            .await;

        assert_eq!(result.unwrap_err(), InvitationConsumeError::ThreadMismatch);
    }

    #[test]
    fn canonical_connection_point_access_uses_parent_tenant_and_child_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:connection-points:cp-1\z").unwrap(),
        ))));
        let mut gateway = Gateway::new("Gateway".into(), String::new(), "did:web:gateway".into(), GatewayType::Remote);
        gateway.id = "gateway-1".into();
        gateway.tenant_id = Some("tenant-a".into());
        let mut connection_point = GatewayConnectionPoint::new(
            gateway.id.clone(),
            "mediator-1".into(),
            "did:web:cp".into(),
            "Connection".into(),
            String::new(),
            String::new(),
            String::new(),
            serde_json::json!({}),
            None,
            super::super::types::ConnectionPointType::User,
            String::new(),
        );
        connection_point.id = "cp-1".into();

        assert!(connection_point_allowed(&connection_point, &gateway, &context, &scope));

        gateway.tenant_id = Some("tenant-b".into());
        assert!(!connection_point_allowed(&connection_point, &gateway, &context, &scope));

        gateway.tenant_id = None;
        // Untenanted (legacy) parent gateway now denied to a tenant PAT (fail-closed hardening).
        assert!(!connection_point_allowed(&connection_point, &gateway, &context, &scope));

        connection_point.id = "cp-2".into();
        assert!(!connection_point_allowed(&connection_point, &gateway, &context, &scope));
    }

    #[test]
    fn invitation_capabilities_require_bounded_strength() {
        assert!(validate_invitation_capability(&"a".repeat(32)).is_ok());
        assert!(validate_invitation_capability(&"a".repeat(256)).is_ok());
        assert!(validate_invitation_capability(&"a".repeat(31)).is_err());
        assert!(validate_invitation_capability(&"a".repeat(257)).is_err());
    }

    // === Connection Point Identity Tests ===
    /// key_0.json, key_1.json, key_2.json must be written to the storage directory.
    #[tokio::test]
    async fn generate_connection_point_creates_key_files() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        for i in 0..3 {
            let key_path = tmp
                .path()
                .join(&cp_id)
                .join(format!("key_{}.json", i));
            assert!(key_path.exists(), "key_{}.json must exist after identity generation", i);
        }
    }

    /// did.json must be written alongside did.jsonl.
    #[tokio::test]
    async fn generate_connection_point_creates_did_json() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        let did_json_path = tmp
            .path()
            .join(&cp_id)
            .join("did.json");
        assert!(did_json_path.exists(), "did.json must be written after identity generation");

        let did_jsonl_path = tmp
            .path()
            .join(&cp_id)
            .join("did.jsonl");
        assert!(did_jsonl_path.exists(), "did.jsonl must also be written for did:webvh");

        let content = tokio::fs::read_to_string(&did_json_path)
            .await
            .unwrap();
        let _: serde_json::Value = serde_json::from_str(&content).expect("did.json must be valid JSON");
    }

    /// Loading secrets from disk must yield the same key material as was generated.
    #[tokio::test]
    async fn load_connection_point_secrets_round_trips_keys() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        let (_, original_secrets, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        let loaded_secrets = load_connection_point_secrets(&cp_id, tmp.path())
            .await
            .unwrap();

        assert_eq!(loaded_secrets.len(), original_secrets.len(), "Loaded secrets count must match original");

        for (i, (orig, loaded)) in original_secrets
            .iter()
            .zip(loaded_secrets.iter())
            .enumerate()
        {
            assert_eq!(orig.id, loaded.id, "Secret {} ID must round-trip through disk", i);
            let orig_material = serde_json::to_string(&orig.secret_material).unwrap();
            let loaded_material = serde_json::to_string(&loaded.secret_material).unwrap();
            assert_eq!(orig_material, loaded_material, "Secret {} material must round-trip through disk", i);
        }
    }

    /// Each call must produce a unique DID.
    #[tokio::test]
    async fn each_connection_point_gets_unique_did() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id_1 = uuid::Uuid::new_v4().to_string();
        let cp_id_2 = uuid::Uuid::new_v4().to_string();

        let (did_1, _, _) = generate_connection_point_identity_webvh(
            &cp_id_1,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();
        let (did_2, _, _) = generate_connection_point_identity_webvh(
            &cp_id_2,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        assert_ne!(did_1, did_2, "Each connection point must receive a unique DID");
    }

    // === Connection Point Migration Tests ===
    /// A did:webvh connection point must write did.jsonl alongside did.json.
    #[tokio::test]
    async fn connection_point_didwebvh_log_written_to_disk() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        let did_jsonl_path = tmp
            .path()
            .join(&cp_id)
            .join("did.jsonl");
        assert!(did_jsonl_path.exists(), "did.jsonl must be written for a did:webvh connection point");
    }

    /// The DID for a did:webvh connection point must contain a valid SCID (Qm... raw base58btc multihash)
    #[tokio::test]
    async fn connection_point_didwebvh_scid_in_did_string() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        let (did, _, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        assert!(
            did.starts_with("did:webvh:Q") || did.starts_with("did:webvh:z"),
            "did:webvh connection point DID must contain a raw base58btc SCID, got: {}",
            did
        );
    }

    /// The UUID must still be extractable from a did:webvh connection point DID string.
    #[tokio::test]
    async fn connection_point_uuid_extractable_from_didwebvh_string() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        // DID format: did:webvh:<SCID>:<domain>:connection-points:<UUID>
        let (did, _, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        let extracted_uuid = did
            .split(':')
            .next_back()
            .unwrap();
        assert_eq!(extracted_uuid, cp_id, "UUID must be extractable from a did:webvh connection point DID string");
    }

    /// The did.jsonl log produced for a did:webvh connection point must pass the library validator.
    #[tokio::test]
    async fn connection_point_didwebvh_log_passes_verifier() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        let (did, _, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        let jsonl_path = tmp
            .path()
            .join(&cp_id)
            .join("did.jsonl");
        let jsonl_content = tokio::fs::read_to_string(&jsonl_path)
            .await
            .unwrap();

        let mut lib_state = didwebvh_rs::DIDWebVHState::default();
        lib_state
            .resolve_log(&did, &jsonl_content, None)
            .await
            .expect("connection point did:webvh log must pass library validator");
    }

    /// A did:webvh connection point must also write did.json so that legacy did:web consumers
    /// can still resolve the document without did:webvh support.
    #[tokio::test]
    async fn existing_did_web_connection_point_not_broken_by_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        let (did, _, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            None,
            None,
        )
        .await
        .unwrap();

        // did.json must exist alongside did.jsonl so did:web document consumers still resolve correctly
        let did_json_path = tmp
            .path()
            .join(&cp_id)
            .join("did.json");
        assert!(
            did_json_path.exists(),
            "did.json must exist alongside did.jsonl for backward compat with did:web consumers"
        );

        // did.json must be valid JSON with verificationMethod
        let content = tokio::fs::read_to_string(&did_json_path)
            .await
            .unwrap();
        let doc: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert!(doc["verificationMethod"].is_array(), "did.json must contain verificationMethod");

        // did.json must reference the did:webvh DID in alsoKnownAs so consumers can cross-resolve
        let also_known_as = doc["alsoKnownAs"]
            .as_array()
            .expect("did.json must have alsoKnownAs array");
        assert!(
            also_known_as
                .iter()
                .any(|v| v.as_str() == Some(&did)),
            "did.json alsoKnownAs must include the did:webvh DID '{}', got: {:?}",
            did,
            also_known_as
        );
    }

    /// When DidLogStorage is provided, the birth log must be registered so /v1/resolve works.
    #[tokio::test]
    async fn webvh_identity_registers_with_did_log_storage() {
        let tmp = tempfile::tempdir().unwrap();
        let cp_id = uuid::Uuid::new_v4().to_string();

        let log_storage: std::sync::Arc<dyn crate::storage::DidLogStorage> =
            std::sync::Arc::new(crate::storage::FileDidLogStorage::new(tmp.path().join("logs")));

        let (did, _, _) = generate_connection_point_identity_webvh(
            &cp_id,
            "example.com",
            tmp.path(),
            "https://mediator.example.com",
            Some(log_storage.clone()),
            None,
        )
        .await
        .unwrap();

        let raw_entries = log_storage
            .load_all_raw(&did)
            .await
            .expect("load_all_raw must succeed");
        assert_eq!(raw_entries.len(), 1, "Exactly one birth log entry must be registered in DidLogStorage");
    }
}
