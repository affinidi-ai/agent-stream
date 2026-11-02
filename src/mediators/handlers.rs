use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::{Deserialize, Serialize};

use crate::auth_manager::pat::{PatContext, PatResourceScope};
use crate::gateways::connection_points::ConnectionPointStore;
use crate::mediators::utils::extract_mediator_info;
use crate::tenancy::{PatTenantContext, ResourceKind, can_access, scope_allows_resource, tenant_for_create};

use super::MediatorStore;
use super::types::{Mediator, MediatorResponse, MediatorStatus};

// Trust pings and other mediator DIDComm operations go through a
// `DIDCommClient`, which owns the ATM/profile/TDK state and creates a fresh
// ephemeral session profile per ping (tearing its websocket down afterwards) so
// a reset mediator never wedges a stale cached socket.
use crate::comm::didcomm::client::DIDCommClient;

/// Request body for creating a mediator
#[derive(Debug, Deserialize)]
pub struct CreateMediatorRequest {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub did: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<serde_json::Value>,
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

fn mediator_allowed(
    mediator: &Mediator,
    context: &Option<Extension<PatTenantContext>>,
    scope: &Option<Extension<PatResourceScope>>,
) -> bool {
    can_access(mediator.tenant_id.as_deref(), tenant_context(context))
        && scope_allows_resource(resource_scope(scope), tenant_context(context), ResourceKind::Mediators, &mediator.id)
}

/// Request body for updating a mediator
#[derive(Debug, Deserialize)]
pub struct UpdateMediatorRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub did: Option<String>,
    pub status: Option<MediatorStatus>,
}

/// Request body for checking authentication compatibility
#[derive(Debug, Deserialize)]
pub struct CheckAuthRequest {
    pub did: String,
    pub did_document: serde_json::Value,
}

/// Response body for authentication compatibility check
#[derive(Debug, Serialize)]
pub struct CheckAuthResponse {
    pub compatible: bool,
    pub error: Option<String>,
    pub endpoint_url: Option<String>,
}

/// List all mediators
pub async fn list_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    let mut mediators = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?;
    mediators.retain(|mediator| mediator_allowed(mediator, &context, &scope));

    Ok(Json(
        mediators
            .into_iter()
            .map(MediatorResponse::from)
            .collect(),
    ))
}

/// List mediators compatible with OOB invitation creation
/// All stored mediators are compatible (validated during addition)
pub async fn list_compatible_mediators<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<Vec<MediatorResponse>>, (StatusCode, String)> {
    let mut mediators = store
        .list_all()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to list mediators: {}", e)))?;
    mediators.retain(|mediator| mediator_allowed(mediator, &context, &scope));

    tracing::info!("Returning {} mediators (all are compatible)", mediators.len());

    Ok(Json(
        mediators
            .into_iter()
            .map(MediatorResponse::from)
            .collect(),
    ))
}

/// Get a mediator by ID
pub async fn get_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::NOT_FOUND, "Mediator not found".to_string()));
    }

    Ok(Json(mediator.into()))
}

/// Create a new mediator
pub async fn create_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    pat: Option<Extension<PatContext>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(mut req): Json<CreateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    use affinidi_secrets_resolver::secrets::Secret;
    use did_peer::{
        DIDPeer, DIDPeerCreateKeys, DIDPeerKeys, DIDPeerService, PeerServiceEndPoint, PeerServiceEndPointShort,
    };

    req.tenant_id = tenant_for_create(req.tenant_id.take(), pat.is_some(), tenant_context(&context))
        .map_err(|message| (StatusCode::FORBIDDEN, message.to_string()))?;
    if let Err(e) = crate::config::enforce_add("connections.mediators").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    // Generate did:peer for this mediator connection.
    // Key agreement uses X25519 (the DIDComm default curve required for
    // authentication/encryption with the mediator).
    let mut ed25519_secret = Secret::generate_ed25519(None, None);
    let mut x25519_secret = Secret::generate_x25519(None, None)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate X25519 key: {}", e)))?;

    // Extract public key multibase from secrets
    let ed25519_multibase = ed25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get Ed25519 multibase: {:?}", e)))?;
    let x25519_multibase = x25519_secret
        .get_public_keymultibase()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get X25519 multibase: {:?}", e)))?;

    let keys = vec![
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Verification,
            type_: None,
            public_key_multibase: Some(ed25519_multibase),
        },
        DIDPeerCreateKeys {
            purpose: DIDPeerKeys::Encryption,
            type_: None,
            public_key_multibase: Some(x25519_multibase),
        },
    ];

    // DIDComm service endpoint pointing at the mediator (by DID), so the
    // mediator recognises it routes for this DID during authentication.
    let services = vec![DIDPeerService {
        _type: "dm".into(),
        id: None,
        service_end_point: PeerServiceEndPoint::Short(PeerServiceEndPointShort::URI(req.did.clone())),
    }];

    let (our_did, _) = DIDPeer::create_peer_did(&keys, Some(&services))
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create did:peer: {}", e)))?;

    tracing::info!("Generated did:peer {} for mediator connection", our_did);

    // Update secret IDs to match the did:peer.
    // #key-1 = Ed25519 (verification), #key-2 = X25519 (key agreement).
    ed25519_secret.id = format!("{}#key-1", our_did);
    x25519_secret.id = format!("{}#key-2", our_did);

    let secrets = vec![ed25519_secret, x25519_secret];
    let secrets_json = serde_json::to_value(&secrets)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to serialize secrets: {}", e)))?;

    // Fix malformed service endpoints in the DID document
    // Some mediators incorrectly use colons instead of slashes in URLs
    let fixed_did_document = req
        .did_document
        .map(|doc| fix_malformed_service_endpoints(doc, &req.did));
    crate::mediators::transport::resolve_and_validate_mediator_documents(&req.did, fixed_did_document.clone())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;

    let mut mediator = Mediator::new(req.name, req.description, req.did, fixed_did_document);
    mediator.tenant_id = req.tenant_id;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }
    mediator.our_did = Some(our_did);
    mediator.our_secrets = Some(secrets_json);

    store
        .create(&mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to store mediator: {}", e)))?;

    // Trigger mediator created event
    if let Some(ref notif_store) = notification_store {
        let mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: mediator_clone.id.clone(),
                name: mediator_clone.name.clone(),
                description: mediator_clone
                    .description
                    .clone(),
                did: mediator_clone.did.clone(),
                status: status_str,
                our_did: mediator_clone.our_did.clone(),
                created_at: Some(
                    mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_created(&notif, &mediator_trigger)
                .await;
        });
    }

    Ok(Json(mediator.into()))
}

/// Fix malformed service endpoints in DID documents
/// Some mediators incorrectly generate serviceEndpoint URLs with colons instead of slashes
/// Example: https://domain:path:to -> https://domain/path/to
fn fix_malformed_service_endpoints(
    mut did_document: serde_json::Value,
    did: &str,
) -> serde_json::Value {
    // Extract the domain from the DID
    // did:web:domain:path:segments -> domain
    // did:webvh:scid:domain:path:segments -> domain
    let domain = if let Some(domain_part) = did.strip_prefix("did:web:") {
        domain_part
            .split(':')
            .next()
            .unwrap_or("")
    } else if let Some(domain_part) = did.strip_prefix("did:webvh:") {
        let parts: Vec<&str> = domain_part
            .split(':')
            .collect();
        if parts.is_empty() {
            return did_document;
        }
        let has_scid = parts.len() >= 2 && !parts[0].contains('.') && !parts[0].contains('%');
        let domain_idx = if has_scid { 1 } else { 0 };
        parts
            .get(domain_idx)
            .copied()
            .unwrap_or("")
    } else {
        return did_document; // Not a did:web, return as-is
    };

    // Process services array
    if let Some(services) = did_document
        .get_mut("service")
        .and_then(|v| v.as_array_mut())
    {
        for service in services.iter_mut() {
            if let Some(endpoint) = service.get_mut("serviceEndpoint")
                && let Some(url_str) = endpoint.as_str()
            {
                // Check if URL has malformed colons after the domain
                // Pattern: https://domain:something -> https://domain/something
                if let Some(fixed_url) = fix_malformed_url(url_str, domain) {
                    tracing::warn!("Fixed malformed service endpoint: {} -> {}", url_str, fixed_url);
                    *endpoint = serde_json::Value::String(fixed_url);
                }
            }
        }
    }

    did_document
}

/// Fix a malformed URL by replacing colons with slashes after the domain
fn fix_malformed_url(
    url: &str,
    domain: &str,
) -> Option<String> {
    // Check if URL contains the domain followed by colons
    if let Some(after_https) = url.strip_prefix("https://")
        && after_https.starts_with(domain)
        && after_https.len() > domain.len()
    {
        let rest = &after_https[domain.len()..];
        // If the character after domain is a colon (not part of port), it's malformed
        if rest.starts_with(':')
            && !rest[1..]
                .chars()
                .next()
                .is_some_and(|c| c.is_ascii_digit())
        {
            // Replace colons with slashes in the path portion
            let fixed_path = rest.replace(':', "/");
            return Some(format!("https://{}{}", domain, fixed_path));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::{
        CheckAuthRequest, Mediator, PatResourceScope, PatTenantContext, fix_malformed_service_endpoints,
        mediator_allowed,
    };
    use axum::Extension;
    use serde_json::json;

    #[test]
    fn canonical_mediator_access_combines_tenant_kind_and_id() {
        let context = Some(Extension(PatTenantContext {
            token_id: "asat_test".into(),
            tenant_id: "tenant-a".into(),
        }));
        let scope = Some(Extension(PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:mediators:mediator-1\z").unwrap(),
        ))));
        let mut mediator = Mediator::new("Mediator".into(), String::new(), "did:web:mediator".into(), None);
        mediator.id = "mediator-1".into();

        mediator.tenant_id = Some("tenant-a".into());
        assert!(mediator_allowed(&mediator, &context, &scope));

        mediator.tenant_id = None;
        // Untenanted (legacy) record now denied to a tenant PAT (fail-closed hardening).
        assert!(!mediator_allowed(&mediator, &context, &scope));

        mediator.tenant_id = Some("tenant-b".into());
        assert!(!mediator_allowed(&mediator, &context, &scope));

        let wrong_kind = Some(Extension(PatResourceScope(std::sync::Arc::new(
            regex::Regex::new(r"\ATENANT:tenant-a:gateways:mediator-1\z").unwrap(),
        ))));
        mediator.tenant_id = Some("tenant-a".into());
        assert!(!mediator_allowed(&mediator, &context, &wrong_kind));
    }

    #[test]
    fn check_auth_requires_an_independent_mediator_did() {
        let document = json!({
            "id": "did:web:attacker.example",
            "service": []
        });
        let missing_did = serde_json::from_value::<CheckAuthRequest>(json!({
            "did_document": document.clone()
        }));
        assert!(missing_did.is_err(), "the DID must not be derived from the supplied document");

        let request = serde_json::from_value::<CheckAuthRequest>(json!({
            "did": "did:web:configured.example",
            "did_document": document
        }))
        .expect("an independently supplied DID is accepted");
        assert_eq!(request.did, "did:web:configured.example");
    }

    #[test]
    fn fix_malformed_service_endpoints_supports_didwebvh() {
        let doc = json!({
            "service": [{
                "serviceEndpoint": "https://mediator.example.com:mediator:v1"
            }]
        });

        let fixed = fix_malformed_service_endpoints(doc, "did:webvh:z6MkScid123:mediator.example.com:mediator:v1");

        assert_eq!(fixed["service"][0]["serviceEndpoint"], json!("https://mediator.example.com/mediator/v1"));
    }
}

/// Update a mediator
pub async fn update_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<UpdateMediatorRequest>,
) -> Result<Json<MediatorResponse>, (StatusCode, String)> {
    let mut mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    let old_mediator = mediator.clone();

    if let Some(name) = req.name {
        mediator.name = name;
    }
    if let Some(description) = req.description {
        mediator.description = description;
    }
    if let Some(did) = req.did {
        mediator.did = did;
    }
    if let Some(status) = req.status {
        mediator.status = status;
    }

    crate::mediators::transport::resolve_and_validate_mediator_documents(&mediator.did, mediator.did_document.clone())
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    mediator.updated_at = chrono::Utc::now();

    store
        .update(&mediator)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update mediator: {}", e)))?;

    // Trigger mediator updated event
    if let Some(ref notif_store) = notification_store {
        let old_mediator_clone = old_mediator.clone();
        let new_mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let old_status_str = match old_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let new_status_str = match new_mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let old_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: old_mediator_clone.id.clone(),
                name: old_mediator_clone
                    .name
                    .clone(),
                description: old_mediator_clone
                    .description
                    .clone(),
                did: old_mediator_clone.did.clone(),
                status: old_status_str,
                our_did: old_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    old_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    old_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            let new_mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: new_mediator_clone.id.clone(),
                name: new_mediator_clone
                    .name
                    .clone(),
                description: new_mediator_clone
                    .description
                    .clone(),
                did: new_mediator_clone.did.clone(),
                status: new_status_str,
                our_did: new_mediator_clone
                    .our_did
                    .clone(),
                created_at: Some(
                    new_mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    new_mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_updated(
                &notif,
                &old_mediator_trigger,
                &new_mediator_trigger,
            )
            .await;
        });
    }

    Ok(Json(mediator.into()))
}

/// Delete a mediator
pub async fn delete_mediator<S: MediatorStore>(
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(notification_store): Extension<Option<std::sync::Arc<crate::integrations::FileSystemNotificationStore>>>,
    Extension(cp_store): Extension<Option<std::sync::Arc<crate::gateways::FileSystemConnectionPointStore>>>,
    Extension(listener_manager): Extension<
        Option<std::sync::Arc<crate::gateways::connection_points::ws_listener::ConnectionPointListenerManager>>,
    >,
    Path(id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<StatusCode, (StatusCode, String)> {
    tracing::info!("Deleting mediator: {}", id);

    // Get mediator before deletion for trigger
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    // Stop all connection point listeners using this mediator
    if let (Some(cp_store_ref), Some(listener_mgr)) = (cp_store.as_ref(), listener_manager.as_ref()) {
        tracing::info!("Finding connection points using mediator '{}'...", id);

        // Get all connection points
        match cp_store_ref.list_all().await {
            Ok(connection_points) => {
                // Filter to those using this mediator
                let affected_cps: Vec<_> = connection_points
                    .into_iter()
                    .filter(|cp| cp.mediator_id == id)
                    .collect();

                if !affected_cps.is_empty() {
                    tracing::info!("Found {} connection point(s) using this mediator", affected_cps.len());

                    // Stop listener for each affected connection point
                    for cp in affected_cps {
                        tracing::info!("  Stopping listener for connection point '{}'...", cp.id);
                        if let Err(e) = listener_mgr
                            .stop_listener(&cp.id)
                            .await
                        {
                            tracing::warn!("    Failed to stop listener for connection point '{}': {}", cp.id, e);
                        } else {
                            tracing::info!("    ✓ Listener stopped for connection point '{}'", cp.id);
                        }
                    }
                } else {
                    tracing::info!("No connection points using this mediator");
                }
            }
            Err(e) => {
                tracing::error!("Failed to list connection points: {}", e);
                // Continue with mediator deletion even if we can't clean up listeners
            }
        }
    } else {
        tracing::warn!("Cannot stop connection point listeners: store or listener manager not available");
    }

    store
        .delete(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to delete mediator: {}", e)))?;

    // Trigger mediator deleted event
    if let Some(ref notif_store) = notification_store {
        let mediator_clone = mediator.clone();
        let notif = notif_store.clone();
        tokio::spawn(async move {
            let status_str = match mediator_clone.status {
                crate::mediators::types::MediatorStatus::Active => "Active".to_string(),
                crate::mediators::types::MediatorStatus::Disabled => "Inactive".to_string(),
            };
            let mediator_trigger = crate::integrations::mediator_integration_triggers::Mediator {
                id: mediator_clone.id.clone(),
                name: mediator_clone.name.clone(),
                description: mediator_clone
                    .description
                    .clone(),
                did: mediator_clone.did.clone(),
                status: status_str,
                our_did: mediator_clone.our_did.clone(),
                created_at: Some(
                    mediator_clone
                        .created_at
                        .to_rfc3339(),
                ),
                updated_at: Some(
                    mediator_clone
                        .updated_at
                        .to_rfc3339(),
                ),
            };
            crate::integrations::mediator_integration_triggers::trigger_mediator_deleted(&notif, &mediator_trigger)
                .await;
        });
    }

    Ok(StatusCode::NO_CONTENT)
}

/// Check if a mediator's authentication endpoints are accessible
/// Uses the actual SDK authentication flow to verify compatibility
pub async fn check_auth_compatibility(
    Extension(vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    Json(req): Json<CheckAuthRequest>,
) -> Result<Json<CheckAuthResponse>, (StatusCode, String)> {
    tracing::info!("Extracting mediator info from DID: {}", req.did);
    crate::mediators::transport::resolve_and_validate_mediator_documents(&req.did, Some(req.did_document.clone()))
        .await
        .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
    let mediator_did = req.did;

    // Extract DIDCommMessaging service endpoint (could be URL or DID)
    let (mediator_url, final_did_document) = extract_mediator_info(&req.did_document)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    tracing::info!("Testing authentication with mediator: {} (DID: {})", mediator_url, mediator_did);

    // Get gateway DID and secrets from VC issuer
    let gateway_did_doc = vc_issuer
        .get_did_document()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway DID: {}", e)))?;

    let gateway_did = gateway_did_doc
        .get("id")
        .and_then(|v| v.as_str())
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Gateway DID not found".to_string()))?
        .to_string();

    let secrets = vc_issuer
        .get_signing_secrets()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway secrets: {}", e)))?;

    tracing::info!("Testing authentication: {} -> {}", gateway_did, mediator_did);

    // Try to authenticate using the SDK
    match test_mediator_authentication(
        &mediator_url,
        &mediator_did,
        Some(&final_did_document),
        &gateway_did,
        secrets,
        gateway_did_doc,
    )
    .await
    {
        Ok(_) => {
            tracing::info!("✓ Authentication successful with mediator: {}", mediator_url);
            Ok(Json(CheckAuthResponse {
                compatible: true,
                error: None,
                endpoint_url: Some(mediator_url),
            }))
        }
        Err(e) => {
            tracing::warn!("✗ Authentication failed with mediator {}: {}", mediator_url, e);
            Ok(Json(CheckAuthResponse {
                compatible: false,
                error: Some(e),
                endpoint_url: Some(mediator_url),
            }))
        }
    }
}

/// Test authentication with a mediator using the ATM SDK
async fn test_mediator_authentication(
    mediator_url: &str,
    mediator_did: &str,
    mediator_did_document: Option<&serde_json::Value>,
    gateway_did: &str,
    secrets: Vec<affinidi_secrets_resolver::secrets::Secret>,
    did_document: serde_json::Value,
) -> Result<(), String> {
    use affinidi_messaging_sdk::{ATM, config::ATMConfig, profiles::ATMProfile};
    use affinidi_tdk_common::{TDKSharedState, profiles::TDKProfile};
    use std::sync::Arc;

    // Initialize TDK Shared State
    let tdk_state = Arc::new(
        TDKSharedState::new(
            crate::gateways::did_cache::headless_tdk_config()
                .map_err(|e| format!("Failed to build TDK config: {:?}", e))?,
        )
        .await
        .map_err(|e| format!("Failed to create TDK shared state: {:?}", e))?,
    );

    crate::comm::didcomm::mediator::cache_did_document_in_tdk_state(&tdk_state, gateway_did, did_document).await?;

    let mediator_documents = crate::mediators::transport::resolve_and_validate_mediator_documents(
        mediator_did,
        mediator_did_document.cloned(),
    )
    .await?;
    for (document_did, mediator_document) in mediator_documents {
        crate::comm::didcomm::mediator::cache_did_document_in_tdk_state(&tdk_state, &document_did, mediator_document)
            .await?;
    }

    // Create TDK Profile with secrets
    let tdk_profile = TDKProfile::new(&format!("auth-test-{}", uuid::Uuid::new_v4()), gateway_did, None, secrets);

    tdk_state
        .add_profile(&tdk_profile)
        .await;

    // Create ATM configuration
    let config = ATMConfig::builder()
        .build()
        .map_err(|e| format!("Failed to build ATM config: {}", e))?;

    // Initialize ATM SDK
    let atm = ATM::new(config, tdk_state.clone())
        .await
        .map_err(|e| format!("Failed to initialize ATM: {}", e))?;

    let compatibility_result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
        let profile = ATMProfile::new(
            &atm,
            Some(format!("auth-test-{}", uuid::Uuid::new_v4())),
            gateway_did.to_string(),
            Some(mediator_did.to_string()),
        )
        .await
        .map_err(|error| format!("Failed to authenticate with mediator: {error:?}"))?;
        let profile = Arc::new(profile);
        atm.profile_enable_websocket(&profile)
            .await
            .map_err(|error| format!("Failed to establish mediator WebSocket: {error:?}"))?;
        profile
            .stop_websocket()
            .await
            .map_err(|error| format!("Failed to close mediator WebSocket probe: {error:?}"))?;
        Ok::<(), String>(())
    })
    .await
    .unwrap_or_else(|_| Err("Mediator authentication and WebSocket probe timed out".to_string()));

    atm.graceful_shutdown().await;
    compatibility_result.map_err(|error| {
        if error.contains("404") || error.contains("Not Found") {
            format!("Authentication endpoint not found: {mediator_url}/authenticate/challenge")
        } else {
            error
        }
    })
}

/// Extract the base URL from a DIDCommMessaging service endpoint
#[allow(dead_code)]
fn extract_didcomm_service_endpoint(did_document: &serde_json::Value) -> Option<String> {
    tracing::debug!(
        "Extracting DIDComm service endpoint from DID document: {}",
        serde_json::to_string_pretty(did_document).unwrap_or_default()
    );

    let services = did_document
        .get("service")?
        .as_array()?;
    tracing::debug!("Found {} services in DID document", services.len());

    // Find DIDCommMessaging service
    let didcomm_service = services
        .iter()
        .find(|service| {
            if let Some(service_type) = service.get("type") {
                tracing::debug!("Checking service type: {:?}", service_type);
                if let Some(type_str) = service_type.as_str() {
                    return type_str == "DIDCommMessaging";
                }
                if let Some(type_array) = service_type.as_array() {
                    return type_array
                        .iter()
                        .any(|t| t.as_str() == Some("DIDCommMessaging"));
                }
            }
            false
        })?;

    tracing::debug!(
        "Found DIDCommMessaging service: {}",
        serde_json::to_string_pretty(didcomm_service).unwrap_or_default()
    );

    // Extract serviceEndpoint
    let service_endpoint = didcomm_service.get("serviceEndpoint")?;

    let base_url = if let Some(url_str) = service_endpoint.as_str() {
        // Simple string endpoint
        // support for port:
        // url_str.replace("%3A", ":").to_string()
        url_str.to_string()
    } else if let Some(uri) = service_endpoint
        .get("uri")
        .and_then(|v| v.as_str())
    {
        // Object with uri field
        uri.to_string()
    } else if let Some(url) = service_endpoint
        .get("url")
        .and_then(|v| v.as_str())
    {
        // Object with url field
        url.to_string()
    } else if let Some(endpoint_array) = service_endpoint.as_array() {
        // Array of endpoint objects - find the first HTTPS endpoint
        endpoint_array
            .iter()
            .find_map(|ep| {
                if let Some(uri) = ep
                    .get("uri")
                    .and_then(|v| v.as_str())
                    && uri.starts_with("https://")
                {
                    return Some(uri.to_string());
                }
                None
            })
            .or_else(|| {
                // If no HTTPS found, try any URI
                endpoint_array
                    .first()
                    .and_then(|ep| ep.get("uri"))
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string())
            })?
    } else {
        tracing::warn!("Could not extract URL from serviceEndpoint: {:?}", service_endpoint);
        return None;
    };

    // Extract base URL (protocol + host)
    if let Ok(parsed_url) = url::Url::parse(&base_url) {
        Some(format!("{}://{}", parsed_url.scheme(), parsed_url.host_str()?))
    } else {
        // Try to extract with regex
        let re = regex::Regex::new(r"^(https?://[^/]+)").ok()?;
        re.captures(&base_url)
            .and_then(|cap| cap.get(1))
            .map(|m| m.as_str().to_string())
    }
}

/// Response body for trust ping
#[derive(Debug, Serialize)]
pub struct TrustPingResponse {
    pub success: bool,
    pub message: String,
    pub round_trip_ms: Option<u64>,
}

/// Send a trust ping to a mediator to test connectivity
pub async fn trust_ping_mediator<S: MediatorStore>(
    Path(id): Path<String>,
    Extension(store): Extension<std::sync::Arc<S>>,
    Extension(_vc_issuer): Extension<std::sync::Arc<crate::identity::vc_issuer::VCIssuer>>,
    _listener_manager: Option<Extension<std::sync::Arc<crate::gateways::ConnectionPointListenerManager>>>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
) -> Result<Json<TrustPingResponse>, (StatusCode, String)> {
    use std::time::Instant;

    let total_start = Instant::now();
    let request_id = uuid::Uuid::new_v4().to_string()[..8].to_string();

    tracing::info!("[{request_id}] Trust ping requested for mediator: {}", id);

    // Get mediator from store
    let mediator = store
        .get(&id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;
    if !mediator_allowed(&mediator, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Mediator is outside this token's permitted scope".into()));
    }

    tracing::warn!("🆕 [{request_id}] Mediator: {} ({})", mediator.name, mediator.did);

    // Get our stored did:peer and secrets for this mediator.
    let (our_did, secrets) = if let (Some(did), Some(secrets_json)) = (&mediator.our_did, &mediator.our_secrets) {
        use affinidi_secrets_resolver::secrets::Secret;

        let secrets: Vec<Secret> = serde_json::from_value(secrets_json.clone())
            .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to deserialize secrets: {}", e)))?;

        tracing::info!("[{request_id}] Using stored did:peer {} for trust ping", did);
        (did.clone(), secrets)
    } else {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Mediator missing did:peer configuration. Please recreate the mediator.".to_string(),
        ));
    };

    // Build a fresh DIDComm client for this ping. `new_with_mediator_document`
    // seeds the mediator DID document into the client's resolver cache so
    // authentication can find the mediator's #auth service; the client's
    // `trust_ping_mediator` then spins an ephemeral session profile per ping and
    // tears its websocket down afterwards, so a reset mediator can never wedge a
    // stale/dead socket the way the previous global profile cache did.
    let client = DIDCommClient::new_with_mediator_document(
        our_did,
        secrets,
        Some(mediator.did.clone()),
        mediator.did_document.clone(),
        Some("trust-ping".to_string()),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build DIDComm client: {}", e)))?;

    tracing::info!("🔵 [{request_id}] Sending trust ping...");
    let ping = client
        .trust_ping_mediator(&mediator.did, std::time::Duration::from_secs(5))
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Trust ping failed: {}", e)))?;

    let total_elapsed = total_start.elapsed();
    tracing::warn!("🏁 [{request_id}] Trust ping operation COMPLETE - total time: {}ms", total_elapsed.as_millis());

    if ping.success {
        tracing::info!(
            "✓ [{request_id}] Trust ping successful to {} ({}ms RTT, {}ms total)",
            mediator.name,
            ping.round_trip_ms
                .unwrap_or(0),
            total_elapsed.as_millis()
        );
        Ok(Json(TrustPingResponse {
            success: true,
            message: format!(
                "Trust ping successful ({}ms)",
                ping.round_trip_ms
                    .unwrap_or(0)
            ),
            round_trip_ms: ping.round_trip_ms,
        }))
    } else {
        let message = ping
            .error
            .unwrap_or_else(|| "No pong response received".to_string());
        tracing::warn!("✗ [{request_id}] Trust ping unsuccessful for {}: {}", mediator.name, message);
        Ok(Json(TrustPingResponse {
            success: false,
            message,
            round_trip_ms: None,
        }))
    }
}
