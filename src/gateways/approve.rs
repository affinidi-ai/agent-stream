//! Gateway approval handler for human-in-the-loop OOB connections

use axum::{Extension, Json, extract::Path, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use tracing::info;

use crate::auth_manager::pat::PatResourceScope;
use crate::comm::didcomm::client::DIDCommClient;
use crate::gateways::connection_points::{ConnectionPointListenerManager, ConnectionPointStore};
use crate::gateways::{GatewayStore, types::Gateway};
use crate::tenancy::{PatTenantContext, ResourceKind, can_reference, scope_allows_resource};
/// Request body for approving a gateway connection
#[derive(Debug, Deserialize)]
pub struct ApproveGatewayRequest {
    pub name: String,
    pub description: String,
}

/// Approve a pending gateway connection
/// This completes the OOB handshake by sending connection-accepted to the acceptor
pub async fn approve_gateway<
    S: GatewayStore + 'static,
    P: ConnectionPointStore + 'static,
    M: crate::mediators::MediatorStore,
>(
    Extension(store): Extension<Arc<S>>,
    Extension(cp_store): Extension<Arc<P>>,
    Extension(mediator_store): Extension<Arc<M>>,
    Extension(pending_store): Extension<Arc<crate::gateways::PendingConnectionStore>>,
    Extension(bootstrap_config): Extension<Arc<crate::config::BootstrapConfig>>,
    Extension(network_config): Extension<Arc<crate::config::NetworkConfig>>,
    Extension(listener_manager): Extension<Option<Arc<ConnectionPointListenerManager>>>,
    #[cfg(feature = "didwebvh")] Extension(log_storage): Extension<
        Option<std::sync::Arc<dyn crate::storage::DidLogStorage>>,
    >,
    #[cfg(feature = "didwebvh")] Extension(identity_store): Extension<
        Option<std::sync::Arc<dyn crate::identity::didwebvh::DidWebVhIdentityStore>>,
    >,
    Path(gateway_id): Path<String>,
    context: Option<Extension<PatTenantContext>>,
    scope: Option<Extension<PatResourceScope>>,
    Json(req): Json<ApproveGatewayRequest>,
) -> Result<Json<Gateway>, (StatusCode, String)> {
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Approving gateway connection");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("  Gateway ID: {}", gateway_id);
    info!("  New Name: {}", req.name);
    info!("  New Description: {}", req.description);

    // Step 1: Get the pending gateway
    let mut gateway = store
        .get(&gateway_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get gateway: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Gateway not found".to_string()))?;
    if !crate::gateways::handlers::gateway_allowed(&gateway, &context, &scope) {
        return Err((StatusCode::FORBIDDEN, "Gateway is outside this token's permitted scope".to_string()));
    }

    // Verify it's in AwaitingApproval status
    if gateway.status != crate::gateways::types::GatewayStatus::AwaitingApproval {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("Gateway is not awaiting approval (status: {:?})", gateway.status),
        ));
    }

    info!("✓ Found gateway awaiting approval");

    // Step 2: Get the pending connection context
    let pending_conn = pending_store
        .get_approval_by_gateway_id(&gateway_id)
        .await
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Pending connection context not found".to_string()))?;
    if pending_conn.is_expired(chrono::Utc::now()) {
        return Err((StatusCode::GONE, "Pending connection approval has expired".to_string()));
    }

    info!("✓ Retrieved pending connection context");
    info!("  Our temporary DID: {}", pending_conn.our_temporary_did);
    info!("  Our secure DID: {}", pending_conn.our_secure_did);
    info!("  Their temporary DID: {}", pending_conn.their_temporary_did);
    info!("  Their secure DID: {:?}", pending_conn.their_secure_did);

    // Approval provisions a connection point; enforce that limit before we mutate
    // any state so a capped appliance fails the approval cleanly.
    if let Err(e) = crate::config::enforce_add("connections.connectionpoints").await {
        return Err((StatusCode::FORBIDDEN, e.message()));
    }

    // Step 3: Update gateway with provided name/description and set to Active
    gateway.name = req.name;
    gateway.description = req.description;
    gateway.status = crate::gateways::types::GatewayStatus::Active;
    gateway.updated_at = chrono::Utc::now();

    store
        .update(&gateway)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update gateway: {}", e)))?;

    info!("✓ Gateway updated with new name and Active status");

    // Step 4: Get the connection point to retrieve mediator information
    let connection_point = cp_store
        .get(&pending_conn.invitation_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get connection point: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Connection point not found".to_string()))?;

    // Get mediator details
    let mediator = mediator_store
        .get(&connection_point.mediator_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to get mediator: {}", e)))?
        .ok_or_else(|| (StatusCode::NOT_FOUND, "Mediator not found".to_string()))?;

    let tenant_context = context
        .as_ref()
        .map(|Extension(context)| context);
    let resource_scope = scope
        .as_ref()
        .map(|Extension(scope)| scope);
    if !can_reference(gateway.tenant_id.as_deref(), mediator.tenant_id.as_deref())
        || !scope_allows_resource(resource_scope, tenant_context, ResourceKind::Mediators, &mediator.id)
    {
        return Err((StatusCode::BAD_REQUEST, "Mediator reference is not accessible".to_string()));
    }

    let mediator_did = mediator.did.clone();
    info!("Using mediator: {}", mediator_did);

    // Step 5: Send connection-accepted message to acceptor
    info!("📤 Sending connection-accepted message to acceptor...");

    // Load the temporary DID's secrets from storage
    let storage_path = std::path::Path::new(
        &bootstrap_config
            .storage_paths
            .connection_points,
    );
    let temp_secrets = crate::gateways::connection_points::handlers::load_connection_point_secrets(
        &pending_conn.invitation_id,
        storage_path,
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to load temporary DID secrets: {}", e)))?;

    info!("✓ Loaded {} secrets for temporary DID", temp_secrets.len());

    // Build a DIDComm client for the temporary DID and register its profile
    // (no live_stream — this is a one-shot send of the connection-accepted
    // message). Registration authenticates with the mediator.
    let mut client = DIDCommClient::new(
        pending_conn
            .our_temporary_did
            .clone(),
        temp_secrets,
        Some(mediator_did.clone()),
        Some("oob-inviter-approval".to_string()),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to build DIDComm client: {}", e)))?;

    client
        .register_profile()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to register profile with ATM: {}", e)))?;

    info!("✓ Temporary DID profile registered with mediator");

    // Step 4.5: Create connection points for bidirectional communication BEFORE sending connection-accepted
    // We need to send the gateway CP DID in the connection-accepted message
    info!("📝 Creating connection points for gateway communication...");

    // IMPORTANT: Use the SAME mediator as the OOB connection point (already retrieved above)
    // Both sides of the connection MUST use the same mediator for the handshake to work!
    let gw_mediator_did = mediator_did.clone();
    let gw_mediator_id = connection_point
        .mediator_id
        .clone();

    let gw_mediator_url =
        crate::mediators::transport::resolve_mediator_rest_endpoint(&gw_mediator_did, mediator.did_document.clone())
            .await
            .map_err(|e| (StatusCode::BAD_GATEWAY, format!("Failed to resolve mediator endpoint: {}", e)))?;

    info!("  Using mediator from OOB connection point: {}", gw_mediator_did);

    // Create gateway connection point (for receiving from acceptor)
    let gateway_cp_id = uuid::Uuid::new_v4().to_string();
    if !scope_allows_resource(resource_scope, tenant_context, ResourceKind::ConnectionPoints, &gateway_cp_id) {
        return Err((StatusCode::FORBIDDEN, "Connection point is outside this token's permitted scope".to_string()));
    }

    let (gateway_cp_did, _gateway_cp_secrets, _gateway_cp_doc) =
        crate::gateways::connection_points::handlers::generate_connection_point_identity(
            &gateway_cp_id,
            &network_config.did.domain,
            std::path::Path::new(
                &bootstrap_config
                    .storage_paths
                    .connection_points,
            ),
            &gw_mediator_url,
            &connection_point.did_method,
            #[cfg(feature = "didwebvh")]
            log_storage.clone(),
            #[cfg(feature = "didwebvh")]
            identity_store.clone(),
        )
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to generate gateway connection point identity: {}", e))
        })?;

    // Store acceptor's secure DID in oob_message for ACL setup when listener starts
    let acceptor_secure_did = pending_conn
        .their_secure_did
        .as_ref()
        .ok_or_else(|| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Acceptor secure DID not found in pending connection".to_string())
        })?;

    let mut gateway_connection_point = super::connection_points::types::GatewayConnectionPoint::new(
        gateway.id.clone(),
        gw_mediator_id.clone(),
        gateway_cp_did.clone(),
        format!("Connection Point for {}", gateway.name),
        "Auto-created for OOB connection (inviter side, for receiving from acceptor)".to_string(),
        String::new(),
        String::new(),
        serde_json::json!({"acceptor_secure_did": acceptor_secure_did}), // Store for ACL setup
        None,
        super::connection_points::types::ConnectionPointType::OobResponder,
        String::new(),
    );

    gateway_connection_point.id = gateway_cp_id.clone();
    gateway_connection_point.last_used_at = Some(chrono::Utc::now());
    gateway_connection_point.did_method = connection_point
        .did_method
        .clone();

    cp_store
        .create(&gateway_connection_point)
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create gateway connection point: {}", e))
        })?;

    info!("  ✓ Gateway connection point {} created", gateway_cp_id);

    // Step 4.5: Start listener for the gateway connection point BEFORE sending connection-accepted
    // This ensures the DID is authenticated with the mediator before the other side tries to reach us
    info!("🎧 Starting WebSocket listener for gateway connection point...");

    let manager = listener_manager
        .as_ref()
        .ok_or_else(|| (StatusCode::INTERNAL_SERVER_ERROR, "Listener manager not available".to_string()))?;

    // Use request_start_listener for event-driven completion notification
    match manager.request_start_listener(gateway_connection_point.clone(), gw_mediator_did.clone()) {
        Ok(completion_rx) => {
            info!("  ✓ Gateway listener startup requested");

            // Wait for the listener to actually start (event-driven, no polling)
            info!("  ⏳ Waiting for listener to start...");
            match completion_rx.await {
                Ok(Ok(())) => {
                    info!("  ✓ Listener started successfully");
                }
                Ok(Err(e)) => {
                    // Listener failed to start - this is a critical error
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("Failed to start gateway listener: {}", e),
                    ));
                }
                Err(_) => {
                    return Err((
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Listener start notification channel closed".to_string(),
                    ));
                }
            }
        }
        Err(e) => {
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to request gateway listener startup: {}", e),
            ));
        }
    }

    info!("✓ Gateway connection point listener started and authenticated with mediator");

    // Step 5: NOW send connection-accepted with the gateway CP DID (not the OOB secure DID!)
    use crate::messages::MessageType;
    use affinidi_messaging_didcomm::Message as DIDCommMessage;
    use serde_json::json;

    let connection_accepted_msg = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ConnectionAccepted.to_string(),
        json!({"channel_did": gateway_cp_did.clone()}), // Send gateway CP DID, not OOB secure DID!
    )
    .from(
        pending_conn
            .our_temporary_did
            .clone(),
    )
    .to(pending_conn
        .their_temporary_did
        .clone())
    .thid(uuid::Uuid::new_v4().to_string())
    .finalize();

    client
        .pack_and_send_message(
            &connection_accepted_msg,
            &pending_conn.their_temporary_did,
            &pending_conn.our_temporary_did,
        )
        .await
        .map_err(|e| {
            (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to send connection-accepted message: {}", e))
        })?;

    info!("✓ Connection-accepted sent successfully with gateway CP DID: {}", gateway_cp_did);

    // Note: Temporary connection point is intentionally NOT cleaned up here
    // It must remain available for DID resolution so the acceptor can decrypt the message
    // Cleanup happens at server startup (see cleanup_expired_connection_points in server initialization)

    // Remove pending connection context (this can be cleaned up now)
    pending_store
        .remove_approval(&gateway_id)
        .await;
    info!("✓ Pending connection context removed");

    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    info!("✅ Gateway connection approved successfully");
    info!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");

    Ok(Json(gateway))
}
