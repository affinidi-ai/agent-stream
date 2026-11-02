//! Fabric forwarding utility for marketplace handlers.
//!
//! Provides `fabric_forward()` — a high-level function that sends a
//! `ForwardRequest` DIDComm message through an established inter-gateway
//! connection and waits for the `ForwardResponse`.
//!
//! Used by `get_marketplace_models` and `post_marketplace_purchase` when
//! the configured `marketplace_url` starts with `fabric://`.

use crate::gateways::ConnectionPointListenerManager;
use crate::messages::MessageType;
use affinidi_messaging_didcomm::Message as DIDCommMessage;
use std::collections::HashMap;
use std::time::Duration;
use tracing::{debug, info, warn};

/// Result of a fabric-forwarded request.
pub struct FabricForwardResult {
    pub status: u16,
    pub body: String,
    pub headers: HashMap<String, String>,
}

/// How long [`fabric_forward`] waits for the peer's answer.
pub const FABRIC_FORWARD_TIMEOUT: Duration = Duration::from_secs(30);

/// Send a request through the DIDComm fabric and wait for a response.
///
/// `listener_manager` — the gateway's connection point listener manager
/// `fabric_url`       — `fabric://{gateway_id}/{channel_id}`
/// `method`           — HTTP method (GET / POST)
/// `path`             — request path, e.g. `/api/models`
/// `headers`          — request headers to forward
/// `body`             — request body bytes
pub async fn fabric_forward(
    listener_manager: &ConnectionPointListenerManager,
    fabric_url: &str,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: &[u8],
) -> Result<FabricForwardResult, String> {
    fabric_forward_within(listener_manager, fabric_url, method, path, headers, body, FABRIC_FORWARD_TIMEOUT).await
}

/// [`fabric_forward`], waiting at most `timeout` for the answer. The peer gets
/// the same deadline.
pub async fn fabric_forward_within(
    listener_manager: &ConnectionPointListenerManager,
    fabric_url: &str,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: &[u8],
    timeout: Duration,
) -> Result<FabricForwardResult, String> {
    // Parse fabric://{gateway_id}/{channel_id}
    let fabric_path = fabric_url
        .strip_prefix("fabric://")
        .ok_or_else(|| format!("Invalid fabric URL: {}", fabric_url))?;

    let parts: Vec<&str> = fabric_path
        .split('/')
        .collect();
    if parts.len() < 2 {
        return Err(format!(
            "Invalid fabric URL format: {}. Expected: fabric://{{gateway_id}}/{{channel_id}}",
            fabric_url
        ));
    }

    let gateway_id = parts[0];
    let channel_id = parts[1];

    info!("[fabric_forward] Sending {} {} to gateway {} channel {}", method, path, gateway_id, channel_id);

    // Get the gateway listener (WebSocket connection)
    let gateway_listener = listener_manager
        .get_listener(gateway_id)
        .await
        .ok_or_else(|| {
            format!(
                "No active connection to gateway '{}'. Ensure the gateway is connected via a connection point.",
                gateway_id
            )
        })?;

    // Get the remote gateway's DID
    let remote_gateway_did = listener_manager
        .get_gateway_did(gateway_id)
        .await
        .ok_or_else(|| format!("Could not find DID for gateway '{}'", gateway_id))?;

    // Build the body value
    let body_string = String::from_utf8_lossy(body).to_string();
    let body_value = if !body_string.is_empty() {
        serde_json::from_str::<serde_json::Value>(&body_string)
            .unwrap_or_else(|_| serde_json::Value::String(body_string))
    } else {
        serde_json::Value::Null
    };

    // Build the ForwardRequest DIDComm message
    let expires_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        + timeout;
    let expires_time = expires_at
        .as_millis()
        .div_ceil(1000) as u64;
    let deadline_ms = expires_at.as_millis() as u64;

    let forward_request_msg = DIDCommMessage::build(
        uuid::Uuid::new_v4().to_string(),
        MessageType::ForwardRequest
            .as_str()
            .to_string(),
        serde_json::json!({
            "channel_id": channel_id,
            "method": method,
            "path": path,
            "headers": headers,
            "body": body_value,
            "deadline_ms": deadline_ms,
        }),
    )
    .from(
        gateway_listener
            .gateway_did
            .clone(),
    )
    .to(remote_gateway_did.clone())
    .thid(uuid::Uuid::new_v4().to_string())
    .expires_time(expires_time)
    .finalize();

    debug!("[fabric_forward] Sending ForwardRequest (ID: {}) to {}", forward_request_msg.id, remote_gateway_did);

    // Pre-resolve and cache the remote gateway's DID document
    let did_cache = listener_manager.get_did_cache();
    let tdk_state = gateway_listener
        .client
        .atm()
        .get_tdk();
    if let Err(e) = did_cache
        .resolve_and_cache_for_atm(&remote_gateway_did, tdk_state)
        .await
    {
        warn!("[fabric_forward] Failed to resolve remote DID: {}. Trying anyway.", e);
    }

    // Pack and send the message
    let packed = gateway_listener
        .client
        .atm()
        .pack_encrypted(
            &forward_request_msg,
            &remote_gateway_did,
            Some(&gateway_listener.gateway_did),
            Some(&gateway_listener.gateway_did),
        )
        .await
        .map_err(|e| format!("Failed to pack message: {:?}", e))?;

    gateway_listener
        .client
        .atm()
        .send_message(
            gateway_listener
                .client
                .profile(),
            &packed.0,
            &forward_request_msg.id,
            false,
            false,
        )
        .await
        .map_err(|e| format!("Failed to send message: {:?}", e))?;

    debug!("[fabric_forward] Message sent, waiting for response...");

    let result = gateway_listener
        .client
        .atm()
        .message_pickup()
        .live_stream_get(
            gateway_listener
                .client
                .profile(),
            &forward_request_msg.id,
            timeout,
            true,
        )
        .await;

    match result {
        Ok(Some((response_msg, _metadata))) => {
            let is_forward_response = response_msg.typ == MessageType::ForwardResponse.as_str();
            if !is_forward_response {
                return Err(format!("Unexpected message type: {}", response_msg.typ));
            }

            let status = response_msg
                .body
                .get("status")
                .and_then(|v| v.as_u64())
                .unwrap_or(500) as u16;

            let response_headers: HashMap<String, String> = response_msg
                .body
                .get("headers")
                .and_then(|v| v.as_object())
                .map(|obj| {
                    obj.iter()
                        .filter_map(|(k, v)| {
                            v.as_str()
                                .map(|s| (k.clone(), s.to_string()))
                        })
                        .collect()
                })
                .unwrap_or_default();

            let response_body = response_msg
                .body
                .get("body")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            info!("[fabric_forward] Response received: status={} body_len={}", status, response_body.len());

            Ok(FabricForwardResult {
                status,
                body: response_body,
                headers: response_headers,
            })
        }
        Ok(None) => Err("Timeout waiting for fabric response".to_string()),
        Err(e) => Err(format!("Error receiving fabric response: {:?}", e)),
    }
}
