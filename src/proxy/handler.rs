//! Shared proxy helper functions.
//!
//! The inbound/outbound surface proxy pipeline has been removed (pipe-only
//! gateway). What remains are small, protocol-agnostic helpers still consumed
//! by the fabric forwarding paths.

use std::sync::Arc;

use axum::http::Method;
use tracing::{debug, warn};

use crate::{channel_debug, channel_info, channel_warn};

/// Join a request path under a target endpoint. A path without a leading `/`
/// is joined with one, so no path (`@attacker.example/x`,
/// `.attacker.example/x`) can change the target's host. The same join Agent
/// Gateway uses.
pub(crate) fn join_endpoint_path(
    endpoint: &str,
    path_and_query: &str,
) -> String {
    if path_and_query == "/" {
        endpoint
            .trim_end_matches('/')
            .to_string()
    } else if path_and_query.starts_with('/') {
        format!("{}{}", endpoint.trim_end_matches('/'), path_and_query)
    } else {
        format!("{}/{}", endpoint.trim_end_matches('/'), path_and_query)
    }
}

/// Extract UCP operation type from request path and method
/// Supports UCP REST, MCP, and A2A transport bindings per spec
pub(crate) fn extract_ucp_operation(
    path: &str,
    method: &Method,
) -> Option<String> {
    // UCP Discovery endpoint (common to all transports)
    // Includes the standard A2A agent card path used by the UCP A2A binding
    // Also includes /.well-known/agent.json (A2A agent descriptor) — both are metadata-only
    if crate::proxy::paths::is_public_request(method.as_str(), path) {
        return Some("discovery".to_string());
    }

    // UCP REST Transport - Official UCP paths per https://ucp.dev/specification/checkout-rest/
    // POST /checkout-sessions -> create_checkout
    if method == Method::POST && (path.ends_with("/checkout-sessions") || path.contains("/checkout-sessions?")) {
        return Some("create_checkout".to_string());
    }

    // GET /checkout-sessions/{id} -> get_checkout
    if method == Method::GET
        && path.contains("/checkout-sessions/")
        && !path.contains("/complete")
        && !path.contains("/cancel")
    {
        return Some("get_checkout".to_string());
    }

    // PUT /checkout-sessions/{id} -> update_checkout
    if method == Method::PUT && path.contains("/checkout-sessions/") {
        return Some("update_checkout".to_string());
    }

    // POST /checkout-sessions/{id}/complete -> complete_checkout
    if method == Method::POST && path.contains("/checkout-sessions/") && path.contains("/complete") {
        return Some("complete_checkout".to_string());
    }

    // POST /checkout-sessions/{id}/cancel -> cancel_checkout
    if method == Method::POST && path.contains("/checkout-sessions/") && path.contains("/cancel") {
        return Some("cancel_checkout".to_string());
    }

    // Additional UCP REST endpoints for commerce operations
    // GET /products -> products_list
    if method == Method::GET && (path.ends_with("/products") || path.contains("/products?")) {
        return Some("products_list".to_string());
    }

    // POST /carts -> cart_create
    if method == Method::POST && (path.ends_with("/carts") || path.contains("/carts?")) {
        return Some("cart_create".to_string());
    }

    // GET /carts -> carts_list
    if method == Method::GET && (path.ends_with("/carts") || path.contains("/carts?")) {
        return Some("carts_list".to_string());
    }

    // POST /carts/{id}/items -> cart_add_item
    if method == Method::POST && path.contains("/carts/") && path.contains("/items") {
        return Some("cart_add_item".to_string());
    }

    // GET /carts/{id} -> cart_get
    if method == Method::GET && path.contains("/carts/") && !path.contains("/items") {
        return Some("cart_get".to_string());
    }

    // GET /orders -> orders_list
    if method == Method::GET && (path.ends_with("/orders") || path.contains("/orders?")) {
        return Some("orders_list".to_string());
    }

    // GET /orders/{id} -> order_get
    if method == Method::GET && path.contains("/orders/") {
        return Some("order_get".to_string());
    }

    // Legacy/generic UCP REST patterns (for backward compatibility)
    if method == Method::POST && path.contains("/checkout") && !path.contains("/complete") && !path.contains("/cancel")
    {
        return Some("checkout_create".to_string());
    }

    if method == Method::POST && path.contains("/payment") {
        return Some("payment".to_string());
    }

    if method == Method::GET && path.contains("/order/") {
        return Some("order_query".to_string());
    }

    if method == Method::GET && path.contains("/discount/") {
        return Some("discount_query".to_string());
    }

    None
}

/// Extract UCP operation type from request body JSON.
/// This handles MCP and A2A transports where the operation type is embedded in the body
/// rather than in the URL path.
///
/// This is a standalone helper so it can be called from both the direct proxy path
/// (handler.rs) and the fabric forwarding path (message_processor.rs).
pub(crate) fn extract_ucp_operation_from_body(
    body_bytes: &[u8],
    config_id: &str,
) -> Option<String> {
    if body_bytes.is_empty() {
        return None;
    }
    let mut ucp_operation: Option<String> = None;
    // Try to parse body as JSON and scan for UCP operation signals.
    // No channel-type gate: a2a.ucp.* and a2a.product* keys are specific enough to avoid false positives.
    if let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(body_bytes) {
        // Priority 1: Check A2A Transport with UCP data in nested message parts first
        // This handles params.message.parts[].data.action or parts[].text (JSON-encoded) or UCP-specific keys
        // Also handles JSON-RPC response format: result.parts[] (push notifications / webhooks)
        // Two-pass approach: first collect action + all UCP keys from both data and text fields, then decide
        let parts_from_params = body_json
            .get("params")
            .and_then(|p| p.get("message"))
            .and_then(|m| m.get("parts"))
            .and_then(|p| p.as_array());
        let parts_from_result = body_json
            .get("result")
            .and_then(|r| r.get("parts"))
            .and_then(|p| p.as_array());
        if let Some(parts) = parts_from_params.or(parts_from_result) {
            let mut found_action: Option<String> = None;
            let mut found_ucp_keys: Vec<String> = Vec::new();
            let mut found_product_keys: Vec<String> = Vec::new();

            for part in parts {
                // Process data field if present
                if let Some(data) = part
                    .get("data")
                    .and_then(|d| d.as_object())
                {
                    // Collect explicit action field — first found wins across all parts
                    if found_action.is_none()
                        && let Some(action) = data
                            .get("action")
                            .and_then(|a| a.as_str())
                    {
                        found_action = Some(action.to_string());
                    }
                    // Collect all a2a.ucp.* keys
                    for key in data.keys() {
                        if key.starts_with("a2a.ucp.") {
                            found_ucp_keys.push(key.clone());
                        } else if key.starts_with("a2a.product") {
                            found_product_keys.push(key.clone());
                        }
                    }
                }

                // Also check text field for JSON-encoded UCP operations
                if let Some(text) = part
                    .get("text")
                    .and_then(|t| t.as_str())
                {
                    // Try to parse text as JSON
                    if let Ok(text_json) = serde_json::from_str::<serde_json::Value>(text)
                        && let Some(text_obj) = text_json.as_object()
                    {
                        // Collect action field from parsed text — first found wins across all parts
                        if found_action.is_none()
                            && let Some(action) = text_obj
                                .get("action")
                                .and_then(|a| a.as_str())
                        {
                            found_action = Some(action.to_string());
                        }
                        // Collect all a2a.ucp.* keys from parsed text
                        for key in text_obj.keys() {
                            if key.starts_with("a2a.ucp.") {
                                found_ucp_keys.push(key.clone());
                            } else if key.starts_with("a2a.product") {
                                found_product_keys.push(key.clone());
                            }
                        }
                    }
                }
            }

            // Sort keys for deterministic operation inference across multi-part messages
            found_ucp_keys.sort();
            // Determine operation: UCP key evidence takes priority for specificity,
            // then action field, then generic inference from UCP key prefixes.
            // Use exact key matches for payment detection to avoid false positives
            // (e.g. prevent a2a.ucp.cart.payment_data from triggering complete_checkout).
            let has_payment_keys = found_ucp_keys
                .iter()
                .any(|k| k == "a2a.ucp.checkout.payment_data");
            let has_cart_keys = found_ucp_keys
                .iter()
                .any(|k| k.starts_with("a2a.ucp.cart"));

            if has_payment_keys {
                // Exact payment/mandate key present → complete_checkout (most specific)
                ucp_operation = Some("complete_checkout".to_string());
                channel_info!(config_id, "🛒 UCP (request): complete_checkout");
            } else if let Some(ref action) = found_action {
                // Explicit action field from parts — accept as-is.
                // Unknown actions are forwarded but warned for observability.
                ucp_operation = Some(action.clone());
                let known_ucp_actions = [
                    "create_checkout",
                    "get_checkout",
                    "update_checkout",
                    "complete_checkout",
                    "cancel_checkout",
                    "cart_create",
                    "cart_add_item",
                    "cart_get",
                    "cart_update",
                    "cart_remove_item",
                    "add_to_checkout",
                    "start_payment",
                    "checkout",
                    "payment",
                    "discovery",
                ];
                if known_ucp_actions.contains(&action.as_str()) {
                    channel_info!(config_id, "🛒 UCP (request): {}", action);
                } else {
                    channel_warn!(config_id, "🛒 UCP (request): unrecognized action '{}'", action);
                }
            } else if !found_ucp_keys.is_empty() {
                // Infer operation from the first (sorted) a2a.ucp.* key.
                // Key format: a2a.ucp.{operation}[.subfield] → extract first segment.
                // e.g. "a2a.ucp.checkout" → "checkout", "a2a.ucp.cart" → "cart_create"
                let first_key = &found_ucp_keys[0];
                let op = first_key
                    .strip_prefix("a2a.ucp.")
                    .unwrap_or(first_key.as_str());
                let op = op
                    .split('.')
                    .next()
                    .unwrap_or(op);
                // Map bare "cart" key to "cart_create" to align with REST operation names
                let op = if op == "cart" && has_cart_keys {
                    "cart_create"
                } else {
                    op
                };
                ucp_operation = Some(op.to_string());
                channel_info!(config_id, "🛒 UCP (request): {} (from key '{}')", op, first_key);
            } else if !found_product_keys.is_empty() {
                // a2a.product_results or similar → product discovery response
                ucp_operation = Some("discovery".to_string());
                channel_info!(config_id, "🛒 UCP (request): discovery (from '{}')", found_product_keys[0]);
            }
        }

        if ucp_operation.is_none()
            && body_json
                .get("jsonrpc")
                .and_then(|v| v.as_str())
                == Some("2.0")
            && let Some(method) = body_json
                .get("method")
                .and_then(|v| v.as_str())
        {
            // Map MCP methods to UCP operation names
            match method {
                // UCP MCP Transport - direct UCP operations
                "create_checkout" | "get_checkout" | "update_checkout" | "complete_checkout" | "cancel_checkout" => {
                    ucp_operation = Some(method.to_string());
                    channel_debug!(config_id, "Extracted UCP MCP method: {}", method);
                }
                // A2A Transport envelope methods on UCP channels:
                // These are A2A/JSON-RPC wrappers — the actual UCP operation is inside
                // the message parts (handled by Priority 1 above). If Priority 1 found
                // nothing, this is a non-UCP A2A message. Track as A2A method, not UCP.
                "message/send"
                | "message/stream"
                | "tasks/send"
                | "tasks/get"
                | "tasks/cancel"
                | "tasks/pushNotificationConfig/set"
                | "tasks/pushNotificationConfig/get"
                | "tasks/resubscribe"
                | "SendMessage"
                | "SendStreamingMessage"
                | "GetTask"
                | "CancelTask" => {
                    // These are A2A envelope methods, NOT UCP operations.
                    // Priority 1 already tried to extract UCP operation from parts.
                    // If we're here, there was no UCP data in parts → skip.
                    channel_debug!(
                        config_id,
                        "A2A envelope method '{}' on UCP channel, no UCP operation in parts — skipping",
                        method
                    );
                }
                _ => {
                    // Unknown method on UCP channel — could be a UCP extension or custom op
                    ucp_operation = Some(method.to_string());
                    channel_debug!(config_id, "Extracted unknown method as UCP operation: {}", method);
                }
            }
        }

        // Priority 3: UCP A2A Transport or custom implementations - operation in body
        // { "operation": "cart.create", ... } or { "params": { "operation": "..." } }
        if ucp_operation.is_none() {
            if let Some(operation) = body_json
                .get("operation")
                .and_then(|v| v.as_str())
            {
                ucp_operation = Some(operation.to_string());
                channel_debug!(config_id, "Extracted UCP operation from body: {}", operation);
            }
            // Also check params.operation for wrapped requests
            else if let Some(operation) = body_json
                .get("params")
                .and_then(|p| p.get("operation"))
                .and_then(|v| v.as_str())
            {
                ucp_operation = Some(operation.to_string());
                channel_debug!(config_id, "Extracted UCP operation from params.operation: {}", operation);
            }
        }
    }
    ucp_operation
}

/// Inject target authentication credentials into an outbound request header.
/// Returns the header name and value to inject, or None if method is not implemented.
pub(crate) async fn inject_target_auth_header(
    target_auth: &crate::config::TargetAuthConfig,
    secrets_store: &Option<Arc<dyn crate::secrets::SecretsStore>>,
    channel_name: &str,
) -> anyhow::Result<Option<(String, String)>> {
    use crate::config::TargetAuthMethod;

    match &target_auth.method {
        TargetAuthMethod::StaticSecret {
            secret_id,
            header_name,
            header_format,
        } => {
            let store = secrets_store
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Secrets store not available"))?;

            let secret = store
                .get_by_secret_id(secret_id)
                .await
                .map_err(|e| anyhow::anyhow!("Failed to load secret '{}': {}", secret_id, e))?
                .ok_or_else(|| anyhow::anyhow!("Secret with secret_id '{}' not found", secret_id))?;

            // Format the header value
            let header_value = header_format.replace("{value}", &secret.value);

            debug!(channel = channel_name, secret_id = %secret_id, header = %header_name, "Resolved target auth secret");

            Ok(Some((header_name.clone(), header_value)))
        }
        TargetAuthMethod::CredentialLookup => {
            // CredentialLookup method not yet implemented - using Secrets approach instead
            warn!(channel = channel_name, "CredentialLookup method not implemented, skipping target auth injection");
            Ok(None)
        }
    }
}
