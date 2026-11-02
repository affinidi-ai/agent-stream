//! Utility functions for mediators

use dashmap::DashMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::{Arc, LazyLock};
use tracing::info;
use trust_tasks_rs::specs::messaging::account::update::v0_1::{MediatorAcl, MediatorAclAccessListMode};

/// well-known DID document response structure
#[derive(Debug, Deserialize)]
struct WellKnownDidResponse {
    id: String,
}

impl std::fmt::Display for WellKnownDidResponse {
    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

fn delivery_acl(
    mode: MediatorAclAccessListMode,
    anonymous_receive: bool,
) -> Result<MediatorAcl, String> {
    MediatorAcl::builder()
        .access_list_mode(mode)
        .anon_receive(anonymous_receive)
        .blocked(false)
        .create_invites(true)
        .local(true)
        .receive_forwarded(true)
        .receive_messages(true)
        .self_manage_list(true)
        .self_manage_receive_queue_limit(true)
        .self_manage_send_queue_limit(true)
        .send_forwarded(true)
        .send_messages(true)
        .try_into()
        .map_err(|error| format!("Failed to build mediator ACL: {error}"))
}

fn allow_all_acl() -> Result<MediatorAcl, String> {
    delivery_acl(MediatorAclAccessListMode::ExplicitDeny, true)
}

fn peer_only_acl() -> Result<MediatorAcl, String> {
    delivery_acl(MediatorAclAccessListMode::ExplicitAllow, false)
}

fn did_hash(did: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    format!("{:x}", hasher.finalize())
}

static ACL_MUTATION_LOCKS: LazyLock<DashMap<String, Arc<tokio::sync::Mutex<()>>>> = LazyLock::new(DashMap::new);

async fn replace_acl(
    atm: &affinidi_messaging_sdk::ATM,
    profile: &Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
    acl: MediatorAcl,
    allowed_peer: Option<&str>,
) -> Result<(), String> {
    let did = profile.inner.did.to_string();
    let lock = ACL_MUTATION_LOCKS
        .entry(did.clone())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone();
    let _guard = lock.lock().await;

    atm.trust_tasks()
        .account_update(profile, Some(did_hash(&did)), None, Some(acl), None)
        .await
        .map_err(|error| format!("Failed to replace mediator ACL mode: {error}"))?;
    atm.trust_tasks()
        .access_list_update(
            profile,
            None,
            true,
            allowed_peer
                .map(did_hash)
                .into_iter()
                .collect(),
            vec![],
        )
        .await
        .map_err(|error| format!("Failed to replace mediator ACL entries: {error}"))?;
    Ok(())
}

/// Try to fetch and parse a `did.jsonl` (webvh DID log) from the given URL.
/// Returns `Some(did)` on success, `None` on any failure (silent fallthrough).
/// The URL is SSRF-validated before the request is made.
async fn try_fetch_did_jsonl(url: &str) -> Option<String> {
    info!("Trying mediator did.jsonl at {}", crate::url_validation::redact_url_for_logging(url));
    let body = crate::outbound_fetch::fetch_public_bounded(url)
        .await
        .ok()?;
    let body = std::str::from_utf8(&body).ok()?;
    // The current DID state is the last non-empty line of the webvh log.
    let last_line = body
        .lines()
        .rfind(|l| !l.trim().is_empty())?;
    let entry: serde_json::Value = serde_json::from_str(last_line).ok()?;
    let did = entry
        .get("state")?
        .get("id")?
        .as_str()?;
    info!("Successfully fetched mediator DID from did.jsonl: {}", did);
    Some(did.to_string())
}

/// Try to fetch and parse a `did.json` from the given URL.
/// Returns `Some(did)` on success, `None` on any failure (silent fallthrough).
/// The URL is SSRF-validated before the request is made.
async fn try_fetch_did_json(url: &str) -> Option<String> {
    info!("Trying mediator did.json at {}", crate::url_validation::redact_url_for_logging(url));
    let body = crate::outbound_fetch::fetch_public_bounded(url)
        .await
        .ok()?;
    let doc: WellKnownDidResponse = serde_json::from_slice(&body).ok()?;
    info!("Successfully fetched mediator DID from did.json: {}", doc);
    Some(doc.id)
}

/// Return mediator DID for a specified mediator URL by resolving its DID.
///
/// Probes the origin-scoped `.well-known` location first (per RFC 8615,
/// well-known URIs always live at the origin root regardless of any path in
/// the input URL), then falls back to path-scoped locations for `did:web`
/// mediators hosted under a sub-path. Within each scope, tries `did.jsonl`
/// (did:webvh DID log) before `did.json` (did:web DID document).
///
/// Every candidate URL (and the input URL) is SSRF-validated before it is
/// fetched, preserving the service-endpoint guard.
///
/// Probe order for `https://host/mediator/v1`:
///   1. `https://host/.well-known/did.jsonl`
///   2. `https://host/.well-known/did.json`
///   3. `https://host/mediator/v1/did.jsonl`
///   4. `https://host/mediator/v1/did.json`
///
/// # Arguments
/// * `mediator_url` - root mediator URL
pub async fn fetch_mediator_did_from_url(mediator_url: &str) -> Result<String, String> {
    tokio::time::timeout(std::time::Duration::from_secs(10), fetch_mediator_did_from_url_inner(mediator_url))
        .await
        .map_err(|_| "Mediator DID discovery timed out".to_string())?
}

async fn fetch_mediator_did_from_url_inner(mediator_url: &str) -> Result<String, String> {
    let parsed = url::Url::parse(mediator_url).map_err(|e| format!("Invalid mediator URL: {}", e))?;

    let origin = parsed
        .origin()
        .ascii_serialization();
    let path = parsed
        .path()
        .trim_end_matches('/');
    let has_path = !path.is_empty() && path != "/";

    // Origin-scoped .well-known probes first (root did:web / did:webvh — common case)
    if let Some(did) = try_fetch_did_jsonl(&format!("{}/.well-known/did.jsonl", origin)).await {
        return Ok(did);
    }
    if let Some(did) = try_fetch_did_json(&format!("{}/.well-known/did.json", origin)).await {
        return Ok(did);
    }

    // Path-scoped fallback (did:web with sub-paths serve did.json{l} under the path)
    if has_path {
        let base = format!("{}{}", origin, path);
        if let Some(did) = try_fetch_did_jsonl(&format!("{}/did.jsonl", base)).await {
            return Ok(did);
        }
        if let Some(did) = try_fetch_did_json(&format!("{}/did.json", base)).await {
            return Ok(did);
        }
    }

    let tried = if has_path {
        format!(
            "{}/.well-known/did.jsonl, {}/.well-known/did.json, {}{}/did.jsonl, {}{}/did.json",
            origin, origin, origin, path, origin, path
        )
    } else {
        format!("{}/.well-known/did.jsonl, {}/.well-known/did.json", origin, origin)
    };
    Err(format!(
        "Failed to fetch mediator DID document from {} (tried: {})",
        crate::url_validation::redact_url_for_logging(mediator_url),
        tried
    ))
}

pub async fn set_acl_to_allow_everything_and_more(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> Result<(), String> {
    let did = profile.inner.did.to_string();
    info!("set_acl_to_allow_everything_and_more called for did: {}", did);

    // ⚠️ ▼▼▼ !!! do not uncomment unless you know what you are doing
    replace_acl(atm, &profile, allow_all_acl()?, None).await?;
    info!("profile Access Lists set to Allow Everything and More");
    Ok(())
}

pub async fn set_acl_to_peer(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
    peer_did: &str,
) -> Result<(), String> {
    replace_acl(atm, &profile, peer_only_acl()?, Some(peer_did)).await?;
    info!("profile Access List restricted to peer {}", peer_did);
    Ok(())
}

pub async fn set_acl_to_deny_all(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> Result<(), String> {
    replace_acl(atm, &profile, peer_only_acl()?, None).await?;
    info!("profile Access List denies all inbound delivery");
    Ok(())
}

pub async fn _set_acl_to_explicit_deny(
    atm: &affinidi_messaging_sdk::ATM,
    profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
) -> Result<(), String> {
    let did = profile.inner.did.to_string();
    info!("set_acl_to_explicit_deny called for did: {}", did);

    let profile_info = atm
        .trust_tasks()
        .account_get(&profile, None)
        .await
        .map_err(|e| format!("profile account not found on mediator: {}", e))?;
    info!("profile active: {:?}", profile_info);

    // Convert account::get MediatorAcl → account::update MediatorAcl via serde (structurally identical)
    let mut acl: MediatorAcl = serde_json::from_value(
        serde_json::to_value(&profile_info.acl).map_err(|e| format!("Failed to serialize ACL: {}", e))?,
    )
    .map_err(|e| format!("Failed to deserialize ACL: {}", e))?;
    acl.access_list_mode = Some(MediatorAclAccessListMode::ExplicitDeny);

    let mut hasher = Sha256::new();
    hasher.update(did.as_bytes());
    let did_hash = format!("{:x}", hasher.finalize());
    atm.trust_tasks()
        .account_update(&profile, Some(did_hash), None, Some(acl), None)
        .await
        .map_err(|e| format!("Failed to update ACL: {}", e))?;

    // Ensure their DID is removed from our temp did explicit deny list
    atm.trust_tasks()
        .access_list_update(&profile, None, true, vec![], vec![])
        .await
        .map_err(|e| format!("Failed to clear ACL: {}", e))?;

    info!("profile Access Lists set to Explicit Deny");
    Ok(())
}

pub async fn _update_acls(
    atm: &affinidi_messaging_sdk::ATM,
    our_profile: Arc<affinidi_messaging_sdk::profiles::ATMProfile>,
    their_did: &str,
) -> Result<(), String> {
    info!("update_acls called for did: {}", their_did);

    // Step 5.1: Update our temp DID's access lists for their temporary DID
    let our_profile_info = atm
        .trust_tasks()
        .account_get(&our_profile, None)
        .await
        .map_err(|e| format!("our profile account not found on mediator: {}", e))?;

    info!("our profile active: {:?}", our_profile_info);
    let is_explicit_allow = our_profile_info
        .acl
        .access_list_mode
        .as_ref()
        .is_some_and(|m| m.to_string() == "explicitAllow");
    info!(
        "our profile ACL Mode Type: {:?}",
        our_profile_info
            .acl
            .access_list_mode
    );

    let mut hasher = Sha256::new();
    hasher.update(their_did.as_bytes());
    let their_did_hash = format!("{:x}", hasher.finalize());
    if is_explicit_allow {
        // Ensure their DID is added to our temp did explicit allow list
        atm.trust_tasks()
            .access_list_update(&our_profile, None, false, vec![their_did_hash], vec![])
            .await
            .map_err(|e| format!("Failed to update ACL: {}", e))?;
    } else {
        // Ensure their DID is removed from our temp did explicit deny list
        atm.trust_tasks()
            .access_list_update(&our_profile, None, false, vec![], vec![their_did_hash])
            .await
            .map_err(|e| format!("Failed to update ACL: {}", e))?;
    }
    info!("our profile Access Lists reset");
    Ok(())
}

fn _get_didcomm_service_endpoint(did_document: &serde_json::Value) -> Result<&serde_json::Value, String> {
    let services = did_document
        .get("service")
        .and_then(|s| s.as_array())
        .ok_or_else(|| "No services found in DID document".to_string())?;

    let didcomm_service = services
        .iter()
        .find(|service| {
            service
                .get("type")
                .map(|service_type| {
                    (service_type.as_str() == Some("DIDCommMessaging"))
                        || service_type
                            .as_array()
                            .is_some_and(|arr| {
                                arr.iter()
                                    .any(|v| v.as_str() == Some("DIDCommMessaging"))
                            })
                })
                .unwrap_or(false)
        })
        .ok_or_else(|| "No DIDCommMessaging service found in DID document".to_string())?;

    tracing::debug!(
        "Found DIDCommMessaging service: {}",
        serde_json::to_string_pretty(didcomm_service).unwrap_or_default()
    );

    // Extract serviceEndpoint
    didcomm_service
        .get("serviceEndpoint")
        .ok_or_else(|| "DIDCommMessaging service missing serviceEndpoint".to_string())
}

/// Extract mediator information from a DID document.
/// Handles two scenarios:
/// 1. DIDCommMessaging service endpoint is a URL - extract directly
/// 2. DIDCommMessaging service endpoint is a DID - resolve it first, then extract URL
///
/// Returns: (mediator_url, final_did_document)
pub async fn extract_mediator_info(did_document: &serde_json::Value) -> Result<(String, serde_json::Value), String> {
    let endpoint_value = _get_didcomm_service_endpoint(did_document).and_then(extract_endpoint_value)?;

    tracing::info!("Extracted endpoint value: {}", endpoint_value);

    // Check if the endpoint is a DID or a URL
    if endpoint_value.starts_with("did:") {
        tracing::info!("Endpoint is a DID ({}), resolving to get actual URL...", endpoint_value);

        // Resolve the DID to get the actual service endpoint
        let resolved_doc = &resolve_did(&endpoint_value).await?;

        // Extract URL from the resolved DID document
        let mediator_url = _get_didcomm_service_endpoint(resolved_doc).and_then(extract_endpoint_value)?;

        if mediator_url.starts_with("did:") {
            return Err("Resolved endpoint is still a DID, expected a URL".to_string());
        }

        tracing::info!(
            "Resolved DID {} to URL: {}",
            endpoint_value,
            crate::url_validation::redact_url_for_logging(&mediator_url)
        );

        // Return the URL and the original DID document (not the resolved one)
        Ok((mediator_url, did_document.clone()))
    } else if endpoint_value.starts_with("http://")
        || endpoint_value.starts_with("https://")
        || endpoint_value.starts_with("ws://")
        || endpoint_value.starts_with("wss://")
    {
        // Endpoint is already a URL
        tracing::info!("Endpoint is a URL: {}", crate::url_validation::redact_url_for_logging(&endpoint_value));

        // Extract base URL (protocol + host) without path
        let base_url = extract_base_url(&endpoint_value)?;

        Ok((base_url, did_document.clone()))
    } else {
        Err(format!("Service endpoint is neither a DID nor a valid URL: {}", endpoint_value))
    }
}

/// Extract the endpoint value from a serviceEndpoint field.
/// Handles: string, object with uri/url field, or array of endpoint objects.
fn extract_endpoint_value(service_endpoint: &serde_json::Value) -> Result<String, String> {
    if let Some(url_str) = service_endpoint.as_str() {
        // Simple string endpoint
        return Ok(url_str.to_string());
    }

    if let Some(uri) = service_endpoint
        .get("uri")
        .and_then(|v| v.as_str())
    {
        // Object with uri field
        return Ok(uri.to_string());
    }

    if let Some(url) = service_endpoint
        .get("url")
        .and_then(|v| v.as_str())
    {
        // Object with url field
        return Ok(url.to_string());
    }

    if let Some(endpoint_array) = service_endpoint.as_array() {
        // Array of endpoint objects - find the first HTTP/HTTPS endpoint
        for ep in endpoint_array {
            if let Some(uri) = ep
                .get("uri")
                .and_then(|v| v.as_str())
                && (uri.starts_with("http://") || uri.starts_with("https://") || uri.starts_with("did:"))
            {
                return Ok(uri.to_string());
            }
        }

        // If no HTTP/HTTPS found, try the first URI
        if let Some(first_ep) = endpoint_array.first()
            && let Some(uri) = first_ep
                .get("uri")
                .and_then(|v| v.as_str())
        {
            return Ok(uri.to_string());
        }
    }

    Err(format!("Could not extract endpoint value from: {:?}", service_endpoint))
}

/// Extract base URL (protocol + host) from a full URL
fn extract_base_url(url: &str) -> Result<String, String> {
    url::Url::parse(url)
        .map_err(|e| format!("Failed to parse URL '{}': {}", url, e))
        .and_then(|parsed| {
            parsed
                .host_str()
                .map(|host| {
                    if let Some(port) = parsed.port() {
                        format!("{}://{}:{}", parsed.scheme(), host, port)
                    } else {
                        format!("{}://{}", parsed.scheme(), host)
                    }
                })
                .ok_or_else(|| format!("Could not extract host from URL: {}", url))
        })
}

/// Resolve a DID to get its DID document
async fn resolve_did(did: &str) -> Result<serde_json::Value, String> {
    tracing::info!("Resolving DID: {}", did);

    let client = crate::gateways::did_cache::shared_resolver();

    let resolution_result = client
        .resolve(did)
        .await
        .map_err(|e| format!("Failed to resolve DID {}: {}", did, e))?;

    let did_document = resolution_result.doc;

    // Convert to JSON for easier manipulation
    serde_json::to_value(&did_document).map_err(|e| format!("Failed to serialize resolved DID document: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn peer_acl_is_explicit_allow_without_anonymous_delivery() {
        let acl = peer_only_acl().unwrap();
        assert_eq!(
            acl.access_list_mode
                .unwrap()
                .to_string(),
            "explicitAllow"
        );
        assert_eq!(acl.anon_receive, Some(false));
        assert_eq!(did_hash("did:example:peer").len(), 64);
    }

    #[test]
    fn allow_all_acl_grants_every_capability_in_explicit_deny_mode() {
        let acl = serde_json::to_value(allow_all_acl().unwrap()).unwrap();
        assert_eq!(
            acl,
            json!({
                "accessListMode": "explicitDeny",
                "anonReceive": true,
                "blocked": false,
                "createInvites": true,
                "local": true,
                "receiveForwarded": true,
                "receiveMessages": true,
                "selfManageList": true,
                "selfManageReceiveQueueLimit": true,
                "selfManageSendQueueLimit": true,
                "sendForwarded": true,
                "sendMessages": true,
            })
        );
    }

    // ── extract_endpoint_value ────────────────────────────────────────────────

    #[test]
    fn test_extract_endpoint_value_string() {
        let endpoint = json!("https://mediator.example.com/didcomm");
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_object_uri() {
        let endpoint = json!({ "uri": "https://mediator.example.com/didcomm" });
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_object_url() {
        let endpoint = json!({ "url": "https://mediator.example.com/didcomm" });
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_array_http_uri() {
        let endpoint = json!([
            { "uri": "https://mediator.example.com/didcomm" },
            { "uri": "wss://mediator.example.com/ws" }
        ]);
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "https://mediator.example.com/didcomm");
    }

    #[test]
    fn test_extract_endpoint_value_array_did_uri() {
        let endpoint = json!([{ "uri": "did:web:mediator.example.com" }]);
        assert_eq!(extract_endpoint_value(&endpoint).unwrap(), "did:web:mediator.example.com");
    }

    #[test]
    fn test_extract_endpoint_value_unsupported_returns_error() {
        let endpoint = json!(42);
        assert!(extract_endpoint_value(&endpoint).is_err());
    }

    // ── extract_base_url ──────────────────────────────────────────────────────

    #[test]
    fn test_extract_base_url_https_no_port() {
        assert_eq!(extract_base_url("https://mediator.example.com/path").unwrap(), "https://mediator.example.com");
    }

    #[test]
    fn test_extract_base_url_https_with_port() {
        assert_eq!(
            extract_base_url("https://mediator.example.com:8443/path").unwrap(),
            "https://mediator.example.com:8443"
        );
    }

    #[test]
    fn test_extract_base_url_http() {
        assert_eq!(extract_base_url("http://localhost:8080/agents").unwrap(), "http://localhost:8080");
    }

    #[test]
    fn test_extract_base_url_wss_for_ssl() {
        assert_eq!(extract_base_url("wss://mediator.example.com:443/ws").unwrap(), "wss://mediator.example.com");
    }

    #[test]
    fn test_extract_base_url_wss() {
        assert_eq!(extract_base_url("wss://mediator.example.com:1234/ws").unwrap(), "wss://mediator.example.com:1234");
    }

    #[test]
    fn test_extract_base_url_invalid_returns_error() {
        assert!(extract_base_url("not a url").is_err());
    }
}
